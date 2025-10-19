from sys import api_version

from BaseModel.UserUpdateBase import UsersUpdateBase
from models.PostLike import PostLike
from models.db_session import global_init
from models import db_session
import uvicorn
from datetime import datetime, timedelta
from typing import Union, Optional
from uuid import uuid4
from fastapi import FastAPI, HTTPException, Depends, Cookie, Response, Header, status, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
import sqlalchemy
from BaseModel.PostBase import PostBase
from pydantic import BaseModel
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from jose import JWTError, jwt
import httpx
from sqlalchemy import or_
from typing import List
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from BaseModel.UsersBase import UsersBase
from models.Users import Users
from BaseModel.UserLoginBase import UserLogin
import redis.asyncio as aioredis
from BaseModel.ResponseUserBase import UserRead
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException, Depends
from jose import jwt, JWTError
from models.Posts import Posts
from models.attachments import Attachment
from pathlib import Path
import shutil
from models.db_session import SqlAlchemyBase
from models.subscriptions import Subscription

target_metadata = SqlAlchemyBase.metadata


def get_db():
    db = db_session.create_session()
    try:
        yield db
    finally:
        db.close()


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # адрес React
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
global_init()
SECRET_KEY = "supersecretkey"  # ⚠️ вынеси в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
redis_client = aioredis.Redis(host="localhost", port=6379, decode_responses=True)
# Your nginx server configuration
NGINX_SERVER = "http://your-domain.com"  # Change to your nginx server URL
AUTH_TOKEN = "abcdef123456"  # Same token as in nginx config

UPLOAD_DIR = Path("/var/www/static-files")
AUTH_TOKEN = "abcdef123456"


async def save_refresh_token(user_id: str, token: str):
    """Сохраняем refresh-токен в Redis с TTL"""
    await redis_client.setex(
        f"refresh:{user_id}", REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600, token
    )


async def verify_refresh_token(user_id: str, token: str):
    """Проверяем, совпадает ли refresh-токен"""
    stored_token = await redis_client.get(f"refresh:{user_id}")
    return stored_token == token


def get_user_id_from_token_header(authorization: str) -> str:
    """
    Декодирует JWT access токен из заголовка Authorization и возвращает user_id.
    Выбрасывает HTTPException, если токен некорректный.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing user ID")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# генерация JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, db_sess: Session, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    token_id = str(uuid4())
    expire = datetime.utcnow() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire, "type": "refresh", "jti": token_id})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# хеширование и проверка пароля
def hashed_password(password):
    ph = PasswordHasher()
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


PUBLIC_DIR = Path("public")
PUBLIC_DIR.mkdir(parents=True, exist_ok=True)


async def save_file_locally(file: UploadFile) -> str:
    """
    Сохраняет файл локально в папке /public и возвращает относительный URL.
    """
    filename = f"{uuid4()}-{file.filename}"
    file_path = PUBLIC_DIR / filename

    # сохраняем файл на диск
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # возвращаем путь, по которому можно будет получить файл
    return f"/public/{filename}"


@app.post("/register")
async def register_user(
        email: str = Form(...),  # обязательно
        password: str = Form(...),  # обязательно
        phone: str | None = Form(None),
        description: str | None = Form(None),
        main_tag: str | None = Form(None),
        additional_tags: str | None = Form(None),
        name: str | None = Form(None),
        age: int | None = Form(None),
        company_name: str | None = Form(None),
        is_group: bool = Form(False),
        avatar: UploadFile | None = File(None),
        db_sess: Session = Depends(get_db)
):
    # Проверка на существующий email
    if db_sess.query(Users).filter(Users.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid4())
    new_user = Users(
        id=user_id,
        email=email,
        phone=phone,
        password=hashed_password(password),
        description=description,
        is_group=is_group
    )

    # Дополнительные поля в зависимости от типа пользователя
    if is_group:
        new_user.company_name = company_name
        new_user.main_tag = main_tag
        new_user.additional_tags = [tag.strip() for tag in additional_tags.split(",")] if additional_tags else []
        new_user.subscriber_count = 0
    else:
        new_user.name = name
        new_user.age = age
        new_user.main_tag = main_tag
        new_user.additional_tags = [tag.strip() for tag in additional_tags.split(",")] if additional_tags else []
        new_user.subscriptions_count = 0

    # Сохраняем аватар, если есть
    if avatar:
        new_user.avatar_url = await save_file_locally(avatar)

    db_sess.add(new_user)
    db_sess.commit()
    db_sess.refresh(new_user)

    return {
        "id": new_user.id,
        "email": new_user.email,
        "phone": new_user.phone,
        "is_group": new_user.is_group,
        "description": new_user.description,
        "main_tag": new_user.main_tag,
        "additional_tags": new_user.additional_tags,
        "avatar_url": new_user.avatar_url,
        "company_name": new_user.company_name if is_group else None,
        "name": new_user.name if not is_group else None,
        "age": new_user.age if not is_group else None
    }


@app.post("/login")
async def login_user(user: UserLogin, response: Response, db_sess: Session = Depends(get_db)):
    # 1️⃣ Проверяем пользователя
    db_user = db_sess.query(Users).filter(Users.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 2️⃣ Генерируем токены
    access_token = create_access_token(data={"sub": str(db_user.id)})
    refresh_token = create_refresh_token(data={"sub": str(db_user.id)}, db_sess=db_sess)

    # 3️⃣ Сохраняем refresh-токен в Redis
    await save_refresh_token(db_user.id, refresh_token)

    # ✅ Возвращаем токены в заголовках
    response.headers["access_token"] = access_token
    response.headers["refresh_token"] = refresh_token

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/refresh")
async def refresh_token(request: Request, response: Response):
    refresh_token = request.headers.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token header missing")

    # Декодируем токен
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")

        if token_type != "refresh":
            raise HTTPException(status_code=401, detail="Not a refresh token")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Проверяем в Redis
    valid = await verify_refresh_token(user_id, refresh_token)
    if not valid:
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    # Генерируем новый access-токен
    new_access_token = create_access_token({"sub": user_id})

    # Можно обновить refresh токен (ротация)
    new_refresh_token = create_refresh_token({"sub": user_id}, db_sess=None)
    await save_refresh_token(user_id, new_refresh_token)

    response.headers["access_token"] = new_access_token
    response.headers["refresh_token"] = new_refresh_token

    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """
    Middleware для проверки access_token из headers (Authorization: Bearer <token>)
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        request.state.user = None
        return await call_next(request)

    token = auth_header.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("sub")
        token_type = payload.get("type")

        if token_type != "access":
            raise JWTError("Not an access token")

        request.state.user = user_id
    except JWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired access token"})

    return await call_next(request)


@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return response


@app.get("/about_user/{id}")
def about_me(id: str, request: Request, db_sess: Session = Depends(get_db)):
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    db_user = db_sess.query(Users).filter(Users.id == id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.is_group:
        return {
            "id": db_user.id,
            "email": db_user.email,
            "is_group": db_user.is_group,
            "company_name": db_user.company_name,
            "description": db_user.description,
            "main_tag": db_user.main_tag,
            "additional_tags": db_user.additional_tags,
            "avatar_url": db_user.avatar_url,
            "subscriber_count": db_user.subscriber_count,
            "phone": db_user.phone,
            "posts_count": db_user.posts_count,
            "age": db_user.age
        }
    else:
        return {
            "id": db_user.id,
            "email": db_user.email,
            "is_group": db_user.is_group,
            "name": db_user.name,
            "age": db_user.age,
            "description": db_user.description,
            "main_tag": db_user.main_tag,
            "additional_tags": db_user.additional_tags,
            "avatar_url": db_user.avatar_url,
            "posts_count": db_user.posts_count,
            "subscriptions_count": db_user.subscriptions_count,
        }


@app.get("/me")
def about_me(request: Request, db_sess: Session = Depends(get_db)):
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    db_user = db_sess.query(Users).filter(Users.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.is_group:
        return {
            "id": db_user.id,
            "email": db_user.email,
            "is_group": db_user.is_group,
            "company_name": db_user.company_name,
            "description": db_user.description,
            "main_tag": db_user.main_tag,
            "additional_tags": db_user.additional_tags,
            "avatar_url": db_user.avatar_url,
            "subscriber_count": db_user.subscriber_count,
            "posts_count": db_user.posts_count,
            "phone": db_user.phone,
            "age": db_user.age
        }
    else:
        return {
            "id": db_user.id,
            "email": db_user.email,
            "is_group": db_user.is_group,
            "name": db_user.name,
            "age": db_user.age,
            "description": db_user.description,
            "main_tag": db_user.main_tag,
            "additional_tags": db_user.additional_tags,
            "avatar_url": db_user.avatar_url,
            "posts_count": db_user.posts_count,
            "subscriptions_count": db_user.subscriptions_count,
        }


@app.post("/logout", response_model=None)
async def logout(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    user_id = get_user_id_from_token_header(auth_header)

    # Удаляем refresh-токен из Redis
    await redis_client.delete(f"refresh:{user_id}")

    return {"detail": "Logged out successfully"}


@app.get("/group-subscribers/{group_id}")
def group_subscribers(group_id: str, db_sess: Session = Depends(get_db)):
    group = db_sess.query(Users).filter(Users.id == group_id, Users.is_group == True).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    subscribers = db_sess.query(Subscription).filter_by(group_id=group_id).all()
    result = []
    for sub in subscribers:
        user = db_sess.query(Users).filter(Users.id == sub.user_id).first()
        result.append({
            "user_id": user.id,
            "name": user.name,
            "main_tag": user.main_tag,
            "avatar_url": user.avatar_url
        })

    return result


@app.get("/my-subscriptions")
def my_subscriptions(request: Request, db_sess: Session = Depends(get_db)):
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    subscriptions = db_sess.query(Subscription).filter_by(user_id=user_id).all()
    result = []
    for sub in subscriptions:
        group = db_sess.query(Users).filter(Users.id == sub.group_id).first()
        result.append({
            "id": group.id,
            "company_name": group.company_name,
            "main_tag": group.main_tag,
            "avatar_url": group.avatar_url
        })

    return result


@app.post("/subscribe/{group_id}/toggle")
def toggle_subscription(group_id: str, request: Request, db_sess: Session = Depends(get_db)):
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if user_id == group_id:
        raise HTTPException(status_code=400, detail="Cannot subscribe to yourself")

    user = db_sess.query(Users).filter(Users.id == user_id).first()
    group = db_sess.query(Users).filter(Users.id == group_id, Users.is_group == True).with_for_update().first()

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    try:
        existing_sub = db_sess.query(Subscription).filter_by(user_id=user_id, group_id=group_id).first()
        if existing_sub:
            # Отписываемся
            db_sess.delete(existing_sub)
            group.subscriber_count = max(group.subscriber_count - 1, 0)
            action = "unsubscribed"
        else:
            # Подписываемся
            new_sub = Subscription(id=str(uuid4()), user_id=user_id, group_id=group_id)
            db_sess.add(new_sub)
            group.subscriber_count += 1
            action = "subscribed"

        db_sess.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        db_sess.rollback()
        raise HTTPException(status_code=500, detail="DB error")

    return {"detail": f"{action} successfully", "subscriber_count": group.subscriber_count}


@app.get("/users", response_model=List[UserRead])
def get_entities(db_sess: Session = Depends(get_db)):
    users = db_sess.query(Users).all()

    # Приводим None к пустому списку для additional_tags
    for u in users:
        if u.additional_tags is None:
            u.additional_tags = []

    # Объединяем всё в один список
    return users


@app.delete("/delete_user")
def delete_user(request: Request, db_sess: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    user_id = get_user_id_from_token_header(auth_header)

    user = db_sess.query(Users).filter(Users.id == user_id).first()
    db_sess.delete(user)

    # 3️⃣ Сохраняем изменения
    db_sess.commit()
    return {"detail": "User deleted successfully"}


@app.post("/create-post")
async def create_post(
        request: Request,
        title: str = Form(...),
        content: str = Form(...),
        file: UploadFile = File(None),
        db_sess: Session = Depends(get_db)
):
    # 1️⃣ Проверка авторизации через middleware
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="No token provided")

    user = db_sess.query(Users).filter(Users.id == user_id).first()
    user.posts_count += 1

    # 2️⃣ Создаём пост
    post_id = str(uuid4())
    new_post = Posts(
        id=post_id,
        title=title,
        content=content,
        owner_id=user_id
    )
    db_sess.add(new_post)
    db_sess.commit()
    db_sess.refresh(new_post)

    attachment_url = None

    # 3️⃣ Если передан файл — сохраняем его в /public
    if file:
        attachment_url = await save_file_locally(file)
        new_attachment = Attachment(
            id=str(uuid4()),
            file_url=attachment_url,
            post_id=post_id
        )
        db_sess.add(new_attachment)
        db_sess.commit()

    return {
        "post_id": new_post.id,
        "title": new_post.title,
        "content": new_post.content,
        "attachment_url": attachment_url
    }


@app.get("/posts")
def get_posts(
        offset: int = Query(0, ge=0),
        limit: int = Query(10, le=50),
        db_sess: Session = Depends(get_db)
):
    """
    Возвращает ленту постов с ленивой загрузкой (pagination)
    """
    posts = (
        db_sess.query(Posts)
        .order_by(Posts.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Чтобы сразу вернуть и вложения
    result = []
    for post in posts:
        result.append({
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "created_at": post.created_at,
            "owner_id": post.owner_id,
            "likes_count": post.likes_count,
            "attachments": [
                {"id": a.id, "file_url": a.file_url} for a in post.attachments
            ]
        })

    return {"posts": result, "next_offset": offset + len(result)}


@app.get("/posts/{user_id}")
def get_posts(
        user_id: str,
        db_sess: Session = Depends(get_db),
        offset: int = Query(0, ge=0),
        limit: int = Query(10, le=50),
):
    """
    Возвращает посты с ленивой загрузкой (пагинация) и возможностью фильтрации по пользователю.
    """
    query = db_sess.query(Posts).order_by(Posts.created_at.desc())

    # 🔹 Если указан user_id — фильтруем только его посты
    if user_id:
        query = query.filter(Posts.owner_id == user_id)

    posts = query.offset(offset).limit(limit).all()

    result = []
    for post in posts:
        result.append({
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "created_at": post.created_at,
            "owner_id": post.owner_id,
            "likes_count": post.likes_count,
            "attachments": [
                {"id": a.id, "file_url": a.file_url} for a in post.attachments
            ]
        })

    return {
        "posts": result,
        "next_offset": offset + len(result),
        "has_more": len(posts) == limit  # 👈 фронт может использовать это для проверки
    }



@app.get("/search/users")
def search_users(
        tag: Optional[str] = Query(None, min_length=1, description="Поиск по тегу"),
        is_group: Optional[bool] = Query(None, description="True — только группы, False — только пользователи"),
        offset: int = Query(0, ge=0),
        limit: int = Query(20, le=50),
        db_sess: Session = Depends(get_db)
):
    query = db_sess.query(Users)

    # Фильтр по is_group, если указан
    if is_group is not None:
        query = query.filter(Users.is_group == is_group)

    # Фильтр по тегу, если указан
    if tag:
        tag_pattern = f"%{tag.lower()}%"
        query = query.filter(
            or_(
                Users.main_tag.ilike(tag_pattern),
                Users.additional_tags.any(tag.lower())  # для Postgres массивов
            )
        )

    # Пагинация
    users = query.offset(offset).limit(limit).all()

    results = [{
        "id": user.id,
        "email": user.email,
        "is_group": user.is_group,
        "description": user.description,
        "main_tag": user.main_tag,
        "additional_tags": user.additional_tags,
        "avatar_url": user.avatar_url,
        "company_name": user.company_name if user.is_group else None,
        "name": user.name if not user.is_group else None,
        "age": user.age if not user.is_group else None
    } for user in users]

    has_more = len(users) == limit

    return {
        "users": results,
        "next_offset": offset + len(users),
        "has_more": has_more
    }


@app.post("/posts/{post_id}/like-toggle")
async def toggle_like(post_id: str, request: Request, db_sess: Session = Depends(get_db)):
    user_id = request.state.user
    if not user_id:
        raise HTTPException(status_code=401, detail="No token provided")

    post = db_sess.query(Posts).filter(Posts.id == post_id).with_for_update().first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    try:
        existing_like = db_sess.query(PostLike).filter_by(post_id=post_id, user_id=user_id).first()
        if existing_like:
            # Удаляем лайк
            db_sess.delete(existing_like)
            post.likes_count = max(post.likes_count - 1, 0)
            action = "unliked"
        else:
            # Добавляем лайк
            new_like = PostLike(id=str(uuid4()), post_id=post_id, user_id=user_id)
            db_sess.add(new_like)
            post.likes_count += 1
            action = "liked"

        db_sess.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        db_sess.rollback()
        raise HTTPException(status_code=500, detail="DB error")

    return {"detail": f"Post {action} successfully", "likes_count": post.likes_count}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
