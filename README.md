# Я.Проф - Backend API

Backend для мобильного приложения "Я.Проф" - профессиональной социальной платформы.

## 🚀 Технологии

### Основной стек
- **FastAPI** - современный Python веб-фреймворк
- **PostgreSQL** - основная реляционная БД
- **Redis** - кэш и хранение refresh-токенов
- **SQLAlchemy** - ORM для работы с БД
- **JWT** - аутентификация
- **Argon2** - хеширование паролей

### Зависимости
- `fastapi` - веб-фреймворк
- `uvicorn` - ASGI сервер
- `sqlalchemy` - ORM
- `argon2-cffi` - хеширование паролей
- `python-jose` - JWT токены
- `redis` - Redis клиент
- `python-dotenv` - переменные окружения

## 📁 Структура проекта

```
├── main.py                 # Точка входа приложения
├── models/                 # Модели базы данных
│   ├── db_session.py       # Сессии БД
│   ├── Users.py           # Модель пользователей
│   ├── Posts.py           # Модель постов
│   ├── attachments.py     # Модель вложений
│   ├── subscriptions.py   # Модель подписок
│   └── PostLike.py        # Модель лайков
├── BaseModel/             # Pydantic схемы
│   ├── UsersBase.py       # Базовая схема пользователя
│   ├── UserLoginBase.py   # Схема логина
│   ├── UserUpdateBase.py  # Схема обновления
│   ├── PostBase.py        # Схема постов
│   └── ResponseUserBase.py # Схема ответа
└── .env                   # Переменные окружения
```

## ⚙️ Установка и запуск

### Предварительные требования
- Python 3.8+
- PostgreSQL
- Redis

### Установка зависимостей
```bash
pip install fastapi uvicorn sqlalchemy argon2-cffi python-jose redis python-dotenv
```

### Настройка окружения
Создайте файл `.env`:
```env
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
REDIS_HOST=localhost
REDIS_PORT=6379
NGINX_SERVER=your-nginx-server
AUTH_TOKEN=your-auth-token
DATABASE_URL=postgresql://user:password@localhost/yaprof
```

### Запуск приложения
```bash
# Development режим
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production режим
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 🔐 Аутентификация

Используется JWT с access/refresh токенами:
- **Access токен** - короткоживущий (30 минут)
- **Refresh токен** - долгоживущий (7 дней), хранится в Redis

## 📡 API Endpoints

### Аутентификация
- `POST /register` - регистрация пользователя/компании
- `POST /login` - вход в систему
- `POST /refresh` - обновление токенов
- `POST /logout` - выход из системы

### Пользователи
- `GET /me` - информация о текущем пользователе
- `GET /about_user/{id}` - информация о пользователе по ID
- `GET /users` - список всех пользователей
- `DELETE /delete_user` - удаление аккаунта
- `GET /search/users` - поиск пользователей по тегам

### Посты
- `POST /create-post` - создание поста
- `GET /posts` - лента постов
- `GET /posts/{user_id}` - посты конкретного пользователя
- `POST /posts/{post_id}/like-toggle` - лайк/анлайк поста

### Подписки
- `GET /my-subscriptions` - мои подписки
- `GET /group-subscribers/{group_id}` - подписчики группы
- `POST /subscribe/{group_id}/toggle` - подписка/отписка

## 🗄 Базы данных

### PostgreSQL
Основная БД с таблицами:
- `users` - пользователи и компании
- `posts` - посты пользователей
- `attachments` - вложения к постам
- `subscriptions` - подписки пользователей
- `post_likes` - лайки постов

### Redis
Используется для:
- Хранения refresh-токенов
- Кэширования данных
- Сессий пользователей

## 🔧 Конфигурация

### Переменные окружения
- `SECRET_KEY` - секретный ключ для JWT
- `ALGORITHM` - алгоритм шифрования (по умолчанию HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES` - время жизни access токена
- `REFRESH_TOKEN_EXPIRE_DAYS` - время жизни refresh токена
- `REDIS_HOST`, `REDIS_PORT` - настройки Redis
- `NGINX_SERVER` - сервер для статических файлов

### CORS
Приложение настроено для работы с мобильным приложением:
```python
allow_origins=["*"]
allow_methods=["*"]
allow_headers=["*"]
```

## 📁 Работа с файлами

Статические файлы сохраняются в `/var/www/public/` и обслуживаются через nginx.

## 🚀 Production развертывание

1. Настройте PostgreSQL и Redis
2. Установите зависимости
3. Настройте переменные окружения
4. Запустите через uvicorn с reverse proxy (nginx)
5. Настройте SSL сертификаты

```bash
# Пример запуска в production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

## 📚 Документация API

После запуска приложения доступна автоматическая документация:
- Swagger UI: `http://localhost:8000/docs`
