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
│   └── ...       
├── BaseModel/             # Pydantic схемы
│   └── ...
└── .env                   # Переменные окружения
```

## ⚙️ Установка и запуск

### Предварительные требования
- Python 3.11
- PostgreSQL
- Redis

### Установка зависимостей
```bash
pip install -r requirements.txt
```

### Запуск сервисов
```bash
docker compose up -d
```

### Настройка окружения
Создайте файл `.env`:
```env
REDIS_PASSWORD=123
REDIS_PORT=6379
REDIS_DB=1
REDIS_HOST=127.0.0.1
REDIS_TLS=true
POSTGRES_USER=postgres
POSTGRES_PASSWORD=123
POSTGRES_DB=stage
POSTGRES_URL=postgresql://127.0.0.1:5432/stage?user=postgres&password=123
SECRET_KEY=supersecretkey
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
REDIS_HOST=localhost
REDIS_PORT=6379
AUTH_TOKEN=abcdef123456
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

Статические файлы сохраняются в `/var/www/public/` на VPS-сервере с nginx на порте :80
### Конфигурация nginx
```
user www-data;
worker_processes auto;

events {
    worker_connections 1024;
}

http {

include /etc/nginx/mime.types;
default_type application/octet-stream;

sendfile on;
keepalive_timeout 65;

server {
    listen 80;
    root /var/www/public;
    
    # Serve static files
    location / {
        autoindex on;
        try_files $uri $uri/ =404;
    }

}}
```

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
