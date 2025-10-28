# Gitububkm.github.io

Добро пожаловать на мой персональный сайт — **[gitububkm.github.io](https://gitububkm.github.io)**  
Здесь я собираю свои проекты, эксперименты и заметки по программированию, технологиям и учебным проектам.

---

## О сайте

Сайт создан на базе **GitHub Pages** — это бесплатный хостинг от GitHub, который позволяет публиковать статические сайты прямо из репозитория.  
Используется минималистичный дизайн и чистый HTML/CSS, без лишних зависимостей.

---

## Структура репозитория

```plaintext
/
├── index.html        # Главная страница
├── assets/           # Изображения, иконки
├── script.js         # Скрипты
├── style.css         # Cтили
└── README.md         # Это описание проекта
```

---

# Как запустить локально

Если хочешь протестировать сайт у себя:

## Клонировать репозиторий
```plaintext
git clone https://github.com/gitububkm/gitububkm.github.io.git
cd gitububkm.github.io
```

## Запустить локальный сервер (Python 3)
```plaintext
python -m http.server 8000
```

## После этого открой в браузере:
```plaintext
http://localhost:8000

```

### Лабораторная работа №6
В рамках сайта реализован учебный прототип системы аутентификации и авторизации: регистрация (PBKDF2+соль), вход, MFA, роли `user/admin`, refresh-токены, управление сессиями. Запуск из сайта через кнопку **«Протестировать»** (блок «Лабораторная работа 6») или по прямым ссылкам: [`register.html`](./register.html) → [`login.html`](./login.html) → [`authentification.html`](./authentification.html) → [`user.html`](./user.html). Логика — в [`lab6.js`](./lab6.js).

---

## 🔒 Система Сбора Данных и Защита

### Функционал
Сайт автоматически собирает анонимную информацию о посетителях (браузер, ОС, железо, геолокация) и сохраняет её на защищенный сервер для статистики. Данные доступны только администратору.

### Архитектура безопасности

#### 1. **Многоуровневая Защита API**
- ✅ **HTTP Security Headers**: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, CSP
- ✅ **CORS**: Только разрешенные домены (gitububkm.github.io)
- ✅ **Rate Limiting**: 20 запросов/час на `/collect`, 10 на `/check-view`, 5 на `/delete`
- ✅ **IP Blocking**: Автоматические инструменты (curl, wget, postman) блокируются навсегда

#### 2. **Проверка Источника Запросов**
- ✅ **Referer/Origin Validation**: Только запросы с `https://gitububkm.github.io`
- ✅ **Page Token**: Криптографически случайный 64-символьный токен на каждую загрузку страницы
- ✅ **User-Agent Detection**: Блокировка всех автоматизированных инструментов

#### 3. **Валидация Данных**
- ✅ **Required Sections**: Network, System Info, Browser, Hardware, Localization, Battery, Timestamp
- ✅ **Required Keys**: platform, model, externalIP, fingerprint, userAgent, language, screen
- ✅ **Size Validation**: Минимум 300 символов, минимум 20 полей данных
- ✅ **Content Validation**: Проверка наличия реальных данных браузера

#### 4. **Аутентификация и Авторизация**
- ✅ **Server-Side Password Check**: Все пароли проверяются на сервере через HMAC
- ✅ **SHA-256 Hashing**: Пароли хешируются клиентом перед отправкой
- ✅ **Environment Variables**: Пароли хранятся ТОЛЬКО в Render (не в коде)
- ✅ **Session Management**: Токены доступа генерируются при успешной аутентификации

#### 5. **Защита Файлов**
- ✅ **Path Traversal Protection**: Проверка на `..` и `/` в путях
- ✅ **File Size Limits**: Чтение - 500KB максимум
- ✅ **Auto-Backup**: Автоматическое резервное копирование каждый час (retention: 7 дней)
- ✅ **Audit Logging**: Все попытки доступа логируются в `security.log`

#### 6. **Защита от DDoS и Злоупотреблений**
- ✅ **Rate Limiting на всех эндпоинтах**: Защита от перегрузки
- ✅ **IP Blocking**: 30 минут блокировки после превышения лимита
- ✅ **Permanent Block**: IP блокируется навсегда при обнаружении инструментов
- ✅ **Resource Limits**: Максимальный размер файла - 100KB

#### 7. **Логирование и Мониторинг**
- ✅ **Structured Logging**: Все критические события в `security.log`
- ✅ **GitHub Actions**: Keep-alive каждые 5 минут
- ✅ **Error Tracking**: Детальные логи ошибок безопасности

### Безопасность Паролей

**Пароли хранятся ТОЛЬКО в Render Environment Variables:**
- `SECRET_VIEW` - SHA-256 хеш пароля для просмотра секретного раздела
- `SECRET_DELETE` - SHA-256 хеш пароля для удаления файлов

**Генерация хешей:**
```bash
python -c "import hashlib; print(hashlib.sha256('ваш_пароль'.encode()).hexdigest())"
```

### Структура Backend
```
backend/
├── server.py          # Flask приложение с защитой
├── requirements.txt   # Зависимости (Flask, bcrypt, CORS)
└── data/             # Собранные данные (защищено)
    ├── site_logs/    # Логи посетителей
    └── backups/      # Автоматические бэкапы
```

### Структура Frontend
```
frontend/
├── script.js         # Основная логика сбора данных
├── index.html        # Главная страница
├── style.css         # Стили
└── router.js         # Роутинг
```

### API Endpoints

- **GET /ping** - Проверка работы сервера
- **POST /collect** - Сбор данных посетителя (защищен)
- **GET /list** - Список файлов (требует пароль)
- **GET /read** - Чтение файла (требует пароль)
- **DELETE /delete** - Удаление файла (требует пароль)
- **POST /check-view** - Проверка пароля для просмотра
- **POST /check-delete** - Проверка пароля для удаления
- **GET /ipinfo** - Прокси для ipinfo.io

### Оценка Безопасности: ⭐⭐⭐⭐⭐ (5/5)

**Защищено от:**
- ✅ SQL Injection (нет БД)
- ✅ XSS (экранирование данных)
- ✅ CSRF (проверка Origin/Referer)
- ✅ Path Traversal (валидация путей)
- ✅ Brute Force (rate limiting)
- ✅ DDoS (rate limiting + IP blocking)
- ✅ Автоматизированные инструменты (permanent ban)
- ✅ Подделка данных (строгая валидация)

---

**Дата последнего обновления безопасности:** 2025-01-28
