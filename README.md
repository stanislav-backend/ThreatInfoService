# ThreatInfoService

ThreatInfoService — REST API на Go для хранения и обмена информацией об угрозах по MD5-хешу. Сервис позволяет создавать записи, получать сведения об угрозе и обновлять её название.

## Технологии

- Go
- PostgreSQL 17 и pgx
- Docker и Docker Compose
- golang-migrate
- Zap Logger
- OpenAPI 3.0 и Swagger UI
- Nginx

## Архитектура

Проект разделён на слои:

- **Domain Layer** — модель угрозы и валидация данных.
- **Repository Layer** — работа с PostgreSQL.
- **Service Layer** — бизнес-логика.
- **HTTP Transport** — обработка запросов и формирование ответов.
- **Core** — конфигурация, логирование и инфраструктура.

```text
ThreatInfoService/
├── cmd/
│   └── threatinfoservice/
├── internal/
│   ├── core/
│   └── features/
│       └── threats/
│           ├── repository/
│           ├── service/
│           └── transport/
├── migrations/
├── tests/
│   └── integration/
├── docs/
│   └── swagger/
│       ├── openapi.yaml
│       └── nginx.conf
├── .env.example
├── Dockerfile
├── docker-compose.yaml
├── Makefile
└── README.md
```

## Требования

Для запуска через Docker необходимы Docker Desktop с Docker Compose, Git и Make. Для локальной разработки также нужен Go версии, указанной в `go.mod`.

## Установка и настройка

Клонируйте репозиторий:

```bash
git clone https://github.com/stanislav-backend/ThreatInfoService.git
cd ThreatInfoService
```

Создайте `.env` на основе `.env.example` и укажите параметры PostgreSQL, HTTP-сервера и логирования. Файл `.env` не следует добавлять в Git.

## Запуск через Docker

```bash
make deploy
```

Docker Compose запускает PostgreSQL, применяет миграции и поднимает ThreatInfoService, Swagger UI и Nginx.

| Компонент | Адрес |
|---|---|
| REST API | http://localhost:8080 |
| Swagger UI | http://localhost:8081 |

В Swagger UI можно просматривать схемы API и отправлять запросы через **Try it out**.

Для остановки:

```bash
make undeploy
```

Данные PostgreSQL сохраняются в именованном Docker-томе.

## REST API

### POST /info — создание угрозы

```bash
curl -X POST http://localhost:8080/info \
  -H "Content-Type: application/json" \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic"}'
```

Успешный ответ — `201 Created`:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Trojan.Win32.Generic"
}
```

### GET /info/{md5} — получение угрозы

```bash
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

Успешный ответ — `200 OK`:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Trojan.Win32.Generic"
}
```

### PUT /info/{md5} — обновление угрозы

```bash
curl -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H "Content-Type: application/json" \
  -d '{"name":"Trojan.Win32.Updated"}'
```

Успешный ответ — `200 OK`:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Trojan.Win32.Updated"
}
```

### HTTP-статусы

| Код | Значение |
|---|---|
| 200 | Успешное получение или обновление |
| 201 | Запись создана |
| 400 | Некорректные данные |
| 404 | Запись не найдена |
| 409 | Запись уже существует |
| 500 | Внутренняя ошибка сервера |

## PostgreSQL и миграции

```bash
make db-up       # Запуск PostgreSQL
make db-status   # Состояние PostgreSQL
make db-down     # Остановка PostgreSQL
make migrate-up  # Применение миграций
make migrate-down # Откат миграции
```

При `make deploy` миграции применяются автоматически. **Внимание:** откат миграций может удалить таблицы и данные.

## Тестирование

В проекте реализовано 30 тестовых сценариев:

- 18 Unit Tests для Service Layer.
- 6 Integration Tests для PostgreSQL Repository.
- 6 Integration Tests для HTTP API.

Unit Tests не требуют PostgreSQL. Для Integration Tests необходимы переменные окружения из `.env` и отдельная база `threatinfoservice_test` с применёнными миграциями.

Запуск всех тестов:

```bash
go test -count=1 ./...
```

Проверка кода:

```bash
go vet ./...
```

## Логирование

Приложение использует Zap Logger. Логи HTTP-запросов содержат метод, путь, HTTP-статус и продолжительность обработки. В HTTP-интеграционных тестах файлы логов создаются во временных директориях.

## Swagger / OpenAPI

Спецификация находится в `docs/swagger/openapi.yaml`. После `make deploy` интерактивная документация доступна по адресу **http://localhost:8081**.
