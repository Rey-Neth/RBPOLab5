# Лабораторная 5 — JWT и refresh-сессии

Продолжение RBPOLab4, Java 17+, PostgreSQL. API опросов и разграничение USER/ADMIN сохранены. Вход теперь через Bearer JWT, без Basic Auth и cookie-сессий.

## Запуск

Для новой базы выполните `database/setup-role.sql` через `psql` от имени `postgres`, передав переменные `database_name=survey_lab5` и `app_password`. Затем в базе `survey_lab5` последовательно выполните `src/main/resources/schema.sql`, `src/main/resources/data.sql` и `database/grants.sql` с переменной `database_name=survey_lab5`.

Создайте `.env` по образцу `.env.example` и укажите пароль роли `survey_lab5_app` и случайный `JWT_SECRET`.

1. `./mvnw.cmd spring-boot:run`. Адрес: http://localhost:8080.
2. Импортировать `requests.postman_collection.json` в Postman и запустить по порядку.

Аккаунты: `admin / TestAdmin123!`, `respondent / TestAccount123!`.
Настройки: JWT_SECRET (обязателен, минимум 32 байта), JWT_ACCESS_SECONDS (900), JWT_REFRESH_SECONDS (604800).

## Контракт

- `POST /auth/login`: username, password, необязательный deviceId; 200.
- `POST /auth/register`: username, password, необязательные email, deviceId; 201. Роль всегда USER.
- `POST /auth/refresh`: refreshToken; 200, без access и пароля.

Все три возвращают только accessToken и refreshToken. Access передаётся в `Authorization: Bearer ...` для `/api/**`. Старые `/api/auth/register` и Basic Auth больше не используются.
400 — пустые обязательные поля; 401 — неверный вход/токен/сессия; 409 — занятый логин. Проверка пароля и прав сохранена.

HS256, уникальный jti, обязательные sub/type/iat/exp; подпись и тип проверяются отдельно для access/refresh. Время БД совпадает с exp до секунды. Подписанный JWT читаем, поэтому пароль в payload не помещается.

Каждая пара имеет отдельную строку user_sessions. Refresh выполняется в одной транзакции с PESSIMISTIC_WRITE: ACTIVE → USED, новая строка ACTIVE. Повторное использование USED фиксирует REVOKED и возвращает 401 после коммита. Ошибка сохранения новой пары откатывает изменения; регистрация и выдача пары также атомарны. Немедленный отзыв access и всей цепочки не реализуются по условиям задания.

Для существующей БД выполнить `database/lab5-sessions.sql` от администратора (роль survey_lab5_app должна существовать). Проверка SQL после коллекции: `SELECT username, device_id, status, access_token_expiry, refresh_token_expiry FROM user_sessions ORDER BY refresh_token_expiry, id;` Старый refresh должен иметь REVOKED, новый — ACTIVE, без третьей строки от неуспешного повтора.

## Проверки

`mvn test` использует отдельную БД survey_lab5_test; задать TEST_DB_URL, DB_USER, DB_PASSWORD и JWT_SECRET. Схема и data.sql должны быть загружены заранее. Тесты покрывают JWT, HTTP-контракт, конкурентный refresh, откат регистрации, права и бизнес-операции опросов.

Материалы: https://www.jwt.io/introduction и https://www.rfc-editor.org/rfc/rfc7519.html.

Код задания сосредоточен в небольших классах: JwtService создаёт и проверяет JWT; TokenService выполняет вход, регистрацию и обновление пары; JwtFilter проверяет Bearer на защищённых запросах; AuthController связывает три адреса с сервисом. UserSession и репозиторий отвечают за хранение.

В refresh аннотация `@Transactional(noRollbackFor = BadCredentialsException.class)` нужна для одного случая: сохранить REVOKED даже при ответе 401 на повторный refresh. Ошибка сохранения новой пары остаётся обычной ошибкой транзакции и откатывает USED. Блокировка строки не позволяет двум запросам одновременно обновить одну сессию.
