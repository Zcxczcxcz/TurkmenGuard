# TurkmenGuard — Backend API сигнатур

Спецификация HTTP API для команды backend-разработчиков.  
Desktop-клиент (`SignatureUpdateService.cs`) уже реализован — нужен рабочий сервер.

---

## Обзор

Клиент **не** отправляет файлы пользователя на сервер. Сеть используется **только** для загрузки обновлений сигнатур (hash DB + YARA pack). Сканирование полностью офлайн.

```
Desktop (TurkmenGuard.exe)
    │
    │  GET manifest.json
    ▼
Backend CDN / API
    │
    ├── hash-signatures.db  (~95 MB, SQLite)
    └── rules-pack.zip      (~1 MB, YARA .yar files)
```

---

## Endpoints

Базовый URL (настраивается в клиенте):

```
https://signatures.turkmenguard.local/v1/
```

Production URL подставьте в `settings.json` → `SignatureUpdateEndpoint`.

### 1. Manifest

```
GET /v1/manifest.json
Content-Type: application/json
```

**Response 200:**

```json
{
  "version": "2026.07.14",
  "hashDbUrl": "https://signatures.turkmenguard.local/v1/hash-signatures.db",
  "hashDbSha256": "a1b2c3d4e5f6...64 hex chars...",
  "rulesPackUrl": "https://signatures.turkmenguard.local/v1/rules-pack.zip"
}
```

| Поле | Тип | Обязательно | Описание |
|------|-----|-------------|----------|
| `version` | string | да | Версия набора сигнатур (любой строковый ID, например дата `YYYY.MM.DD`) |
| `hashDbUrl` | string | нет* | Прямая ссылка на SQLite hash DB |
| `hashDbSha256` | string | нет | SHA-256 hash DB в hex (рекомендуется) |
| `rulesPackUrl` | string | нет* | Прямая ссылка на zip с YARA правилами |

\* Хотя бы одно из `hashDbUrl` / `rulesPackUrl` должно быть заполнено, иначе обновление бессмысленно.

**Пример файла в репозитории:** [manifest.sample.json](./manifest.sample.json)

### 2. Hash database

```
GET /v1/hash-signatures.db
Content-Type: application/octet-stream
```

- Файл SQLite, формат совместим с `Core/HashDatabase.cs`
- ~540 000 записей MD5 + SHA256
- Максимальный размер GitHub: не проблема для CDN; для git — ~95 MB

**SHA-256:** клиент проверяет hash если `hashDbSha256` указан в manifest. При несовпадении обновление отклоняется.

### 3. YARA rules pack

```
GET /v1/rules-pack.zip
Content-Type: application/zip
```

Структура zip (плоская или с подпапками):

```
rules-pack.zip
├── meta.json          (опционально)
├── eicar.yar
├── ransomware_extended.yar
└── ... (остальные .yar из Rules/)
```

Клиент распаковывает в `{exe}/Rules/` с защитой от Zip Slip (`SignatureUpdateService.ExtractRulesPack`).

---

## Логика клиента

Источник: `src/TurkmenGuard/Services/SignatureUpdateService.cs`

1. По расписанию (`weekly`) или кнопке «Обновить сейчас»
2. `GET manifest.json`
3. Если `version` == `LastSignatureVersion` — skip (кроме force)
4. Скачать hash DB → проверить SHA-256 → заменить `%AppData%/TurkmenGuard/hash-signatures.db`
5. Скачать rules zip → распаковать в `Rules/` → перезагрузить YARA
6. Запустить `freshclam` для ClamAV CVD (если engine установлен)
7. Сохранить `LastSignatureVersion`, `LastSignatureUpdate` в settings

### Настройки клиента (`settings.json`)

```json
{
  "SignatureUpdatesEnabled": true,
  "SignatureUpdateSchedule": "weekly",
  "SignatureUpdateEndpoint": "https://signatures.turkmenguard.local/v1/manifest.json",
  "CheckUpdatesOnStartup": false,
  "LastSignatureVersion": null,
  "LastSignatureUpdate": null
}
```

---

## Рекомендуемая реализация backend

### Минимальный MVP

| Компонент | Вариант |
|-----------|---------|
| Static files | Nginx / Caddy / Azure Blob / S3 + CloudFront |
| Manifest | JSON файл в bucket или генерируется CI |
| Auth | Не требуется (публичные read-only URL) |
| HTTPS | Обязательно |

### CI pipeline (пример)

```
1. tools/build-hash-db.ps1     → hash-signatures.db
2. zip Rules/*.yar               → rules-pack.zip
3. sha256sum hash-signatures.db  → hashDbSha256
4. generate manifest.json
5. upload to CDN
6. bump version (date or semver)
```

### Версионирование

Рекомендуется:

- `version`: `YYYY.MM.DD` или `YYYY.MM.DD.N` (N — патч в день)
- Хранить историю manifest для rollback
- Не перезаписывать старые файлы — immutable URLs (`/v1/2026.07.14/hash-signatures.db`)

---

## Безопасность

- **HTTPS only** — клиент не проверяет certificate pinning (можно добавить позже)
- **hashDbSha256** — обязательно в production
- **Zip Slip** — уже защищено на клиенте; backend не должен отдавать вредоносные пути в zip
- **Rate limiting** — опционально на CDN

---

## Локальная разработка backend

### Mock server (Python)

```python
# backend/mock_server.py — пример для тестов
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
os.chdir(os.path.dirname(__file__) + "/static")
HTTPServer(("127.0.0.1", 8080), SimpleHTTPRequestHandler).serve_forever()
```

Структура `backend/static/`:

```
static/
├── v1/
│   ├── manifest.json
│   ├── hash-signatures.db
│   └── rules-pack.zip
```

Клиент для теста:

```json
"SignatureUpdateEndpoint": "http://127.0.0.1:8080/v1/manifest.json"
```

---

## TODO для backend-команды

- [ ] Выбрать хостинг (VPS / cloud / static CDN)
- [ ] Реализовать отдачу `manifest.json`, hash DB, rules zip
- [ ] CI: автосборка hash DB и rules pack при изменении `Rules/`
- [ ] Production URL вместо `signatures.turkmenguard.local`
- [ ] Мониторинг доступности endpoint
- [ ] (Опционально) API для статистики / телеметрии — **не реализовано в клиенте**

---

## Связанные файлы в репозитории

| Файл | Описание |
|------|----------|
| `backend/manifest.sample.json` | Пример manifest |
| `Data/hash-signatures.db` | Текущая hash DB для ship |
| `Rules/` | YARA правила для упаковки в zip |
| `tools/build-hash-db.ps1` | Сборка hash DB |
| `src/.../SignatureUpdateService.cs` | Клиентская логика |
