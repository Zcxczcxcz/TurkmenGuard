# TurkmenGuard — руководство для разработчиков

Документ для команды, которая продолжит работу над **desktop-клиентом (WPF)**, **backend API сигнатур** и интеграцией.

---

## 1. Быстрый старт (клон → запуск)

### Требования

| Компонент | Версия |
|-----------|--------|
| Windows | 7 SP1+ / 10 / 11 **x64** |
| .NET Framework | 4.8 (runtime) |
| .NET SDK | 8+ (только для сборки) |
| Git | 2.x |
| PowerShell | 5.1+ |

### Шаги

```powershell
git clone https://github.com/Zcxczcxcz/TurkmenGuard.git
cd TurkmenGuard

dotnet build TurkmenGuard.sln -c Release
.\start.bat
```

**После клонирования всё уже на месте:**

| Что | Где | В git? |
|-----|-----|--------|
| ClamAV engine 1.5.3 (exe + dll) | `ThirdParty/ClamAV/` | Да (~277 МБ) |
| ClamAV CVD (main, daily, bytecode) | `ThirdParty/ClamAV/database/*.cvd` | Да |
| Hash SQLite (540k+) | `Data/hash-signatures.db` | Да (~95 МБ) |
| YARA rules (23 файла) | `Rules/` | Да |
| Backend API (заглушка) | `backend/` | Да (sample) |

Скрипт `tools/setup-clamav.ps1` нужен только если папка `ThirdParty/ClamAV` повреждена или отсутствует — он скачает движок заново.

### Проверка сборки

```powershell
dotnet run --project tests\TurkmenGuard.Tests\TurkmenGuard.Tests.csproj -c Release
# Ожидается: 17 passed, 0 failed
```

### Сборка релиза для пользователей

```powershell
.\publish.bat
# dist\TurkmenGuard-v4.5.0\  и  dist\TurkmenGuard-v4.5.0-win-x64.zip
```

---

## 2. Роли в проекте

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop (WPF) — src/TurkmenGuard/                          │
│  UI, сканер, карантин, настройки, tray                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS (только обновления)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend API — backend/  (TODO: ваш сервер)                 │
│  manifest.json + hash DB + rules zip                        │
└─────────────────────────────────────────────────────────────┘
```

| Роль | Папки | Задачи |
|------|-------|--------|
| **Frontend / Desktop** | `src/TurkmenGuard/`, `Views/`, `ViewModels/` | UI, UX, локализация (tk/ru/en), темы |
| **Engine / Core** | `src/TurkmenGuard/Core/`, `Monitoring/` | ClamAV, YARA, hash, entropy, real-time |
| **Backend** | `backend/` (новый код) | REST API сигнатур, CDN, версионирование |
| **DevOps** | `tools/`, `.github/` | CI, publish, setup-скрипты |

Подробная спецификация API: **[backend/README.md](../backend/README.md)**

---

## 3. Архитектура desktop-клиента

### Цепочка сканирования

```
Файл
  → ScanPolicy (расширения, exclusions)
  → ClamAvEngine (clamd / clamdscan / clamscan)
  → YaraScanner (libyara.NET, Rules/*.yar)
  → HashChecker (SQLite fallback)
  → EntropyAnalyzer (только Full Scan, PE, порог 7.95)
  → DetectionFilter (скрывает PUA/PUP, только High+ в Quick/Full)
```

### Ключевые файлы

| Файл | Назначение |
|------|------------|
| `Core/ScannerEngine.cs` | Оркестрация сканирования |
| `Core/ClamAvEngine.cs` | ClamAV pipe, daemon, severity mapping |
| `Core/DetectionFilter.cs` | Снижение ложных срабатываний |
| `Core/YaraScanner.cs` | Компиляция и запуск YARA |
| `Services/SignatureUpdateService.cs` | Загрузка обновлений с backend |
| `Services/SettingsService.cs` | `%AppData%\TurkmenGuard\settings.json` |
| `Security/SelfProtectionService.cs` | Single-instance, integrity |
| `Monitoring/RealTimeGuard.cs` | FileSystemWatcher |

### Пути на машине пользователя

| Назначение | Путь |
|------------|------|
| Настройки | `%AppData%\TurkmenGuard\settings.json` |
| Hash DB (runtime) | `%AppData%\TurkmenGuard\hash-signatures.db` |
| Логи | `%AppData%\TurkmenGuard\logs\` |
| Карантин | `%ProgramData%\TurkmenGuard\Quarantine\` |
| ClamAV (dev) | `{repo}\ThirdParty\ClamAV\` |
| ClamAV (release) | `{exe}\ClamAV\` |
| YARA | `{exe}\Rules\` |

---

## 4. Доступ к репозиторию (для владельца)

Добавить разработчика на GitHub:

1. Откройте: `https://github.com/Zcxczcxcz/TurkmenGuard/settings/access`
2. **Add people** → введите GitHub username → роль **Write** (или **Maintain** для lead)
3. Разработчик принимает invite по email

Через CLI (от владельца):

```powershell
gh repo add-collaborator Zcxczcxcz/TurkmenGuard USERNAME --permission push
```

Рекомендуемая модель веток:

- `main` — стабильные релизы
- `develop` — интеграция
- `feature/*`, `fix/*` — задачи разработчиков

---

## 5. Backend — что нужно реализовать

Клиент уже умеет качать обновления. Нужен HTTP-сервер, который отдаёт:

1. `GET /v1/manifest.json` — JSON с версией и URL файлов
2. `GET /v1/hash-signatures.db` — SQLite (~95 МБ)
3. `GET /v1/rules-pack.zip` — архив с `.yar` файлами

Пример manifest: `backend/manifest.sample.json`  
Полная спецификация: `backend/README.md`

После деплоя backend измените endpoint в настройках клиента или в `AppSettings.SignatureUpdateEndpoint`.

Placeholder URL сейчас: `https://signatures.turkmenguard.local/v1/manifest.json`

---

## 6. Полезные команды

```powershell
# Сброс настроек пользователя (счётчики, exclusions)
powershell -ExecutionPolicy Bypass -File tools\reset-user-settings.ps1

# Принудительная остановка всех процессов AV
.\stop-turkmenguard.bat

# Пересборка hash DB из JSON (dev)
powershell -ExecutionPolicy Bypass -File tools\build-hash-db.ps1

# Восстановить ClamAV если папка повреждена
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
```

---

## 7. Тестирование перед merge

1. `dotnet build TurkmenGuard.sln -c Release` — 0 errors
2. Тесты — 17/17 PASS
3. Quick Scan на чистой Windows — **0–2** угрозы (не тысячи)
4. EICAR — должен детектироваться (Test severity)
5. Смена темы в Settings — UI обновляется
6. Cancel во время скана — останавливается

---

## 8. Контакты и версия

- **Версия продукта:** 4.5.0
- **Репозиторий:** https://github.com/Zcxczcxcz/TurkmenGuard
- **Лицензии:** ClamAV (GPL/LGPL) — см. `ThirdParty/ClamAV/COPYING/`

При вопросах по desktop — см. `README.md`.  
При вопросах по API — см. `backend/README.md`.
