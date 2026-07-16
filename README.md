# TurkmenGuard (Türkmen Goragçy) v4.8.0

**Репозиторий:** https://github.com/Zcxczcxcz/TurkmenGuard  
**Для разработчиков:** [docs/DEVELOPERS.md](docs/DEVELOPERS.md) · **Backend API:** [backend/README.md](backend/README.md)

**Автономный антивирус для Windows 7 SP1+ / 10 / 11 (x64)**  
Офлайн-сканирование локально. Сеть — **только** для обновления сигнатур (раз в неделю или вручную).

---

## Что это

**TurkmenGuard** — desktop WPF-антивирус с тёмным минималистичным интерфейсом (тёмно-синий + зелёный акцент). Türkmençe — основной язык, также Русский и English.

| Параметр | Значение |
|----------|----------|
| Платформа | **.NET Framework 4.8** (`net48`) — совместимость с Windows 7 |
| UI | WPF + Material Design 3, корпоративная тёмная тема |
| Движок | **ClamAV 1.5.3** → YARA (entropy gate) → Hash fallback |
| Hash fallback | SQLite 540k+ (если ClamAV engine не установлен) |
| Сеть | `SignatureUpdateService` + `freshclam` для CVD |
| Версия | **4.8.0** |

### Функции

- Dashboard — статус защиты, YARA, счётчики
- Quick / Full / Custom / File Scan
- Real-time защита (FileSystemWatcher)
- Карантин (AES-256, restore/delete)
- Настройки: язык, исключения, расписание, **автозапуск**, **самозащита**, обновление сигнатур
- Tray: Open / Exit; автозапуск с `--tray` (в трей без окна)

---

## Деплой (Release)

### Быстрая сборка дистрибутива (~1.1 ГБ)

```powershell
cd TurkmenGuard
publish.bat
```

Результат:
- `dist/TurkmenGuard-v4.5.2/` — готовая папка для пользователя
- `dist/TurkmenGuard-v4.5.2-win-x64.zip` — архив для отправки (не коммитится в git)

> Основной объём — ClamAV engine + CVD (~400 МБ) и `hash-signatures.db` (~95 МБ). Папка `dist/` в `.gitignore`.

### Сброс счётчиков и настроек

```powershell
powershell -ExecutionPolicy Bypass -File tools\reset-user-settings.ps1
```

### Что входит в дистрибутив

| Компонент | Размер (примерно) |
|-----------|-------------------|
| TurkmenGuard.exe + DLL | ~15 МБ |
| ClamAV engine + CVD | ~400 МБ |
| hash-signatures.db | ~95 МБ |
| YARA Rules (23 файла) | ~1 МБ |

**Не копируется:** `UserManual/`, `database/unpacked/`, `clamav-download/` (экономия ~3+ ГБ).

### Git — клонирование (всё для работы уже в репозитории)

```powershell
git clone https://github.com/Zcxczcxcz/TurkmenGuard.git
cd TurkmenGuard
dotnet build TurkmenGuard.sln -c Release
start.bat
```

| В репозитории | Назначение |
|---------------|------------|
| `ThirdParty/ClamAV/` | Движок ClamAV 1.5.3 + CVD сигнатуры |
| `Data/hash-signatures.db` | Hash SQLite fallback (~540k) |
| `Rules/` | 23 YARA правила |
| `backend/` | Спецификация API для backend-команды |

`tools/setup-clamav.ps1` — только если папка ClamAV повреждена.

**Доступ для команды:** владелец добавляет collaborators в GitHub → Settings → Collaborators (см. [docs/DEVELOPERS.md](docs/DEVELOPERS.md)).

---

## Быстрый старт

### Требования

- Windows 7 SP1+ / 10 / 11 x64
- [.NET Framework 4.8](https://dotnet.microsoft.com/download/dotnet-framework/net48)
- [.NET SDK 8+](https://dotnet.microsoft.com/download) — только для сборки

### Сборка и запуск

```powershell
cd TurkmenGuard

# Первый раз: скачать ClamAV engine + CVD базы (~400 MB)
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1

dotnet build TurkmenGuard.sln -c Release
start.bat
```

`start.bat` автоматически запускает `setup-clamav.ps1`, если движок ещё не установлен.

### Принудительная остановка

Если антивирус мешает (трей, автозапуск, самозащита) — двойной клик:

```batch
stop-turkmenguard.bat
```

Скрипт:
1. Завершает `TurkmenGuard.exe` и все процессы ClamAV (`clamscan`, `clamd`, `clamdscan`, `freshclam`)
2. Удаляет автозапуск из реестра `HKCU\...\Run\TurkmenGuard`
3. В `%AppData%\TurkmenGuard\settings.json` отключает: AutoStart, RealTime, SelfProtection, ProcessMonitor

Или из PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File tools\force-stop.ps1
```

Если процессы не завершились — запустите `stop-turkmenguard.bat` **от имени администратора**.

Или:

```powershell
.\src\TurkmenGuard\bin\Release\TurkmenGuard.exe
```

При первом запуске — окно выбора языка (🇹🇲 / 🇷🇺 / 🇬🇧).

### Тесты

```powershell
dotnet run --project tests\TurkmenGuard.Tests\TurkmenGuard.Tests.csproj -c Release
```

Ожидаемо: **17/17 PASS** (EICAR может быть SKIP если Defender блокирует).

### Установка полного ClamAV (обязательно для v4.2)

```powershell
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
```

Скрипт:
1. Скачивает **clamav-1.5.3.win.x64.zip** (~220 MB) с GitHub / clamav.net
2. Распаковывает в `ThirdParty/ClamAV/` (`clamscan`, `clamd`, `clamdscan`, `freshclam`)
3. Скачивает **main.cvd + daily.cvd + bytecode.cvd** через `freshclam` или `cvdupdate`

Если GitHub обрывает загрузку, используйте отдельный скрипт с возобновлением:

```powershell
powershell -ExecutionPolicy Bypass -File tools\download-clamav-zip.ps1
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1 -SkipDatabase
```

> **Важно:** прямой curl/wget для `database.clamav.net` без `?version=` возвращает 403/HTML. Используйте `freshclam` или `cvdupdate`.

### Автозапуск с Windows

В **Настройки → Start with Windows** включается запись в реестр:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TurkmenGuard
"C:\...\TurkmenGuard.exe" --tray
```

- При загрузке Windows приложение стартует **в системном трее** (без главного окна)
- Защита от подмены: `SelfProtectionService` восстанавливает запись реестра, если она удалена
- Двойной клик по иконке трея — открыть главное окно

### Самозащита антивируса

Включена по умолчанию (**Настройки → Self-protection**):

| Механизм | Описание |
|----------|----------|
| Single-instance mutex | Только один экземпляр TurkmenGuard |
| FileSystemWatcher | Мониторинг `Rules/`, `ClamAV/`, настроек, карантина |
| Integrity check | Проверка размера exe, clamscan, settings каждые 5 мин |
| Registry watchdog | Восстановление автозапуска при вмешательстве |
| Priority AboveNormal | Повышенный приоритет процесса при активной защите |

### YARA правила (23 файла, 74 правила)

Категории в `Rules/`:

| Категория | Файлы |
|-----------|-------|
| Credential theft | `credential_theft.yar` |
| Persistence | `persistence_registry.yar`, `persistence_services.yar` |
| Webshells | `webshell_php.yar`, `webshell_asp.yar` |
| Office macros | `macro_office.yar` |
| Crypto miners | `crypto_miner.yar` |
| AMSI bypass | `amsi_bypass.yar` |
| Shellcode / PE | `shellcode_pe.yar`, `packed_pe.yar` |
| RAT / trojan | `trojan_rat.yar` |
| Lateral movement | `lateral_movement.yar` |
| Ransomware | `ransomware_markers.yar`, `ransomware_extended.yar` |
| Info stealers | `info_stealer.yar` |
| LOLBins | `script_dropper.yar`, `lolbin_extended.yar` |
| PowerShell | `powershell_obfuscation.yar`, `downloader_powershell.yar` |
| WMI abuse | `wmi_abuse.yar` |
| Batch scripts | `suspicious_batch.yar` |
| Test | `eicar.yar`, `test_malware.yar` |

Пайплайн: **ClamAV → YARA (74 rules) → Entropy**

### Сборка hash-базы из ClamAV (fallback / dev)

```powershell
pip install cvdupdate
python tools/import-clamav-db.py --download
```

Скрипт:
1. Скачивает `main.cvd` + `daily.cvd` через **cvdupdate** (официальный клиент ClamAV)
2. Распаковывает `.hdb` / `.hsb` (MD5 + SHA256 hash-сигнатуры)
3. Создаёт `Data/hash-signatures.db` (~95 MB, **540 000+** записей)

> **Важно:** curl/wget для database.clamav.net заблокированы (403). Используйте только `cvdupdate` или `freshclam`.

### Сборка hash-базы из JSON (dev/fallback)

```powershell
powershell -ExecutionPolicy Bypass -File tools\build-hash-db.ps1
```

---

## Инструкция пользования

### Первый запуск
1. Запустите `start.bat` или `TurkmenGuard.exe`
2. Выберите язык: Türkmençe / Русский / English
3. На Dashboard — статус YARA и hash-сигнатур

### Сканирование
| Кнопка | Действие |
|--------|----------|
| **Quick Scan** | Downloads, Desktop, Temp, Documents (ClamAV + YARA) |
| **Full Scan** | Все локальные диски (без лимита времени, качество > скорость) |
| **Custom Scan** | Выбранная папка |
| **File Scan** | Один файл (полный ClamAV + YARA) |

**Политика v4.8.x:** Full Scan без лимита по времени — ClamAV ждёт столько, сколько нужно (30 с–5 мин на файл). Пропущенные файлы идут в **retry-очередь** (до 8 раундов, 5 мин/файл). Quick Scan остаётся быстрым (2–3 с). В UI: прошедшее `H:MM:SS` / `MM:SS` и оценка `~N ч M мин осталось` при длинном скане.

### Защита в реальном времени
Вкладка **Goragçylyk / Protection** — включить/выключить FileSystemWatcher.

### Карантин
Вкладка **Karantin** — восстановить или удалить навсегда.

### Настройки
- Язык, тема, расписание сканов
- Исключения (папки + расширения) — только то, что вы добавите вручную
- **Обновление сигнатур**: еженедельно / вручную, URL backend, кнопка «Обновить сейчас»
- Журнал приложения

### Выход
- Меню tray → **Exit**
- Кнопка Exit в настройках
- **Ctrl+Q** — выход без подтверждения (по умолчанию)

---

## Архитектура сканирования

```
Файл ≤ 8 МБ  → ClamAV INSTREAM → YARA (по режиму)
Файл > 8 МБ  → LargeFileScanner:
                 PE header + section samples + overlay
                 head/tail edges (non-PE)
                 ZIP/SFX → извлечь .exe/.dll/.js… → ClamAV/YARA
File Scan    → опционально полный ClamAV до 256 МБ, затем large-path
```

Гигабайтные приложения не гоняются целиком через ClamAV — проверяются места посадки вредоноса (overlay, края, вложенные PE).

### ClamAV как основной движок (v4.2)

- Встроенный portable **ClamAV 1.5.3 x64** в `ThirdParty/ClamAV/`
- Демон **clamd** + **clamdscan** для быстрого сканирования (TCP 127.0.0.1:3310)
- Fallback на **clamscan.exe** если демон не стартует
- Полные CVD: `main.cvd`, `daily.cvd`, `bytecode.cvd` — все типы сигнатур
- Обновление CVD: `freshclam` при обновлении сигнатур из настроек

### ClamAV hash SQLite (fallback)

Встроенная база `Data/hash-signatures.db` (v4.1):
- **540 326** hash-сигнатур (MD5 + SHA256)
- Используется только когда portable ClamAV не установлен

### Снижение ложных срабатываний (v4.0)

- **Extension allow-list** — сканируются только исполняемые, скрипты, архивы, Office
- **Packed_PE / UPX** — severity `Info`, не попадает в угрозы
- **Entropy** — только PE, анализ по секциям, порог **7.95** (не 7.8 по всему файлу)
- **Auto-quarantine** — только `High+` (не Medium/Low/Test/Info)

---

## Обновление сигнатур (единственная сеть)

Backend хранит и отдаёт:
- `manifest.json` — версия, URL hash DB, SHA-256, URL rules zip
- `hash-signatures.db` — SQLite до ~1M SHA-256
- `rules-pack.zip` — YARA правила

Пример manifest: `backend/manifest.sample.json`

Клиент: `Services/SignatureUpdateService.cs`
- Проверка при старте (опционально)
- Автораз в неделю (`SignatureUpdateSchedule = weekly`)
- Ручное обновление в Settings

Настройки в `%AppData%/TurkmenGuard/settings.json`:

```json
{
  "SignatureUpdatesEnabled": true,
  "SignatureUpdateSchedule": "weekly",
  "SignatureUpdateEndpoint": "https://signatures.turkmenguard.local/v1/manifest.json",
  "CheckUpdatesOnStartup": true,
  "LastSignatureVersion": null,
  "LastSignatureUpdate": null
}
```

---

## Структура проекта

```
TurkmenGuard/
├── TurkmenGuard.sln
├── README.md
├── screenshot-main.png
├── start.bat / publish.bat
├── backend/
│   └── manifest.sample.json      # Пример API backend
├── Data/
│   ├── hash-signatures.json      # Fallback / dev
│   └── hash-signatures.db        # ClamAV SQLite (~540k, ~95 MB)
├── Rules/                        # 6 YARA правил
├── tools/
│   ├── setup-clamav.ps1          # ClamAV engine + CVD setup (v4.2)
│   ├── force-stop.ps1            # Force stop all AV processes
│   ├── download-clamav-zip.ps1   # Resumable engine zip download
│   ├── import-clamav-db.py       # ClamAV CVD → SQLite (fallback)
│   ├── build-hash-db.ps1         # JSON → SQLite (dev)
│   └── capture.py
├── ThirdParty/
│   └── ClamAV/                   # Portable ClamAV 1.5.3 + CVD (в git)
├── docs/
│   └── DEVELOPERS.md             # Онбординг для команды
├── src/TurkmenGuard/
│   ├── Core/
│   │   ├── ScannerEngine.cs
│   │   ├── ClamAvEngine.cs       # clamd + clamdscan (v4.2)
│   │   ├── YaraScanner.cs        # libyara.NET
│   │   ├── HashChecker.cs
│   │   ├── HashDatabase.cs       # SQLite O(1) lookup
│   │   ├── EntropyAnalyzer.cs
│   │   ├── ScanPolicy.cs
│   │   └── ScanModels.cs
│   ├── Services/
│   │   ├── SignatureUpdateService.cs
│   │   ├── AppSettings.cs
│   │   └── ...
│   ├── Monitoring/               # RealTimeGuard, ProcessMonitor
│   ├── Quarantine/
│   ├── Security/                 # Single-instance only
│   ├── ViewModels/ + Views/
│   ├── Themes/Colors.xaml
│   └── Localization/             # tk / ru / en
└── tests/TurkmenGuard.Tests/
```

---

## Библиотеки (NuGet)

| Пакет | Версия | Назначение |
|-------|--------|------------|
| **MaterialDesignThemes** | 5.1.0 | UI Material Design 3 |
| **MaterialDesignColors** | 3.1.0 | Палитры |
| **Microsoft.O365.Security.Native.libyara.NET** | 4.5.5 | YARA движок (.NET Framework 4.8) |
| **CommunityToolkit.Mvvm** | 8.2.2 | MVVM |
| **System.Data.SQLite.Core** | 1.0.118 | Hash DB SQLite |
| **System.Text.Json** | 8.0.5 | settings.json, manifest |
| **System.Management** | 8.0.0 | WMI ProcessMonitor |

| **cvdupdate** (Python) | 1.2+ | Скачивание ClamAV CVD (dev/build) |
| **ClamAV** (bundled) | 1.5.3 | Полный движок libclamav (portable x64) |

---

## Пути на диске

| Назначение | Путь |
|------------|------|
| Настройки | `%AppData%/TurkmenGuard/settings.json` |
| ClamAV engine | `{exe}/ClamAV/` (clamscan, clamd, clamdscan) |
| ClamAV CVD DB | `{exe}/ClamAV/database/*.cvd` |
| ClamAV logs | `%AppData%/TurkmenGuard/clamav/` |
| Hash DB (runtime) | `%AppData%/TurkmenGuard/hash-signatures.db` |
| Логи | `%AppData%/TurkmenGuard/logs/` |
| Карантин | `%ProgramData%/TurkmenGuard/Quarantine/` |
| YARA rules | `{exe}/Rules/` |
| Встроенная DB | `{exe}/Data/hash-signatures.db` |

---

## История изменений (Changelog)

### v4.8.1 (2026-07-16) — scan-all policy, unified threats, process kill + quarantine
**Главная цель:** не терять угрозы и не пропускать файлы даже при таймаутах.

**Что изменено:**
- **Scan-all policy:** убраны пользовательские исключения и extension skip-листы; все файлы идут в пайплайн сканера (кроме действительно недоступных OS-locked файлов типа `pagefile.sys`)
- **Unified Threat Feed:** все угрозы (Quick/Full/Custom/File/Real-time/Process monitor) попадают в общий раздел **All threats** на странице Scan
- **Process hard response:** для `Dangerous/Malware` из ProcessMonitor добавлен kill процесса + попытка карантина файла
- **Auto quarantine не обязателен:** process-угрозы `Dangerous+` теперь уходят в карантин даже если global AutoQuarantine выключен
- **Retry после timeout:** таймаутные файлы ставятся в повторную очередь с увеличением времени обработки (экспоненциальный backoff до 10 минут)
- **Производительность:** увеличена параллельность Quick/Batch; Full scan получил adaptive 2–4 worker режима при здоровом clamd
- **Quick Scan coverage расширен:** добавлены AppData/Temp/Program Files/CommonApplicationData + Startup paths

**Важно:**
- Самозащита движка сохранена: собственные бинарники/базы не удаляются и не карантинятся.
- Если файл заблокирован во время первой попытки, он не теряется — переходит в retry-проход.

### Hotfix (2026-07-16) — окно не открывалось после UI-оптимизации
**Проблема:** после переноса стилей в `App.xaml` процесс запускался (трей/ClamAV), но главное окно не появлялось.

**Причина:** из `MergedDictionaries` убрали `Themes/Styles.xaml` и `Themes/Animations.xaml`, а ресурсы `TgStatValue` (StatCard) и `TgPulseLoader` (Dashboard) не перенесли. `XamlParseException` глотался в `DispatcherUnhandledException` → «невидимый» процесс.

**Исправление:**
- Вернули merge `Themes/Animations.xaml`
- Добавили алиас `TgStatValue` → `TgStatNumber` в `App.xaml`
- `CardCornerRadius` → `sys:Double` (для `UniformCornerRadius`)
- `CardPadding` → `Thickness` (для `Padding`)
- Ошибки создания MainWindow больше не оставляют процесс без UI (try/catch + не глотать исключения до готовности окна)

### v4.8.0 (2026-07-15) — Full Scan: качество без тайм-лимитов + ETA в часах
**Проблема:** лог забивался `INSTREAM slow/connect (streak=1)` — ClamAV скипал файлы из‑за коротких таймаутов (1.5–3.5 с) и «overload shrink».

**Решение:**
- **Full Scan quality mode:** таймауты 30 с–5 мин по размеру файла; без урезания maxBytes при streak
- **clamd:** ReadTimeout 300 с, CommandReadTimeout 120 с; Full идёт **последовательно** (1 воркер)
- **Retry-очередь:** до **8 раундов**, 5 мин/файл — пропущенные ставятся заново, пока не проверятся
- **Quick Scan** без изменений — 2–3 с на файл
- **UI:** прошедшее `H:MM:SS` при >1 ч; ETA `~2 ч 15 мин` / `~45 мин`

**Инструкция:** полностью перезапустите TurkmenGuard (clamd.conf перезапишется при старте).

### v4.8.0 (2026-07-15) — полная модернизация
- **Сканирование**: `LastScanSkipped` вместо ложного OK; `StreamMaxLength` 256M; entropy-gate → YARA на Full Scan; hash fallback в Quick; `clamscan` fallback при мёртвом daemon; mid-sample для large non-PE; rush archive 1 entry
- **Real-time**: очередь 128 с coalesce вместо drop/skip при bulk scan
- **Безопасность**: HTTPS-only обновления; restore path validation; reparse-point skip; log redaction
- **UI**: design system (`Themes/Styles.xaml`, `Animations.xaml`, `Controls/StatCard`); Dashboard SOC; PackIcon навигация
- **Производительность**: lazy YARA init; DataGrid virtualization
- **Hotfix start.bat**: `Brush` ambiguity (WPF vs Drawing); `CardCornerRadius` → double для `UniformCornerRadius`; `CardPadding` → Thickness

### v4.7.9 (2026-07-15) — Full без жёсткого лимита, таймер в UI
- Убран **принудительный стоп** через 30 мин — скан идёт до конца
- В прогрессе: **MM:SS** с начала + мягкая **«~N мин осталось»** (оценка по скорости, не дедлайн)
- Сохранены: retry ClamAV, YARA на PE timeout, ускорение (дедуп, skip кэшей, 3 воркера)

### v4.7.8 (2026-07-15) — Full Scan ~30 мин + retry ClamAV + меньше skip-троянов
**Проблема:** Full шёл часами; редкий ClamAV timeout на `.exe` = дыра без YARA.

**Решение:**
- **Бюджет 30 мин:** основной проход 27 мин → retry ClamAV 3 мин → корректное завершение
- **Retry-очередь:** файлы с timeout пересканируются в конце (1 поток, 20 с)
- **YARA при timeout** на PE (`.exe`/`.dll`/`.msi` …) до 16 МБ
- **Счётчик** `ClamAV incomplete` в UI + сообщение при лимите времени
- **Скорость:** дедуп путей, 3 воркера, skip кэшей/Fonts/DriverStore/Packages/тестов bin
- **Rush mode** (&lt;8 мин): меньшие LargeFile-срезы, без распаковки архивов

**Инструкция:** после обновления полностью перезапустите TurkmenGuard.

### v4.7.7 (2026-07-15) — ClamAV: стабильный INSTREAM под Full (installers)
**Проблема после 4.7.6:** на больших установщиках (Notion, NDP, MSI…) снова `streak=1` / overload.

**Причина:** LargeFile слал срезы по **4 МБ** с таймаутом **3 с** + 3 параллельных воркера → clamd не успевал; мелкие файлы успевали (streak сбрасывался в 0) → вечный `streak=1`. Пул IDSESSION под нагрузкой тоже давал сбои.

**Исправление:**
- Один TCP = один `zINSTREAM` (без пула/IDSESSION) — как в официальном протоколе
- Таймаут масштабируется по размеру (до 20 с на multi‑MB)
- Full: края **1 МБ**, max **2** секции PE; параллелизм **2**
- LargeFile region timeout Full = **8 с**

**Важно:** полностью закройте TurkmenGuard и запустите `bin\Release\TurkmenGuard.exe` заново.

### v4.7.6 (2026-07-15) — фикс ClamAV INSTREAM (пул сокетов) + скорость Full
**Проблема:** лог забивался `INSTREAM slow/timeout (streak=1)`, ClamAV почти не сканировал файлы.

**Причина:** в v4.7.4 сокеты после обычного `zINSTREAM` клались в пул и переиспользовались. У clamd без `IDSESSION` это **невалидно** → пустой ответ/таймаут → «успех» на новом connect сбрасывал streak → снова `streak=1`.

**Исправление:**
- Пул на **`zIDSESSION`**: одно TCP-соединение → много `zINSTREAM`, закрытие через `zEND`
- Проверка half-closed сокетов перед reuse; битые сессии выбрасываются
- Ожидание слота gate **не** считается timeout clamd (нет ложного streak)
- Парсинг ответов вида `1: stream: OK` / `1: stream: Trojan FOUND`

**Скорость Full (без урезания покрытия):**
- До **3** параллельных IDSESSION-воркеров (стабильно, без flood)
- Буферы TCP 256 КБ; clamd MaxQueue 200, ReadTimeout 20
- Реальные сканы вместо секундных timeout-пропусков — главный прирост

**Важно:** полностью закройте TurkmenGuard и запустите снова (clamd перечитает conf).

### v4.7.5 (2026-07-15) — группы риска в результатах скана
**Проблема:** Full Scan показывал ~130 «угроз», в основном Rules/.yar и скрипты самого антивируса.

**Решение (баланс без тупого whitelist):**
- Результаты делятся на **4 группы**: Вредонос / Опасные / Подозрительные / Низкий риск
- Сводка сверху: `Вредонос: N · Опасные: …`
- `.yar`/CVD и папки `TurkmenGuard\Rules|tools|tests` не считаются malware
- Автокарантин только для групп Malware/Dangerous

### v4.7.4 (2026-07-15) — ускорение самого процесса скана (без урезания покрытия)
**Проблема:** на каждый файл открывалось новое TCP-соединение к clamd (~сотни мс) — скан был медленным при любом числе файлов.

**Решение:**
- **Пул постоянных сокетов** к clamd — один connect, много zINSTREAM
- До **4** параллельных сканов файла + clamd MaxThreads **8**
- SequentialScan / буфер 256 КБ при чтении файла
- Откат лишних пропусков путей/PDF-лимитов из 4.7.3 — покрытие как раньше
- Приоритет рискованных папок (порядок, не пропуск) сохранён

### v4.7.3 (2026-07-15) — ускорение Full Scan без потери покрытия
**Скорость (качество детекции сохранено):**
- Full: **приоритет** Downloads/Desktop/Documents/Startup/Program Files/Temp, затем диски (без повторного обхода)
- Адаптивный параллелизм **1–2** INSTREAM (падает до 1 при TimeoutStreak≥6)
- clamd MaxThreads **4**, TCP gate **2**
- LargeFile на Full: 1 секция + меньшие edges (1 МБ) — те же зоны посадки, меньше round-trip’ов
- Техпропуски: Fonts/Speech/Help/Package Cache/$Windows.~BT/.vs/INetCache (не Program Files)
- PDF/DOC/XLS/PPT на Full ≤2 МБ (макросы .docm/.xlsm без лимита по этому фильтру)
- Меньше CleanupScratch и CanOpen-проб на Full

Trojan/Worm/Virus/Ransom по-прежнему не фильтруются; LargeFile/structural path без изменений по задумке.

### v4.7.2 (2026-07-15) — LargeFileScanner для гигабайтных приложений
- Файлы **> 8 МБ** больше не игнорируются и не гоняются целиком через INSTREAM
- **PE:** заголовок, сэмплы секций, overlay (head/tail если overlay огромный)
- **Non-PE:** первые и последние 4 МБ
- **ZIP/SFX:** извлечение исполняемых вложений во scratch → ClamAV + YARA
- **File Scan:** structural first, затем опционально полный ClamAV до **256 МБ**; любой выбранный файл сканируется
- ClamAV `ScanBytes` + YARA `ScanMemory` для срезов
- **TrustedPaths:** только движок (exe/dll/ClamAV/Data/Rules/AppData), не вся папка установки
- Интеграционные тесты: **21/21 PASS**
- `pagefile`/`hiberfil` по-прежнему пропускаются по имени

### v4.7.1 (2026-07-15) — таймауты ClamAV + ускорение Full Scan
**Что значит `INSTREAM slow/timeout`:** демон clamd **жив**, но этот файл не успел провериться (очередь/тяжёлый файл). Скан не останавливается — файл пропускается для ClamAV; при маленьком размере подключается YARA.

**Исправления скорости Full:**
- Таймаут Full 1.2–3 с (раньше до 20 с на файл)
- Лимит ClamAV 8 МБ (не 25 МБ); архивы ≤2 МБ; ISO не сканируются на Full
- Full **последовательно** (2 параллельных INSTREAM перегружали clamd → streak=25)
- YARA на Full только для скриптов / реального timeout / SingleFile — **не** на каждый DLL ≤2 МБ
- Oversized файлы больше не считаются «timeout»
- При streak≥8 clamd автоматически уменьшает размер/таймаут, пока не восстановится
- Пропуск: SoftwareDistribution, Prefetch, node_modules, .git

**Важно:** полностью перезапустите TurkmenGuard (clamd.conf переписывается при старте).

### v4.7.0 (2026-07-15) — полное системное сканирование без белых списков ПО
**Политика:**
- Убраны whitelist’ы Chrome/Steam/VS Code/chocolatey/Program Files/Windows
- Full Scan снова идёт по всей системе (диски), включая Program Files
- Автоисключения `C:\Windows` + Program Files из settings **снимаются** при загрузке

**Скорость (без потери троянов/червей):**
- ClamAV INSTREAM — основной детектор known malware
- YARA на Full — скрипты / timeout / SingleFile
- Технические пропуски: WinSxS, Installer, pagefile/hiberfil, GPUCache

**FP:** PUA/Adware по-прежнему режутся; Trojan/Worm/Virus/Ransom **никогда** не фильтруются как шум  
**Свой процесс** (bin + AppData TurkmenGuard + ClamAV) — единственный «trust», чтобы не карантинировать себя

### v4.6.8 (2026-07-15) — покрытие скана + тестовые вирусы
- **Почему 500k → 70k:** раньше в счёт шли extensionless/кэши (LOCK, Steam htmlcache…); это не «больше защиты», а шум. Сейчас считаются реальные кандидаты
- **Почему 0 угроз:** Quick после чистого ClamAV **не вызывал YARA** — кастомный `TURKMENGUARD_TEST_VIRUS` и часть EICAR-.txt не ловились
- Quick снова: **ClamAV INSTREAM + YARA** (оба слоя)
- Full: снова сканирует unknown/.txt(≤4KB)/мелкие extensionless; тестовые сэмплы в папке проекта больше не в TrustedPaths
- ClamAV daemon **работает на Windows** (zINSTREAM) — это не Linux-only
- Сохранены: UI без зависаний, INSTREAM скорость, FP-фильтры, AUMID, живая Защита

### v4.6.7 (2026-07-15) — ClamAV INSTREAM (быстрый Quick)
- **Корень тормозов:** команда `nSCAN` на Windows зависает; PING работал, сканы — нет
- Переход на **`zINSTREAM`** (байты файла в clamd) — ~30 мс на мелкий файл вместо таймаутов
- Quick: таймаут 3с, файлы > 8 МБ → лёгкий YARA; после 8 таймаутов — авто-fallback на YARA
- Полностью закрой старый процесс перед стартом (иначе clamd остаётся «заклиненным»)

### v4.6.6 (2026-07-15) — Quick Scan скорость (ClamAV TCP)
- **Причина тормозов:** на каждый файл запускался `clamdscan.exe` с таймаутом 20с → десятки минут
- Теперь сканирование через **TCP `nSCAN` к clamd** (без нового процесса на файл)
- Quick: таймаут 6с, файлы > 12 МБ пропускаются, параллелизм 2
- clamd.conf: MaxFileSize 25M / MaxThreads 4
- Advisory Shellcode в логах до 10:57 — старый скан; в 4.6.5 правило уже отключено

### v4.6.5 (2026-07-15) — ClamAV daemon + AUMID + строгие YARA
- **Почему только YARA:** `clamd.conf` писался с UTF-8 BOM → ClamAV не читал конфиг → `daemon=False`, работали только YARA/hash
- Конфиги ClamAV теперь **без BOM**, `Foreground yes`, всегда перезаписываются при старте
- **Уведомления:** `AppUserModelID=TurkmenGuard.Desktop` + бренд `Turkmen Guard` (вместо «notifyicon generated aumid»)
- **YARA ужесточены:** webshell/AMSI/ransomware требуют реальные маркеры; `shellcode_pe.yar` отключён (ложные PE)
- Пропуск: extensionless/LevelDB/Steam/Chrome/chocolatey caches
- `Hash check failed` на locked-файлах больше не спамит WARN (это нормально — файл занят)

### v4.6.4 (2026-07-15) — меньше FP, короткие уведомления, живая Защита
- **Ложные срабатывания (до v4.7.0):** раньше TrustedPaths включал IDE/расширения; с 4.7.0 — только свой install/AppData/ClamAV
- DetectionFilter: packer/PUA/adware noise + эвристики Obfuscat/Encoded только для Single File
- **Уведомления:** заголовок всегда `TurkmenGuard`, короткий текст без длинных имён сигнатур
- **Раздел Защита:** пульс, счётчики (папки/файлы/процессы/блокировки), лента «Процесс · … / ОК · …»
- Включение защиты автоматически запускает мониторинг процессов (раньше UI был «мёртвым»)

### v4.6.3 (2026-07-15) — Full Scan застревал на одном файле
- **Реальная причина (не UI):** Full Scan начинал с `C:\hiberfil.sys` / `pagefile.sys` → YARA/hash зависали на multi‑GB locked файлах
- Пропуск volume-файлов: `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `dumpstack.log*`
- Лимит размера: YARA ≤ 32 МБ, hash ≤ 64 МБ; locked-файлы пропускаются до скана
- **ClamAV daemon:** `Foreground yes` (раньше `Foreground no` → процесс «выходил» и демон считался мёртвым)
- UI: фаза «Сбор файлов…», прогресс обновляется чаще
- YARA: исправлен `persistence_registry.yar` (unused `$hidden` ломал компиляцию правила)

### v4.6.2 (2026-07-15) — белый экран при сканировании
- **Причина:** Quick/Full/Custom scan выполнялись на UI-потоке WPF (`Task.Yield` возвращал управление обратно в UI → зависание и белый экран)
- **Исправление:** `RunScanAsync` / `ExecuteLockedScanAsync` / scheduled scan всегда на thread pool (`Task.Run`)
- Вместо `Task.Yield()` — `HopToThreadPoolAsync()` (не возвращает на WPF SynchronizationContext)
- UI: сразу «Запуск сканирования…», перехват ошибок скана (`ScanError`), безопасный `Dispatcher` для результатов
- `App`: обработчики `DispatcherUnhandledException` / unobserved tasks — окно не падает в белый экран
- Локализация: `ScanStarting`, `ScanError` (en/ru/tk)

### v4.6.1 (2026-07-14) — исправлено сканирование
- **Quick Scan** — параллельное сканирование батчами по 48 файлов (раньше создавалось 10k+ Task → зависание)
- **Quick Scan** — прогресс во время перечисления файлов (Desktop/Downloads больше не «молчит» минутами)
- **Quick Scan без clamd** — только YARA, последовательно (hash на 10k+ файлов убран)
- **Quick Scan с clamd** — параллельно батчами по 48 файлов
- **Single File без clamd** — YARA → hash, без медленного clamscan
- Убран лишний `Task.Run` в `ScanFileAsync` (deadlock thread pool)

### v4.6.0 (2026-07-14) — стабилизация: все обещанные фичи в коде
- **Отмена скана** — мгновенное убийство активного `clamscan`/`clamdscan` (`CancelActiveScan`)
- **Custom/File scan** — через `ExecuteLockedScanAsync` + `_scanLock` (не конфликтуют с Full/Quick)
- **BulkScanSession** — корректный `EnterBulkScan()` при создании
- **Real-time** — файлы из очереди не теряются во время bulk scan (re-enqueue)
- **Real-time Restart()** — папки мониторинга применяются после сохранения настроек
- **ProcessMonitor** — все угрозы обрабатываются; работает **независимо** от Real-time
- **Планировщик** — первый scheduled scan запускается при `LastScheduledScan == null`
- **Manual vs Scheduled** — `LastManualScan` / `LastScheduledScan` разделены
- **Исключения** — Windows/Program Files добавляются только при первом запуске, не каждый Load
- **Dashboard** — обновляется после ручного скана
- **Темы** — `DynamicResource` для всех theme-brush во Views
- **SignatureUpdateService.Restart()** — применяет настройки обновлений без перезапуска
- **Quick Scan** — YARA fallback если ClamAV daemon недоступен
- **Entropy** убран из Full Scan (всё равно фильтровался — лишняя нагрузка)
- **SettingsViewModel** — defaults совпадают с `AppSettings` (AutoQuarantine off, PM off)

### v4.5.3 (2026-07-14) — Full Scan не морозит UI
- **Full Scan** — потоковое перечисление файлов (без `.ToList()` на весь диск)
- **Пропуск папок** на уровне каталогов (`Windows`, `$Recycle.Bin`, исключения) — не обходим миллионы файлов впустую
- **`ConfigureAwait(false)`** в движке сканирования — работа не блокирует UI-поток WPF
- Прогресс Full Scan обновляется во время обхода; сохранение settings в фоне
- UI: `DispatcherPriority.Background` для прогресса и результатов

### v4.5.2 (2026-07-14) — мягкие YARA, только реальные угрозы
- **YARA v4.5.2 strict** — правила требуют 2–4 индикатора вместе (не один `powershell` или `Quasar`)
- Отключены шумные `lateral_movement` (файл `.yar.disabled`)
- Macro/LOLBin/Persist/Stealer/Miner/RAT — переписаны под реальные цепочки атак
- Quick Scan — ClamAV only; Full/SingleFile — строгий YARA

### v4.5.1 (2026-07-14) — ложные срабатывания, скорость Quick Scan, RT+процессы
- **Quick Scan** — только ClamAV (без YARA); YARA остаётся в Full и «Скан файла»
- **Quick Scan быстрее** — убран `%TEMP%`, архивы/DLL/PDF пропускаются, 3 параллельных потока
- **YARA heuristics** (LOLBin, Macro, PS_Downloader…) — severity Medium; в Full только Critical
- **Real-time** — при включении автоматически стартует **мониторинг процессов** (новые .exe)
- ProcessMonitor: интервал 5 с (было 10)

### v4.5.0 (2026-07-14) — деплой + GitHub
- **GitHub:** https://github.com/Zcxczcxcz/TurkmenGuard — ClamAV engine + CVD + hash DB + YARA в репозитории
- **docs/DEVELOPERS.md** — онбординг для frontend/backend команды
- **backend/README.md** — спецификация API сигнатур
- **publish.bat** + `tools/publish-release.ps1` — дистрибутив ~1.1 ГБ
- **DetectionFilter v2** — PUA/PUP/Adware → Info, Quick/Full/RealTime только **High+**
- Исключения: `node_modules`, `.git`, WinSxS, AppData\Local\Programs
- Счётчики сброшены, defaults: RealTime/ProcessMonitor/AutoQuarantine **off**
- `tools/reset-user-settings.ps1` — сброс `%AppData%\TurkmenGuard\settings.json`
- csproj: не копировать `unpacked/`, `UserManual/`, `clamav-download/`
- `.gitignore`: `dist/`, pdb/lib ClamAV; runtime engine в git
- **SelfProtectionService** — без NRE в headless-тестах

### v4.4.1 (2026-07-14) — ложные срабатывания, стоп, темы
- **DetectionFilter** — в Quick/Full скане скрыты PUA/PUP/Heuristics, entropy и Medium; только High+
- **Исключения по умолчанию**: `C:\Windows`, `Program Files`, `Program Files (x86)`
- Entropy только при **Full Scan** (не Quick)
- Hash DB fallback только для **High+** сигнатур
- **Кнопка «Отмена»** — исправлен CanExecute (была отключена во время скана)
- **Планировщик** — не перезапускает скан каждый час при `LastScheduledScan == null`
- **Темы** — `DynamicResource` в MainWindow + обновление CardHover при смене темы
- AutoQuarantine **выключен** по умолчанию
- Счётчик угроз на Dashboard — только High+ (не PUA-шум)

### v4.4.0 (2026-07-14) — аудит: стабильность + производительность
**Фаза 1 — критические исправления:**
- **ClamAV pipe-deadlock** — `BeginOutputReadLine`/`BeginErrorReadLine`, гарантированный `Kill()` по таймауту
- **Дедлок авто-карантина** — `QuarantineChanged` вне `lock`, `BeginInvoke` в UI
- **Самозащита** — приоритет `Normal`, убран watcher на `AppData`/логи, throttle tamper-уведомлений
- **ProcessMonitor** — dispose всех `Process`/WMI, guard реентерабельности
- **Logger** — буферизованный `StreamWriter`, ротация 10 МБ / 14 дней
- **ClamAV daemon** — health-check каждые 60с + auto-restart; bulk/realtime без per-file `clamscan` (YARA+hash fallback)

**Фаза 2 — HIGH/MEDIUM:**
- Zip Slip защита при распаковке правил
- Hash DB: закрытие SQLite перед `File.Copy`
- Race fixes в `ScannerEngine` (`Interlocked`, `_ctsLock`)
- RealTimeGuard: исправлен инвертированный фильтр (`||`), очистка `_debounce`
- HashDatabase TOCTOU, UI marshalling для tray, отписка событий трея

**Фаза 3 — полировка:**
- Карантин: ключ через **DPAPI** (`ProtectedData`), транзакционность, restore без перезаписи
- Entropy `Log2` cache, quoted `explorer.exe` path

**Тесты:** 16/16 PASS (EICAR — skip если Defender удалил файл)

### v4.3.1 (2026-07-13)
- **stop-turkmenguard.bat** — принудительная остановка всех процессов и отключение автозапуска/самозащиты
- `tools/force-stop.ps1` — PowerShell-логика force stop
- **force-stop v2** — `taskkill /F /T` (дерево процессов), 3 прохода, поиск по пути `ClamAV`, авто-запрос прав администратора в `.bat`, настройки/реестр отключаются **до** kill
- **Исправлено зависание** при одновременном скане и real-time защите
- Один `clamscan` за раз (глобальный семафор) — ноут больше не «умирает»
- Real-time: очередь вместо сотен параллельных Task; пауза во время bulk-скана
- UI: `BeginInvoke` + троттлинг прогресса (не блокирует интерфейс)
- ClamAV: приоритет BelowNormal, таймаут 30с для real-time

### v4.3.0 (2026-07-13)
- **YARA rule pack расширен**: 6 → **23 файла**, **74 скомпилированных правила**
- Новые категории: credential theft, persistence, webshells, macros, miners, AMSI bypass, RAT, lateral movement, stealers, WMI, LOLBins
- **Автозапуск**: `--tray` в реестре, старт в системном трее, `SyncEnabled()` / `IsRegistryCorrect()`
- **Самозащита**: FileSystemWatcher, integrity check, registry watchdog, priority AboveNormal
- Расширенная карта severity в `YaraScanner` (Critical для RAT/webshell/AMSI)
- Тесты: **17/17 PASS** (YARA heuristics, autostart, self-protection)
- Локализация: уведомления о tamper (en/ru/tk)

### v4.2.0 (2026-07-13)
- **Полный ClamAV engine**: portable 1.5.3 x64 (`clamscan`, `clamd`, `clamdscan`, `freshclam`)
- `Core/ClamAvEngine.cs` — демон clamd + clamdscan, fallback clamscan
- Пайплайн: **ClamAV → YARA → Entropy** (hash SQLite только как fallback)
- `tools/setup-clamav.ps1` — автоматическая установка engine + CVD
- `tools/download-clamav-zip.ps1` — докачка zip с GitHub/clamav.net (curl `-C -`, проверка CRC zip)
- `setup-clamav.ps1`: сохранение `database/` при распаковке; исправлен вызов `cvdupdate`; точный размер zip 229959640 байт
- `SignatureUpdateService` — обновление CVD через `freshclam`
- Dashboard: статус ClamAV (версия, БД, демон)
- `DetectionMethod.ClamAV` в моделях сканирования

### v4.1.0 (2026-07-13)
- **ClamAV hash database**: 540 326 сигнатур (main.cvd + daily.cvd) встроены в `Data/hash-signatures.db`
- MD5 + SHA256 lookup с проверкой размера файла
- `tools/import-clamav-db.py` — пайплайн сборки через cvdupdate
- Dashboard показывает источник ClamAV и количество сигнатур
- Тесты: проверка загрузки DB > 100k записей

### v4.0.0 (2026-07-13)
- **Миграция на .NET Framework 4.8** — поддержка Windows 7 SP1+
- **libyara.NET** вместо YaraXSharp (net8-only)
- **SQLite hash database** — `HashDatabase.cs`, встроенная + обновляемая база
- **SignatureUpdateService** — единственный сетевой модуль (weekly/manual)
- **False positives**: entropy 7.95 per PE section, packer rules → Info, auto-quarantine High+
- **Self-protection**: только single-instance, нормальный выход
- Исправлена сборка libyara для WPF temp projects
- Локализация блока обновления сигнатур (tk/ru/en)
- `tools/build-hash-db.ps1`, `backend/manifest.sample.json`

### v3.4.0 (2026-07-12)
- File Scan, tray menu, log viewer

### v3.0.0 (2026-07-12)
- WPF перезапуск, YARA rules, ScannerEngine

---

## Лицензия

Проект в **образовательных целях**. EICAR — тестовый файл, не вредонос.
