# TurkmenGuard (Türkmen Goragçy) v4.5.0

**Автономный антивирус для Windows 7 SP1+ / 10 / 11 (x64)**  
Офлайн-сканирование локально. Сеть — **только** для обновления сигнатур (раз в неделю или вручную).

---

## Что это

**TurkmenGuard** — desktop WPF-антивирус с тёмным минималистичным интерфейсом (тёмно-синий + зелёный акцент). Türkmençe — основной язык, также Русский и English.

| Параметр | Значение |
|----------|----------|
| Платформа | **.NET Framework 4.8** (`net48`) — совместимость с Windows 7 |
| UI | WPF + Material Design 3, корпоративная тёмная тема |
| Движок | **ClamAV 1.5.3** (полный libclamav) → YARA → Entropy (PE, 7.95) |
| Hash fallback | SQLite 540k+ (если ClamAV engine не установлен) |
| Сеть | `SignatureUpdateService` + `freshclam` для CVD |
| Версия | **4.5.0** |

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
- `dist/TurkmenGuard-v4.5.0/` — готовая папка для пользователя
- `dist/TurkmenGuard-v4.5.0-win-x64.zip` — архив для отправки (не коммитится в git)

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

### Git — исходники и релиз

**В репозитории:** исходный код, YARA rules, `Data/hash-signatures.db`, скрипты.  
**Не в git:** `dist/`, `ThirdParty/ClamAV/` (скачивается `setup-clamav.ps1`).

```powershell
# Клонирование
git clone https://github.com/<user>/TurkmenGuard.git
cd TurkmenGuard
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
dotnet build TurkmenGuard.sln -c Release
publish.bat
```

**Публикация на GitHub (для разработчика):**

```powershell
gh auth login
powershell -ExecutionPolicy Bypass -File tools\push-github.ps1
```

Или вручную:

```powershell
gh repo create TurkmenGuard --public --source=. --remote=origin --push
gh release create v4.5.0 dist\TurkmenGuard-v4.5.0-win-x64.zip --title "TurkmenGuard v4.5.0"
```

ClamAV (~400 МБ) скачивается скриптом `setup-clamav.ps1`, не хранится в git.

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
| **Quick Scan** | Downloads, Desktop, Temp, Documents |
| **Full Scan** | Все локальные диски |
| **Custom Scan** | Выбранная папка |
| **File Scan** | Один файл |

### Защита в реальном времени
Вкладка **Goragçylyk / Protection** — включить/выключить FileSystemWatcher.

### Карантин
Вкладка **Karantin** — восстановить или удалить навсегда.

### Настройки
- Язык, тема, расписание сканов
- Исключения (папки + расширения)
- **Обновление сигнатур**: еженедельно / вручную, URL backend, кнопка «Обновить сейчас»
- Журнал приложения

### Выход
- Меню tray → **Exit**
- Кнопка Exit в настройках
- **Ctrl+Q** — выход без подтверждения (по умолчанию)

---

## Архитектура сканирования

```
Файл → exclusions + extension filter
     → ClamAV engine (libclamav: .ndb, .ldb, .hdb, .hsb, bytecode)
     → YARA (libyara.NET, 6 rule files)
     → Entropy (только PE .exe/.dll, per-section, порог 7.95)
```

Если ClamAV engine недоступен — автоматический fallback на SQLite hash (540k сигнатур).

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
│   └── ClamAV/                   # Portable engine (не в git, setup script)
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

### v4.5.0 (2026-07-14) — деплой
- **publish.bat** + `tools/publish-release.ps1` — дистрибутив ~1.1 ГБ (без unpacked/UserManual)
- **DetectionFilter v2** — PUA/PUP/Adware → Info, Quick/Full/RealTime только **High+**
- Исключения: `node_modules`, `.git`, WinSxS, AppData\Local\Programs
- Счётчики сброшены, defaults: RealTime/ProcessMonitor/AutoQuarantine **off**
- `tools/reset-user-settings.ps1` — сброс `%AppData%\TurkmenGuard\settings.json`
- csproj: не копировать `unpacked/`, `UserManual/`, `clamav-download/`
- `.gitignore`: весь `dist/`, ClamAV zip; git-репозиторий для исходников
- **SelfProtectionService** — без NRE в headless-тестах (нет WPF Application)

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
