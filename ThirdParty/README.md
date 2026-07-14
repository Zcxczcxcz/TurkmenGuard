# ThirdParty — ClamAV engine

В репозитории включён **portable ClamAV 1.5.3 x64** для Windows.

## Содержимое `ClamAV/`

| Путь | Описание |
|------|----------|
| `clamscan.exe`, `clamd.exe`, `clamdscan.exe`, `freshclam.exe` | Основные утилиты |
| `libclamav.dll` и зависимости | Runtime DLL |
| `database/main.cvd`, `daily.cvd`, `bytecode.cvd` | Сигнатуры ClamAV |
| `clamd.conf`, `freshclam.conf` | Конфигурация |

## Не включено в git (экономия места)

- `UserManual/` — HTML-документация ClamAV
- `database/unpacked/` — распакованные .hdb (не нужны при наличии .cvd)
- `*.pdb`, `*.lib` — отладочные/линковочные файлы

## Если папка отсутствует после клонирования

```powershell
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
```

Скрипт скачает zip с GitHub Cisco-Talos (~230 MB) и распакует CVD.

## Лицензия

ClamAV — GPL/LGPL. Файлы `COPYING/` внутри `ClamAV/`.
