# YARA Rules v4.5.2 (strict)

Политика: **ловим только реальные угрозы**, не обычные скрипты и exe.

## Принципы

1. **Несколько индикаторов** — правило срабатывает только если совпали 2–4 специфичных строки (download + bypass + execute).
2. **Без одиночных маркеров** — `Invoke-WebRequest`, `AutoOpen`, `Quasar`, `schtasks` сами по себе не детектятся.
3. **Quick Scan** — YARA не используется (только ClamAV).
4. **Full / Single file** — YARA strict + фильтр `DetectionFilter`.

## Отключённые правила

- `lateral_movement.yar.disabled` — слишком много FP на IT/admin скриптах.

## Категории (активные)

| Файл | Назначение |
|------|------------|
| `amsi_bypass.yar` | AMSI bypass (Critical) |
| `credential_theft.yar` | Mimikatz, LSASS dump |
| `ransomware_*.yar` | Shadow delete, ransom notes |
| `trojan_rat.yar` | RAT families (2+ markers) |
| `webshell_*.yar` | PHP/ASP webshells |
| `downloader_powershell.yar` | Malicious PS cradles only |
| `macro_office.yar` | AutoRun + payload together |
| `eicar.yar`, `test_malware.yar` | Тестовые сигнатуры |
