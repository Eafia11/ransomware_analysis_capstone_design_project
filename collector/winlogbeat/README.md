# Winlogbeat Collector

This folder contains a local Winlogbeat configuration for collecting Windows, Sysmon, and PowerShell event logs.

Default output is file-based:

```text
C:/ProgramData/Winlogbeat/exported/winlogbeat-*.ndjson
```

Use `collector/sample_inputs/winlogbeat_sample.json` when you want to test the backend without running Winlogbeat.

Typical flow:

```powershell
cd collector/scripts
python send_sample_log.py
```

For live file monitoring:

```powershell
.\watch_log.ps1 -Path "C:\ProgramData\Winlogbeat\exported\winlogbeat"
```
