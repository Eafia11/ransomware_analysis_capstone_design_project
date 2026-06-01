# Winlogbeat 수집기 설정

이 폴더는 Windows, Sysmon, PowerShell 이벤트 로그를 수집하기 위한 Winlogbeat 설정을 보관합니다.

설정 파일:

```text
collector/winlogbeat/winlogbeat.yml
```

기본 출력은 파일 기반입니다.

```text
C:/ProgramData/Winlogbeat/exported/winlogbeat-*.ndjson
```

Winlogbeat를 직접 실행하지 않고 백엔드를 테스트하려면 샘플 로그를 사용합니다.

```text
collector/sample_inputs/winlogbeat_sample-20260415.jsonl
```

샘플 로그 업로드:

```powershell
python collector/scripts/send_sample_log.py
```

업로드 후 바로 분석:

```powershell
python collector/scripts/send_sample_log.py --analyze
```

실시간 파일 모니터링:

```powershell
.\collector\scripts\watch_log.ps1 -Path "C:\ProgramData\Winlogbeat\exported\winlogbeat"
```

Logstash로 전송하는 운영 구성은 [docs/aws_logstash_setup.md](../../docs/aws_logstash_setup.md)를 참고합니다.
