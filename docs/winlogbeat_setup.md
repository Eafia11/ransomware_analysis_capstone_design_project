# Winlogbeat 설정

## 목적

Windows 분석 VM에서 이벤트 로그와 Sysmon 로그를 수집해 파일로 저장하거나 Logstash로 전송합니다. 이 프로젝트의 기본 분석 입력은 Winlogbeat JSON/JSONL 형식입니다.

## 기본 설정 파일

```text
collector/winlogbeat/winlogbeat.yml
```

현재 설정은 다음 채널을 수집합니다.

```text
Application
System
Security
Microsoft-Windows-Sysmon/Operational
Microsoft-Windows-PowerShell/Operational
```

기본 출력은 파일입니다.

```yaml
output.file:
  path: "C:/ProgramData/Winlogbeat/exported"
  filename: winlogbeat
```

## 설치 순서

1. Windows VM에 Sysmon을 설치합니다.
2. Winlogbeat를 설치합니다.
3. `collector/winlogbeat/winlogbeat.yml` 내용을 VM의 Winlogbeat 설정에 반영합니다.
4. 설정 검사를 실행합니다.

```powershell
.\winlogbeat.exe test config -c .\winlogbeat.yml
```

5. 출력 설정을 검사합니다.

```powershell
.\winlogbeat.exe test output -c .\winlogbeat.yml
```

6. Winlogbeat를 실행합니다.

```powershell
.\winlogbeat.exe -e -c .\winlogbeat.yml
```

## Logstash로 전송하는 경우

운영/EC2 배포에서는 파일 출력 대신 Logstash 출력으로 변경합니다.

```yaml
output.logstash:
  hosts: ["<EC2_PUBLIC_IP>:5044"]
```

이 경우 Logstash가 이벤트를 받아 백엔드 `/logs` API로 전달합니다.

## 샘플 로그

현재 저장된 샘플 로그:

```text
collector/sample_inputs/winlogbeat_sample-20260415.jsonl
```

샘플 로그 전송:

```bash
python collector/scripts/send_sample_log.py --analyze
```

## 주의점

- 실제 악성 샘플 실행은 격리된 VM에서만 수행합니다.
- 수집된 로그에는 사용자/호스트 정보가 포함될 수 있으므로 외부 공유 전 민감 정보를 제거합니다.
- 발표 시에는 실제 악성코드 재실행보다 저장된 샘플 로그를 사용하는 방식이 안전합니다.
