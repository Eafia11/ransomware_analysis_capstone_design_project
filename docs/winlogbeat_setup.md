# Winlogbeat 설정 가이드

이 문서는 Windows 분석 VM에서 Sysmon 이벤트를 Winlogbeat로 수집해 AWS Logstash로 전송하는 절차를 설명한다.

## 설치 대상

분석 VM에는 다음 구성 요소가 필요하다.

```text
Sysmon      Windows 행위 이벤트 생성
Winlogbeat  Windows 이벤트 로그 수집 및 전송
```

Logstash는 분석 VM마다 설치하지 않는다. AWS EC2에 1개만 두고, 여러 VM이 같은 Logstash로 전송한다.

## Sysmon 설치

Sysmon과 설정 파일을 준비한 뒤 관리자 PowerShell에서 실행한다.

```powershell
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

상태 확인:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

설정 갱신:

```powershell
Sysmon64.exe -c sysmonconfig-export.xml
```

## Winlogbeat 설치

Winlogbeat ZIP을 내려받아 예시 경로에 압축 해제한다.

```text
C:\Program Files\Winlogbeat
```

관리자 PowerShell:

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
```

## winlogbeat.yml 핵심 설정

Sysmon 로그를 포함한다.

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System
  - name: Application
```

AWS Logstash로 전송한다.

```yaml
output.logstash:
  hosts: ["<EC2_PUBLIC_IP>:5044"]
```

Elasticsearch output을 사용하지 않는다면 비활성화한다.

```yaml
# output.elasticsearch:
#   hosts: ["localhost:9200"]
```

프로젝트 예시 파일:

```text
collector/winlogbeat/winlogbeat.yml
```

## 설정 테스트와 실행

```powershell
.\winlogbeat.exe test config -c .\winlogbeat.yml
.\winlogbeat.exe test output -c .\winlogbeat.yml
Start-Service winlogbeat
Get-Service winlogbeat
```

실시간 로그 확인:

```powershell
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Wait
```

## 분석 전 체크리스트

- Sysmon 서비스가 실행 중인지 확인한다.
- Winlogbeat 서비스가 실행 중인지 확인한다.
- 분석 VM에서 EC2 `5044/tcp` 연결이 되는지 확인한다.
- EC2 보안 그룹에서 분석 VM IP를 허용했는지 확인한다.
- EC2 Logstash 로그에 이벤트 수신 흔적이 있는지 확인한다.

연결 확인:

```powershell
Test-NetConnection <EC2_PUBLIC_IP> -Port 5044
```
