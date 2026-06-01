# AWS Logstash 연동

## 목적

Winlogbeat가 Windows VM에서 수집한 이벤트를 EC2의 Logstash로 보내고, Logstash가 백엔드 `/logs` API로 전달하는 구성입니다.

## 전체 흐름

```text
Windows VM
-> Winlogbeat
-> Logstash 5044/tcp
-> backend POST /logs
-> data/ingested/
-> POST /analyze/stream/{analysis_id}
```

## 서버 실행

```bash
cp .env.example .env
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

Logstash 로그 확인:

```bash
docker compose -f docker-compose.prod.yml logs -f logstash
```

## Logstash pipeline

설정 파일:

```text
deploy/logstash/pipeline/winlogbeat-to-backend.conf
```

Logstash는 Beats input으로 이벤트를 받고 HTTP output으로 backend에 전달합니다.

백엔드 endpoint:

```text
POST /logs
```

API key를 사용할 경우 `.env`에 설정합니다.

```text
NETGUARDIAN_API_KEY=<secret>
```

## Winlogbeat 설정

Windows VM의 `winlogbeat.yml`에서 output을 Logstash로 변경합니다.

```yaml
output.logstash:
  hosts: ["<EC2_PUBLIC_IP>:5044"]
```

파일 출력 설정과 Logstash 출력 설정은 동시에 사용하지 않는 것을 권장합니다. 테스트 목적이라면 파일 출력으로 먼저 확인한 뒤 Logstash 출력으로 전환합니다.

## 보안 그룹

EC2 inbound rule:

```text
5044/tcp  Windows 분석 VM IP만 허용
80/tcp    관리자/시연 접근 IP 허용
22/tcp    관리자 SSH IP만 허용
```

## 확인 절차

1. EC2에서 Logstash 컨테이너가 실행 중인지 확인합니다.
2. Windows VM에서 `winlogbeat test output`을 실행합니다.
3. 이벤트가 들어오면 `data/ingested/`에 JSONL 파일이 생성되는지 확인합니다.
4. 생성된 `analysis_id`로 `/analyze/stream/{analysis_id}`를 호출합니다.

## 장애 확인

```bash
docker compose -f docker-compose.prod.yml logs -f logstash
docker compose -f docker-compose.prod.yml logs -f backend
```

주요 원인:

- 보안 그룹에서 5044 포트가 닫힘
- Winlogbeat output host 오타
- `NETGUARDIAN_API_KEY` 불일치
- backend 컨테이너 미실행
