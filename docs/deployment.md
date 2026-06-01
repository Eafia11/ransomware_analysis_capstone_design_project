# 배포 문서

## 배포 구성

운영 배포는 Docker Compose 기준입니다.

```text
frontend container  -> Nginx, React 정적 파일, reverse proxy
backend container   -> FastAPI, 분석 API
logstash container  -> Winlogbeat 이벤트 수신 후 backend /logs 전달
data volume         -> 분석 산출물과 SQLite DB 저장
ml/models volume    -> XGBoost 모델 파일 read-only mount
```

Compose 파일:

```text
docker-compose.prod.yml
```

## 사전 준비

`.env` 파일을 생성합니다.

```bash
cp .env.example .env
```

주요 환경 변수:

```text
APP_ENV=production
DATA_DIR=/app/data
MODEL_DIR=/app/ml/models
XGBOOST_MODEL_PATH=/app/ml/models/xgboost_model.json
DATABASE_URL=sqlite:////app/data/app.db
NETGUARDIAN_API_KEY=
OPENAI_API_KEY=
LLM_MODEL=gpt-5.2
```

샌드박스를 사용할 경우 AWS 관련 값도 설정합니다.

```text
AWS_REGION
NG_WINDOWS_AMI_ID
NG_WINDOWS_KEY_NAME
NG_WINDOWS_SUBNET_ID
NG_WINDOWS_SECURITY_GROUP_IDS
NG_WINDOWS_SSH_USERNAME
NG_WINDOWS_SSH_PASSWORD 또는 NG_WINDOWS_SSH_KEY_PATH
```

## 실행

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

상태 확인:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f backend
docker compose -f docker-compose.prod.yml logs -f frontend
docker compose -f docker-compose.prod.yml logs -f logstash
```

Health check:

```bash
curl http://localhost/health
```

## 포트

| 포트 | 용도 |
|---:|---|
| 80 | Nginx/Frontend, API reverse proxy |
| 5044 | Logstash Beats input |
| 8000 | backend 내부 포트, 외부 직접 개방 금지 |

## Nginx

설정 파일:

```text
deploy/nginx/default.conf
```

Nginx는 React 정적 파일을 제공하고 다음 API 경로를 backend로 proxy합니다.

```text
/health
/upload
/analyze
/result
/ingest
/sandbox
/llm-report
```

`/logs`는 Logstash 컨테이너가 내부 Docker network에서 backend로 직접 호출하는 수집용 endpoint입니다.

## Logstash

설정 파일:

```text
deploy/logstash/pipeline/winlogbeat-to-backend.conf
```

Winlogbeat 이벤트를 받아 backend `/logs` API로 전달합니다. 외부 VM에서 Logstash로 전송하려면 Winlogbeat에 다음 설정을 사용합니다.

```yaml
output.logstash:
  hosts: ["<SERVER_IP>:5044"]
```

## systemd 자동 실행

서비스 파일:

```text
deploy/systemd/netguardian.service
```

등록:

```bash
sudo cp deploy/systemd/netguardian.service /etc/systemd/system/netguardian.service
sudo systemctl daemon-reload
sudo systemctl enable --now netguardian
sudo systemctl status netguardian
```

## 보안 그룹 권장

```text
22/tcp    관리자 SSH IP만 허용
80/tcp    발표/운영 접근 IP 허용
5044/tcp  분석 VM 또는 실습망 IP만 허용
8000/tcp  외부 개방 금지
```

## 배포 전 검증

```bash
python -m pytest backend/tests
cd frontend && npm run build
docker compose -f docker-compose.prod.yml config
```

현재 작업 환경에서는 Docker가 설치되어 있지 않아 compose config/up 검증은 별도 Docker 환경에서 수행해야 합니다.
