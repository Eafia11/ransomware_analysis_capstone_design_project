# 배포 및 운영 실행 문서

이 문서는 AWS EC2 한 대에서 프론트엔드, FastAPI 백엔드, Logstash를 함께 운영하는 구성을 기준으로 한다.

## 1. 운영 구조

```text
분석 VM
  Sysmon + Winlogbeat
        |
        | TCP 5044
        v
AWS EC2
  Logstash -> FastAPI backend -> SQLite/data artifacts
  Nginx    -> React static frontend + backend reverse proxy
```

컨테이너 구성:

```text
frontend  : Nginx가 React 빌드 결과를 서빙하고 backend API를 프록시
backend   : FastAPI 분석 서버
logstash  : Winlogbeat Beats 입력을 받아 /ingest/winlogbeat로 전달
```

## 2. EC2 준비

권장:

```text
Ubuntu 22.04 LTS 이상
2 vCPU / 4GB RAM 이상
디스크 20GB 이상
```

필수 패키지:

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

`usermod` 적용 후 SSH 재접속이 필요하다.

## 3. 프로젝트 배치

예시 경로:

```bash
sudo mkdir -p /opt/netguardian
sudo chown -R $USER:$USER /opt/netguardian
git clone <REPOSITORY_URL> /opt/netguardian
cd /opt/netguardian
```

환경 파일 생성:

```bash
cp .env.example .env
```

운영 기본값은 다음과 같다.

```env
APP_ENV=production
DATA_DIR=/app/data
MODEL_DIR=/app/ml/models
XGBOOST_MODEL_PATH=/app/ml/models/xgboost_model.json
DATABASE_URL=sqlite:////app/data/app.db
```

## 4. Docker Compose 배포

빌드 및 실행:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

상태 확인:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f backend
docker compose -f docker-compose.prod.yml logs -f logstash
```

헬스 체크:

```bash
curl http://localhost/health
```

외부 접속:

```text
http://<EC2_PUBLIC_IP>/
```

## 5. systemd 자동 시작

서버 재부팅 후 자동으로 Compose 스택을 올리려면 systemd 유닛을 설치한다.

```bash
sudo cp deploy/systemd/netguardian.service /etc/systemd/system/netguardian.service
sudo systemctl daemon-reload
sudo systemctl enable --now netguardian
```

운영 명령:

```bash
sudo systemctl status netguardian
sudo systemctl restart netguardian
sudo journalctl -u netguardian -f
```

## 6. Logstash 자동 수집

Logstash 파이프라인 파일:

```text
deploy/logstash/pipeline/winlogbeat-to-backend.conf
```

동작:

```text
input  : beats { port => 5044 }
output : http://backend:8000/ingest/winlogbeat
```

Winlogbeat VM 설정 예시:

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System
  - name: Application

output.logstash:
  hosts: ["<EC2_PUBLIC_IP>:5044"]
```

## 7. AWS 보안 그룹

최소 인바운드 규칙:

```text
22/tcp    내 IP만 허용
80/tcp    발표/프론트 접속 IP 또는 0.0.0.0/0
5044/tcp  분석 VM 공인 IP만 허용
```

권장:

```text
8000/tcp  외부 공개 금지
443/tcp   도메인/HTTPS 적용 시 허용
```

FastAPI는 Nginx 내부 프록시를 통해 접근한다. 따라서 운영 환경에서는 `8000`을 보안 그룹에 열지 않는 구성이 더 안전하다.

## 8. 데이터와 백업

컨테이너가 생성하는 분석 결과는 호스트의 `data/`에 남는다.

```text
data/app.db
data/uploads/
data/ingested/
data/parsed/
data/normalized/
data/analyzed/
data/reports/
```

백업 예시:

```bash
tar -czf netguardian-data-$(date +%Y%m%d).tar.gz data
```

## 9. 업데이트 절차

```bash
cd /opt/netguardian
git pull
docker compose -f docker-compose.prod.yml up -d --build
curl http://localhost/health
```

프론트만 바뀌어도 `frontend` 이미지를 다시 빌드해야 한다.

## 10. 장애 확인

백엔드 로그:

```bash
docker compose -f docker-compose.prod.yml logs -f backend
```

Logstash 수신 확인:

```bash
docker compose -f docker-compose.prod.yml logs -f logstash
```

Nginx/프론트 확인:

```bash
docker compose -f docker-compose.prod.yml logs -f frontend
```

컨테이너 재시작:

```bash
docker compose -f docker-compose.prod.yml restart
```
