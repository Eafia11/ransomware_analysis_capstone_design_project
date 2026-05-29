# AWS Logstash 설정 가이드

이 문서는 분석 VM의 Winlogbeat 이벤트를 AWS EC2의 Logstash로 받고, Logstash가 FastAPI ingest API로 전달하는 운영 구성을 설명한다.

## 목표 구조

```text
Windows 분석 VM
  Sysmon + Winlogbeat
        |
        | TCP 5044
        v
AWS EC2
  Logstash -> http://backend:8000/ingest/winlogbeat
  Nginx    -> React frontend + FastAPI reverse proxy
```

## EC2 준비

권장 사양:

```text
Ubuntu 22.04 LTS 이상
2 vCPU / 4GB RAM 이상
20GB 디스크 이상
```

필수 패키지:

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

`usermod` 적용 후 SSH를 다시 접속한다.

## 프로젝트 배포

```bash
sudo mkdir -p /opt/netguardian
sudo chown -R $USER:$USER /opt/netguardian
git clone <REPOSITORY_URL> /opt/netguardian
cd /opt/netguardian
cp .env.example .env
docker compose -f docker-compose.prod.yml up -d --build
```

상태 확인:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f logstash
curl http://localhost/health
```

## Logstash 파이프라인

운영 파이프라인 파일:

```text
deploy/logstash/pipeline/winlogbeat-to-backend.conf
```

동작:

```text
input  : beats, port 5044
output : http://backend:8000/ingest/winlogbeat
```

Winlogbeat 이벤트가 들어오면 Logstash는 이벤트 JSON을 그대로 백엔드 ingest API에 POST한다.

## systemd 자동 시작

EC2 재부팅 후 자동 실행:

```bash
sudo cp deploy/systemd/netguardian.service /etc/systemd/system/netguardian.service
sudo systemctl daemon-reload
sudo systemctl enable --now netguardian
sudo systemctl status netguardian
```

재시작:

```bash
sudo systemctl restart netguardian
```

## AWS 보안 그룹

최소 권장 규칙:

```text
22/tcp   관리자 SSH IP만 허용
80/tcp   프론트엔드 접근 IP 허용
5044/tcp 분석 VM 또는 실습망 IP만 허용
8000/tcp 외부 개방 금지
```

FastAPI `8000`은 Nginx와 Logstash 컨테이너 내부에서만 접근한다.

## 장애 확인

Logstash 수신 여부:

```bash
docker compose -f docker-compose.prod.yml logs -f logstash
```

백엔드 ingest API 상태:

```bash
curl http://localhost/health
ls -al data/ingested
```

프론트 접근:

```text
http://<EC2_PUBLIC_IP>/
```

분석 VM에서 5044 연결 확인:

```powershell
Test-NetConnection <EC2_PUBLIC_IP> -Port 5044
```
