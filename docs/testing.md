# 테스트와 검증

## 전체 검증

Windows PowerShell:

```powershell
.\scripts\verify.ps1
```

이 스크립트는 백엔드 테스트와 프론트엔드 빌드를 순서대로 실행합니다.

프론트엔드 검증을 건너뛰려면:

```powershell
.\scripts\verify.ps1 -SkipFrontend
```

## 백엔드 테스트

```bash
python -m pytest backend/tests
```

현재 테스트 범위:

```text
health/upload/analyze/result API
Winlogbeat parsing
ingest API
rule detector
MITRE mapper
IOC extractor
ML detector
LLM report service/API
sandbox API/service
E2E analysis pipeline
```

최근 확인 결과:

```text
47 passed
```

## 프론트엔드 빌드

```bash
cd frontend
npm run build
```

최근 확인 결과:

```text
vite build success
```

## Docker 검증

Docker가 설치된 환경에서 실행합니다.

```bash
docker compose -f docker-compose.prod.yml config
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

현재 작업 PC에서는 `docker` 명령이 설치되어 있지 않아 compose 실행 검증은 별도 환경에서 확인해야 합니다.

## 수동 API 검증 순서

1. 백엔드 실행

```bash
scripts/run_backend.bat
```

2. health 확인

```bash
curl http://127.0.0.1:8000/health
```

3. 샘플 로그 업로드와 분석

```bash
python collector/scripts/send_sample_log.py --analyze
```

4. 브라우저에서 API 문서 확인

```text
http://127.0.0.1:8000/docs
```
