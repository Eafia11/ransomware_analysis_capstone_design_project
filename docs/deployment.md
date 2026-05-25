# 배포 및 실행 문서

## 1. 목적

이 문서는 프로젝트를 로컬 개발 환경 또는 Docker 환경에서 실행하기 위한 절차를 정리한다. 현재 프로젝트는 캡스톤 개발/시연 환경을 기준으로 구성되어 있으며, 운영 배포 전에는 인증, 파일 보관 정책, 작업 큐 도입 등을 추가 검토해야 한다.

## 2. 로컬 실행 환경

권장 환경:

```text
Python 3.10
Windows PowerShell 또는 Git Bash
```

의존성 설치:

```bash
cd backend
pip install -r requirements.txt
cd ..
```

DB 초기화:

```bash
scripts/init_db.bat
```

백엔드 실행:

```bash
scripts/run_backend.bat
```

접속:

```text
http://127.0.0.1:8000
http://127.0.0.1:8000/docs
```

## 3. Docker Compose 실행

루트에 `docker-compose.yml`이 있다.

실행:

```bash
docker compose up
```

Compose 서비스:

```text
backend
```

컨테이너 설정:

```text
DATA_DIR=/app/data
MODEL_DIR=/app/ml/models
XGBOOST_MODEL_PATH=/app/ml/models/xgboost_model.json
DATABASE_URL=sqlite:////app/data/app.db
```

Docker 환경에서는 저장소 전체를 `/app`으로 마운트한다. 따라서 컨테이너에서 생성된 분석 결과도 호스트의 `data/` 폴더에 남는다.

## 4. 데이터와 산출물

주요 산출물 경로:

```text
data/uploads/      업로드 로그
data/parsed/       파싱 결과
data/normalized/   정규화/필터링 결과
data/analyzed/     공격 체인 및 탐지 결과
data/reports/      최종 보고서 JSON, LLM 입력 JSON
```

DB:

```text
data/app.db
```

Git 추적 제외 대상:

```text
data/app.db*
data/uploads/*
samples/benign/*
samples/ransomware/*
samples/expected_outputs/*
```

## 5. 샘플 분석 시연

1. 백엔드 실행

```bash
scripts/run_backend.bat
```

2. 샘플 로그 업로드 및 분석

```bash
python collector/scripts/send_sample_log.py --analyze
```

3. 결과 확인

```text
data/reports/{analysis_id}_analysis_report.json
data/reports/{analysis_id}_llm_input.json
```

## 6. 테스트

```bash
cd backend
python -m pytest tests
cd ..
```

현재 테스트는 API, 파서, 룰 탐지, IOC 추출, ML helper를 포함한다.

## 7. 운영 전 보완 사항

운영 환경으로 확장하려면 다음 항목을 검토해야 한다.

- API 인증 및 권한 관리
- 업로드 파일 용량 제한 정책 강화
- 업로드 파일 보관 기간 및 삭제 정책
- 비동기 분석 작업 큐 도입
- SQLite에서 PostgreSQL 등 서버형 DB로 전환
- Docker image 고정 빌드 방식 도입
- 로그와 분석 산출물 백업 정책 수립
