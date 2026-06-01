# 시스템 아키텍처

## 목적

이 프로젝트는 Windows 이벤트 로그와 Sysmon/Winlogbeat 로그를 기반으로 랜섬웨어 의심 행위를 분석하는 동적 분석 파이프라인입니다. 단순 로그 목록을 보여주는 것이 아니라, 이벤트를 정규화하고 프로세스 중심 공격 체인을 만든 뒤 룰/ML/IOC/MITRE/LLM 보고서 입력으로 연결합니다.

## 주요 구성

```text
collector/      Winlogbeat 설정, 샘플 로그, 로그 전송 스크립트
backend/        FastAPI API, 분석 서비스, SQLite 저장소, 테스트
ml/             동적 행위 피처 전처리, XGBoost 학습/평가/추론
frontend/       React 대시보드와 API 클라이언트
deploy/         Nginx, Logstash, systemd 배포 설정
data/           업로드 파일과 분석 산출물 저장 경로
docs/           프로젝트 문서
```

## 데이터 흐름

```text
Winlogbeat/Sysmon log
-> upload 또는 ingest
-> parse
-> normalize
-> core Sysmon event filtering
-> attack chain building
-> rule detection
-> ML prediction
-> IOC extraction
-> MITRE ATT&CK mapping
-> JSON artifacts
-> frontend / LLM report
```

## 백엔드 구조

```text
backend/app/api/          HTTP API 라우터
backend/app/services/     분석 파이프라인 핵심 로직
backend/app/models/       Pydantic 응답 모델
backend/app/db/           SQLite 초기화와 CRUD
backend/app/core/         설정, 로깅, API key 보안
backend/tests/            단위/통합 테스트
```

주요 서비스 역할은 다음과 같습니다.

| 파일 | 역할 |
|---|---|
| `winlogbeat_parser.py` | JSON/JSONL Winlogbeat 로그 파싱 |
| `normalizer.py` | 이벤트 타입 요약과 채널 필터링 |
| `attack_chain_builder.py` | Sysmon 핵심 이벤트를 프로세스 체인으로 구성 |
| `rule_detector.py` | 랜섬웨어 의심 행위 점수화 |
| `ml_detector.py` | XGBoost 모델 기반 보조 판정 |
| `ioc_extractor.py` | IP, URL, hash, file path, registry key 등 IOC 추출 |
| `mitre_mapper.py` | MITRE ATT&CK technique 매핑 |
| `report_service.py` | 전체 분석 파이프라인 실행과 산출물 저장 |
| `llm_report_service.py` | OpenAI API를 이용한 자연어 보고서 생성 |
| `sandbox_service.py` | AWS Windows 샌드박스 실행/상태/로그 분석 |

## 저장 경로

```text
data/uploads/            업로드된 로그 파일
data/ingested/           Logstash/Winlogbeat ingest 로그
data/parsed/             파싱된 전체 이벤트
data/normalized/         Sysmon 필터링 결과
data/analyzed/           공격 체인, 룰 탐지, 의심 체인
data/reports/            LLM 입력 JSON, 최종 분석 JSON, AI 보고서
data/sandbox_uploads/    샌드박스 실행 대상 파일
data/sandbox_sessions/   샌드박스 세션 상태
```

## 외부 연동

- Frontend는 `/upload`, `/analyze`, `/result`, `/sandbox`, `/llm-report` API를 호출합니다.
- Winlogbeat는 Logstash로 전송하고, Logstash는 백엔드 `/logs` API로 이벤트를 전달합니다.
- OpenAI API는 `/llm-report/{analysis_id}` 호출 시 사용됩니다.
- AWS Windows 샌드박스는 선택 기능이며, API key와 AWS 설정이 필요합니다.
