# 시스템 아키텍처 문서

## 1. 개요

본 프로젝트는 Windows 기반 랜섬웨어 의심 행위를 분석하기 위한 로그 분석 파이프라인이다. 전체 구조는 수집기, 백엔드 분석 API, ML 학습 영역, 산출물 저장 영역, 프론트엔드/LLM 연동 영역으로 나뉜다.

핵심 설계 방향은 다음과 같다.

- 수집과 분석 로직을 분리한다.
- 분석 결과는 JSON 산출물로 남긴다.
- 프론트엔드와 LLM 모듈은 백엔드 분석 결과를 소비하는 구조로 둔다.
- 모델 학습 코드는 운영 API와 분리하여 `ml/` 영역에서 관리한다.

## 2. 전체 구성

```text
collector -> backend API -> services -> data/reports -> frontend or LLM module
                         -> ml/models
```

주요 폴더 역할:

```text
backend/    FastAPI API 서버와 분석 서비스
collector/  Winlogbeat 설정 및 샘플 로그 전송 도구
data/       분석 결과 JSON, 리포트, DB 파일 저장 위치
ml/         XGBoost 학습/평가/추론 코드와 모델 산출물
frontend/   프론트엔드 작업 영역
samples/    별도 샘플 파일 보관 영역
scripts/    실행 편의 스크립트
docs/       설계 및 기능 문서
```

## 3. 백엔드 계층

백엔드는 다음 계층으로 구성된다.

```text
api/       HTTP endpoint
services/  분석 로직
models/    Pydantic 응답 모델
db/        SQLAlchemy DB 계층
core/      설정, 로깅, 보안 유틸
utils/     파일, 시간, 해시 공통 유틸
tests/     pytest 테스트
```

API 계층은 요청과 응답의 경계를 담당한다. 실제 분석 로직은 `services/` 내부에서 수행한다. DB 접근은 `services/storage.py`를 통해 감싸서 API가 SQLAlchemy 구현에 직접 의존하지 않도록 구성했다.

## 4. 분석 파이프라인

분석 흐름은 다음과 같다.

1. `/upload`로 로그 파일 업로드
2. SQLite에 분석 상태 `uploaded` 저장
3. `/analyze/{analysis_id}` 호출
4. Winlogbeat JSON Lines 파싱
5. 이벤트 정규화
6. Sysmon 핵심 이벤트 필터링
7. 공격 체인 후보 생성
8. 룰 기반 점수화
9. MITRE ATT&CK 매핑
10. IOC 추출
11. LLM 입력용 JSON 생성
12. 산출물 저장 및 `/result/{analysis_id}` 조회 가능 상태로 변경

## 5. 데이터 저장 구조

런타임 산출물은 루트 `data/` 아래에 저장한다.

```text
data/
├─ uploads/      업로드 원본 로그
├─ parsed/       전체 파싱 결과
├─ normalized/   Sysmon 등 정규화/필터링 결과
├─ analyzed/     공격 체인, 룰 탐지 결과
└─ reports/      최종 분석 리포트 및 LLM 입력 JSON
```

SQLite DB는 기본적으로 다음 경로를 사용한다.

```text
data/app.db
```

DB 파일과 업로드 파일은 실행 산출물이므로 Git 추적 대상에서 제외한다.

## 6. 외부 연동 지점

프론트엔드 연동:

- `/upload`
- `/analyze/{analysis_id}`
- `/result/{analysis_id}`
- `/health`

LLM 연동:

- `data/reports/{analysis_id}_llm_input.json`
- API 응답의 `result.llm_report`

ML 모델 연동:

- 기본 모델 경로: `ml/models/xgboost_model.json`
- 모델 입력은 백엔드 공격 체인에서 추출한 8개 동적 행위 피처다.
- 분석 결과의 `rule_results[].ml_result`에 ML 예측 결과가 함께 포함된다.
- 모델 파일이 없거나 피처가 호환되지 않으면 서버 오류 대신 비활성 상태와 사유를 반환한다.

## 7. 운영상 주의점

- 현재 DB는 SQLite이므로 단일 서버/개발 환경에 적합하다.
- 대용량 로그 분석 시 응답 시간이 길어질 수 있으므로 추후 비동기 작업 큐 도입을 고려할 수 있다.
- 업로드 파일은 `data/uploads/`에 저장되며, 운영 환경에서는 보관 주기와 삭제 정책이 필요하다.
- LLM 보고서 생성은 별도 팀원 모듈에서 수행하며, 백엔드는 입력 JSON 제공까지만 담당한다.
