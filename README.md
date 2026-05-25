# 랜섬웨어 분석 캡스톤 프로젝트

이 프로젝트는 Windows 이벤트 로그와 Sysmon 행위 로그를 기반으로 랜섬웨어 의심 행위를 분석하는 백엔드 중심의 동적 분석 파이프라인입니다. 로그를 수집하고, 파싱하고, 공격 체인 후보를 만들고, 룰/ML 기반 탐지와 IOC/MITRE 매핑을 거쳐 최종적으로 프론트엔드 또는 LLM 보고서 생성 모듈이 사용할 수 있는 JSON 결과를 생성합니다.

핵심 목표는 단순히 로그를 읽는 것이 아니라, 분석 결과를 구조화해서 사람이 이해할 수 있는 보고서와 시스템 연동이 가능한 데이터로 만드는 것입니다.

## 프로젝트가 하는 일

1. Winlogbeat JSON 로그를 업로드하거나 샘플로 입력받습니다.
2. Windows, Sysmon, PowerShell 이벤트를 파싱합니다.
3. 이벤트를 정규화하고 핵심 Sysmon 이벤트를 추출합니다.
4. 프로세스 중심의 공격 체인 후보를 생성합니다.
5. 룰 기반 점수로 의심 체인을 분류합니다.
6. IP, URL, 해시, 파일 경로, 레지스트리 키 등 IOC를 추출합니다.
7. 의심 행위를 MITRE ATT&CK 기법과 매핑합니다.
8. 분석 산출물을 `data/` 아래에 저장합니다.
9. LLM이 자연어 보고서를 작성할 수 있도록 입력용 JSON을 생성합니다.

## 프로젝트 구조

```text
backend/       FastAPI 백엔드, 분석 서비스, DB 계층, API 스키마, 테스트
collector/     Winlogbeat 설정, 샘플 로그, 로그 전송 스크립트
data/          분석 과정에서 생성되는 JSON 산출물
frontend/      프론트엔드 담당자를 위한 기본 폴더
ml/            데이터 전처리, XGBoost 학습, 평가, 추론 코드
samples/       benign/ransomware 샘플 보관용 폴더
scripts/       백엔드 실행, DB 초기화, 모델 학습용 스크립트
```

## 백엔드 API

주요 API는 다음과 같습니다.

```text
GET  /health
POST /upload
POST /analyze/{analysis_id}
GET  /result/{analysis_id}
GET  /
```

기본 흐름은 다음과 같습니다.

```text
로그 업로드 -> analysis_id 발급 -> analysis_id 분석 실행 -> 결과 조회
```

최종 분석 응답에는 다음 정보가 포함됩니다.

```text
summary
risk_level
key_findings
iocs
llm_report
attack_chains
abstracted_attack_chains
rule_results
suspicious_results
artifact_paths
```

## 실행 방법

백엔드 의존성을 설치합니다.

```bash
cd backend
pip install -r requirements.txt
cd ..
```

SQLite DB를 초기화합니다.

```bash
scripts/init_db.bat
```

백엔드를 실행합니다.

```bash
scripts/run_backend.bat
```

API 문서는 아래 주소에서 확인할 수 있습니다.

```text
http://127.0.0.1:8000/docs
```

## 샘플 로그 분석

샘플 Winlogbeat 로그는 아래 위치에 있습니다.

```text
collector/sample_inputs/winlogbeat_sample.json
```

백엔드가 실행 중인 상태에서 샘플 로그를 업로드하고 바로 분석하려면 다음 명령을 사용합니다.

```bash
python collector/scripts/send_sample_log.py --analyze
```

분석 산출물은 아래 폴더에 저장됩니다.

```text
data/parsed/
data/normalized/
data/analyzed/
data/reports/
```

LLM 보고서 생성 담당자가 가장 중요하게 봐야 하는 파일은 다음입니다.

```text
data/reports/{analysis_id}_llm_input.json
```

## LLM 입력 JSON 구조

백엔드는 LLM이 바로 사용할 수 있도록 `llm_report` 객체를 생성합니다.

구조는 다음과 같습니다.

```json
{
  "schema_version": "1.0",
  "analysis_id": "...",
  "summary": {
    "parsed_events": 0,
    "sysmon_events": 0,
    "sysmon_core_events": 0,
    "attack_chains": 0,
    "suspicious_chains": 0,
    "risk_level": "low",
    "ioc_counts": {}
  },
  "key_findings": [],
  "iocs": {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": [],
    "file_paths": [],
    "registry_keys": []
  },
  "mitre_attack": [],
  "suspicious_processes": [],
  "attack_chain_summaries": [],
  "reporting_instruction": "..."
}
```

LLM 모듈은 이 JSON을 입력으로 받아 자연어 분석 보고서를 작성하면 됩니다.

## ML 파이프라인

원본 ML 데이터는 Winlogbeat/Sysmon JSON 또는 JSONL 로그를 사용합니다. 기본 입력은 아래 파일입니다.

```text
ml/data/raw/sample_logs.json
```

`ransom.csv`는 참고용 원본 데이터로 보관할 수 있지만, 현재 백엔드에 연결되는 모델은 정적 PE 피처가 아니라 동적 공격 체인 피처로 학습합니다.

피처 추출 코드는 아래 파일에 있습니다.

```text
ml/src/preprocess.py
```

현재 생성되는 ML 산출물은 다음과 같습니다.

```text
ml/data/processed/features.csv
ml/data/processed/train.csv
ml/data/processed/test.csv
ml/models/label_encoder.pkl
ml/models/feature_columns.json
```

XGBoost 모델 학습:

```bash
scripts/train_model.bat
```

학습 피처는 백엔드 공격 체인에서 추출되는 8개 동적 행위 피처입니다.

```text
event_count
process_create_count
file_create_count
registry_modify_count
network_connect_count
uses_suspicious_process
uses_suspicious_command
has_multiple_behaviors
```

학습된 모델 평가:

```bash
cd ml/src
python evaluate.py
```

예상되는 모델/평가 결과 파일은 다음과 같습니다.

```text
ml/models/xgboost_model.json
ml/reports/classification_report.txt
ml/reports/confusion_matrix.png
ml/reports/feature_importance.png
```

## Collector

Winlogbeat 설정 파일:

```text
collector/winlogbeat/winlogbeat.yml
```

샘플 로그 전송:

```bash
python collector/scripts/send_sample_log.py --analyze
```

PowerShell 로그 모니터링:

```powershell
collector/scripts/watch_log.ps1
```

## Docker

백엔드 실행용 Docker Compose 파일이 포함되어 있습니다.

```bash
docker compose up
```

컨테이너 내부에서는 다음 명령으로 백엔드를 실행합니다.

```text
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 테스트

백엔드 테스트 실행:

```bash
cd backend
python -m pytest tests
cd ..
```

현재 테스트 범위는 다음과 같습니다.

```text
업로드 API
분석 API
Winlogbeat 파싱
룰 기반 탐지
IOC 추출
ML 보조 함수
E2E 분석 파이프라인
```

## 현재 진행 상태

완료된 항목:

- FastAPI 백엔드 구조
- SQLite 기반 분석 상태 저장
- Winlogbeat 파서와 정규화 로직
- 공격 체인 후보 생성
- 룰 기반 탐지
- MITRE ATT&CK 매핑
- IOC 추출
- LLM 입력용 JSON 생성
- 동적 공격 체인 기반 ML 피처 추출
- XGBoost 모델 학습 및 평가
- Collector 폴더와 샘플 전송 스크립트
- 실행 스크립트 정리
- Docker Compose 기본 구성
- 백엔드 테스트 코드

남은 항목:

- MITRE 매핑 룰 보강
- 프론트엔드 연동
- LLM 보고서 생성 모듈 구현
