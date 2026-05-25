# ML 파이프라인 문서

## 1. 목적

ML 파이프라인은 Winlogbeat/Sysmon 로그에서 생성된 공격 체인 피처를 기반으로 XGBoost 분류 모델을 학습하기 위한 영역이다. 본 프로젝트의 목표는 정적 PE 분석이 아니라 동적 행위 분석이므로, 백엔드 분석 파이프라인에서 실제로 사용하는 체인 단위 행위 피처와 모델 학습 피처를 일치시킨다.

## 2. 폴더 구조

```text
ml/
├─ data/
│  ├─ raw/
│  │  ├─ ransom.csv
│  │  └─ sample_logs.json
│  └─ processed/
│     ├─ features.csv
│     ├─ train.csv
│     └─ test.csv
├─ models/
│  ├─ xgboost_model.json
│  ├─ label_encoder.pkl
│  └─ feature_columns.json
├─ src/
│  ├─ preprocess.py
│  ├─ train_xgboost.py
│  ├─ evaluate.py
│  └─ inference.py
└─ reports/
   ├─ classification_report.txt
   ├─ confusion_matrix.png
   └─ feature_importance.png
```

`ransom.csv`는 기존 확보 데이터로 보관하지만, 현재 백엔드 연동 모델은 `sample_logs.json` 같은 동적 로그 파일에서 추출한 체인 피처를 사용한다.

## 3. 입력 데이터

기본 입력 로그:

```text
ml/data/raw/sample_logs.json
collector/sample_inputs/winlogbeat_sample.json
```

추가 샘플은 아래 위치에 넣을 수 있다.

```text
samples/benign/
samples/ransomware/
```

폴더명이 `benign`이면 정상, `ransomware` 또는 `malware`이면 의심 행위 라벨로 사용할 수 있다. 폴더 라벨이 없는 로그는 초기 부트스트랩 단계에서 룰 탐지 결과를 기준으로 체인 라벨을 생성한다.

## 4. 피처 추출 정책

전처리 구현 위치:

```text
ml/src/preprocess.py
```

전처리 흐름:

```text
Winlogbeat JSON/JSONL
-> 이벤트 정규화
-> 핵심 Sysmon 이벤트 필터링
-> 프로세스 단위 공격 체인 생성
-> 체인별 행위 피처 추출
-> label 생성
-> features/train/test CSV 저장
```

현재 학습 피처:

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

이 8개 피처는 백엔드 `feature_extractor.py`에서 분석 결과에 붙는 피처와 동일하다.

## 5. 학습

학습 스크립트:

```text
ml/src/train_xgboost.py
```

실행:

```bash
scripts/train_model.bat
```

직접 실행:

```bash
cd ml/src
python train_xgboost.py --preprocess
```

특정 로그 파일로 학습하려면 다음처럼 실행한다.

```bash
python train_xgboost.py --log-path ../../collector/sample_inputs/winlogbeat_sample.json --preprocess
```

생성되는 모델:

```text
ml/models/xgboost_model.json
ml/models/label_encoder.pkl
ml/models/feature_columns.json
```

## 6. 평가

평가 실행:

```bash
cd ml/src
python evaluate.py
```

산출물:

```text
ml/reports/classification_report.txt
ml/reports/confusion_matrix.png
ml/reports/feature_importance.png
```

현재 초기 데이터셋은 실제 샘플 로그와 seed row를 함께 사용한다. 따라서 평가 수치는 운영 성능을 보증하는 지표라기보다, 모델 학습/추론 파이프라인이 정상 연결되었는지 확인하는 기준으로 해석해야 한다.

## 7. 백엔드 연결

백엔드는 기본적으로 아래 모델을 로드한다.

```text
ml/models/xgboost_model.json
```

분석 흐름에서는 룰 탐지 결과에 ML 결과가 추가된다.

```text
rule_results[].ml_result
```

예시:

```json
{
  "enabled": true,
  "label": "suspicious",
  "confidence": 0.96,
  "feature_columns": [
    "event_count",
    "process_create_count",
    "file_create_count",
    "registry_modify_count",
    "network_connect_count",
    "uses_suspicious_process",
    "uses_suspicious_command",
    "has_multiple_behaviors"
  ]
}
```

모델 파일이 없거나 피처 수가 맞지 않으면 서버 오류를 내지 않고 `enabled: false`와 사유를 반환한다.

## 8. 개선 방향

- 실제 benign/ransomware 로그 샘플 추가
- 룰 기반 부트스트랩 라벨을 사람이 검수한 라벨로 보강
- 체인 피처 확장: 프로세스 트리 깊이, 파일 확장자 분포, 시간 간격, 권한 상승 흔적 등
- 모델 버전 관리 및 학습 데이터셋 버전 기록
- 룰 점수와 ML confidence를 결합한 최종 위험도 산정
