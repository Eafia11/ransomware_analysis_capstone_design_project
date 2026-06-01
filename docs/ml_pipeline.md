# ML 파이프라인

## 목적

ML 파이프라인은 동적 행위 feature를 기반으로 XGBoost 모델을 학습합니다. 기본 학습 데이터는 `ransom.csv`이며, 이 파일 안의 `registry_*`, `network_*`, `processes_*`, `files_*` 컬럼을 백엔드 공격 체인 feature와 같은 8개 feature로 변환합니다. Winlogbeat/Sysmon 로그도 같은 schema로 변환할 수 있습니다.

정적 PE feature는 현재 백엔드 실시간 추론에서 직접 생성할 수 없으므로 모델 입력에서 제외합니다. 백엔드와 ML 모델의 입력 feature를 맞추기 위해 동적 행위 컬럼만 사용합니다.

## 입력 데이터

기본 학습 CSV:

```text
ml/data/raw/ransom.csv
```

보조 샘플 로그:

```text
collector/sample_inputs/winlogbeat_sample-20260415.jsonl
```

추가 학습 로그를 넣을 수 있는 위치:

```text
samples/benign/
samples/ransomware/
```

폴더명이 `benign`이면 정상 라벨, `ransomware` 또는 `malware`이면 의심 라벨로 처리합니다. 폴더 라벨이 없는 경우에는 룰 탐지 결과를 기준으로 초기 라벨을 생성합니다.

## 전처리 흐름

구현 위치:

```text
ml/src/preprocess.py
```

처리 순서:

```text
ransom.csv
-> dynamic behavior columns 선택
-> backend feature schema로 변환
-> label 생성
-> features/train/test CSV 저장
```

Winlogbeat/Sysmon 로그를 사용하는 경우:

```text
Winlogbeat JSON/JSONL
-> parse_winlogbeat_file
-> Sysmon channel filtering
-> core Sysmon event filtering
-> attack chain building
-> extract_chain_features
-> label 생성
-> features/train/test CSV 저장
```

## 현재 feature

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

이 feature들은 `backend/app/services/feature_extractor.py`의 `ML_FEATURE_COLUMNS`와 맞춰져 있습니다.

## 산출물

```text
ml/data/processed/features.csv
ml/data/processed/train.csv
ml/data/processed/test.csv
ml/models/label_encoder.pkl
ml/models/feature_columns.json
ml/models/xgboost_model.json
ml/reports/classification_report.txt
ml/reports/confusion_matrix.png
ml/reports/feature_importance.png
```

## 실행 방법

전처리:

```bash
cd ml/src
python preprocess.py
```

모델 학습:

```bash
scripts/train_model.bat
```

또는 Linux/macOS:

```bash
bash scripts/train_model.sh
```

평가:

```bash
cd ml/src
python evaluate.py
```

## 해석 시 주의점

현재 모델은 `ransom.csv`의 동적 행위 컬럼을 백엔드 feature schema로 축약해서 학습합니다. 따라서 성능 수치는 해당 CSV와 현재 feature mapping 기준의 성능입니다. 운영 환경 일반화 성능을 주장하려면 더 많은 실제 Sysmon/Winlogbeat 로그와 샘플 단위 holdout 검증이 추가로 필요합니다.
