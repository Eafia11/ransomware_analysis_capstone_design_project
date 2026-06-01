# ML 파이프라인

## 목적

ML 파이프라인은 정적 PE feature가 아니라 Winlogbeat/Sysmon 로그에서 만들어진 동적 공격 체인 feature를 기반으로 XGBoost 모델을 학습합니다. 백엔드 탐지 로직과 모델 학습 feature를 맞추는 것이 핵심입니다.

`ransom.csv`는 참고용 원본 데이터로 보관할 수 있지만, 현재 백엔드에 직접 연결되는 모델은 `ransom.csv`의 PE feature가 아니라 공격 체인 기반 feature를 사용합니다.

## 입력 데이터

기본 샘플 로그:

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

현재 평가 결과가 높게 나오더라도 샘플 수와 seed row의 영향을 함께 설명해야 합니다. 캡스톤 발표에서는 “운영 탐지 모델”이라기보다 “동적 행위 feature 기반 탐지 보조 모델의 프로토타입”으로 설명하는 것이 안전합니다.
