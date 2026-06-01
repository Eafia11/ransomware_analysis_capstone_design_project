# 공격 체인 구성 로직

## 목적

공격 체인은 개별 이벤트를 그대로 나열하는 대신, 하나의 프로세스를 중심으로 관련 행위를 묶은 분석 단위입니다. 랜섬웨어는 보통 프로세스 실행, 파일 생성/변경, 레지스트리 변경, 네트워크 연결, 복구 방해 명령 등이 함께 나타나므로 체인 단위 분석이 단일 이벤트 분석보다 설명력이 좋습니다.

## 입력 이벤트

기본 입력은 Winlogbeat가 수집한 Sysmon 이벤트입니다.

```text
Microsoft-Windows-Sysmon/Operational
```

핵심적으로 사용하는 이벤트 예시는 다음과 같습니다.

| Sysmon Event ID | 의미 |
|---:|---|
| 1 | Process Create |
| 3 | Network Connection |
| 11 | File Create |
| 12/13/14 | Registry 변경 |

## 처리 흐름

```text
parsed_events
-> Sysmon channel filtering
-> core Sysmon event filtering
-> process_guid 기준 그룹화
-> parent/child process 정보 보강
-> attack_chains 생성
-> abstracted_attack_chains 생성
```

구현 위치:

```text
backend/app/services/attack_chain_builder.py
```

## 체인에 포함되는 대표 정보

```text
process_guid
image
command_line
parent_image
parent_command_line
actions
```

`actions`에는 프로세스 생성, 파일 생성, 레지스트리 변경, 네트워크 연결 같은 세부 이벤트가 들어갑니다.

## 룰 탐지와의 연결

공격 체인은 `rule_detector.py`에서 점수화됩니다.

주요 판단 기준:

- 의심 프로세스 실행 여부
- 의심 command line 포함 여부
- 파일 생성이 반복되는지
- 레지스트리 변경이 있는지
- 네트워크 연결이 있는지
- 여러 행위 유형이 한 체인에 동시에 나타나는지
- 복구 방해 명령이나 암호화 흔적이 있는지

점수가 임계값을 넘으면 `suspicious`로 분류됩니다.

## ML feature와의 연결

공격 체인은 ML feature 추출의 기준이기도 합니다.

```text
backend/app/services/feature_extractor.py
```

현재 feature는 이벤트 수, 파일 생성 수, 레지스트리 변경 수, 네트워크 연결 수, 의심 프로세스/명령 여부 등 동적 행위 중심입니다.

## 산출물

```text
data/analyzed/{analysis_id}_attack_chains.json
data/analyzed/{analysis_id}_abstracted_attack_chains.json
data/analyzed/{analysis_id}_rule_detection_results.json
data/analyzed/{analysis_id}_suspicious_only.json
```
