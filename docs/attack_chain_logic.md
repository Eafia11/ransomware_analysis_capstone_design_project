# 공격 체인 구성 로직

## 1. 목적

공격 체인 구성 로직은 개별 Windows 이벤트를 프로세스 중심의 행위 묶음으로 재구성하기 위한 기능이다. 단일 이벤트만으로는 공격 흐름을 이해하기 어렵기 때문에, 같은 프로세스에서 발생한 실행, 파일 생성, 레지스트리 수정, 네트워크 연결 등을 하나의 후보 체인으로 묶는다.

구현 위치:

```text
backend/app/services/attack_chain_builder.py
```

## 2. 입력 데이터

입력은 정규화된 Sysmon 이벤트 목록이다. 현재 핵심 이벤트로 사용하는 Sysmon Event ID는 다음과 같다.

```text
1   Process Create
3   Network Connection
11  File Create
12  Registry Object Create/Delete
13  Registry Value Set
14  Registry Object Rename
```

이벤트 필터링 함수:

```text
filter_core_sysmon_events()
```

## 3. 그룹핑 기준

이벤트를 공격 체인 후보로 묶을 때 우선순위는 다음과 같다.

1. `ProcessGuid`가 존재하고 `{GUID-REDACTED}`가 아니면 `ProcessGuid` 기준으로 그룹핑
2. Process Create 이벤트인 경우 `process_id + image + command_line` 기준으로 그룹핑
3. 그 외 이벤트는 `process_id + image + parent_image + user + timestamp bucket` 기준으로 fallback 그룹핑

이 구조는 실제 로그에서 `ProcessGuid`가 마스킹되거나 누락되는 경우를 고려한 방어적인 방식이다.

## 4. 프로세스 인덱스

`build_process_index()`는 Process Create 이벤트를 기반으로 다음 두 가지 맵을 만든다.

```text
process_info_map: process_guid -> process metadata
children_map: parent_process_guid -> child process guid list
```

이를 통해 각 체인에 부모 프로세스와 자식 프로세스 정보를 연결한다.

## 5. 체인 결과 구조

공격 체인 후보는 다음 필드를 포함한다.

```json
{
  "group_key": "...",
  "process_guid": "...",
  "process_id": "...",
  "image": "...",
  "command_line": "...",
  "parent_process": {},
  "child_processes": [],
  "user": "...",
  "start_time": "...",
  "event_count": 0,
  "actions": []
}
```

`actions`는 각 이벤트를 분석에 필요한 형태로 축약한 목록이다.

```json
{
  "timestamp": "...",
  "event_id": "1",
  "event_type": "ProcessCreate",
  "image": "...",
  "command_line": "...",
  "target_filename": "...",
  "target_object": "...",
  "destination_ip": "...",
  "destination_port": "...",
  "details": "..."
}
```

## 6. 추상화된 체인

`build_abstracted_attack_chains()`는 LLM과 프론트엔드가 읽기 쉬운 요약 형태의 체인을 만든다.

예시:

```text
Process execution: C:\Windows\System32\cmd.exe | command: cmd /c ...
Network connection: powershell.exe -> 8.8.8.8:443
File created: C:\Users\Public\payload.exe
Registry value changed: HKCU\Software\...\Run
```

## 7. 한계와 개선 방향

현재 로직은 단일 프로세스 중심의 행위 묶음에 가깝다. 실제 공격 시나리오에서는 여러 프로세스가 부모-자식 관계로 이어지므로, 향후에는 다음 개선이 가능하다.

- parent-child tree 기반 전체 공격 그래프 생성
- 시간 범위 기반 세션 구성
- 사용자 계정 기준 행위 묶음 추가
- 네트워크 IOC와 프로세스 체인 연계 강화
- LLM 보고서용 evidence selection 고도화
