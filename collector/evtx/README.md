# EVTX 로그 보관 폴더

이 폴더는 Windows Event Log 원본 `.evtx` 파일을 임시로 보관하기 위한 위치입니다.

현재 백엔드 `/upload` API는 다음 형식의 정규화된 로그 파일을 분석합니다.

```text
.json
.jsonl
.log
.txt
```

따라서 `.evtx` 파일은 직접 업로드하기보다 Winlogbeat/Sysmon JSON 또는 JSONL 형식으로 변환한 뒤 분석에 사용해야 합니다.

권장 흐름:

```text
Windows Event Log export (.evtx)
-> Winlogbeat/Sysmon JSON 또는 JSONL 변환
-> /upload 또는 collector/scripts/send_sample_log.py로 분석
```

샘플 분석에는 아래 파일을 사용할 수 있습니다.

```text
collector/sample_inputs/winlogbeat_sample-20260415.jsonl
```
