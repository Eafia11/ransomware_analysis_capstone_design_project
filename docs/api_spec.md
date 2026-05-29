# API 명세서

## 1. 스펙 고정 기준

본 문서는 프론트엔드와 LLM 보고서 생성 모듈이 의존하는 백엔드 API 계약이다. 별도 합의 없이 아래 필드명과 타입을 변경하지 않는다.

기본 주소:

```text
http://127.0.0.1:8000
```

상태 값:

```text
uploaded | analyzing | completed | failed
```

위험도 값:

```text
low | medium | high
```

## 2. 상태 확인

### GET `/health`

서버 상태와 저장된 분석 건수를 반환한다.

응답 필드:

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `status` | string | 정상일 때 `ok` |
| `service` | string | 서비스 이름 |
| `stored_analyses` | integer | DB에 저장된 분석 레코드 수 |

응답 예시:

```json
{
  "status": "ok",
  "service": "Ransomware Analysis Backend",
  "stored_analyses": 0
}
```

## 3. 로그 업로드

### POST `/upload`

Winlogbeat JSON/JSONL 로그 파일을 업로드하고 `analysis_id`를 발급한다.

요청 형식:

```text
multipart/form-data
file: 업로드할 로그 파일
```

허용 확장자:

```text
.json, .jsonl, .log, .txt
```

응답 필드:

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `analysis_id` | string | UUID 형식 분석 ID |
| `filename` | string | 원본 파일명 |
| `saved_path` | string | 서버에 저장된 파일 경로 |
| `sha256` | string | 업로드 파일 SHA-256 |
| `status` | string | 최초 상태, 항상 `uploaded` |

응답 예시:

```json
{
  "analysis_id": "0bce1b2e-e2ea-4127-b9ea-d612e27ceef9",
  "filename": "winlogbeat_sample.json",
  "saved_path": "data/uploads/0bce1b2e-e2ea-4127-b9ea-d612e27ceef9_winlogbeat_sample.json",
  "sha256": "64-char-sha256",
  "status": "uploaded"
}
```

실패 조건:

| 상태 코드 | 조건 |
| --- | --- |
| `400` | 파일명 없음, 빈 파일, 허용되지 않은 확장자, 최대 크기 초과 |

## 4. 분석 실행

### POST `/analyze/{analysis_id}`

업로드된 로그를 분석한다. `uploaded` 또는 `failed` 상태일 때만 실제 분석을 수행한다. 이미 `analyzing` 또는 `completed` 상태이면 기존 상태와 결과를 반환한다.

응답 필드:

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `analysis_id` | string | 분석 ID |
| `status` | string | 분석 상태 |
| `message` | string | 처리 메시지 |
| `result` | object \| null | 분석 결과. 완료 전에는 null 가능 |

응답 예시:

```json
{
  "analysis_id": "0bce1b2e-e2ea-4127-b9ea-d612e27ceef9",
  "status": "completed",
  "message": "Analysis completed.",
  "result": {
    "summary": {},
    "risk_level": "high",
    "key_findings": [],
    "iocs": {},
    "llm_report": {},
    "attack_chains": [],
    "abstracted_attack_chains": [],
    "rule_results": [],
    "suspicious_results": [],
    "artifact_paths": {}
  }
}
```

실패 조건:

| 상태 코드 | 조건 |
| --- | --- |
| `404` | 존재하지 않는 `analysis_id` |
| `500` | 분석 중 예외 발생. DB 상태는 `failed`로 저장 |

## 5. 결과 조회

### GET `/result/{analysis_id}`

분석 레코드와 저장된 결과를 조회한다.

응답 필드:

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `analysis_id` | string | 분석 ID |
| `filename` | string | 업로드 파일명 |
| `saved_path` | string | 업로드 파일 저장 경로 |
| `sha256` | string | 업로드 파일 SHA-256 |
| `status` | string | 분석 상태 |
| `result` | object \| null | 분석 결과 |
| `error` | string \| null | 실패 사유 |

응답 예시:

```json
{
  "analysis_id": "0bce1b2e-e2ea-4127-b9ea-d612e27ceef9",
  "filename": "winlogbeat_sample.json",
  "saved_path": "data/uploads/0bce1b2e-e2ea-4127-b9ea-d612e27ceef9_winlogbeat_sample.json",
  "sha256": "64-char-sha256",
  "status": "completed",
  "result": {},
  "error": null
}
```

## 6. `result` 객체

`/analyze/{analysis_id}`와 `/result/{analysis_id}`의 `result` 필드는 동일한 구조를 사용한다.

고정 필드:

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `summary` | object | 이벤트 수, 체인 수, 위험도 요약 |
| `risk_level` | string \| null | `low`, `medium`, `high` |
| `key_findings` | array[string] | 핵심 분석 문장 |
| `iocs` | object | IOC 목록 |
| `llm_report` | object | LLM 보고서 생성용 축약 JSON |
| `attack_chains` | array[object] | 상세 공격 체인 |
| `abstracted_attack_chains` | array[object] | 사람이 읽기 쉬운 공격 체인 요약 |
| `rule_results` | array[object] | 룰/ML 탐지 결과 |
| `suspicious_results` | array[object] | 의심으로 분류된 결과 |
| `artifact_paths` | object | 저장된 산출물 경로 |

### 6.1 `summary`

```json
{
  "parsed_events": 14178,
  "sysmon_events": 3567,
  "sysmon_core_events": 1922,
  "attack_chains": 1908,
  "suspicious_chains": 3,
  "risk_level": "high",
  "ioc_counts": {
    "ips": 5,
    "domains": 8,
    "urls": 23,
    "hashes": 167,
    "file_paths": 198,
    "registry_keys": 0,
    "ransom_notes": 2,
    "encrypted_extensions": 4,
    "suspicious_file_names": 3,
    "bitcoin_addresses": 1,
    "email_addresses": 1
  },
  "events_by_type": {
    "total": 14178,
    "by_channel": {},
    "by_provider": {},
    "by_event_id": {}
  }
}
```

### 6.2 `iocs`

아래 6개 키는 항상 유지한다.

```json
{
  "ips": [],
  "domains": [],
  "urls": [],
  "hashes": [],
  "file_paths": [],
  "registry_keys": [],
  "ransom_notes": [],
  "encrypted_extensions": [],
  "suspicious_file_names": [],
  "bitcoin_addresses": [],
  "email_addresses": []
}
```

### 6.3 `rule_results[]`

룰 탐지와 ML 예측이 결합된 체인별 결과다.

```json
{
  "process_guid": "{GUID}",
  "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "command_line": "powershell.exe ...",
  "parent_image": "C:\\Windows\\System32\\cmd.exe",
  "user": "HOST\\user",
  "start_time": "2026-05-25T10:00:00Z",
  "event_count": 6,
  "features": {
    "event_count": 6,
    "process_create_count": 1,
    "file_create_count": 3,
    "registry_modify_count": 1,
    "network_connect_count": 1,
    "uses_suspicious_process": 1,
    "uses_suspicious_command": 1,
    "has_multiple_behaviors": 1
  },
  "score": 11,
  "label": "suspicious",
  "reasons": [],
  "actions": [],
  "mitre_attack": [
    {
      "technique_id": "T1490",
      "technique": "Inhibit System Recovery",
      "tactic": "Impact",
      "evidence": ["vssadmin delete shadows /all /quiet"],
      "confidence": "low"
    }
  ],
  "ml_result": {
    "enabled": true,
    "label": "suspicious",
    "confidence": 0.96,
    "reason": null,
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
}
```

`ml_result.enabled`가 `false`일 수 있는 경우:

- 모델 파일 없음
- XGBoost 미설치
- 모델 피처 수와 백엔드 피처 수 불일치

### 6.4 `llm_report`

LLM 보고서 생성 담당 모듈이 우선적으로 사용해야 하는 입력 객체다.

```json
{
  "schema_version": "1.0",
  "analysis_id": "0bce1b2e-e2ea-4127-b9ea-d612e27ceef9",
  "summary": {},
  "key_findings": [],
  "iocs": {},
  "mitre_attack": [],
  "suspicious_processes": [],
  "attack_chain_summaries": [],
  "reporting_instruction": "Write a concise ransomware analysis report..."
}
```

### 6.5 `artifact_paths`

아래 키는 분석 완료 시 유지한다.

```json
{
  "parsed_events": "data/parsed/{analysis_id}_parsed_logs.json",
  "sysmon_events": "data/normalized/{analysis_id}_sysmon_only.json",
  "sysmon_core_events": "data/normalized/{analysis_id}_sysmon_core.json",
  "attack_chains": "data/analyzed/{analysis_id}_attack_chains.json",
  "abstracted_attack_chains": "data/analyzed/{analysis_id}_abstracted_attack_chains.json",
  "rule_results": "data/analyzed/{analysis_id}_rule_detection_results.json",
  "suspicious_results": "data/analyzed/{analysis_id}_suspicious_only.json",
  "llm_report": "data/reports/{analysis_id}_llm_input.json",
  "report": "data/reports/{analysis_id}_analysis_report.json"
}
```

## 7. 프론트엔드/LLM 연동 기준

프론트엔드는 우선 아래 필드를 사용한다.

```text
result.summary
result.risk_level
result.key_findings
result.iocs
result.rule_results
result.suspicious_results
result.artifact_paths
```

LLM 보고서 생성 모듈은 아래 필드를 사용한다.

```text
result.llm_report
```

LLM 입력 파일 경로:

```text
result.artifact_paths.llm_report
```

## 8. 테스트용 호출

백엔드 실행:

```bash
scripts/run_backend.bat
```

샘플 업로드 및 분석:

```bash
python collector/scripts/send_sample_log.py --analyze
```

자동화 테스트:

```bash
cd backend
python -m pytest -q
```

## 8. 실시간 ingest API

### 8.1 `POST /ingest/winlogbeat`

Logstash HTTP output이 Winlogbeat 이벤트를 전달하는 엔드포인트다. 요청 본문은 Winlogbeat 이벤트 JSON 1건이다.

요청 예시:

```json
{
  "@timestamp": "2026-05-25T10:00:00Z",
  "agent": {
    "name": "analysis-vm-01",
    "type": "winlogbeat"
  },
  "winlog": {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "event_id": 1,
    "event_data": {
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -NoProfile"
    }
  }
}
```

응답 예시:

```json
{
  "analysis_id": "stream-analysis-vm-01",
  "stream_id": "analysis-vm-01",
  "status": "uploaded",
  "event_count": 1,
  "saved_path": "data/ingested/analysis-vm-01.jsonl"
}
```

빈 JSON 객체는 `400`으로 거절한다.

### 8.2 `POST /analyze/stream/{analysis_id}`

ingest API로 누적된 JSONL 파일을 분석한다. 기존 업로드 분석 API와 같은 응답 구조를 사용한다.

```text
POST /analyze/stream/stream-analysis-vm-01
```

분석 중 예외가 발생하면 분석 레코드 상태는 `failed`로 저장되고 API는 `500`을 반환한다.

## 9. 테스트와 검증

백엔드 테스트:

```bash
python -m pytest backend/tests
```

프론트엔드 빌드:

```bash
cd frontend
npm run build
```

PowerShell 통합 검증:

```powershell
.\scripts\verify.ps1
```
