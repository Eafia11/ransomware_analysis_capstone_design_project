# API 명세

기본 주소:

```text
http://127.0.0.1:8000
```

운영 배포에서는 Nginx를 통해 `http://<server>/`로 접근합니다.

## 인증

일부 API는 `X-NetGuardian-Api-Key` 헤더가 필요합니다.

```http
X-NetGuardian-Api-Key: <NETGUARDIAN_API_KEY>
```

적용 대상:

- `POST /ingest/winlogbeat`
- `POST /sandbox/run`
- `GET /sandbox/status/{session_id}`
- `POST /llm-report/{analysis_id}`

`POST /logs`는 내부 네트워크 요청이거나 API key가 있는 요청만 허용합니다.

## 상태 확인

```http
GET /health
```

응답:

```json
{
  "status": "ok",
  "service": "Ransomware Analysis Backend",
  "stored_analyses": 0
}
```

## 로그 업로드

```http
POST /upload
Content-Type: multipart/form-data
```

form field:

```text
file=<Winlogbeat JSON/JSONL file>
```

허용 확장자:

```text
.json, .jsonl, .log, .txt
```

응답:

```json
{
  "analysis_id": "...",
  "filename": "winlogbeat_sample-20260415.jsonl",
  "saved_path": "data/uploads/...",
  "sha256": "...",
  "status": "uploaded"
}
```

## 분석 실행

```http
POST /analyze/{analysis_id}
```

업로드된 로그를 분석합니다. 이미 완료된 분석이면 기존 결과를 반환합니다.

응답의 핵심 필드:

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

## 결과 조회

```http
GET /result/{analysis_id}
```

분석 상태와 결과를 조회합니다.

상태값:

```text
uploaded
analyzing
completed
failed
```

## Winlogbeat 이벤트 수신

```http
POST /ingest/winlogbeat
```

쿼리 파라미터:

```text
stream_id=<optional>
analysis_id=<optional>
```

단일 Winlogbeat 이벤트 JSON을 받아 `data/ingested/`에 누적 저장합니다.

Logstash 연동용 endpoint:

```http
POST /logs
```

Logstash pipeline은 이 endpoint로 이벤트를 전달합니다.

## Ingest stream 분석

```http
POST /analyze/stream/{analysis_id}
```

`/ingest/winlogbeat` 또는 `/logs`로 생성된 분석 레코드를 기존 분석 흐름과 동일하게 처리합니다.

## LLM 보고서 생성

```http
POST /llm-report/{analysis_id}
```

조건:

- 분석 상태가 `completed`여야 합니다.
- 분석 결과에 `llm_report` 입력 JSON이 있어야 합니다.
- `.env`에 `OPENAI_API_KEY`가 설정되어 있어야 합니다.

응답:

```json
{
  "analysis_id": "...",
  "status": "completed",
  "provider": "openai",
  "model": "gpt-5.2",
  "response_id": "...",
  "report": "...",
  "saved_path": "data/reports/..._ai_report.md",
  "metadata_path": "data/reports/..._ai_report_metadata.json"
}
```

## AWS Windows 샌드박스

```http
POST /sandbox/run
```

form field:

```text
file=<executable or sample>
runtime_seconds=<optional>
```

응답 상태 코드는 `202 Accepted`입니다. 실제 실행과 분석은 background task로 진행됩니다.

상태 조회:

```http
GET /sandbox/status/{session_id}
```

샌드박스 상태값:

```text
queued
launching
waiting_for_ssh
transferring
running
terminating
analyzing_logs
terminated
failed
```

## 주요 오류

| 상황 | HTTP status |
|---|---:|
| 없는 analysis_id | 404 |
| 빈 이벤트 본문 | 400 |
| 허용되지 않는 파일 | 400 |
| API key 누락 | 401/403 |
| 분석 전 LLM 보고서 요청 | 409 |
| 분석 처리 실패 | 500 |
