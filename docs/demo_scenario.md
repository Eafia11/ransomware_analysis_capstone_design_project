# 시연 시나리오

## 목표

캡스톤 발표에서 “로그 업로드 → 분석 → 탐지 결과 → MITRE/IOC → LLM 보고서” 흐름을 짧고 안정적으로 보여주는 시나리오입니다.

## 사전 준비

필수:

```text
Python dependencies 설치
backend 실행 가능
frontend build 가능
collector/sample_inputs/winlogbeat_sample-20260415.jsonl 존재
```

선택:

```text
OPENAI_API_KEY 설정
Docker 설치
AWS sandbox 환경 구성
```

## 1. 백엔드 실행

```bash
scripts/run_backend.bat
```

API 문서:

```text
http://127.0.0.1:8000/docs
```

상태 확인:

```bash
curl http://127.0.0.1:8000/health
```

## 2. 샘플 로그 분석

```bash
python collector/scripts/send_sample_log.py --analyze
```

이 명령은 다음 과정을 한 번에 수행합니다.

```text
POST /upload
POST /analyze/{analysis_id}
```

분석 결과에서 설명할 포인트:

- `risk_level`
- `key_findings`
- `iocs`
- `mitre_attack`
- `suspicious_results`
- `artifact_paths`

## 3. 산출물 확인

```text
data/parsed/
data/normalized/
data/analyzed/
data/reports/
```

가장 설명하기 좋은 파일:

```text
data/reports/{analysis_id}_analysis_report.json
data/reports/{analysis_id}_llm_input.json
data/analyzed/{analysis_id}_suspicious_only.json
```

## 4. 프론트엔드 확인

개발 서버:

```bash
cd frontend
npm run dev
```

빌드 검증:

```bash
cd frontend
npm run build
```

## 5. LLM 보고서 생성

`.env` 또는 실행 환경에 다음 값이 필요합니다.

```text
OPENAI_API_KEY
LLM_MODEL=gpt-5.2
NETGUARDIAN_API_KEY
```

API:

```http
POST /llm-report/{analysis_id}
```

생성 파일:

```text
data/reports/{analysis_id}_ai_report.md
```

## 발표 설명 순서

1. Winlogbeat/Sysmon 로그를 수집한다.
2. 백엔드가 이벤트를 파싱하고 정규화한다.
3. Sysmon 핵심 이벤트로 공격 체인을 만든다.
4. 룰 기반 탐지와 ML 보조 판정을 수행한다.
5. IOC와 MITRE ATT&CK mapping을 생성한다.
6. 프론트엔드와 LLM 보고서가 사용할 수 있는 JSON 산출물을 저장한다.

## 안전한 시연 원칙

- 발표 현장에서는 실제 악성코드를 실행하지 않습니다.
- 이미 수집된 샘플 로그를 사용합니다.
- 샌드박스 기능은 네트워크/클라우드 상태에 따라 실패할 수 있으므로 선택 시연으로 둡니다.
