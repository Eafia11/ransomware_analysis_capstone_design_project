# LLM 보고서 생성

## 목적

백엔드는 분석 결과를 사람이 읽기 쉬운 자연어 보고서로 바꿀 수 있도록 두 단계를 제공합니다.

1. 분석 중 `llm_report` 입력 JSON을 생성합니다.
2. `/llm-report/{analysis_id}` API가 OpenAI API를 호출해 Markdown 보고서를 생성합니다.

## LLM 입력 JSON

분석 완료 후 아래 경로에 저장됩니다.

```text
data/reports/{analysis_id}_llm_input.json
```

주요 필드:

```text
schema_version
analysis_id
summary
key_findings
iocs
mitre_attack
suspicious_processes
attack_chain_summaries
reporting_instruction
```

이 JSON은 LLM이 보고서를 쓸 때 사용할 근거 자료입니다. 보고서 생성 시 근거 없는 내용을 만들지 않도록 `reporting_instruction`에 제한을 둡니다.

## OpenAI 보고서 생성

API:

```http
POST /llm-report/{analysis_id}
```

필수 환경 변수:

```text
OPENAI_API_KEY
LLM_MODEL
```

기본 모델:

```text
gpt-5.2
```

생성 산출물:

```text
data/reports/{analysis_id}_ai_report.md
data/reports/{analysis_id}_ai_report_metadata.json
```

## 보고서에 포함되는 내용

- 전체 위험도 요약
- 핵심 탐지 근거
- IOC 목록
- MITRE ATT&CK 해석
- 의심 프로세스와 command line
- 오탐 가능성
- 대응 권고

## 주의점

LLM 보고서는 분석 결과를 설명하는 보조 산출물입니다. 최종 판단은 원본 로그, `rule_results`, `suspicious_results`, IOC, MITRE mapping을 함께 확인해야 합니다.
