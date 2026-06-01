# MITRE ATT&CK 매핑

## 목적

MITRE ATT&CK 매핑은 탐지 결과를 보안 분석가가 이해하기 쉬운 전술/기법 체계로 바꾸기 위한 단계입니다. 이 프로젝트에서는 의심 체인의 command line, process image, file path, registry key, event id 등을 기준으로 technique을 매핑합니다.

구현 위치:

```text
backend/app/services/mitre_mapper.py
```

## 처리 흐름

```text
rule_results
-> map_action_to_mitre
-> map_chain_to_mitre
-> enrich_results_with_mitre
-> suspicious_results / llm_report에 포함
```

## 현재 매핑 예시

| Technique ID | Technique | Tactic | 주요 근거 |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | `powershell`, `encodedcommand`, `Invoke-WebRequest` |
| T1059.003 | Windows Command Shell | Execution | `cmd.exe`, `cmd /c` |
| T1105 | Ingress Tool Transfer | Command and Control | `certutil`, `bitsadmin`, `curl`, `wget` |
| T1003 | OS Credential Dumping | Credential Access | `mimikatz`, `lsass`, `procdump` |
| T1087 | Account Discovery | Discovery | `net user`, `whoami /all` |
| T1053.005 | Scheduled Task | Execution | `schtasks`, `Register-ScheduledTask` |
| T1543.003 | Windows Service | Persistence | `sc create`, `New-Service` |
| T1218 | System Binary Proxy Execution | Defense Evasion | `mshta`, `rundll32`, `regsvr32` |
| T1490 | Inhibit System Recovery | Impact | `vssadmin`, `delete shadows`, `wbadmin` |
| T1486 | Data Encrypted for Impact | Impact | `.locked`, `.encrypted`, ransom note |
| T1112 | Modify Registry | Defense Evasion | Sysmon 12/13/14, `reg add`, `reg delete` |

## confidence 기준

```text
low     keyword 1개만 매칭
medium  event id 매칭 또는 keyword 2개 이상
high    event id와 keyword가 함께 매칭
```

같은 technique이 여러 action에서 반복되면 evidence를 병합하고 더 높은 confidence를 유지합니다.

## 한계

현재 매핑은 룰 기반입니다. 실제 운영 수준으로 확장하려면 다음 보강이 필요합니다.

- 더 많은 ATT&CK technique rule 추가
- command line parser 정교화
- benign admin activity와 malicious activity 구분 강화
- event id별 context 기반 confidence 조정
