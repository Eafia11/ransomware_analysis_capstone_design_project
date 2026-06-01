# 문서 읽는 순서

이 폴더는 랜섬웨어 분석 캡스톤 프로젝트를 이해하고 실행, 시연, 배포하기 위한 문서 모음입니다. 처음 보는 사람도 흐름을 따라갈 수 있도록 아래 순서대로 읽는 것을 권장합니다.

## 1. 전체 이해

1. [architecture.md](architecture.md)  
   전체 시스템 구조, 데이터 흐름, 주요 모듈 역할을 설명합니다.

2. [attack_chain_logic.md](attack_chain_logic.md)  
   Sysmon 이벤트를 어떻게 프로세스 중심 공격 체인으로 묶고 의심 행위를 판단하는지 설명합니다.

3. [mitre_mapping.md](mitre_mapping.md)  
   탐지 결과를 MITRE ATT&CK 기법으로 매핑하는 기준을 설명합니다.

## 2. 실행과 기능 확인

4. [api_spec.md](api_spec.md)  
   백엔드 API 목록, 요청/응답 구조, 주요 오류 상황을 정리합니다.

5. [demo_scenario.md](demo_scenario.md)  
   발표나 캡스톤 시연에서 사용할 수 있는 기본 시나리오입니다.

6. [testing.md](testing.md)  
   백엔드 테스트, 프론트엔드 빌드, 통합 검증 방법을 정리합니다.

## 3. 데이터와 모델

7. [ml_pipeline.md](ml_pipeline.md)  
   Winlogbeat/Sysmon 로그에서 ML 피처를 만들고 XGBoost 모델을 학습/평가하는 과정을 설명합니다.

8. [llm_report.md](llm_report.md)  
   분석 결과를 LLM 보고서 입력 JSON으로 만들고, OpenAI API로 자연어 보고서를 생성하는 흐름을 설명합니다.

## 4. 수집과 배포

9. [winlogbeat_setup.md](winlogbeat_setup.md)  
   Windows 분석 VM에서 Winlogbeat와 Sysmon 이벤트를 수집하는 방법입니다.

10. [aws_logstash_setup.md](aws_logstash_setup.md)  
    Winlogbeat 이벤트를 Logstash로 받아 백엔드 `/logs` API에 전달하는 구성을 설명합니다.

11. [aws_windows_sandbox.md](aws_windows_sandbox.md)  
    AWS Windows 샌드박스 실행, 샘플 전송, 로그 분석 자동화 구조를 설명합니다.

12. [deployment.md](deployment.md)  
    Docker Compose, Nginx, Logstash, systemd 기반 운영 배포 방법을 정리합니다.

## 빠른 확인 명령

```powershell
.\scripts\verify.ps1
```

```bash
python -m pytest backend/tests
cd frontend
npm run build
```

현재 기준으로 백엔드 테스트는 `47 passed`, 프론트엔드 빌드는 성공 상태입니다. Docker 실행 검증은 Docker가 설치된 환경에서 별도로 확인해야 합니다.
