# AWS Windows 샌드박스

## 목적

AWS Windows 인스턴스를 임시 샌드박스로 사용해 샘플을 실행하고, 수집된 로그를 분석 파이프라인으로 연결하는 선택 기능입니다. 발표 시 필수 기능은 아니며, 네트워크와 AWS 환경에 영향을 받으므로 안정적인 시연에는 저장된 샘플 로그 사용을 권장합니다.

## API

샌드박스 실행:

```http
POST /sandbox/run
```

상태 조회:

```http
GET /sandbox/status/{session_id}
```

두 API 모두 `X-NetGuardian-Api-Key` 헤더가 필요합니다.

## 상태 흐름

```text
queued
-> launching
-> waiting_for_ssh
-> transferring
-> running
-> terminating
-> analyzing_logs
-> terminated
```

오류 발생 시:

```text
failed
```

## 환경 변수

```text
NETGUARDIAN_API_KEY
AWS_REGION
NG_WINDOWS_AMI_ID
NG_WINDOWS_KEY_NAME
NG_WINDOWS_SUBNET_ID
NG_WINDOWS_SECURITY_GROUP_IDS
NG_WINDOWS_INSTANCE_TYPE
NG_WINDOWS_SSH_USERNAME
NG_WINDOWS_SSH_PASSWORD
NG_WINDOWS_SSH_KEY_PATH
NG_WINDOWS_REMOTE_SAMPLE_DIR
SANDBOX_RUNTIME_SECONDS
SANDBOX_MAX_ACTIVE_SESSIONS
SANDBOX_SSH_WAIT_SECONDS
SANDBOX_LOG_WAIT_SECONDS
SANDBOX_LOG_POLL_INTERVAL_SECONDS
SANDBOX_TERMINATE_WAIT
```

## 내부 처리

구현 위치:

```text
backend/app/services/sandbox_service.py
```

처리 개요:

```text
sample upload
-> sandbox session 생성
-> Windows EC2 instance 시작
-> SSH 대기
-> sample 전송
-> 제한 시간 동안 실행
-> instance 종료
-> ingested log slice 분석
-> analysis_result 저장
```

## 보안 주의

- 실제 악성 샘플은 격리된 네트워크에서만 실행합니다.
- 샌드박스 보안 그룹은 최소 권한으로 구성합니다.
- 실행 후 인스턴스 종료와 세션 상태를 반드시 확인합니다.
- 샘플 파일, 로그, API key, SSH key는 외부 저장소에 노출하지 않습니다.

## 시연 권장 방식

실시간 AWS 샌드박스 실행은 실패 변수가 많습니다. 발표에서는 다음 순서를 권장합니다.

1. 저장된 샘플 로그로 기본 분석 흐름을 시연합니다.
2. 샌드박스 API와 상태 흐름을 화면 또는 문서로 설명합니다.
3. 시간이 충분하고 네트워크가 안정적일 때만 실제 실행을 선택합니다.
