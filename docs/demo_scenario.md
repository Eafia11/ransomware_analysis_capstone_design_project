# 데모 시나리오

이 문서는 발표 또는 시연에서 랜섬웨어 분석 파이프라인을 안정적으로 보여주기 위한 순서를 정리한다.

## 시연 목표

```text
분석 VM에서 이벤트 발생
-> Winlogbeat가 Logstash로 전송
-> FastAPI ingest API가 이벤트 저장
-> 분석 실행
-> 프론트엔드에서 위험도, 룰 근거, MITRE evidence, IOC, LLM 입력 JSON 확인
```

## 사전 준비

AWS EC2:

```bash
cd /opt/netguardian
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
curl http://localhost/health
```

분석 VM:

```powershell
Get-Service Sysmon64
Get-Service winlogbeat
Test-NetConnection <EC2_PUBLIC_IP> -Port 5044
```

프론트엔드:

```text
http://<EC2_PUBLIC_IP>/
```

## 정상 파일 오탐 방어 시연

목표: 설치 파일처럼 이벤트가 많은 정상 실행이 바로 high로 올라가지 않는지 확인한다.

1. 정상 설치 파일 또는 샘플 정상 로그를 업로드한다.
2. 분석을 실행한다.
3. 결과 화면에서 위험도가 낮음 또는 중간인지 확인한다.
4. 룰 탐지 근거가 랜섬웨어 특화 행위 없이 일반 이벤트 수만으로 과하게 판단하지 않는지 설명한다.

확인 포인트:

```text
복구 방해 명령 없음
랜섬노트 없음
암호화 확장자 없음
Run key 또는 PowerShell 다운로드 조합 없음
```

## 랜섬웨어 의심 행위 시연

안전한 실습 환경에서 실제 악성코드 대신 행위 재현 스크립트 또는 준비된 샘플 로그를 사용한다.

대표 행위:

```text
vssadmin delete shadows /all /quiet
다량 파일 생성 또는 변경
.locked, .encrypted, .crypt, .enc 확장자 생성
HOW_TO_DECRYPT, RECOVER_FILES 계열 랜섬노트 생성
PowerShell 다운로드 명령
Run key 등록
외부 네트워크 연결
```

분석 흐름:

1. 분석 VM에서 이벤트를 발생시킨다.
2. EC2에서 Logstash 로그를 확인한다.
3. 프론트엔드에서 stream 분석 또는 업로드 분석을 실행한다.
4. 결과 화면에서 위험도, 공격 체인, 룰 근거, MITRE evidence, IOC를 확인한다.
5. LLM 입력 JSON을 다운로드하거나 복사해 자연어 보고서 생성 모듈에 넘긴다.

## 발표 설명 순서

1. 왜 Sysmon/Winlogbeat/Logstash 구조를 선택했는지 설명한다.
2. 백엔드는 단순 로그 저장이 아니라 정규화, 공격 체인 생성, 룰 탐지, ML 보조 판정, IOC 추출, MITRE 매핑을 수행한다고 설명한다.
3. 룰 탐지는 단일 이벤트보다 조합을 더 중요하게 본다고 설명한다.
4. XGBoost는 룰 탐지를 대체하지 않고 보조 신호로 사용한다고 설명한다.
5. MITRE 매핑은 technique ID만 보여주는 것이 아니라 evidence와 confidence를 포함한다고 설명한다.
6. 최종 JSON은 프론트엔드와 LLM 보고서 생성 모듈이 공통으로 사용하는 계약이라고 설명한다.

## 장애 대응 포인트

Winlogbeat 이벤트가 안 들어올 때:

```powershell
.\winlogbeat.exe test output -c .\winlogbeat.yml
Test-NetConnection <EC2_PUBLIC_IP> -Port 5044
```

EC2에서 확인:

```bash
docker compose -f docker-compose.prod.yml logs -f logstash
docker compose -f docker-compose.prod.yml logs -f backend
ls -al data/ingested
```

프론트엔드가 백엔드와 연결되지 않을 때:

```bash
curl http://localhost/health
docker compose -f docker-compose.prod.yml logs -f frontend
```
