# Ransomware Samples

본 디렉토리는 Sysmon 기반 랜섬웨어 행위 분석 프로젝트의 샘플 저장소입니다.
모든 샘플은 **격리된 Windows 가상머신 내부에서만** 압축 해제 및 실행해야 합니다.

> ⚠️ **경고**
> - 호스트(실물 PC)에서 절대 ZIP을 풀거나 실행하지 마십시오.
> - 분석 전 VM 스냅샷을 반드시 생성하고, 네트워크는 host-only 또는 분리된 상태로 구성하십시오.
> - 본 샘플은 **교육 및 연구 목적**으로만 사용됩니다.

---

## 샘플 목록

### 1. mauri870-ransomware.zip

- **원본 레포**: https://github.com/mauri870/ransomware
- **언어**: Go
- **대상 플랫폼**: Windows
- **크기**: 약 75 KB
- **SHA256**: `43346e5dc1511cc29719e657e6a7cad3c4288ec6a6158c7648593fe70d0774c4`
- **Microsoft Defender 탐지명**: `Ransom:Win32/MauriCrypt.MK!MTB`

**개요**
컴퓨터 보안 수업용으로 개발된 학술 crypto-ransomware POC. 백그라운드에서 파일을 탐색하고 AES-256-CTR로 암호화하며, C2 서버와의 키 교환에는 RSA-4096을 사용한다. Windows 환경에서의 실제 랜섬웨어 동작(파일 열람 → 암호화 → 확장자 변경 → 몸값 메모 드롭)을 가장 현실적으로 재현하는 샘플.

**Sysmon 관찰 포인트**
- Event ID 1 (Process Create): 랜섬웨어 프로세스 및 자식 프로세스 생성
- Event ID 11 (FileCreate): 암호화된 파일(`.enc` 등) 생성
- Event ID 23 (FileDelete): 원본 파일 삭제
- Event ID 3 (Network Connect): C2 서버로의 키 교환 트래픽
- Event ID 13 (Registry Set): 지속성 관련 레지스트리 변경 여부

---

### 2. marmos91-ransomware.zip

- **원본 레포**: https://github.com/marmos91/ransomware
- **언어**: Python
- **대상 플랫폼**: Cross-platform (교육/데모용)
- **크기**: 약 35 KB
- **SHA256**: `70e481f1c5f10d5e93c40b3c86cb20364014fac07cf768a8ebe32aeeaace9b78`

**개요**
랜섬웨어 공격을 로컬에서 시뮬레이션하기 위한 단순 데모 도구. 실제 네트워크 동작 없이 파일 암호화/복호화 흐름을 학습하기 위한 용도로 설계되었다. 간단한 구조 덕분에 소스 분석과 이벤트 로그 매핑 학습에 적합하다.

**Sysmon 관찰 포인트**
- Event ID 1: Python 인터프리터 프로세스 실행 (`python.exe` 하위 프로세스)
- Event ID 11: 암호화 파일 생성
- Event ID 23: 원본 파일 삭제
- Event ID 7 (Image Loaded): `cryptography`, `pycryptodome` 등 암호화 모듈 로드 여부

---

### 3. HugoLB0-Ransom0.zip

- **원본 레포**: https://github.com/HugoLB0/Ransom0
- **언어**: Python
- **대상 플랫폼**: Cross-platform
- **크기**: 약 8 KB
- **SHA256**: `422c5055e95987dc032aa5d74ac3cdf03bed1a3f3610ca92241e9aa19606ddb9`

**개요**
사용자 데이터를 탐색하고 암호화하는 단순 구조의 Python 오픈소스 교육용 랜섬웨어. 코드 규모가 작아 가장 먼저 분석하기 좋은 입문용 샘플이다.

**Sysmon 관찰 포인트**
- Event ID 1: `python.exe` 실행 및 인자
- Event ID 11: 순회하며 생성되는 암호화 파일
- Event ID 23: 원본 파일 삭제 이벤트의 연속 발생 패턴
- Event ID 2 (File Creation Time Changed): 타임스탬프 조작 여부

---

## 법적·윤리적 고지

- 본 샘플은 오픈소스로 공개된 **교육/연구 목적**의 코드이며, 실제 피해 사례와는 무관하다.
- 타인의 시스템, 네트워크, 데이터에 대한 무단 실행은 법적 책임을 수반한다.
- 본 프로젝트는 대학 캡스톤 디자인의 일환으로, 방어적 보안 연구(탐지·분석) 목적에 한해 샘플을 사용한다.
