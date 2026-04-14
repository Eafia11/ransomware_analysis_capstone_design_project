# Ransomware Samples

본 디렉토리는 Sysmon 기반 랜섬웨어 행위 분석 프로젝트의 샘플 저장소입니다.
모든 샘플은 **격리된 Windows 가상머신 내부에서만** 압축 해제 및 실행해야 합니다.

> ⚠️ **경고**
> - 호스트(실물 PC)에서 절대 ZIP을 풀거나 실행하지 마십시오.
> - 분석 전 VM 스냅샷을 반드시 생성하고, 네트워크는 host-only 또는 분리된 상태로 구성하십시오.
> - 본 샘플은 **교육 및 연구 목적**으로만 사용됩니다.
> - 본 파일들은 **실제 범죄 활동에서 수집된 라이브 랜섬웨어 바이너리**입니다. 더블클릭 즉시 암호화가 시작되며 복구가 불가능할 수 있습니다.

## 공통 정보

- **출처**: [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/)
- **파일 형식**: AES-256 암호화 ZIP
- **압축 해제 비밀번호**: `infected`
- **ZIP 내부**: Windows PE 바이너리 (`.exe`) — 별도 빌드 불필요, 즉시 실행 가능

> 🔒 **GitHub에는 바이너리를 커밋하지 않습니다.** 본 저장소의 `mal_sample/.gitignore`에 의해 `*.zip`, `*.exe` 등이 제외됩니다. 샘플은 아래 "샘플 다운로드 방법" 절차에 따라 **본인 VM에서 직접** 다운로드하십시오.

---

## 샘플 다운로드 방법

### 1단계: MalwareBazaar API 키 발급
1. https://auth.abuse.ch/ 에서 무료 계정 생성
2. 로그인 → Profile → **Auth-Key** 발급
3. 키를 안전하게 보관 (절대 Git에 커밋 금지)

### 2단계: VM 내부에서 다운로드

**반드시 Windows 가상머신 내부에서 실행하십시오.** 호스트 PC에 바이너리가 생성되면 Windows Defender 또는 OneDrive 동기화로 인해 문제가 발생할 수 있습니다.

```bash
# 환경 변수로 API 키 설정
export MB_API_KEY="여러분의_Auth-Key"

# ClearWater 샘플 다운로드
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -H "Auth-Key: $MB_API_KEY" \
  -d "query=get_file&sha256_hash=00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746" \
  -o ClearWater_00202340.zip

# PCLocker 샘플 다운로드
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -H "Auth-Key: $MB_API_KEY" \
  -d "query=get_file&sha256_hash=214aef60ec3145deea73c796bd025967cda84182041a0c76b56ce6c61304a64e" \
  -o PCLocker_214aef60.zip
```

PowerShell을 사용하는 경우:

```powershell
$headers = @{ "Auth-Key" = "여러분의_Auth-Key" }

# ClearWater
Invoke-WebRequest -Uri "https://mb-api.abuse.ch/api/v1/" -Method POST -Headers $headers `
  -Body "query=get_file&sha256_hash=00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746" `
  -OutFile ClearWater_00202340.zip

# PCLocker
Invoke-WebRequest -Uri "https://mb-api.abuse.ch/api/v1/" -Method POST -Headers $headers `
  -Body "query=get_file&sha256_hash=214aef60ec3145deea73c796bd025967cda84182041a0c76b56ce6c61304a64e" `
  -OutFile PCLocker_214aef60.zip
```

### 3단계: 무결성 검증 (필수)

다운로드 후 SHA256 해시가 본 문서의 값과 일치하는지 확인하십시오.

```bash
sha256sum ClearWater_00202340.zip PCLocker_214aef60.zip
```

> 참고: ZIP 자체 해시는 다운로드 시점에 따라 달라질 수 있으나, ZIP 내부의 `.exe` 해시는 본 문서의 "MalwareBazaar SHA256" 값과 **반드시 일치**해야 합니다. 일치하지 않으면 변조된 파일이므로 즉시 폐기하십시오.

### 4단계: 압축 해제

- 도구: 7-Zip (권장) 또는 WinRAR
- 비밀번호: `infected`
- **반드시 VM 내부에서만** 해제하십시오.

---

## 샘플 목록

### 1. ClearWater_00202340.zip

- **패밀리**: ClearWater
- **내부 파일명**: `zeksmi_x64.exe`
- **파일 형식**: PE32+ (Windows 64-bit)
- **아키텍처**: AMD64
- **파일 크기 (원본 `.exe`)**: 약 1,007,049 bytes
- **ZIP 크기**: 약 913 KB
- **MalwareBazaar SHA256**: `00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746`
- **MD5**: `cf4840ae85d7acba4974d6dd55893d6c`
- **SHA1**: `82357963420e55a3e99cfe20bd5bea6ddfa32a54`
- **Imphash**: `22e7125b95acf497b07e79559bdc556c`
- **First Seen**: 2026-03-31
- **ClamAV 시그니처**: `SecuriteInfo.com.Win64.Malware-gen.13916474`
- **MalwareBazaar URL**: https://bazaar.abuse.ch/sample/00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746/

**개요**
MalwareBazaar에 ClearWater 패밀리로 분류된 실제 Windows 랜섬웨어. Microsoft Visual C++로 컴파일된 64비트 PE 실행 파일로, 즉시 실행되어 파일 암호화를 수행한다. 별도의 빌드나 인터프리터 없이 VM에서 바로 실행 가능하기 때문에 Sysmon 이벤트 로그 수집 실험의 기준 샘플로 적합하다.

**Sysmon 관찰 포인트**
- Event ID 1 (Process Create): `zeksmi_x64.exe` 실행, Parent 프로세스 및 명령행 인자
- Event ID 7 (Image Loaded): 암호화/시스템 API DLL 로드 (`bcrypt.dll`, `advapi32.dll`)
- Event ID 11 (FileCreate): 암호화본 파일 생성 — 확장자 변경 패턴 관찰
- Event ID 23 (FileDelete): 원본 파일 대량 삭제 이벤트
- Event ID 3 (Network Connect): C2 통신 여부
- Event ID 13 (Registry Set): `Run` 키 등록 / 지속성 설정
- Event ID 22 (DNS Query): C2 도메인 쿼리 기록

---

### 2. PCLocker_214aef60.zip

- **패밀리**: PCLocked / RustyStealer
- **내부 파일명**: `PCLocker.exe`
- **파일 형식**: PE32+ (Windows 64-bit)
- **아키텍처**: AMD64
- **파일 크기 (원본 `.exe`)**: 약 756,736 bytes
- **ZIP 크기**: 약 327 KB
- **MalwareBazaar SHA256**: `214aef60ec3145deea73c796bd025967cda84182041a0c76b56ce6c61304a64e`
- **MD5**: `5b3f36f15838ad75e24b0b6a4ada1876`
- **SHA1**: `83f949e3adc2228f441eb087bd164755b1673677`
- **Imphash**: `0cc76de9d55e7b43542e5f9378f32ac0`
- **First Seen**: 2026-03-24
- **ClamAV 시그니처**: `SecuriteInfo.com.Win64.MalwareX-gen.44427617`
- **MalwareBazaar URL**: https://bazaar.abuse.ch/sample/214aef60ec3145deea73c796bd025967cda84182041a0c76b56ce6c61304a64e/

**개요**
PCLocked 계열 랜섬웨어로, 분석 결과 RustyStealer 관련 태그가 함께 부여되어 있어 **정보 탈취 + 파일 암호화** 복합 행위를 수행할 것으로 추정된다. Rust로 작성된 바이너리 특성상 정적 분석이 까다롭지만, Sysmon 기반 동적 관찰에는 유리하다.

**Sysmon 관찰 포인트**
- Event ID 1: `PCLocker.exe` 프로세스 생성 (Parent 및 인자)
- Event ID 7: Rust 런타임 및 crypto 관련 라이브러리 로드
- Event ID 11: 파일 생성 이벤트 — 암호화본 확장자 패턴
- Event ID 23: 원본 파일 삭제 이벤트
- Event ID 3: 외부 통신(스틸러 기능 연관 가능성)
- Event ID 22: DNS 쿼리 기록
- Event ID 10 (ProcessAccess): 다른 프로세스 메모리 접근 (인젝션 여부)
- Event ID 13: 레지스트리 기반 지속성

---

## 실행 환경 체크리스트

| 항목 | 요건 |
|---|---|
| Hypervisor | VMware Workstation / VirtualBox |
| Guest OS | Windows 10 / 11 (분석 전용 이미지) |
| 스냅샷 | 실행 직전 생성, 종료 후 롤백 |
| 네트워크 | Host-only 또는 Isolated (완전 격리 권장) |
| Windows Defender | VM 내부에서 일시 비활성화 |
| Sysmon | 최신 버전 + SwiftOnSecurity sysmon-config |
| 로그 수집 | `Microsoft-Windows-Sysmon/Operational` 이벤트 채널 |
| 압축 해제 도구 | 7-Zip (비밀번호: `infected`) |

## 분석 절차 (VM 내부)

1. VM 스냅샷 생성 (되돌릴 수 있는 안전 상태 확보)
2. Sysmon 설치 및 설정 적용: `sysmon.exe -accepteula -i sysmonconfig.xml`
3. 이벤트 로그 수집 시작 (`wevtutil` 또는 Event Viewer)
4. ZIP 압축 해제 (비밀번호 `infected`) → 나온 `.exe` 실행
5. 일정 시간 경과 후 이벤트 로그 export (`.evtx`)
6. 수집된 로그를 호스트의 `analyzer/`로 안전하게 이동
7. VM 스냅샷 롤백으로 감염 상태 완전 제거

## 법적·윤리적 고지

- 본 샘플은 [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/)에서 **연구 목적**으로 제공받은 실제 악성 바이너리이다.
- 타인의 시스템, 네트워크, 데이터에 대한 무단 실행은 법적 책임을 수반한다.
- 본 프로젝트는 대학 캡스톤 디자인의 일환으로, **방어적 보안 연구(탐지·분석)** 목적에 한해 샘플을 사용한다.
- 분석 완료 후 샘플 파일은 안전하게 폐기한다.
