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

### 2. goliate-hidden-tear.zip

- **원본 레포**: https://github.com/goliate/hidden-tear
- **언어**: C# (.NET Framework)
- **대상 플랫폼**: Windows
- **크기**: 약 289 KB
- **SHA256**: `18e879d91c47ab163e6707aa91f5203796c2e11cf14fe0be088c055a832b3c06`

**개요**
2015년 utkusen에 의해 최초 공개된 **세계 최초의 오픈소스 랜섬웨어**. C#으로 작성되어 Visual Studio 또는 `msbuild`로 Windows 네이티브 `.exe`로 빌드된다. AES 알고리즘으로 지정된 디렉토리의 파일을 암호화하고, 키는 HTTP POST로 원격 서버에 전송하는 구조. 학술 논문 및 악성코드 분석 교재에 가장 많이 인용되는 샘플.

**빌드 방법 (VM 내부)**
```powershell
# Visual Studio 또는 Build Tools 설치 후
msbuild hidden-tear\hidden-tear.sln /p:Configuration=Release
```

**Sysmon 관찰 포인트**
- Event ID 1: `hidden-tear.exe` 실행, Parent는 탐색기/CMD
- Event ID 11: 암호화된 파일 생성 (`.locked` 확장자)
- Event ID 3: 키 전송을 위한 HTTP POST 트래픽
- Event ID 13: 바탕화면 변경 관련 레지스트리 쓰기(변형 시)

---

### 3. hackthedev-teardrop.zip

- **원본 레포**: https://github.com/hackthedev/teardrop
- **언어**: C# (.NET)
- **대상 플랫폼**: Windows
- **크기**: 약 16.6 MB
- **SHA256**: `ba82fd082c95c8f0fbff72dcb6d10d6d3e4b4984455931bb89de9365fe6e2448`

**개요**
교육 목적으로 작성된 C# 랜섬웨어 프로젝트. HiddenTear 계열에 비해 최근 활동이 있는 프로젝트이며, 코드 구조가 모던 .NET 기반으로 구성되어 있다. Visual Studio에서 빌드 시 단일 `.exe`로 산출된다.

**Sysmon 관찰 포인트**
- Event ID 1: `teardrop.exe` 실행 및 명령행 인자
- Event ID 11: 파일 생성 이벤트(암호화본)
- Event ID 23: 원본 파일 삭제
- Event ID 22 (DNS Query): C2 도메인 쿼리 여부

---

### 4. jaenudin86-CryptoJoker.zip

- **원본 레포**: https://github.com/jaenudin86/CryptoJoker
- **언어**: C# (.NET Framework)
- **대상 플랫폼**: Windows
- **크기**: 약 4.8 MB
- **SHA256**: `7f4440b1ecf914b282f2d78b69f9b57b4ac15dc2e2a850a73232b58a21fd7611`

**개요**
교육 목적 전용으로 공개된 Managed C# 랜섬웨어. 파일 열람 → 암호화 → 몸값 메모 표시의 고전적인 흐름을 깔끔하게 구현하고 있으며, 소스 규모가 적당해 정적 분석과 동적 분석을 함께 학습하기 좋다.

**Sysmon 관찰 포인트**
- Event ID 1: `CryptoJoker.exe` 실행
- Event ID 11: 암호화본 파일 생성(확장자 변경)
- Event ID 23: 원본 파일 삭제
- Event ID 7: .NET 런타임(`clr.dll`, `mscoreei.dll`) 로드
- Event ID 13: 자동 실행 레지스트리(`Run` 키) 설정 여부

---

## Windows 실행 가능 여부 요약

| 샘플 | 언어 | 실행 방식 | Windows 네이티브 |
|---|---|---|---|
| mauri870-ransomware | Go | `go build` → `.exe` | ✅ |
| goliate-hidden-tear | C# | `msbuild` → `.exe` | ✅ |
| hackthedev-teardrop | C# | Visual Studio → `.exe` | ✅ |
| jaenudin86-CryptoJoker | C# | Visual Studio → `.exe` | ✅ |

모든 샘플은 Windows 가상머신에서 네이티브 `.exe`로 빌드·실행되며, Sysmon 이벤트 로그 기반 행위 분석에 적합하다.

---

## 법적·윤리적 고지

- 본 샘플은 오픈소스로 공개된 **교육/연구 목적**의 코드이며, 실제 피해 사례와는 무관하다.
- 타인의 시스템, 네트워크, 데이터에 대한 무단 실행은 법적 책임을 수반한다.
- 본 프로젝트는 대학 캡스톤 디자인의 일환으로, 방어적 보안 연구(탐지·분석) 목적에 한해 샘플을 사용한다.
