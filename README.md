# system-automative-3
시스템 보안 자동화 프로젝트 - 현대오토에버 모빌리티 SW 3조
## 개요
이 프로젝트는 <RAPA - 현대오토에버 모빌리티 SW IT보안 과정> 3조에서 개발한 시스템 보안 자동화 도구입니다. 주요 기능은 다음과 같습니다:
- KISA에서 제시한 보안 점검 항목에 대한 자동 점검
- RHEL 계열 (Rocky Linux 9, 10) 및 Debian 계열 (Ubuntu 24) OS 지원
- Ansible 기반 대시보드 제공으로 점검 결과 시각화

```
## 폴더 구조 (src 상세)

- `src/` : 프로젝트 주요 스크립트와 OS별 점검 모듈
    - `main.sh` : 사용자 메뉴 및 실행 진입점
    - `test.sh` : 통합 점검 실행 스크립트
    - `dashboard_0210/` : 대시보드 및 관련 리소스
        - `ansible.cfg` : Ansible 설정 파일
        - `app.py` : 대시보드 웹 앱 메인 스크립트
        - `check_playbook.yml` : 점검용 Ansible 플레이북
        - `temp_inventory.ini` : 임시 인벤토리 파일
        - `fonts/`, `history/`, `images/` : 대시보드 정적 자원 및 로그 저장소
        - `reports/` : 원격 호스트 점검 결과 저장
            - `192.168.2.139_result.txt`, `192.168.2.141_result.txt`, `192.168.2.147_result.txt` : 예시 리포트 파일
        - `scripts/` : 대시보드에서 호출하는 점검 스크립트
            - `rocky_check_10.sh`, `rocky_check_9.sh`, `ubuntu_check.sh`
    - `OS_Scripts/` : OS 계열별 점검 스크립트 모음
        - `Debian-family/`
            - `Ubuntu24.sh`
        - `RHEL-family/`
            - `kisa_rockylinux9_check_fixed_mix.sh`, `Rocky10.sh`, `Rocky9.sh`

```

## 실행 흐름

```
main.sh (사용자 메뉴 선택)
    ↓
test.sh (자동 OS 감지 & KISA 점검 실행)
    ↓
Report/KISA_RESULT_*.txt (결과 저장)
```

## 주요 파일 설명# 프로젝트 내 스크립트 실행
./install-nuclei.sh

| 파일 | 역할 |
|------|------|
| **main.sh** | 사용자가 OS를 선택하는 메뉴 인터페이스 |
| **test.sh** | KISA 14개 항목 자동 점검 (U-01~U-27) |
| **Rocky9.sh, Rocky10.sh** | RHEL 계열 스크립트 (test.sh 참조) |
| **Ubuntu24.sh** | Debian 계열 스크립트 (test.sh 참조) |

## 📋 사전 요구사항

- **OS**: Linux (Ubuntu 20.04+, Rocky Linux 9+) 또는 macOS 
- **Python**: 3.9 이상
- **Go**: 1.22.6 (Nuclei 빌드용)

---

## ⚡ 빠른 설치 (권장)

팀원들이 모든 설정을 자동으로 진행하려면 다음 명령어를 실행하기만 하면 됩니다:

```bash
# 1. 저장소 클론
git clone https://github.com/Hyundai-Autoever-mobility-sw-ITSec/system-automative-3.git
cd system-automative-3

# 2. Python 가상환경 설정
python3 -m venv venv
source venv/bin/activate

# 3. Python 패키지 설치
pip install -r requirements.txt

# 4. Nuclei 자동 설치 (모든 단계를 자동으로 진행)
sudo bash install-nuclei.sh

# 5. 대시보드 실행
cd src/dashboard_0210
streamlit run app.py
```

> 💡 **`install-nuclei.sh`가 자동으로 해주는 작업:**
> - Go 1.22.6 설치
> - Nuclei 소스코드 클론 및 빌드  
> - `/usr/local/bin/`에 설치 (전역 경로 등록)

---

## 🚀 상세 설치 가이드

`install-nuclei.sh`를 사용하지 않고 **수동으로 단계별 설치**하려면 아래를 따르세요:

### 1️⃣ 저장소 클론 및 디렉토리 이동

```bash
git clone https://github.com/Hyundai-Autoever-mobility-sw-ITSec/system-automative-3.git
cd system-automative-3
```

### 2️⃣ Python 가상 환경 생성

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS 기준
# Windows의 경우: venv\Scripts\activate
```

### 3️⃣ Python 패키지 설치

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

> **requirements.txt**: 대시보드 및 스크립트 실행에 필요한 Python 라이브러리들이 포함되어 있습니다.

### 4️⃣ Nuclei 설치 ⚠️ (필수)

Nuclei는 **Go 바이너리**이므로 pip로 설치할 수 없습니다. 소스코드에서 빌드하여 설치합니다.

#### **Step 1: 필수 도구 설치**

```bash
sudo apt update
sudo apt install -y git curl build-essential ca-certificates
```

#### **Step 2: Go 설치 (1.22.6 버전)**

```bash
# 기존 Go 제거 (설치되어 있는 경우)
sudo apt remove golang-go -y
sudo rm -rf /usr/local/go

# Go 1.22.6 다운로드 및 설치
curl -LO https://go.dev/dl/go1.22.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.6.linux-amd64.tar.gz

# PATH에 Go 바이너리 경로 추가
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Go 설치 확인
go version
```

#### **Step 3: Nuclei 소스코드에서 빌드**

```bash
# Nuclei 저장소 클론
git clone https://github.com/projectdiscovery/nuclei.git
cd nuclei

# 바이너리 빌드
go build -o nuclei ./cmd/nuclei

# 현재 디렉토리에서 설치 확인
./nuclei -version
```

#### **Step 4: PATH에 Nuclei 추가 (선택사항)**

전역으로 `nuclei` 명령어를 사용하려면:

```bash
sudo mv nuclei /usr/local/bin/
nuclei -version  # 전역 경로에서 실행 확인
```

> 만약 `nuclei: command not found` 에러가 나면, nuclei 바이너리가 있는 디렉토리를 PATH에 추가하거나 전체 경로로 실행해주세요.
> 예: `./nuclei -version` 또는 `/usr/local/bin/nuclei -version`

---

## 📊 대시보드 실행

### Streamlit 대시보드 시작

```bash
cd src/dashboard_0210
streamlit run app.py
```

**예상 출력:**
```
You can now view your Streamlit app in your browser.
  Local URL: http://localhost:8501
  Network URL: http://192.168.x.x:8501
```

대시보드는 자동으로 브라우저에서 열립니다. (열리지 않으면 위의 URL을 수동으로 방문하세요)

---

## 🔧 OS별 점검 스크립트 실행

```bash
# Rocky Linux 9
sudo bash src/OS_Scripts/RHEL-family/Rocky9.sh

# Rocky Linux 10
sudo bash src/OS_Scripts/RHEL-family/Rocky10.sh

# Ubuntu 24
sudo bash src/OS_Scripts/Debian-family/Ubuntu24.sh
```

결과는 `Report/` 폴더에 자동 저장됩니다.

---

## 🔍 주요 스크립트 설명

| 파일 | 위치 | 설명 |
|------|------|------|
| `main.sh` | `src/` | 사용자 메뉴 진입점 |
| `test.sh` | `src/` | KISA 보안 점검 자동 실행 |
| `app.py` | `src/dashboard_0210/` | Streamlit 대시보드 |
| `nuclei_check.py` | `src/dashboard_0210/scripts/` | Nuclei 실행 래퍼 |
| `Rocky9.sh, Rocky10.sh` | `src/OS_Scripts/RHEL-family/` | RHEL 계열 점검 스크립트 |
| `Ubuntu24.sh` | `src/OS_Scripts/Debian-family/` | Debian 계열 점검 스크립트 |

---

## ✅ 환경 설정 확인

모든 설정이 완료되었는지 확인하려면:

```bash
# Python 패키지 확인
pip list | grep streamlit  # streamlit이 출력되어야 함

# Go 버전 확인
go version  # Go 1.22.6 이상이어야 함

# Nuclei 설치 확인
which nuclei  # 또는 /usr/local/bin/nuclei로 직접 실행
nuclei -version  # 버전 정보 확인

# Python 버전 확인
python3 --version  # Python 3.9 이상이어야 함
```

---

## 🆘 문제 해결

### ❌ `ModuleNotFoundError: No module named 'streamlit'`

**해결:**
```bash
source venv/bin/activate  # 가상환경 활성화 확인
pip install -r requirements.txt  # 패키지 재설치
```

### ❌ `nuclei: command not found`

**해결:**
```bash
# Step 1: nuclei 바이너리 경로 확인
# nuclei를 빌드한 디렉토리에서 직접 실행
cd ~/nuclei  # 또는 nuclei를 빌드한 경로
./nuclei -version

# Step 2: 전역 PATH에 추가하려면
sudo cp nuclei /usr/local/bin/
nuclei -version  # 확인

# Step 3: 설치 경로 재확인
which nuclei  # 또는
ls -l /usr/local/bin/nuclei  # 설치 위치 확인
```

### ❌ `Permission denied` 에러

**해결:**
```bash
chmod +x src/main.sh
chmod +x src/test.sh
chmod +x src/OS_Scripts/**/*.sh
```

---

## 📝 추가 참고사항

- **원격 호스트 점검**: `check_playbook.yml`에 대상 호스트를 등록한 후 Ansible로 실행하세요.
- **결과 저장**: 점검 결과는 `reports/` 디렉토리에 자동 저장됩니다.
- **로그 조회**: `history/` 디렉토리에서 과거 실행 로그를 확인할 수 있습니다.
