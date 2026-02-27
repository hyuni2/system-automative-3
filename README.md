# system-automative-3
시스템 보안 자동화 프로젝트 - 현대오토에버 모빌리티 SW 3조

## 개요
이 프로젝트는 Linux 서버 보안 점검을 자동화하고, 결과를 Streamlit 대시보드에서 확인하기 위한 도구입니다.

주요 기능:
- OS별 보안 점검 자동 실행 (Rocky 9/10, Ubuntu 24)
- Ansible 기반 원격 점검
- Nuclei 템플릿 기반 취약점 스캔 통합
- 대시보드에서 결과 조회 및 Excel 저장

## 현재 기준 폴더 구조
```text
.
├─ app.py                        # Streamlit 실행 엔트리포인트 (루트에서 실행)
├─ install-nuclei.sh
├─ requirements.txt
└─ dashboard_0210/
   ├─ ansible.cfg
   ├─ check_playbook.yml
   ├─ temp_inventory.ini
   ├─ scripts/
   │  ├─ nuclei_check.py
   │  ├─ rocky_check_9.sh
   │  ├─ rocky_check_10.sh
   │  └─ ubuntu_check.sh
   ├─ reports/
   ├─ history/
   ├─ templates/
   ├─ images/
   ├─ fonts/
   ├─ styles.css
   └─ nuclei-templates/
```

## 스크립트 역할 정리
### 1) `src/OS_Scripts/*`
- 원격 서버에서 실제 점검을 수행하는 **원본 점검 스크립트**입니다.
- 사람이 터미널에서 직접 실행하는 용도/Ansible script 모듈 실행용입니다.

### 2) `src/dashboard_0210/scripts/*`
- 대시보드 연동을 위한 **JSON 출력 중심 스크립트**입니다.
- 특히 `nuclei_check.py`는 Nuclei 실행 결과를 JSON 라인으로 출력해 대시보드가 파싱합니다.

### 3) `check.py` 관련
- 현재 프로젝트 기준으로 별도 `check.py` 파일은 없습니다.
- 대시보드 원격 진단 오케스트레이션 파일은 `src/dashboard_0210/check_playbook.yml` 입니다.

## 실행 흐름 (대시보드 점검)
1. 사용자 입력(IP/계정/비밀번호)
2. `app.py`가 `temp_inventory.ini` 생성
3. `ansible-playbook`로 `check_playbook.yml` 실행
4. 원격에서 OS 점검 스크립트 실행 (`src/OS_Scripts/*`)
5. 로컬에서 Nuclei 실행 (`src/dashboard_0210/scripts/nuclei_check.py`)
6. 결과를 `src/dashboard_0210/reports/{ip}_result.txt`에 저장
7. 대시보드가 JSON 파싱 후 표로 렌더링

## 빠른 시작
```bash
# 1) 프로젝트 이동
cd ~/system-automative-3

# 2) 가상환경 활성화
source venv/bin/activate

# 3) 의존성 설치 (최초 1회)
pip install -r requirements.txt

# 4) nuclei 설치 확인
which nuclei
nuclei -version

# 5) nuclei 템플릿 준비 (최초 1회)
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git src/dashboard_0210/nuclei-templates
# 이미 있으면 업데이트
git -C src/dashboard_0210/nuclei-templates pull

# 6) 대시보드 실행
streamlit run app.py
```

## 터미널에서 직접 점검 (선택)
```bash
# Rocky 9
sudo bash src/OS_Scripts/RHEL-family/Rocky9.sh

# Rocky 10
sudo bash src/OS_Scripts/RHEL-family/Rocky10.sh

# Ubuntu 24
sudo bash src/OS_Scripts/Debian-family/Ubuntu24.sh
```

## 결과 파일
- 실시간 점검 결과: `src/dashboard_0210/reports/`
- 저장(보관) 결과: `src/dashboard_0210/history/`

## 트러블슈팅
### 1) `/bin/bash^M: bad interpreter`
원인: 쉘 스크립트 줄바꿈이 CRLF(Windows)인 경우

해결:
```bash
sed -i 's/\r$//' src/OS_Scripts/RHEL-family/Rocky9.sh
sed -i 's/\r$//' src/OS_Scripts/RHEL-family/Rocky10.sh
sed -i 's/\r$//' src/OS_Scripts/Debian-family/Ubuntu24.sh
```

### 2) Nuclei 실행 실패 (`NUC-ERR-RUN`)
확인:
```bash
nuclei -h
```
- 현재 코드(`nuclei_check.py`)는 JSONL 출력 플래그 `-j` 기준입니다.

### 3) `NUC-ERR-TEMPLATES`
원인: `src/dashboard_0210/nuclei-templates` 경로 미존재

해결:
```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git src/dashboard_0210/nuclei-templates
```

### 4) 점검 페이지에서 오래 로딩됨
확인:
```bash
ps -ef | rg "ansible-playbook|Rocky9.sh|Rocky10.sh|nuclei" -S
```
- 원격 OS 점검 스크립트 실행 중이면 수 분 걸릴 수 있습니다.
- 비정상으로 오래 걸리면 대시보드의 디버그 로그(STDOUT/STDERR) 확인 후 원인 파악하세요.

## 참고
- `main`/`history` 페이지 이동 시 리포트 정리 로직으로 `reports/*_result.txt`가 삭제될 수 있습니다.
- 점검 직후 결과 확인은 `점검` 페이지에서 바로 확인하는 것을 권장합니다.
