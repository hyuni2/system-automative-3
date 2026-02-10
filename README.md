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

## 주요 파일 설명

| 파일 | 역할 |
|------|------|
| **main.sh** | 사용자가 OS를 선택하는 메뉴 인터페이스 |
| **test.sh** | KISA 14개 항목 자동 점검 (U-01~U-27) |
| **Rocky9.sh, Rocky10.sh** | RHEL 계열 스크립트 (test.sh 참조) |
| **Ubuntu24.sh** | Debian 계열 스크립트 (test.sh 참조) |

## 사용방법
1. 저장소 클론:
   ```bash
   git clone https://github.com/Hyundai-Autoever-mobility-sw-ITSec/system-automative-3.git
    cd system-automative-3
    ```
2. 실행 권한 부여:
    ```bash
    chmod +x main.sh
    ```
3. 스크립트 실행:
    ```bash
    sudo ./main.sh
    sudo ./[해당_OS_스크립트.sh]
    ```
4. 메뉴에서 OS 선택 후 점검 시작    
4. 결과는 `Report/` 폴더에 `KISA_RESULT_*.txt` 파일로 저장
5. 대시보드 실행:
    ```bash
    cd src/dashboard_0210
    python3 app.py
    ```
6. 웹 브라우저에서 `http://localhost:5000` 접속하여 대시보드 확인