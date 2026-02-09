# system-automative-3
시스템 보안 자동화 프로젝트 - 현대오토에버 모빌리티 sw 3조

#파일구조
.
├── OS_Scripts              # [OS별 점검 스크립트 저장 폴더]
│   ├── Debian-family
│   │   └── Ubuntu24.sh     # Ubuntu 24.04 점검 스크립트
│   └── RHEL-family
│       ├── Rocky10.sh      # Rocky Linux 10 점검 스크립트
│       └── Rocky9.sh       # Rocky Linux 9 점검 스크립트
├── README.md
├── Report                  # [결과물] 점검 리포트가 저장될 폴더
└── main.sh                 # [중앙 제어] 사용자 입력 및 OS별 스크립트 호출