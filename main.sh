#!/bin/bash
# main.sh

echo "=================================================="
echo " ISMS 기반 시스템 취약점 점검 자동화 도구"
echo "=================================================="
echo " 점검할 OS 버전을 선택하세요:"
echo " 1) Rocky Linux 9"
echo " 2) Rocky Linux 10"
echo " 3) Ubuntu 24.04"
echo "--------------------------------------------------"
read -p "번호 입력 (1-3): " choice

case $choice in
    1)
        TARGET_SCRIPT="OS_Scripts/RHEL-family/Rocky9.sh"
        OS_NAME="Rocky 9"
        ;;
    2)
        TARGET_SCRIPT="OS_Scripts/RHEL-family/Rocky10.sh"
        OS_NAME="Rocky 10"
        ;;
    3)
        TARGET_SCRIPT="OS_Scripts/Debian-family/Ubuntu2404.sh"
        OS_NAME="Ubuntu 24.04"
        ;;
    *)
        echo "잘못된 선택입니다. 종료합니다."
        exit 1
        ;;
esac

if [ -f "$TARGET_SCRIPT" ]; then
    echo "[$OS_NAME] 점검을 시작합니다..."
    # 실행 권한 부여 후 실행
    chmod +x "$TARGET_SCRIPT"
    bash "$TARGET_SCRIPT"
else
    echo "에러: $TARGET_SCRIPT 파일을 찾을 수 없습니다."
fi