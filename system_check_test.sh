#!/bin/bash

result="results.txt"

U_01() {
    echo "" >> $result 2>&1
    echo "▶ U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한 ◀" >> $result 2>&1
    echo " 양호 판단 기준 : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우" >> $result 2>&1

    VULN=0
    REASON=""

    BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

    # 1. 취약 원격 터미널 서비스 점검
    for svc in "${BAD_SERVICES[@]}"; do
        if systemctl list-unit-files | grep -q "^$svc"; then
            if systemctl is-active "$svc" &>/dev/null; then
                VULN=1
                REASON="$svc 서비스 실행 중 입니다."
                break
            fi
        fi
    done

    # 2. SSH 점검 
    if [ $VULN -eq 0 ] && systemctl is-active sshd &>/dev/null; then
        ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')

        if [[ "$ROOT_LOGIN" != "no" ]]; then
            VULN=1
            REASON="SSH 서비스를 사용하고, root 계정의 원격 접속이 허용중입니다."
        fi
    fi

    # 3. 결과 출력 
    if [ $VULN -eq 1 ]; then
        echo "※ U-01 결과 : 취약(Vulnerable)" >> $result 2>&1
        echo " $REASON" >> $result 2>&1
    else
        echo "※ U-01 결과 : 양호(Good)" >> $result 2>&1
    fi
}

U_05() {
    echo "" >> $result 2>&1
    echo "▶ U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 ◀"  >> $result 2>&1
    echo " 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $result 2>&1
    if [ -f /etc/passwd ]; then
        if [ `awk -F : '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | wc -l` -gt 0 ]; then
            echo "※ U-44 결과 : 취약(Vulnerable)" >> $result 2>&1
            echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $result 2>&1
        else
            echo "※ U-44 결과 : 양호(Good)" >> $result 2>&1
        fi
    fi
}

U_06(){
    echo "" >> $result 2>&1
    echo "▶ U-06(상) | 1. 계정관리 > 1.6 사용자 계정 su 기능 제한 ◀" >> $result 2>&1
    echo " 양호 판단 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※ 일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요" >> $result 2>&1

    VULN=0
    REASON=""
    PAM_SU="/etc/pam.d/su"

    # 1. /etc/pam.d/su 파일이 있는지 확인
    if [ -f "$PAM_SU" ]; then
        SU_RESTRICT=$(grep -vE "^#|^\s*#" $PAM_SU | grep "pam_wheel.so" | grep "use_uid")

        # 2. pam_wheel.so 모듈 활성화 되어있는지 확인
        if [ -z "$SU_RESTRICT" ]; then
            VULN=1
            REASON="/etc/pam.d/su 파일에 pam_wheel.so 모듈 설정이 없거나 주석 처리되어 있습니다."
        else
            VULN=0
        fi
    else
        VULN=1
        REASON="$PAM_SU 파일이 존재하지 않습니다."
    fi

    # 3. 예외  처리 : 일반 사용자가 없고 root만 있을 경우
    # 일반 유저 있는지 확인
    USER_COUNT=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd | wc -l)

    if [ $VULN -eq 1 ] && [ "$USER_COUNT" -eq 0 ]; then
        VULN=0
        REASON="일반 사용자 계정 없이 root 계정만 사용하여 su 명령어 사용 제한이 불필요합니다."
    fi

    # 4. 결과 출력
    if [ $VULN -eq 1 ]; then
        echo "※ U-06 결과 : 취약(Vulnerable)" >> $result 2>&1
        echo " $REASON" >> $result 2>&1
    else
        echo "※ U-06 결과 : 양호(Good)" >> $result 2>&1
    fi 
}

U_10() {
    echo "" >> $result 2>&1
    echo "▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀"  >> $result 2>&1
    echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $result 2>&1
    if [ -f /etc/passwd ]; then
        if [ `awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l` -gt 0 ]; then
            echo "※ U-10 결과 : 취약(Vulnerable)" >> $result 2>&1
            echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> $result 2>&1
        fi
    fi
    echo "※ U-10 결과 : 양호(Good)" >> $result 2>&1
}

U_11(){
    echo "" >> $result 2>&1
    echo "▶ U-11(하) | 1. 계정관리 > 1.11 사용자 shell 점검 ◀" >> $result 2>&1
    echo " 양호 판단 기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우" >> $result 2>&1

    VULN=0
    REASON=""
    VUL_ACCOUNTS=""

    # 예외 처리 : 쉘 사용 필수 계정
    EXCEPT_USERS="^(sync|shutdown|halt)$"

    # 1. /etc/passwd 파일 내 시스템 계정들 점검 
    while IFS=: read -r user pass uid gid comment home shell; do 
        if { [ "$uid" -ge 1 ] && [ "$uid" -lt 1000 ]; } || [ "$user" == "nobody" ]; then
            # 예외 대상 점검 제외 
            if [[ "$user" =~ $EXCEPT_USERS ]]; then
                continue
            fi
            # 2. 로그인이 허용된 쉘인지 확인
            if [[ "$shell" != "/bin/false" ]] && \
               [[ "$shell" != "/sbin/nologin" ]] && \
               [[ "$shell" != "/usr/sbin/nologin" ]]; then
                if [ -z "$VUL_ACCOUNTS" ]; then 
                    VUL_ACCOUNTS="$user($shell)"
                else
                    VUL_ACCOUNTS="$VUL_ACCOUNTS, $user($shell)"
                fi
            fi
        fi
    done < /etc/passwd

    # 3. 취약 여부 최종 판단 
    if [ -n "$VUL_ACCOUNTS" ]; then
        VULN=1
        REASON="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: $VUL_ACCOUNTS"
    fi

    # 4. 결과 출력
    if [ $VULN -eq 1 ]; then
        echo "※ U-11 결과 : 취약(Vulnerable)" >> $result 2>&1
        echo " $REASON" >> $result 2>&1
    else
        echo "※ U-11 결과 : 양호(Good)" >> $result 2>&1
    fi
}

U_15() {
    echo "" >> $result 2>&1
    echo "▶ U-15(상) | 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정 ◀"  >> $result 2>&1
    echo " 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"  >> $result 2>&1
    if [ `find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l` -gt 0 ]; then
        echo "※ U-15 결과 : 취약(Vulnerable)" >> $result 2>&1
        echo " 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다." >> $result 2>&1
    else
        echo "※ U-15 결과 : 양호(Good)" >> $result 2>&1
    fi
}

U_16(){
    echo "" >> $result 2>&1
    echo "▶ U-16(상) | 2. 파일 및 디렉토리 관리 > 2.3 /etc/passwd 파일 소유자 및 권한 설정 ◀" >> $result 2>&1
    echo " 양호 판단 기준 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> $result 2>&1

    VULN=0
    REASON=""
    FILE="/etc/passwd"

    # 1. /etc/passwd 파일 존재 여부 확인
    if [ -f "$FILE" ]; then
        # 2. 소유자 및 권한 확인
        OWNER=$(stat -c "%U" "$FILE")
        PERMIT=$(stat -c "%a" "$FILE")

         # 3. 취약 여부 판단
        if [ "$OWNER" != "root" ] || [ "$PERMIT" -gt 644 ]; then
            VULN=1
            if [ "$OWNER" != "root" ]; then
                REASON="/etc/passwd 파일의 소유자가 root가 아닙니다 (현재: $OWNER)."
            fi
            if [ "$PERMIT" -gt 644 ]; then
                if [ -n "$REASON" ]; then
                    REASON="$REASON / 권한이 644보다 높습니다 (현재: $PERMIT). "
                else
                    REASON="권한이 644보다 높습니다 (현재: $PERMIT). "
                fi
            fi
        fi
    else
        VULN=1
        REASON="$FILE 파일이 존재하지 않습니다."
    fi

    # 4. 결과 출력
    if [ $VULN -eq 1 ]; then
        echo "※ U-16 결과 : 취약(Vulnerable)" >> $result 2>&1
        echo " $REASON" >> $result 2>&1
    else
        echo "※ U-16 결과 : 양호(Good)" >> $result 2>&1
    fi

}

U_20() {
    # ------------------------------------------------------------------------
    # 원래 inetd.conf 파일은 데몬들의 서비스 매핑 테이블을 담고 있던 파일임 
    # inetd 가 systemd 로 대체되면서, 
    # inetd.conf 파일 내의 내용이 여러 폴더 내에 unit 별로 분리되어 저장되었는데
    #   *.socket 파일 (inetd.conf 파일의 '포트 대기' 역할)
    #   *.service 파일 (inetd.conf 파일의 '실행 파일 + 계정' 역할)
    # -> /usr/lib/systemd/system, /etc/systemd/system 에 있으므로 
    #    점검 대상이 두 디렉터리가 되면 됨
    #
    # + 주요정보통신기반시설 가이드에서 inetd 는 권한이 600 초과면 취약이라고 판단했는데,
    #   찾아보니 systemd 는 644를 주로 실무에서 사용한다고 하여,
    #   644 초과면 취약이라고 판단하는 스크립트로 작성
    #
    # 아래는 /etc/systemd/system, /usr/lib/systemd/system 점검 스크립트
    # ------------------------------------------------------------------------
    echo "" >> $result 2>&1
    echo "▶ U-20(상) | 2. 파일 및 디렉토리 관리 > 2.7 systemd *.socket, *.service 파일 소유자 및 권한 설정 ◀"  >> $result 2>&1
    echo " 양호 판단 기준 : systemd *.socket, *.service 파일의 소유자가 root이고, 권한이 644 이하인 경우"  >> $result 2>&1
    file_exists_count=0
    # /usr/lib/systemd/system 점검
    if [ -d /usr/lib/systemd/system ]; then
        unit_files=$(find /usr/lib/systemd/system -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null)
        if [ -n "$unit_files" ]; then
            ((file_exists_count++))
            for file in $unit_files
            do
                owner=$(stat -c %U "$file")
                perm=$(stat -c %a "$file")
                if [ "$owner" != "root" ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $result 2>&1
                    echo " $file 파일의 소유자가 root가 아닙니다." >> $result 2>&1
                elif [ "$perm" -gt 644 ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $result 2>&1
                    echo " $file 파일의 권한이 644 초과입니다." >> $result 2>&1
                fi
            done
        fi
    fi
    # /etc/systemd/system 점검
    if [ -d /etc/systemd/system ]; then
        unit_files=$(find /etc/systemd/system -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null)
        if [ -n "$unit_files" ]; then
            ((file_exists_count++))
            for file in $unit_files
            do
                owner=$(stat -c %U "$file")
                perm=$(stat -c %a "$file")
                if [ "$owner" != "root" ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $result 2>&1
                    echo " $file 파일의 소유자가 root가 아닙니다." >> $result 2>&1
                elif [ "$perm" -gt 644 ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $result 2>&1
                    echo " $file 파일의 권한이 644 초과입니다." >> $result 2>&1
                fi
            done
        fi
    fi
    if [ $file_exists_count -eq 0 ]; then
        echo "※ U-20 결과 : N/A" >> $result 2>&1
        echo " systemd socket/service 파일이 없습니다." >> $result 2>&1
    else
        echo "※ U-20 결과 : 양호(Good)" >> $result 2>&1
    fi
}


U_01
U_05
U_06
U_10
U_11
U_15
U_16
U_20
