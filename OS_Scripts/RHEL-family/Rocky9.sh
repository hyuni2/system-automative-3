#!/bin/bash

resultfile="Results_$(date '+%F_%H:%M:%S').txt"
#rocky9에서는 점검 대상 파일 경로가 다르므로 별도 변수로 정의
CHECK_FILES=("/etc/profile" "/etc/bashrc" "/root/.bashrc" "/root/.bash_profile")

#연진
U_04() {
    #진단항목 정보 출력
	echo ""  >> $resultfile 2>&1
	echo "▶ U-04(상) | 1. 계정관리 > 1.4 패스워드 파일 보호 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : shadow 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우"  >> $resultfile 2>&1

    # /etc/shadow를 사용하면 두 번째 필드(password)는 무조건 'x'여야 함 (Shadow 패스워드 정책)
	# /etc/passwd의 두 번째 필드가 'x'가 아닌 계정의 개수를 카운트
    VULN_COUNT=$(awk -F : '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd | wc -l)
    if [ $VULN_COUNT -gt 0 ]; then
        #취약한 계정 목록 추출(x나 !!이 아닌 섀도우패스워드를 사용하지 않는 계정)
        VULN_USERS=$(awk -F : '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd | cut -d: -f1)
        echo "※ U-04 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " /etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재: $VULN_USERS" >> "$resultfile" 2>&1
    else
        # /etc/shadow 파일 자체의 존재 여부도 추가 점검
        if [ -f /etc/shadow ]; then
            echo "※ U-04 결과 : 양호(Good)" >> $resultfile 2>&1
        else
            echo "[결과] 취약(Vulnerable): /etc/shadow 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        fi
    fi
}

#연진
U_09() {
	echo ""  >> $resultfile 2>&1
	echo "▶ U-09(하) | 1. 계정관리 > 1.12 계정이 존재하지 않는 GID 금지 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우" >> $resultfile 2>&1

	#1. /etc/passwd에서 현재 사용 중인 모든 GID 추출 (정렬)
	USED_GIDS=$(awk -F: '{print $4}' /etc/passwd | sort -u)

	# 2. /etc/group에서 점검 대상 GID 추출 (보통 500번 또는 1000번 이상이 일반 사용자 그룹)
    # $3 필드가 GID. (그룹이름:비밀번호:그룹ID:그룹에 속한 사용자 이름)
	# 실제 사용자가 기록된 /etc/passwd와 대조해야 정확한 진단이 나옴.
    CHECK_GIDS=$(awk -F: '$3 >= 500 {print $3}' /etc/group)
	VULN_GROUPS=""
    for gid in $CHECK_GIDS; do
        # 사용 중인 GID 목록에 현재 GID가 있는지 확인
        if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
            # 해당 GID를 가진 그룹명을 추출하여 목록에 추가
            GROUP_NAME=$(grep -w ":$gid:" /etc/group | cut -d: -f1)
            VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
        fi
    done

    # 3. 결과 판정(교차검증)
    if [ -n "$VULN_GROUPS" ]; then
        echo "※ U-09 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] 계정이 존재하지 않는 불필요한 그룹 존재:$VULN_GROUPS" >> "$resultfile" 2>&1
    else
        echo "※ U-09 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

#연진
U_14() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-14(상) | 2. 파일 및 디렉토리 관리 > 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함되지 않은 경우" >> "$resultfile" 2>&1

    VULN_FOUND=0
    DETAILS=""

    # 1. 현재 실행 중인 쉘의 런타임 PATH 점검
    # 패턴: 맨 앞이 .이거나(:|^.), 중간에 빈 경로(::) 또는 (:.:)가 포함된 경우
    if echo "$PATH" | grep -qE '^\.:|:.:|^:|::'; then
        VULN_FOUND=1
        DETAILS="[Runtime] 현재 PATH 환경변수 내 우선순위 높은 '.' 또는 '::' 발견: $PATH"
    fi

    # 2. 시스템 공통 설정 파일 점검
    if [ $VULN_FOUND -eq 0 ]; then
        # OS별(Ubuntu/Rocky) 차이를 고려한 확장된 파일 목록
        path_settings_files=("/etc/profile" "/etc/.login" "/etc/csh.cshrc" "/etc/csh.login" "/etc/environment" "/etc/bashrc" "/etc/bash.bashrc")
        
        for file in "${path_settings_files[@]}"; do
            if [ -f "$file" ]; then
                # 주석 제외 후 PATH 설정 라인 추출 및 패턴 매칭
                VULN_LINE=$(grep -vE '^#|^\s#' "$file" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$')
                if [ ! -z "$VULN_LINE" ]; then #취약한 path 설정 발견시
                    VULN_FOUND=1
                    DETAILS="[System File] $file: $VULN_LINE" #어떤 파일, 어떤 라인인지 기록
                    break
                fi
            fi
        done
    fi

    # 3. 모든 사용자 홈 디렉터리 내 설정 파일 점검
    if [ $VULN_FOUND -eq 0 ]; then
        user_dot_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
        # /etc/passwd에서 실제 홈 디렉터리 추출 (불필요한 계정 제외)
        user_homedirs=$(awk -F: '$7!="/bin/false" && $7!="/sbin/nologin" {print $6}' /etc/passwd | sort | uniq)

        for dir in $user_homedirs; do
            for dotfile in "${user_dot_files[@]}"; do
                target="$dir/$dotfile" #실제 검사할 파일 경로 생성
                if [ -f "$target" ]; then #일반파일이 존재하면 true
                    VULN_LINE=$(grep -vE '^#|^\s#' "$target" \
                                | grep 'PATH=' \
                                | grep -E '=\.:|=\.|:\.:|::|:$')
                    if [ ! -z "$VULN_LINE" ]; then
                        VULN_FOUND=1
                        DETAILS="[User File] $target: $VULN_LINE"
                        break 2
                    fi
                fi
            done
        done
    fi

    # 최종 결과 출력
    if [ $VULN_FOUND -eq 1 ]; then
        echo "※ U-14 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] $DETAILS" >> "$resultfile" 2>&1
    else
        echo "※ U-14 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi

    return 0
}

#연진
U_19() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-19(상) | 2. 파일 및 디렉토리 관리 > 2.6 /etc/hosts 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> "$resultfile" 2>&1

    VULN_FOUND=0
    DETAILS=""

    # 1. 파일 존재 여부 확인
    if [ -f "/etc/hosts" ]; then
        # [Step 2] 소유자 확인 (UID 확인이 더 정확함)
        FILE_OWNER_UID=$(stat -c "%u" /etc/hosts)
        FILE_OWNER_NAME=$(stat -c "%U" /etc/hosts)
        
        # [Step 3] 권한 확인 (8진수 형태, 예: 644)
        FILE_PERM=$(stat -c "%a" /etc/hosts)
        
        # 8진수 권한을 각 자리수별로 분리
        #User, Group, Other 순서 
        USER_PERM=${FILE_PERM:0:1}
        GROUP_PERM=${FILE_PERM:1:1}
        OTHER_PERM=${FILE_PERM:2:1}

        # 판단 로직: 소유자가 root(UID 0)가 아니거나 권한이 644(rw-r--r--)보다 큰 경우
        if [ "$FILE_OWNER_UID" -ne 0 ]; then
            VULN_FOUND=1
            DETAILS="소유자(owner)가 root가 아님 (현재: $FILE_OWNER_NAME)"
        elif [ "$USER_PERM" -gt 6 ] || [ "$GROUP_PERM" -gt 4 ] || [ "$OTHER_PERM" -gt 4 ]; then
            VULN_FOUND=1
            DETAILS="권한이 644보다 큼 (현재: $FILE_PERM)"
        fi
    else
        echo "※ U-19 결과 : N/A (파일이 존재하지 않음)" >> "$resultfile" 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ "$VULN_FOUND" -eq 1 ]; then
        echo "※ U-19 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] $DETAILS" >> "$resultfile" 2>&1
    else
        echo "※ U-19 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi

    return 0
}


