#!/bin/bash

resultfile="Results_$(date '+%F_%H:%M:%S').txt"

#희윤
U_01() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우" >> $resultfile 2>&1

    VULN=0
    REASON=""

    BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

    # 1. 취약 원격 터미널 서비스 점검
    for svc in "${BAD_SERVICES[@]}"; do
        if systemctl is-active "$svc" &>/dev/null; then
            if [[ "$svc" == *"telnet"* ]]; then
                break 
            else
                VULN=1
                REASON="$svc 서비스가 실행 중입니다."
                break
            fi
        fi
    done

    # 2. Telnet 서비스가 ps나 netstat으로 확인될 경우
    if [ $VULN -eq 0 ]; then
        if ps -ef | grep -i 'telnet' | grep -v 'grep' &>/dev/null || \
           netstat -nat 2>/dev/null | grep -w 'tcp' | grep -i 'LISTEN' | grep ':23 ' &>/dev/null; then  
            # PAM 설정 확인
            if [ -f /etc/pam.d/login ]; then
                if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty.so'; then
                    VULN=1
                    REASON="Telnet 서비스 사용 중이며, /etc/pam.d/login에 pam_securetty.so 설정이 없습니다."
                fi
            fi
            # securetty 설정 확인
            if [ $VULN -eq 0 ]; then
                if [ -f /etc/securetty ]; then
                    if grep -vE '^#|^\s#' /etc/securetty | grep -q '^ *pts'; then
                        VULN=1
                        REASON="Telnet 서비스 사용 중이며, /etc/securetty에 pts 터미널이 허용되어 있습니다."
                    fi
                fi
            fi
        fi
    fi

    # 3. SSH 점검 
    if [ $VULN -eq 0 ] && (systemctl is-active sshd &>/dev/null || ps -ef | grep -v grep | grep -q sshd); then
        # sshd -T로 현재 적용된 PermitRootLogin 설정을 확인
        ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')
        
        if [[ "$ROOT_LOGIN" != "no" ]]; then
            VULN=1
            REASON="SSH root 접속이 허용 중입니다 (PermitRootLogin: $ROOT_LOGIN)."
        fi
    fi

    # 4. 결과 출력 
    if [ $VULN -eq 1 ]; then
        echo "※ U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-01 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

#연수
U_03() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-03(상) | UNIX > 1. 계정 관리| 계정 잠금 임계값 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우"  >> "$resultfile" 2>&1

  local pam_files=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
  )

  local faillock_conf="/etc/security/faillock.conf"

  local found_any=0
  local found_from=""
  local max_deny=-1
  local file_exists_count=0

  _extract_deny_from_pam_file() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null \
      | grep -Ei 'pam_tally2\.so|pam_faillock\.so' \
      | grep -oE 'deny=[0-9]+' \
      | cut -d= -f2
  }

  _extract_deny_from_faillock_conf() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null \
      | grep -Ei '^[[:space:]]*deny[[:space:]]*=' \
      | grep -oE '[0-9]+' \
      | head -n 1
  }

  for f in "${pam_files[@]}"; do
    if [ -f "$f" ]; then
      ((file_exists_count++))
      while IFS= read -r deny; do
        [ -z "$deny" ] && continue
        found_any=1
        found_from+="$f(pam):deny=$deny; "
        if [ "$deny" -gt "$max_deny" ]; then
          max_deny="$deny"
        fi
      done < <(_extract_deny_from_pam_file "$f")
    fi
  done

  if [ -f "$faillock_conf" ]; then
    local conf_deny="$(_extract_deny_from_faillock_conf "$faillock_conf")"
    if [ -n "$conf_deny" ]; then
      found_any=1
      found_from+="$faillock_conf(conf):deny=$conf_deny; "
      if [ "$conf_deny" -gt "$max_deny" ]; then
        max_deny="$conf_deny"
      fi
    fi
  fi

  if [ "$file_exists_count" -eq 0 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 계정 잠금 임계값을 점검할 PAM 파일이 없습니다. (system-auth/password-auth 미존재)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$found_any" -eq 0 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " deny 설정을 찾지 못했습니다. (PAM 라인 또는 faillock.conf에서 deny=값 미발견)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$max_deny" -eq 0 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 계정 잠금 임계값(deny)이 0으로 설정되어 있습니다. (잠금 미적용 가능)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$max_deny" -gt 10 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 계정 잠금 임계값(deny)이 11회 이상으로 설정되어 있습니다. (max deny=$max_deny)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-03 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 계정 잠금 임계값(deny)이 10회 이하로 확인되었습니다. (max deny=$max_deny)" >> "$resultfile" 2>&1
  return 0
}

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

#수진
U_05() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $resultfile 2>&1
    if [ -f /etc/passwd ]; then
        if [ `awk -F : '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | wc -l` -gt 0 ]; then
            echo "※ U-44 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $resultfile 2>&1
        else
            echo "※ U-44 결과 : 양호(Good)" >> $resultfile 2>&1
        fi
    fi
}

#희윤
U_06(){
    echo "" >> $resultfile 2>&1
    echo "▶ U-06(상) | 1. 계정관리 > 1.6 사용자 계정 su 기능 제한 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※ 일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요" >> $resultfile 2>&1

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
        echo "※ U-06 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-06 결과 : 양호(Good)" >> $resultfile 2>&1
    fi 
}
#연수
U_08() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-08(중) | UNIX > 1. 계정 관리| 관리자 그룹에 최소한의 계정 포함 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> "$resultfile" 2>&1

  local admin_groups=("root" "wheel" "sudo" "admin")
  local unnecessary_accounts=(
    "daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag"
    "operator" "gopher" "games" "ftp" "apache" "httpd" "www-data"
    "mysql" "mariadb" "postgres" "mail" "postfix" "news" "lp" "uucp" "nuucp"
  )

  if [ ! -f /etc/group ]; then
    echo "※ U-08 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/group 파일이 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  _group_exists() { getent group "$1" >/dev/null 2>&1; }

  _collect_group_users() {
    local g="$1" users="" line members
    line="$(getent group "$g" 2>/dev/null)"
    members="$(echo "$line" | awk -F: '{print $4}')"
    [ -n "$members" ] && users+="$members,"

    if [ -f /etc/gshadow ]; then
      local gsh admins gmembers
      gsh="$(awk -F: -v gg="$g" '$1==gg{print $0}' /etc/gshadow 2>/dev/null)"
      admins="$(echo "$gsh" | awk -F: '{print $3}')"
      gmembers="$(echo "$gsh" | awk -F: '{print $4}')"
      [ -n "$admins" ] && users+="$admins,"
      [ -n "$gmembers" ] && users+="$gmembers,"
    fi

    echo "$users" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sed 's/[[:space:]]//g' | sort -u
  }

  _is_unnecessary() {
    local u="$1" x
    for x in "${unnecessary_accounts[@]}"; do
      [ "$u" = "$x" ] && return 0
    done
    return 1
  }

  local any_admin_group_found=0 vuln_found=0

  for g in "${admin_groups[@]}"; do
    if _group_exists "$g"; then
      any_admin_group_found=1
      local u bads=""
      while IFS= read -r u; do
        [ -z "$u" ] && continue
        _is_unnecessary "$u" && bads+="$u "
      done < <(_collect_group_users "$g")

      if [ -n "$bads" ]; then
        vuln_found=1
        echo "※ 취약 징후: 관리자 그룹($g)에 불필요 계정 포함: $bads" >> "$resultfile" 2>&1
      fi
    fi
  done

  if [ "$any_admin_group_found" -eq 0 ]; then
    echo "※ U-08 결과 : N/A" >> "$resultfile" 2>&1
    echo " 점검할 관리자 그룹(root/wheel/sudo/admin)이 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-08 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 관리자 그룹에 불필요한 계정이 등록되어 있습니다. (위 근거 참고)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-08 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 관리자 그룹에서 불필요 계정이 확인되지 않았습니다." >> "$resultfile" 2>&1
  return 0
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

#수진
U_10() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $resultfile 2>&1
    if [ -f /etc/passwd ]; then
        if [ "$(awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l)" -gt 0 ]; then
            echo "※ U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> $resultfile 2>&1
        fi
    fi
    echo "※ U-10 결과 : 양호(Good)" >> $resultfile 2>&1
}
#희윤
U_11(){
    echo "" >> $resultfile 2>&1
    echo "▶ U-11(하) | 1. 계정관리 > 1.11 사용자 shell 점검 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우" >> $resultfile 2>&1

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
        echo "※ U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-11 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

# Main execution - call all check functions
main() {
    U_01
    U_02
    U_03
    U_04
    U_05
    U_06
    U_08
    U_09
    U_10
    U_11
    U_12
    U_13
    U_14
    U_15
    U_16
    U_17
    U_18
    U_19
    U_20
    U_21
    U_23
    U_24
    U_25
    U_26
    U_28
    U_29
    U_30
    U_31
    U_32
    U_33
    U_34
    U_35
    U_36
    U_38
    U_39
    U_40
    U_41
    U_43
    U_44
    U_45
    U_46
    U_48
    U_49
    U_50
    U_51
    U_53
    U_54
    U_55
    U_56
    U_58
    U_59
    U_60
    U_61
    U_63
    U_64
    U_65
    U_66
    U_27
    U_37
    U_42
    U_47
    U_52
    U_07
}

# Execute main function
main

#연수
U_13() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-13(중) | 1. 계정관리 > 안전한 비밀번호 암호화 알고리즘 사용 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SHA-2 기반 알고리즘($5:SHA-256, $6:SHA-512)을 사용하는 경우" >> "$resultfile" 2>&1

  local shadow="/etc/shadow"

  # 0) 파일 접근 가능 여부
  if [ ! -e "$shadow" ]; then
    echo "※ U-13 결과 : N/A" >> "$resultfile" 2>&1
    echo " $shadow 파일이 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ ! -r "$shadow" ]; then
    echo "※ U-13 결과 : N/A" >> "$resultfile" 2>&1
    echo " $shadow 파일을 읽을 수 없습니다. (권한 부족: root 권한 필요)" >> "$resultfile" 2>&1
    return 0
  fi

  # 1) 계정별 해시 알고리즘 검사
  local vuln_found=0
  local checked=0
  local evidence=""

  # /etc/shadow: user:hash:...
  # hash가
  # - 비어있거나, !, *, !! 등: 비밀번호 미설정/잠금 -> 점검 제외
  # - $id$... 형태: id로 알고리즘 판별 (1,2,5,6 등)
  while IFS=: read -r user hash rest; do
    # 시스템 행 이상치 방지
    [ -z "$user" ] && continue

    # 비밀번호 미설정/잠금 계정 제외
    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    # $로 시작 안 하면(특이 케이스): 취약으로 분류(근거 남김)
    if [[ "$hash" != \$* ]]; then
      ((checked++))
      vuln_found=1
      evidence+="$user:UNKNOWN_FORMAT; "
      continue
    fi

    # 알고리즘 ID 추출: $1$..., $5$..., $6$...
    # 예: $6$salt$hash -> id=6
    local id
    id="$(echo "$hash" | awk -F'$' '{print $2}')"
    [ -z "$id" ] && id="UNKNOWN"

    ((checked++))

    # 이미지 기준(양호: 5/6만)
    if [ "$id" = "5" ] || [ "$id" = "6" ]; then
      : # good
    else
      vuln_found=1
      evidence+="$user:\$$id\$; "
    fi
  done < "$shadow"

  if [ "$checked" -eq 0 ]; then
    echo "※ U-13 결과 : N/A" >> "$resultfile" 2>&1
    echo " 점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-13 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 취약하거나 기준(SHA-2) 미만의 해시 알고리즘을 사용하는 계정이 존재합니다." >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-13 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " SHA-2 기반 해시 알고리즘($5/$6)만 사용 중입니다. (점검계정 수: $checked)" >> "$resultfile" 2>&1
  return 0
}

#연진
U_14() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-14(상) | 2. 파일 및 디렉토리 관리 > 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함되지 않은 경우" >> "$resultfile" 2>&1

    VULN_FOUND=0
    DETAILS=""

    # 1. 현재 실행 중인 쉘의 런타임 PATH 점검
    if echo "$PATH" | grep -qE '^\.:|:.:|^:|::|:$'; then
        VULN_FOUND=1
        DETAILS="[Runtime] 현재 PATH 내 우선순위 높은 '.' 또는 '::' 발견: $PATH"
    fi

    # 2. 시스템 공통 설정 파일 점검 (Rocky Linux 9 최적화)
    if [ $VULN_FOUND -eq 0 ]; then
        # Rocky 9에서 실제로 사용되는 주요 환경 설정 파일 목록
        path_settings_files=("/etc/profile" "/etc/bashrc" "/etc/environment")
        
        # Rocky 9의 핵심 경로인 /etc/profile.d/*.sh 파일들을 점검 대상에 추가
        for sh_file in /etc/profile.d/*.sh; do
            [ -f "$sh_file" ] && path_settings_files+=("$sh_file")
        done
        
        for file in "${path_settings_files[@]}"; do
            if [ -f "$file" ]; then
                # 주석 제외 후 PATH 설정 라인 추출 및 패턴 매칭
                VULN_LINE=$(grep -vE '^#|^\s#' "$file" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$')
                if [ ! -z "$VULN_LINE" ]; then
                    VULN_FOUND=1
                    DETAILS="[System File] $file: $VULN_LINE"
                    break
                fi
            fi
        done
    fi

    # 3. 모든 사용자 홈 디렉터리 내 설정 파일 점검
    if [ $VULN_FOUND -eq 0 ]; then
        # Rocky Linux에서 주로 사용되는 닷파일(.profile은 Ubuntu 계열에서 주로 사용하나 가이드 준수를 위해 유지)
        user_dot_files=(".bash_profile" ".bashrc" ".profile" ".cshrc" ".login" ".kshrc")
        
        # /etc/passwd에서 실제 홈 디렉터리 추출
        user_homedirs=$(awk -F: '$7!="/bin/false" && $7!="/sbin/nologin" {print $6}' /etc/passwd | sort | uniq)

        for dir in $user_homedirs; do
            for dotfile in "${user_dot_files[@]}"; do
                target="$dir/$dotfile"
                if [ -f "$target" ]; then
                    VULN_LINE=$(grep -vE '^#|^\s#' "$target" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$')
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

#수진
U_15() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-15(상) | 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"  >> $resultfile 2>&1
    if [ `find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l` -gt 0 ]; then
        echo "※ U-15 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다." >> $resultfile 2>&1
    else
        echo "※ U-15 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}
#희윤
U_16(){
    echo "" >> $resultfile 2>&1
    echo "▶ U-16(상) | 2. 파일 및 디렉토리 관리 > 2.3 /etc/passwd 파일 소유자 및 권한 설정 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> $resultfile 2>&1

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
        echo "※ U-16 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-16 결과 : 양호(Good)" >> $resultfile 2>&1
    fi

}
#연수
U_18() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-18(상) | UNIX > 2. 파일 및 디렉토리 관리| /etc/shadow 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /etc/shadow 파일의 소유자가 root이고, 권한이 400인 경우"  >> "$resultfile" 2>&1

  local target="/etc/shadow"

  # 0) 존재/파일 타입 체크
  if [ ! -e "$target" ]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target 파일이 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ ! -f "$target" ]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target 가 일반 파일이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 1) 소유자/권한 읽기 (출력 포맷 고정)
  local owner perm
  owner="$(stat -c '%U' "$target" 2>/dev/null)"
  perm="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " stat 명령으로 $target 정보를 읽지 못했습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 소유자 체크 (정확히 root)
  if [ "$owner" != "root" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 소유자가 root가 아닙니다. (owner=$owner)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 권한 정규화
  #   - stat -c %a 가 0 / 00 / 000 처럼 나올 수도 있으니 3자리로 맞춤
  #   - 4자리(특수권한 포함)면 마지막 3자리만 사용 (예: 0400 -> 400)
  if [[ "$perm" =~ ^[0-7]{4}$ ]]; then
    perm="${perm:1:3}"
  elif [[ "$perm" =~ ^[0-7]{1,3}$ ]]; then
    perm="$(printf "%03d" "$perm")"
  fi

  # 형식 검증
  if ! [[ "$perm" =~ ^[0-7]{3}$ ]]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target 파일 권한 형식이 예상과 다릅니다. (perm=$perm)" >> "$resultfile" 2>&1
    return 0
  fi

  # 4) 핵심 기준: 권한이 정확히 400만 양호 (000도 취약 처리)
  if [ "$perm" != "400" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일 권한이 400이 아닙니다. (perm=$perm)" >> "$resultfile" 2>&1
    return 0
  fi

  # (옵션) 자리별 확인(방어적) - perm=400이면 사실상 필요 없지만 명확성 위해 유지
  local o g oth
  o="${perm:0:1}"; g="${perm:1:1}"; oth="${perm:2:1}"
  if [ "$o" != "4" ] || [ "$g" != "0" ] || [ "$oth" != "0" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일 권한 구성(owner/group/other)이 기준과 다릅니다. (perm=$perm)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-18 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " $target 소유자(root) 및 권한(perm=$perm)이 기준(400)을 만족합니다." >> "$resultfile" 2>&1
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

#수진
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
    echo "" >> $resultfile 2>&1
    echo "▶ U-20(상) | 2. 파일 및 디렉토리 관리 > 2.7 systemd *.socket, *.service 파일 소유자 및 권한 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : systemd *.socket, *.service 파일의 소유자가 root이고, 권한이 644 이하인 경우"  >> $resultfile 2>&1
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
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " $file 파일의 소유자가 root가 아닙니다." >> $resultfile 2>&1
                elif [ "$perm" -gt 644 ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " $file 파일의 권한이 644 초과입니다." >> $resultfile 2>&1
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
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " $file 파일의 소유자가 root가 아닙니다." >> $resultfile 2>&1
                elif [ "$perm" -gt 644 ]; then
                    echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " $file 파일의 권한이 644 초과입니다." >> $resultfile 2>&1
                fi
            done
        fi
    fi
    if [ $file_exists_count -eq 0 ]; then
        echo "※ U-20 결과 : N/A" >> $resultfile 2>&1
        echo " systemd socket/service 파일이 없습니다." >> $resultfile 2>&1
    else
        echo "※ U-20 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}
#희윤
U_21(){
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-21(상) | 2. 파일 및 디렉토리 관리 > 2.8 /etc/(r)syslog.conf 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 :  /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우" >> "$resultfile" 2>&1

  local target
  # 1. rsyslog.conf 또는 syslog.conf파일 존재하는지 확인
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else 
    echo "※ U-21 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2. 1에서 파일의 소유자 및 권한 확인
  local OWNER PERMIT
  OWNER="$(sudo stat -c '%U' "$target" 2>/dev/null)"
  PERMIT="$(sudo stat -c'%a' "$target" 2>/dev/null)"
  # 정보 못읽어 올때 처리 어떻게 할지 
  # [정보 못 읽어올 때 처리] - 변수가 비어있는지 체크
  if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
    echo "※ U-21 결과 : N/A" >> "$resultfile" 2>&1
    echo " stat 명령으로 $target 정보를 읽지 못했습니다. (권한 문제 등)" >> "$resultfile" 2>&1
    return 0
  fi

  if [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
    echo "※ U-21 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 소유자가 root, bin, sys가 아닙니다. (owner=$OWNER)" >> "$resultfile" 2>&1
    return 0
  fi

  
  # 3. 파일의 권한이 640이하 인지 체크 
  if [ "$PERMIT" -gt 640 ]; then
    echo "※ U-21 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 권한이 640보다 큽니다. (permit=$PERMIT)" >> "$resultfile" 2>&1
    return 0
  fi

  # 4. 결과 출력
  echo "※ U-21 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " $target 파일의 소유자($OWNER) 및 권한($PERMIT)이 기준에 적합합니다." >> "$resultfile" 2>&1

}
#연수
U_23() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-23(상) | UNIX > 2. 파일 및 디렉토리 관리| SUID, SGID, Sticky bit 설정 파일 점검 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"  >> "$resultfile" 2>&1

  # 점검 대상(가이드에서 지정한 주요 실행 파일)
  local executables=(
    "/sbin/dump"
    "/sbin/restore"
    "/sbin/unix_chkpwd"
    "/usr/bin/at"
    "/usr/bin/lpq" "/usr/bin/lpq-lpd"
    "/usr/bin/lpr" "/usr/bin/lpr-lpd"
    "/usr/bin/lprm" "/usr/bin/lprm-lpd"
    "/usr/bin/newgrp"
    "/usr/sbin/lpc" "/usr/sbin/lpc-lpd"
    "/usr/sbin/traceroute"
  )

  # ✅ 정상적으로 SUID/SGID가 존재할 수 있는(배포판 기본) 예외 목록
  # - 환경에 따라 다를 수 있으니, 네 시스템에서 실제 기본값을 기준으로 조정
  local whitelist=(
    "/sbin/unix_chkpwd"
    "/usr/bin/newgrp"
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
  )

  # whitelist 포함 여부 함수
  _is_whitelisted() {
    local file="$1"
    for w in "${whitelist[@]}"; do
      if [ "$file" = "$w" ]; then
        return 0
      fi
    done
    return 1
  }

  local vuln_found=0
  local warn_found=0

  for f in "${executables[@]}"; do
    if [ -f "$f" ]; then
      local oct_perm mode special
      oct_perm="$(stat -c '%a' "$f" 2>/dev/null)"
      mode="$(stat -c '%A' "$f" 2>/dev/null)"
      [ -z "$oct_perm" ] && continue

      # 특수권한 자리(4xxx/2xxx/6xxx/7xxx) 추출
      special="0"
      if [ "${#oct_perm}" -eq 4 ]; then
        special="${oct_perm:0:1}"
      fi

      # SUID/SGID 여부: mode에 s/S가 있는지로 최종 확인
      if [[ "$special" =~ [2467] ]] && [[ "$mode" =~ [sS] ]]; then
        if _is_whitelisted "$f"; then
          warn_found=1
        else
          vuln_found=1
        fi
      fi
    fi
  done

  # 최종 판정
  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-23 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " whitelist(예외) 외 주요 실행 파일에서 SUID/SGID 설정이 확인되었습니다. (위 근거 참고)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$warn_found" -eq 1 ]; then
    echo "※ U-23 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " SUID/SGID 설정이 일부 파일에서 확인되었으나, whitelist(기본값 가능)로 분류했습니다. (Warning 항목 참고)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-23 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 점검 대상 주요 실행 파일에서 SUID/SGID 설정이 확인되지 않았습니다." >> "$resultfile" 2>&1
  return 0
}

#연진
U_24() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-24(상) | 2. 파일 및 디렉토리 관리 > 2.11 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정이고, 쓰기 권한이 통제된 경우" >> "$resultfile" 2>&1
  
    VULN=0
    REASON=""
  
    # 1. OS별 주요 점검 파일 지정
    # Rocky: .bash_profile 중심 / Ubuntu: .profile 중심
    CHECK_FILES=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout" ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts")
  
    # 2. 로그인 가능한 사용자 추출 (Ubuntu 24.04의 /usr/sbin/nologin 경로 고려)
    USER_LIST=$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd)
  
    for USER_INFO in $USER_LIST; do
        USER_NAME=$(echo "$USER_INFO" | cut -d: -f1)
        USER_HOME=$(echo "$USER_INFO" | cut -d: -f2)
    
        if [ -d "$USER_HOME" ]; then
            for FILE in "${CHECK_FILES[@]}"; do
                TARGET="$USER_HOME/$FILE"
        
                if [ -f "$TARGET" ]; then
                    # 4. 파일 소유자 확인 (stat 명령어가 ls보다 결과값이 고정적임)
                    FILE_OWNER=$(stat -c "%U" "$TARGET")
                    
                    if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
                        VULN=1
                        REASON="$REASON [소유자 불일치] $TARGET (소유자: $FILE_OWNER) |"
                    fi
          
                    # 5. 파일 권한 확인 (8진수 권한 추출)
                    PERM_OCT=$(stat -c "%a" "$TARGET") # 예: 644
                    
                    # 8진수 권한의 각 자리수 분리 (사용자/그룹/기타)
                    # 그룹(2번째 자리) 또는 기타(3번째 자리)에 쓰기(2, 3, 6, 7) 권한이 있는지 확인
                    if [[ "$PERM_OCT" =~ .[2367]. ]] || [[ "$PERM_OCT" =~ ..[2367] ]]; then
                        VULN=1
                        REASON="$REASON [권한 취약] $TARGET (권한: $PERM_OCT) |"
                    fi
                fi
            done
        fi
    done
  
    if [ $VULN -eq 1 ]; then
        echo "※ U-24 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-24 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

#수진
U_25() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-25(상) | 2. 파일 및 디렉토리 관리 > 2.12 world writable 파일 점검 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"  >> $resultfile 2>&1
    if [ `find / -type f -perm -2 2>/dev/null | wc -l` -gt 0 ]; then
        echo "※ U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " world writable 설정이 되어있는 파일이 있습니다." >> $resultfile 2>&1
    else
        echo "※ U-25 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}
#희윤
U_26(){
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-26(상) | 2. 파일 및 디렉토리 관리 > /dev에 존재하지 않는 device 파일 점검 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우" >> "$resultfile" 2>&1

  local target_dir="/dev"
  local VULN=0
  local REASON=""

  # 1. /dev 디렉터리 존재 여부 체크
  if [ ! -d "$target_dir" ]; then
    echo  
    echo "※ U-26 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target_dir 디렉터리가 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2. /dev 디렉터리가 있다면 존재하지 않는 디바이스인지 확인하기 위해 파일 type이 일반 파일 인것만 찾기
  # /dev/mqueue나 /dev/shm 파일은 제외함 
  VUL_FILES=$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null)

  if [ -n "$VUL_FILES" ]; then
    VULN=1
    REASON="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되었습니다. $(echo $VUL_FILES | tr '\n' ' ')"
  fi

  # 3. 결과 출력 
  if [ "$VULN" -eq 1 ]; then
        echo "※ U-26 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [Reason] $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-26 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_28() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-28(상) | 2. 파일 및 디렉토리 관리 > 접속 IP 및 포트 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우" >> "$resultfile" 2>&1

  local deny="/etc/hosts.deny"
  local allow="/etc/hosts.allow"

  # ---- 0) TCP Wrapper(libwrap) 적용 가능성 체크
  local libwrap_exists=0
  if ls /lib*/libwrap.so* /usr/lib*/libwrap.so* >/dev/null 2>&1; then
    libwrap_exists=1
  fi

  local sshd_uses_wrap="unknown"
  if command -v sshd >/dev/null 2>&1; then
    local sshd_path
    sshd_path="$(command -v sshd 2>/dev/null)"
    if command -v ldd >/dev/null 2>&1; then
      if ldd "$sshd_path" 2>/dev/null | grep -qi 'libwrap'; then
        sshd_uses_wrap="yes"
      else
        sshd_uses_wrap="no"
      fi
    fi
  fi

  if [ "$libwrap_exists" -eq 0 ]; then
    echo "※ U-28 결과 : N/A" >> "$resultfile" 2>&1
    echo " TCP Wrapper(libwrap) 라이브러리가 확인되지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # ---- 1) 파일 존재 여부
  if [ ! -f "$deny" ]; then
    echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $deny 파일이 없습니다. (기본 차단 정책 없음)" >> "$resultfile" 2>&1
    return 0
  fi

  # 정규화 함수 (공백/주석 제거)
  _normalized_lines() {
    local f="$1"
    sed -e 's/[[:space:]]//g' -e '/^#/d' -e '/^$/d' "$f" 2>/dev/null
  }

  # ---- 2) deny ALL:ALL 확인
  local deny_allall_count
  deny_allall_count="$(_normalized_lines "$deny" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"

  # ---- 3) allow ALL:ALL 확인
  local allow_allall_count=0
  if [ -f "$allow" ]; then
    allow_allall_count="$(_normalized_lines "$allow" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"
  fi

  # allow 전체허용 → 무조건 취약
  if [ "$allow_allall_count" -gt 0 ]; then
    echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $allow 파일에 'ALL:ALL' 설정이 있습니다. (전체 허용)" >> "$resultfile" 2>&1
    return 0
  fi

  # deny ALL:ALL 없으면 서비스별 규칙 확인
  if [ "$deny_allall_count" -eq 0 ]; then
    local deny_has_rules
    deny_has_rules="$(_normalized_lines "$deny" | grep -Eci '^[^:]+:[^:]+')"

    if [ "$deny_has_rules" -gt 0 ]; then
      echo "※ U-28 결과 : 양호(Good)" >> "$resultfile" 2>&1
      echo " 기본 ALL:ALL은 없지만, 서비스별 접근 제한 규칙이 존재합니다." >> "$resultfile" 2>&1
      return 0
    fi

    echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 접근 제한 규칙이 설정되어 있지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # ---- 정상 (deny ALL:ALL + allow 전체허용 없음)
  echo "※ U-28 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 기본 차단 정책(ALL:ALL)이 적용되어 있으며 전체 허용 설정이 없습니다." >> "$resultfile" 2>&1
  return 0
}

#연진
U_29() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-29(하) | 2. 파일 및 디렉토리 관리 > 2.16 hosts.lpd 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : /etc/hosts.lpd 파일이 존재하지 않거나, 소유자가 root이고 권한이 600 이하인 경우" >> "$resultfile" 2>&1
  
    VULN=0
    REASON=""
    
    # [수정] ldp -> lpd 로 변경 (매우 중요!)
    TARGET="/etc/hosts.lpd"
  
    # 1. /etc/hosts.lpd 파일 존재 여부 확인
    if [ -f "$TARGET" ]; then
        OWNER=$(stat -c "%U" "$TARGET")
        PERMIT=$(stat -c "%a" "$TARGET")
  
        # 2. 파일 소유자가 root인지 확인
        if [ "$OWNER" != "root" ]; then
            VULN=1
            REASON="$REASON 파일의 소유자가 root가 아닙니다(현재: $OWNER). |"
        fi
    
        # 3. 파일 권한 체크
        if [ "$PERMIT" -gt 600 ]; then
            VULN=1
            REASON="$REASON 파일 권한이 600보다 큽니다(현재: $PERMIT). |"
        fi
    else
        :
    fi
  
    # 4. 결과 출력
    if [ $VULN -eq 1 ]; then
        echo "※ U-29 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-29 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

#수진
U_30() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-30(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> $resultfile 2>&1
    umaks_value=`umask`

    # 현재 세션 umask 설정 점검
    if [ ${umaks_value:2:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    elif [ ${umaks_value:3:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    fi

    # /etc/profile 파일 내 umask 설정 점검
    if [ ${umaks_value:2:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    elif [ ${umaks_value:3:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    fi
    # /etc/profile 파일 내 umask 설정 점검
    # 변수로 선언한 umask, 즉 umask=값 형태는 무시
    if [ -f /etc/profile ]; then
        umaks_value=($(
            grep -vE '^[[:space:]]*#' /etc/profile \
            | grep -i 'umask' \
            | grep -vE 'if|=' \
            | awk '{print $2}'
        ))
        for ((i=0; i<${#umaks_value[@]}; i++))
        do
            if [ ${#umaks_value[$i]} -eq 2 ]; then
                if [ ${umaks_value[$i]:0:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                elif [ ${umaks_value[$i]:1:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                fi
            elif [ ${#umaks_value[$i]} -eq 4 ]; then
                if [ ${umaks_value[$i]:2:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                elif [ ${umaks_value[$i]:3:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                fi
            elif [ ${#umaks_value[$i]} -eq 3 ]; then
                if [ ${umaks_value[$i]:1:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                elif [ ${umaks_value[$i]:2:1} -lt 2 ]; then
                    echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                fi
            elif [ ${#umaks_value[$i]} -eq 1 ]; then
                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                echo " /etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
            else
                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                echo " /etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
            fi
        done
    fi

    # /etc/bashrc, /etc/csh.login, /etc/csh.cshrc 파일 내 umask 설정 확인
    umask_settings_files=("/etc/bashrc" "/etc/csh.login" "/etc/csh.cshrc")
    for ((i=0; i<${#umask_settings_files[@]}; i++))
    do
        if [ -f ${umask_settings_files[$i]} ]; then
            file_umask_count=`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l`
            if [ $file_umask_count -gt 0 ]; then
                umaks_value=(`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
                for ((j=0; j<${#umaks_value[@]}; j++))
                do
                    if [ ${#umaks_value[$j]} -eq 2 ]; then
                        if [ ${umaks_value[$j]:0:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        elif [ ${umaks_value[$j]:1:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        fi
                    elif [ ${#umaks_value[$j]} -eq 4 ]; then
                        if [ ${umaks_value[$j]:2:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        elif [ ${umaks_value[$j]:3:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        fi
                    elif [ ${#umaks_value[$j]} -eq 3 ]; then
                        if [ ${umaks_value[$j]:1:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        elif [ ${umaks_value[$j]:2:1} -lt 2 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        fi
                    elif [ ${#umaks_value[$j]} -eq 1 ]; then
                        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                        echo " ${umask_settings_files[$i]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                    else
                        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                        echo " ${umask_settings_files[$i]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
                    fi
                done
            fi
        fi
    done

    # 사용자 홈 디렉터리 설정 파일에서 umask 설정 확인
    mapfile -t user_homedirectory_path < <(awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq)
    user_homedirectory_path2=(/home/*)
    for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
    do
        user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]}
    done
    umask_settings_files=(".cshrc" ".profile" ".login" ".bashrc" ".kshrc")
    for ((i=0; i<${#user_homedirectory_path[@]}; i++))
    do
        for ((j=0; j<${#umask_settings_files[@]}; j++))
        do
            if [ -f ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} ]; then
                user_homedirectory_setting_umask_count=$(grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l)
                if [ $user_homedirectory_setting_umask_count -gt 0 ]; then
                    umaks_value=($(grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'))
                    for ((k=0; k<${#umaks_value[@]}; k++))
                    do
                        if [ ${#umaks_value[$k]} -eq 2 ]; then
                            if [ ${umaks_value[$k]:0:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            elif [ ${umaks_value[$k]:1:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            fi
                        elif [ ${#umaks_value[$k]} -eq 4 ]; then
                            if [ ${umaks_value[$k]:2:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            elif [ ${umaks_value[$k]:3:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            fi
                        elif [ ${#umaks_value[$k]} -eq 3 ]; then
                            if [ ${umaks_value[$k]:1:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            elif [ ${umaks_value[$k]:2:1} -lt 2 ]; then
                                echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                                echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                            fi
                        elif [ ${#umaks_value[$k]} -eq 1 ]; then
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
                        else
                            echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                            echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
                        fi
                    done
                fi
            fi
        done
    done
    echo "※ U-30 결과 : 양호(Good)" >> $resultfile 2>&1
}
#희윤
U_31() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-31(중) | 2. 파일 및 디렉토리 관리 > 2.18 홈 디렉토리 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우" >> "$resultfile" 2>&1

  VULN=0
  REASON=""

  # 1. /etc/passwd에서 일반 사용자 계정 추출 (UID 1000이상, 시스템 계정 제외하고)
  USER_LIST=$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd)

  for USER in $USER_LIST; do
    USERNAME=$(echo "$USER" | cut -d: -f1)
    HOMEDIR=$(echo "$USER" | cut -d: -f2)

    # 2. 홈 디렉토리 실제로 존재하는지 확인
    if [ -d "$HOMEDIR" ]; then
      OWNER=$(stat -c '%U' "$HOMEDIR")
      PERMIT=$(stat -c '%a' "$HOMEDIR")
      OTHERS_PERMIT=$(echo "$PERMIT" | sed 's/.*\(.\)$/\1/')

      # 3. 홈 디렉토리 소유자가 계정명과 일치하는지 여부 판단
      if [ "$OWNER" != "$USERNAME" ]; then
        VULN=1
        REASON="$REASON 소유자가 불일치 합니다. $USERNAME 계정의 홈($HOMEDIR), 현재 소유자 : $OWNER 입니다. |"
      fi

      # 4. 타 사용자 쓰기 권한이 포함되어 있는지 여부 판단
      if [[ "$OTHERS_PERMIT" =~ [2367] ]]; then
        VULN=1
        REASON="$REASON 타 사용자 쓰기권한이 $USERNAME 계정의 홈 $HOMEDIR 에 존재합니다. (현재 권한: $PERMIT) |"
      fi
    else
      VULN=1
      REASON="$REASON $USERNAME 계정의 홈 디렉토리가 존재하지 않습니다. "
    fi
  done

  # 5. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-31 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo "$REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-31 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_33() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-33(하) | UNIX > 2. 파일 및 디렉토리 관리 > 숨겨진 파일 및 디렉토리 검색 및 제거 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 삭제한 경우" >> "$resultfile" 2>&1

  ########################################################
  # 1) 전체 숨김 파일/디렉터리 목록 (정보 제공)
  ########################################################
  ALL_HIDDEN=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" \( -type f -o -type d \) -print 2>/dev/null)

  ########################################################
  # 2) 의심 징후 숨김파일
  # 기준: 실행 가능 / SUID / SGID / 최근 7일 변경
  ########################################################
  SUS_HIDDEN_FILES=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" -type f \
    \( -executable -o -perm -4000 -o -perm -2000 -o -mtime -7 \) \
    -print 2>/dev/null)

  # 개수 계산
  if [ -n "$SUS_HIDDEN_FILES" ]; then
    SUS_COUNT=$(echo "$SUS_HIDDEN_FILES" | wc -l)
  else
    SUS_COUNT=0
  fi

  ########################################################
  # 3) 최종 판정 (요약 1줄)
  ########################################################
  if [ "$SUS_COUNT" -gt 0 ]; then
    echo "※ U-33 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 의심 징후 숨김파일이 발견되었습니다. (count=$SUS_COUNT)" >> "$resultfile" 2>&1
  else
    echo "※ U-33 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " 의심 징후 숨김파일이 발견되지 않았습니다. (count=0)" >> "$resultfile" 2>&1
  fi

  return 0
}
#연진
U_34() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-34(상) | 3. 서비스 관리 > 3.1 Finger 서비스 비활성화 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : Finger 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

    VULN=0
    REASON=""
  
    # 1. finger 서비스 실행 여부 확인 (systemctl)
    SERVICES=("finger" "fingerd" "in.fingerd" "finger.socket")
    for SVC in "${SERVICES[@]}"; do
        if systemctl is-active "$SVC" >/dev/null 2>&1; then
            VULN=1
            REASON="$REASON Finger 서비스가 활성화되어 있습니다. |"
        fi
    done
  
    # 2. finger 프로세스 실행 여부 확인 
    if ps -ef | grep -v grep | grep -Ei "fingerd|in.fingerd" >/dev/null; then
        VULN=1
        REASON="$REASON Finger 프로세스가 실행 중입니다. |"
    fi
  
    # 3. finger 포트 리스닝 여부 확인 
    if command -v ss >/dev/null 2>&1; then
        PORT_CHECK=$(ss -nlp | grep -w ":79")
    else
        PORT_CHECK=$(netstat -natp 2>/dev/null | grep -w ":79")
    fi  
  
    if [ -n "$PORT_CHECK" ]; then
        VULN=1
        REASON="$REASON Finger 포트가 리스닝 중입니다. |"
    fi
  
    # 4. 결과 출력 
    if [ $VULN -eq 1 ]; then
        echo "※ U-34 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-34 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
} # [수정] 맨 마지막에 있던 불필요한 fi 제거
#수진
U_35() {
    vuln_flag=0
    evidence_flag=0
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-35(상) | 3. 서비스 관리 > 3.2 공유 서비스에 대한 익명 접근 제한 설정 ◀"  >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 공유 서비스에 대해 익명 접근을 제한한 경우" >> "$resultfile" 2>&1
    print_vuln_header_once() {
        if [ "$evidence_flag" -eq 0 ]; then
            echo "※ U-35 결과 : 취약(Vulnerable)" >> "$resultfile"
            evidence_flag=1
        fi
    }
    is_listening_port() {
        ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
    }
    is_active_service() {
        systemctl is-active "$1" >/dev/null 2>&1
    }
    # FTP 점검 (vsftp / proftp)
    ftp_checked=0
    ftp_running=0
    ftp_pkg=0
    ftp_conf_found=0
    if command -v rpm >/dev/null 2>&1; then
        rpm -q vsftpd >/dev/null 2>&1 && ftp_pkg=1
        rpm -q proftpd >/dev/null 2>&1 && ftp_pkg=1
        rpm -q proftpd-core >/dev/null 2>&1 && ftp_pkg=1
    fi
    if is_active_service vsftpd || is_active_service proftpd; then
        ftp_running=1
    fi
    if is_listening_port 21; then
        ftp_running=1
    fi
    VSFTPD_FILES=()
    PROFTPD_FILES=()
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [ -f "$f" ] && VSFTPD_FILES+=("$f")
    done
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/proftpd.d/proftpd.conf; do
        [ -f "$f" ] && PROFTPD_FILES+=("$f")
    done
    if command -v rpm >/dev/null 2>&1; then
        if rpm -q vsftpd >/dev/null 2>&1; then
            while IFS= read -r f; do
                [ -f "$f" ] && VSFTPD_FILES+=("$f")
            done < <(rpm -qc vsftpd 2>/dev/null)
        fi
        for pkg in proftpd proftpd-core; do
            if rpm -q "$pkg" >/dev/null 2>&1; then
                while IFS= read -r f; do
                    [ -f "$f" ] && PROFTPD_FILES+=("$f")
                done < <(rpm -qc "$pkg" 2>/dev/null)
            fi
        done
    fi
    dedup() { printf "%s\n" "$@" | awk 'NF && !seen[$0]++'; }
    mapfile -t VSFTPD_FILES < <(dedup "${VSFTPD_FILES[@]}")
    mapfile -t PROFTPD_FILES < <(dedup "${PROFTPD_FILES[@]}")
    if [ "${#VSFTPD_FILES[@]}" -gt 0 ] || [ "${#PROFTPD_FILES[@]}" -gt 0 ]; then
        ftp_conf_found=1
    fi
    if [ "$ftp_conf_found" -eq 1 ] || [ "$ftp_running" -eq 1 ] || [ "$ftp_pkg" -eq 1 ]; then
        ftp_checked=1
    fi
    if [ "$ftp_checked" -eq 1 ]; then
        for conf in "${PROFTPD_FILES[@]}"; do
            [ -f "$conf" ] || continue
            block_hit=$(
                awk '
                    BEGIN{inblk=0;hit=0}
                    /^[[:space:]]*#/ {next}
                    /<Anonymous[[:space:]>]/ {inblk=1}
                    inblk && /<\/Anonymous>/ {inblk=0}
                    inblk && ($1 ~ /^User$/ || $1 ~ /^UserAlias$/) {hit=1}
                    END{print hit}
                ' "$conf" 2>/dev/null
            )
            if [ "$block_hit" = "1" ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " $conf 파일에서 익명(Anonymous) FTP 설정 블록이 존재합니다." >> "$resultfile"
            fi
        done
        for conf in "${VSFTPD_FILES[@]}"; do
            [ -f "$conf" ] || continue
            last_val=$(
                grep -i '^[[:space:]]*anonymous_enable[[:space:]]*=' "$conf" 2>/dev/null \
                | grep -v '^[[:space:]]*#' \
                | tail -n 1 \
                | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}'
            )
            if [ -n "$last_val" ] && [ "$last_val" = "yes" ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " $conf 파일에서 익명 FTP 접속 허용(anonymous_enable=YES)." >> "$resultfile"
            fi
        done
        if [ "$ftp_conf_found" -eq 0 ] && [ "$ftp_running" -eq 1 ]; then
            vuln_flag=1
            print_vuln_header_once
            echo " FTP 서비스가 동작 중이나(vsftpd/proftpd 또는 21/tcp 리슨), 설정 파일을 확인할 수 없습니다." >> "$resultfile"
        fi
    fi

    # NFS 점검
    nfs_checked=0
    nfs_running=0
    nfs_conf_found=0
    [ -f /etc/exports ] && nfs_conf_found=1
    is_active_service nfs-server && nfs_running=1
    nfs_pkg=0
    if command -v rpm >/dev/null 2>&1; then
        rpm -q nfs-utils >/dev/null 2>&1 && nfs_pkg=1
    fi
    if [ "$nfs_conf_found" -eq 1 ] || [ "$nfs_running" -eq 1 ] || [ "$nfs_pkg" -eq 1 ]; then
        nfs_checked=1
    fi
    if [ "$nfs_checked" -eq 1 ]; then
        if [ -f /etc/exports ]; then
            cnt_no_root=$(
                grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
                | grep -E '(^|[[:space:]\(,])no_root_squash([[:space:]\),]|$)' \
                | wc -l
            )
            if [ "$cnt_no_root" -gt 0 ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " /etc/exports 에 no_root_squash 설정이 존재합니다." >> "$resultfile"
            fi
            cnt_star=$(
                grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
                | grep -E '(^|[[:space:]])\*([[:space:]\(]|$)' \
                | wc -l
            )
            if [ "$cnt_star" -gt 0 ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " /etc/exports 전체 호스트(*) 공유 설정이 존재합니다." >> "$resultfile"
            fi
        else
            if [ "$nfs_running" -eq 1 ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " NFS 서비스가 동작 중이나(nfs-server active), /etc/exports 파일이 존재하지 않습니다." >> "$resultfile"
            fi
        fi
    fi

    # Samba 점검
    smb_checked=0
    smb_running=0
    smb_conf_found=0
    [ -f /etc/samba/smb.conf ] && smb_conf_found=1
    (is_active_service smb || is_active_service nmb) && smb_running=1
    smb_pkg=0
    if command -v rpm >/dev/null 2>&1; then
        rpm -q samba >/dev/null 2>&1 && smb_pkg=1
    fi
    if [ "$smb_conf_found" -eq 1 ] || [ "$smb_running" -eq 1 ] || [ "$smb_pkg" -eq 1 ]; then
        smb_checked=1
    fi
    if [ "$smb_checked" -eq 1 ]; then
        if [ -f /etc/samba/smb.conf ]; then
            smb_hits=$(
                grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
                | grep -Ei '^[[:space:]]*(guest[[:space:]]+ok|public|map[[:space:]]+to[[:space:]]+guest|security)[[:space:]]*='
            )
            if [ -n "$smb_hits" ]; then
                cnt_guest=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' | wc -l)
                cnt_public=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*public[[:space:]]*=[[:space:]]*yes' | wc -l)
                cnt_share=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*security[[:space:]]*=[[:space:]]*share' | wc -l)
                cnt_map=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=' | wc -l)
                if [ "$cnt_guest" -gt 0 ] || [ "$cnt_public" -gt 0 ] || [ "$cnt_share" -gt 0 ] || [ "$cnt_map" -gt 0 ]; then
                    vuln_flag=1
                    print_vuln_header_once
                    echo " /etc/samba/smb.conf 익명/게스트 접근 유발 가능 설정이 존재합니다." >> "$resultfile"
                    echo "$smb_hits" | head -n 5 | sed 's/^/  - /' >> "$resultfile"
                fi
            fi
        else
            if [ "$smb_running" -eq 1 ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " Samba 서비스가 동작 중이나(smb/nmb active), /etc/samba/smb.conf 파일이 존재하지 않습니다." >> "$resultfile"
            fi
        fi
    fi
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-35 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}
#희윤
U_36(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-36(상) | 3. 서비스 관리 > 3.3 r 계열 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 r 계열 서비스가 비활성화된 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""

  # 1. rexec, rlogin, rsh포트가 Listen 중인지 확인
  CHECK_PORT=$(ss -antl | grep -E ':512|:513|:514')
  
  if [ -n "$CHECK_PORT" ]; then
    VULN=1
    REASON="$REASON r-command 관련 포트(512, 513, 514)가 활성화되어 있습니다. |"
  fi

  # 2. systemctl을 사용하는 서비스 점검
  SERVICES=("rlogin" "rsh" "rexec" "shell" "login" "exec")
  
  for SVC in "${SERVICES[@]}"; do
    # 3. 서비스가 존재하는지 확인하고, 실행 여부 체크
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
      VULN=1
      REASON="$REASON 활성화된 r 계열 서비스를 발견하였습니다. $SVC 서비스가 구동 중입니다. |"
    fi
  done

  # 4. xinetd 설정 파일 점검
  if [ -d "/etc/xinetd.d" ]; then
    XINTETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec 2>/dev/null)
    if [ -n "$XINTETD_VUL" ]; then
      VULN=1
      REASON=" $REASON xinetd 설정이 취약합니다. 다음 파일에서 서비스가 활성화 되었습니다. $(echo $XINETD_VUL | tr '\n' ' ') |"
    fi
  fi

  # 5. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-36 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-36 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_38() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-38(상) | UNIX > 3. 서비스 관리 | DoS 공격에 취약한 서비스 비활성화 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 해당 서비스를 사용하지 않는 경우 N/A, (2) DoS 공격에 취약한 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

  local in_scope_active=0     # 점검 대상 서비스가 실제로 '활성'인지 (N/A 판단용)
  local vulnerable=0
  local evidences=()

  # (1) inetd/xinetd 계열(전통 DoS 취약 서비스)
  local inetd_services=("echo" "discard" "daytime" "chargen")

  # (2) systemd socket 유닛(inetd 대체)
  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")

  # (3) 확장 예시: SNMP / DNS (NTP는 보통 필요 → 기본은 info)
  local snmp_units=("snmpd.service")
  local dns_units=("named.service" "bind9.service")

  # NTP는 정책 스위치로 제어 (기본: 취약 판정에서 제외)
  local CHECK_NTP=0
  local ntp_units=("chronyd.service" "ntpd.service" "systemd-timesyncd.service")

  ############################
  # A. xinetd 점검
  ############################
  if [ -d /etc/xinetd.d ]; then
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
        # disable=yes면 비활성
        local disable_yes_count
        disable_yes_count=$(grep -vE '^\s*#' "/etc/xinetd.d/${svc}" 2>/dev/null \
          | grep -iE '^\s*disable\s*=\s*yes\s*$' | wc -l)

        if [ "$disable_yes_count" -eq 0 ]; then
          in_scope_active=1
          vulnerable=1
          evidences+=("xinetd: ${svc} 서비스가 비활성화(disable=yes) 되어 있지 않습니다. (/etc/xinetd.d/${svc})")
        else
          evidences+=("xinetd: ${svc} 서비스가 disable=yes 로 비활성화되어 있습니다.")
        fi
      fi
    done
  fi

  ############################
  # B. inetd.conf 점검
  ############################
  if [ -f /etc/inetd.conf ]; then
    for svc in "${inetd_services[@]}"; do
      local enable_count
      enable_count=$(grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w "$svc" | wc -l)
      if [ "$enable_count" -gt 0 ]; then
        in_scope_active=1
        vulnerable=1
        evidences+=("inetd: ${svc} 서비스가 /etc/inetd.conf 에서 활성화되어 있습니다.")
      fi
    done
  fi

  ############################
  # C. systemd socket / service 점검
  ############################
  if command -v systemctl >/dev/null 2>&1; then
    # 전통 inetd 대체 socket
    for sock in "${systemd_sockets[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$sock"; then
        if systemctl is-enabled --quiet "$sock" 2>/dev/null || systemctl is-active --quiet "$sock" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("systemd: ${sock} 가 활성화되어 있습니다. (enabled/active)")
        else
          evidences+=("systemd: ${sock} 가 비활성화 상태입니다.")
        fi
      fi
    done

    # SNMP
    for unit in "${snmp_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("SNMP: ${unit} 가 활성화되어 있습니다.")
        else
          evidences+=("SNMP: ${unit} 가 비활성화 상태입니다.")
        fi
      fi
    done

    # DNS
    for unit in "${dns_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("DNS: ${unit} 가 활성화되어 있습니다.")
        else
          evidences+=("DNS: ${unit} 가 비활성화 상태입니다.")
        fi
      fi
    done

    # NTP (기본은 info로만)
    for unit in "${ntp_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          if [ "$CHECK_NTP" -eq 1 ]; then
            in_scope_active=1
            vulnerable=1
            evidences+=("NTP: ${unit} 가 활성화되어 있습니다. (정책상 점검 포함)")
          else
            evidences+=("info: NTP(${unit}) 활성화 감지(시간동기 서비스, 일반적으로 필요)")
          fi
        fi
      fi
    done
  fi

  ############################
  # D. N/A 판정 (점검 대상 서비스 미사용)
  #    - 취약 서비스 후보가 '활성'된 흔적이 하나도 없으면 N/A
  ############################
  if [ "$in_scope_active" -eq 0 ]; then
    echo "※ U-38 결과 : N/A" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스(대상)가 사용되지 않는 것으로 확인되어 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  ############################
  # 최종 판정
  ############################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-38 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스가 활성화되어 있습니다. (활성 서비스 존재)" >> "$resultfile" 2>&1
  else
    echo "※ U-38 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스가 비활성화되어 있습니다. (활성 서비스 미확인)" >> "$resultfile" 2>&1
  fi

  return 0
}
#연수
U_39() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-39(상) | UNIX > 3. 서비스 관리 > 불필요한 NFS 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> "$resultfile" 2>&1

  local found=0
  local reason=""

  # 1) systemd 기반 서비스 활성 여부 확인
  if command -v systemctl >/dev/null 2>&1; then
    local nfs_units=(
      "nfs-server"
      "nfs"
      "nfs-mountd"
      "rpcbind"
      "rpc-statd"
      "rpc-statd-notify"
      "rpc-gssd"
      "rpc-svcgssd"
      "rpc-idmapd"
      "nfs-idmapd"
    )

    for u in "${nfs_units[@]}"; do
      # 등록된 유닛만 대상으로 체크
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${u}.service"; then
        if systemctl is-active --quiet "${u}.service" 2>/dev/null; then
          found=1
          reason+="${u}.service active; "
        fi
      fi
    done

    # nfs 관련 서비스 전체에서 active 항목이 있는지 보조 체크
    if systemctl list-units --type=service 2>/dev/null | grep -Eiq 'nfs|rpcbind|statd|mountd|idmapd|gssd'; then
      # 위에서 이미 잡았을 수 있으니, 근거가 비어있을 때만 보강
      if [ -z "$reason" ]; then
        found=1
        reason="systemctl 목록에서 nfs/rpc 관련 서비스가 동작 중으로 보입니다."
      fi
    fi
  fi

  # 2) 프로세스 기반 보조 확인 (기존 U-24 스타일 유지)
  if ps -ef 2>/dev/null | grep -iE 'nfs|rpc\.statd|statd|rpc\.lockd|lockd|rpcbind|mountd|idmapd|gssd' \
    | grep -ivE 'grep|kblockd|rstatd' >/dev/null 2>&1; then
    found=1
    if [ -z "$reason" ]; then
      reason="NFS 관련 데몬 프로세스가 실행 중입니다. (ps -ef 기준)"
    fi
  fi

  if [ "$found" -eq 1 ]; then
    echo "※ U-39 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 불필요한 NFS 서비스 관련 데몬이 실행 중입니다. ($reason)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-39 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " NFS 서비스 관련 데몬이 비활성/미사용 상태입니다." >> "$resultfile" 2>&1
  return 0
}
#수진
U_40() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-40(상) | 3. 서비스 관리 > 3.7 NFS 접근 통제 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우" >> $resultfile 2>&1
    if [ "$(ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd|' | wc -l)" -gt 0 ]; then
        if [ -f /etc/exports ]; then
            etc_exports_all_count=$(grep -vE '^#|^\s#' /etc/exports | grep '/' | grep '*' | wc -l)
            etc_exports_insecure_count=$(grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -i 'insecure' | wc -l)
            etc_exports_directory_count=$(grep -vE '^#|^\s#' /etc/exports | grep '/' | wc -l)
            etc_exports_squash_count=$(grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -iE 'root_squash|all_squash' | wc -l)
            if [ $etc_exports_all_count -gt 0 ]; then
                echo "※ U-40 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                echo " /etc/exports 파일에 '*' 설정이 있습니다." >> $resultfile 2>&1
                echo " ### '*' 설정 = 모든 클라이언트에 대해 전체 네트워크 공유 허용" >> $resultfile 2>&1
            elif [ $etc_exports_insecure_count -gt 0 ]; then
                echo "※ U-40 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                echo " /etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다." >> $resultfile 2>&1
            else
                if [ $etc_exports_directory_count -ne $etc_exports_squash_count ]; then
                    echo "※ U-40 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " /etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다." >> $resultfile 2>&1
                fi
            fi
        fi
    else
        echo "※ U-40 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}
#희윤
U_41(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-41(상) | 3. 서비스 관리 > 3.8 불필요한 automountd 제거 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : automountd 서비스가 비활성화된 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""

  # 1. systemctl로 automountd 서비스 활성화 여부 확인
  if systemctl is-active --quiet autofs 2>/dev/null; then
    VULN=1
    REASON="$REASON automountd 서비스가 활성화되어 있습니다. |"
  fi

  # 2. 1번에서 확인되지 않았지만 프로세스가 실행되고 있는지 여부 확인
  if ps -ef | grep -v grep | grep -Ei "automount|autofs"; then
    if [ "$VULN" -eq 0 ]; then 
      VULN=1
      REASON="$REASON automountd 서비스가 활성화되어 실행중입니다. |"
    fi
  fi 

  # 3. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-41 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-41 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_43() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-43(상) | UNIX > 3. 서비스 관리 > NIS, NIS+ 점검 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) NIS 서비스를 사용하지 않는 경우 N/A, (2) 사용 시 NIS 서비스 비활성화 또는 불가피 시 NIS+ 사용" >> "$resultfile" 2>&1

  local mail_like_na=0   # N/A 여부 (여기서는 nis_in_use의 반대 개념)
  local nis_in_use=0     # NIS 사용 여부
  local vulnerable=0
  local evidences=()

  # NIS 관련 대표 프로세스
  local nis_procs_regex='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated'
  # NIS+ 관련(참고용)
  local nisplus_procs_regex='nisplus|rpc\.nisd|nisd'

  ########################################################
  # 1) NIS 사용 여부 판단 (핵심: yp* 실행/활성 흔적)
  ########################################################

  # (1-A) systemd 유닛 (NIS 핵심만 판단에 사용)
  if command -v systemctl >/dev/null 2>&1; then
    local nis_units=("ypserv.service" "ypbind.service" "ypxfrd.service")

    for unit in "${nis_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
          nis_in_use=1
          vulnerable=1
          evidences+=("systemd: ${unit} 가 active/enabled 상태입니다.")
        fi
      fi
    done

    # rpcbind는 NIS 전용이 아니라 N/A 판정엔 쓰지 않고 참고로만 남김
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "rpcbind.service"; then
      if systemctl is-active --quiet "rpcbind.service" 2>/dev/null || systemctl is-enabled --quiet "rpcbind.service" 2>/dev/null; then
        evidences+=("info: rpcbind.service 가 active/enabled 입니다. (NIS/RPC 계열 사용 가능성, 단 NIS 단독 증거는 아님)")
      fi
    fi
  fi

  # (1-B) 프로세스 실행 여부 (NIS 핵심)
  if ps -ef 2>/dev/null | grep -iE "$nis_procs_regex" | grep -vE 'grep|U_43\(|U_28\(' >/dev/null 2>&1; then
    nis_in_use=1
    vulnerable=1
    evidences+=("process: NIS 관련 프로세스(yp*)가 실행 중입니다.")
  fi

  # (1-C) 네트워크 리스닝(111 포트는 참고용)
  if command -v ss >/dev/null 2>&1; then
    if ss -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(ss). (RPC 사용 흔적)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(netstat). (RPC 사용 흔적)")
    fi
  fi

  # (1-D) NIS+ 감지(참고)
  if ps -ef 2>/dev/null | grep -iE "$nisplus_procs_regex" | grep -v grep >/dev/null 2>&1; then
    evidences+=("info: NIS+ 관련 프로세스 흔적이 감지되었습니다. (환경에 따라 양호 조건 충족 가능)")
  fi

  ########################################################
  # 2) NIS 미사용이면 N/A
  ########################################################
  if [ "$nis_in_use" -eq 0 ]; then
    echo "※ U-43 결과 : N/A" >> "$resultfile" 2>&1
    echo " NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (yp* 서비스/프로세스 미검출)" >> "$resultfile" 2>&1
    # 참고 정보가 있으면 같이 보여주기
    if [ "${#evidences[@]}" -gt 0 ]; then
      echo " --- 근거(Evidence) ---" >> "$resultfile" 2>&1
      for e in "${evidences[@]}"; do
        echo " - $e" >> "$resultfile" 2>&1
      done
    fi
    return 0
  fi

  ########################################################
  # 3) 사용 중이면(= NIS 활성 흔적) 취약/양호 판정
  #    - 이미지 기준상 "NIS 서비스가 활성화된 경우 취약"
  #    - (불가피 시 NIS+ 사용) 조건은 자동으로 확정하기 어려워서 Evidence로만 남김
  ########################################################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-43 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " NIS 서비스가 활성화(실행/enable)된 흔적이 확인되었습니다." >> "$resultfile" 2>&1
  else
    # 이 케이스는 거의 없지만, nis_in_use=1인데 active/enabled가 아닌 특이 케이스 대비
    echo "※ U-43 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " NIS 사용 흔적은 있으나 활성화(실행/enable) 상태는 확인되지 않았습니다." >> "$resultfile" 2>&1
  fi

  echo " --- 근거(Evidence) ---" >> "$resultfile" 2>&1
  for e in "${evidences[@]}"; do
    echo " - $e" >> "$resultfile" 2>&1
  done

  return 0
}
#연수
U_44() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-44(상) | UNIX > 3. 서비스 관리 > tftp, talk 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우" >> "$resultfile" 2>&1

  local services=("tftp" "talk" "ntalk")

  # 1) systemd 서비스 체크 (활성/동작 중이면 취약)
  if command -v systemctl >/dev/null 2>&1; then
    for s in "${services[@]}"; do
      # 흔한 유닛 이름들까지 같이 체크 (tftp/tftp-server, talk/talk-server 등 환경차 대응)
      local units=("$s" "$s.service" "${s}d" "${s}d.service" "${s}-server" "${s}-server.service" "tftp-server.service" "tftpd.service" "talkd.service")
      for u in "${units[@]}"; do
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
          if systemctl is-active --quiet "$u" 2>/dev/null; then
            echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " $s 서비스가 systemd에서 활성 상태입니다. (unit=$u)" >> "$resultfile" 2>&1
            return 0
          fi
        fi
      done
    done
  fi

  # 2) xinetd 설정 체크 (disable=yes가 아니면 취약)
  if [ -d /etc/xinetd.d ]; then
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        # 주석/공백 제외 후 disable 설정 확인
        local disable_line
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
          echo " $s 서비스가 /etc/xinetd.d/$s 에서 비활성화(disable=yes)되어 있지 않습니다." >> "$resultfile" 2>&1
          return 0
        fi
      fi
    done
  fi

  # 3) inetd.conf 체크 (주석 아닌 라인에 서비스가 있으면 취약)
  if [ -f /etc/inetd.conf ]; then
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -Eiq "(^|[[:space:]])$s([[:space:]]|$)"; then
        echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $s 서비스가 /etc/inetd.conf 파일에서 활성 상태(주석 아님)로 존재합니다." >> "$resultfile" 2>&1
        return 0
      fi
    done
  fi

  echo "※ U-44 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " tftp/talk/ntalk 서비스가 systemd/xinetd/inetd 설정에서 모두 비활성 상태입니다." >> "$resultfile" 2>&1
  return 0
}
#수진
U_45() {
    # 2026/02/06 기준 sendmail 최신 버전 : 8.18.2 를 기준으로 점검
    echo ""  >> $resultfile 2>&1
    echo "▶ U-45(상) | 3. 서비스 관리 > 3.12 메일 서비스 버전 점검 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 메일 서비스 버전이 최신버전인 경우" >> $resultfile 2>&1
    if [ -f /etc/services ]; then
        smtp_port_count=$(grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l)
        if [ $smtp_port_count -gt 0 ]; then
            smtp_port=($(grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'))
            for ((i=0; i<${#smtp_port[@]}; i++))
            do
                netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]} " | wc -l`
                if [ $netstat_smtp_count -gt 0 ]; then
                    rpm_smtp_version=`rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}'`
                    dnf_smtp_version=`dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}'`
                    if [[ $rpm_smtp_version != 8.18.2* ]] && [[ $dnf_smtp_version != 8.18.2* ]]; then
                        echo "※ U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                        echo " 메일 서비스 버전이 최신 버전(8.18.2)이 아닙니다." >> $resultfile 2>&1
                        return 0
                    fi
                fi
            done
        fi
    fi
    ps_smtp_count=$(ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l)
    if [ $ps_smtp_count -gt 0 ]; then
        rpm_smtp_version=$(rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}')
        dnf_smtp_version=$(dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}')
        if [[ $rpm_smtp_version != 8.18.2* ]] && [[ $dnf_smtp_version != 8.18.2* ]]; then
            echo "※ U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " 메일 서비스 버전이 최신 버전(8.18.2)이 아닙니다." >> $resultfile 2>&1
            return 0
        fi
    fi
    echo "※ U-45 결과 : 양호(Good)" >> $resultfile 2>&1
}
#희윤
U_46(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-46(상) | 3. 서비스 관리 > 3.13 일반 사용자의 메일 서비스 실행 방지 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 일반 사용자의 메일 서비스 실행 방지가 설정된 경우 " >> "$resultfile" 2>&1

  VULN=0 
  REASON=""

  # 1. Sendmail 서비스가 실행되고 있는지 확인
  if ps -ef | grep -v grep | grep -q "sendmail"; then

    # 2. Sendmail 설정 파일(/etc/mail/sendmail.cf) 점검
    if [ -f "/etc/mail/sendmail.cf" ]; then
      CHECK=$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf | grep "restrictqrun")

      if [-z "$CHECK" ]; then
        VULN=1
        REASON="$REASON Sendmail 서비스가 실행 중이며, 일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않습니다. |"
      fi
    else
      VULN=1
      REASON="$REASON Sendmail 서비스가 실행 중이나 설정파일이 존재하지 않습니다. |"
    fi
  fi
  
  # 3. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-46 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-46 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_48() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-48(중) | UNIX > 3. 서비스 관리 > expn, vrfy 명령어 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 메일 서비스를 사용하지 않는 경우 N/A, (2) 사용 시 noexpn, novrfy 옵션(또는 goaway)이 설정된 경우" >> "$resultfile" 2>&1

  local mail_in_use=0
  local vulnerable=0
  local evidences=()

  # MTA 감지 플래그 (검출된 것만 평가하기 위함)
  local has_sendmail=0
  local has_postfix=0
  local has_exim=0

  ########################################################
  # 1) 메일(SMTP) 서비스 사용 여부 판단
  #    - 25/tcp LISTEN 또는 MTA 서비스/프로세스 감지 시 "사용 중"
  ########################################################
  if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:25)$'; then
      mail_in_use=1
      evidences+=("network: TCP 25(smtp) LISTEN 감지(ss)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:25)$'; then
      mail_in_use=1
      evidences+=("network: TCP 25(smtp) LISTEN 감지(netstat)")
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    for unit in sendmail.service postfix.service exim4.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
          mail_in_use=1
          evidences+=("systemd: ${unit} active")
          case "$unit" in
            sendmail.service) has_sendmail=1 ;;
            postfix.service)  has_postfix=1 ;;
            exim4.service)    has_exim=1 ;;
          esac
        fi
      fi
    done
  fi

  # 프로세스 감지(서비스가 없어도 실행 중인 경우 대비)
  if ps -ef 2>/dev/null | grep -iE 'sendmail' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_sendmail=1
    evidences+=("process: sendmail 프로세스 감지")
  fi
  if ps -ef 2>/dev/null | grep -iE 'postfix|master' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_postfix=1
    evidences+=("process: postfix(master 등) 프로세스 감지")
  fi
  if ps -ef 2>/dev/null | grep -iE 'exim' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_exim=1
    evidences+=("process: exim 프로세스 감지")
  fi

  ########################################################
  # 2) 미사용이면 N/A 처리
  ########################################################
  if [ "$mail_in_use" -eq 0 ]; then
    echo "※ U-48 결과 : N/A" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (25/tcp LISTEN 및 MTA 미검출)" >> "$resultfile" 2>&1
    return 0
  fi

  ########################################################
  # 3) 사용 중이면 설정 점검
  ########################################################
  local ok_cnt=0
  local bad_cnt=0

  # 3-A) Sendmail 점검: PrivacyOptions에 goaway 또는 noexpn+novrfy
  if [ "$has_sendmail" -eq 1 ]; then
    local sendmail_ok=0
    local sendmail_cf_candidates=("/etc/mail/sendmail.cf" "/etc/sendmail.cf")
    local found_cf=""

    for cf in "${sendmail_cf_candidates[@]}"; do
      if [ -f "$cf" ]; then
        found_cf="$cf"
        local goaway_count
        local noexpn_novrfy_count

        goaway_count=$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'goaway' | wc -l)
        noexpn_novrfy_count=$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'noexpn' | grep -i 'novrfy' | wc -l)

        if [ "$goaway_count" -gt 0 ] || [ "$noexpn_novrfy_count" -gt 0 ]; then
          sendmail_ok=1
          evidences+=("sendmail: ${cf} 에 PrivacyOptions(goaway 또는 noexpn+novrfy) 설정 확인")
        else
          evidences+=("sendmail: ${cf} 에 noexpn/novrfy(goaway 포함) 설정이 없음")
        fi
        break
      fi
    done

    if [ -z "$found_cf" ]; then
      # sendmail 사용 흔적은 있는데 설정 파일을 못 찾으면 보수적으로 취약
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("sendmail: 실행 흔적은 있으나 sendmail.cf 파일을 찾지 못했습니다. (설정 점검 불가)")
    else
      if [ "$sendmail_ok" -eq 1 ]; then
        ok_cnt=$((ok_cnt+1))
      else
        vulnerable=1
        bad_cnt=$((bad_cnt+1))
      fi
    fi
  fi

  # 3-B) Postfix 점검: disable_vrfy_command = yes
  #      (이미지 기준의 noexpn/novrfy와 1:1은 아니지만, VRFY 차단은 핵심 통제라서 포함)
  if [ "$has_postfix" -eq 1 ]; then
    if [ -f /etc/postfix/main.cf ]; then
      local postfix_vrfy
      postfix_vrfy=$(grep -vE '^\s*#' /etc/postfix/main.cf 2>/dev/null \
        | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l)

      if [ "$postfix_vrfy" -gt 0 ]; then
        ok_cnt=$((ok_cnt+1))
        evidences+=("postfix: /etc/postfix/main.cf 에 disable_vrfy_command=yes 설정 확인")
      else
        vulnerable=1
        bad_cnt=$((bad_cnt+1))
        evidences+=("postfix: postfix 사용 중이나 disable_vrfy_command=yes 설정이 없음")
      fi
    else
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("postfix: postfix 사용 흔적은 있으나 /etc/postfix/main.cf 파일이 없습니다. (설정 점검 불가)")
    fi
  fi

  # 3-C) Exim (자동 판별 난이도 높음 → 기본은 Evidence만)
  if [ "$has_exim" -eq 1 ]; then
    evidences+=("exim: exim 사용 흔적 감지(구성 파일 기반 vrfy/expn 제한 수동 확인 필요)")
    # 정책을 더 보수적으로 하고 싶으면 아래를 활성화:
    # vulnerable=1
    # bad_cnt=$((bad_cnt+1))
  fi

  ########################################################
  # 4) 최종 출력(네가 원하는 스타일)
  ########################################################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-48 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 미흡합니다. (미설정/점검불가=$bad_cnt, 설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  else
    echo "※ U-48 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 확인되었습니다. (설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  fi

  echo " --- 근거(Evidence) ---" >> "$resultfile" 2>&1
  for e in "${evidences[@]}"; do
    echo " - $e" >> "$resultfile" 2>&1
  done

  return 0
}
#연수
U_49() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-49(상) | UNIX > 3. 서비스 관리 > DNS 보안 버전 패치 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우" >> "$resultfile" 2>&1

  local named_active=0
  local named_running=0
  local bind_ver=""
  local major="" minor="" patch=""
  local evidence=""

  # 1) DNS 서비스 사용 여부 (named)
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet named 2>/dev/null; then
      named_active=1
    fi
  fi
  if ps -ef 2>/dev/null | grep -i 'named' | grep -v grep >/dev/null 2>&1; then
    named_running=1
  fi

  # 서비스 미사용이면 양호
  if [ "$named_active" -eq 0 ] && [ "$named_running" -eq 0 ]; then
    echo "※ U-49 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DNS 서비스(named)가 비활성/미사용 상태입니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) BIND 버전 확인 (named -v 우선)
  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi

  # named -v로 못 얻으면 패키지에서 추출
  if [ -z "$bind_ver" ]; then
    if command -v rpm >/dev/null 2>&1; then
      bind_ver="$(rpm -q bind 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
    fi
  fi

  if [ -z "$bind_ver" ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " named는 동작 중이나 BIND 버전을 확인하지 못했습니다. (named -v / rpm -q bind 실패)" >> "$resultfile" 2>&1
    return 0
  fi

  major="$(echo "$bind_ver" | awk -F. '{print $1}')"
  minor="$(echo "$bind_ver" | awk -F. '{print $2}')"
  patch="$(echo "$bind_ver" | awk -F. '{print $3}')"

  # 3) 판정 (9.18.7 이상이면 양호 / 9.19+는 개발/테스트로 간주 -> 취약 처리)
  if [ "$major" -ne 9 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND 메이저 버전이 9가 아닙니다. (현재: $bind_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$minor" -ge 19 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND $bind_ver 는 9.19+ (개발/테스트 버전으로 간주) 입니다. 운영 권고 버전(9.18.7 이상)으로 관리 필요." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$minor" -lt 18 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND 버전이 9.18 미만입니다. (현재: $bind_ver, 기준: 9.18.7 이상)" >> "$resultfile" 2>&1
    return 0
  fi

  # minor == 18 인 경우 patch 비교
  if [ "$patch" -lt 7 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다. (현재: $bind_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-49 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " DNS 서비스 사용 중이며 BIND 버전이 기준 이상입니다. (현재: $bind_ver)" >> "$resultfile" 2>&1
  return 0
}
#수진
U_50() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-50(상) | 3. 서비스 관리 > 3.17 DNS Zone Transfer 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : Zone Transfer를 허가된 사용자에게만 허용한 경우" >> $resultfile 2>&1
    ps_dns_count=`ps -ef | grep -i 'named' | grep -v 'grep' | wc -l`
    if [ $ps_dns_count -gt 0 ]; then
        if [ -f /etc/named.conf ]; then
            etc_namedconf_allowtransfer_count=`grep -vE '^#|^\s#' /etc/named.conf | grep -i 'allow-transfer' | grep -i 'any' | wc -l`
            if [ $etc_namedconf_allowtransfer_count -gt 0 ]; then
                echo "※ U-50 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                echo " /etc/named.conf 파일에 allow-transfer { any; } 설정이 있습니다." >> $resultfile 2>&1
            fi
        fi
    fi
    echo "※ U-50 결과 : 양호(Good)" >> $resultfile 2>&1
}
#희윤
U_51(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-51(중) | 3. 서비스 관리 > 3.18 DNS 서비스의 취약한 동적 업데이트 설정 금지 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""

  # 1. DNS 서비스 실행 여부 확인
  if ps -ef | grep -v grep | grep -q "named"; then
    CONF="/etc/named.conf"
    CONF_FILES=("$CONF")

    # 2. 점검 파일 대상 추출
    if [ -f "$CONF" ]; then
        EXTRACTED_PATHS=$(grep -E "^\s*(include|file)" "$CONF" | awk -F'"' '{print $2}')

        for IN_FILE in $EXTRACTED_PATHS; do
            if [ -f "$IN_FILE" ]; then
                CONF_FILES+=("$IN_FILE")
            elif [ -f "/etc/$IN_FILE" ]; then
                CONF_FILES+=("/etc/$IN_FILE")
            elif [ -f "/var/named/$IN_FILE" ]; then
                CONF_FILES+=("/var/named/$IN_FILE")
            fi
        done
    fi

    # 3. 2에서 확보된 모든 설정 파일 점검 
    for FILE in "${CONF_FILES[@]}"; do
      if [ -f "$FILE" ]; then
        CHECK=$(grep -vE "^\s*//|^\s*#|^\s*/\*" "$FILE" | grep -i "allow-update" | grep -Ei "any|\{\s*any\s*;\s*\}")
        if [ -n "$CHECK" ]; then
          VULN=1
          REASON="$REASON $FILE 파일에서 동적 업데이트가 전체로 허용되어 있습니다. |"
        fi
      fi
    done

  else
   :
  fi

  # 4. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-51 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-51 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_53() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-53(하) | UNIX > 3. 서비스 관리 > FTP 서비스 정보 노출 제한 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : FTP 접속 배너에 노출되는 정보가 없는 경우" >> "$resultfile" 2>&1

  # 0) FTP(21/tcp) 리스닝 여부 확인
  local listen_info=""
  if command -v ss >/dev/null 2>&1; then
    listen_info=$(ss -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)
  else
    listen_info=$(netstat -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)
  fi

  if [ -z "$listen_info" ]; then
    echo "※ U-53 결과 : N/A" >> "$resultfile" 2>&1
    echo " FTP 서비스(21/tcp)가 리스닝 상태가 아니므로 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 1) 데몬 식별 (vsftpd / proftpd)
  local daemon=""
  if echo "$listen_info" | grep -qi "vsftpd"; then
    daemon="vsftpd"
  elif echo "$listen_info" | grep -Eqi "proftpd|proftp"; then
    daemon="proftpd"
  else
    # systemd로 보조 판별
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vsftpd 2>/dev/null; then
      daemon="vsftpd"
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet proftpd 2>/dev/null; then
      daemon="proftpd"
    fi
  fi

  # 2) 설정 파일에서 배너 설정 확인 (가이드 반영)
  local config_leak=0

  if [ "$daemon" = "vsftpd" ]; then
    # Rocky에서 흔한 경로 2개
    local f=""
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
      if [ -f "$f" ]; then
        # ftpd_banner가 설정되어 있고, 그 값에 제품명/버전/숫자버전 패턴이 있으면 노출로 판단
        local vline
        vline=$(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$f" 2>/dev/null | tail -n 1)
        if [ -n "$vline" ]; then
          echo "$vline" | grep -Eqi '(vsftpd|ftp server|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' && config_leak=1
        fi
      fi
    done

  elif [ "$daemon" = "proftpd" ]; then
    local f=""
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
      if [ -f "$f" ]; then
        local pline
        pline=$(grep -E '^[[:space:]]*ServerIdent[[:space:]]+' "$f" 2>/dev/null | tail -n 1)
        if [ -n "$pline" ]; then
          # ServerIdent on 이거나, 버전/숫자버전 패턴이 있으면 노출 가능
          echo "$pline" | grep -Eqi '(ServerIdent[[:space:]]+on|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' && config_leak=1
        fi
      fi
    done
  fi

  # 3) 실제 FTP 배너(접속 첫 줄) 확인
  local banner=""
  if command -v timeout >/dev/null 2>&1; then
    if command -v nc >/dev/null 2>&1; then
      banner=$( (echo -e "QUIT\r\n"; sleep 0.2) | timeout 3 nc -n 127.0.0.1 21 2>/dev/null | head -n 1 | tr -d '\r')
    else
      banner=$(timeout 3 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/21 || exit 1
        IFS= read -r line <&3 || true
        echo "$line"
        echo -e "QUIT\r\n" >&3
        exec 3<&-; exec 3>&-
      ' 2>/dev/null | head -n 1 | tr -d '\r')
    fi
  fi

  local banner_leak=0
  if [ -n "$banner" ]; then
    echo "$banner" | grep -Eqi \
      '(vsftpd|proftpd|pure-?ftpd|wu-?ftpd|ftp server|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' \
      && banner_leak=1
  fi

  # 4) 최종 판정
  if [ "$config_leak" -eq 1 ] || [ "$banner_leak" -eq 1 ]; then
    echo "※ U-53 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 가능성이 있습니다." >> "$resultfile" 2>&1
  else
    echo "※ U-53 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " FTP 접속 배너에 노출되는 정보가 없습니다." >> "$resultfile" 2>&1
  fi

  return 0
}
#연수
U_54() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-54(중) | UNIX > 3. 서비스 관리 > 암호화되지 않는 FTP 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 암호화되지 않은 FTP 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

  local ftp_active=0
  local reason=""

  # ==============================
  # 1) vsftpd 확인
  # ==============================
  if systemctl list-unit-files 2>/dev/null | grep -q "^vsftpd.service"; then
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
      ftp_active=1
      reason+="vsftpd 서비스가 활성 상태; "
    fi
  fi

  # ==============================
  # 2) proftpd 확인
  # ==============================
  if systemctl list-unit-files 2>/dev/null | grep -q "^proftpd.service"; then
    if systemctl is-active --quiet proftpd 2>/dev/null; then
      ftp_active=1
      reason+="proftpd 서비스가 활성 상태; "
    fi
  fi

  # ==============================
  # 3) xinetd ftp 확인
  # ==============================
  if [ -f /etc/xinetd.d/ftp ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/ftp 2>/dev/null | grep -iq "disable[[:space:]]*=[[:space:]]*no"; then
      ftp_active=1
      reason+="xinetd ftp 서비스가 활성(disable=no); "
    fi
  fi

  # ==============================
  # 4) inetd ftp 확인
  # ==============================
  if [ -f /etc/inetd.conf ]; then
    if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -iq "ftp"; then
      ftp_active=1
      reason+="inetd ftp 서비스 활성 설정 존재; "
    fi
  fi

  # ==============================
  # 판정
  # ==============================
  if [ "$ftp_active" -eq 1 ]; then
    echo "※ U-54 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 암호화되지 않은 FTP 서비스가 활성 상태입니다. ($reason)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-54 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " vsftpd / proftpd / xinetd / inetd 기반 FTP 서비스가 모두 비활성 상태입니다." >> "$resultfile" 2>&1
  return 0
}
#수진
U_55() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-55(중) | 3. 서비스 관리 > 3.22 FTP 계정 Shell 제한 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우" >> $resultfile 2>&1
    # FTP 서비스 설치 여부 확인
    if ! rpm -qa | egrep -qi 'vsftpd|proftpd'; then
        echo "※ U-55 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " FTP 서비스가 미설치되어 있습니다." >> $resultfile 2>&1
        return 0
    fi
    # ftp, vsftpd, proftpd 전부 점검
    ftp_users=("ftp" "vsftpd" "proftpd")
    ftp_exist=0
    ftp_vuln=0
    for user in "${ftp_users[@]}"; do
        if id "$user" >/dev/null 2>&1; then
            ftp_exist=1
            shell=$(grep "^$user:" /etc/passwd | awk -F: '{print $7}')
            if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" ]]; then
                ftp_vuln=1
            fi
        fi
    done
    if [[ $ftp_exist -eq 0 ]]; then
        echo "※ U-55 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " FTP 계정이 존재하지 않습니다." >> $resultfile 2>&1
    elif [[ $ftp_vuln -eq 1 ]]; then
        echo "※ U-55 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " ftp 계정에 /bin/false 쉘이 부여되어 있지 않습니다." >> $resultfile 2>&1
    else
        echo "※ U-55 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " ftp 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다." >> $resultfile 2>&1
    fi
}
#희윤
U_56(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-56(하) | 3. 서비스 관리 > 3.23 FTP 서비스 접근 제어 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""
  
  # 1. FTP 프로세스 확인
  if ps -ef | grep -v grep | grep -q "vsftpd"; then
    CONF="/etc/vsftpd/vsftpd.conf"
    if [ ! -f "$CONF" ]; then CONF="/etc/vsftpd.conf"; fi

    if [ -f "$CONF" ]; then
      USERLIST_ENABLE=$(grep -vE "^\s*#" "$CONF" | grep -i "userlist_enable" | awk -F= '{print $2}' | tr -d ' ')

      if [ "$USERLIST_ENABLE" = "YES" ]; then
        if [ ! -f "/etc/vsftpd/user_list" ] && [ ! -f "/etc/vsftpd.user_list" ]; then
          VULN=1
          REASON="$REASON vsftpd(userlist_enable=YES)를 사용 중이나, 접근 제어 파일이 없습니다. |"
        fi
      else
        if [ ! -f "/etc/vsftpd/ftpusers" ] && [ ! -f "/etc/vsftpd.ftpusers" ]; then
          VULN=1
          REASON="$REASON vsftpd(userlist_enable=NO)를 사용 중이나, 접근 제어 파일이 없습니다. |"
        fi
      fi
    else
      VULN=1
      REASON="$REASON vsftpd 서비스가 실행중이나 설정파일을 찾을 수 없습니다. |"
    fi
  
  # 2. FTP 서비스(proftpd) 프로세스 및 설정 점검 
  elif ps -ef | grep -v grep | grep -q "proftpd"; then
    CONF="/etc/proftpd.conf"
    if [ ! -f "$CONF" ]; then CONF="/etc/proftpd/proftpd.conf"; fi

    if [ -f "$CONF" ]; then
      U_F_U=$(grep -vE "^\s*#" "$CONF" | grep -i "UseFtpUsers" | awk '{print $2}')

      if [ -z "$U_F_U" ] || [ "$U_F_U" = "on" ]; then
        if [ ! -f "/etc/ftpusers" ] && [ ! -f "/etc/ftpd/ftpusers" ]; then
          VULN=1
          REASON="$REASON proftpd(UseFtpUsers=on)를 사용 중이나, 접근 제어 파일이 없습니다. |"
        fi
      else
        LIMIT=$(grep -i "<Limit LOGIN>" "$CONF")
        if [ -z "$LIMIT" ]; then
          VULN=1
          REASON="$REASON proftpd(UseFtpUsers=off)를 사용 중이나, 설정 파일 내 접근 제어 설정이 없습니다. |"
        fi
      fi
    fi
  
  else
    :
  fi

  # 3. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-56 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-56 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_58() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-58(중) | UNIX > 3. 서비스 관리 > 불필요한 SNMP 서비스 구동 점검 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SNMP 서비스를 사용하지 않는 경우" >> "$resultfile" 2>&1

  local found=0
  local reason=""

  # 1) systemd 서비스 상태 확인 (snmpd / snmptrapd)
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      found=1
      reason="snmpd 서비스가 활성(Active) 상태입니다."
    elif systemctl is-active --quiet snmptrapd 2>/dev/null; then
      found=1
      reason="snmptrapd 서비스가 활성(Active) 상태입니다."
    fi
  fi

  # 2) 프로세스 확인 (보조 검증)
  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1; then
      found=1
      reason="snmpd 프로세스가 실행 중입니다."
    elif pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
      reason="snmptrapd 프로세스가 실행 중입니다."
    fi
  fi

  # 3) 포트 리스닝 확인 (UDP 161/162)
  if [ "$found" -eq 0 ]; then
    if command -v ss >/dev/null 2>&1; then
      if ss -lunp 2>/dev/null | awk '$5 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        reason="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    elif command -v netstat >/dev/null 2>&1; then
      if netstat -lunp 2>/dev/null | awk '$4 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        reason="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    fi
  fi

  # 최종 판정
  if [ "$found" -eq 1 ]; then
    echo "※ U-58 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " SNMP 서비스를 사용하고 있습니다." >> "$resultfile" 2>&1
    echo " $reason" >> "$resultfile" 2>&1
  else
    echo "※ U-58 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " SNMP 서비스가 비활성화되어 있습니다." >> "$resultfile" 2>&1
  fi

  return 0
}
#연수
U_59() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-59(상) | UNIX > 3. 서비스 관리 > 안전한 SNMP 버전 사용 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SNMP 서비스를 v3 이상으로 사용하는 경우" >> "$resultfile" 2>&1

  local snmpd_conf="/etc/snmp/snmpd.conf"
  local snmpd_persist="/var/lib/net-snmp/snmpd.conf"

  local snmp_active=0
  local cfg_files=()
  local cfg_exists_count=0

  local found_v1v2=0
  local found_v3_user=0
  local found_createuser=0
  local found_sha=0
  local found_aes=0

  # 1) SNMP 서비스 활성 여부 확인 (미사용이면 N/A 처리)
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      snmp_active=1
    fi
  fi

  if [ "$snmp_active" -eq 0 ]; then
    echo "※ U-59 결과 : N/A" >> "$resultfile" 2>&1
    echo " SNMP 서비스(snmpd)가 비활성/미사용 상태입니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 설정 파일 수집
  if [ -f "$snmpd_conf" ]; then
    cfg_files+=("$snmpd_conf")
    ((cfg_exists_count++))
  fi
  if [ -f "$snmpd_persist" ]; then
    cfg_files+=("$snmpd_persist")
    ((cfg_exists_count++))
  fi

  if [ "$cfg_exists_count" -eq 0 ]; then
    echo "※ U-59 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " snmpd는 활성 상태이나 설정 파일이 없습니다. ($snmpd_conf / $snmpd_persist 미존재)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 설정 검사 (주석/공백 제외)
  _scan_snmp_cfg() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null
  }

  for f in "${cfg_files[@]}"; do
    # v1/v2c 흔적(community 기반) 있으면 취약
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*(rocommunity|rwcommunity|community|com2sec)[[:space:]]+'; then
      found_v1v2=1
    fi

    # v3 사용자 권한(rouser/rwuser)
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*(rouser|rwuser)[[:space:]]+'; then
      found_v3_user=1
    fi

    # createUser 존재 여부
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]]+'; then
      found_createuser=1
    fi

    # createUser 라인에서 SHA/AES 사용 확인
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]].*(SHA|SHA1|SHA224|SHA256|SHA384|SHA512)'; then
      found_sha=1
    fi
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]].*(AES|AES128|AES192|AES256)'; then
      found_aes=1
    fi
  done

  # 4) 판정
  if [ "$found_v1v2" -eq 1 ]; then
    echo "※ U-59 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " SNMP v1/v2c(community 기반) 설정이 존재합니다. (rocommunity/rwcommunity/com2sec 등)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$found_v3_user" -eq 1 ] && [ "$found_createuser" -eq 1 ] && [ "$found_sha" -eq 1 ] && [ "$found_aes" -eq 1 ]; then
    echo "※ U-59 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " SNMPv3 설정이 확인되었습니다. (createUser: SHA 인증 + AES 암호화, rouser/rwuser 권한 존재)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-59 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  echo " snmpd는 활성 상태이나 SNMPv3 필수 설정이 미흡합니다. (createUser(SHA+AES) 또는 rouser/rwuser 미확인)" >> "$resultfile" 2>&1
  return 0
}
#수진
U_60() {
    echo ""  >> $resultfile 2>&1
    echo " ▶ U-60(중) | 3. 서비스 관리 > 3.27 SNMP Community String 복잡성 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우" >> $resultfile 2>&1
    vuln_flag=0
    community_found=0
    # SNMP 사용 여부 판단 - 미설치 시 양호
    ps_snmp_count=$(ps -ef | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l)
    if [ $ps_snmp_count -eq 0 ]; then
        echo "※ U-60 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " SNMP 서비스가 미설치되어있습니다." >> $resultfile 2>&1
        return 0
    fi
    # snmpd.conf 검색
    snmpdconf_files=()
    [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
    [ -f /usr/local/etc/snmp/snmpd.conf ] && snmpdconf_files+=("/usr/local/etc/snmp/snmpd.conf")
    while IFS= read -r f; do
        snmpdconf_files+=("$f")
    done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)
    if [ ${#snmpdconf_files[@]} -gt 0 ]; then
        mapfile -t snmpdconf_files < <(printf "%s\n" "${snmpdconf_files[@]}" | awk '!seen[$0]++')
    fi
    if [ ${#snmpdconf_files[@]} -eq 0 ]; then
        echo "※ U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " SNMP 서비스를 사용하고, Community String을 설정하는 파일이 없습니다." >> $resultfile 2>&1
        return 0
    fi
    # 복잡성 판단
    is_strong_community() {
        local s="$1"
        s="${s%\"}"; s="${s#\"}"
        s="${s%\'}"; s="${s#\'}"
        # 기본값 금지
        echo "$s" | grep -qiE '^(public|private)$' && return 1
        local len=${#s}
        local has_alpha=0
        local has_digit=0
        local has_special=0
        echo "$s" | grep -qE '[A-Za-z]' && has_alpha=1
        echo "$s" | grep -qE '[0-9]' && has_digit=1
        echo "$s" | grep -qE '[^A-Za-z0-9]' && has_special=1
        # 영문 + 숫자 포함 10자리 이상
        if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $len -ge 10 ]; then
            return 0
        fi
        # 영문 + 숫자 + 특수문자 포함 8자리 이상
        if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $has_special -eq 1 ] && [ $len -ge 8 ]; then
            return 0
        fi
        return 1
    }
    for ((i=0; i<${#snmpdconf_files[@]}; i++))
    do
        while IFS= read -r comm; do
            community_found=1
            if ! is_strong_community "$comm"; then
                if [ $vuln_flag -eq 0 ]; then
                    echo "※ U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다." >> $resultfile 2>&1
                fi
                vuln_flag=1
            fi
        done < <(grep -vE '^\s*#|^\s*$' ${snmpdconf_files[$i]} 2>/dev/null \
                | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}' )
        while IFS= read -r comm; do
            community_found=1
            if ! is_strong_community "$comm"; then
                if [ $vuln_flag -eq 0 ]; then
                    echo "※ U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
                    echo " SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다." >> $resultfile 2>&1
                fi
                vuln_flag=1
            fi
        done < <(grep -vE '^\s*#|^\s*$' ${snmpdconf_files[$i]} 2>/dev/null \
                | awk 'tolower($1)=="com2sec" {print $4}' )
    done
    # community 를 못찾으면, 즉 설정 확인이 불가하면 취약
    if [ $community_found -eq 0 ]; then
        echo "※ U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " SNMP 서비스를 사용하나 Community String 설정(rocommunity/rwcommunity/com2sec)을 확인할 수 없습니다." >> $resultfile 2>&1
        return 0
    fi
    if [ $vuln_flag -eq 0 ]; then
        echo "※ U-60 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " SNMP Community String이 복잡성 기준을 만족합니다." >> $resultfile 2>&1
    fi
}
#희윤
U_61(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-61(상) | 3. 서비스 관리 > 3.28 SNMP Access Control 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 :  SNMP 서비스에 접근 제어 설정이 되어 있는 경우 " >> "$resultfile" 2>&1
  
  VULN=0
  REASON=""

  # 1. SNMP 서비스 프로세스 실행 여부 확인
  if ps -ef | grep -v grep | grep -q "snmpd" ; then 
    
    CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      # 2. com2sec 설정 점검 
      CHECK_COM2SEC=$(grep -vE "^\s*#" "$CONF" | grep -E "^\s*com2sec" | awk '$3=="default" {print $0}')
      # 3. rocommunity/rwcommunity 설정 점검
      CHECK_COMM=$(grep -vE "^\s*#" "$CONF" | grep -Ei "^\s*(ro|rw)community6?|^\s*(ro|rw)user")

      IS_COMM_VULN=0
      if [ -n "$CHECK_COMM" ]; then
        while read -r line; do  
          COMM_STR=$(echo "$line" | awk '{print $2}')
          SOURCE_IP=$(echo "$line" | awk '{print $3}')

          if [[ "$SOURCE_IP" == "default" ]] || [[ "$COMM_STR" =~ public|private ]]; then
              IS_COMM_VULN=1
              break
          fi
        done <<< "$CHECK_COMM"
      fi

      # 4. 취약 여부 종합 판단
      if [ -n "$CHECK_COM2SEC" ] || [ "$IS_COMM_VULN" -eq 1 ]; then
        VULN=1
        REASON="$REASON SNMP 설정 파일($CONF)에 모든 호스트 접근을 허용하는 설정이 존재합니다. |"
      fi
    else
      VULN=1
      REASON="$REASON SNMP 서비스가 실행 중이고, 설정 파일을 찾을 수 없습니다. |"
    fi
  
  else
    :
  fi

  # 5. 결과 출력
  if [ "$VULN" -eq 1 ]; then
    echo "※ U-61 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-61 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}
#연수
U_63() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-63(중) | UNIX > 3. 서비스 관리 > sudo 명령어 접근 관리 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우" >> "$resultfile" 2>&1

  # 1) /etc/sudoers 존재 여부
  if [ ! -e /etc/sudoers ]; then
    echo "※ U-63 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 소유자/권한 확인
  local owner perm
  owner=$(stat -c %U /etc/sudoers 2>/dev/null)
  perm=$(stat -c %a /etc/sudoers 2>/dev/null)

  # stat 실패 대비 (일부 Unix 호환)
  if [ -z "$owner" ] || [ -z "$perm" ]; then
    owner=$(ls -l /etc/sudoers 2>/dev/null | awk '{print $3}')
    perm=$(ls -l /etc/sudoers 2>/dev/null | awk '{print $1}')
    # perm이 "rwxr-x---" 형태라면 숫자로 바꾸기 어려워서 취약/양호 판정 불가 → 점검불가 처리
    echo "※ U-63 결과 : 점검불가" >> "$resultfile" 2>&1
    echo " /etc/sudoers 권한 정보를 숫자(예: 640)로 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 판정 기준: owner=root AND perm==640
  if [ "$owner" = "root" ] && [ "$perm" = "640" ]; then
    echo "※ U-63 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " /etc/sudoers 소유자: $owner, 권한: $perm" >> "$resultfile" 2>&1
  else
    echo "※ U-63 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " /etc/sudoers 소유자 또는 권한 설정이 기준에 부합하지 않습니다." >> "$resultfile" 2>&1
    echo " 현재 소유자: $owner, 권한: $perm" >> "$resultfile" 2>&1
  fi

  return 0
}
#연수
U_64() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-64(상) | UNIX > 4. 패치 관리 > 주기적 보안 패치 및 벤더 권고사항 적용 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 수행하고 최신 보안 패치 및 Kernel이 적용된 경우" >> "$resultfile" 2>&1

  local os_name="" os_ver=""
  local kernel_running=""
  local latest_kernel=""
  local evidence=""
  local pending_sec=0

  # OS/Kernel 기본 정보
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_name="$NAME"
    os_ver="$VERSION_ID"
  fi
  kernel_running="$(uname -r 2>/dev/null)"

  # 1) Rocky 9.x 여부
  if ! echo "$os_name" | grep -qi "Rocky" || ! echo "$os_ver" | grep -q "^9"; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " Rocky 9.x 환경이 아닙니다. (현재: $os_name $os_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 보안 업데이트 대기 여부
  if ! command -v dnf >/dev/null 2>&1; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " dnf 명령 확인 불가로 보안 패치 적용 여부를 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if dnf -q updateinfo list --updates security 2>/dev/null | grep -q .; then
    pending_sec=1
  fi

  if [ "$pending_sec" -eq 1 ]; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 보안 업데이트(SECURITY) 미적용 대기 항목이 존재합니다. (dnf updateinfo 기준)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 커널 최신/재부팅 필요 여부
  latest_kernel="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n1)"

  if [ -n "$latest_kernel" ]; then
    if ! echo "$kernel_running" | grep -q "$latest_kernel"; then
      echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
      echo " 최신 커널이 적용되지 않았거나 재부팅이 필요합니다. (running=$kernel_running, latest=$latest_kernel)" >> "$resultfile" 2>&1
      return 0
    fi
  else
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 설치된 커널 정보를 확인하지 못했습니다. (rpm -q kernel 확인 실패)" >> "$resultfile" 2>&1
    return 0
  fi

  # 양호
  echo "※ U-64 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " Rocky 9.x 환경이며 보안 업데이트 대기 없음 + 최신 커널 적용 확인됨. (kernel=$kernel_running)" >> "$resultfile" 2>&1
  return 0
}
#수진
U_65() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-65(중) | 5. 로그 관리 > 5.1 NTP 및 시각 동기화 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우" >> $resultfile 2>&1
    vuln_flag=0
    # 사용 중인 시간 동기화 방식 판단
    # - systemd-timesyncd (timedatectl / systemctl)
    # - chronyd
    # - ntpd
    is_active_service() {
        local svc="$1"
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service" || return 1
        systemctl is-active --quiet "${svc}.service" 2>/dev/null
    }
    # systemd-timesyncd 기반 NTP 사용 여부
    timedatectl_ntp=$(timedatectl show -p NTP --value 2>/dev/null | tr -d '\r')
    time_sync_state=$(timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d '\r')
    timesyncd_active=0
    chronyd_active=0
    ntpd_active=0
    is_active_service "systemd-timesyncd" && timesyncd_active=1
    is_active_service "chronyd" && chronyd_active=1
    is_active_service "ntpd" && ntpd_active=1
    if [ $ntpd_active -eq 0 ]; then
        is_active_service "ntp" && ntpd_active=1
    fi
    if [ $timesyncd_active -eq 0 ] && [ $chronyd_active -eq 0 ] && [ $ntpd_active -eq 0 ] && [ "$timedatectl_ntp" != "yes" ]; then
        echo "※ U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " NTP/시각동기화 서비스(chronyd/ntpd/systemd-timesyncd)가 활성화되어 있지 않습니다." >> $resultfile 2>&1
        return 0
    fi
    # NTP 설정/동기화 상태 점검
    server_found=0
    sync_ok=0
    # CHRONY 점검
    if [ $chronyd_active -eq 1 ]; then
        chrony_conf_files=()
        [ -f /etc/chrony.conf ] && chrony_conf_files+=("/etc/chrony.conf")
        [ -f /etc/chrony/chrony.conf ] && chrony_conf_files+=("/etc/chrony/chrony.conf")
        [ -d /etc/chrony.d ] && while IFS= read -r f; do chrony_conf_files+=("$f"); done < <(find /etc/chrony.d -type f 2>/dev/null | sort)
        [ -d /etc/chrony/conf.d ] && while IFS= read -r f; do chrony_conf_files+=("$f"); done < <(find /etc/chrony/conf.d -type f 2>/dev/null | sort)
        if [ ${#chrony_conf_files[@]} -gt 0 ]; then
            mapfile -t chrony_conf_files < <(printf "%s\n" "${chrony_conf_files[@]}" | awk '!seen[$0]++')
        fi
        for ((i=0; i<${#chrony_conf_files[@]}; i++)); do
            if grep -vE '^\s*#|^\s*$' "${chrony_conf_files[$i]}" 2>/dev/null | grep -qiE '^\s*(server|pool)\s+'; then
                server_found=1
                break
            fi
        done
        # 동기화 상태 확인
        if command -v chronyc >/dev/null 2>&1; then
            if chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+'; then
                sync_ok=1
            fi
        fi
    fi
    # NTPD 점검
    if [ $server_found -eq 0 ] && [ $ntpd_active -eq 1 ]; then
        ntp_conf_files=()
        [ -f /etc/ntp.conf ] && ntp_conf_files+=("/etc/ntp.conf")
        [ -f /etc/ntp/ntp.conf ] && ntp_conf_files+=("/etc/ntp/ntp.conf")
        while IFS= read -r f; do
            ntp_conf_files+=("$f")
        done < <(find /etc -maxdepth 4 -type f -name 'ntp.conf' 2>/dev/null | sort -u)
        if [ ${#ntp_conf_files[@]} -gt 0 ]; then
            mapfile -t ntp_conf_files < <(printf "%s\n" "${ntp_conf_files[@]}" | awk '!seen[$0]++')
        fi
        for ((i=0; i<${#ntp_conf_files[@]}; i++)); do
            if grep -vE '^\s*#|^\s*$' "${ntp_conf_files[$i]}" 2>/dev/null | grep -qiE '^\s*server\s+'; then
                server_found=1
                break
            fi
        done
        if command -v ntpq >/dev/null 2>&1; then
            if ntpq -pn 2>/dev/null | awk 'NR>2{print $1}' | grep -q '^\*'; then
                sync_ok=1
            fi
        fi
    fi
    # systemd-timesyncd 점검
    if [ $server_found -eq 0 ] && { [ $timesyncd_active -eq 1 ] || [ "$timedatectl_ntp" = "yes" ]; }; then
        ts_conf_found=0
        if [ -f /etc/systemd/timesyncd.conf ]; then
            if grep -vE '^\s*#|^\s*$' /etc/systemd/timesyncd.conf 2>/dev/null | grep -qiE '^\s*NTP\s*='; then
                ts_conf_found=1
            fi
        fi
        if [ $ts_conf_found -eq 0 ] && [ -d /etc/systemd/timesyncd.conf.d ]; then
            if find /etc/systemd/timesyncd.conf.d -type f -name '*.conf' 2>/dev/null | head -n 1 | grep -q .; then
                if grep -R -vE '^\s*#|^\s*$' /etc/systemd/timesyncd.conf.d 2>/dev/null | grep -qiE '^\s*NTP\s*='; then
                    ts_conf_found=1
                fi
            fi
        fi
        if [ $ts_conf_found -eq 1 ]; then
            server_found=1
        fi
        if [ "$time_sync_state" = "yes" ]; then
            sync_ok=1
        fi
    fi
    if [ $server_found -eq 0 ]; then
        echo "※ U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " NTP/시각동기화 서비스는 활성화되어 있으나, NTP 서버 설정(server/pool/NTP=)을 확인할 수 없습니다." >> $resultfile 2>&1
        vuln_flag=1
    else
        sync_check_available=0
        command -v chronyc >/dev/null 2>&1 && sync_check_available=1
        command -v ntpq >/dev/null 2>&1 && sync_check_available=1
        [ -n "$time_sync_state" ] && sync_check_available=1

        if [ $sync_check_available -eq 1 ] && [ $sync_ok -eq 0 ]; then
            echo "※ U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " NTP 서버 설정은 존재하나, 현재 동기화 상태를 정상으로 확인하지 못했습니다." >> $resultfile 2>&1
            echo " (참고) chronyc sources 또는 ntpq -pn 또는 timedatectl 상태를 확인하세요." >> $resultfile 2>&1
            vuln_flag=1
        else
            echo "※ U-65 결과 : 양호(Good)" >> $resultfile 2>&1
        fi
    fi
}
#희윤
U_66(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-66(중) | 5. 로그 관리 > 5.2 정책에 따른 시스템 로깅 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""
  CONF="/etc/rsyslog.conf"
  CONF_FILES=("$CONF")
  [ -d "/etc/rsyslog.d" ] && CONF_FILES+=($(ls /etc/rsyslog.d/*.conf 2>/dev/null))

  # 1. rsyslog 프로세스 확인
  if ps -ef | grep -v grep | grep -q "rsyslogd"; then

      if [ -f "$CONF" ]; then
          ALL_CONF_CONTENT=$(cat "${CONF_FILES[@]}" 2>/dev/null | grep -vE "^\s*#")

          # 2. 주요 로그 설정 항목 점검 (정규식 보완: 공백 및 '-' 대응)
          CHECK_MSG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.info[[:space:]]+-?\/var\/log\/messages")
          CHECK_SECURE=$(echo "$ALL_CONF_CONTENT" | grep -E "auth(priv)?\.\*[[:space:]]+-?\/var\/log\/secure")
          CHECK_MAIL=$(echo "$ALL_CONF_CONTENT" | grep -E "mail\.\*[[:space:]]+-?\/var\/log\/maillog")
          CHECK_CRON=$(echo "$ALL_CONF_CONTENT" | grep -E "cron\.\*[[:space:]]+-?\/var\/log\/cron")
          CHECK_ALERT=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.alert[[:space:]]+(\/dev\/console|:omusrmsg:\*|root)")
          CHECK_EMERG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.emerg[[:space:]]+(\*|:omusrmsg:\*)")

          # 3. 누락 항목 확인
          MISSING_LOGS=""
          [ -z "$CHECK_MSG" ] && MISSING_LOGS="$MISSING_LOGS [messages]"
          [ -z "$CHECK_SECURE" ] && MISSING_LOGS="$MISSING_LOGS [secure]"
          [ -z "$CHECK_MAIL" ] && MISSING_LOGS="$MISSING_LOGS [maillog]"
          [ -z "$CHECK_CRON" ] && MISSING_LOGS="$MISSING_LOGS [cron]"
          [ -z "$CHECK_ALERT" ] && MISSING_LOGS="$MISSING_LOGS [console/alert]"
          [ -z "$CHECK_EMERG" ] && MISSING_LOGS="$MISSING_LOGS [emerg]"

          if [ -n "$MISSING_LOGS" ]; then
              VULN=1
              REASON="rsyslog 설정에 다음 주요 로그 항목이 누락되었습니다: $MISSING_LOGS |"
          fi

      else
          VULN=1
          REASON="rsyslog 데몬은 실행 중이나 설정 파일($CONF)을 찾을 수 없습니다. |"
      fi
  else
      VULN=1
      REASON="시스템 로그 데몬(rsyslogd)이 실행 중이지 않습니다. |"
  fi

  # 4. 결과 출력
  if [ "$VULN" -eq 1 ]; then
      echo "※ U-66 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
      echo " $REASON" >> "$resultfile" 2>&1
  else
      echo "※ U-66 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi 
}

# ---- 통합 추가(U-02) ----
U_02() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # 주요통신기반시설 UNIX U-02(상) | 비밀번호 관리정책 설정 (Rocky Linux 9)
    # 출력 형식 2: 제목 1줄 + 기준 1줄 + 결과 1줄
    # 종료코드: 0=양호, 1=취약, 2=N/A
    # ============================================================
    
    set -u
    LANG=C
    LC_ALL=C
    
    # 가이드 기준값(이미지 기준)
    TARGET_PASS_MAX_DAYS=90
    TARGET_PASS_MIN_DAYS=1
    TARGET_MINLEN=8
    TARGET_CREDIT=-1
    TARGET_REMEMBER=4
    
    is_int(){ [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }
    
    trim() {
      local s="${1:-}"
      s="${s#"${s%%[![:space:]]*}"}"
      s="${s%"${s##*[![:space:]]}"}"
      printf "%s" "$s"
    }
    
    # /etc/login.defs에서 마지막 설정값(주석 제외)
    get_login_defs_value() {
      local key="$1"
      [[ -r /etc/login.defs ]] || return 1
      awk -v k="$key" '
        /^[[:space:]]*#/ {next}
        NF<2 {next}
        $1==k {v=$2}
        END { if (v!="") print v }
      ' /etc/login.defs 2>/dev/null
    }
    
    # key=value 파일들에서 마지막 값(주석 제외)
    get_last_kv_eq() {
      local want="$1"; shift
      local f line k v out=""
      for f in "$@"; do
        [[ -r "$f" ]] || continue
        while IFS= read -r line; do
          line="${line%%#*}"
          line="$(trim "$line")"
          [[ -z "$line" ]] && continue
          if [[ "$line" =~ ^([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            k="${BASH_REMATCH[1]}"
            v="$(trim "${BASH_REMATCH[2]}")"
            [[ "$k" == "$want" ]] && out="$v"
          fi
        done < "$f"
      done
      [[ -n "$out" ]] && printf "%s" "$out"
    }
    
    # 파일들에서 단어 존재(주석 제외)
    has_word_in_files() {
      local word="$1"; shift
      local f line
      for f in "$@"; do
        [[ -r "$f" ]] || continue
        while IFS= read -r line; do
          line="${line%%#*}"
          line="$(trim "$line")"
          [[ -z "$line" ]] && continue
          if [[ "$line" =~ (^|[[:space:]])${word}($|[[:space:]]) ]]; then
            return 0
          fi
        done < "$f"
      done
      return 1
    }
    
    # PAM 파일에서 password 스택 내 모듈 라인(마지막 1줄)
    get_pam_password_line_last() {
      local pam_file="$1"
      local module_pat="$2"
      [[ -r "$pam_file" ]] || return 1
      grep -E '^[[:space:]]*password[[:space:]]+' "$pam_file" 2>/dev/null \
        | grep -Ev '^[[:space:]]*#' \
        | grep -E "$module_pat" \
        | tail -n 1
    }
    
    # PAM 라인에서 옵션 파싱
    pam_minlen=""
    pam_dcredit=""
    pam_ucredit=""
    pam_lcredit=""
    pam_ocredit=""
    pam_enforce=0
    pam_remember=""
    
    parse_pam_args() {
      local line="${1:-}"
      local module="${2:-}"
      local rest tok
      pam_minlen=""; pam_dcredit=""; pam_ucredit=""; pam_lcredit=""; pam_ocredit=""
      pam_enforce=0; pam_remember=""
    
      rest="${line#*${module}}"
      for tok in $rest; do
        case "$tok" in
          minlen=*)   pam_minlen="${tok#minlen=}" ;;
          dcredit=*)  pam_dcredit="${tok#dcredit=}" ;;
          ucredit=*)  pam_ucredit="${tok#ucredit=}" ;;
          lcredit=*)  pam_lcredit="${tok#lcredit=}" ;;
          ocredit=*)  pam_ocredit="${tok#ocredit=}" ;;
          remember=*) pam_remember="${tok#remember=}" ;;
          enforce_for_root) pam_enforce=1 ;;
        esac
      done
    }
    
    pam_has_enforce_for_root_any() {
      local pf
      for pf in "$@"; do
        [[ -r "$pf" ]] || continue
        grep -E '^[[:space:]]*password[[:space:]]+' "$pf" 2>/dev/null \
          | grep -Ev '^[[:space:]]*#' \
          | grep -qE 'enforce_for_root' && return 0
      done
      return 1
    }
    
    pam_first_line_no() {
      local pam_file="$1"
      local pat="$2"
      [[ -r "$pam_file" ]] || return 1
      awk -v p="$pat" '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && $0 ~ p {print NR; exit}
      ' "$pam_file" 2>/dev/null
    }
    
    check_pam_order() {
      local pam_file="$1"
      local nr_unix nr_pwq nr_ph
      nr_unix="$(pam_first_line_no "$pam_file" 'pam_unix\.so' || true)"
      nr_pwq="$(pam_first_line_no "$pam_file" 'pam_pwquality\.so|pam_cracklib\.so' || true)"
      nr_ph="$(pam_first_line_no "$pam_file" 'pam_pwhistory\.so' || true)"
    
      # pam_unix가 없으면 판단불가
      [[ -n "${nr_unix:-}" ]] || return 2
    
      # pwquality/pwhistory가 없으면 정책 적용을 확인할 수 없으니 취약 처리
      [[ -n "${nr_pwq:-}" ]] || return 1
      [[ -n "${nr_ph:-}" ]] || return 1
    
      # 둘 다 pam_unix 위에 있어야 함
      (( nr_pwq < nr_unix )) || return 1
      (( nr_ph  < nr_unix )) || return 1
    
      return 0
    }
    
    # ---------------- OS 확인 ----------------
    OS_ID=""
    OS_ID_LIKE=""
    if [[ -r /etc/os-release ]]; then
      OS_ID="$(. /etc/os-release 2>/dev/null; printf "%s" "${ID:-}")"
      OS_ID_LIKE="$(. /etc/os-release 2>/dev/null; printf "%s" "${ID_LIKE:-}")"
    fi
    
    if [[ "$OS_ID" != "rocky" && "$OS_ID" != "rhel" && "$OS_ID" != "centos" && "$OS_ID_LIKE" != *"rhel"* ]]; then
      echo "▶ U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정 ◀"
      echo " 양호 판단 기준 : PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1, 복잡성(minlen>=8, credit<=-1, enforce_for_root), 이력(remember>=4, enforce_for_root), PAM 순서 적정"
      echo " 결과 : N/A"
      exit 2
    fi
    
    # ---------------- 파일 목록 ----------------
    shopt -s nullglob
    PWQ_FILES=(/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    PWH_FILES=(/etc/security/pwhistory.conf /etc/security/pwhistory.conf.d/*.conf)
    shopt -u nullglob
    
    PAM_FILES=(/etc/pam.d/system-auth /etc/pam.d/password-auth)
    
    # ---------------- 1) /etc/login.defs ----------------
    ok_login=1
    pass_max="$(get_login_defs_value PASS_MAX_DAYS || true)"
    pass_min="$(get_login_defs_value PASS_MIN_DAYS || true)"
    
    if ! is_int "$pass_max" || ! is_int "$pass_min"; then
      ok_login=0
    else
      (( pass_max <= TARGET_PASS_MAX_DAYS )) || ok_login=0
      (( pass_min >= TARGET_PASS_MIN_DAYS )) || ok_login=0
    fi
    
    # ---------------- 2) pwquality(복잡성) ----------------
    ok_pwq=1
    
    # 파일 값
    pwq_minlen="$(get_last_kv_eq minlen "${PWQ_FILES[@]}" || true)"
    pwq_dcredit="$(get_last_kv_eq dcredit "${PWQ_FILES[@]}" || true)"
    pwq_ucredit="$(get_last_kv_eq ucredit "${PWQ_FILES[@]}" || true)"
    pwq_lcredit="$(get_last_kv_eq lcredit "${PWQ_FILES[@]}" || true)"
    pwq_ocredit="$(get_last_kv_eq ocredit "${PWQ_FILES[@]}" || true)"
    pwq_enforce=0
    has_word_in_files enforce_for_root "${PWQ_FILES[@]}" && pwq_enforce=1
    
    # PAM 값(있으면 우선)
    eff_minlen="$pwq_minlen"
    eff_dcredit="$pwq_dcredit"
    eff_ucredit="$pwq_ucredit"
    eff_lcredit="$pwq_lcredit"
    eff_ocredit="$pwq_ocredit"
    eff_enforce=0
    
    pam_pwq_line="$(get_pam_password_line_last /etc/pam.d/system-auth 'pam_pwquality\.so|pam_cracklib\.so' || true)"
    if [[ -z "${pam_pwq_line:-}" ]]; then
      pam_pwq_line="$(get_pam_password_line_last /etc/pam.d/password-auth 'pam_pwquality\.so|pam_cracklib\.so' || true)"
    fi
    
    if [[ -n "${pam_pwq_line:-}" ]]; then
      module_name="pam_pwquality.so"
      [[ "$pam_pwq_line" == *"pam_cracklib.so"* ]] && module_name="pam_cracklib.so"
      parse_pam_args "$pam_pwq_line" "$module_name"
      [[ -n "${pam_minlen:-}" ]] && eff_minlen="$pam_minlen"
      [[ -n "${pam_dcredit:-}" ]] && eff_dcredit="$pam_dcredit"
      [[ -n "${pam_ucredit:-}" ]] && eff_ucredit="$pam_ucredit"
      [[ -n "${pam_lcredit:-}" ]] && eff_lcredit="$pam_lcredit"
      [[ -n "${pam_ocredit:-}" ]] && eff_ocredit="$pam_ocredit"
      (( pam_enforce==1 )) && eff_enforce=1
    fi
    
    # enforce_for_root: config 또는 PAM 어디든 있으면 통과
    if (( eff_enforce==0 )); then
      if (( pwq_enforce==1 )) || pam_has_enforce_for_root_any "${PAM_FILES[@]}"; then
        eff_enforce=1
      fi
    fi
    
    if ! is_int "$eff_minlen" || (( eff_minlen < TARGET_MINLEN )); then ok_pwq=0; fi
    for v in "$eff_dcredit" "$eff_ucredit" "$eff_lcredit" "$eff_ocredit"; do
      if ! is_int "$v" || (( v > TARGET_CREDIT )); then ok_pwq=0; fi
    done
    (( eff_enforce==1 )) || ok_pwq=0
    
    # ---------------- 3) pwhistory(이력) ----------------
    ok_pwh=1
    
    pwh_remember="$(get_last_kv_eq remember "${PWH_FILES[@]}" || true)"
    pwh_enforce=0
    has_word_in_files enforce_for_root "${PWH_FILES[@]}" && pwh_enforce=1
    
    eff_remember="$pwh_remember"
    eff_pwh_enforce=0
    
    # PAM 우선: pam_pwhistory, 없으면 pam_unix remember 옵션
    pam_ph_line="$(get_pam_password_line_last /etc/pam.d/system-auth 'pam_pwhistory\.so' || true)"
    if [[ -z "${pam_ph_line:-}" ]]; then
      pam_ph_line="$(get_pam_password_line_last /etc/pam.d/password-auth 'pam_pwhistory\.so' || true)"
    fi
    
    if [[ -n "${pam_ph_line:-}" ]]; then
      parse_pam_args "$pam_ph_line" "pam_pwhistory.so"
      [[ -n "${pam_remember:-}" ]] && eff_remember="$pam_remember"
      (( pam_enforce==1 )) && eff_pwh_enforce=1
    else
      pam_unix_line="$(get_pam_password_line_last /etc/pam.d/system-auth 'pam_unix\.so' || true)"
      if [[ -z "${pam_unix_line:-}" ]]; then
        pam_unix_line="$(get_pam_password_line_last /etc/pam.d/password-auth 'pam_unix\.so' || true)"
      fi
      if [[ -n "${pam_unix_line:-}" ]]; then
        parse_pam_args "$pam_unix_line" "pam_unix.so"
        [[ -n "${pam_remember:-}" ]] && eff_remember="$pam_remember"
      fi
    fi
    
    # enforce_for_root: config 또는 PAM 어디든 있으면 통과
    if (( eff_pwh_enforce==0 )); then
      if (( pwh_enforce==1 )) || pam_has_enforce_for_root_any "${PAM_FILES[@]}"; then
        eff_pwh_enforce=1
      fi
    fi
    
    if ! is_int "$eff_remember" || (( eff_remember < TARGET_REMEMBER )); then ok_pwh=0; fi
    (( eff_pwh_enforce==1 )) || ok_pwh=0
    
    # ---------------- 4) PAM 순서 ----------------
    ok_pam=1
    any_na=0
    for pf in "${PAM_FILES[@]}"; do
      rc=0
      check_pam_order "$pf"; rc=$?
      if (( rc==1 )); then ok_pam=0; fi
      if (( rc==2 )); then any_na=1; fi
    done
    
    # ---------------- 최종 판정 ----------------
    RESULT="취약"
    RC=1
    
    if (( ok_login==1 && ok_pwq==1 && ok_pwh==1 && ok_pam==1 )); then
      RESULT="양호"
      RC=0
    fi
    
    if (( any_na==1 )) && (( RC!=0 )); then
      # 핵심 파일/라인이 없어서 정확한 판정이 어려운 경우 N/A로 처리
      # (단, 명백히 설정값 위반이 확인되면 취약 유지)
      if (( ok_login==0 )) || (( ok_pwq==0 )) || (( ok_pwh==0 )); then
        : # 취약 유지
      else
        RESULT="N/A"
        RC=2
      fi
    fi
    
    echo "▶ U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정 ◀"
    echo " 양호 판단 기준 : PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1, 복잡성(minlen>=8, d/u/l/ocredit<=-1, enforce_for_root), 이력(remember>=4, enforce_for_root), PAM 순서(pwquality/pwhistory가 pam_unix 위)"
    echo " 결과 : $RESULT"
    exit "$RC"
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1, 복잡성(minlen>=8, d/u/l/ocredit<=-1, enforce_for_root), 이력(remember>=4, enforce_for_root), PAM 순서(pwquality/pwhistory가 pam_unix 위)" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-02 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-02 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-02 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-07) ----
U_07() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # KISA 주요통신기반시설(UNIX) U-07 불필요한 계정 제거 점검 (Rocky Linux 9)
    #
    # 핵심 포인트
    # - "불필요한 계정"은 조직 정책/인사 기준이 필요하므로 100% 자동판정 불가
    # - 그래서 기본 모드는 STRICT:
    #     * allowlist(허용 계정 목록)가 없으면 결과를 N/A로 내고 수동확인을 요구
    #     * allowlist가 있으면 로그인 가능한 계정이 allowlist에 모두 포함되는지로 양호/취약 판정
    #
    # 실행:
    #   sudo bash kisa_u07_check_rocky9.sh
    #
    # 옵션(환경변수):
    #   MODE=STRICT|CANDIDATE   (기본 STRICT)
    #   ALLOWLIST_FILE=/etc/kisa_u07_allowlist  (기본값)
    #   INACTIVE_DAYS=90        (기본 90일, 후보 탐지용 참고)
    # ============================================================
    
    set -euo pipefail
    LANG=C
    LC_ALL=C
    
    MODE="${MODE:-STRICT}"
    ALLOWLIST_FILE="${ALLOWLIST_FILE:-/etc/kisa_u07_allowlist}"
    INACTIVE_DAYS="${INACTIVE_DAYS:-90}"
    
    say(){ printf "%s\n" "$*"; }
    hr(){  printf "%s\n" "------------------------------------------------------------"; }
    
    need_root(){
      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        say "[U-07] 결과: N/A"
        say "사유: root 권한 필요(sudo로 실행)"
        exit 2
      fi
    }
    
    get_uid_min(){
      local v
      v="$(awk '$1=="UID_MIN"{print $2; exit}' /etc/login.defs 2>/dev/null || true)"
      if [[ -n "${v}" && "${v}" =~ ^[0-9]+$ ]]; then
        echo "${v}"
      else
        echo "1000"
      fi
    }
    
    is_login_shell(){
      local sh="${1:-}"
      case "${sh}" in
        ""|*/nologin|*/false) return 1 ;;
        *) return 0 ;;
      esac
    }
    
    is_locked_account(){
      local u="$1"
      local st=""
      if command -v passwd >/dev/null 2>&1; then
        st="$(passwd -S "$u" 2>/dev/null | awk '{print $2}' || true)"
      fi
      case "${st}" in
        LK|L) return 0 ;;
        "") ;;
        *) return 1 ;;
      esac
    
      local pw
      pw="$(awk -F: -v user="$u" '$1==user{print $2}' /etc/shadow 2>/dev/null || true)"
      [[ -z "${pw}" ]] && return 1
      [[ "${pw}" == "!"* || "${pw}" == "*"* ]] && return 0
      return 1
    }
    
    get_lastlog_epoch(){
      # 반환:
      #   NEVER / UNKNOWN / <epoch>
      local u="$1"
      local line date_str epoch
      line="$(lastlog -u "$u" 2>/dev/null | awk 'NR==2{print}' || true)"
      if [[ -z "${line}" ]]; then
        echo "UNKNOWN"
        return 0
      fi
      if echo "${line}" | grep -qi "Never logged in"; then
        echo "NEVER"
        return 0
      fi
    
      date_str="$(echo "${line}" | awk '
        {
          for(i=1;i<=NF;i++){
            if($i ~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/){
              for(j=i;j<=NF;j++){
                printf "%s%s", $j, (j==NF?ORS:OFS)
              }
              exit
            }
          }
        }' | sed 's/[[:space:]]*$//')"
    
      if [[ -z "${date_str}" ]]; then
        echo "UNKNOWN"
        return 0
      fi
    
      epoch="$(date -d "${date_str}" +%s 2>/dev/null || true)"
      if [[ -z "${epoch}" || ! "${epoch}" =~ ^[0-9]+$ ]]; then
        echo "UNKNOWN"
      else
        echo "${epoch}"
      fi
    }
    
    trim(){
      local s="$1"
      s="${s#"${s%%[![:space:]]*}"}"
      s="${s%"${s##*[![:space:]]}"}"
      printf "%s" "$s"
    }
    
    need_root
    
    UID_MIN="$(get_uid_min)"
    NOW_EPOCH="$(date +%s)"
    THRESHOLD_EPOCH="$(( NOW_EPOCH - INACTIVE_DAYS*86400 ))"
    
    declare -A ALLOW=()
    ALLOW["root"]=1
    
    if [[ -f "${ALLOWLIST_FILE}" ]]; then
      while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "$line")"
        [[ -z "$line" ]] && continue
        [[ "${line}" == \#* ]] && continue
        ALLOW["$line"]=1
      done < "${ALLOWLIST_FILE}"
    fi
    
    # 수집 결과
    declare -a LOGIN_USERS=()
    declare -a EXTRA_USERS=()
    declare -a CANDIDATES=()
    declare -a INVENTORY_LINES=()
    
    while IFS=: read -r user _ uid _ _ _ shell; do
      [[ -z "${user}" ]] && continue
    
      local_login="N"
      local_locked="N"
      local_last="UNKNOWN"
      local_days=""
    
      if is_login_shell "${shell}"; then
        local_login="Y"
        LOGIN_USERS+=("${user}")
      fi
    
      if is_locked_account "${user}"; then
        local_locked="Y"
      fi
    
      if [[ "${local_login}" == "Y" ]]; then
        ll="$(get_lastlog_epoch "${user}")"
        local_last="${ll}"
        if [[ "${ll}" =~ ^[0-9]+$ ]]; then
          d="$(( (NOW_EPOCH - ll) / 86400 ))"
          local_days="${d}"
          if [[ "${ll}" -lt "${THRESHOLD_EPOCH}" ]]; then
            CANDIDATES+=("${user}: ${INACTIVE_DAYS}일 이상 미사용 추정(lastlog ${d} days)")
          fi
        elif [[ "${ll}" == "NEVER" ]]; then
          CANDIDATES+=("${user}: Never logged in")
        else
          CANDIDATES+=("${user}: lastlog 확인 불가")
        fi
    
        # STRICT 모드에서 allowlist 기반 초과 계정 탐지
        if [[ "${MODE}" == "STRICT" ]]; then
          if [[ -z "${ALLOW[$user]+x}" ]]; then
            EXTRA_USERS+=("${user}")
          fi
        fi
      fi
    
      INVENTORY_LINES+=("${user}|${uid}|${shell}|login=${local_login}|locked=${local_locked}|last=${local_last}|days=${local_days}")
    done < /etc/passwd
    
    hr
    say "[U-07] 불필요한 계정 제거 점검 (Rocky Linux 9)"
    say "MODE=${MODE}, ALLOWLIST_FILE=${ALLOWLIST_FILE}, INACTIVE_DAYS=${INACTIVE_DAYS}, UID_MIN=${UID_MIN}"
    say "판단기준: 불필요한 계정이 존재하지 않으면 양호, 존재하면 취약"
    hr
    
    # 인벤토리 출력(목록을 항상 보여줘야 '목록 제대로 점검'이 됨)
    say "계정 인벤토리(/etc/passwd 기반, login=Y가 로그인 가능):"
    say "형식: user|uid|shell|login=Y/N|locked=Y/N|last=...|days=..."
    for line in "${INVENTORY_LINES[@]}"; do
      say "${line}"
    done
    hr
    
    if [[ "${MODE}" == "STRICT" ]]; then
      if [[ ! -f "${ALLOWLIST_FILE}" ]]; then
        say "[U-07] 결과: N/A"
        say "사유: allowlist가 없어서 '불필요 계정이 없다'를 자동으로 확정할 수 없음(수동확인 필요)"
        say "조치: ${ALLOWLIST_FILE}에 허용할 계정명을 1줄 1계정으로 등록 후 재실행 권장"
        hr
        say "참고(로그인 가능 계정):"
        if (( ${#LOGIN_USERS[@]} == 0 )); then
          say "- (없음)"
        else
          for u in "${LOGIN_USERS[@]}"; do say "- ${u}"; done
        fi
        hr
        say "참고(미사용/미로그인 후보):"
        if (( ${#CANDIDATES[@]} == 0 )); then
          say "- (없음)"
        else
          for c in "${CANDIDATES[@]}"; do say "- ${c}"; done
        fi
        exit 2
      fi
    
      if (( ${#EXTRA_USERS[@]} > 0 )); then
        say "[U-07] 결과: 취약"
        say "사유: 로그인 가능한 계정 중 allowlist에 없는 계정이 존재"
        hr
        say "allowlist 미포함(초과) 계정:"
        for u in "${EXTRA_USERS[@]}"; do say "- ${u}"; done
        hr
        say "조치 참고:"
        say "- 불필요 계정이면 삭제: userdel <계정명>"
        say "- 즉시 삭제가 어렵다면 우선 로그인 차단 후 추후 정리(정책에 따라): usermod -L <계정명> 또는 쉘을 nologin으로 변경"
        exit 1
      else
        say "[U-07] 결과: 양호"
        say "사유: 로그인 가능한 계정이 allowlist 범위 내에 있음(초과 계정 없음)"
        hr
        say "참고(미사용/미로그인 후보, 정책에 따라 검토 권고):"
        if (( ${#CANDIDATES[@]} == 0 )); then
          say "- (없음)"
        else
          for c in "${CANDIDATES[@]}"; do say "- ${c}"; done
        fi
        exit 0
      fi
    fi
    
    # CANDIDATE 모드: 예전 방식(미사용 후보가 있으면 취약, 없으면 양호)
    if [[ "${MODE}" == "CANDIDATE" ]]; then
      if (( ${#CANDIDATES[@]} > 0 )); then
        say "[U-07] 결과: 취약"
        say "사유: 로그인 가능한 계정 중 미사용/미로그인 후보가 존재"
        hr
        for c in "${CANDIDATES[@]}"; do say "- ${c}"; done
        exit 1
      else
        say "[U-07] 결과: 양호"
        say "사유: 로그인 가능한 계정 중 미사용/미로그인 후보가 발견되지 않음"
        exit 0
      fi
    fi
    
    say "[U-07] 결과: N/A"
    say "사유: MODE 값이 올바르지 않음(STRICT 또는 CANDIDATE)"
    exit 2
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-07(상) | 1. 계정관리 > 불필요한 계정 제거 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 계정이 존재하지 않으면 양호, 존재하면 취약" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-07 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-07 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-07 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-12) ----
U_12() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # KISA 주요통신기반시설 UNIX U-12 (하) 세션 종료 시간 설정 점검
    # 대상: Rocky Linux 9 (RHEL 계열 일반 Linux에도 대부분 동작)
    # 실행: sudo bash kisa_unix_u12_check.sh
    # 판정:
    #   - bash/sh/ksh 계열: TMOUT 값이 600초(10분) 이하로 설정되어 있고(export 포함) 적용 흔적이 있으면 양호
    #   - csh/tcsh 계열: autologout 값이 10분 이하로 설정되어 있으면 양호
    # 종료코드: 0=양호, 1=취약, 2=N/A(판단불가/실행조건 불충족)
    # ============================================================
    
    set -euo pipefail
    LANG=C
    LC_ALL=C
    shopt -s nullglob
    
    LIMIT_TMOUT_SEC=600
    LIMIT_AUTOLOGOUT_MIN=10
    
    say(){ printf "%s\n" "$*"; }
    hr(){  printf "%s\n" "------------------------------------------------------------"; }
    
    need_root(){
      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        say "[U-12] 취약점 진단"
        say "결과: N/A (sudo로 실행 필요)"
        exit 2
      fi
    }
    
    detect_os(){
      local id_like id ver
      id_like="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")"
      id="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
      ver="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"
      say "[정보] OS: ${id:-unknown} ${ver:-unknown} (ID_LIKE=${id_like:-none})"
      if [[ "${id}" != "rocky" || "${ver}" != 9* ]]; then
        say "[정보] Rocky Linux 9가 아니어도 점검은 수행합니다."
      fi
    }
    
    list_login_shells(){
      # root + 일반 사용자(UID>=1000) 중 로그인 가능 쉘만
      awk -F: '
        ($1=="root" || $3>=1000) && $7 !~ /(nologin|false)$/ { print $7 }
      ' /etc/passwd 2>/dev/null | sort -u
    }
    
    is_bash_like(){
      case "$1" in
        */bash|*/sh|*/ksh|*/zsh) return 0 ;;
        *) return 1 ;;
      esac
    }
    
    is_csh_like(){
      case "$1" in
        */csh|*/tcsh) return 0 ;;
        *) return 1 ;;
      esac
    }
    
    collect_bash_files(){
      local -a files=()
      [[ -f /etc/profile ]] && files+=("/etc/profile")
      [[ -f /etc/bashrc  ]] && files+=("/etc/bashrc")
      for f in /etc/profile.d/*.sh; do
        [[ -f "$f" ]] && files+=("$f")
      done
      printf "%s\n" "${files[@]:-}"
    }
    
    collect_csh_files(){
      local -a files=()
      [[ -f /etc/csh.cshrc ]] && files+=("/etc/csh.cshrc")
      [[ -f /etc/csh.login ]] && files+=("/etc/csh.login")
      for f in /etc/profile.d/*.csh; do
        [[ -f "$f" ]] && files+=("$f")
      done
      printf "%s\n" "${files[@]:-}"
    }
    
    scan_tmout(){
      # 출력: file:line:value
      local f
      while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        awk -v F="$f" '
          /^[[:space:]]*#/ {next}
          {
            line=$0
            sub(/[[:space:]]*#.*/,"",line)
            if (match(line,/(^|[^A-Za-z0-9_])TMOUT[[:space:]]*=[[:space:]]*([0-9]+)/,a)) {
              print F ":" NR ":" a[2]
            }
            if (match(line,/(^|[;[:space:]])export[[:space:]]+TMOUT=([0-9]+)/,b)) {
              print F ":" NR ":" b[2]
            }
            if (match(line,/(^|[;[:space:]])(declare|typeset)[[:space:]]+(-[A-Za-z]*x[A-Za-z]*|-x)[[:space:]]+TMOUT=([0-9]+)/,c)) {
              print F ":" NR ":" c[4]
            }
          }
        ' "$f"
      done < <(collect_bash_files)
    }
    
    scan_tmout_export_present(){
      local f
      while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        if awk '
          /^[[:space:]]*#/ {next}
          {
            line=$0
            sub(/[[:space:]]*#.*/,"",line)
            if (line ~ /(^|[;[:space:]])export[[:space:]]+TMOUT([[:space:];]|$)/) {found=1}
            if (line ~ /(^|[;[:space:]])export[[:space:]]+TMOUT=/) {found=1}
            if (line ~ /(^|[;[:space:]])(declare|typeset)[[:space:]]+.*-x.*[[:space:]]+TMOUT=/) {found=1}
          }
          END{ exit(found?0:1) }
        ' "$f"; then
          return 0
        fi
      done < <(collect_bash_files)
      return 1
    }
    
    scan_autologout(){
      # 출력: file:line:value(min)
      local f
      while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        awk -v F="$f" '
          /^[[:space:]]*#/ {next}
          {
            line=$0
            sub(/[[:space:]]*#.*/,"",line)
            # csh: set autologout=10 또는 set autologout = 10 형태
            if (match(line,/set[[:space:]]+(-r[[:space:]]+)?autologout[[:space:]]*=?[[:space:]]*([0-9]+)/,a)) {
              print F ":" NR ":" a[2]
            }
          }
        ' "$f"
      done < <(collect_csh_files)
    }
    
    main(){
      need_root
      say "[U-12] 계정관리 - 세션 종료 시간 설정 점검"
      say "기준: (bash/sh/ksh) TMOUT <= ${LIMIT_TMOUT_SEC}초, (csh/tcsh) autologout <= ${LIMIT_AUTOLOGOUT_MIN}분"
      hr
    
      detect_os
      local shells used_bash=0 used_csh=0
      shells="$(list_login_shells || true)"
      if [[ -z "${shells// }" ]]; then
        say "[정보] 로그인 가능한 사용자 쉘을 찾지 못했습니다."
        say "결과: N/A"
        exit 2
      fi
    
      say "[정보] 로그인 쉘 목록:"
      say "$shells"
      hr
    
      while IFS= read -r s; do
        is_bash_like "$s" && used_bash=1
        is_csh_like "$s" && used_csh=1
      done <<< "$shells"
    
      local vuln=0
      local bash_ok=0 csh_ok=0
      local tmout_lines tmout_export=0
      local autologout_lines
    
      # 1) bash/sh/ksh 계열 점검
      if [[ "$used_bash" -eq 1 ]]; then
        tmout_lines="$(scan_tmout || true)"
        if scan_tmout_export_present; then tmout_export=1; fi
    
        if [[ -z "${tmout_lines// }" ]]; then
          bash_ok=0
          vuln=1
          say "[bash 계열] TMOUT 설정을 /etc/profile, /etc/bashrc, /etc/profile.d/*.sh 에서 찾지 못함"
        else
          # 유효값(1..600) 존재 여부
          local ok_line=""
          while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            local val="${line##*:}"
            if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= LIMIT_TMOUT_SEC )); then
              ok_line="$line"
              break
            fi
          done <<< "$tmout_lines"
    
          if [[ -n "$ok_line" && "$tmout_export" -eq 1 ]]; then
            bash_ok=1
            say "[bash 계열] 양호 후보 TMOUT 발견(<=${LIMIT_TMOUT_SEC}초) + export 흔적 존재"
            say "근거(예): $ok_line"
          else
            bash_ok=0
            vuln=1
            say "[bash 계열] TMOUT 값은 발견했으나 기준 미충족(값>600 또는 export 흔적 부족)"
            say "[bash 계열] 발견된 TMOUT 후보(상위 일부):"
            echo "$tmout_lines" | head -n 10 | sed 's/^/  - /'
            [[ "$tmout_export" -eq 1 ]] && say "[bash 계열] export TMOUT 흔적: 있음" || say "[bash 계열] export TMOUT 흔적: 없음"
          fi
        fi
        hr
      else
        say "[bash 계열] 해당 쉘 사용자 없음 -> N/A"
        hr
      fi
    
      # 2) csh/tcsh 계열 점검
      if [[ "$used_csh" -eq 1 ]]; then
        autologout_lines="$(scan_autologout || true)"
        if [[ -z "${autologout_lines// }" ]]; then
          csh_ok=0
          vuln=1
          say "[csh 계열] autologout 설정을 /etc/csh.cshrc, /etc/csh.login, /etc/profile.d/*.csh 에서 찾지 못함"
        else
          local ok_line=""
          while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            local val="${line##*:}"
            if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= LIMIT_AUTOLOGOUT_MIN )); then
              ok_line="$line"
              break
            fi
          done <<< "$autologout_lines"
    
          if [[ -n "$ok_line" ]]; then
            csh_ok=1
            say "[csh 계열] 양호 후보 autologout 발견(<=${LIMIT_AUTOLOGOUT_MIN}분)"
            say "근거(예): $ok_line"
          else
            csh_ok=0
            vuln=1
            say "[csh 계열] autologout 값은 발견했으나 기준 초과(>10분) 또는 0"
            say "[csh 계열] 발견된 autologout 후보(상위 일부):"
            echo "$autologout_lines" | head -n 10 | sed 's/^/  - /'
          fi
        fi
        hr
      else
        say "[csh 계열] 해당 쉘 사용자 없음 -> N/A"
        hr
      fi
    
      # 최종 판정
      if [[ "$vuln" -eq 0 ]]; then
        say "결과: 양호"
        exit 0
      else
        say "결과: 취약"
        say "조치 예시:"
        say "  - bash 계열: /etc/profile.d/tmout.sh 등에 아래 추가"
        say "      TMOUT=600"
        say "      export TMOUT"
        say "      (선택) readonly TMOUT"
        say "  - csh 계열: /etc/csh.cshrc 또는 /etc/csh.login 등에 아래 추가"
        say "      set autologout=10"
        exit 1
      fi
    }
    
    main
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-12(하) | 1. 계정관리 > 세션 종료 시간 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (bash/sh/ksh) TMOUT <= 600초, (csh/tcsh) autologout <= 10분으로 설정된 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-12 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-12 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-12 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-17) ----
U_17() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # KISA 주요통신기반시설 가이드 UNIX U-17 점검 스크립트 (Rocky Linux 9)
    # 항목: 시스템 시작 스크립트 권한 설정
    # 실행: sudo bash kisa_unix_u17_check_rocky9.sh
    # 종료코드: 0=양호, 1=취약, 2=N/A(점검불가/오류)
    # ============================================================
    
    set -u
    set -o pipefail
    LANG=C
    LC_ALL=C
    
    say(){ printf "%s\n" "$*"; }
    
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      say "N/A: root 권한이 필요합니다. sudo로 실행하세요."
      exit 2
    fi
    
    # 후보 수집(실파일 기준 중복 제거: realpath 기준)
    declare -A seen_real=()
    declare -A example_path=()
    reals=()
    
    add_path() {
      local p="$1"
      [[ -e "$p" ]] || return 0
    
      local real
      real="$(readlink -f -- "$p" 2>/dev/null || echo "$p")"
      [[ -e "$real" ]] || return 0
      [[ -f "$real" ]] || return 0
    
      if [[ -z "${seen_real["$real"]+x}" ]]; then
        seen_real["$real"]=1
        example_path["$real"]="$p"
        reals+=("$real")
      fi
    }
    
    add_find_dir() {
      local d="$1"
      [[ -d "$d" ]] || return 0
    
      # -L: 심볼릭 링크를 따라 실제 파일 권한/소유자 점검
      while IFS= read -r -d '' f; do
        add_path "$f"
      done < <(find -L "$d" -type f -print0 2>/dev/null)
    }
    
    # systemd 경로
    add_find_dir "/etc/systemd/system"
    add_find_dir "/usr/lib/systemd/system"
    
    # SysV/init 흔적 경로
    add_find_dir "/etc/rc.d/init.d"
    add_path "/etc/rc.local"
    add_path "/etc/rc.d/rc.local"
    add_find_dir "/etc/init.d"   # 존재하면(대개 /etc/rc.d/init.d 링크)
    
    if [[ "${#reals[@]}" -eq 0 ]]; then
      say "N/A: 점검 대상 파일을 찾지 못했습니다."
      exit 2
    fi
    
    VULN=0
    NA=0
    
    say "U-17 | 시스템 시작 스크립트 권한 설정 (Rocky Linux 9)"
    say "기준: 소유자 root(UID 0) + 그룹/기타 쓰기권한 없음(022 비트 제거)"
    
    for real in "${reals[@]}"; do
      ex="${example_path["$real"]}"
    
      # stat 실패 시 N/A 처리
      if ! uid="$(stat -Lc '%u' -- "$real" 2>/dev/null)"; then
        NA=1
        continue
      fi
      if ! mode="$(stat -Lc '%a' -- "$real" 2>/dev/null)"; then
        NA=1
        continue
      fi
    
      # 8진수 변환(특수비트 포함 가능: 4755 등)
      m=$((8#$mode))
    
      reason=""
      if [[ "$uid" -ne 0 ]]; then
        reason="${reason}owner_not_root "
      fi
    
      # 그룹/기타 쓰기 비트(020/002) 체크
      if (( (m & 020) != 0 )); then
        reason="${reason}group_writable "
      fi
      if (( (m & 002) != 0 )); then
        reason="${reason}other_writable "
      fi
    
      if [[ -n "$reason" ]]; then
        VULN=1
        # 표시: example 경로가 real과 다르면 링크 관계도 같이 보여줌
        if [[ "$ex" != "$real" ]]; then
          say "취약: $ex -> $real | uid=$uid mode=$mode | $reason"
        else
          say "취약: $real | uid=$uid mode=$mode | $reason"
        fi
      fi
    done
    
    if [[ "$VULN" -eq 1 ]]; then
      say "결과: 취약"
      exit 1
    fi
    
    if [[ "$NA" -eq 1 ]]; then
      say "결과: N/A (일부 파일 정보를 읽지 못했습니다)"
      exit 2
    fi
    
    say "결과: 양호"
    exit 0
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-17 | 시스템 시작 스크립트 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 소유자 root(UID 0)이고 그룹/기타 쓰기 권한이 없으면 양호" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-17 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-17 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-17 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-22) ----
U_22() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # KISA 주요통신기반시설 UNIX U-22 점검 스크립트 (Rocky Linux 9)
    # 점검항목: /etc/services 파일 소유자 및 권한 설정
    # 기준: 소유자 root(또는 bin, sys), 권한 644 이하
    # 판정:
    #   0 = 양호, 1 = 취약, 2 = N/A(점검불가)
    # 실행: sudo bash kisa_unix_u22_check.sh
    # ============================================================
    
    set -u
    LANG=C
    LC_ALL=C
    
    FILE="/etc/services"
    
    say(){ printf "%s\n" "$*"; }
    
    if [[ ! -e "$FILE" ]]; then
      say "U-22 /etc/services 파일 소유자 및 권한 설정"
      say "결과: N/A"
      say "사유: $FILE 파일이 존재하지 않습니다."
      exit 2
    fi
    
    # 소유자/그룹/권한 수집
    owner_name="$(stat -c '%U' "$FILE" 2>/dev/null || echo "UNKNOWN")"
    owner_uid="$(stat -c '%u' "$FILE" 2>/dev/null || echo "UNKNOWN")"
    group_name="$(stat -c '%G' "$FILE" 2>/dev/null || echo "UNKNOWN")"
    perm_str="$(stat -c '%a' "$FILE" 2>/dev/null || echo "")"
    
    if [[ -z "$perm_str" ]]; then
      say "U-22 /etc/services 파일 소유자 및 권한 설정"
      say "결과: N/A"
      say "사유: stat 정보를 가져오지 못했습니다."
      exit 2
    fi
    
    # stat -c %a 는 644 또는 1644(특수비트 포함)처럼 나올 수 있으므로 정수(8진)로 변환
    # 예: "1644" -> 8진수 01644
    perm_oct=$((8#$perm_str))
    
    vuln=0
    reasons=()
    
    # 1) 소유자 체크: root 또는 bin 또는 sys (이름이 없으면 UID로 보조 판단)
    is_owner_ok=0
    case "$owner_name" in
      root|bin|sys) is_owner_ok=1 ;;
    esac
    if [[ "$is_owner_ok" -eq 0 ]]; then
      # UID가 0이면 root로 간주
      if [[ "$owner_uid" == "0" ]]; then
        is_owner_ok=1
      fi
    fi
    if [[ "$is_owner_ok" -eq 0 ]]; then
      vuln=1
      reasons+=("소유자 조건 불만족(허용: root/bin/sys). 현재 소유자: ${owner_name}(uid=${owner_uid})")
    fi
    
    # 2) 권한 체크: 644 이하(실무적 해석)
    # - 특수권한(suid/sgid/sticky) 있으면 취약
    # - group/other 쓰기 있으면 취약(022)
    # - 어떤 실행 비트라도 있으면 취약(111)
    if (( (perm_oct & 8#7000) != 0 )); then
      vuln=1
      reasons+=("특수권한(suid/sgid/sticky) 비트가 설정되어 있음(perm=${perm_str})")
    fi
    if (( (perm_oct & 8#022) != 0 )); then
      vuln=1
      reasons+=("group/other 쓰기 권한이 존재함(perm=${perm_str})")
    fi
    if (( (perm_oct & 8#111) != 0 )); then
      vuln=1
      reasons+=("실행(x) 권한이 존재함(perm=${perm_str})")
    fi
    
    # 출력
    say "U-22 /etc/services 파일 소유자 및 권한 설정"
    say "현재: owner=${owner_name}(uid=${owner_uid}), group=${group_name}, perm=${perm_str}"
    
    if [[ "$vuln" -eq 0 ]]; then
      say "결과: 양호"
      exit 0
    else
      say "결과: 취약"
      for r in "${reasons[@]}"; do
        say "사유: $r"
      done
      exit 1
    fi
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-22 | /etc/services 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 소유자 root(또는 bin, sys)이고 권한 644 이하인 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-22 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-22 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-22 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

U_27() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-27(상) | 2. 파일 및 디렉토리 관리 > 2.14 \$HOME/.rhosts, hosts.equiv 사용 금지 (Rocky 9) ◀" >> "$resultfile" 2>&1
    
    VULN=0
    DETAILS=""

    # 1. 서비스 확인: Rocky는 rsh-server 패키지 등을 사용
    if systemctl list-units --type=service --all | grep -qiE 'rsh|rlogin|rexec'; then
        R_ACTIVE=$(systemctl is-active rsh.socket rlogin.socket rexec.socket 2>/dev/null | grep 'active' || true)
        [ -n "$R_ACTIVE" ] && DETAILS="[Service] r-command 서비스 활성화됨"
    fi

    # 2. /etc/hosts.equiv 점검
    if [ -f "/etc/hosts.equiv" ]; then
        PERM=$(stat -c "%a" /etc/hosts.equiv)
        [ "$PERM" -gt 600 ] && VULN=1 && DETAILS="$DETAILS | /etc/hosts.equiv 권한 과다($PERM)"
        grep -q "+" /etc/hosts.equiv && VULN=1 && DETAILS="$DETAILS | /etc/hosts.equiv 내 '+' 설정 존재"
    fi

    # 3. 사용자 .rhosts 점검 (UID 1000 이상 일반 사용자 타겟)
    USER_HOMES=$(awk -F: '$3 >= 1000 && $7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd)
    for INFO in $USER_HOMES; do
        U_NAME=$(echo "$INFO" | cut -d: -f1); U_HOME=$(echo "$INFO" | cut -d: -f2)
        TARGET="$U_HOME/.rhosts"
        if [ -f "$TARGET" ]; then
            [ "$(stat -c "%a" "$TARGET")" -gt 600 ] && VULN=1 && DETAILS="$DETAILS | $U_NAME: .rhosts 권한 취약"
            grep -q "+" "$TARGET" && VULN=1 && DETAILS="$DETAILS | $U_NAME: .rhosts '+' 존재"
        fi
    done

    [ $VULN -eq 1 ] && echo "※ U-27 결과 : 취약(Vulnerable) - $DETAILS" >> "$resultfile" 2>&1 || echo "※ U-27 결과 : 양호(Good)" >> "$resultfile" 2>&1
}

U_32() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # ============================================================
    # 주요통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (UNIX) - U-32
    # 점검항목: 홈 디렉터리로 지정한 디렉터리의 존재 관리
    # 대상: Rocky Linux 9 (Linux 공통 로직)
    #
    # 판정 기준(가이드 요지):
    # - 양호: (로그인 가능한 계정 중) 홈 디렉터리가 존재하지 않는 계정이 발견되지 않은 경우
    # - 취약: (로그인 가능한 계정 중) 홈 디렉터리가 없거나(빈 값) / 존재하지 않거나 / 디렉터리가 아닌 계정이 발견된 경우
    #
    # 실행: sudo bash kisa_unix_u32_check_rl9.sh
    # 종료코드: 0=양호, 1=취약, 2=오류/점검불가
    # ============================================================
    
    set -u
    LANG=C
    LC_ALL=C
    
    hr(){ printf "%s\n" "------------------------------------------------------------"; }
    say(){ printf "%s\n" "$*"; }
    
    # root 권한 확인
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      say "U-32 결과: N/A"
      say "사유: root 권한이 필요합니다. sudo로 실행하세요."
      exit 2
    fi
    
    PASSWD_FILE="/etc/passwd"
    if [[ ! -r "$PASSWD_FILE" ]]; then
      say "U-32 결과: N/A"
      say "사유: /etc/passwd 를 읽을 수 없습니다."
      exit 2
    fi
    
    # 로그인 불가 쉘 목록(일반적으로 로그인 차단)
    is_login_enabled_shell() {
      local sh="${1:-}"
      case "$sh" in
        "" ) return 0 ;; # 빈 쉘은 환경에 따라 기본 쉘로 동작할 수 있어 로그인 가능으로 간주
        /sbin/nologin|/usr/sbin/nologin|/bin/false|/usr/bin/false) return 1 ;;
        * ) return 0 ;;
      esac
    }
    
    TOTAL=0
    CHECKED=0
    VULN=0
    DETAILS=()
    
    # /etc/passwd 파싱: user:pw:uid:gid:gecos:home:shell
    while IFS=: read -r user pw uid gid gecos home shell; do
      [[ -z "${user:-}" ]] && continue
      TOTAL=$((TOTAL+1))
    
      # 로그인 가능한 계정만 점검(가이드 취지: 로그인 시 홈 디렉터리 문제)
      if ! is_login_enabled_shell "${shell:-}"; then
        continue
      fi
    
      CHECKED=$((CHECKED+1))
    
      # 홈 경로가 비어있으면 취약
      if [[ -z "${home:-}" ]]; then
        VULN=$((VULN+1))
        DETAILS+=("계정=${user} | home=(빈 값) | shell=${shell:-'(빈 값)'} | 사유=홈 디렉터리 항목이 비어있음")
        continue
      fi
    
      # 존재/디렉터리 여부 점검
      if [[ ! -e "$home" ]]; then
        VULN=$((VULN+1))
        DETAILS+=("계정=${user} | home=${home} | shell=${shell:-'(빈 값)'} | 사유=홈 디렉터리가 존재하지 않음")
        continue
      fi
    
      if [[ ! -d "$home" ]]; then
        VULN=$((VULN+1))
        DETAILS+=("계정=${user} | home=${home} | shell=${shell:-'(빈 값)'} | 사유=홈 경로가 디렉터리가 아님")
        continue
      fi
    done < "$PASSWD_FILE"
    
    hr
    say "U-32(중) | 파일 및 디렉터리 관리 | 홈 디렉터리로 지정한 디렉터리의 존재 관리"
    say "점검대상: /etc/passwd (로그인 가능한 계정: nologin/false 제외)"
    say "판정기준: 홈 디렉터리 미존재(또는 빈 값/디렉터리 아님) 계정 발견 시 취약"
    hr
    
    say "점검 요약: passwd총계정=${TOTAL}, 로그인가능계정점검수=${CHECKED}, 취약건수=${VULN}"
    hr
    
    if [[ "$VULN" -eq 0 ]]; then
      say "U-32 결과: 양호"
      exit 0
    else
      say "U-32 결과: 취약"
      say "취약 상세:"
      for line in "${DETAILS[@]}"; do
        say " - ${line}"
      done
      hr
      say "조치 가이드(예시):"
      say " - 불필요 계정이면 삭제: userdel <계정>"
      say " - 필요한 계정이면 홈 디렉터리 생성/지정:"
      say "   1) 홈 생성: mkdir -p <홈경로> && chown <계정>:<그룹> <홈경로> && chmod 700 <홈경로>"
      say "   2) 홈 지정(필요 시): usermod -d <홈경로> <계정>   (기존 자료 이동은 usermod -m 옵션 검토)"
      exit 1
    fi
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-32(중) | 2. 파일 및 디렉터리 관리 > 홈 디렉터리 지정 및 존재 관리 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그인 가능한 계정의 홈 디렉터리가 지정되어 있고 실제 디렉터리가 존재하는 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-32 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-32 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-32 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-37) ----
U_37() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # KISA 주요통신기반시설 UNIX 가이드 U-37 (상)
    # crontab/at 관련 설정 미흡(권한/소유자/일반사용자 사용 제한) 점검 스크립트
    # 대상: Rocky Linux 9 (RHEL 계열 공통)
    # 실행: sudo bash kisa_unix_u37_check_rocky9.sh
    
    set -u
    export LC_ALL=C
    
    # ---------- 공통 ----------
    fail=0
    declare -a FAIL_REASONS=()
    
    hr(){ echo "---------------------------------------------------------------------"; }
    mark_fail(){
      fail=1
      FAIL_REASONS+=("$1")
    }
    
    need_root(){
      if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "오류: sudo로 실행해야 합니다."
        exit 1
      fi
    }
    
    oct_to_dec(){
      # $1: "640" or "4755" etc
      local s="${1:-}"
      [[ -z "$s" ]] && echo 0 && return
      echo $((8#$s))
    }
    
    perm_leq(){
      # $1 actual(문자열), $2 max(문자열)
      local a d
      a="$(oct_to_dec "$1")"
      d="$(oct_to_dec "$2")"
      (( a <= d ))
    }
    
    has_special_bits(){
      # setuid/setgid/sticky 여부(권한 문자열이 4자리 이상이면 첫자리가 특수비트)
      local p="${1:-}"
      if [[ "$p" =~ ^[0-7]{4,}$ ]]; then
        local special="${p:0:1}"
        (( 8#$special != 0 )) && return 0
      fi
      return 1
    }
    
    stat_field(){
      local fmt="$1" path="$2"
      stat -c "$fmt" "$path" 2>/dev/null || echo "UNKNOWN"
    }
    
    is_file(){ [[ -e "$1" && -f "$1" ]]; }
    is_dir(){ [[ -e "$1" && -d "$1" ]]; }
    
    # ---------- 관리자(관리자 계정) 판정 ----------
    # 가이드 표현은 "관리자 외 사용 불가"이므로, 여기서는 기본 관리자 집합을:
    # root + wheel 그룹 구성원(+ sudo 그룹이 있으면 포함)
    declare -A ADMIN=()
    ADMIN["root"]=1
    
    add_group_members(){
      local g="$1"
      local members
      members="$(getent group "$g" 2>/dev/null | awk -F: '{print $4}' || true)"
      [[ -z "$members" ]] && return 0
      # 쉼표 분리
      IFS=',' read -r -a arr <<< "$members"
      for u in "${arr[@]}"; do
        [[ -n "${u// /}" ]] && ADMIN["$u"]=1
      done
    }
    
    add_group_members "wheel"
    add_group_members "sudo"
    
    is_admin(){
      local u="$1"
      [[ -n "${ADMIN[$u]+x}" ]]
    }
    
    list_interactive_users(){
      # Rocky/RHEL 계열: 일반 사용자 UID는 보통 1000 이상
      # 로그인 불가 쉘(nologin/false)은 제외
      awk -F: '($3>=1000) && ($7 !~ /(nologin|false)$/) {print $1}' /etc/passwd 2>/dev/null | sort -u
    }
    
    # ---------- (A) cron/at 사용 권한(allow/deny) 점검 ----------
    # 정책:
    # 1) *.allow 존재: allow에 있는 사용자가 관리자 집합에만 속하면 양호(비어있어도 일반 사용자 허용은 아님)
    # 2) *.allow 미존재, *.deny 존재: "deny에 없는 사용자는 허용"이므로,
    #    비관리자(일반) 인터랙티브 사용자들이 모두 deny에 포함되어야 양호
    # 3) 둘 다 미존재: root만 가능(가이드 표의 주석과 man 페이지 동작) -> 양호
    read_allow_users(){
      local f="$1"
      grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | awk '{print $1}' | sort -u
    }
    file_contains_user(){
      local f="$1" u="$2"
      grep -Eq "^[[:space:]]*$u([[:space:]]|$)" "$f" 2>/dev/null
    }
    
    check_allow_deny(){
      local svc="$1" allow="$2" deny="$3"
      local ok=1
    
      echo "[점검] $svc 사용자 사용 제한(allow/deny)"
      if is_file "$allow"; then
        local bad=()
        while IFS= read -r u; do
          [[ -z "$u" ]] && continue
          if ! is_admin "$u"; then
            bad+=("$u")
          fi
        done < <(read_allow_users "$allow")
    
        if ((${#bad[@]} > 0)); then
          ok=0
          echo "  결과: 취약 (allow에 비관리자 포함)"
          echo "  파일: $allow"
          echo "  비관리자 항목: ${bad[*]}"
          mark_fail "$svc: $allow 에 비관리자 계정이 포함되어 있어 일반 사용자 사용이 가능함"
        else
          echo "  결과: 양호 (allow가 관리자만 허용)"
          echo "  파일: $allow"
        fi
    
      elif is_file "$deny"; then
        # deny 기반: deny에 없는 사용자는 허용이므로, 비관리자 일반 사용자가 전부 deny에 있어야 제한됨
        local missing=()
        while IFS= read -r u; do
          [[ -z "$u" ]] && continue
          if is_admin "$u"; then
            continue
          fi
          if ! file_contains_user "$deny" "$u"; then
            missing+=("$u")
          fi
        done < <(list_interactive_users)
    
        if ((${#missing[@]} > 0)); then
          ok=0
          echo "  결과: 취약 (deny에 없는 비관리자 존재 -> 사용 가능)"
          echo "  파일: $deny"
          echo "  deny에 없는 비관리자: ${missing[*]}"
          mark_fail "$svc: $deny 방식이며 deny에 없는 비관리자가 존재하여 일반 사용자 사용이 가능함"
        else
          echo "  결과: 양호 (비관리자 사용자를 deny로 차단)"
          echo "  파일: $deny"
        fi
    
      else
        echo "  결과: 양호 (allow/deny 미존재 -> root만 가능)"
      fi
    
      return $ok
    }
    
    # ---------- (B) crontab/at 명령 파일 권한(<=750) 및 SUID 점검 ----------
    check_cmd_perm(){
      local label="$1" path="$2"
      local maxperm="750"
    
      if [[ -z "$path" || ! -e "$path" ]]; then
        echo "[점검] $label 명령 파일: 없음 (SKIP)"
        return 0
      fi
    
      local owner group perm
      owner="$(stat_field "%U" "$path")"
      group="$(stat_field "%G" "$path")"
      perm="$(stat_field "%a" "$path")"
    
      echo "[점검] $label 명령 파일 권한/소유자"
      echo "  대상: $path"
      echo "  소유자/그룹: $owner:$group"
      echo "  권한(8진): $perm (기준: <= $maxperm, SUID/SGID 제거)"
    
      local ok=1
    
      if [[ "$owner" != "root" ]]; then
        ok=0
        echo "  판정: 취약 (소유자 root 아님)"
        mark_fail "$label: $path 소유자가 root가 아님($owner)"
      fi
    
      if ! perm_leq "$perm" "$maxperm"; then
        ok=0
        echo "  판정: 취약 (권한이 기준 초과)"
        mark_fail "$label: $path 권한($perm)이 기준(<=${maxperm})을 초과"
      fi
    
      if has_special_bits "$perm"; then
        ok=0
        echo "  판정: 취약 (특수비트(SUID/SGID/Sticky) 설정)"
        mark_fail "$label: $path 에 SUID/SGID/Sticky 등 특수비트가 설정됨(권한=$perm)"
      fi
    
      if (( ok == 1 )); then
        echo "  판정: 양호"
      fi
    
      return $ok
    }
    
    # ---------- (C) cron/at 관련 파일(<=640) 및 디렉터리(<=750) 권한/소유자 점검 ----------
    check_path_owner_perm(){
      local path="$1" kind="$2" maxperm="$3"
    
      local owner group perm
      owner="$(stat_field "%U" "$path")"
      group="$(stat_field "%G" "$path")"
      perm="$(stat_field "%a" "$path")"
    
      local ok=1
    
      if [[ "$owner" != "root" ]]; then
        ok=0
        mark_fail "$path: 소유자가 root가 아님($owner)"
      fi
    
      if ! perm_leq "$perm" "$maxperm"; then
        ok=0
        mark_fail "$path: 권한($perm)이 기준(<=${maxperm})을 초과"
      fi
    
      if (( ok == 1 )); then
        echo "  양호: $kind $path (owner=$owner:$group perm=$perm)"
      else
        echo "  취약: $kind $path (owner=$owner:$group perm=$perm, 기준<=${maxperm})"
      fi
    
      return $ok
    }
    
    check_dir_and_files(){
      # $1 dir, $2 depth
      local dir="$1" depth="${2:-1}"
    
      if ! is_dir "$dir"; then
        echo "[점검] $dir : 없음 (SKIP)"
        return 0
      fi
    
      echo "[점검] 디렉터리 및 내부 파일 권한 점검: $dir"
      # 디렉터리 자체
      check_path_owner_perm "$dir" "DIR" "750" || true
    
      # 내부 파일/디렉터리(제한된 depth)
      while IFS= read -r -d '' p; do
        if [[ "$p" == "$dir" ]]; then
          continue
        fi
        if is_dir "$p"; then
          check_path_owner_perm "$p" "DIR" "750" || true
        elif is_file "$p"; then
          check_path_owner_perm "$p" "FILE" "640" || true
        fi
      done < <(find "$dir" -maxdepth "$depth" -mindepth 1 \( -type f -o -type d \) -print0 2>/dev/null)
    
      return 0
    }
    
    # ---------- 메인 ----------
    need_root
    
    echo "▶ U-37(상) | 3. 서비스 관리 | crontab/at 관련 설정 미흡 점검 (Rocky Linux 9)"
    echo "판단기준(요약):"
    echo " - 양호: crontab/at 일반 사용자 사용 제한(관리자만 가능) + 관련 파일 권한 적정(명령<=750, 관련 파일<=640)"
    echo " - 취약: 일반 사용자 사용 가능 + 관련 파일 권한 과다(명령>750 또는 관련 파일>640 등)"
    hr
    
    # (1) 사용자 사용 제한 점검
    check_allow_deny "cron" "/etc/cron.allow" "/etc/cron.deny" || true
    hr
    check_allow_deny "at"   "/etc/at.allow"   "/etc/at.deny"   || true
    hr
    
    # (2) 명령 파일 권한/소유자/SUID 점검
    CRONTAB_BIN="$(command -v crontab 2>/dev/null || true)"
    AT_BIN="$(command -v at 2>/dev/null || true)"
    ATQ_BIN="$(command -v atq 2>/dev/null || true)"
    ATRM_BIN="$(command -v atrm 2>/dev/null || true)"
    
    check_cmd_perm "crontab" "$CRONTAB_BIN" || true
    hr
    check_cmd_perm "at" "$AT_BIN" || true
    # atq/atrm도 함께 보는 것이 실무적으로 안전
    if [[ -n "$ATQ_BIN" ]]; then hr; check_cmd_perm "atq" "$ATQ_BIN" || true; fi
    if [[ -n "$ATRM_BIN" ]]; then hr; check_cmd_perm "atrm" "$ATRM_BIN" || true; fi
    hr
    
    # (3) cron 관련 파일/디렉터리 점검
    echo "[점검] cron 관련 파일/디렉터리 권한/소유자"
    # 대표 파일
    if is_file "/etc/crontab"; then
      check_path_owner_perm "/etc/crontab" "FILE" "640" || true
    else
      echo "  /etc/crontab 없음 (SKIP)"
    fi
    
    # allow/deny 파일도 권한 기준 적용
    if is_file "/etc/cron.allow"; then check_path_owner_perm "/etc/cron.allow" "FILE" "640" || true; fi
    if is_file "/etc/cron.deny";  then check_path_owner_perm "/etc/cron.deny"  "FILE" "640" || true; fi
    
    hr
    # cron 디렉터리들
    check_dir_and_files "/etc/cron.d" 1
    hr
    check_dir_and_files "/etc/cron.hourly" 1
    hr
    check_dir_and_files "/etc/cron.daily" 1
    hr
    check_dir_and_files "/etc/cron.weekly" 1
    hr
    check_dir_and_files "/etc/cron.monthly" 1
    hr
    # 사용자별 crontab 스풀
    check_dir_and_files "/var/spool/cron" 1
    hr
    
    # (4) at 관련 파일/디렉터리 점검
    echo "[점검] at 관련 파일/디렉터리 권한/소유자"
    if is_file "/etc/at.allow"; then check_path_owner_perm "/etc/at.allow" "FILE" "640" || true; fi
    if is_file "/etc/at.deny";  then check_path_owner_perm "/etc/at.deny"  "FILE" "640" || true; fi
    hr
    # at 스풀(배포판에 따라 경로 차이 대응)
    check_dir_and_files "/var/spool/at" 2
    hr
    check_dir_and_files "/var/spool/atjobs" 2
    hr
    
    # ---------- 결과 ----------
    if (( fail == 0 )); then
      echo "결과: 양호"
    else
      echo "결과: 취약"
      echo "취약 사유:"
      for r in "${FAIL_REASONS[@]}"; do
        echo " - $r"
      done
    fi
    
    exit 0
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-37(상) | 3. 서비스 관리 > tftp, talk, ntalk 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : tftp, talk, ntalk, finger 서비스가 비활성 또는 미설치인 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-37 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-37 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-37 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-42) ----
U_42() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/bin/bash
    
    #################################################################
    # 항목코드: U-42
    # 항목명: 불필요한 RPC 서비스 비활성화
    # 중요도: 상
    # 대상 OS: Rocky Linux 9 (RHEL 계열)
    #################################################################
    
    # 점검 대상 RPC 관련 서비스 목록 (가이드 기준 및 일반적인 RPC 서비스)
    RPC_SERVICES=("rpcbind" "rpc-statd" "rpcsvcgssd")
    
    echo "=========================================================="
    echo " [U-42] 불필요한 RPC 서비스 비활성화 점검 시작"
    echo "=========================================================="
    
    VULN_COUNT=0
    CHECK_RESULTS=""
    
    for SERVICE in "${RPC_SERVICES[@]}"; do
        # 서비스 존재 여부 확인
        if systemctl list-unit-files | grep -q "^${SERVICE}.service"; then
            # 서비스 활성화(Active) 및 자동 실행(Enabled) 상태 확인
            IS_ACTIVE=$(systemctl is-active "$SERVICE")
            IS_ENABLED=$(systemctl is-enabled "$SERVICE")
    
            if [ "$IS_ACTIVE" == "active" ] || [ "$IS_ENABLED" == "enabled" ]; then
                CHECK_RESULTS+="- [취약] $SERVICE 서비스가 구동 중이거나 활성화되어 있습니다.\n"
                ((VULN_COUNT++))
            else
                CHECK_RESULTS+="- [양호] $SERVICE 서비스가 비활성화되어 있습니다.\n"
            fi
        else
            CHECK_RESULTS+="- [정보] $SERVICE 서비스가 시스템에 존재하지 않습니다.\n"
        fi
    done
    
    # 결과 판정
    echo -e "$CHECK_RESULTS"
    
    if [ $VULN_COUNT -gt 0 ]; then
        echo "----------------------------------------------------------"
        echo "▶ 결과: [취약]"
        echo "▶ 조치: 사용하지 않는 RPC 서비스를 중지하고 비활성화하십시오."
        echo "   (명령어 예시: systemctl stop <service> && systemctl disable <service>)"
    else
        echo "----------------------------------------------------------"
        echo "▶ 결과: [양호]"
    fi
    echo "=========================================================="
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-42(상) | 3. 서비스 관리 > 불필요한 RPC 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 RPC 서비스(rpcbind 등)가 비활성 상태이면 양호" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-42 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-42 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-42 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-47) ----
U_47() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # KISA 주요통신기반시설(UNIX) U-47(상) 스팸 메일 릴레이 제한 점검 - Rocky Linux 9
    # 실행: sudo ./u47.sh  (또는 sudo bash ./u47.sh)
    # 결과 코드: 양호/N/A=0, 취약=1
    
    set -o pipefail
    
    TITLE="U-47(상) 스팸 메일 릴레이 제한"
    RESULT="N/A"
    DETAILS=()
    EVIDENCES=()
    
    is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
    have_cmd() { command -v "$1" >/dev/null 2>&1; }
    
    add_detail(){ DETAILS+=("$1"); }
    add_evidence(){ EVIDENCES+=("$1"); }
    
    svc_is_active() {
      local s="$1"
      if have_cmd systemctl; then
        systemctl is-active --quiet "$s" 2>/dev/null
        return $?
      fi
      return 1
    }
    
    listening_25() {
      if have_cmd ss; then
        ss -lntp 2>/dev/null | grep -E 'LISTEN' | grep -E '([.:])25[[:space:]]' >/dev/null 2>&1
        return $?
      elif have_cmd netstat; then
        netstat -lntp 2>/dev/null | grep -E 'LISTEN' | grep -E '([.:])25[[:space:]]' >/dev/null 2>&1
        return $?
      fi
      return 1
    }
    
    detect_mtas() {
      local mtas=()
    
      svc_is_active postfix && mtas+=("postfix")
      svc_is_active sendmail && mtas+=("sendmail")
      svc_is_active exim && mtas+=("exim")
      svc_is_active exim4 && mtas+=("exim4")
    
      # 서비스로 못 잡아도 25/tcp 리슨이면 추정
      if [ "${#mtas[@]}" -eq 0 ] && listening_25 && have_cmd ss; then
        local procs
        procs="$(ss -lntp 2>/dev/null | grep -E '([.:])25[[:space:]]' | sed -n 's/.*users:(\(.*\)).*/\1/p' | tr ',' '\n' | sed -n 's/.*"\([^"]\+\)".*/\1/p' | sort -u)"
        echo "$procs" | grep -qiE 'master|postfix' && mtas+=("postfix")
        echo "$procs" | grep -qiE 'sendmail' && mtas+=("sendmail")
        echo "$procs" | grep -qiE 'exim' && mtas+=("exim")
      fi
    
      printf "%s\n" "${mtas[@]}"
    }
    
    trim() { sed -e 's/^[[:space:]]\+//; s/[[:space:]]\+$//'; }
    
    postfix_get() {
      local key="$1"
      if have_cmd postconf; then
        postconf -h "$key" 2>/dev/null | tr -d '\r'
        return 0
      fi
      if [ -f /etc/postfix/main.cf ]; then
        awk -v k="$key" '
          BEGIN{IGNORECASE=1}
          /^[[:space:]]*#/ {next}
          $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
            sub("^[[:space:]]*"k"[[:space:]]*=[[:space:]]*","")
            print
            exit
          }
        ' /etc/postfix/main.cf 2>/dev/null | tr -d '\r'
        return 0
      fi
      return 1
    }
    
    postfix_check() {
      local ok=1
      local relay rcpt mynet
      relay="$(postfix_get smtpd_relay_restrictions | trim)"
      rcpt="$(postfix_get smtpd_recipient_restrictions | trim)"
      mynet="$(postfix_get mynetworks | trim)"
    
      add_detail "[Postfix] 설정값 점검"
      add_detail "[Postfix] smtpd_relay_restrictions = ${relay:-<empty>}"
      add_detail "[Postfix] smtpd_recipient_restrictions = ${rcpt:-<empty>}"
      add_detail "[Postfix] mynetworks = ${mynet:-<empty>}"
    
      if [ -f /etc/postfix/main.cf ]; then
        add_evidence "[Postfix] /etc/postfix/main.cf 관련 라인(최대 50줄)"
        add_evidence "$(grep -nE '^[[:space:]]*(smtpd_(relay|recipient)_restrictions|mynetworks)[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | head -n 50 || true)"
      fi
    
      # 릴레이 제한 핵심 토큰(둘 중 하나라도 있으면 제한 존재로 판단)
      local has_guard=0
      echo "$relay" | grep -qiE 'reject_unauth_destination|defer_unauth_destination' && has_guard=1
      echo "$rcpt"  | grep -qiE 'reject_unauth_destination|defer_unauth_destination' && has_guard=1
    
      # 명백한 위험 토큰
      local has_permit_all=0
      echo "$relay $rcpt" | grep -qiE 'permit_all' && has_permit_all=1
    
      # mynetworks 전체 허용 패턴
      local mynet_bad=0
      echo "$mynet" | grep -qiE '(^|[ ,])0\.0\.0\.0/0([ ,]|$)|(^|[ ,])0/0([ ,]|$)|(^|[ ,])::/0([ ,]|$)' && mynet_bad=1
    
      if [ "$has_permit_all" -eq 1 ]; then
        add_detail "[Postfix] 취약 징후: permit_all 존재"
        ok=0
      fi
    
      if [ "$mynet_bad" -eq 1 ]; then
        add_detail "[Postfix] 취약 징후: mynetworks가 전체망(0.0.0.0/0 또는 ::/0) 허용"
        ok=0
      fi
    
      if [ "$has_guard" -eq 0 ]; then
        add_detail "[Postfix] 취약 징후: reject_unauth_destination 또는 defer_unauth_destination 미확인"
        ok=0
      fi
    
      [ "$ok" -eq 1 ]
    }
    
    sendmail_check() {
      local ok=1
      local mc="/etc/mail/sendmail.mc"
      local cf="/etc/mail/sendmail.cf"
      local access="/etc/mail/access"
    
      add_detail "[Sendmail] 설정값 점검"
    
      if [ -f "$mc" ]; then
        add_evidence "[Sendmail] /etc/mail/sendmail.mc 릴레이 관련(최대 80줄)"
        add_evidence "$(grep -nE 'promiscuous_relay|relay_entire_domain|access_db|FEATURE' "$mc" 2>/dev/null | head -n 80 || true)"
        if grep -qE 'FEATURE\(`(promiscuous_relay|relay_entire_domain)'\''\)' "$mc" 2>/dev/null; then
          add_detail "[Sendmail] 취약 징후: FEATURE(promiscuous_relay) 또는 FEATURE(relay_entire_domain) 존재"
          ok=0
        fi
      fi
    
      if [ -f "$cf" ]; then
        add_evidence "[Sendmail] /etc/mail/sendmail.cf Relaying denied(최대 30줄)"
        add_evidence "$(grep -nE 'Relaying denied|550[[:space:]]+Relaying denied' "$cf" 2>/dev/null | head -n 30 || true)"
      fi
    
      if [ -f "$access" ]; then
        add_evidence "[Sendmail] /etc/mail/access RELAY/REJECT 일부(최대 80줄)"
        add_evidence "$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$access" 2>/dev/null | grep -nE '[[:space:]](RELAY|REJECT)[[:space:]]*$' | head -n 80 || true)"
        if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$access" 2>/dev/null \
          | grep -qiE '(^|[[:space:]])(Connect:)?(ALL|0\.0\.0\.0/0|0/0|::/0)[[:space:]]+RELAY([[:space:]]|$)'; then
          add_detail "[Sendmail] 취약 징후: access에서 ALL 또는 전체망을 RELAY 허용"
          ok=0
        fi
      fi
    
      [ "$ok" -eq 1 ]
    }
    
    exim_check() {
      local ok=1
      local conf=""
      for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/exim4.conf.template; do
        [ -f "$f" ] && conf="$f" && break
      done
    
      add_detail "[Exim] 설정값 점검"
    
      if [ -z "$conf" ]; then
        add_detail "[Exim] 설정 파일 미발견"
        return 1
      fi
    
      add_evidence "[Exim] ${conf} relay_from_hosts/accept 일부(최대 120줄)"
      add_evidence "$(grep -nE 'relay_from_hosts|hostlist[[:space:]]+relay_from_hosts|accept[[:space:]]+hosts' "$conf" 2>/dev/null | head -n 120 || true)"
    
      if grep -Ev '^[[:space:]]*#' "$conf" 2>/dev/null | grep -qiE 'hostlist[[:space:]]+relay_from_hosts[[:space:]]*=[[:space:]]*\*|relay_from_hosts[[:space:]]*=[[:space:]]*\*'; then
        add_detail "[Exim] 취약 징후: relay_from_hosts가 전체(*) 허용"
        ok=0
      fi
    
      [ "$ok" -eq 1 ]
    }
    
    print_report() {
      echo "------------------------------------------------------------"
      echo "$TITLE"
      echo "판단 기준: 양호(릴레이 제한 설정) / 취약(미설정) / N/A(메일 서비스 미사용)"
      echo "------------------------------------------------------------"
      echo "점검 상세:"
      for d in "${DETAILS[@]}"; do
        echo "- $d"
      done
      echo "------------------------------------------------------------"
      echo "근거(일부):"
      for e in "${EVIDENCES[@]}"; do
        [ -n "$e" ] && echo "$e"
      done
      echo "------------------------------------------------------------"
      echo "결과: $RESULT"
      echo "------------------------------------------------------------"
    }
    
    main() {
      if ! is_root; then
        echo "sudo로 실행해야 합니다."
        exit 1
      fi
    
      local mtas=()
      if have_cmd mapfile; then
        mapfile -t mtas < <(detect_mtas)
      else
        while IFS= read -r line; do mtas+=("$line"); done < <(detect_mtas)
      fi
    
      # 메일 미사용 판단: 서비스 active 없음 + 25/tcp 리스닝 없음
      if [ "${#mtas[@]}" -eq 0 ] && ! listening_25; then
        RESULT="N/A"
        add_detail "메일 서비스 비활성이고 25/tcp 리스닝이 없어 미사용으로 판단"
        print_report
        exit 0
      fi
    
      if have_cmd ss; then
        add_evidence "[네트워크] 25/tcp LISTEN"
        add_evidence "$(ss -lntp 2>/dev/null | grep -E '([.:])25[[:space:]]' || true)"
      elif have_cmd netstat; then
        add_evidence "[네트워크] 25/tcp LISTEN"
        add_evidence "$(netstat -lntp 2>/dev/null | grep -E '([.:])25[[:space:]]' || true)"
      fi
    
      add_detail "탐지된 SMTP 구성요소: ${mtas[*]:-<unknown>}"
    
      local any_vuln=0
      local checked_any=0
    
      local m
      for m in "${mtas[@]}"; do
        case "$m" in
          postfix)
            checked_any=1
            if postfix_check; then
              add_detail "[Postfix] 릴레이 제한 설정이 확인됨"
            else
              add_detail "[Postfix] 릴레이 제한 미흡(또는 취약 징후)으로 판단"
              any_vuln=1
            fi
            ;;
          sendmail)
            checked_any=1
            if sendmail_check; then
              add_detail "[Sendmail] 명시적 오픈 릴레이 허용 설정 미확인"
            else
              add_detail "[Sendmail] 오픈 릴레이 허용 설정(취약 징후) 확인"
              any_vuln=1
            fi
            ;;
          exim|exim4)
            checked_any=1
            if exim_check; then
              add_detail "[Exim] relay_from_hosts 전체(*) 허용 미확인"
            else
              add_detail "[Exim] relay_from_hosts 전체(*) 허용(취약 징후) 확인"
              any_vuln=1
            fi
            ;;
          *)
            add_detail "알 수 없는 MTA 항목: $m"
            ;;
        esac
      done
    
      if [ "$any_vuln" -eq 1 ]; then
        RESULT="취약"
        print_report
        exit 1
      fi
    
      # 25/tcp가 열려있는데도 아무것도 체크 못했으면 보수적으로 취약 처리
      if [ "$checked_any" -eq 0 ] && listening_25; then
        RESULT="취약"
        add_detail "25/tcp 리스닝은 있으나 MTA/설정 파일을 확인하지 못해 보수적으로 취약 처리"
        print_report
        exit 1
      fi
    
      RESULT="양호"
      print_report
      exit 0
    }
    
    main
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-47(상) | 3. 서비스 관리 > 스팸 메일 릴레이 제한 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 메일 서비스 사용 시 오픈 릴레이가 아니도록 릴레이 제한이 설정된 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-47 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-47 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-47 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-52) ----
U_52() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # KISA 주요통신기반시설 UNIX U-52 (중) : Telnet 서비스 비활성화 (Rocky Linux 9)
    # 실행: sudo ./u52.sh
    # 결과: 양호/취약/판단불가
    # 종료코드: 0(양호), 1(취약), 2(판단불가)
    
    set -u
    set -o pipefail
    
    TITLE="U-52 Telnet 서비스 비활성화 (Rocky Linux 9)"
    CRITERIA="판단 기준: Telnet 비활성/미사용이면 양호, Telnet 활성(서비스 실행/부팅활성 또는 23/tcp LISTEN)이면 취약"
    
    VULN=0
    UNKNOWN=0
    CHECKED=0
    REASONS=()
    EVIDENCES=()
    
    have_cmd() { command -v "$1" >/dev/null 2>&1; }
    hr() { echo "------------------------------------------------------------------"; }
    
    add_reason() { REASONS+=("$1"); }
    add_evidence() { EVIDENCES+=("$1"); }
    
    need_root_hint() {
      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "주의: root 권한이 아니면 일부 점검(systemd/프로세스/포트)이 제한될 수 있습니다."
        echo "권장: sudo로 실행"
        hr
      fi
    }
    
    check_systemd_telnet() {
      if ! have_cmd systemctl; then
        UNKNOWN=1
        add_reason "systemctl 명령이 없어 systemd 기반 점검을 수행할 수 없음"
        return
      fi
      CHECKED=$((CHECKED + 1))
    
      local units=("telnet.socket" "telnet.service" "telnetd.socket" "telnetd.service")
      local found=0
    
      for u in "${units[@]}"; do
        # 존재 여부: LoadState=not-found 이면 없음
        local load_state
        load_state="$(systemctl show -p LoadState --value "$u" 2>/dev/null || true)"
        if [[ -n "$load_state" && "$load_state" != "not-found" ]]; then
          found=1
          local active enabled
          active="$(systemctl is-active "$u" 2>/dev/null || true)"
          enabled="$(systemctl is-enabled "$u" 2>/dev/null || true)"
          add_evidence "systemd: $u active=$active enabled=$enabled (LoadState=$load_state)"
    
          if [[ "$active" == "active" || "$active" == "activating" ]]; then
            VULN=1
            add_reason "systemd에서 $u 가 실행 중(active)"
          fi
          if [[ "$enabled" == "enabled" || "$enabled" == "enabled-runtime" ]]; then
            VULN=1
            add_reason "systemd에서 $u 가 부팅 시 활성(enabled)"
          fi
        fi
      done
    
      # 보조: socket 목록에 telnet 관련이 active인지 확인
      local sockets
      sockets="$(systemctl list-units --type=socket --all --no-legend 2>/dev/null | grep -iE 'telnet' || true)"
      if [[ -n "$sockets" ]]; then
        found=1
        add_evidence "systemd socket 목록에 telnet 관련 항목 발견:\n$sockets"
        if echo "$sockets" | grep -qE '[[:space:]]active[[:space:]]'; then
          VULN=1
          add_reason "systemd socket 목록에서 telnet 관련 socket이 active로 표시됨"
        fi
      fi
    
      if [[ $found -eq 0 ]]; then
        add_evidence "systemd: telnet 관련 unit/socket 미발견"
      fi
    }
    
    check_xinetd_telnet() {
      local f="/etc/xinetd.d/telnet"
      if [[ ! -f "$f" ]]; then
        add_evidence "xinetd: $f 파일 없음"
        return
      fi
      CHECKED=$((CHECKED + 1))
    
      local disable_val=""
      disable_val="$(awk -F= '
        /^[[:space:]]*disable[[:space:]]*=/{
          gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2);
          print tolower($2);
          exit
        }' "$f" 2>/dev/null || true)"
    
      local xin_active="unknown"
      local xin_enabled="unknown"
      if have_cmd systemctl; then
        xin_active="$(systemctl is-active xinetd 2>/dev/null || true)"
        xin_enabled="$(systemctl is-enabled xinetd 2>/dev/null || true)"
      fi
    
      add_evidence "xinetd: $f 존재, xinetd active=$xin_active enabled=$xin_enabled, disable=${disable_val:-미설정}"
    
      # xinetd가 실제로 동작(실행/부팅활성) 중이고 telnet disable!=yes 이면 취약
      # xinetd가 꺼져 있으면 즉시 취약으로 단정하지 않고, 포트(23/tcp) LISTEN 여부가 최종판단에 더 중요
      if [[ "${disable_val:-}" != "yes" ]]; then
        if [[ "$xin_active" == "active" || "$xin_enabled" == "enabled" || "$xin_enabled" == "enabled-runtime" ]]; then
          VULN=1
          add_reason "xinetd가 실행/부팅활성 상태이며 telnet 설정이 disable=yes가 아님"
        else
          add_evidence "xinetd가 비활성 상태이지만 telnet 설정이 disable=yes가 아님(서비스 켜면 열릴 수 있음)"
        fi
      fi
    }
    
    check_inetd_telnet() {
      local f="/etc/inetd.conf"
      if [[ ! -f "$f" ]]; then
        add_evidence "inetd: $f 파일 없음"
        return
      fi
      CHECKED=$((CHECKED + 1))
    
      local hits
      hits="$(grep -nE '^[[:space:]]*[^#].*(telnet|in\.telnetd|telnetd)' "$f" 2>/dev/null || true)"
      if [[ -n "$hits" ]]; then
        VULN=1
        add_reason "/etc/inetd.conf에 telnet 관련 활성 라인이 존재"
        add_evidence "inetd: $f telnet 의심 라인:\n$hits"
      else
        add_evidence "inetd: $f 내 telnet 활성 라인 미발견"
      fi
    }
    
    check_listen_port23() {
      local out=""
      if have_cmd ss; then
        CHECKED=$((CHECKED + 1))
        out="$(ss -ltnp 2>/dev/null | awk 'NR>1 && $1=="LISTEN" && ($4 ~ /:23$/ || $4 ~ /\]:23$/){print}' || true)"
      elif have_cmd netstat; then
        CHECKED=$((CHECKED + 1))
        out="$(netstat -ltnp 2>/dev/null | awk 'NR>2 && $4 ~ /:23$/ {print}' || true)"
      else
        UNKNOWN=1
        add_reason "ss/netstat 명령이 없어 23/tcp 리스닝 점검을 수행할 수 없음"
        return
      fi
    
      if [[ -n "$out" ]]; then
        VULN=1
        add_reason "23/tcp 포트가 LISTEN 상태"
        add_evidence "LISTEN(23/tcp) 결과:\n$out"
      else
        add_evidence "23/tcp LISTEN 없음"
      fi
    }
    
    check_rpm_hint() {
      if ! have_cmd rpm; then
        return
      fi
      CHECKED=$((CHECKED + 1))
      local p1 p2
      p1="$(rpm -q telnet-server 2>/dev/null || true)"
      p2="$(rpm -q telnet 2>/dev/null || true)"
      add_evidence "패키지 참고: telnet-server=[$p1], telnet(client)=[$p2] (설치만으로 취약 확정 아님)"
    }
    
    main() {
      echo "$TITLE"
      echo "$CRITERIA"
      hr
      need_root_hint
    
      check_systemd_telnet
      check_xinetd_telnet
      check_inetd_telnet
      check_listen_port23
      check_rpm_hint
    
      hr
    
      if [[ $CHECKED -eq 0 ]]; then
        UNKNOWN=1
        add_reason "점검에 필요한 명령/파일을 거의 확인하지 못함(환경 제약)"
      fi
    
      if [[ $UNKNOWN -eq 1 && $VULN -eq 0 ]]; then
        echo "결과: 판단불가"
        if ((${#REASONS[@]} > 0)); then
          echo "사유:"
          for r in "${REASONS[@]}"; do echo "- $r"; done
        fi
        hr
        echo "근거:"
        for e in "${EVIDENCES[@]}"; do echo "- $e"; done
        exit 2
      fi
    
      if [[ $VULN -eq 1 ]]; then
        echo "결과: 취약"
        if ((${#REASONS[@]} > 0)); then
          echo "사유:"
          for r in "${REASONS[@]}"; do echo "- $r"; done
        fi
        hr
        echo "근거:"
        for e in "${EVIDENCES[@]}"; do echo "- $e"; done
        exit 1
      fi
    
      echo "결과: 양호"
      hr
      echo "근거:"
      for e in "${EVIDENCES[@]}"; do echo "- $e"; done
      exit 0
    }
    
    main "$@"
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-52(상) | 3. 서비스 관리 > syslog 서비스 활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그 수집 데몬(syslog/rsyslog/journald)이 활성화되어 로그가 적절히 기록되는 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-52 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-52 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-52 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-57) ----
U_57() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # KISA 주요통신기반시설 UNIX U-57 (중) | ftpusers 파일 설정
    # Rocky Linux 9 기준 점검 스크립트
    # - 점검 내용: FTP 서비스에서 root 계정 FTP 접속 차단 여부
    # - 판단 기준: (1) FTP 미사용/비활성 이면 양호, (2) FTP 사용 시 root FTP 접속 차단이면 양호, 허용이면 취약
    #
    # 실행: sudo bash u57.sh
    
    set -u
    set -o pipefail
    
    TITLE="U-57(중) | 3. 서비스 관리 | ftpusers 파일 설정"
    DESC="FTP 서비스에서 root 계정 FTP 접속 차단 여부 점검"
    
    log() {
      echo "$*"
    }
    
    add_detail() {
      DETAILS+=("$*")
    }
    
    is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
    
    # 파일에서 주석(#) 라인 제외하고, "root"가 항목으로 존재하는지 확인
    file_has_root_user() {
      local f="$1"
      [[ -r "$f" ]] || return 2
      awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*$/ {next}
        {
          # 첫 토큰이 root이면 인정
          if ($1=="root") { found=1; exit 0 }
        }
        END{ exit (found?0:1) }
      ' "$f"
    }
    
    # vsftpd.conf 키=값 읽기 (마지막 값을 사용)
    vs_kv_get() {
      local f="$1" key="$2"
      [[ -r "$f" ]] || return 1
      awk -v k="$key" '
        BEGIN{IGNORECASE=1}
        {
          line=$0
          sub(/#.*/, "", line)
          if (line ~ /^[[:space:]]*$/) next
          n=split(line, a, "=")
          if (n<2) next
          kk=a[1]
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", kk)
          if (tolower(kk)==tolower(k)) {
            val=substr(line, index(line,"=")+1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
          }
        }
        END{
          if (val!="") print val
        }
      ' "$f"
    }
    
    # proftpd 설정에서 특정 directive의 마지막 값을 찾기 (주석/인라인주석 제거)
    pro_last_directive() {
      local directive="$1"; shift
      local f=""
      local last_val=""
      local last_file=""
      for f in "$@"; do
        [[ -r "$f" ]] || continue
        local out
        out="$(awk -v d="$directive" '
          BEGIN{IGNORECASE=1}
          /^[[:space:]]*#/ {next}
          {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            if (match(line, "^[[:space:]]*" d "[[:space:]]+")) {
              sub("^[[:space:]]*" d "[[:space:]]+", "", line)
              gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
              if (line!="") v=line
            }
          }
          END{ if (v!="") print v }
        ' "$f")"
        if [[ -n "${out:-}" ]]; then
          last_val="$out"
          last_file="$f"
        fi
      done
      if [[ -n "${last_val:-}" ]]; then
        echo "${last_val}|${last_file}"
        return 0
      fi
      return 1
    }
    
    # 포트 21 리스닝 프로세스명 추출
    detect_port21_procs() {
      ss -ltnpH 2>/dev/null \
        | awk '$4 ~ /(:21|:ftp)$/ {print}' \
        | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' \
        | sort -u
    }
    
    systemd_active() {
      local unit="$1"
      command -v systemctl >/dev/null 2>&1 || return 1
      systemctl is-active --quiet "$unit" 2>/dev/null
    }
    
    lower() { tr '[:upper:]' '[:lower:]'; }
    
    DETAILS=()
    FINAL="N/A"
    EXITCODE=2
    
    log "[$TITLE]"
    log "$DESC"
    log "로그 파일: $resultfile"
    log ""
    
    if ! is_root; then
      log "오류: root 권한으로 실행해야 합니다. (sudo로 실행)"
      exit 1
    fi
    
    OS_PRETTY="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    log "대상 OS: $OS_PRETTY"
    log "호스트: $(hostname 2>/dev/null || echo unknown)"
    log ""
    
    # 1) FTP 서비스 사용 여부 판단
    PORT_PROCS="$(detect_port21_procs | paste -sd',' -)"
    FTP_ACTIVE_UNITS=()
    if systemd_active vsftpd.service; then FTP_ACTIVE_UNITS+=("vsftpd.service"); fi
    if systemd_active proftpd.service; then FTP_ACTIVE_UNITS+=("proftpd.service"); fi
    if systemd_active pure-ftpd.service; then FTP_ACTIVE_UNITS+=("pure-ftpd.service"); fi
    
    if [[ -n "${PORT_PROCS:-}" ]]; then
      add_detail "포트 21(ftp) 리스닝 프로세스: ${PORT_PROCS}"
    else
      add_detail "포트 21(ftp) 리스닝 없음"
    fi
    
    if [[ "${#FTP_ACTIVE_UNITS[@]}" -gt 0 ]]; then
      add_detail "systemd 활성 FTP 유닛: ${FTP_ACTIVE_UNITS[*]}"
    else
      add_detail "systemd 활성 FTP 유닛 없음"
    fi
    
    # FTP 미사용(포트 21 리스닝 없음 + 활성 유닛 없음)이면 양호 처리
    if [[ -z "${PORT_PROCS:-}" && "${#FTP_ACTIVE_UNITS[@]}" -eq 0 ]]; then
      FINAL="양호"
      EXITCODE=0
      add_detail "판단: FTP 서비스가 비활성/미사용 상태이므로 root FTP 접속 이슈가 발생하지 않음"
      log "결과: $FINAL"
      log ""
      log "근거:"
      for d in "${DETAILS[@]}"; do log " - $d"; done
      exit "$EXITCODE"
    fi
    
    # 2) FTP 데몬별 root 차단 여부 점검
    VULN_FOUND=0
    UNKNOWN_FOUND=0
    
    # 공통 후보 ftpusers 경로
    FTPUSERS_CANDIDATES=(
      "/etc/ftpusers"
      "/etc/ftpd/ftpusers"
      "/etc/vsftpd/ftpusers"
    )
    
    # 2-1) vsftpd 점검
    VSFTPD_SEEN=0
    if systemd_active vsftpd.service; then VSFTPD_SEEN=1; fi
    if echo "${PORT_PROCS:-}" | tr ',' '\n' | grep -qi '^vsftpd$'; then VSFTPD_SEEN=1; fi
    
    if [[ "$VSFTPD_SEEN" -eq 1 ]]; then
      add_detail "[vsftpd] 점검 시작"
    
      VS_CONF=""
      for p in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        if [[ -r "$p" ]]; then VS_CONF="$p"; break; fi
      done
    
      USERLIST_ENABLE="NO"
      USERLIST_DENY="YES"
      USERLIST_FILE="/etc/vsftpd/user_list"
    
      if [[ -n "$VS_CONF" ]]; then
        v="$(vs_kv_get "$VS_CONF" "userlist_enable" 2>/dev/null || true)"
        [[ -n "${v:-}" ]] && USERLIST_ENABLE="$(echo "$v" | lower)"
        v="$(vs_kv_get "$VS_CONF" "userlist_deny" 2>/dev/null || true)"
        [[ -n "${v:-}" ]] && USERLIST_DENY="$(echo "$v" | lower)"
        v="$(vs_kv_get "$VS_CONF" "userlist_file" 2>/dev/null || true)"
        [[ -n "${v:-}" ]] && USERLIST_FILE="$v"
    
        add_detail "[vsftpd] 설정파일: $VS_CONF"
        add_detail "[vsftpd] userlist_enable=${USERLIST_ENABLE}, userlist_deny=${USERLIST_DENY}, userlist_file=${USERLIST_FILE}"
      else
        add_detail "[vsftpd] 설정파일을 찾지 못함(기본값 가정: userlist_enable=NO, userlist_deny=YES, userlist_file=/etc/vsftpd/user_list)"
      fi
    
      # A) pam_listfile 기반 deny 확인 (RHEL 계열 기본)
      PAM_VS="/etc/pam.d/vsftpd"
      PAM_DENY_OK=0
      if [[ -r "$PAM_VS" ]]; then
        mapfile -t PAM_LISTFILES < <(awk '
          /^[[:space:]]*#/ {next}
          {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ /pam_listfile\.so/ && line ~ /sense=deny/ && line ~ /file=/) {
              n=split(line, a, /file=/)
              if (n>=2) {
                rest=a[2]
                split(rest, b, /[[:space:]]+/)
                if (b[1]!="") print b[1]
              }
            }
          }
        ' "$PAM_VS")
    
        if [[ "${#PAM_LISTFILES[@]}" -gt 0 ]]; then
          for lf in "${PAM_LISTFILES[@]}"; do
            if file_has_root_user "$lf"; then
              PAM_DENY_OK=1
              add_detail "[vsftpd] PAM deny-list 파일(${lf})에 root 존재"
              break
            else
              add_detail "[vsftpd] PAM deny-list 파일(${lf})에 root 없음 또는 확인 불가"
            fi
          done
        else
          add_detail "[vsftpd] PAM에서 pam_listfile 기반 root 차단 설정을 확인하지 못함"
        fi
      else
        add_detail "[vsftpd] /etc/pam.d/vsftpd 없음(또는 읽기 불가)"
      fi
    
      # B) 가이드 기준: userlist_enable=NO면 ftpusers에 root가 있어야 함
      FTPUSERS_OK=0
      for f in "/etc/vsftpd/ftpusers" "/etc/ftpusers" "/etc/ftpd/ftpusers"; do
        if file_has_root_user "$f"; then
          FTPUSERS_OK=1
          add_detail "[vsftpd] ftpusers 계열 파일(${f})에 root 존재"
          break
        else
          [[ -r "$f" ]] && add_detail "[vsftpd] ftpusers 계열 파일(${f})에 root 없음"
        fi
      done
    
      # C) userlist_enable=YES면 userlist_file 기준으로 판정
      USERLIST_OK="UNKNOWN"
      if [[ "$USERLIST_ENABLE" == "yes" || "$USERLIST_ENABLE" == "YES" ]]; then
        if [[ "$USERLIST_DENY" == "yes" || "$USERLIST_DENY" == "YES" ]]; then
          if file_has_root_user "$USERLIST_FILE"; then
            USERLIST_OK="DENY_OK"
            add_detail "[vsftpd] userlist_deny=YES 이며 userlist_file(${USERLIST_FILE})에 root 존재(차단)"
          else
            USERLIST_OK="DENY_BAD"
            add_detail "[vsftpd] userlist_deny=YES 이나 userlist_file(${USERLIST_FILE})에 root 없음(허용 가능)"
          fi
        else
          # allow-list 모드: root가 목록에 있으면 허용(취약), 없으면 차단(양호)
          if file_has_root_user "$USERLIST_FILE"; then
            USERLIST_OK="ALLOW_BAD"
            add_detail "[vsftpd] userlist_deny=NO(allow-list) 인데 userlist_file(${USERLIST_FILE})에 root 존재(허용=취약)"
          else
            USERLIST_OK="ALLOW_OK"
            add_detail "[vsftpd] userlist_deny=NO(allow-list) 이며 userlist_file(${USERLIST_FILE})에 root 없음(차단)"
          fi
        fi
      else
        add_detail "[vsftpd] userlist_enable=NO 이므로 user_list 기반 차단은 미사용(가이드상 ftpusers 확인)"
      fi
    
      VS_ROOT_BLOCKED=0
      # 가장 보수적으로: PAM deny OK 또는 (userlist 기준으로 root 차단 확정) 또는 (ftpusers에 root 존재)
      if [[ "$PAM_DENY_OK" -eq 1 ]]; then
        VS_ROOT_BLOCKED=1
      elif [[ "$USERLIST_OK" == "DENY_OK" || "$USERLIST_OK" == "ALLOW_OK" ]]; then
        VS_ROOT_BLOCKED=1
      elif [[ "$FTPUSERS_OK" -eq 1 ]]; then
        VS_ROOT_BLOCKED=1
      fi
    
      if [[ "$VS_ROOT_BLOCKED" -eq 1 ]]; then
        add_detail "[vsftpd] 판정: root FTP 접속 차단 설정 확인됨(양호)"
      else
        add_detail "[vsftpd] 판정: root FTP 접속 차단 설정을 확인하지 못함(취약으로 판정)"
        VULN_FOUND=1
      fi
    fi
    
    # 2-2) ProFTPD 점검
    PROFTPD_SEEN=0
    if systemd_active proftpd.service; then PROFTPD_SEEN=1; fi
    if echo "${PORT_PROCS:-}" | tr ',' '\n' | grep -qi '^proftpd$'; then PROFTPD_SEEN=1; fi
    
    if [[ "$PROFTPD_SEEN" -eq 1 ]]; then
      add_detail "[ProFTPD] 점검 시작"
    
      PRO_FILES=()
      for p in \
        /etc/proftpd.conf \
        /etc/proftpd/proftpd.conf \
        /etc/proftpd/*.conf \
        /etc/proftpd/conf.d/*.conf \
        /etc/proftpd/modules.conf; do
        for f in $p; do
          [[ -r "$f" ]] && PRO_FILES+=("$f")
        done
      done
    
      ROOTLOGFILEIN_VAL=""
      USEFTPUSERS_VAL=""
      if [[ "${#PRO_FILES[@]}" -gt 0 ]]; then
        out="$(pro_last_directive "RootLogin" "${PRO_FILES[@]}" 2>/dev/null || true)"
        if [[ -n "${out:-}" ]]; then
          ROOTLOGFILEIN_VAL="${out%%|*}"
          add_detail "[ProFTPD] RootLogin=${ROOTLOGFILEIN_VAL} (출처: ${out#*|})"
        else
          add_detail "[ProFTPD] RootLogin 설정을 찾지 못함"
        fi
    
        out="$(pro_last_directive "UseFtpUsers" "${PRO_FILES[@]}" 2>/dev/null || true)"
        if [[ -n "${out:-}" ]]; then
          USEFTPUSERS_VAL="${out%%|*}"
          add_detail "[ProFTPD] UseFtpUsers=${USEFTPUSERS_VAL} (출처: ${out#*|})"
        else
          add_detail "[ProFTPD] UseFtpUsers 설정을 찾지 못함"
        fi
      else
        add_detail "[ProFTPD] 설정파일을 찾지 못함"
      fi
    
      PRO_ROOT_BLOCKED=0
    
      if [[ -n "${ROOTLOGFILEIN_VAL:-}" ]] && [[ "$(echo "$ROOTLOGFILEIN_VAL" | lower)" == "off" ]]; then
        PRO_ROOT_BLOCKED=1
        add_detail "[ProFTPD] RootLogin off 확인(차단)"
      else
        # RootLogin이 off가 아니면, ftpusers + UseFtpUsers on 조합 확인
        if [[ -n "${USEFTPUSERS_VAL:-}" ]] && [[ "$(echo "$USEFTPUSERS_VAL" | lower)" == "on" ]]; then
          for f in "/etc/ftpusers" "/etc/ftpd/ftpusers"; do
            if file_has_root_user "$f"; then
              PRO_ROOT_BLOCKED=1
              add_detail "[ProFTPD] UseFtpUsers on 이며 ${f}에 root 존재(차단)"
              break
            else
              [[ -r "$f" ]] && add_detail "[ProFTPD] ${f}에 root 없음"
            fi
          done
        else
          add_detail "[ProFTPD] UseFtpUsers가 on으로 확인되지 않음(ftpusers 기반 차단 확정 불가)"
        fi
      fi
    
      if [[ "$PRO_ROOT_BLOCKED" -eq 1 ]]; then
        add_detail "[ProFTPD] 판정: root FTP 접속 차단 설정 확인됨(양호)"
      else
        add_detail "[ProFTPD] 판정: root FTP 접속 차단 설정을 확인하지 못함(취약으로 판정)"
        VULN_FOUND=1
      fi
    fi
    
    # 2-3) 기타/미확인 FTP 데몬
    # 알려진 데몬이 전혀 잡히지 않았는데 포트 21이 열려 있으면 N/A(수동확인)로 처리
    KNOWN=0
    [[ "$VSFTPD_SEEN" -eq 1 ]] && KNOWN=1
    [[ "$PROFTPD_SEEN" -eq 1 ]] && KNOWN=1
    
    if [[ "$KNOWN" -eq 0 ]]; then
      add_detail "알려진 FTP 데몬(vsftpd/proftpd)을 확인하지 못함"
      if [[ -n "${PORT_PROCS:-}" ]]; then
        UNKNOWN_FOUND=1
        add_detail "포트 21 리스닝 프로세스가 존재하므로, 해당 데몬의 root 로그인 차단 설정을 수동 점검 필요"
        # 참고로 ftpusers에 root가 있더라도 적용 여부는 데몬/설정에 따라 다를 수 있으므로 확정 판정하지 않음
        for f in "${FTPUSERS_CANDIDATES[@]}"; do
          if [[ -r "$f" ]]; then
            if file_has_root_user "$f"; then
              add_detail "참고: ${f}에 root 존재"
            else
              add_detail "참고: ${f}에 root 없음"
            fi
          fi
        done
      fi
    fi
    
    # 3) 최종 판정
    if [[ "$VULN_FOUND" -eq 1 ]]; then
      FINAL="취약"
      EXITCODE=1
    elif [[ "$UNKNOWN_FOUND" -eq 1 ]]; then
      FINAL="N/A"
      EXITCODE=2
    else
      FINAL="양호"
      EXITCODE=0
    fi
    
    log "결과: $FINAL"
    log ""
    log "근거:"
    for d in "${DETAILS[@]}"; do
      log " - $d"
    done
    
    log ""
    log "조치 가이드(요약):"
    log " - vsftpd 사용 시: /etc/vsftpd/ftpusers 또는 /etc/ftpusers에 root가 차단 목록으로 존재하는지 확인"
    log "   그리고 userlist_enable=YES인 경우 /etc/vsftpd/user_list에 root 포함 여부 + userlist_deny 설정을 함께 확인"
    log " - ProFTPD 사용 시: RootLogin off 또는 UseFtpUsers on + /etc/ftpusers에 root 포함을 확인"
    log " - FTP 미사용이 목적이면: 서비스 중지/비활성(systemctl disable --now vsftpd/proftpd) 및 포트 21 리스닝 제거"
    
    exit "$EXITCODE"
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-57(중) | 3. 서비스 관리 > ftpusers 파일 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : FTP 미사용 또는 사용 시 root FTP 로그인이 차단된 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-57 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-57 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-57 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-62) ----
U_62() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # KISA 주요통신기반시설 UNIX U-62 (상) 로그인 시 경고 메시지 설정 점검 (Rocky Linux 9 포함 RHEL계열)
    # 실행: sudo bash u62.sh  또는 sudo ./u62.sh
    
    set -u
    set -o pipefail
    
    # root 권한 체크
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "최종 결과: N/A"
      echo "사유: root 권한 필요(sudo로 실행)"
      exit 0
    fi
    
    # ---------- 공통 유틸 ----------
    out() { echo "$*"; }
    
    is_active() {
      local unit="$1"
      systemctl is-active --quiet "$unit" 2>/dev/null
    }
    
    has_cmd() { command -v "$1" >/dev/null 2>&1; }
    
    trim() {
      local s="${1:-}"
      echo "$s" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
    }
    
    # 경고/법적고지 키워드(필요 시 여기만 추가하면 됨)
    warn_keywords_regex='(경고|무단|허가|인가|권한|불법|금지|주의|Authorized|authorised|Unauthorized|unauthorized|WARNING|Notice|prohibited|permit|permission|monitor|monitored|consent|legal)'
    
    # OS/버전 노출로 흔히 쓰이는 문자열/토큰(이것만 있고 경고키워드 없으면 취약으로 판단)
    info_tokens_regex='(\\S|\\r|\\m|\\v|\\n|\\l|Rocky|CentOS|Red Hat|Ubuntu|Debian|Linux|Kernel|release|Version|\\(GNU/Linux\\))'
    
    check_banner_text() {
      # return codes:
      # 0 = OK(경고키워드 존재)
      # 1 = FAIL(비어있음/없음)
      # 2 = FAIL(정보노출 토큰/OS정보만 있고 경고키워드 없음으로 추정)
      local content="${1:-}"
      content="$(echo "$content" | tr -d '\r')"
      local compact
      compact="$(echo "$content" | sed '/^[[:space:]]*$/d' | head -n 30)"
    
      if [[ -z "$(trim "$compact")" ]]; then
        return 1
      fi
    
      if echo "$compact" | grep -Eqi "$warn_keywords_regex"; then
        return 0
      fi
    
      if echo "$compact" | grep -Eqi "$info_tokens_regex"; then
        return 2
      fi
    
      return 2
    }
    
    check_banner_file() {
      local f="$1"
      if [[ ! -e "$f" || ! -r "$f" ]]; then
        return 1
      fi
      local content
      content="$(cat "$f" 2>/dev/null || true)"
      check_banner_text "$content"
      return $?
    }
    
    # sshd 배너는 sshd -T 로 "실효값" 확인
    get_sshd_banner_path() {
      if ! has_cmd sshd; then
        echo ""
        return 0
      fi
      sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2; exit}'
    }
    
    # Postfix smtpd_banner는 postconf로 실효값 확인
    get_postfix_smtpd_banner() {
      if has_cmd postconf; then
        postconf -h smtpd_banner 2>/dev/null | tr -d '\r'
        return 0
      fi
      if [[ -r /etc/postfix/main.cf ]]; then
        awk -F= '
          /^[[:space:]]*smtpd_banner[[:space:]]*=/{
            val=$2; sub(/^[[:space:]]*/,"",val); sub(/[[:space:]]*$/,"",val);
            print val; exit
          }' /etc/postfix/main.cf 2>/dev/null | tr -d '\r'
        return 0
      fi
      echo ""
    }
    
    # key=value 형태 (vsftpd 등)
    get_conf_value_kv() {
      local key="$1"
      local file="$2"
      [[ -r "$file" ]] || return 1
      awk -v k="$key" -F= '
        $0 ~ "^[[:space:]]*#" {next}
        tolower($1) ~ "^[[:space:]]*"tolower(k)"[[:space:]]*$" {
          val=$2; sub(/^[[:space:]]*/,"",val); sub(/[[:space:]]*$/,"",val);
          print val; exit
        }' "$file" 2>/dev/null
    }
    
    # bind version "..." ; 형태 추출
    get_bind_version_value() {
      local f="$1"
      [[ -r "$f" ]] || return 1
      awk '
        BEGIN{IGNORECASE=1}
        $0 ~ /^[[:space:]]*#/ {next}
        $0 ~ /version[[:space:]]+/{
          line=$0
          if (match(line, /version[[:space:]]+"[^"]*"/)) {
            s=substr(line, RSTART, RLENGTH)
            gsub(/version[[:space:]]+"/,"",s)
            gsub(/"$/,"",s)
            print s
            exit
          }
          if (match(line, /version[[:space:]]+[^;{]+/)) {
            s=substr(line, RSTART, RLENGTH)
            gsub(/version[[:space:]]+/,"",s)
            gsub(/[[:space:]]*$/,"",s)
            print s
            exit
          }
        }' "$f" 2>/dev/null
    }
    
    bind_version_is_safe() {
      # 0 = safe(정보노출 방지용 값으로 추정)
      # 1 = unsafe(버전/제품명 노출로 추정)
      local v="${1:-}"
      v="$(trim "$v")"
      [[ -n "$v" ]] || return 1
    
      if echo "$v" | grep -Eq '[0-9]+\.[0-9]+'; then
        return 1
      fi
      if echo "$v" | grep -Eqi '(bind|named)'; then
        return 1
      fi
      if echo "$v" | grep -Eqi '(unknown|none|not[[:space:]]*disclosed|not[[:space:]]*available|unavailable|private|hidden|refused|disabled|censored|정보|비공개|숨김)'; then
        return 0
      fi
      return 1
    }
    
    # ---------- 점검 시작 ----------
    out "U-62 (상) 로그인 시 경고 메시지 설정 점검"
    out "기준: 서버 및 사용하는 Telnet/FTP/SMTP/DNS 서비스에 로그온 경고 메시지가 설정되어 있으면 양호"
    out ""
    
    # OS 정보(참고용)
    if [[ -r /etc/os-release ]]; then
      os_name="$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
    else
      os_name="unknown"
    fi
    out "[환경] $os_name"
    out ""
    
    VULN=0
    NA_COUNT=0
    
    # 1) 서버(로컬) 배너: /etc/issue, /etc/motd(/etc/motd.d)
    out "[서버] /etc/issue, /etc/motd 점검"
    
    issue_rc=1
    motd_rc=1
    
    if check_banner_file "/etc/issue"; then
      issue_rc=0
    else
      issue_rc=$?
    fi
    
    # motd는 /etc/motd 또는 /etc/motd.d/* 중 하나라도 경고키워드 있으면 OK
    if check_banner_file "/etc/motd"; then
      motd_rc=0
    else
      if [[ -d /etc/motd.d ]]; then
        found_ok=0
        shopt -s nullglob
        for f in /etc/motd.d/*; do
          if [[ -f "$f" ]]; then
            if check_banner_file "$f"; then
              found_ok=1
              break
            fi
          fi
        done
        shopt -u nullglob
        if [[ $found_ok -eq 1 ]]; then
          motd_rc=0
        else
          motd_rc=2
        fi
      else
        motd_rc=2
      fi
    fi
    
    if [[ $issue_rc -eq 0 && $motd_rc -eq 0 ]]; then
      out "  - OK: /etc/issue, /etc/motd(또는 motd.d)에 경고 메시지로 추정되는 문구 존재"
    else
      VULN=1
      out "  - FAIL: 서버 로그인 경고 메시지 설정이 미흡한 것으로 추정"
      if [[ $issue_rc -ne 0 ]]; then
        out "    * /etc/issue: 경고 문구 확인 실패(비어있음/없음/OS정보노출로 추정)"
      fi
      if [[ $motd_rc -ne 0 ]]; then
        out "    * /etc/motd(/etc/motd.d): 경고 문구 확인 실패(비어있음/없음/OS정보노출로 추정)"
      fi
    fi
    out ""
    
    # 2) SSH 배너
    out "[SSH] sshd 배너(Banner) 설정 점검"
    if is_active sshd || is_active ssh; then
      banner_path="$(get_sshd_banner_path)"
      banner_path="$(trim "$banner_path")"
      if [[ -z "$banner_path" || "$banner_path" == "none" ]]; then
        VULN=1
        out "  - FAIL: sshd Banner 미설정(sshd -T 기준 banner=none)"
      else
        if [[ "$banner_path" != /* ]]; then
          banner_path="/$banner_path"
        fi
        if check_banner_file "$banner_path"; then
          out "  - OK: sshd Banner 설정됨 -> $banner_path"
        else
          VULN=1
          out "  - FAIL: sshd Banner 파일은 지정되어 있으나 경고 문구 확인 실패 -> $banner_path"
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: sshd 서비스 비활성"
    fi
    out ""
    
    # 3) Telnet
    out "[Telnet] 서비스 사용 시 /etc/issue.net 경고 메시지 점검"
    telnet_used=0
    if is_active telnet.socket || is_active telnet.service || is_active telnetd.service || is_active xinetd.service; then
      telnet_used=1
    fi
    if [[ -r /etc/xinetd.d/telnet ]] && grep -Eiq 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/telnet 2>/dev/null; then
      telnet_used=1
    fi
    
    if [[ $telnet_used -eq 1 ]]; then
      if check_banner_file "/etc/issue.net"; then
        out "  - OK: /etc/issue.net 경고 문구 존재"
      else
        VULN=1
        out "  - FAIL: Telnet 사용으로 추정되나 /etc/issue.net 경고 문구 확인 실패"
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: Telnet 미사용(비활성/미설치로 추정)"
    fi
    out ""
    
    # 4) FTP: vsftpd
    out "[FTP:vsftpd] 서비스 사용 시 ftpd_banner 점검"
    if is_active vsftpd; then
      vs_conf=""
      [[ -r /etc/vsftpd/vsftpd.conf ]] && vs_conf="/etc/vsftpd/vsftpd.conf"
      [[ -r /etc/vsftpd.conf ]] && vs_conf="/etc/vsftpd.conf"
    
      if [[ -z "$vs_conf" ]]; then
        VULN=1
        out "  - FAIL: vsftpd active이나 설정파일을 찾지 못함(/etc/vsftpd.conf 계열)"
      else
        v="$(get_conf_value_kv "ftpd_banner" "$vs_conf" | tr -d '"')"
        v="$(trim "$v")"
        if [[ -z "$v" ]]; then
          VULN=1
          out "  - FAIL: ftpd_banner 미설정 ($vs_conf)"
        else
          if echo "$v" | grep -Eqi "$warn_keywords_regex"; then
            out "  - OK: ftpd_banner에 경고 문구 포함 ($vs_conf)"
          else
            VULN=1
            out "  - FAIL: ftpd_banner는 있으나 경고 문구로 보기 어려움 ($vs_conf)"
          fi
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: vsftpd 비활성"
    fi
    out ""
    
    # 5) FTP: ProFTPD
    out "[FTP:ProFTPD] 서비스 사용 시 DisplayLogin/welcome.msg 점검"
    if is_active proftpd; then
      pf_conf=""
      [[ -r /etc/proftpd/proftpd.conf ]] && pf_conf="/etc/proftpd/proftpd.conf"
      [[ -r /etc/proftpd.conf ]] && pf_conf="/etc/proftpd.conf"
    
      if [[ -z "$pf_conf" ]]; then
        VULN=1
        out "  - FAIL: proftpd active이나 설정파일을 찾지 못함(/etc/proftpd*.conf)"
      else
        dl="$(awk 'BEGIN{IGNORECASE=1} $0 ~ /^[[:space:]]*#/ {next} tolower($1)=="displaylogin"{print $2; exit}' "$pf_conf" 2>/dev/null | tr -d '"')"
        dl="$(trim "$dl")"
        if [[ -z "$dl" ]]; then
          VULN=1
          out "  - FAIL: DisplayLogin 미설정 ($pf_conf)"
        else
          if [[ "$dl" != /* ]]; then
            if [[ -r "/etc/proftpd/$dl" ]]; then
              dl="/etc/proftpd/$dl"
            fi
          fi
          if check_banner_file "$dl"; then
            out "  - OK: DisplayLogin 파일에 경고 문구 존재 -> $dl"
          else
            VULN=1
            out "  - FAIL: DisplayLogin 파일은 지정되어 있으나 경고 문구 확인 실패 -> $dl"
          fi
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: ProFTPD 비활성"
    fi
    out ""
    
    # 6) SMTP: Postfix
    out "[SMTP:Postfix] 서비스 사용 시 smtpd_banner 점검"
    if is_active postfix; then
      b="$(get_postfix_smtpd_banner)"
      b="$(trim "$b")"
      if [[ -z "$b" ]]; then
        VULN=1
        out "  - FAIL: smtpd_banner 미설정(postconf 기준)"
      else
        if echo "$b" | grep -Eqi "$warn_keywords_regex"; then
          out "  - OK: smtpd_banner에 경고 문구 포함"
        else
          VULN=1
          out "  - FAIL: smtpd_banner는 있으나 경고 문구로 보기 어려움(기본 배너/정보노출 가능)"
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: Postfix 비활성"
    fi
    out ""
    
    # 7) SMTP: Sendmail
    out "[SMTP:Sendmail] 서비스 사용 시 SmtpGreetingMessage 점검"
    if is_active sendmail; then
      sm_cf="/etc/mail/sendmail.cf"
      if [[ -r "$sm_cf" ]]; then
        msg="$(awk '
          $0 ~ /^[[:space:]]*#/ {next}
          $0 ~ /^[Oo][[:space:]]+SmtpGreetingMessage[[:space:]]*=/{
            sub(/^[Oo][[:space:]]+SmtpGreetingMessage[[:space:]]*=/,"")
            print; exit
          }' "$sm_cf" 2>/dev/null)"
        msg="$(trim "$msg")"
        if [[ -z "$msg" ]]; then
          VULN=1
          out "  - FAIL: SmtpGreetingMessage 미설정($sm_cf)"
        else
          if echo "$msg" | grep -Eqi "$warn_keywords_regex"; then
            out "  - OK: SmtpGreetingMessage에 경고 문구 포함"
          else
            VULN=1
            out "  - FAIL: SmtpGreetingMessage는 있으나 경고 문구로 보기 어려움"
          fi
        fi
      else
        VULN=1
        out "  - FAIL: sendmail active이나 $sm_cf 를 읽을 수 없음"
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: Sendmail 비활성"
    fi
    out ""
    
    # 8) SMTP: Exim
    out "[SMTP:Exim] 서비스 사용 시 smtp_banner 점검"
    if is_active exim || is_active exim4; then
      ex_conf=""
      [[ -r /etc/exim/exim.conf ]] && ex_conf="/etc/exim/exim.conf"
      [[ -r /etc/exim4/exim4.conf ]] && ex_conf="/etc/exim4/exim4.conf"
      [[ -r /etc/exim.conf ]] && ex_conf="/etc/exim.conf"
    
      if [[ -z "$ex_conf" ]]; then
        VULN=1
        out "  - FAIL: exim active이나 설정파일을 찾지 못함(/etc/exim*/exim*.conf)"
      else
        exb="$(awk -F= '
          BEGIN{IGNORECASE=1}
          $0 ~ /^[[:space:]]*#/ {next}
          tolower($1) ~ "^[[:space:]]*smtp_banner[[:space:]]*$"{
            val=$2; sub(/^[[:space:]]*/,"",val); sub(/[[:space:]]*$/,"",val);
            print val; exit
          }' "$ex_conf" 2>/dev/null | tr -d '"')"
        exb="$(trim "$exb")"
        if [[ -z "$exb" ]]; then
          VULN=1
          out "  - FAIL: smtp_banner 미설정($ex_conf)"
        else
          if echo "$exb" | grep -Eqi "$warn_keywords_regex"; then
            out "  - OK: smtp_banner에 경고 문구 포함"
          else
            VULN=1
            out "  - FAIL: smtp_banner는 있으나 경고 문구로 보기 어려움"
          fi
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: Exim 비활성"
    fi
    out ""
    
    # 9) DNS: BIND(named)
    out "[DNS:BIND(named)] 서비스 사용 시 version 설정 점검"
    if is_active named; then
      named_conf=""
      [[ -r /etc/named.conf ]] && named_conf="/etc/named.conf"
      [[ -r /etc/bind/named.conf.options ]] && named_conf="/etc/bind/named.conf.options"
    
      if [[ -z "$named_conf" ]]; then
        VULN=1
        out "  - FAIL: named active이나 설정파일을 찾지 못함(/etc/named.conf 또는 /etc/bind/named.conf.options)"
      else
        vv="$(get_bind_version_value "$named_conf" | tr -d '"')"
        vv="$(trim "$vv")"
        if [[ -z "$vv" ]]; then
          VULN=1
          out "  - FAIL: version 지시자 미설정($named_conf)"
        else
          if bind_version_is_safe "$vv"; then
            out "  - OK: version 값이 정보노출 방지용으로 추정됨($named_conf)"
          else
            VULN=1
            out "  - FAIL: version 값이 제품/버전 노출로 추정됨 -> $vv ($named_conf)"
          fi
        fi
      fi
    else
      NA_COUNT=$((NA_COUNT+1))
      out "  - N/A: named 비활성"
    fi
    out ""
    
    out "----------------------------------------"
    if [[ $VULN -eq 0 ]]; then
      out "최종 결과: 양호"
    else
      out "최종 결과: 취약"
    fi
    out "N/A(미사용/비활성) 항목 수: $NA_COUNT"
    out "----------------------------------------"
    
    exit 0
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-62(상) | 3. 서비스 관리 > 로그인 시 경고 메시지 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그인 배너(/etc/issue, sshd Banner 등)에 경고 문구가 설정된 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-62 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-62 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-62 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

# ---- 통합 추가(U-67) ----
U_67() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""
    #!/usr/bin/env bash
    # U-67 (중) 로그 관리 - 로그 디렉터리 내 로그 파일 소유자/권한 점검
    # 기준:
    # - 양호: /var/log 이하 파일 소유자 root, 권한 644 이하
    # - 취약: 소유자 root 아님 또는 권한 644 초과
    
    set -u
    set -o pipefail
    
    TITLE="U-67 로그 디렉터리 소유자 및 권한 설정"
    LOG_DIR="/var/log"
    MAX_MODE="644"
    
    print_line() { printf '%s\n' "------------------------------------------------------------"; }
    
    need_root() {
      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "결과: N/A"
        echo "사유: root 권한 필요(sudo로 실행)"
        exit 0
      fi
    }
    
    is_octal_digits() {
      [[ "${1:-}" =~ ^[0-7]+$ ]]
    }
    
    need_root
    print_line
    echo "점검 항목: $TITLE"
    echo "점검 기준: $LOG_DIR 이하 파일 소유자=root, 권한=${MAX_MODE} 이하"
    print_line
    
    if [[ ! -d "$LOG_DIR" ]]; then
      echo "결과: N/A"
      echo "사유: $LOG_DIR 디렉터리가 존재하지 않습니다."
      exit 0
    fi
    
    total=0
    vuln=0
    
    declare -a bad_list=()
    declare -a err_list=()
    
    while IFS= read -r -d '' f; do
      total=$((total + 1))
    
      owner="$(stat -c '%U' "$f" 2>/dev/null || echo "__STAT_FAIL__")"
      mode="$(stat -c '%a' "$f" 2>/dev/null || echo "__STAT_FAIL__")"
    
      if [[ "$owner" == "__STAT_FAIL__" || "$mode" == "__STAT_FAIL__" ]]; then
        err_list+=("$f")
        continue
      fi
    
      bad_reason=()
    
      if [[ "$owner" != "root" ]]; then
        bad_reason+=("소유자=$owner")
      fi
    
      if is_octal_digits "$mode"; then
        if (( 8#$mode > 8#$MAX_MODE )); then
          bad_reason+=("권한=$mode")
        fi
      else
        bad_reason+=("권한파싱실패=$mode")
      fi
    
      if (( ${#bad_reason[@]} > 0 )); then
        vuln=$((vuln + 1))
        bad_list+=("파일=$f | ${bad_reason[*]}")
      fi
    done < <(find "$LOG_DIR" -xdev -type f -print0 2>/dev/null)
    
    if (( total == 0 )); then
      echo "결과: N/A"
      echo "사유: $LOG_DIR 이하에 점검 대상 파일이 없습니다."
      exit 0
    fi
    
    if (( vuln == 0 )) && (( ${#err_list[@]} == 0 )); then
      echo "결과: 양호"
    else
      echo "결과: 취약"
    fi
    
    print_line
    echo "점검 요약:"
    echo " - 점검 파일 수: $total"
    echo " - 기준 위반 파일 수: $vuln"
    echo " - stat 조회 실패 파일 수: ${#err_list[@]}"
    print_line
    
    if (( vuln > 0 )); then
      echo "기준 위반(취약) 파일 목록:"
      for item in "${bad_list[@]}"; do
        echo " - $item"
      done
      print_line
      echo "조치 가이드(예시):"
      echo " - 소유자 변경: chown root <파일>"
      echo " - 권한 변경:   chmod 644 <파일>"
    fi
    
    if (( ${#err_list[@]} > 0 )); then
      print_line
      echo "참고: 아래 파일은 stat 조회 실패로 점검에서 제외되었습니다(수동 확인 필요)."
      for f in "${err_list[@]}"; do
        echo " - $f"
      done
    fi
    
    print_line
    exit 0
  ) >"$_tmp" 2>&1
  _rc=$?

  echo "" >> "$resultfile" 2>&1
  echo "▶ U-67(중) | 4. 로그 관리 > 로그 디렉터리 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /var/log 및 관련 로그 파일 소유자가 root이고 권한이 644 이하인 경우" >> "$resultfile" 2>&1
# 결과 판정(출력 문구 우선 파싱, 실패 시 종료코드 fallback)
  local _status=""
  local _line=""
  _line="$(grep -E '(최종 결과|최종판정|결과|▶ 결과)[[:space:]]*[:：]' "$_tmp" 2>/dev/null | tail -n 1 || true)"
  if echo "$_line" | grep -qE '취약'; then
    _status="VULN"
  elif echo "$_line" | grep -qE '양호'; then
    _status="GOOD"
  elif echo "$_line" | grep -qE 'N/A|판단불가|NA'; then
    _status="NA"
  else
    if [[ "$_rc" -eq 0 ]]; then
      _status="GOOD"
    elif [[ "$_rc" -eq 1 ]]; then
      _status="VULN"
    else
      _status="NA"
    fi
  fi
  
if [[ "$_status" == "GOOD" ]]; then
    echo "※ U-67 결과 : 양호(Good)" >> "$resultfile" 2>&1
  elif [[ "$_status" == "VULN" ]]; then
    echo "※ U-67 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  else
    echo "※ U-67 결과 : N/A" >> "$resultfile" 2>&1
  fi
  
# 상세 출력 생략(요약만 출력)
  rm -f "$_tmp"
    return 0
}

U_01
U_02
U_03
U_04
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
U_16
U_17
U_18
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_42
U_43
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
U_55
U_56
U_57
U_58
U_59
U_60
U_61
U_62
U_63
U_64
U_65
U_66
U_67
