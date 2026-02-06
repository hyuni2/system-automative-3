#!/bin/bash

resultfile="Results_$(date '+%F_%H:%M:%S').txt"

U_01() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우" >> $resultfile 2>&1

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
        echo "※ U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-01 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

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

U_10() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $resultfile 2>&1
    if [ -f /etc/passwd ]; then
        if [ `awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l` -gt 0 ]; then
            echo "※ U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> $resultfile 2>&1
        fi
    fi
    echo "※ U-10 결과 : 양호(Good)" >> $resultfile 2>&1
}

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

U_01
U_03
U_05
U_06
U-08
U_10
U_11
U_13
U_15
U_16
U_18
U_20
U_23
U_28