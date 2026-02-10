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

    if [ $VULN -eq 0 ]; then
        if ps -ef | grep -i 'telnet' | grep -v 'grep' &>/dev/null || \
           netstat -nat 2>/dev/null | grep -w 'tcp' | grep -i 'LISTEN' | grep ':23 ' &>/dev/null; then  
            if [ -f /etc/pam.d/login ]; then
                if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty.so'; then
                    VULN=1
                    REASON="Telnet 서비스 사용 중이며, /etc/pam.d/login에 pam_securetty.so 설정이 없습니다."
                fi
            fi
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

    if [ $VULN -eq 0 ] && (systemctl is-active sshd &>/dev/null || ps -ef | grep -v grep | grep -q sshd); then
        ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')

        if [[ "$ROOT_LOGIN" != "no" ]]; then
            VULN=1
            REASON="SSH root 접속이 허용 중입니다 (PermitRootLogin: $ROOT_LOGIN)."
        fi
    fi

    if [ $VULN -eq 1 ]; then
        echo "※ U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-01 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

#태훈 (수정: 원본 통합용 포맷으로 재작성)
U_02() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-02(상) | 1. 계정관리 > 1. 계정관리 > 비밀번호 관리정책 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : PASS_MAX_DAYS 90일 이하, PASS_MIN_DAYS 1일 이상, 비밀번호 최소 길이 8자 이상, 복잡성(minclass 3 이상 또는 u/l/d/o credit 설정), 재사용 제한(remember 4 이상) 적용" >> "$resultfile" 2>&1

    local TARGET_PASS_MAX_DAYS=90
    local TARGET_PASS_MIN_DAYS=1
    local TARGET_MINLEN=8
    local TARGET_CREDIT=-1
    local TARGET_REMEMBER=4

    local vuln=0
    local reasons=()

    # 1) /etc/login.defs: PASS_MAX_DAYS / PASS_MIN_DAYS
    local pass_max pass_min
    pass_max="$(awk 'BEGIN{v=""} $1=="PASS_MAX_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
    pass_min="$(awk 'BEGIN{v=""} $1=="PASS_MIN_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"

    if [[ -z "$pass_max" || ! "$pass_max" =~ ^[0-9]+$ ]]; then
        vuln=1; reasons+=("/etc/login.defs 에 PASS_MAX_DAYS 설정을 확인할 수 없습니다.")
    elif (( pass_max > TARGET_PASS_MAX_DAYS )); then
        vuln=1; reasons+=("PASS_MAX_DAYS($pass_max) > 기준($TARGET_PASS_MAX_DAYS)")
    fi

    if [[ -z "$pass_min" || ! "$pass_min" =~ ^[0-9]+$ ]]; then
        vuln=1; reasons+=("/etc/login.defs 에 PASS_MIN_DAYS 설정을 확인할 수 없습니다.")
    elif (( pass_min < TARGET_PASS_MIN_DAYS )); then
        vuln=1; reasons+=("PASS_MIN_DAYS($pass_min) < 기준($TARGET_PASS_MIN_DAYS)")
    fi

    # 2) 복잡성(최소 길이/문자군) : pwquality.conf 또는 PAM pam_pwquality 인자
    local pwq_files=()
    [[ -r /etc/security/pwquality.conf ]] && pwq_files+=("/etc/security/pwquality.conf")
    [[ -d /etc/security/pwquality.conf.d ]] && pwq_files+=(/etc/security/pwquality.conf.d/*.conf)

    local minlen="" minclass="" ucredit="" lcredit="" dcredit="" ocredit=""
    for f in "${pwq_files[@]}"; do
        [[ -r "$f" ]] || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue
            line="${line%%#*}"
            if [[ "$line" =~ ^[[:space:]]*minlen[[:space:]]*=[[:space:]]*([0-9]+) ]]; then minlen="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ ^[[:space:]]*minclass[[:space:]]*=[[:space:]]*([0-9]+) ]]; then minclass="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ ^[[:space:]]*ucredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then ucredit="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ ^[[:space:]]*lcredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then lcredit="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ ^[[:space:]]*dcredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then dcredit="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ ^[[:space:]]*ocredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then ocredit="${BASH_REMATCH[1]}"; fi
        done < "$f"
    done

    # PAM에서 직접 설정된 경우도 확인 (RHEL 계열: system-auth/password-auth)
    local pam_pwq_args=""
    for pf in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -r "$pf" ]] || continue
        pam_pwq_args="$(grep -E '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pf" 2>/dev/null | tail -n 1)"
        [[ -n "$pam_pwq_args" ]] && break
    done
    if [[ -n "$pam_pwq_args" ]]; then
        [[ "$pam_pwq_args" =~ minlen=([0-9]+) ]] && minlen="${BASH_REMATCH[1]}"
        [[ "$pam_pwq_args" =~ minclass=([0-9]+) ]] && minclass="${BASH_REMATCH[1]}"
        [[ "$pam_pwq_args" =~ ucredit=([+-]?[0-9]+) ]] && ucredit="${BASH_REMATCH[1]}"
        [[ "$pam_pwq_args" =~ lcredit=([+-]?[0-9]+) ]] && lcredit="${BASH_REMATCH[1]}"
        [[ "$pam_pwq_args" =~ dcredit=([+-]?[0-9]+) ]] && dcredit="${BASH_REMATCH[1]}"
        [[ "$pam_pwq_args" =~ ocredit=([+-]?[0-9]+) ]] && ocredit="${BASH_REMATCH[1]}"
    fi

    if [[ -z "$minlen" || ! "$minlen" =~ ^[0-9]+$ ]]; then
        vuln=1; reasons+=("비밀번호 최소 길이(minlen) 설정을 확인할 수 없습니다.")
    elif (( minlen < TARGET_MINLEN )); then
        vuln=1; reasons+=("minlen($minlen) < 기준($TARGET_MINLEN)")
    fi

    local complexity_ok=0
    if [[ -n "$minclass" && "$minclass" =~ ^[0-9]+$ && "$minclass" -ge 3 ]]; then
        complexity_ok=1
    fi
    if [[ "$ucredit" =~ ^-?[0-9]+$ && "$lcredit" =~ ^-?[0-9]+$ && "$dcredit" =~ ^-?[0-9]+$ && "$ocredit" =~ ^-?[0-9]+$ ]]; then
        if (( ucredit <= TARGET_CREDIT && lcredit <= TARGET_CREDIT && dcredit <= TARGET_CREDIT && ocredit <= TARGET_CREDIT )); then
            complexity_ok=1
        fi
    fi
    if (( complexity_ok == 0 )); then
        vuln=1; reasons+=("복잡성(minclass 또는 *credit) 기준 충족 여부를 확인하지 못했습니다.")
    fi

    # 3) 재사용 제한(remember) : pam_pwhistory / pam_unix / pwhistory.conf
    local remember=""
    local pwh_line=""
    for pf in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -r "$pf" ]] || continue
        pwh_line="$(grep -E '^[[:space:]]*password[[:space:]].*(pam_pwhistory\.so|pam_unix\.so)' "$pf" 2>/dev/null | grep -E 'remember=' | tail -n 1)"
        [[ -n "$pwh_line" ]] && break
    done
    if [[ -n "$pwh_line" && "$pwh_line" =~ remember=([0-9]+) ]]; then
        remember="${BASH_REMATCH[1]}"
    fi
    if [[ -z "$remember" && -r /etc/security/pwhistory.conf ]]; then
        remember="$(awk 'BEGIN{v=""} $1=="remember"{gsub(" ","",$3); v=$3} END{print v}' /etc/security/pwhistory.conf 2>/dev/null)"
    fi

    if [[ -z "$remember" || ! "$remember" =~ ^[0-9]+$ ]]; then
        vuln=1; reasons+=("비밀번호 재사용 제한(remember) 설정을 확인할 수 없습니다.")
    elif (( remember < TARGET_REMEMBER )); then
        vuln=1; reasons+=("remember($remember) < 기준($TARGET_REMEMBER)")
    fi

    # 결과 출력
    if (( vuln == 0 )); then
        echo "※ U-02 결과 : 양호" >> "$resultfile" 2>&1
    else
        echo "※ U-02 결과 : 취약" >> "$resultfile" 2>&1
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
	echo ""  >> $resultfile 2>&1
	echo "▶ U-04(상) | 1. 계정관리 > 1.4 패스워드 파일 보호 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : shadow 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우"  >> $resultfile 2>&1

    VULN_COUNT=$(awk -F : '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd | wc -l)
    if [ $VULN_COUNT -gt 0 ]; then
        VULN_USERS=$(awk -F : '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd | cut -d: -f1)
        echo "※ U-04 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " /etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재: $VULN_USERS" >> "$resultfile" 2>&1
    else
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
            echo "※ U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
            echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $resultfile 2>&1
        else
            echo "※ U-05 결과 : 양호(Good)" >> $resultfile 2>&1
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

    if [ -f "$PAM_SU" ]; then
        SU_RESTRICT=$(grep -vE "^#|^\s*#" $PAM_SU | grep "pam_wheel.so" | grep "use_uid")

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

    USER_COUNT=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd | wc -l)

    if [ $VULN -eq 1 ] && [ "$USER_COUNT" -eq 0 ]; then
        VULN=0
        REASON="일반 사용자 계정 없이 root 계정만 사용하여 su 명령어 사용 제한이 불필요합니다."
    fi

    if [ $VULN -eq 1 ]; then
        echo "※ U-06 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-06 결과 : 양호(Good)" >> $resultfile 2>&1
    fi 
}

#태훈
U_07() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-07(하) | 1. 계정관리 > 7. 불필요한 계정 제거 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 불필요 계정이 삭제/잠금 또는 로그인 불가 쉘(/sbin/nologin,/bin/false 등)로 설정되어 있는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local uid_min
    uid_min="$(awk 'BEGIN{v=1000} $1=="UID_MIN"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

    # 시스템 계정(UID<UID_MIN) 중 로그인 가능 쉘을 가진 계정이 있으면 취약
    local suspicious=()
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [[ "$user" == "root" ]] && continue
        if (( uid < uid_min )); then
            case "$shell" in
                */nologin|*/false) ;;  # 로그인 차단
                *) suspicious+=("$user:$uid:$shell") ;;
            esac
        fi
    done < /etc/passwd

    if (( ${#suspicious[@]} > 0 )); then
        vuln=1
    fi

    if (( vuln == 0 )); then
        echo "※ U-07 결과 : 양호" >> "$resultfile" 2>&1
    else
        echo "※ U-07 결과 : 취약" >> "$resultfile" 2>&1
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

	USED_GIDS=$(awk -F: '{print $4}' /etc/passwd | sort -u)

    CHECK_GIDS=$(awk -F: '$3 >= 500 {print $3}' /etc/group)
	VULN_GROUPS=""
    for gid in $CHECK_GIDS; do
        if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
            GROUP_NAME=$(grep -w ":$gid:" /etc/group | cut -d: -f1)
            VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
        fi
    done

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
        if [ `awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l` -gt 0 ]; then
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

    EXCEPT_USERS="^(sync|shutdown|halt)$"

    while IFS=: read -r user pass uid gid comment home shell; do 
        if { [ "$uid" -ge 1 ] && [ "$uid" -lt 1000 ]; } || [ "$user" == "nobody" ]; then
            if [[ "$user" =~ $EXCEPT_USERS ]]; then
                continue
            fi
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

    if [ -n "$VUL_ACCOUNTS" ]; then
        VULN=1
        REASON="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: $VUL_ACCOUNTS"
    fi

    if [ $VULN -eq 1 ]; then
        echo "※ U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-11 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

#태훈
U_12() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-12(하) | 1. 계정관리 > 12. 세션 종료 시간 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 유휴 세션 종료(TMOUT 등) 값이 설정되어 있고(권고: 600초 이하) 시스템 전반에 적용되는 경우" >> "$resultfile" 2>&1

    local TARGET_TMOUT=600
    local vuln=0
    local found=()

    # 점검 대상 파일(전역)
    local files=("/etc/profile" "/etc/bashrc" "/etc/profile.d" "/etc/csh.cshrc" "/etc/csh.login")
    local f line
    for f in "${files[@]}"; do
        if [[ -d "$f" ]]; then
            while IFS= read -r -d '' x; do
                files+=("$x")
            done < <(find "$f" -maxdepth 1 -type f -name "*.sh" -print0 2>/dev/null)
        fi
    done

    # TMOUT 값 추출: 가장 마지막으로 설정된 값을 기준으로 기록(파일별)
    for f in "${files[@]}"; do
        [[ -r "$f" && -f "$f" ]] || continue
        # 주석 제거 후 TMOUT=숫자 형태만 추출
        local tm
        tm="$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null | sed 's/#.*$//' | tail -n 1 | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
        if [[ "$tm" =~ ^[0-9]+$ ]]; then
            found+=("$f:$tm")
        fi
    done

    if (( ${#found[@]} == 0 )); then
        vuln=1
        echo " [확인] TMOUT 설정을 전역 설정 파일에서 찾지 못했습니다." >> "$resultfile" 2>&1
        echo " 조치 예: /etc/profile 등에 'readonly TMOUT=600; export TMOUT' 추가" >> "$resultfile" 2>&1
    else
        echo " [확인] TMOUT 설정 발견:" >> "$resultfile" 2>&1
        local ok=0
        for e in "${found[@]}"; do
            echo "  - $e" >> "$resultfile" 2>&1
            local val="${e##*:}"
            if [[ "$val" =~ ^[0-9]+$ ]] && (( val <= TARGET_TMOUT )); then
                ok=1
            fi
        done
        if (( ok == 0 )); then
            vuln=1
            echo " [판단] 설정값은 있으나 $TARGET_TMOUT 초 이하 조건을 충족하지 못했습니다." >> "$resultfile" 2>&1
        fi
    fi

    if (( vuln == 0 )); then
        echo "※ U-12 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-12 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}


#연수
U_13() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-13(중) | 1. 계정관리 > 안전한 비밀번호 암호화 알고리즘 사용 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SHA-2 기반 알고리즘($5:SHA-256, $6:SHA-512)을 사용하는 경우" >> "$resultfile" 2>&1

  local shadow="/etc/shadow"

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

  local vuln_found=0
  local checked=0
  local evidence=""

  while IFS=: read -r user hash rest; do
    [ -z "$user" ] && continue

    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    if [[ "$hash" != \$* ]]; then
      ((checked++))
      vuln_found=1
      evidence+="$user:UNKNOWN_FORMAT; "
      continue
    fi

    local id
    id="$(echo "$hash" | awk -F'$' '{print $2}')"
    [ -z "$id" ] && id="UNKNOWN"

    ((checked++))

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

    if echo "$PATH" | grep -qE '^\.:|:.:|^:|::'; then
        VULN_FOUND=1
        DETAILS="[Runtime] 현재 PATH 환경변수 내 우선순위 높은 '.' 또는 '::' 발견: $PATH"
    fi

    if [ $VULN_FOUND -eq 0 ]; then
        path_settings_files=("/etc/profile" "/etc/.login" "/etc/csh.cshrc" "/etc/csh.login" "/etc/environment" "/etc/bashrc" "/etc/bash.bashrc")

        for file in "${path_settings_files[@]}"; do
            if [ -f "$file" ]; then
                VULN_LINE=$(grep -vE '^#|^\s#' "$file" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$')
                if [ ! -z "$VULN_LINE" ]; then #취약한 path 설정 발견시
                    VULN_FOUND=1
                    DETAILS="[System File] $file: $VULN_LINE" #어떤 파일, 어떤 라인인지 기록
                    break
                fi
            fi
        done
    fi

    if [ $VULN_FOUND -eq 0 ]; then
        user_dot_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
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

    if [ -f "$FILE" ]; then
        OWNER=$(stat -c "%U" "$FILE")
        PERMIT=$(stat -c "%a" "$FILE")

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

    if [ $VULN -eq 1 ]; then
        echo "※ U-16 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " $REASON" >> $resultfile 2>&1
    else
        echo "※ U-16 결과 : 양호(Good)" >> $resultfile 2>&1
    fi

}

#태훈
U_17() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-17(중) | 2. 파일 및 디렉터리 관리 > 17. 시스템 시작 스크립트 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 시스템 시작 스크립트(초기화 스크립트/서비스 유닛)의 소유자 및 권한이 적절하고, 일반 사용자가 변경할 수 없는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local offenders=()

    check_path_perm() {
        local path="$1"
        [[ -e "$path" ]] || return 0

        local owner perm
        owner="$(stat -Lc '%U' "$path" 2>/dev/null)"
        perm="$(stat -Lc '%a' "$path" 2>/dev/null)"

        # 소유자 root 권고, 그리고 group/other write(022) 금지
        if [[ "$owner" != "root" ]]; then
            offenders+=("$path (owner=$owner, perm=$perm)")
            return 0
        fi
        # 권한 비트 계산: 022가 포함되면 취약
        local mode
        mode="$(stat -Lc '%a' "$path" 2>/dev/null)"
        [[ "$mode" =~ ^[0-9]+$ ]] || return 0

        # bash에서 8진수로 처리
        local oct="0$mode"
        if (( (oct & 18) != 0 )); then
            offenders+=("$path (group/other writable, perm=$perm)")
        fi
    }

    # 대표 시작 스크립트/디렉터리
    local candidates=(
        "/etc/rc.d/rc.local" "/etc/rc.local"
        "/etc/init.d" "/etc/rc.d/init.d"
        "/etc/systemd/system" "/usr/lib/systemd/system"
    )

    local p
    for p in "${candidates[@]}"; do
        [[ -e "$p" ]] || continue
        if [[ -d "$p" ]]; then
            while IFS= read -r -d '' f; do
                check_path_perm "$f"
            done < <(find "$p" -maxdepth 2 -type f -print0 2>/dev/null)
        else
            check_path_perm "$p"
        fi
    done

    if (( ${#offenders[@]} > 0 )); then
        vuln=1
        echo " [취약 후보] 시작 스크립트/유닛 파일 소유자/권한 이상:" >> "$resultfile" 2>&1
        for o in "${offenders[@]}"; do
            echo "  - $o" >> "$resultfile" 2>&1
        done
    else
        echo " [확인] 시작 스크립트/유닛 파일에서 root 소유 및 쓰기권한(그룹/기타) 이상 없음(최대 깊이 2)" >> "$resultfile" 2>&1
    fi

    if (( vuln == 0 )); then
        echo "※ U-17 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-17 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_18() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-18(상) | UNIX > 2. 파일 및 디렉토리 관리| /etc/shadow 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /etc/shadow 파일의 소유자가 root이고, 권한이 400인 경우"  >> "$resultfile" 2>&1

  local target="/etc/shadow"

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

  local owner perm
  owner="$(stat -c '%U' "$target" 2>/dev/null)"
  perm="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " stat 명령으로 $target 정보를 읽지 못했습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$owner" != "root" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 소유자가 root가 아닙니다. (owner=$owner)" >> "$resultfile" 2>&1
    return 0
  fi

  if [[ "$perm" =~ ^[0-7]{4}$ ]]; then
    perm="${perm:1:3}"
  elif [[ "$perm" =~ ^[0-7]{1,3}$ ]]; then
    perm="$(printf "%03d" "$perm")"
  fi

  if ! [[ "$perm" =~ ^[0-7]{3}$ ]]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target 파일 권한 형식이 예상과 다릅니다. (perm=$perm)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$perm" != "400" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일 권한이 400이 아닙니다. (perm=$perm)" >> "$resultfile" 2>&1
    return 0
  fi

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

    if [ -f "/etc/hosts" ]; then
        FILE_OWNER_UID=$(stat -c "%u" /etc/hosts)
        FILE_OWNER_NAME=$(stat -c "%U" /etc/hosts)

        FILE_PERM=$(stat -c "%a" /etc/hosts)

        USER_PERM=${FILE_PERM:0:1}
        GROUP_PERM=${FILE_PERM:1:1}
        OTHER_PERM=${FILE_PERM:2:1}

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
    echo "" >> $resultfile 2>&1
    echo "▶ U-20(상) | 2. 파일 및 디렉토리 관리 > 2.7 systemd *.socket, *.service 파일 소유자 및 권한 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : systemd *.socket, *.service 파일의 소유자가 root이고, 권한이 644 이하인 경우"  >> $resultfile 2>&1
    file_exists_count=0
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
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else 
    echo "※ U-21 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  local OWNER PERMIT
  OWNER="$(sudo stat -c '%U' "$target" 2>/dev/null)"
  PERMIT="$(sudo stat -c'%a' "$target" 2>/dev/null)"
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

  if [ "$PERMIT" -gt 640 ]; then
    echo "※ U-21 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 권한이 640보다 큽니다. (permit=$PERMIT)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-21 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " $target 파일의 소유자($OWNER) 및 권한($PERMIT)이 기준에 적합합니다." >> "$resultfile" 2>&1

}

#태훈
U_22() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-22(상) | 2. 파일 및 디렉터리 관리 > 22. /etc/services 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : /etc/services 파일 소유자가 root이고, 일반 사용자가 수정할 수 없도록 권한이 설정된 경우" >> "$resultfile" 2>&1

    local vuln=0
    local f="/etc/services"

    if [[ ! -e "$f" ]]; then
        vuln=1
        echo " [확인] $f 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
    else
        local owner group perm
        owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
        group="$(stat -Lc '%G' "$f" 2>/dev/null)"
        perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
        echo " [현황] $f owner=$owner group=$group perm=$perm" >> "$resultfile" 2>&1

        if [[ "$owner" != "root" ]]; then
            vuln=1; echo " - 소유자가 root가 아닙니다." >> "$resultfile" 2>&1
        fi

        local oct="0$perm"
        if (( (oct & 18) != 0 )); then
            vuln=1; echo " - 그룹/기타 쓰기 권한이 존재합니다(022)." >> "$resultfile" 2>&1
        fi
    fi

    if (( vuln == 0 )); then
        echo "※ U-22 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-22 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_23() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-23(상) | UNIX > 2. 파일 및 디렉토리 관리| SUID, SGID, Sticky bit 설정 파일 점검 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"  >> "$resultfile" 2>&1

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

  local whitelist=(
    "/sbin/unix_chkpwd"
    "/usr/bin/newgrp"
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
  )

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

      special="0"
      if [ "${#oct_perm}" -eq 4 ]; then
        special="${oct_perm:0:1}"
      fi

      if [[ "$special" =~ [2467] ]] && [[ "$mode" =~ [sS] ]]; then
        if _is_whitelisted "$f"; then
          warn_found=1
        else
          vuln_found=1
        fi
      fi
    fi
  done

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

    CHECK_FILES=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout" ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts")

    USER_LIST=$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd)

    for USER_INFO in $USER_LIST; do
        USER_NAME=$(echo "$USER_INFO" | cut -d: -f1)
        USER_HOME=$(echo "$USER_INFO" | cut -d: -f2)

        if [ -d "$USER_HOME" ]; then
            for FILE in "${CHECK_FILES[@]}"; do
                TARGET="$USER_HOME/$FILE"

                if [ -f "$TARGET" ]; then

                    FILE_OWNER=$(ls -l "$TARGET" | awk '{print $3}')

                    if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
                        VULN=1
                        REASON="$REASON 파일 소유자 불일치: $TARGET (소유자: $FILE_OWNER) |"
                    fi

                    PERM=$(ls -l "$TARGET")

                    GROUP_WRITE=${PERM:5:1}
                    OTHER_WRITE=${PERM:8:1}

                    if [ "$GROUP_WRITE" == "w" ] || [ "$OTHER_WRITE" == "w" ]; then
                        VULN=1
                        REASON="$REASON 권한 취약: $TARGET (권한: $PERM - 쓰기 권한 존재) |"
                    fi
                fi
            done
        fi
    done

    if [ $VULN -eq 1 ]; then
        echo "※ U-24 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $REASON" >> "$resultfile" 2>&1
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

  if [ ! -d "$target_dir" ]; then
    echo  
    echo "※ U-26 결과 : N/A" >> "$resultfile" 2>&1
    echo " $target_dir 디렉터리가 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  VUL_FILES=$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null)

  if [ -n "$VUL_FILES" ]; then
    VULN=1
    REASON="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되었습니다. $(echo $VUL_FILES | tr '\n' ' ')"
  fi

  if [ "$VULN" -eq 1 ]; then
        echo "※ U-26 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [Reason] $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-26 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_27() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-27(상) | 2. 파일 및 디렉터리 관리 > $HOME/.rhosts, hosts.equiv 사용 금지 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : .rhosts 및 /etc/hosts.equiv 파일이 존재하지 않거나 사용되지 않는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local found=()

    # /etc/hosts.equiv
    if [[ -e /etc/hosts.equiv ]]; then
        found+=("/etc/hosts.equiv")
        vuln=1
    fi

    # .rhosts (대표 경로만 탐색)
    local rh
    for rh in /root/.rhosts /home/*/.rhosts; do
        [[ -e "$rh" ]] || continue
        found+=("$rh")
        vuln=1
    done

    if (( ${#found[@]} > 0 )); then
        echo " [발견] 다음 파일이 존재합니다:" >> "$resultfile" 2>&1
        for f in "${found[@]}"; do
            echo "  - $f" >> "$resultfile" 2>&1
            # 내용이 있는 경우 추가 표시
            if [[ -r "$f" ]]; then
                local non_comment
                non_comment="$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | head -n 1)"
                [[ -n "$non_comment" ]] && echo "    (주의) 비주석 설정 존재" >> "$resultfile" 2>&1
            fi
        done
        echo " 조치 예: 파일 삭제 또는 r-commands 서비스 비활성화" >> "$resultfile" 2>&1
    else
        echo " [확인] /etc/hosts.equiv 및 대표 경로의 .rhosts 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
    fi

    if (( vuln == 0 )); then
        echo "※ U-27 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-27 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_28() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-28(상) | 2. 파일 및 디렉토리 관리 > 접속 IP 및 포트 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우" >> "$resultfile" 2>&1

  local deny="/etc/hosts.deny"
  local allow="/etc/hosts.allow"

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

  if [ ! -f "$deny" ]; then
    echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $deny 파일이 없습니다. (기본 차단 정책 없음)" >> "$resultfile" 2>&1
    return 0
  fi

  _normalized_lines() {
    local f="$1"
    sed -e 's/[[:space:]]//g' -e '/^#/d' -e '/^$/d' "$f" 2>/dev/null
  }

  local deny_allall_count
  deny_allall_count="$(_normalized_lines "$deny" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"

  local allow_allall_count=0
  if [ -f "$allow" ]; then
    allow_allall_count="$(_normalized_lines "$allow" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"
  fi

  if [ "$allow_allall_count" -gt 0 ]; then
    echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $allow 파일에 'ALL:ALL' 설정이 있습니다. (전체 허용)" >> "$resultfile" 2>&1
    return 0
  fi

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

    TARGET="/etc/hosts.lpd"

    if [ -f "$TARGET" ]; then
        OWNER=$(stat -c "%U" "$TARGET")
        PERMIT=$(stat -c "%a" "$TARGET")

        if [ "$OWNER" != "root" ]; then
            VULN=1
            REASON="$REASON 파일의 소유자가 root가 아닙니다(현재: $OWNER). |"
        fi

        if [ "$PERMIT" -gt 600 ]; then
            VULN=1
            REASON="$REASON 파일 권한이 600보다 큽니다(현재: $PERMIT). |"
        fi
    else
        :
    fi

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

    if [ ${umaks_value:2:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    elif [ ${umaks_value:3:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    fi

    if [ ${umaks_value:2:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    elif [ ${umaks_value:3:1} -lt 2 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
    fi
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

    user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq`)
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
                user_homedirectory_setting_umask_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l`
                if [ $user_homedirectory_setting_umask_count -gt 0 ]; then
                    umaks_value=(`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
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

  USER_LIST=$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd)

  for USER in $USER_LIST; do
    USERNAME=$(echo "$USER" | cut -d: -f1)
    HOMEDIR=$(echo "$USER" | cut -d: -f2)

    if [ -d "$HOMEDIR" ]; then
      OWNER=$(stat -c '%U' "$HOMEDIR")
      PERMIT=$(stat -c '%a' "$HOMEDIR")
      OTHERS_PERMIT=$(echo "$PERMIT" | sed 's/.*\(.\)$/\1/')

      if [ "$OWNER" != "$USERNAME" ]; then
        VULN=1
        REASON="$REASON 소유자가 불일치 합니다. $USERNAME 계정의 홈($HOMEDIR), 현재 소유자 : $OWNER 입니다. |"
      fi

      if [[ "$OTHERS_PERMIT" =~ [2367] ]]; then
        VULN=1
        REASON="$REASON 타 사용자 쓰기권한이 $USERNAME 계정의 홈 $HOMEDIR 에 존재합니다. (현재 권한: $PERMIT) |"
      fi
    else
      VULN=1
      REASON="$REASON $USERNAME 계정의 홈 디렉토리가 존재하지 않습니다. "
    fi
  done

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-31 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo "$REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-31 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_32() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-32(하) | 2. 파일 및 디렉터리 관리 > 32. 홈 디렉터리로 지정한 디렉터리의 존재 관리 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 로그인 가능한 계정의 홈 디렉터리가 존재하며, 부적절한 홈 디렉터리 지정이 없는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local missing=()

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue

        # 로그인 차단 쉘은 제외
        case "$shell" in
            */nologin|*/false) continue ;;
        esac

        # 홈 디렉터리 공란/없음 점검
        if [[ -z "$home" || "$home" == "/" ]]; then
            missing+=("$user (home=$home)")
            continue
        fi
        if [[ ! -d "$home" ]]; then
            missing+=("$user (home=$home)")
        fi
    done < /etc/passwd

    if (( ${#missing[@]} > 0 )); then
        vuln=1
        echo " [취약 후보] 홈 디렉터리가 없거나 부적절한 계정:" >> "$resultfile" 2>&1
        for m in "${missing[@]}"; do
            echo "  - $m" >> "$resultfile" 2>&1
        done
    else
        echo " [확인] 로그인 가능한 계정의 홈 디렉터리가 모두 존재합니다." >> "$resultfile" 2>&1
    fi

    if (( vuln == 0 )); then
        echo "※ U-32 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-32 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_33() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-33(하) | UNIX > 2. 파일 및 디렉토리 관리 > 숨겨진 파일 및 디렉토리 검색 및 제거 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 삭제한 경우" >> "$resultfile" 2>&1

  ALL_HIDDEN=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" \( -type f -o -type d \) -print 2>/dev/null)

  SUS_HIDDEN_FILES=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" -type f \
    \( -executable -o -perm -4000 -o -perm -2000 -o -mtime -7 \) \
    -print 2>/dev/null)

  if [ -n "$SUS_HIDDEN_FILES" ]; then
    SUS_COUNT=$(echo "$SUS_HIDDEN_FILES" | wc -l)
  else
    SUS_COUNT=0
  fi

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

    SERVICES=("finger" "fingerd" "in.fingerd" "finger.socket")
    for SVC in "${SERVICES[@]}"; do
        if systemctl is-active "$SVC" >/dev/null 2>&1; then
            VULN=1
            REASON="$REASON Finger 서비스가 활성화되어 있습니다. |"
        fi
    done

    if ps -ef | grep -v grep | grep -Ei "fingerd|in.fingerd" >/dev/null; then
        VULN=1
        REASON="$REASON Finger 프로세스가 실행 중입니다. |"
    fi

    if command -v ss >/dev/null 2>&1; then
        PORT_CHECK=$(ss -nlp | grep -w ":79")
    else
        PORT_CHECK=$(netstat -natp 2>/dev/null | grep -w ":79")
    fi  

    if [ -n "$PORT_CHECK" ]; then
        VULN=1
        REASON="$REASON Finger 포트가 리스닝 중입니다. |"
    fi

    if [ $VULN -eq 1 ]; then
        echo "※ U-34 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-34 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
} 

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
    VSFTPD_FILES=( $(dedup "${VSFTPD_FILES[@]}") )
    PROFTPD_FILES=( $(dedup "${PROFTPD_FILES[@]}") )
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

  CHECK_PORT=$(ss -antl | grep -E ':512|:513|:514')

  if [ -n "$CHECK_PORT" ]; then
    VULN=1
    REASON="$REASON r-command 관련 포트(512, 513, 514)가 활성화되어 있습니다. |"
  fi

  SERVICES=("rlogin" "rsh" "rexec" "shell" "login" "exec")

  for SVC in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
      VULN=1
      REASON="$REASON 활성화된 r 계열 서비스를 발견하였습니다. $SVC 서비스가 구동 중입니다. |"
    fi
  done

  if [ -d "/etc/xinetd.d" ]; then
    XINTETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec 2>/dev/null)
    if [ -n "$XINTETD_VUL" ]; then
      VULN=1
      REASON=" $REASON xinetd 설정이 취약합니다. 다음 파일에서 서비스가 활성화 되었습니다. $(echo $XINETD_VUL | tr '\n' ' ') |"
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-36 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-36 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_37() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-37(상) | 2. 파일 및 디렉터리 관리 > 37. crontab 설정 파일 권한 설정 미흡 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : cron 관련 설정 파일/디렉터리의 소유자 및 권한이 적절하며, 일반 사용자가 임의 변경할 수 없는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local offenders=()

    add_offender() { offenders+=("$1"); }

    check_file_no_wo() {
        local f="$1"
        [[ -e "$f" ]] || return 0
        local owner perm
        owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
        perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
        local oct="0$perm"
        if [[ "$owner" != "root" ]]; then
            add_offender "$f (owner=$owner, perm=$perm)"
            return 0
        fi
        if (( (oct & 18) != 0 )); then
            add_offender "$f (group/other writable, perm=$perm)"
        fi
    }

    check_dir_no_wo() {
        local d="$1"
        [[ -d "$d" ]] || return 0
        local owner perm
        owner="$(stat -Lc '%U' "$d" 2>/dev/null)"
        perm="$(stat -Lc '%a' "$d" 2>/dev/null)"
        local oct="0$perm"
        if [[ "$owner" != "root" ]]; then
            add_offender "$d (owner=$owner, perm=$perm)"
            return 0
        fi
        if (( (oct & 2) != 0 )); then
            add_offender "$d (other writable, perm=$perm)"
        fi
    }

    # 시스템 cron 설정
    check_file_no_wo "/etc/crontab"
    check_file_no_wo "/etc/anacrontab"
    check_dir_no_wo "/etc/cron.d"
    check_dir_no_wo "/etc/cron.hourly"
    check_dir_no_wo "/etc/cron.daily"
    check_dir_no_wo "/etc/cron.weekly"
    check_dir_no_wo "/etc/cron.monthly"

    # /etc/cron.d 및 cron.* 내부 파일 권한
    local dir
    for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            check_file_no_wo "$f"
        done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
    done

    # 사용자 crontab (RHEL 계열: /var/spool/cron)
    if [[ -d /var/spool/cron ]]; then
        while IFS= read -r -d '' f; do
            local owner perm
            owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
            perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
            local oct="0$perm"
            # 사용자 파일은 owner가 해당 사용자일 가능성이 있어 root 강제하지 않음
            if (( (oct & 63) != 0 )); then
                add_offender "$f (owner=$owner, perm=$perm) : 600 권고"
            fi
        done < <(find /var/spool/cron -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    if (( ${#offenders[@]} > 0 )); then
        vuln=1
        echo " [취약 후보] cron 설정 소유자/권한 이상:" >> "$resultfile" 2>&1
        for o in "${offenders[@]}"; do
            echo "  - $o" >> "$resultfile" 2>&1
        done
    else
        echo " [확인] cron 관련 주요 파일/디렉터리에서 쓰기권한(그룹/기타) 이상 없음" >> "$resultfile" 2>&1
    fi

    if (( vuln == 0 )); then
        echo "※ U-37 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-37 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
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

  local inetd_services=("echo" "discard" "daytime" "chargen")

  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")

  local snmp_units=("snmpd.service")
  local dns_units=("named.service" "bind9.service")

  local CHECK_NTP=0
  local ntp_units=("chronyd.service" "ntpd.service" "systemd-timesyncd.service")

  if [ -d /etc/xinetd.d ]; then
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
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

  if command -v systemctl >/dev/null 2>&1; then
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

  if [ "$in_scope_active" -eq 0 ]; then
    echo "※ U-38 결과 : N/A" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스(대상)가 사용되지 않는 것으로 확인되어 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-38 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스가 활성화되어 있습니다. (활성 서비스 존재)" >> "$resultfile" 2>&1
  else
    echo "※ U-38 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 서비스가 비활성화되어 있습니다. (활성 서비스 미확인)" >> "$resultfile" 2>&1
  fi

  return 0
}

#수진
U_40() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-40(상) | 3. 서비스 관리 > 3.7 NFS 접근 통제 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우" >> $resultfile 2>&1
    if [ `ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd|' | wc -l` -gt 0 ]; then
        if [ -f /etc/exports ]; then
            etc_exports_all_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep '*' | wc -l`
            etc_exports_insecure_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -i 'insecure' | wc -l`
            etc_exports_directory_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | wc -l`
            etc_exports_squash_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -iE 'root_squash|all_squash' | wc -l`
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

  if systemctl is-active --quiet autofs 2>/dev/null; then
    VULN=1
    REASON="$REASON automountd 서비스가 활성화되어 있습니다. |"
  fi

  if ps -ef | grep -v grep | grep -Ei "automount|autofs"; then
    if [ "$VULN" -eq 0 ]; then 
      VULN=1
      REASON="$REASON automountd 서비스가 활성화되어 실행중입니다. |"
    fi
  fi 

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-41 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-41 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_42() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-42(상) | 3. 서비스 관리 > 42. 불필요한 RPC 서비스 비활성화 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : RPC 서비스(rpcbind 등)가 불필요하게 활성화되어 있지 않은 경우" >> "$resultfile" 2>&1

    local vuln=0

    local rpc_active=0
    if systemctl is-active rpcbind.service &>/dev/null || systemctl is-active rpcbind.socket &>/dev/null; then
        rpc_active=1
    fi

    if (( rpc_active == 0 )); then
        echo " [확인] rpcbind 서비스가 비활성(미실행) 상태입니다." >> "$resultfile" 2>&1
        echo "※ U-42 결과 : 양호(Good)" >> "$resultfile" 2>&1
        return 0
    fi

    echo " [현황] rpcbind 서비스가 실행 중입니다." >> "$resultfile" 2>&1
    systemctl --no-pager -l status rpcbind.service 2>/dev/null | head -n 10 >> "$resultfile" 2>&1

    # 의존 서비스(NFS 등) 동작 여부로 "불필요" 판단 보조
    local nfs_active=0
    if systemctl is-active nfs-server.service &>/dev/null; then
        nfs_active=1
    fi

    if command -v rpcinfo &>/dev/null; then
        echo " [rpcinfo -p] 등록된 RPC 프로그램:" >> "$resultfile" 2>&1
        rpcinfo -p 2>/dev/null | head -n 50 >> "$resultfile" 2>&1
    else
        echo " [참고] rpcinfo 명령이 없어 등록 RPC 목록 출력은 생략합니다." >> "$resultfile" 2>&1
    fi

    if (( nfs_active == 1 )); then
        echo " [판단 보조] nfs-server가 활성화되어 있어 rpcbind가 필요할 수 있습니다(업무 사용 여부 수동 확인 권고)." >> "$resultfile" 2>&1
        echo "※ U-42 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        vuln=1
        echo " [판단] nfs-server 등 대표 의존 서비스가 비활성인데 rpcbind가 실행 중입니다." >> "$resultfile" 2>&1
        echo " 조치 예: systemctl disable --now rpcbind.socket rpcbind.service" >> "$resultfile" 2>&1
        echo "※ U-42 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
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

  local nis_procs_regex='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated'
  local nisplus_procs_regex='nisplus|rpc\.nisd|nisd'

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

    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "rpcbind.service"; then
      if systemctl is-active --quiet "rpcbind.service" 2>/dev/null || systemctl is-enabled --quiet "rpcbind.service" 2>/dev/null; then
        evidences+=("info: rpcbind.service 가 active/enabled 입니다. (NIS/RPC 계열 사용 가능성, 단 NIS 단독 증거는 아님)")
      fi
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nis_procs_regex" | grep -vE 'grep|U_43\(|U_28\(' >/dev/null 2>&1; then
    nis_in_use=1
    vulnerable=1
    evidences+=("process: NIS 관련 프로세스(yp*)가 실행 중입니다.")
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(ss). (RPC 사용 흔적)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(netstat). (RPC 사용 흔적)")
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nisplus_procs_regex" | grep -v grep >/dev/null 2>&1; then
    evidences+=("info: NIS+ 관련 프로세스 흔적이 감지되었습니다. (환경에 따라 양호 조건 충족 가능)")
  fi

  if [ "$nis_in_use" -eq 0 ]; then
    echo "※ U-43 결과 : N/A" >> "$resultfile" 2>&1
    echo " NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (yp* 서비스/프로세스 미검출)" >> "$resultfile" 2>&1
    if [ "${#evidences[@]}" -gt 0 ]; then
      echo " --- 근거(Evidence) ---" >> "$resultfile" 2>&1
      for e in "${evidences[@]}"; do
        echo " - $e" >> "$resultfile" 2>&1
      done
    fi
    return 0
  fi

  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-43 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " NIS 서비스가 활성화(실행/enable)된 흔적이 확인되었습니다." >> "$resultfile" 2>&1
  else
    echo "※ U-43 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " NIS 사용 흔적은 있으나 활성화(실행/enable) 상태는 확인되지 않았습니다." >> "$resultfile" 2>&1
  fi

  echo " --- 근거(Evidence) ---" >> "$resultfile" 2>&1
  for e in "${evidences[@]}"; do
    echo " - $e" >> "$resultfile" 2>&1
  done

  return 0
}

#수진
U_45() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-45(상) | 3. 서비스 관리 > 3.12 메일 서비스 버전 점검 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 메일 서비스 버전이 최신버전인 경우" >> $resultfile 2>&1
    if [ -f /etc/services ]; then
        smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
        if [ $smtp_port_count -gt 0 ]; then
            smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
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
    ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
    if [ $ps_smtp_count -gt 0 ]; then
        rpm_smtp_version=`rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}'`
        dnf_smtp_version=`dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}'`
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

  if ps -ef | grep -v grep | grep -q "sendmail"; then

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

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-46 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-46 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_47() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-47(상) | 3. 서비스 관리 > 47. 스팸메일 릴레이 제한 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 메일 서버가 오픈 릴레이(open relay)로 동작하지 않도록 릴레이 제한 설정이 적용된 경우" >> "$resultfile" 2>&1

    local vuln=0

    # 1) Postfix 우선 점검
    if systemctl is-active postfix.service &>/dev/null || command -v postconf &>/dev/null; then
        if command -v postconf &>/dev/null; then
            local relay_restr recip_restr mynet
            relay_restr="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"
            recip_restr="$(postconf -h smtpd_recipient_restrictions 2>/dev/null)"
            mynet="$(postconf -h mynetworks 2>/dev/null)"

            echo " [Postfix] smtpd_relay_restrictions: ${relay_restr:-N/A}" >> "$resultfile" 2>&1
            echo " [Postfix] smtpd_recipient_restrictions: ${recip_restr:-N/A}" >> "$resultfile" 2>&1
            echo " [Postfix] mynetworks: ${mynet:-N/A}" >> "$resultfile" 2>&1

            local has_reject=0
            echo "$relay_restr $recip_restr" | grep -q "reject_unauth_destination" && has_reject=1

            local net_ok=1
            echo "$mynet" | grep -Eq '0\.0\.0\.0/0|::/0' && net_ok=0

            if (( has_reject == 1 && net_ok == 1 )); then
                echo "※ U-47 결과 : 양호(Good)" >> "$resultfile" 2>&1
                return 0
            fi

            vuln=1
            echo " [판단] reject_unauth_destination 설정 누락 또는 mynetworks 과다 설정 가능성" >> "$resultfile" 2>&1
            echo " 조치 예: smtpd_relay_restrictions 또는 smtpd_recipient_restrictions에 reject_unauth_destination 포함" >> "$resultfile" 2>&1
            echo "※ U-47 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            return 0
        fi
    fi

    # 2) Sendmail(활성 시) - 자동 판정이 어려워 수동 점검 안내
    if systemctl is-active sendmail.service &>/dev/null || command -v sendmail &>/dev/null; then
        echo " [Sendmail] 실행 가능성이 있습니다. 설정 파일(/etc/mail/sendmail.cf 또는 sendmail.mc)에서 릴레이 제한을 수동 확인하세요." >> "$resultfile" 2>&1
        echo "※ U-47 결과 : 수동점검(Manual)" >> "$resultfile" 2>&1
        return 0
    fi

    # 3) 메일 서비스 미사용
    echo " [확인] Postfix/Sendmail 사용(실행) 흔적이 없거나 점검 도구가 없습니다." >> "$resultfile" 2>&1
    echo "※ U-47 결과 : 양호(Good)" >> "$resultfile" 2>&1
}

#연수
U_48() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-48(중) | UNIX > 3. 서비스 관리 > expn, vrfy 명령어 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 메일 서비스를 사용하지 않는 경우 N/A, (2) 사용 시 noexpn, novrfy 옵션(또는 goaway)이 설정된 경우" >> "$resultfile" 2>&1

  local mail_in_use=0
  local vulnerable=0
  local evidences=()

  local has_sendmail=0
  local has_postfix=0
  local has_exim=0

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

  if [ "$mail_in_use" -eq 0 ]; then
    echo "※ U-48 결과 : N/A" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (25/tcp LISTEN 및 MTA 미검출)" >> "$resultfile" 2>&1
    return 0
  fi

  local ok_cnt=0
  local bad_cnt=0

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

  if [ "$has_exim" -eq 1 ]; then
    evidences+=("exim: exim 사용 흔적 감지(구성 파일 기반 vrfy/expn 제한 수동 확인 필요)")
  fi

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

  if ps -ef | grep -v grep | grep -q "named"; then
    CONF="/etc/named.conf"
    CONF_FILES=("$CONF")

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

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-51 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-51 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_52() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-52(중) | 3. 서비스 관리 > Telnet 서비스 비활성화 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 원격 접속 시 Telnet 서비스(23/tcp)가 비활성화되어 있는 경우" >> "$resultfile" 2>&1

    local vuln=0
    local details=()

    # 1) 가장 결정적: 23/tcp 리슨 여부 확인
    local listen23=""
    listen23="$(ss -lntp 2>/dev/null | awk '$4 ~ /:23$/ {print}' | head -n 1)"
    if [[ -n "$listen23" ]]; then
        vuln=1
        details+=("23/tcp LISTEN 감지: ${listen23}")
    fi

    # 2) systemd 기반 흔적(보조 근거)
    local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
    local u
    for u in "${units[@]}"; do
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
            local is_act="inactive" is_en="disabled"
            systemctl is-active "$u" &>/dev/null && is_act="active"
            systemctl is-enabled "$u" &>/dev/null && is_en="enabled"

            if [[ "$is_act" == "active" || "$is_en" == "enabled" ]]; then
                details+=("$u 상태: $is_act / $is_en")
                vuln=1
            fi
        fi
    done

    # 3) xinetd 기반(보조 근거)
    if [[ -r /etc/xinetd.d/telnet ]]; then
        local disabled=""
        disabled="$(awk 'tolower($1)=="disable"{print tolower($3)}' /etc/xinetd.d/telnet 2>/dev/null | tail -n 1)"
        if [[ "$disabled" == "yes" ]]; then
            details+=("/etc/xinetd.d/telnet 존재: disable=yes(비활성)")
        else
            details+=("/etc/xinetd.d/telnet 존재: disable=${disabled:-unknown}(활성 가능)")
            vuln=1
        fi
    fi

    # 4) inetd 기반(보조 근거)
    if [[ -r /etc/inetd.conf ]]; then
        if grep -Eq '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
            details+=("/etc/inetd.conf: telnet 설정 존재")
            vuln=1
        fi
    fi

    if (( vuln == 0 )); then
        echo " [확인] 23/tcp Telnet 리스너가 없으며 활성화 흔적이 없습니다." >> "$resultfile" 2>&1
        echo "※ U-52 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo " [확인] Telnet 사용/활성화 가능 징후:" >> "$resultfile" 2>&1
        for d in "${details[@]}"; do
            echo "  - $d" >> "$resultfile" 2>&1
        done
        echo " 조치 예: sudo systemctl disable --now telnet.socket (또는 해당 서비스) / xinetd 설정 비활성화" >> "$resultfile" 2>&1
        echo "※ U-52 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_53() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-53(하) | UNIX > 3. 서비스 관리 > FTP 서비스 정보 노출 제한 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : FTP 접속 배너에 노출되는 정보가 없는 경우" >> "$resultfile" 2>&1

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

  local daemon=""
  if echo "$listen_info" | grep -qi "vsftpd"; then
    daemon="vsftpd"
  elif echo "$listen_info" | grep -Eqi "proftpd|proftp"; then
    daemon="proftpd"
  else
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vsftpd 2>/dev/null; then
      daemon="vsftpd"
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet proftpd 2>/dev/null; then
      daemon="proftpd"
    fi
  fi

  local config_leak=0

  if [ "$daemon" = "vsftpd" ]; then
    local f=""
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
      if [ -f "$f" ]; then
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
          echo "$pline" | grep -Eqi '(ServerIdent[[:space:]]+on|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' && config_leak=1
        fi
      fi
    done
  fi

  local banner=""
  if command -v timeout >/dev/null 2>&1; then
    if command -v nc >/dev/null 2>&1; then
      banner=$((echo -e "QUIT\r\n"; sleep 0.2) | timeout 3 nc -n 127.0.0.1 21 2>/dev/null | head -n 1 | tr -d '\r')
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

  if [ "$config_leak" -eq 1 ] || [ "$banner_leak" -eq 1 ]; then
    echo "※ U-53 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 가능성이 있습니다." >> "$resultfile" 2>&1
  else
    echo "※ U-53 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " FTP 접속 배너에 노출되는 정보가 없습니다." >> "$resultfile" 2>&1
  fi

  return 0
}

#수진
U_55() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-55(중) | 3. 서비스 관리 > 3.22 FTP 계정 Shell 제한 ◀" >> $resultfile 2>&1
    echo " 양호 판단 기준 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우" >> $resultfile 2>&1
    if ! rpm -qa | egrep -qi 'vsftpd|proftpd'; then
        echo "※ U-55 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " FTP 서비스가 미설치되어 있습니다." >> $resultfile 2>&1
        return 0
    fi
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

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-56 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-56 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_57() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-57(상) | 3. 서비스 관리 > 57. ftpusers 파일 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : FTP 사용 시 ftpusers(또는 동등 기능)로 접속 금지 사용자(특히 root)가 적절히 설정된 경우" >> "$resultfile" 2>&1

    local vuln=0

    # FTP 서비스가 실제로 동작 중인지 확인(vsftpd/proftpd/pure-ftpd 등)
    local ftp_running=0
    for svc in vsftpd.service proftpd.service pure-ftpd.service; do
        if systemctl is-active "$svc" &>/dev/null; then
            ftp_running=1
            echo " [현황] FTP 데몬 실행: $svc" >> "$resultfile" 2>&1
        fi
    done

    # 데몬 미사용이면 위험 노출이 없다고 보고 양호 처리
    if (( ftp_running == 0 )); then
        echo " [확인] FTP 데몬 실행 흔적이 없습니다." >> "$resultfile" 2>&1
        echo "※ U-57 결과 : 양호(Good)" >> "$resultfile" 2>&1
        return 0
    fi

    # ftpusers 후보 파일
    local candidates=("/etc/vsftpd/ftpusers" "/etc/ftpusers" "/etc/vsftpd/user_list")
    local file_found=""
    local f
    for f in "${candidates[@]}"; do
        if [[ -r "$f" ]]; then
            file_found="$f"
            break
        fi
    done

    if [[ -z "$file_found" ]]; then
        vuln=1
        echo " [확인] ftpusers/user_list 후보 파일을 찾지 못했습니다." >> "$resultfile" 2>&1
        echo "※ U-57 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        return 0
    fi

    echo " [확인] 점검 파일: $file_found" >> "$resultfile" 2>&1
    local has_root=0
    grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$file_found" && has_root=1

    local owner perm
    owner="$(stat -Lc '%U' "$file_found" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$file_found" 2>/dev/null)"
    echo " [현황] owner=$owner perm=$perm, root 포함 여부=$has_root" >> "$resultfile" 2>&1

    if [[ "$owner" != "root" ]]; then
        vuln=1; echo " - 소유자가 root가 아닙니다." >> "$resultfile" 2>&1
    fi

    local oct="0$perm"
    if (( (oct & 18) != 0 )); then
        vuln=1; echo " - 그룹/기타 쓰기 권한이 존재합니다(022)." >> "$resultfile" 2>&1
    fi

    if (( has_root == 0 )); then
        vuln=1; echo " - root 계정이 차단 목록에 포함되어 있지 않습니다." >> "$resultfile" 2>&1
    fi

    if (( vuln == 0 )); then
        echo "※ U-57 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-57 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_58() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-58(중) | UNIX > 3. 서비스 관리 > 불필요한 SNMP 서비스 구동 점검 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SNMP 서비스를 사용하지 않는 경우" >> "$resultfile" 2>&1

  local found=0
  local reason=""

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      found=1
      reason="snmpd 서비스가 활성(Active) 상태입니다."
    elif systemctl is-active --quiet snmptrapd 2>/dev/null; then
      found=1
      reason="snmptrapd 서비스가 활성(Active) 상태입니다."
    fi
  fi

  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1; then
      found=1
      reason="snmpd 프로세스가 실행 중입니다."
    elif pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
      reason="snmptrapd 프로세스가 실행 중입니다."
    fi
  fi

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

#수진
U_60() {
    echo ""  >> $resultfile 2>&1
    echo " ▶ U-60(중) | 3. 서비스 관리 > 3.27 SNMP Community String 복잡성 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우" >> $resultfile 2>&1
    vuln_flag=0
    community_found=0
    ps_snmp_count=`ps -ef | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l`
    if [ $ps_snmp_count -eq 0 ]; then
        echo "※ U-60 결과 : 양호(Good)" >> $resultfile 2>&1
        echo " SNMP 서비스가 미설치되어있습니다." >> $resultfile 2>&1
        return 0
    fi
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
    is_strong_community() {
        local s="$1"
        s="${s%\"}"; s="${s#\"}"
        s="${s%\'}"; s="${s#\'}"
        echo "$s" | grep -qiE '^(public|private)$' && return 1
        local len=${#s}
        local has_alpha=0
        local has_digit=0
        local has_special=0
        echo "$s" | grep -qE '[A-Za-z]' && has_alpha=1
        echo "$s" | grep -qE '[0-9]' && has_digit=1
        echo "$s" | grep -qE '[^A-Za-z0-9]' && has_special=1
        if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $len -ge 10 ]; then
            return 0
        fi
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

  if ps -ef | grep -v grep | grep -q "snmpd" ; then 

    CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      CHECK_COM2SEC=$(grep -vE "^\s*#" "$CONF" | grep -E "^\s*com2sec" | awk '$3=="default" {print $0}')
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

  if [ "$VULN" -eq 1 ]; then
    echo "※ U-61 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $REASON" >> "$resultfile" 2>&1
  else
    echo "※ U-61 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi
}

#태훈
U_62() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-62(중) | 3. 서비스 관리 > 62. 로그인 시 경고 메시지 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 로그인 배너(/etc/issue, /etc/issue.net, SSH Banner 등)에 비인가 사용 금지 경고 메시지가 설정된 경우" >> "$resultfile" 2>&1

    local ok=0
    local issue_files=("/etc/issue" "/etc/issue.net")
    local f content

    # 1) 콘솔 로그인 배너(/etc/issue, /etc/issue.net) 점검 (상위 일부 라인에서 키워드 확인)
    for f in "${issue_files[@]}"; do
        [[ -r "$f" ]] || continue
        content="$(grep -vE '^[[:space:]]*$' "$f" 2>/dev/null | head -n 20)"
        if [[ -n "$content" ]]; then
            if echo "$content" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
                ok=1
                break
            fi
        fi
    done

    # 2) SSH Banner 점검 (sshd_config의 Banner 파일 내용에서 키워드 확인)
    if (( ok == 0 )) && [[ -r /etc/ssh/sshd_config ]]; then
        local banner bcontent
        banner="$(grep -E '^[[:space:]]*Banner[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n 1)"
        if [[ -n "$banner" && "$banner" != "none" && -r "$banner" ]]; then
            bcontent="$(grep -vE '^[[:space:]]*$' "$banner" 2>/dev/null | head -n 20)"
            if [[ -n "$bcontent" ]] && echo "$bcontent" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
                ok=1
            fi
        fi
    fi

    if (( ok == 1 )); then
        echo "※ U-62 결과 : 양호(Good)" >> "$resultfile" 2>&1
    else
        echo "※ U-62 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    fi
}

#연수
U_63() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-63(중) | UNIX > 3. 서비스 관리 > sudo 명령어 접근 관리 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우" >> "$resultfile" 2>&1

  if [ ! -e /etc/sudoers ]; then
    echo "※ U-63 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  local owner perm
  owner=$(stat -c %U /etc/sudoers 2>/dev/null)
  perm=$(stat -c %a /etc/sudoers 2>/dev/null)

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    owner=$(ls -l /etc/sudoers 2>/dev/null | awk '{print $3}')
    perm=$(ls -l /etc/sudoers 2>/dev/null | awk '{print $1}')
    echo "※ U-63 결과 : 점검불가" >> "$resultfile" 2>&1
    echo " /etc/sudoers 권한 정보를 숫자(예: 640)로 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

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

#수진
U_65() {
    echo ""  >> $resultfile 2>&1
    echo "▶ U-65(중) | 5. 로그 관리 > 5.1 NTP 및 시각 동기화 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우" >> $resultfile 2>&1
    vuln_flag=0
    is_active_service() {
        local svc="$1"
        systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service" || return 1
        systemctl is-active --quiet "${svc}.service" 2>/dev/null
    }
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
    server_found=0
    sync_ok=0
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
        if command -v chronyc >/dev/null 2>&1; then
            if chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+'; then
                sync_ok=1
            fi
        fi
    fi
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

  if ps -ef | grep -v grep | grep -q "rsyslogd"; then

      if [ -f "$CONF" ]; then
          ALL_CONF_CONTENT=$(cat "${CONF_FILES[@]}" 2>/dev/null | grep -vE "^\s*#")

          CHECK_MSG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.info[[:space:]]+-?\/var\/log\/messages")
          CHECK_SECURE=$(echo "$ALL_CONF_CONTENT" | grep -E "auth(priv)?\.\*[[:space:]]+-?\/var\/log\/secure")
          CHECK_MAIL=$(echo "$ALL_CONF_CONTENT" | grep -E "mail\.\*[[:space:]]+-?\/var\/log\/maillog")
          CHECK_CRON=$(echo "$ALL_CONF_CONTENT" | grep -E "cron\.\*[[:space:]]+-?\/var\/log\/cron")
          CHECK_ALERT=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.alert[[:space:]]+(\/dev\/console|:omusrmsg:\*|root)")
          CHECK_EMERG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.emerg[[:space:]]+(\*|:omusrmsg:\*)")

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

  if [ "$VULN" -eq 1 ]; then
      echo "※ U-66 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
      echo " $REASON" >> "$resultfile" 2>&1
  else
      echo "※ U-66 결과 : 양호(Good)" >> "$resultfile" 2>&1
  fi 
}

#태훈
U_67() {
  local _tmp _rc
  _tmp="$(mktemp)"
  (
    echo ""

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
U_40
U_41
U_42
U_43
U_45
U_46
U_47
U_48
U_50
U_51
U_52
U_53
U_55
U_56
U_57
U_58
U_60
U_61
U_62
U_63
U_65
U_66
U_67
