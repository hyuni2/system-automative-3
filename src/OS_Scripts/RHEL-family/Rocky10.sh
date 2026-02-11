#!/bin/bash
resultfile="results.txt"

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

#태훈 (수정: 원본 통합용 포맷으로 재작성)
U_02() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-02(상) | 1. 계정관리 > 1.2 비밀번호 관리정책 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-03(상) | 1. 계정 관리 > 1.3 계정 잠금 임계값 설정 ◀"  >> "$resultfile" 2>&1
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

#태훈
U_07() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-07(하) | 1. 계정관리 > 1.7 불필요한 계정 제거 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-08(중) | 1. 계정 관리 > 1.8 관리자 권한(그룹/ sudoers) 최소화 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 관리자 권한(관리자 그룹 및 sudo 권한)에 불필요한 계정이 등록되어 있지 않은 경우" >> "$resultfile" 2>&1

  # Rocky 10.x는 wheel + sudoers 기반이 핵심.
  # gid=0(root 그룹) + wheel(존재 시) + sudoers에서 권한 부여된 사용자/그룹을 함께 점검한다.

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

  _is_unnecessary() {
    local u="$1" x
    for x in "${unnecessary_accounts[@]}"; do
      [ "$u" = "$x" ] && return 0
    done
    return 1
  }

  _user_exists() { id "$1" >/dev/null 2>&1; }
  _group_exists() { getent group "$1" >/dev/null 2>&1; }

  # 특정 그룹의 구성원( /etc/group + /etc/gshadow(있으면) )을 모아 unique 출력
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

  # gid=0 그룹명(보통 root)을 찾아서 관리자 그룹 후보로 포함
  _gid0_group_name() {
    getent group | awk -F: '$3==0{print $1; exit}'
  }

  # sudoers에서 사용자/그룹 추출:
  # - "user ALL=(ALL) ..." 형태의 user
  # - "%group ALL=(ALL) ..." 형태의 group
  # - "includedir /etc/sudoers.d" 도 함께 반영
  _collect_sudoers_identities() {
    local files=("/etc/sudoers")
    [ -d /etc/sudoers.d ] && files+=(/etc/sudoers.d/*)

    # 파일이 없거나 glob이 비면 무시
    local f
    for f in "${files[@]}"; do
      [ -e "$f" ] || continue
      # 주석/빈줄 제거, Defaults 제외, alias/Runas_Alias 등은 일단 제외(보수적으로)
      awk '
        BEGIN{IGNORECASE=1}
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*$/ {next}
        /^[[:space:]]*Defaults/ {next}
        /^[[:space:]]*(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)[[:space:]]+/ {next}
        {
          # 첫 토큰이 %group 이거나 user
          # 예: %wheel ALL=(ALL) ALL
          # 예: alice ALL=(ALL) ALL
          gsub(/[[:space:]]+/, " ");
          split($0, a, " ");
          print a[1];
        }
      ' "$f" 2>/dev/null
    done | sed 's/[[:space:]]//g' | sed '/^$/d' | sort -u
  }

  local vuln_found=0
  local evidence=""

  # 1) Rocky 10.x 핵심 관리자 그룹 후보 구성
  local admin_groups=()
  local gid0g
  gid0g="$(_gid0_group_name)"
  [ -n "$gid0g" ] && admin_groups+=("$gid0g")
  _group_exists "wheel" && admin_groups+=("wheel")

  # 2) 그룹 구성원 점검 (gid0 + wheel)
  if [ "${#admin_groups[@]}" -gt 0 ]; then
    local g u bads
    for g in "${admin_groups[@]}"; do
      bads=""
      while IFS= read -r u; do
        [ -z "$u" ] && continue
        _is_unnecessary "$u" && bads+="$u "
      done < <(_collect_group_users "$g")

      if [ -n "$bads" ]; then
        vuln_found=1
        evidence+="[관리자그룹:${g}] 불필요 계정: ${bads}\n"
      fi
    done
  fi

  # 3) sudoers 기반 관리자 권한 점검
  # - sudoers에 직접 등록된 사용자
  # - sudoers에 등록된 그룹(%group) -> 해당 그룹 구성원까지 확장
  local sudo_id idtoken
  while IFS= read -r idtoken; do
    [ -z "$idtoken" ] && continue

    if echo "$idtoken" | grep -q '^%'; then
      # 그룹
      local sg="${idtoken#%}"
      if _group_exists "$sg"; then
        local u bads=""
        while IFS= read -r u; do
          [ -z "$u" ] && continue
          _is_unnecessary "$u" && bads+="$u "
        done < <(_collect_group_users "$sg")

        if [ -n "$bads" ]; then
          vuln_found=1
          evidence+="[sudoers그룹:%${sg}] 불필요 계정: ${bads}\n"
        fi
      fi
    else
      # 사용자
      if _user_exists "$idtoken"; then
        if _is_unnecessary "$idtoken"; then
          vuln_found=1
          evidence+="[sudoers사용자:${idtoken}] 불필요 계정이 sudo 권한 보유\n"
        fi
      fi
    fi
  done < <(_collect_sudoers_identities)

  # 결과 출력
  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-08 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 관리자 권한(그룹/ sudoers)에 불필요한 계정이 포함되어 있습니다." >> "$resultfile" 2>&1
    echo -e " 근거:\n${evidence}" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-08 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 관리자 권한(관리자 그룹 및 sudo 권한)에서 불필요 계정이 확인되지 않았습니다." >> "$resultfile" 2>&1
  return 0
}

#연진
U_09() {
    echo ""  >> "$resultfile" 2>&1
    echo "▶ U-09(하) | 1. 계정관리 > 1.12 계정이 존재하지 않는 GID 금지 ◀"  >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우" >> "$resultfile" 2>&1

    # 1. /etc/passwd에서 기본 그룹으로 사용 중인 모든 GID 추출
    USED_GIDS=$(awk -F: '{print $4}' /etc/passwd | sort -u)

    # 2. Rocky 10 기준(rocky9와 차이): 일반 사용자 그룹인 1000번 이상만 필터링
    # 시스템 그룹(0-999)은 계정이 없어도 서비스용으로 존재하는 경우가 많아 제외하는 것이 안전함
    CHECK_GIDS=$(awk -F: '$3 >= 1000 {print $3}' /etc/group)
    
    VULN_GROUPS=""
    for gid in $CHECK_GIDS; do
        # 해당 GID가 /etc/passwd의 기본 그룹으로 사용 중인지 확인
        if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
            # 추가 확인: /etc/group의 4번째 필드(보조 그룹 사용자)에도 사람이 없는지 확인
            MEMBER_EXISTS=$(grep -w "^[^:]*:[^:]*:$gid:[^:]*" /etc/group | cut -d: -f4)
            
            if [ -z "$MEMBER_EXISTS" ]; then
                GROUP_NAME=$(grep -w "^[^:]*:[^:]*:$gid:" /etc/group | cut -d: -f1)
                VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
            fi
        fi
    done

    # 3. 결과 판정
    if [ -n "$VULN_GROUPS" ]; then
        echo "※ U-09 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] 계정이 존재하지 않는 불필요한 그룹(GID 1000 이상) 존재:$VULN_GROUPS" >> "$resultfile" 2>&1
    else
        echo "※ U-09 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

#수진
U_10() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> "$resultfile" 2>&1

    vuln_flag=0

    if [ -f /etc/passwd ]; then
        dup_uid_count=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | wc -l)

        if [ "$dup_uid_count" -gt 0 ]; then
            echo "※ U-10 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> "$resultfile" 2>&1
            vuln_flag=1
        fi
    else
        echo "※ /etc/passwd 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        vuln_flag=1
    fi
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-10 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
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

#태훈
U_12() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-12(하) | 1. 계정관리 > 1.12 세션 종료 시간 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-13(중) | 1. 계정관리 > 1.13 안전한 비밀번호 암호화 알고리즘 사용 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 안전한 해시 알고리즘(yescrypt:\$y\$, SHA-512:\$6\$, SHA-256:\$5\$) 사용" >> "$resultfile" 2>&1

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
  local good_count=0
  local evidence_bad=""
  local evidence_good_sample=""

  # /etc/shadow: user:hash:...
  # hash가
  # - 비어있거나, !, *, !! 등: 비밀번호 미설정/잠금 -> 점검 제외
  # - $id$... 또는 $y$... 형태: prefix로 알고리즘 판별
  while IFS=: read -r user hash rest; do
    [ -z "$user" ] && continue

    # 비밀번호 미설정/잠금 계정 제외
    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    ((checked++))

    # 2) Rocky 10.x에서 흔한 yescrypt($y$) 포함
    # - yescrypt: $y$...
    # - SHA-512 : $6$...
    # - SHA-256 : $5$...
    # 취약(예시):
    # - MD5     : $1$...
    # - Blowfish: $2a$ / $2y$ / $2b$... (환경에 따라 안전하지만, shadow 표준 관점에서 혼재 가능)
    # - DES(legacy): 13글자 정도의 해시( $로 시작 안함 )
    if [[ "$hash" == \$y\$* ]]; then
      ((good_count++))
      # 샘플 근거는 너무 길어지지 않게 5개만
      if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
        evidence_good_sample+="$user:yescrypt "
      fi
      continue
    fi

    if [[ "$hash" == \$6\$* ]]; then
      ((good_count++))
      if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
        evidence_good_sample+="$user:sha512 "
      fi
      continue
    fi

    if [[ "$hash" == \$5\$* ]]; then
      ((good_count++))
      if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
        evidence_good_sample+="$user:sha256 "
      fi
      continue
    fi

    # 명확히 취약한 케이스들
    if [[ "$hash" == \$1\$* ]]; then
      vuln_found=1
      evidence_bad+="$user:MD5(\$1\$) "
      continue
    fi

    # $로 시작하긴 하는데 위에서 못 잡은 경우: UNKNOWN(정책/환경 혼재 가능) -> 취약으로 분류 + 근거
    if [[ "$hash" == \$* ]]; then
      local id
      id="$(echo "$hash" | awk -F'$' '{print $2}')"
      [ -z "$id" ] && id="UNKNOWN"
      vuln_found=1
      evidence_bad+="$user:UNKNOWN(\$$id\$) "
      continue
    fi

    # $로 시작 안 하는 경우: 레거시(DES 등) 가능성 -> 취약
    vuln_found=1
    evidence_bad+="$user:LEGACY/UNKNOWN_FORMAT "
  done < "$shadow"

  if [ "$checked" -eq 0 ]; then
    echo "※ U-13 결과 : N/A" >> "$resultfile" 2>&1
    echo " 점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 결과 출력
  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-13 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 안전 기준(yescrypt/SHA-2) 미만 또는 불명확한 해시 알고리즘을 사용하는 계정이 존재합니다." >> "$resultfile" 2>&1
    echo " 점검계정 수: $checked, 양호 추정 계정 수: $good_count" >> "$resultfile" 2>&1
    echo " 취약 근거: $evidence_bad" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-13 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 안전한 해시 알고리즘(yescrypt/SHA-2)만 사용 중입니다." >> "$resultfile" 2>&1
  echo " 점검계정 수: $checked, 샘플 근거: $evidence_good_sample" >> "$resultfile" 2>&1
  return 0
}

#연진
U_14() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-14(상) | 2. 파일 및 디렉토리 관리 > 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함되지 않은 경우" >> "$resultfile" 2>&1

    VULN_FOUND=0
    DETAILS=""

    # 1. 런타임 PATH 점검 (현재 실행 환경)
    if echo "$PATH" | grep -qE '^\.:|:.:|^:|::|:$'; then
        VULN_FOUND=1
        DETAILS="[Runtime] 현재 PATH 내 '.' 또는 '::' 발견: $PATH"
    fi

    # 2. Rocky 10 시스템 설정 파일 점검
    if [ $VULN_FOUND -eq 0 ]; then
        # Rocky 10에서 주로 사용하는 설정 파일 및 profile.d 디렉토리 포함
        path_settings_files=("/etc/profile" "/etc/bashrc" "/etc/environment")
        # profile.d 내의 모든 쉘 스크립트 추가 점검
        for file in "${path_settings_files[@]}" /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                VULN_LINE=$(grep -vE '^#|^\s#' "$file" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$')
                if [ ! -z "$VULN_LINE" ]; then
                    VULN_FOUND=1
                    DETAILS="[System File] $file: $VULN_LINE"
                    break
                fi
            fi
        done
    fi

    # 3. 사용자별 설정 파일 (Rocky 10 기준)
    if [ $VULN_FOUND -eq 0 ]; then
        user_dot_files=(".bash_profile" ".bashrc" ".shrc")
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

    # 최종 출력
    if [ $VULN_FOUND -eq 1 ]; then
        echo "※ U-14 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] $DETAILS" >> "$resultfile" 2>&1
    else
        echo "※ U-14 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

#수진
U_15() {
    echo "" >> $resultfile 2>&1
    echo "▶ U-15(상) | 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"  >> $resultfile 2>&1
    if [ "$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l)" -gt 0 ]; then
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

#태훈
U_17() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-17(중) | 2. 파일 및 디렉터리 관리 > 2.4 시스템 시작 스크립트 권한 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-18(상) | 2. 파일 및 디렉토리 관리 > 2.5 /etc/shadow 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
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

#태훈
U_22() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-22(상) | 2. 파일 및 디렉터리 관리 > 2.9 /etc/services 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-23(상) | 2. 파일 및 디렉토리 관리 > 2.10 SUID, SGID, Sticky bit 설정 파일 점검 ◀"  >> "$resultfile" 2>&1
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
    if [ "$(find / -type f -perm -2 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "※ U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " world writable 설정이 되어있는 파일이 있습니다." >> $resultfile 2>&1
    else
        echo "※ U-25 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

#희윤
U_26(){
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-26(상) | 2. 파일 및 디렉토리 관리 > 2.13 /dev에 존재하지 않는 device 파일 점검 ◀"  >> "$resultfile" 2>&1
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

#태훈
U_27() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-27(상) | 2. 파일 및 디렉터리 관리 > 2.14 $HOME/.rhosts, hosts.equiv 사용 금지 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-28(상) | 2. 파일 및 디렉토리 관리 > 2.15 접속 IP 및 포트 제한 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) SSH 데몬/방화벽에서 특정 IP/대역만 허용하는 제한 정책이 존재하는 경우" >> "$resultfile" 2>&1

  local sshd_cfg="/etc/ssh/sshd_config"
  local sshd_dropin_dir="/etc/ssh/sshd_config.d"
  local good=0
  local evidence=""

  # ---------------------------
  # Helper: 정규화(주석/공백 제거)
  # ---------------------------
  _norm_grep() {
    # $1: file, $2: regex(대소문자 무시)
    local f="$1" r="$2"
    [ -f "$f" ] || return 1
    grep -Eiv '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ei "$r" >/dev/null 2>&1
  }

  _list_cfg_files() {
    # sshd_config + drop-in을 순서대로
    echo "$sshd_cfg"
    if [ -d "$sshd_dropin_dir" ]; then
      ls -1 "$sshd_dropin_dir"/*.conf 2>/dev/null | sort
    fi
  }

  # ---------------------------
  # 1) SSH 설정 기반 제한 정책 확인
  #   - AllowUsers/AllowGroups/DenyUsers/DenyGroups
  #   - Match Address (특정 IP/대역에만 허용 등)
  #   - ListenAddress (특정 인터페이스 바인딩)
  # ---------------------------
  local f
  local ssh_policy_hit=0

  for f in $(_list_cfg_files); do
    [ -f "$f" ] || continue

    if _norm_grep "$f" '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD 제한] ${f}에 Allow/Deny Users/Groups 설정 존재\n"
    fi

    if _norm_grep "$f" '^[[:space:]]*Match[[:space:]]+Address[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD 제한] ${f}에 Match Address(IP/대역 조건) 존재\n"
    fi

    if _norm_grep "$f" '^[[:space:]]*ListenAddress[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD 제한] ${f}에 ListenAddress(바인딩 제한) 존재\n"
    fi
  done

  if [ "$ssh_policy_hit" -eq 1 ]; then
    good=1
  fi

  # ---------------------------
  # 2) Firewalld 기반 제한 정책 확인 (Rocky 10 기본)
  #   - ssh 서비스가 열려있더라도 source 제한(rich rule)이 있으면 양호로 판단
  #   - firewalld 미사용이면 nft/iptables 확인은 프로젝트 범위 따라 확장 가능
  # ---------------------------
  local fw_hit=0
  if command -v firewall-cmd >/dev/null 2>&1; then
    # firewalld 동작 여부
    if firewall-cmd --state >/dev/null 2>&1; then
      # 활성 zone 확인
      local zones z
      zones="$(firewall-cmd --get-active-zones 2>/dev/null)"

      # rich-rule 중 source address + ssh 관련(서비스 ssh 또는 port 22) 제한 찾기
      # (zone별로 확인)
      while read -r z rest; do
        [ -z "$z" ] && continue
        # zone 라인 형태: "public" 다음 줄에 interfaces: ... 일 수 있어 필터링
        echo "$z" | grep -q ':' && continue

        local rr
        rr="$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null)"

        if echo "$rr" | grep -Eqi 'source[[:space:]]+address=.+(service[[:space:]]+name="ssh"|port[[:space:]]+port="22")'; then
          fw_hit=1
          evidence+="[FW 제한] zone(${z}) rich-rule에 source address 기반 SSH(22) 제한 존재\n"
          break
        fi
      done <<< "$zones"

      # 추가: zone에 직접 source 바인딩(특정 소스만 zone에 매핑)된 경우도 제한으로 볼 수 있음
      if [ "$fw_hit" -eq 0 ]; then
        local zlist
        zlist="$(firewall-cmd --get-zones 2>/dev/null)"
        for z in $zlist; do
          # zone source 목록이 있으면 제한 가능성(ssh가 그 zone에만 열렸다면 더 강함)
          local srcs
          srcs="$(firewall-cmd --zone="$z" --list-sources 2>/dev/null)"
          if [ -n "$srcs" ]; then
            # ssh(서비스 또는 포트)가 그 zone에 열려있는지 같이 확인
            local svc ports
            svc="$(firewall-cmd --zone="$z" --list-services 2>/dev/null)"
            ports="$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)"
            if echo "$svc" | grep -qw ssh || echo "$ports" | grep -Eq '(^|[[:space:]])22/tcp([[:space:]]|$)'; then
              fw_hit=1
              evidence+="[FW 제한] zone(${z})에 source(${srcs}) 지정 + SSH(22) 허용(소스 제한 형태)\n"
              break
            fi
          fi
        done
      fi
    fi
  fi

  if [ "$fw_hit" -eq 1 ]; then
    good=1
  fi

  # ---------------------------
  # 3) 레거시(TCP Wrapper) 참고: Rocky 10에서는 대부분 미적용
  #   - libwrap 존재 + hosts.deny/allow 설정이 있어도, 데몬이 libwrap 사용하지 않으면 의미 없음
  # ---------------------------
  local deny="/etc/hosts.deny"
  local allow="/etc/hosts.allow"
  local libwrap_exists=0
  if ls /lib*/libwrap.so* /usr/lib*/libwrap.so* >/dev/null 2>&1; then
    libwrap_exists=1
  fi

  if [ "$libwrap_exists" -eq 1 ]; then
    # 참고 증거만 남김 (양호 판정 근거로 쓰기엔 Rocky 10에서 애매)
    if [ -f "$deny" ] || [ -f "$allow" ]; then
      evidence+="[참고] TCP Wrapper(libwrap) 파일 존재: "
      [ -f "$deny" ] && evidence+="$deny "
      [ -f "$allow" ] && evidence+="$allow "
      evidence+="\n"
    fi
  fi

  # ---------------------------
  # 최종 판정
  # ---------------------------
  if [ "$good" -eq 1 ]; then
    echo "※ U-28 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " SSH 또는 방화벽에서 접속 IP/대역 제한 정책이 확인되었습니다." >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-28 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  echo " SSH(또는 방화벽)에서 특정 IP/대역 제한 정책이 확인되지 않습니다." >> "$resultfile" 2>&1
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
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-30(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> "$resultfile" 2>&1
    vuln_flag=0
    # systemd UMask 점검
    for svc in $(systemctl list-unit-files --type=service --no-legend | awk '{print $1}'); do
        umask_val=$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')
        [ -z "$umask_val" ] && continue

        umask_dec=$((8#$umask_val))
        if [ "$umask_dec" -lt 18 ]; then
            vuln_flag=1
            break
        fi
    done
    # login.defs, PAM 점검
    if [ "$vuln_flag" -eq 0 ]; then
        if grep -q "pam_umask.so" /etc/pam.d/common-session 2>/dev/null; then
            login_umask=$(grep -E "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
            if [ -z "$login_umask" ] || [ $((8#$login_umask)) -lt 18 ]; then
                vuln_flag=1
            fi
        else
            vuln_flag=1
        fi
    fi
    if [ "$vuln_flag" -eq 1 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    else
        echo "※ U-30 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
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

#태훈
U_32() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-32(하) | 2. 파일 및 디렉터리 관리 > 2.19 홈 디렉터리로 지정한 디렉터리의 존재 관리 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-33(하) | 2. 파일 및 디렉토리 관리 > 2.20 숨겨진 파일 및 디렉토리 검색 및 제거 ◀" >> "$resultfile" 2>&1
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
    XINETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec 2>/dev/null)
    if [ -n "$XINETD_VUL" ]; then
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

#태훈
U_37() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-37(상) | 3. 서비스 관리 > 3.4 crontab 설정 파일 권한 설정 미흡 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-38(상) | 3. 서비스 관리 | 3.5 DoS 공격에 취약한 서비스 비활성화 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 대상 서비스를 사용하지 않는 경우 N/A, (2) 대상 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

  # Rocky 10.x 기본: inetd/xinetd 거의 미사용, systemd socket도 기본 제공 적음.
  # 따라서 '전통 inetd 취약 서비스' 중심으로 판정하고,
  # SNMP/DNS/NTP는 옵션으로만 취약 판정에 포함하도록 분리.

  # ===== 정책 스위치 =====
  local CHECK_SNMP=0
  local CHECK_DNS=0
  local CHECK_NTP=0   # 기본 0: 시간동기는 보통 필수라 "info"로만 기록

  # ===== 대상 정의 =====
  local inetd_services=("echo" "discard" "daytime" "chargen")
  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")

  local snmp_units=("snmpd.service")
  local dns_units=("named.service" "bind9.service")
  local ntp_units=("chronyd.service" "ntpd.service" "systemd-timesyncd.service")

  local in_scope_used=0    # 대상이 "존재/사용 흔적"이 있는지 (N/A 판단용)
  local vulnerable=0
  local evidences=()

  _unit_exists() {
    # unit 파일 존재 여부(설치 여부에 가까움)
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1"
  }

  _unit_enabled_or_active() {
    # enabled 또는 active면 "사용 중"으로 간주
    systemctl is-enabled --quiet "$1" 2>/dev/null && return 0
    systemctl is-active  --quiet "$1" 2>/dev/null && return 0
    return 1
  }

  ############################
  # A. inetd/xinetd (레거시) - 참고용
  ############################
  if [ -d /etc/xinetd.d ]; then
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
        in_scope_used=1
        local disable_yes_count
        disable_yes_count=$(grep -vE '^\s*#' "/etc/xinetd.d/${svc}" 2>/dev/null \
          | grep -iE '^\s*disable\s*=\s*yes\s*$' | wc -l)

        if [ "$disable_yes_count" -eq 0 ]; then
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
        in_scope_used=1
        vulnerable=1
        evidences+=("inetd: ${svc} 서비스가 /etc/inetd.conf 에서 활성화되어 있습니다.")
      fi
    done
  fi

  ############################
  # B. systemd socket (Rocky 10에서 현실적인 체크)
  ############################
  if command -v systemctl >/dev/null 2>&1; then
    for sock in "${systemd_sockets[@]}"; do
      if _unit_exists "$sock"; then
        in_scope_used=1
        if _unit_enabled_or_active "$sock"; then
          vulnerable=1
          evidences+=("systemd: ${sock} 가 활성화되어 있습니다. (enabled/active)")
        else
          evidences+=("systemd: ${sock} 는 설치되어 있으나 비활성화 상태입니다.")
        fi
      fi
    done

    ############################
    # C. 추가 서비스(옵션)
    ############################
    if [ "$CHECK_SNMP" -eq 1 ]; then
      for unit in "${snmp_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("SNMP: ${unit} 가 활성화되어 있습니다. (정책상 점검 포함)")
          else
            evidences+=("SNMP: ${unit} 는 설치되어 있으나 비활성화 상태입니다.")
          fi
        fi
      done
    else
      # 정보 기록만
      for unit in "${snmp_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: SNMP(${unit}) 활성화 감지(정책상 U-38 취약 판정에는 미포함)")
        fi
      done
    fi

    if [ "$CHECK_DNS" -eq 1 ]; then
      for unit in "${dns_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("DNS: ${unit} 가 활성화되어 있습니다. (정책상 점검 포함)")
          else
            evidences+=("DNS: ${unit} 는 설치되어 있으나 비활성화 상태입니다.")
          fi
        fi
      done
    else
      for unit in "${dns_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: DNS(${unit}) 활성화 감지(정책상 U-38 취약 판정에는 미포함)")
        fi
      done
    fi

    if [ "$CHECK_NTP" -eq 1 ]; then
      for unit in "${ntp_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("NTP: ${unit} 가 활성화되어 있습니다. (정책상 점검 포함)")
          else
            evidences+=("NTP: ${unit} 는 설치되어 있으나 비활성화 상태입니다.")
          fi
        fi
      done
    else
      for unit in "${ntp_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: NTP(${unit}) 활성화 감지(시간동기 서비스, 일반적으로 필요)")
        fi
      done
    fi
  fi

  ############################
  # D. N/A 판정
  ############################
  if [ "$in_scope_used" -eq 0 ]; then
    echo "※ U-38 결과 : N/A" >> "$resultfile" 2>&1
    echo " 전통 DoS 취약 서비스(echo/discard/daytime/chargen)가 설치/사용되지 않아 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  ############################
  # E. 최종 판정 + 근거 출력
  ############################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-38 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 활성화되어 있습니다." >> "$resultfile" 2>&1
  else
    echo "※ U-38 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 비활성화되어 있습니다." >> "$resultfile" 2>&1
  fi
  return 0
}
U_39() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-39(상) | 3. 서비스 관리 > 3.6 불필요한 NFS 서비스 비활성화 ◀" >> "$resultfile" 2>&1
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

  # 1. systemctl로 automountd 서비스 활성화 여부 확인
  if systemctl is-active --quiet autofs 2>/dev/null; then
    VULN=1
    REASON="$REASON automountd 서비스가 활성화되어 있습니다. |"
  fi

  # 2. 1번에서 확인되지 않았지만 프로세스가 실행되고 있는지 여부 확인
  if ps -ef | grep -v grep | grep -Ei "automount|autofs" >/dev/null 2>&1; then
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
#태훈
U_42() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-42(상) | 3. 서비스 관리 > 3.9 불필요한 RPC 서비스 비활성화 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-43(상) | 3. 서비스 관리 > 3.10 NIS, NIS+ 점검 ◀"  >> "$resultfile" 2>&1
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
  echo "▶ U-44(상) | 3. 서비스 관리 > 3.11 tftp, talk 서비스 비활성화 ◀" >> "$resultfile" 2>&1
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
  return 0
}
#수진
U_45() {
    # 2026/02/06 기준 sendmail 최신 버전 : 8.18.2 를 기준으로 점검
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

  # 1. Sendmail 서비스가 실행되고 있는지 확인
  if ps -ef | grep -v grep | grep -q "sendmail"; then

    # 2. Sendmail 설정 파일(/etc/mail/sendmail.cf) 점검
    if [ -f "/etc/mail/sendmail.cf" ]; then
      CHECK=$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf | grep "restrictqrun")

      if [ -z "$CHECK" ]; then
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
#태훈
U_47() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-47(상) | 3. 서비스 관리 > 3.14 스팸메일 릴레이 제한 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-48(중) | 3. 서비스 관리 > 3.15 expn, vrfy 명령어 제한 ◀"  >> "$resultfile" 2>&1
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
U_49() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-49(상) | 3. 서비스 관리 > 3.16 DNS 보안 버전 패치 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우" >> "$resultfile" 2>&1

  local named_active=0
  local named_running=0
  local bind_ver=""
  local pending_sec=0

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

  # 2) BIND 버전 확인 (근거 출력용)
  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi
  if [ -z "$bind_ver" ] && command -v rpm >/dev/null 2>&1; then
    bind_ver="$(rpm -q bind 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi
  [ -z "$bind_ver" ] && bind_ver="unknown"

  # 3) 보안 패치 대기 여부 확인 (Rocky 9/10 공통 핵심)
  if ! command -v dnf >/dev/null 2>&1; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DNS 서비스는 사용 중이나 dnf 미존재로 보안 패치 적용 여부를 확인할 수 없습니다. (BIND=$bind_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  # bind 관련 보안 업데이트가 대기 중인지 확인 (updateinfo가 없으면 일반 보안대기 체크로 폴백)
  if dnf -q updateinfo list --updates security 2>/dev/null | grep -Eiq '(^|[[:space:]])bind([[:space:]]|-)'; then
    pending_sec=1
  else
    # 환경에 따라 bind가 문자열로 안 잡힐 수 있어, installed bind* 대상으로도 한번 더 확인
    if dnf -q updateinfo list --updates security 2>/dev/null | grep -q .; then
      # 여기서 전체 security 업데이트가 있는 경우도 "주기적 패치 관리 미흡"으로 취약 처리할지 애매할 수 있음
      # U-49는 DNS(BIND) 항목이므로 bind가 없으면 전체 security만으로는 취약 처리하지 않음
      pending_sec=0
    fi
  fi

  if [ "$pending_sec" -eq 1 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND 보안 업데이트(SECURITY) 미적용 대기 항목이 존재합니다. (BIND=$bind_ver, dnf updateinfo 기준)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-49 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " DNS 서비스 사용 중이며 BIND 관련 보안 업데이트 대기 항목이 확인되지 않습니다. (BIND=$bind_ver)" >> "$resultfile" 2>&1
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
#태훈
U_52() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-52(중) | 3. 서비스 관리 > 3.19 Telnet 서비스 비활성화 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-53(하) | 3. 서비스 관리 > 3.20 FTP 서비스 정보 노출 제한 ◀" >> "$resultfile" 2>&1
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
U_54() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-54(중) | 3. 서비스 관리 > 3.21 암호화되지 않는 FTP 서비스 비활성화 ◀" >> "$resultfile" 2>&1
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
    if ! rpm -qa | grep -Eqi 'vsftpd|proftpd'; then
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
#태훈
U_57() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-57(상) | 3. 서비스 관리 > 3.24 ftpusers 파일 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-58(중) | 3. 서비스 관리 > 3.25 불필요한 SNMP 서비스 구동 점검 (Rocky 10.x 기준) ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SNMP 서비스를 사용하지 않는 경우" >> "$resultfile" 2>&1

  local found=0

  # 1) systemd 서비스 상태 확인 (Rocky 10.x: unit명은 보통 snmpd.service)
  if command -v systemctl >/dev/null 2>&1; then
    # 설치 여부 확인 후, active/enabled 중 하나라도면 '사용 중'으로 판단
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "snmpd.service"; then
      if systemctl is-active --quiet snmpd.service 2>/dev/null || systemctl is-enabled --quiet snmpd.service 2>/dev/null; then
        found=1
      fi
    fi

    if [ "$found" -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "snmptrapd.service"; then
      if systemctl is-active --quiet snmptrapd.service 2>/dev/null || systemctl is-enabled --quiet snmptrapd.service 2>/dev/null; then
        found=1
      fi
    fi
  fi

  # 2) 프로세스 확인 (보조)
  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1 || pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
    fi
  fi

  # 3) 포트 리스닝 확인 (UDP 161/162) - Rocky 10 기본: ss 사용
  if [ "$found" -eq 0 ] && command -v ss >/dev/null 2>&1; then
    # ss 출력에서 161/162 UDP 리스닝이 있으면 사용 중으로 판단
    if ss -lunp 2>/dev/null | awk '$5 ~ /:(161|162)$/ {print; exit 0} END{exit 1}' >/dev/null 2>&1; then
      found=1
    fi
  fi

  # 최종 판정 (근거 출력 없음)
  if [ "$found" -eq 1 ]; then
    echo "※ U-58 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " SNMP 서비스를 사용하고 있습니다." >> "$resultfile" 2>&1
  else
    echo "※ U-58 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " SNMP 서비스가 비활성화되어 있습니다." >> "$resultfile" 2>&1
  fi

  return 0
}
U_59() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-59(상) | 3. 서비스 관리 > 3. 26 안전한 SNMP 버전 사용 ◀" >> "$resultfile" 2>&1
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
    ps_snmp_count=`ps -ef | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l`
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
#태훈
U_62() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-62(중) | 3. 서비스 관리 > 3.29 로그인 시 경고 메시지 설정 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-63(중) | 3. 서비스 관리 > 3.30 sudo 명령어 접근 관리 ◀" >> "$resultfile" 2>&1
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
  echo "▶ U-64(상) | 4. 패치 관리 > 4.1 주기적 보안 패치 및 벤더 권고사항 적용 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 수행하고 최신 보안 패치 및 Kernel이 적용된 경우" >> "$resultfile" 2>&1

  local os_name="" os_ver=""
  local kernel_running=""
  local latest_kernel=""
  local pending_sec=0

  # OS/Kernel 기본 정보
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_name="$NAME"
    os_ver="$VERSION_ID"
  fi
  kernel_running="$(uname -r 2>/dev/null)"

  # 1) Rocky 10.1 고정 체크
  if ! echo "$os_name" | grep -qi "Rocky"; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " Rocky Linux가 아닙니다. (현재: $os_name $os_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$os_ver" != "10.1" ]; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " Rocky 10.1 환경이 아닙니다. (현재: Rocky $os_ver)" >> "$resultfile" 2>&1
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

  echo "※ U-64 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " Rocky 10.1 환경이며 보안 업데이트 대기 없음 + 최신 커널 적용 확인됨. (kernel=$kernel_running)" >> "$resultfile" 2>&1
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
          CHECK_MSG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.info[[:space:]]+-?/var/log/messages")
          CHECK_SECURE=$(echo "$ALL_CONF_CONTENT" | grep -E "auth(priv)?\.\*[[:space:]]+-?/var/log/secure")
          CHECK_MAIL=$(echo "$ALL_CONF_CONTENT" | grep -E "mail\.\*[[:space:]]+-?/var/log/maillog")
          CHECK_CRON=$(echo "$ALL_CONF_CONTENT" | grep -E "cron\.\*[[:space:]]+-?/var/log/cron")
          CHECK_ALERT=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.alert[[:space:]]+(/dev/console|:omusrmsg:\*|root)")
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
  echo "▶ U-67(중) | 5. 로그 관리 > 5.3 로그 디렉터리 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
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
U_05
U_06
U_07
U_08
U_10
U_11
U_12
U_13
U_15
U_16
U_17
U_18
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
