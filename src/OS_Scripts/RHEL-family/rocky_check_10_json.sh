#!/bin/bash

U_01() {
  local code="U-01"
  local item="root 계정 원격접속 제한"
  local severity="상"
  local status="양호"
  local reason="원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
  
  local VULN=0
  local BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

  # 1. 취약 원격 터미널 서비스 점검
  for svc in "${BAD_SERVICES[@]}"; do
    if systemctl is-active "$svc" &>/dev/null; then
      if [[ "$svc" == *"telnet"* ]]; then
        break 
      else
        VULN=1
        reason="$svc 서비스가 실행 중입니다."
        break
      fi
    fi
  done

  # 2. Telnet 서비스 상세 점검
  if [ $VULN -eq 0 ]; then
    if ps -ef | grep -i 'telnet' | grep -v 'grep' &>/dev/null || \
       netstat -nat 2>/dev/null | grep -w 'tcp' | grep -i 'LISTEN' | grep ':23 ' &>/dev/null; then  
      
      if [ -f /etc/pam.d/login ]; then
        if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty.so'; then
          VULN=1
          reason="Telnet 서비스 사용 중이며, /etc/pam.d/login에 pam_securetty.so 설정이 없습니다."
        fi
      fi
      
      if [ $VULN -eq 0 ] && [ -f /etc/securetty ]; then
        if grep -vE '^#|^\s#' /etc/securetty | grep -q '^ *pts'; then
          VULN=1
          reason="Telnet 서비스 사용 중이며, /etc/securetty에 pts 터미널이 허용되어 있습니다."
        fi
      fi
    fi
  fi

  # 3. SSH 점검 
  if [ $VULN -eq 0 ] && (systemctl is-active sshd &>/dev/null || ps -ef | grep -v grep | grep -q sshd); then
    ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')
    
    if [[ "$ROOT_LOGIN" != "no" ]]; then
      VULN=1
      reason="SSH root 접속이 허용 중입니다."
    fi
  fi

  # 4. 최종 결과 설정
  if [ $VULN -eq 1 ]; then
    status="취약"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_02() {
  local code="U-02"
  local item="비밀번호 관리정책 설정"
  local severity="상"
  local status="양호"
  local reason="PASS_MAX_DAYS 90일 이하, PASS_MIN_DAYS 1일 이상, 비밀번호 최소 길이 8자 이상, 복잡성 및 재사용 제한 설정이 적절합니다."

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

  # 3) 재사용 제한(remember)
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

  # 결과 정리
  if (( vuln == 1 )); then
    status="취약"
    # 모든 사유를 하나의 문자열로 결합 (콤마로 구분)
    reason=$(printf "%s / " "${reasons[@]}")
    reason="${reason% / }"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_03() {
  local code="U-03"
  local item="계정 잠금 임계값 설정"
  local severity="상"
  local status="양호"
  local reason=""

  local pam_files=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
  )
  local faillock_conf="/etc/security/faillock.conf"

  local found_any=0
  local max_deny=-1
  local file_exists_count=0

  # 내부 헬퍼 함수
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

  # PAM 파일 점검
  for f in "${pam_files[@]}"; do
    if [ -f "$f" ]; then
      ((file_exists_count++))
      while IFS= read -r deny; do
        [ -z "$deny" ] && continue
        found_any=1
        if [ "$deny" -gt "$max_deny" ]; then
          max_deny="$deny"
        fi
      done < <(_extract_deny_from_pam_file "$f")
    fi
  done

  # faillock.conf 점검
  if [ -f "$faillock_conf" ]; then
    local conf_deny="$(_extract_deny_from_faillock_conf "$faillock_conf")"
    if [ -n "$conf_deny" ]; then
      found_any=1
      if [ "$conf_deny" -gt "$max_deny" ]; then
        max_deny="$conf_deny"
      fi
    fi
  fi

  # 결과 판정 로직
  if [ "$file_exists_count" -eq 0 ]; then
    status="취약"
    reason="계정 잠금 임계값을 점검할 PAM 파일이 없습니다. (system-auth/password-auth 미존재)"
  elif [ "$found_any" -eq 0 ]; then
    status="취약"
    reason="deny 설정을 찾지 못했습니다. (PAM 라인 또는 faillock.conf에서 deny=값 미발견)"
  elif [ "$max_deny" -eq 0 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 0으로 설정되어 있습니다. (잠금 미적용)"
  elif [ "$max_deny" -gt 10 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 11회 이상으로 설정되어 있습니다. (현재 max deny=$max_deny)"
  else
    status="양호"
    reason="계정 잠금 임계값(deny)이 10회 이하로 확인되었습니다. (현재 max deny=$max_deny)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_04() {
  local code="U-04"
  local item="패스워드 파일 보호"
  local severity="상"
  local status="양호"
  local reason="shadow 패스워드를 사용하며, 패스워드가 암호화되어 저장되어 있습니다."

  # 1. /etc/passwd의 두 번째 필드가 'x', '!!', '*'가 아닌 계정 확인
  local VULN_USERS
  VULN_USERS=$(awk -F : '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd | cut -d: -f1 | tr '\n' ',' | sed 's/,$//')
  
  if [ -n "$VULN_USERS" ]; then
    status="취약"
    reason="/etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재합니다: $VULN_USERS"
  else
    # 2. /etc/shadow 파일 자체의 존재 여부 점검
    if [ ! -f /etc/shadow ]; then
      status="취약"
      reason="/etc/shadow 파일이 존재하지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local severity="상"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  if [ -f /etc/passwd ]; then
    # root를 제외하고 UID가 0인 계정 목록 추출 (쉼표로 구분)
    local dup_users
    dup_users=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | tr '\n' ',' | sed 's/,$//')

    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다: [$dup_users]"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_06() {
  local code="U-06"
  local item="사용자 계정 su 기능 제한"
  local severity="상"
  local status="양호"
  local reason="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있습니다."

  local VULN=0
  local REASON=""
  local PAM_SU="/etc/pam.d/su"

  # 1. /etc/pam.d/su 파일 존재 확인
  if [ -f "$PAM_SU" ]; then
    local SU_RESTRICT
    SU_RESTRICT=$(grep -vE "^#|^\s*#" "$PAM_SU" | grep "pam_wheel.so" | grep "use_uid")

    # 2. pam_wheel.so 모듈 활성화 여부 확인
    if [ -z "$SU_RESTRICT" ]; then
      VULN=1
      REASON="/etc/pam.d/su 파일에 pam_wheel.so 모듈 설정이 없거나 주석 처리되어 있습니다."
    fi
  else
    VULN=1
    REASON="$PAM_SU 파일이 존재하지 않습니다."
  fi

  # 3. 예외 처리: 일반 사용자가 없는 경우 (UID 1000~60000)
  local USER_COUNT
  USER_COUNT=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd | wc -l)

  if [ "$VULN" -eq 1 ] && [ "$USER_COUNT" -eq 0 ]; then
    VULN=0
    REASON="일반 사용자 계정 없이 root 계정만 사용 중이므로 점검 기준에서 예외(양호) 처리됩니다."
  fi

  # 4. 결과 설정 및 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  elif [ -n "$REASON" ]; then
    # 예외 처리로 인해 양호가 된 경우 사유를 기재
    reason="$REASON"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_07() {
  local code="U-07"
  local item="불필요한 계정 제거"
  local severity="하"
  local status="양호"
  local reason="불필요한 시스템 계정이 존재하지 않거나, 로그인 불가 쉘로 설정되어 있습니다."

  local vuln=0
  local uid_min
  uid_min="$(awk 'BEGIN{v=1000} $1=="UID_MIN"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
  [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

  # 시스템 계정(UID < UID_MIN) 중 로그인 가능 쉘을 가진 계정 점검
  local suspicious=()
  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$user" == "root" ]] && continue
    if (( uid < uid_min )); then
      case "$shell" in
        */nologin|*/false) ;;  # 정상 (로그인 차단)
        *) suspicious+=("$user($shell)") ;;
      esac
    fi
  done < /etc/passwd

  # 결과 판정
  if (( ${#suspicious[@]} > 0 )); then
    vuln=1
    status="취약"
    # 발견된 계정 목록을 쉼표로 연결하여 사유에 저장
    local list_str
    list_str=$(printf ", %s" "${suspicious[@]}")
    reason="로그인 가능한 쉘을 가진 시스템 계정이 존재합니다: [${list_str:2}]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_08() {
  local code="U-01"
  local item="관리자 권한(그룹/ sudoers) 최소화"
  local severity="중"
  local status="양호"
  local reason="관리자 권한 범위에 root 외 계정이 존재하지 않습니다."

  if [ ! -f /etc/group ]; then
    status="N/A"
    reason="/etc/group 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 내부 헬퍼 함수들
  _user_exists() { id "$1" >/dev/null 2>&1; }
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

  _gid0_group_name() { getent group | awk -F: '$3==0{print $1; exit}'; }

  _collect_sudoers_identities() {
    local files=("/etc/sudoers")
    [ -d /etc/sudoers.d ] && files+=(/etc/sudoers.d/*)
    local f
    for f in "${files[@]}"; do
      [ -e "$f" ] || continue
      awk '
        BEGIN{IGNORECASE=1}
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*$/ {next}
        /^[[:space:]]*Defaults/ {next}
        /^[[:space:]]*(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)[[:space:]]+/ {next}
        {
          gsub(/[[:space:]]+/, " ");
          split($0, a, " ");
          print a[1];
        }
      ' "$f" 2>/dev/null
    done | sed 's/[[:space:]]//g' | sed '/^$/d' | sort -u
  }

  local vuln_found=0
  local evidence=""

  # 1) 관리자 그룹 점검
  local admin_groups=()
  local gid0g
  gid0g="$(_gid0_group_name)"
  [ -n "$gid0g" ] && admin_groups+=("$gid0g")
  _group_exists "wheel" && admin_groups+=("wheel")

  if [ "${#admin_groups[@]}" -gt 0 ]; then
    local g u others=""
    for g in "${admin_groups[@]}"; do
      others=""
      while IFS= read -r u; do
        [ -z "$u" ] && [ "$u" = "root" ] && continue
        _user_exists "$u" || continue
        others+="$u "
      done < <(_collect_group_users "$g")
      if [ -n "$others" ]; then
        vuln_found=1
        evidence+="[그룹:${g}] 계정:${others} "
      fi
    done
  fi

  # 2) sudoers 점검
  local idtoken
  while IFS= read -r idtoken; do
    [ -z "$idtoken" ] && continue
    if echo "$idtoken" | grep -q '^%'; then
      local sg="${idtoken#%}"
      if _group_exists "$sg"; then
        local u others=""
        while IFS= read -r u; do
          [ -z "$u" ] && [ "$u" = "root" ] && continue
          _user_exists "$u" || continue
          others+="$u "
        done < <(_collect_group_users "$sg")
        if [ -n "$others" ]; then
          vuln_found=1
          evidence+="[sudo그룹:%${sg}] 계정:${others} "
        fi
      fi
    else
      if _user_exists "$idtoken" && [ "$idtoken" != "root" ]; then
        vuln_found=1
        evidence+="[sudo사용자:${idtoken}] "
      fi
    fi
  done < <(_collect_sudoers_identities)

  # 결과 처리
  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="관리자 권한 범위에 root 외 계정이 포함되어 있습니다. 근거: ${evidence}"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_09() {
  local code="U-09"
  local item="계정이 존재하지 않는 GID 금지"
  local severity="하"
  local status="양호"
  local reason="시스템 관리나 운용에 불필요한 그룹이 존재하지 않습니다."

  # 1. /etc/passwd에서 기본 그룹으로 사용 중인 모든 GID 추출
  local USED_GIDS
  USED_GIDS=$(awk -F: '{print $4}' /etc/passwd | sort -u)

  # 2. 일반 사용자 그룹 범위(GID 1000 이상)만 필터링하여 점검
  local CHECK_GIDS
  CHECK_GIDS=$(awk -F: '$3 >= 1000 {print $3}' /etc/group)
  
  local VULN_GROUPS=""
  for gid in $CHECK_GIDS; do
    # 해당 GID가 /etc/passwd의 기본 그룹으로 사용 중인지 확인
    if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
      # 추가 확인: /etc/group의 4번째 필드(보조 그룹 사용자) 확인
      local MEMBER_EXISTS
      MEMBER_EXISTS=$(grep -w "^[^:]*:[^:]*:$gid:[^:]*" /etc/group | cut -d: -f4)
      
      if [ -z "$MEMBER_EXISTS" ]; then
        local GROUP_NAME
        GROUP_NAME=$(grep -w "^[^:]*:[^:]*:$gid:" /etc/group | cut -d: -f1)
        VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
      fi
    fi
  done

  # 3. 결과 판정
  if [ -n "$VULN_GROUPS" ]; then
    status="취약"
    # 앞뒤 공백 제거 후 사유 입력
    VULN_GROUPS=$(echo "$VULN_GROUPS" | sed 's/^ //')
    reason="계정이 존재하지 않는 불필요한 그룹(GID 1000 이상)이 존재합니다: $VULN_GROUPS"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_10() {
  local code="U-10"
  local item="동일한 UID 금지"
  local severity="중"
  local status="양호"
  local reason="동일한 UID로 설정된 사용자 계정이 존재하지 않습니다."

  if [ -f /etc/passwd ]; then
    # 중복된 UID 값들을 추출 (예: 1001, 1005)
    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | tr '\n' ',' | sed 's/,$//')

    if [ -n "$dup_uids" ]; then
      status="취약"
      reason="동일한 UID를 공유하는 계정들이 존재합니다. 중복된 UID: [$dup_uids]"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_11() {
  local code="U-11"
  local item="사용자 shell 점검"
  local severity="하"
  local status="양호"
  local reason="로그인이 필요하지 않은 모든 계정에 로그인 제한 쉘이 설정되어 있습니다."

  local VULN=0
  local VUL_ACCOUNTS=""

  # 예외 처리 : 쉘 사용 필수 계정
  local EXCEPT_USERS="^(sync|shutdown|halt)$"

  # 1. /etc/passwd 파일 내 시스템 계정들 점검 
  while IFS=: read -r user pass uid gid comment home shell; do 
    # UID 1~999 범위 또는 nobody 계정 확인
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
    status="취약"
    reason="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: [$VUL_ACCOUNTS]"
  fi

  # 4. 결과 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_12() {
  local code="U-12"
  local item="세션 종료 시간 설정"
  local severity="하"
  local status="양호"
  local reason="유휴 세션 종료(TMOUT) 값이 설정되어 있고 권고 기준을 충족합니다."

  local TARGET_TMOUT=600
  local vuln=0
  local found=()

  # 1. 점검 대상 파일 수집
  local files=("/etc/profile" "/etc/bashrc" "/etc/profile.d" "/etc/csh.cshrc" "/etc/csh.login")
  local f
  
  for f in "${files[@]}"; do
    if [[ -d "$f" ]]; then
      while IFS= read -r -d '' x; do
        files+=("$x")
      done < <(find "$f" -maxdepth 1 -type f -name "*.sh" -print0 2>/dev/null)
    fi
  done

  # 2. TMOUT 값 추출
  for f in "${files[@]}"; do
    [[ -r "$f" && -f "$f" ]] || continue
    local tm
    tm="$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null \
        | sed 's/#.*$//' | tail -n 1 \
        | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
    
    if [[ "$tm" =~ ^[0-9]+$ ]]; then
      found+=("$f:$tm")
    fi
  done

  # 3. 판정 로직 (제시된 로직 유지)
  if (( ${#found[@]} == 0 )); then
    vuln=1
    reason="TMOUT 설정을 전역 설정 파일에서 찾지 못했습니다."
  else
    local ok=0
    local has_zero=0
    local found_list=""

    for e in "${found[@]}"; do
      found_list+="$e "
      local val="${e##*:}"

      if [[ "$val" =~ ^[0-9]+$ ]] && (( val == 0 )); then
        has_zero=1
      fi

      if [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 && val <= TARGET_TMOUT )); then
        ok=1
      fi
    done

    if (( has_zero == 1 )); then
      vuln=1
      reason="TMOUT=0 설정이 확인되었습니다(비활성). 발견된 설정: [$found_list]"
    elif (( ok == 0 )); then
      vuln=1
      reason="설정값($found_list)이 기준($TARGET_TMOUT 초 이하)을 충족하지 않습니다."
    else
      reason="TMOUT 설정이 적절합니다. 발견된 설정: [$found_list]"
    fi
  fi

  # 최종 상태 업데이트
  if (( vuln == 1 )); then
    status="취약"
  fi

  # 4. JSON 형식 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_13() {
  local code="U-13"
  local item="안전한 비밀번호 암호화 알고리즘 사용"
  local severity="중"
  local status="양호"
  local reason="안전한 해시 알고리즘(yescrypt, SHA-512, SHA-256)만 사용 중입니다."

  local shadow="/etc/shadow"

  # 0) 파일 접근 가능 여부
  if [ ! -e "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  if [ ! -r "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일을 읽을 수 없습니다. (root 권한 필요)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 1) 계정별 해시 알고리즘 검사
  local vuln_found=0
  local checked=0
  local good_count=0
  local evidence_bad=""
  local evidence_good_sample=""

  while IFS=: read -r user hash rest; do
    [ -z "$user" ] && continue
    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    ((checked++))

    # yescrypt ($y$), SHA-512 ($6$), SHA-256 ($5$)
    if [[ "$hash" == \$y\$* ]]; then
      ((good_count++))
      [[ $(echo "$evidence_good_sample" | wc -w) -lt 5 ]] && evidence_good_sample+="$user:yescrypt "
      continue
    elif [[ "$hash" == \$6\$* ]]; then
      ((good_count++))
      [[ $(echo "$evidence_good_sample" | wc -w) -lt 5 ]] && evidence_good_sample+="$user:sha512 "
      continue
    elif [[ "$hash" == \$5\$* ]]; then
      ((good_count++))
      [[ $(echo "$evidence_good_sample" | wc -w) -lt 5 ]] && evidence_good_sample+="$user:sha256 "
      continue
    fi

    # 취약 케이스
    vuln_found=1
    if [[ "$hash" == \$1\$* ]]; then
      evidence_bad+="$user:MD5(\$1\$) "
    elif [[ "$hash" == \$* ]]; then
      local id_val
      id_val="$(echo "$hash" | awk -F'$' '{print $2}')"
      [ -z "$id_val" ] && id_val="UNKNOWN"
      evidence_bad+="$user:UNKNOWN(\$$id_val\$) "
    else
      evidence_bad+="$user:LEGACY/UNKNOWN_FORMAT "
    fi
  done < "$shadow"

  # 2) 결과 판정 및 출력
  if [ "$checked" -eq 0 ]; then
    status="N/A"
    reason="점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정)"
  elif [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="안전 기준 미달 해시 알고리즘 사용 계정 존재 ($evidence_bad). 총 점검: $checked"
  else
    reason="안전한 해시 알고리즘 사용 중. (총 $checked 개 계정 확인, 샘플: $evidence_good_sample)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_14() {
  local code="U-14"
  local item="root 홈, 패스 디렉터리 권한 및 패스 설정"
  local severity="상"
  local status="양호"
  local reason="PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함되지 않았습니다."

  local VULN_FOUND=0
  local DETAILS=""

  # 1. 런타임 PATH 점검 (현재 실행 환경)
  if echo "$PATH" | grep -qE '^\.:|:.:|^:|::|:$'; then
    VULN_FOUND=1
    DETAILS="[Runtime] 현재 PATH 내 '.' 또는 '::' 발견: $PATH"
  fi

  # 2. Rocky 10 시스템 설정 파일 점검
  if [ $VULN_FOUND -eq 0 ]; then
    local path_settings_files=("/etc/profile" "/etc/bashrc" "/etc/environment")
    # profile.d 내의 모든 쉘 스크립트 추가 점검
    for file in "${path_settings_files[@]}" /etc/profile.d/*.sh; do
      if [ -f "$file" ]; then
        local VULN_LINE
        VULN_LINE=$(grep -vE '^#|^\s#' "$file" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$' | tail -n 1)
        if [ -n "$VULN_LINE" ]; then
          VULN_FOUND=1
          DETAILS="[System File] $file: $VULN_LINE"
          break
        fi
      fi
    done
  fi

  # 3. 사용자별 설정 파일 점검
  if [ $VULN_FOUND -eq 0 ]; then
    local user_dot_files=(".bash_profile" ".bashrc" ".shrc")
    local user_homedirs
    user_homedirs=$(awk -F: '$7!="/bin/false" && $7!="/sbin/nologin" {print $6}' /etc/passwd | sort | uniq)

    for dir in $user_homedirs; do
      for dotfile in "${user_dot_files[@]}"; do
        local target="$dir/$dotfile"
        if [ -f "$target" ]; then
          local VULN_LINE
          VULN_LINE=$(grep -vE '^#|^\s#' "$target" | grep 'PATH=' | grep -E '=\.:|=\.|:\.:|::|:$' | tail -n 1)
          if [ -n "$VULN_LINE" ]; then
            VULN_FOUND=1
            DETAILS="[User File] $target: $VULN_LINE"
            break 2
          fi
        fi
      done
    done
  fi

  # 결과 설정 및 출력
  if [ $VULN_FOUND -eq 1 ]; then
    status="취약"
    reason="$DETAILS"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_15() {
  local code="U-15"
  local item="파일 및 디렉터리 소유자 설정"
  local severity="상"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  # 소유자나 그룹이 없는 파일 찾기 (샘플 5개 추출)
  local nouser_list
  nouser_list=$(find / \( -nouser -or -nogroup \) 2>/dev/null | head -n 5 | tr '\n' ',' | sed 's/,$//')

  if [ -n "$nouser_list" ]; then
    status="취약"
    # 발견된 파일 개수 확인
    local total_count
    total_count=$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l)
    reason="소유자나 그룹이 없는 파일이 ${total_count}개 존재합니다. 샘플: [$nouser_list]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_16() {
  local code="U-16"
  local item="/etc/passwd 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하입니다."

  local VULN=0
  local REASON=""
  local FILE="/etc/passwd"

  # 1. /etc/passwd 파일 존재 여부 확인
  if [ -f "$FILE" ]; then
    # 2. 소유자 및 권한 확인
    local OWNER
    local PERMIT
    OWNER=$(stat -c "%U" "$FILE")
    PERMIT=$(stat -c "%a" "$FILE")

    # 3. 취약 여부 판단
    if [ "$OWNER" != "root" ] || [ "$PERMIT" -gt 644 ]; then
      VULN=1
      if [ "$OWNER" != "root" ]; then
        REASON="파일의 소유자가 root가 아닙니다 (현재: $OWNER)."
      fi
      if [ "$PERMIT" -gt 644 ]; then
        [ -n "$REASON" ] && REASON="$REASON / "
        REASON="${REASON}권한이 644보다 높습니다 (현재: $PERMIT)."
      fi
    fi
  else
    VULN=1
    REASON="$FILE 파일이 존재하지 않습니다."
  fi

  # 4. 결과 설정 및 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_17() {
  local code="U-17"
  local item="시스템 시작 스크립트 권한 설정"
  local severity="중"
  local status="양호"
  local reason="시스템 시작 스크립트 및 서비스 유닛 파일의 소유자 및 권한 설정이 적절합니다."

  local vuln=0
  local offenders=()

  # 내부 헬퍼 함수: 권한 및 소유자 점검
  check_path_perm() {
    local path="$1"
    [[ -e "$path" ]] || return 0

    local owner perm
    owner="$(stat -Lc '%U' "$path" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$path" 2>/dev/null)"

    # 1. 소유자가 root가 아닌 경우
    if [[ "$owner" != "root" ]]; then
      offenders+=("$path(소유자:$owner)")
      return 0
    fi

    # 2. Group 또는 Other에게 쓰기 권한(2)이 있는 경우 (8진수 비트 연산)
    local mode
    mode="$(stat -Lc '%a' "$path" 2>/dev/null)"
    [[ "$mode" =~ ^[0-9]+$ ]] || return 0

    local oct="0$mode"
    if (( (oct & 022) != 0 )); then
      offenders+=("$path(권한:$perm)")
    fi
  }

  # 점검 대상 경로
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

  # 결과 판정 및 JSON 출력 데이터 생성
  if (( ${#offenders[@]} > 0 )); then
    vuln=1
    status="취약"
    local list_str
    list_str=$(printf "%s, " "${offenders[@]}")
    reason="일반 사용자가 수정 가능한 시작 스크립트 발견: [${list_str%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_18() {
  local code="U-18"
  local item="/etc/shadow 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/shadow 파일의 소유자가 root이고, 권한이 400입니다."

  local target="/etc/shadow"

  # 0) 존재/파일 타입 체크
  if [ ! -e "$target" ]; then
    status="N/A"
    reason="$target 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  if [ ! -f "$target" ]; then
    status="N/A"
    reason="$target 가 일반 파일이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 1) 소유자/권한 읽기
  local owner perm
  owner="$(stat -c '%U' "$target" 2>/dev/null)"
  perm="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    status="N/A"
    reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2) 소유자 체크
  if [ "$owner" != "root" ]; then
    status="취약"
    reason="$target 파일의 소유자가 root가 아닙니다. (현재 소유자: $owner)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3) 권한 정규화
  if [[ "$perm" =~ ^[0-7]{4}$ ]]; then
    perm="${perm:1:3}"
  elif [[ "$perm" =~ ^[0-7]{1,3}$ ]]; then
    perm="$(printf "%03d" "$perm")"
  fi

  # 형식 검증
  if ! [[ "$perm" =~ ^[0-7]{3}$ ]]; then
    status="N/A"
    reason="$target 파일 권한 형식이 예상과 다릅니다. (표기: $perm)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 4) 핵심 기준 판정
  if [ "$perm" != "400" ]; then
    status="취약"
    reason="$target 파일 권한이 400이 아닙니다. (현재 권한: $perm)"
  else
    status="양호"
    reason="$target 소유자(root) 및 권한($perm)이 기준(400)을 만족합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_19() {
  local code="U-19"
  local item="/etc/hosts 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하입니다."

  local VULN_FOUND=0
  local DETAILS=""

  # 1. 파일 존재 여부 확인
  if [ -f "/etc/hosts" ]; then
    # [Step 2] 소유자 확인 (UID 확인)
    local FILE_OWNER_UID=$(stat -c "%u" /etc/hosts)
    local FILE_OWNER_NAME=$(stat -c "%U" /etc/hosts)
    
    # [Step 3] 권한 확인 (8진수 형태)
    local FILE_PERM=$(stat -c "%a" /etc/hosts)
    
    # 8진수 권한을 각 자리수별로 분리
    local USER_PERM=${FILE_PERM:0:1}
    local GROUP_PERM=${FILE_PERM:1:1}
    local OTHER_PERM=${FILE_PERM:2:1}

    # 판단 로직: 소유자가 root(UID 0)가 아니거나 권한이 644보다 큰 경우
    if [ "$FILE_OWNER_UID" -ne 0 ]; then
      VULN_FOUND=1
      DETAILS="소유자가 root가 아님 (현재: $FILE_OWNER_NAME)"
    elif [ "$USER_PERM" -gt 6 ] || [ "$GROUP_PERM" -gt 4 ] || [ "$OTHER_PERM" -gt 4 ]; then
      VULN_FOUND=1
      DETAILS="권한이 644보다 큼 (현재: $FILE_PERM)"
    fi
  else
    status="N/A"
    reason="/etc/hosts 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 최종 결과 설정
  if [ "$VULN_FOUND" -eq 1 ]; then
    status="취약"
    reason="$DETAILS"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_20() {
  local code="U-20"
  local item="systemd *.socket, *.service 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="systemd 서비스 및 소켓 파일의 소유자가 root이고 권한이 644 이하입니다."

  local offenders=()
  local file_exists_count=0
  local check_dirs=("/usr/lib/systemd/system" "/etc/systemd/system")

  for dir in "${check_dirs[@]}"; do
    if [ -d "$dir" ]; then
      # 유닛 파일 검색 (공백 포함 파일명을 대비해 while read 사용)
      while IFS= read -r file; do
        [ -z "$file" ] && continue
        ((file_exists_count++))

        local owner
        local perm
        owner=$(stat -c %U "$file" 2>/dev/null)
        perm=$(stat -c %a "$file" 2>/dev/null)

        # 소유자 root 체크 및 권한 644 이하 체크
        if [ "$owner" != "root" ]; then
          offenders+=("$file(소유자:$owner)")
        elif [ "$perm" -gt 644 ]; then
          offenders+=("$file(권한:$perm)")
        fi
      done < <(find "$dir" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null)
    fi
  done

  # 결과 판정
  if [ "$file_exists_count" -eq 0 ]; then
    status="N/A"
    reason="점검 대상인 systemd socket/service 파일이 존재하지 않습니다."
  elif [ ${#offenders[@]} -gt 0 ]; then
    status="취약"
    # 취약 파일이 너무 많을 수 있으므로 최대 5개만 샘플로 출력
    local sample_count=5
    local sample_str
    sample_str=$(printf "%s, " "${offenders[@]:0:$sample_count}")
    reason="부적절한 권한/소유자의 유닛 파일이 존재합니다(총 ${#offenders[@]}건). 샘플: [${sample_str%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_21() {
  local code="U-21"
  local item="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason=""

  local target=""
  # 1. rsyslog.conf 또는 syslog.conf 파일 존재 여부 확인
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else
    status="N/A"
    reason="/etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. 파일의 소유자 및 권한 확인
  local OWNER PERMIT
  OWNER="$(stat -c '%U' "$target" 2>/dev/null)"
  PERMIT="$(stat -c '%a' "$target" 2>/dev/null)"

  # 정보 못 읽어올 때 처리
  if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
    status="N/A"
    reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3. 소유자 및 권한 판단 로직
  local vuln_found=0
  if [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
    vuln_found=1
    reason="$target 파일의 소유자가 부적절합니다 (현재: $OWNER)."
  elif [ "$PERMIT" -gt 640 ]; then
    vuln_found=1
    reason="$target 파일의 권한이 640을 초과합니다 (현재: $PERMIT)."
  else
    reason="$target 파일의 소유자($OWNER) 및 권한($PERMIT) 설정이 적절합니다."
  fi

  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_22() {
  local code="U-22"
  local item="/etc/services 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/services 파일 소유자가 root이고, 권한 설정이 적절합니다."

  local vuln=0
  local f="/etc/services"
  local details=""

  if [[ ! -e "$f" ]]; then
    status="취약"
    reason="/etc/services 파일이 존재하지 않습니다."
  else
    local owner group perm
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    group="$(stat -Lc '%G' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"

    # 소유자 체크
    if [[ "$owner" != "root" ]]; then
      vuln=1
      details="소유자가 root가 아님(현재: $owner) "
    fi

    # 권한 체크 (그룹/기타 쓰기 권한 022 비트 마스크 확인)
    local oct="0$perm"
    if (( (oct & 18) != 0 )); then
      vuln=1
      details+="그룹 또는 기타 사용자 쓰기 권한 존재(현재: $perm)"
    fi

    if [[ "$vuln" -eq 1 ]]; then
      status="취약"
      reason="$details"
    else
      reason="/etc/services 소유자(root) 및 권한($perm) 설정이 양호합니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_23() {
  local code="U-23"
  local item="SUID, SGID, Sticky bit 설정 파일 점검"
  local severity="상"
  local status="양호"
  local reason="불필요하거나 비정상 경로에 SUID/SGID 설정 파일이 존재하지 않습니다."

  local SEARCH_ROOT="/"
  local MAX_EVIDENCE=5  # JSON 가독성을 위해 샘플 개수 제한
  local vuln_found=0
  local evidence_vuln=""
  local count_v=0

  # 배포판 기본 허용 목록
  local whitelist=(
    "/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/newgrp"
    "/usr/bin/gpasswd" "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/mount"
    "/usr/bin/umount" "/usr/bin/crontab" "/usr/sbin/unix_chkpwd"
    "/usr/sbin/pam_timestamp_check" "/usr/libexec/utempter/utempter"
    "/usr/sbin/mount.nfs"
  )

  _is_whitelisted() {
    local f="$1" w
    for w in "${whitelist[@]}"; do
      [ "$f" = "$w" ] && return 0
    done
    return 1
  }

  _is_bad_path() {
    local f="$1"
    case "$f" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/run/user/*) return 0 ;;
    esac
    return 1
  }

  # 1) SUID/SGID 파일 탐색
  while IFS= read -r f; do
    [ -f "$f" ] || continue

    local mode owner group
    mode="$(stat -c '%a' "$f" 2>/dev/null)"
    owner="$(stat -c '%U' "$f" 2>/dev/null)"
    group="$(stat -c '%G' "$f" 2>/dev/null)"

    # 1-A) 비정상 경로 확인
    if _is_bad_path "$f"; then
      vuln_found=1
      if (( count_v < MAX_EVIDENCE )); then
        evidence_vuln+="$f(비정상경로), "
        ((count_v++))
      fi
      continue
    fi

    # 1-B) 화이트리스트 통과
    _is_whitelisted "$f" && continue

    # 1-C) 패키지 소유 여부 확인 (RPM 미소유 시 취약)
    if command -v rpm >/dev/null 2>&1; then
      if ! rpm -qf "$f" >/dev/null 2>&1; then
        vuln_found=1
        if (( count_v < MAX_EVIDENCE )); then
          evidence_vuln+="$f(패키지미소유), "
          ((count_v++))
        fi
        continue
      fi
    fi
  done < <(find "$SEARCH_ROOT" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

  # 2) Sticky bit 정보 수집 (참고용)
  local tmpperm
  tmpperm="$(stat -c '%a' /tmp 2>/dev/null)"

  # 3) 최종 결과 설정
  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="비정상 경로 또는 패키지 미소유 SUID/SGID 파일 존재: [${evidence_vuln%, }]"
  else
    reason="안전한 경로 내 패키지 소유 SUID/SGID 파일만 확인되었습니다. (/tmp 권한: $tmpperm)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_24() {
  local code="U-24"
  local item="사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="홈 디렉터리 환경변수 파일의 소유자가 적절하고 쓰기 권한이 통제되어 있습니다."

  local VULN=0
  local REASON_LIST=""
  
  # 1. 점검 대상 환경 파일 지정
  local CHECK_FILES=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout" ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts")
  
  # 2. 로그인 가능한 사용자 추출
  local USER_LIST
  USER_LIST=$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd)
  
  for USER_INFO in $USER_LIST; do
    local USER_NAME=$(echo "$USER_INFO" | cut -d: -f1)
    local USER_HOME=$(echo "$USER_INFO" | cut -d: -f2)
    
    if [ -d "$USER_HOME" ]; then
      for FILE in "${CHECK_FILES[@]}"; do
        local TARGET="$USER_HOME/$FILE"
        
        if [ -f "$TARGET" ]; then
          # 3. 소유자 확인
          local FILE_OWNER
          FILE_OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)
          
          if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
            VULN=1
            REASON_LIST+="${TARGET}(소유자:${FILE_OWNER}), "
          fi
          
          # 4. 권한 확인 (그룹 또는 기타 사용자 쓰기 권한 체크)
          local PERM_OCT
          PERM_OCT=$(stat -c "%a" "$TARGET" 2>/dev/null)
          
          # 8진수 권한 중 2번째(그룹) 또는 3번째(기타) 자리에 2, 3, 6, 7(쓰기 포함 권한)이 있는지 확인
          if [[ "$PERM_OCT" =~ .[2367]. ]] || [[ "$PERM_OCT" =~ ..[2367] ]]; then
            VULN=1
            REASON_LIST+="${TARGET}(권한:${PERM_OCT}), "
          fi
        fi
      done
    fi
  done
  
  # 5. 결과 설정 및 출력
  if [ $VULN -eq 1 ]; then
    status="취약"
    # 마지막 쉼표와 공백 제거
    reason="부적절한 소유자 또는 권한이 설정된 환경파일 존재: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local severity="상"
  local status="양호"
  local reason="시스템 내 world writable 파일이 존재하지 않습니다."

  # World Writable 파일 탐색 (기타 사용자에게 쓰기 권한이 있는 일반 파일)
  local ww_files
  ww_files=$(find / -type f -perm -2 2>/dev/null | head -n 5 | tr '\n' ',' | sed 's/,$//')

  if [ -n "$ww_files" ]; then
    status="취약"
    local total_count
    total_count=$(find / -type f -perm -2 2>/dev/null | wc -l)
    reason="world writable 설정이 되어 있는 파일이 ${total_count}개 존재합니다. 샘플: [$ww_files]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_26() {
  local code="U-26"
  local item="/dev에 존재하지 않는 device 파일 점검"
  local severity="상"
  local status="양호"
  local reason="/dev 디렉터리에 비정상적인 device 파일이 존재하지 않습니다."

  local target_dir="/dev"
  local VULN=0
  local REASON=""

  # 1. /dev 디렉터리 존재 여부 체크
  if [ ! -d "$target_dir" ]; then
    status="N/A"
    reason="$target_dir 디렉터리가 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. /dev 내 일반 파일(type f) 검색 (mqueue, shm 제외)
  local VUL_FILES
  VUL_FILES=$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null | tr '\n' ',' | sed 's/,$//')

  if [ -n "$VUL_FILES" ]; then
    VULN=1
    status="취약"
    reason="/dev 내부에 비정상적인 일반 파일이 발견되었습니다: [$VUL_FILES]"
  fi

  # 3. 결과 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_27() {
  local code="U-27"
  local item=".rhosts, hosts.equiv 사용 금지"
  local severity="상"
  local status="양호"
  local reason="/etc/hosts.equiv 및 .rhosts 파일이 존재하지 않습니다."

  local vuln=0
  local found=()

  # 1. /etc/hosts.equiv 점검
  if [[ -e /etc/hosts.equiv ]]; then
    found+=("/etc/hosts.equiv")
    vuln=1
  fi

  # 2. .rhosts 점검 (대표 경로 탐색)
  local rh
  for rh in /root/.rhosts /home/*/.rhosts; do
    [[ -e "$rh" ]] || continue
    found+=("$rh")
    vuln=1
  done

  # 3. 결과 판정 및 사유 작성
  if (( vuln == 1 )); then
    status="취약"
    local list_str
    list_str=$(printf "%s, " "${found[@]}")
    reason="보안에 취약한 설정 파일이 발견되었습니다: [${list_str%, }]"
    
    # 비주석 설정 존재 여부 추가 확인 (첫 번째 발견 파일 기준 샘플링)
    for f in "${found[@]}"; do
      if [[ -r "$f" ]]; then
        local non_comment
        non_comment="$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | head -n 1)"
        if [[ -n "$non_comment" ]]; then
          reason="$reason (일부 파일에 활성화된 설정값 존재)"
          break
        fi
      fi
    done
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_28() {
  local code="U-28"
  local item="접속 IP 및 포트 제한"
  local severity="상"
  local status="취약"
  local reason="SSH 또는 방화벽에서 접속 IP/대역 제한 정책이 확인되지 않습니다."

  local sshd_cfg="/etc/ssh/sshd_config"
  local sshd_dropin_dir="/etc/ssh/sshd_config.d"
  local good=0
  local evidence=""

  # Helper 함수: 주석 제외 검색
  _norm_grep() {
    local f="$1" r="$2"
    [ -f "$f" ] || return 1
    grep -Eiv '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ei "$r" >/dev/null 2>&1
  }

  _list_cfg_files() {
    echo "$sshd_cfg"
    if [ -d "$sshd_dropin_dir" ]; then
      ls -1 "$sshd_dropin_dir"/*.conf 2>/dev/null | sort
    fi
  }

  # 1) SSH 설정 기반 제한 정책 확인
  local f
  local ssh_policy_hit=0
  for f in $(_list_cfg_files); do
    [ -f "$f" ] || continue
    if _norm_grep "$f" '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD:Allow/Deny] "
    fi
    if _norm_grep "$f" '^[[:space:]]*Match[[:space:]]+Address[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD:MatchAddress] "
    fi
    if _norm_grep "$f" '^[[:space:]]*ListenAddress[[:space:]]+'; then
      ssh_policy_hit=1
      evidence+="[SSHD:ListenAddress] "
    fi
  done

  if [ "$ssh_policy_hit" -eq 1 ]; then good=1; fi

  # 2) Firewalld 기반 제한 정책 확인
  local fw_hit=0
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    local zones z
    zones="$(firewall-cmd --get-active-zones 2>/dev/null)"
    while read -r z rest; do
      [ -z "$z" ] || echo "$z" | grep -q ':' && continue
      local rr
      rr="$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null)"
      if echo "$rr" | grep -Eqi 'source[[:space:]]+address=.+(service[[:space:]]+name="ssh"|port[[:space:]]+port="22")'; then
        fw_hit=1
        evidence+="[FW:RichRule] "
        break
      fi
    done <<< "$zones"

    if [ "$fw_hit" -eq 0 ]; then
      local zlist
      zlist="$(firewall-cmd --get-zones 2>/dev/null)"
      for z in $zlist; do
        local srcs svc ports
        srcs="$(firewall-cmd --zone="$z" --list-sources 2>/dev/null)"
        svc="$(firewall-cmd --zone="$z" --list-services 2>/dev/null)"
        ports="$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)"
        if [ -n "$srcs" ] && (echo "$svc" | grep -qw ssh || echo "$ports" | grep -Eq '(^|[[:space:]])22/tcp([[:space:]]|$)'); then
          fw_hit=1
          evidence+="[FW:ZoneSource] "
          break
        fi
      done
    fi
  fi

  if [ "$fw_hit" -eq 1 ]; then good=1; fi

  # 최종 판정 및 JSON 출력
  if [ "$good" -eq 1 ]; then
    status="양호"
    reason="접속 IP/대역 제한 정책이 확인되었습니다. 근거: ${evidence% }"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_29() {
  local code="U-29"
  local item="hosts.lpd 파일 소유자 및 권한 설정"
  local severity="하"
  local status="양호"
  local reason="/etc/hosts.lpd 파일이 존재하지 않아 양호합니다."

  local VULN=0
  local REASON=""
  local TARGET="/etc/hosts.lpd"

  # 1. /etc/hosts.lpd 파일 존재 여부 확인
  if [ -f "$TARGET" ]; then
    local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)
    local PERMIT=$(stat -c "%a" "$TARGET" 2>/dev/null)

    # 2. 파일 소유자 확인
    if [ "$OWNER" != "root" ]; then
      VULN=1
      REASON="파일의 소유자가 root가 아닙니다(현재: $OWNER). "
    fi

    # 3. 파일 권한 체크
    if [ "$PERMIT" -gt 600 ]; then
      VULN=1
      [ -n "$REASON" ] && REASON+="/ "
      REASON="${REASON}파일 권한이 600을 초과합니다(현재: $PERMIT)."
    fi

    # 파일은 존재하지만 위반 사항이 없는 경우
    if [ $VULN -eq 0 ]; then
      reason="/etc/hosts.lpd 파일의 소유자(root) 및 권한($PERMIT) 설정이 적절합니다."
    else
      status="취약"
      reason="$REASON"
    fi
  fi

  # 4. 결과 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local severity="중"
  local status="양호"
  local reason="UMASK 값이 022 이상으로 적절하게 설정되어 있습니다."

  local vuln_flag=0
  local details=""

  # 1. systemd 서비스별 UMask 점검
  # 모든 서비스를 전수조사하되, 첫 번째 취약점 발견 시 효율을 위해 중단합니다.
  local services
  services=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')

  for svc in $services; do
    local umask_val
    umask_val=$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')
    
    # 설정이 없거나 기본값(0000)인 경우 점검 건너뜀
    [ -z "$umask_val" ] || [ "$umask_val" == "0000" ] && continue

    # 8진수 비교 (022 미만인 경우 취약)
    if [ $((8#$umask_val)) -lt $((8#022)) ]; then
      vuln_flag=1
      details="systemd 서비스 [$svc]의 UMask($umask_val)가 022 미만입니다."
      break
    fi
  done

  # 2. 글로벌 설정 점검 (서비스 단에서 취약점이 발견되지 않은 경우)
  if [ "$vuln_flag" -eq 0 ]; then
    # pam_umask.so 적용 여부 확인
    if grep -rq "pam_umask.so" /etc/pam.d/ 2>/dev/null; then
      local login_umask
      login_umask=$(grep -E "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')

      if [ -z "$login_umask" ]; then
        vuln_flag=1
        details="/etc/login.defs 파일에 UMASK 설정이 존재하지 않습니다."
      elif [ $((8#$login_umask)) -lt $((8#022)) ]; then
        vuln_flag=1
        details="/etc/login.defs의 UMASK 값($login_umask)이 022 미만입니다."
      fi
    else
      # pam_umask가 명시적으로 설정되지 않은 경우를 취약으로 판단하는 기존 로직 유지
      vuln_flag=1
      details="PAM 설정(/etc/pam.d/)에 pam_umask.so 모듈이 확인되지 않습니다."
    fi
  fi

  # 최종 결과 판정 및 JSON 출력
  if [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    reason="$details"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_31() {
  local code="U-31"
  local item="홈 디렉토리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="모든 사용자의 홈 디렉토리 소유자 설정 및 권한(타인 쓰기 제한)이 적절합니다."

  local VULN=0
  local REASON_LIST=""

  # 1. /etc/passwd에서 일반 사용자 계정 추출 (UID 1000 이상, 로그인 가능 계정)
  local USER_LIST
  USER_LIST=$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd)

  for USER in $USER_LIST; do
    local USERNAME=$(echo "$USER" | cut -d: -f1)
    local HOMEDIR=$(echo "$USER" | cut -d: -f2)

    # 2. 홈 디렉토리 실재 여부 확인
    if [ -d "$HOMEDIR" ]; then
      local OWNER=$(stat -c '%U' "$HOMEDIR" 2>/dev/null)
      local PERMIT=$(stat -c '%a' "$HOMEDIR" 2>/dev/null)
      # 타인(Others) 권한 비트 추출
      local OTHERS_PERMIT="${PERMIT: -1}"

      # 3. 소유자 일치 여부 및 타인 쓰기 권한(2, 3, 6, 7) 체크
      local issue=""
      if [ "$OWNER" != "$USERNAME" ]; then
        issue="소유자불일치($OWNER)"
      fi

      if [[ "$OTHERS_PERMIT" =~ [2367] ]]; then
        [ -n "$issue" ] && issue+="/"
        issue+="타인쓰기권한($PERMIT)"
      fi

      if [ -n "$issue" ]; then
        VULN=1
        REASON_LIST+="$USERNAME:$issue, "
      fi
    else
      # 홈 디렉터리 부재는 운영상 점검 필요 항목
      VULN=1
      REASON_LIST+="$USERNAME:디렉터리없음, "
    fi
  done

  # 4. 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="일부 홈 디렉토리 설정이 부적절합니다: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_32() {
  local code="U-32"
  local item="홈 디렉터리로 지정한 디렉터리의 존재 관리"
  local severity="하"
  local status="양호"
  local reason="로그인 가능한 모든 계정의 홈 디렉터리가 정상적으로 존재합니다."

  local vuln=0
  local missing=()

  # 1. /etc/passwd를 순회하며 홈 디렉터리 존재 여부 체크
  while IFS=: read -r user pass uid gid comment home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue

    # 로그인 차단 쉘 계정은 점검 제외
    case "$shell" in
      */nologin|*/false) continue ;;
    esac

    # 홈 디렉터리 경로가 비어있거나, 루트(/)로 설정된 경우, 또는 실제 디렉터리가 없는 경우
    if [[ -z "$home" || "$home" == "/" ]]; then
      missing+=("$user(path:$home)")
      vuln=1
    elif [[ ! -d "$home" ]]; then
      missing+=("$user(missing)")
      vuln=1
    fi
  done < /etc/passwd

  # 2. 결과 판정 및 JSON 출력
  if (( vuln == 1 )); then
    status="취약"
    local list_str
    list_str=$(printf "%s, " "${missing[@]}")
    reason="홈 디렉터리가 없거나 부적절하게 지정된 계정 발견: [${list_str%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_33() {
  local code="U-33"
  local item="숨겨진 파일 및 디렉토리 검색 및 제거"
  local severity="하"
  local status="양호"
  local reason="의심스러운 숨겨진 파일이 발견되지 않았습니다."

  local SUS_HIDDEN_FILES=""
  local SUS_COUNT=0

  # 1. 의심 징후 숨김파일 탐색
  # 기준: 실행 가능 / SUID / SGID / 최근 7일 내 변경된 숨김 파일
  # 시스템 부하를 고려하여 주요 경로(/proc, /sys 등)는 제외
  SUS_HIDDEN_FILES=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" -type f \
    \( -executable -o -perm -4000 -o -perm -2000 -o -mtime -7 \) \
    -print 2>/dev/null)

  # 2. 개수 계산 및 결과 리스트화
  if [ -n "$SUS_HIDDEN_FILES" ]; then
    SUS_COUNT=$(echo "$SUS_HIDDEN_FILES" | wc -l)
  fi

  # 3. 최종 판정 및 JSON 구성
  if [ "$SUS_COUNT" -gt 0 ]; then
    status="취약"
    # 발견된 파일 중 상위 5개만 샘플로 포함
    local sample
    sample=$(echo "$SUS_HIDDEN_FILES" | head -n 5 | tr '\n' ',' | sed 's/,$//')
    reason="의심 징후(실행권한/최근변경 등)가 있는 숨김 파일이 ${SUS_COUNT}개 발견되었습니다. 샘플: [$sample]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_34() {
  local code="U-34"
  local item="Finger 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="Finger 서비스가 비활성화되어 있습니다."

  local VULN=0
  local REASON_LIST=""

  # 1. finger 서비스 실행 여부 확인 (systemctl)
  local SERVICES=("finger" "fingerd" "in.fingerd" "finger.socket")
  for SVC in "${SERVICES[@]}"; do
    if systemctl is-active "$SVC" >/dev/null 2>&1; then
      VULN=1
      REASON_LIST+="서비스 활성화($SVC), "
    fi
  done

  # 2. finger 프로세스 실행 여부 확인 
  if ps -ef | grep -v grep | grep -Ei "fingerd|in.fingerd" >/dev/null; then
    VULN=1
    REASON_LIST+="프로세스 실행 중, "
  fi

  # 3. finger 포트(79) 리스닝 여부 확인 
  local PORT_CHECK=""
  if command -v ss >/dev/null 2>&1; then
    PORT_CHECK=$(ss -tunlp | grep -w ":79")
  else
    PORT_CHECK=$(netstat -tunlp 2>/dev/null | grep -w ":79")
  fi

  if [ -n "$PORT_CHECK" ]; then
    VULN=1
    REASON_LIST+="79번 포트 리스닝 중, "
  fi

  # 4. 결과 판정 및 JSON 출력
  if [ $VULN -eq 1 ]; then
    status="취약"
    reason="Finger 서비스가 활성화되어 있습니다: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_35() {
  local code="U-35"
  local item="공유 서비스에 대한 익명 접근 제한 설정"
  local severity="상"
  local status="양호"
  local reason="공유 서비스(FTP, NFS, Samba)에서 익명 접근 제한 설정이 적절합니다."

  local vuln_flag=0
  local details=""

  # Helper: 서비스 활성 확인
  is_active_service() { systemctl is-active "$1" >/dev/null 2>&1; }
  # Helper: 포트 리스닝 확인
  is_listening_port() { ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"; }

  # 1. FTP 점검 (vsftpd, proftpd)
  local VSFTPD_FILES=("/etc/vsftpd/vsftpd.conf" "/etc/vsftpd.conf")
  local PROFTPD_FILES=("/etc/proftpd/proftpd.conf" "/etc/proftpd.conf")
  
  # vsftpd 익명 허용 체크
  for conf in "${VSFTPD_FILES[@]}"; do
    if [ -f "$conf" ]; then
      if grep -i '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*yes' "$conf" | grep -v '^[[:space:]]*#' >/dev/null; then
        vuln_flag=1
        details+="FTP 익명 허용($conf), "
      fi
    fi
  done
  
  # proftpd 익명 블록 체크
  for conf in "${PROFTPD_FILES[@]}"; do
    if [ -f "$conf" ]; then
      local block_hit
      block_hit=$(awk '/^[[:space:]]*#/ {next} /<Anonymous[[:space:]>]/ {inblk=1} inblk && /<\/Anonymous>/ {inblk=0} inblk && ($1 ~ /^User$/ || $1 ~ /^UserAlias$/) {hit=1} END{print hit}' "$conf")
      if [ "$block_hit" = "1" ]; then
        vuln_flag=1
        details+="FTP 익명 블록 발견($conf), "
      fi
    fi
  done

  # 2. NFS 점검 (no_root_squash, 전역 공유)
  if [ -f /etc/exports ]; then
    if grep -v '^[[:space:]]*#' /etc/exports | grep -E '(^|[[:space:]\(,])no_root_squash([[:space:]\),]|$)' >/dev/null; then
      vuln_flag=1
      details+="NFS no_root_squash 존재, "
    fi
    if grep -v '^[[:space:]]*#' /etc/exports | grep -E '(^|[[:space:]])\*([[:space:]\(]|$)' >/dev/null; then
      vuln_flag=1
      details+="NFS 전역 호스트(*) 공유 존재, "
    fi
  elif is_active_service nfs-server; then
    vuln_flag=1
    details+="NFS 서비스 구동 중이나 exports 파일 없음, "
  fi

  # 3. Samba 점검 (guest ok, public, security=share 등)
  if [ -f /etc/samba/smb.conf ]; then
    local smb_check
    smb_check=$(grep -v '^[[:space:]]*#' /etc/samba/smb.conf | grep -Ei '^[[:space:]]*(guest[[:space:]]+ok|public|map[[:space:]]+to[[:space:]]+guest|security)[[:space:]]*=[[:space:]]*(yes|share|guest)')
    if [ -n "$smb_check" ]; then
      vuln_flag=1
      details+="Samba 익명/게스트 허용 설정 존재, "
    fi
  elif is_active_service smb; then
    vuln_flag=1
    details+="Samba 서비스 구동 중이나 smb.conf 없음, "
  fi

  # 결과 판정
  if [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    reason="익명 접근이 가능한 공유 설정 발견: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_36() {
  local code="U-36"
  local item="r 계열 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="모든 r 계열 서비스(rsh, rlogin, rexec 등)가 비활성화되어 있습니다."

  local VULN=0
  local REASON_LIST=""

  # 1. r-command 관련 포트 리스닝 확인 (512: rexec, 513: rlogin, 514: rsh)
  local CHECK_PORT
  CHECK_PORT=$(ss -antl 2>/dev/null | grep -E ':512|:513|:514')
  
  if [ -n "$CHECK_PORT" ]; then
    VULN=1
    REASON_LIST+="r-command 포트(512/513/514) 활성화, "
  fi

  # 2. systemctl 서비스 점검
  local SERVICES=("rlogin" "rsh" "rexec" "shell" "login" "exec")
  for SVC in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
      VULN=1
      REASON_LIST+="서비스 구동 중($SVC), "
    fi
  done

  # 3. xinetd 설정 파일 점검
  if [ -d "/etc/xinetd.d" ]; then
    local XINETD_VUL
    XINETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/{rlogin,rsh,rexec,shell,login,exec} 2>/dev/null | tr '\n' ' ')
    if [ -n "$XINETD_VUL" ]; then
      VULN=1
      REASON_LIST+="xinetd 설정 활성($(echo "$XINETD_VUL" | xargs)), "
    fi
  fi

  # 4. 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="활성화된 r 계열 서비스가 존재합니다: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_37() {
  local code="U-37"
  local item="crontab 설정 파일 권한 설정 미흡"
  local severity="상"
  local status="양호"
  local reason="cron 관련 주요 파일 및 디렉터리의 소유자 및 권한 설정이 적절합니다."

  local vuln=0
  local offenders=()

  # 헬퍼 함수: 파일 권한/소유자 점검 (root 소유, Group/Other 쓰기 금지)
  check_file_no_wo() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    local owner perm
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
    local oct="0$perm"
    if [[ "$owner" != "root" ]]; then
      offenders+=("$f(owner:$owner)")
      return 0
    fi
    if (( (oct & 022) != 0 )); then
      offenders+=("$f(perm:$perm)")
    fi
  }

  # 헬퍼 함수: 디렉터리 권한/소유자 점검 (root 소유, Other 쓰기 금지)
  check_dir_no_wo() {
    local d="$1"
    [[ -d "$d" ]] || return 0
    local owner perm
    owner="$(stat -Lc '%U' "$d" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$d" 2>/dev/null)"
    local oct="0$perm"
    if [[ "$owner" != "root" ]]; then
      offenders+=("$d(owner:$owner)")
      return 0
    fi
    if (( (oct & 002) != 0 )); then
      offenders+=("$d(perm:$perm)")
    fi
  }

  # 1. 시스템 cron 설정 파일 점검
  check_file_no_wo "/etc/crontab"
  check_file_no_wo "/etc/anacrontab"
  check_dir_no_wo "/etc/cron.d"
  check_dir_no_wo "/etc/cron.hourly"
  check_dir_no_wo "/etc/cron.daily"
  check_dir_no_wo "/etc/cron.weekly"
  check_dir_no_wo "/etc/cron.monthly"

  # 2. cron 디렉터리 내부 파일들 점검
  local dir
  for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' f; do
      check_file_no_wo "$f"
    done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
  done

  # 3. 사용자 개별 crontab 점검 (/var/spool/cron)
  if [[ -d /var/spool/cron ]]; then
    while IFS= read -r -d '' f; do
      local perm
      perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
      local oct="0$perm"
      # 사용자 파일은 Group/Other 접근 금지(600) 권고
      if (( (oct & 077) != 0 )); then
        offenders+=("$f(perm:$perm)")
      fi
    done < <(find /var/spool/cron -maxdepth 1 -type f -print0 2>/dev/null)
  fi

  # 4. 결과 판정 및 출력
  if (( ${#offenders[@]} > 0 )); then
    status="취약"
    # 결과가 많을 수 있으므로 최대 5개 샘플링
    local sample_str
    sample_str=$(printf "%s, " "${offenders[@]:0:5}")
    reason="cron 설정 소유자/권한 이상 발견(총 ${#offenders[@]}건): [${sample_str%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_38() {
  local code="U-38"
  local item="DoS 공격에 취약한 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="DoS 공격에 취약한 전통 서비스가 비활성화되어 있습니다."

  # ===== 대상 정의 =====
  local inetd_services=("echo" "discard" "daytime" "chargen")
  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")

  local in_scope_used=0
  local vulnerable=0
  local evidence_list=""

  # Helper: 유닛 존재 여부 확인
  _unit_exists() {
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1"
  }

  # Helper: 유닛 활성화 여부 확인
  _unit_enabled_or_active() {
    systemctl is-enabled --quiet "$1" 2>/dev/null && return 0
    systemctl is-active --quiet "$1" 2>/dev/null && return 0
    return 1
  }

  # 1. xinetd 설정 점검 (레거시)
  if [ -d /etc/xinetd.d ]; then
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
        in_scope_used=1
        if ! grep -vE '^\s*#' "/etc/xinetd.d/${svc}" 2>/dev/null | grep -iE '^\s*disable\s*=\s*yes' >/dev/null; then
          vulnerable=1
          evidence_list+="xinetd:${svc}(활성), "
        fi
      fi
    done
  fi

  # 2. inetd.conf 점검
  if [ -f /etc/inetd.conf ]; then
    for svc in "${inetd_services[@]}"; do
      if grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -qw "$svc"; then
        in_scope_used=1
        vulnerable=1
        evidence_list+="inetd:${svc}(활성), "
      fi
    done
  fi

  # 3. systemd socket 점검 (현대적인 방식)
  if command -v systemctl >/dev/null 2>&1; then
    for sock in "${systemd_sockets[@]}"; do
      if _unit_exists "$sock"; then
        in_scope_used=1
        if _unit_enabled_or_active "$sock"; then
          vulnerable=1
          evidence_list+="systemd:${sock}(활성), "
        fi
      fi
    done
  fi

  # 4. 결과 판정
  if [ "$in_scope_used" -eq 0 ]; then
    status="N/A"
    reason="DoS 취약 서비스(echo/discard 등)가 설치되어 있지 않습니다."
  elif [ "$vulnerable" -eq 1 ]; then
    status="취약"
    reason="DoS 공격에 취약한 서비스가 활성화되어 있습니다: [${evidence_list%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_39() {
  local code="U-39"
  local item="불필요한 NFS 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="NFS 관련 서비스 및 프로세스가 비활성화되어 있습니다."

  local found=0
  local details=""

  # 1) systemd 기반 서비스 활성 여부 확인
  if command -v systemctl >/dev/null 2>&1; then
    # Rocky 9/10 표준 NFS 관련 유닛 목록
    local nfs_units=("nfs-server" "rpcbind" "nfs-mountd" "rpc-statd" "rpc-idmapd")

    for u in "${nfs_units[@]}"; do
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        found=1
        details+="$u(active), "
      fi
    done
  fi

  # 2) 프로세스 기반 보조 확인 (커널 스레드 포함)
  if ps -ef | grep -v "grep" | grep -iwE "nfsd|mountd|rpcbind|statd|lockd|idmapd" >/dev/null 2>&1; then
    if [ "$found" -eq 0 ]; then
      found=1
      details="NFS 관련 커널 스레드 또는 프로세스 실행 중"
    fi
  fi

  # 최종 결과 판정 및 JSON 출력
  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="불필요한 NFS 관련 서비스가 구동 중입니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local severity="상"
  local status="양호"
  local reason="NFS 서비스를 사용하지 않거나 접근 제한 설정이 적절합니다."

  local vuln=0
  local details=""

  # 1. NFS 서비스 구동 여부 확인
  if [ $(ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd' | wc -l) -gt 0 ]; then
    
    # 2. /etc/exports 파일 점검
    if [ -f /etc/exports ]; then
      local exports_content=$(grep -vE '^#|^\s#' /etc/interactive /etc/exports | grep '/')
      
      if [ -n "$exports_content" ]; then
        local etc_exports_all_count=$(echo "$exports_content" | grep '*' | wc -l)
        local etc_exports_insecure_count=$(echo "$exports_content" | grep -i 'insecure' | wc -l)
        local etc_exports_directory_count=$(echo "$exports_content" | wc -l)
        local etc_exports_squash_count=$(echo "$exports_content" | grep -iE 'root_squash|all_squash' | wc -l)

        if [ "$etc_exports_all_count" -gt 0 ]; then
          vuln=1
          details="와일드카드(*) 설정 발견"
        elif [ "$etc_exports_insecure_count" -gt 0 ]; then
          vuln=1
          details="'insecure' 옵션 사용 중"
        elif [ "$etc_exports_directory_count" -ne "$etc_exports_squash_count" ]; then
          vuln=1
          details="일부 공유 디렉터리에 squash 옵션 누락"
        fi
      fi
    fi
  fi

  # 최종 결과 판정 및 JSON 출력
  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="NFS 접근 통제 설정이 미흡합니다: [$details]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_41() {
  local code="U-41"
  local item="불필요한 automountd 제거"
  local severity="상"
  local status="양호"
  local reason="automountd(autofs) 서비스가 비활성화되어 있습니다."

  local VULN=0
  local REASON_LIST=""

  # 1. systemctl로 autofs(automountd) 서비스 활성화 여부 확인
  if systemctl is-active --quiet autofs 2>/dev/null; then
    VULN=1
    REASON_LIST+="서비스 활성화(autofs), "
  fi

  # 2. 프로세스 실행 여부 추가 확인 (autofs 유닛 외에 직접 실행된 경우 등)
  if ps -ef | grep -v grep | grep -Ei "automount|autofs" >/dev/null 2>&1; then
    if [ "$VULN" -eq 0 ]; then
      VULN=1
      REASON_LIST+="프로세스 실행 중(automount/autofs), "
    fi
  fi

  # 3. 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="automountd 서비스가 활성화되어 있습니다: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_42() {
  local code="U-42"
  local item="불필요한 RPC 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="rpcbind(RPC) 서비스가 비활성화되어 있습니다."

  local rpc_active=0
  local details=""

  # 1. rpcbind 서비스 및 소켓 활성 여부 확인
  if systemctl is-active rpcbind.service &>/dev/null || systemctl is-active rpcbind.socket &>/dev/null; then
    rpc_active=1
  fi

  # 2. rpcbind가 켜져 있는 경우 상세 점검 및 취약 판정
  if [ "$rpc_active" -eq 1 ]; then
    status="취약"
    details="rpcbind 서비스가 활성(Active) 상태입니다. "

    # 포트 리스닝 확인 (111번 포트)
    if command -v ss &>/dev/null; then
      if ss -tuln 2>/dev/null | grep -qE '(:111\b)'; then
        details+="(111번 포트 리스닝 중) "
      fi
    fi

    # NFS 서버 의존성 참고 (사유 보강)
    if systemctl is-active nfs-server.service &>/dev/null; then
      details+="[참고: nfs-server 활성 상태]"
    else
      details+="[참고: nfs-server 비활성 상태]"
    fi
    
    reason="$details"
  fi

  # 3. 최종 결과 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_43() {
  local code="U-43"
  local item="NIS, NIS+ 점검"
  local severity="상"
  local status="양호"
  local reason="NIS 서비스를 사용하지 않거나 비활성화되어 있습니다."

  local nis_in_use=0
  local vulnerable=0
  local evidences=()

  # NIS 관련 대표 프로세스 정규식
  local nis_procs_regex='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated'
  # NIS+ 관련 프로세스 정규식 (참고용)
  local nisplus_procs_regex='nisplus|rpc\.nisd|nisd'

  # 1. systemd 유닛 상태 확인 (NIS 핵심 서비스)
  if command -v systemctl >/dev/null 2>&1; then
    local nis_units=("ypserv.service" "ypbind.service" "ypxfrd.service")

    for unit in "${nis_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | grep -qw "$unit"; then
        local s_active=$(systemctl is-active "$unit" 2>/dev/null)
        local s_enabled=$(systemctl is-enabled "$unit" 2>/dev/null)
        
        if [ "$s_active" == "active" ] || [ "$s_enabled" == "enabled" ]; then
          nis_in_use=1
          vulnerable=1
          evidences+=("${unit}(상태:${s_active}/설정:${s_enabled})")
        fi
      fi
    done
  fi

  # 2. 프로세스 실행 여부 확인 (yp* 관련)
  if ps -ef | grep -v grep | grep -qiE "$nis_procs_regex"; then
    nis_in_use=1
    vulnerable=1
    evidences+=("NIS 관련 프로세스 실행 중")
  fi

  # 3. 네트워크 리스닝 확인 (참고용 - RPC 111 포트)
  if ss -lntup 2>/dev/null | grep -Eq ':(111)\b'; then
    evidences+=("RPC(111) 포트 활성화")
  fi

  # 4. NIS+ 감지 (참고용)
  if ps -ef | grep -v grep | grep -qiE "$nisplus_procs_regex"; then
    evidences+=("NIS+ 관련 프로세스 감지")
  fi

  # 5. 최종 판정 로직
  if [ "$nis_in_use" -eq 0 ]; then
    # 사용 흔적이 전혀 없는 경우
    status="N/A"
    reason="NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다."
  elif [ "$vulnerable" -eq 1 ]; then
    # NIS 서비스가 활성화된 경우
    status="취약"
    reason="보안에 취약한 NIS 서비스가 활성화되어 있습니다: [$(IFS=', '; echo "${evidences[*]}")]"
  else
    # 사용 흔적은 있으나 현재 실행/자동실행 상태가 아닌 경우
    reason="NIS 관련 설정은 존재하나 서비스가 비활성화 상태입니다."
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_44() {
  local code="U-44"
  local item="tftp, talk 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="tftp, talk, ntalk 서비스가 비활성화되어 있습니다."

  local VULN=0
  local details=""
  local services=("tftp" "talk" "ntalk")

  # 1) systemd 서비스 체크
  if command -v systemctl >/dev/null 2>&1; then
    for s in "${services[@]}"; do
      # 다양한 유닛 명칭 대응
      local units=("$s" "$s.service" "${s}d" "${s}d.service" "${s}-server" "${s}-server.service" "tftp-server.service" "tftpd.service" "talkd.service")
      for u in "${units[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -qw "$u"; then
          if systemctl is-active --quiet "$u" 2>/dev/null; then
            VULN=1
            details+="$u(활성), "
            break
          fi
        fi
      done
    done
  fi

  # 2) xinetd 설정 체크
  if [ "$VULN" -eq 0 ] && [ -d /etc/xinetd.d ]; then
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        local disable_line
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          VULN=1
          details+="xinetd:$s(활성), "
        fi
      fi
    done
  fi

  # 3) inetd.conf 체크
  if [ "$VULN" -eq 0 ] && [ -f /etc/inetd.conf ]; then
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -Eiq "(^|[[:space:]])$s([[:space:]]|$)"; then
        VULN=1
        details+="inetd:$s(활성), "
      fi
    done
  fi

  # 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="취약한 서비스가 활성화되어 있습니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local severity="상"
  local status="양호"
  local reason="메일 서비스(Sendmail)를 사용하지 않거나 최신 버전(8.18.2)을 사용 중입니다."

  local LATEST_VERSION="8.18.2"
  local is_running=0
  local current_version=""

  # 1. 포트 기반 구동 확인 (SMTP)
  if [ -f /etc/services ]; then
    local smtp_ports
    smtp_ports=($(grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'))
    
    for port in "${smtp_ports[@]}"; do
      if ss -tuln 2>/dev/null | grep -qw ":$port"; then
        is_running=1
        break
      fi
    done
  fi

  # 2. 프로세스 기반 구동 확인 (Sendmail)
  if [ "$is_running" -eq 0 ]; then
    if ps -ef | grep -iE 'sendmail' | grep -v 'grep' >/dev/null 2>&1; then
      is_running=1
    fi
  fi

  # 3. 서비스가 구동 중일 경우 버전 점검
  if [ "$is_running" -eq 1 ]; then
    # RPM 또는 DNF를 통해 설치된 버전 확인
    local rpm_ver
    rpm_ver=$(rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}')
    
    local dnf_ver
    dnf_ver=$(dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}')

    current_version="${rpm_ver:-$dnf_ver}"

    if [ -z "$current_version" ]; then
      # 설치 정보가 없으나 구동 중인 경우 (바이너리 직접 실행 등)
      status="취약"
      reason="메일 서비스가 구동 중이나 패키지 버전을 확인할 수 없습니다."
    elif [[ "$current_version" != "$LATEST_VERSION"* ]]; then
      status="취약"
      reason="메일 서비스 버전이 최신($LATEST_VERSION)이 아닙니다. (현재: $current_version)"
    fi
  fi

  # 4. 결과 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_46() {
  local code="U-46"
  local item="일반 사용자의 메일 서비스 실행 방지"
  local severity="상"
  local status="양호"
  local reason="메일 서비스 큐 실행 제한(restrictqrun)이 설정되어 있습니다."

  local VULN=0
  local REASON=""
  local cf_file="/etc/mail/sendmail.cf"

  # 1. Sendmail 서비스 실행 여부 확인
  if ps -ef | grep -v grep | grep -q "sendmail"; then
    # 2. 설정 파일 존재 여부 및 restrictqrun 옵션 확인
    if [ -f "$cf_file" ]; then
      # PrivacyOptions 설정에서 restrictqrun 문자열이 포함되어 있는지 확인 (주석 제외)
      local check
      check=$(grep -i "^O[[:space:]]*PrivacyOptions" "$cf_file" | grep "restrictqrun")

      if [ -z "$check" ]; then
        VULN=1
        REASON="Sendmail 설정 파일($cf_file)에 restrictqrun 옵션이 누락되었습니다."
      fi
    else
      # 서비스는 실행 중인데 설정 파일이 없는 경우
      VULN=1
      REASON="Sendmail 서비스가 구동 중이나 설정 파일($cf_file)을 찾을 수 없습니다."
    fi
  else
    # 서비스가 실행 중이지 않으면 점검 기준상 양호/해당없음
    reason="Sendmail 서비스가 실행 중이지 않습니다."
  fi

  # 3. 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_47() {
  local code="U-47"
  local item="스팸메일 릴레이 제한"
  local severity="상"
  local status="양호"
  local reason="메일 릴레이 제한 설정이 적절하거나 메일 서비스를 사용하지 않습니다."

  local vuln=0
  local details=""

  # 1) Postfix 점검
  if systemctl is-active postfix.service &>/dev/null || command -v postconf &>/dev/null; then
    if command -v postconf &>/dev/null; then
      local relay_restr recip_restr mynet
      relay_restr="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"
      recip_restr="$(postconf -h smtpd_recipient_restrictions 2>/dev/null)"
      mynet="$(postconf -h mynetworks 2>/dev/null)"

      # 필수 설정(reject_unauth_destination) 포함 여부 확인
      local has_reject=0
      echo "$relay_restr $recip_restr" | grep -q "reject_unauth_destination" && has_reject=1

      # 오픈 네트워크(0.0.0.0/0) 허용 여부 확인
      local net_ok=1
      echo "$mynet" | grep -Eq '0\.0\.0\.0/0|::/0' && net_ok=0

      if (( has_reject == 0 )); then
        vuln=1
        details="Postfix: reject_unauth_destination 설정 누락 "
      fi

      if (( net_ok == 0 )); then
        vuln=1
        details+="Postfix: mynetworks 과다 설정(오픈 릴레이 위험) "
      fi

      if (( vuln == 1 )); then
        status="취약"
        reason="$details"
        printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
        return 0
      fi
    fi
  fi

  # 2) Sendmail 점검 (자동 판정의 복잡성으로 인해 수동 점검 유도)
  if systemctl is-active sendmail.service &>/dev/null || command -v sendmail &>/dev/null; then
    status="수동점검"
    reason="Sendmail 사용 중; /etc/mail/sendmail.cf의 Access 테이블 및 릴레이 설정 수동 확인 필요"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3) 메일 서비스 미사용 시 초기값(양호) 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_48() {
  local code="U-48"
  local item="expn, vrfy 명령어 제한"
  local severity="중"
  local status="양호"
  local reason="메일 서비스를 사용하지 않거나 expn, vrfy 명령어 제한 설정이 적절합니다."

  local mail_in_use=0
  local vulnerable=0
  local details=""

  # MTA 감지 플래그
  local has_sendmail=0
  local has_postfix=0

  # 1. 메일(SMTP) 서비스 사용 여부 판단 (25번 포트 및 프로세스)
  if ss -lnt 2>/dev/null | grep -Eq '(:25)$'; then
    mail_in_use=1
  fi

  if ps -ef | grep -v grep | grep -qiE 'sendmail|postfix|master'; then
    mail_in_use=1
    ps -ef | grep -v grep | grep -qi 'sendmail' && has_sendmail=1
    ps -ef | grep -v grep | grep -qiE 'postfix|master' && has_postfix=1
  fi

  # 2. 미사용 시 N/A 처리
  if [ "$mail_in_use" -eq 0 ]; then
    status="N/A"
    reason="메일(SMTP) 서비스를 사용하고 있지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3. 사용 중일 경우 설정 점검
  # 3-A) Sendmail 점검
  if [ "$has_sendmail" -eq 1 ]; then
    local cf_file=""
    [ -f "/etc/mail/sendmail.cf" ] && cf_file="/etc/mail/sendmail.cf"
    [ -z "$cf_file" ] && [ -f "/etc/sendmail.cf" ] && cf_file="/etc/sendmail.cf"

    if [ -n "$cf_file" ]; then
      local check
      # goaway 옵션이 있거나, noexpn과 novrfy가 모두 있는지 확인
      check=$(grep -vE '^\s*#' "$cf_file" | grep -i 'PrivacyOptions')
      if [[ "$check" =~ "goaway" ]] || ([[ "$check" =~ "noexpn" ]] && [[ "$check" =~ "novrfy" ]]); then
        : # 양호
      else
        vulnerable=1
        details+="Sendmail(PrivacyOptions 제한 미흡), "
      fi
    else
      vulnerable=1
      details+="Sendmail(설정파일 미찾음), "
    fi
  fi

  # 3-B) Postfix 점검
  if [ "$has_postfix" -eq 1 ]; then
    if [ -f /etc/postfix/main.cf ]; then
      if ! grep -vE '^\s*#' /etc/postfix/main.cf | grep -iE '^\s*disable_vrfy_command\s*=\s*yes' >/dev/null; then
        vulnerable=1
        details+="Postfix(disable_vrfy_command 미설정), "
      fi
    else
      vulnerable=1
      details+="Postfix(main.cf 미찾음), "
    fi
  fi

  # 4. 최종 결과 판정
  if [ "$vulnerable" -eq 1 ]; then
    status="취약"
    reason="메일 서비스에서 정보 수집 명령어 제한이 미흡합니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_49() {
  local code="U-49"
  local item="DNS 보안 버전 패치"
  local severity="상"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나 최신 보안 패치가 적용되어 있습니다."

  local named_active=0
  local named_running=0
  local bind_ver="unknown"
  local pending_sec=0

  # 1) DNS 서비스 사용 여부 확인
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet named 2>/dev/null && named_active=1
  fi
  if ps -ef 2>/dev/null | grep -i 'named' | grep -v grep >/dev/null 2>&1; then
    named_running=1
  fi

  # 서비스 미사용 시 즉시 양호 반환
  if [ "$named_active" -eq 0 ] && [ "$named_running" -eq 0 ]; then
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2) BIND 버전 정보 수집
  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  elif command -v rpm >/dev/null 2>&1; then
    bind_ver="$(rpm -q bind 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi
  [ -z "$bind_ver" ] && bind_ver="unknown"

  # 3) 보안 패치 대기 여부 확인 (dnf updateinfo 활용)
  if ! command -v dnf >/dev/null 2>&1; then
    status="취약"
    reason="DNS 서비스 사용 중이나 dnf 부재로 보안 패치 확인 불가(버전: $bind_ver)"
  else
    # bind 관련 보안(security) 업데이트 대기 항목이 있는지 확인
    if dnf -q updateinfo list --updates security 2>/dev/null | grep -Eiq '(^|[[:space:]])bind([[:space:]]|-)'; then
      pending_sec=1
    fi

    if [ "$pending_sec" -eq 1 ]; then
      status="취약"
      reason="BIND 보안 업데이트(Security Patch) 대기 항목이 존재합니다. (현재버전: $bind_ver)"
    else
      reason="DNS 사용 중이며 BIND 관련 보안 패치가 최신 상태입니다. (버전: $bind_ver)"
    fi
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local severity="상"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나 Zone Transfer 제한 설정이 적절합니다."

  local VULN=0
  local reason_detail=""

  # 1. DNS 서비스(named) 구동 여부 확인
  if ps -ef | grep -i 'named' | grep -v 'grep' >/dev/null 2>&1; then
    # 2. 설정 파일 존재 여부 확인
    if [ -f /etc/named.conf ]; then
      # 주석을 제외하고 allow-transfer 설정에 'any'가 포함되어 있는지 확인
      # BIND 주석 형식(#, //, /* */) 중 주요 패턴 대응
      local transfer_any
      transfer_any=$(grep -vE '^[[:space:]]*#|^[[:space:]]*//' /etc/named.conf | grep -i 'allow-transfer' | grep -i 'any')

      if [ -n "$transfer_any" ]; then
        VULN=1
        reason_detail="/etc/named.conf 파일에 allow-transfer { any; } 설정이 존재합니다."
      else
        reason="DNS 서비스 사용 중이며 allow-transfer 설정이 제한되어 있습니다."
      fi
    else
      # 서비스는 구동 중이나 설정 파일을 찾을 수 없는 경우
      VULN=1
      reason_detail="DNS 서비스가 구동 중이나 /etc/named.conf 파일을 찾을 수 없습니다."
    fi
  fi

  # 3. 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$reason_detail"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_51() {
  local code="U-51"
  local item="DNS 서비스의 취약한 동적 업데이트 설정 금지"
  local severity="중"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나 동적 업데이트 제한 설정이 적절합니다."

  local VULN=0
  local REASON_LIST=""

  # 1. DNS 서비스(named) 실행 여부 확인
  if ps -ef | grep -v grep | grep -q "named"; then
    local CONF="/etc/named.conf"
    local CONF_FILES=("$CONF")

    # 2. 포함된 설정 파일(include) 경로 추출
    if [ -f "$CONF" ]; then
      local EXTRACTED_PATHS
      EXTRACTED_PATHS=$(grep -E "^\s*include" "$CONF" | awk -F'"' '{print $2}')

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

    # 3. 확보된 모든 설정 파일 내 allow-update { any; } 점검
    for FILE in "${CONF_FILES[@]}"; do
      if [ -f "$FILE" ]; then
        # 주석을 제외하고 allow-update에 any가 포함된 설정 탐색
        local CHECK
        CHECK=$(grep -vE "^\s*//|^\s*#|^\s*/\*" "$FILE" | grep -i "allow-update" | grep -Ei "any|\{\s*any\s*;\s*\}")
        
        if [ -n "$CHECK" ]; then
          VULN=1
          REASON_LIST+="$(basename "$FILE"), "
        fi
      fi
    done
    
    if [ "$VULN" -eq 0 ]; then
       reason="DNS 서비스 사용 중이며 동적 업데이트가 적절히 제한되어 있습니다."
    fi
  fi

  # 4. 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="다음 설정 파일에서 동적 업데이트가 전체 허용(any)되어 있습니다: [${REASON_LIST%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_52() {
  local code="U-52"
  local item="Telnet 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="Telnet 서비스가 비활성화되어 있습니다."

  local vuln=0
  local details=""

  # 1) 포트 리스닝 확인 (23/tcp)
  local listen23
  listen23=$(ss -lntp 2>/dev/null | grep -w ":23")
  if [ -n "$listen23" ]; then
    vuln=1
    details+="23/tcp 리스닝 중, "
  fi

  # 2) systemd 유닛 상태 확인
  local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
  for u in "${units[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -qw "$u"; then
      if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
        vuln=1
        details+="$u 활성화됨, "
      fi
    fi
  done

  # 3) xinetd 설정 확인
  if [ -f /etc/xinetd.d/telnet ]; then
    local x_check
    x_check=$(grep -i "disable" /etc/xinetd.d/telnet | grep -i "no")
    if [ -n "$x_check" ]; then
      vuln=1
      details+="xinetd telnet 활성(disable=no), "
    fi
  fi

  # 4) inetd 설정 확인
  if [ -f /etc/inetd.conf ]; then
    if grep -Eq '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
      vuln=1
      details+="inetd telnet 설정 존재, "
    fi
  fi

  # 최종 결과 판정 및 JSON 출력
  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="Telnet 서비스 활성화 징후가 발견되었습니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_53() {
  local code="U-53"
  local item="FTP 서비스 정보 노출 제한"
  local severity="하"
  local status="양호"
  local reason="FTP 접속 배너에 노출되는 정보가 없거나 적절히 제한되어 있습니다."

  local VULN=0
  local details=""
  local listen_info=""

  # 1. FTP(21/tcp) 리스닝 여부 확인
  if command -v ss >/dev/null 2>&1; then
    listen_info=$(ss -ltnp 2>/dev/null | grep -w ":21")
  else
    listen_info=$(netstat -ltnp 2>/dev/null | grep -w ":21")
  fi

  if [ -z "$listen_info" ]; then
    status="N/A"
    reason="FTP 서비스(21/tcp)가 리스닝 상태가 아니므로 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. 데몬 식별 및 설정 파일 점검
  local daemon="unknown"
  [[ "$listen_info" =~ "vsftpd" ]] && daemon="vsftpd"
  [[ "$listen_info" =~ "proftpd" ]] && daemon="proftpd"

  if [ "$daemon" = "vsftpd" ]; then
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
      if [ -f "$f" ]; then
        if grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$f" | grep -Eqi '(vsftpd|ftp server|version|[0-9])'; then
          VULN=1
          details+="vsftpd 배너 설정 정보 노출, "
        fi
      fi
    done
  elif [ "$daemon" = "proftpd" ]; then
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
      if [ -f "$f" ]; then
        if grep -E '^[[:space:]]*ServerIdent[[:space:]]+' "$f" | grep -Eqi '(on|version|[0-9])'; then
          VULN=1
          details+="proftpd ServerIdent 노출 설정, "
        fi
      fi
    done
  fi

  # 3. 실제 배너 응답 확인 (nc 또는 bash tcp 활용)
  local banner=""
  if command -v timeout >/dev/null 2>&1; then
    banner=$(timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/21; read -r line <&3; echo "$line"; exec 3<&-' 2>/dev/null)
    if [ -n "$banner" ]; then
      if echo "$banner" | grep -Eqi '(vsftpd|proftpd|pure-?ftpd|version|[0-9]\.[0-9])'; then
        VULN=1
        details+="응답 배너 정보 노출($banner), "
      fi
    fi
  fi

  # 4. 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="FTP 배너를 통해 불필요한 정보가 노출되고 있습니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_54() {
  local code="U-54"
  local item="암호화되지 않는 FTP 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="암호화되지 않은 FTP 서비스가 비활성화되어 있습니다."

  local ftp_active=0
  local details=""

  # 1) vsftpd 활성 여부 확인
  if systemctl list-unit-files 2>/dev/null | grep -q "^vsftpd.service"; then
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
      ftp_active=1
      details+="vsftpd 활성, "
    fi
  fi

  # 2) proftpd 활성 여부 확인
  if systemctl list-unit-files 2>/dev/null | grep -q "^proftpd.service"; then
    if systemctl is-active --quiet proftpd 2>/dev/null; then
      ftp_active=1
      details+="proftpd 활성, "
    fi
  fi

  # 3) xinetd 기반 FTP 확인
  if [ -f /etc/xinetd.d/ftp ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/ftp 2>/dev/null | grep -iq "disable[[:space:]]*=[[:space:]]*no"; then
      ftp_active=1
      details+="xinetd ftp 활성, "
    fi
  fi

  # 4) inetd 기반 FTP 확인
  if [ -f /etc/inetd.conf ]; then
    if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -iq "ftp"; then
      ftp_active=1
      details+="inetd ftp 설정 존재, "
    fi
  fi

  # 최종 판정 및 JSON 출력
  if [ "$ftp_active" -eq 1 ]; then
    status="취약"
    reason="암호화되지 않은 FTP 서비스가 활성화되어 있습니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local severity="중"
  local status="양호"
  local reason="FTP 계정이 존재하지 않거나 로그인 제한 쉘이 설정되어 있습니다."

  local ftp_exist=0
  local ftp_vuln=0
  local vuln_users=""

  # 1. FTP 서비스 설치 여부 확인 (RPM 기준)
  if ! rpm -qa | grep -Eqi 'vsftpd|proftpd'; then
    status="양호"
    reason="FTP 서비스(vsftpd, proftpd)가 설치되어 있지 않습니다."
  else
    # 2. ftp, vsftpd, proftpd 계정 쉘 점검
    local ftp_users=("ftp" "vsftpd" "proftpd")
    for user in "${ftp_users[@]}"; do
      if id "$user" >/dev/null 2>&1; then
        ftp_exist=1
        local user_shell
        user_shell=$(grep "^$user:" /etc/passwd | awk -F: '{print $7}')
        
        # /bin/false 또는 /sbin/nologin 이외의 쉘인 경우 취약
        if [[ "$user_shell" != "/bin/false" && "$user_shell" != "/sbin/nologin" && "$user_shell" != "/usr/sbin/nologin" ]]; then
          ftp_vuln=1
          vuln_users+="$user($user_shell), "
        fi
      fi
    done

    # 3. 결과 판정
    if [[ $ftp_exist -eq 0 ]]; then
      reason="FTP 관련 계정이 시스템에 존재하지 않습니다."
    elif [[ $ftp_vuln -eq 1 ]]; then
      status="취약"
      reason="일부 FTP 계정에 로그인 제한 쉘이 설정되지 않았습니다: [${vuln_users%, }]"
    else
      reason="모든 FTP 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."
    fi
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_56() {
  local code="U-56"
  local item="FTP 서비스 접근 제어 설정"
  local severity="하"
  local status="양호"
  local reason="FTP 서비스를 사용하지 않거나 접근 제어 설정이 적절합니다."

  local VULN=0
  local REASON=""

  # 1. vsftpd 점검
  if ps -ef | grep -v grep | grep -q "vsftpd"; then
    local CONF="/etc/vsftpd/vsftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/vsftpd.conf"

    if [ -f "$CONF" ]; then
      local USERLIST_ENABLE
      USERLIST_ENABLE=$(grep -vE "^\s*#" "$CONF" | grep -i "userlist_enable" | awk -F= '{print $2}' | tr -d ' ' | tr -d '\r')

      if [ "$USERLIST_ENABLE" = "YES" ]; then
        if [ ! -f "/etc/vsftpd/user_list" ] && [ ! -f "/etc/vsftpd.user_list" ]; then
          VULN=1
          REASON="vsftpd(userlist_enable=YES) 사용 중이나 접근 제어 파일(user_list)이 없습니다."
        fi
      else
        if [ ! -f "/etc/vsftpd/ftpusers" ] && [ ! -f "/etc/vsftpd.ftpusers" ] && [ ! -f "/etc/ftpusers" ]; then
          VULN=1
          REASON="vsftpd 사용 중이나 접근 제어 파일(ftpusers)이 없습니다."
        fi
      fi
    else
      VULN=1
      REASON="vsftpd 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다."
    fi

  # 2. proftpd 점검
  elif ps -ef | grep -v grep | grep -q "proftpd"; then
    local CONF="/etc/proftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/proftpd/proftpd.conf"

    if [ -f "$CONF" ]; then
      local U_F_U
      U_F_U=$(grep -vE "^\s*#" "$CONF" | grep -i "UseFtpUsers" | awk '{print $2}' | tr -d '\r')

      if [ -z "$U_F_U" ] || [ "$U_F_U" = "on" ]; then
        if [ ! -f "/etc/ftpusers" ] && [ ! -f "/etc/ftpd/ftpusers" ]; then
          VULN=1
          REASON="proftpd(UseFtpUsers=on) 사용 중이나 접근 제어 파일(ftpusers)이 없습니다."
        fi
      else
        local LIMIT
        LIMIT=$(grep -i "<Limit LOGIN>" "$CONF")
        if [ -z "$LIMIT" ]; then
          VULN=1
          REASON="proftpd(UseFtpUsers=off) 사용 중이나 설정 내 접근 제어(<Limit LOGIN>)가 없습니다."
        fi
      fi
    else
      VULN=1
      REASON="proftpd 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다."
    fi
  fi

  # 3. 최종 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  elif ps -ef | grep -v grep | grep -qE "vsftpd|proftpd"; then
    reason="FTP 서비스 접근 제어 설정이 확인되었습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_57() {
  local code="U-57"
  local item="ftpusers 파일 설정"
  local severity="상"
  local status="양호"
  local reason="FTP 서비스에서 root 계정 접속이 적절히 차단되어 있습니다."

  local vuln=0
  local details=""

  # 1. FTP 서비스 동작 여부 확인
  local ftp_running=0
  for svc in vsftpd.service proftpd.service pure-ftpd.service; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      ftp_running=1
      break
    fi
  done

  # FTP 데몬 미사용 시 양호 반환
  if [ "$ftp_running" -eq 0 ]; then
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "FTP 서비스가 실행 중이지 않아 양호합니다."
    return 0
  fi

  # 2. ftpusers 후보 파일 탐색
  local candidates=("/etc/vsftpd/ftpusers" "/etc/ftpusers" "/etc/vsftpd/user_list")
  local file_found=""
  for f in "${candidates[@]}"; do
    if [ -r "$f" ]; then
      file_found="$f"
      break
    fi
  done

  if [ -z "$file_found" ]; then
    status="취약"
    reason="FTP 접속 차단 설정 파일(ftpusers 등)을 찾을 수 없습니다."
  else
    # 3. 상세 점검 (root 차단 여부, 소유자, 권한)
    local has_root=0
    grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$file_found" && has_root=1

    local owner perm
    owner=$(stat -Lc '%U' "$file_found" 2>/dev/null)
    perm=$(stat -Lc '%a' "$file_found" 2>/dev/null)
    local oct="0$perm"

    # root 계정 차단 여부 확인
    if [ "$has_root" -eq 0 ]; then
      vuln=1
      details+="root 계정 차단 미설정, "
    fi

    # 소유자 확인
    if [ "$owner" != "root" ]; then
      vuln=1
      details+="소유자($owner)가 root가 아님, "
    fi

    # 권한 확인 (Group/Other 쓰기 권한 체크)
    if (( (oct & 022) != 0 )); then
      vuln=1
      details+="그룹/기타 쓰기 권한 존재($perm), "
    fi

    # 결과 판정
    if [ "$vuln" -eq 1 ]; then
      status="취약"
      reason="FTP 차단 설정($file_found) 미흡: [${details%, }]"
    else
      reason="FTP 차단 설정($file_found)에서 root 차단 및 파일 권한 설정이 적절합니다."
    fi
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_58() {
  local code="U-58"
  local item="불필요한 SNMP 서비스 구동 점검"
  local severity="중"
  local status="양호"
  local reason="SNMP 서비스가 비활성화되어 있습니다."

  local found=0
  local details=""

  # 1) systemd 서비스 상태 확인 (snmpd, snmptrapd)
  if command -v systemctl >/dev/null 2>&1; then
    local units=("snmpd.service" "snmptrapd.service")
    for unit in "${units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | grep -qw "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
          found=1
          details+="$unit(활성), "
        fi
      fi
    done
  fi

  # 2) 프로세스 확인 (pgrep 이용)
  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1 || pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
      details+="SNMP 프로세스 실행 중, "
    fi
  fi

  # 3) 네트워크 포트 확인 (UDP 161, 162)
  if [ "$found" -eq 0 ] && command -v ss >/dev/null 2>&1; then
    if ss -lunp 2>/dev/null | grep -Eiq ':(161|162)\b'; then
      found=1
      details+="SNMP 포트(161/162) 리스닝 중, "
    fi
  fi

  # 4) 최종 판정 및 JSON 출력
  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="SNMP 서비스가 구동 중입니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_59() {
  local code="U-59"
  local item="안전한 SNMP 버전 사용"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스를 사용하지 않거나 v3 이상의 안전한 설정을 사용 중입니다."

  local snmp_active=0
  local v1v2_found=0
  local v3_valid=0
  local details=""

  # 1. SNMP 서비스 활성 여부 확인
  if systemctl is-active --quiet snmpd 2>/dev/null; then
    snmp_active=1
  else
    # 서비스 미사용 시 즉시 양호 반환
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. 설정 파일 내 버전 및 보안 설정 점검
  local cfg_files=("/etc/snmp/snmpd.conf" "/var/lib/net-snmp/snmpd.conf")

  for f in "${cfg_files[@]}"; do
    [ ! -f "$f" ] && continue

    # v1, v2c 커뮤니티 설정 탐지 (rocommunity, rwcommunity, com2sec)
    if grep -vE '^[[:space:]]*#' "$f" | grep -Ei 'rocommunity|rwcommunity|com2sec' >/dev/null 2>&1; then
      v1v2_found=1
    fi

    # v3 인증/암호화(authPriv: SHA/AES) 설정 탐지
    # rouser/rwuser 설정과 함께 강력한 암호화 알고리즘이 명시되어 있는지 확인
    if grep -vE '^[[:space:]]*#' "$f" | grep -Ei 'rouser|rwuser|createUser' | grep -Ei 'SHA|AES' >/dev/null 2>&1; then
      v3_valid=1
    fi
  done

  # 3. 최종 판정
  if [ "$v1v2_found" -eq 1 ]; then
    status="취약"
    reason="SNMP v1/v2c 취약 설정(community)이 발견되었습니다."
  elif [ "$v3_valid" -eq 0 ]; then
    status="취약"
    reason="SNMP v3 보안 설정(인증 및 SHA/AES 암호화)이 미흡합니다."
  else
    reason="SNMP v3의 안전한 인증/암호화 설정을 사용 중입니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local severity="중"
  local status="양호"
  local reason="SNMP Community String이 복잡성 기준을 만족합니다."

  local vuln_flag=0
  local community_found=0
  local details=""

  # 1. SNMP 서비스 실행 여부 확인
  if ! ps -ef | grep -v grep | grep -qiE 'snmpd|snmptrapd'; then
    status="양호"
    reason="SNMP 서비스가 실행 중이지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. snmpd.conf 파일 탐색
  local snmpdconf_files=()
  [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
  [ -f /usr/local/etc/snmp/snmpd.conf ] && snmpdconf_files+=("/usr/local/etc/snmp/snmpd.conf")
  
  while IFS= read -r f; do
    snmpdconf_files+=("$f")
  done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null)

  # 중복 제거
  mapfile -t snmpdconf_files < <(printf "%s\n" "${snmpdconf_files[@]}" | sort -u)

  if [ ${#snmpdconf_files[@]} -eq 0 ]; then
    status="취약"
    reason="SNMP 서비스를 사용 중이나 설정 파일(snmpd.conf)을 찾을 수 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3. 복잡성 판단 내부 함수
  is_strong_community() {
    local s="$1"
    s="${s%\"}"; s="${s#\"}" # 따옴표 제거
    s="${s%\'}"; s="${s#\'}"
    
    # 기본값 금지
    if echo "$s" | grep -qiE '^(public|private)$'; then return 1; fi
    
    local len=${#s}
    local has_alpha=0
    local has_digit=0
    local has_special=0
    
    echo "$s" | grep -qE '[A-Za-z]' && has_alpha=1
    echo "$s" | grep -qE '[0-9]' && has_digit=1
    echo "$s" | grep -qE '[^A-Za-z0-9]' && has_special=1
    
    # 기준 1: 영문+숫자 10자 이상
    if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $len -ge 10 ]; then return 0; fi
    # 기준 2: 영문+숫자+특수문자 8자 이상
    if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $has_special -eq 1 ] && [ $len -ge 8 ]; then return 0; fi
    
    return 1
  }

  # 4. 설정 파일 분석
  for file in "${snmpdconf_files[@]}"; do
    # rocommunity, rwcommunity 추출
    while IFS= read -r comm; do
      [ -z "$comm" ] && continue
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
        details+="취약한 스트링 발견($comm), "
      fi
    done < <(grep -vE '^\s*#|^\s*$' "$file" 2>/dev/null | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}')

    # com2sec 추출
    while IFS= read -r comm; do
      [ -z "$comm" ] && continue
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
        details+="com2sec 내 취약한 스트링 발견($comm), "
      fi
    done < <(grep -vE '^\s*#|^\s*$' "$file" 2>/dev/null | awk 'tolower($1)=="com2sec" {print $4}')
  done

  # 5. 최종 결과 도출
  if [ $community_found -eq 0 ]; then
    status="취약"
    reason="SNMP를 사용 중이나 Community String 설정을 확인할 수 없습니다."
  elif [ $vuln_flag -eq 1 ]; then
    status="취약"
    reason="SNMP Community String이 복잡성 기준에 미달합니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_61() {
  local code="U-61"
  local item="SNMP Access Control 설정"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스에 적절한 접근 제어 설정이 되어 있습니다."

  local VULN=0
  local REASON_DETAIL=""

  # 1. SNMP 서비스 프로세스 실행 여부 확인
  if ps -ef | grep -v grep | grep -q "snmpd"; then
    local CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      # 2. com2sec 설정 점검 (Source가 default인 경우)
      local check_com2sec
      check_com2sec=$(grep -vE "^\s*#" "$CONF" | grep -E "^\s*com2sec" | awk '$3=="default" {print $0}')

      # 3. rocommunity/rwcommunity 설정 점검
      local check_comm
      check_comm=$(grep -vE "^\s*#" "$CONF" | grep -Ei "^\s*(ro|rw)community6?|^\s*(ro|rw)user")

      local is_comm_vuln=0
      if [ -n "$check_comm" ]; then
        while read -r line; do
          [ -z "$line" ] && continue
          local comm_str=$(echo "$line" | awk '{print $2}')
          local source_ip=$(echo "$line" | awk '{print $3}')

          # 소스가 default이거나 스트링이 public/private인 경우 취약으로 간주
          if [[ "$source_ip" == "default" ]] || [[ "$comm_str" =~ public|private ]]; then
            is_comm_vuln=1
            break
          fi
        done <<< "$check_comm"
      fi

      # 4. 취약 여부 종합 판단
      if [ -n "$check_com2sec" ] || [ "$is_comm_vuln" -eq 1 ]; then
        VULN=1
        REASON_DETAIL="SNMP 설정 파일($CONF)에 모든 호스트(default) 접근 허용 또는 취약한 스트링 설정이 존재합니다."
      fi
    else
      # 서비스는 실행 중인데 설정 파일이 없는 경우
      VULN=1
      REASON_DETAIL="SNMP 서비스가 실행 중이나 설정 파일($CONF)을 찾을 수 없습니다."
    fi
  else
    # 서비스 미구동 시 양호
    reason="SNMP 서비스가 실행 중이지 않습니다."
  fi

  # 5. 결과 판정 및 JSON 출력
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON_DETAIL"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_62() {
  local code="U-62"
  local item="로그인 시 경고 메시지 설정"
  local severity="중"
  local status="취약"
  local reason="로그인 배너에 비인가 사용 금지 경고 메시지가 설정되어 있지 않습니다."

  local ok=0
  local issue_files=("/etc/issue" "/etc/issue.net")
  local details=""

  # 1) 콘솔 로그인 배너(/etc/issue, /etc/issue.net) 점검
  for f in "${issue_files[@]}"; do
    if [[ -r "$f" ]]; then
      local content
      content="$(grep -vE '^[[:space:]]*$' "$f" 2>/dev/null | head -n 20)"
      if [[ -n "$content" ]]; then
        if echo "$content" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
          ok=1
          details+="배너 확인($f), "
          break
        fi
      fi
    fi
  done

  # 2) SSH Banner 점검 (sshd_config에 설정된 배너 파일 내용 확인)
  if [[ $ok -eq 0 ]] && [[ -r /etc/ssh/sshd_config ]]; then
    local banner_path
    banner_path="$(grep -E '^[[:space:]]*Banner[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n 1)"
    
    if [[ -n "$banner_path" && "$banner_path" != "none" && -r "$banner_path" ]]; then
      local bcontent
      bcontent="$(grep -vE '^[[:space:]]*$' "$banner_path" 2>/dev/null | head -n 20)"
      if [[ -n "$bcontent" ]] && echo "$bcontent" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
        ok=1
        details+="SSH 배너 확인($banner_path)"
      fi
    fi
  fi

  # 최종 결과 판정
  if [[ $ok -eq 1 ]]; then
    status="양호"
    reason="적절한 경고 메시지가 설정되어 있습니다: [${details%, }]"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_63() {
  local code="U-63"
  local item="sudo 명령어 접근 관리"
  local severity="중"
  local status="양호"
  local reason="/etc/sudoers 파일의 소유자 및 권한 설정이 적절합니다."

  local file="/etc/sudoers"

  # 1) /etc/sudoers 존재 여부 확인
  if [ ! -e "$file" ]; then
    status="N/A"
    reason="/etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2) 소유자 및 권한 정보 수집
  local owner perm
  owner=$(stat -c %U "$file" 2>/dev/null)
  perm=$(stat -c %a "$file" 2>/dev/null)

  # stat 실패 시 보조 수단 (ls 활용)
  if [ -z "$owner" ] || [ -z "$perm" ]; then
    owner=$(ls -l "$file" 2>/dev/null | awk '{print $3}')
    status="점검불가"
    reason="/etc/sudoers 권한 정보를 숫자 형태로 확인할 수 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3) 판정 기준: 소유자 root AND 권한 640 (또는 더 엄격한 440 등 포함 여부는 기준에 따름)
  # 요청하신 기준인 '640'을 정확히 체크하되, 통상적인 보안 권한(440)도 고려될 수 있으나 여기서는 요청하신 수치를 우선합니다.
  if [ "$owner" != "root" ] || [ "$perm" != "640" ]; then
    status="취약"
    reason="/etc/sudoers 설정 미흡 (현재 소유자: $owner, 권한: $perm / 기준: root, 640)"
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_64() {
  local code="U-64"
  local item="주기적 보안 패치 및 벤더 권고사항 적용"
  local severity="상"
  local status="양호"
  local reason="보안 패치가 최신 상태이며 최신 커널로 구동 중입니다."

  local running_kernel=$(uname -r)
  local latest_kernel=""
  local pending_updates=""
  local details=""

  # 1. 보안 업데이트 대기 확인 (dnf updateinfo 활용)
  if command -v dnf >/dev/null 2>&1; then
    pending_updates=$(dnf updateinfo list --updates security -q 2>/dev/null | grep -i "security" || true)
  fi

  # 2. 설치된 커널 중 가장 최신 버전 확인
  latest_kernel=$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1)

  # 3. 판정 로직
  if [ -n "$pending_updates" ]; then
    status="취약"
    reason="미적용된 보안 업데이트 항목이 존재합니다."
  elif [ -n "$latest_kernel" ] && [[ "$running_kernel" != *"$latest_kernel"* ]]; then
    # 설치는 되었으나 현재 구동 버전이 낮은 경우 (재부팅 필요)
    status="취약"
    reason="최신 커널 설치 후 재부팅되지 않았습니다. (구동중: $running_kernel / 최신: $latest_kernel)"
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_65() {
  local code="U-65"
  local item="NTP 및 시각 동기화 설정"
  local severity="중"
  local status="양호"
  local reason="NTP 시각 동기화 서비스가 정상적으로 설정 및 동작 중입니다."

  local vuln_flag=0
  local details=""

  # 1. 서비스 활성화 여부 확인 함수
  is_active_service() {
    local svc="$1"
    systemctl list-unit-files 2>/dev/null | grep -qw "${svc}.service" || return 1
    systemctl is-active --quiet "${svc}.service" 2>/dev/null
  }

  # 2. 동기화 방식별 상태 수집
  local timedatectl_ntp=$(timedatectl show -p NTP --value 2>/dev/null | tr -d '\r')
  local time_sync_state=$(timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d '\r')
  
  local timesyncd_active=0
  local chronyd_active=0
  local ntpd_active=0

  is_active_service "systemd-timesyncd" && timesyncd_active=1
  is_active_service "chronyd" && chronyd_active=1
  is_active_service "ntpd" && ntpd_active=1
  [ $ntpd_active -eq 0 ] && is_active_service "ntp" && ntpd_active=1

  # 서비스가 하나도 활성화되지 않은 경우
  if [ $timesyncd_active -eq 0 ] && [ $chronyd_active -eq 0 ] && [ $ntpd_active -eq 0 ] && [ "$timedatectl_ntp" != "yes" ]; then
    status="취약"
    reason="활성화된 시각 동기화 서비스(chronyd, ntpd, timesyncd)가 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 3. 설정 및 동기화 상태 점검
  local server_found=0
  local sync_ok=0

  # [CHRONY 점검]
  if [ $chronyd_active -eq 1 ]; then
    if grep -r -vE '^\s*#|^\s*$' /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony.d /etc/chrony/conf.d 2>/dev/null | grep -qiE '^\s*(server|pool)\s+'; then
      server_found=1
    fi
    if command -v chronyc >/dev/null 2>&1 && chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+'; then
      sync_ok=1
    fi
    details="chronyd"
  fi

  # [NTPD 점검]
  if [ $server_found -eq 0 ] && [ $ntpd_active -eq 1 ]; then
    if grep -r -vE '^\s*#|^\s*$' /etc/ntp.conf /etc/ntp/ntp.conf 2>/dev/null | grep -qiE '^\s*server\s+'; then
      server_found=1
    fi
    if command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | awk 'NR>2{print $1}' | grep -q '^\*'; then
      sync_ok=1
    fi
    details="ntpd"
  fi

  # [TIMESYNCD 점검]
  if [ $server_found -eq 0 ] && { [ $timesyncd_active -eq 1 ] || [ "$timedatectl_ntp" = "yes" ]; }; then
    if grep -r -vE '^\s*#|^\s*$' /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d 2>/dev/null | grep -qiE '^\s*NTP\s*='; then
      server_found=1
    fi
    [ "$time_sync_state" = "yes" ] && sync_ok=1
    details="systemd-timesyncd"
  fi

  # 4. 최종 판정
  if [ $server_found -eq 0 ]; then
    status="취약"
    reason="시각 동기화 서비스($details)는 구동 중이나 서버(NTP Server/Pool) 설정이 없습니다."
  elif [ $sync_ok -eq 0 ]; then
    status="취약"
    reason="NTP 서버 설정은 존재하나, 현재 시각 동기화 상태가 정상이 아닙니다. ($details)"
  else
    reason="정상적으로 시각 동기화가 이루어지고 있습니다. (방식: $details)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_66() {
  local code="U-66"
  local item="정책에 따른 시스템 로깅 설정"
  local severity="중"
  local status="양호"
  local reason="시스템 로깅 설정이 보안 정책에 따라 적절히 설정되어 있습니다."

  local VULN=0
  local REASON_DETAIL=""
  local CONF="/etc/rsyslog.conf"
  local CONF_FILES=("$CONF")

  # 1. rsyslog 프로세스 실행 확인
  if ! ps -ef | grep -v grep | grep -q "rsyslogd"; then
    VULN=1
    REASON_DETAIL="시스템 로그 데몬(rsyslogd)이 실행 중이지 않습니다."
  else
    # 2. 설정 파일 존재 확인
    if [ ! -f "$CONF" ]; then
      VULN=1
      REASON_DETAIL="rsyslog 데몬은 실행 중이나 설정 파일($CONF)을 찾을 수 없습니다."
    else
      # 추가 설정 디렉토리 포함
      if [ -d "/etc/rsyslog.d" ]; then
        # .conf 파일이 있을 경우에만 추가
        local d_files=$(ls /etc/rsyslog.d/*.conf 2>/dev/null)
        [ -n "$d_files" ] && CONF_FILES+=($d_files)
      fi

      local ALL_CONF_CONTENT
      ALL_CONF_CONTENT=$(cat "${CONF_FILES[@]}" 2>/dev/null | grep -vE "^\s*#")

      # 3. 주요 로그 설정 항목 점검
      local CHECK_MSG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.info[[:space:]]+-?/var/log/messages")
      local CHECK_SECURE=$(echo "$ALL_CONF_CONTENT" | grep -E "auth(priv)?\.\*[[:space:]]+-?/var/log/secure")
      local CHECK_MAIL=$(echo "$ALL_CONF_CONTENT" | grep -E "mail\.\*[[:space:]]+-?/var/log/maillog")
      local CHECK_CRON=$(echo "$ALL_CONF_CONTENT" | grep -E "cron\.\*[[:space:]]+-?/var/log/cron")
      local CHECK_ALERT=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.alert[[:space:]]+(/dev/console|:omusrmsg:\*|root)")
      local CHECK_EMERG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.emerg[[:space:]]+(\*|:omusrmsg:\*)")

      # 4. 누락 항목 수집
      local MISSING_LOGS=""
      [ -z "$CHECK_MSG" ] && MISSING_LOGS+="[messages] "
      [ -z "$CHECK_SECURE" ] && MISSING_LOGS+="[secure] "
      [ -z "$CHECK_MAIL" ] && MISSING_LOGS+="[maillog] "
      [ -z "$CHECK_CRON" ] && MISSING_LOGS+="[cron] "
      [ -z "$CHECK_ALERT" ] && MISSING_LOGS+="[alert] "
      [ -z "$CHECK_EMERG" ] && MISSING_LOGS+="[emerg] "

      if [ -n "$MISSING_LOGS" ]; then
        VULN=1
        REASON_DETAIL="rsyslog 설정에 다음 주요 로그 항목이 누락되었습니다: ${MISSING_LOGS% }"
      fi
    fi
  fi

  # 최종 판정
  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON_DETAIL"
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_67() {
  local code="U-67"
  local item="로그 디렉터리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="/var/log 내 로그 파일의 소유자 및 권한 설정이 적절합니다."

  local log_dir="/var/log"
  local max_mode="644"
  local vuln_count=0
  local total_count=0
  local details=""

  # 1. 디렉터리 존재 여부 확인
  if [ ! -d "$log_dir" ]; then
    status="N/A"
    reason="/var/log 디렉터리가 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  # 2. 파일 전수 조사 (find를 사용하여 성능 및 정확도 확보)
  while IFS= read -r -d '' f; do
    total_count=$((total_count + 1))
    
    local owner perm
    owner=$(stat -c '%U' "$f" 2>/dev/null)
    perm=$(stat -c '%a' "$f" 2>/dev/null)

    local file_vuln=0
    local file_reason=""

    # 소유자 점검
    if [ "$owner" != "root" ]; then
      file_vuln=1
      file_reason="소유자($owner)"
    fi

    # 권한 점검 (8진수 비교)
    if [ -n "$perm" ]; then
      if (( 8#$perm > 8#$max_mode )); then
        file_vuln=1
        file_reason="${file_reason:+$file_reason, }권한($perm)"
      fi
    fi

    if [ "$file_vuln" -eq 1 ]; then
      vuln_count=$((vuln_count + 1))
      # 리포트 가독성을 위해 최대 3개까지만 상세 기록
      if [ "$vuln_count" -le 3 ]; then
        details+="$(basename "$f")($file_reason), "
      fi
    fi
  done < <(find "$log_dir" -xdev -type f -print0 2>/dev/null)

  # 3. 결과 판정
  if [ "$total_count" -eq 0 ]; then
    status="N/A"
    reason="/var/log 내에 점검 대상 파일이 없습니다."
  elif [ "$vuln_count" -gt 0 ]; then
    status="취약"
    reason="총 $total_count개 중 $vuln_count개 파일의 설정이 미흡합니다: [${details%, } ...]"
  fi

  # 최종 JSON 출력
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
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