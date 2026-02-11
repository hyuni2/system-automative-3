#!/bin/bash
resultfile="results.txt"

is_login_shell() {
  local sh="${1:-}"
  [[ -n "$sh" ]] || return 1
  case "$sh" in
    */nologin|*/false) return 1 ;;
    *) return 0 ;;
  esac
}


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

U_02() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-02(상) | 1. 계정관리 > 1.2 비밀번호 관리정책 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그인/패스워드 정책이 기준에 맞게 설정된 경우" >> "$resultfile" 2>&1

  local NA=0
  local -a reasons=()

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    NA=1
    reasons+=("root 권한 필요(sudo로 실행 권장)")
  fi

  local LOGIN_DEFS="/etc/login.defs"
  local PAM_FILE="/etc/pam.d/common-password"

  local MAX_DAYS_MIN=1
  local MAX_DAYS_MAX=90
  local MIN_DAYS_MIN=1

  local MINLEN_MIN=8
  local UCREDIT_MAX=-1
  local LCREDIT_MAX=-1
  local DCREDIT_MAX=-1
  local OCREDIT_MAX=-1
  local REMEMBER_MIN=4

  u02_trim(){ local s="${1:-}"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf "%s" "$s"; }
  u02_is_int(){ [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }
  u02_get_login_defs_val(){
    local key="$1"
    [[ -r "$LOGIN_DEFS" ]] || { echo ""; return 0; }
    awk -v k="$key" '
      BEGIN{IGNORECASE=1}
      /^[[:space:]]*#/ {next}
      $1==k {print $2}
    ' "$LOGIN_DEFS" 2>/dev/null | tail -n 1
  }
  u02_first_lineno(){
    local pat="$1" file="$2"
    [[ -r "$file" ]] || { echo ""; return 0; }
    awk -v p="$pat" '
      /^[[:space:]]*#/ {next}
      $0 ~ p {print NR; exit}
    ' "$file" 2>/dev/null
  }
  u02_first_line(){
    local pat="$1" file="$2"
    [[ -r "$file" ]] || { echo ""; return 0; }
    awk -v p="$pat" '
      /^[[:space:]]*#/ {next}
      $0 ~ p {print; exit}
    ' "$file" 2>/dev/null
  }

  if [[ "$NA" -eq 0 ]]; then
    if [[ ! -r "$LOGIN_DEFS" ]]; then
      NA=1
      reasons+=("$LOGIN_DEFS 파일을 읽을 수 없음")
    else
      local pass_max pass_min
      pass_max="$(u02_get_login_defs_val PASS_MAX_DAYS)"
      pass_min="$(u02_get_login_defs_val PASS_MIN_DAYS)"

      if ! u02_is_int "$pass_max"; then
        reasons+=("PASS_MAX_DAYS 미설정 또는 숫자 아님")
      else
        if (( pass_max < MAX_DAYS_MIN || pass_max > MAX_DAYS_MAX )); then
          reasons+=("PASS_MAX_DAYS=$pass_max (기준 ${MAX_DAYS_MIN}~${MAX_DAYS_MAX}일)")
        fi
      fi

      if ! u02_is_int "$pass_min"; then
        reasons+=("PASS_MIN_DAYS 미설정 또는 숫자 아님")
      else
        if (( pass_min < MIN_DAYS_MIN )); then
          reasons+=("PASS_MIN_DAYS=$pass_min (기준 >=${MIN_DAYS_MIN}일)")
        fi
      fi
    fi
  fi

  if [[ "$NA" -eq 0 ]]; then
    if [[ ! -r "$PAM_FILE" ]]; then
      NA=1
      reasons+=("$PAM_FILE 파일을 읽을 수 없음")
    else
      local pwq_line pwq_no unix_no
      pwq_line="$(u02_first_line "pam_(pwquality|cracklib)[.]so" "$PAM_FILE")"
      pwq_no="$(u02_first_lineno "pam_(pwquality|cracklib)[.]so" "$PAM_FILE")"
      unix_no="$(u02_first_lineno "pam_unix[.]so" "$PAM_FILE")"

      if [[ -z "$pwq_line" ]]; then
        reasons+=("PAM에서 pam_pwquality.so 또는 pam_cracklib.so 설정이 없음")
      else
        if [[ -n "$unix_no" && -n "$pwq_no" ]]; then
          if (( pwq_no > unix_no )); then
            reasons+=("pam_pwquality/pam_cracklib 라인이 pam_unix.so 보다 아래에 있음(순서 오류)")
          fi
        fi

        local -A U02_PWQ_OPT=()
        local enforce_pwq=0
        local tok
        for tok in $pwq_line; do
          case "$tok" in
            *enforce_for_root*) enforce_pwq=1 ;;
            *=*)
              local k="${tok%%=*}"
              local v="${tok#*=}"
              U02_PWQ_OPT["$k"]="$(u02_trim "$v")"
            ;;
          esac
        done

        local -A U02_PWQ_CONF=()
        local f
        for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
          [[ -r "$f" ]] || continue
          awk '
            /^[[:space:]]*#/ {next}
            /^[[:space:]]*$/ {next}
            /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=/ {
              gsub(/[[:space:]]+/,"",$0)
              split($0,a,"=")
              print a[1]"="a[2]
            }
          ' "$f" 2>/dev/null | while IFS='=' read -r k v; do
            [[ -n "$k" ]] || continue
            U02_PWQ_CONF["$k"]="$(u02_trim "$v")"
          done
        done

        u02_eff(){
          local k="$1"
          if [[ -n "${U02_PWQ_OPT[$k]+x}" && -n "${U02_PWQ_OPT[$k]}" ]]; then
            echo "${U02_PWQ_OPT[$k]}"
          elif [[ -n "${U02_PWQ_CONF[$k]+x}" && -n "${U02_PWQ_CONF[$k]}" ]]; then
            echo "${U02_PWQ_CONF[$k]}"
          else
            echo ""
          fi
        }

        local minlen ucredit lcredit dcredit ocredit
        minlen="$(u02_eff minlen)"
        ucredit="$(u02_eff ucredit)"
        lcredit="$(u02_eff lcredit)"
        dcredit="$(u02_eff dcredit)"
        ocredit="$(u02_eff ocredit)"

        if ! u02_is_int "$minlen" || (( minlen < MINLEN_MIN )); then
          reasons+=("minlen=${minlen:-미설정} (기준 >=${MINLEN_MIN})")
        fi
        if ! u02_is_int "$ucredit" || (( ucredit > UCREDIT_MAX )); then
          reasons+=("ucredit=${ucredit:-미설정} (기준 <=${UCREDIT_MAX})")
        fi
        if ! u02_is_int "$lcredit" || (( lcredit > LCREDIT_MAX )); then
          reasons+=("lcredit=${lcredit:-미설정} (기준 <=${LCREDIT_MAX})")
        fi
        if ! u02_is_int "$dcredit" || (( dcredit > DCREDIT_MAX )); then
          reasons+=("dcredit=${dcredit:-미설정} (기준 <=${DCREDIT_MAX})")
        fi
        if ! u02_is_int "$ocredit" || (( ocredit > OCREDIT_MAX )); then
          reasons+=("ocredit=${ocredit:-미설정} (기준 <=${OCREDIT_MAX})")
        fi
        if (( enforce_pwq == 0 )); then
          reasons+=("pam_pwquality/pam_cracklib에 enforce_for_root 미설정")
        fi
      fi

      local ph_line ph_no
      ph_line="$(u02_first_line "pam_pwhistory[.]so" "$PAM_FILE")"
      ph_no="$(u02_first_lineno "pam_pwhistory[.]so" "$PAM_FILE")"

      if [[ -n "$ph_line" ]]; then
        if [[ -n "$unix_no" && -n "$ph_no" ]]; then
          if (( ph_no > unix_no )); then
            reasons+=("pam_pwhistory 라인이 pam_unix.so 보다 아래에 있음(순서 오류)")
          fi
        fi

        local -A U02_PH_OPT=()
        local enforce_ph=0
        local t
        for t in $ph_line; do
          case "$t" in
            *enforce_for_root*) enforce_ph=1 ;;
            *=*)
              U02_PH_OPT["${t%%=*}"]="$(u02_trim "${t#*=}")"
            ;;
          esac
        done

        local -A U02_PH_CONF=()
        for f in /etc/security/pwhistory.conf /etc/security/pwhistory.conf.d/*.conf; do
          [[ -r "$f" ]] || continue
          awk '
            /^[[:space:]]*#/ {next}
            /^[[:space:]]*$/ {next}
            /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=/ {
              gsub(/[[:space:]]+/,"",$0)
              split($0,a,"=")
              print a[1]"="a[2]
            }
          ' "$f" 2>/dev/null | while IFS='=' read -r k v; do
            [[ -n "$k" ]] || continue
            U02_PH_CONF["$k"]="$(u02_trim "$v")"
          done
        done

        u02_ph_eff(){
          local k="$1"
          if [[ -n "${U02_PH_OPT[$k]+x}" && -n "${U02_PH_OPT[$k]}" ]]; then
            echo "${U02_PH_OPT[$k]}"
          elif [[ -n "${U02_PH_CONF[$k]+x}" && -n "${U02_PH_CONF[$k]}" ]]; then
            echo "${U02_PH_CONF[$k]}"
          else
            echo ""
          fi
        }

        local remember
        remember="$(u02_ph_eff remember)"
        if ! u02_is_int "$remember" || (( remember < REMEMBER_MIN )); then
          reasons+=("pwhistory remember=${remember:-미설정} (기준 >=${REMEMBER_MIN})")
        fi
        if (( enforce_ph == 0 )); then
          reasons+=("pam_pwhistory에 enforce_for_root 미설정")
        fi
      else
        local unix_line remember2
        unix_line="$(u02_first_line "pam_unix[.]so" "$PAM_FILE")"
        remember2=""
        if [[ -n "$unix_line" ]]; then
          remember2="$(echo "$unix_line" | awk '
            {
              for(i=1;i<=NF;i++){
                if($i ~ /^remember=/){split($i,a,"="); print a[2]; exit}
              }
            }'
          )"
        fi
        if ! u02_is_int "$remember2" || (( remember2 < REMEMBER_MIN )); then
          reasons+=("패스워드 재사용 제한(remember>=${REMEMBER_MIN}) 설정이 확인되지 않음(pam_pwhistory 없음, pam_unix remember 미흡)")
        fi
      fi
    fi
  fi


  if [[ "$NA" -eq 1 ]]; then
    echo "※ U-02 결과 : N/A" >> "$resultfile" 2>&1
  else
    if [[ "${#reasons[@]}" -gt 0 ]]; then
      echo "※ U-02 결과 : 취약" >> "$resultfile" 2>&1
    else
      echo "※ U-02 결과 : 양호" >> "$resultfile" 2>&1
    fi
  fi
  return 0
}

U_03() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-03(상) | 1. 계정 관리 > 1.3 계정 잠금 임계값 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우"  >> "$resultfile" 2>&1

  local pam_auth="/etc/pam.d/common-auth"
  local pam_acct="/etc/pam.d/common-account"
  local faillock_conf="/etc/security/faillock.conf"

  local pam_has_faillock=0
  if [ -f "$pam_auth" ] && grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$pam_auth" 2>/dev/null | grep -q 'pam_faillock\.so'; then
    pam_has_faillock=1
  fi
  if [ -f "$pam_acct" ] && grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$pam_acct" 2>/dev/null | grep -q 'pam_faillock\.so'; then
    pam_has_faillock=1
  fi

  if [ "$pam_has_faillock" -eq 0 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " pam_faillock이 PAM에 적용되어 있지 않아 계정 잠금 정책이 구성되어 있지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ ! -f "$faillock_conf" ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $faillock_conf 파일이 존재하지 않아 계정 잠금 임계값(deny)을 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  local deny=""
  deny=$(
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$faillock_conf" 2>/dev/null \
      | grep -Ei '^[[:space:]]*deny[[:space:]]*=' \
      | tail -n 1 \
      | grep -oE '[0-9]+' \
      | head -n 1
  )

  if [ -z "$deny" ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " faillock.conf에서 deny 설정을 찾지 못했습니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$deny" -eq 0 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 계정 잠금 임계값(deny)이 0으로 설정되어 있습니다. (잠금 미적용 가능)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$deny" -gt 10 ]; then
    echo "※ U-03 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 계정 잠금 임계값(deny)이 11회 이상으로 설정되어 있습니다. (deny=$deny)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-03 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 계정 잠금 임계값(deny)이 10회 이하로 확인되었습니다. (deny=$deny)" >> "$resultfile" 2>&1
  return 0

}

#연진
U_04() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-04(상) | 1. 계정관리 > 1.4 패스워드 파일 보호 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : shadow 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우" >> "$resultfile" 2>&1

    # 1. /etc/passwd의 두 번째 필드가 'x'인지 확인
    VULN_USERS=$(awk -F: '$2 != "x" {print $1}' /etc/passwd)

    if [ -n "$VULN_USERS" ]; then
        echo "※ U-04 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " [현황] shadow 패스워드를 사용하지 않는 계정 발견: $VULN_USERS" >> "$resultfile" 2>&1
    else
        # 2. Ubuntu 24 특화: /etc/shadow 파일 존재 및 접근 권한 추가 확인
        if [ -f /etc/shadow ]; then
            # shadow 파일은 root만 읽을 수 있어야 함 (보통 640 또는 600)
            SHADOW_PERM=$(stat -c "%a" /etc/shadow)
            if [ "$SHADOW_PERM" -le 640 ]; then
                echo "※ U-04 결과 : 양호(Good)" >> "$resultfile" 2>&1
            else
                echo "※ U-04 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                echo " [현황] /etc/shadow 파일의 권한이 너무 낮습니다(현재: $SHADOW_PERM)." >> "$resultfile" 2>&1
            fi
        else
            echo "※ U-04 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " [현황] /etc/shadow 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        fi
    fi
}

U_05() {
	echo ""  >> $resultfile 2>&1
	echo "▶ U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	if [ -f /etc/passwd ]; then
    if [ "$(awk -F : '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | wc -l)" -gt 0 ]; then
			echo "※ U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $resultfile 2>&1
			return 0
		else
			echo "※ U-05 결과 : 양호(Good)" >> $resultfile 2>&1
			return 0
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

U_07() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-07(하) | 1. 계정관리 > 1.7 불필요한 계정 제거 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 계정이 존재하지 않는 경우" >> "$resultfile" 2>&1
  echo " 점검 방식 : 자동으로 '관리 필요' 후보를 탐지(운영 정책에 따라 최종 판단 필요)" >> "$resultfile" 2>&1

  local INACTIVE_DAYS="${U07_INACTIVE_DAYS:-90}"
  local NA=0
  local -a flag_user=()
  local -a flag_reason=()

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    NA=1
  fi

  u07_is_login_shell() {
    local sh="${1:-}"
    [[ -n "$sh" ]] || return 1
    case "$sh" in
      */nologin|*/false) return 1 ;;
      *) return 0 ;;
    esac
  }

  u07_passwd_status() {
    local u="$1"
    passwd -S "$u" 2>/dev/null | awk '{print $2}'
  }

  u07_lastlog_age() {
    local u="$1"
    local line date_str epoch now age_days
    line="$(lastlog -u "$u" 2>/dev/null | awk 'NR==2{print}')"
    [[ -n "$line" ]] || { echo "unknown"; return 0; }
    if echo "$line" | grep -qi "Never logged in"; then
      echo "never"; return 0
    fi
    date_str="$(echo "$line" | awk '{for(i=4;i<=NF;i++){printf $i (i<NF?" ":"")}}')"
    epoch="$(date -d "$date_str" +%s 2>/dev/null || true)"
    [[ -n "$epoch" ]] || { echo "unknown"; return 0; }
    now="$(date +%s)"
    age_days=$(( (now - epoch) / 86400 ))
    echo "age_days:$age_days"
  }

  if [[ "$NA" -eq 0 ]]; then
    while IFS=: read -r user _ uid _ _ home shell; do
      [[ -n "${user:-}" && -n "${uid:-}" ]] || continue

      if [[ "$uid" -lt 1000 ]]; then
        case "$user" in root|sync|shutdown|halt) continue ;; esac
        if u07_is_login_shell "$shell"; then
          flag_user+=("$user")
          flag_reason+=("시스템/서비스 계정(UID=$uid)이 로그인 가능한 셸($shell)을 보유")
        fi
        continue
      fi

      [[ "$user" == "nobody" ]] && continue
      if u07_is_login_shell "$shell"; then
        local st ll age
        st="$(u07_passwd_status "$user")"

        if [[ "$st" == "L" ]]; then
          continue
        fi

        if [[ "$st" == "NP" ]]; then
          flag_user+=("$user")
          flag_reason+=("일반계정(UID=$uid)이 로그인 가능한 셸($shell)인데 비밀번호 상태가 NP(미설정)")
          continue
        fi

        ll="$(u07_lastlog_age "$user")"
        if [[ "$ll" == "never" ]]; then
          flag_user+=("$user")
          flag_reason+=("일반계정(UID=$uid)이 로그인 가능한 셸($shell)인데 로그인 이력 없음(Never logged in), 잠금 아님")
          continue
        fi
        if [[ "$ll" == age_days:* ]]; then
          age="${ll#age_days:}"
          if [[ "$age" =~ ^[0-9]+$ ]] && [[ "$age" -gt "$INACTIVE_DAYS" ]]; then
            flag_user+=("$user")
            flag_reason+=("일반계정(UID=$uid) 마지막 로그인 ${age}일 경과(기준 ${INACTIVE_DAYS}일 초과), 잠금 아님")
          fi
        fi
      fi
    done < /etc/passwd
  fi

  if [[ "$NA" -eq 1 ]]; then
    echo "※ U-07 결과 : N/A" >> "$resultfile" 2>&1
    echo " - root 권한으로 실행하세요. 예) sudo ./스크립트" >> "$resultfile" 2>&1
  else
    if [[ "${#flag_user[@]}" -eq 0 ]]; then
      echo "※ U-07 결과 : 양호" >> "$resultfile" 2>&1
    else
      echo "※ U-07 결과 : 취약" >> "$resultfile" 2>&1
      echo " 취약(관리 필요) 후보 계정 수: ${#flag_user[@]}" >> "$resultfile" 2>&1
      echo " 상세:" >> "$resultfile" 2>&1
      local i
      for i in "${!flag_user[@]}"; do
        echo " - ${flag_user[$i]} : ${flag_reason[$i]}" >> "$resultfile" 2>&1
      done
    fi
  fi
  return 0
}

U_08() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-08(중) | 1. 계정 관리 > 1.8 관리자 그룹에 최소한의 계정 포함 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> "$resultfile" 2>&1

  local admin_groups=("sudo" "admin")

  local unnecessary_accounts=(
    "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp"
    "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network"
    "systemd-resolve" "messagebus" "uuidd" "sshd"
    "ftp" "tftp" "apache" "httpd" "nginx"
    "mysql" "mariadb" "postgres"
    "postfix" "dovecot"
  )

  if [ ! -f /etc/group ]; then
    echo "※ U-08 결과 : N/A" >> "$resultfile" 2>&1
    echo " /etc/group 파일이 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  _group_exists() { getent group "$1" >/dev/null 2>&1; }

  _collect_group_users() {
    local g="$1" line members
    line="$(getent group "$g" 2>/dev/null)"
    members="$(echo "$line" | awk -F: '{print $4}')"
    echo "$members" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sed 's/[[:space:]]//g' | sort -u
  }

  _is_unnecessary() {
    local u="$1" x
    for x in "${unnecessary_accounts[@]}"; do
      [ "$u" = "$x" ] && return 0
    done
    return 1
  }

  _uid_of_user() {
    id -u "$1" 2>/dev/null
  }

  local any_admin_group_found=0
  local vuln_found=0

  for g in "${admin_groups[@]}"; do
    if _group_exists "$g"; then
      any_admin_group_found=1

      local u bads="" suspects=""
      while IFS= read -r u; do
        [ -z "$u" ] && continue

        if _is_unnecessary "$u"; then
          bads+="$u "
          continue
        fi

        local uid
        uid=$(_uid_of_user "$u")
        if [ -n "$uid" ] && [ "$uid" -lt 1000 ] && [ "$u" != "root" ]; then
          suspects+="$u(uid=$uid) "
        fi
      done < <(_collect_group_users "$g")

      if [ -n "$bads" ]; then
        vuln_found=1
        echo "※ 취약 징후: 관리자 그룹($g)에 불필요/서비스 계정 포함: $bads" >> "$resultfile" 2>&1
      fi

      if [ -n "$suspects" ]; then
        echo "※ 참고: 관리자 그룹($g)에 시스템/특수 계정(UID<1000) 의심: $suspects" >> "$resultfile" 2>&1
      fi
    fi
  done

  if [ "$any_admin_group_found" -eq 0 ]; then
    echo "※ U-08 결과 : N/A" >> "$resultfile" 2>&1
    echo " 점검할 관리자 그룹(sudo/admin)이 존재하지 않습니다." >> "$resultfile" 2>&1
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
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-09(하) | 1. 계정관리 > 1.9 계정이 존재하지 않는 GID 금지 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우" >> "$resultfile" 2>&1

    # 1. /etc/passwd에서 현재 사용 중인 모든 기본 GID 추출
    USED_GIDS=$(awk -F: '{print $4}' /etc/passwd | sort -u)

    # 2. Ubuntu 24 기준: 일반 사용자 그룹인 1000번 이상만 점검 대상으로 설정
    CHECK_GIDS=$(awk -F: '$3 >= 1000 {print $3}' /etc/group)
    
    VULN_GROUPS=""
    for gid in $CHECK_GIDS; do
        # 해당 GID가 /etc/passwd의 기본 그룹으로 사용 중인지 확인
        if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
            # 보조 그룹(Supplementary Group)으로 등록된 사용자가 있는지 추가 확인
            MEMBER_EXISTS=$(grep "^[^:]*:[^:]*:$gid:" /etc/group | cut -d: -f4)
            
            if [ -z "$MEMBER_EXISTS" ]; then
                GROUP_NAME=$(grep "^[^:]*:[^:]*:$gid:" /etc/group | cut -d: -f1)
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

U_12() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-12(하) | 1. 계정관리 > 1.12 세션 종료 시간 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : bash/sh 계열에서 TMOUT 값이 600초(10분) 이하로 설정되어 있고 export 되어 있는 경우" >> "$resultfile" 2>&1

  local TARGET_MAX=600
  local NA=0
  local -a reasons=()

  u12_is_int(){ [[ "${1:-}" =~ ^[0-9]+$ ]]; }

  u12_probe() {
    local mode="$1" out cmd
    command -v bash >/dev/null 2>&1 || { echo "NA|bash_not_found"; return 0; }
    cmd='declare -p TMOUT 2>/dev/null || echo TMOUT_UNSET'
    if [[ "$mode" == "login" ]]; then
      out="$(env -i HOME=/nonexistent PATH=/usr/sbin:/usr/bin:/sbin:/bin bash -lc "$cmd" 2>/dev/null || true)"
    else
      out="$(env -i HOME=/nonexistent PATH=/usr/sbin:/usr/bin:/sbin:/bin PS1= PS2= bash -ic "$cmd" 2>/dev/null || true)"
    fi
    out="${out//$'\r'/}"
    out="$(printf "%s" "$out" | head -n 1)"
    [[ -n "$out" ]] || { echo "NA|probe_failed"; return 0; }
    if [[ "$out" == "TMOUT_UNSET" ]]; then
      echo "UNSET|$out"; return 0
    fi
    local exported="NO" val=""
    [[ "$out" == *" -x "* || "$out" == declare\ -*x* ]] && exported="YES"
    if [[ "$out" == *"TMOUT="* ]]; then
      val="${out#*TMOUT=}"
      val="${val%\"}"; val="${val#\"}"
      val="${val%\'}"; val="${val#\'}"
    fi
    if ! u12_is_int "$val"; then
      echo "BAD|$out"; return 0
    fi
    echo "SET|val=$val|exported=$exported|raw=$out"
  }

  u12_judge() {
    local probe="$1"
    if [[ "$probe" == NA* ]]; then echo "NA"; return 0; fi
    if [[ "$probe" == UNSET* ]]; then echo "FAIL|TMOUT 미설정"; return 0; fi
    if [[ "$probe" == BAD* ]]; then echo "FAIL|TMOUT 값 형식 이상"; return 0; fi
    local val exported
    val="$(printf "%s" "$probe" | sed -n 's/.*val=\([0-9]\+\).*/\1/p' | head -n1)"
    exported="$(printf "%s" "$probe" | sed -n 's/.*exported=\(YES\|NO\).*/\1/p' | head -n1)"
    if [[ -z "$val" || -z "$exported" ]]; then echo "NA"; return 0; fi
    if [[ "$val" -ge 1 && "$val" -le "$TARGET_MAX" && "$exported" == "YES" ]]; then
      echo "PASS|TMOUT=$val (<=${TARGET_MAX}) 및 export 확인"
    else
      if [[ "$val" -le 0 ]]; then
        echo "FAIL|TMOUT=$val (비활성/0)"
      elif [[ "$val" -gt "$TARGET_MAX" ]]; then
        echo "FAIL|TMOUT=$val (기준 ${TARGET_MAX}초 초과)"
      elif [[ "$exported" != "YES" ]]; then
        echo "FAIL|TMOUT=$val 이지만 export 미확인"
      else
        echo "FAIL|TMOUT 설정 기준 미충족"
      fi
    fi
  }

  local login_probe inter_probe decision
  login_probe="$(u12_probe login)"
  inter_probe="$(u12_probe interactive)"
  decision="$(u12_judge "$login_probe")"
  if [[ "$decision" == "NA" ]]; then
    decision="$(u12_judge "$inter_probe")"
  fi

  echo " 점검(로그인 쉘 기준): $login_probe" >> "$resultfile" 2>&1
  echo " 점검(인터랙티브 쉘 기준): $inter_probe" >> "$resultfile" 2>&1

  if [[ "$decision" == "NA" ]]; then
    echo "※ U-12 결과 : N/A" >> "$resultfile" 2>&1
    echo " - TMOUT 판단에 필요한 정보를 확인하지 못했습니다." >> "$resultfile" 2>&1
  elif [[ "$decision" == PASS* ]]; then
    echo "※ U-12 결과 : 양호" >> "$resultfile" 2>&1
    echo " - ${decision#*|}" >> "$resultfile" 2>&1
  else
    echo "※ U-12 결과 : 취약" >> "$resultfile" 2>&1
    echo " - ${decision#*|}" >> "$resultfile" 2>&1
  fi
  return 0
}

U_13() {
  local shadow="/etc/shadow"
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-13(중) | 1. 계정관리 > 1.13 안전한 비밀번호 암호화 알고리즘 사용 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 안전한 알고리즘(yescrypt:\\\$y\\\$, SHA-2:\\\$5/\\\$6)을 사용하는 경우" >> "$resultfile" 2>&1

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

    ((checked++))

    if [[ "$hash" != \$* ]]; then
      vuln_found=1
      evidence+="$user:UNKNOWN_FORMAT; "
      continue
    fi

    if [[ "$hash" == \$y\$* ]]; then
      continue
    fi

    local id
    id="$(echo "$hash" | awk -F'$' '{print $2}')"
    [ -z "$id" ] && id="UNKNOWN"

    if [ "$id" = "5" ] || [ "$id" = "6" ]; then
      continue
    fi

    vuln_found=1
    evidence+="$user:\$$id\$; "
  done < "$shadow"

  if [ "$checked" -eq 0 ]; then
    echo "※ U-13 결과 : N/A" >> "$resultfile" 2>&1
    echo " 점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)" >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$vuln_found" -eq 1 ]; then
    echo "※ U-13 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 취약하거나 정책 외 알고리즘을 사용하는 계정이 존재합니다." >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-13 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 안전한 알고리즘(yescrypt:\$y\$, SHA-2:\$5/\$6)만 사용 중입니다. (점검계정 수: $checked)" >> "$resultfile" 2>&1
  return 0
}

#연진
U_14() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-14(상) | 2. 파일 및 디렉토리 관리 > 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : PATH 환경변수에 \".\" 이 맨 앞이나 중간에 포함되지 않은 경우" >> "$resultfile" 2>&1

    VULN_FOUND=0
    DETAILS=""

    # 1. 런타임 PATH 점검
    if echo "$PATH" | grep -qE '^\.:|:.:|^:|::|:$'; then
        VULN_FOUND=1
        DETAILS="[Runtime] 현재 PATH 내 '.' 또는 '::' 발견: $PATH"
    fi

    # 2. Ubuntu 24 시스템 설정 파일 점검 (파일 명칭 주의)
    if [ $VULN_FOUND -eq 0 ]; then
        # Ubuntu는 /etc/bash.bashrc와 /etc/environment가 핵심입니다.
        ubuntu_files=("/etc/profile" "/etc/bash.bashrc" "/etc/environment" "/etc/profile.d/*.sh")
        
        # /etc/environment는 PATH="경로" 형식으로 저장되므로 별도 체크가 필요할 수 있음
        for file in /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/*.sh; do
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

    # 3. Ubuntu 사용자 홈 디렉터리 점검 ( .profile 중심 )
    if [ $VULN_FOUND -eq 0 ]; then
        # Ubuntu는 .bash_profile 대신 .profile을 기본으로 사용합니다.
        user_dot_files=(".profile" ".bashrc" ".bash_login")
        user_homedirs=$(awk -F: '$7!="/usr/sbin/nologin" && $7!="/bin/false" {print $6}' /etc/passwd | sort | uniq)

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

U_17() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-17(상) | 2. 파일 및 디렉터리 관리 > 2.4 시스템 시작파일 및 환경파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 시스템 시작/환경 파일이 root 소유이며 다른 사용자 쓰기 권한이 없는 경우" >> "$resultfile" 2>&1

  local NA=0
  local -a bad_list=()
  local -a bad_reason=()

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    NA=1
  fi

  u17_check_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    local target="$f"
    if [[ -L "$f" ]]; then
      target="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    fi
    [[ -e "$target" ]] || return 0
    [[ -f "$target" ]] || return 0
    local uid perm
    uid="$(stat -c '%u' "$target" 2>/dev/null || echo "")"
    perm="$(stat -c '%a' "$target" 2>/dev/null || echo "")"
    [[ -n "$uid" && -n "$perm" ]] || return 0

    if [[ "$uid" != "0" ]]; then
      bad_list+=("$target")
      bad_reason+=("root 소유 아님(uid=$uid)")
      return 0
    fi

    local mode=$((8#$perm))
    if (( (mode & 0022) != 0 )); then
      bad_list+=("$target")
      bad_reason+=("그룹/기타 쓰기 권한 존재(perm=$perm)")
      return 0
    fi
  }

  if [[ "$NA" -eq 0 ]]; then
    local d f
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
      [[ -d "$d" ]] || continue
      while IFS= read -r -d '' f; do
        u17_check_file "$f"
      done < <(find "$d" -type f \( -name "*.service" -o -name "*.socket" -o -name "*.target" -o -name "*.timer" -o -name "*.mount" -o -name "*.path" -o -name "*.slice" \) -print0 2>/dev/null)
    done

    if [[ -d /etc/init.d ]]; then
      while IFS= read -r -d '' f; do
        u17_check_file "$f"
      done < <(find /etc/init.d -type f -print0 2>/dev/null)
    fi
  fi

  if [[ "$NA" -eq 1 ]]; then
    echo "※ U-17 결과 : N/A" >> "$resultfile" 2>&1
    echo " - root 권한으로 실행하세요. 예) sudo ./스크립트" >> "$resultfile" 2>&1
  else
    if [[ "${#bad_list[@]}" -eq 0 ]]; then
      echo "※ U-17 결과 : 양호" >> "$resultfile" 2>&1
    else
      echo "※ U-17 결과 : 취약" >> "$resultfile" 2>&1
      echo " 취약 항목 수: ${#bad_list[@]}" >> "$resultfile" 2>&1
      local i limit=30
      for i in "${!bad_list[@]}"; do
        [[ "$i" -ge "$limit" ]] && { echo " - ... (생략)" >> "$resultfile" 2>&1; break; }
        echo " - ${bad_list[$i]} : ${bad_reason[$i]}" >> "$resultfile" 2>&1
      done
    fi
  fi
  return 0
}

U_18() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-18(상) | 2. 파일 및 디렉토리 관리 > 2.5 /etc/shadow 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
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

  if [ "$perm" = "400" ]; then
    echo "※ U-18 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " $target 소유자(root) 및 권한(perm=$perm)이 기준(400)을 만족합니다." >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  echo " $target 파일 권한이 400이 아닙니다. (perm=$perm)" >> "$resultfile" 2>&1
  return 0
}

#연진
U_19() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-19(상) | 2. 파일 및 디렉토리 관리 > 2.6 /etc/hosts 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    # Ubuntu 환경임을 리포트에 명시하고 싶을 경우 추가
    echo " 점검 환경: Ubuntu 24.04 (Debian-family)" >> "$resultfile" 2>&1

    # (stat 명령어는 Ubuntu에서도 표준으로 사용됨)
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

U_20() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-20(상) | 2. 파일 및 디렉토리 관리 > 2.7 systemd *.socket, *.service 파일 소유자 및 권한 설정 ◀"  >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : systemd *.socket, *.service 파일의 소유자가 root이고, 권한이 644 이하인 경우"  >> "$resultfile" 2>&1
    vuln_flag=0
    evidence_flag=0
    file_exists_count=0
    print_vuln_header_once() {
        if [ "$evidence_flag" -eq 0 ]; then
            echo "※ U-20 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            evidence_flag=1
        fi
    }
    check_dir_units() {
        dir="$1"
        [ -d "$dir" ] || return 0
        tmpfile="$(mktemp 2>/dev/null)"
        if [ -z "$tmpfile" ]; then
            tmpfile="/tmp/u20_unit_files.$$"
            : > "$tmpfile"
        fi
        find "$dir" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null > "$tmpfile"
        if [ -s "$tmpfile" ]; then
            file_exists_count=$((file_exists_count + 1))
            while IFS= read -r file; do
                [ -f "$file" ] || continue
                owner="$(stat -c %U "$file" 2>/dev/null)"
                perm="$(stat -c %a "$file" 2>/dev/null)"
                if [ -z "$owner" ] || [ -z "$perm" ]; then
                    vuln_flag=1
                    print_vuln_header_once
                    echo " $file 파일의 소유자/권한 정보를 확인할 수 없습니다." >> "$resultfile" 2>&1
                    continue
                fi
                if [ "$owner" != "root" ]; then
                    vuln_flag=1
                    print_vuln_header_once
                    echo " $file 파일의 소유자가 root가 아닙니다. (owner=$owner)" >> "$resultfile" 2>&1
                fi
                if [ "$perm" -gt 644 ] 2>/dev/null; then
                    vuln_flag=1
                    print_vuln_header_once
                    echo " $file 파일의 권한이 644 초과입니다. (perm=$perm)" >> "$resultfile" 2>&1
                fi
            done < "$tmpfile"
        fi
        rm -f "$tmpfile" >/dev/null 2>&1
        return 0
    }
    check_dir_units "/usr/lib/systemd/system"
    check_dir_units "/etc/systemd/system"
    if [ "$file_exists_count" -eq 0 ]; then
        echo "※ U-20 결과 : N/A" >> "$resultfile" 2>&1
        echo " systemd socket/service 파일이 없습니다." >> "$resultfile" 2>&1
        return 0
    fi
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-20 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
    return 0
}

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

U_22() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-22(상) | 2. 파일 및 디렉터리 관리 > 2.9 /etc/services 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : /etc/services 파일이 root 소유이고 권한이 644 이하이며 기타 사용자 쓰기 권한이 없는 경우" >> "$resultfile" 2>&1

  local target="/etc/services"
  if [[ ! -e "$target" ]]; then
    echo "※ U-22 결과 : N/A" >> "$resultfile" 2>&1
    echo " - $target 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
    return 0
  fi

  local uid perm
  uid="$(stat -c '%u' "$target" 2>/dev/null || echo "")"
  perm="$(stat -c '%a' "$target" 2>/dev/null || echo "")"

  if [[ -z "$uid" || -z "$perm" ]]; then
    echo "※ U-22 결과 : N/A" >> "$resultfile" 2>&1
    echo " - $target 파일 정보를 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  local mode=$((8#$perm))
  local bad=0
  [[ "$uid" != "0" ]] && bad=1
  (( (mode & 0002) != 0 )) && bad=1
  (( perm > 644 )) && bad=1

  if [[ "$bad" -eq 0 ]]; then
    echo "※ U-22 결과 : 양호" >> "$resultfile" 2>&1
  else
    echo "※ U-22 결과 : 취약" >> "$resultfile" 2>&1
    echo " - owner_uid=$uid, perm=$perm (기준: root 소유, 644 이하, 기타 사용자 쓰기 금지)" >> "$resultfile" 2>&1
  fi
  return 0
}

U_23() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-23(상) | 2. 파일 및 디렉토리 관리 > 2.10 SUID, SGID, Sticky bit 설정 파일 점검 ◀"  >> "$resultfile" 2>&1
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

U_25() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-25(상) | 2. 파일 및 디렉토리 관리 > 2.12 world writable 파일 점검 ◀"  >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"  >> "$resultfile" 2>&1
    found=0
    find / -xdev -type f -perm -0002 2>/dev/null |
    while IFS= read -r file; do
        if [ "$found" -eq 0 ]; then
            echo "※ U-25 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " world writable 설정이 되어있는 파일이 존재합니다." >> "$resultfile" 2>&1
            found=1
        fi
        echo "  - $file" >> "$resultfile" 2>&1
        break
    done
    if [ "$found" -eq 0 ]; then
        echo "※ U-25 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

U_26(){
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-26(상) | 2. 파일 및 디렉토리 관리 > 2.13 /dev에 존재하지 않는 device 파일 점검 ◀"  >> "$resultfile" 2>&1
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

U_27() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-27(중) | 2. 파일 및 디렉터리 관리 > 2.14 .rhosts, hosts.equiv 사용 제한 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : r-command 서비스를 사용하지 않거나(.rhosts/hosts.equiv 미사용), 사용 시 파일 권한/내용이 안전한 경우" >> "$resultfile" 2>&1

  local NA=0
  local -a reasons=()

  u27_is_rcommand_in_use() {
    local in_use=0

    if command -v ss >/dev/null 2>&1; then
      ss -lnt 2>/dev/null | grep -Eq ':(512|513|514)[[:space:]]' && in_use=1
    elif command -v netstat >/dev/null 2>&1; then
      netstat -lnt 2>/dev/null | grep -Eq ':(512|513|514)[[:space:]]' && in_use=1
    fi

    if [[ -r /etc/inetd.conf ]]; then
      grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf | grep -Eq '(^|[[:space:]])(shell|login|exec)[[:space:]]' && in_use=1
    fi

    if [[ -d /etc/xinetd.d ]]; then
      grep -R --include="*" -E '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d 2>/dev/null | grep -Eq '(rsh|rlogin|rexec|shell|login|exec)' && in_use=1
    fi

    if command -v systemctl >/dev/null 2>&1; then
      for svc in rsh.socket rlogin.socket rexec.socket; do
        systemctl is-active "$svc" &>/dev/null && in_use=1
      done
    fi

    [[ "$in_use" -eq 1 ]]
  }

  u27_perm_ok_600_or_less() {
    local file="$1" perm
    perm="$(stat -c '%a' "$file" 2>/dev/null || echo "")"
    [[ -n "$perm" ]] || return 1
    (( perm <= 600 )) || return 1
    local mode=$((8#$perm))
    (( (mode & 0077) == 0 )) || return 1
    return 0
  }

  u27_check_hosts_equiv() {
    local f="/etc/hosts.equiv"
    [[ -e "$f" ]] || return 0
    local uid
    uid="$(stat -c '%u' "$f" 2>/dev/null || echo "")"
    [[ "$uid" == "0" ]] || reasons+=("$f 가 root 소유가 아님(uid=$uid)")
    u27_perm_ok_600_or_less "$f" || reasons+=("$f 권한이 600 이하가 아님")
    grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -q '^\s*\+' && reasons+=("$f 에 '+' 허용 설정 존재")
  }

  u27_check_user_rhosts() {
    local user home f uid
    while IFS=: read -r user _ _ _ _ home _; do
      [[ -n "$user" && -n "$home" ]] || continue
      f="$home/.rhosts"
      [[ -e "$f" ]] || continue
      uid="$(stat -c '%U' "$f" 2>/dev/null || echo "")"
      [[ "$uid" == "$user" ]] || reasons+=("$f 소유자가 사용자($user)와 다름(현재=$uid)")
      u27_perm_ok_600_or_less "$f" || reasons+=("$f 권한이 600 이하가 아님")
      grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -q '^\s*\+' && reasons+=("$f 에 '+' 허용 설정 존재")
    done < /etc/passwd
  }

  if u27_is_rcommand_in_use; then
    u27_check_hosts_equiv
    u27_check_user_rhosts
    if [[ "${#reasons[@]}" -eq 0 ]]; then
      echo "※ U-27 결과 : 양호" >> "$resultfile" 2>&1
      echo " - r-command 서비스 사용 징후가 있으나(.rhosts/hosts.equiv) 위험 설정은 확인되지 않음" >> "$resultfile" 2>&1
    else
      echo "※ U-27 결과 : 취약" >> "$resultfile" 2>&1
      echo " 사유:" >> "$resultfile" 2>&1
      local r
      for r in "${reasons[@]}"; do
        echo " - $r" >> "$resultfile" 2>&1
      done
    fi
  else
    echo "※ U-27 결과 : 양호" >> "$resultfile" 2>&1
    echo " - r-command 서비스 미사용(포트/설정 기반 확인)" >> "$resultfile" 2>&1
  fi
  return 0
}

U_28() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-28(상) | 2. 파일 및 디렉토리 관리 > 2.15 접속 IP 및 포트 제한 ◀"  >> "$resultfile" 2>&1
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

U_30() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-30(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> "$resultfile" 2>&1

    vuln_flag=0
    vuln_reason=""
    for svc in $(systemctl list-unit-files --type=service --no-legend | awk '{print $1}'); do
        umask_val=$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')
        [ -z "$umask_val" ] && continue
        umask_dec=$((8#$umask_val))
        if [ "$umask_dec" -lt 18 ]; then
            vuln_flag=1
            vuln_reason="systemd 서비스 [$svc]의 UMask 값($umask_val)이 022 미만입니다."
            break
        fi
    done
    if [ "$vuln_flag" -eq 0 ]; then
        if grep -q "pam_umask.so" /etc/pam.d/common-session 2>/dev/null; then
            login_umask=$(grep -E "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')

            if [ -z "$login_umask" ]; then
                vuln_flag=1
                vuln_reason="/etc/login.defs 파일에 UMASK 설정이 존재하지 않습니다."

            elif [ $((8#$login_umask)) -lt 18 ]; then
                vuln_flag=1
                vuln_reason="/etc/login.defs 파일의 UMASK 값($login_umask)이 022 미만입니다."
            fi
        else
            vuln_flag=1
            vuln_reason="PAM 설정에 pam_umask.so 모듈이 적용되어 있지 않습니다."
        fi
    fi
    if [ "$vuln_flag" -eq 1 ]; then
        echo "※ U-30 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $vuln_reason" >> "$resultfile" 2>&1
    else
        echo "※ U-30 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

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

U_32() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-32(중) | 2. 파일 및 디렉터리 관리 > 2.19 사용자 계정 홈디렉터리 존재 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 사용자 계정의 홈디렉터리가 존재하며, 소유자/권한이 적절한 경우" >> "$resultfile" 2>&1

  local UID_MIN=1000
  if [[ -r /etc/login.defs ]]; then
    local v
    v="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
    [[ "$v" =~ ^[0-9]+$ ]] && UID_MIN="$v"
  fi

  local -a bad=()
  local -a bad_reason=()

  u32_is_login_shell() {
    local sh="${1:-}"
    [[ -n "$sh" ]] || return 1
    case "$sh" in */nologin|*/false) return 1 ;; *) return 0 ;; esac
  }

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ -n "$user" && -n "$uid" ]] || continue
    [[ "$uid" -ge "$UID_MIN" ]] || continue
    [[ "$user" == "nobody" ]] && continue
    u32_is_login_shell "$shell" || continue

    if [[ -z "$home" || "$home" == "/" ]]; then
      bad+=("$user")
      bad_reason+=("HOME 경로 이상(home=$home)")
      continue
    fi
    if [[ ! -e "$home" ]]; then
      bad+=("$user")
      bad_reason+=("홈디렉터리 미존재($home)")
      continue
    fi
    if [[ ! -d "$home" ]]; then
      bad+=("$user")
      bad_reason+=("홈 경로가 디렉터리가 아님($home)")
      continue
    fi
    if [[ -L "$home" ]]; then
      bad+=("$user")
      bad_reason+=("홈디렉터리가 심볼릭 링크($home)")
      continue
    fi

    local owner perm mode
    owner="$(stat -c '%U' "$home" 2>/dev/null || echo "")"
    perm="$(stat -c '%a' "$home" 2>/dev/null || echo "")"
    [[ -n "$owner" && -n "$perm" ]] || continue
    if [[ "$owner" != "$user" ]]; then
      bad+=("$user")
      bad_reason+=("홈디렉터리 소유자 불일치(owner=$owner, home=$home)")
    fi
    mode=$((8#$perm))
    if (( (mode & 0022) != 0 )); then
      bad+=("$user")
      bad_reason+=("홈디렉터리 그룹/기타 쓰기 권한 존재(perm=$perm, home=$home)")
    fi
  done < /etc/passwd

  if [[ "${#bad[@]}" -eq 0 ]]; then
    echo "※ U-32 결과 : 양호(Good)" >> "$resultfile" 2>&1
  else
    echo "※ U-32 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 취약 항목 수: ${#bad[@]}" >> "$resultfile" 2>&1
    local i limit=30
    for i in "${!bad[@]}"; do
      [[ "$i" -ge "$limit" ]] && { echo " - ... (생략)" >> "$resultfile" 2>&1; break; }
      echo " - ${bad[$i]} : ${bad_reason[$i]}" >> "$resultfile" 2>&1
    done
  fi
  return 0
}

U_33() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-33(하) | 2. 파일 및 디렉토리 관리 > 2.20 숨겨진 파일 및 디렉토리 검색 및 제거 ◀" >> "$resultfile" 2>&1
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
        PORT_CHECK=$(ss -nlp 2>/dev/null | grep -w ":79")
    else
        PORT_CHECK=$(netstat -natp 2>/dev/null | grep -w ":79")
    fi  # [수정] 여기에 fi를 추가하여 if문을 닫았습니다.

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

U_35() {
    vuln_flag=0
    evidence_flag=0
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-35(상) | 3. 서비스 관리 > 3.2 공유 서비스에 대한 익명 접근 제한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 공유 서비스에 대해 익명 접근을 제한한 경우" >> "$resultfile" 2>&1
    print_vuln_header_once() {
        if [ "$evidence_flag" -eq 0 ]; then
            echo "※ U-35 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
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
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q installed && ftp_pkg=1
        dpkg-query -W -f='${Status}' proftpd 2>/dev/null | grep -q installed && ftp_pkg=1
    fi
    is_active_service vsftpd && ftp_running=1
    is_active_service proftpd && ftp_running=1
    is_listening_port 21 && ftp_running=1
    for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        if [ -f "$conf" ]; then
            ftp_conf_found=1
            last_val=$(
                grep -i '^[[:space:]]*anonymous_enable[[:space:]]*=' "$conf" 2>/dev/null \
                | grep -v '^[[:space:]]*#' \
                | tail -n 1 \
                | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}'
            )
            if [ "$last_val" = "yes" ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " $conf 파일에서 익명 FTP 접속 허용(anonymous_enable=YES)." >> "$resultfile" 2>&1
            fi
        fi
    done
    for conf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        if [ -f "$conf" ]; then
            ftp_conf_found=1
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
                echo " $conf 파일에서 익명(Anonymous) FTP 설정 블록이 존재합니다." >> "$resultfile" 2>&1
            fi
        fi
    done
    if { [ "$ftp_pkg" -eq 1 ] || [ "$ftp_running" -eq 1 ]; } && [ "$ftp_conf_found" -eq 0 ]; then
        vuln_flag=1
        print_vuln_header_once
        echo " FTP 서비스가 동작 중이거나 설치되어 있으나, 설정 파일을 확인할 수 없습니다." >> "$resultfile" 2>&1
    fi
    nfs_checked=0
    nfs_running=0
    nfs_conf_found=0
    [ -f /etc/exports ] && nfs_conf_found=1
    is_active_service nfs-server && nfs_running=1
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Status}' nfs-kernel-server 2>/dev/null | grep -q installed && nfs_checked=1
    fi
    if [ "$nfs_conf_found" -eq 1 ] || [ "$nfs_running" -eq 1 ]; then
        nfs_checked=1
    fi
    if [ "$nfs_checked" -eq 1 ]; then
        if [ -f /etc/exports ]; then
            grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
            | grep -E 'no_root_squash|\*' >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " /etc/exports 파일에 익명/전체 공유 설정(no_root_squash 또는 *)이 존재합니다." >> "$resultfile" 2>&1
            fi
        elif [ "$nfs_running" -eq 1 ]; then
            vuln_flag=1
            print_vuln_header_once
            echo " NFS 서비스가 동작 중이나 /etc/exports 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        fi
    fi
    smb_checked=0
    smb_running=0
    smb_conf_found=0
    [ -f /etc/samba/smb.conf ] && smb_conf_found=1
    is_active_service smbd && smb_running=1
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Status}' samba 2>/dev/null | grep -q installed && smb_checked=1
    fi
    if [ "$smb_conf_found" -eq 1 ] || [ "$smb_running" -eq 1 ]; then
        smb_checked=1
    fi
    if [ "$smb_checked" -eq 1 ]; then
        if [ -f /etc/samba/smb.conf ]; then
            smb_hits=$(
                grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
                | grep -Ei 'guest[[:space:]]+ok|public[[:space:]]*=|map[[:space:]]+to[[:space:]]+guest|security[[:space:]]*=[[:space:]]*share'
            )
            if [ -n "$smb_hits" ]; then
                vuln_flag=1
                print_vuln_header_once
                echo " /etc/samba/smb.conf 익명/게스트 접근 유발 가능 설정이 존재합니다." >> "$resultfile" 2>&1
                echo "$smb_hits" | head -n 5 | sed 's/^/  - /' >> "$resultfile" 2>&1
            fi
        elif [ "$smb_running" -eq 1 ]; then
            vuln_flag=1
            print_vuln_header_once
            echo " Samba 서비스가 동작 중이나 /etc/samba/smb.conf 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        fi
    fi
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-35 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

U_36(){
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-36(상) | 3. 서비스 관리 > 3.3 r 계열 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 r 계열 서비스가 비활성화된 경우 " >> "$resultfile" 2>&1

  VULN=0
  REASON=""

  CHECK_PORT=$(ss -antl 2>/dev/null | grep -E ':512|:513|:514')

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
    XINETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec 2>/dev/null)
    if [ -n "$XINETD_VUL" ]; then
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

U_37() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-37(상) | 3. 서비스 관리 > 3.4 cron/at 관련 파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : cron/at 관련 파일이 root 소유이며 다른 사용자 쓰기 권한이 없는 경우" >> "$resultfile" 2>&1

  local -a bad=()
  local -a bad_reason=()

  u37_chk_owner_root_nowrite() {
    local p="$1"
    [[ -e "$p" ]] || return 0
    local uid perm mode
    uid="$(stat -c '%u' "$p" 2>/dev/null || echo "")"
    perm="$(stat -c '%a' "$p" 2>/dev/null || echo "")"
    [[ -n "$uid" && -n "$perm" ]] || return 0
    mode=$((8#$perm))
    if [[ "$uid" != "0" ]]; then
      bad+=("$p"); bad_reason+=("root 소유 아님(uid=$uid)")
      return 0
    fi
    if (( (mode & 0022) != 0 )); then
      bad+=("$p"); bad_reason+=("그룹/기타 쓰기 권한 존재(perm=$perm)")
      return 0
    fi
  }

  u37_chk_suid_sgid() {
    local p="$1"
    [[ -e "$p" ]] || return 0
    local perm mode
    perm="$(stat -c '%a' "$p" 2>/dev/null || echo "")"
    [[ -n "$perm" ]] || return 0
    mode=$((8#$perm))
    if (( (mode & 06000) != 0 )); then
      bad+=("$p"); bad_reason+=("SUID/SGID 설정 존재(perm=$perm)")
    fi
  }

  u37_chk_owner_root_nowrite /etc/crontab
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$d" ]] || continue
    u37_chk_owner_root_nowrite "$d"
    while IFS= read -r -d '' f; do
      u37_chk_owner_root_nowrite "$f"
    done < <(find "$d" -type f -print0 2>/dev/null)
  done

  for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [[ -e "$f" ]] && u37_chk_owner_root_nowrite "$f"
  done

  u37_chk_suid_sgid /usr/bin/crontab
  u37_chk_suid_sgid /usr/bin/at

  if [[ "${#bad[@]}" -eq 0 ]]; then
    echo "※ U-37 결과 : 양호" >> "$resultfile" 2>&1
  else
    echo "※ U-37 결과 : 취약" >> "$resultfile" 2>&1
    echo " 취약 항목 수: ${#bad[@]}" >> "$resultfile" 2>&1
    local i limit=40
    for i in "${!bad[@]}"; do
      [[ "$i" -ge "$limit" ]] && { echo " - ... (생략)" >> "$resultfile" 2>&1; break; }
      echo " - ${bad[$i]} : ${bad_reason[$i]}" >> "$resultfile" 2>&1
    done
  fi
  return 0
}

U_38() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-38(상) | 3. 서비스 관리 > 3.5 DoS 공격에 취약한 서비스 비활성화 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 해당 서비스를 사용하지 않는 경우 N/A, (2) DoS 공격에 취약한 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

  local in_scope_active=0
  local vulnerable=0

  local ports=("7" "9" "13" "19")
  local protos=("tcp" "udp")

  if command -v systemctl >/dev/null 2>&1; then
    local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")
    local sock
    for sock in "${systemd_sockets[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$sock"; then
        if systemctl is-enabled --quiet "$sock" 2>/dev/null || systemctl is-active --quiet "$sock" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          echo "※ 취약 징후: systemd ${sock} 가 활성화되어 있습니다. (enabled/active)" >> "$resultfile" 2>&1
        else
          echo "※ 참고: systemd ${sock} 유닛이 존재하나 비활성화 상태입니다." >> "$resultfile" 2>&1
        fi
      fi
    done
  fi

  if command -v ss >/dev/null 2>&1; then
    local p proto
    for p in "${ports[@]}"; do
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
        in_scope_active=1
        vulnerable=1
        echo "※ 취약 징후: ${p}/tcp 포트가 리스닝 중입니다. (echo/discard/daytime/chargen 계열 가능)" >> "$resultfile" 2>&1
      fi
      if ss -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
        in_scope_active=1
        vulnerable=1
        echo "※ 취약 징후: ${p}/udp 포트가 리스닝 중입니다. (echo/discard/daytime/chargen 계열 가능)" >> "$resultfile" 2>&1
      fi
    done
  else
    if command -v netstat >/dev/null 2>&1; then
      local p
      for p in "${ports[@]}"; do
        if netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
          in_scope_active=1
          vulnerable=1
          echo "※ 취약 징후: ${p}/tcp 포트가 리스닝 중입니다. (netstat 기준)" >> "$resultfile" 2>&1
        fi
        if netstat -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
          in_scope_active=1
          vulnerable=1
          echo "※ 취약 징후: ${p}/udp 포트가 리스닝 중입니다. (netstat 기준)" >> "$resultfile" 2>&1
        fi
      done
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local info_units=("snmpd.service" "bind9.service" "named.service" "systemd-timesyncd.service" "chronyd.service" "ntpd.service")
    local u
    for u in "${info_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
        if systemctl is-enabled --quiet "$u" 2>/dev/null || systemctl is-active --quiet "$u" 2>/dev/null; then
          echo "※ info: ${u} 활성화 감지(환경에 따라 정상일 수 있음)" >> "$resultfile" 2>&1
        fi
      fi
    done
  fi

  if [ "$in_scope_active" -eq 0 ]; then
    echo "※ U-38 결과 : N/A" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스(echo/discard/daytime/chargen)가 사용되지 않는 것으로 확인되어 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-38 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 활성화되어 있습니다. (포트 리스닝 또는 socket 활성)" >> "$resultfile" 2>&1
  else
    echo "※ U-38 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 비활성화되어 있습니다. (활성 서비스 미확인)" >> "$resultfile" 2>&1
  fi

  return 0
}

U_40() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-40(상) | 3. 서비스 관리 > 3.7 NFS 접근 통제 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우" >> "$resultfile" 2>&1
    nfs_proc_count=$(ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd' | wc -l)
    if [ "$nfs_proc_count" -gt 0 ]; then
        if [ -f /etc/exports ]; then
            etc_exports_all_count=$(grep -vE '^#|^[[:space:]]#' /etc/exports | grep '/' | grep '\*' | wc -l)
            etc_exports_insecure_count=$(grep -vE '^#|^[[:space:]]#' /etc/exports | grep '/' | grep -i 'insecure' | wc -l)
            etc_exports_directory_count=$(grep -vE '^#|^[[:space:]]#' /etc/exports | grep '/' | wc -l)
            etc_exports_squash_count=$(grep -vE '^#|^[[:space:]]#' /etc/exports | grep '/' | grep -iE 'root_squash|all_squash' | wc -l)
            if [ "$etc_exports_all_count" -gt 0 ]; then
                echo "※ U-40 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                echo " /etc/exports 파일에 '*' 설정이 있습니다." >> "$resultfile" 2>&1
                echo " ### '*' 설정 = 모든 클라이언트에 대해 전체 네트워크 공유 허용" >> "$resultfile" 2>&1
            elif [ "$etc_exports_insecure_count" -gt 0 ]; then
                echo "※ U-40 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                echo " /etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다." >> "$resultfile" 2>&1
            else
                if [ "$etc_exports_directory_count" -ne "$etc_exports_squash_count" ]; then
                    echo "※ U-40 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                    echo " /etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다." >> "$resultfile" 2>&1
                else
                    echo "※ U-40 결과 : 양호(Good)" >> "$resultfile" 2>&1
                fi
            fi
        else
            echo "※ U-40 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " NFS 관련 프로세스가 동작 중이나 /etc/exports 파일이 존재하지 않습니다." >> "$resultfile" 2>&1
        fi
    else
        echo "※ U-40 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
}

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

U_42() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-42(상) | 3. 서비스 관리 > 3.9 RPC 서비스 확인 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 RPC 서비스가 동작하지 않는 경우" >> "$resultfile" 2>&1

  local -a bad=()
  local -a observed=()
  local -a risky=("rusersd" "rstatd" "rwalld" "sprayd" "rexd" "ypserv" "yppasswdd" "ypxfrd" "ttdbserverd" "sadmind" "cmsd")

  local rpc_listen=0
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -Eq '(:111[[:space:]]|:sunrpc[[:space:]])' && rpc_listen=1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -Eq '(:111[[:space:]]|:sunrpc[[:space:]])' && rpc_listen=1
  fi

  if [[ "$rpc_listen" -eq 0 ]]; then
    echo "※ U-42 결과 : 양호" >> "$resultfile" 2>&1
    echo " - RPC 포트(111) 리스닝 없음" >> "$resultfile" 2>&1
    return 0
  fi

  if ! command -v rpcinfo >/dev/null 2>&1; then
    echo "※ U-42 결과 : N/A" >> "$resultfile" 2>&1
    echo " - rpcinfo 명령이 없어 RPC 서비스 목록을 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  local out line
  out="$(rpcinfo -p 2>/dev/null || true)"
  if [[ -z "$out" ]]; then
    echo "※ U-42 결과 : N/A" >> "$resultfile" 2>&1
    echo " - rpcinfo 출력이 비어있어 RPC 프로그램을 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  while IFS= read -r line; do
    [[ "$line" =~ ^program[[:space:]] ]] && continue
    local name
    name="$(echo "$line" | awk '{print $NF}')"
    [[ -n "$name" ]] && observed+=("$name")
  done <<< "$out"

  local r s
  for r in "${risky[@]}"; do
    if echo "$out" | grep -qw "$r"; then
      bad+=("$r")
    fi
  done

  if [[ "${#bad[@]}" -eq 0 ]]; then
    echo "※ U-42 결과 : 양호" >> "$resultfile" 2>&1
    echo " - RPC 서비스 동작은 확인되나(예: NFS), 위험 RPC 서비스는 확인되지 않음" >> "$resultfile" 2>&1
  else
    echo "※ U-42 결과 : 취약" >> "$resultfile" 2>&1
    echo " - 위험 RPC 서비스 동작 확인: ${bad[*]}" >> "$resultfile" 2>&1
  fi

  echo " - rpcinfo -p 요약:" >> "$resultfile" 2>&1
  echo "$out" | head -n 30 >> "$resultfile" 2>&1
  if [[ "$(echo "$out" | wc -l)" -gt 30 ]]; then
    echo " - ... (생략)" >> "$resultfile" 2>&1
  fi
  return 0
}

U_43() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-43(상) | 3. 서비스 관리 > 3.10 NIS, NIS+ 점검 ◀"  >> "$resultfile" 2>&1
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

U_45() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-45(상) | 3. 서비스 관리 > 3.12 메일 서비스 버전 점검 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 메일 서비스 버전이 최신버전인 경우" >> "$resultfile" 2>&1
    smtp_running=0
    if command -v ss >/dev/null 2>&1; then
        ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ':(25|465|587)$' && smtp_running=1
    fi
    ps -ef | grep -iE 'sendmail|smtp' | grep -v grep >/dev/null 2>&1 && smtp_running=1
    if [ "$smtp_running" -eq 0 ]; then
        echo "※ U-45 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " 메일 서비스가 동작 중이지 않습니다." >> "$resultfile" 2>&1
        return 0
    fi
    if command -v dpkg-query >/dev/null 2>&1; then
        sendmail_ver=$(dpkg-query -W -f='${Version}' sendmail 2>/dev/null)
        if [ -n "$sendmail_ver" ]; then
            echo "$sendmail_ver" | grep -q '^8\.18\.2' && {
                echo "※ U-45 결과 : 양호(Good)" >> "$resultfile" 2>&1
                return 0
            }
            echo "※ U-45 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " 메일 서비스 버전이 최신 버전(8.18.2)이 아닙니다. (version=$sendmail_ver)" >> "$resultfile" 2>&1
            return 0
        fi
    fi
    echo "※ U-45 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 메일 서비스(sendmail)가 동작 중이나 버전 정보를 확인할 수 없습니다." >> "$resultfile" 2>&1
}

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

U_47() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-47(상) | 3. 서비스 관리 > 3.14 스팸 메일 릴레이 제한 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SMTP 릴레이가 인증/허용 네트워크로 제한되어 오픈 릴레이가 아닌 경우" >> "$resultfile" 2>&1

  local listening=0
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -Eq ':(25|465|587)[[:space:]]' && listening=1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -Eq ':(25|465|587)[[:space:]]' && listening=1
  fi

  if [[ "$listening" -eq 0 ]]; then
    echo "※ U-47 결과 : 양호" >> "$resultfile" 2>&1
    echo " - SMTP 포트(25/465/587) 리스닝 없음" >> "$resultfile" 2>&1
    return 0
  fi

  local -a reasons=()
  local ok=1

  if command -v postconf >/dev/null 2>&1 || [[ -r /etc/postfix/main.cf ]]; then
    local relay_recipient mynetworks
    relay_recipient="$(postconf -n 2>/dev/null | awk -F' = ' '/^(smtpd_relay_restrictions|smtpd_recipient_restrictions)\s*=/{print $2}' | tr '\n' ' ')"
    mynetworks="$(postconf -n 2>/dev/null | awk -F' = ' '/^mynetworks\s*=/{print $2}' | tail -n1)"

    if ! echo "$relay_recipient" | grep -Eq '(reject_unauth_destination|defer_unauth_destination)'; then
      ok=0
      reasons+=("Postfix 릴레이 제한 규칙(reject_unauth_destination)이 확인되지 않음")
    fi

    if echo "${mynetworks:-}" | grep -Eq '(^|,|\s)(0\.0\.0\.0/0|0/0|::/0)(,|\s|$)'; then
      ok=0
      reasons+=("mynetworks 가 과도하게 넓음(mynetworks=$mynetworks)")
    fi

    if [[ "$ok" -eq 1 ]]; then
      echo "※ U-47 결과 : 양호" >> "$resultfile" 2>&1
      echo " - Postfix 릴레이 제한 설정 확인(reject_unauth_destination 포함)" >> "$resultfile" 2>&1
    else
      echo "※ U-47 결과 : 취약" >> "$resultfile" 2>&1
      local r
      for r in "${reasons[@]}"; do
        echo " - $r" >> "$resultfile" 2>&1
      done
    fi
    return 0
  fi

  if [[ -r /etc/exim4/update-exim4.conf.conf ]]; then
    local relay_nets
    relay_nets="$(grep -E '^[[:space:]]*dc_relay_nets=' /etc/exim4/update-exim4.conf.conf 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"')"
    if echo "${relay_nets:-}" | grep -Eq '(0\.0\.0\.0/0|0/0|::/0)'; then
      echo "※ U-47 결과 : 취약" >> "$resultfile" 2>&1
      echo " - Exim4 dc_relay_nets 가 과도하게 넓음($relay_nets)" >> "$resultfile" 2>&1
    else
      echo "※ U-47 결과 : N/A" >> "$resultfile" 2>&1
      echo " - Exim4 사용 가능성이 있으나 오픈 릴레이 여부 정밀 판단은 수동 확인 필요" >> "$resultfile" 2>&1
      echo " - 참고: dc_relay_nets=$relay_nets" >> "$resultfile" 2>&1
    fi
    return 0
  fi

  echo "※ U-47 결과 : N/A" >> "$resultfile" 2>&1
  echo " - SMTP 리스닝은 확인되나(Postfix/Exim 설정 미확인), MTA별 설정에 따라 수동 점검 필요" >> "$resultfile" 2>&1
  return 0
}

U_48() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-48(중) | 3. 서비스 관리 > 3.15 expn, vrfy 명령어 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 메일 서비스를 사용하지 않는 경우 N/A, (2) 사용 시 VRFY/EXPN 제한 설정이 적용된 경우" >> "$resultfile" 2>&1

  local mail_in_use=0
  local vulnerable=0
  local evidences=()

  local has_postfix=0
  local has_exim=0

  local STRICT_EXIM=1

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
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "postfix.service"; then
      if systemctl is-active --quiet "postfix.service" 2>/dev/null; then
        mail_in_use=1
        has_postfix=1
        evidences+=("systemd: postfix.service active")
      fi
    fi
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "exim4.service"; then
      if systemctl is-active --quiet "exim4.service" 2>/dev/null; then
        mail_in_use=1
        has_exim=1
        evidences+=("systemd: exim4.service active")
      fi
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE 'postfix.*master|/usr/lib/postfix/sbin/master|/usr/sbin/postfix' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_postfix=1
    evidences+=("process: postfix(master 등) 프로세스 감지")
  fi
  if ps -ef 2>/dev/null | grep -iE '\bexim4?\b' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_exim=1
    evidences+=("process: exim/exim4 프로세스 감지")
  fi

  if [ "$mail_in_use" -eq 0 ]; then
    echo "※ U-48 결과 : N/A" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (25/tcp LISTEN 및 MTA 미검출)" >> "$resultfile" 2>&1
    return 0
  fi

  local ok_cnt=0
  local bad_cnt=0

  if [ "$has_postfix" -eq 1 ]; then
    local maincf="/etc/postfix/main.cf"
    if [ -f "$maincf" ]; then
      local postfix_vrfy
      postfix_vrfy=$(grep -vE '^\s*#' "$maincf" 2>/dev/null \
        | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l)

      local discard_ehlo
      discard_ehlo=$(grep -vE '^\s*#' "$maincf" 2>/dev/null \
        | grep -iE '^\s*smtpd_discard_ehlo_keywords\s*=')

      if [ "$postfix_vrfy" -gt 0 ]; then
        ok_cnt=$((ok_cnt+1))
        evidences+=("postfix: $maincf 에 disable_vrfy_command=yes 설정 확인")
      else
        vulnerable=1
        bad_cnt=$((bad_cnt+1))
        evidences+=("postfix: postfix 사용 중이나 disable_vrfy_command=yes 설정이 없음")
      fi

      if [ -n "$discard_ehlo" ]; then
        if echo "$discard_ehlo" | grep -qiE 'vrfy|expn'; then
          evidences+=("postfix: smtpd_discard_ehlo_keywords 에 vrfy/expn 관련 설정 확인: $discard_ehlo")
        else
          evidences+=("postfix: smtpd_discard_ehlo_keywords 설정 존재(참고): $discard_ehlo")
        fi
      else
        evidences+=("postfix: smtpd_discard_ehlo_keywords 미설정(권장 옵션, 필수는 아님)")
      fi
    else
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("postfix: postfix 사용 흔적은 있으나 $maincf 파일이 없습니다. (설정 점검 불가)")
    fi
  fi

  if [ "$has_exim" -eq 1 ]; then
    if [ "$STRICT_EXIM" -eq 1 ]; then
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("exim4: exim4 사용 감지. vrfy/expn 제한 설정 자동 판별이 어려워 보수적으로 취약 처리(정책 STRICT_EXIM=1).")
      evidences+=("exim4: 수동 확인 후보: /etc/exim4/exim4.conf.template 또는 /var/lib/exim4/config.autogenerated")
    else
      evidences+=("exim4: exim4 사용 감지(구성 기반 VRFY/EXPN 제한 수동 확인 필요).")
      evidences+=("exim4: 확인 후보: /etc/exim4/exim4.conf.template 또는 /var/lib/exim4/config.autogenerated")
    fi
  fi

  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-48 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 VRFY/EXPN 제한 설정이 미흡합니다. (미설정/점검불가=$bad_cnt, 설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  else
    echo "※ U-48 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 VRFY/EXPN 제한 설정이 확인되었습니다. (설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  fi

  return 0
}

U_50() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-50(상) | 3. 서비스 관리 > 3.17 DNS Zone Transfer 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : Zone Transfer를 허가된 사용자에게만 허용한 경우" >> "$resultfile" 2>&1
    dns_running=0
    systemctl is-active --quiet bind9 2>/dev/null && dns_running=1
    ps -ef | grep -i named | grep -v grep >/dev/null 2>&1 && dns_running=1
    if [ "$dns_running" -eq 1 ]; then
        if [ -f /etc/bind/named.conf.options ]; then
            if grep -vE '^#|^[[:space:]]#' /etc/bind/named.conf.options | grep -qiE 'allow-transfer[[:space:]]*\{[[:space:]]*any[[:space:]]*;' ; then
                echo "※ U-50 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                echo " /etc/bind/named.conf.options 파일에 allow-transfer { any; } 설정이 있습니다." >> "$resultfile" 2>&1
                return 0
            fi
        fi
        if grep -R -vE '^#|^[[:space:]]#' /etc/bind 2>/dev/null | grep -qiE 'allow-transfer[[:space:]]*\{[[:space:]]*any[[:space:]]*;' ; then
            echo "※ U-50 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            echo " /etc/bind 설정 파일에 allow-transfer { any; } 설정이 있습니다." >> "$resultfile" 2>&1
            return 0
        fi
    fi
    echo "※ U-50 결과 : 양호(Good)" >> "$resultfile" 2>&1
}

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

U_52() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-52(중) | 3. 서비스 관리 > 3.19 DNS 보안 버전 정보 숨김 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : DNS(BIND) 사용 시 버전 정보가 노출되지 않도록 version 옵션이 적절히 설정된 경우" >> "$resultfile" 2>&1

  local listening=0
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -Eq ':(53)[[:space:]]' && listening=1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -Eq ':(53)[[:space:]]' && listening=1
  fi

  if [[ "$listening" -eq 0 ]]; then
    echo "※ U-52 결과 : 양호" >> "$resultfile" 2>&1
    echo " - DNS 포트(53) 리스닝 없음" >> "$resultfile" 2>&1
    return 0
  fi

  local -a files=()
  local f
  for f in /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/*.conf /etc/bind/*.options; do
    [[ -r "$f" ]] && files+=("$f")
  done
  if [[ "${#files[@]}" -eq 0 ]]; then
    echo "※ U-52 결과 : N/A" >> "$resultfile" 2>&1
    echo " - /etc/bind 설정 파일을 찾지 못했습니다(BIND 사용 여부 수동 확인 필요)" >> "$resultfile" 2>&1
    return 0
  fi

  local version_line=""
  version_line="$(grep -R --line-number -E '^[[:space:]]*version[[:space:]]+"[^"]+"' "${files[@]}" 2>/dev/null | head -n1 || true)"

  if [[ -z "$version_line" ]]; then
    echo "※ U-52 결과 : 취약" >> "$resultfile" 2>&1
    echo " - version \"...\" 설정이 확인되지 않음(기본 버전 정보 노출 가능)" >> "$resultfile" 2>&1
    return 0
  fi

  local ver_value
  ver_value="$(echo "$version_line" | sed -n 's/.*version[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if echo "$ver_value" | grep -Eq '[0-9]+\.[0-9]+'; then
    echo "※ U-52 결과 : 취약" >> "$resultfile" 2>&1
    echo " - version 값에 버전 문자열로 보이는 숫자 패턴 포함(version=\"$ver_value\")" >> "$resultfile" 2>&1
    echo " - 발견 위치: $version_line" >> "$resultfile" 2>&1
  else
    echo "※ U-52 결과 : 양호" >> "$resultfile" 2>&1
    echo " - version 옵션 설정 확인(version=\"$ver_value\")" >> "$resultfile" 2>&1
    echo " - 발견 위치: $version_line" >> "$resultfile" 2>&1
  fi
  return 0
}

U_53() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-53(하) | 3. 서비스 관리 > 3.20 FTP 서비스 정보 노출 제한 ◀" >> "$resultfile" 2>&1
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

U_55() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-55(중) | 3. 서비스 관리 > 3.22 FTP 계정 Shell 제한 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우" >> "$resultfile" 2>&1
    ftp_installed=0
    dpkg -l 2>/dev/null | grep -qE 'vsftpd|proftpd' && ftp_installed=1
    if [ "$ftp_installed" -eq 0 ]; then
        echo "※ U-55 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " FTP 서비스가 미설치되어 있습니다." >> "$resultfile" 2>&1
        return 0
    fi
    ftp_users="ftp vsftpd proftpd"
    ftp_exist=0
    ftp_vuln=0
    for user in $ftp_users; do
        if id "$user" >/dev/null 2>&1; then
            ftp_exist=1
            shell=$(awk -F: -v u="$user" '$1==u{print $7}' /etc/passwd)
            if [ "$shell" != "/bin/false" ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/sbin/nologin" ]; then
                ftp_vuln=1
            fi
        fi
    done
    if [ "$ftp_exist" -eq 0 ]; then
        echo "※ U-55 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " FTP 계정이 존재하지 않습니다." >> "$resultfile" 2>&1
    elif [ "$ftp_vuln" -eq 1 ]; then
        echo "※ U-55 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " ftp 계정에 /bin/false 쉘이 부여되어 있지 않습니다." >> "$resultfile" 2>&1
    else
        echo "※ U-55 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " ftp 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다." >> "$resultfile" 2>&1
    fi
}

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

U_57() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-57(중) | 3. 서비스 관리 > 3.24 ftpusers 파일 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : FTP 사용 시 root 등 중요 계정의 FTP 접속이 제한되어 있는 경우" >> "$resultfile" 2>&1

  local ftp_on=0
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -Eq ':(21)[[:space:]]' && ftp_on=1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -Eq ':(21)[[:space:]]' && ftp_on=1
  fi
  pgrep -f 'vsftpd|proftpd|pure-ftpd|in\.ftpd|ftpd' >/dev/null 2>&1 && ftp_on=1

  if [[ "$ftp_on" -eq 0 ]]; then
    echo "※ U-57 결과 : 양호" >> "$resultfile" 2>&1
    echo " - FTP 서비스 미사용(포트/프로세스 기반 확인)" >> "$resultfile" 2>&1
    return 0
  fi

  local -a candidates=(
    "/etc/ftpusers"
    "/etc/vsftpd/ftpusers"
    "/etc/vsftpd.ftpusers"
    "/etc/vsftpd.user_list"
    "/etc/vsftpd.userlist"
    "/etc/proftpd/ftpusers"
  )

  if [[ -r /etc/vsftpd.conf ]]; then
    local uf
    uf="$(grep -E '^[[:space:]]*userlist_file=' /etc/vsftpd.conf 2>/dev/null | tail -n1 | cut -d= -f2-)"
    [[ -n "$uf" ]] && candidates=("$uf" "${candidates[@]}")
  fi

  local found_file=""
  local f2
  for f2 in "${candidates[@]}"; do
    [[ -r "$f2" ]] || continue
    found_file="$f2"
    break
  done

  if [[ -z "$found_file" ]]; then
    echo "※ U-57 결과 : 취약" >> "$resultfile" 2>&1
    echo " - FTP 사용 징후가 있으나 ftpusers(userlist) 파일을 찾지 못함" >> "$resultfile" 2>&1
    return 0
  fi

  if grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$found_file" 2>/dev/null; then
    echo "※ U-57 결과 : 양호" >> "$resultfile" 2>&1
    echo " - root 계정 FTP 접속 제한 확인($found_file)" >> "$resultfile" 2>&1
  else
    echo "※ U-57 결과 : 취약" >> "$resultfile" 2>&1
    echo " - root 계정 차단이 확인되지 않음($found_file)" >> "$resultfile" 2>&1
  fi
  return 0
}

U_58() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-58(중) | 3. 서비스 관리 > 3.25 불필요한 SNMP 서비스 구동 점검 ◀" >> "$resultfile" 2>&1
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

U_60() {
    echo "" >> "$resultfile" 2>&1
    echo " ▶ U-60(중) | 3. 서비스 관리 > 3.27 SNMP Community String 복잡성 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우" >> "$resultfile" 2>&1
    vuln_flag=0
    community_found=0
    if ! dpkg -l 2>/dev/null | grep -qE '^ii\s+snmpd'; then
        echo "※ U-60 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " SNMP 서비스가 미설치되어있습니다." >> "$resultfile" 2>&1
        return 0
    fi
    if ! systemctl is-active snmpd >/dev/null 2>&1; then
        echo "※ U-60 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " SNMP 서비스가 비활성 상태입니다." >> "$resultfile" 2>&1
        return 0
    fi
    snmpdconf_files=()
    [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
    while IFS= read -r f; do snmpdconf_files+=("$f"); done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)
    if [ ${#snmpdconf_files[@]} -eq 0 ]; then
        echo "※ U-60 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " SNMP 서비스를 사용하고, Community String을 설정하는 파일이 없습니다." >> "$resultfile" 2>&1
        return 0
    fi
    is_strong_community() {
        s="$1"
        s="${s%\"}"; s="${s#\"}"
        s="${s%\'}"; s="${s#\'}"
        echo "$s" | grep -qiE '^(public|private)$' && return 1
        len=${#s}
        echo "$s" | grep -qE '[A-Za-z]' || return 1
        echo "$s" | grep -qE '[0-9]' || return 1
        if [ "$len" -ge 10 ]; then return 0; fi
        echo "$s" | grep -qE '[^A-Za-z0-9]' || return 1
        [ "$len" -ge 8 ] && return 0
        return 1
    }
    for conf in "${snmpdconf_files[@]}"; do
        while IFS= read -r comm; do
            community_found=1
            if ! is_strong_community "$comm"; then
                [ "$vuln_flag" -eq 0 ] && echo "※ U-60 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                [ "$vuln_flag" -eq 0 ] && echo " SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다." >> "$resultfile" 2>&1
                vuln_flag=1
            fi
        done < <(grep -vE '^\s*#|^\s*$' "$conf" 2>/dev/null | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}')
        while IFS= read -r comm; do
            community_found=1
            if ! is_strong_community "$comm"; then
                [ "$vuln_flag" -eq 0 ] && echo "※ U-60 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
                [ "$vuln_flag" -eq 0 ] && echo " SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다." >> "$resultfile" 2>&1
                vuln_flag=1
            fi
        done < <(grep -vE '^\s*#|^\s*$' "$conf" 2>/dev/null | awk 'tolower($1)=="com2sec" {print $4}')
    done
    if [ "$community_found" -eq 0 ]; then
        echo "※ U-60 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " SNMP 서비스를 사용하나 Community String 설정(rocommunity/rwcommunity/com2sec)을 확인할 수 없습니다." >> "$resultfile" 2>&1
        return 0
    fi
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-60 결과 : 양호(Good)" >> "$resultfile" 2>&1
        echo " SNMP Community String이 복잡성 기준을 만족합니다." >> "$resultfile" 2>&1
    fi
}

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

U_62() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-62(상) | 3. 서비스 관리 > 3.29 경고 메시지 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그인(SSH/콘솔) 시 비인가 접근 금지 경고 문구가 설정된 경우" >> "$resultfile" 2>&1

  local -a warn_files=("/etc/issue" "/etc/issue.net" "/etc/motd")
  local -a candidates=()
  local f
  for f in "${warn_files[@]}"; do
    [[ -r "$f" ]] && candidates+=("$f")
  done

  if command -v sshd >/dev/null 2>&1; then
    local banner
    banner="$(sshd -T 2>/dev/null | awk '/^banner /{print $2}' | tail -n1)"
    if [[ -n "$banner" && "$banner" != "none" && -r "$banner" ]]; then
      candidates+=("$banner")
    fi
  fi

  if [[ "${#candidates[@]}" -eq 0 ]]; then
    echo "※ U-62 결과 : 취약" >> "$resultfile" 2>&1
    echo " - 경고 메시지 파일(/etc/issue, /etc/issue.net, /etc/motd, sshd Banner)을 확인할 수 없음" >> "$resultfile" 2>&1
    return 0
  fi

  local found=0
  local best_file=""
  local kw
  local -a keywords=("unauthorized" "authorized" "warning" "prohibited" "무단" "불법" "경고" "허가" "접근 금지" "접속 금지")
  for f in "${candidates[@]}"; do
    local content
    content="$(tr -d '\000' < "$f" 2>/dev/null | head -n 50 | tr '[:upper:]' '[:lower:]')"
    [[ -n "$content" ]] || continue
    for kw in "${keywords[@]}"; do
      if echo "$content" | grep -q "$(echo "$kw" | tr '[:upper:]' '[:lower:]')"; then
        found=1
        best_file="$f"
        break 2
      fi
    done
  done

  if [[ "$found" -eq 1 ]]; then
    echo "※ U-62 결과 : 양호" >> "$resultfile" 2>&1
    echo " - 경고 메시지 문구 확인: $best_file" >> "$resultfile" 2>&1
  else
    echo "※ U-62 결과 : 취약" >> "$resultfile" 2>&1
    echo " - 관련 파일은 존재하나 '비인가 접근 금지' 성격의 경고 문구를 찾지 못함" >> "$resultfile" 2>&1
    echo " - 확인 대상: ${candidates[*]}" >> "$resultfile" 2>&1
  fi
  return 0
}

U_63() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-63(중) | 3. 서비스 관리 > 3.30 sudo 명령어 접근 관리 ◀" >> "$resultfile" 2>&1
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

U_65() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-65(중) | 5. 로그 관리 > 5.1 NTP 및 시각 동기화 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우" >> "$resultfile" 2>&1
    timedatectl_ntp=$(timedatectl show -p NTP --value 2>/dev/null | tr -d '\r')
    time_sync_state=$(timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d '\r')
    if [ "$time_sync_state" = "yes" ] && [ "$timedatectl_ntp" = "yes" ]; then
        echo "※ U-65 결과 : 양호(Good)" >> "$resultfile" 2>&1
        return 0
    fi
    is_active_service() { systemctl is-active --quiet "$1" 2>/dev/null; }
    timesyncd_active=0
    chronyd_active=0
    ntpd_active=0
    is_active_service systemd-timesyncd && timesyncd_active=1
    is_active_service chrony && chronyd_active=1
    is_active_service ntp && ntpd_active=1
    if [ "$timesyncd_active" -eq 0 ] && [ "$chronyd_active" -eq 0 ] && [ "$ntpd_active" -eq 0 ]; then
        echo "※ U-65 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " NTP/시각동기화 서비스(systemd-timesyncd/chrony/ntp)가 활성화되어 있지 않습니다." >> "$resultfile" 2>&1
        return 0
    fi
    server_found=0
    sync_ok=0
    if [ "$chronyd_active" -eq 1 ]; then
        for f in /etc/chrony/chrony.conf /etc/chrony.conf /etc/chrony/*.conf; do
            [ -f "$f" ] || continue
            grep -vE '^\s*#|^\s*$' "$f" | grep -qiE '^\s*(server|pool)\s+' && server_found=1 && break
        done
        command -v chronyc >/dev/null 2>&1 && chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+' && sync_ok=1
    fi
    if [ "$server_found" -eq 0 ] && [ "$ntpd_active" -eq 1 ]; then
        for f in /etc/ntp.conf /etc/ntp/*.conf; do
            [ -f "$f" ] || continue
            grep -vE '^\s*#|^\s*$' "$f" | grep -qiE '^\s*server\s+' && server_found=1 && break
        done
        command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | awk 'NR>2{print $1}' | grep -q '^\*' && sync_ok=1
    fi
    if [ "$server_found" -eq 0 ] && [ "$timesyncd_active" -eq 1 ]; then
        if grep -R -vE '^\s*#|^\s*$' /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d 2>/dev/null | grep -qiE '^\s*NTP\s*='; then
            server_found=1
        fi
        [ "$time_sync_state" = "yes" ] && sync_ok=1
    fi
    if [ "$sync_ok" -eq 1 ]; then
        echo "※ U-65 결과 : 양호(Good)" >> "$resultfile" 2>&1
        return 0
    fi
    echo "※ U-65 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " NTP 서비스는 활성화되어 있으나, 서버 설정 또는 동기화 상태를 정상으로 확인하지 못했습니다." >> "$resultfile" 2>&1
}

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

U_67() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-67(중) | 5. 로그 관리 > 5.3 로그 디렉터리 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 로그 디렉터리(/var/log) 및 주요 로그 파일에 불필요한 쓰기 권한이 없는 경우" >> "$resultfile" 2>&1

  local target="/var/log"
  if [[ ! -d "$target" ]]; then
    echo "※ U-67 결과 : N/A" >> "$resultfile" 2>&1
    return 0
  fi

  local vuln=0

  u67_check_path() {
    local p="$1"
    [[ -e "$p" ]] || return 0
    local perm mode
    perm="$(stat -c '%a' "$p" 2>/dev/null || echo "")"
    [[ -n "$perm" ]] || return 0
    mode=$((8#$perm))

    if (( (mode & 0002) != 0 )); then
      vuln=1
      return 0
    fi
    if (( (mode & 0020) != 0 )); then
      vuln=1
      return 0
    fi
    return 0
  }

  u67_check_path "$target"

  if [[ "$vuln" -eq 0 ]]; then
    local p
    while IFS= read -r -d '' p; do
      u67_check_path "$p"
      [[ "$vuln" -eq 1 ]] && break
    done < <(find "$target" \( -type f -o -type d \) -print0 2>/dev/null)
  fi

  if [[ "$vuln" -eq 0 ]]; then
    echo "※ U-67 결과 : 양호" >> "$resultfile" 2>&1
  else
    echo "※ U-67 결과 : 취약" >> "$resultfile" 2>&1
  fi
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
