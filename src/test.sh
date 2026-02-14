#!/usr/bin/env bash
# ============================================================
# KISA UNIX 점검 통합 스크립트 (Rocky Linux 9/10)
# 포함:
#  - U-01, U-02, U-05, U-06, U-07, U-10, U-11, U-12, U-15, U-16, U-17, U-20, U-22, U-27
# 실행: sudo ./kisa_unix_all_report.sh
# 출력:
#  - 화면: 각 항목당 3줄(제목/기준/결과)만 출력
#  - 파일: 같은 내용을 TXT로 저장
# 저장파일:
#  - ./KISA_RESULT_<HOST>_<YYYYmmdd_HHMMSS>.txt
# 종료코드(전체):
#  - 0: 전체 양호
#  - 1: 하나라도 취약
#  - 2: 취약은 없지만 N/A가 하나라도 있음
# ============================================================

set -euo pipefail
LANG=C
LC_ALL=C

HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "HOST")"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="./KISA_RESULT_${HOST}_${TS}.txt"

say(){ printf "%s\n" "$*"; }
log(){ printf "%s\n" "$*" >> "$OUT_FILE"; printf "\n" >> "$OUT_FILE"; }

# 연번 카운터 (1,2,3...)
SEQ=0

emit3(){
  # $1=title, $2=criteria, $3=result_line
  SEQ=$((SEQ + 1))
  say "${SEQ}. $1"; log "${SEQ}. $1"
  say "$2";          log "$2"
  say "$3";          log "$3"
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ======================================================================
# U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한
# ======================================================================
u01_check() {
  local title="▶ U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한 ◀"
  local crit=" 양호 판단 기준 : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"

  local VULN=0
  local BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

  for svc in "${BAD_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}[[:space:]]"; then
      if systemctl is-active "$svc" &>/dev/null; then
        VULN=1
        break
      fi
    fi
  done

  if [[ $VULN -eq 0 ]] && systemctl is-active sshd &>/dev/null; then
    local ROOT_LOGIN
    ROOT_LOGIN="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')"
    [[ "${ROOT_LOGIN:-}" != "no" ]] && VULN=1
  fi

  if [[ $VULN -eq 1 ]]; then
    emit3 "$title" "$crit" "* U-01 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-01 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정
# ======================================================================
u02_check() {
  local TARGET_PASS_MAX_DAYS=90
  local TARGET_PASS_MIN_DAYS=1
  local TARGET_MINLEN=8
  local TARGET_CREDIT=-1
  local TARGET_REMEMBER=4

  is_int(){ [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

  detect_pam_files() {
    local id_like id name
    id_like="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")"
    id="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
    name="$(. /etc/os-release 2>/dev/null; echo "${NAME:-}")"

    local -a files=()
    if [[ "$id_like" == *rhel* || "$id_like" == *fedora* || "$id" == rocky || "$id" == rhel || "$id" == centos || "$name" == *Rocky* ]]; then
      files+=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    else
      files+=("/etc/pam.d/common-password" "/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    fi

    for f in "${files[@]}"; do
      [[ -r "$f" ]] && echo "$f"
    done
  }

  append_conf_d() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    ls -1 "$dir"/*.conf 2>/dev/null | sort || true
  }

  get_kv_last() {
    local key="$1"; shift
    local files=("$@")
    local val="" line f
    for f in "${files[@]}"; do
      [[ -r "$f" ]] || continue
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        if [[ "$line" =~ ^[[:space:]]*$key[[:space:]]*=[[:space:]]*([^[:space:]#]+) ]]; then
          val="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*$key[[:space:]]+([^[:space:]#]+) ]]; then
          val="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*$key([[:space:]]+|$) ]]; then
          if [[ "$key" == "enforce_for_root" ]]; then
            val="__FLAG_PRESENT__"
          fi
        fi
      done < "$f"
    done
    [[ -n "$val" ]] && echo "$val" || echo ""
  }

  pam_check_order_onefile() {
    local module="$1" pam_file="$2"
    [[ -r "$pam_file" ]] || { echo "NA"; return 0; }

    local mod_ln unix_ln
    mod_ln="$(grep -nE "^[[:space:]]*password[[:space:]]+.*${module}\.so\b" "$pam_file" 2>/dev/null | head -n 1 | cut -d: -f1 || true)"
    unix_ln="$(grep -nE "^[[:space:]]*password[[:space:]]+.*pam_unix\.so\b" "$pam_file" 2>/dev/null | head -n 1 | cut -d: -f1 || true)"

    if [[ -n "$mod_ln" && -n "$unix_ln" ]]; then
      (( mod_ln < unix_ln )) && echo "OK" || echo "BAD"
    else
      echo "NA"
    fi
  }

  pam_extract_opt_firstline() {
    local module="$1" key="$2"; shift 2
    local -a pam_files=("$@")
    local f line v
    for f in "${pam_files[@]}"; do
      [[ -r "$f" ]] || continue
      line="$(grep -E "^[[:space:]]*password[[:space:]]+.*${module}\.so\b" "$f" 2>/dev/null | head -n 1 || true)"
      [[ -z "$line" ]] && continue

      v="$(echo "$line" | sed -n "s/.*\b${key}=\([^[:space:]]\+\).*/\1/p")"
      [[ -n "$v" ]] && { echo "$v"; return 0; }

      if [[ "$key" == "enforce_for_root" ]]; then
        echo "$line" | grep -Eq "\benforce_for_root\b" && { echo "__FLAG_PRESENT__"; return 0; }
      fi
    done
    echo ""
  }

  local status="GOOD"
  mapfile -t PAM_FILES < <(detect_pam_files)
  if [[ "${#PAM_FILES[@]}" -eq 0 ]]; then
    status="NA"
  fi

  if [[ "$status" != "NA" ]]; then
    local pass_max pass_min
    pass_max="$(get_kv_last "PASS_MAX_DAYS" "/etc/login.defs")"
    pass_min="$(get_kv_last "PASS_MIN_DAYS" "/etc/login.defs")"

    if ! is_int "${pass_max:-}" || (( pass_max > TARGET_PASS_MAX_DAYS )); then status="VULN"; fi
    if ! is_int "${pass_min:-}" || (( pass_min < TARGET_PASS_MIN_DAYS )); then status="VULN"; fi
  fi

  if [[ "$status" == "GOOD" ]]; then
    local -a PWQUALITY_FILES=()
    [[ -r /etc/security/pwquality.conf ]] && PWQUALITY_FILES+=("/etc/security/pwquality.conf")
    while IFS= read -r f; do [[ -r "$f" ]] && PWQUALITY_FILES+=("$f"); done < <(append_conf_d "/etc/security/pwquality.conf.d")

    if ! grep -qE "^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so\b" "${PAM_FILES[@]}" 2>/dev/null; then
      status="VULN"
    fi

    local f
    for f in "${PAM_FILES[@]}"; do
      [[ "$(pam_check_order_onefile "pam_pwquality" "$f")" == "BAD" ]] && { status="VULN"; break; }
    done

    local minlen dcredit ucredit lcredit ocredit enf_root
    minlen="$(get_kv_last "minlen" "${PWQUALITY_FILES[@]}")"
    dcredit="$(get_kv_last "dcredit" "${PWQUALITY_FILES[@]}")"
    ucredit="$(get_kv_last "ucredit" "${PWQUALITY_FILES[@]}")"
    lcredit="$(get_kv_last "lcredit" "${PWQUALITY_FILES[@]}")"
    ocredit="$(get_kv_last "ocredit" "${PWQUALITY_FILES[@]}")"
    enf_root="$(get_kv_last "enforce_for_root" "${PWQUALITY_FILES[@]}")"

    [[ -z "$minlen" ]] && minlen="$(pam_extract_opt_firstline "pam_pwquality" "minlen" "${PAM_FILES[@]}")"
    [[ -z "$dcredit" ]] && dcredit="$(pam_extract_opt_firstline "pam_pwquality" "dcredit" "${PAM_FILES[@]}")"
    [[ -z "$ucredit" ]] && ucredit="$(pam_extract_opt_firstline "pam_pwquality" "ucredit" "${PAM_FILES[@]}")"
    [[ -z "$lcredit" ]] && lcredit="$(pam_extract_opt_firstline "pam_pwquality" "lcredit" "${PAM_FILES[@]}")"
    [[ -z "$ocredit" ]] && ocredit="$(pam_extract_opt_firstline "pam_pwquality" "ocredit" "${PAM_FILES[@]}")"
    [[ -z "$enf_root" ]] && enf_root="$(pam_extract_opt_firstline "pam_pwquality" "enforce_for_root" "${PAM_FILES[@]}")"

    if ! is_int "${minlen:-}" || (( minlen < TARGET_MINLEN )); then status="VULN"; fi
    if ! is_int "${dcredit:-}" || (( dcredit != TARGET_CREDIT )); then status="VULN"; fi
    if ! is_int "${ucredit:-}" || (( ucredit != TARGET_CREDIT )); then status="VULN"; fi
    if ! is_int "${lcredit:-}" || (( lcredit != TARGET_CREDIT )); then status="VULN"; fi
    if ! is_int "${ocredit:-}" || (( ocredit != TARGET_CREDIT )); then status="VULN"; fi
    if [[ "$enf_root" != "__FLAG_PRESENT__" ]]; then status="VULN"; fi
  fi

  if [[ "$status" == "GOOD" ]]; then
    local -a PWHISTORY_FILES=()
    [[ -r /etc/security/pwhistory.conf ]] && PWHISTORY_FILES+=("/etc/security/pwhistory.conf")
    while IFS= read -r f; do [[ -r "$f" ]] && PWHISTORY_FILES+=("$f"); done < <(append_conf_d "/etc/security/pwhistory.conf.d")

    if ! grep -qE "^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so\b" "${PAM_FILES[@]}" 2>/dev/null; then
      status="VULN"
    fi

    local f
    for f in "${PAM_FILES[@]}"; do
      [[ "$(pam_check_order_onefile "pam_pwhistory" "$f")" == "BAD" ]] && { status="VULN"; break; }
    done

    local remember enf_root2
    remember="$(get_kv_last "remember" "${PWHISTORY_FILES[@]}")"
    enf_root2="$(get_kv_last "enforce_for_root" "${PWHISTORY_FILES[@]}")"
    [[ -z "$remember" ]] && remember="$(pam_extract_opt_firstline "pam_pwhistory" "remember" "${PAM_FILES[@]}")"
    [[ -z "$enf_root2" ]] && enf_root2="$(pam_extract_opt_firstline "pam_pwhistory" "enforce_for_root" "${PAM_FILES[@]}")"

    if ! is_int "${remember:-}" || (( remember < TARGET_REMEMBER )); then status="VULN"; fi
    if [[ "$enf_root2" != "__FLAG_PRESENT__" ]]; then status="VULN"; fi
  fi

  local title="▶ U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정 ◀"
  local crit=" 양호 판단 기준 : 비밀번호 최대/최소 사용기간, 복잡성(pwquality), 재사용 제한(pwhistory)이 기준에 맞고 PAM 적용 및 순서가 적절한 경우"

  if [[ "$status" == "GOOD" ]]; then
    emit3 "$title" "$crit" "* U-02 결과 : 양호 (Good)"
    return 0
  elif [[ "$status" == "NA" ]]; then
    emit3 "$title" "$crit" "* U-02 결과 : N/A"
    return 2
  else
    emit3 "$title" "$crit" "* U-02 결과 : 취약 (Vulnerable)"
    return 1
  fi
}

# ======================================================================
# U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지
# ======================================================================
u05_check() {
  local title="▶ U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 ◀"
  local crit=" 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"

  if [[ ! -r /etc/passwd ]]; then
    emit3 "$title" "$crit" "* U-05 결과 : N/A"
    return 2
  fi

  if [[ "$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | wc -l)" -gt 0 ]]; then
    emit3 "$title" "$crit" "* U-05 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-05 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-06(상) | 1. 계정관리 > 1.6 사용자 계정 su 기능 제한
# ======================================================================
u06_check() {
  local title="▶ U-06(상) | 1. 계정관리 > 1.6 사용자 계정 su 기능 제한 ◀"
  local crit=" 양호 판단 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 (일반 사용자 없으면 예외)"

  local PAM_SU="/etc/pam.d/su"
  local VULN=0

  if [[ -r "$PAM_SU" ]]; then
    if ! grep -vE "^[[:space:]]*#|^[[:space:]]*$" "$PAM_SU" | grep -qE "pam_wheel\.so\b.*\buse_uid\b"; then
      VULN=1
    fi
  else
    VULN=1
  fi

  local USER_COUNT
  USER_COUNT="$(awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd 2>/dev/null | wc -l || true)"
  if [[ $VULN -eq 1 && "${USER_COUNT:-0}" -eq 0 ]]; then
    VULN=0
  fi

  if [[ $VULN -eq 1 ]]; then
    emit3 "$title" "$crit" "* U-06 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-06 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-07(상) | 1. 계정관리 > 불필요한 계정 제거
# ======================================================================
u07_check() {
  local INACTIVE_DAYS="${INACTIVE_DAYS:-90}"
  local UID_MIN="${UID_MIN:-1000}"
  local UID_MAX="${UID_MAX:-60000}"
  local EXCLUDE_USERS_REGEX="${EXCLUDE_USERS_REGEX:-^(root|nfsnobody|nobody)$}"

  local PASSWD_FILE="/etc/passwd"
  local SHADOW_FILE="/etc/shadow"

  is_interactive_shell() {
    local sh="$1"
    case "$sh" in
      ""|"/sbin/nologin"|"/usr/sbin/nologin"|"/bin/false"|"/usr/bin/false") return 1 ;;
      *) return 0 ;;
    esac
  }

  get_shadow_field() {
    local user="$1"
    if [[ -r "$SHADOW_FILE" ]]; then
      awk -F: -v u="$user" '$1==u{print $2}' "$SHADOW_FILE" 2>/dev/null || true
    else
      echo ""
    fi
  }

  shadow_status() {
    local pwfield="$1"
    if [[ -z "$pwfield" ]]; then echo "unknown(no_shadow_access)"; return 0; fi
    if [[ "$pwfield" == "!"* || "$pwfield" == "*"* ]]; then echo "locked"; return 0; fi
    if [[ "$pwfield" == "" ]]; then echo "empty_password"; return 0; fi
    echo "active"
  }

  get_last_login_iso() {
    local user="$1"
    local line
    line="$(last -n 1 -F --time-format iso "$user" 2>/dev/null | head -n 1 || true)"
    if [[ -z "$line" ]]; then echo ""; return 0; fi
    if echo "$line" | grep -qiE '^wtmp begins|^btmp begins'; then echo ""; return 0; fi
    echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -n 1 || true
  }

  days_since() {
    local iso="$1"
    [[ -z "$iso" ]] && { echo ""; return 0; }
    local last_epoch now_epoch
    last_epoch="$(date -d "$iso" +%s 2>/dev/null || true)"
    now_epoch="$(date +%s)"
    [[ -z "$last_epoch" ]] && { echo ""; return 0; }
    echo $(( (now_epoch - last_epoch) / 86400 ))
  }

  local title="▶ U-07(상) | 1. 계정관리 > 불필요한 계정 제거 ◀"
  local crit=" 양호 판단 기준 : root 외 UID 0 계정이 없고, 불필요(미사용/장기미접속/비밀번호 미설정) 계정이 존재하지 않는 경우"

  if ! need_cmd awk || ! need_cmd last || ! need_cmd date || ! need_cmd grep; then
    emit3 "$title" "$crit" "* U-07 결과 : N/A"
    return 2
  fi
  if [[ ! -r "$PASSWD_FILE" ]]; then
    emit3 "$title" "$crit" "* U-07 결과 : N/A"
    return 2
  fi

  local final="양호"
  local uid0_others
  uid0_others="$(awk -F: '$3==0 && $1!="root" {print $1}' "$PASSWD_FILE" | tr '\n' ' ' | sed 's/[[:space:]]\+$//')"
  if [[ -n "${uid0_others:-}" ]]; then
    final="취약"
  fi

  local issues=0
  while IFS=: read -r user _ uid _ _ _ shell; do
    echo "$user" | grep -Eq "$EXCLUDE_USERS_REGEX" && continue
    [[ "$uid" -lt "$UID_MIN" || "$uid" -gt "$UID_MAX" ]] && continue
    is_interactive_shell "$shell" || continue

    local pwfield st
    pwfield="$(get_shadow_field "$user")"
    st="$(shadow_status "$pwfield")"

    if [[ "$st" == "empty_password" ]]; then
      issues=1
      break
    fi

    if [[ "$st" == "active" ]]; then
      local last_iso d
      last_iso="$(get_last_login_iso "$user")"
      if [[ -z "$last_iso" ]]; then
        issues=1
        break
      fi
      d="$(days_since "$last_iso")"
      if [[ -n "$d" && "$d" -ge "$INACTIVE_DAYS" ]]; then
        issues=1
        break
      fi
    fi
  done < "$PASSWD_FILE"

  [[ "$issues" -gt 0 ]] && final="취약"

  if [[ "$final" == "양호" ]]; then
    emit3 "$title" "$crit" "* U-07 결과 : 양호 (Good)"
    return 0
  else
    emit3 "$title" "$crit" "* U-07 결과 : 취약 (Vulnerable)"
    return 1
  fi
}

# ======================================================================
# U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지
# ======================================================================
u10_check() {
  local title="▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀"
  local crit=" 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"

  if [[ ! -r /etc/passwd ]]; then
    emit3 "$title" "$crit" "* U-10 결과 : N/A"
    return 2
  fi

  if [[ -n "$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d)" ]]; then
    emit3 "$title" "$crit" "* U-10 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-10 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-11(하) | 1. 계정관리 > 1.11 사용자 shell 점검
# ======================================================================
u11_check() {
  local title="▶ U-11(하) | 1. 계정관리 > 1.11 사용자 shell 점검 ◀"
  local crit=" 양호 판단 기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"

  if [[ ! -r /etc/passwd ]]; then
    emit3 "$title" "$crit" "* U-11 결과 : N/A"
    return 2
  fi

  local EXCEPT_USERS="^(sync|shutdown|halt)$"
  local VUL=0

  while IFS=: read -r user _ uid _ _ _ shell; do
    if { [[ "$uid" -ge 1 && "$uid" -lt 1000 ]] || [[ "$user" == "nobody" ]]; }; then
      [[ "$user" =~ $EXCEPT_USERS ]] && continue
      if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" && "$shell" != "/usr/sbin/nologin" ]]; then
        VUL=1
        break
      fi
    fi
  done < /etc/passwd

  if [[ $VUL -eq 1 ]]; then
    emit3 "$title" "$crit" "* U-11 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-11 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-12(하) | 계정관리 > 세션 종료 시간 설정
# ======================================================================
u12_check() {
  local TARGET_MAX=600

  last_tmout_value_in_file() {
    local file="$1"
    awk '
      /^[[:space:]]*#/ {next}
      {
        line=$0
        if (match(line, /(^|[[:space:];])TMOUT[[:space:]]*=[[:space:]]*("?)[0-9]+("?)/)) {
          s=substr(line, RSTART, RLENGTH)
          gsub(/[^0-9]/, "", s)
          if (s != "") last=s
        }
      }
      END { if (last != "") print last }
    ' "$file" 2>/dev/null || true
  }

  local ordered=()
  [[ -f /etc/profile ]] && ordered+=("/etc/profile")
  if [[ -d /etc/profile.d ]]; then
    while IFS= read -r -d '' f; do ordered+=("$f"); done < <(find /etc/profile.d -maxdepth 1 -type f \( -name "*.sh" -o -name "*.bash" -o -name "*.ksh" \) -print0 2>/dev/null | sort -z)
  fi
  [[ -f /etc/bashrc ]] && ordered+=("/etc/bashrc")

  local effective_tmout=""
  local f v
  for f in "${ordered[@]}"; do
    v="$(last_tmout_value_in_file "$f" || true)"
    [[ -n "${v:-}" ]] && effective_tmout="$v"
  done

  local result="취약"
  if [[ -n "${effective_tmout:-}" && "$effective_tmout" =~ ^[0-9]+$ ]]; then
    if (( effective_tmout > 0 && effective_tmout <= TARGET_MAX )); then
      result="양호"
    fi
  fi

  local title="▶ U-12(하) | 계정관리 > 세션 종료 시간 설정 ◀"
  local crit=" 양호 판단 기준 : TMOUT가 설정되어 있고 0보다 크며 ${TARGET_MAX}초 이하인 경우"

  if [[ "$result" == "양호" ]]; then
    emit3 "$title" "$crit" "* U-12 결과 : 양호 (Good)"
    return 0
  else
    emit3 "$title" "$crit" "* U-12 결과 : 취약 (Vulnerable)"
    return 1
  fi
}

# ======================================================================
# U-15(상) | 파일/디렉터리 소유자 미존재(nouser/nogroup)
# ======================================================================
u15_check() {
  local title="▶ U-15(상) | 2. 파일 및 디렉터리 관리 > 2.2 파일 및 디렉터리 소유자 설정 ◀"
  local crit=" 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"

  if ! need_cmd find; then
    emit3 "$title" "$crit" "* U-15 결과 : N/A"
    return 2
  fi

  if [[ "$(find / \( -nouser -o -nogroup \) 2>/dev/null | head -n 1 | wc -l)" -gt 0 ]]; then
    emit3 "$title" "$crit" "* U-15 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-15 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-16(상) | /etc/passwd 소유자/권한
# ======================================================================
u16_check() {
  local title="▶ U-16(상) | 2. 파일 및 디렉터리 관리 > 2.3 /etc/passwd 파일 소유자 및 권한 설정 ◀"
  local crit=" 양호 판단 기준 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"

  local FILE="/etc/passwd"
  if [[ ! -e "$FILE" ]]; then
    emit3 "$title" "$crit" "* U-16 결과 : 취약 (Vulnerable)"
    return 1
  fi
  if ! need_cmd stat; then
    emit3 "$title" "$crit" "* U-16 결과 : N/A"
    return 2
  fi

  local owner perm
  owner="$(stat -c "%U" "$FILE" 2>/dev/null || echo "")"
  perm="$(stat -c "%a" "$FILE" 2>/dev/null || echo "")"

  if [[ "$owner" != "root" || -z "$perm" || "$perm" -gt 644 ]]; then
    emit3 "$title" "$crit" "* U-16 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-16 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-17(중) | 시스템 시작 스크립트 권한
# ======================================================================
u17_check() {
  local title="▶ U-17(중) | 파일 및 디렉터리 관리 > 시스템 시작 스크립트 권한 설정 ◀"
  local crit=" 양호 판단 기준 : 시스템 시작 스크립트가 root 소유이며 group/other 쓰기 권한이 없는 경우"

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    emit3 "$title" "$crit" "* U-17 결과 : N/A"
    return 2
  fi

  local VULN=0
  local CHECKED=0

  check_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0

    local real="$f"
    [[ -L "$f" ]] && real="$(readlink -f -- "$f" 2>/dev/null || echo "$f")"
    [[ -e "$real" ]] || return 0

    local owner perm p g o
    owner="$(stat -c '%U' "$real" 2>/dev/null || echo "?")"
    perm="$(stat -c '%a' "$real" 2>/dev/null || echo "???")"

    p="${perm: -3}"
    g="${p:1:1}"
    o="${p:2:1}"

    [[ "$owner" != "root" ]] && VULN=1
    [[ "$g" =~ [2367] ]] && VULN=1
    [[ "$o" =~ [2367] ]] && VULN=1

    CHECKED=$((CHECKED + 1))
  }

  collect_targets() {
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
      [[ -d "$d" ]] && find "$d" -xdev -type f 2>/dev/null
    done
    [[ -d /etc/rc.d/init.d ]] && find /etc/rc.d/init.d -xdev -type f 2>/dev/null
    [[ -d /etc/init.d ]] && find /etc/init.d -xdev -type f 2>/dev/null
  }

  while IFS= read -r f; do
    check_file "$f"
  done < <(collect_targets | sort -u)

  if [[ "$CHECKED" -eq 0 ]]; then
    emit3 "$title" "$crit" "* U-17 결과 : N/A"
    return 2
  elif [[ "$VULN" -eq 1 ]]; then
    emit3 "$title" "$crit" "* U-17 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-17 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-20(상) | systemd unit 파일 소유자/권한
# ======================================================================
u20_check() {
  local title="▶ U-20(상) | 2. 파일 및 디렉터리 관리 > 2.7 systemd *.socket, *.service 파일 소유자 및 권한 설정 ◀"
  local crit=" 양호 판단 기준 : systemd *.socket, *.service 파일의 소유자가 root이고, 권한이 644 이하인 경우"

  if ! need_cmd find || ! need_cmd stat; then
    emit3 "$title" "$crit" "* U-20 결과 : N/A"
    return 2
  fi

  local VULN=0
  local found=0

  check_dir() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    while IFS= read -r f; do
      found=1
      local owner perm
      owner="$(stat -c %U "$f" 2>/dev/null || echo "")"
      perm="$(stat -c %a "$f" 2>/dev/null || echo "")"
      [[ "$owner" != "root" ]] && VULN=1
      [[ -n "$perm" && "$perm" -gt 644 ]] && VULN=1
    done < <(find "$dir" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null)
  }

  check_dir "/usr/lib/systemd/system"
  check_dir "/etc/systemd/system"

  if [[ $found -eq 0 ]]; then
    emit3 "$title" "$crit" "* U-20 결과 : N/A"
    return 2
  fi
  if [[ $VULN -eq 1 ]]; then
    emit3 "$title" "$crit" "* U-20 결과 : 취약 (Vulnerable)"
    return 1
  else
    emit3 "$title" "$crit" "* U-20 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# U-22(중) | /etc/services 소유자/권한
# ======================================================================
u22_check() {
  local TARGET="/etc/services"
  local OK_OWNERS=("root" "bin" "sys")
  local OK_MAX_MODE_OCT="644"

  local result="양호"
  [[ ! -e "$TARGET" ]] && result="취약"
  [[ "$result" == "양호" && -L "$TARGET" ]] && result="취약"
  [[ "$result" == "양호" && ! -f "$TARGET" ]] && result="취약"

  if [[ "$result" == "양호" ]]; then
    local owner mode_str owner_ok="no"
    owner="$(stat -c '%U' "$TARGET" 2>/dev/null || echo "")"
    mode_str="$(stat -c '%a' "$TARGET" 2>/dev/null || echo "")"

    local o
    for o in "${OK_OWNERS[@]}"; do
      [[ "$owner" == "$o" ]] && owner_ok="yes"
    done
    [[ "$owner_ok" != "yes" ]] && result="취약"

    if [[ -n "$mode_str" ]]; then
      local mode_val ok_max_val
      mode_val=$((8#$mode_str))
      ok_max_val=$((8#$OK_MAX_MODE_OCT))
      (( mode_val > ok_max_val )) && result="취약"
    else
      result="취약"
    fi
  fi

  local title="▶ U-22(중) | 파일 및 디렉터리 관리 > /etc/services 파일 소유자 및 권한 ◀"
  local crit=" 양호 판단 기준 : /etc/services 파일의 소유자가 root(bin, sys 포함)이고 권한이 644 이하인 경우"

  if [[ "$result" == "양호" ]]; then
    emit3 "$title" "$crit" "* U-22 결과 : 양호 (Good)"
    return 0
  else
    emit3 "$title" "$crit" "* U-22 결과 : 취약 (Vulnerable)"
    return 1
  fi
}

# ======================================================================
# U-27(상) | r-command 사용 금지
# ======================================================================
u27_check() {
  local VULN=0
  local NA=0

  get_mode_dec(){ stat -c '%a' "$1" 2>/dev/null || return 1; }
  get_owner(){ stat -c '%U' "$1" 2>/dev/null || return 1; }

  has_plus_rule() {
    awk '
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      { for (i=1; i<=NF; i++) if ($i=="+") found=1 }
      END { exit(found?0:1) }
    ' "$1" 2>/dev/null
  }

  is_mode_too_open() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] || return 2
    (( $1 > 600 ))
  }

  detect_r_services_in_use() {
    local used=0
    if command -v ss >/dev/null 2>&1; then
      ss -lntup 2>/dev/null | awk '{print $5}' | grep -Eq ':(512|513|514)$' && used=1
    fi
    ls /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec >/dev/null 2>&1 && used=1
    command -v rpm >/dev/null 2>&1 && rpm -q rsh-server rsh >/dev/null 2>&1 && used=1
    return $used
  }

  if detect_r_services_in_use; then
    :
  fi

  if [[ -e /etc/hosts.equiv ]]; then
    if [[ ! -f /etc/hosts.equiv ]]; then
      NA=1
    else
      local owner mode
      owner="$(get_owner /etc/hosts.equiv || echo "")"
      mode="$(get_mode_dec /etc/hosts.equiv || echo "")"
      [[ "$owner" != "root" ]] && VULN=1
      is_mode_too_open "$mode" && VULN=1
      has_plus_rule /etc/hosts.equiv && VULN=1
    fi
  fi

  if [[ -r /etc/passwd ]]; then
    awk -F: '{ if ($7 !~ /(nologin|false)$/) print $1 "|" $6 }' /etc/passwd \
    | while IFS="|" read -r user home; do
        [[ -d "$home" ]] || continue
        local f="$home/.rhosts"
        [[ -e "$f" ]] || continue
        if [[ ! -f "$f" ]]; then
          NA=1; continue
        fi
        local owner mode
        owner="$(get_owner "$f" || echo "")"
        mode="$(get_mode_dec "$f" || echo "")"
        [[ "$owner" != "$user" ]] && VULN=1
        is_mode_too_open "$mode" && VULN=1
        has_plus_rule "$f" && VULN=1
      done
  else
    NA=1
  fi

  local title="▶ U-27(상) | 계정관리 > r-command 사용 금지 ◀"
  local crit=" 양호 판단 기준 : rlogin/rsh/rexec 서비스를 사용하지 않거나, 관련 설정 파일이 없거나 소유자·권한·'+' 규칙이 적절한 경우"

  if (( VULN == 1 )); then
    emit3 "$title" "$crit" "* U-27 결과 : 취약 (Vulnerable)"
    return 1
  elif (( NA == 1 )); then
    emit3 "$title" "$crit" "* U-27 결과 : N/A"
    return 2
  else
    emit3 "$title" "$crit" "* U-27 결과 : 양호 (Good)"
    return 0
  fi
}

# ======================================================================
# 메인
# ======================================================================
main() {
  : > "$OUT_FILE"
  say "결과 저장 파일: $OUT_FILE"
  log "결과 저장 파일: $OUT_FILE"
  say ""
  log ""

  local any_vuln=0
  local any_na=0

  run_one() {
    local rc=0
    "$@" || rc=$?
    [[ $rc -eq 1 ]] && any_vuln=1
    [[ $rc -eq 2 ]] && any_na=1
    say ""
    log ""
  }

  # 번호(연번)도 1,2,3.. / 실행도 U번호 오름차순
  run_one u01_check
  run_one u02_check
  run_one u05_check
  run_one u06_check
  run_one u07_check
  run_one u10_check
  run_one u11_check
  run_one u12_check
  run_one u15_check
  run_one u16_check
  run_one u17_check
  run_one u20_check
  run_one u22_check
  run_one u27_check

  if [[ $any_vuln -eq 1 ]]; then
    exit 1
  elif [[ $any_na -eq 1 ]]; then
    exit 2
  else
    exit 0
  fi
}

main "$@"
