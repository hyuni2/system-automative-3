#!/bin/bash
resultfile="results.txt"

#태훈
U_02(){
  #!/usr/bin/env bash
# KISA U-02 (Linux) 비밀번호 관리정책 설정 점검 스크립트 (출력 최소)
# - 진단 로직은 동일
# - 출력은 "제목 1줄 + 판단기준 1줄 + 결과 1줄"만
# - 취약 사유/참고/개선요약 등 추가 출력 없음

set -u

TARGET_PASS_MAX_DAYS=90
TARGET_PASS_MIN_DAYS=1
TARGET_MINLEN=8
TARGET_CREDIT=-1
TARGET_REMEMBER=4

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

# -------------------- 진단 --------------------
status="GOOD"

mapfile -t PAM_FILES < <(detect_pam_files)
if [[ "${#PAM_FILES[@]}" -eq 0 ]]; then
  status="NA"
fi

# 1) /etc/login.defs
if [[ "$status" != "NA" ]]; then
  pass_max="$(get_kv_last "PASS_MAX_DAYS" "/etc/login.defs")"
  pass_min="$(get_kv_last "PASS_MIN_DAYS" "/etc/login.defs")"

  if ! is_int "${pass_max:-}" || (( pass_max > TARGET_PASS_MAX_DAYS )); then
    status="VULN"
  fi
  if ! is_int "${pass_min:-}" || (( pass_min < TARGET_PASS_MIN_DAYS )); then
    status="VULN"
  fi
fi

# 2) pwquality
if [[ "$status" == "GOOD" ]]; then
  PWQUALITY_FILES=()
  [[ -r /etc/security/pwquality.conf ]] && PWQUALITY_FILES+=("/etc/security/pwquality.conf")
  while IFS= read -r f; do [[ -r "$f" ]] && PWQUALITY_FILES+=("$f"); done < <(append_conf_d "/etc/security/pwquality.conf.d")

  # PAM 적용 여부(없으면 취약)
  if ! grep -qE "^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so\b" "${PAM_FILES[@]}" 2>/dev/null; then
    status="VULN"
  fi

  # PAM 순서(하나라도 BAD면 취약)
  for f in "${PAM_FILES[@]}"; do
    [[ "$(pam_check_order_onefile "pam_pwquality" "$f")" == "BAD" ]] && { status="VULN"; break; }
  done

  # 값 체크
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

# 3) pwhistory
if [[ "$status" == "GOOD" ]]; then
  PWHISTORY_FILES=()
  [[ -r /etc/security/pwhistory.conf ]] && PWHISTORY_FILES+=("/etc/security/pwhistory.conf")
  while IFS= read -r f; do [[ -r "$f" ]] && PWHISTORY_FILES+=("$f"); done < <(append_conf_d "/etc/security/pwhistory.conf.d")

  if ! grep -qE "^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so\b" "${PAM_FILES[@]}" 2>/dev/null; then
    status="VULN"
  fi

  for f in "${PAM_FILES[@]}"; do
    [[ "$(pam_check_order_onefile "pam_pwhistory" "$f")" == "BAD" ]] && { status="VULN"; break; }
  done

  remember="$(get_kv_last "remember" "${PWHISTORY_FILES[@]}")"
  enf_root2="$(get_kv_last "enforce_for_root" "${PWHISTORY_FILES[@]}")"
  [[ -z "$remember" ]] && remember="$(pam_extract_opt_firstline "pam_pwhistory" "remember" "${PAM_FILES[@]}")"
  [[ -z "$enf_root2" ]] && enf_root2="$(pam_extract_opt_firstline "pam_pwhistory" "enforce_for_root" "${PAM_FILES[@]}")"

  if ! is_int "${remember:-}" || (( remember < TARGET_REMEMBER )); then status="VULN"; fi
  if [[ "$enf_root2" != "__FLAG_PRESENT__" ]]; then status="VULN"; fi
fi

# -------------------- 출력(딱 3줄) --------------------
echo "▶ U-02(상) | 1. 계정관리 > 비밀번호 관리정책 설정 ◀"
echo " 양호 판단 기준 : 비밀번호 최대/최소 사용기간, 복잡성(pwquality), 재사용 제한(pwhistory)이 기준에 맞고 PAM 적용 및 순서가 적절한 경우"

if [[ "$status" == "GOOD" ]]; then
  echo "* U-02 결과 : 양호 (Good)"
  exit 0
elif [[ "$status" == "NA" ]]; then
  echo "* U-02 결과 : N/A"
  exit 2
else
  echo "* U-02 결과 : 취약 (Vulnerable)"
  exit 1
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
#연수
U_08() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-08(중) | UNIX > 1. 계정 관리 | 관리자 권한(그룹/ sudoers) 최소화 ◀"  >> "$resultfile" 2>&1
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
#연수
U_13() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-13(중) | UNIX > 1. 계정관리 > 안전한 비밀번호 암호화 알고리즘 사용 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 안전한 해시 알고리즘(yescrypt:$y$, SHA-512:$6$, SHA-256:$5$) 사용" >> "$resultfile" 2>&1

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
#연수
U_28() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-28(상) | UNIX > 2. 파일 및 디렉토리 관리 > 접속 IP 및 포트 제한 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
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
#연수
U_38() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-38(상) | UNIX > 3. 서비스 관리 | DoS 공격에 취약한 서비스 비활성화 (Rocky 10.x 기준) ◀"  >> "$resultfile" 2>&1
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
#연수
U_58() {
  echo "" >> "$resultfile" 2>&1
  echo "▶ U-58(중) | UNIX > 3. 서비스 관리 > 불필요한 SNMP 서비스 구동 점검 (Rocky 10.x 기준) ◀" >> "$resultfile" 2>&1
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

U_02
U_03
U_05
U_08
U_10
U_13
U_15
U_18
U_20
U_23
U_25
U_28
U_30
U_33
U_35
U_38
U_39
U_40
U_43
U_44
U_45
U_48
U_49
U_50
U_53
U_54
U_55
U_58
U_59
U_60
U_63
U_64
U_65