#!/bin/bash

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local severity="상"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  if [ -f /etc/passwd ]; then
    dup_users="$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root)"
    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다."
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
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
    dup_uid_count="$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | wc -l)"
    if [ "$dup_uid_count" -gt 0 ]; then
      status="취약"
      reason="동일한 UID로 설정된 사용자 계정이 존재합니다."
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_15() {
  local code="U-15"
  local item="소유자 없는 파일 및 디렉터리 점검"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  orphan_count="$(find / \
    \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
    \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l)"

  if [ "$orphan_count" -gt 0 ]; then
    status="취약"
    reason="소유자가 존재하지 않는 파일 또는 디렉터리가 존재합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_20() {
  local code="U-20"
  local item="systemd socket/service 파일 소유자 및 권한 설정"
  local status="양호"
  local reason="systemd socket/service 파일의 소유자가 root이고 권한이 644 이하로 설정되어 있습니다."

  vuln_found=0

  check_dir_units() {
    local dir="$1"
    [ -d "$dir" ] || return 0

    find "$dir" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null |
    while IFS= read -r file; do
      owner="$(stat -c %U "$file" 2>/dev/null)"
      perm="$(stat -c %a "$file" 2>/dev/null)"

      if [ "$owner" != "root" ] || [ "$perm" -gt 644 ]; then
        vuln_found=1
        return 1
      fi
    done
  }

  check_dir_units "/usr/lib/systemd/system"
  check_dir_units "/etc/systemd/system"

  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="root 소유가 아니거나 권한이 644를 초과한 systemd socket/service 파일이 존재합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local status="양호"
  local reason="world writable 설정이 된 파일이 존재하지 않습니다."

  ww_count="$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)"

  if [ "$ww_count" -gt 0 ]; then
    status="취약"
    reason="world writable 설정이 된 파일이 존재합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local status="양호"
  local reason="UMASK 값이 022 이상으로 적절하게 설정되어 있습니다."

  vuln_found=0

  # 1. systemd 서비스 UMask 점검
  for svc in $(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'); do
    umask_val="$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')"
    [ -z "$umask_val" ] && continue

    umask_dec=$((8#$umask_val))
    if [ "$umask_dec" -lt 18 ]; then
      vuln_found=1
      break
    fi
  done

  # 2. login.defs + PAM 점검
  if [ "$vuln_found" -eq 0 ]; then
    if grep -q "pam_umask.so" /etc/pam.d/common-session 2>/dev/null; then
      login_umask="$(grep -E '^UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')"
      if [ -z "$login_umask" ] || [ $((8#$login_umask)) -lt 18 ]; then
        vuln_found=1
      fi
    else
      vuln_found=1
    fi
  fi

  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="systemd UMask 또는 login.defs/PAM 설정에서 UMASK 값이 022 미만이거나 설정이 누락되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_35() {
  local code="U-35"
  local item="공유 서비스 익명 접근 제한 설정"
  local status="양호"
  local reason="FTP, NFS, Samba 서비스에서 익명 또는 전체 접근이 제한되어 있습니다."

  vuln_found=0

  # FTP (vsftpd / proftpd)
  if systemctl is-active vsftpd >/dev/null 2>&1 || systemctl is-active proftpd >/dev/null 2>&1; then
    grep -iR "anonymous_enable[[:space:]]*=[[:space:]]*YES" /etc/vsftpd* 2>/dev/null && vuln_found=1
    grep -iR "<Anonymous" /etc/proftpd* 2>/dev/null && vuln_found=1
  fi

  # NFS
  if systemctl is-active nfs-server >/dev/null 2>&1; then
    grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -E '\*|no_root_squash' >/dev/null && vuln_found=1
  fi

  # Samba
  if systemctl is-active smbd >/dev/null 2>&1; then
    grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
      | grep -Ei 'guest[[:space:]]+ok|public[[:space:]]*=|map[[:space:]]+to[[:space:]]+guest|security[[:space:]]*=[[:space:]]*share' \
      >/dev/null && vuln_found=1
  fi

  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="FTP, NFS 또는 Samba 서비스에서 익명 또는 전체 접근이 허용된 설정이 존재합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local status="양호"
  local reason="NFS 서비스를 사용하지 않거나, 전체 공유가 제한되어 있습니다."

  if systemctl is-active nfs-server >/dev/null 2>&1; then
    if [ ! -f /etc/exports ]; then
      status="취약"
      reason="NFS 서비스가 동작 중이나 /etc/exports 파일이 존재하지 않습니다."
    else
      grep -v '^[[:space:]]*#' /etc/exports | grep -E '\*|insecure' >/dev/null && {
        status="취약"
        reason="NFS 설정에서 전체(*) 또는 insecure 옵션이 허용되어 있습니다."
      }
      grep -v '^[[:space:]]*#' /etc/exports | grep '/' >/dev/null && \
      ! grep -qiE 'root_squash|all_squash' /etc/exports && {
        status="취약"
        reason="NFS 설정에 root_squash 또는 all_squash 옵션이 적용되어 있지 않습니다."
      }
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local status="양호"
  local reason="메일 서비스가 동작하지 않거나 최신 버전을 사용 중입니다."

  # SMTP 동작 여부
  if ss -lnt 2>/dev/null | grep -qE ':(25|465|587)[[:space:]]'; then
    if command -v sendmail >/dev/null 2>&1; then
      sendmail_ver="$(sendmail -d0.1 -bv root 2>/dev/null | grep Version | awk '{print $NF}')"
      if ! echo "$sendmail_ver" | grep -q '^8\.18\.2'; then
        status="취약"
        reason="메일 서비스(sendmail)가 최신 버전(8.18.2)이 아닙니다."
      fi
    else
      status="취약"
      reason="메일 서비스가 동작 중이나 버전 정보를 확인할 수 없습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나 Zone Transfer가 제한되어 있습니다."

  if systemctl is-active --quiet bind9 2>/dev/null || ps -ef | grep -i named | grep -v grep >/dev/null 2>&1; then
    if grep -R -vE '^\s*#' /etc/bind 2>/dev/null \
        | grep -qiE 'allow-transfer\s*\{\s*any\s*;' ; then
      status="취약"
      reason="DNS 설정에서 allow-transfer { any; } 로 Zone Transfer가 전체 허용되어 있습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local status="양호"
  local reason="FTP 서비스가 미설치되었거나 FTP 계정에 로그인 불가 쉘이 설정되어 있습니다."

  dpkg -l 2>/dev/null | grep -qE 'vsftpd|proftpd' || {
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
    return
  }

  for user in ftp vsftpd proftpd; do
    if id "$user" >/dev/null 2>&1; then
      shell="$(awk -F: -v u="$user" '$1==u{print $7}' /etc/passwd)"
      case "$shell" in
        /bin/false|/sbin/nologin|/usr/sbin/nologin) ;;
        *)
          status="취약"
          reason="FTP 계정에 로그인 가능한 쉘이 설정되어 있습니다."
          break
          ;;
      esac
    fi
  done

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local status="양호"
  local reason="SNMP 서비스를 사용하지 않거나 Community String이 복잡성 기준을 만족합니다."

  dpkg -l 2>/dev/null | grep -q '^ii\s\+snmpd' || {
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  }

  systemctl is-active --quiet snmpd || {
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  }

  weak_found=0

  grep -R -vE '^\s*#|^\s*$' /etc/snmp 2>/dev/null \
    | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}
           tolower($1)=="com2sec" {print $4}' |
  while read -r comm; do
    [ "$comm" = "public" ] || [ "$comm" = "private" ] && weak_found=1
    [ "${#comm}" -lt 8 ] && weak_found=1
  done

  if [ "$weak_found" -eq 1 ]; then
    status="취약"
    reason="SNMP Community String이 기본값이거나 복잡성 기준을 만족하지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_65() {
  local code="U-65"
  local item="NTP 및 시각 동기화 설정"
  local status="양호"
  local reason="시스템 시각 동기화가 정상적으로 구성되어 있습니다."

  ntp_enabled="$(timedatectl show -p NTP --value 2>/dev/null)"
  ntp_sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"

  if [ "$ntp_enabled" = "yes" ] && [ "$ntp_sync" = "yes" ]; then
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  fi

  systemctl is-active --quiet systemd-timesyncd \
  || systemctl is-active --quiet chrony \
  || systemctl is-active --quiet ntp \
  || {
    status="취약"
    reason="NTP 또는 시각 동기화 서비스가 활성화되어 있지 않습니다."
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  }

  status="취약"
  reason="시각 동기화 서비스는 활성화되어 있으나 동기화 상태를 확인하지 못했습니다."

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason"
}

U_05
U_10
U_15
U_20
U_25
U_30
U_35
U_40
U_45
U_50
U_55
U_60
U_65