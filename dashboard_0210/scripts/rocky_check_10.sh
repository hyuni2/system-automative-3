#!/bin/bash

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  if [ -f /etc/passwd ]; then
    dup_users="$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root)"
    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 외 UID 0 계정 발견: ${dup_users}"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_10() {
  local code="U-10"
  local item="동일한 UID 금지"
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

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_15() {
  local code="U-15"
  local item="소유자 없는 파일 및 디렉터리 점검"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  # /proc, /sys, /run 등은 제외(속도/오탐 방지)
  local orphan_count
  orphan_count="$(find / \
    \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
    \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l)"

  if [ "$orphan_count" -gt 0 ]; then
    status="취약"
    reason="소유자가 존재하지 않는 파일 또는 디렉터리가 존재합니다. (건수: ${orphan_count})"
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_20() {
  local code="U-20"
  local item="systemd *.socket, *.service 파일 소유자 및 권한 설정"
  local status="양호"
  local reason="systemd socket/service 파일의 소유자가 root이고 권한이 644 이하입니다."

  local vuln_found=0
  local check_dirs="/usr/lib/systemd/system /etc/systemd/system"

  for dir in $check_dirs; do
    [ -d "$dir" ] || continue

    for file in $(find "$dir" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null); do
      owner="$(stat -c %U "$file")"
      perm="$(stat -c %a "$file")"

      if [ "$owner" != "root" ]; then
        status="취약"
        reason="systemd 파일 중 root 소유가 아닌 파일이 존재합니다."
        vuln_found=1
        break 2
      elif [ "$perm" -gt 644 ]; then
        status="취약"
        reason="systemd 파일 중 권한이 644를 초과한 파일이 존재합니다."
        vuln_found=1
        break 2
      fi
    done
  done

  if [ "$vuln_found" -eq 0 ]; then
    # 점검 대상 파일이 하나도 없는 경우
    file_count="$(find $check_dirs -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null | wc -l)"
    if [ "$file_count" -eq 0 ]; then
      status="N/A"
      reason="systemd socket/service 파일이 존재하지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local status="양호"
  local reason="world writable 파일이 존재하지 않습니다."

  local cnt
  cnt="$(find / -xdev \
    \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
    -type f -perm -0002 -print 2>/dev/null | wc -l)"

  if [ "$cnt" -gt 0 ]; then
    status="취약"
    reason="world writable 파일이 존재합니다. (건수: ${cnt})"
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local status="양호"
  local reason="UMASK 값이 022 이상으로 설정되어 있습니다."

  cur_umask="$(umask)"
  g="${cur_umask:2:1}"
  o="${cur_umask:3:1}"

  if [ "$g" -lt 2 ] || [ "$o" -lt 2 ]; then
    status="취약"
    reason="현재 세션 UMASK 값이 022 미만입니다. (현재: ${cur_umask})"
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_35() {
  local code="U-35"
  local item="공유 서비스 익명 접근 제한"
  local status="양호"
  local reason="익명 접근이 허용된 공유 서비스가 발견되지 않았습니다."

  # FTP
  if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE '[:.]21$'; then
    status="취약"
    reason="FTP 서비스(21/tcp)가 동작 중이며 익명 접근 가능성 존재"
  fi

  # NFS
  if grep -qE 'no_root_squash|\*' /etc/exports 2>/dev/null; then
    status="취약"
    reason="NFS 설정에 no_root_squash 또는 전체 공유(*) 설정이 존재합니다."
  fi

  # Samba
  if grep -Ei 'guest ok\s*=\s*yes|public\s*=\s*yes' /etc/samba/smb.conf 2>/dev/null; then
    status="취약"
    reason="Samba 설정에서 게스트/익명 접근이 허용되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local status="양호"
  local reason="불필요한 NFS 서비스가 동작하지 않거나, 안전하게 설정되어 있습니다."

  # NFS 관련 프로세스 동작 여부
  if ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd' >/dev/null; then
    if [ -f /etc/exports ]; then
      if grep -vE '^#|^\s#' /etc/exports | grep -qE '^\s*/.*\*'; then
        status="취약"
        reason="/etc/exports 파일에 전체 호스트(*) 공유 설정이 존재합니다."
      elif grep -vE '^#|^\s#' /etc/exports | grep -qi 'insecure'; then
        status="취약"
        reason="/etc/exports 파일에 insecure 옵션이 설정되어 있습니다."
      elif ! grep -vE '^#|^\s#' /etc/exports | grep -qEi 'root_squash|all_squash'; then
        status="취약"
        reason="/etc/exports 파일에 root_squash 또는 all_squash 옵션이 설정되어 있지 않습니다."
      fi
    else
      status="취약"
      reason="NFS 서비스가 동작 중이나 /etc/exports 파일이 존재하지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local status="양호"
  local reason="메일 서비스가 최신 버전이거나 동작하지 않습니다."
  local latest="8.18.2"

  if ps -ef | grep -iE 'sendmail|smtp' | grep -v grep >/dev/null; then
    rpm_ver="$(rpm -qa 2>/dev/null | grep '^sendmail-' | awk -F'sendmail-' '{print $2}' | head -n 1)"
    dnf_ver="$(dnf list installed sendmail 2>/dev/null | awk 'NR==2{print $2}')"

    if [[ "$rpm_ver" != $latest* && "$dnf_ver" != $latest* ]]; then
      status="취약"
      reason="sendmail 버전이 최신($latest)이 아닙니다. (설치 버전: ${rpm_ver:-unknown})"
    fi
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local status="양호"
  local reason="DNS 서비스가 안전하게 설정되어 있거나 동작하지 않습니다."

  if ps -ef | grep -i 'named' | grep -v grep >/dev/null; then
    if [ -f /etc/named.conf ]; then
      if grep -vE '^#|^\s#' /etc/named.conf | grep -qiE 'allow-transfer\s*\{\s*any\s*;'; then
        status="취약"
        reason="/etc/named.conf 파일에 allow-transfer { any; } 설정이 존재합니다."
      fi
    else
      status="취약"
      reason="DNS 서비스(named)가 동작 중이나 /etc/named.conf 파일이 존재하지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local status="양호"
  local reason="FTP 서비스가 미설치되어 있습니다."

  if ! rpm -qa | grep -Eqi 'vsftpd|proftpd'; then
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  fi

  ftp_users=("ftp" "vsftpd" "proftpd")
  ftp_exist=0
  ftp_vuln=0

  for user in "${ftp_users[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      ftp_exist=1
      shell=$(awk -F: -v u="$user" '$1==u {print $7}' /etc/passwd)
      if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" ]]; then
        ftp_vuln=1
      fi
    fi
  done

  if [ "$ftp_exist" -eq 0 ]; then
    status="양호"
    reason="FTP 계정이 존재하지 않습니다."
  elif [ "$ftp_vuln" -eq 1 ]; then
    status="취약"
    reason="FTP 계정에 /bin/false 또는 nologin 쉘이 부여되어 있지 않습니다."
  else
    status="양호"
    reason="FTP 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local status="양호"
  local reason="SNMP 서비스가 미설치 또는 미동작 상태입니다."
  ps_snmp_count=$(ps -ef | grep -iE 'snmpd|snmptrapd' | grep -v grep | wc -l)
  # SNMP 미설치 시 양호
  if [ "$ps_snmp_count" -eq 0 ]; then
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  fi
  status="취약"
  reason="SNMP Community String 설정을 확인할 수 없습니다."
  # snmpd.conf 검색
  snmpdconf_files=()
  [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")

  if [ "${#snmpdconf_files[@]}" -eq 0 ]; then
    printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$status" "$reason"
    return
  fi
  for f in "${snmpdconf_files[@]}"; do
    if grep -qiE 'public|private' "$f"; then
      reason="SNMP Community String이 기본값(public/private)으로 설정되어 있습니다."
      printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
        "$code" "$item" "$status" "$reason"
      return
    fi
  done
  status="양호"
  reason="SNMP Community String이 복잡성 기준을 만족합니다."

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
}

U_65() {
  local code="U-65"
  local item="NTP 및 시각 동기화 설정"
  local status="양호"
  local reason="NTP 또는 시각 동기화 서비스가 정상적으로 설정 및 동작 중입니다."

  timesyncd_ntp="$(timedatectl show -p NTP --value 2>/dev/null)"
  chronyd_active=$(systemctl is-active chronyd 2>/dev/null)
  ntpd_active=$(systemctl is-active ntpd 2>/dev/null)

  if [[ "$timesyncd_ntp" != "yes" && "$chronyd_active" != "active" && "$ntpd_active" != "active" ]]; then
    printf '{"item":"%s","status":"취약","reason":"NTP 또는 시각 동기화 서비스가 활성화되어 있지 않습니다."}\n' \
      "$item"
    return
  fi

  sync_ok=0
  command -v chronyc >/dev/null 2>&1 && chronyc sources 2>/dev/null | grep -qE '^\^\*|^\^\+' && sync_ok=1
  command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | grep -q '^\*' && sync_ok=1
  timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes && sync_ok=1

  if [ "$sync_ok" -eq 0 ]; then
    status="취약"
    reason="NTP 서버 설정은 존재하나, 현재 동기화 상태를 정상으로 확인하지 못했습니다."
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$status" "$reason"
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