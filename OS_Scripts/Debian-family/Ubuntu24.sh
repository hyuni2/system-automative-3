#!/bin/bash
resultfile="results.txt"
#연수
U_03() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-03(상) | UNIX > 1. 계정 관리| 계정 잠금 임계값 설정 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우"  >> "$resultfile" 2>&1

  local pam_auth="/etc/pam.d/common-auth"
  local pam_acct="/etc/pam.d/common-account"
  local faillock_conf="/etc/security/faillock.conf"

  # 1) Ubuntu에서 pam_faillock 적용 여부 확인
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

  # 2) /etc/security/faillock.conf에서 deny 값 추출 (주석/빈줄 제외, 마지막 설정 우선)
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

  # 3) deny 값 판정
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
#수진
U_05() {
	echo ""  >> $resultfile 2>&1
	echo "▶ U-05(상) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	if [ -f /etc/passwd ]; then
		if [ `awk -F : '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | wc -l` -gt 0 ]; then
			echo "※ U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $resultfile 2>&1
			return 0
		else
			echo "※ U-05 결과 : 양호(Good)" >> $resultfile 2>&1
			return 0
		fi
	fi
}
#연수
U_08() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-08(중) | UNIX > 1. 계정 관리| 관리자 그룹에 최소한의 계정 포함 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> "$resultfile" 2>&1

  # Ubuntu에서 실질 관리자 그룹
  local admin_groups=("sudo" "admin")

  # 명백히 관리자 그룹에 들어가면 이상한(서비스/시스템) 계정들
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
    # 유저 없으면 빈값
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

        # 1) 명백한 서비스/시스템 계정이 sudo/admin 그룹에 있으면 취약 징후
        if _is_unnecessary "$u"; then
          bads+="$u "
          continue
        fi

        # 2) Ubuntu에서는 일반 사용자 UID가 보통 1000 이상
        #    UID가 1000 미만인데 sudo/admin에 있으면 '의심'으로 기록(정책상 취약으로 볼지 선택 가능)
        local uid
        uid=$(_uid_of_user "$u")
        if [ -n "$uid" ] && [ "$uid" -lt 1000 ] && [ "$u" != "root" ]; then
          suspects+="$u(uid=$uid) "
        fi
      done < <(_collect_group_users "$g")

      # 취약은 "명백한 불필요 계정 포함" 기준으로 판정
      if [ -n "$bads" ]; then
        vuln_found=1
        echo "※ 취약 징후: 관리자 그룹($g)에 불필요/서비스 계정 포함: $bads" >> "$resultfile" 2>&1
      fi

      # 의심 계정은 참고용(취약 판정에 포함시키려면 아래 주석 해제)
      if [ -n "$suspects" ]; then
        echo "※ 참고: 관리자 그룹($g)에 시스템/특수 계정(UID<1000) 의심: $suspects" >> "$resultfile" 2>&1
        # vuln_found=1   # <- 정책상 UID<1000을 곧바로 취약으로 볼 거면 주석 해제
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
#수진
U_10() {
	echo ""  >> $resultfile 2>&1
	echo "▶ U-10(중) | 1. 계정관리 > 1.10 동일한 UID 금지 ◀"  >> $resultfile 2>&1
	echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	if [ -f /etc/passwd ]; then
		if [ `awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l` -gt 0 ]; then
			echo "※ U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> $resultfile 2>&1
			return 0
		fi
	fi
	echo "※ U-10 결과 : 양호(Good)" >> $resultfile 2>&1
	return 0
}
#연수
U_13() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-13(중) | UNIX > 1. 계정관리 > 안전한 비밀번호 암호화 알고리즘 사용 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 안전한 알고리즘(yescrypt:$y$, SHA-2:$5/$6)을 사용하는 경우" >> "$resultfile" 2>&1

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

  # Ubuntu 24.04 허용 알고리즘:
  # - $y$ : yescrypt (Ubuntu 기본/권장)
  # - $6$ : SHA-512
  # - $5$ : SHA-256
  #
  # 취약으로 강하게 보는 것:
  # - $1$ : MD5 (약함)
  # - 형식이 $로 시작하지 않는 경우(UNKNOWN_FORMAT)
  while IFS=: read -r user hash rest; do
    [ -z "$user" ] && continue

    # 비밀번호 미설정/잠금 계정 제외
    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    ((checked++))

    # $로 시작 안 하면(특이 케이스): 취약
    if [[ "$hash" != \$* ]]; then
      vuln_found=1
      evidence+="$user:UNKNOWN_FORMAT; "
      continue
    fi

    # Ubuntu yescrypt는 $y$ 로 시작
    if [[ "$hash" == \$y\$* ]]; then
      continue
    fi

    # 전통적인 $id$ 형식: $6$, $5$, $1$ 등
    local id
    id="$(echo "$hash" | awk -F'$' '{print $2}')"
    [ -z "$id" ] && id="UNKNOWN"

    if [ "$id" = "5" ] || [ "$id" = "6" ]; then
      continue
    fi

    # MD5 등 정책 외는 취약 처리
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
    # 근거를 남기고 싶으면 아래 주석 해제 (계정명만, 해시 원문은 출력하지 않음)
    # echo " 근거: $evidence" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-13 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " 안전한 알고리즘(yescrypt:$y$, SHA-2:$5/$6)만 사용 중입니다. (점검계정 수: $checked)" >> "$resultfile" 2>&1
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

  # 1) 소유자/권한 읽기
  local owner perm
  owner="$(stat -c '%U' "$target" 2>/dev/null)"
  perm="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    echo "※ U-18 결과 : N/A" >> "$resultfile" 2>&1
    echo " stat 명령으로 $target 정보를 읽지 못했습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 소유자 체크
  if [ "$owner" != "root" ]; then
    echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " $target 파일의 소유자가 root가 아닙니다. (owner=$owner)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 권한 정규화 (0400 -> 400, 00 -> 000)
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

  # 4) 기준: 권한이 정확히 400만 양호
  if [ "$perm" = "400" ]; then
    echo "※ U-18 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " $target 소유자(root) 및 권한(perm=$perm)이 기준(400)을 만족합니다." >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-18 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
  echo " $target 파일 권한이 400이 아닙니다. (perm=$perm)" >> "$resultfile" 2>&1
  return 0
}
#수진
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
#연수
U_28() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-28(상) | UNIX > 2. 파일 및 디렉토리 관리 > 접속 IP 및 포트 제한 ◀"  >> "$resultfile" 2>&1
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

#수진
# U_30() {
#     echo "" >> "$resultfile" 2>&1
#     echo "▶ U-30(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 ◀" >> "$resultfile" 2>&1
#     echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> "$resultfile" 2>&1
#     vuln_flag=0
#     print_vuln_once() {
#         if [ "$vuln_flag" -eq 0 ]; then
#             echo "※ U-30 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
#             vuln_flag=1
#         fi
#     }
#     # 현재 세션 umask 설정 점검
#     cur_umask="$(umask)"
#     group_umask=$(printf "%s" "$cur_umask" | sed 's/^.*\(..\)$/\1/' | cut -c1)
#     other_umask=$(printf "%s" "$cur_umask" | sed 's/^.*\(..\)$/\1/' | cut -c2)
#     if [ "$group_umask" -lt 2 ] 2>/dev/null; then
#         print_vuln_once
#         echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다. (umask=$cur_umask)" >> "$resultfile" 2>&1
#     fi
#     if [ "$other_umask" -lt 2 ] 2>/dev/null; then
#         print_vuln_once
#         echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다. (umask=$cur_umask)" >> "$resultfile" 2>&1
#     fi
#     # /etc/profile 파일 내 umask 설정 점검
#     check_umask_file() {
#         file="$1"
#         [ -f "$file" ] || return 0
#         grep -i 'umask' "$file" 2>/dev/null \
#         | grep -vE '^[[:space:]]*#|=' \
#         | while read _ val; do
#             val="$(printf "%s" "$val" | tr -d '[:space:]')"
#             case "$val" in
#                 [0-9][0-9][0-9]|[0-9][0-9])
#                     g=$(printf "%s" "$val" | sed 's/^.*\(..\)$/\1/' | cut -c1)
#                     o=$(printf "%s" "$val" | sed 's/^.*\(..\)$/\1/' | cut -c2)
#                     if [ "$g" -lt 2 ] || [ "$o" -lt 2 ]; then
#                         print_vuln_once
#                         echo " $file 파일에 umask 값이 022 이상으로 설정되지 않았습니다. (umask $val)" >> "$resultfile" 2>&1
#                     fi
#                     ;;
#                 *)
#                     print_vuln_once
#                     echo " $file 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다. (umask $val)" >> "$resultfile" 2>&1
#                     ;;
#             esac
#         done
#     }
#     check_umask_file "/etc/profile"
#     check_umask_file "/etc/bash.bashrc"
#     check_umask_file "/etc/login.defs"
#     # 사용자 홈 디렉터리 설정 파일에서 umask 설정 확인
#     awk -F: '$7 !~ /(nologin|false)/ {print $6}' /etc/passwd | sort -u |
#     while IFS= read -r home; do
#         for f in ".profile" ".bashrc" ".bash_profile" ".cshrc" ".login"; do
#             check_umask_file "$home/$f"
#         done
#     done
#     if [ "$vuln_flag" -eq 0 ]; then
#         echo "※ U-30 결과 : 양호(Good)" >> "$resultfile" 2>&1
#     fi
# }
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
    # FTP 점검 (vsftpd / proftpd)
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
    # vsftpd 설정 파일 점검
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
    # proftpd 설정 파일 점검
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
    # NFS 점검
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
    # Samba 점검
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
#연수
U_38() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-38(상) | UNIX > 3. 서비스 관리 | DoS 공격에 취약한 서비스 비활성화 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 해당 서비스를 사용하지 않는 경우 N/A, (2) DoS 공격에 취약한 서비스가 비활성화된 경우" >> "$resultfile" 2>&1

  local in_scope_active=0
  local vulnerable=0

  # Ubuntu에서는 inetd/xinetd가 거의 없으므로 “포트 리스닝” 기반이 가장 신뢰도 높음
  # 전통 DoS 취약 서비스 포트:
  # echo: 7/tcp,7/udp | discard: 9/tcp,9/udp | daytime: 13/tcp,13/udp | chargen: 19/tcp,19/udp
  local ports=("7" "9" "13" "19")
  local protos=("tcp" "udp")

  ########################################
  # A) systemd socket 단위 존재 여부 확인 (있으면 보조 근거)
  ########################################
  if command -v systemctl >/dev/null 2>&1; then
    local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")
    local sock
    for sock in "${systemd_sockets[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$sock"; then
        # 존재하면 활성 상태 체크(근거로만 기록)
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

  ########################################
  # B) 포트 리스닝 기반 점검 (Ubuntu 24.04 핵심)
  ########################################
  if command -v ss >/dev/null 2>&1; then
    local p proto
    for p in "${ports[@]}"; do
      # TCP 리스닝
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
        in_scope_active=1
        vulnerable=1
        echo "※ 취약 징후: ${p}/tcp 포트가 리스닝 중입니다. (echo/discard/daytime/chargen 계열 가능)" >> "$resultfile" 2>&1
      fi
      # UDP 리스닝
      if ss -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"; then
        in_scope_active=1
        vulnerable=1
        echo "※ 취약 징후: ${p}/udp 포트가 리스닝 중입니다. (echo/discard/daytime/chargen 계열 가능)" >> "$resultfile" 2>&1
      fi
    done
  else
    # ss가 없다면 최소한 netstat로 대체 (Ubuntu 기본은 ss라 보통 여기 안 옴)
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

  ########################################
  # C) (옵션) 참고용 서비스 상태 로그 (U-38 판정에는 미포함)
  #     - SNMP/DNS/NTP는 환경상 정상 사용 가능성이 높아 info로만 출력
  ########################################
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

  ########################################
  # D) N/A 판정
  ########################################
  if [ "$in_scope_active" -eq 0 ]; then
    echo "※ U-38 결과 : N/A" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스(echo/discard/daytime/chargen)가 사용되지 않는 것으로 확인되어 점검 대상이 아닙니다." >> "$resultfile" 2>&1
    return 0
  fi

  ########################################
  # E) 최종 판정
  ########################################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-38 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 활성화되어 있습니다. (포트 리스닝 또는 socket 활성)" >> "$resultfile" 2>&1
  else
    echo "※ U-38 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DoS 공격에 취약한 전통 서비스가 비활성화되어 있습니다. (활성 서비스 미확인)" >> "$resultfile" 2>&1
  fi

  return 0
}
#수진
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
#수진
U_45() {
    # 2026/02/06 기준 sendmail 최신 버전 : 8.18.2 를 기준으로 점검
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
#연수
U_48() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-48(중) | UNIX > 3. 서비스 관리 > expn, vrfy 명령어 제한 ◀"  >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : (1) 메일 서비스를 사용하지 않는 경우 N/A, (2) 사용 시 VRFY/EXPN 제한 설정이 적용된 경우" >> "$resultfile" 2>&1

  local mail_in_use=0
  local vulnerable=0
  local evidences=()

  # Ubuntu에서 주로 보는 MTA
  local has_postfix=0
  local has_exim=0

  # Exim을 “점검불가=취약”으로 볼지 정책 스위치(기본: 보수적으로 취약 처리)
  local STRICT_EXIM=1

  ########################################################
  # 1) 메일(SMTP) 서비스 사용 여부 판단
  #    - 25/tcp LISTEN 또는 MTA 서비스 active/프로세스 감지 시 사용 중
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
    # postfix
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "postfix.service"; then
      if systemctl is-active --quiet "postfix.service" 2>/dev/null; then
        mail_in_use=1
        has_postfix=1
        evidences+=("systemd: postfix.service active")
      fi
    fi
    # exim4
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "exim4.service"; then
      if systemctl is-active --quiet "exim4.service" 2>/dev/null; then
        mail_in_use=1
        has_exim=1
        evidences+=("systemd: exim4.service active")
      fi
    fi
  fi

  # 프로세스 감지(서비스가 비활성인데도 실행 중인 경우 대비)
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

  ########################################################
  # 2) 미사용이면 N/A
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

  ############################
  # 3-A) Postfix 점검 (Ubuntu 핵심)
  ############################
  if [ "$has_postfix" -eq 1 ]; then
    local maincf="/etc/postfix/main.cf"
    if [ -f "$maincf" ]; then
      # disable_vrfy_command = yes (핵심)
      local postfix_vrfy
      postfix_vrfy=$(grep -vE '^\s*#' "$maincf" 2>/dev/null \
        | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l)

      # EHLO keyword discard(선택적으로 권장)
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
        # expn/vrfy 문자열 포함 여부까지 적당히 체크(없어도 치명은 아님)
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

  ############################
  # 3-B) Exim4 점검 (Ubuntu 환경에서 가끔 존재)
  ############################
  if [ "$has_exim" -eq 1 ]; then
    # Exim4는 구성 자동판별이 어려워서 증거만 남기거나(느슨), 점검불가=취약(보수) 선택
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

  ########################################################
  # 4) 최종 판정
  ########################################################
  if [ "$vulnerable" -eq 1 ]; then
    echo "※ U-48 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 VRFY/EXPN 제한 설정이 미흡합니다. (미설정/점검불가=$bad_cnt, 설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  else
    echo "※ U-48 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " 메일(SMTP) 서비스 사용 중이며 VRFY/EXPN 제한 설정이 확인되었습니다. (설정확인=$ok_cnt)" >> "$resultfile" 2>&1
  fi

  return 0
}
#수진
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
#수진
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
#수진
U_60() {
    echo "" >> "$resultfile" 2>&1
    echo " ▶ U-60(중) | 3. 서비스 관리 > 3.27 SNMP Community String 복잡성 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우" >> "$resultfile" 2>&1
    vuln_flag=0
    community_found=0
    # SNMP 사용 여부 판단 - 미설치 시 양호
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
    # snmpd.conf 검색
    snmpdconf_files=()
    [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
    while IFS= read -r f; do snmpdconf_files+=("$f"); done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)
    if [ ${#snmpdconf_files[@]} -eq 0 ]; then
        echo "※ U-60 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " SNMP 서비스를 사용하고, Community String을 설정하는 파일이 없습니다." >> "$resultfile" 2>&1
        return 0
    fi
    # 복잡성 판단
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
#수진
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
U_40
U_43
U_45
U_48
U_50
U_53
U_55
U_58
U_60
U_63
U_65