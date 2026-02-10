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
#연진
U_24() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-24(상) | 2. 파일 및 디렉토리 관리 > 2.11 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정이고, 쓰기 권한이 통제된 경우" >> "$resultfile" 2>&1
  
    VULN=0
    REASON=""
  
    # 1. [오류 수정] 배열 선언 괄호 '(' 추가
    CHECK_FILES=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout" ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts")
  
    # 2. 사용자 추출 (요청하신 로직 반영됨)
    # nologin이나 false가 포함된 쉘을 쓰는 계정은 제외
    USER_LIST=$(awk -F: '$7!~/nologin/ && $7!~/false/ {print $1":"$6}' /etc/passwd)
  
    for USER_INFO in $USER_LIST; do
        USER_NAME=$(echo "$USER_INFO" | cut -d: -f1)
        USER_HOME=$(echo "$USER_INFO" | cut -d: -f2)
    
        # 3. 홈 디렉터리 존재 확인
        if [ -d "$USER_HOME" ]; then
            for FILE in "${CHECK_FILES[@]}"; do
                TARGET="$USER_HOME/$FILE"
        
                if [ -f "$TARGET" ]; then
          
                    # 4. 파일 소유자 확인 
                    FILE_OWNER=$(ls -l "$TARGET" | awk '{print $3}')
                    
                    # [오류 수정] 대괄호 뒤 공백 추가: [ "$FILE_OWNER"
                    if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
                        VULN=1
                        REASON="$REASON 파일 소유자 불일치: $TARGET (소유자: $FILE_OWNER) |"
                    fi
          
                    # 5. 파일 권한 확인 
                    PERM=$(ls -l "$TARGET" | awk '{print $1}')
                    
                    # [오류 수정] 변수명 통일 (PERMIT -> PERM)
                    GROUP_WRITE=${PERM:5:1}
                    OTHER_WRITE=${PERM:8:1}
          
                    # [오류 수정] 변수 앞 $ 추가 ("GROUP_WRITE" -> "$GROUP_WRITE")
                    if [ "$GROUP_WRITE" == "w" ] || [ "$OTHER_WRITE" == "w" ]; then
                        VULN=1
                        REASON="$REASON 권한 취약: $TARGET (권한: $PERM - 쓰기 권한 존재) |"
                    fi
                fi
            done
        fi
    done
  
    # 결과 출력
    if [ $VULN -eq 1 ]; then
        echo "※ U-24 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $REASON" >> "$resultfile" 2>&1
    else
        echo "※ U-24 결과 : 양호(Good)" >> "$resultfile" 2>&1
    fi
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
#희윤
U_26(){
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-26(상) | 2. 파일 및 디렉토리 관리 > /dev에 존재하지 않는 device 파일 점검 ◀"  >> "$resultfile" 2>&1
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
    
        # 3. 파일 권한 체크 (600보다 크면 취약)
        if [ "$PERMIT" -gt 600 ]; then
            VULN=1
            REASON="$REASON 파일 권한이 600보다 큽니다(현재: $PERMIT). |"
        fi
    else
        # 파일이 없으면 양호 (그냥 넘어감)
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
    fi  # [수정] 여기에 fi를 추가하여 if문을 닫았습니다.
  
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
    XINTETD_VUL=$(grep -lE "disable\s*=\s*no" /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec 2>/dev/null)
    if [ -n "$XINTETD_VUL" ]; then
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
#연수
U_39() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-39(상) | UNIX > 3. 서비스 관리 > 불필요한 NFS 서비스 비활성화 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> "$resultfile" 2>&1

  local found=0
  local reason=""

  # 0) Ubuntu 24.04 기준: NFS "서버" 데몬 중심으로 판정 (클라이언트 오탐 방지)
  # 핵심 서버 판단: nfs-server.service active OR rpc.nfsd/mountd 프로세스 존재

  # 1) systemd 기반 서비스 체크 (Ubuntu)
  if command -v systemctl >/dev/null 2>&1; then
    # NFS 서버 서비스가 활성인지
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "nfs-server.service"; then
      if systemctl is-active --quiet nfs-server.service 2>/dev/null; then
        found=1
        reason+="nfs-server.service active; "
      fi
    fi

    # rpcbind가 활성인지만으로는 NFS 서버 확정이 아님(다른 RPC 서비스도 사용 가능)
    if [ "$found" -eq 0 ]; then
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "rpcbind.service"; then
        if systemctl is-active --quiet rpcbind.service 2>/dev/null; then
          reason+="rpcbind.service active(보조 근거); "
        fi
      fi
    fi
  fi

  # 2) 프로세스 기반 확인 (Ubuntu에서 확실한 서버 프로세스 위주)
  # rpc.nfsd / rpc.mountd 가 있으면 NFS 서버로 간주
  if ps -ef 2>/dev/null | grep -E 'rpc\.nfsd|[[:space:]]nfsd([[:space:]]|$)|rpc\.mountd|[[:space:]]mountd([[:space:]]|$)' \
    | grep -v grep >/dev/null 2>&1; then
    found=1
    reason+="rpc.nfsd/mountd 프로세스 실행 중; "
  fi

  # 3) 보조 프로세스(클라이언트/부가) 확인: 이것만으로는 취약 판정 X
  # 단, found=1일 때 근거 설명을 풍부하게 하기 위해 추가
  if [ "$found" -eq 1 ]; then
    if ps -ef 2>/dev/null | grep -iE 'rpcbind|rpc\.statd|statd|rpc\.idmapd|idmapd|gssd' \
      | grep -ivE 'grep|kblockd|rstatd' >/dev/null 2>&1; then
      reason+="(보조) rpc/statd/idmapd/gssd 등 관련 프로세스도 확인됨; "
    fi
  fi

  if [ "$found" -eq 1 ]; then
    echo "※ U-39 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 불필요한 NFS 서버 서비스/데몬이 실행 중입니다. ($reason)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-39 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " NFS 서버 서비스/데몬(nfs-server, rpc.nfsd, rpc.mountd)이 비활성/미사용 상태입니다." >> "$resultfile" 2>&1
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
  if ps -ef | grep -v grep | grep -Ei "automount|autofs"; then
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

  # Ubuntu 24.04 기준: tftp는 tftpd-hpa/atftpd + socket 형태까지 고려
  local services=("tftp" "talk" "ntalk")

  # 1) systemd 서비스/소켓 체크 (활성/동작 중이면 취약)
  if command -v systemctl >/dev/null 2>&1; then
    # Ubuntu에서 자주 쓰는 유닛/소켓 포함
    local units=(
      "tftpd-hpa.service"
      "atftpd.service"
      "tftp.service"
      "tftp.socket"
      "tftpd.socket"
      "tftpd-hpa.socket"
      "talk.service"
      "ntalk.service"
      "talkd.service"
      "ntalkd.service"
      "inetd.service"
      "openbsd-inetd.service"
      "xinetd.service"
    )

    for u in "${units[@]}"; do
      # 등록되어 있고 active이면 취약
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
        if systemctl is-active --quiet "$u" 2>/dev/null; then
          echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
          echo " tftp/talk/ntalk 관련 서비스가 systemd에서 활성 상태입니다. (unit=$u)" >> "$resultfile" 2>&1
          return 0
        fi
      fi
    done

    # 혹시 이름이 다른 tftp 계열이 있는 경우를 위해 보조 검사
    if systemctl list-units --type=service --all 2>/dev/null | grep -Eiq 'tftp|tftpd|talk|ntalk'; then
      # 위에서 이미 잡혔으면 return 됐을 거라, 여기서는 소켓/서비스가 목록에 존재하는지 확인 후 active를 한 번 더 본다
      if systemctl list-units --type=service 2>/dev/null | grep -Eiq 'tftp|tftpd|talk|ntalk'; then
        echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " tftp/talk/ntalk 관련 서비스가 systemctl 목록에서 동작 중으로 확인됩니다." >> "$resultfile" 2>&1
        return 0
      fi
    fi
  fi

  # 2) xinetd 설정 체크 (disable=yes가 아니면 취약) - Ubuntu에선 흔치 않지만 있으면 확인
  if [ -d /etc/xinetd.d ]; then
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        local disable_line
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null \
          | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
          echo " $s 서비스가 /etc/xinetd.d/$s 에서 비활성화(disable=yes)되어 있지 않습니다." >> "$resultfile" 2>&1
          return 0
        fi
      fi
    done
  fi

  # 3) inetd(openbsd-inetd) 설정 체크: /etc/inetd.conf 또는 /etc/inetd.d/* (Ubuntu는 openbsd-inetd 사용 가능)
  if [ -f /etc/inetd.conf ]; then
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null \
        | grep -Eiq "(^|[[:space:]])$s([[:space:]]|$)"; then
        echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $s 서비스가 /etc/inetd.conf 파일에서 활성 상태(주석 아님)로 존재합니다." >> "$resultfile" 2>&1
        return 0
      fi
    done
  fi

  if [ -d /etc/inetd.d ]; then
    for s in "${services[@]}"; do
      if grep -R --include="*" -nE "^[[:space:]]*($s)[[:space:]]" /etc/inetd.d 2>/dev/null | grep -q .; then
        # 주석 제거까지 엄격히 하려면 파일별 파싱이 필요한데, 여기서는 존재 자체를 취약 근거로 처리
        echo "※ U-44 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
        echo " $s 관련 설정이 /etc/inetd.d/ 디렉터리 내에 존재합니다. (openbsd-inetd 사용 가능성)" >> "$resultfile" 2>&1
        return 0
      fi
    done
  fi

  echo "※ U-44 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " tftp/talk/ntalk 관련 서비스가 systemd/xinetd/inetd 설정에서 모두 비활성 상태입니다." >> "$resultfile" 2>&1
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

      if [-z "$CHECK" ]; then
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
#연수
U_49() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-49(상) | UNIX > 3. 서비스 관리 > DNS 보안 버전 패치 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우" >> "$resultfile" 2>&1

  local bind_active=0
  local bind_running=0
  local bind_ver=""
  local upg_bind=0

  # 1) DNS 서비스 사용 여부 (Ubuntu: bind9)
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet bind9 2>/dev/null; then
      bind_active=1
    fi
  fi

  # 프로세스(named)로도 보조 확인 (컨테이너/수동 실행 케이스)
  if ps -ef 2>/dev/null | grep -E '[[:space:]]named([[:space:]]|$)|/named' | grep -v grep >/dev/null 2>&1; then
    bind_running=1
  fi

  # 서비스 미사용이면 양호
  if [ "$bind_active" -eq 0 ] && [ "$bind_running" -eq 0 ]; then
    echo "※ U-49 결과 : 양호(Good)" >> "$resultfile" 2>&1
    echo " DNS 서비스(bind9/named)가 비활성/미사용 상태입니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 2) BIND 버전 확인 (근거 출력용)
  # Ubuntu에서는 named -v가 있을 수도/없을 수도 있어서 dpkg로도 확인
  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi

  if [ -z "$bind_ver" ] && command -v dpkg-query >/dev/null 2>&1; then
    # bind9 패키지 버전에서 x.y.z 형태만 추출
    bind_ver="$(dpkg-query -W -f='${Version}\n' bind9 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi

  [ -z "$bind_ver" ] && bind_ver="unknown"

  # 3) 최신 패치 여부(업그레이드 대기) 확인 - Ubuntu용
  if ! command -v apt >/dev/null 2>&1; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " DNS 서비스는 사용 중이나 apt 명령이 없어 패치 상태를 확인할 수 없습니다. (BIND=$bind_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  # apt 목록 갱신(환경에 따라 오래돼서 미탐 방지) - 에러는 무시
  apt-get update -y >/dev/null 2>&1

  # bind9 업그레이드 대기 여부 확인
  if apt list --upgradable 2>/dev/null | grep -Eiq '^bind9/|^bind9-utils/|^bind9-host/|^dnsutils/'; then
    upg_bind=1
  fi

  if [ "$upg_bind" -eq 1 ]; then
    echo "※ U-49 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " BIND(bind9) 관련 업그레이드 대기 항목이 존재합니다. (BIND=$bind_ver, apt upgradable 기준)" >> "$resultfile" 2>&1
    return 0
  fi

  echo "※ U-49 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " DNS 서비스 사용 중이며 BIND(bind9) 관련 업그레이드 대기 항목이 확인되지 않습니다. (BIND=$bind_ver)" >> "$resultfile" 2>&1
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

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "※ U-54 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " systemctl 명령을 사용할 수 없어 FTP 서비스 상태를 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  _is_unit_active_if_exists() {
    local unit="$1"
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
      if systemctl is-active --quiet "$unit" 2>/dev/null; then
        return 0
      fi
    fi
    return 1
  }

  # ==============================
  # 1) vsftpd 확인 (Ubuntu에도 동일)
  # ==============================
  if _is_unit_active_if_exists "vsftpd.service"; then
    ftp_active=1
    reason+="vsftpd.service 활성; "
  fi

  # ==============================
  # 2) proftpd 확인 (proftpd.service / proftpd@*.service 등)
  # ==============================
  # 등록된 proftpd 유닛이 하나라도 active면 취약
  local pro_units
  pro_units="$(systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -E '^proftpd(@.*)?\.service$' || true)"
  if [ -n "$pro_units" ]; then
    while IFS= read -r u; do
      [ -z "$u" ] && continue
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        ftp_active=1
        reason+="$u 활성; "
      fi
    done <<< "$pro_units"
  fi

  # ==============================
  # 3) pure-ftpd 확인 (Ubuntu에서 종종 사용)
  # ==============================
  if _is_unit_active_if_exists "pure-ftpd.service"; then
    ftp_active=1
    reason+="pure-ftpd.service 활성; "
  fi

  # ==============================
  # 4) xinetd ftp 확인 (Ubuntu에서는 드물지만 있으면 체크)
  # ==============================
  if [ -f /etc/xinetd.d/ftp ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/ftp 2>/dev/null \
      | grep -Eiq "disable[[:space:]]*=[[:space:]]*no"; then
      ftp_active=1
      reason+="xinetd ftp 활성(disable=no); "
    fi
  fi

  # ==============================
  # 5) inetd(openbsd-inetd) ftp 확인
  # ==============================
  if [ -f /etc/inetd.conf ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -Eiq '(^|[[:space:]])ftp([[:space:]]|$)'; then
      ftp_active=1
      reason+="inetd.conf ftp 활성 설정 존재; "
    fi
  fi

  if [ -d /etc/inetd.d ]; then
    # /etc/inetd.d/ 안에 ftp 관련 설정이 존재하면 활성 가능성으로 취약 처리
    if grep -R --include="*" -nEi '(^|[[:space:]])ftp([[:space:]]|$)' /etc/inetd.d 2>/dev/null | grep -q .; then
      ftp_active=1
      reason+="/etc/inetd.d 내 ftp 관련 설정 존재; "
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
  echo " vsftpd/proftpd/pure-ftpd 및 inetd/xinetd 기반 FTP 서비스가 모두 비활성 상태입니다." >> "$resultfile" 2>&1
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
#연수
U_59() {
  echo ""  >> "$resultfile" 2>&1
  echo "▶ U-59(상) | UNIX > 3. 서비스 관리 > 안전한 SNMP 버전 사용 ◀" >> "$resultfile" 2>&1
  echo " 양호 판단 기준 : SNMP 서비스를 v3 이상으로 사용하는 경우" >> "$resultfile" 2>&1

  # Ubuntu 24.04 전용 경로 보강
  local snmpd_conf="/etc/snmp/snmpd.conf"
  local snmpd_persist1="/var/lib/net-snmp/snmpd.conf"
  local snmpd_persist2="/var/lib/snmp/snmpd.conf"

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
  if [ -f "$snmpd_persist1" ]; then
    cfg_files+=("$snmpd_persist1")
    ((cfg_exists_count++))
  fi
  if [ -f "$snmpd_persist2" ]; then
    cfg_files+=("$snmpd_persist2")
    ((cfg_exists_count++))
  fi

  if [ "$cfg_exists_count" -eq 0 ]; then
    echo "※ U-59 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " snmpd는 활성 상태이나 설정 파일이 없습니다. ($snmpd_conf / $snmpd_persist1 / $snmpd_persist2 미존재)" >> "$resultfile" 2>&1
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
  local latest_kernel_pkg_ver=""
  local pending_updates=0

  # 0) OS/Kernel 기본 정보
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_name="$NAME"
    os_ver="$VERSION_ID"
  fi
  kernel_running="$(uname -r 2>/dev/null)"

  # 1) Ubuntu 24.04 여부
  if ! echo "$os_name" | grep -qi "Ubuntu" || [ "$os_ver" != "24.04" ]; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " Ubuntu 24.04 환경이 아닙니다. (현재: $os_name $os_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  # 2) 업데이트 대기 여부 확인 (apt)
  if ! command -v apt >/dev/null 2>&1; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " apt 명령 확인 불가로 보안 패치 적용 여부를 확인할 수 없습니다." >> "$resultfile" 2>&1
    return 0
  fi

  # 목록 갱신(미탐 방지) - 실패해도 계속 진행
  apt-get update -y >/dev/null 2>&1

  # 업그레이드 대기 패키지가 있으면 취약 처리
  if apt list --upgradable 2>/dev/null | grep -q "/"; then
    pending_updates=1
  fi

  if [ "$pending_updates" -eq 1 ]; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 업데이트(패치) 미적용 대기 항목이 존재합니다. (apt upgradable 기준)" >> "$resultfile" 2>&1
    return 0
  fi

  # 3) 커널 최신/재부팅 필요 여부 확인
  # 설치된 linux-image 패키지 중 최신 버전 추출
  if command -v dpkg-query >/dev/null 2>&1; then
    latest_kernel_pkg_ver="$(
      dpkg-query -W -f='${Package}\t${Version}\n' 'linux-image-[0-9]*' 2>/dev/null \
        | awk '{print $2}' \
        | sort -V \
        | tail -n 1
    )"
  fi

  if [ -z "$latest_kernel_pkg_ver" ]; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 설치된 커널 패키지 정보를 확인하지 못했습니다. (dpkg-query linux-image-* 실패)" >> "$resultfile" 2>&1
    return 0
  fi

  # 실행 커널이 설치된 최신 커널 패키지와 크게 불일치하면(대부분 재부팅 필요 케이스)
  # running 커널 문자열에 최신 패키지 버전의 일부(숫자/점/하이픈)가 포함되는지로 보수적으로 체크
  if ! echo "$kernel_running" | grep -q "$(echo "$latest_kernel_pkg_ver" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+' )"; then
    echo "※ U-64 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
    echo " 최신 커널 적용 여부가 불명확하거나 재부팅이 필요할 수 있습니다. (running=$kernel_running, latest_pkg=$latest_kernel_pkg_ver)" >> "$resultfile" 2>&1
    return 0
  fi

  # 양호
  echo "※ U-64 결과 : 양호(Good)" >> "$resultfile" 2>&1
  echo " Ubuntu 24.04 환경이며 업데이트 대기 없음 + 커널 적용 상태가 최신으로 확인됩니다. (kernel=$kernel_running)" >> "$resultfile" 2>&1
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
          CHECK_MSG=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.info[[:space:]]+-?\/var\/log\/messages")
          CHECK_SECURE=$(echo "$ALL_CONF_CONTENT" | grep -E "auth(priv)?\.\*[[:space:]]+-?\/var\/log\/secure")
          CHECK_MAIL=$(echo "$ALL_CONF_CONTENT" | grep -E "mail\.\*[[:space:]]+-?\/var\/log\/maillog")
          CHECK_CRON=$(echo "$ALL_CONF_CONTENT" | grep -E "cron\.\*[[:space:]]+-?\/var\/log\/cron")
          CHECK_ALERT=$(echo "$ALL_CONF_CONTENT" | grep -E "\*\.alert[[:space:]]+(\/dev\/console|:omusrmsg:\*|root)")
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

U_01
U_03
U_05
U_06
U_08
U_10
U_11
U_13
U_15
U_16
U_18
U_20
U_21
U_23
U_24
U_25
U_26
U_28
U_29
U_30
U_31
U_33
U_34
U_35
U_36
U_38
U_39
U_40
U_41
U_43
U_44
U_45
U_46
U_48
U_49
U_50
U_51
U_53
U_54
U_55
U_56
U_58
U_59
U_60
U_61
U_63
U_64
U_65
U_66