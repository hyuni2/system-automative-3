#!/bin/bash
resultfile="results.txt"

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

U_30() {
    echo "" >> "$resultfile" 2>&1
    echo "▶ U-30(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 ◀" >> "$resultfile" 2>&1
    echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> "$resultfile" 2>&1
    vuln_flag=0
    print_vuln_once() {
        if [ "$vuln_flag" -eq 0 ]; then
            echo "※ U-30 결과 : 취약(Vulnerable)" >> "$resultfile" 2>&1
            vuln_flag=1
        fi
    }
    # 현재 세션 umask 설정 점검
    cur_umask="$(umask)"
    group_umask=$(printf "%s" "$cur_umask" | sed 's/^.*\(..\)$/\1/' | cut -c1)
    other_umask=$(printf "%s" "$cur_umask" | sed 's/^.*\(..\)$/\1/' | cut -c2)
    if [ "$group_umask" -lt 2 ] 2>/dev/null; then
        print_vuln_once
        echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다. (umask=$cur_umask)" >> "$resultfile" 2>&1
    fi
    if [ "$other_umask" -lt 2 ] 2>/dev/null; then
        print_vuln_once
        echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다. (umask=$cur_umask)" >> "$resultfile" 2>&1
    fi
    # /etc/profile 파일 내 umask 설정 점검
    check_umask_file() {
        file="$1"
        [ -f "$file" ] || return 0
        grep -i 'umask' "$file" 2>/dev/null \
        | grep -vE '^[[:space:]]*#|=' \
        | while read _ val; do
            val="$(printf "%s" "$val" | tr -d '[:space:]')"
            case "$val" in
                [0-9][0-9][0-9]|[0-9][0-9])
                    g=$(printf "%s" "$val" | sed 's/^.*\(..\)$/\1/' | cut -c1)
                    o=$(printf "%s" "$val" | sed 's/^.*\(..\)$/\1/' | cut -c2)
                    if [ "$g" -lt 2 ] || [ "$o" -lt 2 ]; then
                        print_vuln_once
                        echo " $file 파일에 umask 값이 022 이상으로 설정되지 않았습니다. (umask $val)" >> "$resultfile" 2>&1
                    fi
                    ;;
                *)
                    print_vuln_once
                    echo " $file 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다. (umask $val)" >> "$resultfile" 2>&1
                    ;;
            esac
        done
    }
    check_umask_file "/etc/profile"
    check_umask_file "/etc/bash.bashrc"
    check_umask_file "/etc/login.defs"
    # 사용자 홈 디렉터리 설정 파일에서 umask 설정 확인
    awk -F: '$7 !~ /(nologin|false)/ {print $6}' /etc/passwd | sort -u |
    while IFS= read -r home; do
        for f in ".profile" ".bashrc" ".bash_profile" ".cshrc" ".login"; do
            check_umask_file "$home/$f"
        done
    done
    if [ "$vuln_flag" -eq 0 ]; then
        echo "※ U-30 결과 : 양호(Good)" >> "$resultfile" 2>&1
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