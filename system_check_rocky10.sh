#!/bin/bash
resultfile="results.txt"

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