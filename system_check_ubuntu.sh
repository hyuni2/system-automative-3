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

U_05
U_10
U_15
U_20
U_25