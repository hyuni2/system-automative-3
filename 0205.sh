#!/bin/bash

result="results.txt"

U_05() {
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
    echo "▶ U-15(상) | 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정 ◀"  >> $resultfile 2>&1
    echo " 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"  >> $resultfile 2>&1
    if [ `find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l` -gt 0 ]; then
        echo "※ U-15 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo " 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다." >> $resultfile 2>&1
    else
        echo "※ U-15 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
}

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
U_20() {
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

# -------------------------------------------------------
# 혹시 몰라서 긁어둔 inet.conf 점검 스크립트도 첨부해두겠습니다
# -------------------------------------------------------
# # U-20 /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# resultfile="results.txt"
# echo "▶ U-20(상) | 2. 파일 및 디렉토리 관리 > 2.7 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 ◀"  >> $resultfile 2>&1
# echo " 양호 판단 기준 : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"  >> $resultfile 2>&1
# file_exists_count=0
# # etc/xinetd.conf 파일 소유자 및 권한 점검
# if [ -f /etc/xinetd.conf ]; then
# 	((file_exists_count++))
# 	etc_xinetdconf_owner_name=`ls -l /etc/xinetd.conf | awk '{print $3}'`
# 	if [[ $etc_xinetdconf_owner_name =~ root ]]; then
# 		etc_xinetdconf_permission=`stat /etc/xinetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
# 		if [ $etc_xinetdconf_permission -gt 600 ]; then
# 			echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 			echo " /etc/(x)inetd.conf 파일의 권한이 600 초과입니다." >> $resultfile 2>&1
# 		fi
# 	else
# 		echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 		echo " /etc/(x)inetd.conf 파일의 소유자가 root가 아닙니다." >> $resultfile 2>&1
# 	fi
# fi
# # etc/xinetd.d 디렉터리 내 모든 파일의 소유자 및 권한 점검
# if [ -d /etc/xinetd.d ]; then
# 	etc_xinetdd_file_count=`find /etc/xinetd.d -type f 2>/dev/null | wc -l`
# 	if [ $etc_xinetdd_file_count -gt 0 ]; then
# 		xinetdd_files=(`find /etc/xinetd.d -type f 2>/dev/null`)
# 		for ((i=0; i<${#xinetdd_files[@]}; i++))
# 		do
# 			xinetdd_file_owner_name=`ls -l ${xinetdd_files[$i]} | awk '{print $3}'`
# 			if [[ $xinetdd_file_owner_name =~ root ]]; then
# 				xinetdd_file_permission=`stat ${xinetdd_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
# 				if [ $xinetdd_file_permission -gt 600 ]; then
# 					echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 					echo " /etc/xinetd.d 디렉터리 내 파일의 권한이 600 초과입니다." >> $resultfile 2>&1
# 				fi
# 			else
# 				echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 				echo " /etc/xinetd.d 디렉터리 내 파일의 소유자가 root가 아닙니다." >> $resultfile 2>&1
# 			fi
# 		done
# 	fi
# fi
# # etc/inetd.conf 파일 소유자 및 권한 점검
# if [ -f /etc/inetd.conf ]; then
# 	((file_exists_count++))
# 	etc_inetdconf_owner_name=`ls -l /etc/inetd.conf | awk '{print $3}'`
# 	if [[ $etc_inetdconf_owner_name =~ root ]]; then
# 		etc_inetdconf_permission=`stat /etc/inetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
# 		if [ $etc_inetdconf_permission -gt 600 ]; then
# 			echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 			echo " /etc/inetd.conf 파일의 권한이 600 초과입니다." >> $resultfile 2>&1
# 		fi
# 	else
# 		echo "※ U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
# 		echo " /etc/inetd.conf 파일의 소유자가 root가 아닙니다." >> $resultfile 2>&1
# 	fi
# fi
# if [ $file_exists_count -eq 0 ]; then
# 	echo "※ U-20 결과 : N/A" >> $resultfile 2>&1
# 	echo " /etc/inetd.conf 파일이 없습니다." >> $resultfile 2>&1
# else
# 	echo "※ U-20 결과 : 양호(Good)" >> $resultfile 2>&1
# fi

U_05
U_10
U_15
U_20