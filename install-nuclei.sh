#!/bin/bash

# Nuclei 자동 설치 스크립트
# 이 스크립트는 소스코드에서 Nuclei를 빌드하여 설치합니다.

set -e  # 에러 발생 시 즉시 종료

echo "================================================"
echo "🚀 Nuclei 설치 관리자"
echo "================================================"
echo ""

# 1. 필수 도구 설치
echo "📦 필수 도구 설치 중..."
sudo apt update
sudo apt install -y git curl build-essential ca-certificates
echo "✅ 필수 도구 설치 완료"
echo ""

# 2. Go 설치 (1.22.6 버전)
echo "🔍 Go 설치 상태 확인..."

if command -v go &> /dev/null; then
    go_version=$(go version | cut -d' ' -f3)
    echo "✅ Go 설치됨: $go_version"
else
    echo "📥 Go 1.22.6 설치 중..."
    
    # 기존 Go 제거 (설치되어 있는 경우)
    if [ -d "/usr/local/go" ]; then
        echo "   기존 Go 제거 중..."
        sudo rm -rf /usr/local/go
    fi
    
    # Go 1.22.6 다운로드 및 설치
    curl -LO https://go.dev/dl/go1.22.6.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.22.6.linux-amd64.tar.gz
    rm go1.22.6.linux-amd64.tar.gz
    
    # PATH에 Go 바이너리 경로 추가
    if ! grep -q "export PATH=/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
    fi
    source ~/.bashrc
    
    go_version=$(go version | cut -d' ' -f3)
    echo "✅ Go 설치 완료: $go_version"
fi
echo ""

# 3. Nuclei 빌드
echo "🔨 Nuclei 소스코드에서 빌드 중..."
echo ""

# 임시 디렉토리에서 빌드
temp_dir=$(mktemp -d)
cd "$temp_dir"

# Nuclei 저장소 클론
git clone https://github.com/projectdiscovery/nuclei.git
cd nuclei

# 바이너리 빌드
echo "   빌드 진행 중... (시간이 걸릴 수 있습니다)"
go build -o nuclei ./cmd/nuclei

# 빌드 성공 확인
if [ -f "nuclei" ]; then
    echo "✅ Nuclei 빌드 성공"
else
    echo "❌ Nuclei 빌드 실패"
    exit 1
fi
echo ""

# 4. 전역 PATH에 설치
echo "📍 Nuclei를 /usr/local/bin/ 에 설치 중..."
sudo mv nuclei /usr/local/bin/
echo "✅ Nuclei 설치 완료"
echo ""

# 5. 버전 확인
echo "📋 설치된 버전:"
nuclei -version

echo ""
echo "================================================"
echo "✅ 설치 완료!"
echo "================================================"
echo ""
echo "다음 명령어로 Nuclei를 사용할 수 있습니다:"
echo ""
echo "  nuclei -h                  # 도움말 표시"
echo "  nuclei -u <target>         # 대상 스캔"
echo "  nuclei -u <target> -json   # JSON 형식 출력"
echo ""

# 정리
cd /
rm -rf "$temp_dir"

