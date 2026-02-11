import streamlit as st
import subprocess
import os
import pandas as pd
import json
import re
from streamlit_option_menu import option_menu
import base64
from pathlib import Path
from docx import Document
from docx.shared import Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from datetime import datetime

BASE_DIR = Path(__file__).parent
IMAGES_DIR = BASE_DIR / "images"
CURRENT_DIR = BASE_DIR
def save_df_to_docx(df: pd.DataFrame, save_path, target_ip: str):
    doc = Document()

    style = doc.styles["Normal"]
    style.font.name = "NanumGothic"
    style._element.rPr.rFonts.set(qn("w:eastAsia"), "NanumGothic")
    style.font.size = Pt(10)

    title = doc.add_heading(
        f"{datetime.now().strftime('%Y-%m-%d')} 취약점 점검 결과",
        level=1
    )
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p = doc.add_paragraph(f"대상 서버 : {target_ip}")
    p.paragraph_format.space_after = Pt(12)

    table = doc.add_table(rows=1, cols=len(df.columns))
    table.style = "Table Grid"

    hdr_cells = table.rows[0].cells
    for i, col in enumerate(df.columns):
        hdr_cells[i].text = col

    for _, row in df.iterrows():
        row_cells = table.add_row().cells
        for i, value in enumerate(row):
            row_cells[i].text = str(value)

    doc.save(str(save_path))

def load_image_base64(path: Path) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()

RAPA_LOGO = load_image_base64(IMAGES_DIR / "rapa.png")
AUTOEVER_LOGO = load_image_base64(IMAGES_DIR / "hyundai_autoever.jpg")

# =========================================================
# Page Config
# =========================================================
st.set_page_config(
    page_title="Linux Security Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =========================================================
# Page State
# =========================================================
if "page" not in st.session_state:
    st.session_state.page = "main"

# =========================================================
# Global style
# =========================================================
st.markdown("""
<style>
/* =====================================================
   1. RESET / BASE LAYOUT
===================================================== */
html, body {
    height: 100%;
}

.block-container {
    display: flex;
    flex-direction: column;

    padding-top: 0;
    padding-left: 0;
    padding-right: 0;
    padding-bottom: 0 !important;
    margin-bottom: 0 !important;
}


/* =====================================================
   2. HERO WRAPPER (Full Width)
===================================================== */
.hero-wrapper {
    width: 100%;
    margin-left: 0;
}

/* =====================================================
   3. HERO BASE
===================================================== */
.hero {
    position: sticky;
    top: 0;

    height: 80vh;
    min-height: 420px;

    overflow: hidden;
    border-radius: 0;
    z-index: 10;

    transition:
        height 0.6s cubic-bezier(0.22, 1, 0.36, 1),
        transform 0.6s cubic-bezier(0.22, 1, 0.36, 1);
}

/* =====================================================
   4. HERO BACKGROUND
===================================================== */
.hero::before {
    content: "";
    position: absolute;
    inset: 0;

    background:
        linear-gradient(rgba(0,0,0,0.25), rgba(0,0,0,0.55)),
        url("https://images.unsplash.com/photo-1558494949-ef010cbdcc31")
        center / cover no-repeat;

    z-index: 0;

    transition: transform 0.6s cubic-bezier(0.22, 1, 0.36, 1);
}

/* =====================================================
   5. HERO CONTENT (CENTER TEXT)
===================================================== */
.hero-content {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);

    text-align: center;
    color: white;
    z-index: 1;

    transition:
        transform 0.6s cubic-bezier(0.22, 1, 0.36, 1),
        opacity 0.6s ease;
}

.hero-content h1 {
    font-size: 52px;
    margin: 0;
}

.hero-content p {
    margin-top: 6px;
    opacity: 0.85;
}

/* =====================================================
   6. HERO STATES
===================================================== */

/* 스크롤 or 사이드바 열림 */
.hero.shrink {
    height: 220px;
    transform: translateY(-6px);
}

.hero.shrink::before {
    transform: scale(1.05); /* subtle parallax */
}

.hero.shrink .hero-content {
    transform: translate(-50%, -55%);
    opacity: 0.95;
}

/* 사이드바 열림 시 텍스트 보정 */
.hero.sidebar-open .hero-content {
    transform: translate(calc(-50% + 160px), -50%);
}

/* =====================================================
   7. MAIN CONTENT SECTION
===================================================== */
.section {
    max-width: 1100px;
    margin: auto;
    padding: 80px 20px 120px;
}

/* =====================================================
   8. SIDEBAR STYLE
===================================================== */
section[data-testid="stSidebar"] {
    background-color: #f2f2f2;
}

/* option-menu */
.nav-link {
    margin: 6px 8px;
    padding: 10px 14px !important;

    font-size: 16px;
    color: #333 !important;
    border-radius: 14px !important;
}

.nav-link:hover {
    background-color: #e5e5e5 !important;
}

.nav-link.active,
.nav-link-selected {
    background-color: #dcdcdc !important;
    color: #000 !important;
    font-weight: 700 !important;
}

.nav-link i {
    font-size: 18px;
}

/* =====================================================
   9. SIDEBAR TOGGLE BUTTON
===================================================== */
button[data-testid="collapsedControl"] {
    display: flex !important;
    align-items: center;
    gap: 6px;

    padding: 6px 12px !important;
    border-radius: 20px;

    background-color: #f2f2f2;
    color: #444;
    font-weight: 600;
}

button[data-testid="collapsedControl"]::after {
    content: "menu";
    font-size: 14px;
    letter-spacing: 0.5px;
}

button[data-testid="collapsedControl"]:hover {
    background-color: #e0e0e0;
}
</style>

<style>
/* Streamlit 전체 레이아웃을 flex column으로 */
section[data-testid="stAppViewContainer"] {
    padding-bottom: 0 !important;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* 메인 콘텐츠 영역 */
section[data-testid="stAppViewContainer"] > .block-container {
    flex: 1;
}

section[data-testid="stMain"] {
    padding-bottom: 0 !important;
}
</style>


<style>
/* CHECK PAGE – 카드 스타일 */
.diagnosis-wrapper {
    display: flex;
    justify-content: center;
    margin-top: 0 !important;
}

.diagnosis-card {
    width: 100%;
    max-width: 720px;
    background-color: #f8f9fa;
    padding: 32px 36px;
    border-radius: 18px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
}

.diagnosis-title {
    text-align: center;
    font-weight: 700;
    margin-bottom: 8px;
}

.diagnosis-desc {
    text-align: center;
    opacity: 0.8;
    line-height: 1.6;
    margin-bottom: 28px;
}
</style>

/* ===============================
   RESULT WIDTH CONTROL
=============================== */
<style>
.result-wrapper {
    max-width: 1200px;
    margin: 0 auto;
}

.result-wrapper [data-testid="stStatus"],
.result-wrapper [data-testid="stAlert"] {
    width: 100% !important;
    max-width: 100% !important;
}
</style>

<style>
/* download_button를 텍스트 링크처럼 */
div[data-testid="stDownloadButton"] button {
    all: unset;                /* 버튼 스타일 제거 */
    cursor: pointer;
    color: #2563eb;            /* 링크 블루 */
    font-size: 15px;
}

div[data-testid="stDownloadButton"] button:hover {
    text-decoration: underline;
}
</style>

<script>
/* =====================================================
   HERO STATE CONTROLLER
===================================================== */
const updateHeroState = () => {
    const hero = document.querySelector(".hero");
    if (!hero) return;

    const sidebar = document.querySelector(
        'section[data-testid="stSidebar"]'
    );
    const sidebarOpen = sidebar && sidebar.offsetWidth > 100;

    if (window.scrollY > 160 || sidebarOpen) {
        hero.classList.add("shrink");
    } else {
        hero.classList.remove("shrink");
    }

    if (sidebarOpen) {
        hero.classList.add("sidebar-open");
    } else {
        hero.classList.remove("sidebar-open");
    }
};

window.addEventListener("scroll", updateHeroState);

const observer = new MutationObserver(updateHeroState);
observer.observe(document.body, {
    attributes: true,
    childList: true,
    subtree: true
});

const resetHero = () => {
  const hero = document.querySelector(".hero");
  if (!hero) return;
  hero.classList.remove("shrink");
  hero.classList.remove("sidebar-open");
};

// 메인 페이지 진입 시 강제 초기화
resetHero();

// Streamlit 렌더 타이밍 보정
setTimeout(resetHero, 200);

setTimeout(updateHeroState, 300);

</script>
""", unsafe_allow_html=True)


# =========================================================
# Sidebar Navigation
# =========================================================
with st.sidebar:
    selected = option_menu(
        menu_title=None,
        options=["main", "점검", "기록"],
        icons=["star-fill", "shield-check", "clock-history"],
        menu_icon="list",
        default_index=0,
        styles={
            "container": {"padding": "8px"},
            "icon": {"font-size": "18px"},
            "nav-link": {
                "font-size": "16px",
                "margin": "6px",
                "border-radius": "14px",
            },
            "nav-link-selected": {
                "background-color": "#dcdcdc",
                "color": "#000",
            },
        }
    )
    page_map = {
        "main": "main",
        "점검": "check",
        "기록": "history",
    }

    st.session_state.page = page_map[selected]

# =========================================================
# MAIN / CHECK PAGE ROUTING
# =========================================================
if st.session_state.page == "main":

    st.markdown("""
    <div class="hero-wrapper">
        <div class="hero">
            <div class="hero-content">
                <h1>WEB 이름</h1>
                <p>by 치약좋지</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="section">
        <h2>About Project</h2>
        <p>
            주요정보통신기반시설 기술적 취약점 분석 상세 가이드(2026)를 기반으로<br>
            여러 리눅스 서버의 보안 취약점 점검 자동화를 목표로 개발되었습니다.<br>
            여기에 파일 pdf 로 첨부할까 아님 kisa 페이지 링크 연결할까 <br><br>
            <ul>[ 주요 제공 서비스]
                <li>1.</li>
                <li>2.</li>
                <li>3.</li>
                <li>4.</li>
            </ul><br>
            추가적으로, CVE(Common Vulnerabiliteis and Exposurs) ~~~ 서비스도 제공합니다.<br>
            왜 진단가이드뿐만 아니라 CVE 추가했는지 그럴싸한 취지가 들어가면 좋을 것 같음 
        </p>
        <hr>
        <h2>About us</h2>
        <p>
            팀원 소개
            -> 뭐뭐 넣을건지 / 이름 이메일 사진(?)
        </p>
    </div>
    """, unsafe_allow_html=True)


elif st.session_state.page == "check":

    # ===============================
    # 배너
    # ===============================
    st.markdown("""
    <div style="
        width: 100%;
        overflow: hidden;
        box-shadow: 0 8px 24px rgba(0,0,0,0.08);
        margin-bottom: 32px;
    ">
        <img src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b"
             style="width:100%; height:220px; object-fit:cover;">
    </div>
    """, unsafe_allow_html=True)

    # ===============================
    # DIAGNOSIS CARD
    # ===============================
    st.markdown("""
    <div class="diagnosis-wrapper">
        <div class="diagnosis-card">
            <h3 class="diagnosis-title">⚙️ 진단 설정</h3>
            <div class="diagnosis-desc">
                대상 서버 정보를 입력하여 보안 점검을 실행합니다.<br>
                SSH 접속 정보를 입력하면 Ansible 기반 점검을 수행합니다.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)

    # ===============================
    # INPUT FORM (좁게 유지)
    # ===============================
    _, center, _ = st.columns([1, 3, 1])
    with center:
        target_ip = st.text_input("대상 서버 IP", placeholder="192.168.x.x")
        ssh_user = st.text_input("SSH 계정", value="")
        ssh_pw = st.text_input("SSH 비밀번호", type="password")

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        start_btn = st.button("🚀 진단 시작", use_container_width=True)

        if start_btn:
            st.session_state.pop("latest_result_ip", None)
            st.session_state.pop("latest_result_df", None)

    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
    st.divider()
    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)

    # ===============================
    # EXECUTE DIAGNOSIS
    # ===============================

    _, result_center, _ = st.columns([0.3, 6, 0.3])

    if start_btn:
        if not target_ip:
            st.error("IP 주소를 입력해주세요!")
        else:
            with result_center:
                with st.status(f"🌐 {target_ip} 진단 중...", expanded=True) as status:

                    inventory_path = CURRENT_DIR / "temp_inventory.ini"
                    playbook_path = CURRENT_DIR / "check_playbook.yml"

                    with open(inventory_path, "w", encoding="utf-8") as f:
                        f.write(
                            "[targets]\n"
                            f"{target_ip} ansible_user={ssh_user} "
                            f"ansible_password={ssh_pw}\n"
                        )

                    result = subprocess.run(
                        ["ansible-playbook", "-i", str(inventory_path), str(playbook_path)],
                        capture_output=True,
                        text=True
                    )

                    if result.returncode == 0:
                        status.update(label="✅ 진단 완료!", state="complete")
                        st.session_state["latest_result_ip"] = target_ip
                        st.balloons()
                        st.success(f"🎉 {target_ip} 서버 점검 성공!")
                    else:
                        status.update(label="❌ 진단 실패", state="error")
                        st.error("진단 실행 중 오류가 발생했습니다.")
                        st.code(result.stderr)


    # =====================================================
    # RESULT REPORT (넓게)
    # =====================================================
    if st.session_state.get("latest_result_ip"):
        recent_ip = st.session_state["latest_result_ip"]
        report_path = CURRENT_DIR / "reports" / f"{recent_ip}_result.txt"

        if report_path.exists():

            _, result_center, _ = st.columns([0.3, 6, 0.3])
            with result_center:

                st.markdown(
                    f"<h3>📊 {recent_ip} 진단 결과</h3>",
                    unsafe_allow_html=True
                )

                try:
                    parsed_results = []
                    with open(report_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("{") and line.endswith("}"):
                                data = json.loads(line)
                                parsed_results.append({
                                    "항목": data.get("item"),
                                    "상태": data.get("status"),
                                    "상세 사유": data.get("reason"),
                                })

                    if parsed_results:
                        df = pd.DataFrame(parsed_results)
                        st.session_state["latest_result_df"] = df
                        st.dataframe(
                            df.style.map(
                                lambda x: "color:red" if "취약" in x else "color:green",
                                subset=["상태"]
                            ),
                            use_container_width=True,
                            height=420
                        )
                        from datetime import datetime

                        HISTORY_DIR = CURRENT_DIR / "history"
                        HISTORY_DIR.mkdir(exist_ok=True)

                        st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)
                        
                        if st.button("📝 Word(.docx)로 보관함 저장"):
                            df = st.session_state["latest_result_df"]

                            date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
                            docx_path = HISTORY_DIR / f"{date_str}.docx"

                            save_df_to_docx(
                                df,
                                docx_path,
                                target_ip=st.session_state["latest_result_ip"]
                            )

                            st.success(f"📁 Word 파일이 보관함에 기록되었습니다: {docx_path.name}")

                            with open(str(docx_path), "rb") as f:
                                docx_bytes = f.read()

                            st.download_button(
                                label="⬇️ Word 다운로드",
                                data=docx_bytes,
                                file_name=docx_path.name,
                                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                            )
                        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)

                    else:
                        st.info("진단 결과가 존재하지 않습니다.")

                except Exception as e:
                    st.error(f"리포트 처리 중 오류 발생: {e}")



# =========================================================
# HISTORY PAGE
# =========================================================
elif st.session_state.page == "history":
    # ===============================
    # 배너
    # ===============================
    st.markdown("""
        <div style="
            width: 100%;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0,0,0,0.08);
            margin-bottom: 32px;
        ">
            <img src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b"
                style="width:100%; height:220px; object-fit:cover;">
        </div>
        """, unsafe_allow_html=True)
    
    # ===============================
    # DIAGNOSIS CARD
    # ===============================
    st.markdown("""
    <div class="diagnosis-wrapper">
        <div class="diagnosis-card">
            <h3 class="diagnosis-title">⚙️ 진단 결과</h3>
            <div class="diagnosis-desc">
                진단 결과를 출력합니다.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)

    _, center, _ = st.columns([1, 3, 1])

    with center:
        st.markdown(
            """
            <div style="
                font-size: 20px;
                font-weight: 500;
                margin-bottom: 12px;
            ">
                📂 진단 기록
            </div>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        HISTORY_DIR = CURRENT_DIR / "history"
        HISTORY_DIR.mkdir(exist_ok=True)

        files = sorted(HISTORY_DIR.glob("*.docx"), reverse=True)

        if not files:
            st.info("저장된 진단 기록이 없습니다.")
        else:
            for f in files:
                # 가로 칸 나누기 (파일명/다운로드 8 : 삭제 버튼 2)
                col_file, col_del = st.columns([8, 2])
                
                with col_file:
                    with open(f, "rb") as file_data:
                        st.download_button(
                            label=f"📄 {f.name}",
                            data=file_data,
                            file_name=f.name,
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            key=f"download_{f.name}",
                            use_container_width=True
                        )
                
                with col_del:
                    # 개별 삭제 버튼
                    if st.button("🗑️ 삭제", key=f"del_{f.name}", use_container_width=True):
                        import os
                        
                        # 1. history 폴더의 .docx 삭제
                        if f.exists():
                            f.unlink()
                        
                        # 2. reports 폴더의 연동된 .txt 삭제
                        # 파일명 규칙에 따라 매칭 (예: IP_result.docx -> IP_result.txt)
                        txt_filename = f.name.replace(".docx", ".txt")
                        txt_file = REPORTS_DIR / txt_filename
                        
                        if txt_file.exists():
                            txt_file.unlink()
                            st.success(f"{f.name} 및 리포트 삭제 완료")
                        else:
                            st.warning(f"워드 파일은 삭제되었으나, {txt_filename} 파일을 찾을 수 없습니다.")
                        
                        st.rerun() # 화면 새로고침
    # ===============================
    # FLEX SPACER (footer 밀어내기)
    # ===============================
    st.markdown(
        "<div style='flex:1'></div>",
        unsafe_allow_html=True
    )

# =========================================================
# footer
# =========================================================
st.markdown(f"""
<style>
.app-footer {{
    width: 100%;
    margin-top: auto;
    margin-bottom: 0 !important;
    padding: 12px 0;
    border-top: 1px solid #e5e5e5;
    background-color: #ffffff;
}}

.footer-inner {{
    max-width: 1100px;
    margin: auto;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 48px;
}}

.footer-inner img {{
    height: 48px;
    object-fit: contain;
    opacity: 0.9;
}}
</style>

<div class="app-footer">
    <div class="footer-inner">
        <img src="data:image/png;base64,{RAPA_LOGO}" alt="RAPA">
        <img src="data:image/png;base64,{AUTOEVER_LOGO}" alt="Hyundai AutoEver">
    </div>
</div>
""", unsafe_allow_html=True)
