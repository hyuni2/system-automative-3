import streamlit as st
import subprocess
import os
import pandas as pd
import json
import re
import io
import sys
import shlex
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
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.utils import get_column_letter

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "src" / "dashboard_0210"

# Ensure dashboard modules are importable when running from repo root
if str(DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(DASHBOARD_DIR))

from scripts.nuclei_check import run_nuclei, map_severity

REPORTS_DIR = DASHBOARD_DIR / "reports"
HISTORY_DIR = DASHBOARD_DIR / "history"
IMAGES_DIR = DASHBOARD_DIR / "images"
SCRIPTS_DIR = DASHBOARD_DIR / "scripts"
CURRENT_DIR = DASHBOARD_DIR
CSS_PATH = DASHBOARD_DIR / "styles.css"
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
NUCLEI_TEMPLATES_DIR = DASHBOARD_DIR / "nuclei-templates"

# --------------------추가
def load_local_css():
    if CSS_PATH.exists():
        css_text = CSS_PATH.read_text(encoding="utf-8")
        st.markdown(f"<style>{css_text}</style>", unsafe_allow_html=True)


def load_template(name: str) -> str:
    path = TEMPLATES_DIR / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")

def cleanup_reports():
    import shutil
    report_dir = CURRENT_DIR / "reports"
    if report_dir.exists():
        for f in report_dir.glob("*_result.txt"):
            try:
                f.unlink()
            except:
                pass
#--------------------------
def run_nuclei_from_dashboard(target_ip):
    results = []
    script_path = SCRIPTS_DIR / "nuclei_check.py"
    try:
        process = subprocess.Popen(
            ["python3", str(script_path), target_ip, str(NUCLEI_TEMPLATES_DIR)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in process.stdout:
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        process.wait()

    except Exception as e:
        print("Nuclei 실행 실패:", str(e))

    return results

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

st.set_page_config(
    page_title="Linux Security Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

if "page" not in st.session_state:
    st.session_state.page = "main"
load_local_css()

st.markdown(
    """
<script>
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

resetHero();

setTimeout(resetHero, 200);

setTimeout(updateHeroState, 300);

</script>
""",
    unsafe_allow_html=True,
)


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
     #--------------추가
    cleanup_reports()
    #------------------
    st.markdown(load_template("main.html"), unsafe_allow_html=True)
    
elif st.session_state.page == "check":

    # ===============================
    # 배너
    # ===============================
    st.markdown(load_template("check_intro.html"), unsafe_allow_html=True)

    st.markdown("<div style='height:80px'></div>", unsafe_allow_html=True)

    # ===============================
    # INPUT FORM (탭 적용: 개별 입력 vs CSV 업로드)
    # ===============================
    _, center, _ = st.columns([1, 3, 1])
    with center:
        # 탭 디자인 생성
        tab1, tab2 = st.tabs(["🎯 개별 서버 진단 (OS + Nuclei)", "📁 다중 서버 진단 (OS + Nuclei)"])
        with tab1:
            target_ip = st.text_input("대상 서버 IP", placeholder="192.168.x.x", key="single_ip")
            ssh_user = st.text_input("SSH 계정", value="", key="single_user")
            ssh_pw = st.text_input("SSH 비밀번호", type="password", key="single_pw")
            uploaded_file = None # 탭1일 때는 업로드 파일 무시
            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            start_single_btn = st.button("🚀 통합 진단 시작 (OS + Nuclei)", use_container_width=True, key="start_single")

        with tab2:
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            uploaded_file = st.file_uploader("서버 목록 CSV 업로드 (필수: ip, user, pw)", type=["csv"], key="bulk_upload")
            if uploaded_file:
                try:
                    df_targets = pd.read_csv(uploaded_file, encoding='utf-8-sig')
                    st.dataframe(df_targets, use_container_width=True, height=150)
                except Exception as e:
                    st.error(f"CSV 읽기 실패: {e}")
            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            start_bulk_btn = st.button("🚀 통합 진단 시작 (OS + Nuclei)", use_container_width=True, key="start_bulk")

    # 버튼 클릭 시 세션 초기화
    if 'start_single_btn' in locals() and start_single_btn:
        st.session_state.pop("latest_result_ip", None)
        st.session_state.pop("latest_result_df", None)
    if 'start_bulk_btn' in locals() and start_bulk_btn:
        st.session_state.pop("latest_result_ip", None)
        st.session_state.pop("latest_result_df", None)

    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
    st.divider()

    # ===============================
    # EXECUTE DIAGNOSIS (통합 처리 로직)
    # ===============================
    _, result_center, _ = st.columns([0.3, 6, 0.3])

    # 버튼 클릭 여부 확인
    start_triggered = False
    if 'start_single_btn' in locals() and start_single_btn:
        start_triggered = True
        is_single = True
    elif 'start_bulk_btn' in locals() and start_bulk_btn:
        start_triggered = True
        is_single = False

    if start_triggered:
        inventory_path = CURRENT_DIR / "temp_inventory.ini"
        playbook_path = CURRENT_DIR / "check_playbook.yml"
        
        # 1. 대상 확인 및 인벤토리 생성
        valid_target = False
        with open(inventory_path, "w", encoding="utf-8") as f:
            f.write("[targets]\n")
            
            # CSV 파일이 업로드된 경우 (탭2)
            if not is_single and uploaded_file is not None:
                for _, row in df_targets.iterrows():
                    f.write(f"{row['ip']} ansible_user={row['user']} ansible_password={row['pw']} ansible_become_password={row['pw']}\n")
                display_msg = "다중 서버"
                valid_target = True
            
            # 개별 IP가 입력된 경우 (탭1)
            elif is_single and target_ip:
                f.write(f"{target_ip} ansible_user={ssh_user} ansible_password={ssh_pw} ansible_become_password={ssh_pw}\n")
                display_msg = target_ip
                valid_target = True

        if not valid_target:
            st.error("진단 대상을 입력하거나 CSV 파일을 업로드해주세요!")
        else:
            with result_center:
                with st.status(f"🌐 {display_msg} 통합 진단 중 (OS + Nuclei)...", expanded=True) as status:
                    cmd = ["ansible-playbook", "-i", str(inventory_path), str(playbook_path)]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True
                    )

                    if result.returncode == 0:
                        status.update(label="✅ 통합 진단 완료!", state="complete")
                        # 단일 진단일 경우 바로 결과 세션 저장
                        if is_single:
                            st.session_state["latest_result_ip"] = target_ip
                        st.balloons()
                        st.success(f"🎉 {display_msg} 통합 점검 성공!")
                    else:
                        status.update(label="❌ 진단 실패", state="error")
                        st.error("진단 실행 중 오류가 발생했습니다.")
                        st.write(f"Return code: `{result.returncode}`")
                        st.write("실행 명령어:")
                        st.code(" ".join(shlex.quote(part) for part in cmd), language="bash")

                        with st.expander("진단 디버그 로그 보기", expanded=True):
                            st.write("Inventory 내용:")
                            try:
                                st.code(inventory_path.read_text(encoding="utf-8"))
                            except Exception:
                                st.code("(inventory 파일을 읽을 수 없습니다.)")

                            st.write("STDOUT:")
                            st.code(result.stdout if result.stdout.strip() else "(비어 있음)")
                            st.write("STDERR:")
                            st.code(result.stderr if result.stderr.strip() else "(비어 있음)")

    # =====================================================
    # RESULT REPORT (넓게)
    # =====================================================
    report_dir = CURRENT_DIR / "reports"

    # 1. 진단 결과 파일 목록 확인
    if report_dir.exists():
        report_files = sorted([f.name for f in report_dir.glob("*_result.txt")])

        if report_files:
            _, result_center, _ = st.columns([0.3, 6, 0.3])
            with result_center:
                st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
                st.markdown("### 📋 진단 결과 리포트 선택")

                # 여러 대 진단 시 선택할 수 있는 드롭다운 메뉴
                selected_file = st.selectbox(
                    "결과를 확인할 서버를 선택하세요",
                    report_files,
                    index=0,
                    help="점검이 완료된 서버의 IP 목록입니다."
                )
                st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
                # 선택된 파일에서 IP 추출하여 세션에 저장 (기존 로직과 연동)
                recent_ip = selected_file.replace("_result.txt", "")
                st.session_state["latest_result_ip"] = recent_ip
                report_path = report_dir / selected_file

                # --- 여기서부터 기존 리포트 출력 및 저장 로직 ---
                st.markdown(
                    f"<h3>📊 {recent_ip} 진단 결과</h3>",
                    unsafe_allow_html=True
                )

                try:
                    parsed_results = []
                    nuclei_findings = []
                    nuclei_scan_meta = []

                    with open(report_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            # JSON 형태만 파싱
                            if line.startswith("{") and line.endswith("}"):
                                data = json.loads(line)
                                source = data.get("source", "")
                                record_type = data.get("record_type", "")

                                if source == "nuclei" and record_type == "scan_meta":
                                    nuclei_scan_meta.append(data)
                                    continue

                                code = data.get("code", "")
                                is_nuclei = (
                                    source == "nuclei"
                                    or str(code).startswith("NUC-")
                                    or str(code).startswith("CVE-")
                                )

                                parsed_row = {
                                    "분류": "Nuclei" if is_nuclei else "OS",
                                    "코드": data.get("code"),
                                    "중요도": data.get("severity"),
                                    "항목": data.get("item"),
                                    "상태": data.get("status"),
                                    "상세 사유": data.get("reason"),
                                    "템플릿ID": data.get("template_id", "-") if is_nuclei else "-",
                                }
                                parsed_results.append(parsed_row)
                                if is_nuclei:
                                    nuclei_findings.append(parsed_row)

                    if parsed_results:
                        df = pd.DataFrame(parsed_results)
                        df = df[["분류", "코드", "중요도", "항목", "상태", "상세 사유", "템플릿ID"]]

                        df = df[df["코드"].notna()]

                        df["STATUS_ORDER"] = df["상태"].apply(
                            lambda x: 0 if "취약" in str(x) else 1
                        )

                        # 취약 우선 + OS 먼저 + U- 계열 순서 정렬
                        df["U_NUM"] = df["코드"].str.extract(r'U-(\d+)')
                        df["U_NUM"] = pd.to_numeric(df["U_NUM"], errors="coerce").fillna(9999)
                        df["TYPE_ORDER"] = df["분류"].apply(lambda x: 0 if str(x) == "OS" else 1)

                        df = df.sort_values(
                            by=["STATUS_ORDER", "TYPE_ORDER", "U_NUM"],
                            ascending=[True, True, True]
                        )

                        df = df.drop(columns=["STATUS_ORDER", "U_NUM", "TYPE_ORDER"])
                        df = df.reset_index(drop=True)

                        st.session_state["latest_result_df"] = df

                        if nuclei_scan_meta:
                            st.markdown("#### 🧪 Nuclei 템플릿 실행 결과")
                            meta_templates_dir = next(
                                (m.get("templates_dir") for m in nuclei_scan_meta if m.get("templates_dir")),
                                str(NUCLEI_TEMPLATES_DIR)
                            )
                            meta_templates_count = next(
                                (m.get("templates_count") for m in nuclei_scan_meta if m.get("templates_count") is not None),
                                0
                            )
                            meta_duration = next(
                                (m.get("duration_sec") for m in reversed(nuclei_scan_meta) if m.get("duration_sec") is not None),
                                None
                            )
                            detected_count = len(nuclei_findings)
                            scan_errors = [
                                m for m in nuclei_scan_meta
                                if str(m.get("status")) == "점검불가" or str(m.get("code", "")).startswith("NUC-ERR")
                            ]

                            st.caption(
                                f"템플릿 경로: `{meta_templates_dir}` | "
                                f"템플릿 수: `{meta_templates_count}` | "
                                f"탐지 건수: `{detected_count}`"
                                + (f" | 실행 시간: `{meta_duration}초`" if meta_duration is not None else "")
                            )

                            if scan_errors:
                                last_err = scan_errors[-1]
                                st.error(f"Nuclei 실행 상태: 점검불가 ({last_err.get('reason', '원인 불명')})")
                            elif nuclei_findings:
                                nuclei_df = pd.DataFrame(nuclei_findings)[["코드", "항목", "템플릿ID", "중요도", "상태"]]
                                st.dataframe(nuclei_df, use_container_width=True, height=220)
                            else:
                                st.info("Nuclei 템플릿 실행은 완료되었고 탐지된 취약점은 없습니다.")

                            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

                        def highlight_vulnerable(row):
                            if "취약" in str(row["상태"]):
                                return ["background-color: #ffe6e1"] * len(row)
                            return [""] * len(row)

                        st.dataframe(
                            df.style
                                .apply(highlight_vulnerable, axis=1)   # 행 배경
                                .map(
                                    lambda x: "color:red; font-weight:bold;"
                                    if "취약" in str(x)
                                    else ("color:#8a6d3b; font-weight:bold;" if "점검불가" in str(x) else "color:green;"),
                                    subset=["상태"])
                                .map(lambda x: "color:red;" if x == "상" else "color:orange;",
                                    subset=["중요도"]),
                            use_container_width=True,
                            height=420
                        )

                        st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)
                        if st.button(f"📊 {recent_ip} 결과 Excel로 보관함 저장"):

                            HISTORY_DIR = CURRENT_DIR / "history"
                            HISTORY_DIR.mkdir(exist_ok=True)

                            date_str = datetime.now().strftime("%Y-%m-%d")
                            file_time = datetime.now().strftime("%Y-%m-%d_%H%M%S")

                            excel_path = HISTORY_DIR / f"{recent_ip}_{file_time}.xlsx"

                            wb = Workbook()
                            ws = wb.active
                            ws.title = "Diagnosis Result"

                            col_count = len(df.columns)
                            last_col_letter = get_column_letter(col_count)

                            ws.merge_cells(f"A1:{last_col_letter}1")
                            ws["A1"] = f"{date_str} 취약점 점검 결과"
                            ws["A1"].font = Font(size=16, bold=True)
                            ws["A1"].alignment = Alignment(horizontal="center")

                            ws.merge_cells(f"A2:{last_col_letter}2")
                            ws["A2"] = f"대상 서버 : {recent_ip}"
                            ws["A2"].font = Font(size=12, bold=True)
                            ws["A2"].alignment = Alignment(horizontal="center")

                            start_row = 4

                            for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start_row):
                                for c_idx, value in enumerate(row, 1):
                                    ws.cell(row=r_idx, column=c_idx, value=value)

                            vuln_fill = PatternFill(start_color="FFE6E1", end_color="FFE6E1", fill_type="solid")
                            red_font = Font(color="FF0000", bold=True)
                            green_font = Font(color="008000")
                            orange_font = Font(color="FF8C00")
                            brown_font = Font(color="8A6D3B", bold=True)

                            from openpyxl.styles import Border, Side

                            thin = Side(style="thin")
                            border = Border(left=thin, right=thin, top=thin, bottom=thin)
                            status_col_idx = df.columns.get_loc("상태")
                            severity_col_idx = df.columns.get_loc("중요도")

                            for row in ws.iter_rows(min_row=start_row+1, max_row=ws.max_row):
                                status_cell = row[status_col_idx]
                                severity_cell = row[severity_col_idx]

                                # 모든 셀에 동일한 border 적용
                                for cell in row:
                                    cell.border = border

                                if status_cell.value == "취약":
                                    for cell in row:
                                        cell.fill = vuln_fill
                                    status_cell.font = red_font

                                elif status_cell.value == "양호":
                                    status_cell.font = green_font
                                elif status_cell.value == "점검불가":
                                    status_cell.font = brown_font

                                if severity_cell.value == "상":
                                    severity_cell.font = red_font
                                elif severity_cell.value == "중":
                                    severity_cell.font = orange_font

                            from openpyxl.utils import get_column_letter

                            for col_idx in range(1, ws.max_column + 1):
                                ws.column_dimensions[get_column_letter(col_idx)].width = 22

                            wb.save(excel_path)

                            st.success(f"📁 {recent_ip} Excel 리포트가 저장되었습니다.")

                            with open(excel_path, "rb") as f:
                                st.download_button(
                                    label="⬇️ Excel 다운로드",
                                    data=f.read(),
                                    file_name=excel_path.name,
                                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                )

                    else:
                        st.info(f"{recent_ip} 서버의 상세 진단 결과가 비어있습니다.")

                except Exception as e:
                    st.error(f"리포트 처리 중 오류 발생: {e}") 

# =========================================================
# HISTORY PAGE
# =========================================================
elif st.session_state.page == "history":
    cleanup_reports()
    
    # ===============================
    # 배너
    # ===============================
    st.markdown(load_template("history_intro.html"), unsafe_allow_html=True)
    st.markdown("<div style='height:80px'></div>", unsafe_allow_html=True)

    _, center, _ = st.columns([1, 3, 1])

    with center:
        st.markdown("#### 📂 보관함")
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        HISTORY_DIR = CURRENT_DIR / "history"
        HISTORY_DIR.mkdir(exist_ok=True)

        files = sorted(HISTORY_DIR.glob("*.xlsx"), reverse=True)

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
                    if st.button("삭제", key=f"del_{f.name}", use_container_width=True):

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
<div class="app-footer">
    <div class="footer-inner">
        <img src="data:image/png;base64,{RAPA_LOGO}" alt="RAPA">
        <img src="data:image/png;base64,{AUTOEVER_LOGO}" alt="Hyundai AutoEver">
    </div>
</div>
""", unsafe_allow_html=True)
