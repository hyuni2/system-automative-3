import sys
import subprocess
import json
import shutil

def run_nuclei(target_ip):
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        raise RuntimeError("Nuclei not found in PATH")

    cmd = [
        nuclei_path,
        "-u", target_ip,
        "-json",
        "-silent",
        "-rate-limit", "50",
        "-timeout", "10"
    ]

    findings = []

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        ) as process:

            for line in process.stdout:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            process.wait()

            if process.returncode != 0:
                error_output = process.stderr.read()
                print("Nuclei error:", error_output)

        return findings

    except Exception as e:
        print("Execution failed:", str(e))
        return []

def map_severity(nuclei_severity):
    """
    뉴클리 심각도 -> 대시보드 심각도로 매핑(상,중,하)
    """
    s = nuclei_severity.lower()
    if s in ["critical", "high"]:
        return "상"
    elif s in ["medium"]:
        return "중"
    else:
        # low, info, unknown
        return "하"

def main():
    if len(sys.argv) < 2:
        print("Usage: python nuclei_check.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    nuclei_results = run_nuclei(target_ip)

    if not nuclei_results:
        print("[Nuclei] 취약점이 발견되지 않았습니다.")
        return

    for res in nuclei_results:
        template_id = res.get("template-id", "NUCLEI-UNKNOWN")
        info = res.get("info", {})
        name = info.get("name", template_id)

        severity_raw = info.get("severity", "info")
        severity = map_severity(severity_raw)

        matcher_name = res.get("matcher-name", "")

        classification = info.get("classification", {})
        cve_list = classification.get("cve-id", [])
        cvss_score = classification.get("cvss-score", "N/A")

        # CVE 우선 사용
        if cve_list:
            code = cve_list[0]
        else:
            code = f"NUC-{template_id.upper()}"

        reason = f"Nuclei Detection: {name}"
        if matcher_name:
            reason += f" ({matcher_name})"

        output = {
            "code": code,
            "item": name,
            "severity": severity,
            "severity_raw": severity_raw,
            "cvss_score": cvss_score,
            "status": "취약",
            "reason": reason
        }

        print(json.dumps(output, ensure_ascii=False))

if __name__ == "__main__":
    main()
