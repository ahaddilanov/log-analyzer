from fpdf import FPDF

def read_log(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()
    return lines

def detect_failed_logins(log_lines, threshold=5):
    failed_attempts = {}

    for line in log_lines:
        if "401" in line: #401 indicates that this is unauthorized
            ip = line.split(" ")[0]
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    suspicious_ips = {}
    for ip in failed_attempts:
        if failed_attempts[ip] >= threshold:
            suspicious_ips[ip] = failed_attempts[ip]

    return suspicious_ips

def detect_sql_injection(log_lines):
    suspicious_patterns= ["' OR", "--",";","UNION SELECT","DROP TABLE","OR 1=1"]  #there are some other patterns too
    flagged_lines = []
    for line in log_lines:
        for pattern in suspicious_patterns:
            if pattern in line:
                flagged_lines.append(line.strip())
                break

    return flagged_lines

def generate_report(log_lines):
    report = []

    brute_force_results = detect_failed_logins(log_lines)
    for ip, count in brute_force_results.items():
        if count >= 10:
            risk = "High"
        else:
            risk = "Medium"
        report.append({
            "type": "Brute-force login attempt",
            "detail": f"{ip} failed login {count} times",
            "risk": risk
        })

    sql_results = detect_sql_injection(log_lines)
    for line in sql_results:
        report.append({
            "type": "SQL Injection Attempt",
            "detail": line,
            "risk": "High"
        })

    return report

def export_to_pdf(report, output_file="security_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica","B",16)
    pdf.cell(0,10,"Security Alert Report",ln=True,align="C")
    pdf.ln(10)

    pdf.set_font("Helvetica","",11)
    for alert in report:
        text = f"[{alert['risk']}] {alert['type']}: {alert['detail']}"
        pdf.multi_cell(0,8,text)
        pdf.ln(2)


    pdf.output(output_file)
    print(f"PDF report saved as {output_file}")

log_lines = read_log("sample_log.txt")
report = generate_report(log_lines)
export_to_pdf(report)
