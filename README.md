# 📋 Log Analyzer

A Python security tool that scans server access logs for signs of attack — brute-force login attempts and SQL injection — and exports the findings into a clean, risk-scored PDF report.

![Python](https://img.shields.io/badge/Python-3.14-blue) ![PDF](https://img.shields.io/badge/Export-PDF-red) ![License](https://img.shields.io/badge/License-MIT-lightgrey)


<img width="500" alt="Screenshot 2026-08-27 170540" src="https://github.com/user-attachments/assets/ed29ae4e-8651-4f3e-8547-6762df5e90e2" />
<img width="500" alt="Screenshot 2026-08-27 165720" src="https://github.com/user-attachments/assets/2e9a4fb8-6855-4be2-abf6-53dfe06ec1b2" />



---

## 📖 What It Does

Server access logs record every request made to a web server — and attackers leave fingerprints in them. Manually scrolling through thousands of log lines to spot an attack is slow and error-prone. This tool automates that process.

1. **Reads** a server log file, line by line
2. **Detects brute-force attacks** — flags any IP address with repeated failed login attempts (HTTP 401 responses)
3. **Detects SQL injection attempts** — scans each request for known malicious patterns (`' OR`, `UNION SELECT`, `DROP TABLE`, etc.)
4. **Assigns a risk score** to each finding (Medium / High) based on severity
5. **Exports** everything into a polished PDF report — ready to share, archive, or hand off to a team

---

## ⚙️ How It Works

**Brute-force detection:** the tool counts failed login attempts (`401` status codes) per IP address. If a single IP crosses a threshold (default: 5 failures), it's flagged — 10+ failures are marked **High** risk, 5–9 are marked **Medium**. This mirrors how real intrusion detection systems catch password-guessing attacks: not by the content of any single request, but by the *pattern* across many.

**SQL injection detection:** the tool checks each log line against a list of known malicious text patterns commonly used to manipulate database queries (e.g. `' OR 1=1 --`, which attackers use to try to bypass login checks by making a query always evaluate as true). Any match is automatically flagged as **High** risk, since these patterns indicate a deliberate attack technique rather than ordinary traffic.

```
192.168.1.10 - "POST /login" 401   → normal, single failure
192.168.1.10 - "POST /login" 401   → 
192.168.1.10 - "POST /login" 401   → repeated 8x = Brute-force (High)

"GET /search?q=admin' OR 1=1 --"   → SQL Injection pattern (High)
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or later
- The `fpdf2` library for PDF generation (everything else — `os`, reading files — is built into Python)

### Installation

```bash
git clone https://github.com/ahaddilanov/log-analyzer.git
cd log-analyzer
pip install fpdf2
```

### Running the Tool

```bash
python log_analyzer.py
```

This will:
1. Read `sample_log.txt` (a generated test log with both normal and malicious traffic mixed in)
2. Run both detection functions
3. Print a summary to the console
4. Generate `security_report.pdf` in the project folder

To generate a fresh sample log to test against:
```bash
python generate_sample_log.py
```

---

## 🧠 Design Choices

- **Threshold-based brute-force detection:** rather than flagging a single failed login (which happens normally — people mistype passwords), the tool only raises an alert once an IP crosses a configurable threshold. This reduces false positives while still catching genuine attack patterns.
- **Pattern list for SQL injection:** a simplified but realistic version of what production tools use — checking for known malicious substrings is a common, effective first line of defense, even though sophisticated attackers can sometimes evade simple pattern matching.
- **Separating detection from reporting:** `detect_failed_logins()` and `detect_sql_injection()` each do one job and return raw data; `generate_report()` combines and scores that data separately. Keeping these responsibilities apart made each piece easier to test and debug independently.
- **PDF export over plain text:** a formatted PDF is more useful in a real workflow — something you could hand to a manager or attach to an incident ticket — than a wall of console output.

---

## 📚 What I Learned

- How brute-force and SQL injection attacks show up as recognizable patterns in raw log data
- Using dictionaries to count and aggregate data (failed attempts per IP)
- Nested loops, and using `break` to stop unnecessary work once a match is found
- Structuring findings as a list of dictionaries to represent multiple fields per record (type, detail, risk)
- Installing and using an external Python library (`fpdf2`) for the first time, beyond Python's built-in tools
- Generating a real PDF file programmatically — text, fonts, layout, and page structure

---

## 🔮 Possible Future Improvements

- [ ] Support parsing real Apache/Nginx log formats, not just the custom sample format
- [ ] Add detection for other attack patterns (XSS attempts, directory traversal, etc.)
- [ ] Make the failed-login threshold configurable via command-line argument
- [ ] Add timestamps and a summary chart to the PDF report
- [ ] Support scanning multiple log files at once

---

## 📄 License

MIT — free to use, modify, and learn from.

---

*Built as part of a personal cybersecurity portfolio project — written and understood line by line, not copy-pasted.*
