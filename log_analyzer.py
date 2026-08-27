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

log_lines = read_log("sample_log.txt")
sql_injections = detect_sql_injection(log_lines)
print("Possible SQL Injection attempts:")
for line in sql_injections:
    print(" -", line)