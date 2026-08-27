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

log_lines = read_log("sample_log.txt")
suspicious = detect_failed_logins(log_lines)
print("Suspicious IPs (brute-force):", suspicious)