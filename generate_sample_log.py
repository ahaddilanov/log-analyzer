import random

ips = ["192.168.1.10", "192.168.1.25", "10.0.0.5", "203.0.113.7"]
normal_requests = [
    'GET /home HTTP/1.1',
    'GET /about HTTP/1.1',
    'POST /login HTTP/1.1',
    'GET /images/logo.png HTTP/1.1'
]

lines = []

for i in range(30):
    ip = random.choice(ips)
    request = random.choice(normal_requests)
    status = 200
    lines.append(f'{ip} - - [21/Aug/2026:10:15:{i:02d}] "{request}" {status}')

# Simulate a brute-force attack: one IP failing login many times
attacker_ip = "45.33.32.156"
for i in range(8):
    lines.append(f'{attacker_ip} - - [21/Aug/2026:10:16:{i:02d}] "POST /login HTTP/1.1" 401')

# Simulate a SQL injection attempt
lines.append(f'{attacker_ip} - - [21/Aug/2026:10:17:00] "GET /search?q=admin\' OR 1=1 -- HTTP/1.1" 200')

with open("sample_log.txt", "w") as f:
    for line in lines:
        f.write(line + "\n")

print("Sample log created!")