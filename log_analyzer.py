def read_log(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()
    return lines

log_lines = read_log("sample_log.txt")
print(f"Total lines: {len(log_lines)}")
print(log_lines[0])