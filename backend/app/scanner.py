import os
import subprocess
import json

# C 모듈 실행 함수
def execute_c_scan(scan_type: str, ip: str, start_port: int, end_port: int):
    # C 모듈 바이너리 경로
    binary_path = os.path.join(os.path.dirname(__file__), f"../c_modules/{scan_type}_scan")
    try:
        result = subprocess.run(
            [binary_path, ip, str(start_port), str(end_port)],
            capture_output=True,
            text=True,
            check=True,
        )
        # JSON 결과 파싱
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error executing {scan_type}_scan: {e.stderr}")

# 스캔 수행 함수
def scan_ports(ip: str, start_port: int, end_port: int, scan_type: str):
    return execute_c_scan(scan_type, ip, start_port, end_port)
