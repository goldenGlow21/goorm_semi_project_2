import ctypes
import os

# C 모듈 로드
lib_path = os.path.join(os.path.dirname(__file__), "../c_modules/libscan.so")
lib = ctypes.CDLL(lib_path)

# 공통 스캔 함수
def scan_port_with_c_module(scan_function_name: str, ip: str, port: int):
    scan_function = getattr(lib, scan_function_name, None)
    if not scan_function:
        raise ValueError(f"Scan function {scan_function_name} not found in C module")
    
    result = scan_function(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return result

# 포트 스캔 함수
def scan_ports(ip: str, ports: range, scan_type: str):
    open_ports = []
    open_or_filtered_ports = []
    
    # 스캔 함수 이름 맵핑
    scan_function_map = {
        "tcp_connect": "tcp_connect",
        "tcp_syn": "tcp_syn",
        "udp": "udp_scan",
        "xmas": "xmas_scan",
        "null": "null_scan",
        "ack": "ack_scan",
    }
    scan_function_name = scan_function_map.get(scan_type)
    if not scan_function_name:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    for port in ports:
        try:
            status = scan_port_with_c_module(scan_function_name, ip, port)
            if status == 1:
                open_ports.append(port)
            elif status == 2:  # open|filtered 상태
                open_or_filtered_ports.append(port)
        except Exception as e:
            continue  # 에러가 발생한 경우 해당 포트는 무시하고 다음으로 진행

    return open_ports, open_or_filtered_ports