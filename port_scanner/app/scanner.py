import ctypes
import os

# C 모듈 로드
lib_path = os.path.join(os.path.dirname(__file__), "../c_modules/libscan.so")
lib = ctypes.CDLL(lib_path)

# 각 스캔 기법에 대한 함수 정의
def tcp_connect_scan(ip: str, port: int):
    result = lib.tcp_connect(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

def tcp_syn_scan(ip: str, port: int):
    result = lib.tcp_syn(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

def udp_scan(ip: str, port: int):
    result = lib.udp_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

def xmas_scan(ip: str, port: int):
    result = lib.xmas_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

def null_scan(ip: str, port: int):
    result = lib.null_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

def ack_scan(ip: str, port: int):
    result = lib.ack_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))
    return "open" if result == 1 else "closed"

# 스캔 포트 관리 함수
def scan_ports(ip: str, ports: range, scan_type: str):
    results = {}
    for port in ports:
        if scan_type == "tcp_connect":
            results[port] = tcp_connect_scan(ip, port)
        elif scan_type == "tcp_syn":
            results[port] = tcp_syn_scan(ip, port)
        elif scan_type == "udp":
            results[port] = udp_scan(ip, port)
        elif scan_type == "xmas":
            results[port] = xmas_scan(ip, port)
        elif scan_type == "null":
            results[port] = null_scan(ip, port)
        elif scan_type == "ack":
            results[port] = ack_scan(ip, port)
        else:
            results[port] = "unknown"
    return results
