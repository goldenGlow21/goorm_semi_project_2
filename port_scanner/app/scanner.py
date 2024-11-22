import ctypes
import os

# C 라이브러리 로드
lib_path = os.path.join(os.path.dirname(__file__), "../c_modules/libscan.so")
lib = ctypes.CDLL(lib_path)

# 각 스캔 기법을 독립적인 함수로 정의
def tcp_connect_scan(ip: str, port: int):
    lib.tcp_connect(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def tcp_syn_scan(ip: str, port: int):
    lib.tcp_syn(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def udp_scan(ip: str, port: int):
    lib.udp_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def xmas_scan(ip: str, port: int):
    lib.xmas_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def ack_scan(ip: str, port: int):
    lib.ack_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def null_scan(ip: str, port: int):
    lib.null_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

# scan_type에 따라 적절한 함수를 호출
def scan_ports(ip: str, ports: list, scan_type: str):
    results = {}

    for port in ports:
        if scan_type == "tcp_connect":
            tcp_connect_scan(ip, port)
        elif scan_type == "tcp_syn":
            tcp_syn_scan(ip, port)
        elif scan_type == "udp":
            udp_scan(ip, port)
        elif scan_type == "xmas":
            xmas_scan(ip, port)
        elif scan_type == "ack":
            ack_scan(ip, port)
        elif scan_type == "null":
            null_scan(ip, port)
        else:
            results[port] = "Unknown scan type"
            continue

        results[port] = f"{scan_type} scanned"
    return results
