import ctypes

# Load the shared library
lib = ctypes.CDLL("./c_modules/libscan.so")

def tcp_scan(ip: str, port: int):
    lib.tcp_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def udp_scan(ip: str, port: int):
    lib.udp_scan(ctypes.c_char_p(ip.encode("utf-8")), ctypes.c_int(port))

def scan_ports(ip: str, ports: list):
    results = {}
    # 문자열을 정수로 변환
    ports = [int(port) for port in ports]

    for port in ports:
        tcp_scan(ip, port)
        udp_scan(ip, port)
        results[port] = "Scanned"
    return results
