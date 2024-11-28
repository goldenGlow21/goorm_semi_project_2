from modules.tcp_ack_scan import ack_scan
from modules.tcp_connection_scan import connection_scan
from modules.tcp_half_scan import syn_scan
from modules.tcp_stealth_scan import stealth_scan
from modules.udp_scan import udp_scan

# 스캔 수행 함수 매핑
SCAN_FUNCTIONS = {
    "tcp_connect": connection_scan,
    "tcp_syn": syn_scan,
    "udp": udp_scan,
    "xmas": stealth_scan,
    "null": stealth_scan,
    "ack": ack_scan,
}

def scan_ports(ip: str, start_port: int, end_port: int, scan_type: str):
    """
    포트 스캔 수행
    """
    if scan_type not in SCAN_FUNCTIONS:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    
    scan_function = SCAN_FUNCTIONS[scan_type]
    try:
        results = scan_function(ip, start_port, end_port, scan_type)
        return {
            "open": results.get("open", []),
            "open_or_filtered": results.get("open_or_filtered", []),
        }
    except Exception as e:
        raise RuntimeError(f"Scanning failed: {str(e)}")
