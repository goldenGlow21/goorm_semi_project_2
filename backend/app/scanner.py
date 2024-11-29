from modules.tcp_ack_scan import hybrid_ack_scan
from modules.tcp_connection_scan import hybrid_connection_scan
from modules.tcp_syn_scan import hybrid_syn_scan
from modules.tcp_stealth_scan import hybrid_stealth_scan
from modules.udp_scan import hybrid_udp_scan
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 스캔 수행 함수 매핑
SCAN_FUNCTIONS = {
    "tcp_connect": hybrid_connection_scan,
    "tcp_syn": hybrid_syn_scan,
    "tcp_fin": hybrid_stealth_scan,
    "udp": hybrid_udp_scan,
    "xmas": hybrid_stealth_scan,
    "null": hybrid_stealth_scan,
    "ack": hybrid_ack_scan,
}

def scan_ports(ip: str, start_port: int, end_port: int, scan_type: str):
    """
    포트 스캔 수행
    """
    if scan_type not in SCAN_FUNCTIONS:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    
    scan_function = SCAN_FUNCTIONS[scan_type]
    try:
        if scan_type == "tcp_fin":
            results = scan_function("F", ip, start_port, end_port)
        elif scan_type == "xmas":
            results = scan_function("X", ip, start_port, end_port)
        elif scan_type == "null":
            results = scan_function("N", ip, start_port, end_port)
        else :
            results = scan_function(ip, start_port, end_port)
        # 리스트를 딕셔너리로 변환
        if isinstance(results, list):
            return {
                "open_ports": results,  # 열린 포트 리스트
                "total_ports_scanned": len(results)  # 스캔된 포트 개수
            }
        else:
            # 예외적인 반환값 처리
            raise RuntimeError("Unexpected result format from scan function")
    except Exception as e:
        raise RuntimeError(f"Scanning failed: {str(e)}")
