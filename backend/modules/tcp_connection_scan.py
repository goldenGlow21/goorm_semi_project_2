# 양인규 로컬에서 테스트 함 추가 테스트 필요함
import socket
import sys
import time
from contextlib import closing


# connection 스캔 함수
def connection_scan(target, port):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(1)
            sock.connect((target, port))
            return port
    except Exception as e:
        pass
    finally:
        sock.close()
    time.sleep(0) # 속도 조절 시 사용할 것

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_connection_scan.py <target> <port1>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = int(sys.argv[2])

    port = connection_scan(target_ip, port)

    if port:
        print(f"포트 열림 : {port}")
    else:
        print("포트 닫힘")
