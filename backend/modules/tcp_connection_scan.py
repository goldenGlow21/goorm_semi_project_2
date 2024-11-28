# 양인규 로컬에서 테스트 함 추가 테스트 필요함
import socket
import sys
import time
import random
import os
from concurrent.futures import ThreadPoolExecutor
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

def multi_connection_scan(target, start_port, end_port):
    start = time.time()
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        results = list(executor.map(lambda port: connection_scan(target, port), random_ports))
    open_ports = list(filter(None, results)) # 필터링된 포트
    open_ports.sort()
    end = time.time()
    print(f"{end - start:.5f} sec")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_connection_scan.py <target> <start_port> <end_port>")
        sys.exit(1)
    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    ports = multi_connection_scan(target_ip, start_port, end_port)
    if ports:
        print(f"포트 열림 : {ports}")
    else:
        print("포트 닫힘")
