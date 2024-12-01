# 양인규 로컬에서 테스트 함 추가 테스트 필요함
import socket
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from multiprocessing import Pool, cpu_count

LOCK = threading.Lock() # 뮤텍스 락
CPU_CORES = cpu_count()


# connection 스캔 함수
def connection_scan(target_ip, port):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(1)
            sock.connect((target_ip, port))
            return port
    except Exception as e:
        pass
    finally:
        sock.close()
    time.sleep(0) # 속도 조절 시 사용할 것

# 멀티스레드 단독으로 사용시
def multi_connection_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=cpu_count() * 2) as executor:
        results = list(executor.map(lambda port: connection_scan(target_ip, port), random_ports))
    open_ports = list(filter(None, results)) # 필터링된 포트
    open_ports.sort()
    return open_ports

# 멀티스레딩 작업자 함수
def thread_connection_worker_for_processing(args):
    target, ports = args
    open_ports = []
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        results = executor.map(lambda port: connection_scan(target, port), ports)
        open_ports.extend(filter(None, results))
    return open_ports

# 멀티프로세싱 + 멀티스레딩 스캔 함수
def hybrid_connection_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port + 1))
    random.shuffle(random_ports)

    # 멀티프로세싱: 포트 범위를 여러 그룹으로 분할
    num_processes = min(cpu_count(), len(random_ports))  # 프로세스 수는 최대 포트 수만큼
    chunk_size = max(1, len(random_ports) // num_processes)
    port_chunks = [random_ports[i:i + chunk_size] for i in range(0, len(random_ports), chunk_size)]

    args = [(target_ip, chunk) for chunk in port_chunks]

    # 멀티프로세싱 실행
    with Pool(processes=CPU_CORES) as pool:
        results = pool.map(thread_connection_worker_for_processing, args)

    # 결과 합치기
    open_ports = [port for sublist in results for port in sublist]
    open_ports.sort()
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_connection_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)
    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    start = time.time()
    open_ports = hybrid_connection_scan(target_ip, start_port, end_port)
    print(f"{time.time() - start:.5f}sec")
    if open_ports:
        print(f"포트 총 {len(open_ports)}개 열림 : {open_ports}")
    else:
        print("포트 닫힘")
