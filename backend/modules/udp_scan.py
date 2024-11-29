import os, sys
import time
import random
import threading

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, cpu_count
from scapy.all import sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, UDP, ICMP
from common import get_available_port

LOCK = threading.Lock() # 뮤텍스 락
CPU_CORES = cpu_count()

# UDP 스캔 함수
def udp_scan(target_ip, port):
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    with LOCK:
        random_port = get_available_port()
    # UDP 패킷 생성
    packet = IP(dst=target_ip) / UDP(sport=random_port, dport=port) # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)

    if response is None:  # 응답x == 열려 있거나 필터링 됨
        return port
    elif response.haslayer(ICMP) and response[ICMP].type == 3: # 응답o == 닫혀잇음
        pass
    time.sleep(0) # 속도 조절 시 사용할 것

# 멀티스레드 단독으로 사용시
def multi_udp_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    time.sleep(1)
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=CPU_CORES * 2) as executor:
        results = list(executor.map(lambda port: udp_scan(target_ip, port), random_ports))
    open_or_fiterd_ports = list(filter(None, results)) # 필터링된 포트
    open_or_fiterd_ports.sort()
    return open_or_fiterd_ports

# 멀티스레딩 작업자 함수
def thread_udp_worker_for_processing(args):
    target, ports = args
    open_or_fiterd_ports = []
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        results = executor.map(lambda port: udp_scan(target, port), ports)
        open_or_fiterd_ports.extend(filter(None, results))
    return open_or_fiterd_ports

# 멀티프로세싱 + 멀티스레딩 스캔 함수
def hybrid_udp_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port + 1))
    random.shuffle(random_ports)

    # 멀티프로세싱: 포트 범위를 여러 그룹으로 분할
    num_processes = cpu_count()
    chunk_size = len(random_ports) // num_processes
    port_chunks = [random_ports[i:i + chunk_size] for i in range(0, len(random_ports), chunk_size)]

    args = [(target_ip, chunk) for chunk in port_chunks]

    # 멀티프로세싱 실행
    with Pool(processes=CPU_CORES) as pool:
        results = pool.map(thread_udp_worker_for_processing, args)

    # 결과 합치기
    open_or_fiterd_ports = [port for sublist in results for port in sublist]
    open_or_fiterd_ports.sort()
    return open_or_fiterd_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python udp_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    start = time.time()
    open_or_fiterd_ports = hybrid_udp_scan(target_ip, start_port, end_port)
    print(f"{time.time() - start:.5f}sec")
    if open_or_fiterd_ports:
        print(f"포트 총 {len(open_or_fiterd_ports)}개 열려 있거나 필터링 됨 : {open_or_fiterd_ports}")
    else:
        print("포트 닫힘")
