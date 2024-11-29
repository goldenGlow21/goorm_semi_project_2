import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, cpu_count
from scapy.all import sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP
from .common import get_port

LOCK = threading.Lock() # 뮤텍스 락
CPU_CORES = cpu_count()

# FIN null xmas 스캔 함수
def stealth_scan(flag, target, port):
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    with LOCK:
        random_port = get_port()
    # stealth 패킷 생성
    if flag == "F":
        packet = IP(dst=target) / TCP(sport=random_port, dport=port, flags="F") # / ip와 tcp를 묶는 연산자
    elif flag == "N":
        packet = IP(dst=target) / TCP(sport=random_port, dport=port, flags="")
    elif flag == "X":
        packet = IP(dst=target) / TCP(sport=random_port, dport=port, flags="FPU")
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)
    if response is None:  # 응답x == 포트 열림
        return port
    time.sleep(0) # 속도 조절 시 사용할 것

# 멀티스레딩 단독 작업 시
def multi_stealth_scan(flag, target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    time.sleep(1)
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=CPU_CORES * 2) as executor:
        results = list(executor.map(lambda port: stealth_scan(flag, target_ip, port), random_ports))
    open_or_fiterd_ports = list(filter(None, results)) # 필터링된 포트
    open_or_fiterd_ports.sort()
    return open_or_fiterd_ports

# 멀티스레딩 작업자 함수
def thread_stealth_worker_for_processing(args):
    flag, target, ports = args
    open_or_filtered_ports = []
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        results = executor.map(lambda port: stealth_scan(flag, target, port), ports)
        open_or_filtered_ports.extend(filter(None, results))
    return open_or_filtered_ports

# 멀티프로세싱 + 멀티스레딩 스캔 함수
def hybrid_stealth_scan(flag, target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port + 1))
    random.shuffle(random_ports)

    # 멀티프로세싱: 포트 범위를 여러 그룹으로 분할
    num_processes = cpu_count()
    chunk_size = len(random_ports) // num_processes
    port_chunks = [random_ports[i:i + chunk_size] for i in range(0, len(random_ports), chunk_size)]

    args = [(flag, target_ip, chunk) for chunk in port_chunks]

    # 멀티프로세싱 실행
    with Pool(processes=CPU_CORES) as pool:
        results = pool.map(thread_stealth_worker_for_processing, args)

    # 결과 합치기
    open_or_filtered_ports = [port for sublist in results for port in sublist]
    open_or_filtered_ports.sort()
    return open_or_filtered_ports

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python tcp_stealth_scan.py <type> <target_ip> <start_port> <end_port>")
        sys.exit(1)

    flag = sys.argv[1]
    target_ip = sys.argv[2]
    start_port = int(sys.argv[3])
    end_port = int(sys.argv[4])
    start = time.time()
    open_or_fiterd_ports = hybrid_stealth_scan(flag, target_ip, start_port, end_port)
    print(f"{time.time() - start:.5f}sec")
    if open_or_fiterd_ports:
        print(f"포트 총 {len(open_or_fiterd_ports)}개 열려 있거나 필터링 됨 : {open_or_fiterd_ports}")
    else:
        print("포트 닫힘")