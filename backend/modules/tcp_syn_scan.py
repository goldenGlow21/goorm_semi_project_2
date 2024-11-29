import os, sys
import time
import random
import threading

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, cpu_count
from scapy.all import send, sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP
from common import get_available_port

LOCK = threading.Lock() # 뮤텍스 락
CPU_CORES = cpu_count()

# syn 스캔 함수
def syn_scan(target_ip, port):
    conf.verb = 0  # 출력 억제
    packet = IP(dst=target_ip) / TCP(sport=get_available_port(), dport=port, flags="S")  # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)

    if response is None:
        pass
    elif response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN/ACK응답 == 포트 열림
        packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
        send(packet)
        return port
    time.sleep(0)  # 속도 조절 시 사용할 것

# 멀티스레드 단독으로 사용시
def multi_syn_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=CPU_CORES * 2) as executor:
        results = list(executor.map(lambda port: syn_scan(target_ip, port), random_ports))
    open_ports = list(filter(None, results))
    open_ports.sort()
    return open_ports

# 멀티스레딩 작업자 함수
def thread_syn_worker_for_processing(args):
    target, ports = args
    open_ports = []
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        results = executor.map(lambda port: syn_scan(target, port), ports)
        open_ports.extend(filter(None, results))
    return open_ports

# 멀티프로세싱 + 멀티스레딩 스캔 함수
def hybrid_syn_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port + 1))
    random.shuffle(random_ports)

    # 멀티프로세싱: 포트 범위를 여러 그룹으로 분할
    num_processes = cpu_count()
    chunk_size = len(random_ports) // num_processes
    port_chunks = [random_ports[i:i + chunk_size] for i in range(0, len(random_ports), chunk_size)]

    args = [(target_ip, chunk) for chunk in port_chunks]

    # 멀티프로세싱 실행
    with Pool(processes=CPU_CORES) as pool:
        results = pool.map(thread_syn_worker_for_processing, args)

    # 결과 합치기
    open_ports = [port for sublist in results for port in sublist]
    open_ports.sort()
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_syn_scan.py <target_ip> <port> <port>")
        sys.exit(1)
    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    start = time.time()
    open_ports = hybrid_syn_scan(target_ip, start_port, end_port)
    print(f"{time.time() - start:.5f}sec")
    if open_ports:
        print(f"포트 총 {open_ports}개 열림 : {open_ports}")
    else:
        print("포트 닫힘")
