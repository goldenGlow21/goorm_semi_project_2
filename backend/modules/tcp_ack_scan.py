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
from scapy.layers.inet import IP, TCP, ICMP
from common import get_available_port

LOCK = threading.Lock() # 뮤텍스 락
CPU_CORES = cpu_count()

# ack 스캔 함수
def ack_scan(target_ip, port):
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    with LOCK:
        random_port = get_available_port()
    # ACK 패킷 생성
    packet = IP(dst=target_ip) / TCP(sport=random_port, dport=port, flags="A")  # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)
    if response is None:
        pass
    elif response.haslayer(TCP) and response[TCP].flags == 0x4:  # SYN/ACK응답 == 포트 열림
        return port
    time.sleep(0)  # 속도 조절 시 사용할 것

# 멀티스레딩 단독으로 사용시
def multi_ack_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=CPU_CORES * 2) as executor:
        results = list(executor.map(lambda port: ack_scan(target_ip, port), random_ports))
    unfiltered_ports = list(filter(None, results)) # 필터링된 포트
    unfiltered_ports.sort()
    return unfiltered_ports

# 멀티스레딩 작업자 함수
def thread_ack_worker_for_processing(args):
    target, ports = args
    filtered_ports = []
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        results = executor.map(lambda port: ack_scan(target, port), ports)
        filtered_ports.extend(filter(None, results))
    return filtered_ports

# 멀티프로세싱 + 멀티스레딩 스캔 함수
def hybrid_ack_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port + 1))
    random.shuffle(random_ports)

    # 멀티프로세싱: 포트 범위를 여러 그룹으로 분할
    num_processes = cpu_count()
    chunk_size = len(random_ports) // num_processes
    port_chunks = [random_ports[i:i + chunk_size] for i in range(0, len(random_ports), chunk_size)]

    args = [(target_ip, chunk) for chunk in port_chunks]

    # 멀티프로세싱 실행
    with Pool(processes=CPU_CORES) as pool:
        results = pool.map(thread_ack_worker_for_processing, args)

    # 결과 합치기
    unfiltered_ports = [port for sublist in results for port in sublist]
    unfiltered_ports.sort()
    return unfiltered_ports


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python tcp_ack_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    start = time.time()
    unfiltered_ports = hybrid_ack_scan(target_ip, start_port, end_port)
    print(f"{time.time() - start:.5f}sec")

    if unfiltered_ports:
        print(f"방화벽 총 {len(unfiltered_ports)}개 열림 : {unfiltered_ports}")
    else:
        print("방화벽 다 설정됨")
