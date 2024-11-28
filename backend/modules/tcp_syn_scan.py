# 양인규 테스트 함 추가 테스트 필요함
import random
from common import get_port
from scapy.all import send, sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP
from concurrent.futures import ThreadPoolExecutor
import sys
import time
import os


# syn 스캔 함수
def syn_scan(target, port):
    conf.verb = 0  # 출력 억제
    packet = IP(dst=target) / TCP(sport=get_port(), dport=port, flags="S")  # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)

    if response is None:
        print(f"응답 없음 : {port}")
        pass
    elif response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN/ACK응답 == 포트 열림
        packet = IP(dst=target) / TCP(dport=port, flags="R")
        send(packet)
        return port
    time.sleep(0)  # 속도 조절 시 사용할 것

def multi_syn_scan(target, start_port, end_port):
    start = time.time()
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        results = list(executor.map(lambda port: syn_scan(target, port), random_ports))
    open_ports = list(filter(None, results))
    open_ports.sort()
    end = time.time()
    print(f"{end - start:.5f} sec")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_syn_scan.py <target> <port> <port>")
        sys.exit(1)
    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    port = multi_syn_scan(target_ip, start_port, end_port)

    if port:
        print(f"포트 열림 : {port}")
    else:
        print("포트 닫힘")
