# 테스트 필요함
import sys
import time
import random
import os
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP, ICMP
from .common import get_port

# ack 스캔 함수
def ack_scan(target_ip, port):
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    # ACK 패킷 생성
    packet = IP(dst=target_ip) / TCP(sport=get_port(), dport=port, flags="A")  # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)
    if response is None:
        return port
    elif response.haslayer(ICMP) and response[ICMP].type == 3:
        return port
    time.sleep(0)  # 속도 조절 시 사용할 것

def multi_ack_scan(target_ip, start_port, end_port):
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        results = list(executor.map(lambda port: ack_scan(target_ip, port), random_ports))
    filtered_ports = list(filter(None, results)) # 필터링된 포트
    filtered_ports.sort()
    return filtered_ports


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python tcp_ack_scan.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    filtered_ports = multi_ack_scan(target_ip, start_port, end_port)

    if filtered_ports:
        print(f"방화벽 총 {len(filtered_ports)}개 설정 됨 : {filtered_ports}")
    else:
        print("방화벽 설정 안됨")
