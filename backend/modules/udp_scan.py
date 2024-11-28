# 테스트 필요함
from scapy.all import sr1, conf #from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, UDP, ICMP
import sys
import time
import random
import os
from concurrent.futures import ThreadPoolExecutor
from common import get_port

# UDP 스캔 함수
def udp_scan(target, port):
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함

    # UDP 패킷 생성
    packet = IP(dst=target) / UDP(sport=get_port(), dport=port) # / ip와 tcp를 묶는 연산자
    # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
    response = sr1(packet, timeout=1)

    if response is None:  # 응답x == 열려 있거나 필터링 됨
        return port
    elif response.haslayer(ICMP) and response[ICMP].type == 3: # 응답o == 닫혀잇음
        pass
    time.sleep(0) # 속도 조절 시 사용할 것


def multi_udp_scan(target, start_port, end_port):
    start = time.time()
    random_ports = list(range(start_port, end_port+1))
    time.sleep(1)
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 10) as executor:
        results = list(executor.map(lambda port: udp_scan(target, port), random_ports))
    open_or_fiterd_ports = list(filter(None, results)) # 필터링된 포트
    open_or_fiterd_ports.sort()
    end = time.time()
    print(f"{end - start:.5f} sec")
    return open_or_fiterd_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python udp_scan.py <target> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    ports = multi_udp_scan(target_ip, start_port, end_port)

    if ports:
        print(f"포트 총 {len(ports)}개 열려 있거나 필터링 됨 : {ports}")
    else:
        print("포트 닫힘")
