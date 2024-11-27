# 테스트 필요함
from scapy.all import sr1, conf #from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, UDP, ICMP
import sys
import time

# UDP 스캔 함수
def udp_scan(target, ports):
    print(f"{target} ip에서 {ports} 포트 스캔")
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    open_or_filtered_ports = []

    for port in ports:
        # UDP 패킷 생성
        packet = IP(dst=target) / UDP(dport=port) # / ip와 tcp를 묶는 연산자
        # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
        response = sr1(packet, timeout=1)

        if response is None:  # 응답x == 열려 있거나 닫혀 있음
            open_or_filtered_ports.append(port)

        time.sleep(0) # 속도 조절 시 사용할 것

    return open_or_filtered_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python udp_scan.py <target> <port1,port2,port3,...>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_list = list(map(int, sys.argv[2].split(',')))

    open_ports = udp_scan(target_ip, port_list)

    if open_ports:
        print(f"포트 열림 또는 필터링 됨 : {open_ports}")
    else:
        print("포트 닫힘")
