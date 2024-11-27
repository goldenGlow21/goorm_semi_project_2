# 양인규 테스트 함 추가 테스트 필요함
from scapy.all import send, sr1, conf #from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP
import sys
import time

from scapy.sendrecv import sendp


# syn 스캔 함수
def syn_scan(target, ports):
    print(f"{target} ip에서 {ports} 포트 스캔")
    conf.verb = 0  # 출력 억제
    open_ports = []

    for port in ports:
        # FIN 패킷 생성
        packet = IP(dst=target)/TCP(dport=port, flags="S") # / ip와 tcp를 묶는 연산자
        # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
        response = sr1(packet, timeout=1)

        if response is None:
            print(f"응답 없음 : {port}")
            pass
        elif response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN/ACK응답 == 포트 열림
            packet = IP(dst=target)/TCP(dport=port, flags="R")
            send(packet)
            open_ports.append(port)
        time.sleep(0) # 속도 조절 시 사용할 것
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_syn_scan.py <target> <port1,port2,port3,...>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_list = list(map(int, sys.argv[2].split(',')))

    open_ports = syn_scan(target_ip, port_list)

    if open_ports:
        print(f"포트 열림 : {open_ports}")
    else:
        print("포트 닫힘")
