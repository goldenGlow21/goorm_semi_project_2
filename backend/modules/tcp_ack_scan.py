# 테스트 필요함
from scapy.all import sr1, conf  # from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP, ICMP
import sys
import time


# ack 스캔 함수
def ack_scan(target, ports):
    print(f"{target} ip에서 {ports} 방화벽 스캔")
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    filtered_ports = []
    for port in ports:
        # ACK 패킷 생성
        packet = IP(dst=target) / TCP(dport=port, flags="A")  # / ip와 tcp를 묶는 연산자
        # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
        response = sr1(packet, timeout=1)
        if response is None:
            print("응답 없음")
        elif response.haslayer(ICMP) and response[ICMP].type == 3:
            filtered_ports.append(port)
        time.sleep(0)  # 속도 조절 시 사용할 것
    return filtered_ports


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_ack_scan.py <target> <port1,port2,port3,...>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_list = list(map(int, sys.argv[2].split(',')))

    open_ports = ack_scan(target_ip, port_list)

    if open_ports:
        print(f"방화벽 설정 됨 : {open_ports}")
    else:
        print("방화벽 설정 안됨")
