# 양인규 로컬에서 테스트 함 추가 테스트 필요함
from scapy.all import sr1, conf #from scapy.all import IP, TCP, sr1, conf
from scapy.layers.inet import IP, TCP
import sys
import time

# FIN null xmas 스캔 함수
def stealth_scan(flag, target, ports):
    print(f"{target} ip에서 {ports} 포트 스캔")
    conf.verb = 0  # 디버깅 메시지 0이면 출력 안함 1이면 출력 함
    open_ports = []

    for port in ports:
        # stealth 패킷 생성
        if flag == "F":
            packet = IP(dst=target) / TCP(dport=port, flags="F") # / ip와 tcp를 묶는 연산자
        elif flag == "N":
            packet = IP(dst=target) / TCP(dport=port)
        elif flag == "X":
            packet = IP(dst=target) / TCP(dport=port, flags="FPU")
        # 패킷 전송 및 응답 수신 sr1함수는 패킷을 전송하고 첫 번째 응답을 기다리는 함수
        response = sr1(packet, timeout=1)


        if response is None:  # 응답x == 포트 열림
            open_ports.append(port)

        time.sleep(0) # 속도 조절 시 사용할 것

    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python tcp_stealth_scan.py <type> <target> <port1,port2,port3,...>")
        sys.exit(1)

    flag = sys.argv[1]
    target_ip = sys.argv[2]
    port_list = list(map(int, sys.argv[3].split(',')))

    open_ports = stealth_scan(flag, target_ip, port_list)

    if open_ports:
        print(f"포트 열림 : {open_ports}")
    else:
        print("포트 닫힘")
