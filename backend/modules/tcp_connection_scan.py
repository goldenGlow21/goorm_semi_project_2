# 양인규 로컬에서 테스트 함 추가 테스트 필요함
import socket
import sys
import time

# connection 스캔 함수
def connection_scan(target, ports):
    print(f"{target} ip에서 {ports} 포트 스캔")

    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            open_ports.append(port)
        except Exception as e:
            pass
        finally:
            sock.close()

        time.sleep(0) # 속도 조절 시 사용할 것

    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tcp_connection_scan.py <target> <port1,port2,port3,...>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_list = list(map(int, sys.argv[2].split(',')))

    open_ports = connection_scan(target_ip, port_list)

    if open_ports:
        print(f"포트 열림 : {open_ports}")
    else:
        print("포트 닫힘")
