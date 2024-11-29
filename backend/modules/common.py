
from contextlib import closing
import socket
import random

def get_port():
    max_try = 10
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        for _ in range(max_try):
            try:
                port = random.randint(1024, 65535)
                sock.bind(('', port))
                return port
            except socket.error as e:
                print(f"다른 소켓으로 사용 시도..")
        print("사용가능한 포트를 찾지 못했습니다.")


