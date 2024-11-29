import socket
import random
from contextlib import closing
from urllib.parse import urlparse

def get_port():
    max_try = 10
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        for _ in range(max_try):
            try:
                port = random.randint(49152, 65535)
                sock.bind(('', port))
                return port
            except socket.error as e:
                print(f"다른 소켓으로 사용 시도..")
        print("사용가능한 포트를 찾지 못했습니다.")

def get_ip_from_domain(url):
    try:
        domain = urlparse(url).netloc
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        print("URL로 IP주소를 찾지 못했습니다." + str(e))