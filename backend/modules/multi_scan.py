import time
import os
import sys
import random
from tcp_syn_scan import syn_scan
from tcp_ack_scan import ack_scan
from tcp_stealth_scan import stealth_scan
from udp_scan import udp_scan
from concurrent.futures import ThreadPoolExecutor

def multi_syn_scan(scan, target, start_port, end_port, flag=None):
    start = time.time()
    random_ports = list(range(start_port, end_port+1))
    random.shuffle(random_ports)
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        if scan == "syn":
            results = list(executor.map(lambda port: syn_scan(target, port), random_ports))
        elif scan == "ack":
            results = list(executor.map(lambda port: ack_scan(target, port), random_ports))
        elif scan == "stealth":
            results = list(executor.map(lambda port: stealth_scan(flag, target, port), random_ports))
        elif scan == "udp":
            results = list(executor.map(lambda port: udp_scan(target, port), random_ports))
    open_ports = list(filter(None, results))
    open_ports.sort()
    end = time.time()
    print(f"{end - start:.5f} sec")
    return open_ports

if __name__ == "__main__":
    if len (sys.argv) < 5:
        print("Usage: python multi_scan.py <scan> <target> <start_port> <end_port> <flag>")
        sys.exit(1)
    scan = sys.argv[1]
    target_ip = sys.argv[2]
    start_port = int(sys.argv[3])
    end_port = int(sys.argv[4])
    # flag가 입력되지 않은 경우 기본값 설정
    flag = sys.argv[5] if len(sys.argv) > 5 else None
    print(multi_syn_scan(scan, target_ip, start_port, end_port, flag))
