#include <stdio.h>
#include "xmas_scan.c"

int main() {
    const char *src_ip = "192.168.1.2";  // 자신의 IP 주소
    const char *target_ip = "13.125.143.118";  // 대상 서버 IP
    int ports[] = {22, 80, 443, 8080};
    int port_count = sizeof(ports) / sizeof(ports[0]);

    printf("XMAS 스캔 시작: 대상 IP %s\n", target_ip);
    for (int i = 0; i < port_count; i++) {
        xmas_scan(src_ip, target_ip, ports[i]);
    }
    printf("XMAS 스캔 완료\n");

    return 0;
}
