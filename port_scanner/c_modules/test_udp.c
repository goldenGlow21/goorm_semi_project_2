#include <stdio.h>

// udp_scan 함수 선언
void udp_scan(const char *target_ip, int *ports, int num_ports);

int main() {
    // 스캔할 대상 IP와 포트 설정
    const char *target_ip = "13.125.143.118"; // 테스트할 대상 IP
    int ports[] = {53, 123, 9999, 8888, 8080}; // 스캔할 포트 번호 리스트
    int num_ports = sizeof(ports) / sizeof(ports[0]); // 포트 개수 계산

    printf("UDP 스캔 시작: 대상 IP %s\n", target_ip);
    udp_scan(target_ip, ports, num_ports); // 스캔 수행
    printf("UDP 스캔 완료\n");

    return 0;
}
