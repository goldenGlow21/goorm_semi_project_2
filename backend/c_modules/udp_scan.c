#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <errno.h>

// ICMP Destination Unreachable 코드 확인
int is_icmp_destination_unreachable(struct icmphdr *icmp) {
    return (icmp->type == ICMP_DEST_UNREACH &&
            icmp->code == ICMP_PORT_UNREACH);
}

// UDP 스캔 함수
void udp_scan(const char *target_ip, int *ports, int num_ports) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("소켓 생성 실패. root 권한 필요");
        exit(EXIT_FAILURE);
    }

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) {
        perror("수신 소켓 생성 실패");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 소켓 옵션 설정
    struct timeval timeout = {3, 0}; // 3초 타임아웃
    if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("타임아웃 설정 실패");
        close(sockfd);
        close(recv_sock);
        exit(EXIT_FAILURE);
    }

    char packet[4096]; // 전송 패킷 버퍼
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip);

    for (int i = 0; i < num_ports; i++) {
        int target_port = ports[i];
        memset(packet, 0, sizeof(packet));

        // UDP 헤더 설정
        struct udphdr *udph = (struct udphdr *)packet;
        udph->source = htons(12345); // 출발 포트 (임의)
        udph->dest = htons(target_port);
        udph->len = htons(sizeof(struct udphdr));
        udph->check = 0; // 체크섬은 생략 가능

        dest.sin_port = htons(target_port);

        // UDP 패킷 전송
        if (sendto(sockfd, packet, sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("패킷 전송 실패");
            continue;
        }

        printf("UDP 패킷 보냄 %s:%d\n", target_ip, target_port);

        // 응답 대기
        char recv_buffer[4096];
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);

        ssize_t recv_len = recvfrom(recv_sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&source, &source_len);
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("포트 %d: open|filtered (응답 없음)\n", target_port);
            } else {
                perror("recvfrom 에러");
            }
            continue;
        }

        // ICMP 메시지 확인
        struct iphdr *iph = (struct iphdr *)recv_buffer;
        struct icmphdr *icmp = (struct icmphdr *)(recv_buffer + (iph->ihl * 4));

        if (is_icmp_destination_unreachable(icmp)) {
            printf("포트 %d: closed (ICMP Destination Unreachable 수신)\n", target_port);
        } else {
            printf("포트 %d: open (UDP 응답 수신)\n", target_port);
        }
    }

    close(sockfd);
    close(recv_sock);
}
