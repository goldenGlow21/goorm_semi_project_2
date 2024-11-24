#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>

// TCP 체크섬 계산 함수
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// XMAS 스캔 함수
void xmas_scan(const char *src_ip, const char *target_ip, int target_port) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("소켓 생성 실패. Root 권한 필요.");
        return;
    }

    char packet[1024];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;

    // IP 헤더 설정
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(target_ip);
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // TCP 헤더 설정
    tcph->source = htons(12345);
    tcph->dest = htons(target_port);
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->psh = 1;
    tcph->urg = 1;
    tcph->window = htons(512);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // 의사 헤더로 체크섬 계산
    struct {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
        struct tcphdr tcp;
    } pseudo_header;

    pseudo_header.src_addr = inet_addr(src_ip);
    pseudo_header.dst_addr = inet_addr(target_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr));
    tcph->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));

    // 대상 주소 설정
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    // 패킷 전송
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("패킷 전송 실패");
        close(sockfd);
        return;
    }
    printf("XMAS 패킷 보냄 %s:%d\n", target_ip, target_port);

    // 응답 수신
    char recv_buffer[1024];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    ssize_t data_size = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&source, &source_len);

    if (data_size < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            printf("포트 %d: filtered (응답 없음)\n", target_port);
        else
            perror("recvfrom 에러");
    } else {
        struct iphdr *recv_iph = (struct iphdr *)recv_buffer;
        struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4));

        if (recv_tcph->rst == 1)
            printf("포트 %d: closed (RST 수신)\n", target_port);
        else
            printf("포트 %d: open (예상치 못한 응답)\n", target_port);
    }

    close(sockfd);
}
