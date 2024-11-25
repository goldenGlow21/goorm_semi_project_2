#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>
#define SYN 1
#define FIN 2

// SYN/ACK 패킷 확인 함수
int is_syn_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->syn == 1 && tcph->ack == 1);
}

int is_rst_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1 && tcph->ack == 1);
}

int is_rst(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1);
}

// TCP Checksum 계산 함수
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

// 로우 소켓 생성 함수
int create_raw_socket() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }
    return sockfd;
}

// 소켓 옵션 설정 함수
void set_socket_options(int sockfd) {
    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("IP_HDRINCL 설정 실패");
        close(sockfd);
        exit(1);
    }
}

// 패킷 생성 함수
void create_packet(char *packet, const char *src_ip, int src_port, const char *dst_ip, int dst_port, int flag) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    memset(packet, 0, sizeof(char) * 1024);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
    if (flag == SYN)
        tcph->syn = 1;
    else if (flag == FIN)
        tcph->fin = 1;
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = 5;

    tcph->window = htons(512);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    struct {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
        struct tcphdr tcp;
    } pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header.src_addr = inet_addr(src_ip);
    pseudo_header.dst_addr = inet_addr(dst_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr));
    tcph->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));
}

// 패킷 전송 함수
void send_packet(int sockfd, char *packet, const char *dst_ip, int dst_port) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("데이터 보내지 못함.");
        close(sockfd);
        exit(1);
    }

    printf("SYN 패킷 보냄 %s:%d\n", dst_ip, dst_port);
}

// 응답 수신 함수
void receive_syn_response(int sockfd, int src_port, int time_limit) {
    char recv_buffer[65536];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    struct timeval timeout;
    timeout.tv_sec = time_limit;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == -1) {
        perror("타임 아웃 설정 실패");
        close(sockfd);
        exit(1);
    }

    ssize_t data_size = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
    if (data_size == -1) {
        if (errno == EAGAIN)
            perror("포트 필터링됨(타임아웃)");
        else
            perror("syn recvfrom 에러");
        return;
    }

    struct iphdr *recv_iph = (struct iphdr *)recv_buffer;
    struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4));

    if (is_syn_ack(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        printf("포트 열림(SYN/ACK 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
    } else if (is_rst_ack(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        printf("포트 닫힘(RST/ACK 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
    }
}

void receive_fin_response(int sockfd, int src_port, int time_limit)
{
    char recv_buffer[65536];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    struct timeval timeout;
    timeout.tv_sec = time_limit;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == -1) {
        perror("타임 아웃 설정 실패");
        close(sockfd);
        exit(1);
    }

    ssize_t data_size = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
    if (data_size == -1) {
        if (errno == EAGAIN)
            perror("포트 열림(타임 아웃)");
        else
            perror("fin recvfrom 에러");
        return;
    }

    struct iphdr *recv_iph = (struct iphdr *)recv_buffer;
    struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4));

    if (is_rst(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        printf("포트 닫힘(RST 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
    }
}
// main 함수
void start_syn_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit) {

    int sockfd = create_raw_socket();
    set_socket_options(sockfd);

    char packet[1024];
    create_packet(packet, src_ip, src_port, dst_ip, dst_port, SYN);

    send_packet(sockfd, packet, dst_ip, dst_port);
    receive_syn_response(sockfd, src_port, time_limit);

    close(sockfd);
}
void start_fin_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit)
{
    int sockfd = create_raw_socket();
    set_socket_options(sockfd);
    char packet[1024];
    create_packet(packet, src_ip, src_port, dst_ip, dst_port, FIN);
    send_packet(sockfd, packet, dst_ip, dst_port);
    receive_fin_response(sockfd, src_port, time_limit);
    close(sockfd);
}
// 메인
int main()
{
    start_syn_scan("192.168.79.11", 10000, "192.168.79.3", 8080, 3);
    start_fin_scan("192.168.79.11", 10000, "192.168.79.3", 8080, 3);
}
