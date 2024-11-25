#include "common.h"

// 로우 소켓 생성 함수
int create_raw_socket() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }
    return sockfd;
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
void create_raw_packet(char *packet, const char *src_ip, int src_port, const char *dst_ip, int dst_port, int flag) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    memset(packet, 0, PACKET_SIZE);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(PACKET_SIZE);
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

    tcph->window = htons(65535);
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
    pseudo_header.tcp_len = htons(PACKET_SIZE - sizeof(struct iphdr));
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr));
    tcph->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));
}

// 패킷 전송 함수
void send_raw_packet(int sockfd, char *packet, const char *dst_ip, int dst_port) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("데이터 보내지 못함.");
        close(sockfd);
        exit(1);
    }

    printf("패킷 보냄 %s:%d\n", dst_ip, dst_port);
}

int is_rst_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1 && tcph->ack == 1);
}