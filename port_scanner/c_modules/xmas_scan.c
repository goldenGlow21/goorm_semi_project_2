#include "common.h"

void start_xmas_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit)
{
    int sockfd = create_raw_socket(); // Raw 소켓 생성
    set_socket_options(sockfd);      // 소켓 옵션 설정

    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    // 패킷 생성
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP 헤더 설정
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // TCP 헤더 설정 (PSH, URG, FIN 플래그 활성화)
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->psh = 1;
    tcph->urg = 1;
    tcph->fin = 1;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // 의사 헤더 설정 및 체크섬 계산
    struct {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
        struct tcphdr tcp;
    } pseudo_header;

    pseudo_header.src_addr = inet_addr(src_ip);
    pseudo_header.dst_addr = inet_addr(dst_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header));

    // 패킷 전송
    send_raw_packet(sockfd, packet, dst_ip, dst_port);

    // 응답 수신
    receive_fin_null_xmas_response(sockfd, src_port, time_limit);

    close(sockfd); // 소켓 닫기
}

int main()
{
    start_xmas_scan("180.68.168.239", 10000, "13.125.143.118", 10000, 3);
    return 0;
}
