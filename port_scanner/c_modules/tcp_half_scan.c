#include "common.h"

// SYN/ACK 패킷 확인 함수
int is_syn_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->syn == 1 && tcph->ack == 1);
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


void start_syn_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit) {

    int sockfd = create_raw_socket();
    set_socket_options(sockfd);

    char packet[1024];
    create_packet(packet, src_ip, src_port, dst_ip, dst_port, SYN);

    send_packet(sockfd, packet, dst_ip, dst_port);
    receive_syn_response(sockfd, src_port, time_limit);

    close(sockfd);
}

// 메인
int main()
{
    start_syn_scan("192.168.79.11", 10000, "192.168.79.3", 8080, 3);
}
