#include "common.h"

void receive_ack_response(int sockfd, int src_port, int time_limit)
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
        if (errno == EAGAIN || errno == ECONNREFUSED)
            perror("방화벽 설정됨(타임 아웃 또는 ICMP 에러)");
        else
            perror("ack recvfrom 에러");
        return;
    }

    struct iphdr *recv_iph = (struct iphdr *)recv_buffer;
    struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4));

    if (is_rst(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        printf("방화벽 필터링 안됨(RST 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
    }


}

void start_ack_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit)
{
    int sockfd = create_raw_socket();
    set_socket_options(sockfd);
    char packet[PACKET_SIZE];
    create_raw_packet(packet, src_ip, src_port, dst_ip, dst_port, ACK);
    send_raw_packet(sockfd, packet, dst_ip, dst_port);
    receive_ack_response(sockfd, src_port, time_limit);
    close(sockfd);
}

int main()
{
    start_ack_scan(get_ip(), available_port(TCP), "192.168.79.3", 8080, 3);
}