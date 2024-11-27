#include "common.h"

void start_xmas_scan(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int time_limit)
{
    int sockfd = create_raw_socket();
    set_socket_options(sockfd);
    char packet[PACKET_SIZE];
    create_raw_packet(packet, src_ip, src_port, dst_ip, dst_port, XMAS);
    send_raw_packet(sockfd, packet, dst_ip, dst_port);
    receive_fin_null_xmas_response(sockfd, src_port, time_limit);
    close(sockfd);
}

int main()
{
    start_xmas_scan(get_ip(), available_port(TCP), "192.168.79.3", 8080, 3);
    return 0;
}