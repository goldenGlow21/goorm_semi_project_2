#include "common.h"

void start_connect_scan(const char *dst_ip, int dst_port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dst_addr;
    if (sockfd < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    if (connect(sockfd, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) == 0)
        printf("포트 열림(tcp connection 성공) %s:%d\n", dst_ip, dst_port);
    else
        printf("포트 닫힘(tcp connection 실패) %s:%d", dst_ip, dst_port);

    close(sockfd);
}

int main()
{
    start_connect_scan("192.168.79.3", 8080);
}
