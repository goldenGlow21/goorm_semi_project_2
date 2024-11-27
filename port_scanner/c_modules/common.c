#include "common.h"

#include <stdbool.h>

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
    else if (flag == ACK)
        tcph->ack = 1;
    else if (flag == XMAS) {
        tcph->fin = 1;
        tcph->psh = 1;
        tcph->urg = 1;
    }
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

void receive_fin_null_xmas_response(int sockfd, int src_port, int time_limit)
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
            perror("fin_null_xmas recvfrom 에러");
        return;
    }

    struct iphdr *recv_iph = (struct iphdr *)recv_buffer;
    struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4));

    if (is_rst(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        printf("포트 닫힘(RST 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
    }
}

int is_rst_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1 && tcph->ack == 1);
}

int is_rst(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1);
}

int available_port() {
    int sock;
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // 모든 인터페이스에서 접속 허용
    if (sock < 0) {
        perror("포트 확인용 소켓 생성 실패");
        return 0;
    }

    while (1)
    {
        int port = rand() % (65535 - 1024 + 1) + 1024;
        addr.sin_port = htons(port);  // 포트 번호 설정
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(sock);  // 포트가 이미 사용 중이거나 사용할 수 없으면 소켓 닫기
            continue;  // 포트가 사용 중
        }
        close(sock);  // 바인딩 성공하면 소켓 닫기
        return port;  // 포트가 사용 가능
    }
}

void get_ip_and_interfaces(char *src_ip, char *src_interface) {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *ifa = NULL;
    char ip[INET_ADDRSTRLEN];

    // 인터페이스 목록 가져오기
    if (getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    // 인터페이스 목록 순회
    for (ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET) {  // IPv4 주소만 처리
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, src_ip, sizeof(ip));  // IP 주소 문자열로 변환

            // 루프백 주소(127.0.0.1) 제외
            if (strcmp(ip, "127.0.0.1") != 0) {
                // 네트워크 인터페이스 이름과 IP 출력
                printf("Interface: %s\tIP Address: %s\n", ifa->ifa_name, ip);
                strncpy(src_interface, ifa->ifa_name, IF_NAMESIZE);
                src_interface[IF_NAMESIZE - 1] = '\0';
                return;
            }
        }
    }

    // 메모리 해제
    if (interfaces != NULL) {
        freeifaddrs(interfaces);
    }
}
