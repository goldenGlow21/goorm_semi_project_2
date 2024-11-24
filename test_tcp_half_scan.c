// 리눅스에서만 동작함
// 출발 도착 ip port 변경할 것
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
#include <asm-generic/errno.h>

// SYN/ACK 패킷 확인 함수
int is_syn_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->syn == 1 && tcph->ack == 1); // tcp이고 syn/ack 플래그 설정 됐는지 확인
}

int is_rst_ack(struct iphdr *iph, struct tcphdr *tcph) {
    return (iph->protocol == IPPROTO_TCP && tcph->rst == 1 && tcph->ack == 1); // tcp이고 rst/ack 플래그 설정 됐는지 확인
}

// TCP Checksum 계산 함수
unsigned short checksum(void *b, int len) { // *b 체크섬을 계산할 데이터의 시작주소, len 데이터의 길이(바이트)
    unsigned short *buf = b; // 데이터를 16비트 단위로 처리하기 위해 만든 포인터
    unsigned int sum = 0; // 합계를 저장할 변수
    unsigned short result; // 최종 체크섬 값

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++; // 16비트 단위(2바이트)로 읽어서 합산
    if (len == 1)
        // 데이터 길이가 홀수이면
        sum += *(unsigned char *)buf; // 남은 1바이트도 합산
    sum = (sum >> 16) + (sum & 0xFFFF); // 상위 16비트 하위 16비트 합산
    sum += (sum >> 16); // 비트 정리
    result = ~sum; // 비트 반전(1의 보수)
    return result;
}

int main() {
    // 수정 필요
    const char *target_ip = "192.168.79.3"; // 스캔 대상
    int target_port = 8080; // 스캔 대상 포트
    const char *src_ip = "192.168.79.11"; // 출발 ip
    int src_port = 10000;
    struct timeval timeout;
    timeout.tv_sec = 3; // 초 단위 마이크로단위는 .tv_usec 사용

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // 로우 소켓 생성 AF_INET : ipv4, SOCK_RAW : 로우 소켓, IPPROTO_TCP : tcp
    if (sockfd < 0) { // 생성 실패시
        perror("소켓 생성 실패");
        return 1;
    }

    char packet[1024]; // 패킷 생성 (헤더만 포함할 경우 20바이트)
    struct iphdr *iph = (struct iphdr *)packet; // ip 헤더 구조체
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr)); // tcp 헤더 구조체
    struct sockaddr_in dest; // 패킷이 전송될 대상 주소를 저장하기 위한 공간

    // IP_HDRINCL 옵션 설정
    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        // 소켓 옵션 설정 sockfd : 소켓, IPROTO_IP : ip 프로토콜 레벨, IP_HDRINCL : 사용자 IP 헤더 직접 작성, &opt : IP_HDRINCL : 활성화(0일시 비활성화), sizeof(opt) : opt의 크기
        perror("IP_HDRINCL 설정 실패");
        close(sockfd);
        return 1;
    }



    memset(packet, 0, sizeof(packet)); // 패킷 0으로 초기화

    iph->ihl = 5; // ip 헤더의 길이 5 * 4(32비트) = 20 바이트
    iph->version = 4; // ipv4
    iph->tos = 0; // 우선순위 기본값 0
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // ip 패킷의 전체 길이를 네트워크 바이트 정렬
    iph->id = htons(54321); // 패킷의 고유 식별자를 네트워크 바이트 정렬
    iph->frag_off = 0; // 패킷 조각화를 성정 값이 0일시 조작화x
    iph->ttl = 64; // ttl 64로 설정
    iph->protocol = IPPROTO_TCP; // TCP 프로토콜 설정
    iph->saddr = inet_addr(src_ip);  // 출발 ip
    iph->daddr = inet_addr(target_ip);  // 대상 ip
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr)); // 체크섬


    tcph->source = htons(src_port);  // 출발 포트
    tcph->dest = htons(target_port);  // 대상 포트
    tcph->seq = htonl(0); // 시퀀스 번호
    tcph->ack_seq = 0; // 웅답 번호
    tcph->doff = 5; //tcp 헤더 길이(20바이트)
    tcph->syn = 1;  // SYN 플래그 설정
    tcph->window = htons(512); // tcp 윈도우 사이즈
    tcph->check = 0; // 체크섬 나중에 밑에 계산함
    tcph->urg_ptr = 0; // 긴급 포인터 사용하지 않는 것 추천(0)

    // tcp 헤더 체크섬 계산을 위한 의사 헤더 구조체
    struct {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
        struct tcphdr tcp;
    } pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header)); // 0으로 초기화
    pseudo_header.src_addr = inet_addr(src_ip); // 출발 ip
    pseudo_header.dst_addr = inet_addr(target_ip); // 도착 ip
    pseudo_header.zero = 0; // 체크섬 계산 규칙에 따라 항상 0
    pseudo_header.protocol = IPPROTO_TCP; // tcp
    pseudo_header.tcp_len = htons(sizeof(struct tcphdr)); // tcp 전체 크기
    memcpy(&pseudo_header.tcp, tcph, sizeof(struct tcphdr)); // tcp 헤더 복붙
    tcph->check = checksum((unsigned short *)&pseudo_header, sizeof(pseudo_header)); // 체크섬 계산

    // 대상 정보
    dest.sin_family = AF_INET; // ipv4
    dest.sin_port = htons(target_port); // 대상 포트
    dest.sin_addr.s_addr = inet_addr(target_ip); // 대상 ip

    // 패킷 전송
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        // sockfd : 소켓, packet : 패킷, 패킷 크기, 플래그 : 기본값 0, &dest : 목적지 구조체, 목적지 구조체 크기
        perror("데이터 보내지 못함.");
        close(sockfd);
        return 1;
    }

    printf("SYN 패킷 보냄 %s:%d\n", target_ip, target_port);

    // SYN/ACK 수신 로직
    char recv_buffer[65536]; // 버퍼 생성
    struct sockaddr_in src_addr; // 패킷의 소스 주소를 저장할 구조체
    socklen_t addr_len = sizeof(src_addr); // 구조체의 크기

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == -1) {
        perror("타임 아웃 설정 실패");
        close(sockfd);
        return 1;
    }
    ssize_t data_size = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
    // data_size 수신한 데이터 크기, recvfrom를 사용한 이유 송신자의 정보를 알 수 있음
    // recvfrom의 인자 sockfd : 소켓, recv_buffer : 데이터를 담을 버퍼, 버퍼의 크기, 0 : 기본 플래그, src_addr : 소스 주소를 저장할 구조체, addr_len : 소스 주소 크기를 저장할 변수
    if (data_size == -1) {
        // 받은 데이터가 없을 경우 또는 오류가 남
        if (errno == EAGAIN)
            perror("포트 필터링됨(타임아웃)");
        else
            perror("recvfrom 에러");
        return 0;
    }


    struct iphdr *recv_iph = (struct iphdr *)recv_buffer; // 소스 ip 헤더 파싱
    struct tcphdr *recv_tcph = (struct tcphdr *)(recv_buffer + (recv_iph->ihl * 4)); // 소스 tcp 헤더 파싱

    if (is_syn_ack(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port) {
        // syn/ack 패킷 확인 && syn패킷 출발 포트와 같은지 확인
        printf("포트 열림(SYN/ACK 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source)); // inet_ntoa 사람이 읽을 수 있는 문자열로 변환
        return 0;
    }
    if (is_rst_ack(recv_iph, recv_tcph) && ntohs(recv_tcph->dest) == src_port){
        printf("포트 닫힘(RST/ACK 패킷 받음 %s:%d)\n", inet_ntoa(*(struct in_addr *)&recv_iph->saddr), ntohs(recv_tcph->source));
        return 0;
    }




    close(sockfd);
    return 0;

}
