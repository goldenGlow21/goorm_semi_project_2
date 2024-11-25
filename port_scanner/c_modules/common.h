#ifndef COMMON_H
#define COMMON_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

// TCP 플래그 정의
#define SYN 1
#define FIN 2

// 공용 함수 선언

/**
 * 로우 소켓 생성 함수
 * @return 소켓 디스크립터
 */
int create_raw_socket();

/**
 * TCP 체크섬 계산 함수
 * @param b 체크섬을 계산할 데이터
 * @param len 데이터의 길이
 * @return 계산된 체크섬 값
 */
unsigned short checksum(void *b, int len);

/**
 * 소켓 옵션 설정 함수
 * @param sockfd 설정할 소켓 디스크립터
 */
void set_socket_options(int sockfd);

/**
 * 패킷 생성 함수
 * @param packet 생성된 패킷이 저장될 버퍼
 * @param src_ip 출발 IP 주소
 * @param src_port 출발 포트
 * @param dst_ip 대상 IP 주소
 * @param dst_port 대상 포트
 * @param flag TCP 플래그 (SYN, FIN 등)
 */
void create_packet(char *packet, const char *src_ip, int src_port, const char *dst_ip, int dst_port, int flag);

/**
 * 패킷 전송 함수
 * @param sockfd 송신에 사용할 소켓 디스크립터
 * @param packet 전송할 패킷
 * @param dst_ip 대상 IP 주소
 * @param dst_port 대상 포트
 */
void send_packet(int sockfd, char *packet, const char *dst_ip, int dst_port);

/**
 * TCP RST/ACK 확인 함수
 * @param iph 수신된 IP 헤더
 * @param tcph 수신된 TCP 헤더
 * @return RST/ACK 플래그가 설정되어 있는 경우 1, 그렇지 않으면 0
 */
int is_rst_ack(struct iphdr *iph, struct tcphdr *tcph);

#endif // COMMON_H