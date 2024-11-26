#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

// 스캔 함수 포인터 타입 정의
typedef void (*scan_func_t)(const char *, int, const char *, int, int);

// 스캔 함수 선언
void start_ack_scan(const char *, int, const char *, int, int);
void start_null_scan(const char *, int, const char *, int, int);
void start_fin_scan(const char *, int, const char *, int, int);
void start_syn_scan(const char *, int, const char *, int, int);
void start_xmas_scan(const char *, int, const char *, int, int);
void udp_scan(const char *, int *, int);

// 스캔 타입 매핑
typedef struct {
    const char *type;
    scan_func_t func;
} scan_mapping_t;

scan_mapping_t scan_mappings[] = {
    {"ack", start_ack_scan},
    {"null", start_null_scan},
    {"fin", start_fin_scan},
    {"syn", start_syn_scan},
    {"xmas", start_xmas_scan},
    {"tcp_connect", start_connect_scan},
    // UDP는 포트 리스트 기반
    {"udp", NULL},
};

#define NUM_SCAN_TYPES (sizeof(scan_mappings) / sizeof(scan_mapping_t))

int main(int argc, char *argv[]) {
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <scan_type> <src_ip> <src_port> <dst_ip> <start_port> <end_port> <time_limit>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *scan_type = argv[1];
    const char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    const char *dst_ip = argv[4];
    int start_port = atoi(argv[5]);
    int end_port = atoi(argv[6]);
    int time_limit = (argc > 7) ? atoi(argv[7]) : 3;

    // 스캔 함수 탐색
    scan_func_t scan_func = NULL;
    for (size_t i = 0; i < NUM_SCAN_TYPES; i++) {
        if (strcmp(scan_type, scan_mappings[i].type) == 0) {
            scan_func = scan_mappings[i].func;
            break;
        }
    }

    if (!scan_func) {
        fprintf(stderr, "Unsupported scan type: %s\n", scan_type);
        return EXIT_FAILURE;
    }

    // UDP 스캔 처리
    if (strcmp(scan_type, "udp") == 0) {
        int ports[65536];
        int port_count = 0;
        for (int p = start_port; p <= end_port; p++) {
            ports[port_count++] = p;
        }
        udp_scan(dst_ip, ports, port_count);
    } else {
        // 다른 스캔 수행
        scan_func(src_ip, src_port, dst_ip, start_port, time_limit);
    }

    // JSON 결과 생성 (예제)
    struct json_object *result = json_object_new_object();
    json_object_object_add(result, "scan_type", json_object_new_string(scan_type));
    json_object_object_add(result, "ip", json_object_new_string(dst_ip));
    json_object_object_add(result, "open", json_object_new_array()); // 실제 결과를 여기에 추가
    json_object_object_add(result, "scan_time", json_object_new_string("2024-11-26T15:00:00Z"));

    printf("%s\n", json_object_to_json_string_ext(result, JSON_C_TO_STRING_PRETTY));

    json_object_put(result); // 메모리 해제
    return EXIT_SUCCESS;
}
