#include "common.h"

#define MAX_THREADS 16

void task(void *arg);

void start_connect_scan(const char *dst_ip, int dst_port)
{

    // printf("start_connect_scan %d\n", dst_port);
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
    // else
    //     printf("포트 닫힘(tcp connection 실패) %s:%d", dst_ip, dst_port);

    close(sockfd);
}


int main() {
    GHashTable *set = g_hash_table_new(g_direct_hash, g_direct_equal);
    clock_t start = clock(), finish;
    double duration;
    threadpool thpool = thpool_init(MAX_THREADS);
    int start_port = 1;
    int end_port = 8080;
    int i = start_port;

    srand(time(NULL));
    while (i <= end_port) {
        int port = rand() % (end_port - start_port + 1) + start_port;

        if (g_hash_table_contains(set, GINT_TO_POINTER(port)))
            continue;

        g_hash_table_add(set, GINT_TO_POINTER(port));

        thpool_add_work(thpool, task, (void *)(intptr_t)port);
        i++;
    }

    thpool_wait(thpool);
    thpool_destroy(thpool);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("duration: %fsec\n", duration);

    g_hash_table_destroy(set);
    return 0;
}

void task(void *arg) {
    start_connect_scan("192.168.79.3", (intptr_t)arg);
}