#include "common.h"


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
    int start_port = 1; // 수정 필요
    int end_port = 8080; // 수정 필요
    GHashTable *set = g_hash_table_new(g_direct_hash, g_direct_equal);
    clock_t start = clock(), finish;
    double duration;
    threadpool thpool = thpool_init(MAX_THREADS);
    int i = start_port;
    srand(time(NULL));
    while (i <= end_port) {
        info *arg = malloc(sizeof(info));
        if (!arg) {
            perror("메모리 할당 실패");
            exit(1);
        }
        arg->dst_ip = "192.168.79.3"; // 수정 필요
        arg->dst_port = rand() % (end_port - start_port + 1) + start_port;
        if (g_hash_table_contains(set, GINT_TO_POINTER(arg->dst_port)))
            continue;
        g_hash_table_add(set, GINT_TO_POINTER(arg->dst_port));

        thpool_add_work(thpool, task, (void *)arg);
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
    info *task_arg = arg;
    start_connect_scan(task_arg->dst_ip, task_arg->dst_port);
    free(arg);
}