#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "threadpool.h"

void task_function(void *arg) {
    int num = *(int *)arg;
    printf("Task %d is being processed by thread %ld\n", num, pthread_self());
    sleep(1);  // 模拟任务处理时间
}

int main(int argc, char const *argv[]) {
    threadpool_t *pool;
    int num_tasks = 10;
    int task_args[num_tasks];

    // 创建线程池
    pool = threadpool_create(4, 10);
    if (pool == NULL) {
        fprintf(stderr, "Failed to create thread pool\n");
        return -1;
    }

    // 添加任务到线程池
    for (int i = 0; i < num_tasks; i++) {
        task_args[i] = i;
        if (threadpool_add(pool, task_function, &task_args[i]) != 0) {
            fprintf(stderr, "Failed to add task %d to thread pool\n", i);
        }
    }

    // 销毁线程池
    sleep(5);  // 等待所有任务完成
    if (threadpool_destroy(pool, 0) != 0) {
        fprintf(stderr, "Failed to destroy thread pool\n");
        return -1;
    }

    return 0;
}
