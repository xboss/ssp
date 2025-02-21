#ifndef _THREADPOOL_H
#define _THREADPOOL_H

#include <pthread.h>

// 任务结构体
typedef struct {
    void (*function)(void *arg);
    void *arg;
} threadpool_task_t;

// 线程池结构体
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    threadpool_task_t *task_queue;
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
    int started;
} threadpool_t;

// 创建线程池
threadpool_t *threadpool_create(int thread_count, int queue_size);

// 添加任务到线程池
int threadpool_add(threadpool_t *pool, void (*function)(void *), void *arg);

// 销毁线程池
int threadpool_destroy(threadpool_t *pool, int flags);

#endif /* _THREADPOOL_H */
