#include "thread_pool.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _OK 0
#define _ERR -1

#define MAX_TASKS 1024
#define DEF_NUM_THREADS 4

typedef struct {
    void (*cb)(void *);
    void *arg;
} task_t;

struct threadpool_s {
    pthread_t *threads;
    task_t *task_queue;
    int task_front, task_rear, task_cnt, max_tasks;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int shutdown;
    int num_threads;
};

static void *worker(void *arg) {
    threadpool_t *pool = (threadpool_t *)arg;
    task_t task;
    while (1) {
        pthread_mutex_lock(&pool->lock);
        while (pool->task_cnt == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->cond, &pool->lock);
        }
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
        }
        task = pool->task_queue[pool->task_front];
        pool->task_front = (pool->task_front + 1) % pool->max_tasks;
        pool->task_cnt--;
        pthread_mutex_unlock(&pool->lock);
        task.cb(task.arg);
    }
}

threadpool_t *threadpool_init(int num_threads, int max_tasks) {
    threadpool_t *pool = (threadpool_t *)malloc(sizeof(threadpool_t));
    if (!pool) {
        perror("alloc error");
        return NULL;
    }
    if (num_threads <= 0) num_threads = DEF_NUM_THREADS;
    if (max_tasks <= 0) max_tasks = MAX_TASKS;
    pool->threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    if (!pool->threads) {
        perror("alloc error");
        free(pool);
        return NULL;
    }
    pool->task_queue = (task_t *)malloc(max_tasks * sizeof(task_t));
    if (!pool->task_queue) {
        perror("alloc error");
        free(pool->threads);
        free(pool);
        return NULL;
    }
    pool->task_front = pool->task_rear = pool->task_cnt = 0;
    pool->shutdown = 0;
    pool->num_threads = num_threads;
    pool->max_tasks = max_tasks;
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->cond, NULL);
    int i;
    for (i = 0; i < num_threads; i++) {
        printf("create thread %d\n", i);
        pthread_create(&pool->threads[i], NULL, worker, pool);
    }
    return pool;
}

void threadpool_add_task(threadpool_t *pool, void (*cb)(void *), void *arg) {
    pthread_mutex_lock(&pool->lock);
    if (pool->task_cnt == pool->max_tasks) {
        printf("Task queue is full\n");
        pthread_mutex_unlock(&pool->lock);
        return;
    }
    pool->task_queue[pool->task_rear].cb = cb;
    pool->task_queue[pool->task_rear].arg = arg;
    pool->task_rear = (pool->task_rear + 1) % pool->max_tasks;
    pool->task_cnt++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
}

void threadpool_destroy(threadpool_t *pool) {
    if (!pool) {
        return;
    }
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->cond);
    int i;
    for (i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    if (pool->threads) {
        free(pool->threads);
        pool->threads = NULL;
    }
    if (pool->task_queue) {
        free(pool->task_queue);
        pool->task_queue = NULL;
    }
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->cond);
    free(pool);
    printf("destroy threadpool ok.\n");
}