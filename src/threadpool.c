#include "threadpool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 释放线程池资源
static void threadpool_free(threadpool_t *pool) {
    if (pool == NULL || pool->started > 0) {
        return;
    }

    if (pool->threads) {
        free(pool->threads);
        free(pool->task_queue);

        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->notify));
    }
    free(pool);
}

// 工作线程函数
static void *threadpool_thread(void *threadpool) {
    threadpool_t *pool = (threadpool_t *)threadpool;
    threadpool_task_t task;

    for (;;) {
        pthread_mutex_lock(&(pool->lock));

        while ((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if ((pool->shutdown == 1) || ((pool->shutdown == 2) && (pool->count == 0))) {
            break;
        }

        task.function = pool->task_queue[pool->head].function;
        task.arg = pool->task_queue[pool->head].arg;
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count -= 1;

        pthread_mutex_unlock(&(pool->lock));

        (*(task.function))(task.arg);
    }

    pool->started--;

    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
    return (NULL);
}

// 创建线程池
threadpool_t *threadpool_create(int thread_count, int queue_size) {
    threadpool_t *pool;
    int i;

    if ((pool = (threadpool_t *)malloc(sizeof(threadpool_t))) == NULL) {
        goto err;
    }

    pool->thread_count = 0;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = pool->started = 0;

    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    pool->task_queue = (threadpool_task_t *)malloc(sizeof(threadpool_task_t) * queue_size);

    if ((pthread_mutex_init(&(pool->lock), NULL) != 0) || (pthread_cond_init(&(pool->notify), NULL) != 0) ||
        (pool->threads == NULL) || (pool->task_queue == NULL)) {
        goto err;
    }

    for (i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_thread, (void *)pool) != 0) {
            threadpool_destroy(pool, 0);
            return NULL;
        }
        pool->thread_count++;
        pool->started++;
    }

    return pool;

err:
    if (pool) {
        threadpool_destroy(pool, 0);
    }
    return NULL;
}

// 添加任务到线程池
int threadpool_add(threadpool_t *pool, void (*function)(void *), void *arg) {
    int next, err = 0;

    if (pool == NULL || function == NULL) {
        return -1;
    }

    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return -1;
    }

    next = (pool->tail + 1) % pool->queue_size;

    do {
        if (pool->count == pool->queue_size) {
            err = -1;
            break;
        }

        if (pool->shutdown) {
            err = -1;
            break;
        }

        pool->task_queue[pool->tail].function = function;
        pool->task_queue[pool->tail].arg = arg;
        pool->tail = next;
        pool->count += 1;

        if (pthread_cond_signal(&(pool->notify)) != 0) {
            err = -1;
            break;
        }
    } while (0);

    if (pthread_mutex_unlock(&pool->lock) != 0) {
        err = -1;
    }

    return err;
}

// 销毁线程池
int threadpool_destroy(threadpool_t *pool, int flags) {
    int i, err = 0;

    if (pool == NULL) {
        return -1;
    }

    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return -1;
    }

    do {
        if (pool->shutdown) {
            err = -1;
            break;
        }

        pool->shutdown = (flags & 1) ? 2 : 1;

        if ((pthread_cond_broadcast(&(pool->notify)) != 0) || (pthread_mutex_unlock(&(pool->lock)) != 0)) {
            err = -1;
            break;
        }

        for (i = 0; i < pool->thread_count; i++) {
            if (pthread_join(pool->threads[i], NULL) != 0) {
                err = -1;
            }
        }
    } while (0);

    if (!err) {
        threadpool_free(pool);
    }

    return err;
}
