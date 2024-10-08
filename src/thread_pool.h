#ifndef _THREAD_POOL_H
#define _THREAD_POOL_H

typedef struct threadpool_s threadpool_t;
threadpool_t * threadpool_init(int num_threads, int max_tasks);
void threadpool_add_task(threadpool_t *pool, void (*cb)(void *), void *arg);
void threadpool_destroy(threadpool_t *pool);

#endif /* THREAD_POOL_H */