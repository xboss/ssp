#ifndef _SSQUEUE_H
#define _SSQUEUE_H

#include "uthash.h"

typedef struct {
    int* data;
    int front;
    int rear;
    int size;
    int capacity;
    struct hash_entry* hash_table;  // 哈希表
} ssqueue_t;

typedef struct hash_entry {
    int key;
    UT_hash_handle hh;
} hash_entry_t;

// 初始化队列
ssqueue_t* ssqueue_init();

// 调整队列大小
int ssqueue_resize(ssqueue_t* queue, int new_capacity);

// 入队
int ssqueue_enqueue(ssqueue_t* queue, int item);

// 出队
int ssqueue_dequeue(ssqueue_t* queue, int* item);

// 打印队列
void ssqueue_print(ssqueue_t* queue);

// 释放队列
void ssqueue_free(ssqueue_t* queue);

// 查询元素是否在队列中
int ssqueue_contains(ssqueue_t* queue, int item);

// 迭代遍历队列
void ssqueue_iterate(ssqueue_t* queue, int (*func)(int item));

#endif /* _SSQUEUE_H */
