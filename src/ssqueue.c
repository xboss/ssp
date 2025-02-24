#include "ssqueue.h"

#include <stdio.h>
#include <stdlib.h>

#define INITIAL_CAPACITY 4

ssqueue_t* ssqueue_init() {
    ssqueue_t* queue = (ssqueue_t*)malloc(sizeof(ssqueue_t));
    if (!queue) return NULL;

    queue->data = (int*)malloc(INITIAL_CAPACITY * sizeof(int));
    if (!queue->data) {
        free(queue);
        return NULL;
    }

    queue->front = 0;
    queue->rear = -1;
    queue->size = 0;
    queue->capacity = INITIAL_CAPACITY;
    queue->hash_table = NULL;
    return queue;
}

int ssqueue_resize(ssqueue_t* queue, int new_capacity) {
    if (new_capacity < INITIAL_CAPACITY) {
        new_capacity = INITIAL_CAPACITY;
    }

    int* new_data = (int*)malloc(new_capacity * sizeof(int));
    if (!new_data) return -1;  // malloc failed, we do not change the original array

    for (int i = 0; i < queue->size; i++) {
        new_data[i] = queue->data[(queue->front + i) % queue->capacity];
    }

    free(queue->data);
    queue->data = new_data;
    queue->capacity = new_capacity;
    queue->front = 0;
    queue->rear = queue->size - 1;

    return 0;
}

int ssqueue_enqueue(ssqueue_t* queue, int item) {
    if (queue->size == queue->capacity) {
        if (ssqueue_resize(queue, queue->capacity * 2) != 0) {
            return -1;  // resize failed
        }
    }

    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->data[queue->rear] = item;
    queue->size++;

    // 添加到哈希表
    hash_entry_t* entry = (hash_entry_t*)malloc(sizeof(hash_entry_t));
    if (!entry) return -1;  // malloc failed
    entry->key = item;
    HASH_ADD_INT(queue->hash_table, key, entry);

    return 0;
}

int ssqueue_dequeue(ssqueue_t* queue, int* item) {
    if (queue->size == 0) {
        // printf("Queue is empty!\n");
        return -1;  // queue is empty
    }

    *item = queue->data[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size--;

    // 从哈希表中删除
    hash_entry_t* entry;
    HASH_FIND_INT(queue->hash_table, item, entry);
    if (entry) {
        HASH_DEL(queue->hash_table, entry);
        free(entry);
    }

    if (queue->size > 0 && queue->size <= queue->capacity / 4) {
        if (ssqueue_resize(queue, queue->capacity / 2) != 0) {
            return -1;  // resize failed
        }
    }

    return 0;
}

void ssqueue_print(ssqueue_t* queue) {
    if (queue->size == 0) {
        printf("Queue is empty!\n");
        return;
    }

    printf("Queue: ");
    for (int i = 0; i < queue->size; i++) {
        printf("%d ", queue->data[(queue->front + i) % queue->capacity]);
    }
    printf("\n");
}

void ssqueue_free(ssqueue_t* queue) {
    if (queue) {
        free(queue->data);

        // 释放哈希表
        hash_entry_t* entry;
        hash_entry_t* tmp;
        HASH_ITER(hh, queue->hash_table, entry, tmp) {
            HASH_DEL(queue->hash_table, entry);
            free(entry);
        }

        free(queue);
    }
}

int ssqueue_contains(ssqueue_t* queue, int item) {
    hash_entry_t* entry;
    HASH_FIND_INT(queue->hash_table, &item, entry);
    return entry != NULL;
}

void ssqueue_iterate(ssqueue_t* queue, int (*func)(int item)) {
    int i = 0;
    while (i < queue->size) {
        int item = queue->data[(queue->front + i) % queue->capacity];
        if (func(item)) {
            // 删除元素
            for (int j = i; j < queue->size - 1; j++) {
                queue->data[(queue->front + j) % queue->capacity] =
                    queue->data[(queue->front + j + 1) % queue->capacity];
            }
            queue->rear = (queue->rear - 1 + queue->capacity) % queue->capacity;
            queue->size--;

            // 从哈希表中删除
            hash_entry_t* entry;
            HASH_FIND_INT(queue->hash_table, &item, entry);
            if (entry) {
                HASH_DEL(queue->hash_table, entry);
                free(entry);
            }

            if (queue->size > 0 && queue->size <= queue->capacity / 4) {
                ssqueue_resize(queue, queue->capacity / 2);
            }
        } else {
            i++;
        }
    }
}
