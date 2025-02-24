// #include <stdio.h>
// #include <stdlib.h>

// #include "ssqueue.h"

// int print_and_remove_even(int item) {
//     printf("Item: %d\n", item);
//     return item % 2 == 0;  // 删除偶数元素
// }

// int main() {
//     ssqueue_t* queue = ssqueue_init();
//     if (!queue) {
//         fprintf(stderr, "Failed to create queue\n");
//         return -1;
//     }

//     // 测试空队列出队操作
//     int item;
//     if (ssqueue_dequeue(queue, &item) != 0) {
//         printf("Queue is empty, cannot dequeue\n");
//     }

//     // 测试入队操作
//     if (ssqueue_enqueue(queue, 11) != 0) {
//         fprintf(stderr, "Failed to enqueue 11\n");
//     }
//     if (ssqueue_enqueue(queue, 22) != 0) {
//         fprintf(stderr, "Failed to enqueue 22\n");
//     }
//     if (ssqueue_enqueue(queue, 33) != 0) {
//         fprintf(stderr, "Failed to enqueue 33\n");
//     }
//     if (ssqueue_enqueue(queue, 44) != 0) {
//         fprintf(stderr, "Failed to enqueue 44\n");
//     }

//     // 打印队列
//     ssqueue_print(queue);  // 输出: Queue: 11 22 33 44

//     // 测试查询元素是否在队列中
//     printf("Contains 22: %d\n", ssqueue_contains(queue, 22));  // 输出: Contains 22: 1
//     printf("Contains 55: %d\n", ssqueue_contains(queue, 55));  // 输出: Contains 55: 0

//     // 测试出队操作
//     if (ssqueue_dequeue(queue, &item) == 0) {
//         printf("Dequeued: %d\n", item);  // 输出: Dequeued: 11
//     } else {
//         fprintf(stderr, "Failed to dequeue\n");
//     }
//     if (ssqueue_dequeue(queue, &item) == 0) {
//         printf("Dequeued: %d\n", item);  // 输出: Dequeued: 22
//     } else {
//         fprintf(stderr, "Failed to dequeue\n");
//     }

//     // 打印队列
//     ssqueue_print(queue);  // 输出: Queue: 33 44

//     // 测试自动扩展和收缩
//     if (ssqueue_enqueue(queue, 55) != 0) {
//         fprintf(stderr, "Failed to enqueue 55\n");
//     }
//     if (ssqueue_enqueue(queue, 66) != 0) {
//         fprintf(stderr, "Failed to enqueue 66\n");
//     }
//     if (ssqueue_enqueue(queue, 77) != 0) {
//         fprintf(stderr, "Failed to enqueue 77\n");
//     }
//     if (ssqueue_enqueue(queue, 88) != 0) {
//         fprintf(stderr, "Failed to enqueue 88\n");
//     }

//     // 打印队列
//     ssqueue_print(queue);  // 输出: Queue: 33 44 55 66 77 88

//     // 测试迭代遍历队列并删除偶数元素
//     printf("Iterating over queue and removing even items:\n");
//     ssqueue_iterate(queue, print_and_remove_even);

//     // 打印队列
//     ssqueue_print(queue);  // 输出: Queue: 33 55 77

//     // 测试再次入队和出队操作
//     if (ssqueue_enqueue(queue, 99) != 0) {
//         fprintf(stderr, "Failed to enqueue 99\n");
//     }
//     if (ssqueue_dequeue(queue, &item) == 0) {
//         printf("Dequeued: %d\n", item);  // 输出: Dequeued: 33
//     } else {
//         fprintf(stderr, "Failed to dequeue\n");
//     }

//     // 打印队列
//     ssqueue_print(queue);  // 输出: Queue: 55 77 99

//     // 测试队列释放
//     ssqueue_free(queue);
//     printf("Queue freed\n");

//     return 0;
// }
