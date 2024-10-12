#include "ilist.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)        \
    _type(_p) = (_type)malloc((_size)); \
    if (!(_p)) {                        \
        perror("alloc error");          \
        exit(1);                        \
    }
#endif

typedef struct node_s {
    int i;
    struct node_s *next;
} node_t;

struct ilist_s {
    int size;
    node_t *head;
    node_t *tail;
};

int ilist_push(ilist_t *list, int i) {
    if (!list) return _ERR;
    _ALLOC(node, node_t *, sizeof(node_t));
    memset(node, 0, sizeof(node_t));
    node->i = i;
    if (list->size == 0) {
        list->head = list->tail = node;
    } else {
        list->tail->next = node;
        list->tail = list->tail->next;
    }
    list->size++;
    return _OK;
}

int ilist_pop(ilist_t *list, int *i) {
    if (!list) return _ERR;
    if (list->size == 0) return _ERR;
    *i = list->head->i;
    node_t *node = list->head;
    list->head = list->head->next;
    free(node);
    list->size--;
    if (list->size == 0) list->tail = NULL;
    return _OK;
}

int ilist_size(ilist_t *list) {
    if (!list) return 0;
    return list->size;
}

int ilist_exist(ilist_t *list, int i) {
    if (!list) return _ERR;
    int j, sz = list->size;
    node_t *node = list->head;
    for (j = 0; j < sz; j++) {
        assert(node);
        if (i == node->i) return _OK;
        node = list->head->next;
    }
    return _ERR;
}

ilist_t *ilist_init() {
    _ALLOC(list, ilist_t *, sizeof(ilist_t));
    memset(list, 0, sizeof(ilist_t));
    return list;
}

void ilist_free(ilist_t *list) {
    if (!list) return;
    int n, i, sz = ilist_size(list);
    for (i = 0; i < sz; i++) {
        ilist_pop(list, &n);
    }
    free(list);
}
