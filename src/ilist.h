#ifndef _ISET_H
#define _ISET_H

typedef struct ilist_s ilist_t;

ilist_t *ilist_init();
void ilist_free(ilist_t *list);
int ilist_size(ilist_t *list);
int ilist_exist(ilist_t *list, int i);
int ilist_push(ilist_t *list, int i);
int ilist_pop(ilist_t *list, int *i);

#endif /* ISET_H */
