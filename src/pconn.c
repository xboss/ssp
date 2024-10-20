#include "pconn.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sslog.h"
#include "uthash.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define _FREE_PCONN_ITEM                   \
    sb_free(c->snd_buf);                   \
    c->snd_buf = NULL;                     \
    sb_free(c->rcv_buf);                   \
    c->rcv_buf = NULL;                     \
    if (g_conn_tb) HASH_DEL(g_conn_tb, c); \
    free(c);                               \
    c = NULL

#define _CHECK_PCONN_EXISTS(_code_block) \
    if (id <= 0) {                       \
        _code_block                      \
    }                                    \
    pconn_t *c = NULL;                   \
    HASH_FIND_INT(g_conn_tb, &id, c);    \
    if (!c) {                            \
        _code_block                      \
    }

struct pconn_s {
    int id;
    int cp_id;
    int is_secret;
    int is_packet;
    int status;
    int type;
    int ex;
    int can_write;
    uint64_t ctime;
    stream_buf_t *snd_buf;
    stream_buf_t *rcv_buf;
    UT_hash_handle hh;
};
typedef struct pconn_s pconn_t;

static pconn_t *g_conn_tb = NULL;

int pconn_init(int id, int type, uint64_t ctime) {
    if (id < 0 || (type != PCONN_TYPE_FR && type != PCONN_TYPE_BK)) {
        return _ERR;
    }

    /* TODO: debug */
    pconn_t *c = NULL;
    HASH_FIND_INT(g_conn_tb, &id, c);
    if (c) {
        _LOG_E("pconn_init conn exsits, fd:%d cp_id:%d type:%d status:%d", c->id, c->cp_id, c->type, c->status);
    }

    _ALLOC(c, pconn_t *, sizeof(pconn_t));
    memset(c, 0, sizeof(pconn_t));
    c->id = id;
    c->type = type;
    c->ctime = ctime;
    c->rcv_buf = sb_init(NULL, 0);
    c->snd_buf = sb_init(NULL, 0);
    HASH_ADD_INT(g_conn_tb, id, c);
    _LOG("pconn_init ok. id:%d", id);
    return _OK;
}

void pconn_free(int id /* , int cp_id */) {
    if (id <= 0) return;
    pconn_t *c = NULL;
    HASH_FIND_INT(g_conn_tb, &id, c);
    if (c) {
        /* if (cp_id <= 0) cp_id = c->cp_id; */
        /* assert(cp_id == c->cp_id); */
        _FREE_PCONN_ITEM;
        _LOG("pconn_free id:%d", id);
    }
    /*     if (cp_id <= 0) {
            return;
        }
        HASH_FIND_INT(g_conn_tb, &cp_id, c);
        if (c) {
            assert(id == c->cp_id);
            _FREE_PCONN_ITEM;
            _LOG("pconn_free cp_id:%d", cp_id);
        }
    _LOG("pconn_free ok. id:%d cp_id:%d", id, cp_id);
    */
}

void pconn_free_all(void *u, void (*fn)(int id, void *u)) {
    if (!g_conn_tb) return;
    pconn_t *c, *tmp;
    HASH_ITER(hh, g_conn_tb, c, tmp) {
        fn(c->id, u);
        pconn_free(c->id);
    }
    g_conn_tb = NULL;
    _LOG("pconn_free_all ok.");
}

int pconn_get_type(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->type;
}

int pconn_get_couple_id(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->cp_id;
}

int pconn_set_couple_id(int id, int cp_id) {
    if (cp_id <= 0) return _ERR;
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->cp_id = cp_id;
    return _OK;
}

int pconn_get_status(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->status;
}

int pconn_set_status(int id, int status) {
    if (status != PCONN_ST_OFF && status != PCONN_ST_READY && status != PCONN_ST_ON && status != PCONN_ST_WAIT) {
        return _ERR;
    }
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->status = status;
    return _OK;
}

int pconn_get_ex(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->ex;
}

int pconn_set_ex(int id, int ex) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->ex = ex;
    return _OK;
}

stream_buf_t *pconn_get_snd_buf(int id) {
    _CHECK_PCONN_EXISTS(return NULL;)
    return c->snd_buf;
}

stream_buf_t *pconn_get_rcv_buf(int id) {
    _CHECK_PCONN_EXISTS(return NULL;)
    return c->rcv_buf;
}

int pconn_can_write(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->can_write;
}

int pconn_set_can_write(int id, int can_write) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->can_write = can_write;
    return _OK;
}

int pconn_is_secret(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->is_secret;
}

int pconn_set_is_secret(int id, int is_secret) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->is_secret = is_secret;
    return _OK;
}

int pconn_is_packet(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->is_packet;
}

int pconn_set_is_packet(int id, int is_packet) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->is_packet = is_packet;
    return _OK;
}

uint64_t pconn_get_ctime(int id) {
    _CHECK_PCONN_EXISTS(return 0lu;)
    return c->ctime;
}

/* ----------test------------ */
/* int main(int argc, char const *argv[]) { return 0; } */
