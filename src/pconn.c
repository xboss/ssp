#include "pconn.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

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
    if (c->snd_buf) {                      \
        sb_free(c->snd_buf);               \
        c->snd_buf = NULL;                 \
    }                                      \
    if (c->rcv_buf) {                      \
        sb_free(c->rcv_buf);               \
        c->rcv_buf = NULL;                 \
    }                                      \
    if (c->wait_buf) {                     \
        sb_free(c->wait_buf);              \
        c->wait_buf = NULL;                \
    }                                      \
    if (c->status) {                       \
        free(c->status);                   \
        c->status = NULL;                  \
    }                                      \
    if (g_conn_tb) HASH_DEL(g_conn_tb, c); \
    free(c);                               \
    c = NULL

#define _CHECK_PCONN_EXISTS(_code_block) \
    if (id <= 0) {                       \
        _code_block                      \
    }                                    \
    pconn_t* c = get_conn(id);           \
    if (!c) {                            \
        _code_block                      \
    }

typedef struct {
    pconn_st_t fr_st;
    pconn_st_t bk_st;
    pconn_st_t st;
} status_t;

struct pconn_s {
    int id;
    int cp_id;
    int is_secret;
    int is_packet;
    status_t* status;
    pconn_type_t type;
    int ex;
    int can_write;
    uint64_t ctime;
    stream_buf_t* snd_buf;
    stream_buf_t* rcv_buf;
    stream_buf_t* wait_buf;
    UT_hash_handle hh;
};
typedef struct pconn_s pconn_t;

static pconn_t* g_conn_tb = NULL;

static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

static pconn_t* get_conn(int id) {
    if (id < 0) return NULL;
    pconn_t* c = NULL;
    HASH_FIND_INT(g_conn_tb, &id, c);
    return c;
}

int pconn_init(int id, pconn_type_t type, int cp_id) {
    if (id < 0 || (type != PCONN_TYPE_FR && type != PCONN_TYPE_BK)) {
        return _ERR;
    }
    /* TODO: debug */
    pconn_t* c = get_conn(id);
    if (c) {
        _LOG_E("pconn_init conn exsits, fd:%d cp_id:%d type:%d status:%d", c->id, c->cp_id, c->type, c->status);
    }

    status_t* status = NULL;
    if (type == PCONN_TYPE_BK) {
        pconn_t* cp = get_conn(cp_id);
        assert(cp);
        assert(cp->status);
        status = cp->status;
    } else {
        _ALLOC(status, status_t*, sizeof(status_t));
    }
    status->fr_st = PCONN_ST_NONE;
    status->bk_st = PCONN_ST_NONE;
    status->st = PCONN_ST_NONE;

    _ALLOC(c, pconn_t*, sizeof(pconn_t));
    memset(c, 0, sizeof(pconn_t));
    c->id = id;
    c->type = type;
    c->ctime = mstime();
    c->rcv_buf = sb_init(NULL, 0);
    c->snd_buf = sb_init(NULL, 0);
    c->wait_buf = sb_init(NULL, 0);
    c->status = status;
    HASH_ADD_INT(g_conn_tb, id, c);
    _LOG("pconn_init ok. id:%d", id);
    return _OK;
}

void pconn_free(int id /* , int cp_id */) {
    if (id <= 0) return;
    pconn_t* c = get_conn(id);
    if (c) {
        pconn_t* cp = get_conn(c->cp_id);
        if (cp) cp->status = NULL;
        _FREE_PCONN_ITEM;
        _LOG("pconn_free id:%d", id);
    }
}

void pconn_free_all(void* u, void (*fn)(int id, void* u)) {
    if (!g_conn_tb) return;
    pconn_t *c, *tmp;
    HASH_ITER(hh, g_conn_tb, c, tmp) {
        fn(c->id, u);
        pconn_free(c->id);
    }
    g_conn_tb = NULL;
    _LOG("pconn_free_all ok.");
}

pconn_st_t pconn_chg_status(int id, pconn_st_t status) {
    pconn_t* c = get_conn(id);
    if (!c) return PCONN_ST_NONE;
    if (c->type == PCONN_TYPE_FR)
        c->status->fr_st = status;
    else
        c->status->bk_st = status;

    if (c->status->fr_st == PCONN_ST_OFF || c->status->bk_st == PCONN_ST_OFF) {
        c->status->st = PCONN_ST_OFF;
    } else if (c->status->fr_st == PCONN_ST_WAIT) {
        c->status->st = PCONN_ST_WAIT;
        assert(c->status->bk_st == PCONN_ST_NONE);
    } else if (c->status->bk_st == PCONN_ST_READY) {
        c->status->st = PCONN_ST_READY;
        assert(c->status->fr_st == PCONN_ST_ON);
    } else {
        c->status->st = PCONN_ST_ON;
        /* assert((c->status->fr_st == PCONN_ST_ON && c->status->bk_st == PCONN_ST_ON) ||
               (c->status->fr_st == PCONN_ST_ON && c->status->bk_st == PCONN_ST_READY)); */
    }
    return c->status->st;
}

pconn_st_t pconn_get_status(int id) {
    _CHECK_PCONN_EXISTS(return PCONN_ST_OFF;)
    assert(c->status);
    return c->status->st;
}

pconn_type_t pconn_get_type(int id) {
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

int pconn_get_ex(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->ex;
}

int pconn_set_ex(int id, int ex) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->ex = ex;
    return _OK;
}

stream_buf_t* pconn_get_snd_buf(int id) {
    _CHECK_PCONN_EXISTS(return NULL;)
    if (!c->snd_buf) c->snd_buf = sb_init(NULL, 0);
    return c->snd_buf;
}

int pconn_set_snd_buf(int id, stream_buf_t* sb) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (c->snd_buf) {
        sb_free(c->snd_buf);
        c->snd_buf = NULL;
    }
    c->snd_buf = sb;
    return _OK;
}

stream_buf_t* pconn_get_rcv_buf(int id) {
    _CHECK_PCONN_EXISTS(return NULL;)
    if (!c->rcv_buf) c->rcv_buf = sb_init(NULL, 0);
    return c->rcv_buf;
}

stream_buf_t* pconn_get_wait_buf(int id) {
    _CHECK_PCONN_EXISTS(return NULL;)
    if (!c->wait_buf) c->wait_buf = sb_init(NULL, 0);
    return c->wait_buf;
}

int pconn_set_wait_buf(int id, stream_buf_t* sb) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (c->wait_buf) {
        sb_free(c->wait_buf);
        c->wait_buf = NULL;
    }
    c->wait_buf = sb;
    return _OK;
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

/* int pconn_is_packet(int id) {
    _CHECK_PCONN_EXISTS(return 0;)
    return c->is_packet;
} */

/* int pconn_set_is_packet(int id, int is_packet) {
    _CHECK_PCONN_EXISTS(return _ERR;)
    c->is_packet = is_packet;
    return _OK;
} */

uint64_t pconn_get_ctime(int id) {
    _CHECK_PCONN_EXISTS(return 0lu;)
    return c->ctime;
}

int pconn_send(int id, const char* buf, int len) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    assert(c->snd_buf);
    int rt = sb_write(c->snd_buf, buf, len);
    assert(rt == _OK);
    return _OK;
}

int pconn_rcv(int id, const char* buf, int len) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    assert(c->rcv_buf);
    int rt = sb_write(c->rcv_buf, buf, len);
    assert(rt == _OK);
    return _OK;
}

int pconn_wait(int id, const char* buf, int len) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    assert(c->wait_buf);
    int rt = sb_write(c->wait_buf, buf, len);
    assert(rt == _OK);
    return _OK;
}

int pconn_is_exist(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return 0;
    return 1;
}

/* ----------test------------ */
/* int main(int argc, char const *argv[]) { return 0; } */
