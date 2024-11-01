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

#define _CHECK_PCONN_EXISTS(_code_block) \
    if (id <= 0) {                       \
        _code_block                      \
    }                                    \
    pconn_t* c = get_conn(id);           \
    if (!c) {                            \
        _code_block                      \
    }

typedef struct pconn_s pconn_t;

typedef struct {
    pconn_st_t fr_st;
    pconn_st_t bk_st;
    /* pconn_st_t st; */
    stream_buf_t* fr_snd_buf;
    stream_buf_t* fr_rcv_buf;
    stream_buf_t* bk_snd_buf;
    stream_buf_t* bk_rcv_buf;
    /*     pconn_t* fr;
        pconn_t* bk; */
    int ref_cnt;
} pconn_info_t;

struct pconn_s {
    int id;
    int cp_id;
    int is_secret;
    int is_packet;
    pconn_type_t type;
    int ex;
    int can_write;
    uint64_t ctime;
    /* uint64_t cp_ctime; */
    pconn_info_t* info;
    UT_hash_handle hh;
};

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
    assert(c == NULL);

    /* uint64_t cp_time = 0L; */
    pconn_info_t* info = NULL;
    if (type == PCONN_TYPE_BK) {
        pconn_t* cp = get_conn(cp_id);
        assert(cp);
        assert(cp->info);
        info = cp->info;
        /* info->bk = c; */
        /* cp_time = cp->ctime; */
    } else {
        _ALLOC(info, pconn_info_t*, sizeof(pconn_info_t));
        memset(info, 0, sizeof(pconn_info_t));
        /* info->fr = c; */
        info->fr_st = PCONN_ST_NONE;
        info->bk_st = PCONN_ST_NONE;
        /* info->st = PCONN_ST_NONE; */
        info->fr_rcv_buf = sb_init(NULL, 0);
        info->fr_snd_buf = sb_init(NULL, 0);
        info->bk_rcv_buf = sb_init(NULL, 0);
        info->bk_snd_buf = sb_init(NULL, 0);
    }

    _ALLOC(c, pconn_t*, sizeof(pconn_t));
    memset(c, 0, sizeof(pconn_t));
    c->id = id;
    c->type = type;
    c->ctime = mstime();
    c->info = info;
    info->ref_cnt++;
    c->can_write = 0;
    /* c->cp_ctime = cp_time; */
    HASH_ADD_INT(g_conn_tb, id, c);
    _LOG("pconn_init ok. id:%d", id);
    return _OK;
}

void pconn_free(int id) {
    if (id <= 0) return;
    pconn_t* c = get_conn(id);
    if (!c) {
        return;
    }
    if (c->info) {
        if (c->info->fr_snd_buf) {
            sb_free(c->info->fr_snd_buf);
            c->info->fr_snd_buf = NULL;
        }
        if (c->info->fr_rcv_buf) {
            sb_free(c->info->fr_rcv_buf);
            c->info->fr_rcv_buf = NULL;
        }
        if (c->info->bk_snd_buf) {
            sb_free(c->info->bk_snd_buf);
            c->info->bk_snd_buf = NULL;
        }
        if (c->info->bk_rcv_buf) {
            sb_free(c->info->bk_rcv_buf);
            c->info->bk_rcv_buf = NULL;
        }
        /*         if (c->type == PCONN_TYPE_FR) {
                    c->info->fr = NULL;
                }
                if (c->type == PCONN_TYPE_BK) {
                    c->info->bk = NULL;
                } */
        c->info->ref_cnt--;
        if (c->info->ref_cnt <= 0) {
            free(c->info);
            c->info = NULL;
        }
    }
    if (g_conn_tb) HASH_DEL(g_conn_tb, c);
    free(c);
    _LOG("pconn_free id:%d", id);
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

int pconn_set_status(int id, pconn_st_t status) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (c->type == PCONN_TYPE_FR)
        c->info->fr_st = status;
    else
        c->info->bk_st = status;
    return _OK;
}

pconn_st_t pconn_get_status(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    assert(c->info);
    if (c->type == PCONN_TYPE_FR) {
        return c->info->fr_st;
    }
    return c->info->bk_st;
}

pconn_type_t pconn_get_type(int id) {
    _CHECK_PCONN_EXISTS(return PCONN_TYPE_NONE;)
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
    pconn_t* c = get_conn(id);
    if (!c) return NULL;
    assert(c->info);
    if (c->type == PCONN_TYPE_FR) {
        return c->info->fr_snd_buf;
    }
    return c->info->bk_snd_buf;
}

stream_buf_t* pconn_get_rcv_buf(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return NULL;
    assert(c->info);
    if (c->type == PCONN_TYPE_FR) {
        return c->info->fr_rcv_buf;
    }
    return c->info->bk_rcv_buf;
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

int pconn_is_exist(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return 0;
    return 1;
}

int pconn_is_couple(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return 0;
    pconn_t* cp = get_conn(c->cp_id);
    if (!cp) return 0;
    if (c->info != cp->info) {
        return 0;
    }
    return 1;
}

/* ----------test------------ */
/* int main(int argc, char const *argv[]) { return 0; } */
