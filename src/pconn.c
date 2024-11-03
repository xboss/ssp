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

struct pconn_s {
    int id;
    pconn_type_t type;
    int is_secret;
    pconn_st_t st;
    stream_buf_t* snd_buf;
    stream_buf_t* rcv_buf;
    int ex;
    int can_write;
    uint64_t ctime;
    pconn_t* cp;
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

int pconn_init(int id, pconn_type_t type, int cp_id, stream_buf_t* snd_buf, stream_buf_t* rcv_buf) {
    if (id < 0 || (type != PCONN_TYPE_SERV && type != PCONN_TYPE_CLI)) return _ERR;
    if (type == PCONN_TYPE_CLI && (cp_id <= 0 || get_conn(cp_id) == NULL || get_conn(cp_id)->cp != NULL)) return _ERR;

    {
        /* TODO: debug */
        pconn_t* c = get_conn(id);
        assert(c == NULL);
    }

    pconn_t* _ALLOC(c, pconn_t*, sizeof(pconn_t));
    memset(c, 0, sizeof(pconn_t));
    c->id = id;
    c->type = type;
    c->ctime = mstime();
    c->snd_buf = snd_buf;
    c->rcv_buf = rcv_buf;
    c->can_write = 0;
    if (cp_id > 0) {
        c->cp = get_conn(cp_id);
    }
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
    if (c->snd_buf) {
        sb_free(c->snd_buf);
        c->snd_buf = NULL;
    }
    if (c->rcv_buf) {
        sb_free(c->rcv_buf);
        c->rcv_buf = NULL;
    }
    c->cp = NULL;
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
    c->st = status;
    return _OK;
}

pconn_st_t pconn_get_status(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    return c->st;
}

pconn_type_t pconn_get_type(int id) {
    _CHECK_PCONN_EXISTS(return PCONN_TYPE_NONE;)
    return c->type;
}

int pconn_get_couple_id(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (!c->cp) return _ERR;
    if (!pconn_is_couple(id, c->cp->id)) {
        return _ERR;
    }
    return c->cp->id;
}

/* int pconn_get_serv_id(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (!c->cp) return _ERR;
    assert(c->type == PCONN_TYPE_CLI);
    if (!pconn_is_couple(id, c->cp->id)) {
        return _ERR;
    }
    return c->cp->id;
}

int pconn_get_cli_id(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return _ERR;
    if (!c->cp) return _ERR;
    assert(c->type == PCONN_TYPE_SERV);
    if (!pconn_is_couple(id, c->cp->id)) {
        return _ERR;
    }
    return c->cp->id;
} */

int pconn_add_cli_id(int serv_id, int cli_id) {
    pconn_t* c = get_conn(serv_id);
    if (!c) return _ERR;
    pconn_t* cp = get_conn(cli_id);
    if (!cp) return _ERR;
    c->cp = cp;
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
    assert(c->snd_buf);
    return c->snd_buf;
}

stream_buf_t* pconn_get_rcv_buf(int id) {
    pconn_t* c = get_conn(id);
    if (!c) return NULL;
    assert(c->rcv_buf);
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

int pconn_is_couple(int id, int cp_id) {
    pconn_t* c = get_conn(id);
    if (!c) return 0;
    pconn_t* cp = get_conn(cp_id);
    if (!cp) return 0;
    if (c->cp != cp || cp->cp != c) {
        return 0;
    }
    return 1;
}

/* ----------test------------ */
/* int main(int argc, char const *argv[]) { return 0; } */
