#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns_resolver.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sslog.h"
#include "thread_pool.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_type, _size) (_type) malloc((_size))
#endif

#ifndef _CHECK_ALLOC
#define _CHECK_ALLOC(_p, _code_block)    \
    if (!(_p)) {                         \
        perror("allocate memory error"); \
        _code_block                      \
    }
#endif

struct domain_req_s {
    int id;
    int resp; /* 0:ok; -1:error */
    char *name;

    char ip[INET_ADDRSTRLEN + 1];
    unsigned short port;
    struct addrinfo *addrinfo;
    domain_cb_t cb;
    void *userdata;
    struct domain_req_s *next;
};

/* ------ dns resolver ------ */

static int g_pipefd[2] = {-1, -1};
static threadpool_t *g_threadpool = NULL;
static domain_req_t *g_req_queue_head = NULL;
static int g_req_queue_size = 0;
static pthread_mutex_t g_lock;

static int notify() {
    _LOG("dns notify g_pipefd %d ", g_pipefd[0]);
    assert(g_pipefd[0] > 0);
    int r, len = 1;
    const char *buf = "";
    do r = write(g_pipefd[1], buf, len);
    while (r == -1 && errno == EINTR);
    if (r == len) return _OK;
    if ((r == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        perror("notify EAGAIN in dns.");
        return _ERR;
    }
    perror("notify error in dns.");
    return _ERR;
}

static void worker(void *arg) {
    if (!arg) {
        _LOG_E("worker's arg is NULL in dns resolver.");
        return;
    }
    domain_req_t *req = (domain_req_t *)arg;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; /* TODO: AF_INET or AF_INET6 or AF_UNSPEC(ipv4 and ipv6) */
    hints.ai_socktype = SOCK_STREAM;
    /* assert(req->name); */
    req->resp = _OK;
    int ret = getaddrinfo(req->name, NULL, &hints, &req->addrinfo);
    if (ret != 0) {
        _LOG_E("getaddrinfo error: %s", gai_strerror(ret));
        req->resp = _ERR;
    }
    if (ret == 0 &&
        !inet_ntop(AF_INET, &(((struct sockaddr_in *)(req->addrinfo->ai_addr))->sin_addr), req->ip, INET_ADDRSTRLEN)) {
        perror("inet_ntop in dns resolver.");
        req->resp = _ERR;
    }
    freeaddrinfo(req->addrinfo);
    req->addrinfo = NULL;
    assert(req->next == NULL);
    /* lock and put req */
    pthread_mutex_lock(&g_lock);
    if (g_req_queue_head == NULL) {
        g_req_queue_head = req;
    } else {
        req->next = g_req_queue_head;
        g_req_queue_head = req;
    }
    g_req_queue_size++;
    pthread_mutex_unlock(&g_lock);
    _LOG("dns worker tid:%lu id:%d  name:%p req:%p", req->id, pthread_self(), req->name, req);
    if (notify() != _OK) {
        _LOG("notify failled in dns.");
        /* remove req */
        domain_req_t *req_t = NULL;
        domain_req_t *req_last = NULL;
        pthread_mutex_lock(&g_lock);
        for (req_t = g_req_queue_head; req_t != NULL; req_t = req_t->next) {
            if (req_t->id == req->id) {
                if (req_last) {
                    req_last->next = req_t->next;
                } else {
                    g_req_queue_head = NULL;
                }
                g_req_queue_size--;
                _LOG("dns worker notify failled and remove req. tid:%lu id:%d name:%p req:%p", pthread_self(), req->id,
                     req->name, req);
                break;
            }
            req_last = req_t;
        }
        pthread_mutex_unlock(&g_lock);
        free_domain_req(req);
    }
}

static int ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud) {
    int r;
    char buf[1024];
    for (;;) {
        r = read(fd, buf, sizeof(buf));
        if (r == sizeof(buf)) continue;
        if (r != -1) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        perror("read from pipe error in dns.");
    }
    /* get req */
    domain_req_t *req_q = NULL;
    if (g_req_queue_size > 0) {
        pthread_mutex_lock(&g_lock);
        if (g_req_queue_size > 0) {
            req_q = g_req_queue_head;
            g_req_queue_size = 0;
            g_req_queue_head = NULL;
        }
        pthread_mutex_unlock(&g_lock);
    }
    if (req_q) {
        domain_req_t *req_tmp = NULL;
        while (req_q != NULL) {
            _LOG("dns ssev_cb tid:%lu name:%p req:%p", pthread_self(), req_q->name, req_q);
            req_q->cb(req_q);
            req_tmp = req_q;
            req_q = req_q->next;
            free_domain_req(req_tmp);
        }
        assert(req_q == NULL);
    }
    return _OK;
}

/* ========== API ========== */

int init_domain_resolver(ssev_loop_t *loop) {
    /* if (!loop) return _ERR; */

    /* init pipe */
    if (pipe(g_pipefd) == -1) {
        perror("pipe");
        return _ERR;
    }
    ssev_set_nonblocking(g_pipefd[0]);
    ssev_set_nonblocking(g_pipefd[1]);
    _LOG("dns g_pipefd %d %d", g_pipefd[0], g_pipefd[1]);
    /* init thread pool */
    g_threadpool = threadpool_init(4, 1024);
    if (!g_threadpool) {
        _LOG("init thread pool error.");
        close(g_pipefd[0]);
        close(g_pipefd[1]);
        g_pipefd[0] = -1;
        g_pipefd[1] = -1;
        return _ERR;
    }
    if (pthread_mutex_init(&g_lock, NULL) != 0) {
        _LOG("pthread_mutex_init error.");
        threadpool_destroy(g_threadpool);
        close(g_pipefd[0]);
        close(g_pipefd[1]);
        g_pipefd[0] = -1;
        g_pipefd[1] = -1;
    }
    /* ssev_watch */
    if (ssev_watch(loop, SSEV_EV_READ, g_pipefd[0], ssev_cb) != 0) {
        _LOG("ssev watch error. %d", g_pipefd[0]);
        threadpool_destroy(g_threadpool);
        close(g_pipefd[0]);
        close(g_pipefd[1]);
        g_pipefd[0] = -1;
        g_pipefd[1] = -1;
        pthread_mutex_destroy(&g_lock);
        return _ERR;
    }
    _LOG("init domain resolver ok.");
    return _OK;
}

void free_domain_resolver(ssev_loop_t *loop) {
    if (g_threadpool) {
        threadpool_destroy(g_threadpool);
    }
    ssev_unwatch(loop, SSEV_EV_ALL, g_pipefd[0]);
    if (g_pipefd[0] != -1) {
        close(g_pipefd[0]);
        g_pipefd[0] = -1;
    }
    if (g_pipefd[1] != -1) {
        close(g_pipefd[1]);
        g_pipefd[1] = -1;
    }
    if (g_req_queue_size > 0) {
        _LOG("dns free domain resolver req queue size:%d", g_req_queue_size);
        domain_req_t *req = NULL;
        for (req = g_req_queue_head; req != NULL; req = req->next) {
            free_domain_req(req);
            g_req_queue_size--;
        }
        assert(g_req_queue_size == 0);
    }
    pthread_mutex_destroy(&g_lock);
    _LOG("dns free domain resolver ok.");
}

/* TODO: ipv6 */
int resolve_domain(domain_req_t *req) {
    if (!req) {
        return _ERR;
    }
    /* add to threadpool */
    threadpool_add_task(g_threadpool, worker, req);
    _LOG("resolve_domain add task id:%d name:%s", req->id, req->name);
    return _OK;
}

domain_req_t *init_domain_req(int id, const char *name, int name_len, domain_cb_t cb, unsigned short port,
                              void *userdata) {
    if (id < 0 || !name || !cb) return NULL;
    domain_req_t *req = _ALLOC(domain_req_t *, sizeof(domain_req_t));
    _CHECK_ALLOC(req, return NULL;)
    memset(req, 0, sizeof(domain_req_t));
    req->name = _ALLOC(char *, name_len + 1);
    _CHECK_ALLOC(req, {
        free(req);
        return NULL;
    })
    memcpy(req->name, name, name_len);
    req->name[name_len] = '\0';
    req->cb = cb;
    req->id = id;
    req->port = port;
    req->userdata = userdata;
    req->next = NULL;
    _LOG("init_domain_req: tid:%lu name:%p req:%p", pthread_self(), req->name, req);
    return req;
}

void free_domain_req(domain_req_t *req) {
    if (!req) {
        return;
    }
    if (req->name) {
        free(req->name);
        req->name = NULL;
    }
    if (req->addrinfo) {
        freeaddrinfo(req->addrinfo);
        req->addrinfo = NULL;
    }
    _LOG("dns free domain req ok. %d", req->id);
    free(req);
}

int get_domain_req_id(domain_req_t *req) {
    if (!req) return _ERR;
    return req->id;
}

int get_domain_req_resp(domain_req_t *req) {
    if (!req) return _ERR;
    return req->resp;
}

char *get_domain_req_name(domain_req_t *req) {
    if (!req) return NULL;
    return req->name;
}

char *get_domain_req_ip(domain_req_t *req) {
    if (!req) return NULL;
    return req->ip;
}

void *get_domain_req_userdata(domain_req_t *req) {
    if (!req) return NULL;
    return req->userdata;
}

unsigned short get_domain_req_port(domain_req_t *req) {
    if (!req) return _ERR;
    return req->port;
}