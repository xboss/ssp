#if (defined(__linux__) || defined(__linux))

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "ssev.h"
#include "sslog.h"
#include "uthash.h"

#define SSEV_OK 0
#define SSEV_ERR -1

#define LISTEN_BACKLOG (128)
#define EPOLL_SIZE (256)
#define MAX_EVENTS (128)
#define DEF_EV_TIMEOUT (1000)
#define DEF_EPOLL_MODE EPOLLET
/* #define DEF_MAX_WATCHERS (128) */

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

#define IS_NOT_SSEV_EVENT_TYPE(_event) \
    (((_event) & SSEV_EV_READ) != SSEV_EV_READ && ((_event) & SSEV_EV_WRITE) != SSEV_EV_WRITE)

struct ssev_watcher_s {
    int fd;
    unsigned int events;
    ssev_cb_t ssev_cb;
    void *userdata;
    UT_hash_handle hh;
};
typedef struct ssev_watcher_s ssev_watcher_t;

struct ssev_loop_s {
    int efd;
    int is_looping;
    int timeout;
    ssev_watcher_t *watchers;
    void *userdata;
    ssev_update_cb_t update_cb;
};

/* ---------- private ---------- */

static ssev_watcher_t *init_watcher(int fd, unsigned int events, ssev_cb_t ssev_cb) {
    ssev_watcher_t *w = _ALLOC(ssev_watcher_t *, sizeof(ssev_watcher_t));
    _CHECK_ALLOC(w, return NULL;)
    memset(w, 0, sizeof(ssev_watcher_t));
    w->fd = fd;
    w->events = events;
    w->ssev_cb = ssev_cb;
    return w;
}

/* static int watchers_size(ssev_loop_t *loop) {
    if (!loop || !loop->watchers) {
        return 0;
    }
    return HASH_COUNT(loop->watchers);
} */

static ssev_watcher_t *get_watcher(ssev_loop_t *loop, int fd) {
    if (!loop || !loop->watchers || fd <= 0) {
        return NULL;
    }
    ssev_watcher_t *w = NULL;
    HASH_FIND_INT(loop->watchers, &fd, w);
    return w;
}

static int add_watcher(ssev_loop_t *loop, ssev_watcher_t *w) {
    if (!w) {
        return SSEV_ERR;
    }
    HASH_ADD_INT(loop->watchers, fd, w);
    return SSEV_OK;
}

static void del_watcher(ssev_loop_t *loop, ssev_watcher_t *w) {
    if (!loop || !loop->watchers || !w) {
        return;
    }
    HASH_DEL(loop->watchers, w);
    free(w);
}

static void free_watchers(ssev_loop_t *loop) {
    if (!loop || !loop->watchers) {
        return;
    }
    ssev_watcher_t *w, *tmp;
    HASH_ITER(hh, loop->watchers, w, tmp) { del_watcher(loop, w); }
    loop->watchers = NULL;
}

static int event_callback(ssev_loop_t *loop, int event, int fd) {
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (!w || (w->events & event) != event) {
        _LOG("event without watcher in event callback");
        ssev_unwatch(loop, event, fd);
        return SSEV_OK;
    }

    if (w->ssev_cb) {
        return w->ssev_cb(loop, event, fd, w->userdata);
    }
    return SSEV_OK;
}

/* ---------- API ---------- */

ssev_loop_t *ssev_init() {
    ssev_loop_t *loop = _ALLOC(ssev_loop_t *, sizeof(ssev_loop_t));
    _CHECK_ALLOC(loop, return NULL;)
    memset(loop, 0, sizeof(ssev_loop_t));
    loop->timeout = DEF_EV_TIMEOUT;
    loop->watchers = NULL;
    loop->efd = epoll_create(EPOLL_SIZE);
    if (loop->efd == -1) {
        perror("epoll create error");
        free(loop);
        return NULL;
    }
    return loop;
}

void ssev_free(ssev_loop_t *loop) {
    _LOG("free ssev start.");
    if (!loop) return;
    loop->is_looping = 0;
    if (loop->watchers) {
        free_watchers(loop);
    }
    close(loop->efd);
    free(loop);
    _LOG("free ssev ok.");
    return;
}

int ssev_run(ssev_loop_t *loop) {
    if (!loop) return SSEV_ERR;
    struct epoll_event events[MAX_EVENTS];
    loop->is_looping = 1;
    int i, nfds, fd = 0;
    while (loop->is_looping) {
        nfds = epoll_wait(loop->efd, events, MAX_EVENTS, loop->timeout);
        if (!loop->is_looping) {
            _LOG("stop looping.");
            break;
        }
        if (nfds == -1) {
            perror("epoll wait error");
            return SSEV_ERR;
            /* break; */
        } else if (nfds == 0) {
            /* _LOG("epoll wait timeout"); */
            if (loop->update_cb) loop->update_cb(loop, loop->userdata);
            continue;
        }
        for (i = 0; i < nfds && loop->is_looping; i++) {
            fd = events[i].data.fd;
            /* _LOG("events[%d] events:%08x", i, events[i].events); */
            if (events[i].events & EPOLLIN) {
                /* _LOG("fd:%d is readable", fd); */
                event_callback(loop, SSEV_EV_READ, fd);
            } else if (events[i].events & EPOLLOUT) {
                /* _LOG("fd:%d is writeable", fd); */
                event_callback(loop, SSEV_EV_WRITE, fd);
            } else if ((events[i].events & EPOLLERR) || ((events[i].events & EPOLLHUP))) {
                _LOG_E("epoll event error. fd:%d event:%u", fd, events[i].events);
                epoll_ctl(loop->efd, EPOLL_CTL_DEL, fd, NULL);
            }
        }
    }
    return SSEV_OK;
}

void ssev_stop(ssev_loop_t *loop) {
    if (!loop) return;
    loop->is_looping = 0;
    _LOG("stop ssev loop...");
}

int ssev_watch(ssev_loop_t *loop, unsigned int event, int fd, ssev_cb_t ssev_cb) {
    if (!loop || fd <= 0 || IS_NOT_SSEV_EVENT_TYPE(event)) return SSEV_ERR;
    ssev_set_nonblocking(fd);
    struct epoll_event epev;
    epev.data.fd = fd;
    epev.events = DEF_EPOLL_MODE;
    if ((event & SSEV_EV_READ) == SSEV_EV_READ) epev.events = epev.events | EPOLLIN;
    if ((event & SSEV_EV_WRITE) == SSEV_EV_WRITE) epev.events = epev.events | EPOLLOUT;

    int ep_opt = EPOLL_CTL_ADD;
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (w) {
        /* mod event */
        ep_opt = EPOLL_CTL_MOD;
        if ((w->events & SSEV_EV_READ) == SSEV_EV_READ) epev.events = epev.events | EPOLLIN;
        if ((w->events & SSEV_EV_WRITE) == SSEV_EV_WRITE) epev.events = epev.events | EPOLLOUT;
        w->events = w->events | event;
    } else {
        /* new event */
        assert(ssev_cb);
        w = init_watcher(fd, event, ssev_cb);
        if (!w) return SSEV_ERR;
        if (add_watcher(loop, w) != SSEV_OK) {
            free(w);
            return SSEV_ERR;
        }
    }
    if (epoll_ctl(loop->efd, ep_opt, fd, &epev) == -1) {
        perror("epoll ctl error");
        del_watcher(loop, w);
        return SSEV_ERR;
    }
    return SSEV_OK;
}

int ssev_unwatch(ssev_loop_t *loop, unsigned int event, int fd) {
    if (!loop || fd <= 0 || IS_NOT_SSEV_EVENT_TYPE(event)) return SSEV_ERR;
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (!w) {
        _LOG("ssev_unwatch watcher does not exists. fd:%d", fd);
        return SSEV_OK;
    }
    struct epoll_event epev;
    epev.data.fd = fd;
    epev.events = DEF_EPOLL_MODE;
    if ((w->events & SSEV_EV_READ) == SSEV_EV_READ) epev.events = epev.events | EPOLLIN;
    if ((w->events & SSEV_EV_WRITE) == SSEV_EV_WRITE) epev.events = epev.events | EPOLLOUT;
    if ((event & SSEV_EV_READ) == SSEV_EV_READ) {
        epev.events = epev.events & ~EPOLLIN;
        w->events = w->events & ~SSEV_EV_READ;
    }
    if ((event & SSEV_EV_WRITE) == SSEV_EV_WRITE) {
        epev.events = epev.events & ~EPOLLOUT;
        w->events = w->events & ~SSEV_EV_WRITE;
    }
    int ep_opt = EPOLL_CTL_MOD;
    if (w->events == 0) {
        ep_opt = EPOLL_CTL_DEL;
        del_watcher(loop, w);
    }

    if (epoll_ctl(loop->efd, ep_opt, fd, &epev) == -1) {
        perror("epoll ctl error");
        return SSEV_ERR;
    }
    return SSEV_OK;
}

void ssev_notify_write(ssev_loop_t *loop, int fd) { return; }

int ssev_set_userdata(ssev_loop_t *loop, void *userdata) {
    if (!loop) return SSEV_ERR;
    loop->userdata = userdata;
    return SSEV_OK;
}

void *ssev_get_userdata(ssev_loop_t *loop) {
    if (!loop) return NULL;
    return loop->userdata;
}

int ssev_set_update_cb(ssev_loop_t *loop, ssev_update_cb_t update_cb) {
    if (!loop) return SSEV_ERR;
    loop->update_cb = update_cb;
    return SSEV_OK;
}

int ssev_set_ev_timeout(ssev_loop_t *loop, int timeout) {
    if (!loop || timeout < 0) return SSEV_ERR;
    loop->timeout = timeout;
    return SSEV_OK;
}

int ssev_set_watcher_userdata(ssev_loop_t *loop, int fd, void *userdata) {
    if (!loop) return SSEV_ERR;
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (!w) return SSEV_ERR;
    w->userdata = userdata;
    return SSEV_OK;
}

void *ssev_get_watcher_userdata(ssev_loop_t *loop, int fd) {
    if (!loop) return NULL;
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (!w) return NULL;
    return w->userdata;
}

ssev_cb_t ssev_get_watcher_cb(ssev_loop_t *loop, int fd) {
    if (!loop) return NULL;
    ssev_watcher_t *w = get_watcher(loop, fd);
    if (!w) return NULL;
    return w->ssev_cb;
}

void ssev_set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

#endif