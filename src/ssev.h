#ifndef _SSEV_H
#define _SSEV_H

#define SSEV_EV_READ (0x01u)
#define SSEV_EV_WRITE (0x01u << 1)
#define SSEV_EV_ALL (SSEV_EV_READ | SSEV_EV_WRITE)

typedef struct ssev_loop_s ssev_loop_t;

typedef int (*ssev_cb_t)(ssev_loop_t *loop, unsigned int event, int fd, void *ud);
typedef int (*ssev_update_cb_t)(ssev_loop_t *loop, void *ud);

ssev_loop_t *ssev_init();
void ssev_free(ssev_loop_t *loop);
int ssev_run(ssev_loop_t *loop);
void ssev_stop(ssev_loop_t *loop);

int ssev_watch(ssev_loop_t *loop, unsigned int event, int fd, ssev_cb_t ssev_cb);
int ssev_unwatch(ssev_loop_t *loop, unsigned int event, int fd);

int ssev_set_ev_timeout(ssev_loop_t *loop, int timeout);

int ssev_set_userdata(ssev_loop_t *loop, void *userdata);
void *ssev_get_userdata(ssev_loop_t *loop);
int ssev_set_update_cb(ssev_loop_t *loop, ssev_update_cb_t update_cb);

int ssev_set_watcher_userdata(ssev_loop_t *loop, int fd, void *userdata);
void *ssev_get_watcher_userdata(ssev_loop_t *loop, int fd);

ssev_cb_t ssev_get_watcher_cb(ssev_loop_t *loop, int fd);

void ssev_set_nonblocking(int fd);

void ssev_notify_write(ssev_loop_t *loop, int fd);

#endif /* SSEV_H */