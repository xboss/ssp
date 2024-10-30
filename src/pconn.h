#ifndef _PCONN_H
#define _PCONN_H

#include <stdint.h>

#include "stream_buf.h"

/* #define PCONN_TYPE_FR 1
#define PCONN_TYPE_BK 2 */

typedef enum { PCONN_TYPE_FR = 1, PCONN_TYPE_BK } pconn_type_t;

/* #define PCONN_ST_OFF 1
#define PCONN_ST_READY 2
#define PCONN_ST_ON 3
#define PCONN_ST_WAIT 4 */

typedef enum { PCONN_ST_NONE = 0, PCONN_ST_OFF, PCONN_ST_READY, PCONN_ST_ON, PCONN_ST_WAIT } pconn_st_t;

/* typedef int (*pconn_output_cb_t)(int fd, const char *buf, int len); */

int pconn_init(int id, pconn_type_t type, int cp_id);
void pconn_free(int id /* , int cp_id */);
void pconn_free_all(void* u, void (*fn)(int id, void* u));
int pconn_send(int id, const char* buf, int len);
int pconn_rcv(int id, const char* buf, int len);
int pconn_wait(int id, const char* buf, int len);
int pconn_is_exist(int id);

pconn_type_t pconn_get_type(int id);
int pconn_get_couple_id(int id);
int pconn_set_couple_id(int id, int cp_id);
pconn_st_t pconn_get_status(int id);
pconn_st_t pconn_chg_status(int id, pconn_st_t status);
int pconn_get_ex(int id);
int pconn_set_ex(int id, int ex);
stream_buf_t* pconn_get_snd_buf(int id);
int pconn_set_snd_buf(int id, stream_buf_t* sb);
stream_buf_t* pconn_get_rcv_buf(int id);
stream_buf_t* pconn_get_wait_buf(int id);
int pconn_can_write(int id);
int pconn_set_can_write(int id, int can_write);
int pconn_is_secret(int id);
int pconn_set_is_secret(int id, int is_secret);
/* int pconn_is_packet(int id);
int pconn_set_is_packet(int id, int is_packet); */
uint64_t pconn_get_ctime(int id);

#endif /* PCONN_H */