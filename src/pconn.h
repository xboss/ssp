#ifndef _PCONN_H
#define _PCONN_H

#include <stdint.h>

#include "stream_buf.h"

#define PCONN_TYPE_FR 1
#define PCONN_TYPE_BK 2

#define PCONN_ST_OFF 1
#define PCONN_ST_READY 2
#define PCONN_ST_ON 3
#define PCONN_ST_WAIT 4

int pconn_init(int id, int type, uint64_t ctime);
void pconn_free(int id /* , int cp_id */);
void pconn_free_all(void* u, void (*fn)(int id, void* u));

int pconn_get_type(int id);
int pconn_get_couple_id(int id);
int pconn_set_couple_id(int id, int cp_id);
int pconn_get_status(int id);
int pconn_set_status(int id, int status);
int pconn_get_ex(int id);
int pconn_set_ex(int id, int ex);
stream_buf_t* pconn_get_snd_buf(int id);
stream_buf_t* pconn_get_rcv_buf(int id);
int pconn_can_write(int id);
int pconn_set_can_write(int id, int can_write);
int pconn_is_secret(int id);
int pconn_set_is_secret(int id, int is_secret);
int pconn_is_packet(int id);
int pconn_set_is_packet(int id, int is_packet);
uint64_t pconn_get_ctime(int id);

#endif /* PCONN_H */