#ifndef _PCONN_H
#define _PCONN_H

#include <stdint.h>

#include "stream_buf.h"

typedef enum { PCONN_TYPE_NONE = 0, PCONN_TYPE_SERV, PCONN_TYPE_CLI } pconn_type_t;

typedef enum { PCONN_ST_NONE = 0, PCONN_ST_OFF, PCONN_ST_READY, PCONN_ST_ON /* , PCONN_ST_WAIT */ } pconn_st_t;

int pconn_init(int id, pconn_type_t type, int cp_id, stream_buf_t* snd_buf, stream_buf_t* rcv_buf);
void pconn_free(int id /* , int cp_id */);
void pconn_free_all(void* u, void (*fn)(int id, void* u));
int pconn_is_exist(int id);

pconn_type_t pconn_get_type(int id);
/* int pconn_get_serv_id(int id);
int pconn_get_cli_id(int id); */
int pconn_get_couple_id(int id);
int pconn_add_cli_id(int serv_id, int cli_id);
pconn_st_t pconn_get_status(int id);
int pconn_set_status(int id, pconn_st_t status);
int pconn_get_ex(int id);
int pconn_set_ex(int id, int ex);
stream_buf_t* pconn_get_snd_buf(int id);
stream_buf_t* pconn_get_rcv_buf(int id);
int pconn_can_write(int id);
int pconn_set_can_write(int id, int can_write);
int pconn_is_secret(int id);
int pconn_set_is_secret(int id, int is_secret);
/* int pconn_is_packet(int id);
int pconn_set_is_packet(int id, int is_packet); */
uint64_t pconn_get_ctime(int id);
int pconn_is_couple(int id, int cp_id);

#endif /* PCONN_H */