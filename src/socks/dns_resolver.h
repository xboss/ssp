#ifndef _DNS_RESOLVER_H
#define _DNS_RESOLVER_H

#include "ssev.h"

typedef struct domain_req_s domain_req_t;
typedef void (*domain_cb_t)(domain_req_t *req);

int init_domain_resolver(ssev_loop_t *loop);
void free_domain_resolver(ssev_loop_t *loop);
int resolve_domain(domain_req_t *req);
domain_req_t *init_domain_req(int id, const char *name, int name_len, domain_cb_t cb, unsigned short port,
                              void *userdata);
void free_domain_req(domain_req_t *req);

int get_domain_req_id(domain_req_t *req);
int get_domain_req_resp(domain_req_t *req);
char *get_domain_req_name(domain_req_t *req);
char *get_domain_req_ip(domain_req_t *req);
void *get_domain_req_userdata(domain_req_t *req);
unsigned short get_domain_req_port(domain_req_t *req);

#endif /* DNS_RESOLVER_H */