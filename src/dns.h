#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#define DOMAIN_NAME_MAX_SIZE 0x200
#define DOMAIN_MAX_COUNT 0x10

struct domain {
  char name[DOMAIN_NAME_MAX_SIZE];
};

struct dns_req {
    struct domain domains[DOMAIN_MAX_COUNT];
    uint32_t ips[DOMAIN_MAX_COUNT];
    int domains_cnt;

};

int dns_post(struct dns_req * req);
void dns_req_dump(struct dns_req * req, char * buf, int size);

#endif