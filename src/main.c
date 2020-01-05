/**
 * 用于测试 TCP dns， 一次查询多个，服务器端没有回应
 *
 * c-ares 提供的工具 ./adig -f usevc -d -s 114.114.114.114 x.com y.com
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef WIN32

#else
#include <unistd.h>
#endif
#include "dns.h"

bool g_force_quit=false;

void test1()
{
    struct dns_req req={0};
    char dump_string[0x200];
    int rc;

    snprintf(req.domains[req.domains_cnt].name, sizeof(req.domains[req.domains_cnt].name),
            "%s", "www.baidu.com");
    req.domains_cnt ++;

    snprintf(req.domains[req.domains_cnt].name, sizeof(req.domains[req.domains_cnt].name),
            "%s", "www.sina.com");
    req.domains_cnt ++;

    rc = dns_post(&req);
    printf("dns_post return=%d \n", rc);


    dns_req_dump(&req, dump_string, sizeof(dump_string));
    printf("dump:%s\n", dump_string);

}

int main()
{
    printf("wait for gdb pid= %llu\n", (unsigned long long)getpid());
    // getchar();
    test1();
    printf("main exit\n");
    return  0;
}
