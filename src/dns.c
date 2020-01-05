
#include "dns.h"

#ifdef WIN32

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>

#endif
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>


#include "ares.h"

struct dns_cb_arg
{
    int domain_idx;
    struct dns_req* req;
};

// macros
#define RTE_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define RTE_MIN(x, y) (((x) < (y)) ? (x) : (y))

// global var
extern bool g_force_quit;

static void dns_wait(ares_channel ch)
{
    int rc;
    int i;

    /**
       c-ares's poll (not select)
     */

    for (; !g_force_quit;) {

        struct timeval tv;
        memset(&tv,0, sizeof(tv));
        struct pollfd pfds[ARES_GETSOCK_MAXNUM + 2] = { {0} };
        int pfd_cnt = 0;
        ares_socket_t socks[ARES_GETSOCK_MAXNUM] = { 0 };
        int timeout_ms = 0;
        int nfds = 0;

        rc = ares_getsock(ch, socks, ARES_GETSOCK_MAXNUM);
        for (i = 0; i < ARES_GETSOCK_MAXNUM; i += 1) {
            if (socks[i] == 0) {
                break;
            }
            uint32_t ev = 0;
            if (ARES_GETSOCK_READABLE(rc, i) > 0) {
                ev = ev | POLLIN;
            }
            if (ARES_GETSOCK_WRITABLE(rc, i) > 0) {
                ev = ev | POLLOUT;
            }
            pfds[pfd_cnt].fd = socks[i];
            pfds[pfd_cnt].events = ev;
            pfd_cnt += 1;
        }
        if (pfd_cnt <= 0) {
            // no queries, will exit
            break;
        }

        // set a init timeout
        tv.tv_sec = 1;
        // get timeout recommanded by ares
        ares_timeout(ch, NULL, &tv);
        timeout_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        timeout_ms = RTE_MAX(1000, timeout_ms);

        nfds = poll(pfds, pfd_cnt, timeout_ms);
        if (g_force_quit) {
            break;
        }

        // Not care about we process other fd, such as quit fd, timer fd
        //   the `ares_process_fd` will check inner.
        if (nfds > 0) {
            for (i = 0; i < pfd_cnt; i += 1) {
                if (pfds[i].revents & POLLIN) {
                    ares_process_fd(ch, pfds[i].fd, ARES_SOCKET_BAD);
                }
                if (pfds[i].revents & POLLOUT) {
                    ares_process_fd(ch, ARES_SOCKET_BAD, pfds[i].fd);
                }
            }
        } else {
            ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        }
        
    }
    ares_cancel(ch);

}

static void dns_cb(void* arg0, int status, int timeout_s, struct hostent* host)
{
    const char* domain = NULL;
    char buf[0x100] = { 0 };
    (void)buf;
    uint32_t n;

    struct dns_cb_arg* arg = arg0;

    domain = arg->req->domains[arg->domain_idx].name;
    if ((status == ARES_SUCCESS) && host &&
        host->h_addr_list &&
        (host->h_length == sizeof(struct in_addr))
        ) {


        //you can use this code to print address for debug.
        if (1) {
            inet_ntop(AF_INET, host->h_addr_list[0], buf, sizeof(buf));
            fprintf(stderr, "get addr of %s idx=%d =%s name=%s timeout_s=%d %s:%d\n", domain,
                arg->domain_idx, buf,
                host->h_name, timeout_s,
                __FILE__, __LINE__);
        }
        n=0;
        memcpy(&n, host->h_addr_list[0],sizeof(n));
        arg->req->ips[arg->domain_idx] = ntohl(n);
    } else {
        fprintf(stderr, "%s() fail dns resolve for [%d]%s status=%d:%s timeout_s=%d %s:%d\n",
            __func__, arg->domain_idx, domain,
            status, ares_strerror(status),
            timeout_s, __FILE__, __LINE__);
    }
}

static int dns_resolve(struct dns_req* req)
{
    /**
     init_by_defaults will init default options.
     default look = fb, include dns and hosts
    */
    int rc = -1;
    ares_channel ch;
    memset(&ch, 0, sizeof(ch));
    struct ares_options opts;
    memset(&opts, 0, sizeof(opts));
    int optmask = 0;

    int i = 0;
    struct dns_cb_arg cb_arg[DOMAIN_MAX_COUNT];
    memset(cb_arg, 0, sizeof(cb_arg));

    /**
    not know difference of `ares_query` `ares_gethostbyaddr` `ares_gethostbyname`
    */

    // TCP will fail for query multi name
    //opts.flags = ARES_FLAG_USEVC;
    //optmask = ARES_OPT_FLAGS;
    //rc = ares_init_options(&ch, &opts, optmask);

    // Not specific TCP, use UDP default
    rc = ares_init_options(&ch, NULL, 0);

    if (rc != ARES_SUCCESS) {
        fprintf(stderr, "%s() fail ares_init_options ares_err=%s %s:%d", __func__,
            ares_strerror(rc), __FILE__, __LINE__);
        rc = -1;
        goto clean;
    }
    for (i = 0; i < req->domains_cnt; i++) {
        cb_arg[i].domain_idx = i;
        cb_arg[i].req = req;
        const char* domain = req->domains[i].name;
        struct in_addr addr;
        memset(&addr, 0, sizeof(addr));
        if (inet_pton(AF_INET, domain, &addr) == 1) {
            req->ips[i] = ntohl(addr.s_addr);
        } else {
            ares_gethostbyname(ch, req->domains[i].name, AF_INET, dns_cb, &cb_arg[i]);
        }

    }
    dns_wait(ch);
    //
    rc = 0;
clean:

    ares_destroy(ch);
    return rc;
}

int dns_post(struct dns_req* req)
{
    int i;
    bool has_domain = false;

    for (i = 0; i < req->domains_cnt; ++i) {
        const char* name = req->domains[i].name;
        struct in_addr addr;
        memset(&addr, 0, sizeof(addr));
        if (inet_pton(AF_INET, name, &addr) == 1) {
            req->ips[i] = ntohl(addr.s_addr);
        } else {
            has_domain = true;
        }
    }

    if (!has_domain) {
        return 0;
    }
    return dns_resolve(req);
}

void dns_req_dump(struct dns_req* req, char* buf, int size)
{
    int rc;
    int i;
    char* off = buf;

    for (i = 0; i < req->domains_cnt; ++i) {
        char tmp[16] = { 0 };
        uint32_t n = 0;
        n = htonl(req->ips[i]);
        inet_ntop(AF_INET, &n, tmp, sizeof(tmp));
        rc = snprintf(off, size, "%s - %s\n", req->domains[i].name, tmp);
        if (!(rc > 0 && rc < size)) {
            return;
        }
        off += rc;
        size -= rc;
    }
}



