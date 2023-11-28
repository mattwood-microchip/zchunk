#ifndef __AFALG_PRIV_H__
#define __AFALG_PRIV_H__

#include <linux/if_alg.h>
#include <linux/socket.h>

typedef struct {
        struct sockaddr_alg alg;
        int sock;
        int digest_fd;
} afalgCtx;

#endif
