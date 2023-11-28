#ifndef __AFALG_H__
#define __AFALG_H__

#include <stdbool.h>
#include <zck.h>
#include "zck_private.h"
#include <linux/if_alg.h>
#include <linux/socket.h>

#include "afalg_priv.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define SHA1_DIGEST_LENGTH      20
#define SHA224_DIGEST_SIZE      28
#define SHA256_DIGEST_SIZE      32
#define SHA384_DIGEST_SIZE      48
#define SHA512_DIGEST_SIZE      64

void lib_hash_ctx_close(zckHash *hash);
bool lib_hash_init(zckCtx *zck, zckHash *hash);
bool lib_hash_update(zckCtx *zck, zckHash *hash, const char *message, const size_t size);
char *lib_hash_final(zckCtx *zck, zckHash *hash);

#endif
