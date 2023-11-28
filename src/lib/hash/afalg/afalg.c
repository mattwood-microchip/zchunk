/*
 * Copyright 2023 Matt Wood <matt.wood@microchip.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include "afalg.h"

void lib_hash_ctx_close(zckHash *hash)
{
        free(hash->ctx);
}

bool lib_hash_init(zckCtx *zck, zckHash *hash)
{
        int err;

        printf("hash_init chunk %d\n", zck->index.count);

        hash->ctx = zmalloc(sizeof(afalgCtx));

        if (!hash->ctx) {
                zck_log(ZCK_LOG_ERROR, "OOM in %s", __func__);
                return false;
        }

        if (hash->type->type == ZCK_HASH_SHA1) {
                zck_log(ZCK_LOG_DDEBUG, "Initializing SHA-1 hash with AFALG Interface");

                struct sockaddr_alg alg_sha1 = {
                        .salg_family = AF_ALG,
                        .salg_type = "hash",
                        .salg_name = "sha1",
                };

                memcpy((afalgCtx *)&hash->ctx->alg, &alg_sha1, sizeof(alg_sha1));
        } else if (hash->type->type == ZCK_HASH_SHA256) {
                zck_log(ZCK_LOG_DDEBUG, "Initializing SHA-256 hash with AFALG Interface");

                struct sockaddr_alg alg_sha256 = {
                        .salg_family = AF_ALG,
                        .salg_type = "hash",
                        .salg_name = "sha256",
                };

                memcpy((afalgCtx *)&hash->ctx->alg, &alg_sha256, sizeof(alg_sha256));
        } else if (hash->type->type >= ZCK_HASH_SHA512 && hash->type->type <= ZCK_HASH_SHA512_128) {
                zck_log(ZCK_LOG_DDEBUG, "Initializing SHA-512 hash with AFALG Interface");

                struct sockaddr_alg alg_sha512 = {
                        .salg_family = AF_ALG,
                        .salg_type = "hash",
                        .salg_name = "sha512",
                };

                memcpy((afalgCtx *)&hash->ctx->alg, &alg_sha512, sizeof(alg_sha512));
        } else {
                printf("Error, wrong hash type\n");
                return false;
        }

        hash->ctx->sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (hash->ctx->sock < 0) {
                zck_log(ZCK_LOG_ERROR, "Error allocating socket");
                return false;
        }

        err = bind(hash->ctx->sock, (struct sockaddr *)&hash->ctx->alg, sizeof(hash->ctx->alg));
        if (err) {
                zck_log(ZCK_LOG_ERROR, "Error %d binding socket in", -EAFNOSUPPORT);
        }

        hash->ctx->digest_fd = accept(hash->ctx->sock, NULL, 0);
        if (hash->ctx->digest_fd < 0) {
                zck_log(ZCK_LOG_ERROR, "Error %d could not connect socket", -EBADF);
                return false;
        }

        return true;
}

bool lib_hash_update(zckCtx *zck, zckHash *hash, const char *message, const size_t size)
{
        int err;

        printf("hash_update chunk %d\n", zck->index.count);
        err = send(hash->ctx->digest_fd, message, size, MSG_MORE);

        if (err != size) {
                //zck_log(ZCK_LOG_ERROR, "Error -%d : %s writing data to socket. Index: %d size: %d, total msg_size %d\n", errno, strerror(errno), zck->index.count, size, hash->ctx->msg_size);
                printf("Error -%d, %s writing data to socket.\n", errno, strerror(errno));
                printf("Chunk Index: %d, Chunk length: %d, msg size: %d\n", zck->index.count, zck->index.length, size);
                return false;
        }

        return true;
}

char *lib_hash_final(zckCtx *zck, zckHash *hash)
{
        unsigned char *digest;
        int ret;

        if(hash->type->type == ZCK_HASH_SHA1) {
                digest = zmalloc(SHA1_DIGEST_LENGTH);
                if (!digest) {
                        zck_log(ZCK_LOG_ERROR, "OOM in %s", __func__);
                        return NULL;
                }
        } else if(hash->type->type == ZCK_HASH_SHA256) {
                digest = zmalloc(SHA256_DIGEST_SIZE);
                if (!digest) {
                        zck_log(ZCK_LOG_ERROR, "OOM in %s", __func__);
                        return NULL;
                }
        } else if(hash->type->type >= ZCK_HASH_SHA512 &&
                hash->type->type <= ZCK_HASH_SHA512_128) {
                digest = zmalloc(SHA512_DIGEST_SIZE);
                if (!digest) {
                        zck_log(ZCK_LOG_ERROR, "OOM in %s", __func__);
                        return NULL;
                }
        } else {
                set_error(zck, "Unsupported hash type: %s", zck_hash_name_from_type(hash->type->type));
                hash_close(hash);
                return NULL;
        }

        //read(hash->ctx->digest_fd, digest, hash->type->digest_size);
        printf("hash_finalize chunk %d\n", zck->index.count);
        ret = recv(hash->ctx->digest_fd, digest, SHA256_DIGEST_SIZE, 0);

	if (ret < 0) {
		printf("Error %s getting digest\n", strerror(errno));
		digest = NULL;
	}

        close(hash->ctx->digest_fd);
        close(hash->ctx->sock);

        hash_close(hash);

        return (char *)digest;
}
