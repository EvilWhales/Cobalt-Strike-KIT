/* SPDX-License-Identifier: MIT */
/*
 * Author: Jianhui Zhao <zhaojh329@gmail.com>
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include "ssl.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/entropy.h>

#if MBEDTLS_VERSION_NUMBER < 0x02040000L
#include <mbedtls/net.h>
#else
#include <mbedtls/net_sockets.h>
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

struct ssl_context {
    mbedtls_ssl_config conf;
    mbedtls_pk_context key;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt cert;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif
    bool server;
    int *ciphersuites;
};

struct mbedtls_ssl {
    int err;
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
};

static inline mbedtls_ssl_context *ssl_to_mbedtls_ssl(struct ssl *ssl)
{
    return &((struct mbedtls_ssl *)ssl)->ssl;
}

static int urandom(void *ctx, unsigned char *out, size_t len)
{
    int ret = 0;
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

    if (read(fd, out, len) < 0)
        ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

    close(fd);

    return ret;
}

#define AES_GCM_CIPHERS(v)				\
    MBEDTLS_TLS_##v##_WITH_AES_128_GCM_SHA256,	\
    MBEDTLS_TLS_##v##_WITH_AES_256_GCM_SHA384

#define AES_CBC_CIPHERS(v)				\
    MBEDTLS_TLS_##v##_WITH_AES_128_CBC_SHA,		\
    MBEDTLS_TLS_##v##_WITH_AES_256_CBC_SHA

#define AES_CIPHERS(v)					\
    AES_GCM_CIPHERS(v),				\
    AES_CBC_CIPHERS(v)

static const int default_ciphersuites_server[] =
{
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    AES_GCM_CIPHERS(ECDHE_ECDSA),
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    AES_GCM_CIPHERS(ECDHE_RSA),
    AES_CBC_CIPHERS(ECDHE_RSA),
    AES_CIPHERS(RSA),
    0
};

static const int default_ciphersuites_client[] =
{
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    AES_GCM_CIPHERS(ECDHE_ECDSA),
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    AES_GCM_CIPHERS(ECDHE_RSA),
    MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    AES_GCM_CIPHERS(DHE_RSA),
    AES_CBC_CIPHERS(ECDHE_ECDSA),
    AES_CBC_CIPHERS(ECDHE_RSA),
    AES_CBC_CIPHERS(DHE_RSA),
#ifdef MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
#endif
    AES_CIPHERS(RSA),
#ifdef MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA
    MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
#endif
    0
};

const char *ssl_last_error_string(struct ssl *ssl, char *buf, int len)
{
    mbedtls_strerror(ssl->err, buf, len);
    return buf;
}

struct ssl_context *ssl_context_new(bool server)
{
    struct ssl_context *ctx;
    mbedtls_ssl_config *conf;
    int ep;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->server = server;
    mbedtls_pk_init(&ctx->key);
    mbedtls_x509_crt_init(&ctx->cert);
    mbedtls_x509_crt_init(&ctx->ca_cert);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&ctx->cache);
    mbedtls_ssl_cache_set_timeout(&ctx->cache, 30 * 60);
    mbedtls_ssl_cache_set_max_entries(&ctx->cache, 5);
#endif

    conf = &ctx->conf;
    mbedtls_ssl_config_init(conf);

    ep = server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

    mbedtls_ssl_config_defaults(conf, ep, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(conf, urandom, NULL);

    if (server) {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites_server);
        mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    } else {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites_client);
    }

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(conf, &ctx->cache,
                       mbedtls_ssl_cache_get,
                       mbedtls_ssl_cache_set);
#endif
    return ctx;
}

void ssl_context_free(struct ssl_context *ctx)
{
    if (!ctx)
        return;

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&ctx->cache);
#endif
    mbedtls_pk_free(&ctx->key);
    mbedtls_x509_crt_free(&ctx->ca_cert);
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_ssl_config_free(&ctx->conf);
    free(ctx->ciphersuites);
    free(ctx);
}

static void ssl_update_own_cert(struct ssl_context *ctx)
{
    if (!ctx->cert.version)
        return;

    if (mbedtls_pk_get_type(&ctx->key) == MBEDTLS_PK_NONE)
        return;

    mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->key);
}

int ssl_load_ca_cert_file(struct ssl_context *ctx, const char *file)
{
    int ret;

    ret = mbedtls_x509_crt_parse_file(&ctx->ca_cert, file);
    if (ret)
        return -1;

    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca_cert, NULL);
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    return 0;
}

int ssl_load_cert_file(struct ssl_context *ctx, const char *file)
{
    int ret;

    ret = mbedtls_x509_crt_parse_file(&ctx->cert, file);
    if (ret)
        return -1;

    ssl_update_own_cert(ctx);

    return 0;
}

int ssl_load_key_file(struct ssl_context *ctx, const char *file)
{
    int ret;

#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
    ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL, urandom, NULL);
#else
    ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL);
#endif
    if (ret)
        return -1;

    ssl_update_own_cert(ctx);

    return 0;
}

int ssl_set_ciphers(struct ssl_context *ctx, const char *ciphers)
{
    int *ciphersuites = NULL, *tmp, id;
    char *cipherstr, *p, *last, c;
    size_t len = 0;

    if (ciphers == NULL)
        return -1;

    cipherstr = strdup(ciphers);

    if (cipherstr == NULL)
        return -1;

    for (p = cipherstr, last = p;; p++) {
        if (*p == ':' || *p == 0) {
            c = *p;
            *p = 0;

            id = mbedtls_ssl_get_ciphersuite_id(last);

            if (id != 0) {
                tmp = realloc(ciphersuites, (len + 2) * sizeof(int));

                if (tmp == NULL) {
                    free(ciphersuites);
                    free(cipherstr);

                    return -1;
                }

                ciphersuites = tmp;
                ciphersuites[len++] = id;
                ciphersuites[len] = 0;
            }

            if (c == 0)
                break;

            last = p + 1;
        }

        /*
         * mbedTLS expects cipher names with dashes while many sources elsewhere
         * like the Firefox wiki or Wireshark specify ciphers with underscores,
         * so simply convert all underscores to dashes to accept both notations.
         */
        else if (*p == '_') {
            *p = '-';
        }
    }

    free(cipherstr);

    if (len == 0)
        return -1;

    mbedtls_ssl_conf_ciphersuites(&ctx->conf, ciphersuites);
    free(ctx->ciphersuites);

    ctx->ciphersuites = ciphersuites;

    return 0;
}

int ssl_set_require_validation(struct ssl_context *ctx, bool require)
{
    int mode = MBEDTLS_SSL_VERIFY_OPTIONAL;

    if (!require)
        mode = MBEDTLS_SSL_VERIFY_NONE;

    mbedtls_ssl_conf_authmode(&ctx->conf, mode);

    return 0;
}

struct ssl *ssl_session_new(struct ssl_context *ctx, int sock)
{
    struct mbedtls_ssl *ssl;

    ssl = calloc(1, sizeof(struct mbedtls_ssl));
    if (!ssl)
        return NULL;

    mbedtls_ssl_init(&ssl->ssl);

    if (mbedtls_ssl_setup(&ssl->ssl, &ctx->conf)) {
        free(ssl);
        return NULL;
    }

    ssl->net.fd = sock;

    mbedtls_ssl_set_bio(&ssl->ssl, &ssl->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    return (struct ssl *)ssl;
}

void ssl_session_free(struct ssl *ssl)
{
    if (!ssl)
        return;

    mbedtls_ssl_free(ssl_to_mbedtls_ssl(ssl));
    free(ssl);
}

void ssl_set_server_name(struct ssl *ssl, const char *name)
{
    mbedtls_ssl_set_hostname(ssl_to_mbedtls_ssl(ssl), name);
}

#define ssl_need_retry(ret)                         \
    do {                                            \
        if (ret == MBEDTLS_ERR_SSL_WANT_READ)       \
            return SSL_WANT_READ;                   \
        else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) \
            return SSL_WANT_WRITE;                  \
    } while (0)

static void ssl_verify_cert(mbedtls_ssl_context *ssl, void (*on_verify_error)(int error, const char *str, void *arg), void *arg)
{
    const char *msg = NULL;
    int r;

    r = mbedtls_ssl_get_verify_result(ssl);
    r &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;

    if (r & MBEDTLS_X509_BADCERT_EXPIRED)
        msg = "certificate has expired";
    else if (r & MBEDTLS_X509_BADCERT_REVOKED)
        msg = "certificate has been revoked";
    else if (r & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        msg = "certificate is self-signed or not signed by a trusted CA";
    else
        msg = "unknown error";

    if (r && on_verify_error)
        on_verify_error(r, msg, arg);
}

static int ssl_handshake(struct ssl *ssl, bool server,
        void (*on_verify_error)(int error, const char *str, void *arg), void *arg)
{
    int r;

    ssl->err = 0;

    r = mbedtls_ssl_handshake(ssl_to_mbedtls_ssl(ssl));
    if (r == 0) {
        ssl_verify_cert(ssl_to_mbedtls_ssl(ssl), on_verify_error, arg);
        return SSL_OK;
    }

    ssl_need_retry(r);

    ssl->err = r;

    return SSL_ERROR;
}

int ssl_accept(struct ssl *ssl, void (*on_verify_error)(int error, const char *str, void *arg), void *arg)
{
    return ssl_handshake(ssl, true, on_verify_error, arg);
}

int ssl_connect(struct ssl *ssl, void (*on_verify_error)(int error, const char *str, void *arg), void *arg)
{
    return ssl_handshake(ssl, false, on_verify_error, arg);
}

int ssl_write(struct ssl *ssl, const void *buf, int len)
{
    int done = 0;
    int ret = 0;

    ssl->err = 0;

    while (done != len) {
        ret = mbedtls_ssl_write(ssl_to_mbedtls_ssl(ssl), (const unsigned char *)buf + done, len - done);

        if (ret < 0) {
            ssl_need_retry(ret);
            ssl->err = ret;
            return -1;
        }

        done += ret;
    }

    return done;
}

int ssl_read(struct ssl *ssl, void *buf, int len)
{
    int ret = mbedtls_ssl_read(ssl_to_mbedtls_ssl(ssl), (unsigned char *)buf, len);

    ssl->err = 0;

    if (ret < 0) {
        ssl_need_retry(ret);

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            return 0;

        ssl->err = ret;
        return SSL_ERROR;
    }

    return ret;
}
