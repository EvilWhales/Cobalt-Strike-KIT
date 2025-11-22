/* SPDX-License-Identifier: MIT */
/*
 * Author: Jianhui Zhao <zhaojh329@gmail.com>
 */

#ifndef __EXAMPLE_H
#define __EXAMPLE_H

#include <sys/select.h>
#include <stdbool.h>
#include <stdio.h>

#include "ssl.h"

static int ssl_select(int sock, int ret)
{
    fd_set fds = {};

    FD_SET(sock, &fds);

    if (ret == SSL_WANT_READ)
        ret = select(sock + 1, &fds, NULL, NULL, NULL);
    else if (ret == SSL_WANT_WRITE)
        ret = select(sock + 1, NULL, &fds, NULL, NULL);

    if (ret < 0) {
        perror("select");
        return -1;
    }

    return 0;
}

static void on_verify_error(int error, const char *str, void *arg)
{
    fprintf(stderr, "WARNING: SSL certificate error(%d): %s\n", error, str);
}

static int ssl_write_nonblock(struct ssl *ssl, int sock, void *data, int len)
{
    char err_buf[128];
    fd_set fds;
    int ret;

    while (true) {
        ret = ssl_write(ssl, data, len);
        if (ret == SSL_ERROR) {
            fprintf(stderr, "ssl_write: %s\n", ssl_last_error_string(ssl, err_buf, sizeof(err_buf)));
            return -1;
        }

        if (ret > 0)
            return ret;

        if (ssl_select(sock, ret))
            return -1;
    }
}

static int ssl_read_nonblock(struct ssl *ssl, int sock, void *data, int len, bool *closed)
{
    char err_buf[128];
    fd_set fds;
    int ret;

    *closed = false;

    while (true) {
        ret = ssl_read(ssl, data, len);
        if (ret == SSL_ERROR) {
            fprintf(stderr, "ssl_read: %s\n", ssl_last_error_string(ssl, err_buf, sizeof(err_buf)));
            return -1;
        }

        if (ret > 0)
            return ret;

        if (ret == 0) {
            *closed = true;
            return 0;
        }

        if (ret == SSL_WANT_READ)
            return 0;

        if (ssl_select(sock, ret))
            return -1;
    }
}

#endif
