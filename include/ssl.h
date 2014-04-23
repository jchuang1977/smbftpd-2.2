/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_SSL_H
#define _SMBFTPD_SSL_H

#include "config.h"

#ifdef WITH_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>


extern SSL_CTX	*ssl_ctx;
extern SSL	*ssl_con;
extern SSL	*ssl_data_con;
#endif

/* dataconn.c */
int ssl_dataconn_open(int datafd);

/* init.c */
int ssl_init_library();

/* io.c */
#ifdef WITH_SSL
int ssl_read(SSL *ssl, void *buf, int num);
int ssl_write(SSL *ssl, void *buf, int num);
#endif
int smbftpd_socket_getc(FILE *stream, int data);
int smbftpd_socket_putc(int c, FILE *stream, int data);
int smbftpd_socket_fflush(FILE *stream, int data);
void smbftpd_socket_printf(const char *fmt, ...);

/* session.c */
int ssl_init_session(void);

#endif /* _SMBFTPD_SSL_H */
