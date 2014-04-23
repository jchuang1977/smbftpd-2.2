/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include <stdarg.h>

#include "ssl.h"
#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

#ifdef WITH_SSL
/*
 * Wrapper around SSL_read(), arguments and return codes are the same.
 * This function handles SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE result
 * codes of TLS/SSL I/O operation.
 */
int ssl_read(SSL *ssl, void *buf, int num)
{
	int ret, err = SSL_ERROR_NONE;

	do {
		ret = SSL_read(ssl, buf, num);
		if (ret <= 0) {
			err = SSL_get_error(ssl, ret);
			if (smbftpd_conf.debug_mode)
				syslog(LOG_ERR, "ssl_read(): SSL_ERROR %d", err);
		}
	} while (ret<0 && (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE));
	return ret;
}

/*
 * Wrapper around SSL_write(), arguments and return codes are the same.
 * This function handles SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE result
 * codes of TLS/SSL I/O operation.
 */
int ssl_write(SSL *ssl, void *buf, int num)
{
	int ret, err = SSL_ERROR_NONE;

	do {
		ret = SSL_write(ssl, buf, num);
		if (ret <= 0) {
			err = SSL_get_error(ssl, ret);
			if (smbftpd_conf.debug_mode)
				syslog(LOG_ERR, "ssl_write(): SSL_ERROR %d", err);
		}
	} while (ret<0 && (err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE));
	return ret;
}

static int ssl_getc(SSL *ssl)
{
	char onebyte;
	int ret;

	if ((ret = ssl_read(ssl, &onebyte, 1)) != 1) {
		if (smbftpd_conf.debug_mode || (ret < 0)) {
			syslog(LOG_ERR, "ssl_getc: ssl_read failed (SSL code: %d, errno: %d)\n",
				   ret, errno);
		}
		return -1;
	} else {
		return onebyte & 0xff;
	}
}

/* got back to this an implemented some rather "simple" buffering */
static char	putc_buf[BUFSIZ];
static int	putc_buf_pos = 0;

static int ssl_putc_flush(SSL *ssl)
{
	if (putc_buf_pos > 0) {
		if (ssl_write(ssl, putc_buf, putc_buf_pos) != putc_buf_pos) {
			if (smbftpd_conf.debug_mode) 
				syslog(LOG_ERR, "ssl_putc_flush: WRITE FAILED");
			putc_buf_pos = 0;
			return -1;
		}
	}
	putc_buf_pos = 0;
	return 0;
}

static int ssl_putc(SSL *ssl, int oneint)
{
	char onebyte;

	onebyte = oneint & 0xff;

	/* make sure there is space */
	if (putc_buf_pos >= sizeof(putc_buf))
		if (ssl_putc_flush(ssl) != 0)
			return EOF;
	putc_buf[putc_buf_pos++] = onebyte;

	return onebyte;
}
#endif

int smbftpd_socket_getc(FILE *stream, int data)
{
#ifdef	WITH_SSL
	if (data && smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
		return ssl_getc(ssl_data_con);
	} else if (!data && smbftpd_session.ssl_ctrl.ssl_active_flag) {
		return ssl_getc(ssl_con);
	} else
#endif
		return getc(stream);
}

int smbftpd_socket_putc(int c, FILE *stream, int data)
{
#ifdef	WITH_SSL
	if (data && smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
		return ssl_putc(ssl_data_con, c);
	} else if (!data && smbftpd_session.ssl_ctrl.ssl_active_flag) {
		return ssl_putc(ssl_con, c);
	} else
#endif
		return putc(c, stream);
}

int smbftpd_socket_fflush(FILE *stream, int data)
{
#ifdef	WITH_SSL
	if (data && smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
		return ssl_putc_flush(ssl_data_con);
	} else if (!data && smbftpd_session.ssl_ctrl.ssl_active_flag) {
		return 1;
	} else
#endif
		return fflush(stream);
}

/**
 * 
 * @param fd     The fd to write. When using SSL, the fd is dummy.
 * @param buf    Buffer to write.
 * @param len    Buffer length
 * @param data   Is this data connection.
 * 
 * @return 
 */
void smbftpd_socket_printf(const char *fmt, ...)
{
	va_list ap;

#ifdef WITH_SSL
	/* The size seems to be enough for normal use */
	char outputbuf[BUFSIZ + MAXPATHLEN + MAXHOSTNAMELEN];
#endif /*WITH_SSL*/
	va_start(ap,fmt);
#ifdef WITH_SSL
	(void)vsnprintf(outputbuf, sizeof(outputbuf), fmt, ap);
	if (smbftpd_session.ssl_ctrl.ssl_active_flag) {
		ssl_write(ssl_con, outputbuf, strlen(outputbuf));
	} else {
		printf("%s", outputbuf);
		fflush(stdout);
	}
#else /*!WITH_SSL*/ 
	vfprintf(stdout, fmt, ap);
#endif /*WITH_SSL*/
	va_end(ap);
}

