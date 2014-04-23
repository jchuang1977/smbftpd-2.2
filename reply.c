/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#include "smbftpd.h"
#include "ssl.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

/**
 * Reply message to client. The message need to be formated but no need to
 * do charset conversion.
 * 
 * @param n      Reply code. If n < 0, it is a long reply. We will append a "-" after
 *               the n.
 *               
 *               For example, when n > 0:
 *               220 Reply Successfully
 *               when n < 0:
 *               220- Reply Successfully
 * @param str
 */
void reply(int n, const char *fmt, ...)
{
	va_list ap;
#ifdef WITH_SSL
	/* the size seems to be enough for normal use */
	char outputbuf[BUFSIZ + MAXPATHLEN + MAXHOSTNAMELEN];
	size_t outputbuflen;
#endif /* WITH_SSL */

#ifdef WITH_SSL
	if (IS_LONG_REPLY(n)) {
		snprintf(outputbuf, sizeof(outputbuf) - 2, "%d- ", n*-1);
	} else {
		snprintf(outputbuf, sizeof(outputbuf) - 2, "%d ", n);
	}
	va_start(ap, fmt);
	outputbuflen = strlen(outputbuf);
	vsnprintf(outputbuf + outputbuflen,
		 sizeof(outputbuf) - outputbuflen - 2, fmt, ap);
	va_end(ap);
	strcat(outputbuf, "\r\n");

	smbftpd_socket_printf("%s", outputbuf);
	smbftpd_socket_fflush(stdout, 0);

	if (smbftpd_conf.debug_mode)
		syslog(LOG_DEBUG, "<--- %s ", outputbuf);
#else /* !WITH_SSL */

	if (IS_LONG_REPLY(n)) {
		(void)printf("%d- ", n*-1);
	} else {
		(void)printf("%d ", n);
	}
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
	(void)printf("\r\n");
	(void)fflush(stdout);
	if (smbftpd_conf.debug_mode) {
		if (IS_LONG_REPLY(n)) {
			syslog(LOG_DEBUG, "<--- %d- ", n*-1);
		} else {
			syslog(LOG_DEBUG, "<--- %d ", n);
		}
		
		va_start(ap, fmt);
		vsyslog(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
#endif /* !WITH_SSL */
}

/**
 * Reply message to client. The message does not need to be formated nor
 * do charset convert.
 * 
 * @param n      Reply code. If n < 0, it is a long reply. We will append a "-" after
 *               the n.
 *               
 *               For example, when n > 0:
 *               220 Reply Successfully
 *               when n < 0:
 *               220- Reply Successfully
 * @param str
 */
void reply_noformat(int n, const char *str)
{
#ifdef WITH_SSL

	if (IS_LONG_REPLY(n)) {
		smbftpd_socket_printf("%d- %s\r\n", n*-1, str);
	} else {
		smbftpd_socket_printf("%d %s\r\n", n, str);
	}
	smbftpd_socket_fflush(stdout, 0);

#else /* !WITH_SSL */

	if (IS_LONG_REPLY(n)) {
		(void)printf("%d- %s\r\n", n*-1, str);
	} else {
		(void)printf("%d %s\r\n", n, str);
	}
	(void)fflush(stdout);

#endif /* !WITH_SSL */

	if (smbftpd_conf.debug_mode) {
		if (IS_LONG_REPLY(n)) {
			syslog(LOG_DEBUG, "<--- %d- %s", n*-1, str);
		} else {
			syslog(LOG_DEBUG, "<--- %d %s", n, str);
		}
	}
		
}

/**
 * Reply message to client. The message contains file name or directory
 * name that might need to convert from codepage to utf8 or from utf8
 * to codepage.
 * 
 * @param n      Reply code. If n < 0, it is a long reply. We will append a "-" after
 *               the n.
 *               
 *               For example, when n > 0:
 *               	220 Reply Successfully
 *               when n < 0:
 *               	220- Reply Successfully
 * @param fmt
 */
void reply_fs2client(int n, const char *fmt, ...)
{
	va_list ap;
	/* the size seems to be enough for normal use */
	char buf[BUFSIZ + MAXPATHLEN + MAXHOSTNAMELEN];
	char outbuf[BUFSIZ + MAXPATHLEN + MAXHOSTNAMELEN];
	const char *p;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	p = smbftpd_charset_fs2client(buf, outbuf, sizeof(outbuf));

#ifdef WITH_SSL
	if (IS_LONG_REPLY(n)) {
		smbftpd_socket_printf("%d- %s\r\n", n*-1, p);
	} else {
		smbftpd_socket_printf("%d %s\r\n", n, p);
	}
	smbftpd_socket_fflush(stdout, 0);
#else /* !WITH_SSL */
	if (IS_LONG_REPLY(n)) {
		(void)printf("%d- %s\r\n", n*-1, p);
	} else {
		(void)printf("%d %s\r\n", n, p);
	}
	(void)fflush(stdout);
#endif /* !WITH_SSL */

	if (smbftpd_conf.debug_mode) {
		if (IS_LONG_REPLY(n)) {
			syslog(LOG_DEBUG, "<--- %d- %s ", n*-1, buf);
		} else {
			syslog(LOG_DEBUG, "<--- %d %s ", n, buf);
		}
	}
}

void fatalerror(const char *s)
{
	reply(451, "Error in server: %s\n", s);
	reply_noformat(221, "Closing connection due to server error.");
	dologout(0);
	/* NOTREACHED */
}
