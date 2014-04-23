/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

#ifdef	WITH_ICONV
#include <iconv.h>

static iconv_t codepage2unicode = (iconv_t)-1;
static iconv_t unicode2codepage = (iconv_t)-1;

/**
 * Initial Unicode convert handler.
 * 
 * We will open iconv handler of utf8->codepage and codepage->utf8.
 * 
 * @param encoding The encoding to convert beween utf8 and codepage.
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_unicode_open(const char *encoding)
{
	if ((iconv_t)-1 != codepage2unicode) {
		iconv_close(codepage2unicode);
		codepage2unicode = (iconv_t)-1;
	}
	codepage2unicode = iconv_open("UTF-8", encoding);
	if ((iconv_t)-1 == codepage2unicode) {
		syslog(LOG_ERR, "%s (%d) Failed to open encoding %s -> UTF-8", __FILE__, __LINE__, encoding);
		return -1;
	}
	if ((iconv_t)-1 != unicode2codepage) {
		iconv_close(unicode2codepage);
		unicode2codepage = (iconv_t)-1;
	}
	unicode2codepage = iconv_open(encoding, "UTF-8");
	if ((iconv_t)-1 == unicode2codepage) {
		syslog(LOG_ERR, "%s (%d) Failed to open encoding UTF-8 -> %s", __FILE__, __LINE__, encoding);
		return -1;
	}

	return 0;
}

/**
 * Close iconv handlers
 */
void smbftpd_unicode_close()
{
	if ((iconv_t)-1 != codepage2unicode) {
		iconv_close(codepage2unicode);
	}
	if ((iconv_t)-1 != unicode2codepage) {
		iconv_close(unicode2codepage);
	}
	codepage2unicode = (iconv_t)-1;
	unicode2codepage = (iconv_t)-1;
}

/**
 * Convert string from codepage to UTF-8.
 * 
 * @param inbuf  The string to convert.
 * @param outbuf The output string. The buffer of output string should be at least
 *               strlen(inbuf) * 4.
 * @param outlen The length of output buffer length.
 * 
 * @return 0: Success
 *         -1: Failed
 */
static int smbftpd_codepage2unicode(const char *inbuf, char *outbuf, size_t outlen)
{
	size_t inlen;

	if (!outbuf || !inbuf) {
		return -1;
	}

	inlen = strlen(inbuf);

	bzero(outbuf, outlen);

	if (-1 == iconv(codepage2unicode, &inbuf, &inlen, &outbuf, &outlen)) {
		return -1;
	}

	return 0;
}

/**
 * Convert string from UTF-8 to codepage to.
 * 
 * @param inbuf  The string to convert.
 * @param outbuf The output string. The buffer of output string should be at least
 *               strlen(inbuf) * 4.
 * @param outlen The length of output buffer length.
 * 
 * @return 0: Success
 *         -1: Failed
 */
static int smbftpd_unicode2codepage(const char *inbuf, char *outbuf, size_t outlen)
{
	size_t inlen;

	if (!outbuf || !inbuf) {
		return -1;
	}

	inlen = strlen(inbuf);

	bzero(outbuf, outlen);

	if (-1 == iconv(unicode2codepage, &inbuf, &inlen, &outbuf, &outlen)) {
		return -1;
	}

	return 0;
}
#endif

/**
 * Convert charset from filesystem to client encoding.
 * 
 * If using utf8 fs, and client is not utf8: utf8->codepage
 * If not utf8 fs, and client is utf8: codepage->utf8
 * 
 * Otherwise, just return the pointer of inbuf.
 * 
 * @param inbuf  The string to convert
 * @param outbuf The buffer for output string
 * @param outlen The length of outbuf
 * 
 * @return If convert successfully, return the pointer of outbuf.
 *         If there is no need to convert or conversion failed, return the
 *         pointer of inbuf.
 */
const char *smbftpd_charset_fs2client(const char *inbuf, char *outbuf, size_t outlen)
{
#ifdef	WITH_ICONV
	if (smbftpd_conf.charset_encoding && 
		smbftpd_conf.using_utf8_filesystem != smbftpd_session.using_utf8_client) {
		if (smbftpd_session.using_utf8_client && !smbftpd_conf.using_utf8_filesystem) {
			if (0 == smbftpd_codepage2unicode(inbuf, outbuf, outlen)) {
				return outbuf;
			}
		} else if (!smbftpd_session.using_utf8_client && smbftpd_conf.using_utf8_filesystem) {
			if (0 == smbftpd_unicode2codepage(inbuf, outbuf, outlen)) {
				return outbuf;
			}
		}
	}
#endif

	return inbuf;
}

/**
 * Convert client encoding to filesystem encoding.
 * 
 * If client is using UTF-8, and filesystem is not: utf8->codepage
 * If client is not using UTF-8, and filesystem is: codepage->utf8
 * 
 * If no need to convert, just return NULL.
 * 
 * @param inbuf  The string to convert.
 * 
 * @return NULL if no need to convert or conversion failed.
 *         malloc() a new string buffer for the converted string. caller should
 *         free() the returned buffer.
 */
char *smbftpd_charset_client2fs(const char *inbuf)
{
#ifdef	WITH_ICONV
	char *outbuf = NULL;
	size_t outlen;

	if (smbftpd_conf.charset_encoding && 
		smbftpd_conf.using_utf8_filesystem != smbftpd_session.using_utf8_client) {
		if (smbftpd_session.using_utf8_client && !smbftpd_conf.using_utf8_filesystem) {
			outlen = strlen(inbuf) + 1;
			outbuf = calloc(outlen, 1);
			if (0 == smbftpd_unicode2codepage(inbuf, outbuf, outlen)) {
				return outbuf;
			}
		} else if (!smbftpd_session.using_utf8_client && smbftpd_conf.using_utf8_filesystem) {
			outlen = strlen(inbuf) * 6 + 1;
			outbuf = calloc(outlen, 1);
			if (0 == smbftpd_codepage2unicode(inbuf, outbuf, outlen)) {
				return outbuf;
			}
		}
	}

	if (outbuf) {
		free(outbuf);
	}
#endif

	return NULL;
}


