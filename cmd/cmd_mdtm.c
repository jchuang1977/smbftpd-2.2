/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <ctype.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

/**
 * Convert string into struct timeval format.
 * 
 * @param str    String to convert
 * @param t      buffer to save the timeval
 * 
 * @return 0: Success
 *         -1: Failed
 */
static int string_to_timeval(const char *str, struct timeval *t)
{
	struct tm tmtime;
	char buf[8];
	char *tz = NULL;
	int i, j;

	if (!str) {
		return -1;
	}
	if (strlen(str) != 14) { // yyyymmddhhmmss
		return -1;
	}

	for (i = 0; i < 14; i++) {
		if (!isdigit(str[i])) {
			return -1;
		}
	}

	bzero(&tmtime, sizeof(tmtime));

	bzero(buf, sizeof(buf));
	for (i = 0; i < 4; i++) buf[i] = str[i];
	tmtime.tm_year = atoi(buf) - 1900;

	bzero(buf, sizeof(buf));
	for (i = 4, j = 0; i < 6; i++, j++) buf[j] = str[i];
	tmtime.tm_mon = atoi(buf) - 1;
	bzero(buf, sizeof(buf));
	for (i = 6, j = 0; i < 8; i++, j++) buf[j] = str[i];
	tmtime.tm_mday = atoi(buf);

	bzero(buf, sizeof(buf));
	for (i = 8, j = 0; i < 10; i++, j++) buf[j] = str[i];
	tmtime.tm_hour = atoi(buf);

	bzero(buf, sizeof(buf));
	for (i = 10, j = 0; i < 12; i++, j++) buf[j] = str[i];
	tmtime.tm_min = atoi(buf);

	bzero(buf, sizeof(buf));
	for (i = 12, j = 0; i < 14; i++, j++) buf[j] = str[i];
	tmtime.tm_sec = atoi(buf);

	/* We need gmtime for utimes. We don't use timegm() because->please man timegm */
	tz = getenv("TZ");
	setenv("TZ", "", 1);
	tzset();
	t->tv_sec = mktime(&tmtime);
	t->tv_usec = 0;
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();

	return 0;
}

/**
 * Check whether str is a MDTM Set command.
 * 
 * A set command:
 *     MDTM yymmddhhmmss filename
 * A get command:
 *     MDTM filename
 * 
 * @param str    String to check
 * 
 * @return 1: Yes, it's MDTM set
 *         0: No
 */
static int is_mdtm_set(const char *str)
{
	int i;

	if (!str) return 0;

	if (strlen(str) < 15) { // yyyymmddhhmmss
		return 0;
	}

	for (i = 0; i < 14; i++) {
		if (!isdigit(str[i])) {
			return 0;
		}
	}
	if (str[14] == ' ') {
		return 1;
	} else {
		return 0;
	}
}

/**
 * Get/Set modify time for file. We will check whether "str"
 * is "yyyymmddhhmmss filename" format. If it is, we will perform
 * set modify time. If the "str" is just a file/dir name,
 * we will just do GET.
 * 
 * @param str    We will check whether "str" is "yyyymmddhhmmss filename" format.
 *               If it is, we will perform set modify time. If the "str" is just
 *               a file/dir name, we will just do GET.
 */
void cmd_mdtm(char *str)
{
	struct stat st;
	char *path, *real_path = NULL, *timestr = NULL;
	int isset = 0;

	if (is_mdtm_set(str)) { /* RFC 3659 */
		isset = 1;
		/* Set MDTM */
		*(str + 14) = 0; /* 14: yyyymmddhhmmss */
		timestr = str;
		path = str + 15;
		while (*path != '\0' && (*path == ' ' || *path == '\t')) {
			path++;
		}
	} else {
		/* Get MDTM */
		path = str;
	}

	if (isset) {
		real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path, FLAG_CHECK_WRITABLE);
	} else {
		real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path, 0);
	}
	if (NULL == real_path) {
		reply_fs2client(550, "%s: No such file or directory.", path);
	} else {
		if (stat(real_path, &st) < 0) {
			reply_fs2client(550, "%s: %s", path, strerror(errno));
		} else if (!S_ISREG(st.st_mode)) {
			reply_fs2client(550, "%s: not a plain file.", path);
		} else {
			if (isset) {
				struct timeval times[2];
				struct timeval t;
				if (0 != string_to_timeval(timestr, &t)) {
					reply(550, "%s: bad time format.", timestr);
				} else {
					times[0].tv_sec = t.tv_sec;
					times[0].tv_usec = t.tv_usec;
					times[1].tv_sec = t.tv_sec;
					times[1].tv_usec = t.tv_usec;

					if (0 != utimes(real_path, times)) {
						reply_fs2client(550, "%s: %s", path, strerror(errno));
					} else {
						reply_noformat(250, "MDTM command successful.");
					}
				}
			} else {
				struct tm *t;
				t = gmtime(&st.st_mtime);
				reply(213, "%04d%02d%02d%02d%02d%02d",
					  1900 + t->tm_year, t->tm_mon+1, t->tm_mday,
					  t->tm_hour, t->tm_min, t->tm_sec);
			}
		}
	}
}
