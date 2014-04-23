/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

#ifdef   HAVE_MD5FILE
	#include <sys/types.h>
	#include <md5.h>
#endif

void cmd_site_mdfive(const char *path)
{
#ifdef   HAVE_MD5FILE
	char p[64], *q;
	char *real_path;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path, 0);
	if (NULL == real_path) {
		reply_fs2client(550, "%s: No such file or direcotry.", path);
		return;
	}

	q = MD5File(real_path, p);
	if (q != NULL)
		reply_fs2client(200, "MD5(%s) = %s", path, p);
	else
		reply_fs2client(550, "%s: %s.", path, strerror(errno));
#else
	reply_noformat(550, "MD5 not supported.");
#endif
}
