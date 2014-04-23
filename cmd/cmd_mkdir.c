/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_mkdir(const char *name)
{
	char *s;
	char *dir = NULL;

	dir = smbftpd_get_realpath(smbftpd_session.valid_shares, name, FLAG_CHECK_WRITABLE);
	if (NULL == dir) {
		reply_fs2client(550, "%s: Permission denied.", name);
		return;
	}

	LOGCMD("mkdir", name);

	if (mkdir(dir, 0777) < 0)
		reply_fs2client(550, "%s: %s.", name, strerror(errno));
	else {
		if ((s = doublequote(name)) == NULL)
			fatalerror("Ran out of memory.");
		reply_fs2client(257, "\"%s\" directory created.", s);
		free(s);
	}
}

