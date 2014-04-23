/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_pwd(void)
{
	char *s, path[MAXPATHLEN + 1];

	if (getcwd(path, sizeof(path)) == NULL)
		reply(550, "Get current directory: %s.", strerror(errno));
	else {
		if (smbfptd_replace_share_path(smbftpd_session.valid_shares, path, sizeof(path)) != 0) {
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
		} else {
			if ((s = doublequote(path)) == NULL)
				fatalerror("Ran out of memory.");
			reply_fs2client(257, "\"%s\" is current directory.", s);
			free(s);
		}
	}
}


