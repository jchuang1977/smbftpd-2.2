/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <smbftpd.h>

extern smbftpd_session_t smbftpd_session;

/**
 * chdir() to given path
 * 
 * @param path   The path where we wanna go.
 */
void cmd_cwd(const char *path)
{
	char *realpath;

	realpath = smbftpd_get_realpath(smbftpd_session.valid_shares, path, 0);
	if (NULL == realpath) {
		reply_noformat(550, "No such file or directory.");
	} else {
		if (chdir(realpath) < 0)
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
		else
			reply_noformat(250, "CWD command successful.");
	}
}

