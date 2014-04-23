/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_rmdir(const char *name)
{
	const smbftpd_valid_share_t *share;
	char *real_path;
	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, name,
							   FLAG_CHECK_WRITABLE | FLAG_NO_FOLLOW_LINK);
	if (NULL == real_path) {
		reply_fs2client(550, "%s: Permission denied.", name);
		return;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share || share->disable_modify) {
			reply_noformat(550, "Remove directory denied.");
			return;
		}
	}

	LOGCMD("rmdir", name);
	if (rmdir(real_path) < 0)
		reply_fs2client(550, "%s: %s.", name, strerror(errno));
	else
		reply_noformat(250, "RMD command successful.");
}

