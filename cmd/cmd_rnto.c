/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_rnto(const char *from, const char *to)
{
	const smbftpd_valid_share_t *share;
	struct stat st;
	char *real_path;
	char real_from[MAXPATHLEN], *real_to;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, from, 
									 FLAG_CHECK_WRITABLE | FLAG_NO_FOLLOW_LAST_LINK);
	if (NULL == real_path) {
		reply_fs2client(550, "%s: Permission denied.", from);
		return;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share || share->disable_modify) {
			reply_noformat(550, "Rename denied.");
			return;
		}
	}

	snprintf(real_from, sizeof(real_from), "%s", real_path);

	real_to = smbftpd_get_realpath(smbftpd_session.valid_shares, to, 
								   FLAG_CHECK_WRITABLE);
	if (NULL == real_to) {
		reply_fs2client(550, "%s permission denied", to);
		return;
	}

	LOGCMD2("rename", from, to);

	if (smbftpd_session.guest && (stat(real_to, &st) == 0)) {
		reply_fs2client(550, "%s: permission denied.", to);
		return;
	}

	if (rename(real_from, real_to) < 0)
		reply(550, "rename: %s.", strerror(errno));
	else
		reply_noformat(250, "RNTO command successful.");
}
