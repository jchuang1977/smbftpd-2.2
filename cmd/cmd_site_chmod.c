/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_site_chmod(const char *path, mode_t mode)
{
	const smbftpd_valid_share_t *share;
	char *real_path;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path, 
									 FLAG_CHECK_WRITABLE);
	if (NULL == real_path) {
		reply_fs2client(550, "%s: Permission denied.", path);
		return;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share || share->disable_modify) {
			reply_noformat(553, "CHMOD command denied.");
			return;
		}
	}

	if (chmod(real_path, mode) < 0) {
		reply_fs2client(550, "%s: %s.", path, strerror(errno));
	} else {
		reply_noformat(200, "CHMOD command successful.");
	}

	return;
}

