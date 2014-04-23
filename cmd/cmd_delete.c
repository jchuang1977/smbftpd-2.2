/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_delete(const char *path)
{
	const smbftpd_valid_share_t *share;
	struct stat st;
	char *real_path;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path,
									FLAG_NO_FOLLOW_LINK | FLAG_CHECK_WRITABLE);

	if (NULL == real_path) {
		reply_fs2client(550, "%s: permission denied.", path);
		return;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share || share->disable_modify) {
			reply_noformat(550, "Delete file denied.");
			return;
		}
	}

	LOGCMD("delete", path);
	if (lstat(real_path, &st) < 0) {
		reply_fs2client(550, "%s: %s.", path, strerror(errno));
		return;
	}
	if (S_ISDIR(st.st_mode)) {
		if (rmdir(real_path) < 0) {
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
			return;
		}
		goto done;
	}
	if (unlink(real_path) < 0) {
		reply_fs2client(550, "%s: %s.", path, strerror(errno));
		return;
	}
done:
	reply_noformat(250, "DELE command successful.");
}

