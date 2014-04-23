/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

int cmd_rnfr(const char *name)
{
	const smbftpd_valid_share_t *share;
	struct stat st;
	char *real_path;

	if ( (strcmp(name,".")==0)||(strcmp(name,"..")==0) ) {
		reply_noformat(530, "Can't rename . and .. .");
		return -1;
	}

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, name, 
									 FLAG_CHECK_WRITABLE | FLAG_NO_FOLLOW_LAST_LINK);
	if (NULL == real_path) {
		reply_fs2client(553, "%s: No such file or directory.", name);
		return -1;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share || share->disable_modify) {
			reply_noformat(550, "Rename denied.");
			return -1;
		}
	}

	if (lstat(real_path, &st) < 0) {
		reply_fs2client(550, "%s: %s.", name, strerror(errno));
		return -1;
	}
	reply_noformat(350, "File exists, ready for destination name.");
	return 0;
}
