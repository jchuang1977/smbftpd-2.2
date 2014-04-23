/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include "smbftpd.h"

int smbftpd_mode_get(int default_mode, const char *exception, const char *user)
{
	enum smbftpd_mode mode = default_mode;

	if (is_user_in_list(user, exception)) {
		if (default_mode == MODE_NORMAL) {
			mode = MODE_SMB;
		} else if (default_mode == MODE_SMB) {
			mode = MODE_NORMAL;
		}
	}

	return mode;
}
