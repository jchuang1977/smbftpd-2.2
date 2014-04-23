/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

void cmd_pbsz()
{
#ifdef WITH_SSL
	if (smbftpd_session.ssl_ctrl.ssl_active_flag) {
		reply_noformat(200, "PBSZ command successful (PBSZ=0).");
		smbftpd_session.ssl_ctrl.PBSZ_used_flag = 1;
	} else {
		reply_noformat(503, "Use AUTH command first.");
	}
#endif /* WITH_SSL */
}
