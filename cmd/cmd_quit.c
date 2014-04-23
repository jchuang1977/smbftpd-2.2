/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>

#include "smbftpd.h"
#include <syslog.h>
extern smbftpd_session_t smbftpd_session;

void cmd_quit()
{
	char upload[32];
	char download[32];

	if (smbftpd_session.byte_uploaded > 1024) {
		snprintf(upload, sizeof(upload), "%0.2f KB", (double)smbftpd_session.byte_uploaded/1024);
	}else{
		snprintf(upload, sizeof(upload), "%ld bytes", (long)smbftpd_session.byte_uploaded);
	}
	if (smbftpd_session.byte_downloaded > 1024) {
		snprintf(download, sizeof(download), "%0.2f KB", (double)smbftpd_session.byte_downloaded/1024);
	}else{													
		snprintf(download, sizeof(download), "%ld bytes", (long)smbftpd_session.byte_downloaded);
	}
	reply(221, "Goodbye. You uploaded %s and downloaded %s.", upload, download);
	dologout(0);
}

