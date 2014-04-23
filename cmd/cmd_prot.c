/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

void cmd_prot(const char *level)
{
#ifdef WITH_SSL
	/* We should support PROT in SSL mode, too. Otherwise, the
	 * Filezilla, TurboFTP would failed to connection.
	 */
	/*if (ssl_compat_flag) {
		reply_noformat(504, "PROT command not available in FTP-SSL "
		"compatibility mode.");
		goto prot_end;
	} else */if (smbftpd_session.ssl_ctrl.ssl_active_flag && smbftpd_session.ssl_ctrl.PBSZ_used_flag) {
		if (!strcasecmp(level, "C")) {
			smbftpd_session.ssl_ctrl.ssl_encrypt_data = 0;
		} else if (!strcasecmp(level, "P")) {
			smbftpd_session.ssl_ctrl.ssl_encrypt_data = 1;
		} else {
			reply(504, "Protection level '%s' not supported.",
				  level);
			return;
		}

		reply(200, "Protection level set to %s.",
			  smbftpd_session.ssl_ctrl.ssl_encrypt_data ? "Private" : "Clear");
		if (smbftpd_conf.log_command)
			syslog(LOG_NOTICE,
				   "data connection protection level set to %s",
				   smbftpd_session.ssl_ctrl.ssl_encrypt_data ? "Private" : "Clear");
		} else {
			reply_noformat(503, "Use AUTH and PBSZ commands first.");
			return;
		}
#endif /* WITH_SSL */
}
