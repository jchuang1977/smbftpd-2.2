/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "smbftpd.h"
#include "ssl.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

int cmd_auth(const char *method)
{
#ifdef	WITH_SSL
	/* Compatibility with early implementations of SSL upgrade. */
	if ((smbftpd_conf.security_policy & SECURITY_POLICY_SECURE) &&
		(smbftpd_conf.encryption_type & ENCRYPTION_TYPE_SSL)) {

		//reply_noformat(!ssl_uorc_flag ? 234 : 334,"AUTH SSL command successful.");
		reply_noformat(234, "AUTH SSL command successful.");
	
		/* Initialize the TLS/SSL session. */
		if (0 != ssl_init_session()) {
			dologout(1);
		}
		smbftpd_session.ssl_ctrl.ssl_encrypt_data = 1;
	
	/* Implementation of the FTP-TLS v12 IETF draft. */
	} else if ((smbftpd_conf.security_policy & SECURITY_POLICY_SECURE) &&
			   (smbftpd_conf.encryption_type & ENCRYPTION_TYPE_TLS)) {
		reply_noformat(234, "AUTH TLS command successful.");
	
		/* Initialize the TLS/SSL session. */
		ssl_init_session();
	} else
#endif
		reply(504, "AUTH: security mechanism '%s' not supported.", method);

	return 0;
}
