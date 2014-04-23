/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/param.h>

#include "ssl.h"
#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

/*
 * Initialize the TLS/SSL session on a control connection.
 */
int ssl_init_session()
{
#ifndef	WITH_SSL
	return 0;
#else
	char errstr[BUFSIZ];
	char *ssl_version;
	int ssl_bits;
	SSL_CIPHER *ssl_cipher;
	int ret=0;

	/* Do the SSL stuff now... Before we play with pty's. */
	ssl_con = (SSL *)SSL_new(ssl_ctx);
	SSL_set_accept_state(ssl_con);

	/* We are working with stdin (inetd based) by default. */
	SSL_set_fd(ssl_con, 0);

	if (SSL_accept(ssl_con) <= 0) {
		switch (SSL_get_verify_result(ssl_con)) {
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			snprintf(errstr, sizeof(errstr),
					 "invalid signature on CRL!");
			break;
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			snprintf(errstr, sizeof(errstr),
					 "found CRL has invalid nextUpdate field");
			break;
		case X509_V_ERR_CRL_HAS_EXPIRED:
			snprintf(errstr, sizeof(errstr),
					 "found CRL expired - revoking all certificates until you get updated CRL");
			break;
		case X509_V_ERR_CERT_REVOKED:
			snprintf(errstr, sizeof(errstr),
					 "client certificate is revoked");
			break;
		default:
			snprintf(errstr, sizeof(errstr), "%s",
					 ERR_reason_error_string(ERR_peek_error()));
		}

		if (smbftpd_conf.log_command)
			syslog(LOG_NOTICE, "TLS/SSL FAILED WITH %s (reason: %s)",
				   smbftpd_session.remotehost, errstr);

		snprintf(errstr, sizeof(errstr), "SSL_accept: %s.",
				 ERR_reason_error_string(ERR_get_error()));
		reply(421, "%s", errstr);

		SSL_free(ssl_con);
		ssl_con = NULL;

		ret=-1;
	} else {
		smbftpd_session.ssl_ctrl.ssl_active_flag = 1;

		ssl_version = SSL_get_cipher_version(ssl_con);
		ssl_cipher = SSL_get_current_cipher(ssl_con);
		SSL_CIPHER_get_bits(ssl_cipher, &ssl_bits);

		if (smbftpd_conf.log_command)
			syslog(LOG_INFO,
				   "TLS/SSL SUCCEEDED WITH %s (FTP-SSL/TLS, %s, cipher %s, %d bits)",
				   smbftpd_session.remotehost, 
				   ssl_version, SSL_CIPHER_get_name(ssl_cipher), ssl_bits);
	}

	/*
	 * ssl_fprintf calls require that this be null to test
	 * for being an ssl stream.
	 */
	if (!smbftpd_session.ssl_ctrl.ssl_active_flag) {
		if (ssl_con != NULL)
			SSL_free(ssl_con);
		ssl_con = NULL;
	}

	return ret;
#endif
}

