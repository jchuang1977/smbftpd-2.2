/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include "ssl.h"
#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

#ifdef WITH_SSL
SSL_CTX	*ssl_ctx;
#endif

/**
 * Initial the SSL library and load cert.
 * 
 * @return 
 */
int ssl_init_library()
{
#ifdef	WITH_SSL
	const unsigned char ctx_sid[] = "smbftpd";

	if (!(smbftpd_conf.security_policy & SECURITY_POLICY_SECURE)) {
		return 0;
	}

	/*
	 * Init things so we will get meaningful error messages rather than
	 * numbers
	 */
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	ssl_ctx = (SSL_CTX *)SSL_CTX_new(SSLv23_method());

	/*
	 * We may require a temp 512 bit RSA key because of the wonderful way
	 * export things work... If so we generate one now!
	 */
	
	SSL_CTX_set_session_id_context(ssl_ctx, ctx_sid, strlen((char *)ctx_sid));

	if (SSL_CTX_need_tmp_RSA(ssl_ctx)) {
		RSA *rsa;

		if (smbftpd_conf.debug_mode)
			syslog(LOG_DEBUG, "Generating temp (512 bit) RSA key...");
		rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
		if (smbftpd_conf.debug_mode)
			syslog(LOG_DEBUG, "Generation of temp (512 bit) RSA key done");

		if (!SSL_CTX_set_tmp_rsa(ssl_ctx, rsa)) {
			syslog(LOG_ERR, "Failed to assign generated temp RSA key!");
		}
		RSA_free(rsa);
		if (smbftpd_conf.debug_mode)
			syslog(LOG_DEBUG, "Assigned temp (512 bit) RSA key");
	}

	/*
	 * Also switch on all the interoperability and bug workarounds so
	 * that we will communicate with people that cannot read poorly
	 * written specs :-)
	 */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);

	/* Add in any certificates if you want to here... */
	if (smbftpd_conf.ssl_cert_file) {
		if (!SSL_CTX_use_certificate_file(ssl_ctx, smbftpd_conf.ssl_cert_file,
										  X509_FILETYPE_PEM)) {
			syslog(LOG_ERR, "%s (%d) Error loading '%s'", 
				   __FILE__, __LINE__, smbftpd_conf.ssl_cert_file);
			return -1;
		} else {
			if (!smbftpd_conf.ssl_key_file)
				smbftpd_conf.ssl_key_file = smbftpd_conf.ssl_cert_file;
			if (!SSL_CTX_use_RSAPrivateKey_file(ssl_ctx,
												smbftpd_conf.ssl_key_file, X509_FILETYPE_PEM)) {
				syslog(LOG_ERR, "%s (%d) Error loading '%s'", 
					   __FILE__, __LINE__, smbftpd_conf.ssl_key_file);
				return -1;
			}
		}
	}

	/*
	 * Make sure we will find certificates in the standard
	 * location ... Otherwise we don't look anywhere for these
	 * things which is going to make client certificate exchange
	 * rather useless :-)
	 */
	SSL_CTX_set_default_verify_paths(ssl_ctx);

	/*
	ssl_verify_flag = SSL_VERIFY_NONE;
	ssl_verify_flag = SSL_VERIFY_PEER;
	ssl_verify_flag = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	*/
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

#endif

	return (0);
}

