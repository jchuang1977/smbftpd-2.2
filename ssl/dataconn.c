/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "ssl.h"
#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

#ifdef WITH_SSL
SSL	*ssl_con;
SSL	*ssl_data_con;

/*
 * Compare two X509 certificates.
 * return:
 *	 1 - certificates are not NULL and equal
 *	 0 - certificates are not NULL and differ
 *	-1 - both certificates are NULL
 *	-2 - x509_cert1 is NULL, x509_cert2 is not NULL
 *	-3 - x509_cert1 in not NULL, x509_cert2 is NULL
 */
static int ssl_X509_cmp(X509 *x509_cert1, X509 *x509_cert2)
{
	/* X509_cmp() will crash if any of its args are NULL
	 */
	if (x509_cert1 != NULL) {
		if (x509_cert2 == NULL) {
			return -3; /* x509_cert1 in not NULL, x509_cert2 is NULL */
		} else {
			if (X509_cmp(x509_cert1, x509_cert2)) {
				return 0; /* certificates are differ */
			} else {
				return 1; /* certificates are equal */
			}
		}
	} else {
		if (x509_cert2 == NULL) {
			return -1; /* both certificates are NULL */
		} else {
			return -2; /* x509_cert1 is NULL, x509_cert2 is not NULL */
		}
	}
}
#endif

int ssl_dataconn_open(int datafd)
{
#ifdef WITH_SSL
	X509 *x509_ssl_data_con, *x509_ssl_con;

	if (ssl_data_con != NULL) {
		SSL_free(ssl_data_con);
		ssl_data_con = NULL;
	}

	ssl_data_con = (SSL *)SSL_new(ssl_ctx);
	SSL_set_accept_state(ssl_data_con);
	SSL_set_fd(ssl_data_con, datafd);

	if (smbftpd_conf.debug_mode) {
		syslog(LOG_DEBUG, "START SSL_accept on DATA connection");
	}

	if (SSL_accept(ssl_data_con) <= 0) {
		char errbuf[BUFSIZ];

		snprintf(errbuf, sizeof(errbuf),
				 "SSL_accept DATA connection error %s.",
				 ERR_reason_error_string(ERR_get_error()));
		reply(425, "%s: %s.", errbuf, strerror(errno));

		return -1;
	} else {
		/* Get client certificates of control and data connections. */
		x509_ssl_con=SSL_get_peer_certificate(ssl_con);
		x509_ssl_data_con=SSL_get_peer_certificate(ssl_data_con);

		/*
		 * Check the certificates if the client certificate
		 * is presented for the control connection.
		 */
		switch (ssl_X509_cmp(x509_ssl_con, x509_ssl_data_con)) {
		char errbuf[BUFSIZ];
		case -3:
			snprintf(errbuf, sizeof(errbuf),
					 "Client did not present a certificate for data connection.");
			reply(425, "%s", errbuf);

			/* Drop an established TLS/SSL connection. */
			SSL_free(ssl_data_con);
			ssl_data_con = NULL;

			return -1;
		case  0:
			snprintf(errbuf, sizeof(errbuf),
					 "Client certificates for control and data connections are different.");
			reply(425, "%s", errbuf);

			/* Drop an established TLS/SSL connection. */
			SSL_free(ssl_data_con);
			ssl_data_con = NULL;

			return -1;
		default:
			break;
		}

		X509_free(x509_ssl_con);
		X509_free(x509_ssl_data_con);

		smbftpd_session.ssl_ctrl.ssl_data_active_flag = 1;
	}

	if (smbftpd_conf.debug_mode) {
		syslog(LOG_DEBUG, "DONE SSL_accept on DATA connection");
	}
#endif
	return 0;
}
