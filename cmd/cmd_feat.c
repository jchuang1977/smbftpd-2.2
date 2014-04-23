/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include "smbftpd.h"
#include "ssl.h"

extern smbftpd_conf_t smbftpd_conf;

/**
 * An implementation of the FEAT command defined in RFC 2389. 
 * Note: The feature names returned are not command names, as
 * such, but simply indications that the server possesses 
 * some attribute or other.
 */
void cmd_feat(void)
{
	struct feat_tab {
		char *name;
	};

	struct feat_tab feat_list[] = {
#ifdef WITH_SSL
		/* RFC 2228 */
		{ "AUTH TLS" }, { "PBSZ" }, { "PROT" },
#endif /* WITH_SSL */
		/* RFC 3659 */
		{ "SIZE" }, { "MDTM" }, { "REST STREAM" },
		{ NULL }
	};

	struct feat_tab *c;

	reply_noformat(LONG_REPLY(211), "Extensions supported:");
	for (c = feat_list; c->name != NULL; c++)
		smbftpd_socket_printf(" %s\r\n", c->name);

	if (smbftpd_conf.support_utf8_client) {
		smbftpd_socket_printf(" UTF8\r\n");
	}
	smbftpd_socket_fflush(stdout, 0);

	reply_noformat(211, "End.");
}
