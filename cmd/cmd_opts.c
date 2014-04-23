/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <string.h>

#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

/*
 * An implementation of the OPTS command defined in RFC 2389.
 * arguments:
 *	command - the string with next syntax:
 *	          command-name [ SP command-options ]
 * return:
 *	none
 * notes:
 *	command-name: any FTP command which allows option setting;
 *	command-options: format specified by individual FTP command.
 */
void cmd_opts(char *command)
{
	char *s;

	if (!command) {
		reply(501, "OPTS command error.");
		return;
	}

	s = strchr(command, ' ');
	if (s) {
		*s++ = '\0';
	}
	if (strcasecmp(command, "UTF8") == 0) {
		if (!smbftpd_conf.support_utf8_client) {
			reply(500, "%s: command not understood.", command);
			return;
		}
		str_trim_space(s);
		//addreply_noformat(500, "Disabled");
		if (strcasecmp(s, "off") == 0) {
			smbftpd_session.using_utf8_client = 0;
			reply(200, "OK, UTF-8 disabled");
		} else if (strcasecmp(s, "on") == 0) {
			smbftpd_session.using_utf8_client = 1;
			reply(200, "OK, UTF-8 enabled");
		} else {
			reply(550, "Unknown option %s", s);
		}
	} else {
		reply(501, "OPTS command is not defined for %s.", command);
	}

	return;
}
