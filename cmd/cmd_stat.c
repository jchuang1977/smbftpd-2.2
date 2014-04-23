/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>

#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;

void cmd_stat()
{
	if (smbftpd_conf.show_program_version) {
		reply_noformat(211, "http://www.twbsd.org");
	} else {
		reply_noformat(211, "http://www.freebsd.org");
	}
}
