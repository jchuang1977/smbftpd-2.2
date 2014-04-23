/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>

#include "smbftpd.h"
#include "cmd.h"
#include "cmd_int.h"

void cmd_statfile(const char *filename)
{
	reply_fs2client(LONG_REPLY(211), "status of %s:", filename);
	smbftpd_dir_list(filename, stdout, 1, 0);
	reply_noformat(211, "End of status");
}

