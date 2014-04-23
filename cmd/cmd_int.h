/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef _SMBFTPD_CMD_INT_H_
#define _SMBFTPD_CMD_INT_H_

/* For cmd_user() and cmd_pass() */
void end_login(void);

/* For cmd_list() and cmd_statfile() */
int smbftpd_dir_list(const char *path, FILE * pfclient, int verbose, int recursive);

#endif
