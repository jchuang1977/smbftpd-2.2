/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include "smbftpd.h"

static int transflag  = 0;
static int recvurg = 0;

/**
 * Turn on recvurg flag if we are transfering files.
 * 
 * This function is called by sigurg.
 */
void set_receive_sigurg()
{
	if (!transflag) {
		return;
	}
	recvurg = 1;
}

/**
 * Check whether we have received SIGURG. If yes, reset the flag.
 * 
 * @return 1: Yes, we got SIGURG
 *         0: No SIGURG pedding
 */
int sigurg_received()
{
	if (recvurg) {
		recvurg = 0;
		return 1;
	}
	return 0;
}

/**
 * Mask/unmask the SIGURG
 * 
 * @param flag   0: unblock SIGURG
 *               1: block SIGURG
 */
void maskurg(int flag)
{
	int oerrno;
	sigset_t sset;

	if (!transflag) {
		syslog(LOG_ERR, "Internal: maskurg() while no transfer");
		return;
	}
	oerrno = errno;
	sigemptyset(&sset);
	sigaddset(&sset, SIGURG);
	sigprocmask(flag ? SIG_BLOCK : SIG_UNBLOCK, &sset, NULL);
	errno = oerrno;
}

/**
 * When start transfer, turn on transflag and unmask SIGURG.
 * After transfer end, turn off transflag and mask SIGURG.
 * 
 * @param flag   1: Start transfer
 *               0: End transfer
 */
void flagxfer(int flag)
{
	if (flag) {
		if (transflag)
			syslog(LOG_ERR, "Internal: flagxfer(1): "
					"transfer already under way");
		transflag = 1;
		maskurg(0);
		recvurg = 0;
	} else {
		if (!transflag)
			syslog(LOG_ERR, "Internal: flagxfer(0): "
					"no active transfer");
		maskurg(1);
		transflag = 0;
	}
}

/*
 * Returns 0 if OK to resume or -1 if abort requested.
 */
int check_oob(void)
{
	char tmpline[16];
	int ret;
#ifdef WITH_SSL /* "pseudo-OOB" with SSL */
	fd_set mask;
	struct timeval tv;
#endif

	if (!transflag) {
		syslog(LOG_ERR, "Internal: myoob() while no transfer");
		return (0);
	}

#ifdef WITH_SSL /* "pseudo-OOB" with SSL */
	FD_ZERO(&mask);
	FD_SET(fileno(stdin),&mask);
	tv.tv_sec=0;
	tv.tv_usec=0;

	if (0 == select(fileno(stdin)+1, &mask, NULL, NULL, &tv)) {
		return 0;
	}
#endif /*USE_SSL*/

	bzero(tmpline, sizeof(tmpline));
	ret = mygetline(tmpline, sizeof(tmpline), stdin);
	if (ret == -1) {
		reply_noformat(221, "You could at least say goodbye.");
		dologout(0);
	} else if (ret == -2) {
		/* Ignore truncated command. */
		return (0);
	}

	if (strcasecmp(tmpline, "ABOR\r\n") == 0) {
		reply_noformat(426, "Transfer aborted. Data connection closed.");
		reply_noformat(226, "Abort successful.");
		return (-1);
	}

	return (0);
}

