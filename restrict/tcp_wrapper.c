/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include "config.h"

#ifdef	HAVE_TCPWRAPPER
#include <syslog.h>
#include <string.h>
#include <tcpd.h>
//	int allow_severity;
//	int deny_severity;
#endif

/**
 * TCP Wrapper. Check whether IP of the socket fd is in black/white list.
 * 
 * It will check /etc/hosts.allow
 * 
 * @param fd     Socket fd
 * 
 * @return 0: Yes, host is allowed
 *         -1: No, refuse connection
 */
int tcp_wrapping_check(int fd)
{
#ifdef	HAVE_TCPWRAPPER
	struct request_info req;
	int allow = 0;

	// TCP Wrapping.
	request_init(&req, RQ_DAEMON, "ftpd", RQ_FILE, fd, NULL);
	fromhost(&req);
	allow = hosts_access(&req);
	if (allow == 0) {
		syslog(LOG_ERR, "%s (%d) FTP refused connection from %.500s", 
			__FILE__, __LINE__, eval_client(&req));
		return -1;
	}
#endif
	return 0;
}

