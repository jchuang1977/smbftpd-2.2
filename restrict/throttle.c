/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "smbftpd.h"
/*               
 * Get value from set by username and transfer the value into
 * bps (bits per second).
 */
off_t smbftpd_transfer_rate_get(struct opt_set *set, const char *user)
{
	off_t size;
	const char *value;

	value = set_get_value(set, user);
	if (NULL == value) {
		return 0;
	}
	size = 1024 * strtol(value, (char **)NULL, 10);

	return size;
}

/* This function is used to block/unblock signale in transfer_rate_throttle()
 * to avoid signal received when select.
 */
static void transfer_rate_sigmask(int block)
{
	static sigset_t sig_set;

	if (block) {
		sigemptyset(&sig_set);

		sigaddset(&sig_set, SIGCHLD);
		sigaddset(&sig_set, SIGINT);
		sigaddset(&sig_set, SIGQUIT);
		sigaddset(&sig_set, SIGURG);
		sigaddset(&sig_set, SIGIO);
		sigaddset(&sig_set, SIGBUS);
		sigaddset(&sig_set, SIGHUP);

		while (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
	} else {
		while (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
	}
	return;
}

/* Returns the difference, in milliseconds, between the given timeval and
 * now.
 */
static long elapsed_time_count(struct timeval *since) 
{
	struct timeval now;
	gettimeofday(&now, NULL);

	return (((now.tv_sec - since->tv_sec) * 1000L) +
			((now.tv_usec - since->tv_usec) / 1000L));
}

/**
 * Delay download/upload task by count the speed and sleep for a
 * while if needed.
 * 
 * @param byte_count
 * @param tvsince
 * @param rate
 */
void transfer_rate_throttle(off_t byte_count, struct timeval *tvsince, off_t rate)
{
	time_t ideal_time = 0, elapsed_time = 0;

	/* Calculate the time interval since the transfer of data started. */
	elapsed_time = elapsed_time_count(tvsince);

	ideal_time = byte_count * 1000L / rate;

	if (ideal_time > elapsed_time) {
		struct timeval tvdelay;

		/* Setup for the select.  We use select() instead of usleep() because it
		 * seems to be far more portable across platforms.
		 *
		 * IdealTime and ElapsedTime are in milleconds, but tv_usec will be microseconds,
		 * so be sure to convert properly.
		 */
		tvdelay.tv_usec = (ideal_time - elapsed_time) * 1000;
		tvdelay.tv_sec = tvdelay.tv_usec / 1000000L;
		tvdelay.tv_usec = tvdelay.tv_usec % 1000000L;

		/* No interruptions, please... */
		transfer_rate_sigmask(1);

		if (select(0, NULL, NULL, NULL, &tvdelay) < 0)
			syslog(LOG_ERR, "warning: unable to throttle bandwidth: %s",
				   strerror(errno));

		transfer_rate_sigmask(0);

	}

	return;
}
