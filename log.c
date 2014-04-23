/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <arpa/ftp.h>

#if __FreeBSD_version < 500000
/* we don't have timeconv.h in 4.x */
#else
#include <timeconv.h>
#endif
#include <utmp.h>
#include <sys/stat.h>

#include "smbftpd.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

static int transfer_log_fd = -1;
static int wtmp_fd = -1;

int smbftpd_xferlog_open(const char *log_path)
{
	if (!log_path) {
		return -1;
	}

	if (transfer_log_fd != -1) {
		close(transfer_log_fd);
	}

	transfer_log_fd = open(smbftpd_conf.transfer_log_path, O_WRONLY|O_APPEND|O_CREAT, 0644);
	if (transfer_log_fd < 0) {
		syslog(LOG_ERR, "%s (%d) Failed to open %s (%s)", __FILE__, __LINE__, 
			   smbftpd_conf.transfer_log_path, strerror(errno));
	}

	return transfer_log_fd;
}

void smbftpd_xferlog_close()
{
	if (transfer_log_fd != -1) {
		close(transfer_log_fd);
	}
	transfer_log_fd = -1;
}

void smbftpd_xferlog_write(const char *cmd, const char *file, off_t size, time_t tstart, time_t tend)
{
	char buf[MAXPATHLEN + 128];
	time_t tcur;
	time_t txfer = tend - tstart + (tend == tstart);

	if (transfer_log_fd < 0) {
		return;
	}
	
	time(&tcur);
	// Current time, remote host, user, command, transfer type(ASCII or Binary), transfer time, bytes, filename
	if (*file != '/') {
		char cwd[MAXPATHLEN + 1];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return;
		}
		snprintf(buf, sizeof(buf), "%.20s%17s%12s%8s%8s%8u%12llu\t%s/%s\n",
				 ctime(&tcur)+4, smbftpd_session.remotehost, smbftpd_session.username,
				 cmd, smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", 
				 txfer, size, cwd, file);
	} else {
		snprintf(buf, sizeof(buf), "%.20s%17s%12s%8s%8s%8u%12llu\t%s\n",
				 ctime(&tcur)+4, smbftpd_session.remotehost, smbftpd_session.username,
				 cmd, smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY",
				 txfer, size, file);
	}
		
	write(transfer_log_fd, buf, strlen(buf));
}

static void appendf(char **strp, const char *fmt, ...)
{
	va_list ap;
	char *ostr, *p;

	va_start(ap, fmt);
	vasprintf(&p, fmt, ap);
	va_end(ap);
	if (p == NULL)
		fatalerror("Ran out of memory.");
	if (*strp == NULL)
		*strp = p;
	else {
		ostr = *strp;
		asprintf(strp, "%s%s", ostr, p);
		if (*strp == NULL)
			fatalerror("Ran out of memory.");
		free(ostr);
	}
}

void smbftpd_logcmd(const char *cmd, const char *file1, const char *file2, off_t cnt)
{
	char *msg = NULL;
	char wd[MAXPATHLEN + 1];

	if (smbftpd_conf.log_command < 1)
		return;

	/* If either filename isn't absolute, get current dir for log message. */
	if (getcwd(wd, sizeof(wd) - 1) == NULL)
		strcpy(wd, strerror(errno));

	appendf(&msg, "%s", cmd);
	if (file1)
		appendf(&msg, " %s", file1);
	if (file2)
		appendf(&msg, " %s", file2);
	if (cnt >= 0)
		appendf(&msg, " = %lld bytes", cnt);
	if (wd[0])
		appendf(&msg, " (wd: %s)", wd);
	appendf(&msg, " (wd: %s", wd);
	if (smbftpd_session.chroot)
		appendf(&msg, "; chrooted");
	appendf(&msg, ")");

	syslog(LOG_INFO, "%s", msg);
	free(msg);
}


/**
 * This function is a modified version of logwtmp that holds wtmp 
 * file open after first call, for use with ftp (which may chroot
 * after login, but before logout).
 * 
 * @param name   user's name
 * @param host   The remote ip
 */
void smbftpd_logwtmp(const char *name, const char *host)
{
	struct utmp ut;
	struct stat buf;
	char line[16];

	snprintf(line, sizeof(line), "ftp%d", getpid());

	if (wtmp_fd < 0 && (wtmp_fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) < 0) {
		syslog(LOG_ERR, "%s (%d) errno:%s", __FILE__, __LINE__, strerror(errno));
		return;
	}
		
	if (fstat(wtmp_fd, &buf) == 0) {
		(void)strncpy(ut.ut_line, line, sizeof(ut.ut_line));
		(void)strncpy(ut.ut_name, name, sizeof(ut.ut_name));
		if (host) {
			(void)strncpy(ut.ut_host, host, sizeof(ut.ut_host));
		} else {
			ut.ut_host[0] = 0;
		}
		
#if	__FreeBSD_version < 500000
		(void)time(&ut.ut_time);
#else
		ut.ut_time = _time_to_time32(time(NULL));
#endif
		if (write(wtmp_fd, &ut, sizeof(struct utmp)) !=
			sizeof(struct utmp))
			(void)ftruncate(wtmp_fd, buf.st_size);
	} else {
		syslog(LOG_ERR, "%s (%d) errno:%s", __FILE__, __LINE__, strerror(errno));
	}
}
