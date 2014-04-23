/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <string.h>
#include <paths.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <grp.h>
#include <arpa/ftp.h>
	   
#include "pathnames.h"
#include "smbftpd.h"
#include "restrict.h"
#include "ssl.h"
#include "auth.h"

extern smbftpd_share_t *smbftpd_shares;
extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

extern int login_attempts;
extern int askpasswd;

#ifndef LINE_MAX
	#define LINE_MAX 2048
#endif

/**
 * Terminate login as previous user, if any, resetting state; 
 * Used when USER command is given or login fails.
 */
void end_login(void)
{
	(void) seteuid(0);
	if (smbftpd_session.logged_in && smbftpd_conf.do_wtmp_log)
		smbftpd_logwtmp("", NULL);


	if (smbftpd_conf.transfer_log_path) {
		smbftpd_xferlog_close();
	}

	smbftpd_valid_share_free(&smbftpd_session.valid_shares);
	if (smbftpd_session.home) {
		free(smbftpd_session.home);
	}
	bzero(&smbftpd_session, sizeof(smbftpd_session));
}

/**
 * Performing password authentication. The USER command shoule send first.
 * 
 * @param passwd
 */
void cmd_pass(const char *passwd)
{
	int login_failed = 1;
	FILE *fd;
	char *chroot_dir = NULL, *home_dir = NULL;
	const char *dir = NULL;

#ifdef WITH_SSL
	if (!smbftpd_session.ssl_ctrl.ssl_active_flag &&
		!(smbftpd_conf.security_policy & SECURITY_POLICY_NOSECURE)) {
		reply_noformat(504, "TLS/SSL protection required.");
		return;
	}
#endif /* WITH_SSL */

	if (smbftpd_session.logged_in || askpasswd == 0) {
		reply_noformat(503, "Login with USER first.");
		return;
	}

	askpasswd = 0;
	if (!smbftpd_session.guest) {

		if (smbftpd_session.pw_user == NULL) {
			/* failure below */
			goto skip;
		}

		if ((*passwd == '\0') && (smbftpd_conf.empty_passwd_login == 0)) {
			reply_noformat(530, "Empty password is not allowed.");
			if (login_attempts++ >= 5) {
				syslog(LOG_NOTICE,
					   "repeated login failures from %s",
					   smbftpd_session.remotehost);
				exit(0);
			}
			return;
		}

		if (0 == smbftpd_auth_check(smbftpd_session.username, passwd)) {
			login_failed = 0;
		}
	skip:
		/*
		 * If login_failed == 1, the user failed the authentication check
		 * above.  If rval == 0, either PAM or local authentication
		 * succeeded.
		 */
		if (login_failed) {
			reply_noformat(530, "Login incorrect.");
			if (smbftpd_conf.log_command) {
				syslog(LOG_NOTICE,
					   "FTP LOGIN FAILED FROM %s",
					   smbftpd_session.remotehost);
				syslog(LOG_AUTHPRIV | LOG_NOTICE,
					   "FTP LOGIN FAILED FROM %s, %s",
					   smbftpd_session.remotehost, smbftpd_session.username);
			}
			smbftpd_session.pw_user = NULL;
			if (login_attempts++ >= 5) {
				syslog(LOG_NOTICE,
					   "repeated login failures from %s",
					   smbftpd_session.remotehost);
				exit(0);
			}
			return;
		}
	}
	login_attempts = 0;		/* this time successful */
	if (setegid(smbftpd_session.pw_user->pw_gid) < 0) {
		reply_noformat(550, "Can't set gid.");
		return;
	}

	/* May be overridden by login.conf */
	(void) umask(smbftpd_conf.umask);

#ifdef	__FreeBSD__
	setlogin(smbftpd_session.username);
#endif
	(void) initgroups(smbftpd_session.pw_user->pw_name, smbftpd_session.pw_user->pw_gid);

	/* open wtmp before chroot */
	if (smbftpd_conf.do_wtmp_log)
		smbftpd_logwtmp(smbftpd_session.username, smbftpd_session.remotehost);

	/* open xfer log before chroot */
	if (smbftpd_conf.transfer_log_path) {
		smbftpd_xferlog_open(smbftpd_conf.transfer_log_path);
	}

	smbftpd_session.logged_in = 1;
	smbftpd_session.transfer_type = TYPE_I;

	/* Get FTP configuration and limitions for current user*/
	smbftpd_session.mode = smbftpd_mode_get(smbftpd_conf.default_mode, 
											smbftpd_conf.exception_list, smbftpd_session.username);
	
	smbftpd_session.max_upload_rate = smbftpd_transfer_rate_get(smbftpd_conf.max_upload_rate, 
																smbftpd_session.username);
	smbftpd_session.max_download_rate = smbftpd_transfer_rate_get(smbftpd_conf.max_download_rate, 
																  smbftpd_session.username);
	smbftpd_valid_share_free(&smbftpd_session.valid_shares);
	
	smbftpd_session.byte_uploaded = 0;
	smbftpd_session.byte_downloaded = 0;

	if (smbftpd_session.guest) {
		home_dir = strdup(smbftpd_session.pw_user->pw_dir);
	} else {
		home_dir = smbftpd_auth_get_home(smbftpd_session.username);
	}
	if (home_dir == NULL) {
		reply_noformat(550, "Can't get home dir.");
		goto bad;
	}

	if (smbftpd_session.guest && smbftpd_session.mode != MODE_SMB) {
		dir = smbftpd_session.pw_user->pw_dir;
	} else {
		dir = smbftpd_chroot_path_get(smbftpd_conf.chroot_set, smbftpd_session.username);
	}
	if (dir) {
		smbftpd_session.chroot = 1;
		smbftpd_session.mode = MODE_NORMAL;

		if (dir[0] == '/') {
			chroot_dir = strdup(dir); /* so it can be freed */
		} else if (dir[0] == '~') {
			asprintf(&chroot_dir, "%s/%s", home_dir, dir+1);
		} else {
			asprintf(&chroot_dir, "%s/%s", home_dir, dir);
		}
		if (chroot_dir == NULL)
			fatalerror("Ran out of memory.");

		free(home_dir);
		home_dir = NULL;

		smbftpd_session.home = strdup("/");
		if (smbftpd_session.home == NULL) {
			fatalerror("Ran out of memory.");
		}

		/*
		 * Finally, do chroot()
		 */
		if (chroot(chroot_dir) < 0) {
			reply_noformat(550, "Can't change root.");
			goto bad;
		}
	} else	{/* real user w/o chroot */
		if (smbftpd_session.mode == MODE_SMB) {
			
			if (0 != smbftpd_valid_share_get(smbftpd_session.username, home_dir,
									smbftpd_shares, &smbftpd_session.valid_shares)) {
				fatalerror("Ran out of memory.");
			}
			free(home_dir);
			home_dir = NULL;

			smbftpd_session.home = strdup(PATH_SMB_FTPD_ROOT);
		} else {
			smbftpd_session.home = home_dir;
		}
	}
	if (smbftpd_session.home == NULL) {
		fatalerror("Ran out of memory.");
	}

	/*
	 * Set euid *before* doing chdir() so
	 * a) the user won't be carried to a directory that he couldn't reach
	 *    on his own due to no permission to upper path components,
	 * b) NFS mounted homedirs w/restrictive permissions will be accessible
	 *    (uid 0 has no root power over NFS if not mapped explicitly.)
	 */
	if (seteuid(smbftpd_session.pw_user->pw_uid) < 0) {
		reply_noformat(550, "Can't set uid.");
		goto bad;
	}

	if (chdir(smbftpd_session.home) < 0) {
		if (smbftpd_session.guest || smbftpd_session.chroot || smbftpd_session.mode == MODE_SMB) {
			reply_noformat(550, "Can't change to base directory.");
			goto bad;
		} else {
			if (chdir("/") < 0) {
				reply_noformat(550, "Root is inaccessible.");
				goto bad;
			}
			reply_noformat(LONG_REPLY(230), "No directory! Logging in with home=/.");
		}
	}

	/*
	 * Display a login message, if it exists.
	 * N.B. reply(230,) must follow the message.
	 */
	fd = fopen(PATH_FTPLOGINMESG, "r");
	if (fd != NULL) {
		char *cp, line[LINE_MAX];

		while (fgets(line, sizeof(line), fd) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			reply_noformat(LONG_REPLY(230), line);
		}
		(void) smbftpd_socket_fflush(stdout, 0);
		(void) fclose(fd);
	}
	if (smbftpd_session.guest) {

		reply_noformat(230, "Guest login ok, access restrictions apply.");

		proc_title_init("%s: anonymous/%s", smbftpd_session.remotehost, passwd);

		if (smbftpd_conf.log_command)
			syslog(LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s, %s",
				   smbftpd_session.remotehost, passwd);
	} else {
		if (smbftpd_session.chroot)
			reply(230, "User %s logged in, "
				  "access restrictions apply.", smbftpd_session.username);
		else
			reply(230, "User %s logged in.", smbftpd_session.username);

		proc_title_init("%s: user/%s", smbftpd_session.remotehost, smbftpd_session.username);

		if (smbftpd_conf.log_command)
			syslog(LOG_INFO, "FTP LOGIN FROM %s as %s",
				   smbftpd_session.remotehost, smbftpd_session.username);
	}

	if (chroot_dir)
		free(chroot_dir);
	return;
	bad:
	/* Forget all about it... */
	if (chroot_dir)
		free(chroot_dir);
	end_login();
}
