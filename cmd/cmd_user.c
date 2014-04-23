/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <paths.h>

#include "smbftpd.h"
#include "restrict.h"
#include "cmd_int.h"

#ifdef	HAVE_SHADOW_H
#include <shadow.h>
#endif

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

int login_attempts;
int askpasswd;

/*
 * Helper function for sgetpwnam().
 */
static char *sgetsave(char *s)
{
	char *new = malloc((unsigned) strlen(s) + 1);

	if (new == NULL) {
		reply_noformat(421, "Ran out of memory.");
		dologout(1);
		/* NOTREACHED */
	}
	(void) strcpy(new, s);
	return(new);
}

/*
 * Save the result of a getpwnam.  Used for USER command, since
 * the data returned must not be clobbered by any other command
 * (e.g., globbing).
 */
static struct passwd *sgetpwnam(const char *name)
{
	static struct passwd save;
	struct passwd *p;
#ifdef	HAVE_SHADOW_H
	struct spwd *sp;
#endif /* HAVE_SHADOW_H */

	if ((p = getpwnam(name)) == NULL)
		return(p);
	if (save.pw_name) {
		free(save.pw_name);
		free(save.pw_passwd);
		free(save.pw_gecos);
		free(save.pw_dir);
		free(save.pw_shell);
	}
	save = *p;
	save.pw_name = sgetsave(p->pw_name);

#ifdef	HAVE_SHADOW_H
	if ((sp = getspnam(p->pw_name)) != NULL) {
		save.pw_passwd = sgetsave(sp->sp_pwdp);
	} else
#endif /* HAVE_SHADOW_H */
		save.pw_passwd = sgetsave(p->pw_passwd);
	save.pw_gecos = sgetsave(p->pw_gecos);
	save.pw_dir = sgetsave(p->pw_dir);
	save.pw_shell = sgetsave(p->pw_shell);
	return(&save);
}
/**
 * USER command.
 * 
 * Sets global passwd pointer smbftpd_session.pw_user if named 
 * account exists and is acceptable; sets askpasswd if a PASS
 * command is expected.  If logged in previously, need to reset
 * state.  If name is "ftp" or "anonymous", the name is not in
 * smbftpd_conf.no_login_list, and ftp account exists, set guest
 * and smbftpd_session.pw_user, then just return. If account 
 * doesn't exist, ask for passwd anyway.  Otherwise, check user
 * requesting login privileges. Disallow anyone who does not
 * have a standard shell as returned by getusershell().  Disallow
 * anyone mentioned in the smbftpd_conf.no_login_list to allow
 * people such as root and uucp to be avoided.
 * 
 * @param name   User name
 */
void cmd_user(const char *name)
{
#ifdef WITH_SSL
	if (!smbftpd_session.ssl_ctrl.ssl_active_flag &&
		!(smbftpd_conf.security_policy & SECURITY_POLICY_NOSECURE)) {
		reply_noformat(504, "TLS/SSL protection required.");
		return;
	}
#endif
	if (smbftpd_session.logged_in) {
		if (smbftpd_session.guest) {
			reply_noformat(530, "Can't change user from guest login.");
			return;
		} else if (smbftpd_session.chroot) {
			reply_noformat(530, "Can't change user from chroot user.");
			return;
		}
		end_login();
	}

	if (smbftpd_conf.anonymous_only || (smbftpd_conf.anonymous_login && 
										(strcmp(name, "ftp") == 0 || strcmp(name, "anonymous") == 0))) {
#ifdef WITH_SSL /* policy checking */
		/* Deny anonymous access over secure session. */
		if (smbftpd_session.ssl_ctrl.ssl_active_flag && smbftpd_conf.anonym_disable_secure) {
			reply(534,
				  "User %s secure access denied for policy reasons.",
				  name);
			return;
		}
#endif /* WITH_SSL */

		smbftpd_session.pw_user = sgetpwnam("ftp");
		if (smbftpd_session.pw_user != NULL) {

			smbftpd_session.guest = 1;
			askpasswd = 1;
			snprintf(smbftpd_session.username, sizeof(smbftpd_session.username), "ftp");

			reply_noformat(331,
						   "Guest login ok, send your email address as password.");
		} else {
			syslog(LOG_ERR, "You must create \"ftp\" user to use anonymous FTP.");
			reply(530, "User %s unknown.", name);
		}
			
		// Both "anonymous" and "ftp" are mapping to "ftp".
		return;
	}
	if (smbftpd_conf.anonymous_only != 0) {
		reply_noformat(530, "Sorry, only anonymous ftp allowed.");
		return;
	}

	smbftpd_session.guest = 0;

#ifdef WITH_SSL /* policy checking */
	/* Deny non-anonymous access over non-secure session. */
	if (!smbftpd_session.ssl_ctrl.ssl_active_flag && smbftpd_conf.normal_user_must_secure) {
		reply(534,
			  "User %s non-secure access denied for policy reasons.",
			  name);
		if (smbftpd_conf.log_command)
			syslog(LOG_NOTICE,
				   "NON-SECURE FTP LOGIN REFUSED FROM %s, %s",
				   smbftpd_session.remotehost, name);
		return;
	}
#endif /* WITH_SSL */

	if (smbftpd_conf.virtual_user_mapping) { // virtual user
		smbftpd_session.pw_user = sgetpwnam(smbftpd_conf.virtual_user_mapping);
	} else {
		smbftpd_session.pw_user = sgetpwnam(name);
	}
	if (smbftpd_session.pw_user) {
		if ((!smbftpd_conf.virtual_user_mapping && smbftpd_conf.require_valid_shell && 
			 0 != smbftpd_valid_shell(smbftpd_session.pw_user->pw_shell)) ||
			0 != smbftpd_check_no_login(smbftpd_conf.no_login_list, name)) {

			reply(530, "User %s access denied.", name);
			if (smbftpd_conf.log_command)
				syslog(LOG_NOTICE,
					   "FTP LOGIN REFUSED FROM %s, %s",
					   smbftpd_session.remotehost, name);
			smbftpd_session.pw_user = (struct passwd *) NULL;
			return;
		}
	}
	snprintf(smbftpd_session.username, sizeof(smbftpd_session.username), "%s", name);

	reply(331, "Password required for %s.", name);

	askpasswd = 1;
	/*
	 * Delay before reading passwd after first failed
	 * attempt to slow down passwd-guessing programs.
	 */
	if (login_attempts)
		sleep((unsigned) login_attempts);
}
