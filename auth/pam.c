/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <grp.h>

#include "smbftpd.h"

#ifdef	USE_PAM

extern smbftpd_session_t smbftpd_session;

#include <security/pam_appl.h>

pam_handle_t *pamh = NULL;

struct usercache {
	char *user;
	char *home;
	uid_t uid;
	gid_t gid;
};
static struct usercache pwcache;

static void user_cache_free(struct usercache *p)
{
	if (p->user) free(p->user);
	if (p->home) free(p->home);
	p->user = NULL;
	p->home = NULL;
	p->uid = -1;
	p->gid = -1;
}

/*
 * the following code is stolen from imap-uw PAM authentication module and
 * login.c
 */
	#define COPY_STRING(s) (s ? strdup(s) : NULL)

struct cred_t {
	const char *uname;		/* user name */
	const char *pass;		/* password */
};
typedef struct cred_t cred_t;

static int auth_conv(int num_msg, const struct pam_message **msg,
					 struct pam_response **resp, void *appdata)
{
	int i;
	cred_t *cred = (cred_t *) appdata;
	struct pam_response *response;

	response = calloc(num_msg, sizeof *response);
	if (response == NULL)
		return PAM_BUF_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:	/* assume want user name */
			response[i].resp_retcode = PAM_SUCCESS;
			response[i].resp = COPY_STRING(cred->uname);
			/* PAM frees resp. */
			break;
		case PAM_PROMPT_ECHO_OFF:	/* assume want password */
			response[i].resp_retcode = PAM_SUCCESS;
			response[i].resp = COPY_STRING(cred->pass);
			/* PAM frees resp. */
			break;
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			response[i].resp_retcode = PAM_SUCCESS;
			response[i].resp = NULL;
			break;
		default:			/* unknown message style */
			free(response);
			return PAM_CONV_ERR;
		}
	}

	*resp = response;
	return PAM_SUCCESS;
}

/**
 * There is no config parser for PAM authentication. This function just
 * initial the user cache.
 * 
 * @param path
 * 
 * @return Always return 0.
 */
int auth_pam_config_parse(const char *path)
{
	/* Initial user cache when daemon starts */
	user_cache_free(&pwcache);

	return 0;
}

/**
 * Attempt to authenticate the user using PAM.  Returns 0 if the user is
 * authenticated, or -1 if not authenticated.
 * 
 * If some sort of PAM system error occurs (e.g., the "/etc/pam.d/ftpd" 
 * is missing) then this function returns -1, too. 
 * 
 * @param user
 * @param password
 * 
 * @return 0: User is authenticated
 *         -1: Not authenticated or PAM system error
 */
int auth_pam_check(const char *user, const char *password)
{
	cred_t auth_cred = { user, password};
	struct pam_conv conv = { &auth_conv, &auth_cred};
	struct passwd *pw;
	int rval = -1;
	int e;

	/* Initial user cache before login. User can login with different name
	 * in the same session. */
	user_cache_free(&pwcache);

	e = pam_start("ftpd", user, &conv, &pamh);
	if (e != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_start: %s", pam_strerror(pamh, e));
		return -1;
	}

	e = pam_set_item(pamh, PAM_RHOST, smbftpd_session.remotehost);
	if (e != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_set_item(PAM_RHOST): %s",
			   pam_strerror(pamh, e));
		return -1;
	}

	e = pam_authenticate(pamh, 0);
	switch (e) {
	case PAM_SUCCESS:
		// User/Password is valid
		break;

	case PAM_AUTH_ERR:
	case PAM_USER_UNKNOWN:
	case PAM_MAXTRIES:
		// Authentication failed
		goto Error;
	default:
		syslog(LOG_ERR, "pam_authenticate: %s", pam_strerror(pamh, e));
		goto Error;
	}

	pw = getpwnam(user);
	if (!pw) {
		goto Error;
	}

	e = pam_acct_mgmt(pamh, 0);
	if (e != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_acct_mgmt: %s", pam_strerror(pamh, e));
		goto Error;
	}

	e = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (e != PAM_SUCCESS) {
		syslog(LOG_ERR, "%s (%d)pam_setcred: %s", __FILE__, __LINE__, pam_strerror(pamh, e));
		goto Error;
	}

	pam_open_session(pamh, 0);
	pam_close_session(pamh,0);

	pwcache.user = strdup(user);
	pwcache.home = strdup(pw->pw_dir);
	pwcache.uid = pw->pw_uid;
	pwcache.gid = pw->pw_gid;

	rval = 0;
Error:
	if (pamh) {
		if ((e = pam_end(pamh, e)) != PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_end: %s", pam_strerror(pamh, e));
		}
		pamh = NULL;
	}
	return rval;
}

/**
 * Close/free config and user cache.
 */
void auth_pam_config_free()
{
	user_cache_free(&pwcache);

	return;
}

/**
 * Check whether user belongs to the group.
 * 
 * We will:
 * 1. getpwnam() to check whether pw_gid is the same with the group's
 *    gr_gid from getgrnam.
 * 2. Check whether user is in group's gr_mem.
 * 
 * @param user   The user name to check
 * @param group  The group name to check
 * 
 * @return 1: Yes, user belongs to the group
 *         0: No, user does not belong to the group
 */
int auth_pam_is_user_in_group(const char *user, const char *group)
{
	struct group *grp = NULL;
	gid_t gid;
	struct passwd *pw = NULL;
	char **ppmember;
	int err = 0;

	if (!user || !group) {
		return err;
	}

	if (pwcache.user && strcmp(pwcache.user, user) == 0 && pwcache.gid != -1) {
		/* user is cached. Use the gid in cache. */
		gid = pwcache.gid;
	} else {
		pw = getpwnam(user);
		if (NULL == pw) {
			return err;
		}
		gid = pw->pw_gid;
	}
	
	grp = getgrnam(group);
	if (NULL == grp) {
		return err;
	}

	if (gid == grp->gr_gid) {
		return 1;
	}
	
	ppmember = grp->gr_mem;
	while (*ppmember) {
		if (strcmp(*ppmember, user) == 0) {
			err = 1;
			break;
		}		
		ppmember++;
	}

	return err;
}

/**
 * Get the user's home. If the user name is in cache. We will return
 * home in cache. Otherwise, use getpwnam() to get pw_dir and return.
 * 
 * Caller should free() the returned string.
 * 
 * @param user   Which user's home to get?
 * 
 * @return String pointer or NULL on faill
 */
char *auth_pam_get_home(const char *user)
{
	struct passwd *pw = NULL;

	if (!user) {
		return NULL;
	}

	if (pwcache.user && strcmp(pwcache.user, user) == 0 && pwcache.home) {
		return strdup(pwcache.home);
	}

	pw = getpwnam(user);
	if (NULL == pw) {
		return NULL;
	}

	if (pw->pw_dir) {
		return strdup(pw->pw_dir);
	}

	return NULL;
}
#endif
