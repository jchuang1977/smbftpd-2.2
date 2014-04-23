/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <grp.h>

#include "config.h"

#ifdef	HAVE_SHADOW_H
#include <shadow.h>
#endif

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

/**
 * There is no config for the UNIX authentication. This function just
 * initial the user cache.
 * 
 * @param path
 * 
 * @return Always return 0
 */
int auth_unix_config_parse(const char *path)
{
	/* Initial user cache when daemon starts */
	user_cache_free(&pwcache);

	return 0;
}

/**
 * Perform password check
 * 
 * @param user     User name
 * @param password Password
 * 
 * @return 0: Success, password matches, user is allowed
 *         -1: The user failed the authentication check
 */
int auth_unix_check(const char *user, const char *password)
{
	struct passwd *pw;
#ifdef	HAVE_SHADOW_H
	struct spwd *sp;
#endif /* HAVE_SHADOW_H */
	char *crypted;
	int error;

	/* Initial user cache before login. User can login with different name
	 * in the same session. */
	user_cache_free(&pwcache);

	pw = getpwnam(user);
	if (!pw) {
		return -1;
	}

#ifdef	HAVE_SHADOW_H
	sp = getspnam(user);
	if (!sp) {
		return -1;
	}
	pw->pw_passwd = sp->sp_pwdp;
#endif /* HAVE_SHADOW_H */


	crypted = crypt(password, pw->pw_passwd);
	if (!crypted) {
		return -1;
	}
	error = strcmp(pw->pw_passwd, crypted);
	if (error != 0) {
		return -1;
	}

#ifdef	HAVE_PWEXPIRE
	if ( pw->pw_expire && time(NULL) >= pw->pw_expire) {
		return -1;
	}
#elif	defined(HAVE_SHADOW_H)
	if (sp->sp_expire > 0 || sp->sp_max > 0) {
		long today = time(NULL) / (24L * 60L * 60L);

		if (sp->sp_expire > 0 && sp->sp_expire < today) {
			return -1;               /* account expired */
		}
		if (sp->sp_max > 0 && sp->sp_lstchg > 0 &&
			(sp->sp_lstchg + sp->sp_max < today)) {
			return -1;               /* password expired */
		}  
	}
#endif 

	pwcache.user = strdup(user);
	pwcache.home = strdup(pw->pw_dir);
	pwcache.uid = pw->pw_uid;
	pwcache.gid = pw->pw_gid;

	return 0;
}

/**
 * Free config and user cache.
 */
void auth_unix_config_free()
{
	user_cache_free(&pwcache);
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
int auth_unix_is_user_in_group(const char *user, const char *group)
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
char *auth_unix_get_home(const char *user)
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

