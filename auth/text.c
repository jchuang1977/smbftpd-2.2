/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>

#include "smbftpd.h"

static smbftpd_text_user_t usercache;
static char *confpath;

/**
 * Parse config file. Do nothing here
 * 
 * @param path
 * 
 * @return 0: Success
 *         -1: Failed
 */
int auth_text_config_parse(const char *path)
{
	if (!path) {
		return -1;
	}
	confpath = strdup(path);
	if (!confpath) {
		return -1;
	}

	return 0;
}


/**
 * Perform authentication by getting user and password from the text use
 * file.
 * 
 * It will:
 * 1. Get password from text user file according to given username.
 * 3. Encrypt the password and compare with password in text file.
 * 4. Cache the user's group and home directory
 * 
 * @param user     The login user
 * @param password The login password
 * 
 * @return 0: Authentication success.
 *         -1: Failed to auth
 */
int auth_text_check(const char *user, const char *password)
{
	char *crypted = NULL;
	int error = -1;

	smbftpd_text_user_free(&usercache);

	if (0 != smbftpd_text_user_get(confpath, user, &usercache)) {
		return -1;
	}

	crypted = crypt(password, usercache.password);
	if (!crypted) {
		goto Error;
	}

	if (strcmp(crypted, usercache.password) != 0) {
		goto Error;
	}

	error = 0;
Error:
	if (usercache.password) {
		/* Remove password from cache for security */
		free(usercache.password);
		usercache.password = NULL;
	}
	return error;
}

/**
 * Free config path and user cache
 */
void auth_text_config_free()
{
	if (confpath) {
		free(confpath);
		confpath = NULL;
	}
	smbftpd_text_user_free(&usercache);
}

/**
 * Check whether user belongs to given group. 
 * 
 * We support only 1 group per user.
 * 
 * We will check the user in cache, if given user is the same with
 * the user in cache, we will compare the group with cached group.
 * 
 * If user is not in cache, we will query file to get the group.
 * 
 * @param user   User to check
 * @param group  Group name to check
 * 
 * @return 1: Yes, user belongs to the group
 *         0: No, user does not belongs to the group or failed to query database
 */
int auth_text_is_user_in_group(const char *user, const char *group)
{
	smbftpd_text_user_t smbftpd_user;
	int error = 0;

	if (!group || !user) {
		return 0;
	}

	if (usercache.user && usercache.group) {
		if (strcmp(user, usercache.user) == 0) {
			if (strcmp(group, usercache.group) == 0) {
				return 1;
			} else {
				return 0;
			}
		}
	}

	bzero(&smbftpd_user, sizeof(smbftpd_user));
	if (0 != smbftpd_text_user_get(confpath, user, &smbftpd_user)) {
		return 0;
	}
	if (strcmp(smbftpd_user.group, group) == 0) {
		error = 1;
	}
	
	smbftpd_text_user_free(&smbftpd_user);

	return error;
}

/**
 * Get user's home directory. If user is current logged in user, we will
 * return the home directory in cache. If user is not current logged in
 * user, we will get text file for the user's home.
 * 
 * Caller should call free() to free the point.
 * 
 * @param user   User name
 * 
 * @return A pointer to the string if user found. If not found, return NULL.
 *         Caller should call free() to free the point.
 */
char *auth_text_get_home(const char *user)
{
	smbftpd_text_user_t smbftpd_user;
	char *home = NULL;

	if (!user) {
		return NULL;
	}

	if (usercache.user && usercache.home) {
		if (strcmp(user, usercache.user) == 0) {
			return strdup(usercache.home);
		}
	}

	bzero(&smbftpd_user, sizeof(smbftpd_user));
	if (0 != smbftpd_text_user_get(confpath, user, &smbftpd_user)) {
		return NULL;
	}

	home = strdup(smbftpd_user.home);

	smbftpd_text_user_free(&smbftpd_user);

	return home;
}
