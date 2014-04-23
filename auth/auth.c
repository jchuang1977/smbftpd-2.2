/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>

#include "config.h"
#include "auth_int.h"

typedef struct smbftpd_auth_method {
	const char *name;
	int (*config_parse)(const char *file);
	int (*check)(const char *user, const char *password);
	void (*config_free)(void);
	int (*is_user_in_group)(const char *user, const char *group);
	char *(*get_home)(const char *user);
} smbftpd_auth_method_t;

static smbftpd_auth_method_t auth_list[] = {
	{ "unix", auth_unix_config_parse, auth_unix_check, auth_unix_config_free, 
		auth_unix_is_user_in_group, auth_unix_get_home },
#ifdef USE_PAM                       
	{ "pam", auth_pam_config_parse, auth_pam_check, auth_pam_config_free, 
		auth_pam_is_user_in_group, auth_pam_get_home },
#endif
	{ "text", auth_text_config_parse, auth_text_check, auth_text_config_free, 
		auth_text_is_user_in_group, auth_text_get_home },
#ifdef WITH_MYSQL
	{ "mysql", auth_mysql_config_parse, auth_mysql_check, auth_mysql_config_free, 
		auth_mysql_is_user_in_group, auth_mysql_get_home },
#endif
#ifdef WITH_PGSQL
	{ "pgsql", auth_pgsql_config_parse, auth_pgsql_check, auth_pgsql_config_free, 
		auth_pgsql_is_user_in_group, auth_pgsql_get_home },
#endif
	{ NULL, NULL, NULL, NULL }
};

static smbftpd_auth_method_t *auth_method;

/**
 * Parse and the authentication method config file.
 * 
 * @param method Authentication method. Could be "unix", "pam", "mysql", "pgsql",
 *               or "smbftpd".
 * @param path   The configuration file of the auth method. It should be a full path.
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_auth_config_parse(const char *method, const char *path)
{
	if (!auth_method) {
		auth_method = auth_list;
	}

	while (auth_method && auth_method->name) {
		if (strcasecmp(auth_method->name, method) == 0) {
			break;
		}
		auth_method++;
	}

	if (!auth_method || !auth_method->name) {
		syslog(LOG_ERR, "Authentication method (%s) not found.", method);
		return -1;
	}

	if (0 != auth_method->config_parse(path)) {
		return -1;
	}

	return 0;
}

/**
 * Perform user/password checking for the authentication method.
 * 
 * For pam and unix authentication, it also check expired time.
 * 
 * @param user     Username
 * @param password Password
 * 
 * @return 0: Pass authentication
 *         -1: Authentication failed. Either user/pass not match or system failed.
 */
int smbftpd_auth_check(const char *user, const char *password)
{
	if (!auth_method || !auth_method->check) {
		syslog(LOG_ERR, "%s (%d) Please do smbftpd_auth_init_config() first.", __FILE__, __LINE__);
		return -1;
	}

	if (0 == auth_method->check(user, password)) {
		return 0;
	} else {
		return -1;
	}
}

/**
 * Perform necessary action after authentication finished or program exists.
 */
void smbftpd_auth_config_free()
{
	if (!auth_method || !auth_method->config_free) {
		return;
	}
	auth_method->config_free();

	return;
}

/**
 * Check whether user belongs to the group.
 * 
 * We will check this by different authentication method. For example,
 * if we are using UNIX or PAM authentication, we will use getpwnam()
 * and getgrnam() to check groups. If we are using database authentication,
 * we will just check the group in database.
 * 
 * @param user   The user name to check
 * @param group  The group name to check
 * 
 * @return 1: Yes, user belongs to the group
 *         0: No, user does not belongs to the group or system failed
 */
int smbftpd_auth_is_user_in_group(const char *user, const char *group)
{
	if (!auth_method || !auth_method->is_user_in_group) {
		return 0;
	}
	return auth_method->is_user_in_group(user, group);
}

/**
 * Get user's home according to different authenticaion method.
 * 
 * Please note that caller should free() the returned buffer.
 * 
 * @param user   Which user's home to get
 * 
 * @return A string pointer of home directory or NULL on failed.
 */
char *smbftpd_auth_get_home(const char *user)
{
	if (!auth_method || !auth_method->get_home) {
		return NULL;
	}
	return auth_method->get_home(user);
}
