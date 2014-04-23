/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "smbftpd.h"

#ifndef	LINE_MAX
#define	LINE_MAX	1024
#endif

static int is_number_string(const char *str)
{
	const char *p = str;

	if (!str) {
		return 0;
	}

	while (*p) {
		if (!isdigit(*p))
			return 0;
		p++;
	}
	return 1;
}

/**
 * Check if a user is in the file "fname".
 * 
 * The file format is like this:
 * 
 *    # comments
 *    user1
 *    user2
 *    @group1
 *    @group2
 * 
 * We will also check whether the user in the in @group by using
 * auth_method's auth_is_user_in_group() function.
 * @param fname  The filename to check
 * @param user   The username
 * 
 * @return 1: Yes, user is listed in the file
 *         0: No, file does not exist or user is not in the file
 */
static int is_user_in_file(const char *fname, const char *user)
{                   
	FILE *pf;
	char buf[LINE_MAX], *p;
	int found = 0;

	pf = fopen(fname, "r");
	if (pf == NULL) {
		syslog(LOG_ERR, "%s (%d) Failed to open no login list %s. (%s)",
			   __FILE__, __LINE__, fname, strerror(errno));
		return 0;
	}

	while (fgets(buf, sizeof(buf), pf)) {
		p = str_trim_space(buf);
		if (*p == '#' || *p == 0) {
			continue;
		}
		if (*p == '@') {
			// Group
			p++;
			if (is_user_in_group(user, p)) {
				found = 1;
				break;
			}
		} else {
			// User
			if (strcmp(p, user) == 0) {
				found = 1;
				break;
			}
		}
	}

	fclose(pf);

	return found;
}

/**
 * Check whether user in is no_login_list. The no_login_list can be
 * a absolute path to file or a user/@group list separated by ",".
 * 
 * @param no_login_list
 *               Absolute path to file or a user/@group list separated by ",".
 * @param user   The username to check
 * 
 * @return 0: User is not in no login list.
 *         -1: User is in no login list.
 */
int smbftpd_check_no_login(const char *no_login_list, const char *user)
{
	if (user == NULL) {
		return -1;
	}

	if (!no_login_list || *no_login_list == 0) {
		return 0;
	}

	if (*no_login_list == '/') {
		if (is_user_in_file(no_login_list, user)) {
			return -1;
		}
	} else if (is_number_string(no_login_list)) {
		int mini_uid;
		struct passwd *pw = NULL;

		mini_uid = atoi(no_login_list);

		pw = getpwnam(user);
		if (pw && pw->pw_uid < mini_uid) {
			return -1;
		}
	} else {
		// The is a list
		if (is_user_in_list(user, no_login_list)) {
			return -1;
		}
	}

	return 0;
}

