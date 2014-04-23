/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>

#include "smbftpd.h"

#ifndef LINE_MAX
#define LINE_MAX 2048
#endif

/**
 * Free the members of smbftpd_text_user_t and bzero it.
 * 
 * @param smbftpd_user
 */
void smbftpd_text_user_free(smbftpd_text_user_t *smbftpd_user)
{
	if (smbftpd_user->user) {
		free(smbftpd_user->user);
	}
	if (smbftpd_user->group) {
		free(smbftpd_user->group);
	}
	if (smbftpd_user->home) {
		free(smbftpd_user->home);
	}
	if (smbftpd_user->password) {
		free(smbftpd_user->password);
	}
	bzero(smbftpd_user, sizeof(smbftpd_text_user_t));
}

/**
 * Get user from path. The file format is:
 * 
 * user:group:home:password
 * 
 * @param path   The path of smbftpd text user config file
 * @param user   The user name to get
 * @param smbftpd_user
 *               Result of the suer's data
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_text_user_get(const char *path, const char *user, smbftpd_text_user_t *smbftpd_user)
{
	FILE *fp = NULL;
	char buf[LINE_MAX];
	char *h, *t;
	int line = 0, error = -1;

	if (!path || !user || !smbftpd_user) {
		return -1;
	}

	bzero(smbftpd_user, sizeof(smbftpd_text_user_t));
	fp = fopen(path, "r");
	if (!fp) {
		syslog(LOG_ERR, "%s (%d) Failed to open %s. (%s)", __FILE__, __LINE__, path, strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		line++;
		str_trim_space(buf);
		if (*buf == 0 || *buf=='#') {
			continue;
		}
		// User
		h = buf;
		t = strchr(h, ':');
		if (!t) {
			syslog(LOG_ERR, "%s (%d) Skip invalid line %d", __FILE__, __LINE__, line);
			continue;
		}
		*t = 0;
		str_trim_space(h);
		if (strcmp(user, h) != 0) {
			continue;
		}
		smbftpd_user->user = strdup(h);
		if (!smbftpd_user->user) {
			syslog(LOG_ERR, "%s (%d) Out of memory.", __FILE__, __LINE__);
			goto Error;
		}

		// group
		h = t+1;
		t = strchr(h, ':');
		if (!t) {
			syslog(LOG_ERR, "%s (%d) Skip invalid line %d", __FILE__, __LINE__, line);
			smbftpd_text_user_free(smbftpd_user);
			continue;
		}
		*t = 0;
		str_trim_space(h);
		smbftpd_user->group = strdup(h);
		if (!smbftpd_user->group) {
			syslog(LOG_ERR, "%s (%d) Out of memory.", __FILE__, __LINE__);
			goto Error;
		}

		// home
		h = t+1;
		t = strchr(h, ':');
		if (!t) {
			syslog(LOG_ERR, "%s (%d) Skip invalid line %d", __FILE__, __LINE__, line);
			smbftpd_text_user_free(smbftpd_user);
			continue;
		}
		*t = 0;
		str_trim_space(h);
		smbftpd_user->home = strdup(h);
		if (!smbftpd_user->home) {
			syslog(LOG_ERR, "%s (%d) Out of memory.", __FILE__, __LINE__);
			goto Error;
		}

		// password
		h = t+1;
		str_trim_space(h);
		smbftpd_user->password = strdup(h);
		if (!smbftpd_user->password) {
			syslog(LOG_ERR, "%s (%d) Out of memory.", __FILE__, __LINE__);
			goto Error;
		}

		break;
	}
	if (ferror(fp)) {
		syslog(LOG_ERR, "%s (%d) Failed to read %s. (%s)", __FILE__, __LINE__, path, strerror(errno));
		goto Error;
	}
	if (!smbftpd_user->password || !smbftpd_user->password ||
		!smbftpd_user->password || !smbftpd_user->password) {
		goto Error;
	}

	error = 0;

Error:
	if (error != 0) {
		smbftpd_text_user_free(smbftpd_user);
	}
	if (fp) {
		fclose(fp);
	}
	return error;
}

/**
 * Add/Edit/Delete a user from user file.
 * 
 * If the smbftpd_user is NULL, we will delete the user.
 * 
 * If user is not found in the file, we will add the user.
 * 
 * if user is found, update the line by the smbftpd_user.
 * 
 * @param path   The path of text user file
 * @param user   The user to add/edit/delete
 * @param smbftpd_user
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_text_user_set(const char *path, const char *user, const smbftpd_text_user_t *smbftpd_user)
{
	FILE *fin = NULL, *fout = NULL;
	char buf[LINE_MAX];
	char tmp_path[PATH_MAX];
	char *p;
	int found = 0, error = -1;

	if (!path || !user) {
		return -1;
	}

	snprintf(tmp_path, sizeof(tmp_path), "%s.%d", path, getpid());

	umask(066);
	fout = fopen(tmp_path, "w");
	if (!fout) {
		syslog(LOG_ERR, "%s (%d) Failed to open %s.(%s)", __FILE__, __LINE__, tmp_path, strerror(errno));
		goto Error;
	}

	fin = fopen(path, "r");
	if (!fin) {
		if (smbftpd_user && errno == ENOENT) {
			fprintf(fout, "%s:%s:%s:%s\n", smbftpd_user->user, 
				smbftpd_user->group, smbftpd_user->home, smbftpd_user->password);
			error = 0;
		}
		goto Error;
	}
	
	if (!fin || !fout) {
		syslog(LOG_ERR, "%s (%d) Failed to open %s.(%s)", __FILE__, __LINE__, path, strerror(errno));
		goto Error;
	}

	while (fgets(buf, sizeof(buf), fin)) {
		if (strncmp(user, buf, strlen(user)) != 0) {
			fputs(buf, fout);
			continue;
		}
		p = buf + strlen(user);
		if (*p != ':') {
			continue;
		}
		if (found) {
			syslog(LOG_ERR, "Skip redundant user %s", user);
			continue;
		}
		found = 1;

		if (smbftpd_user) {
			fprintf(fout, "%s:%s:%s:%s\n", smbftpd_user->user, 
					smbftpd_user->group, smbftpd_user->home, smbftpd_user->password);
		} else {
			// Do nothing to delete user.
		}		
	}
	if (!found) {
		fprintf(fout, "%s:%s:%s:%s\n", smbftpd_user->user, 
				smbftpd_user->group, smbftpd_user->home, smbftpd_user->password);
	}
	if (ferror(fin) || ferror(fout)) {
		syslog(LOG_ERR, "%s (%d) %s: %s", __FILE__, __LINE__, path, strerror(errno));
		goto Error;
	}

    fflush(fout);
    fsync(fileno(fout));

	error = 0;
Error:
	if (fin) {
		fclose(fin);
	}
	if (fout) {
		fclose(fout);
	}
	if (error == 0) {
		rename(tmp_path, path);
	} else {
		unlink(tmp_path);
	}

	return error;
}
