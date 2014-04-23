/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>

#include "smbftpd.h"
#include "pathnames.h"

#ifndef LINE_MAX
	#define LINE_MAX 2048
#endif

extern smbftpd_session_t smbftpd_session;

/**
 * Get the real full path on the filesystem. If the path is a symbolic
 * link, we will chdir to the path and use getcwd to get the realpath.
 * 
 * We need to make sure we are not using symbolic path in the share's
 * path. Otherwise, it will failed in smbftpd_get_realpath()
 * 
 * @param path
 * 
 * @return 
 */
static char *real_full_path(const char *path)
{
	static char real_path[PATH_MAX];
	char curpath[PATH_MAX];    

	bzero(real_path, sizeof(real_path));
	bzero(curpath, sizeof(curpath));

	getcwd(curpath, sizeof(curpath));
	if (chdir(path) == 0) {
		getcwd(real_path, sizeof(real_path));
		chdir(curpath);
		return real_path;
	} else {
		return NULL;   
	}
}

/**
 * Find the share in validshares and return its path.
 * 
 * @param validshares
 *               The linked list of all valid shares
 * @param share  The share name to look for
 * 
 * @return Return path of share when the share is found in the validshares.
 *         Return NULL if not found.
 */
static char *smbftpd_share_path_get(smbftpd_valid_share_t *validshares, const char *share)
{
	smbftpd_valid_share_t *p;
	char *path = NULL;

	if ((NULL == validshares) || (NULL == share)){
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return NULL;
	}

	p = validshares;
	while (p) {
		if (strcmp(share, p->share) == 0) {
			path = p->path;
			break;
		}
		p = p->next;
	}
	return path;
}

/**
 * Check whether the path is one of the share path root in the
 * validshares.
 * 
 * We will traverse the validshares and compare the share path with path.
 * When the path is the same, reture 1.
 * 
 * @param validshares
 *               The linked list of all valid shares
 * @param path   The path to search
 * 
 * @return 1: The path is a share root path
 *         0: The path is not a share root path
 */
static int is_share_root(smbftpd_valid_share_t *validshares, const char *path)
{
	smbftpd_valid_share_t *p;

	if (NULL == path){
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return 0;
	}

	p = validshares;
	while (p) {
		if (strcmp(path, p->path) == 0) {
			return 1;
		}
		p = p->next;
	}
	return 0;
}

/**
 * This function will replace the real path name to virtual path name
 * in the given path.
 * 
 * For example, if share "SHARE" has real path named "/volume1/share1",
 * when user access path "/volume1/share1/abc/cde", we will replace the
 * path to "/SHARE/abc/cde".
 * 
 * @param validshares
 *                The linked list of valid shares
 * @param path    The current path. We will compare the path with path in the
 *                validshares. If path matches, we will write new path in "path"
 * @param bufsize The buffer length of path
 * 
 * @return 0: Success
 *         -1: Failed or path not found in validshares
 */
int smbfptd_replace_share_path(smbftpd_valid_share_t *validshares, char *path, int bufsize)
{
	smbftpd_valid_share_t *p;
	char *slash;
	char buf[PATH_MAX];

	if ( (path == NULL) || (bufsize == 0) ) {
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return -1;
	}

	if (smbftpd_session.mode == MODE_NORMAL) {
		return 0;
	}

	if (strcmp(path, PATH_SMB_FTPD_ROOT) == 0) {
		snprintf(path, bufsize, "/");
		return 0;
	}

	snprintf(buf, sizeof(buf), "%s", path);

	p = validshares;
	while (p) {
		
		if (strncmp(p->path, path, strlen(p->path)) == 0) {
			slash = buf + strlen(p->path);
			if (*slash != '/' && *slash != '\0') {
				continue;
			}
			
			snprintf(path, bufsize, "/%s%s", p->share, slash);

			return 0;
		}
		p = p->next;
	}
	
	return -1;
}

/**
 * Get the pointer of smbftpd_valid_share_t from the given
 * validshares by path.
 * 
 * The path is a real full path. We will compare the path with path of
 * all shares in validshares. If path matches, reture the pointer of
 * the smbftpd_valid_share_t
 * 
 * @param validshares
 *               The linked list of valid shares
 * @param path   Real full path to check
 * 
 * @return NULL if no match share
 *         If found, return the valid share
 *         
 *         Please note the returned valid share is a const pointer. It
 *         is pointed to smbftpd_session.valid_shares.
 */
const smbftpd_valid_share_t *smbftpd_get_share_by_path(smbftpd_valid_share_t *validshares, const char *path)
{
	smbftpd_valid_share_t *p;
	const char *slash;

	// for each share, compare the path with the share path
	for (p = validshares; p; p = p->next) {
		if (!p->path) {
			continue;
		}
		if (strncmp(p->path, path, strlen(p->path)) == 0) {
			slash = path + strlen(p->path);
			if (*slash != '/' && *slash != '\0') {
				continue;
			}
			return p;
		}
	}
	return NULL;
}

/**
 * Check whether szPath is a valid path. We will go through the
 * validshares and check whenther the path is under valid shares.
 * When writable is not 0, we will also check the share must be
 * writable.
 * 
 * @param validshares
 *                 The linked list of valid shares
 * @param path     The path to check
 * @param writable Check whether the share is writable
 * 
 * @return 1: Yes
 *         0: No or failed
 */
static int smbftpd_is_under_valid_path(smbftpd_valid_share_t *validshares, const char *path, int writable)
{
	const smbftpd_valid_share_t *share;
	
	if (!path) {
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return 0;
	}

	share = smbftpd_get_share_by_path(validshares, path);
	if (!share) {
		return 0;
	}
	if (writable && !share->writable) {
		return 0;
	}

	return 1;
}

/**
 * This is the main path parse function.
 * 
 * The function will return the real path in the system by parse
 * the given path. We will chdir() into each component in the
 * given path to make sure the path is valid.
 * 
 * If flags & FLAG_CHECK_WRITABLE, than check whether path is writable.
 * If flags & FLAG_NO_FOLLOW_LINK, then do not follow the link.
 * If flags & FLAG_NO_FOLLOW_LAST_LINK, then we won't check the last
 * component.
 * 
 * @param validshares
 *               The linked list of valid shares
 * @param path   The path to convert
 * @param flags  If flags & FLAG_CHECK_WRITABLE, than check whether path is writable.
 *               If flags & FLAG_NO_FOLLOW_LINK, then do not follow the link.
 *               If flags & FLAG_NO_FOLLOW_LAST_LINK, then we won't check the last
 *               component.
 * 
 * @return Real path if the path is valid.
 *         NULL if the path is not allowed
 */
char *smbftpd_get_realpath(smbftpd_valid_share_t *validshares, const char *path, int flags)
{
	static char return_path[PATH_MAX+1];
	char	orig_pwd[PATH_MAX+1], curdir[PATH_MAX+1];
	char	token_path[PATH_MAX+1], tmp_path[PATH_MAX+1];
	char	*token;
	struct	stat statbuf;
	int err;

	if (!path) {
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return NULL;
	}

	if (smbftpd_session.mode == MODE_NORMAL) {
		if (flags & FLAG_NO_FOLLOW_LAST_LINK) {
			strcpy(return_path, path);
		} else {
			realpath(path, return_path);
		}
		
		return return_path;
	}

	if (*path == '\0') {
		return NULL;
	}

	bzero(tmp_path, sizeof(tmp_path));
	snprintf(tmp_path, sizeof(tmp_path), "%s", path);

REDO:
	bzero((void *)&statbuf, sizeof(statbuf));
	bzero(return_path, sizeof(return_path));
	bzero(orig_pwd, sizeof(orig_pwd));
	bzero(token_path, sizeof(token_path));

	getcwd(orig_pwd, sizeof(orig_pwd));
	// Check whether we are under valid path now
	if ((strcmp(orig_pwd, PATH_SMB_FTPD_ROOT) != 0) && 
		(smbftpd_is_under_valid_path(validshares, orig_pwd, 0) == 0)) {
		chdir(PATH_SMB_FTPD_ROOT);
		return NULL;
	}


	if (tmp_path[0] == '/') {
		snprintf(token_path, sizeof(token_path), "_@SMB_FTPD_ROOT@_%s", tmp_path);
		strcpy(return_path, "/");
	}else{
		snprintf(token_path, sizeof(token_path), "%s", tmp_path);
		snprintf(return_path, sizeof(return_path), "%s", tmp_path);
	}

	// separate the path by '/', and chdir into the path to check
	// whether each component name is in the valid path
	for (token = strtok(token_path, "/"); token != NULL; token = strtok(NULL, "/")) {
		// we are under virtual root
		if (strcmp(token, "_@SMB_FTPD_ROOT@_") == 0) {
			snprintf(return_path, sizeof(return_path), "%s", PATH_SMB_FTPD_ROOT);
			chdir(PATH_SMB_FTPD_ROOT);
			continue;
		}

		bzero(curdir, sizeof(curdir));
		getcwd(curdir, sizeof(curdir));

		//  chdir to / when cd .. if we are under the root of share path
		if ( (strcmp(token, "..") == 0) && (is_share_root(validshares, curdir) == 1) ) {
			snprintf(return_path, sizeof(return_path), "%s", PATH_SMB_FTPD_ROOT);
			chdir(PATH_SMB_FTPD_ROOT);
			continue;
		}

		// When under virtual root
		if (strcmp(curdir, PATH_SMB_FTPD_ROOT) == 0) {
			char *ptr;

			// chdir to virtual root when cd .. or . 
			if ((strcmp(token, ".") == 0) || (strcmp(token, "..") == 0)) {
				snprintf(return_path, sizeof(return_path), "%s", PATH_SMB_FTPD_ROOT);
				chdir(PATH_SMB_FTPD_ROOT);
				continue;
			// if next path is not valid share path, return NULL
			} else if ( (ptr = smbftpd_share_path_get(validshares, token)) == NULL) {
				chdir(orig_pwd);
				return NULL;
			} else {
				snprintf(return_path, sizeof(return_path), "%s", ptr);
				chdir(ptr);
				continue;
			}
		} else {
			// We are under valid share path now.
			if(smbftpd_is_under_valid_path(validshares, curdir, 0) == 0){
				// Not under valid share path
				chdir(orig_pwd);
				return NULL;
			}

			err = lstat(token, (struct stat *) &statbuf);
			if (err != 0) {
				goto LAST_COMPOENT;
			}

			// Dealing with directory
			if (S_ISDIR(statbuf.st_mode)){
				if (chdir(token)) {
					// Failed to chdir (directory not exist or permission denied)
					chdir(orig_pwd);
					return NULL;
				} else {
					bzero(curdir, sizeof(curdir));
					getcwd(curdir, sizeof(curdir));
					if (smbftpd_is_under_valid_path(validshares, curdir, 0) == 1) {
						strncpy(return_path, curdir, sizeof(return_path)-1);
						continue;
					} else {
						chdir(orig_pwd);
						return NULL;
					}
				}
			} else if ( S_ISLNK(statbuf.st_mode) && 
				    !(flags & FLAG_NO_FOLLOW_LINK) ) {  // Dealing with link

				if (flags & FLAG_NO_FOLLOW_LAST_LINK) {
					if (*(token+strlen(token)+1) == '\0') { // Last component
						goto LAST_COMPOENT;
					}
				}
				err = readlink(token, tmp_path, sizeof(tmp_path) - 1);
				if (err < 0) {
					syslog(LOG_ERR, "%s (%d) Why I can lstat, but can't readlink? errno:%d(%s)",
						__FILE__, __LINE__, errno, strerror(errno));
					return NULL;
				} else {
					tmp_path[err] = '\0';
				}

				if (*tmp_path != '/'){
					smbfptd_replace_share_path(validshares, curdir, sizeof(curdir));
					strcpy(return_path, curdir);
					snprintf(curdir, sizeof(curdir), "%s/%s", return_path, tmp_path);

					// Re-compose the path and parse again.
					if ( *(token + strlen(token) + 1) == '\0') {
						snprintf(tmp_path, sizeof(tmp_path), "%s", curdir);
					} else {
						snprintf(tmp_path, sizeof(tmp_path), "%s/%s", curdir, token+strlen(token)+1);
					}
				} else {
					// Re-compose the path and parse again.
					if ( *(token + strlen(token) + 1) != '\0') {
						snprintf(tmp_path, sizeof(tmp_path), "%s/%s", curdir, token+strlen(token)+1);
					}
				}

				chdir(orig_pwd);
				goto REDO;

			} else {	// Dealing with file
	LAST_COMPOENT:
				if ((flags & FLAG_CHECK_WRITABLE) && 
					smbftpd_is_under_valid_path(validshares, curdir, 1) == 0) {
					chdir(orig_pwd);
					return NULL;
				} else {
					snprintf(return_path, sizeof(return_path), "%s/%s", 
							 curdir, token);

					// There should be no next dir since it's a file
					if (strtok(NULL, "/")) {
						chdir(orig_pwd);
						return NULL;
					}
					chdir(orig_pwd);
					return return_path;
				}
			} // end of file or directory
		} // end of if under virtual root
	} // end of for
	if (flags & FLAG_CHECK_WRITABLE) {
		getcwd(curdir, sizeof(curdir));
		if (is_share_root(validshares, curdir) || 
			(smbftpd_is_under_valid_path(validshares, curdir, 1) == 0)) {
			chdir(orig_pwd);
			return NULL;
		}else{
			chdir(orig_pwd);
			return return_path;
		}
	} else {
		chdir(orig_pwd);
		return return_path;
	}
}

/**
 * Free the smbftpd_valid_share_t linked list.
 * 
 * @param validshares
 */
void smbftpd_valid_share_free(smbftpd_valid_share_t **validshares)
{
	smbftpd_valid_share_t *p;

	while (*validshares) {
		p = *validshares;
		*validshares = p->next;
		if (p->share) {
			free(p->share);
		}
		if (p->path) {
			free(p->path);
		}
		free(p);
	}
	
	return;
}

/* Get shares that is accessable by szUser and put in smbftpd_share_t
 *
 * Return Values:
 *	0: Success
 *	-1: Failed
 */
int smbftpd_valid_share_get(const char *user, const char *home_dir,
							smbftpd_share_t *shares, smbftpd_valid_share_t **ppvalid_shares)
{
	smbftpd_share_t *curr;
	struct stat statcheck;
	char *home = NULL;
	int writable = 0;
	int err = -1;
	int deny;

	if (NULL == user) {
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return -1;
	}

	if (NULL == shares) {
		*ppvalid_shares = NULL;
		return 0;
	}

	curr = shares;
	while (curr) {
		home = NULL;
		deny = 1;
		writable = 0;

		if (strcmp(curr->share, "homes") == 0) {
			char *ptr = real_full_path(home_dir);
			if (!ptr) {
				goto SKIP;
			}
			home = strdup(ptr);
			if (!home) {
				syslog(LOG_ERR, "%s (%d) Failed to strdup(%s). (%s)",
					   __FILE__, __LINE__, smbftpd_session.home, strerror(errno));
				goto Error;
			}
			deny = 0;
			writable = 1;
			goto SKIP;
		}

		if (1 == is_user_in_list(user, curr->rw)) {
			writable = 1;
			deny = 0;
		}

		if (deny == 1) {
			if (1 == is_user_in_list(user, curr->ro)) {
				deny = 0;
			}
		}
SKIP:
		// Shared is accessable for szUser
		if (deny == 0) {
			if (home || ((!stat(curr->path, &statcheck)) &&
				(S_ISDIR(statcheck.st_mode)))) {
				smbftpd_valid_share_t *pSet;

				pSet = calloc(1, sizeof(smbftpd_valid_share_t));
				if (pSet == NULL) {
					syslog(LOG_ERR, "%s (%d) Ran out of memory.", __FILE__, __LINE__);
					if (home) {
						free(home);
					}
					goto Error;
				}
				pSet->share = home?strdup("home"):strdup(curr->share);
				pSet->path = home?home:strdup(curr->path);
				pSet->browseable = curr->browseable;

				if (writable) {
					pSet->writable = 1;
				}
				if (is_user_in_list(user, curr->disable_download)) {
					pSet->disable_download = 1;
				}
				if (is_user_in_list(user, curr->disable_ls)) {
					pSet->disable_ls = 1;
				}
				if (is_user_in_list(user, curr->disable_modify)) {
					pSet->disable_modify = 1;
				}
				pSet->next = *ppvalid_shares;
				*ppvalid_shares = pSet;

			}
		}
		curr = curr->next;
	}

	err = 0;
Error:
	if (err) {
		smbftpd_valid_share_free(ppvalid_shares);
	}
	return err;
}

/**
 * Free all smbftpd_share linked list.
 * 
 * Make sure you set the smb_shares->next to NULL if you need to
 * free only one share.
 * 
 * @param smb_shares The linked list of smbftpd_share_t.
 */
void smbftpd_share_free(smbftpd_share_t **smb_shares)
{
	smbftpd_share_t *p;

	while (*smb_shares) {
		p = *smb_shares;
		*smb_shares = p->next;

		if (p->share) {
			free(p->share);
		}
		if (p->path) {
			free(p->path);
		}
		if (p->rw) {
			free(p->rw);
		}
		if (p->ro) {
			free(p->ro);
		}
		if (p->disable_download) {
			free(p->disable_download);
		}
		if (p->disable_ls) {
			free(p->disable_ls);
		}
		free(p);
	}
}

/**
 * This function will read the configuration in given smbftpd_share.conf
 * 
 * It will allocate memory for smb_shares to store share
 * information. So smbftpd_share_free() must be call to free it.
 * 
 * @param path
 * @param smb_shares
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_share_enum(char *path, smbftpd_share_t **smb_shares)
{
	smbftpd_share_t *prev, *cur;
	FILE *fp = NULL;
	char line[LINE_MAX], *ptr1, *ptr2;
	int err = -1;

	if (NULL == path) {
		syslog(LOG_ERR, "%s (%d) bad parameter", __FILE__, __LINE__);
		return -1;
	}

	fp = fopen(path, "r");
	if (NULL == fp) {
		syslog(LOG_ERR, "%s (%d) Failed to open share config [%s], errno:%d (%s)", 
			   __FILE__, __LINE__, path, errno, strerror(errno));
		goto Error;
	}

	while (NULL != fgets(line, sizeof(line), fp)) {
		// Skip spaces
		ptr1 = str_trim_space(line);

		if ((*ptr1 == '#') || (*ptr1 == '\0') || (*ptr1 == '\n')){
			continue;
		} else if (*ptr1 == '[') {
			ptr1++;
			ptr2 = strchr(ptr1, ']');
			if ((ptr2 != NULL) && (ptr2 - ptr1 > 0)) {
				smbftpd_share_t *p;

				*ptr2 = '\0';
				str_trim_space(ptr1);				
					
				p = calloc(1, sizeof(smbftpd_share_t));
				if (p == NULL) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
				p->share = strdup(ptr1);
				if (!p->share) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					free(p);
					goto Error;
				}
				p->browseable = 1;
				p->next = *smb_shares;
				*smb_shares = p;
			}
		} else {
			if (!*smb_shares) {
				/* We have not gotten a section */
				continue;
			}
			ptr2 = strchr(ptr1, '=');
			if (NULL == ptr2) {
				continue;
			}
			*ptr2 = '\0';
			ptr2++;
			str_trim_space_quote(ptr1);
			str_trim_space_quote(ptr2);
			if (strcmp(ptr1, "rw") == 0) {
				(*smb_shares)->rw = strdup(ptr2);
				if (!(*smb_shares)->rw) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
			} else if (strcmp(ptr1, "ro") == 0) {
				(*smb_shares)->ro = strdup(ptr2);
				if (!(*smb_shares)->ro) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
			} else if (strcmp(ptr1, "disable_download") == 0) {
				(*smb_shares)->disable_download = strdup(ptr2);
				if (!(*smb_shares)->disable_download) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
			} else if (strcmp(ptr1, "disable_ls") == 0) {
				(*smb_shares)->disable_ls = strdup(ptr2);
				if (!(*smb_shares)->disable_ls) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
			} else if (strcmp(ptr1, "disable_modify") == 0) {
				(*smb_shares)->disable_modify = strdup(ptr2);
				if (!(*smb_shares)->disable_modify) {
					syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
					goto Error;
				}
			} else if (strcmp(ptr1, "path") == 0) {

				char *ptr = real_full_path(ptr2);
				if (!ptr) {
					syslog(LOG_ERR, "%s (%d) path \"%s\" does not exist.", 
						   __FILE__, __LINE__, ptr2);
				} else {
					(*smb_shares)->path = strdup(ptr);
					if (!(*smb_shares)->path) {
						syslog(LOG_ERR, "%s (%d) Out of memory", __FILE__, __LINE__);
						goto Error;
					}
				}
			} else if (strcmp(ptr1, "browseable") == 0) {
				if (strcasecmp(ptr2, "no") == 0) {
					(*smb_shares)->browseable = 0;
				}
			}
		}
	}

	// Remove shares that have no path beside homes
	prev = cur = *smb_shares;
	while (cur) {
		if ((strcmp(cur->share, "homes") != 0) && !cur->path) {
			if (prev == cur) { /* Head */
				*smb_shares = cur->next;
				cur->next = NULL;
				smbftpd_share_free(&cur);
				prev = cur = *smb_shares;
			} else {
				prev->next = cur->next;
				cur->next = NULL;
				smbftpd_share_free(&cur);
				cur = prev->next;
			}
		} else {
			prev = cur;
			cur = cur->next;
		}
	}
	
	err = 0;
Error:
	if (fp) {
		fclose(fp);
	}
	if (err) {
		if (*smb_shares != NULL) {
			smbftpd_share_free(smb_shares);
		}
		return -1;
	} else {
		return 0;
	}
}

