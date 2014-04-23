/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <errno.h>
#include <glob.h>
#include <stdlib.h>

#include "pathnames.h"
#include "smbftpd.h"
#include "cmd.h"
#include "ssl.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;

/**
 * stat a file or directory and send its information to client.
 * 
 * @param name    The path to list
 * @param pclient data stream
 * @param verbose 1: LIST
 *                0: NLIST
 */
static void smbftpd_stat_filesystem(const char *name, FILE * pclient, int verbose)
{
	struct stat st;
	struct tm tmfile;
	char perm[11], timestr[13];
	char link_target[MAXPATHLEN + 5], tmp[MAXPATHLEN + 1];
#ifdef WITH_SSL
	char buf[MAXPATHLEN + 512];
#endif
	char convert_buf[MAXPATHLEN+1];
	int err;
	time_t t;

	if (lstat(name, (struct stat *) &st) < 0) {
		syslog(LOG_ERR, "%s (%d) Failed to lstat %s", __FILE__, __LINE__, name);
		return;
	}

	if (S_ISLNK(st.st_mode)) {
		if (smbftpd_conf.show_symlinks == 0) {
			return;
		}
		strcpy(perm, "lrwxrwxrwx");
		err = readlink(name, tmp, sizeof(tmp) - 1);
		if (err < 0) {
			syslog(LOG_ERR, "%s (%d) FTP readlink() error, error code:%d", 
				   __FILE__, __LINE__, errno);
			return;
		} else {
			tmp[err] = '\0';
		}

		snprintf(link_target, sizeof(link_target), " -> %s",
				 smbftpd_charset_fs2client(tmp, convert_buf, sizeof(convert_buf)));

	} else {
		strcpy(perm, "----------");
		if (S_ISDIR(st.st_mode))
			perm[0] = 'd';
		if (st.st_mode & S_IRUSR)
			perm[1] = 'r';
		if (st.st_mode & S_IWUSR)
			perm[2] = 'w';
		if (st.st_mode & S_IXUSR)
			perm[3] = 'x';
		if (st.st_mode & S_IRGRP)
			perm[4] = 'r';
		if (st.st_mode & S_IWGRP)
			perm[5] = 'w';
		if (st.st_mode & S_IXGRP)
			perm[6] = 'x';
		if (st.st_mode & S_IROTH)
			perm[7] = 'r';
		if (st.st_mode & S_IWOTH)
			perm[8] = 'w';
		if (st.st_mode & S_IXOTH)
			perm[9] = 'x';
		link_target[0] = '\0';		
	} 
	memcpy(&tmfile, localtime(&(st.st_mtime)), sizeof(struct tm));
	time(&t);
	if (tmfile.tm_year == localtime(&t)->tm_year){
		strncpy(timestr, ctime(&(st.st_mtime)) + 4, 12);
	} else {
		strftime(timestr, sizeof(timestr), "%b %d  %Y", &tmfile);
	}
	timestr[12]='\0';

	name = smbftpd_charset_fs2client(name, convert_buf, sizeof(convert_buf));

	if (verbose) {
#ifdef WITH_SSL
		if (pclient == stdout && smbftpd_session.ssl_ctrl.ssl_active_flag) {
			snprintf(buf, sizeof(buf), "%s %3s %-8s %-8s %12llu %s %s%s\r\n", 
					 perm, "1", user_from_uid(st.st_uid, 0), group_from_gid(st.st_gid, 0),
					 (unsigned long long) st.st_size,
					 timestr, name, link_target);
			ssl_write(ssl_con, buf, strlen(buf));
		} else if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
			snprintf(buf, sizeof(buf), "%s %3s %-8s %-8s %12llu %s %s%s\r\n", 
					 perm, "1", user_from_uid(st.st_uid, 0), group_from_gid(st.st_gid, 0),
					 (unsigned long long) st.st_size,
					 timestr, name, link_target);
			ssl_write(ssl_data_con, buf, strlen(buf));
		} else
#endif
		fprintf(pclient, "%s %3s %-8s %-8s %12llu %s %s%s\r\n", perm, "1", 
				user_from_uid(st.st_uid, 0), group_from_gid(st.st_gid, 0),
				(unsigned long long) st.st_size,
				timestr, name, link_target);
	} else {
#ifdef WITH_SSL
		if (pclient == stdout && smbftpd_session.ssl_ctrl.ssl_active_flag) {
			snprintf(buf, sizeof(buf), "%s\r\n", name);
			ssl_write(ssl_con, buf, strlen(buf));
		} else if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
			snprintf(buf, sizeof(buf), "%s\r\n", name);
			ssl_write(ssl_data_con, buf, strlen(buf));
		} else
#endif
		fprintf(pclient,"%s\r\n", name);
	}

	return;
}

/**
 * List share's information and send to client.
 * 
 * @param share   Share name to list
 * @param name    The realpath of share
 * @param pclient data stream
 * @param verbose LIST or NLIST
 */
static void smbftpd_stat_shares(const char *share, const char *name, FILE * pclient, int verbose)
{
	struct stat st;
	struct tm tmfile;
	char perm[11], timestr[13];
#ifdef WITH_SSL
	char buf[NAME_MAX+512];
#endif
	char convert_buf[NAME_MAX+1];
	time_t t;

	lstat(name, (struct stat *) &st);
	strncpy(perm, "dr-x------", sizeof(perm));
	memcpy(&tmfile, localtime(&(st.st_mtime)), sizeof(struct tm));
	time(&t);
	if (tmfile.tm_year == localtime(&t)->tm_year){
		strncpy(timestr, ctime(&(st.st_mtime)) + 4, 12);
	} else {
		strftime(timestr, sizeof(timestr), "%b %d  %G", &tmfile);
	}
	timestr[12]='\0';

	share = smbftpd_charset_fs2client(share, convert_buf, sizeof(convert_buf));

	if (verbose) {
#ifdef WITH_SSL
		if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
			snprintf(buf, sizeof(buf), "%s %3i %s %-5s %12llu %s %s\r\n", 
					 perm , 1, "root", "users", (unsigned long long) st.st_size, 
					 timestr, share);
			ssl_write(ssl_data_con, buf, strlen(buf));
		} else
#endif
		fprintf(pclient, "%s %3i %s %-5s %12llu %s %s\r\n", perm , 1, "root", "users", 
				(unsigned long long) st.st_size, timestr, share);
	}else{
#ifdef WITH_SSL
		if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
			snprintf(buf, sizeof(buf), "%s\r\n", share);
			ssl_write(ssl_data_con, buf, strlen(buf));
		} else
#endif
		fprintf(pclient, "%s\r\n", share);
	}

	return;
}

static char gcwd[MAXPATHLEN+1];
/**
 * Main routine of list command.
 * 
 * @param path      Path to list
 * @param pfclient  output data stream
 * @param verbose   1: LIST
 *                  0: NLIST
 * @param recursive Recursive list or not
 * 
 * @return -1: Receive Abort command
 *         0: File list transfer complete
 */
int smbftpd_dir_list(const char *path, FILE * pfclient, int verbose, int recursive)
{
	const smbftpd_valid_share_t *share;
	struct stat st;
	char cwd[MAXPATHLEN+1], real_path[MAXPATHLEN+1], search_path[MAXPATHLEN+1];
	char buf[MAXPATHLEN], dir[MAXPATHLEN+1], *ptr;
	const char *name;
	int i, flags = FLAG_NO_FOLLOW_LAST_LINK, need_concate_path = 0;
	glob_t gl;

	if ((strstr(path, "/.")) && strchr(path, '*'))
		return 0; /* DoS protection */

	// When NLIST, we have to show the path so the mget can work
	if (!verbose && strchr(path, '/')) {
		need_concate_path = 1;
	}

	snprintf(search_path, sizeof(search_path), "%s", path);
	if (strchr(path, '*') || strchr(path, '?') || strchr(path, '[')) {
		// Check pattern for glob()

		ptr = strrchr(search_path, '/');
		if (NULL != ptr) {
			*ptr = '\0';
			name = ptr+1;
			if (strchr(search_path, '*') || strchr(search_path, '?') || strchr(search_path, '[')) {
				// We don't support xxx/*/xxx
				return 0;
			}
			flags = 0;
		} else {
			strcpy(search_path, ".");
			name = path;
		}
	} else {
		name = NULL;
		if (search_path[strlen(search_path) - 1] == '/') {
			flags = 0;
		}
	}
	
	ptr = smbftpd_get_realpath(smbftpd_session.valid_shares, search_path, flags);
	if (NULL == ptr) {
		goto ErrorOut;
	}
	snprintf(real_path, sizeof(real_path), "%s", ptr);

	if ((smbftpd_session.mode == MODE_SMB) && strcmp(real_path, PATH_SMB_FTPD_ROOT) == 0) {
		smbftpd_valid_share_t *p = smbftpd_session.valid_shares;
		while (p) {
			// List all readable shares
			if (p->browseable) {
				START_UNSAFE;
				smbftpd_stat_shares(p->share, p->path, pfclient, verbose);
				END_UNSAFE;
				if (sigurg_received()) {
					if (check_oob()) {
						return -1;
					}
				}
			}
			p = p->next;
		}
	} else {
		if (smbftpd_session.mode == MODE_SMB) {
			share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
			if (!share || share->disable_ls) {
				return 0;
			}
		}

		bzero(cwd, sizeof(cwd));
		getcwd(cwd, sizeof(cwd) - 1);

		if (lstat(real_path, (struct stat *) &st) < 0) {
			goto ErrorOut;
		} else  if (S_ISDIR(st.st_mode)) {
			chdir(real_path);
			if (name) {
				glob(name, 0, NULL, &gl);
			} else {
				// Also list file begin with dot
				if (smbftpd_conf.show_dot_files) {
					glob(".*", 0, NULL, &gl);
					glob("*", GLOB_APPEND, NULL, &gl);
				} else {
					glob("*", 0, NULL, &gl);
				}
			}
		} else {
			glob(real_path, 0, NULL, &gl);
		}
				
		// The recursive stuff is for ffftp, it recursive lists all files
		// before deletes them.
		if (recursive == 1) {
			snprintf(gcwd, sizeof(gcwd), "%s", cwd);
		} else if (recursive > 1) {
			char convert_buf[PATH_MAX+1];

			if (strncmp(gcwd, real_path, strlen(gcwd)) == 0) {
				ptr = real_path + strlen(gcwd) + 1;
			} else {
				ptr = real_path;
			}

			snprintf(buf, sizeof(buf), "\r\n./%s:\r\n",
					 smbftpd_charset_fs2client(ptr, convert_buf, sizeof(convert_buf)));

			START_UNSAFE;
#ifdef WITH_SSL
			if (pfclient == stdout && smbftpd_session.ssl_ctrl.ssl_active_flag) {
				ssl_write(ssl_con, buf, strlen(buf));
			} else if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
				ssl_write(ssl_data_con, buf, strlen(buf));
			} else 
#endif
			fprintf(pfclient, "%s", buf);
			END_UNSAFE;
			if (sigurg_received()) {
				if (check_oob()) {
					return -1;
				}
			}
		}


		if (need_concate_path) {
			chdir(cwd);
			strcpy(dir, path);
			ptr = strrchr(dir, '/');
			*ptr = '\0';
		}
		for (i = 0; i < gl.gl_pathc; i++){
			if ((strcmp(gl.gl_pathv[i],".")==0) ||
				(strcmp(gl.gl_pathv[i],"..")==0)) {
				continue;
			}
			START_UNSAFE;
			if (need_concate_path) {
				snprintf(buf, sizeof(buf), "%s/%s", dir, gl.gl_pathv[i]);
				smbftpd_stat_filesystem(buf, pfclient, verbose);
			} else {
				smbftpd_stat_filesystem(gl.gl_pathv[i], pfclient, verbose);
			}
			END_UNSAFE;
			if (sigurg_received()) {
				if (check_oob()) {
					return -1;
				}
			}
		}

		if (recursive) {
			for (i = 0; i < gl.gl_pathc; i++) {

				if ((strcmp(gl.gl_pathv[i],".")==0) ||
					(strcmp(gl.gl_pathv[i],"..")==0)) {
					continue;
				}
				bzero(&st, sizeof(st));
				lstat(gl.gl_pathv[i], (struct stat *) &st);
				if (S_ISDIR(st.st_mode)) {
					smbftpd_dir_list(gl.gl_pathv[i], pfclient, verbose, recursive+1);
				}
			}
		}
		chdir(cwd);
		globfree(&gl);
	}

	return 0;

ErrorOut:
	{
	char convert_buf[MAXPATHLEN + 1];
	path = smbftpd_charset_fs2client(path, convert_buf, sizeof(convert_buf));

	#ifdef WITH_SSL
	if (pfclient == stdout && smbftpd_session.ssl_ctrl.ssl_active_flag) {
		snprintf(buf, sizeof(buf), "ftpd: %s: No such file or directory.\r\n", path);
		ssl_write(ssl_con, buf, strlen(buf));
	} else if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
		snprintf(buf, sizeof(buf), "ftpd: %s: No such file or directory.\r\n", path);
		ssl_write(ssl_data_con, buf, strlen(buf));
	} else 
	#endif
	fprintf(pfclient,"ftpd: %s: No such file or directory.\r\n", path);
	}
	return 0;
}


/**
 * list files in dirname.
 * When verbose == 1, means "ls -l".
 * When verbose == 0, means "ls"
 * 
 * @param dirname Directory or filename to list
 * @param verbose 1: LIST
 *                0: NLIST
 */
void cmd_list(const char *dirname, int verbose)
{
	FILE *datastream = NULL;
	int recursive = 0;
	int error;

	if (dirname[0] != '\0') {
		/* skip arguments */
		if (dirname[0] == '-') {
			while ((dirname[0] != ' ') && (dirname[0] != '\0')) {
				// For ffftp. It send "nlist -l" to do file list.
				if ( (verbose == 0) && (dirname[0] == 'l') ) {
					verbose = 1;
				}
				// This is for ffftp, too. When it delete files, it use
				// nlist -alLR to recursive enlist all files recursive.
				// and then delete them.
				if ( (recursive == 0) && (dirname[0] == 'R')) {
					recursive = 1;
				}
				dirname++;
			}
			if (dirname[0] != '\0')
				dirname++;
		}
	}
	
	datastream = dataconn("file list", -1, "w");
	if (datastream == NULL) {
		reply(550, "Data connection: %s", strerror(errno));
		dataconnclose(datastream);
		return;
	}

	STARTXFER;

	if (dirname[0] == '\0') {
		error = smbftpd_dir_list(".", datastream, verbose, recursive);
	} else {
		error = smbftpd_dir_list(dirname, datastream, verbose, recursive);
	}

	ENDXFER;

	if (error == 0) {
		reply_noformat(226, "Transfer complete.");
	}
	
	dataconnclose(datastream);
}

