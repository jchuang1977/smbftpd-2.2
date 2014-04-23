/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/ftp.h>
#include <time.h>

#include "smbftpd.h"
#include "cmd.h"
#include "restrict.h"
#include "ssl.h"

extern smbftpd_session_t smbftpd_session;

/*
 * Generate unique name for file with basename "local.jpg"
 * and open the file in order to avoid possible races.
 * Try "local.jpg" first, then "local.1.jpg", "local.2.jpg" etc,
 * up to "local.99.jpg".
 * Return descriptor to the file, set "name" to its name.
 *
 * Generates failure reply on error.
 */
static int guniquefd(char *local, char **name)
{
	static char new[MAXPATHLEN];
	struct stat st;
	char *cp, *suffix;
	int count;
	int fd;

	/*
	 * Let not overwrite dirname with counter suffix.
	 * -4 is for /nn\0
	 * In this extreme case dot won't be put in front of suffix.
	 */
	if (strlen(local) > sizeof(new) - 4) {
		reply_noformat(553, "Pathname too long.");
		return(-1);
	}

	cp = strrchr(local, '/');
	if (cp) {
		suffix = strrchr(cp, '.');
		*cp = '\0';
	} else {
		suffix = strrchr(local, '.');
	}

	if (stat(cp ? local : ".", &st) < 0) {
		reply_fs2client(553, "%s: %s.", cp ? local : ".", strerror(errno));
		return(-1);
	}
	if (cp) {
		*cp = '/';
	}
	if (suffix && (suffix == local || *(suffix-1) == '/')) {
		suffix = NULL;
	}
	if (suffix) {
		
		/* Remove suffix. /usr/local/aaa.tgz become /usr/local/aaa */
		*suffix = 0;
		suffix++;

		/* -4 is for the .nn<null> we put on the end below */
		(void) snprintf(new, sizeof(new) - 4 - strlen(suffix), "%s", local);
	} else {
		/* -4 is for the .nn<null> we put on the end below */
		(void) snprintf(new, sizeof(new) - 4, "%s", local);
	}
	cp = new + strlen(new);

	for (count = 0; count < 100; count++) {
		/* At count 0 try unmodified name */
		if (count) {
			if (suffix) {
				(void)sprintf(cp, ".%d.%s", count, suffix);
			} else {
				(void)sprintf(cp, ".%d", count);
			}
		} else if (suffix) {
			(void)sprintf(cp, ".%s", suffix);
		}
		if ((fd = open(new, O_RDWR | O_CREAT | O_EXCL, 0666)) >= 0) {
			*name = new;
			return(fd);
		}
		if (errno != EEXIST) {
			reply_fs2client(553, "%s: %s.", count ? new : local, strerror(errno));
			return(-1);
		}
	}
	reply_noformat(452, "Unique file name cannot be created.");
	return(-1);
}

static off_t receive_data_ascii_mode(FILE *instr, FILE *outstr)
{
	struct timeval tvsince;
	off_t byte_count = 0;
	int c, cp, ret;
	int bare_lfs = 0;

	if (smbftpd_session.max_upload_rate > 0) {
		gettimeofday(&tvsince, NULL);
	}

	cp = EOF;
	for (;;) {
		c = smbftpd_socket_getc(instr, 1);
		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (c == EOF && ferror(instr)) {
			goto data_err;
		}
			
		if (c == EOF && ferror(instr)) { /* resume after OOB */
			clearerr(instr);
			continue;
		}

		if (cp == '\r') {
			if (c != '\n') {
				START_UNSAFE;
				ret = putc('\r', outstr);
				END_UNSAFE;
				if (sigurg_received()) {
					if (check_oob()) {
						return -1;
					}
				} else if (ferror(outstr))
					goto file_err;
			}
		} else
			if (c == '\n')
				bare_lfs++;
		if (c == '\r') {
			byte_count++;
			cp = c;
			continue;
		}

		/* Check for EOF here in order not to lose last \r. */
		if (c == EOF) {
#ifdef	WITH_SSL
			break;
#else
			if (feof(instr))	/* EOF */
				break;
			syslog(LOG_ERR, "Internal: impossible condition"
				   " on data stream after getc()");
			goto data_err;
#endif
		}
		ret = putc(c, outstr);
		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (ferror(outstr))
			goto file_err;
		byte_count++;
		cp = c;
		if (smbftpd_session.max_upload_rate > 0) {
			transfer_rate_throttle(byte_count, &tvsince, smbftpd_session.max_upload_rate);
		}
	}
	if (fflush(outstr) == EOF)
		goto file_err;

	if (bare_lfs) {
		reply(LONG_REPLY(226), "WARNING! %d bare linefeeds received in ASCII mode.", bare_lfs);
		smbftpd_socket_printf("   File may not have transferred correctly.\r\n");
	}
	return byte_count;

data_err:
	reply(426, "Data connection: %s.", strerror(errno));
	return -1;

file_err:
	reply(452, "Error writing to file: %s.", strerror(errno));
	return -1;
}

/*
 * Transfer data from peer to "outstr" using the appropriate encapulation of
 * the data subject to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled.
 */
static off_t receive_data_binary_mode(FILE *instr, FILE *outstr)
{
	struct timeval tvsince;
	off_t byte_count = 0;

	if (smbftpd_session.max_upload_rate > 0) {
		gettimeofday(&tvsince, NULL);
	}
	for (;;) {
		int cnt, len;
		char *bp;
		char buf[NET_BUF_SIZE];
#ifdef	WITH_SSL
		if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
			cnt = ssl_read(ssl_data_con, buf, sizeof(buf));
		} else
#endif /* !WITH_SSL */
			cnt = read(fileno(instr), buf, sizeof(buf));

		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (cnt < 0) {
			goto data_err;
		}
		if (cnt < 0) {	/* resume after OOB */
			continue;
		}
			
		if (cnt == 0)	/* EOF */
			break;
		for (len = cnt, bp = buf; len > 0;) {
			cnt = write(fileno(outstr), bp, len);
			if (sigurg_received()) {
				if (check_oob()) {
					return -1;
				}
			} else if (cnt < 0)
				goto file_err;
			if (cnt == 0)
				continue;
			len -= cnt;
			bp += cnt;
			byte_count += cnt;
		}
		if (smbftpd_session.max_upload_rate > 0) {
			transfer_rate_throttle(byte_count, &tvsince, smbftpd_session.max_upload_rate);
		}
	}
	return byte_count;

data_err:
	reply(426, "Data connection: %s.", strerror(errno));
	return -1;

file_err:
	reply(452, "Error writing to file: %s.", strerror(errno));
	return -1;
}

void cmd_store(const char *name, const char *mode, int unique, off_t restart_point)
{
	int fd;
	FILE *fout = NULL, *din;
	time_t tstart, tend;
	const smbftpd_valid_share_t *share = NULL;
	char *real_path;
	off_t byte_count = 0;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, name, FLAG_CHECK_WRITABLE);
	if (NULL == real_path) {
		reply_fs2client(553, "%s: Permission denied.", name);
		return;
	}

	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share) {
			reply_noformat(553, "No such file or directory.");
			return;
		}
	}

	if (*mode == 'a') {		/* APPE */
		if (unique) {
			/* Programming error */
			syslog(LOG_ERR, "Internal: unique flag to APPE");
			unique = 0;
		}
		if (smbftpd_session.mode == MODE_SMB) {
			if (share->disable_modify) {
				reply_noformat(550, "Appending to existing file denied.");
				goto err;
			}
		}
		restart_point = 0;	/* not affected by preceding REST */
	}
	if (unique)			/* STOU overrides REST */
		restart_point = 0;
		if ((smbftpd_session.mode == MODE_SMB) && share->disable_modify) {
			if (restart_point) {	/* guest STOR w/REST */
				reply_noformat(550, "Modifying existing file denied.");
				goto err;
		} else			/* treat guest STOR as STOU */
			unique = 1;
	}

	if (restart_point)
		mode = "r+";	/* so ASCII manual seek can work */
	if (unique) {
		if ((fd = guniquefd(real_path, &real_path)) < 0)
			goto err;
		fout = fdopen(fd, mode);
	} else
		fout = fopen(real_path, mode);
	if (fout == NULL) {
		reply_fs2client(553, "%s: %s.", name, strerror(errno));
		goto err;
	}
	byte_count = -1;
	if (restart_point) {
		if (smbftpd_session.transfer_type == TYPE_A) {
			off_t i, n;
			int c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fout)) == EOF) {
					reply_fs2client(550, "%s: %s.", name, strerror(errno));
					goto done;
				}
				if (c == '\n')
					i++;
			}
			/*
			 * We must do this seek to "current" position
			 * because we are changing from reading to
			 * writing.
			 */
			if (fseeko(fout, 0, SEEK_CUR) < 0) {
				reply_fs2client(550, "%s: %s.", name, strerror(errno));
				goto done;
			}
		} else if (lseek(fileno(fout), restart_point, L_SET) < 0) {
			reply_fs2client(550, "%s: %s.", name, strerror(errno));
			goto done;
		}
	}
	din = dataconn(name, -1, "r");
	if (din == NULL)
		goto done;

	time(&tstart);

	byte_count = -1;

	STARTXFER;

	switch (smbftpd_session.transfer_type) {
	case TYPE_I:
	case TYPE_L:
		byte_count = receive_data_binary_mode(din, fout);
		break;
	case TYPE_A:
		byte_count = receive_data_ascii_mode(din, fout);
		break;
	default:
		reply(550, "Unimplemented TYPE %d in receive_data.", smbftpd_session.transfer_type);
		break;
	}
	ENDXFER;

	if (byte_count != -1) {
		if (unique) {
			char *ptr;
			ptr = strrchr(real_path, '/');
			if (ptr) {
				ptr++;
			} else {
				ptr = real_path;
			}
			reply_fs2client(226, "Transfer complete (unique file name:%s).", ptr);
		} else
			reply_noformat(226, "Transfer complete.");
	}
	time(&tend);

	dataconnclose(din);

done:
	LOGBYTES(*mode == 'a' ? "append" : "put", name, byte_count);

	if (fout) {
		fclose(fout);
	}
	if (byte_count >= 0) {
		smbftpd_xferlog_write(*mode == 'a' ? "append" : "put", real_path, byte_count, tstart, tend);
		smbftpd_session.byte_uploaded += byte_count;
	}

	return;
	err:
	LOGCMD(*mode == 'a' ? "append" : "put" , name);
	return;
}
