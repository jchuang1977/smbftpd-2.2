/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/ftp.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#include "smbftpd.h"
#include "cmd.h"
#include "restrict.h"
#include "ssl.h"

#ifdef	HAVE_LINUX_SENDFILE
#include <sys/sendfile.h>
#endif

extern smbftpd_session_t smbftpd_session;

static off_t send_data_ascii_mode(FILE *instr, FILE *outstr)
{
	struct timeval tvsince;
	off_t byte_count = 0;
	int c, cp;

	if (smbftpd_session.max_download_rate > 0) {
		gettimeofday(&tvsince, NULL);
	}

	cp = EOF;
	for (;;) {
		c = getc(instr);
		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (c == EOF && ferror(instr))
			goto file_err;
		if (c == EOF) {
			if (ferror(instr)) {	/* resume after OOB */
				clearerr(instr);
				continue;
			}
			if (feof(instr))	/* EOF */
				break;
			syslog(LOG_ERR, "Internal: impossible condition"
				   " on file after getc()");
			goto file_err;
		}

		if (c == '\n' && cp != '\r') {
			START_UNSAFE;
			smbftpd_socket_putc('\r', outstr, 1);
			END_UNSAFE;
			if (sigurg_received()) {
				if (check_oob()) {
					return -1;
				}
			} else if (ferror(outstr))				
				goto data_err;
			byte_count++;
		}
		START_UNSAFE;
		smbftpd_socket_putc(c, outstr, 1);
		END_UNSAFE;
		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (ferror(outstr))				
			goto data_err;
		cp = c;
		byte_count++;
		if (smbftpd_session.max_download_rate > 0) {
			transfer_rate_throttle(byte_count, &tvsince, smbftpd_session.max_download_rate);
		}
	}

	if (smbftpd_socket_fflush(outstr, 1) == EOF)
		goto data_err;

	reply_noformat(226, "Transfer complete.");
	return byte_count;

data_err:
	reply(426, "Data connection: %s.", strerror(errno));
	return -1;

file_err:
	reply(551, "Error on input file: %s.", strerror(errno));
	return -1;
}

/*
 * Tranfer the contents of "instr" to "outstr" peer using the appropriate
 * encapsulation of the data subject to Mode, Structure, and Type.
 *
 * NB: Form isn't handled.
 */
static off_t send_data_biary_mode(FILE *instr, FILE *outstr, off_t blksize, off_t filesize, int isreg)
{
	struct timeval tvsince;
	int filefd, netfd;
	char *buf;
	off_t cnt, byte_count = 0;
#ifdef	HAVE_SENDFILE
	off_t offset;
	int err;
	cnt = offset = 0;
#endif

	if (smbftpd_session.max_download_rate > 0) {
		gettimeofday(&tvsince, NULL);
	}
	if (blksize < NET_BUF_SIZE) {
		blksize = NET_BUF_SIZE;
	}

	/*
	 * isreg is only set if we are not doing restart and we
	 * are sending a regular file
	 */
	netfd = fileno(outstr);
	filefd = fileno(instr);

	if (smbftpd_session.max_download_rate > 0 || smbftpd_session.ssl_ctrl.ssl_data_active_flag || !isreg) {
		goto oldway;
	}
			
#ifdef	HAVE_SENDFILE
	while (filesize > 0) {
#ifndef	HAVE_LINUX_SENDFILE

		err = sendfile(filefd, netfd, offset, 0, NULL, &cnt, 0);

		/*
		 * Calculate byte_count before OOB processing.
		 * It can be used in myoob() later.
		 */
		byte_count += cnt;
		offset += cnt;
		filesize -= cnt;

		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (err == -1) {
			if (errno != EINTR && cnt == 0 && offset == 0)
				goto oldway;
			goto data_err;
		}
		if (err == -1)	{/* resume after OOB */
			continue;
		}

		/*
		 * We hit the EOF prematurely.
		 * Perhaps the file was externally truncated.
		 */
		if (cnt == 0) {
			reply_noformat(226, "Transfer finished due to premature end of file.");
			return -1;
		}
#else
		size_t  count = 0x7FFFFFFF;

		if (filesize < count) {
			count = filesize;
		}
#ifdef __NR_sendfile64
		/* directly syscall to avoid glibc */   
		err = syscall(__NR_sendfile64, netfd, filefd, &offset, count);
#else
		err = sendfile64(netfd, filefd, &offset, count);
#endif
		if (sigurg_received()) {
			if (check_oob()) {
				return -1;
			}
		} else if (err == -1) {
			if (offset == 0) {
				goto oldway;
			}
			goto data_err;
		}
		if (err == -1)	{/* resume after OOB */
			continue;
		}

		filesize -= err;
		byte_count += err;
#endif
	}
	reply_noformat(226, "Transfer complete.");
	return byte_count;
#endif /* HAVE_SENDFILE */


oldway:
	if ((buf = malloc((u_int)blksize)) == NULL) {
		reply_noformat(451, "Ran out of memory.");
		return -1;
	}

	for (;;) {
		int len;
		char *bp;

		cnt = read(filefd, buf, blksize);
		if (sigurg_received()) {
			if (check_oob()) {
				free(buf);
				return -1;
			}
		} else if (cnt < 0) {
			free(buf);
			goto file_err;
		}
		if (cnt < 0){	/* resume after OOB */
			continue;
		}
			
		if (cnt == 0)	/* EOF */
			break;

		for (len = cnt, bp = buf; len > 0;) {
#ifdef WITH_SSL
			if (smbftpd_session.ssl_ctrl.ssl_data_active_flag) {
				cnt = ssl_write(ssl_data_con, bp, len);
			} else
#endif /* WITH_SSL */
				cnt = write(netfd, bp, len);
			if (sigurg_received()) {
				if (check_oob()) {
					free(buf);
					return -1;
				}
			} else if (cnt < 0) {
				free(buf);
				goto data_err;
			}
			if (cnt <= 0)
				continue;
				
			len -= cnt;
			bp += cnt;
			byte_count += cnt;
			if (smbftpd_session.max_download_rate > 0) {
				transfer_rate_throttle(byte_count, &tvsince, smbftpd_session.max_download_rate);
			}
		}
	}
	free(buf);
	reply_noformat(226, "Transfer complete.");
	return byte_count;

data_err:
	reply(426, "Data connection: %s.", strerror(errno));
	return -1;

file_err:
	reply(551, "Error on input file: %s.", strerror(errno));
	return -1;
}

/**
 * Download file from FTP server. (RETR)
 * 
 * We will open data connection and send file to client.
 * 
 * @param file   The filename to send
 * @param restart_point
 *               Restart point of resume download. This is file offset.
 */
void cmd_retr(const char *file, off_t restart_point)
{
	FILE *fin = NULL, *dout;
	const smbftpd_valid_share_t *share;
	struct stat st;
	char *real_path;
	off_t byte_count;
	time_t tstart, tend;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, file, 0);
	if (NULL == real_path) {
		reply_fs2client(550,"%s: Permission deny", file);
		return;
	}
	if (smbftpd_session.mode == MODE_SMB) {
		share = smbftpd_get_share_by_path(smbftpd_session.valid_shares, real_path);
		if (!share) {
			reply_fs2client(550,"%s: Permission deny", file);
			return;
		}
		if (share->disable_download) {
			reply_noformat(500, "RETR command disabled.");
			return;
		}
	}

	fin = fopen(real_path, "r");
	st.st_size = 0;

	if (fin == NULL) {
		if (errno != 0) {
			reply_fs2client(550, "%s: %s.", file, strerror(errno));
			LOGCMD("get", real_path);
		}
		return;
	}
	byte_count = -1;
	if ((fstat(fileno(fin), &st) < 0 || !S_ISREG(st.st_mode))) {
		reply_fs2client(550, "%s: not a plain file.", file);
		goto done;
	}
	if (restart_point) {
		if (smbftpd_session.transfer_type == TYPE_A) {
			off_t i, n;
			int c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fin)) == EOF) {
					reply_fs2client(550, "%s: %s.", file, strerror(errno));
					goto done;
				}
				if (c == '\n')
					i++;
			}
		} else if (lseek(fileno(fin), restart_point, L_SET) < 0) {
			reply_fs2client(550, "%s: %s.", file, strerror(errno));
			goto done;
		}
	}
	dout = dataconn(file, st.st_size, "w");
	if (dout == NULL)
		goto done;
	time(&tstart);

	STARTXFER;

	switch (smbftpd_session.transfer_type) {
	case TYPE_A:
		byte_count = send_data_ascii_mode(fin, dout);
		break;
	case TYPE_I:
	case TYPE_L:
		byte_count = send_data_biary_mode(fin, dout, st.st_blksize, st.st_size,
										  restart_point == 0 && S_ISREG(st.st_mode));
		break;
	default:
		reply(550, "Unimplemented TYPE %d in send_data.", smbftpd_session.transfer_type);
	}

	ENDXFER;

	time(&tend);

	dataconnclose(dout);
done:
	LOGBYTES("get", real_path, byte_count);
	if (fin) {
		fclose(fin);
	}

	if (byte_count >= 0) {
		smbftpd_xferlog_write("get", real_path, byte_count, tstart, tend);
		smbftpd_session.byte_downloaded += byte_count;
	}
	
}

