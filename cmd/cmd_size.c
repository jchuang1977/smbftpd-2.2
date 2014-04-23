/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#define FTP_NAMES
#include <arpa/inet.h>
#include <arpa/ftp.h>


#include "smbftpd.h"

extern smbftpd_session_t smbftpd_session;

#define	MAXASIZE	10240	/* Deny ASCII SIZE on files larger than that */

void cmd_size(const char *path)
{
	char *real_path;

	real_path = smbftpd_get_realpath(smbftpd_session.valid_shares, path, 0);
	if (NULL == real_path) {
		reply_fs2client(550, "%s: No such file or direcotry.", path);
		return;
	}
	switch (smbftpd_session.transfer_type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(real_path, &stbuf) < 0)
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
		else if (!S_ISREG(stbuf.st_mode))
			reply_fs2client(550, "%s: not a plain file.", path);
		else
			reply(213, "%lld", stbuf.st_size);
		break; }
	case TYPE_A: {
		FILE *fin;
		int c;
		off_t count;
		struct stat stbuf;
		fin = fopen(real_path, "r");
		if (fin == NULL) {
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0) {
			reply_fs2client(550, "%s: %s.", path, strerror(errno));
			(void) fclose(fin);
			return;
		} else if (!S_ISREG(stbuf.st_mode)) {
			reply_fs2client(550, "%s: not a plain file.", path);
			(void) fclose(fin);
			return;
		} else if (stbuf.st_size > MAXASIZE) {
			reply_fs2client(550, "%s: too large for type A SIZE.", path);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, "%lld", count);
		break; }
	default:
		reply(504, "SIZE not implemented for type %s.",
			  typenames[smbftpd_session.transfer_type]);
	}
}


