/* Copyright 2003-2005 Wang, Chun-Pin All rights reserved. */
/*
 * Copyright (c) 1985, 1988, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ftpcmd.y	8.3 (Berkeley) 4/6/94
 */

/*
 * Grammar for FTP commands.
 * See RFC 959.
 */

%{
#include "config.h"

#ifndef lint
#if 0
static char sccsid[] = "@(#)ftpcmd.y	8.3 (Berkeley) 4/6/94";
#endif
static const char rcsid[] =
  "$FreeBSD: src/libexec/ftpd/ftpcmd.y,v 1.55 2003/10/26 04:30:05 peter Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/ftp.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>

#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "pathnames.h"
#include "smbftpd.h"
#include "cmd.h"
#include "ssl.h"

extern	smbftpd_session_t smbftpd_session;
extern	smbftpd_conf_t smbftpd_conf;
extern	union sockunion data_dest, his_addr;

off_t	restart_point;

static	int cmd_type;
static	int cmd_form;
static	int cmd_bytesz;
static	int state;
static char	*fromname = NULL;
static char cmdbuf[512];
static int epsvall;

%}

%union {
	struct {
		off_t	o;
		int	i;
	} u;
	char   *s;
}

%token
	A	B	C	E	F	I
	L	N	P	R	S	T
	ALL

	SP	CRLF	COMMA

	USER	PASS	ACCT	REIN	QUIT	PORT
	PASV	TYPE	STRU	MODE	RETR	STOR
	APPE	MLFL	MAIL	MSND	MSOM	MSAM
	MRSQ	MRCP	ALLO	REST	RNFR	RNTO
	ABOR	DELE	CWD	LIST	NLST	SITE
	STAT	HELP	NOOP	MKD	RMD	PWD
	CDUP	STOU	SMNT	SYST	SIZE	MDTM
	LPRT	LPSV	EPRT	EPSV

	UMASK	IDLE	CHMOD	MDFIVE

	FEAT	OPTS
	AUTH	PROT	PBSZ

	LEXERR	NOTIMPL

%token	<s> STRING
%token	<u> NUMBER

%type	<u.i> check_login octal_number byte_size
%type	<u.i> check_login_ro check_login_epsv
%type	<u.i> struct_code mode_code type_code form_code
%type	<s> pathstring pathname password username
%type	<s> ALL NOTIMPL
%type	<u.i> buffer_size
%type	<s> auth_type protection_level

%start	cmd_list

%%

cmd_list
	: /* empty */
	| cmd_list cmd
		{
			if (fromname)
				free(fromname);
			fromname = NULL;
			restart_point = 0;
		}
	| cmd_list rcmd
	;

cmd
	: AUTH SP auth_type CRLF
		{
			cmd_auth($3);
			if ($3 != NULL)
				free($3);
		}
	| PBSZ SP buffer_size CRLF
		{
			cmd_pbsz();
		}
	| PROT SP protection_level CRLF
		{
			cmd_prot($3);
			if ($3 != NULL)
				free($3);
		}
	| USER SP username CRLF
		{
			cmd_user($3);
			free($3);
		}
	| PASS SP password CRLF
		{
			cmd_pass($3);
			free($3);
		}
	| PASS CRLF
		{
			cmd_pass("");
		}
	| PORT check_login SP host_port CRLF
		{
			if (epsvall) {
				reply_noformat(501, "No PORT allowed after EPSV ALL.");
				goto port_done;
			}
			if (!$2)
				goto port_done;

			cmd_port();

		port_done:
			;	/* Life, the universe and everything! */
		}
	| LPRT check_login SP host_long_port CRLF
		{
			if (epsvall) {
				reply_noformat(501, "No LPRT allowed after EPSV ALL.");
				goto lprt_done;
			}
			if (!$2)
				goto lprt_done;

			cmd_lprt();

		lprt_done:
			;	/* Life, the universe and everything! */
		}
	| EPRT check_login SP STRING CRLF
		{
			if (epsvall) {
				reply_noformat(501, "No EPRT allowed after EPSV ALL.");
				goto eprt_done;
			}
			if (!$2)
				goto eprt_done;

			cmd_eprt($4);

		eprt_done:
			free($4);
		}
	| PASV check_login CRLF
		{
			if (epsvall)
				reply_noformat(501, "No PASV allowed after EPSV ALL.");
			else if ($2)
				cmd_passive();
		}
	| LPSV check_login CRLF
		{
			if (epsvall)
				reply_noformat(501, "No LPSV allowed after EPSV ALL.");
			else if ($2)
				cmd_long_passive("LPSV", PF_UNSPEC);
		}
	| EPSV check_login_epsv SP NUMBER CRLF
		{
			if ($2) {
				int pf;
				switch ($4.i) {
				case 1:
					pf = PF_INET;
					break;
#ifdef INET6
				case 2:
					pf = PF_INET6;
					break;
#endif
				default:
					pf = -1;	/*junk value*/
					break;
				}
				cmd_long_passive("EPSV", pf);
			}
		}
	| EPSV check_login_epsv SP ALL CRLF
		{
			if ($2) {
				reply_noformat(200, "EPSV ALL command successful.");
				epsvall++;
			}
		}
	| EPSV check_login_epsv CRLF
		{
			if ($2)
				cmd_long_passive("EPSV", PF_UNSPEC);
		}
	| TYPE check_login SP type_code CRLF
		{
			if ($2) {
				switch (cmd_type) {

				case TYPE_A:
					if (cmd_form == FORM_N) {
						reply_noformat(200, "Type set to A.");
						smbftpd_session.transfer_type = cmd_type;
					} else
						reply_noformat(504, "Form must be N.");
					break;

				case TYPE_E:
					reply_noformat(504, "Type E not implemented.");
					break;

				case TYPE_I:
					reply_noformat(200, "Type set to I.");
					smbftpd_session.transfer_type = cmd_type;
					break;

				case TYPE_L:
#if CHAR_BIT == 8
					if (cmd_bytesz == 8) {
						reply_noformat(200,
						    "Type set to L (byte size 8).");
						smbftpd_session.transfer_type = cmd_type;
					} else
						reply_noformat(504, "Byte size must be 8.");
#else /* CHAR_BIT == 8 */
					UNIMPLEMENTED for CHAR_BIT != 8
#endif /* CHAR_BIT == 8 */
				}
			}
		}
	| STRU check_login SP struct_code CRLF
		{
			if ($2) {
				switch ($4) {

				case STRU_F:
					reply_noformat(200, "STRU F accepted.");
					break;

				default:
					reply_noformat(504, "Unimplemented STRU type.");
				}
			}
		}
	| MODE check_login SP mode_code CRLF
		{
			if ($2) {
				switch ($4) {

				case MODE_S:
					reply_noformat(200, "MODE S ok.");
					break;
	
				default:
					reply_noformat(502, "Unimplemented MODE type.");
				}
			}
		}
	| ALLO check_login SP NUMBER CRLF
		{
			if ($2) {
				reply_noformat(202, "ALLO command ignored.");
			}
		}
	| ALLO check_login SP NUMBER SP R SP NUMBER CRLF
		{
			if ($2) {
				reply_noformat(202, "ALLO command ignored.");
			}
		}
	| RETR check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_retr($4, restart_point);

			if ($4 != NULL)
				free($4);
		}
	| STOR check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_store($4, "w", 0, restart_point);
			if ($4 != NULL)
				free($4);
		}
	| APPE check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_store($4, "a", 0, restart_point);
			if ($4 != NULL)
				free($4);
		}
	| NLST check_login CRLF
		{
			if ($2)
				cmd_list(".", 0);
		}
	| NLST check_login SP pathstring CRLF
		{
			if ($2)
				cmd_list($4, 0);
			free($4);
		}
	| LIST check_login CRLF
		{
			if ($2)
				cmd_list("", 1);
		}
	| LIST check_login SP pathstring CRLF
		{
			if ($2)
				cmd_list($4, 1);
			free($4);
		}
	| STAT check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_statfile($4);
			if ($4 != NULL)
				free($4);
		}
	| STAT check_login CRLF
		{
			if ($2) {
				cmd_stat();
			}
		}
	| DELE check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_delete($4);
			if ($4 != NULL)
				free($4);
		}
	| RNTO check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL) {
				if (fromname) {
					cmd_rnto(fromname, $4);
					free(fromname);
					fromname = NULL;
				} else {
					reply_noformat(503, "Bad sequence of commands.");
				}
			}
			if ($4 != NULL)
				free($4);
		}
	| ABOR check_login CRLF
		{
			if ($2)
				reply_noformat(225, "ABOR command successful.");
		}
	| CWD check_login CRLF
		{
			if ($2) {
				cmd_cwd(smbftpd_session.home);
			}
		}
	| CWD check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_cwd($4);
			if ($4 != NULL)
				free($4);
		}
	| HELP CRLF
		{
			help(cmdtab, NULL);
		}
	| HELP SP STRING CRLF
		{
			char *cp = $3;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = $3 + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, NULL);
			} else
				help(cmdtab, $3);
			free($3);
		}
	| NOOP CRLF
		{
			reply_noformat(200, "NOOP command successful.");
		}
	| MKD check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_mkdir($4);
			if ($4 != NULL)
				free($4);
		}
	| RMD check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_rmdir($4);
			if ($4 != NULL)
				free($4);
		}
	| PWD check_login CRLF
		{
			if ($2)
				cmd_pwd();
		}
	| CDUP check_login CRLF
		{
			if ($2)
				cmd_cwd("..");
		}
	| SITE SP HELP CRLF
		{
			help(sitetab, NULL);
		}
	| SITE SP HELP SP STRING CRLF
		{
			help(sitetab, $5);
			free($5);
		}
	| SITE SP MDFIVE check_login SP pathname CRLF
		{
			if ($4 && $6) {
				cmd_site_mdfive($6);
			}
			if ($6)
				free($6);
		}
	| SITE SP UMASK check_login CRLF
		{
			int oldmask;

			if ($4) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o.", oldmask);
			}
		}
	| SITE SP UMASK check_login SP octal_number CRLF
		{
			int oldmask;

			if ($4) {
				if (($6 == -1) || ($6 > 0777)) {
					reply_noformat(501, "Bad UMASK value.");
				} else {
					oldmask = umask($6);
					reply(200,
						"UMASK set to %03o (was %03o).",
						$6, oldmask);
				}
			}
		}
	| SITE SP CHMOD check_login_ro SP octal_number SP pathname CRLF
		{
			if ($4 && ($8 != NULL)) {
				if (($6 == -1 ) || ($6 > 0777))
					reply_noformat(501, "Bad mode value.");
				else
					cmd_site_chmod($8, $6);
			}
			if ($8 != NULL)
				free($8);
		}
	| SITE SP check_login IDLE CRLF
		{
			if ($3)
				reply(200,
					"Current IDLE time limit is %d seconds; max %d.",
					smbftpd_conf.timeout, smbftpd_conf.max_timeout);
		}
	| SITE SP check_login IDLE SP NUMBER CRLF
		{
			if ($3) {
				if ($6.i < 30 || $6.i > smbftpd_conf.max_timeout) {
					reply(501,
						"Maximum IDLE time must be between 30 and %d seconds.",
						smbftpd_conf.max_timeout);
				} else {
					smbftpd_conf.timeout = $6.i;
					(void) alarm(smbftpd_conf.timeout);
					reply(200,
						"Maximum IDLE time set to %d seconds.",
						smbftpd_conf.timeout);
				}
			}
		}
	| STOU check_login_ro SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_store($4, "w", 1, restart_point);
			if ($4 != NULL)
				free($4);
		}
	| SYST check_login CRLF
		{
			if ($2) {
#ifdef BSD
				reply(215, "UNIX Type: L%d Version: BSD-%d", CHAR_BIT, BSD);
#else /* BSD */
				reply(215, "UNIX Type: L%d", CHAR_BIT);
#endif /* BSD */
			}
		}

		/*
		 * SIZE is not in RFC959, but Postel has blessed it and
		 * it will be in the updated RFC.
		 *
		 * Return size of file in a format suitable for
		 * using with RESTART (we just count bytes).
		 */
	| SIZE check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cmd_size($4);
			if ($4 != NULL)
				free($4);
		}

		/*
		 * MDTM is not in RFC959, but Postel has blessed it and
		 * it will be in the updated RFC.
		 *
		 * Return modification time of file as an ISO 3307
		 * style time. E.g. YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx
		 * where xxx is the fractional second (of any precision,
		 * not necessarily 3 digits)
		 */
	| MDTM check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL) {
				cmd_mdtm($4);
			}
			if ($4 != NULL)
				free($4);
		}
	| FEAT CRLF
		{
			cmd_feat();
		}
	| OPTS SP STRING CRLF
		{
			cmd_opts($3);
			free($3);
		}
	| QUIT CRLF
		{
			cmd_quit();
		}
	| NOTIMPL
		{
			reply(502, "%s command not implemented.", $1);
		}
	| error
		{
			yyclearin;		/* discard lookahead data */
			yyerrok;		/* clear error condition */
			state = CMD;		/* reset lexer state */
		}
	;
rcmd
	: RNFR check_login_ro SP pathname CRLF
		{
			restart_point = 0;
			if ($2 && $4) {
				if (fromname)
					free(fromname);
				fromname = NULL;
				if (0 == cmd_rnfr($4))
					fromname = $4;
				else
					free($4);
			} else if ($4) {
				free($4);
			}
		}
	| REST check_login SP NUMBER CRLF
		{
			if ($2) {
				if (fromname)
					free(fromname);
				fromname = NULL;
				restart_point = $4.o;
				reply(350, "Restarting at %qd. %s",
					restart_point,
					"Send STORE or RETRIEVE to initiate transfer.");
			}
		}
	;

username
	: STRING
	;

password
	: /* empty */
		{
			$$ = (char *)calloc(1, sizeof(char));
		}
	| STRING
	;

auth_type
	: STRING
	;

protection_level
	: STRING
	;

byte_size
	: NUMBER
		{
			$$ = $1.i;
		}
	;

buffer_size
	: NUMBER
		{
			$$ = $1.i;
		}
	;

host_port
	: NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER
		{
			char *a, *p;
#ifdef   HAVE_SI_LEN
			data_dest.su_len = sizeof(struct sockaddr_in);
#endif
			data_dest.su_family = AF_INET;
			p = (char *)&data_dest.su_sin.sin_port;
			p[0] = $9.i; p[1] = $11.i;
			a = (char *)&data_dest.su_sin.sin_addr;
			a[0] = $1.i; a[1] = $3.i; a[2] = $5.i; a[3] = $7.i;
		}
	;

host_long_port
	: NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER
		{
#ifdef   INET6
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));

#ifdef   HAVE_SI_LEN
			data_dest.su_len = sizeof(struct sockaddr_in6);
#endif
			data_dest.su_family = AF_INET6;
			p = (char *)&data_dest.su_port;
			p[0] = $39.i; p[1] = $41.i;
			a = (char *)&data_dest.su_sin6.sin6_addr;
			a[0] = $5.i; a[1] = $7.i; a[2] = $9.i; a[3] = $11.i;
			a[4] = $13.i; a[5] = $15.i; a[6] = $17.i; a[7] = $19.i;
			a[8] = $21.i; a[9] = $23.i; a[10] = $25.i; a[11] = $27.i;
			a[12] = $29.i; a[13] = $31.i; a[14] = $33.i; a[15] = $35.i;
			if (his_addr.su_family == AF_INET6) {
				/* XXX more sanity checks! */
				data_dest.su_sin6.sin6_scope_id =
					his_addr.su_sin6.sin6_scope_id;
			}
#endif
			if ($1.i != 6 || $3.i != 16 || $37.i != 2)
				memset(&data_dest, 0, sizeof(data_dest));
		}
	| NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
		NUMBER
		{
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));
#ifdef   HAVE_SI_LEN
			data_dest.su_sin.sin_len = sizeof(struct sockaddr_in);
#endif
			data_dest.su_family = AF_INET;
			p = (char *)&data_dest.su_port;
			p[0] = $15.i; p[1] = $17.i;
			a = (char *)&data_dest.su_sin.sin_addr;
			a[0] =  $5.i; a[1] = $7.i; a[2] = $9.i; a[3] = $11.i;
			if ($1.i != 4 || $3.i != 4 || $13.i != 2)
				memset(&data_dest, 0, sizeof(data_dest));
		}
	;

form_code
	: N
		{
			$$ = FORM_N;
		}
	| T
		{
			$$ = FORM_T;
		}
	| C
		{
			$$ = FORM_C;
		}
	;

type_code
	: A
		{
			cmd_type = TYPE_A;
			cmd_form = FORM_N;
		}
	| A SP form_code
		{
			cmd_type = TYPE_A;
			cmd_form = $3;
		}
	| E
		{
			cmd_type = TYPE_E;
			cmd_form = FORM_N;
		}
	| E SP form_code
		{
			cmd_type = TYPE_E;
			cmd_form = $3;
		}
	| I
		{
			cmd_type = TYPE_I;
		}
	| L
		{
			cmd_type = TYPE_L;
			cmd_bytesz = CHAR_BIT;
		}
	| L SP byte_size
		{
			cmd_type = TYPE_L;
			cmd_bytesz = $3;
		}
		/* this is for a bug in the BBN ftp */
	| L byte_size
		{
			cmd_type = TYPE_L;
			cmd_bytesz = $2;
		}
	;

struct_code
	: F
		{
			$$ = STRU_F;
		}
	| R
		{
			$$ = STRU_R;
		}
	| P
		{
			$$ = STRU_P;
		}
	;

mode_code
	: S
		{
			$$ = MODE_S;
		}
	| B
		{
			$$ = MODE_B;
		}
	| C
		{
			$$ = MODE_C;
		}
	;

pathname
	: pathstring
		{
			if (smbftpd_session.logged_in && $1) {
				char *p;

				/*
				 * Expand ~user manually since glob(3)
				 * will return the unexpanded pathname
				 * if the corresponding file/directory
				 * doesn't exist yet.  Using sole glob(3)
				 * would break natural commands like
				 * MKD ~user/newdir
				 * or
				 * RNTO ~/newfile
				 */
				if ((p = exptilde($1)) != NULL) {
					$$ = expglob(p);
					free(p);
				} else
					$$ = NULL;
				free($1);
			} else
				$$ = $1;
		}
	;

pathstring
	: STRING
		{
			char *p = smbftpd_charset_client2fs($1);
			if (p) {
				free($1);
				$$ = p;
			}
		}
	;

octal_number
	: NUMBER
		{
			int ret, dec, multby, digit;

			/*
			 * Convert a number that was read as decimal number
			 * to what it would be if it had been read as octal.
			 */
			dec = $1.i;
			multby = 1;
			ret = 0;
			while (dec) {
				digit = dec%10;
				if (digit > 7) {
					ret = -1;
					break;
				}
				ret += digit * multby;
				multby *= 8;
				dec /= 10;
			}
			$$ = ret;
		}
	;


check_login
	: /* empty */
		{
		$$ = check_login1();
		}
	;

check_login_epsv
	: /* empty */
		{
		if (smbftpd_conf.disable_epsv) {
			reply_noformat(500, "EPSV command disabled.");
			$$ = 0;
		}
		else
			$$ = check_login1();
		}
	;

check_login_ro
	: /* empty */
		{
		if (smbftpd_session.guest && smbftpd_conf.anonymous_readonly) {
			reply_noformat(550, "Permission denied.");
			$$ = 0;
		}
		else
			$$ = check_login1();
		}
	;

%%

#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* optional SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

#define	MAXGLOBARGS	1000

struct tab {
	char	*name;
	short	token;
	short	state;
	short	implemented;	/* 1 if command is implemented */
	char	*help;
};

struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"[<sp> [password]]" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4, b5" },
	{ "LPRT", LPRT, ARGS, 1,	"<sp> af, hal, h1, h2, h3,..., pal, p1, p2..." },
	{ "EPRT", EPRT, STR1, 1,	"<sp> |af|addr|port|" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "LPSV", LPSV, ARGS, 1,	"(set server in passive mode)" },
	{ "EPSV", EPSV, ARGS, 1,	"[<sp> af|ALL]" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> { A | E | I | L }" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"<sp> offset (restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
/* RFC 2389 */
	{ "FEAT", FEAT, ARGS, 1,	"(return list of supported extensions)" },
	{ "OPTS", OPTS, STR1, 1,	"<sp> command [ <sp> options ]" },
/* RFC 2228 */
#ifdef WITH_SSL
	{ "AUTH", AUTH, STR1, 1,	"<sp> mechanism-name" },
	{ "PBSZ", PBSZ, ARGS, 1,	"<sp> decimal-integer" },
	{ "PROT", PROT, STR1, 1,	"<sp> prot-code" },
#else /* !WITH_SSL */
	{ "AUTH", AUTH, STR1, 0,	"<sp> mechanism-name" },
	{ "PBSZ", PBSZ, ARGS, 0,	"<sp> decimal-integer" },
	{ "PROT", PROT, STR1, 0,	"<sp> prot-code" },
#endif /* WITH_SSL */
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "MD5", MDFIVE, STR1, 1,	"[ <sp> file-name ]" },
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

static char	*copy(char *);
static void upper(char *);
static char	*expglob(char *);
static char	*exptilde(char *);
static void	 help(struct tab *, char *);
static struct tab *
		 lookup(struct tab *, char *);
static void	 toolong(int);
int	 yylex(void);

static struct tab *
lookup(struct tab *p, char *cmd)
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
int
mygetline(char *s, int n, FILE *iop)
{
	int c;
	register char *cs;
	sigset_t sset, osset;

	cs = s;
#if 0
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (smbftpd_conf.debug_mode)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(0);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
#endif
	/* SIGURG would interrupt stdio if not blocked during the read loop */
	sigemptyset(&sset);
	sigaddset(&sset, SIGURG);
#ifdef WITH_SSL /* "pseudo-OOB" with SSL */
	sigaddset(&sset, SIGIO);
#endif /*WITH_SSL*/
	sigprocmask(SIG_BLOCK, &sset, &osset);

	while ((c = smbftpd_socket_getc(iop, 0)) != EOF) {
#if 0 /* To support Russian reversed 'R' (0xff) char, we disable these telnet command parse. */
		c &= 0377;
		if (c == IAC) {
			if ((c = smbftpd_socket_getc(iop, 0)) == EOF)
				goto got_eof;
			c &= 0377;
			switch (c) {
			case WILL:
			case WONT:
				if ((c = smbftpd_socket_getc(iop, 0)) == EOF)
					goto got_eof;
				smbftpd_socket_printf("%c%c%c", IAC, DONT, 0377&c);
				(void) smbftpd_socket_fflush(stdout, 0);
				continue;
			case DO:
			case DONT:
				if ((c = smbftpd_socket_getc(iop, 0)) == EOF)
					goto got_eof;
				smbftpd_socket_printf("%c%c%c", IAC, WONT, 0377&c);
				(void) smbftpd_socket_fflush(stdout, 0);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		}
#endif /* if 0 */
		*cs++ = c;
		if (--n <= 0) {
			/*
			 * If command doesn't fit into buffer, discard the
			 * rest of the command and indicate truncation.
			 * This prevents the command to be split up into
			 * multiple commands.
			 */
			while (c != '\n' && (c = smbftpd_socket_getc(iop,0)) != EOF)
				;
			return (-2);
		}
		if (c == '\n')
			break;
	}
#if 0 /* To support Russian reversed 'R' (0xff) char, we disable these telnet command parse. */
got_eof:
#endif
	sigprocmask(SIG_SETMASK, &osset, NULL);
	if (c == EOF && cs == s)
		return (-1);
	*cs++ = '\0';
	if (smbftpd_conf.debug_mode) {
		if (!smbftpd_session.guest && strncasecmp("pass ", s, 5) == 0) {
			/* Don't syslog passwords */
			syslog(LOG_DEBUG, "command: %.5s ???", s);
		} else {
			register char *cp;
			register int len;

			/* Don't syslog trailing CR-LF */
			len = strlen(s);
			cp = s + len - 1;
			while (cp >= s && (*cp == '\n' || *cp == '\r')) {
				--cp;
				--len;
			}
			syslog(LOG_DEBUG, "command: %.*s", len, s);
		}
	}
	return (0);
}

static void
toolong(int signo)
{

	reply(421,
		"Timeout (%d seconds): closing control connection.", smbftpd_conf.timeout);
	if (smbftpd_conf.log_command)
		syslog(LOG_INFO, "User %s timed out after %d seconds",
			(smbftpd_session.username[0] ? smbftpd_session.username : "unknown"), smbftpd_conf.timeout);
	dologout(1);
}

int yylex(void)
{
	static int cpos;
	char *cp, *cp2;
	struct tab *p;
	int n;
	char c;

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm(smbftpd_conf.timeout);
			n = mygetline(cmdbuf, sizeof(cmdbuf)-1, stdin);
			if (n == -1) {
				reply_noformat(221, "You could at least say goodbye.");
				dologout(0);
			} else if (n == -2) {
				reply(500, "Command too long.");
				(void) alarm(0);
				continue;
			}
			(void) alarm(0);
			if (strncasecmp(cmdbuf, "PASS", 4) != 0)
				proc_title_set(cmdbuf);
			if ((cp = strchr(cmdbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
			if ((cp = strpbrk(cmdbuf, " \n")))
				cpos = cp - cmdbuf;
			if (cpos == 0)
				cpos = 4;
			c = cmdbuf[cpos];
			cmdbuf[cpos] = '\0';
			upper(cmdbuf);
			p = lookup(cmdtab, cmdbuf);
			cmdbuf[cpos] = c;
			if (p != 0) {
				yylval.s = p->name;
				if (!p->implemented)
					return (NOTIMPL); /* state remains CMD */
				state = p->state;
				return (p->token);
			}
			break;

		case SITECMD:
			if (cmdbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cmdbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cmdbuf;
			c = cmdbuf[cpos];
			cmdbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cmdbuf[cpos] = c;
			if (smbftpd_session.guest == 0 && p != 0) {
				yylval.s = p->name;
				if (!p->implemented) {
					state = CMD;
					return (NOTIMPL);
				}
				state = p->state;
				return (p->token);
			}
			state = CMD;
			break;

		case ZSTR1:
		case OSTR:
			if (cmdbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		dostr1:
			if (cmdbuf[cpos] == ' ') {
				cpos++;
				state = state == OSTR ? STR2 : state+1;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cmdbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cmdbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cmdbuf[cpos] == '\n') {
				cmdbuf[cpos] = '\0';
				yylval.s = copy(cp);
				cmdbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cmdbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit(cmdbuf[cpos])) {
				cp = &cmdbuf[cpos];
				while (isdigit(cmdbuf[++cpos]))
					;
				c = cmdbuf[cpos];
				cmdbuf[cpos] = '\0';
				yylval.u.i = atoi(cp);
				cmdbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit(cmdbuf[cpos])) {
				cp = &cmdbuf[cpos];
				while (isdigit(cmdbuf[++cpos]))
					;
				c = cmdbuf[cpos];
				cmdbuf[cpos] = '\0';
				yylval.u.i = atoi(cp);
				yylval.u.o = strtoull(cp, NULL, 10);
				cmdbuf[cpos] = c;
				return (NUMBER);
			}
			if (strncasecmp(&cmdbuf[cpos], "ALL", 3) == 0
			 && !isalnum(cmdbuf[cpos + 3])) {
				cpos += 3;
				return ALL;
			}
			switch (cmdbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return (A);

			case 'B':
			case 'b':
				return (B);

			case 'C':
			case 'c':
				return (C);

			case 'E':
			case 'e':
				return (E);

			case 'F':
			case 'f':
				return (F);

			case 'I':
			case 'i':
				return (I);

			case 'L':
			case 'l':
				return (L);

			case 'N':
			case 'n':
				return (N);

			case 'P':
			case 'p':
				return (P);

			case 'R':
			case 'r':
				return (R);

			case 'S':
			case 's':
				return (S);

			case 'T':
			case 't':
				return (T);

			}
			break;

		default:
			fatalerror("Unknown state in scanner.");
		}
		state = CMD;
		return (LEXERR);
	}
}

void
upper(char *s)
{
	while (*s != '\0') {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

static char *
copy(char *s)
{
	char *p;

	p = malloc(strlen(s) + 1);
	if (p == NULL)
		fatalerror("Ran out of memory.");
	(void) strcpy(p, s);
	return (p);
}

static void
help(struct tab *ctab, char *s)
{
	struct tab *c;
	int width, NCMDS;
	char *type;

	if (ctab == sitetab)
		type = "SITE ";
	else
		type = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		int i, j, w;
		int columns, lines;

		reply(LONG_REPLY(214), "The following %scommands are recognized %s.",
		    type, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			smbftpd_socket_printf("   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				smbftpd_socket_printf("%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					smbftpd_socket_printf(" ");
					w++;
				}
			}
			smbftpd_socket_printf("\r\n");
		}
		(void) smbftpd_socket_fflush(stdout, 0);
		reply(214, "Direct comments to ftp-bugs@%s.", smbftpd_conf.server_name);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == NULL) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", type, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", type, width,
		    c->name, c->help);
}

static int
check_login1(void)
{
	if (smbftpd_session.logged_in)
		return 1;
	else {
		reply_noformat(530, "Please login with USER and PASS.");
		return 0;
	}
}

/*
 * Replace leading "~user" in a pathname by the user's login directory.
 * Returned string will be in a freshly malloced buffer unless it's NULL.
 */
static char *
exptilde(char *s)
{
	char *p, *q;
	char *path, *user;
	struct passwd *ppw;

	if ((p = strdup(s)) == NULL)
		return (NULL);
	if (*p != '~')
		return (p);

	if (smbftpd_session.mode == MODE_SMB || smbftpd_conf.virtual_user_mapping) {
		return (p);
	}

	user = p + 1;	/* skip tilde */
	if ((path = strchr(p, '/')) != NULL)
		*(path++) = '\0'; /* separate ~user from the rest of path */
	if (*user == '\0') /* no user specified, use the current user */
		user = smbftpd_session.username;
	/* read passwd even for the current user since we may be chrooted */
	if ((ppw = getpwnam(user)) != NULL) {
		/* user found, substitute login directory for ~user */
		if (path)
			asprintf(&q, "%s/%s", ppw->pw_dir, path);
		else
			q = strdup(ppw->pw_dir);
		free(p);
		p = q;
	} else {
		/* user not found, undo the damage */
		if (path)
			path[-1] = '/';
	}
	return (p);
}

/*
 * Expand glob(3) patterns possibly present in a pathname.
 * Avoid expanding to a pathname including '\r' or '\n' in order to
 * not disrupt the FTP protocol.
 * The expansion found must be unique.
 * Return the result as a malloced string, or NULL if an error occured.
 *
 * Problem: this production is used for all pathname
 * processing, but only gives a 550 error reply.
 * This is a valid reply in some cases but not in others.
 */
static char *
expglob(char *s)
{
	char *p, **pp, *rval;
#ifdef GLOB_NOESCAPE
	int flags = GLOB_NOCHECK | GLOB_NOESCAPE;
#else
	int flags = GLOB_NOCHECK;
#endif
	int n;
	glob_t gl;

	memset(&gl, 0, sizeof(gl));
#ifdef   HAVE_BSDGLOB
	flags |= GLOB_LIMIT;
	gl.gl_matchc = MAXGLOBARGS;
#endif
	if (glob(s, flags, NULL, &gl) == 0 && gl.gl_pathc != 0) {
		for (pp = gl.gl_pathv, p = NULL, n = 0; *pp; pp++)
			if (*(*pp + strcspn(*pp, "\r\n")) == '\0') {
				p = *pp;
				n++;
			}
		if (n == 0)
			rval = strdup(s);
		else if (n == 1)
			rval = strdup(p);
		else {
			reply_noformat(550, "Wildcard is ambiguous.");
			rval = NULL;
		}
	} else {
		reply_noformat(550, "Wildcard expansion error.");
		rval = NULL;
	}
	globfree(&gl);
	return (rval);
}

/* ARGSUSED */
static void yyerror(char *s)
{
	char *cp;

	if ((cp = strchr(cmdbuf,'\n')))
		*cp = '\0';
	reply(500, "%s: command not understood.", cmdbuf);
}
