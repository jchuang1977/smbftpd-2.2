#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20100610

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

#define YYPURE 0

#line 43 "ftpcmd.y"
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

#line 96 "ftpcmd.y"
typedef union {
	struct {
		off_t	o;
		int	i;
	} u;
	char   *s;
} YYSTYPE;
#line 79 "ftpcmd.c"
/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

extern int YYPARSE_DECL();
extern int YYLEX_DECL();

#define A 257
#define B 258
#define C 259
#define E 260
#define F 261
#define I 262
#define L 263
#define N 264
#define P 265
#define R 266
#define S 267
#define T 268
#define ALL 269
#define SP 270
#define CRLF 271
#define COMMA 272
#define USER 273
#define PASS 274
#define ACCT 275
#define REIN 276
#define QUIT 277
#define PORT 278
#define PASV 279
#define TYPE 280
#define STRU 281
#define MODE 282
#define RETR 283
#define STOR 284
#define APPE 285
#define MLFL 286
#define MAIL 287
#define MSND 288
#define MSOM 289
#define MSAM 290
#define MRSQ 291
#define MRCP 292
#define ALLO 293
#define REST 294
#define RNFR 295
#define RNTO 296
#define ABOR 297
#define DELE 298
#define CWD 299
#define LIST 300
#define NLST 301
#define SITE 302
#define STAT 303
#define HELP 304
#define NOOP 305
#define MKD 306
#define RMD 307
#define PWD 308
#define CDUP 309
#define STOU 310
#define SMNT 311
#define SYST 312
#define SIZE 313
#define MDTM 314
#define LPRT 315
#define LPSV 316
#define EPRT 317
#define EPSV 318
#define UMASK 319
#define IDLE 320
#define CHMOD 321
#define MDFIVE 322
#define FEAT 323
#define OPTS 324
#define AUTH 325
#define PROT 326
#define PBSZ 327
#define LEXERR 328
#define NOTIMPL 329
#define STRING 330
#define NUMBER 331
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    0,    0,   17,   17,   17,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   17,   17,   17,
   18,   18,   13,   12,   12,   15,   16,    3,   14,   19,
   20,   20,    9,    9,    9,    8,    8,    8,    8,    8,
    8,    8,    8,    6,    6,    6,    7,    7,    7,   11,
   10,    2,    1,    5,    4,
};
static const short yylen[] = {                            2,
    0,    2,    2,    4,    4,    4,    4,    4,    2,    5,
    5,    5,    3,    3,    5,    5,    3,    5,    5,    5,
    5,    9,    5,    5,    5,    3,    5,    3,    5,    5,
    3,    5,    5,    3,    3,    5,    2,    4,    2,    5,
    5,    3,    3,    4,    6,    7,    5,    7,    9,    5,
    7,    5,    3,    5,    5,    2,    4,    2,    1,    1,
    5,    5,    1,    0,    1,    1,    1,    1,    1,   11,
   41,   17,    1,    1,    1,    1,    3,    1,    3,    1,
    1,    3,    2,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    0,    0,    0,
};
static const short yydefred[] = {                         1,
    0,   60,    0,    0,    0,   93,   93,   93,   93,   93,
   93,   95,   95,   93,   93,   95,   95,   93,   95,   93,
   93,   93,    0,   93,    0,    0,   95,   95,   93,   93,
   95,   93,   93,   93,   93,   93,   93,   94,    0,    0,
    0,    0,    0,   59,    2,    3,    0,    0,    9,   58,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   37,   39,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   56,    0,    0,    0,    0,   63,
    0,   65,    0,    0,   13,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   34,    0,    0,   35,    0,
   28,    0,   26,    0,   93,   95,   93,    0,    0,   31,
    0,    0,    0,   42,   43,    0,   53,    0,    0,    0,
   14,    0,    0,   17,    0,   66,    0,   67,    0,   69,
    0,    7,    8,    0,    0,    0,    0,   80,    0,    0,
   84,   86,   85,    0,   88,   89,   87,    0,   91,   90,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   44,    0,    0,    0,    0,    0,   38,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   57,
    4,    6,    5,    0,   10,    0,    0,    0,   68,   83,
   18,   19,   20,   23,   24,   25,    0,   21,   62,   61,
   33,   32,   36,   29,   27,    0,    0,   47,    0,    0,
    0,   50,   30,   40,   41,   52,   54,   55,    0,   11,
   12,   16,   15,    0,   75,   73,   74,   77,   79,   82,
    0,   45,   92,    0,    0,    0,    0,    0,    0,    0,
   48,    0,   46,   51,    0,    0,    0,    0,    0,    0,
   22,   49,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   70,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   71,
};
static const short yydgoto[] = {                          1,
   51,  244,  200,   57,   84,  154,  158,  150,  238,  160,
  161,   93,   91,  141,  137,  139,   45,   46,  145,  186,
};
static const short yysindex[] = {                         0,
 -124,    0, -252, -221, -268,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -243,    0, -202, -257,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -235, -228,
 -224, -219, -216,    0,    0,    0, -269, -247,    0,    0,
 -196, -181, -172, -171, -170, -169, -168, -167, -166, -165,
 -164, -163, -161, -162, -193, -191, -189, -256, -186, -218,
    0,    0, -159, -157, -156, -155, -153, -152, -149, -148,
 -147, -146, -144, -184,    0, -212, -206, -203, -217,    0,
 -143,    0, -142, -201,    0, -187, -226, -242, -199, -199,
 -199, -198, -195, -199, -199,    0, -199, -199,    0, -199,
    0, -199,    0, -182,    0,    0,    0, -185, -199,    0,
 -137, -199, -199,    0,    0, -199,    0, -199, -199, -194,
    0, -188, -267,    0, -132,    0, -130,    0, -128,    0,
 -127,    0,    0, -126, -123, -125, -119,    0, -259, -109,
    0,    0,    0, -108,    0,    0,    0, -107,    0,    0,
 -106, -105, -104, -178, -103,  -84,  -76,  -75,  -74,  -73,
  -67, -183,    0, -176,  -64,  -63, -174,  -62,    0,  -61,
  -60,  -59,  -58,  -57,  -56,  -54,  -53,  -52,  -51,    0,
    0,    0,    0, -116,    0, -197, -197, -110,    0,    0,
    0,    0,    0,    0,    0,    0,  -44,    0,    0,    0,
    0,    0,    0,    0,    0,  -48, -102,    0, -102, -199,
 -101,    0,    0,    0,    0,    0,    0,    0,  -99,    0,
    0,    0,    0,  -47,    0,    0,    0,    0,    0,    0,
  -46,    0,    0,  -45,  -43,  -40,  -38,  -37,  -95,  -94,
    0, -199,    0,    0,  -93,  -33,  -31,  -30,  -29,  -89,
    0,    0,  -87,  -27,  -26,  -83,  -82,  -25,  -22,  -80,
  -79,    0,  -19,  -77,  -17,  -72,  -16,  -71,  -15,  -70,
  -14,  -69,   -9,  -66,   -8,  -65,   -5,  -55,   -4,  -50,
   -3,  -49,   -2,  -42,   -1,  -41,    1,  -39,    2,  -36,
    3,  -35,    0,
};
static const short yyrindex[] = {                         0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    6,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -112,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    7,    8,    0,    9,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -257,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,
};
static const short yygindex[] = {                         0,
   23,   15,   30,   -7,    0,    0,    0,    0,   75,  -97,
 -100,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 296
static const short yytable[] = {                        162,
  163,  188,   50,  166,  167,   58,  168,  169,   61,   62,
  198,   64,  170,   72,  171,  155,  156,   47,  178,   73,
   74,  180,  181,   77,  157,  182,   68,  183,  184,   52,
   53,   54,   55,   56,  151,   85,   59,   60,  152,  153,
   63,   86,   65,   66,   67,   87,   69,  114,   48,   49,
   88,   75,   76,   89,   78,   79,   80,   81,   82,   83,
   90,  235,  115,  189,  116,  117,  236,   70,   71,  146,
  237,  199,  147,   94,  148,  149,  108,  109,  110,  111,
  112,  113,   92,  119,  120,  133,  134,  172,  173,   95,
  118,  207,  208,  217,  218,  221,  222,   96,   97,   98,
   99,  100,  101,  102,  103,  104,  105,  107,  175,  106,
  122,  121,  123,  140,  124,  125,  126,  135,  127,  246,
  128,  129,  130,  136,  131,  132,  138,  142,  143,  144,
  159,    2,  164,  179,  177,  165,  185,  174,  190,  176,
  191,  187,  192,  193,  196,  194,  216,  195,    3,    4,
  197,  258,    5,    6,    7,    8,    9,   10,   11,   12,
   13,  201,  202,  203,  204,  205,  206,  209,   14,   15,
   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,
   26,   27,   28,   29,   30,   31,  210,   32,   33,   34,
   35,   36,   37,   38,  211,  212,  213,  214,   39,   40,
   41,   42,   43,  215,   44,  219,  220,   93,  223,  224,
  225,  226,  227,  228,  234,  229,  230,  231,  232,  233,
  199,  241,  242,  250,  249,  251,  252,  240,  243,  247,
  253,  248,  254,  245,  255,  256,  257,  259,  260,  261,
  262,  264,  263,  265,  266,  267,  270,  268,  269,  271,
  272,  273,  274,  275,  276,  278,  280,  282,  277,  279,
  281,  283,  284,  286,  285,  287,  288,  290,  292,  294,
  296,  239,  298,  300,  302,  289,   64,   76,   78,   81,
  291,  293,    0,    0,    0,    0,    0,    0,  295,  297,
    0,  299,    0,    0,  301,  303,
};
static const short yycheck[] = {                        100,
  101,  269,  271,  104,  105,   13,  107,  108,   16,   17,
  270,   19,  110,  271,  112,  258,  259,  270,  119,   27,
   28,  122,  123,   31,  267,  126,  270,  128,  129,    7,
    8,    9,   10,   11,  261,  271,   14,   15,  265,  266,
   18,  270,   20,   21,   22,  270,   24,  304,  270,  271,
  270,   29,   30,  270,   32,   33,   34,   35,   36,   37,
  330,  259,  319,  331,  321,  322,  264,  270,  271,  257,
  268,  331,  260,  270,  262,  263,  270,  271,  270,  271,
  270,  271,  330,  270,  271,  270,  271,  270,  271,  271,
   68,  270,  271,  270,  271,  270,  271,  270,  270,  270,
  270,  270,  270,  270,  270,  270,  270,  270,  116,  271,
  270,  330,  270,  331,  271,  271,  270,  330,  271,  220,
  270,  270,  270,  330,  271,  270,  330,  271,  271,  331,
  330,  256,  331,  271,  320,  331,  331,  115,  271,  117,
  271,  330,  271,  271,  270,  272,  330,  271,  273,  274,
  270,  252,  277,  278,  279,  280,  281,  282,  283,  284,
  285,  271,  271,  271,  271,  271,  271,  271,  293,  294,
  295,  296,  297,  298,  299,  300,  301,  302,  303,  304,
  305,  306,  307,  308,  309,  310,  271,  312,  313,  314,
  315,  316,  317,  318,  271,  271,  271,  271,  323,  324,
  325,  326,  327,  271,  329,  270,  270,  320,  271,  271,
  271,  271,  271,  271,  331,  272,  271,  271,  271,  271,
  331,  266,  271,  270,  272,  271,  270,  198,  331,  331,
  271,  331,  271,  219,  272,  331,  331,  331,  272,  271,
  271,  331,  272,  331,  272,  272,  272,  331,  331,  272,
  331,  331,  272,  331,  272,  272,  272,  272,  331,  331,
  331,  331,  272,  272,  331,  331,  272,  272,  272,  272,
  272,  197,  272,  272,  272,  331,  271,  271,  271,  271,
  331,  331,   -1,   -1,   -1,   -1,   -1,   -1,  331,  331,
   -1,  331,   -1,   -1,  331,  331,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 331
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"A","B","C","E","F","I","L","N",
"P","R","S","T","ALL","SP","CRLF","COMMA","USER","PASS","ACCT","REIN","QUIT",
"PORT","PASV","TYPE","STRU","MODE","RETR","STOR","APPE","MLFL","MAIL","MSND",
"MSOM","MSAM","MRSQ","MRCP","ALLO","REST","RNFR","RNTO","ABOR","DELE","CWD",
"LIST","NLST","SITE","STAT","HELP","NOOP","MKD","RMD","PWD","CDUP","STOU",
"SMNT","SYST","SIZE","MDTM","LPRT","LPSV","EPRT","EPSV","UMASK","IDLE","CHMOD",
"MDFIVE","FEAT","OPTS","AUTH","PROT","PBSZ","LEXERR","NOTIMPL","STRING",
"NUMBER",
};
static const char *yyrule[] = {
"$accept : cmd_list",
"cmd_list :",
"cmd_list : cmd_list cmd",
"cmd_list : cmd_list rcmd",
"cmd : AUTH SP auth_type CRLF",
"cmd : PBSZ SP buffer_size CRLF",
"cmd : PROT SP protection_level CRLF",
"cmd : USER SP username CRLF",
"cmd : PASS SP password CRLF",
"cmd : PASS CRLF",
"cmd : PORT check_login SP host_port CRLF",
"cmd : LPRT check_login SP host_long_port CRLF",
"cmd : EPRT check_login SP STRING CRLF",
"cmd : PASV check_login CRLF",
"cmd : LPSV check_login CRLF",
"cmd : EPSV check_login_epsv SP NUMBER CRLF",
"cmd : EPSV check_login_epsv SP ALL CRLF",
"cmd : EPSV check_login_epsv CRLF",
"cmd : TYPE check_login SP type_code CRLF",
"cmd : STRU check_login SP struct_code CRLF",
"cmd : MODE check_login SP mode_code CRLF",
"cmd : ALLO check_login SP NUMBER CRLF",
"cmd : ALLO check_login SP NUMBER SP R SP NUMBER CRLF",
"cmd : RETR check_login SP pathname CRLF",
"cmd : STOR check_login_ro SP pathname CRLF",
"cmd : APPE check_login_ro SP pathname CRLF",
"cmd : NLST check_login CRLF",
"cmd : NLST check_login SP pathstring CRLF",
"cmd : LIST check_login CRLF",
"cmd : LIST check_login SP pathstring CRLF",
"cmd : STAT check_login SP pathname CRLF",
"cmd : STAT check_login CRLF",
"cmd : DELE check_login_ro SP pathname CRLF",
"cmd : RNTO check_login_ro SP pathname CRLF",
"cmd : ABOR check_login CRLF",
"cmd : CWD check_login CRLF",
"cmd : CWD check_login SP pathname CRLF",
"cmd : HELP CRLF",
"cmd : HELP SP STRING CRLF",
"cmd : NOOP CRLF",
"cmd : MKD check_login_ro SP pathname CRLF",
"cmd : RMD check_login_ro SP pathname CRLF",
"cmd : PWD check_login CRLF",
"cmd : CDUP check_login CRLF",
"cmd : SITE SP HELP CRLF",
"cmd : SITE SP HELP SP STRING CRLF",
"cmd : SITE SP MDFIVE check_login SP pathname CRLF",
"cmd : SITE SP UMASK check_login CRLF",
"cmd : SITE SP UMASK check_login SP octal_number CRLF",
"cmd : SITE SP CHMOD check_login_ro SP octal_number SP pathname CRLF",
"cmd : SITE SP check_login IDLE CRLF",
"cmd : SITE SP check_login IDLE SP NUMBER CRLF",
"cmd : STOU check_login_ro SP pathname CRLF",
"cmd : SYST check_login CRLF",
"cmd : SIZE check_login SP pathname CRLF",
"cmd : MDTM check_login SP pathname CRLF",
"cmd : FEAT CRLF",
"cmd : OPTS SP STRING CRLF",
"cmd : QUIT CRLF",
"cmd : NOTIMPL",
"cmd : error",
"rcmd : RNFR check_login_ro SP pathname CRLF",
"rcmd : REST check_login SP NUMBER CRLF",
"username : STRING",
"password :",
"password : STRING",
"auth_type : STRING",
"protection_level : STRING",
"byte_size : NUMBER",
"buffer_size : NUMBER",
"host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER",
"host_long_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER",
"host_long_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER",
"form_code : N",
"form_code : T",
"form_code : C",
"type_code : A",
"type_code : A SP form_code",
"type_code : E",
"type_code : E SP form_code",
"type_code : I",
"type_code : L",
"type_code : L SP byte_size",
"type_code : L byte_size",
"struct_code : F",
"struct_code : R",
"struct_code : P",
"mode_code : S",
"mode_code : B",
"mode_code : C",
"pathname : pathstring",
"pathstring : STRING",
"octal_number : NUMBER",
"check_login :",
"check_login_epsv :",
"check_login_ro :",

};
#endif
/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 961 "ftpcmd.y"

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
#line 1188 "ftpcmd.c"

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (data->s_base != 0)
          ? (short *)realloc(data->s_base, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (data->l_base != 0)
          ? (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 2:
#line 145 "ftpcmd.y"
	{
			if (fromname)
				free(fromname);
			fromname = NULL;
			restart_point = 0;
		}
break;
case 4:
#line 156 "ftpcmd.y"
	{
			cmd_auth(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 5:
#line 162 "ftpcmd.y"
	{
			cmd_pbsz();
		}
break;
case 6:
#line 166 "ftpcmd.y"
	{
			cmd_prot(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 7:
#line 172 "ftpcmd.y"
	{
			cmd_user(yystack.l_mark[-1].s);
			free(yystack.l_mark[-1].s);
		}
break;
case 8:
#line 177 "ftpcmd.y"
	{
			cmd_pass(yystack.l_mark[-1].s);
			free(yystack.l_mark[-1].s);
		}
break;
case 9:
#line 182 "ftpcmd.y"
	{
			cmd_pass("");
		}
break;
case 10:
#line 186 "ftpcmd.y"
	{
			if (epsvall) {
				reply_noformat(501, "No PORT allowed after EPSV ALL.");
				goto port_done;
			}
			if (!yystack.l_mark[-3].u.i)
				goto port_done;

			cmd_port();

		port_done:
			;	/* Life, the universe and everything! */
		}
break;
case 11:
#line 200 "ftpcmd.y"
	{
			if (epsvall) {
				reply_noformat(501, "No LPRT allowed after EPSV ALL.");
				goto lprt_done;
			}
			if (!yystack.l_mark[-3].u.i)
				goto lprt_done;

			cmd_lprt();

		lprt_done:
			;	/* Life, the universe and everything! */
		}
break;
case 12:
#line 214 "ftpcmd.y"
	{
			if (epsvall) {
				reply_noformat(501, "No EPRT allowed after EPSV ALL.");
				goto eprt_done;
			}
			if (!yystack.l_mark[-3].u.i)
				goto eprt_done;

			cmd_eprt(yystack.l_mark[-1].s);

		eprt_done:
			free(yystack.l_mark[-1].s);
		}
break;
case 13:
#line 228 "ftpcmd.y"
	{
			if (epsvall)
				reply_noformat(501, "No PASV allowed after EPSV ALL.");
			else if (yystack.l_mark[-1].u.i)
				cmd_passive();
		}
break;
case 14:
#line 235 "ftpcmd.y"
	{
			if (epsvall)
				reply_noformat(501, "No LPSV allowed after EPSV ALL.");
			else if (yystack.l_mark[-1].u.i)
				cmd_long_passive("LPSV", PF_UNSPEC);
		}
break;
case 15:
#line 242 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				int pf;
				switch (yystack.l_mark[-1].u.i) {
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
break;
case 16:
#line 262 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				reply_noformat(200, "EPSV ALL command successful.");
				epsvall++;
			}
		}
break;
case 17:
#line 269 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				cmd_long_passive("EPSV", PF_UNSPEC);
		}
break;
case 18:
#line 274 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
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
break;
case 19:
#line 310 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				switch (yystack.l_mark[-1].u.i) {

				case STRU_F:
					reply_noformat(200, "STRU F accepted.");
					break;

				default:
					reply_noformat(504, "Unimplemented STRU type.");
				}
			}
		}
break;
case 20:
#line 324 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				switch (yystack.l_mark[-1].u.i) {

				case MODE_S:
					reply_noformat(200, "MODE S ok.");
					break;
	
				default:
					reply_noformat(502, "Unimplemented MODE type.");
				}
			}
		}
break;
case 21:
#line 338 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				reply_noformat(202, "ALLO command ignored.");
			}
		}
break;
case 22:
#line 344 "ftpcmd.y"
	{
			if (yystack.l_mark[-7].u.i) {
				reply_noformat(202, "ALLO command ignored.");
			}
		}
break;
case 23:
#line 350 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_retr(yystack.l_mark[-1].s, restart_point);

			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 24:
#line 358 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_store(yystack.l_mark[-1].s, "w", 0, restart_point);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 25:
#line 365 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_store(yystack.l_mark[-1].s, "a", 0, restart_point);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 26:
#line 372 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				cmd_list(".", 0);
		}
break;
case 27:
#line 377 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i)
				cmd_list(yystack.l_mark[-1].s, 0);
			free(yystack.l_mark[-1].s);
		}
break;
case 28:
#line 383 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				cmd_list("", 1);
		}
break;
case 29:
#line 388 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i)
				cmd_list(yystack.l_mark[-1].s, 1);
			free(yystack.l_mark[-1].s);
		}
break;
case 30:
#line 394 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_statfile(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 31:
#line 401 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i) {
				cmd_stat();
			}
		}
break;
case 32:
#line 407 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_delete(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 33:
#line 414 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL) {
				if (fromname) {
					cmd_rnto(fromname, yystack.l_mark[-1].s);
					free(fromname);
					fromname = NULL;
				} else {
					reply_noformat(503, "Bad sequence of commands.");
				}
			}
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 34:
#line 428 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				reply_noformat(225, "ABOR command successful.");
		}
break;
case 35:
#line 433 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i) {
				cmd_cwd(smbftpd_session.home);
			}
		}
break;
case 36:
#line 439 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_cwd(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 37:
#line 446 "ftpcmd.y"
	{
			help(cmdtab, NULL);
		}
break;
case 38:
#line 450 "ftpcmd.y"
	{
			char *cp = yystack.l_mark[-1].s;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = yystack.l_mark[-1].s + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, NULL);
			} else
				help(cmdtab, yystack.l_mark[-1].s);
			free(yystack.l_mark[-1].s);
		}
break;
case 39:
#line 466 "ftpcmd.y"
	{
			reply_noformat(200, "NOOP command successful.");
		}
break;
case 40:
#line 470 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_mkdir(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 41:
#line 477 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_rmdir(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 42:
#line 484 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				cmd_pwd();
		}
break;
case 43:
#line 489 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i)
				cmd_cwd("..");
		}
break;
case 44:
#line 494 "ftpcmd.y"
	{
			help(sitetab, NULL);
		}
break;
case 45:
#line 498 "ftpcmd.y"
	{
			help(sitetab, yystack.l_mark[-1].s);
			free(yystack.l_mark[-1].s);
		}
break;
case 46:
#line 503 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s) {
				cmd_site_mdfive(yystack.l_mark[-1].s);
			}
			if (yystack.l_mark[-1].s)
				free(yystack.l_mark[-1].s);
		}
break;
case 47:
#line 511 "ftpcmd.y"
	{
			int oldmask;

			if (yystack.l_mark[-1].u.i) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o.", oldmask);
			}
		}
break;
case 48:
#line 521 "ftpcmd.y"
	{
			int oldmask;

			if (yystack.l_mark[-3].u.i) {
				if ((yystack.l_mark[-1].u.i == -1) || (yystack.l_mark[-1].u.i > 0777)) {
					reply_noformat(501, "Bad UMASK value.");
				} else {
					oldmask = umask(yystack.l_mark[-1].u.i);
					reply(200,
						"UMASK set to %03o (was %03o).",
						yystack.l_mark[-1].u.i, oldmask);
				}
			}
		}
break;
case 49:
#line 536 "ftpcmd.y"
	{
			if (yystack.l_mark[-5].u.i && (yystack.l_mark[-1].s != NULL)) {
				if ((yystack.l_mark[-3].u.i == -1 ) || (yystack.l_mark[-3].u.i > 0777))
					reply_noformat(501, "Bad mode value.");
				else
					cmd_site_chmod(yystack.l_mark[-1].s, yystack.l_mark[-3].u.i);
			}
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 50:
#line 547 "ftpcmd.y"
	{
			if (yystack.l_mark[-2].u.i)
				reply(200,
					"Current IDLE time limit is %d seconds; max %d.",
					smbftpd_conf.timeout, smbftpd_conf.max_timeout);
		}
break;
case 51:
#line 554 "ftpcmd.y"
	{
			if (yystack.l_mark[-4].u.i) {
				if (yystack.l_mark[-1].u.i < 30 || yystack.l_mark[-1].u.i > smbftpd_conf.max_timeout) {
					reply(501,
						"Maximum IDLE time must be between 30 and %d seconds.",
						smbftpd_conf.max_timeout);
				} else {
					smbftpd_conf.timeout = yystack.l_mark[-1].u.i;
					(void) alarm(smbftpd_conf.timeout);
					reply(200,
						"Maximum IDLE time set to %d seconds.",
						smbftpd_conf.timeout);
				}
			}
		}
break;
case 52:
#line 570 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_store(yystack.l_mark[-1].s, "w", 1, restart_point);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 53:
#line 577 "ftpcmd.y"
	{
			if (yystack.l_mark[-1].u.i) {
#ifdef BSD
				reply(215, "UNIX Type: L%d Version: BSD-%d", CHAR_BIT, BSD);
#else /* BSD */
				reply(215, "UNIX Type: L%d", CHAR_BIT);
#endif /* BSD */
			}
		}
break;
case 54:
#line 595 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL)
				cmd_size(yystack.l_mark[-1].s);
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 55:
#line 612 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s != NULL) {
				cmd_mdtm(yystack.l_mark[-1].s);
			}
			if (yystack.l_mark[-1].s != NULL)
				free(yystack.l_mark[-1].s);
		}
break;
case 56:
#line 620 "ftpcmd.y"
	{
			cmd_feat();
		}
break;
case 57:
#line 624 "ftpcmd.y"
	{
			cmd_opts(yystack.l_mark[-1].s);
			free(yystack.l_mark[-1].s);
		}
break;
case 58:
#line 629 "ftpcmd.y"
	{
			cmd_quit();
		}
break;
case 59:
#line 633 "ftpcmd.y"
	{
			reply(502, "%s command not implemented.", yystack.l_mark[0].s);
		}
break;
case 60:
#line 637 "ftpcmd.y"
	{
			yyclearin;		/* discard lookahead data */
			yyerrok;		/* clear error condition */
			state = CMD;		/* reset lexer state */
		}
break;
case 61:
#line 645 "ftpcmd.y"
	{
			restart_point = 0;
			if (yystack.l_mark[-3].u.i && yystack.l_mark[-1].s) {
				if (fromname)
					free(fromname);
				fromname = NULL;
				if (0 == cmd_rnfr(yystack.l_mark[-1].s))
					fromname = yystack.l_mark[-1].s;
				else
					free(yystack.l_mark[-1].s);
			} else if (yystack.l_mark[-1].s) {
				free(yystack.l_mark[-1].s);
			}
		}
break;
case 62:
#line 660 "ftpcmd.y"
	{
			if (yystack.l_mark[-3].u.i) {
				if (fromname)
					free(fromname);
				fromname = NULL;
				restart_point = yystack.l_mark[-1].u.o;
				reply(350, "Restarting at %qd. %s",
					restart_point,
					"Send STORE or RETRIEVE to initiate transfer.");
			}
		}
break;
case 64:
#line 679 "ftpcmd.y"
	{
			yyval.s = (char *)calloc(1, sizeof(char));
		}
break;
case 68:
#line 695 "ftpcmd.y"
	{
			yyval.u.i = yystack.l_mark[0].u.i;
		}
break;
case 69:
#line 702 "ftpcmd.y"
	{
			yyval.u.i = yystack.l_mark[0].u.i;
		}
break;
case 70:
#line 710 "ftpcmd.y"
	{
			char *a, *p;
#ifdef   HAVE_SI_LEN
			data_dest.su_len = sizeof(struct sockaddr_in);
#endif
			data_dest.su_family = AF_INET;
			p = (char *)&data_dest.su_sin.sin_port;
			p[0] = yystack.l_mark[-2].u.i; p[1] = yystack.l_mark[0].u.i;
			a = (char *)&data_dest.su_sin.sin_addr;
			a[0] = yystack.l_mark[-10].u.i; a[1] = yystack.l_mark[-8].u.i; a[2] = yystack.l_mark[-6].u.i; a[3] = yystack.l_mark[-4].u.i;
		}
break;
case 71:
#line 730 "ftpcmd.y"
	{
#ifdef   INET6
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));

#ifdef   HAVE_SI_LEN
			data_dest.su_len = sizeof(struct sockaddr_in6);
#endif
			data_dest.su_family = AF_INET6;
			p = (char *)&data_dest.su_port;
			p[0] = yystack.l_mark[-2].u.i; p[1] = yystack.l_mark[0].u.i;
			a = (char *)&data_dest.su_sin6.sin6_addr;
			a[0] = yystack.l_mark[-36].u.i; a[1] = yystack.l_mark[-34].u.i; a[2] = yystack.l_mark[-32].u.i; a[3] = yystack.l_mark[-30].u.i;
			a[4] = yystack.l_mark[-28].u.i; a[5] = yystack.l_mark[-26].u.i; a[6] = yystack.l_mark[-24].u.i; a[7] = yystack.l_mark[-22].u.i;
			a[8] = yystack.l_mark[-20].u.i; a[9] = yystack.l_mark[-18].u.i; a[10] = yystack.l_mark[-16].u.i; a[11] = yystack.l_mark[-14].u.i;
			a[12] = yystack.l_mark[-12].u.i; a[13] = yystack.l_mark[-10].u.i; a[14] = yystack.l_mark[-8].u.i; a[15] = yystack.l_mark[-6].u.i;
			if (his_addr.su_family == AF_INET6) {
				/* XXX more sanity checks! */
				data_dest.su_sin6.sin6_scope_id =
					his_addr.su_sin6.sin6_scope_id;
			}
#endif
			if (yystack.l_mark[-40].u.i != 6 || yystack.l_mark[-38].u.i != 16 || yystack.l_mark[-4].u.i != 2)
				memset(&data_dest, 0, sizeof(data_dest));
		}
break;
case 72:
#line 759 "ftpcmd.y"
	{
			char *a, *p;

			memset(&data_dest, 0, sizeof(data_dest));
#ifdef   HAVE_SI_LEN
			data_dest.su_sin.sin_len = sizeof(struct sockaddr_in);
#endif
			data_dest.su_family = AF_INET;
			p = (char *)&data_dest.su_port;
			p[0] = yystack.l_mark[-2].u.i; p[1] = yystack.l_mark[0].u.i;
			a = (char *)&data_dest.su_sin.sin_addr;
			a[0] =  yystack.l_mark[-12].u.i; a[1] = yystack.l_mark[-10].u.i; a[2] = yystack.l_mark[-8].u.i; a[3] = yystack.l_mark[-6].u.i;
			if (yystack.l_mark[-16].u.i != 4 || yystack.l_mark[-14].u.i != 4 || yystack.l_mark[-4].u.i != 2)
				memset(&data_dest, 0, sizeof(data_dest));
		}
break;
case 73:
#line 778 "ftpcmd.y"
	{
			yyval.u.i = FORM_N;
		}
break;
case 74:
#line 782 "ftpcmd.y"
	{
			yyval.u.i = FORM_T;
		}
break;
case 75:
#line 786 "ftpcmd.y"
	{
			yyval.u.i = FORM_C;
		}
break;
case 76:
#line 793 "ftpcmd.y"
	{
			cmd_type = TYPE_A;
			cmd_form = FORM_N;
		}
break;
case 77:
#line 798 "ftpcmd.y"
	{
			cmd_type = TYPE_A;
			cmd_form = yystack.l_mark[0].u.i;
		}
break;
case 78:
#line 803 "ftpcmd.y"
	{
			cmd_type = TYPE_E;
			cmd_form = FORM_N;
		}
break;
case 79:
#line 808 "ftpcmd.y"
	{
			cmd_type = TYPE_E;
			cmd_form = yystack.l_mark[0].u.i;
		}
break;
case 80:
#line 813 "ftpcmd.y"
	{
			cmd_type = TYPE_I;
		}
break;
case 81:
#line 817 "ftpcmd.y"
	{
			cmd_type = TYPE_L;
			cmd_bytesz = CHAR_BIT;
		}
break;
case 82:
#line 822 "ftpcmd.y"
	{
			cmd_type = TYPE_L;
			cmd_bytesz = yystack.l_mark[0].u.i;
		}
break;
case 83:
#line 828 "ftpcmd.y"
	{
			cmd_type = TYPE_L;
			cmd_bytesz = yystack.l_mark[0].u.i;
		}
break;
case 84:
#line 836 "ftpcmd.y"
	{
			yyval.u.i = STRU_F;
		}
break;
case 85:
#line 840 "ftpcmd.y"
	{
			yyval.u.i = STRU_R;
		}
break;
case 86:
#line 844 "ftpcmd.y"
	{
			yyval.u.i = STRU_P;
		}
break;
case 87:
#line 851 "ftpcmd.y"
	{
			yyval.u.i = MODE_S;
		}
break;
case 88:
#line 855 "ftpcmd.y"
	{
			yyval.u.i = MODE_B;
		}
break;
case 89:
#line 859 "ftpcmd.y"
	{
			yyval.u.i = MODE_C;
		}
break;
case 90:
#line 866 "ftpcmd.y"
	{
			if (smbftpd_session.logged_in && yystack.l_mark[0].s) {
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
				if ((p = exptilde(yystack.l_mark[0].s)) != NULL) {
					yyval.s = expglob(p);
					free(p);
				} else
					yyval.s = NULL;
				free(yystack.l_mark[0].s);
			} else
				yyval.s = yystack.l_mark[0].s;
		}
break;
case 91:
#line 893 "ftpcmd.y"
	{
			char *p = smbftpd_charset_client2fs(yystack.l_mark[0].s);
			if (p) {
				free(yystack.l_mark[0].s);
				yyval.s = p;
			}
		}
break;
case 92:
#line 904 "ftpcmd.y"
	{
			int ret, dec, multby, digit;

			/*
			 * Convert a number that was read as decimal number
			 * to what it would be if it had been read as octal.
			 */
			dec = yystack.l_mark[0].u.i;
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
			yyval.u.i = ret;
		}
break;
case 93:
#line 931 "ftpcmd.y"
	{
		yyval.u.i = check_login1();
		}
break;
case 94:
#line 938 "ftpcmd.y"
	{
		if (smbftpd_conf.disable_epsv) {
			reply_noformat(500, "EPSV command disabled.");
			yyval.u.i = 0;
		}
		else
			yyval.u.i = check_login1();
		}
break;
case 95:
#line 950 "ftpcmd.y"
	{
		if (smbftpd_session.guest && smbftpd_conf.anonymous_readonly) {
			reply_noformat(550, "Permission denied.");
			yyval.u.i = 0;
		}
		else
			yyval.u.i = check_login1();
		}
break;
#line 2298 "ftpcmd.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
