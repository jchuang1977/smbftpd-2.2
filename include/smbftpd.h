/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_H_
#define _SMBFTPD_H_

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>

#include <config.h>

/* param.c */
enum smbftpd_mode {
	MODE_NORMAL = 0,
	MODE_SMB
};

struct opt_set {
	struct opt_set *next;
	char *key;
	char *value;
};

#define SECURITY_POLICY_SECURE    0x1
#define SECURITY_POLICY_NOSECURE  0x2
#define ENCRYPTION_TYPE_SSL       0x1
#define ENCRYPTION_TYPE_TLS       0x2

/* system config read from config file */
typedef struct smbftpd_conf_t {
	struct opt_set *chroot_set;
	struct opt_set *max_download_rate;
	struct opt_set *max_upload_rate;
	char *server_name;
	char *listen_on_address;
	char *port;
	char *force_passive_ip;
	char *share_conf_path;
	char *exception_list;
	char *pid_file;
	char *transfer_log_path;
	char *no_login_list;
	char *virtual_user_mapping;
	char *virtual_user_auth_method;
	char *virtual_user_auth_config;
	char *ssl_cert_file;
	char *ssl_key_file;
	char *ssl_debug_log;
	char *charset_encoding;
	enum smbftpd_mode default_mode;
	int support_utf8_client;
	int using_utf8_filesystem;
	int show_program_version;
	int security_policy;
	int encryption_type;
	int normal_user_must_secure;
	int anonym_disable_secure;
	int debug_mode;
	int log_command;
	int do_wtmp_log;
	int require_valid_shell;
	int restricted_ports;
	unsigned int passive_port_low;
	unsigned int passive_port_high;
	int anonymous_login;
	int anonymous_only;
	int anonymous_readonly;
	int empty_passwd_login;
	int show_symlinks;
	int show_dot_files;
	int disable_epsv;
	int umask;
	int max_connection;
	int max_connection_per_ip;
	int timeout;
	int max_timeout;
} smbftpd_conf_t;

/* struct to save smbftpd_share.conf share's information */
typedef struct smbftpd_share {
	struct smbftpd_share *next;
	char *share;
	char *path;
	char *rw;
	char *ro;
	char *disable_download;
	char *disable_ls;
	char *disable_modify;
	int browseable;
} smbftpd_share_t;

void config_init();
void config_release();
int config_read(char *conf_path);

typedef struct smbftpd_valid_share {
	struct smbftpd_valid_share *next;
	char *share;
	char *path;
	int writable;
	int disable_download;
	int disable_ls;
	int disable_modify;
	int browseable;
} smbftpd_valid_share_t;

/**
 * Struct for every forked child.
 */
typedef struct {
	char username[256];
	char *home;
	char remotehost[NI_MAXHOST];
	struct passwd *pw_user;
	smbftpd_valid_share_t *valid_shares;
	int chroot;
	enum smbftpd_mode mode;
	off_t max_upload_rate;
	off_t max_download_rate;
	off_t byte_uploaded;
	off_t byte_downloaded;
	int transfer_type; /* TYPE_A, TYPE_I, TYPE_L; */
	int using_utf8_client;
	int logged_in;
	int guest;
	struct _ssl_ctrl {
		int ssl_encrypt_data;    /* RFC2228: default state is "Clear" */
		int PBSZ_used_flag;      /* RFC2228: PBSZ must be used before first PROT */
		int ssl_active_flag;     /* To replace the ssl_active_flag */
		int ssl_data_active_flag; /* To replace the ssl_data_active_flag */
	} ssl_ctrl;
} smbftpd_session_t;

//struct sockaddr_in;
#ifdef  INET6
//struct sockaddr_in6;
#endif
union sockunion {
	struct sockinet {
#ifdef  HAVE_SI_LEN
		u_char  si_len;
#endif
		sa_family_t  si_family;
		u_short si_port;
#ifdef INET6
		char padding[sizeof(struct sockaddr_in6) - sizeof(sa_family_t) -
			sizeof(unsigned short int)];                 
#else /* !INET6 */
		char padding[sizeof(struct sockaddr_in) - sizeof(sa_family_t) -
			sizeof(unsigned short int)];            
#endif /* INET6 */
	} su_si;
	struct sockaddr_in  su_sin;
#ifdef  INET6
	struct sockaddr_in6 su_sin6;
#endif
};
#ifdef  HAVE_SI_LEN
#define su_len          su_si.si_len
#endif
#define su_family       su_si.si_family
#define su_port         su_si.si_port

/* log.c */
#define LOGCMD(cmd, file)		smbftpd_logcmd((cmd), (file), NULL, -1)
#define LOGCMD2(cmd, file1, file2)	smbftpd_logcmd((cmd), (file1), (file2), -1)
#define LOGBYTES(cmd, file, cnt)	smbftpd_logcmd((cmd), (file), NULL, (cnt))
void smbftpd_logcmd(const char *cmd, const char *file1, const char *file2, off_t cnt);
int smbftpd_xferlog_open(const char *log_path);
void smbftpd_xferlog_close(void);
void smbftpd_xferlog_write(const char *cmd, const char *file, off_t size, time_t tstart, time_t tend);
void smbftpd_logwtmp(const char *name, const char *host);

/* reply.c */
void reply(int n, const char *fmt, ...);
void reply_noformat(int n, const char *str);
void reply_fs2client(int n, const char *fmt, ...);
#define	LONG_REPLY(x)		(x*-1)
#define	IS_LONG_REPLY(x)	(x < 0)

void fatalerror(const char *s);

/* share.c */

/* Used in SzGetRealPath()'s flag */ 
#define FLAG_CHECK_WRITABLE     0x0001
#define FLAG_NO_FOLLOW_LINK     0x0002
#define FLAG_NO_FOLLOW_LAST_LINK        0x0004 /* For rename */

const smbftpd_valid_share_t *smbftpd_get_share_by_path(smbftpd_valid_share_t *validshares, const char *path);
int smbfptd_replace_share_path(smbftpd_valid_share_t *validshares, char *path, int bufsize);
char *smbftpd_get_realpath(smbftpd_valid_share_t *validshares, const char *path, int flags);
int smbftpd_valid_share_get(const char *user, const char *home_dir, smbftpd_share_t *shares,smbftpd_valid_share_t **ppvalid_shares);
void smbftpd_valid_share_free(smbftpd_valid_share_t **validshares);
int smbftpd_share_enum(char *path, smbftpd_share_t **smb_shares);
void smbftpd_share_free(smbftpd_share_t **smb_shares);

/* misc.c */
const char *set_get_value(struct opt_set *set, const char *user);
char *doublequote(const char *s);
char *str_trim_space(char *str);
char *str_trim_space_quote(char *szstr);
int is_user_in_list(const char *user, const char *list);
int is_user_in_group(const char *user, const char *group);
int smbftpd_config_parser(const char *file, int (*opt_handler)(char *option, char *optarg));

/* proctitle.c */
void compat_setproctitle_init(int argc, char *argv[]);
void proc_title_init(const char *fmt, ...);
void proc_title_set(const char *cmd);

/* pwcache.c */
#ifndef HAVE_PWCACHE
char *user_from_uid(uid_t uid, int nouser);
char *group_from_gid(gid_t gid, int nogroup);
#endif

/* ftpcmd.y */
//int yyparse(void);
int mygetline(char *s, int n, FILE *iop);

/* main.c */
void dologout(int status);

/* oob.c */
#define STARTXFER       flagxfer(1) 
#define ENDXFER         flagxfer(0)
#define START_UNSAFE    maskurg(1) 
#define END_UNSAFE      maskurg(0)
void flagxfer(int flag);
void set_receive_sigurg();
int sigurg_received();
int check_oob(void);
void maskurg(int flag);

/* unicode.c */
int smbftpd_unicode_open(const char *encoding);
void smbftpd_unicode_close();
const char *smbftpd_charset_fs2client(const char *inbuf, char *outbuf, size_t outlen);
char *smbftpd_charset_client2fs(const char *inbuf);

/* textuser.c */
typedef struct {
	char *user;
	char *group;
	char *home;
	char *password;
} smbftpd_text_user_t;

void smbftpd_text_user_free(smbftpd_text_user_t *smbftpd_user);
int smbftpd_text_user_get(const char *path, const char *user, smbftpd_text_user_t *smbftpd_user);
int smbftpd_text_user_set(const char *path, const char *user, const smbftpd_text_user_t *smbftpd_user);

#endif /* _SMBFTPD_H_ */
