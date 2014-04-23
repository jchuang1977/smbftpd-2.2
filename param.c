/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>

#include "config.h"
#include "pathnames.h"
#include "smbftpd.h"
#include "auth.h"
#include "restrict.h"

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_share_t *smbftpd_shares;

typedef	enum opt_type_t {
	OPT_TYPE_UNKNOWN = 0,
	OPT_TYPE_INT = 1,
	OPT_TYPE_OCTAL,
	OPT_TYPE_STR,
	OPT_TYPE_SET,
	OPT_TYPE_YES_NO,
	OPT_TYPE_MODE,
	OPT_TYPE_PATH,
	OPT_TYPE_SSL,
	OPT_TYPE_SPECIAL /* this is a special option type. The option have 
	                   to assign 2 conf member or take special handling. */
} opt_type_t;

/* List of all option in config file */
typedef struct conf_opt_list_t {
	char *opt_str;
	opt_type_t opt_type;
	void *smbftpd_conf_member;
} conf_opt_list_t;

static conf_opt_list_t all_conf_list[] = {
	{"ChrootSet",            OPT_TYPE_SET,    &(smbftpd_conf.chroot_set)},
	{"MaxDownloadRate",      OPT_TYPE_SET,    &(smbftpd_conf.max_download_rate)},
	{"MaxUploadRate",        OPT_TYPE_SET,    &(smbftpd_conf.max_upload_rate)},
	{"ShareConfPath",        OPT_TYPE_PATH,   &(smbftpd_conf.share_conf_path)},
	{"TransferLog",          OPT_TYPE_STR,    &(smbftpd_conf.transfer_log_path)},
	{"ServerName",           OPT_TYPE_STR,    &(smbftpd_conf.server_name)},
	{"ListenOnAddress",      OPT_TYPE_STR,    &(smbftpd_conf.listen_on_address)},
	{"Port",                 OPT_TYPE_STR,    &(smbftpd_conf.port)},
	{"ForcePassiveIP",       OPT_TYPE_STR,    &(smbftpd_conf.force_passive_ip)},
	{"ExceptionList",        OPT_TYPE_STR,    &(smbftpd_conf.exception_list)},
	{"PidFile",              OPT_TYPE_STR,    &(smbftpd_conf.pid_file)},
	{"NoLoginList",          OPT_TYPE_STR,    &(smbftpd_conf.no_login_list)},
	{"VirtualUserMapping",   OPT_TYPE_STR,    &(smbftpd_conf.virtual_user_mapping)},
	{"VirtualUserAuthMethod",OPT_TYPE_STR,    &(smbftpd_conf.virtual_user_auth_method)},
	{"VirtualUserAuthConfig",OPT_TYPE_STR,    &(smbftpd_conf.virtual_user_auth_config)},
	{"CharsetEncoding",      OPT_TYPE_STR,    &(smbftpd_conf.charset_encoding)},
	{"DefaultMode",          OPT_TYPE_MODE,   &(smbftpd_conf.default_mode)},
	{"SupportUTF8Client",    OPT_TYPE_YES_NO, &(smbftpd_conf.support_utf8_client)},
	{"UsingUTF8FileSystem",  OPT_TYPE_YES_NO, &(smbftpd_conf.using_utf8_filesystem)},
	{"ShowProgramVersion",   OPT_TYPE_YES_NO, &(smbftpd_conf.show_program_version)},
	{"DebugMode",            OPT_TYPE_YES_NO, &(smbftpd_conf.debug_mode)},
	{"LogCommand",           OPT_TYPE_YES_NO, &(smbftpd_conf.log_command)},
	{"DoWtmpLog",            OPT_TYPE_YES_NO, &(smbftpd_conf.do_wtmp_log)},
	{"AnonymousLogin",       OPT_TYPE_YES_NO, &(smbftpd_conf.anonymous_login)},
	{"AnonymousOnly",        OPT_TYPE_YES_NO, &(smbftpd_conf.anonymous_only)},
	{"AnonymousReadOnly",    OPT_TYPE_YES_NO, &(smbftpd_conf.anonymous_readonly)},
	{"EmptyPasswdLogin",     OPT_TYPE_YES_NO, &(smbftpd_conf.empty_passwd_login)},
	{"ShowSymlinks",         OPT_TYPE_YES_NO, &(smbftpd_conf.show_symlinks)},
	{"ShowDotFiles",         OPT_TYPE_YES_NO, &(smbftpd_conf.show_dot_files)},
	{"RequireValidShell",    OPT_TYPE_YES_NO, &(smbftpd_conf.require_valid_shell)},
	{"DisableEPSV",          OPT_TYPE_YES_NO, &(smbftpd_conf.disable_epsv)},
	{"RestrictedPorts",      OPT_TYPE_YES_NO, &(smbftpd_conf.restricted_ports)},
	{"PassiveModePortRange", OPT_TYPE_SPECIAL, &(smbftpd_conf.passive_port_high)},
	{"Umask",                OPT_TYPE_OCTAL,  &(smbftpd_conf.umask)},
	{"MaxConnection",        OPT_TYPE_INT,    &(smbftpd_conf.max_connection)},
	{"MaxConnectionPerIP",   OPT_TYPE_INT,    &(smbftpd_conf.max_connection_per_ip)},
	{"TimeOut",              OPT_TYPE_INT,    &(smbftpd_conf.timeout)},
	{"MaxTimeOut",           OPT_TYPE_INT,    &(smbftpd_conf.max_timeout)},

	// SSL/TLS Options
	{"SecurityPolicy",       OPT_TYPE_SSL,    &(smbftpd_conf.security_policy)},
	{"EncryptionType",       OPT_TYPE_SSL,    &(smbftpd_conf.encryption_type)},
	{"NormalUserMustSecure", OPT_TYPE_YES_NO, &(smbftpd_conf.normal_user_must_secure)},
	{"AnonymDisableSecure",  OPT_TYPE_YES_NO, &(smbftpd_conf.anonym_disable_secure)},
	{"SSLCertFile",          OPT_TYPE_PATH,   &(smbftpd_conf.ssl_cert_file)},
	{"SSLKeyFile",           OPT_TYPE_PATH,   &(smbftpd_conf.ssl_key_file)},

	{NULL, 0, NULL}
};

/**
 * Initial the default value of smbconf
 */
void config_init()
{
	char hostname[MAXHOSTNAMELEN];

	bzero(hostname, sizeof(hostname));
	bzero(&smbftpd_conf, sizeof(smbftpd_conf));
	if (gethostname(hostname, sizeof(hostname)) == 0) {
		smbftpd_conf.server_name = strdup(hostname);
	} else {
		smbftpd_conf.server_name = strdup("Unkown");
	}
	smbftpd_conf.port = strdup("ftp");
	smbftpd_conf.umask = 022;
	smbftpd_conf.timeout = 900;
	smbftpd_conf.max_timeout = 7200;
	smbftpd_conf.show_program_version = 1;
	smbftpd_conf.default_mode = MODE_NORMAL;
	smbftpd_conf.restricted_ports = 1;
	smbftpd_conf.show_dot_files = 1;
	smbftpd_conf.require_valid_shell = 1;
	smbftpd_conf.no_login_list = strdup("500");
	smbftpd_conf.anonymous_readonly = 1;

	// SSL/TLS options
	smbftpd_conf.security_policy = SECURITY_POLICY_NOSECURE;
	smbftpd_conf.encryption_type = ENCRYPTION_TYPE_SSL | ENCRYPTION_TYPE_TLS;
	smbftpd_conf.ssl_cert_file = strdup(PATH_SSL_CERT_FILE);
	smbftpd_conf.ssl_key_file = strdup(PATH_SSL_KEY_FILE);
}

/**
 * Option/value handler for smbftpd_config_parser() function.
 * 
 * We will assign the option/value to smbftpd_conf
 * 
 * @param option  Option name
 * @param opt_arg Option value
 * 
 * @return 0: Success
 *         -1: Failed
 */
static int smbftpd_config_handler(char *option, char *opt_arg)
{
	conf_opt_list_t *opt_list = NULL;
	struct stat statBuf;
	char *szArg1, *szArg2;
	int error = -1, i;

	for (i = 0; all_conf_list[i].opt_str; i++) {
		if (strcasecmp(option, all_conf_list[i].opt_str) == 0) {
			opt_list = &all_conf_list[i];
			break;
		}
	}

	if (!opt_list) {
		syslog(LOG_ERR, "%s (%d) Skip unknown option %s", __FILE__, __LINE__, option);
		return 0;
	}

	switch (opt_list->opt_type) {
	case OPT_TYPE_OCTAL:
		*((int *)(opt_list->smbftpd_conf_member)) = (int)strtol(opt_arg, (char **)NULL, 8);
		if (*((int *)(opt_list->smbftpd_conf_member)) <= 0) {
			syslog(LOG_ERR, "%s (%d) bad number of config option %s",
				   __FILE__, __LINE__, opt_list->opt_str);
			goto Error;
		}
		break;
	case OPT_TYPE_INT:
		*((int *)(opt_list->smbftpd_conf_member)) = (int)strtol(opt_arg, (char **)NULL, 10);
		if (*((int *)(opt_list->smbftpd_conf_member)) <= 0) {
			syslog(LOG_ERR, "%s (%d) bad number of config option %s",
				   __FILE__, __LINE__, opt_list->opt_str);
			goto Error;
		}
		break;
	case OPT_TYPE_SPECIAL:
		if (strcasecmp(option, "PassiveModePortRange") == 0) {
			int c;
			unsigned int lowport, highport;

			c = sscanf(opt_arg, "%u-%u", &lowport, &highport);
			if (c != 2 || lowport < 1024U || highport > 65535U || highport < lowport) {
				syslog(LOG_ERR, "%s (%d) Bad port range %s", __FILE__, __LINE__, opt_arg);
				goto Error;
			}
			smbftpd_conf.passive_port_low = lowport;
			smbftpd_conf.passive_port_high = highport;
		}
		break;
	case OPT_TYPE_PATH:
		if (0 != stat(opt_arg, &statBuf) || !S_ISREG(statBuf.st_mode)) {
			syslog(LOG_ERR, "%s (%d) The option %s (%s) does not exist",
				   __FILE__, __LINE__, opt_list->opt_str, opt_arg);
			goto Error;
		}
		/* Fall down */
	case OPT_TYPE_STR:
		if (*((char **)opt_list->smbftpd_conf_member)) {
			free(*((char **)opt_list->smbftpd_conf_member));
		}
		*((char **)opt_list->smbftpd_conf_member) = strdup(opt_arg);
		if (*((char **)opt_list->smbftpd_conf_member) == NULL) {
			syslog(LOG_ERR, "%s (%d) Ran out of memory.", __FILE__, __LINE__);
			goto Error;
		}
		break;
	case OPT_TYPE_YES_NO:
		if (strcasecmp(opt_arg, "yes") == 0) {
			*((int *)opt_list->smbftpd_conf_member) = 1;
		} else {
			*((int *)opt_list->smbftpd_conf_member) = 0;
		}
		break;
	case OPT_TYPE_MODE:
		if (strcasecmp(opt_arg, "SMB") == 0) {
			*((int *)opt_list->smbftpd_conf_member) = 1;
		} else {
			*((int *)opt_list->smbftpd_conf_member) = 0;
		}
		break;
	case OPT_TYPE_SET:
		szArg1 = strtok(opt_arg, " \t");
		szArg2 = strtok(NULL, " \t");
		if (szArg1 && szArg2) {
			struct opt_set *p;
			p = calloc(sizeof(struct opt_set), 1);
			p->key = strdup(szArg1);
			p->value = strdup(szArg2);
			if (p->key == NULL || p->value == NULL) {
				syslog(LOG_ERR, "%s (%d) Ran out of memory.", __FILE__, __LINE__);
				goto Error;
			}
			p->next = *((struct opt_set **)opt_list->smbftpd_conf_member);
			*((struct opt_set **)opt_list->smbftpd_conf_member) = p;
		} else {
			syslog(LOG_ERR, "%s (%d) bad syntax of config option %s",
				   __FILE__, __LINE__, opt_list->opt_str);
			goto Error;
		}
		break;
	case OPT_TYPE_SSL:
		if (strcasecmp(opt_list->opt_str, "SecurityPolicy") == 0) {
			if (strcasecmp(opt_arg, "secure") == 0) {
				*((int *)opt_list->smbftpd_conf_member) = SECURITY_POLICY_SECURE;
			} else if (strcasecmp(opt_arg, "nosecure") == 0) {
				*((int *)opt_list->smbftpd_conf_member) = SECURITY_POLICY_NOSECURE;
			} else {
				*((int *)opt_list->smbftpd_conf_member) = SECURITY_POLICY_SECURE | SECURITY_POLICY_NOSECURE;
			}
		} else if (strcasecmp(opt_list->opt_str, "EncryptionType") == 0) {
			if (strcasecmp(opt_arg, "tls") == 0) {
				*((int *)opt_list->smbftpd_conf_member) = ENCRYPTION_TYPE_TLS;
			} else if (strcasecmp(opt_arg, "ssl") == 0) {
				*((int *)opt_list->smbftpd_conf_member) = ENCRYPTION_TYPE_SSL;
			} else {
				*((int *)opt_list->smbftpd_conf_member) = ENCRYPTION_TYPE_TLS | ENCRYPTION_TYPE_SSL;
			}
		} else {
			syslog(LOG_ERR, "%s (%d) bad syntax of config option %s",
				   __FILE__, __LINE__, opt_list->opt_str);
			goto Error;
		}

		break;
	case OPT_TYPE_UNKNOWN:
		break;
	}

	error = 0;
Error:
	return error;
}

/**
 * Read smbftpd.conf, smbftpd_share.conf, smbftpd_(auth mothod).conf.
 * When failed, we will release the config that is read into memory.
 * 
 * @param conf_path The path to smbftpd.conf
 * 
 * @return 0: Success
 *         -1: Failed
 */
int config_read(char *conf_path)
{
	int error = -1;

	if (NULL == conf_path) {
		syslog(LOG_ERR, "%s (%d) Please specify the config file", __FILE__, __LINE__);
		goto Error;
	}

	if (0 != smbftpd_config_parser(conf_path, smbftpd_config_handler)) {
		syslog(LOG_ERR, "%s (%d) Failed to parse %s", __FILE__, __LINE__, conf_path);
		goto Error;
	}

	// Check and enum shares for SMB mode
	if (smbftpd_conf.default_mode == MODE_SMB || 
		(smbftpd_conf.default_mode == MODE_NORMAL && smbftpd_conf.exception_list)) {
		if (smbftpd_conf.share_conf_path == NULL) {
			syslog(LOG_ERR, "%s (%d) Enable SMB mode but failed to find samba config file.",
				   __FILE__, __LINE__);
			goto Error;
		} else if (0 != smbftpd_share_enum(smbftpd_conf.share_conf_path, &smbftpd_shares)) {
			syslog(LOG_ERR, "%s (%d) Failed to enumerate shares", __FILE__, __LINE__);
			goto Error;
		}
	}

	// Check timeout and max timeout.
	if (smbftpd_conf.timeout > smbftpd_conf.max_timeout) {
		syslog(LOG_ERR, "%s (%d) The MaxTimeOut should be bigger than TimeOut.",
			   __FILE__, __LINE__);
		goto Error;
	}

	// Check virtual user mapping config
	if (smbftpd_conf.virtual_user_mapping && (!smbftpd_conf.virtual_user_auth_method ||
											  !smbftpd_conf.virtual_user_auth_config)) {
		syslog(LOG_ERR, "%s (%d) VirtualUserMapping is set. But There is "
			   "no VirtualUserAuthMethod or VirtualUserAuthConfig", __FILE__, __LINE__);
		goto Error;
	}

	// Parse authentication config file
	if (smbftpd_conf.virtual_user_mapping) {
		if (0 != smbftpd_auth_config_parse(smbftpd_conf.virtual_user_auth_method,
										    smbftpd_conf.virtual_user_auth_config)) {
			goto Error;
		}
	} else {
#ifdef	USE_PAM
		if (0 != smbftpd_auth_config_parse("pam", NULL)) {
			goto Error;
		}
#else
		if (0 != smbftpd_auth_config_parse("unix", NULL)) {
			goto Error;
		}
#endif
	}

#ifdef	WITH_ICONV
	if (smbftpd_conf.support_utf8_client || smbftpd_conf.using_utf8_filesystem) {
		if (!smbftpd_conf.charset_encoding) {
			syslog(LOG_ERR, "%s (%d) In order to support UTF8 client/filesystem, you must set the CharsetEncoding.",
				   __FILE__, __LINE__);
			goto Error;
		}
	}
#endif
	// Open Unicode convert
	if (smbftpd_conf.charset_encoding) {
#ifdef	WITH_ICONV
		if (0 != smbftpd_unicode_open(smbftpd_conf.charset_encoding)) {
			goto Error;
		}
#else
		syslog(LOG_ERR, "%s (%d) iconv is not supported. Disable CharsetEncoding.", __FILE__, __LINE__);
#endif
	}

	if (smbftpd_conf.max_connection && smbftpd_conf.max_connection_per_ip) {
		if (0 != smbftpd_iptrack_alloc(smbftpd_conf.max_connection)) {
			syslog(LOG_ERR, "%s (%d) Failed to alloc space for max connection per ip table.", __FILE__, __LINE__);
			goto Error;
		}
	}

	error = 0;
Error:
	if (error != 0) {
		config_release();
	}
	return error;
}


/**
 * Free the struct opt_set
 * 
 * @param pSet
 */
static void opt_set_free(struct opt_set *pSet)
{
	while (pSet) {
		struct opt_set *p = pSet;
		pSet = p->next;
		if (p->key) {
			free(p->key);
		}
		if (p->value) {
			free(p->value);
		}
		free(p);
	}
}

/**
 * Free the smbftpd_conf. We will call smbftpd_auth_config_free() and
 * smbftpd_share_free() to free authenticaion method and smbftpd_shares;
 */
void config_release()
{
	conf_opt_list_t *conf = all_conf_list;

	while (conf->opt_str) {
		switch (conf->opt_type) {
		case OPT_TYPE_SET:
			opt_set_free(*((struct opt_set **)conf->smbftpd_conf_member));
			*(char **)conf->smbftpd_conf_member = NULL;
			break;
		case OPT_TYPE_PATH:
		case OPT_TYPE_STR:
			if (*(char **)conf->smbftpd_conf_member != NULL) {
				free(*((char **)conf->smbftpd_conf_member));
				*(char **)conf->smbftpd_conf_member = NULL;
			}
			break;
		default:
			if (conf->smbftpd_conf_member) {
				*(int **)conf->smbftpd_conf_member = 0;
			}
			break;
		}
		conf++;
	}

	smbftpd_share_free(&smbftpd_shares);

	bzero(&smbftpd_conf, sizeof(smbftpd_conf));

	smbftpd_auth_config_free();
	smbftpd_share_free(&smbftpd_shares);
#ifdef	WITH_ICONV
	smbftpd_unicode_close();
#endif
	smbftpd_iptrack_free();
}

