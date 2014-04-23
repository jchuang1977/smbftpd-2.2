/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_AUTH_H_
#define	_SMBFTPD_AUTH_H_

typedef	struct auth_result {
	int auth_ok;
	char *group;
	char *home;
} auth_result_t;

int smbftpd_auth_config_parse(const char *method, const char *path);
int smbftpd_auth_check(const char *user, const char *password);
void smbftpd_auth_config_free(void);
int smbftpd_auth_is_user_in_group(const char *user, const char *group);
char *smbftpd_auth_get_home(const char *user);

#endif /* _SMBFTPD_AUTH_H_ */
