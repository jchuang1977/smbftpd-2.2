/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_AUTH_INT_H_
#define _SMBFTPD_AUTH_INT_H_

#include "auth.h"

/* unix.c */
int auth_unix_config_parse(const char *path);
int auth_unix_check(const char *user, const char *password);
void auth_unix_config_free(void);
int auth_unix_is_user_in_group(const char *user, const char *group);
char *auth_unix_get_home(const char *user);

/* pam.c */
int auth_pam_config_parse(const char *path);
int auth_pam_check(const char *user, const char *password);
void auth_pam_config_free(void);
int auth_pam_is_user_in_group(const char *user, const char *group);
char *auth_pam_get_home(const char *user);

/* mysql.c */
int auth_mysql_config_parse(const char *path);
int auth_mysql_check(const char *user, const char *password);
void auth_mysql_config_free(void);
int auth_mysql_is_user_in_group(const char *user, const char *group);
char *auth_mysql_get_home(const char *user);

/* pgsql.c */
int auth_pgsql_config_parse(const char *path);
int auth_pgsql_check(const char *user, const char *password);
void auth_pgsql_config_free(void);
int auth_pgsql_is_user_in_group(const char *user, const char *group);
char *auth_pgsql_get_home(const char *user);

/* text.c */
int auth_text_config_parse(const char *path);
int auth_text_check(const char *user, const char *password);
void auth_text_config_free(void);
int auth_text_is_user_in_group(const char *user, const char *group);
char *auth_text_get_home(const char *user);

#endif /* _SMBFTPD_AUTH_INT_H_ */
