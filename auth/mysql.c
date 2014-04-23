/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include "config.h"

#ifdef WITH_MYSQL

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <mysql.h>

#include "smbftpd.h"

#ifdef   HAVE_MD5FILE
	#include <sys/types.h>
	#include <md5.h>
#endif

struct smbftpd_db_info {
	char *host;
	int port;
	char *socket;
	char *user;
	char *pass;
	char *db;
	char *crypt;
	char *sql_get_password;
	char *sql_get_home;
	char *sql_get_group;
};
static struct smbftpd_db_info mysql_db_info;

struct usercache {
	char *user;
	char *home;
	char *group;
};
static struct usercache pwcache;

static void user_cache_free(struct usercache *p)
{
	if (p->user) free(p->user);
	if (p->home) free(p->home);
	if (p->group) free(p->group);
	p->user = NULL;
	p->home = NULL;
	p->group = NULL;
}

/**
 * Connect to MySQL database.
 * 
 * You should call smbftpd_mysql_close() to close the connection.
 * 
 * @return Success: Return pointer of (MYSQL *) connection
 *         Failed: Return NULL
 */
static MYSQL *smbftpd_mysql_connect()
{
	MYSQL *connection = NULL;

	connection = mysql_init(NULL);
	if (NULL == connection) {
		syslog(LOG_ERR, "%s (%d) Failed to malloc MYSQL connection.", __FILE__, __LINE__);
		return NULL;
	}

	if (NULL == mysql_real_connect(connection, mysql_db_info.host,
								   mysql_db_info.user, mysql_db_info.pass,
								   mysql_db_info.db, mysql_db_info.port,
								   mysql_db_info.socket, 0)) {
		syslog(LOG_ERR, "%s (%d) Failed to connect to MySQL.", __FILE__, __LINE__);
		if (mysql_errno(connection)) { 
			syslog(LOG_ERR, "%s (%d) Connection error %d: %s\n", __FILE__, __LINE__,
				   mysql_errno(connection), mysql_error(connection)); 
		}
		free(connection);
		return NULL;
	}
	return connection;
}

/**
 * Close and free MySQL connection
 * 
 * @param connection
 */
static void smbftpd_mysql_close(MYSQL *connection)
{
	if (!connection) {
		return;
	}
	mysql_close(connection);
	return;
}

/**
 * Perform MySQL query by given sql statement.
 * 
 * It would failed in the following case:
 * 1. The result is empty (connection fail or sql fail)
 * 2. The result has more then 1 field or empty.
 * 3. The number of row is not 1
 * 4. Malloc failed
 * 
 * If success, we will allocate a new buffer to put row[0] in it.
 * Caller should free() the returned string.
 * 
 * @param connection MySQL connection
 * @param sql        The SQL statement
 * 
 * @return Success: The first row[0], caller should free() it.
 *         Failed: NULL
 */
static char *smbftpd_mysql_get_query(MYSQL *connection, char *sql)
{
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	char *answer = NULL;
	int error, num_of_row = 0;

	if (!connection || !sql) {
		return NULL;
	}
	error = mysql_query(connection, sql);  
	if (error) {  
		syslog(LOG_ERR, "%s (%d) Failed to run mysql_query: %s", 
			   __FILE__, __LINE__, mysql_error(connection));
		return NULL;
	}

	if (1 != mysql_field_count(connection)) {
		syslog(LOG_ERR, "%s (%d) Bad result. We except only one field in MySQL result.",
			   __FILE__, __LINE__);
		return NULL;
    }

	result = mysql_store_result(connection);
	if (!result) {
		return NULL;
	}

	num_of_row = mysql_num_rows(result);
	if (1 != num_of_row) {
		if (num_of_row > 1) {
			syslog(LOG_ERR, "%s (%d) Rejected result of sql (%s) because there are more then one row in the result.",
			   __FILE__, __LINE__, sql);
		}
		goto Error;
	}

	row = mysql_fetch_row(result);
	if (!row || !row[0]) {
		syslog(LOG_ERR, "%s (%d) Failed to mysql_fetch_row()", __FILE__, __LINE__);
		goto Error;
	}
	answer = strdup(row[0]);

Error:
	if (result) {
		mysql_free_result(result);
	}
	return answer;
}

/**
 * Allocate a new buffer, escape string by mysql_real_escape_string(),
 * and put into new buffer.
 * 
 * Caller should free the returned buffer. 
 * 
 * @param connection Database connection
 * @param from       The string to escape.
 * 
 * @return Success: a new buffer
 *         Fail: NULL
 */
static char *smbftpd_mysql_escape_string(MYSQL *connection, const char *from)
{
	int from_len;
    char *to;
            
    if (from == NULL) {
        return NULL;
    }
    from_len = strlen(from);

	to = malloc(from_len * 2 + 1);
	if (!to) {
		return NULL;
	}

    mysql_real_escape_string(connection, to, from, from_len);
                
    return to;
}

/**
 * Replace the keyword in sql_pattern with "user" and put it into "buf"
 * 
 * @param sql_pattern
 *               The sql pattern
 * @param user   Escaped username
 * @param buf    The buffer to put sql statement.
 * @param buflen The length of buf
 * 
 * @return If buflen is too small, return NULL. Otherwise, return the pointer of buf.
 */
static char *smbftpd_mysql_get_sql(char *sql_pattern, const char *user, char *buf, int buflen)
{
	char *p;
	int user_len = user?strlen(user):0;

	bzero(buf, buflen);
	p = buf;
	while (*sql_pattern) {
		if (*sql_pattern != '%') {
			*p++ = *sql_pattern++;
			buflen--;
			if (buflen <= 1) return NULL;
		} else {
			sql_pattern++;
			switch (toupper(*sql_pattern)) {
			case 'U':
				if (user_len >= buflen) {
                    return NULL;
                }
                memcpy(p, user, user_len);
                p += user_len;
                buflen -= user_len;
				if (buflen <= 1) return NULL;
				break;
			default:
				*p++ = '%';
				buflen--;
				if (buflen <= 1) return NULL;

				*p++ = *sql_pattern;
				buflen--;
				if (buflen <= 1) return NULL;
				break;
			}
			sql_pattern++;
		}
	}
	return buf;
}

/**
 * Call back function for smbftpd_config_parser(). The
 * smbftpd_config_parser() will read config file and pass the option
 * and opt_arg to me.
 * 
 * @param option  Option name in the config file
 * @param opt_arg Option argument in the config file.
 * 
 * @return 0: Success handled
 *         -1: Option not found
 */
static int mysql_config_handler(char *option, char *opt_arg)
{
	if (strcasecmp(option, "Server") == 0) {
		mysql_db_info.host = strdup(opt_arg);
	} else if (strcasecmp(option, "Socket") == 0) {
		mysql_db_info.socket = strdup(opt_arg);
	} else if (strcasecmp(option, "Port") == 0) {
		mysql_db_info.port = atoi(opt_arg);
	} else if (strcasecmp(option, "User") == 0) {
		mysql_db_info.user = strdup(opt_arg);
	} else if (strcasecmp(option, "Password") == 0) {
		mysql_db_info.pass = strdup(opt_arg);
	} else if (strcasecmp(option, "Database") == 0) {
		mysql_db_info.db = strdup(opt_arg);
	} else if (strcasecmp(option, "Crypt") == 0) {
		mysql_db_info.crypt = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetPassword") == 0) {
		mysql_db_info.sql_get_password = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetHome") == 0) {
		mysql_db_info.sql_get_home = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetGroup") == 0) {
		mysql_db_info.sql_get_group = strdup(opt_arg);
	} else {
		syslog(LOG_ERR, "%s (%d) Unknown option %s", __FILE__, __LINE__, option);
		return -1;
	}

	return 0;
}

/**
 * Parse MySQL config file.
 * 
 * @param path   The path of config file (smbftpd_mysql.conf)
 * 
 * @return 0: Success
 *         -1: Failed
 */
int auth_mysql_config_parse(const char *path)
{
	if (!path) {
		syslog(LOG_ERR, "%s (%d) Bad parameter.", __FILE__, __LINE__);
		return -1;
	}
	user_cache_free(&pwcache);

	if (0 != smbftpd_config_parser(path, mysql_config_handler)) {
		syslog(LOG_ERR, "%s (%d) Failed to parse MySQL config file.", __FILE__, __LINE__);
		return -1;
	}

	if (!mysql_db_info.host && !mysql_db_info.socket) {
		syslog(LOG_ERR, "%s (%d) MySQL Server/Socket is not specified.", __FILE__, __LINE__);
		return -1;
	}
	if (mysql_db_info.host && mysql_db_info.socket) {
		free(mysql_db_info.socket);
		mysql_db_info.socket = NULL;
	}
	if (!mysql_db_info.port) {
		mysql_db_info.port = 3306;
	}
	if (!mysql_db_info.user) {
		syslog(LOG_ERR, "%s (%d) MySQL User is not specified.", __FILE__, __LINE__);
		return -1;
	}
	if (!mysql_db_info.pass) {
		syslog(LOG_ERR, "%s (%d) MySQL Pass is not specified.", __FILE__, __LINE__);
		return -1;
	}
	if (!mysql_db_info.db) {
		syslog(LOG_ERR, "%s (%d) MySQL Database is not specified.", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

/**
 * Perform authentication by getting user and password from the MySQL
 * database.
 * 
 * It will:
 * 1. Escape the user string
 * 2. Get password from database according to given username.
 * 3. Encrypt the password and compare with password in database.
 * 4. Cache the user's group and home directory
 * 
 * @param user     The login user
 * @param password The login password
 * 
 * @return 0: Authentication success.
 *         -1: Failed to auth
 */
int auth_mysql_check(const char *user, const char *password)
{
	MYSQL *connection = NULL;
	char *spwd = NULL, *crypted = NULL, *escaped_user = NULL;
	char sql[1024];
	int error = -1;

	user_cache_free(&pwcache);

	connection = smbftpd_mysql_connect();
	if (!connection) {
		return -1;
	}

	escaped_user = smbftpd_mysql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_mysql_get_sql(mysql_db_info.sql_get_password, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	spwd = smbftpd_mysql_get_query(connection, sql);
	if (!spwd) {
		goto Error;
	}

	if (strcasecmp(mysql_db_info.crypt, "crypt") == 0) {
		crypted = crypt(password, spwd);
		if (!crypted) {
			goto Error;
		}
		if (strcmp(crypted, spwd) != 0) {
			goto Error;
		}
	} else if (strcasecmp(mysql_db_info.crypt, "md5") == 0) {
#ifdef   HAVE_MD5FILE
		crypted = MD5Data(password, strlen(password), NULL);
		if (!crypted) {
			goto Error;
		}
		if (strcmp(spwd, crypted) != 0) {
			free(crypted);
			goto Error;
		}
		free(crypted);
#else
		syslog(LOG_ERR, "%s (%d) md5 password encrypt is not supported.", __FILE__, __LINE__);
		goto Error;
#endif
	} else if (strcasecmp(mysql_db_info.crypt, "password") == 0) {
		unsigned long hash_res[2];
		char scrambled_password[24];

#if MYSQL_VERSION_ID < 40100
		hash_password(hash_res, password);
#else
		hash_password(hash_res, password, strlen(password));
#endif
		snprintf(scrambled_password, sizeof(scrambled_password), "%08lx%08lx", 
				 hash_res[0], hash_res[1]);
		if (strcmp(scrambled_password, spwd) != 0) {
			goto Error;
		}
	} else if (strcasecmp(mysql_db_info.crypt, "plaintext") == 0) {
		if (strcmp(password, spwd) != 0) {
			goto Error;
		}
	} else {
		syslog(LOG_ERR, "%s (%d) Unknown MySQL password crypt [%s]", __FILE__, __LINE__, mysql_db_info.crypt);
		goto Error;
	}

	// Get group
	if (NULL == smbftpd_mysql_get_sql(mysql_db_info.sql_get_group, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}
	pwcache.group = smbftpd_mysql_get_query(connection, sql);
	if (NULL == pwcache.group) {
		goto Error;
	}

	// Get home
	if (NULL == smbftpd_mysql_get_sql(mysql_db_info.sql_get_home, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}
	pwcache.home = smbftpd_mysql_get_query(connection, sql);
	if (NULL == pwcache.home) {
		goto Error;
	}

	pwcache.user = strdup(user);
	if (NULL == pwcache.user) {
		syslog(LOG_ERR, "%s (%d) Out of memory.", __FILE__, __LINE__);
		goto Error;
	}

	error = 0;
Error:
	if (connection) {
		smbftpd_mysql_close(connection);
	}
	if (escaped_user) {
		free(escaped_user);
	}
	if (spwd) {
		free(spwd);
	}
	return error;
}

/**
 * Free MySQL config and user cache
 */
void auth_mysql_config_free()
{
	if (mysql_db_info.host) free(mysql_db_info.host);
	if (mysql_db_info.socket) free(mysql_db_info.socket);
	if (mysql_db_info.user) free(mysql_db_info.user);
	if (mysql_db_info.pass) free(mysql_db_info.pass);
	if (mysql_db_info.db) free(mysql_db_info.db);
	if (mysql_db_info.crypt) free(mysql_db_info.crypt);
	if (mysql_db_info.sql_get_password) free(mysql_db_info.sql_get_password);
	if (mysql_db_info.sql_get_home) free(mysql_db_info.sql_get_home);
	if (mysql_db_info.sql_get_group) free(mysql_db_info.sql_get_group);

	bzero(&mysql_db_info, sizeof(mysql_db_info));
	user_cache_free(&pwcache);
}

/**
 * Check whether user belongs to given group. 
 * 
 * We support only 1 group per user.
 * 
 * We will check the user in cache, if given user is the same with
 * the user in cache, we will compare the group with cached group.
 * 
 * If user is not in cache, we will query database to get the group.
 * 
 * @param user   User to check
 * @param group  Group name to check
 * 
 * @return 1: Yes, user belongs to the group
 *         0: No, user does not belongs to the group or failed to query database
 */
int auth_mysql_is_user_in_group(const char *user, const char *group)
{
	MYSQL *connection = NULL;
	char *escaped_user = NULL, *result = NULL;
	char sql[1024];
	int error = 0;

	if (!group || !user) {
		return 0;
	}

	if (pwcache.user && pwcache.group) {
		if (strcmp(user, pwcache.user) == 0) {
			if (strcmp(group, pwcache.group) == 0) {
				return 1;
			} else {
				return 0;
			}
		}
	}

	connection = smbftpd_mysql_connect();
	if (!connection) {
		return 0;
	}

	escaped_user = smbftpd_mysql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_mysql_get_sql(mysql_db_info.sql_get_group, 
									  escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	result = smbftpd_mysql_get_query(connection, sql);
	if (!result || *result == '0') {
		goto Error;
	}
	if (strcmp(result, group) == 0) {
		error = 1;
	}

Error:
	if (connection) {
		smbftpd_mysql_close(connection);
	}
	if (escaped_user) {
		free(escaped_user);
	}
	if (result) {
		free(result);
	}
	return error;
}

/**
 * Get user's home directory. If user is current logged in user, we will
 * return the home directory in cache. If user is not current logged in
 * user, we will select database for the user's home.
 * 
 * Caller should call free() to free the point.
 * 
 * @param user   User name
 * 
 * @return A pointer to the string if user found. If not found, return NULL.
 *         Caller should call free() to free the point.
 */
char *auth_mysql_get_home(const char *user)
{
	MYSQL *connection = NULL;
	char *escaped_user, *result = NULL;
	char sql[1024];

	if (!user) {
		return NULL;
	}

	if (pwcache.user && pwcache.home) {
		if (strcmp(user, pwcache.user) == 0) {
			return strdup(pwcache.home);
		}
	}

	connection = smbftpd_mysql_connect();
	if (!connection) {
		return NULL;
	}

	escaped_user = smbftpd_mysql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_mysql_get_sql(mysql_db_info.sql_get_home, 
									  escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	result = smbftpd_mysql_get_query(connection, sql);

Error:
	if (connection) {
		smbftpd_mysql_close(connection);
	}
	if (escaped_user) {
		free(escaped_user);
	}
	return result;
}

#endif /* WITH_MYSQL */

