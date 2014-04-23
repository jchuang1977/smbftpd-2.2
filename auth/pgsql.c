/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include "config.h"

#ifdef WITH_PGSQL

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <libpq-fe.h>

#include "smbftpd.h"

#ifdef   HAVE_MD5FILE
	#include <sys/types.h>
	#include <md5.h>
#endif

struct smbftpd_db_info {
	char *host;
	char *port;
	char *user;
	char *pass;
	char *db;
	char *crypt;
	char *sql_get_password;
	char *sql_get_home;
	char *sql_get_group;
};
static struct smbftpd_db_info pgsql_db_info;

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
 * Connect to PostgreSQL database.
 * 
 * You should call smbftpd_pgsql_close() to close the connection.
 * 
 * @return Success: Return pointer of (PGconn *) connection
 *         Failed: Return NULL
 */
static PGconn *smbftpd_pgsql_connect()
{
	PGconn *connection = NULL;

	connection = PQsetdbLogin(pgsql_db_info.host, pgsql_db_info.port, NULL, NULL, 
							  pgsql_db_info.db, pgsql_db_info.user, pgsql_db_info.pass);

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(connection) != CONNECTION_OK) {
		syslog(LOG_ERR, "%s (%d) Failed to connect to PostgreSQL. (%s)",
			   __FILE__, __LINE__, PQerrorMessage(connection));
		if (connection) {
			PQfinish(connection);
		}
		return NULL;
	}

	return connection;
}

/**
 * Close and free PostgreSQL connection
 * 
 * @param connection
 */
static void smbftpd_pgsql_close(PGconn *connection)
{
	if (!connection) {
		return;
	}
	PQfinish(connection);
	connection = NULL;
	return;
}

/**
 * Perform PostgreSQL query by given sql statement.
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
 * @param connection PostgreSQL connection
 * @param sql        The SQL statement
 * 
 * @return Success: The first row[0], caller should free() it.
 *         Failed: NULL
 */
static char *smbftpd_pgsql_get_query(PGconn *connection, char *sql)
{
	PGresult *result = NULL;
	char *answer = NULL;
	int num_of_row = 0;

	if (!connection || !sql) {
		return NULL;
	}

	result = PQexec(connection, sql);
	if (!result) {
		syslog(LOG_ERR, "%s (%d) Failed to query PostgreSQL database. (%s)",
			   __FILE__, __LINE__, sql);
		return NULL;
	}

	if (PGRES_TUPLES_OK != PQresultStatus(result)) {
		goto Error;
	}

    num_of_row = PQntuples(result);
	if (1 != num_of_row) {
		if (num_of_row > 1) {
			syslog(LOG_ERR, "%s (%d) Rejected result of sql (%s) because there are more the one row in result.",
				   __FILE__, __LINE__, sql);
		}
		goto Error;
	}

	answer = PQgetvalue(result, 0, 0);
	if (!answer) {
		syslog(LOG_ERR, "%s (%d) Failed to get PostgreSQL value.", __FILE__, __LINE__);
		goto Error;
	}
	answer = strdup(answer);

Error:
	if (result) {
		PQclear(result);
	}
	return answer;
}

/**
 * Allocate a new buffer, escape string by PQescapeStringConn(),
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
static char *smbftpd_pgsql_escape_string(PGconn *connection, const char *from)
{
	int from_len;
	int error = -1;
    char *to;
            
    if (from == NULL) {
        return NULL;
    }
    from_len = strlen(from);

	to = malloc(from_len * 2 + 1);
	if (!to) {
		return NULL;
	}

    PQescapeStringConn(connection, to, from, from_len, &error);
	if (error != 0) {
		syslog(LOG_ERR, "%s (%d) Failed to escape query string.", __FILE__, __LINE__);
		free(to);
		return NULL;
	}
                
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
static char *smbftpd_pgsql_get_sql(char *sql_pattern, const char *user, char *buf, int buflen)
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
static int pgsql_config_handler(char *option, char *opt_arg)
{
	if (strcasecmp(option, "Server") == 0) {
		pgsql_db_info.host = strdup(opt_arg);
	} else if (strcasecmp(option, "Port") == 0) {
		pgsql_db_info.port = strdup(opt_arg);
	} else if (strcasecmp(option, "User") == 0) {
		pgsql_db_info.user = strdup(opt_arg);
	} else if (strcasecmp(option, "Password") == 0) {
		pgsql_db_info.pass = strdup(opt_arg);
	} else if (strcasecmp(option, "Database") == 0) {
		pgsql_db_info.db = strdup(opt_arg);
	} else if (strcasecmp(option, "Crypt") == 0) {
		pgsql_db_info.crypt = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetPassword") == 0) {
		pgsql_db_info.sql_get_password = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetHome") == 0) {
		pgsql_db_info.sql_get_home = strdup(opt_arg);
	} else if (strcasecmp(option, "SQLGetGroup") == 0) {
		pgsql_db_info.sql_get_group = strdup(opt_arg);
	} else {
		syslog(LOG_ERR, "%s (%d) Unknown option %s", __FILE__, __LINE__, option);
		return -1;
	}

	return 0;
}

/**
 * Parse PostgreSQL config file.
 * 
 * @param path   The path of config file (smbftpd_pgsql.conf)
 * 
 * @return 0: Success
 *         -1: Failed
 */
int auth_pgsql_config_parse(const char *path)
{
	if (!path) {
		syslog(LOG_ERR, "%s (%d) Bad parameter.", __FILE__, __LINE__);
		return -1;
	}
	user_cache_free(&pwcache);

	if (0 != smbftpd_config_parser(path, pgsql_config_handler)) {
		syslog(LOG_ERR, "%s (%d) Failed to parse PostgreSQL config file.", __FILE__, __LINE__);
		return -1;
	}

	if (!pgsql_db_info.user) {
		syslog(LOG_ERR, "%s (%d) PostgreSQL User is not specified.", __FILE__, __LINE__);
		return -1;
	}
	if (!pgsql_db_info.pass) {
		syslog(LOG_ERR, "%s (%d) PostgreSQL Pass is not specified.", __FILE__, __LINE__);
		return -1;
	}
	if (!pgsql_db_info.db) {
		syslog(LOG_ERR, "%s (%d) PostgreSQL Database is not specified.", __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

/**
 * Perform authentication by getting user and password from the PostgreSQL
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
int auth_pgsql_check(const char *user, const char *password)
{
	PGconn *connection = NULL;
	char *spwd = NULL, *crypted = NULL, *escaped_user = NULL;
	char sql[1024];
	int error = -1;

	user_cache_free(&pwcache);

	connection = smbftpd_pgsql_connect();
	if (!connection) {
		return -1;
	}

	escaped_user = smbftpd_pgsql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_pgsql_get_sql(pgsql_db_info.sql_get_password, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	spwd = smbftpd_pgsql_get_query(connection, sql);
	if (!spwd) {
		goto Error;
	}

	if (strcasecmp(pgsql_db_info.crypt, "crypt") == 0) {
		crypted = crypt(password, spwd);
		if (!crypted) {
			goto Error;
		}
		if (strcmp(crypted, spwd) != 0) {
			goto Error;
		}
	} else if (strcasecmp(pgsql_db_info.crypt, "md5") == 0) {
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
	} else if (strcasecmp(pgsql_db_info.crypt, "plaintext") == 0) {
		if (strcmp(password, spwd) != 0) {
			goto Error;
		}
	}

	// Get group
	if (NULL == smbftpd_pgsql_get_sql(pgsql_db_info.sql_get_group, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}
	pwcache.group = smbftpd_pgsql_get_query(connection, sql);
	if (NULL == pwcache.group) {
		goto Error;
	}

	// Get home
	if (NULL == smbftpd_pgsql_get_sql(pgsql_db_info.sql_get_home, escaped_user, sql, sizeof(sql))) {
		goto Error;
	}
	pwcache.home = smbftpd_pgsql_get_query(connection, sql);
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
		smbftpd_pgsql_close(connection);
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
 * Free PostgreSQL config and user cache
 */
void auth_pgsql_config_free()
{
	if (pgsql_db_info.host) free(pgsql_db_info.host);
	if (pgsql_db_info.port) free(pgsql_db_info.port);
	if (pgsql_db_info.user) free(pgsql_db_info.user);
	if (pgsql_db_info.pass) free(pgsql_db_info.pass);
	if (pgsql_db_info.db) free(pgsql_db_info.db);
	if (pgsql_db_info.crypt) free(pgsql_db_info.crypt);
	if (pgsql_db_info.sql_get_password) free(pgsql_db_info.sql_get_password);
	if (pgsql_db_info.sql_get_home) free(pgsql_db_info.sql_get_home);
	if (pgsql_db_info.sql_get_group) free(pgsql_db_info.sql_get_group);

	bzero(&pgsql_db_info, sizeof(pgsql_db_info));
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
int auth_pgsql_is_user_in_group(const char *user, const char *group)
{
	PGconn *connection = NULL;
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

	connection = smbftpd_pgsql_connect();
	if (!connection) {
		return 0;
	}

	escaped_user = smbftpd_pgsql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_pgsql_get_sql(pgsql_db_info.sql_get_group, 
									  escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	result = smbftpd_pgsql_get_query(connection, sql);
	if (!result || *result == '0') {
		goto Error;
	}
	if (strcmp(result, group) == 0) {
		error = 1;
	}

Error:
	if (connection) {
		smbftpd_pgsql_close(connection);
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
char *auth_pgsql_get_home(const char *user)
{
	PGconn *connection = NULL;
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

	connection = smbftpd_pgsql_connect();
	if (!connection) {
		return NULL;
	}

	escaped_user = smbftpd_pgsql_escape_string(connection, user);
	if (!escaped_user) {
		goto Error;
	}

	if (NULL == smbftpd_pgsql_get_sql(pgsql_db_info.sql_get_home, 
									  escaped_user, sql, sizeof(sql))) {
		goto Error;
	}

	result = smbftpd_pgsql_get_query(connection, sql);

Error:
	if (connection) {
		smbftpd_pgsql_close(connection);
	}
	if (escaped_user) {
		free(escaped_user);
	}
	return result;
}

#endif /* WITH_PGSQL */

