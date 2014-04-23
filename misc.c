/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>

#include "smbftpd.h"
#include "auth.h"

#ifndef LINE_MAX
	#define LINE_MAX 2048               
#endif

const char *set_get_value(struct opt_set *set, const char *user)
{
	struct opt_set *p = set;
	char *key;
	int match = 0;

	if (!user || !set) {
		return NULL;
	}

	while (p) {
		key = p->key;
		if (*key != '@') {       //user
			if (0 == strcmp(key, user)) {
				match = 1;
			}
		} else if (*(key+1) == '\0') { /* "@" match all */
			match = 1;
		} else {        /* Group */
			if (is_user_in_group(user, key + 1)) {
				match = 1;
			}
		}     
		if (match) {
			return p->value;
		}  
		p = p->next;
	}
	return NULL;
}
/**
 * Allocate another string and copy string "s" into new buffer.
 * When there is double quote in s, put add another double.
 * 
 * For example,
 *     This is "s"
 * will become
 *     This is ""s""
 * 
 * @param s
 * 
 * @return Success: Returen a new string, call should free the string
 *         Malloc failed: Return NULL
 */
char *doublequote(const char *s)
{
	int n;
	const char *p1;
	char *p, *s2;

	for (p1 = s, n = 0; *p1; p1++)
		if (*p1 == '"')
			n++;

	if ((s2 = malloc(p1 - s + n + 1)) == NULL)
		return(NULL);

	for (p = s2; *s; s++, p++) {
		if ((*p = *s) == '"')
			*(++p) = '"';
	}
	*p = '\0';

	return(s2);
}

/**
 * This function will remove the spaces ' ' and tab '\t' and 
 * newline characters '\r', '\n' in the front and tail of the
 * given "str". So the "str" buffer will be modified.
 * 
 * if remove_quote is 1, we will also remove the in pairs double
 * quote '"' or single quote '\''.
 * 
 * For example, if the string is "   this is a string  ", it 
 * will become "this is a string".
 * 
 * If the string is " \"this is a string\" ", when remove_quote
 * is 1, it will become "this is a string".
 * 
 * @param str
 * @param remove_quote
 * 
 * @return The pointer of str
 */
static char *str_trim(char *str, int remove_quote)
{
	char *head, *tail;

	if (!str) {
		return NULL;
	}

	for (head = str; isspace(*head) && *head != 0; head++);
	for (tail = head + strlen(head) - 1; tail>head && isspace(*tail); tail--);

	*(tail+1) = 0;

	if (remove_quote) {
		if ((tail > head) && ((*head == '"' && *tail == '"') ||
							  (*head == '\'' && *tail == '\''))) {
			head++;
			*tail = 0;
			tail--;
		}
	}

	if (str != head) {
		memmove(str, head, (tail - head + 2));
	}
	
	return str;
}

char *str_trim_space(char *str)
{
	return str_trim(str, 0);
}

char *str_trim_space_quote(char *str)
{
	return str_trim(str, 1);
}


/**
 * Check whether user is in list. The list is a string of
 * users/groups that separate by ','. The group name has
 * prefix @.
 * 
 * For example szList = "user1, user2, user3, @group1, @group2..."
 * 
 * We will get each user in the list and check when the user name
 * is the same. When we get group, we will check whether user
 * belongs to the group.
 * 
 * @param user   User name to check
 * @param list   The string that contains users and groups separated by ",".
 * 
 * @return 1: Yes, the user is in the list
 *         0: No, the user is not in the list
 */
int is_user_in_list(const char *user, const char *list)
{
	char *tmplist = NULL, *token;
	int err = 0;

	if (!user || !list) {
		return err;
	}

	tmplist = (char *)malloc(strlen(list) + 1);
	if (tmplist == NULL) {
		syslog(LOG_ERR, "%s (%d) failed to allocate memory, errno:%d(%s)",
			   __FILE__, __LINE__, errno, strerror(errno));
		return err;
	}
	strcpy(tmplist, list);

	for (token = strtok(tmplist, ","); token; token = strtok(NULL, ",")) {
		str_trim_space(token);
		if (*token != '@') {	   //user
			if (0 == strcmp(user, token)) {
				err = 1;
				break;
			}
		} else {
			if (1 == smbftpd_auth_is_user_in_group(user, token+1)) {
				err = 1;
				goto Error;
			}
		}
	}

Error:
	if (tmplist != NULL) {
		free(tmplist);
	}
	return err;
}

/**
 * Check whether user belongs to group. We will check group id and
 * its members.
 * 
 * @param user   The user name to check
 * @param group  The group name to search
 * 
 * @return 1: Yes, the user belongs to the group.
 *         0: No, not belongs to the group.
 */
int is_user_in_group(const char *user, const char *group)
{
	return smbftpd_auth_is_user_in_group(user, group);
}

/**
 * Config file parser function. This function is used to parse config
 * file that is the following format:
 * 
 *    Option1   Value
 *    Option2   Value
 * 
 * We will read each line of config file and pass the option/value to
 * the opt_handler function.
 * 
 * The opt_handler function will then assign/convert the value to
 * proper format.
 * 
 * @param file   The path of the config file.
 * @param opt_handler
 *               The option/value handler function.
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_config_parser(const char *file, int (*opt_handler)(char *option, char *opt_arg))
{
	FILE *pf = NULL;
	char line[LINE_MAX];
	char *option, *opt_arg;
	int error = -1, len = 0;

	if (NULL == file || !opt_handler) {
		return -1;
	}

	pf = fopen(file, "r");
	if (!pf) {
		syslog(LOG_ERR, "%s (%d) Failed to open [%s] (%s)", __FILE__, __LINE__,
			   file, strerror(errno));
		return -1;
	}

	while (NULL != (fgets(line, sizeof(line), pf))) {
		len = strlen(line);
		
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}
		option = line;
		// Trim space
		while ((*option == ' ') || (*option == '\t')) {
			option++;
		}
		if (*option == '\0' || *option == '#') {
			continue;
		}

		opt_arg = option;
		while ((*opt_arg != ' ') && (*opt_arg != '\t') && (*opt_arg != '\0')) {
			opt_arg++;
		}
		if (opt_arg == option) {
			// Empty line
			continue;
		}

		*opt_arg = '\0';
		opt_arg++;
		str_trim_space_quote(opt_arg);
		if (*opt_arg == '\0') {
			syslog(LOG_ERR, "%s (%d) bad syntax of config option %s",
				   __FILE__, __LINE__, option);
			goto Error;
		}

		if (0 != opt_handler(option, opt_arg)) {
			goto Error;
		}
	}

	error = 0;
Error:
	if (pf) {
		fclose(pf);
	}

	return error;
}
