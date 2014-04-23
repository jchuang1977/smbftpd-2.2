/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include <config.h>

#ifndef LINE_MAX
	#define LINE_MAX 2048
#endif

static char proc_title[LINE_MAX]; /* initial part of title */

#ifndef	HAVR_SETPROCTITLE
static char *argv_start = NULL;
static size_t argv_env_len = 0;
#endif

/**
 * Initial proctitle. Try to calculate the available memory size we
 * can steal from argv[] and env[].
 * 
 * @param argc
 * @param argv
 */
void compat_setproctitle_init(int argc, char *argv[])
{
#ifndef	HAVR_SETPROCTITLE
	//extern char **environ;
	char *lastargv = NULL;
	char **envp = environ;
	char *ptr;
	int i;

	/* Fail if we can't allocate room for the new environment */
	for (i = 0; envp[i] != NULL; i++)     
		;
	if ((environ = malloc(sizeof(*environ) * (i + 1))) == NULL) {
		environ = envp; /* put it back */
		return;
	}

	/*
	 * Find the last argv string or environment variable within
	 * our process memory area.
	 */
	for (i = 0; i < argc; i++) {
		if (lastargv == NULL || lastargv + 1 == argv[i])
			lastargv = argv[i] + strlen(argv[i]);
	}
	for (i = 0; envp[i] != NULL; i++) {
		if (lastargv + 1 == envp[i])
			lastargv = envp[i] + strlen(envp[i]);
	}

	argv[1] = NULL;
	argv_start = argv[0];
	argv_env_len = lastargv - argv[0] - 1;

	ptr = strrchr(argv[0], '/');
	if (ptr) {
		ptr++;
	} else {
		ptr = argv[0];
	}

	if (argv_env_len > (strlen(ptr)+2)) { // +2 = ': '
		while (*ptr) {
			*argv_start++ = *ptr++;
			argv_env_len--;
		}
		*argv_start++ = ':';argv_env_len--;
		*argv_start++ = ' ';argv_env_len--;
		*(argv_start+1) = 0;
	}

	/*
	 * Copy environment
	 * XXX - will truncate env on strdup fail
	 */
	for (i = 0; envp[i] != NULL; i++)
		environ[i] = strdup(envp[i]);
	environ[i] = NULL;
#endif
}

#ifndef	HAVR_SETPROCTITLE
/*
 * Clobber argv so ps will show what we're doing.  (Stolen from sendmail.)
 * Warning, since this is usually started from inetd.conf, it often doesn't
 * have much of an environment or arglist to overwrite.
 */
static void setproctitle(const char *fmt, ...)
{
	int i;
	va_list ap;
	char *p, *bp;
	char buf[LINE_MAX];

	if (argv_env_len <= 0)
		return;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);

	/* make ps print our process name */
	p = argv_start;

	i = strlen(buf);
	if (i > argv_env_len - 1) {
		i = argv_env_len - 1;
		buf[i] = '\0';
	}
	bp = buf;
	while (*bp) {
		if (*bp != '\n' && *bp != '\r') {
			*p++ = *bp;
		}
		bp++;
	}
	while (p < (argv_start + argv_env_len)) {
		*p++ = '\0';
	}
}
#endif /* HAVR_SETPROCTITLE */

/**
 * Initial proctile. This proctitle will be the proc prefix every time
 * you call proc_title_set()
 * 
 * @param fmt
 */
void proc_title_init(const char *fmt, ...)
{
	va_list ap;

	va_start(ap,fmt);
	(void)vsnprintf(proc_title, sizeof(proc_title), fmt, ap);
	va_end(ap);

	setproctitle("%s", proc_title);
}

/**
 * Set proctitle. Append cmd in the protitle.
 * 
 * You should call proc_title_init() to init the proc_title before call
 * proc_title_set() to append cmd.
 * 
 * @param cmd
 */
void proc_title_set(const char *cmd)
{
	setproctitle("%s: %s", proc_title, cmd);
}
