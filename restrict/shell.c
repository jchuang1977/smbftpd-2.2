/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <unistd.h>
#include <paths.h>
#include <string.h>

/**
 * Check whether the shell is in system's valid shell list.
 * 
 * @param shell  The shell name to check. If shell is empty, use default /bin/sh
 * 
 * @return 0: Yes, it is valid
 *         -1: No, it is invalid
 */
int smbftpd_valid_shell(const char *shell)
{
	char *ptr;

	if (shell == NULL || *shell == 0) {
		shell = _PATH_BSHELL;
	}

	setusershell();
	while ((ptr = getusershell()) != NULL) {
		if (strcmp(ptr, shell) == 0) {
			break;
		}
	}
	endusershell();

	if (ptr == NULL) {
		return -1;
	} else {
		return 0;
	}
}

