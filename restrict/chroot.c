/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <string.h>

#include "smbftpd.h" 

const char *smbftpd_chroot_path_get(struct opt_set *set, const char *user)
{
	return set_get_value(set, user);
} 
