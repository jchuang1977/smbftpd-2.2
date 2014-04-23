/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_PATHNAMES_H_
#define	_SMBFTPD_PATHNAMES_H_

#include <paths.h>
#include "config.h"

#define PATH_FTPWELCOME	    "/etc/ftpwelcome"
#define PATH_FTPLOGINMESG   "/etc/ftpmotd"
#define PATH_SMB_FTPD_ROOT  "/tmp"
#define PATH_SMBFTPD_CONF   PATH_CONFIG"/smbftpd.conf"
#define PATH_SSL_CERT_FILE  PATH_CONFIG"/ssl.crt/server.crt"
#define PATH_SSL_KEY_FILE   PATH_CONFIG"/ssl.key/server.key"

#endif
