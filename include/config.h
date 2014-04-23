/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_CONFIG_H_
#define	_SMBFTPD_CONFIG_H_

#define	SMBFTPD_VERSION "SmbFTPD Ver 2.2"
#define	PATH_CONFIG     "/home/andy/wnc/fakeroot/etc/smbftpd"
#define	NET_BUF_SIZE    65536

#undef HAVE_EXLOCK
#undef HAVE_FDCOPY
#undef HAVE_TCPWRAPPER
#undef HAVE_PRINTFLIKE
#undef HAVE_PWEXPIRE
#undef HAVE_BSDGLOB
#undef HAVE_MD5FILE
#undef HAVE_PWCACHE
#define HAVE_SHADOW_H
#define HAVE_SENDFILE
#define HAVE_LINUX_SENDFILE
#undef USE_PAM
#undef HAVR_SETPROCTITLE
#undef HAVE_SI_LEN
#undef WITH_MYSQL
#undef WITH_PGSQL
#undef WITH_SSL
#undef WITH_ICONV
#define INET6

#endif /* _SMBFTPD_CONFIG_H_ */
