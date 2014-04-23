/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/ftp.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "smbftpd.h"
#include "ssl.h"
/*
 * Timeout intervals for retrying connections
 * to hosts that don't accept PORT cmds.  This
 * is a kludge, but given the problems with TCP...
 */
#define	SWAITMAX	90	/* wait at most 90 seconds */
#define	SWAITINT	5	/* interval between retries */

extern smbftpd_conf_t smbftpd_conf;
extern smbftpd_session_t smbftpd_session;
union sockunion pasv_addr;

extern union sockunion ctrl_addr;
extern union sockunion his_addr;
static union sockunion data_source;
union sockunion data_dest;

int fd_active_data = -1;
int fd_passive_data = -1;
int usedefault = 1;		/* for data transfers */

static in_addr_t g_force_passive_ip; /* Cache of force_passive_ip */

static FILE *getdatasock(const char *mode)
{
	int on = 1, s, t, tries;

	if (fd_active_data >= 0)
		return(fdopen(fd_active_data, mode));

	s = socket(data_dest.su_family, SOCK_STREAM, 0);
	if (s < 0)
		goto bad;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "data setsockopt (SO_REUSEADDR): %m");
	/* anchor socket to avoid multi-homing problems */
	data_source = ctrl_addr;
	data_source.su_port = htons(ntohs(ctrl_addr.su_port) - 1);
	(void) seteuid(0);
	for (tries = 1; ; tries++) {
		/*
		 * We should loop here since it's possible that
		 * another ftpd instance has passed this point and is
		 * trying to open a data connection in active mode now.
		 * Until the other connection is opened, we'll be getting
		 * EADDRINUSE because no SOCK_STREAM sockets in the system
		 * can share both local and remote addresses, localIP:20
		 * and *:* in this case.
		 */

#ifdef	HAVE_SI_LEN
		if (bind(s, (struct sockaddr *)&data_source,
				 data_source.su_len) >= 0)
#else
		if (bind(s, (struct sockaddr *)&data_source,
				 sizeof(data_source)) >= 0)
#endif
			break;
		if (errno != EADDRINUSE || tries > 10)
			goto bad;
		sleep(tries);
	}
	(void) seteuid(smbftpd_session.pw_user->pw_uid);
#ifdef IP_TOS
	if (data_source.su_family == AF_INET)
	{
		on = IPTOS_THROUGHPUT;
		if (setsockopt(s, IPPROTO_IP, IP_TOS, &on, sizeof(int)) < 0)
			syslog(LOG_WARNING, "data setsockopt (IP_TOS): %m");
	}
#endif
#ifdef TCP_NOPUSH
	/*
	 * Turn off push flag to keep sender TCP from sending short packets
	 * at the boundaries of each write().  Should probably do a SO_SNDBUF
	 * to set the send buffer size as well, but that may not be desirable
	 * in heavy-load situations.
	 */
	on = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_NOPUSH, &on, sizeof on) < 0)
		syslog(LOG_WARNING, "data setsockopt (TCP_NOPUSH): %m");
#endif
#ifdef SO_SNDBUF
	on = 65536;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &on, sizeof on) < 0)
		syslog(LOG_WARNING, "data setsockopt (SO_SNDBUF): %m");
#endif

	return(fdopen(s, mode));
	bad:
	/* Return the real value of errno (close may change it) */
	t = errno;
	(void) seteuid(smbftpd_session.pw_user->pw_uid);
	(void) close(s);
	errno = t;
	return(NULL);
}

/**
 * Create data connection
 * 
 * @param name   File name to transfer. We will reply this file name to client
 *               after connection is built. When sending result of LIST command,
 *               the value could be "file list"
 * @param size   Total file size to transfer. When sending result of LIST command,
 *               the value could be -1.
 * @param mode   BINARY mode or ASCII mode
 * 
 * @return 
 */
FILE *dataconn(const char *name, off_t size, const char *mode)
{
	char sizebuf[32];
	FILE *file;
	int retry = 0, tos, conerrno;

	if (size != -1)
		(void) snprintf(sizebuf, sizeof(sizebuf), " (%qd bytes)", size);
	else
		*sizebuf = '\0';
	if (fd_passive_data >= 0) {
		union sockunion from;
		int flags, s;
#ifdef	HAVE_SI_LEN
		socklen_t fromlen = ctrl_addr.su_len;
#else
		socklen_t fromlen = sizeof(from);
#endif
		struct timeval timeout;
		fd_set set;

		FD_ZERO(&set);
		FD_SET(fd_passive_data, &set);

		timeout.tv_usec = 0;
		timeout.tv_sec = 120;

		/*
		 * Granted a socket is in the blocking I/O mode,
		 * accept() will block after a successful select()
		 * if the selected connection dies in between.
		 * Therefore set the non-blocking I/O flag here.
		 */
		if ((flags = fcntl(fd_passive_data, F_GETFL, 0)) == -1 ||
			fcntl(fd_passive_data, F_SETFL, flags | O_NONBLOCK) == -1)
			goto pdata_err;
		if (select(fd_passive_data+1, &set, NULL, NULL, &timeout) <= 0 ||
			(s = accept(fd_passive_data, (struct sockaddr *) &from, &fromlen)) < 0)
			goto pdata_err;
		(void) close(fd_passive_data);
		fd_passive_data = s;
		/*
		 * Unset the inherited non-blocking I/O flag
		 * on the child socket so stdio can work on it.
		 */
		if ((flags = fcntl(fd_passive_data, F_GETFL, 0)) == -1 ||
			fcntl(fd_passive_data, F_SETFL, flags & ~O_NONBLOCK) == -1)
			goto pdata_err;
#ifdef IP_TOS
		if (from.su_family == AF_INET)
		{
			tos = IPTOS_THROUGHPUT;
			if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(int)) < 0)
				syslog(LOG_WARNING, "pdata setsockopt (IP_TOS): %m");
		}
#endif

#ifdef WITH_SSL
		/*
		 * Time to negotiate SSL on the data connection...
		 * Do this via SSL_accept (as we are still the server
		 * even though things are started around the other way).
		 */
		smbftpd_session.ssl_ctrl.ssl_data_active_flag = 0;
		if (smbftpd_session.ssl_ctrl.ssl_active_flag && smbftpd_session.ssl_ctrl.ssl_encrypt_data) {
			/* Do SSL */

			reply_fs2client(150, "Opening %s mode SSL data connection for '%s'%s.",
							smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);

			if (0 != ssl_dataconn_open(fd_passive_data)) {
				/* Drop an established connection. */
				close(fd_passive_data);
				fd_passive_data = -1;

				return NULL;
			}
			
		} else {
			reply_fs2client(150, "Opening %s mode data connection for '%s'%s.",
							smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
		}
#else /* !WITH_SSL */
		reply_fs2client(150, "Opening %s mode data connection for '%s'%s.",
						smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
#endif /* WITH_SSL */
		return(fdopen(fd_passive_data, mode));
		pdata_err:
		reply_noformat(425, "Can't open data connection.");
		(void) close(fd_passive_data);
		fd_passive_data = -1;
		return(NULL);
	}
	if (fd_active_data >= 0) {
		reply_fs2client(125, "Using existing data connection for '%s'%s.",
						name, sizebuf);
		usedefault = 1;
		return(fdopen(fd_active_data, mode));
	}
	if (usedefault)
		data_dest = his_addr;
	usedefault = 1;
	do {
		file = getdatasock(mode);
		if (file == NULL) {
			char hostbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
#ifdef	HAVE_SI_LEN
			if (getnameinfo((struct sockaddr *)&data_source,
						data_source.su_len, hostbuf, sizeof(hostbuf) - 1,
						portbuf, sizeof(portbuf),
						NI_NUMERICHOST|NI_NUMERICSERV)) {
#else
			if (getnameinfo((struct sockaddr *)&data_source,
						sizeof(data_source), hostbuf, sizeof(hostbuf) - 1,
						portbuf, sizeof(portbuf),
						NI_NUMERICHOST|NI_NUMERICSERV)) {
#endif
				*hostbuf = *portbuf = 0;
			}
			hostbuf[sizeof(hostbuf) - 1] = 0;
			portbuf[sizeof(portbuf) - 1] = 0;
			reply(425, "Can't create data socket (%s,%s): %s.",
				  hostbuf, portbuf, strerror(errno));
			return(NULL);
		}
		fd_active_data = fileno(file);
		conerrno = 0;
#ifdef	HAVE_SI_LEN
		if (connect(fd_active_data, (struct sockaddr *)&data_dest,
					data_dest.su_len) == 0)
#else
		if (connect(fd_active_data, (struct sockaddr *)&data_dest,
					sizeof(data_dest)) == 0)
#endif
			break;
		conerrno = errno;
		(void) fclose(file);
		fd_active_data = -1;
		if (conerrno == EADDRINUSE) {
			sleep((unsigned) SWAITINT);
			retry += SWAITINT;
		} else {
			break;
		}
	} while (retry <= SWAITMAX);
	if (conerrno != 0) {
		reply(425, "Can't build data connection: %s.", strerror(conerrno));
		return(NULL);
	}
#ifdef WITH_SSL
	/*
	 * Time to negotiate SSL on the data connection...
	 * Do this via SSL_accept (as we are still the server
	 * even though things are started around the other way).
	 */
	smbftpd_session.ssl_ctrl.ssl_data_active_flag = 0;
	if (smbftpd_session.ssl_ctrl.ssl_active_flag && smbftpd_session.ssl_ctrl.ssl_encrypt_data) {
		/* Do SSL */

		reply_fs2client(150, "Opening %s mode SSL data connection for '%s'%s.",
						smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);

		if (0 != ssl_dataconn_open(fd_active_data)) {
			/* Drop an established connection. */
			fclose(file);
			fd_active_data = -1;

			return NULL;
		}

	} else {
		reply_fs2client(150, "Opening %s mode data connection for '%s'%s.",
						smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	}
#else /* !WITH_SSL */
	reply_fs2client(150, "Opening %s mode data connection for '%s'%s.",
					smbftpd_session.transfer_type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
#endif /* WITH_SSL */
	return(file);
}

void dataconnclose(FILE *datastream)
{
	if (datastream != NULL) {
#ifdef WITH_SSL
		if (smbftpd_session.ssl_ctrl.ssl_data_active_flag && (ssl_data_con != NULL)) {
			if (SSL_shutdown(ssl_data_con) == 0) {
				switch (SSL_get_shutdown(ssl_data_con)) {
				case SSL_SENT_SHUTDOWN:
					SSL_get_shutdown(ssl_data_con);
					break;
				default:
					break;
				}
			}
			SSL_free(ssl_data_con);
			smbftpd_session.ssl_ctrl.ssl_data_active_flag = 0;
			ssl_data_con = NULL;
		}
#endif /* WITH_SSL */
		(void) fclose(datastream);
	}
	fd_active_data = -1;
	fd_passive_data = -1;
}


/**
 * Bind on port range. If port is in use, port-- and bind again until
 * we run out of ports.
 * 
 * @param s        Socket fd
 * @param addr     The passive socket addr
 * @param portlow  The low port of the port range
 * @param porthigh The high port of port range
 * 
 * @return 0: Success
 *         -1: Faild
 */
static int bind_port_range(int s, union sockunion *addr, unsigned int portlow, unsigned int porthigh)
{
	unsigned int first_port_tried;
	unsigned int p;

	first_port_tried = portlow + (random() ^ getpid()) % (porthigh - portlow + 1);

	p = first_port_tried;

	for (;;) {
		addr->su_port = htons(p);

		if (smbftpd_conf.debug_mode) {
			syslog(LOG_ERR, "Try to bind port:%d", p);
		}

	#ifdef	HAVE_SI_LEN
		if (bind(fd_passive_data, (struct sockaddr *)&pasv_addr, pasv_addr.su_len) == 0)
	#else
		if (bind(fd_passive_data, (struct sockaddr *)&pasv_addr, sizeof(pasv_addr)) == 0)
	#endif
			break;

		p--;
		if (p < portlow) {
			p = porthigh;
		}
		if (p == first_port_tried) {
			return -1;
		}
	}
	return 0;
}

static in_addr_t get_ip_addr(const char *ip)
{
	struct addrinfo hints, *res;
	in_addr_t addr;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_addr = NULL;

	if (getaddrinfo(ip, NULL, &hints, &res) != 0 ||
		res->ai_family != AF_INET) {
		freeaddrinfo(res);
		return 0;
	}

	addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;

	freeaddrinfo(res);

	return addr;
}
/*
 * Note: a response of 425 is not mentioned as a possible response to
 *	the PASV command in RFC959. However, it has been blessed as
 *	a legitimate response by Jon Postel in a telephone conversation
 *	with Rick Adams on 25 Jan 89.
 */
void cmd_passive(void)
{
	socklen_t len;
	int on;
	char *p, *a;

	if (fd_passive_data >= 0)		/* close old port if one set */
		close(fd_passive_data);

	fd_passive_data = socket(ctrl_addr.su_family, SOCK_STREAM, 0);
	if (fd_passive_data < 0) {
		reply(425, "Can't open passive connection: %s", strerror(errno));
		return;
	}
	on = 1;
	if (setsockopt(fd_passive_data, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "pdata setsockopt (SO_REUSEADDR): %m");

	(void) seteuid(0);
#if 0
#ifdef IP_PORTRANGE
	if (ctrl_addr.su_family == AF_INET) {
		on = smbftpd_conf.restricted_data_ports ? IP_PORTRANGE_HIGH
			 : IP_PORTRANGE_DEFAULT;

		if (setsockopt(fd_passive_data, IPPROTO_IP, IP_PORTRANGE,
					   &on, sizeof(on)) < 0)
			goto pasv_error;
	}
#endif
#ifdef IPV6_PORTRANGE
	if (ctrl_addr.su_family == AF_INET6) {
		on = smbftpd_conf.restricted_data_ports ? IPV6_PORTRANGE_HIGH
			 : IPV6_PORTRANGE_DEFAULT;

		if (setsockopt(fd_passive_data, IPPROTO_IPV6, IPV6_PORTRANGE,
					   &on, sizeof(on)) < 0)
			goto pasv_error;
	}
#endif
#endif

	pasv_addr = ctrl_addr;

	if (smbftpd_conf.passive_port_low && smbftpd_conf.passive_port_high) {

		if (0 != bind_port_range(fd_passive_data, &pasv_addr,
								 smbftpd_conf.passive_port_low, smbftpd_conf.passive_port_high)) {
			goto pasv_error;
		}

	} else {
		
		pasv_addr.su_port = 0;

	#ifdef	HAVE_SI_LEN
		len = pasv_addr.su_len;
	#else
		len = sizeof(pasv_addr);
	#endif
		
		if (bind(fd_passive_data, (struct sockaddr *)&pasv_addr, len) < 0)
			goto pasv_error;

		if (getsockname(fd_passive_data, (struct sockaddr *) &pasv_addr, &len) < 0)
			goto pasv_error;
	}
	(void) seteuid(smbftpd_session.pw_user->pw_uid);

	if (listen(fd_passive_data, 1) < 0)
		goto pasv_error;


	if (smbftpd_conf.force_passive_ip && !g_force_passive_ip) {
		g_force_passive_ip = get_ip_addr(smbftpd_conf.force_passive_ip);
		if (!g_force_passive_ip) {
			g_force_passive_ip = 0xffffffff; // Fail below and don't try to get_ip_addr() again.
		}
	}
	if (smbftpd_conf.force_passive_ip && g_force_passive_ip && g_force_passive_ip != 0xffffffff) {
		a = (char *) &g_force_passive_ip;
	} else if (pasv_addr.su_family == AF_INET)
		a = (char *) &pasv_addr.su_sin.sin_addr;
#ifdef	INET6
	else if (pasv_addr.su_family == AF_INET6 &&
			 IN6_IS_ADDR_V4MAPPED(&pasv_addr.su_sin6.sin6_addr))
		a = (char *) &pasv_addr.su_sin6.sin6_addr.s6_addr[12];
#endif
	else
		goto pasv_error;

	p = (char *) &pasv_addr.su_port;
#define UC(b) (((int) b) & 0xff)

	reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
		  UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));

	return;

	pasv_error:
	(void) seteuid(smbftpd_session.pw_user->pw_uid);
	(void) close(fd_passive_data);
	fd_passive_data = -1;
	reply(425, "Can't open passive connection: %s.", strerror(errno));
	return;
}

/*
 * Long Passive defined in RFC 1639.
 *     228 Entering Long Passive Mode
 *         (af, hal, h1, h2, h3,..., pal, p1, p2...)
 */

void cmd_long_passive(const char *cmd, int pf)
{
	socklen_t len;
	int on;
	char *p, *a;

	if (fd_passive_data >= 0)		/* close old port if one set */
		close(fd_passive_data);

	if (pf != PF_UNSPEC) {
		if (ctrl_addr.su_family != pf) {
			switch (ctrl_addr.su_family) {
			case AF_INET:
				pf = 1;
				break;
#ifdef	INET6
			case AF_INET6:
				pf = 2;
				break;
#endif
			default:
				pf = 0;
				break;
			}
			/*
			 * XXX
			 * only EPRT/EPSV ready clients will understand this
			 */
			if (strcmp(cmd, "EPSV") == 0 && pf) {
				reply(522, "Network protocol mismatch, use (%d)", pf);
			} else
				reply_noformat(501, "Network protocol mismatch"); /*XXX*/

			return;
		}
	}

	fd_passive_data = socket(ctrl_addr.su_family, SOCK_STREAM, 0);
	if (fd_passive_data < 0) {
		reply(425, "Can't open passive connection: %s.", strerror(errno));
		return;
	}
	on = 1;
	if (setsockopt(fd_passive_data, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "pdata setsockopt (SO_REUSEADDR): %m");

	(void) seteuid(0);

#if 0
#ifdef IP_PORTRANGE
	if (ctrl_addr.su_family == AF_INET) {
		on = smbftpd_conf.restricted_data_ports ? IP_PORTRANGE_HIGH
			 : IP_PORTRANGE_DEFAULT;

		if (setsockopt(fd_passive_data, IPPROTO_IP, IP_PORTRANGE,
					   &on, sizeof(on)) < 0)
			goto pasv_error;
	}
#endif
#ifdef IPV6_PORTRANGE
	if (ctrl_addr.su_family == AF_INET6) {
		on = smbftpd_conf.restricted_data_ports ? IPV6_PORTRANGE_HIGH
			 : IPV6_PORTRANGE_DEFAULT;

		if (setsockopt(fd_passive_data, IPPROTO_IPV6, IPV6_PORTRANGE,
					   &on, sizeof(on)) < 0)
			goto pasv_error;
	}
#endif
#endif

	pasv_addr = ctrl_addr;

	if (smbftpd_conf.passive_port_low && smbftpd_conf.passive_port_high) {

		if (0 != bind_port_range(fd_passive_data, &pasv_addr,
								 smbftpd_conf.passive_port_low, smbftpd_conf.passive_port_high)) {
			goto pasv_error;
		}

	} else {

		pasv_addr.su_port = 0;

	#ifdef	HAVE_SI_LEN
		len = pasv_addr.su_len;
	#else
		len = sizeof(pasv_addr);
	#endif
	
		if (bind(fd_passive_data, (struct sockaddr *)&pasv_addr, len) < 0)
			goto pasv_error;

		if (getsockname(fd_passive_data, (struct sockaddr *) &pasv_addr, &len) < 0)
			goto pasv_error;

	}
	(void) seteuid(smbftpd_session.pw_user->pw_uid);

	if (listen(fd_passive_data, 1) < 0)
		goto pasv_error;

#define UC(b) (((int) b) & 0xff)

	if (strcmp(cmd, "LPSV") == 0) {
		p = (char *)&pasv_addr.su_port;
		switch (pasv_addr.su_family) {
		case AF_INET:
			if (smbftpd_conf.force_passive_ip && !g_force_passive_ip) {
				g_force_passive_ip = get_ip_addr(smbftpd_conf.force_passive_ip);
				if (!g_force_passive_ip) {
					g_force_passive_ip = 0xffffffff; // Fail below and don't try to get_ip_addr() again.
				}
			}
			if (smbftpd_conf.force_passive_ip && g_force_passive_ip && g_force_passive_ip != 0xffffffff) {
				a = (char *) g_force_passive_ip;
			} else {
				a = (char *) &pasv_addr.su_sin.sin_addr;
			}
#ifdef	INET6
			v4_reply:
#endif
			reply(228,
				  "Entering Long Passive Mode (%d,%d,%d,%d,%d,%d,%d,%d,%d)",
				  4, 4, UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
				  2, UC(p[0]), UC(p[1]));
			return;
#ifdef	INET6
		case AF_INET6:
			if (IN6_IS_ADDR_V4MAPPED(&pasv_addr.su_sin6.sin6_addr)) {
				a = (char *) &pasv_addr.su_sin6.sin6_addr.s6_addr[12];
				goto v4_reply;
			}
			a = (char *) &pasv_addr.su_sin6.sin6_addr;
			reply(228,
				  "Entering Long Passive Mode "
				  "(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)",
				  6, 16, UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
				  UC(a[4]), UC(a[5]), UC(a[6]), UC(a[7]),
				  UC(a[8]), UC(a[9]), UC(a[10]), UC(a[11]),
				  UC(a[12]), UC(a[13]), UC(a[14]), UC(a[15]),
				  2, UC(p[0]), UC(p[1]));
			return;
#endif
		}
	} else if (strcmp(cmd, "EPSV") == 0) {

		switch (pasv_addr.su_family) {
		case AF_INET:
#ifdef	INET6
		case AF_INET6:
#endif
			reply(229, "Entering Extended Passive Mode (|||%d|)",
				  ntohs(pasv_addr.su_port));

			return;
		}
	} else {
		/* more proper error code? */
	}

	pasv_error:
	(void) seteuid(smbftpd_session.pw_user->pw_uid);
	(void) close(fd_passive_data);
	fd_passive_data = -1;
	reply(425, "Can't open passive connection: %s.", strerror(errno));
	return;
}


/* Return 1, if port check is done. Return 0, if not yet. */
static int port_check(const char *pcmd)
{
	if (his_addr.su_family != AF_INET) {
		return 0;
	}
	if (data_dest.su_family != AF_INET) {
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return 1;
	}
	if (smbftpd_conf.restricted_ports &&
		((ntohs(data_dest.su_port) < IPPORT_RESERVED) ||
		 memcmp(&data_dest.su_sin.sin_addr,
				&his_addr.su_sin.sin_addr,
				sizeof(data_dest.su_sin.sin_addr)))) {

		usedefault = 1;
		reply_noformat(500, "Illegal PORT range rejected.");
	} else {
		usedefault = 0;
		if (fd_passive_data >= 0) {
			(void) close(fd_passive_data);
			fd_passive_data = -1;
		}
		reply(200, "%s command successful.", pcmd);
	}
	return 1;
}

#ifdef INET6
static void v4map_data_dest(void)
{
	struct in_addr savedaddr;
	int savedport;

	if (data_dest.su_family != AF_INET) {
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return;
	}

	savedaddr = data_dest.su_sin.sin_addr;
	savedport = data_dest.su_port;

	memset(&data_dest, 0, sizeof(data_dest));
#ifdef   HAVE_SI_LEN
	data_dest.su_sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	data_dest.su_sin6.sin6_family = AF_INET6;
	data_dest.su_sin6.sin6_port = savedport;
	memset((caddr_t)&data_dest.su_sin6.sin6_addr.s6_addr[10], 0xff, 2);
	memcpy((caddr_t)&data_dest.su_sin6.sin6_addr.s6_addr[12],
	       (caddr_t)&savedaddr, sizeof(savedaddr));
}

/* Return 1, if port check is done. Return 0, if not yet. */
static int port_check_v6(const char *pcmd)
{
	if (his_addr.su_family != AF_INET6) {
		return 0;
	}
	if (IN6_IS_ADDR_V4MAPPED(&his_addr.su_sin6.sin6_addr))
		/* Convert data_dest into v4 mapped sockaddr.*/
		v4map_data_dest();
	if (data_dest.su_family != AF_INET6) {
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return 1;
	}
	if (smbftpd_conf.restricted_ports &&
		((ntohs(data_dest.su_port) < IPPORT_RESERVED) ||
		 memcmp(&data_dest.su_sin6.sin6_addr,
				&his_addr.su_sin6.sin6_addr,
				sizeof(data_dest.su_sin6.sin6_addr)))) {
		usedefault = 1;
		reply_noformat(500, "Illegal PORT range rejected.");
	} else {
		usedefault = 0;
		if (fd_passive_data >= 0) {
			(void) close(fd_passive_data);
			fd_passive_data = -1;
		}
		reply(200, "%s command successful.", pcmd);
	}
	return 1;
}
#endif

void cmd_port()
{
	if (port_check("PORT") == 1)
		return;
#ifdef INET6
	if ((his_addr.su_family != AF_INET6 ||
		 !IN6_IS_ADDR_V4MAPPED(&his_addr.su_sin6.sin6_addr))) {
		/* shoud never happen */
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return;
	}
	port_check_v6("pcmd");
#endif
}

void cmd_lprt()
{
	if (port_check("LPRT") == 1)
		return;
#ifdef INET6
	if (his_addr.su_family != AF_INET6) {
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return;
	}
	if (port_check_v6("LPRT") == 1)
		return;
#endif
}

void cmd_eprt(const char *str)
{
	char delim;
	char *tmp = NULL;
	char *p, *q;
	char *result[3];
	struct addrinfo hints;
	struct addrinfo *res;
	int i;

	memset(&data_dest, 0, sizeof(data_dest));
	tmp = strdup(str);
	if (smbftpd_conf.debug_mode)
		syslog(LOG_DEBUG, "%s", tmp);
	if (!tmp) {
		fatalerror("not enough core");
		/*NOTREACHED*/
	}
	p = tmp;
	delim = p[0];
	p++;
	memset(result, 0, sizeof(result));
	for (i = 0; i < 3; i++) {
		q = strchr(p, delim);
		if (!q || *q != delim) {
parsefail:
			reply_noformat(500, "Invalid argument, rejected.");
			if (tmp)
				free(tmp);
			usedefault = 1;
			return;
		}
		*q++ = '\0';
		result[i] = p;
		if (smbftpd_conf.debug_mode)
			syslog(LOG_DEBUG, "%d: %s", i, p);
		p = q;
	}

	/* some more sanity check */
	p = result[0];
	while (*p) {
		if (!isdigit(*p))
			goto parsefail;
		p++;
	}
	p = result[2];
	while (*p) {
		if (!isdigit(*p))
			goto parsefail;
		p++;
	}

	/* grab address */
	memset(&hints, 0, sizeof(hints));
	if (atoi(result[0]) == 1)
		hints.ai_family = PF_INET;
#ifdef INET6
	else if (atoi(result[0]) == 2)
		hints.ai_family = PF_INET6;
#endif
	else
		hints.ai_family = PF_UNSPEC;	/*XXX*/
	hints.ai_socktype = SOCK_STREAM;
	i = getaddrinfo(result[1], result[2], &hints, &res);
	if (i)
		goto parsefail;
	memcpy(&data_dest, res->ai_addr, res->ai_addrlen);
#ifdef INET6
	if (his_addr.su_family == AF_INET6
		&& data_dest.su_family == AF_INET6) {
		/* XXX more sanity checks! */
		data_dest.su_sin6.sin6_scope_id =
			his_addr.su_sin6.sin6_scope_id;
	}
#endif
	free(tmp);
	tmp = NULL;

	if (port_check("EPRT") == 1)
		return;
#ifdef INET6
	if (his_addr.su_family != AF_INET6) {
		usedefault = 1;
		reply_noformat(500, "Invalid address rejected.");
		return;
	}
	if (port_check_v6("EPRT") == 1)
		return;
#endif
}
