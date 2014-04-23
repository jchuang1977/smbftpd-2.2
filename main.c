/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <string.h>
#include <arpa/ftp.h>
#include <sys/select.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef	HAVE_FDCOPY
	#define	FD_COPY(f, t)	(void)(*(t) = *(f))
#endif

#include "smbftpd.h"
#include "pathnames.h"
#include "restrict.h"
#include "ssl.h"

#ifndef LINE_MAX
	#define LINE_MAX 2048
#endif

smbftpd_conf_t smbftpd_conf;
smbftpd_session_t smbftpd_session;
smbftpd_share_t *smbftpd_shares = NULL;
static int child_count = 0;
static char *conf_path;

union sockunion ctrl_addr;
union sockunion his_addr;

/*
 * Record logout in wtmp file
 * and exit with supplied status.
 */
void dologout(int status)
{
	end_login();

	config_release();

	if (conf_path) {
		free(conf_path);
	}

	/* beware of flushing buffers after a SIGPIPE */
	_exit(status);
}

static void lostconn(int signo)
{
	if (smbftpd_conf.debug_mode)
		syslog(LOG_DEBUG, "lost connection");
	dologout(1);
}

static void sigquit(int signo)
{
	syslog(LOG_ERR, "got signal %d", signo);
	dologout(1);
}

static void sigurg(int signo)
{
	set_receive_sigurg();
}
/**
 * setup control channel socket for specified address family.
 * 
 * If af is PF_UNSPEC more than one socket may be returned. The
 * returned list is dynamically allocated, so caller needs to
 * free it.
 * 
 * @param af       Address family
 * @param bindname Bind on which IP
 * @param bindport The port number to bind
 * 
 * @return Failed: NULL
 *         Success: Array of socket fd
 */
static int *socksetup(int af, char *bindname, const char *bindport)
{
	struct addrinfo hints, *res, *r;
	int error, maxs, *s, *socks;
	const int on = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(bindname, bindport, &hints, &res);
	if (error) {
		syslog(LOG_ERR, "%s", gai_strerror(error));
		if (error == EAI_SYSTEM)
			syslog(LOG_ERR, "%s", strerror(errno));
		return NULL;
	}

	/* Count max number of sockets we may open */
	for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
		;
	socks = malloc((maxs + 1) * sizeof(int));
	if (!socks) {
		freeaddrinfo(res);
		syslog(LOG_ERR, "couldn't allocate memory for sockets");
		return NULL;
	}

	*socks = 0;	  /* num of sockets counter at start of array */
	s = socks + 1;
	for (r = res; r; r = r->ai_next) {
		*s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (*s < 0) {
			syslog(LOG_DEBUG, "control socket: %m");
			continue;
		}
		if (setsockopt(*s, SOL_SOCKET, SO_REUSEADDR,
					   &on, sizeof(on)) < 0)
			syslog(LOG_WARNING,
				   "control setsockopt (SO_REUSEADDR): %m");
#if defined(INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (r->ai_family == AF_INET6) {
			if (setsockopt(*s, IPPROTO_IPV6, IPV6_V6ONLY,
						   &on, sizeof(on)) < 0)
				syslog(LOG_WARNING,
					   "control setsockopt (IPV6_V6ONLY): %m");
		}
#endif
		if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
			syslog(LOG_DEBUG, "control bind: %m");
			close(*s);
			continue;
		}
		(*socks)++;
		s++;
	}

	if (res)
		freeaddrinfo(res);

	if (*socks == 0) {
		syslog(LOG_ERR, "control socket: Couldn't bind to any socket");
		free(socks);
		return NULL;
	}
	return(socks);
}

static int writepid(char *file)
{
	int fd;
	char buf[20];

#ifdef	HAVE_EXLOCK
	fd = open(file, O_CREAT | O_WRONLY | O_TRUNC
			  | O_NONBLOCK | O_EXLOCK, 0644);
#else
	fd = open(file, O_CREAT | O_WRONLY | O_TRUNC
			  | O_NONBLOCK, 0644);
#endif
	if (fd < 0) {
		if (errno == EAGAIN)
			syslog(LOG_ERR,
				   "%s: already locked", file);
		else
			syslog(LOG_ERR, "%s: %m", file);

		return -1;
	}
	snprintf(buf, sizeof(buf), "%lu\n", (unsigned long) getpid());

	if (write(fd, buf, strlen(buf)) < 0) {
		syslog(LOG_ERR, "%s: write: %m", file);
		return -1;
	}
	/* Leave the pid file open and locked */

	return 0;
}

static void reapchild(int signo)
{
	pid_t pid;
	while ((pid = waitpid((pid_t) -1, NULL, WNOHANG)) > 0) {
		if (child_count > 0) {
			child_count--;
		}

		smbftpd_iptrack_delete(pid);
	}
}

static void config_reload(int signo)
{
	config_release();
	config_init();
	if (0 != config_read(conf_path)) {
		syslog(LOG_ERR, "%s (%d) Failed to parse config file %s",
			   __FILE__, __LINE__, conf_path);
		exit(1);
	}

	ssl_init_library();
}

static void smbftpd_help_print()
{
	printf("\nsmbftpd (http://www.twbsd.org)\n\n"
		   "options:\n"
		   "     -D          Running smbftpd as a daemon\n"
		   "     -s file     Set the path of smbftpd.conf\n"
		   "     -v          Print the version of smbftpd\n"
		   "     -h          Print this help message\n\n");
}

static void smbftpd_parse_args(int argc, char *argv[], char **conf, int *daemon_mode)
{
	int ch;

	while ((ch = getopt(argc, argv, "Ds:vh")) != -1) {
		switch (ch) {
		case 'D':
			*daemon_mode = 1;
			break;
		case 's':
			*conf = strdup(optarg);
			break;
		case 'v':
			printf("%s\n", SMBFTPD_VERSION);
			exit(0);
			break;
		case 'h':
			smbftpd_help_print();
			exit(0);
		default:
			syslog(LOG_WARNING, "unknown flag -%c ignored", optopt);
			break;
		}
	}
}

int main(int argc, char **argv)
{
	FILE *pf = NULL;
	socklen_t addrlen;
	int on = 1;
	int daemon_mode = 0;
	int error;
#ifdef	INET6
	int family = AF_UNSPEC;
#else
	int family = AF_INET;
#endif
	struct sigaction sa;

	tzset();		/* in case no timezone database in ~ftp */

	/*
	 * Prevent diagnostic messages from appearing on stderr.
	 * We run as a daemon or from inetd; in both cases, there's
	 * more reason in logging to syslog.
	 */
	(void) freopen(_PATH_DEVNULL, "w", stderr);

	/*
	 * LOG_NDELAY sets up the logging connection immediately,
	 * necessary for anonymous ftp's that chroot and can't do it later.
	 */
	openlog("ftpd", LOG_PID | LOG_NDELAY, LOG_FTP);

	smbftpd_parse_args(argc, argv, &conf_path, &daemon_mode);
	if (!conf_path) {
		 conf_path = strdup(PATH_SMBFTPD_CONF);
	}

	config_init();
	error = config_read(conf_path);
	if (error != 0) {
		if (daemon_mode) {
			printf("Failed to parse config file, please see system log from detail\n");
		}
		syslog(LOG_ERR, "%s (%d) Failed to parse config file %s",
			   __FILE__, __LINE__, conf_path);
		exit(1);
	}

	if (0 != ssl_init_library()) {
		if (daemon_mode) {
			printf("Failed to initial SSL configs. Please see syslog for more information.\n");
		}
		syslog(LOG_ERR, "%s (%d) Failed to initial SSL configs.", __FILE__, __LINE__);
		exit(1);
	}

	if (daemon_mode) {
		int *ctl_sock, fd, maxfd = -1, nfds, i;
		fd_set defreadfds, readfds;
		pid_t pid;

		/*
		 * Detach from parent.
		 */
		if (daemon(1, 1) < 0) {
			syslog(LOG_ERR, "failed to become a daemon");
			exit(1);
		}

		/*
		 * Atomically write process ID
		 */
		if (smbftpd_conf.pid_file) {
			if (0!= writepid(smbftpd_conf.pid_file)) {
				exit(1);
			}
		}

		signal(SIGCHLD, reapchild);
		signal(SIGHUP, config_reload);

		/*
		 * Open a socket, bind it to the FTP port, and start
		 * listening.
		 */
		ctl_sock = socksetup(family, smbftpd_conf.listen_on_address, smbftpd_conf.port);
		if (ctl_sock == NULL)
			exit(1);

		FD_ZERO(&defreadfds);
		for (i = 1; i <= *ctl_sock; i++) {
			FD_SET(ctl_sock[i], &defreadfds);
			if (listen(ctl_sock[i], 32) < 0) {
				syslog(LOG_ERR, "control listen: %m");
				exit(1);
			}
			if (maxfd < ctl_sock[i])
				maxfd = ctl_sock[i];
		}

		/*
		 * Loop forever accepting connection requests and forking off
		 * children to handle them.
		 */
		while (1) {
			FD_COPY(&defreadfds, &readfds);
			nfds = select(maxfd + 1, &readfds, NULL, NULL, 0);
			if (nfds <= 0) {
				if (nfds < 0 && errno != EINTR)
					syslog(LOG_WARNING, "select: %m");
				continue;
			}

			pid = -1;
			for (i = 1; i <= *ctl_sock; i++) {
				if (!FD_ISSET(ctl_sock[i], &readfds)) {
					continue;
				}
				addrlen = sizeof(his_addr);
				fd = accept(ctl_sock[i], (struct sockaddr *)&his_addr, &addrlen);
				if (fd < 0) {
					continue;
				}

				if ((smbftpd_conf.max_connection > 0) && (child_count >= smbftpd_conf.max_connection) ) {
					char line[1024];
					syslog(LOG_WARNING, "Too many current connections: %d", child_count);
					snprintf(line, sizeof(line), "421 Too many connections (%d/%d). Please try later...\r\n",
							 child_count, smbftpd_conf.max_connection);
					(void) write(fd, line, strlen(line));
					close(fd);
					continue;
				}

				if (0 != smbftpd_iptrack_check(smbftpd_conf.max_connection_per_ip, &his_addr)) {
					char line[1024];
					snprintf(line, sizeof(line), "421 Too many connections (%d) from this IP.\r\n", smbftpd_conf.max_connection_per_ip);
					(void) write(fd, line, strlen(line));
					close(fd);
					continue;
				}

				pid = fork();
				switch (pid) {
				case 0:
					/* child */
					if (0 != tcp_wrapping_check(fd)) {
						exit(0);
					}
					(void) dup2(fd, 0);
					(void) dup2(fd, 1);
					(void) close(fd);
					for (i = 1; i <= *ctl_sock; i++)
						close(ctl_sock[i]);
					goto gotchild;
				case -1:
					syslog(LOG_WARNING, "fork: %m");
					/* FALLTHROUGH */
				default:
					if (pid > 0) {
						child_count++;
						smbftpd_iptrack_add(&his_addr, pid);
					}
					close(fd);
				}
			}
		}
	} else {
		addrlen = sizeof(his_addr);
		if (getpeername(0, (struct sockaddr *)&his_addr, &addrlen) < 0) {
			syslog(LOG_ERR, "getpeername (%s): %m",argv[0]);
			exit(1);
		}
	}
gotchild:
	/*
	 * Set up default state
	 */
	bzero(&smbftpd_session, sizeof(smbftpd_session));
	smbftpd_session.transfer_type = TYPE_A;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	sa.sa_handler = SIG_DFL;
	(void)sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = sigurg;
	sa.sa_flags = 0;		/* don't restart syscalls for SIGURG */
	(void)sigaction(SIGURG, &sa, NULL);

#ifdef WITH_SSL /* "pseudo-OOB" with SSL */
	sa.sa_flags = SA_RESTART;	/* default BSD style */
	(void)sigaction(SIGIO, &sa, NULL);
#endif /*WITH_SSL*/

	sigfillset(&sa.sa_mask);	/* block all signals in handler */
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigquit;
	(void)sigaction(SIGHUP, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGQUIT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = lostconn;
	(void)sigaction(SIGPIPE, &sa, NULL);

	addrlen = sizeof(ctrl_addr);
	if (getsockname(0, (struct sockaddr *)&ctrl_addr, &addrlen) < 0) {
		syslog(LOG_ERR, "getsockname (%s): %m",argv[0]);
		exit(1);
	}

#ifdef IP_TOS
	if (ctrl_addr.su_family == AF_INET)
	{
		int tos = IPTOS_LOWDELAY;
		if (setsockopt(0, IPPROTO_IP, IP_TOS, &tos, sizeof(int)) < 0)
			syslog(LOG_WARNING, "control setsockopt (IP_TOS): %m");
	}
#endif
	/*
	 * Disable Nagle on the control channel so that we don't have to wait
	 * for peer's ACK before issuing our next reply.
	 */
	if (setsockopt(0, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "control setsockopt (TCP_NODELAY): %m");

	/* Try to handle urgent data inline */
#ifdef SO_OOBINLINE
	if (setsockopt(0, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "control setsockopt (SO_OOBINLINE): %m");
#endif

#ifdef	F_SETOWN
	if (fcntl(fileno(stdin), F_SETOWN, getpid()) == -1)
		syslog(LOG_ERR, "fcntl F_SETOWN: %m");
#endif
#ifdef	WITH_SSL /* "pseudo-OOB" with SSL */
	if (fcntl(fileno(stdin), F_SETFL, O_ASYNC) == -1)
		syslog(LOG_ERR, "fcntl F_SETFL: %m");
#endif /*WITH_SSL*/


	snprintf(smbftpd_session.remotehost, sizeof(smbftpd_session.remotehost), inet_ntoa(his_addr.su_sin.sin_addr));

	compat_setproctitle_init(argc, argv);
	proc_title_init("%s: connected", smbftpd_session.remotehost);

	if (smbftpd_conf.log_command) {
		syslog(LOG_INFO, "connection from %s", smbftpd_session.remotehost);
	}

	/* If logins are disabled, print out the message. */
	if ((pf = fopen(_PATH_NOLOGIN,"r")) != NULL) {
		char *cp, line[LINE_MAX];
		while (fgets(line, sizeof(line), pf) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			reply_noformat(LONG_REPLY(530), line);
		}
		(void) smbftpd_socket_fflush(stdout, 0);
		(void) fclose(pf);
		reply_noformat(530, "System not available.");
		exit(0);
	}
	pf = fopen(PATH_FTPWELCOME, "r");
	if (pf != NULL) {
		char *cp, line[LINE_MAX];
		while (fgets(line, sizeof(line), pf) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			reply_noformat(LONG_REPLY(220), line);
		}
		(void) smbftpd_socket_fflush(stdout, 0);
		(void) fclose(pf);
		/* reply(220,) must follow */
	}

#ifdef	WITH_SSL
	reply(220, "%s FTP server%s ready.", smbftpd_conf.server_name, 
		  smbftpd_conf.show_program_version? " ("SMBFTPD_VERSION" TLS)" : "");
#else
	reply(220, "%s FTP server%s ready.", smbftpd_conf.server_name, 
		  smbftpd_conf.show_program_version? " ("SMBFTPD_VERSION")" : "");
#endif
	for (;;)
		(void) yyparse();
	/* NOTREACHED */
}
