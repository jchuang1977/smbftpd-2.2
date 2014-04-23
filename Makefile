PROG=	smbftpd

OBJS=	misc.o param.o reply.o log.o proctitle.o share.o \
	ftpcmd.o main.o pwcache.o oob.o unicode.o textuser.o

TOOLS=	smbftpd-user
TOOL_OBJS=	misc.o param.o share.o textuser.o unicode.o
TOOLS_LDFLAGS=	-L./auth -lauth -lcrypt -L./restrict -lrestrict
SUBDIRS = auth restrict cmd ssl

HEADERS = include/restrict.h include/config.h include/cmd.h \
	include/ssl.h include/smbftpd.h include/pathnames.h \
	include/auth.h

PROG_LDFLAGS = -L./cmd -lcmd -L./restrict -lrestrict \
	-L./auth -lauth -L./ssl -lftpssl -lcrypt

include Makefile.inc

CFLAGS += -I./include

CONFIGDIR = $(PREFIX)/etc/smbftpd
CONFIGS = smbftpd.conf smbftpd_share.conf smbftpd_mysql.conf smbftpd_pgsql.conf

YFLAGS =

.PHONY: cert $(SUBDIRS)

all: $(PROG) $(TOOLS)

$(OBJS): $(HEADERS)

$(PROG):$(SUBDIRS) $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(PROG_LDFLAGS) $(LDFLAGS)

$(TOOLS): $(SUBDIRS) $(TOOL_OBJS)
	$(CC) $(CFLAGS) -c $@.c -o $@.o
	$(CC) $(CFLAGS) $@.o -o $@ $(TOOL_OBJS) $(TOOLS_LDFLAGS) $(LDFLAGS)

$(SUBDIRS):
	@echo "===>" $@
	$(MAKE) -C $@
	@echo "<===" $@

cert:
	cd cert; ./mkcert.sh; cd ..

clean:
	@for i in $(SUBDIRS); \
	do\
		echo "===>" $$i ; \
		$(MAKE) -C $$i clean; \
		echo "<===" $$i; \
	done
	rm -rf $(PROG) $(TOOLS) *.o ftpcmd.c *.core

distclean: clean
	rm -rf include/config.h Makefile.inc os/FreeBSD/smbftpd.sh
	rm -rf cert/conf cert/.mkcert.cfg cert/.mkcert.serial

ftpcmd.c: ftpcmd.y
	@if [ -f /usr/bin/byacc ]; then \
		echo "/usr/bin/byacc ftpcmd.y"; \
		/usr/bin/byacc -o $@ $?; \
	else \
		if [ -f /usr/local/bin/byacc ]; then \
			echo "/usr/local/bin/byacc ftpcmd.y"; \
			/usr/local/bin/byacc -o $@ $?; \
		else \
			echo "WARNING: Can not find byacc, trying to use yacc."; \
			echo "WARNING: Please note that Berkeley Yacc is required."; \
			if [ -f /usr/bin/yacc ]; then \
				echo "/usr/bin/yacc ftpcmd.y"; \
				/usr/bin/yacc -o $@ $?; \
			else \
				if [ -f /usr/local/bin/yacc ]; then \
					echo "/usr/local/bin/yacc ftpcmd.y"; \
					/usr/local/bin/yacc -o $@ $?; \
				else \
					echo "ERROR: Can not find Berkeley Yacc."; \
				fi; \
			fi; \
		fi; \
	fi;

ftpcmd.o: ftpcmd.c
	$(CC) -c $(CFLAGS) ftpcmd.c

install: $(PROG)
	[ -d $(PREFIX)/bin ] || install -d $(PREFIX)/bin
	[ -d $(PREFIX)/sbin ] || install -d $(PREFIX)/sbin
	[ -d $(CONFIGDIR) ] || install -d $(CONFIGDIR)
	install -c -m 755 -s $(PROG) $(PREFIX)/sbin/

	@for i in $(TOOLS); do \
		echo "install -c -m 755 -s $$i $(PREFIX)/bin/"; \
		install -c -m 755 -s $$i $(PREFIX)/bin/; \
	done

	@for i in $(CONFIGS); do \
		if [ ! -f $(CONFIGDIR)/$$i ]; then \
			echo "install -c -m 644 conf/$$i $(CONFIGDIR)/"; \
			install -c -m 644 conf/$$i $(CONFIGDIR)/; \
		fi; \
	done

	@if [ -d cert/conf ]; then \
		echo "install -d -m 755 $(CONFIGDIR)/ssl.crt";\
		install -d -m755 $(CONFIGDIR)/ssl.crt;\
		echo "install -d -m 755 $(CONFIGDIR)/ssl.csr";\
		install -d -m755 $(CONFIGDIR)/ssl.csr;\
		echo "install -d -m 755 $(CONFIGDIR)/ssl.key";\
		install -d -m755 $(CONFIGDIR)/ssl.key;\
		echo "install -c -m 400 cert/conf/ssl.crt/ca.crt $(CONFIGDIR)/ssl.crt/";\
		install -c -m 400 cert/conf/ssl.crt/ca.crt $(CONFIGDIR)/ssl.crt/;\
		echo "install -c -m 400 cert/conf/ssl.crt/server.crt $(CONFIGDIR)/ssl.crt/";\
		install -c -m 400 cert/conf/ssl.crt/server.crt $(CONFIGDIR)/ssl.crt/;\
		echo "install -c -m 400 cert/conf/ssl.csr/ca.csr $(CONFIGDIR)/ssl.csr/";\
		install -c -m 400 cert/conf/ssl.csr/ca.csr $(CONFIGDIR)/ssl.csr/;\
		echo "install -c -m 400 cert/conf/ssl.csr/server.csr $(CONFIGDIR)/ssl.csr/";\
		install -c -m 400 cert/conf/ssl.csr/server.csr $(CONFIGDIR)/ssl.csr/;\
		echo "install -c -m 400 cert/conf/ssl.key/ca.key $(CONFIGDIR)/ssl.key/";\
		install -c -m 400 cert/conf/ssl.key/ca.key $(CONFIGDIR)/ssl.key/;\
		echo "install -c -m 400 cert/conf/ssl.key/server.key $(CONFIGDIR)/ssl.key/";\
		install -c -m 400 cert/conf/ssl.key/server.key $(CONFIGDIR)/ssl.key/;\
	fi;

	@if [ "$(OSTYPE)" = "FreeBSD" ]; then \
		echo "install -c -m 755 os/FreeBSD/smbftpd.sh $(PREFIX)/etc/rc.d/"; \
		[ -d $(PREFIX)/etc/rc.d ] || install -d $(PREFIX)/etc/rc.d; \
		install -c -m 755 os/FreeBSD/smbftpd.sh $(PREFIX)/etc/rc.d/; \
	elif [ "$(OSTYPE)" = "linux" ]; then \
		if [ ! -f /etc/pam.d/ftpd ]; then       \
			echo "install install -c -m 644 os/linux/ftpd.pam /etc/pam.d/ftpd"; \
			install -c -m 644 os/linux/ftpd.pam /etc/pam.d/ftpd;    \
		fi;     \
	fi;


