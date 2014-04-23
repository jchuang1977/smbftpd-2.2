/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <syslog.h>
	 
#include "smbftpd.h"

typedef struct {
	union sockunion addr;
	pid_t pid;
} smbftpd_iptable_t;

static int table_size = 0;
static smbftpd_iptable_t *iptable;

/**
 * Free the ip table.
 */
void smbftpd_iptrack_free()
{
	if (iptable) {
		free(iptable);
		iptable = NULL;
	}       
	table_size = 0;
}

/**
 * Allocate table to record ip address. So we can use
 * smbftpd_iptrack_add(), smbftpd_iptrack_check(), 
 * smbftpd_iptrack_delete() to control max connection from
 * the same IP.
 * 
 * @param maxclient Max client to accept
 * 
 * @return 0: Success
 *         -1: Failed
 */
int smbftpd_iptrack_alloc(int maxclient)
{
	if (iptable) {
		smbftpd_iptrack_free();
	}

	if (!maxclient) {
		return 0;
	}

	iptable = calloc(maxclient, sizeof(smbftpd_iptable_t));
	if (!iptable) {
		return -1;
	}
	table_size = maxclient;

	return 0;
}

/**
 * Add an IP/pid into iptable
 * 
 * @param addr   The client's ip address
 * @param pid    The process id of the fork()ed process
 */
void smbftpd_iptrack_add(union sockunion *addr, pid_t pid)
{
	int i = 0;

	if (!iptable) {
		return;
	}

	do {
		if (iptable[i].pid == 0) {
			iptable[i].addr = *addr;
			iptable[i].pid = pid;
			return;
		}
		i++;
	} while ( i < table_size );

	// Table full, Remove the first item. Should never happen?
	memmove(&(iptable[0]), &(iptable[1]), sizeof(iptable[0]) * (table_size - 1));
	iptable[table_size-1].addr = *addr;
	iptable[table_size-1].pid = pid;

	return;
}

/**
 * Check whether the max connection from the same ip
 * has reached limit
 * 
 * @param maxip  Max connection per ip.
 * @param addr   The client's IP
 * 
 * @return 0: Allowed
 *         -1: Exceed the limit
 */
int smbftpd_iptrack_check(int maxip, union sockunion *addr)
{
	int i = 0;
	int match = 0;

	if (!iptable || !maxip || !addr) {
		return 0;
	}

	do {
		if (iptable[i].pid != 0 && iptable[i].addr.su_family == addr->su_family) {
			if (iptable[i].addr.su_family == AF_INET && 
				iptable[i].addr.su_sin.sin_addr.s_addr == addr->su_sin.sin_addr.s_addr) {
				match++;
#ifdef INET6
			} else if (iptable[i].addr.su_family == AF_INET6 && 
					   IN6_ARE_ADDR_EQUAL(&iptable[i].addr.su_sin6.sin6_addr, &addr->su_sin6.sin6_addr)) {
				match++;
#endif
			}
		}
		i++;
	} while ( i < table_size );

	if (match >= maxip) {
		return -1;
	}

	return 0;
}

/**
 * Remove the pid/ip from iptable.
 * 
 * This function is called when client disconnects
 * 
 * @param pid    The process id of fork()ed process
 */
void smbftpd_iptrack_delete(pid_t pid)
{
	int i = 0;

	if (!iptable) {
		return;
	}

	do {
		if (iptable[i].pid == pid) {
			iptable[i].pid = 0;
			return;
		}
		i++;
	} while ( i < table_size );
}

