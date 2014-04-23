/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef	_SMBFTPD_RESTRICT_H_
#define	_SMBFTPD_RESTRICT_H_

/* tcp_wrapper.c */
int tcp_wrapping_check(int fd);

/* throttle.c */
off_t smbftpd_transfer_rate_get(struct opt_set *set, const char *user);
void transfer_rate_throttle(off_t byte_count, struct timeval *tvsince, off_t rate);

/* smbmode.c */
int smbftpd_mode_get(int default_mode, const char *exception, const char *user);

/* chroot.c */
const char *smbftpd_chroot_path_get(struct opt_set *set, const char *user);

/* shell.c */
int smbftpd_valid_shell(const char *shell);

/* nologin.c */
int smbftpd_check_no_login(const char *no_login_list, const char *user);

/* iptrack.c */
int smbftpd_iptrack_alloc(int maxclient);
void smbftpd_iptrack_free(void);
void smbftpd_iptrack_add(union sockunion *addr, pid_t pid);
int smbftpd_iptrack_check(int maxip, union sockunion *addr);
void smbftpd_iptrack_delete(pid_t pid);

#endif /* _SMBFTPD_RESTRICT_H_ */
