/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#ifndef _SMBFTPD_CMD_H_
#define _SMBFTPD_CMD_H_

int cmd_auth(const char *method);
void cmd_cwd(const char *path);
void cmd_pass(const char *passwd);
void cmd_delete(const char *path);
void cmd_feat(void);
FILE *dataconn(const char *name, off_t size, const char *mode);
void dataconnclose(FILE *datastream);
void cmd_passive(void);
void cmd_long_passive(const char *cmd, int pf);
void cmd_port(void);
void cmd_lprt(void);
void cmd_eprt(const char *str);
void cmd_list(const char *dirname, int verbose);
void cmd_mdtm(char *str);
void cmd_mkdir(const char *name);
void cmd_opts(char *command);
void cmd_pbsz(void);
void cmd_prot(const char *level);
void cmd_pwd(void);
void cmd_quit(void);
void cmd_retr(const char *file, off_t restart_point);
void cmd_rmdir(const char *name);
int cmd_rnfr(const char *name);
void cmd_rnto(const char *from, const char *to);
void cmd_site_chmod(const char *path, mode_t mode);
void cmd_site_mdfive(const char *path);
void cmd_size(const char *path);
void cmd_stat(void);
void cmd_statfile(const char *filename);
void cmd_store(const char *name, const char *mode, int unique, off_t restart_point);
void cmd_user(const char *name);
#endif /* _SMBFTPD_CMD_H_ */
