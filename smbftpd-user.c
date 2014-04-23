/* Copyright 2003-2008 Wang, Chun-Pin All rights reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>

#include "smbftpd.h"
#include "pathnames.h"
#include "auth.h"
#include "restrict.h"

smbftpd_conf_t smbftpd_conf;
smbftpd_session_t smbftpd_session;
smbftpd_share_t *smbftpd_shares = NULL;
static char *conf_path = PATH_SMBFTPD_CONF;

/* Copy from FreeBSD 4.11 passwd command. */
static unsigned char itoa64[] =         /* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                                 
static void to64(char *s, long v, int n)
{               
	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}                      
}                       
                       
static char *crypt_make_salt(void)
{
	static char salt[32];
	struct timeval tv;
	/* Make a good size salt for algoritms that can use it. */
	gettimeofday(&tv,0);
	/* Salt suitable for anything */
	//to64(&salt[0], random(), 3);
	memcpy(salt, "$1$", 3);
	to64(&salt[3], tv.tv_usec, 3);
	to64(&salt[6], tv.tv_sec, 2);
	to64(&salt[8], random(), 5);
	to64(&salt[13], random(), 5);
	to64(&salt[17], random(), 5);
	to64(&salt[22], random(), 5);
	salt[27] = '\0';

	return salt;
}

static char *inputget(const char *prompt)
{
	char buf[2048];

	while (1) {
		printf("%s", prompt);
		if (!fgets(buf, sizeof(buf), stdin)) {
			printf("Failed to get group.\n");
			return NULL;
		}
		if (strchr(buf, ':')) {
			printf("Colon is not a valid charactor.\n");
			continue;
		}
		if (strchr(buf, '#')) {
			printf("# is not a valid charactor.\n");
			continue;
		}
		break;
	}
	str_trim_space(buf);
	return strdup(buf);
}

static int user_update(const char *user, int newuser)
{
	smbftpd_text_user_t smbftpd_user;
	char *password1 = NULL, *password2 = NULL;
	int error = -1;

	if (0 == smbftpd_text_user_get(smbftpd_conf.virtual_user_auth_config, user, &smbftpd_user)) {
		if (newuser) {
			printf("User [%s] already exists.\n", user);
			goto Error;
		}
	} else {
		if (!newuser) {
			printf("Failed to find user [%s].\n", user);
			goto Error;
		}
	}

	smbftpd_text_user_free(&smbftpd_user);

	smbftpd_user.user = strdup(user);
	if (!smbftpd_user.user) {
		printf("Out of memory.\n");
		goto Error;
	}
	smbftpd_user.group = inputget("Group name: ");
	if (NULL == smbftpd_user.group) {
		goto Error;
	}
	smbftpd_user.home = inputget("Home: ");
	if (NULL == smbftpd_user.group) {
		goto Error;
	}

	while (!password1) {
		password1 = getpass("Enter password: ");
		if (!password1) {
			goto Error;
		}
		password1 = strdup(password1);
		if (!password1) {
			printf("Out of memory.\n");
			goto Error;
		}
		password2 = getpass("Enter password again: ");
		if (!password2) {
			goto Error;
		}
		if (strcmp(password1, password2) != 0) {
			printf("Passwords did not match!\n");
			free(password1);
			password1 = NULL;
		}
	}
	
    password2 = crypt(password1, crypt_make_salt());
	if (!password2) {
		printf("Failed to crypt password.\n");
		goto Error;
	}
	smbftpd_user.password = strdup(password2);

	if (0 != smbftpd_text_user_set(smbftpd_conf.virtual_user_auth_config, user, &smbftpd_user)) {
		if (newuser) {
			printf("Failed to add user.\n");
		} else {
			printf("Failed to update user.\n");
		}
	} else {
		printf("User [%s] is %s.\n", user, newuser?"add":"update");
	}

	error = 0;
Error:
	if (password1) {
		free(password1);
	}
	smbftpd_text_user_free(&smbftpd_user);
	return error;
}

static int user_add(const char *user)
{
	if (strchr(user, ':') || strchr(user, '#')) {
		printf("User name can't contains # or :\n");
		return -1;
	}
	return user_update(user, 1);
}

static int user_edit(const char *user)
{
	return user_update(user, 0);
}

static int user_delete(const char *user)
{
	smbftpd_text_user_t smbftpd_user;
	int error = -1;

	if (0 != smbftpd_text_user_get(smbftpd_conf.virtual_user_auth_config, user, &smbftpd_user)) {
		printf("User [%s] does not exist.\n\n", user);
		goto Error;
	}
	if (0 != smbftpd_text_user_set(smbftpd_conf.virtual_user_auth_config, user, NULL)) {
		printf("Failed to delete user [%s].\n\n", user);
		goto Error;
	}

	error = 0;

Error:
	smbftpd_text_user_free(&smbftpd_user);

	return error;
}

static int user_get(const char *user)
{
	struct passwd *pw = NULL;
	char *home = NULL;
	const char *realuser = NULL, *dir = NULL;
	char *chroot_dir = NULL;

	printf("\n");
	if (smbftpd_conf.virtual_user_mapping) {
		printf("Authentication Method: %s\n\n", smbftpd_conf.virtual_user_auth_method);
	} else {
		#ifdef	USE_PAM
		printf("Authentication Method: pam\n\n");
		#else
		printf("Authentication Method: unix\n\n");
		#endif
	}
	
	if (smbftpd_conf.anonymous_only || (smbftpd_conf.anonymous_login && 
										(strcmp(user, "ftp") == 0 || strcmp(user, "anonymous") == 0))) {
		pw = getpwnam("ftp");
		if (pw) {
			smbftpd_session.guest = 1;
			realuser = "ftp";
			if (!realuser) {
				printf("Out of memory.\n");
				goto Error;
			}
		}
	}

	if (!smbftpd_session.guest) {
		if (smbftpd_conf.virtual_user_mapping) { // virtual user
			realuser = smbftpd_conf.virtual_user_mapping;
		} else {
			realuser = user;
		}
	}

	
	if (smbftpd_session.guest) {
		printf("Anonymouse only. The user will be changed to [ftp].\n");
		snprintf(smbftpd_session.username, sizeof(smbftpd_session.username), "ftp");
		home = strdup(pw->pw_dir);
	} else {
		snprintf(smbftpd_session.username, sizeof(smbftpd_session.username), "%s", user);
		home = smbftpd_auth_get_home(smbftpd_session.username);
	}

	if (!home) {
		printf("User [%s] does not exist.\n", user);
		return -1;
	}


	smbftpd_session.mode = smbftpd_mode_get(smbftpd_conf.default_mode, 
											smbftpd_conf.exception_list, smbftpd_session.username);
	
	smbftpd_session.max_upload_rate = smbftpd_transfer_rate_get(smbftpd_conf.max_upload_rate, 
																smbftpd_session.username);
	smbftpd_session.max_download_rate = smbftpd_transfer_rate_get(smbftpd_conf.max_download_rate, 
																  smbftpd_session.username);


	if (smbftpd_session.guest && smbftpd_session.mode != MODE_SMB) {
		dir = home;
	} else {
		dir = smbftpd_chroot_path_get(smbftpd_conf.chroot_set, smbftpd_session.username);
	}
	if (dir) {
		smbftpd_session.chroot = 1;
		smbftpd_session.mode = MODE_NORMAL;

		if (dir[0] == '/') {
			chroot_dir = strdup(dir); /* so it can be freed */
		} else if (dir[0] == '~') {
			asprintf(&chroot_dir, "%s/%s", home, dir+1);
		} else {
			asprintf(&chroot_dir, "%s/%s", home, dir);
		}
		if (chroot_dir == NULL) {
			printf("Ran out of memory.");
			goto Error;
		}
			
	} else	{/* real user w/o chroot */
		if (smbftpd_session.mode == MODE_SMB && smbftpd_shares) {
			
			if (0 != smbftpd_valid_share_get(smbftpd_session.username, home,
											 smbftpd_shares, &smbftpd_session.valid_shares)) {
				printf("Ran out of memory.");
				goto Error;
			}
		}
	}

	printf("Login              : %s\n", user);
	printf("Real user          : %s\n", realuser);
	printf("Home               : %s\n", home);
	printf("Anonymous          : %s\n", smbftpd_session.guest?"Yes":"No");
	printf("Download bandwidth : %lld KB/s %s\n", smbftpd_session.max_download_rate/1024, (smbftpd_session.max_download_rate == 0)?"(unlimited)":"");
	printf("Upload bandwidth   : %lld KB/s %s\n", smbftpd_session.max_upload_rate/1024, (smbftpd_session.max_upload_rate == 0)?"(unlimited)":"");

	if (smbftpd_session.chroot) {
		printf("Mode               : chrooted (%s)\n", chroot_dir);
	} else if (smbftpd_session.mode == MODE_NORMAL) {
		printf("Mode               : normal\n");
	} else {
		smbftpd_valid_share_t *share;
		printf("Mode               : smb\n");
		printf("Available shares   :\n");

		share = smbftpd_session.valid_shares;
		while (share) {
			printf("    [%s]\n", share->share);
			printf("        Path        : %s\n", share->path);
			printf("        Writeable   : %s\n", share->writable?"Yes":"No");
			printf("        Browseable  : %s\n", share->browseable?"Yes":"No");
			printf("        List files  : %s\n", share->disable_ls?"No":"Yes");
			printf("        Download    : %s\n", share->disable_download?"No":"Yes");
			printf("        Modify data : %s\n", share->disable_modify?"No":"Yes");
			share = share->next;
		}
	}
	printf("\n");
Error:
	if (home) {
		free(home);
	}
	if (chroot_dir) {
		free(chroot_dir);
	}

	smbftpd_valid_share_free(&smbftpd_session.valid_shares);
	return 0;
}

static void help(char *program)
{
	printf("\nUsage: %s -[aedt] user [-t type]\n\n"
		   "options:\n"
		   "     -s file     Set the path of smbftpd.conf\n"
		   "     -a user     Add a smbftpd virtual user into text file\n"
		   "     -e user     Edit a smbftpd virtual user into text file\n"
		   "     -d user     Delete a smbftpd virtual user into text file\n"
		   "     -g user     Get the status of user.\n"
		   "                 The user can be real user or mysql/pgsql/text virtual\n"
		   "                 user. We will print the available share and permission\n"
		   "                 of the user.\n"
		   "     -h          Print this help message\n\n", program);
}

int main(int argc, char **argv)
{
	char *user = NULL;
	int ch, action = 0;
	int error;

	while ((ch = getopt(argc, argv, "a:e:d:hg:s:")) != -1) {
		switch (ch) {
		case 'a':
			action = ch;
			user = optarg;
			break;
		case 'e':
			action = ch;
			user = optarg;
			break;
		case 'd':
			action = ch;
			user = optarg;
			break;
		case 'g':
			action = ch;
			user = optarg;
			break;
		case 's':
			conf_path = optarg;
			break;
		case 'h':
		default:
			help(argv[0]);
			exit(0);
			break;
		}
	}
	if (!action) {
		help(argv[0]);
		exit(1);
	}

	config_init();
	error = config_read(conf_path);
	if (error != 0) {
		printf("Failed to parse config file %s\n"
			   "Please check syslog for detail.\n\n", conf_path);
		exit(1);
	}

	if (action != 'g') {
		if (!smbftpd_conf.virtual_user_auth_config) {
			printf("Please set the VirtualUserAuthConfig in the smbftpd.conf.\n");
			exit(1);
		}
	}
	switch (action) {
	case 'a':
		return user_add(user);
		break;
	case 'e':
		return user_edit(user);
		break;
	case 'd':
		return user_delete(user);
	case 'g':
		return user_get(user);
	default:
		break;
	}

	return 0;

}
