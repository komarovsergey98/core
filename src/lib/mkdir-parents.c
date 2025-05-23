/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "ipwd.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

mode_t mkdir_get_executable_mode(mode_t mode)
{
	/* add the execute bit if either read or write bit is set */
	if ((mode & 0600) != 0) mode |= 0100;
	if ((mode & 0060) != 0) mode |= 0010;
	if ((mode & 0006) != 0) mode |= 0001;
	return mode;
}

static int ATTR_NULL(5)
mkdir_chown_full(const char *path, mode_t mode, uid_t uid,
		 gid_t gid, const char *gid_origin)
{
	string_t *str;
	mode_t old_mask;
	unsigned int i;
	int ret, fd = -1, orig_errno;

	for (i = 0;; i++) {
		old_mask = umask(0);
		ret = mkdir(path, mode);
		umask(old_mask);
		if (ret < 0)
			break;
		if (uid == (uid_t)-1 && gid == (gid_t)-1) {
			/* no changes to owner/group */
			return 0;
		}

		fd = open(path, O_RDONLY);
		if (fd != -1)
			break;
		if (errno != ENOENT || i == 3) {
			i_error("open(%s) failed: %m", path);
			return -1;
		}
		/* it was just rmdir()ed by someone else? retry */
	}

	if (ret < 0) {
		if (errno == EISDIR || errno == ENOSYS) {
			/* EISDIR check is for BSD/OS which returns it if path
			   contains '/' at the end and it exists.

			   ENOSYS check is for NFS mount points. */
			errno = EEXIST;
		}
		i_assert(fd == -1);
		return -1;
	}
	if (fchown(fd, uid, gid) < 0) {
		i_close_fd(&fd);
		orig_errno = errno;
		if (rmdir(path) < 0 && errno != ENOENT)
			i_error("rmdir(%s) failed: %m", path);
		errno = orig_errno;

		if (errno == EPERM && uid == (uid_t)-1) {
			i_error("%s", eperm_error_get_chgrp("fchown", path, gid,
							    gid_origin));
			return -1;
		}

		str = t_str_new(256);
		str_printfa(str, "fchown(%s, %ld", path,
			    uid == (uid_t)-1 ? -1L : (long)uid);
		if (uid != (uid_t)-1) {
			struct passwd pw;

			if (i_getpwuid(uid, &pw) > 0)
				str_printfa(str, "(%s)", pw.pw_name);

		}
		str_printfa(str, ", %ld",
			    gid == (gid_t)-1 ? -1L : (long)gid);
		if (gid != (gid_t)-1) {
			struct group gr;

			if (i_getgrgid(uid, &gr) > 0)
				str_printfa(str, "(%s)", gr.gr_name);
		}
		errno = orig_errno;
		i_error("%s) failed: %m", str_c(str));
		return -1;
	}
	if (gid != (gid_t)-1 && (mode & S_ISGID) == 0) {
		/* make sure the directory doesn't have setgid bit enabled
		   (in case its parent had) */
		if (fchmod(fd, mode) < 0) {
			orig_errno = errno;
			if (rmdir(path) < 0 && errno != ENOENT)
				i_error("rmdir(%s) failed: %m", path);
			errno = orig_errno;
			i_error("fchmod(%s) failed: %m", path);
			i_close_fd(&fd);
			return -1;
		}
	}
	i_close_fd(&fd);
	return 0;
}

int mkdir_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return mkdir_chown_full(path, mode, uid, gid, NULL);
}

int mkdir_chgrp(const char *path, mode_t mode,
		gid_t gid, const char *gid_origin)
{
	return mkdir_chown_full(path, mode, (uid_t)-1, gid, gid_origin);
}

static int ATTR_NULL(5)
mkdir_parents_chown_full(const char *path, mode_t mode, uid_t uid, gid_t gid,
			 const char *gid_origin)
{
	const char *p;
	int ret;

	if (mkdir_chown_full(path, mode, uid, gid, gid_origin) < 0) {
		if (errno != ENOENT)
			return -1;

		/* doesn't exist, try recursively creating our parent dir */
		p = strrchr(path, '/');
		if (p == NULL || p == path)
			return -1; /* shouldn't happen */

		T_BEGIN {
			ret = mkdir_parents_chown_full(t_strdup_until(path, p),
						       mode, uid,
						       gid, gid_origin);
		} T_END;
		if (ret < 0 && errno != EEXIST)
			return -1;

		/* should work now */
		if (mkdir_chown_full(path, mode, uid, gid, gid_origin) < 0)
			return -1;
	}
	return 0;
}

int mkdir_parents_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return mkdir_parents_chown_full(path, mode, uid, gid, NULL);
}

int mkdir_parents_chgrp(const char *path, mode_t mode,
			gid_t gid, const char *gid_origin)
{
	return mkdir_parents_chown_full(path, mode, (uid_t)-1, gid, gid_origin);
}

int mkdir_parents(const char *path, mode_t mode)
{
	return mkdir_parents_chown(path, mode, (uid_t)-1, (gid_t)-1);
}

int stat_first_parent(const char *path, const char **root_dir_r,
		      struct stat *st_r)
{
	const char *p;

	while (stat(path, st_r) < 0) {
		if (errno != ENOENT || strcmp(path, "/") == 0) {
			*root_dir_r = path;
			return -1;
		}
		p = strrchr(path, '/');
		if (p == NULL)
			path = "/";
		else
			path = t_strdup_until(path, p);
	}
	*root_dir_r = path;
	return 0;
}
