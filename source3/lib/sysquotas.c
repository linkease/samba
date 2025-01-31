/* 
   Unix SMB/CIFS implementation.
   System QUOTA function wrappers
   Copyright (C) Stefan (metze) Metzmacher	2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "includes.h"
#include "lib/util_file.h"
#include "lib/util/smb_strtox.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

#ifdef HAVE_SYS_QUOTAS

#if defined(HAVE_QUOTACTL_4A) 

/*#endif HAVE_QUOTACTL_4A */
#elif defined(HAVE_QUOTACTL_4B)

/*#endif HAVE_QUOTACTL_4B */
#elif defined(HAVE_QUOTACTL_3)

#error HAVE_QUOTACTL_3 not implemented

/* #endif  HAVE_QUOTACTL_3 */
#else /* NO_QUOTACTL_USED */

#endif /* NO_QUOTACTL_USED */

#if defined(HAVE_MNTENT) && defined(HAVE_REALPATH)
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;
	SMB_STRUCT_STAT S;
	FILE *fp;
	struct mntent *mnt = NULL;
	SMB_DEV_T devno;
	char *stat_mntpath = NULL;
	char *p;

	/* find the block device file */
	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;

	if (sys_stat(path, &S, false) != 0) {
		return -1;
	}

	devno = S.st_ex_dev ;

	stat_mntpath = sys_realpath(path);
	if (stat_mntpath == NULL) {
		DBG_WARNING("realpath(%s) failed - %s\n", path,
			    strerror(errno));
		goto out;
	}

	if (sys_stat(stat_mntpath, &S, false) != 0) {
		DBG_WARNING("cannot stat real path %s - %s\n", stat_mntpath,
			    strerror(errno));
		goto out;
	}

	if (S.st_ex_dev != devno) {
		DBG_WARNING("device on real path has changed\n");
		goto out;
	}

	while (true) {
		char save_ch;

		p = strrchr(stat_mntpath, '/');
		if (p == NULL) {
			DBG_ERR("realpath for %s does not begin with a '/'\n",
				path);
			goto out;
		}

		if (p == stat_mntpath) {
			++p;
		}

		save_ch = *p;
		*p = 0;
		if (sys_stat(stat_mntpath, &S, false) != 0) {
			DBG_WARNING("cannot stat real path component %s - %s\n",
				    stat_mntpath, strerror(errno));
			goto out;
		}
		if (S.st_ex_dev != devno) {
			*p = save_ch;
			break;
		}

		if (p <= stat_mntpath + 1) {
			break;
		}
	}

	fp = setmntent(MOUNTED,"r");
	if (fp == NULL) {
		goto out;
	}
  
	while ((mnt = getmntent(fp))) {
		if (!strequal(mnt->mnt_dir, stat_mntpath)) {
			continue;
		}

		if ( sys_stat(mnt->mnt_dir, &S, false) == -1 )
			continue ;

		if (S.st_ex_dev == devno) {
			(*mntpath) = SMB_STRDUP(mnt->mnt_dir);
			(*bdev) = SMB_STRDUP(mnt->mnt_fsname);
			(*fs)   = SMB_STRDUP(mnt->mnt_type);
			if ((*mntpath)&&(*bdev)&&(*fs)) {
				ret = 0;
			} else {
				SAFE_FREE(*mntpath);
				SAFE_FREE(*bdev);
				SAFE_FREE(*fs);
				ret = -1;
			}

			break;
		}
	}

	endmntent(fp) ;

out:
	SAFE_FREE(stat_mntpath);
	return ret;
}
/* #endif HAVE_MNTENT */
#elif defined(HAVE_DEVNM)

/* we have this on HPUX, ... */
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;
	char dev_disk[256];
	SMB_STRUCT_STAT S;

	if (!path||!mntpath||!bdev||!fs)
		smb_panic("sys_path_to_bdev: called with NULL pointer");

	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;
	
	/* find the block device file */

	if ((ret=sys_stat(path, &S, false))!=0) {
		return ret;
	}
	
	if ((ret=devnm(S_IFBLK, S.st_ex_dev, dev_disk, 256, 1))!=0) {
		return ret;	
	}

	/* we should get the mntpath right...
	 * but I don't know how
	 * --metze
	 */
	(*mntpath) = SMB_STRDUP(path);
	(*bdev) = SMB_STRDUP(dev_disk);
	if ((*mntpath)&&(*bdev)) {
		ret = 0;
	} else {
		SAFE_FREE(*mntpath);
		SAFE_FREE(*bdev);
		ret = -1;
	}	
	
	
	return ret;	
}

/* #endif HAVE_DEVNM */
#else
/* we should fake this up...*/
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;

	if (!path||!mntpath||!bdev||!fs)
		smb_panic("sys_path_to_bdev: called with NULL pointer");

	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;
	
	(*mntpath) = SMB_STRDUP(path);
	if (*mntpath) {
		ret = 0;
	} else {
		SAFE_FREE(*mntpath);
		ret = -1;
	}

	return ret;
}
#endif

/*********************************************************************
 Now the list of all filesystem specific quota systems we have found
**********************************************************************/
static struct {
	const char *name;
	int (*get_quota)(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
	int (*set_quota)(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
} sys_quota_backends[] = {
#ifdef HAVE_JFS_QUOTA_H
	{"jfs2", sys_get_jfs2_quota, 	sys_set_jfs2_quota},
#endif
#if defined HAVE_XFS_QUOTAS
	{"xfs", sys_get_xfs_quota, 	sys_set_xfs_quota},
	{"gfs", sys_get_xfs_quota, 	sys_set_xfs_quota},
	{"gfs2", sys_get_xfs_quota, 	sys_set_xfs_quota},
#endif /* HAVE_XFS_QUOTAS */
#ifdef HAVE_NFS_QUOTAS
	{"nfs", sys_get_nfs_quota,	sys_set_nfs_quota},
	{"nfs4", sys_get_nfs_quota,	sys_set_nfs_quota},
#endif /* HAVE_NFS_QUOTAS */
	{NULL, 	NULL, 			NULL}
};

static int command_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *get_quota_command;
	char **lines = NULL;

	get_quota_command = lp_get_quota_command(talloc_tos(), lp_sub);
	if (get_quota_command && *get_quota_command) {
		const char *p;
		char *p2;
		int _id = -1;
		int error = 0;
		char **argl = NULL;

		switch(qtype) {
			case SMB_USER_QUOTA_TYPE:
			case SMB_USER_FS_QUOTA_TYPE:
				_id = id.uid;
				break;
			case SMB_GROUP_QUOTA_TYPE:
			case SMB_GROUP_FS_QUOTA_TYPE:
				_id = id.gid;
				break;
			default:
				DEBUG(0,("invalid quota type.\n"));
				return -1;
		}

		argl = str_list_make_empty(talloc_tos());
		str_list_add_printf(&argl, "%s", get_quota_command);
		str_list_add_printf(&argl, "%s", path);
		str_list_add_printf(&argl, "%d", qtype);
		str_list_add_printf(&argl, "%d", _id);
		if (argl == NULL) {
			return -1;
		}

		DBG_NOTICE("Running command %s %s %d %d\n",
			get_quota_command,
			path,
			qtype,
			_id);

		lines = file_lines_ploadv(talloc_tos(), argl, NULL);
		TALLOC_FREE(argl);

		if (lines) {
			char *line = lines[0];

			DEBUG (3, ("Read output from get_quota, \"%s\"\n", line));

			/* we need to deal with long long unsigned here, if supported */

			dp->qflags = smb_strtoul(line,
						 &p2,
						 10,
						 &error,
						 SMB_STR_STANDARD);
			if (error != 0) {
				goto invalid_param;
			}

			p = p2;
			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->curblocks = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->softlimit = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->hardlimit = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->curinodes = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->isoftlimit = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->ihardlimit = STR_TO_SMB_BIG_UINT(p, &p);
			} else {
				goto invalid_param;	
			}

			while (p && *p && isspace(*p)) {
				p++;
			}

			if (p && *p) {
				dp->bsize = STR_TO_SMB_BIG_UINT(p, NULL);
			} else {
				dp->bsize = 1024;
			}

			TALLOC_FREE(lines);
			lines = NULL;

			DEBUG (3, ("Parsed output of get_quota, ...\n"));

			DEBUGADD (5,( 
				"qflags:%u curblocks:%llu softlimit:%llu hardlimit:%llu\n"
				"curinodes:%llu isoftlimit:%llu ihardlimit:%llu bsize:%llu\n", 
				dp->qflags,(long long unsigned)dp->curblocks,
				(long long unsigned)dp->softlimit,(long long unsigned)dp->hardlimit,
				(long long unsigned)dp->curinodes,
				(long long unsigned)dp->isoftlimit,(long long unsigned)dp->ihardlimit,
				(long long unsigned)dp->bsize));
			return 0;
		}

		DEBUG (0, ("get_quota_command failed!\n"));
		return -1;
	}

	errno = ENOSYS;
	return -1;

invalid_param:

	TALLOC_FREE(lines);
	DEBUG(0,("The output of get_quota_command is invalid!\n"));
	return -1;
}

static int command_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *set_quota_command;

	set_quota_command = lp_set_quota_command(talloc_tos(), lp_sub);
	if (set_quota_command && *set_quota_command) {
		char **lines = NULL;
		int _id = -1;
		char **argl = NULL;

		switch(qtype) {
			case SMB_USER_QUOTA_TYPE:
			case SMB_USER_FS_QUOTA_TYPE:
				_id = id.uid;
				break;
			case SMB_GROUP_QUOTA_TYPE:
			case SMB_GROUP_FS_QUOTA_TYPE:
				_id = id.gid;
				break;
			default:
				return -1;
		}

		argl = str_list_make_empty(talloc_tos());
		str_list_add_printf(&argl, "%s", set_quota_command);
		str_list_add_printf(&argl, "%s", path);
		str_list_add_printf(&argl, "%d", qtype);
		str_list_add_printf(&argl, "%d", _id);
		str_list_add_printf(&argl, "%u", dp->qflags);
		str_list_add_printf(
			&argl, "%llu", (long long unsigned)dp->softlimit);
		str_list_add_printf(
			&argl, "%llu", (long long unsigned)dp->hardlimit);
		str_list_add_printf(
			&argl, "%llu", (long long unsigned)dp->isoftlimit);
		str_list_add_printf(
			&argl, "%llu", (long long unsigned)dp->ihardlimit);
		str_list_add_printf(
			&argl, "%llu", (long long unsigned)dp->bsize);
		if (argl == NULL) {
			return -1;
		}

		DBG_NOTICE("Running command "
			"%s %s %d %d "
			"%"PRIu32" %"PRIu64" %"PRIu64" "
			"%"PRIu64" %"PRIu64" %"PRIu64"\n",
			set_quota_command,
			path,
			qtype,
			_id,
			dp->qflags,
			dp->softlimit,
			dp->hardlimit,
			dp->isoftlimit,
			dp->ihardlimit,
			dp->bsize);

		lines = file_lines_ploadv(talloc_tos(), argl, NULL);
		TALLOC_FREE(argl);
		if (lines) {
			char *line = lines[0];

			DEBUG (3, ("Read output from set_quota, \"%s\"\n", line));

			TALLOC_FREE(lines);

			return 0;
		}
		DEBUG (0, ("set_quota_command failed!\n"));
		return -1;
	}

	errno = ENOSYS;
	return -1;
}

int sys_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	int i;
	bool ready = False;
	char *mntpath = NULL;
	char *bdev = NULL;
	char *fs = NULL;

	if (!path||!dp)
		smb_panic("sys_get_quota: called with NULL pointer");

	if (command_get_quota(path, qtype, id, dp)==0) {	
		return 0;
	} else if (errno != ENOSYS) {
		return -1;
	}

	if ((ret=sys_path_to_bdev(path,&mntpath,&bdev,&fs))!=0) {
		DEBUG(0,("sys_path_to_bdev() failed for path [%s]!\n",path));
		return ret;
	}

	errno = 0;
	DEBUG(10,("sys_get_quota() uid(%u, %u), fs(%s)\n", (unsigned)getuid(), (unsigned)geteuid(), fs));

	for (i=0;(fs && sys_quota_backends[i].name && sys_quota_backends[i].get_quota);i++) {
		if (strcmp(fs,sys_quota_backends[i].name)==0) {
			ret = sys_quota_backends[i].get_quota(mntpath, bdev, qtype, id, dp);
			if (ret!=0) {
				DEBUG(3,("sys_get_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d]: %s.\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),strerror(errno)));
			} else {
				DEBUG(10,("sys_get_%s_quota() called for mntpath[%s] bdev[%s] qtype[%d] id[%d].\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid)));
			}
			ready = True;
			break;	
		}		
	}

	if (!ready) {
		/* use the default vfs quota functions */
		ret=sys_get_vfs_quota(mntpath, bdev, qtype, id, dp);
		if (ret!=0) {
			DEBUG(3,("sys_get_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d]: %s\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),strerror(errno)));
		} else {
			DEBUG(10,("sys_get_%s_quota() called for mntpath[%s] bdev[%s] qtype[%d] id[%d].\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid)));
		}
	}

	SAFE_FREE(mntpath);
	SAFE_FREE(bdev);
	SAFE_FREE(fs);

	return ret;
}

int sys_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	int i;
	bool ready = False;
	char *mntpath = NULL;
	char *bdev = NULL;
	char *fs = NULL;

	/* find the block device file */

	if (!path||!dp)
		smb_panic("get_smb_quota: called with NULL pointer");

	if (command_set_quota(path, qtype, id, dp)==0) {	
		return 0;
	} else if (errno != ENOSYS) {
		return -1;
	}

	if ((ret=sys_path_to_bdev(path,&mntpath,&bdev,&fs))!=0) {
		DEBUG(0,("sys_path_to_bdev() failed for path [%s]!\n",path));
		return ret;
	}

	errno = 0;
	DEBUG(10,("sys_set_quota() uid(%u, %u)\n", (unsigned)getuid(), (unsigned)geteuid())); 

	for (i=0;(fs && sys_quota_backends[i].name && sys_quota_backends[i].set_quota);i++) {
		if (strcmp(fs,sys_quota_backends[i].name)==0) {
			ret = sys_quota_backends[i].set_quota(mntpath, bdev, qtype, id, dp);
			if (ret!=0) {
				DEBUG(3,("sys_set_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d]: %s.\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),strerror(errno)));
			} else {
				DEBUG(10,("sys_set_%s_quota() called for mntpath[%s] bdev[%s] qtype[%d] id[%d].\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid)));
			}
			ready = True;
			break;
		}		
	}

	if (!ready) {
		/* use the default vfs quota functions */
		ret=sys_set_vfs_quota(mntpath, bdev, qtype, id, dp);
		if (ret!=0) {
			DEBUG(3,("sys_set_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d]: %s.\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),strerror(errno)));
		} else {
			DEBUG(10,("sys_set_%s_quota() called for mntpath[%s] bdev[%s] qtype[%d] id[%d].\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid)));
		}
	}

	SAFE_FREE(mntpath);
	SAFE_FREE(bdev);
	SAFE_FREE(fs);

	return ret;		
}

#else /* HAVE_SYS_QUOTAS */
 void dummy_sysquotas_c(void);

 void dummy_sysquotas_c(void)
{
	return;
}
#endif /* HAVE_SYS_QUOTAS */

