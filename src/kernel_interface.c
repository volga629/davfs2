/*  kernel_interface.c: interface to fuse and coda kernel mocule.
    Copyright (C) 2006, 2007, 2008, 2009, 2014 Werner Baumann

    This file is part of davfs2.

    davfs2 is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    davfs2 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with davfs2; if not, write to the Free Software Foundation,
    Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. */


#include "config.h"

#include <error.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIBINTL_H
#include <libintl.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <sys/wait.h>

#include "defaults.h"
#include "mount_davfs.h"
#include "cache.h"
#include "coda.h"
#include "fuse_kernel.h"
#include "kernel_interface.h"

#ifdef ENABLE_NLS
#define _(String) gettext(String)
#else
#define _(String) String
#endif


/* Private constants */
/*===================*/

/* Name, major number and minor number of the devices to communicate with the
   kernel file system. */
#define FUSE_DEV_NAME "fuse"
#define CODA_DEV_NAME "cfs"
#define CODA_MAJOR 67
#define MAX_CODADEVS  5   /* Coda minor number may be from 0 to 4. */


/* Private function prototypes */
/*=============================*/

static int
init_coda(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata);

static int
init_fuse(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata,
          size_t *buf_size, const char *url, const char *mpoint,
          unsigned long int mopts, uid_t owner, gid_t group, mode_t mode);


/* Public functions */
/*==================*/

int
dav_init_kernel_interface(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata,
                          char **kernel_fs, size_t *buf_size, const char *url,
                          const char *mpoint, const dav_args *args)
{
    uid_t orig = geteuid();
    if (seteuid(0) != 0)
        error(EXIT_FAILURE, 0, _("can't change effective user id"));

    if (!*kernel_fs)
        *kernel_fs = strdup("fuse");
    if (!*kernel_fs) abort();

    int mounted = 0;
    if (strcmp(*kernel_fs, "coda") == 0) {

        if (init_coda(dev, msg_loop, mdata) != 0) {
            error(0, 0, _("trying fuse kernel file system"));
            if (init_fuse(dev, msg_loop, mdata, buf_size, url, mpoint,
                          args->mopts, args->uid, args->gid, args->dir_mode)
                                                                        == 0) {
                free(*kernel_fs);
                *kernel_fs = strdup("fuse");
                if (!*kernel_fs) abort();
                mounted = 1;
                error(0, 0, _("fuse device opened successfully"));
            } else {
                exit(EXIT_FAILURE);
            }
        } 

    } else if (strcmp(*kernel_fs, "fuse") == 0) {

        if (init_fuse(dev, msg_loop, mdata, buf_size, url, mpoint, args->mopts,
                      args->uid, args->gid, args->dir_mode) == 0) {
            mounted = 1;
        } else {
            error(0, 0, _("trying coda kernel file system"));
            if (init_coda(dev, msg_loop, mdata) == 0) {
                free(*kernel_fs);
                *kernel_fs = strdup("coda");
                if (*kernel_fs == NULL)
                    abort();
                error(0, 0, _("coda device opened successfully"));
            } else {
                exit(EXIT_FAILURE);
            }
        }

    } else {

        error(EXIT_FAILURE, 0, _("unknown kernel file system %s"), *kernel_fs);
    }

    if (seteuid(orig) != 0)
        error(EXIT_FAILURE, 0, _("can't change effective user id"));
    return mounted;
}


/* Private functions */
/*===================*/

static int
init_coda(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata)
{
    *dev = 0;
    int minor = 0;
    while (*dev <= 0 && minor < MAX_CODADEVS) {
        char *path;
        if (asprintf(&path, "%s/%s%i", DAV_DEV_DIR, CODA_DEV_NAME, minor) < 0)
            abort();
        *dev = open(path, O_RDWR | O_NONBLOCK);
        free(path);
        ++minor;
    }

    if (*dev <= 0) {
        error(0, 0, _("no free coda device to mount"));
        return -1;
    }

    int version = 0;
    ioctl(*dev, CIOC_KERNEL_VERSION, &version);
    if (version == 3) {
        *msg_loop = dav_coda_loop;
    } else {
        error(0, 0, _("CODA_KERNEL_VERSION %u not supported"), version);
        close(*dev);
        return -1;
    }

    struct coda_mount_data *md = malloc(sizeof(struct coda_mount_data));
    if (!md) abort();
    md->version = CODA_MOUNT_VERSION;
    md->fd = *dev;
    *mdata = md;

    return 0;
}


static int
init_fuse(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata,
          size_t *buf_size, const char *url, const char *mpoint,
          unsigned long int mopts, uid_t owner, gid_t group, mode_t mode)
{
    char *path;
    if (asprintf(&path, "%s/%s", DAV_DEV_DIR, FUSE_DEV_NAME) < 0)
            abort();

    *dev = open(path, O_RDWR | O_NONBLOCK);

    if (*dev <= 0) {
        error(0, 0, _("loading kernel module fuse"));
        int ret;
        pid_t pid = fork();
        if (pid == 0) {
            execl("/sbin/modprobe", "modprobe", "fuse", NULL);
            _exit(EXIT_FAILURE);
        } else if (pid < 0) {
            ret = -1;
        } else {
            if (waitpid(pid, &ret, 0) != pid)
                ret = -1;
        }

        if (ret) {
            error(0, 0, _("loading kernel module fuse failed"));
        } else {
            *dev = open(path, O_RDWR | O_NONBLOCK);
        }

        if (*dev <= 0) {
            error(0, 0, _("waiting for /dev/fuse to be created"));
            sleep(2); 
            *dev = open(path, O_RDWR | O_NONBLOCK);
        }
    }

    free(path);
    if (*dev <= 0) {
        error(0, 0, _("can't open fuse device"));
        return -1;
    }

    if (*buf_size < (FUSE_MIN_READ_BUFFER + 4096)) {
        *buf_size = FUSE_MIN_READ_BUFFER + 4096;
    }

#if SIZEOF_VOID_P == 8
    if (asprintf((char **) mdata, "fd=%i,rootmode=%o,user_id=%i,group_id=%i,"
                 "allow_other,max_read=%lu", *dev, mode, owner, group,
                 (unsigned long int) (*buf_size - 4096)) < 0)
        abort();
#else
    if (asprintf((char **) mdata, "fd=%i,rootmode=%o,user_id=%i,group_id=%i,"
                 "allow_other,max_read=%u", *dev, mode, owner, group,
                 (unsigned int) (*buf_size - 4096)) < 0)
        abort();
#endif
    if (mount(url, mpoint, "fuse", mopts, *mdata) == 0) {
        *msg_loop = dav_fuse_loop;
        return 0;
    }

    free(*mdata);
    close(*dev);
    error(0, 0, _("can't mount using fuse kernel file system"));
    return -1;
}
