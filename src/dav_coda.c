/*  dav_coda.c: interface to the Coda kernel module CODA_KERNEL_VERSION 3.
    Copyright (C) 2006, 2007, 2008, 2009 Werner Baumann

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

#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIBINTL_H
#include <libintl.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "defaults.h"
#include "mount_davfs.h"
#include "cache.h"
#include "kernel_interface.h"
#include "coda.h"

#ifdef ENABLE_NLS
#define _(String) gettext(String)
#else
#define _(String) String
#endif


/* Constants */
/*===========*/

/* Size of buffer for communication with the kernel module. */
#define BUF_SIZE   2048

/* This constants are used by davfs2 to fill fields of struct CodaFid that
   are not used by davfs2, but are expected by coda. */   
#define DAV_VOL   0x01234567
#define DAV_VNODE 0xffffffff


/* Private global variables */
/*==========================*/

/* Buffer used for communication with the kernel module (in and out). */
static char *buf;

/* The preferred blocksize used by the local filesystem for cache files.
   Used by set_attr(). */
static unsigned int blocksize;

/* Alignment boundary of dav_node in byte.
   Used to compute file numbers from node pointers. */
static size_t alignment;

/* Send debug messages to syslog if != 0. */
int debug;


/* Private function prototypes */
/*=============================*/

/* Functions to handle upcalls fromthe kernel module. */

static uint32_t
coda_access(void);

static uint32_t
coda_close(void);

static uint32_t
coda_create(void);

static uint32_t
coda_getattr(void);

static uint32_t
coda_lookup(void);

static uint32_t
coda_mkdir(void);

static uint32_t
coda_open_by_fd(void);

static uint32_t
coda_root(void);

static uint32_t
coda_setattr(void);

static uint32_t
coda_statfs(void);

/* Functions that will do a downcall to the kernel module. */

static void
coda_flush(int device);

/* Auxiliary functions. */

static off_t
write_dir_entry(int fd, off_t off, const dav_node *node, const char *name);

static void
set_attr(struct coda_vattr *attr, const dav_node *node);


/* Public functions */
/*==================*/

void
dav_coda_loop(int device, char *mpoint, size_t bufsize, time_t idle_time,
                   dav_is_mounted_fn is_mounted,
                   volatile int *keep_on_running, int dbg)
{
    debug = dbg;
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "coda kernel version 3");

    buf = malloc(BUF_SIZE);
    if (!buf) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR),
               _("can't allocate message buffer"));
        return;
    }
    static int flush = 0;
    alignment = dav_register_kernel_interface(&write_dir_entry, &flush,
                                              &blocksize);

    struct timeval tv;
    tv.tv_sec = idle_time;
    tv.tv_usec = 0;
    time_t last_tidy_cache = time(NULL);

    while (*keep_on_running) {

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(device, &fds);
        int ret = select(device + 1, &fds, NULL, NULL, &tv);

        if (ret > 0) {
            ssize_t bytes_read = read(device, buf, BUF_SIZE);
            if (bytes_read <= 0) {
                if (bytes_read == 0 || errno == EINTR || errno == EAGAIN) {
                    if (time(NULL) < (last_tidy_cache + idle_time)) {
                        tv.tv_sec = last_tidy_cache + idle_time - time(NULL);
                    } else {
                        tv.tv_sec = 0;
                    }
                    continue;
                }
                break;
            }
        } else if (ret == 0) {
            if (!is_mounted())
                break;
            if (dav_tidy_cache() == 0) {
                tv.tv_sec = idle_time;
                last_tidy_cache = time(NULL);
            } else {
                tv.tv_sec = 0;
            }
            continue;
        } else {
            break;
        }

        struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
        struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
        uint32_t len;
        switch (ih->opcode) {
        case CODA_ROOT:
            len = coda_root();
            break;
        case CODA_OPEN_BY_FD:
            len = coda_open_by_fd();
            break;
        case CODA_OPEN:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_OPEN:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_CLOSE:
            len = coda_close();
            last_tidy_cache = 0;
            break;
        case CODA_IOCTL:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_IOCTL:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_GETATTR:
            len = coda_getattr();
            break;
        case CODA_SETATTR:
            len = coda_setattr();
            break;
        case CODA_ACCESS:
            len = coda_access();
            break;
        case CODA_LOOKUP:
            len = coda_lookup();
            break;
        case CODA_CREATE:
            len = coda_create();
            break;
        case CODA_REMOVE: {
            struct coda_remove_in *in = (struct coda_remove_in *) buf;
            dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_REMOVE:");
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  p %p, %s", node,
                       buf + in->name);
            }
            oh->result = dav_remove(node, buf + in->name, ih->uid);
            len = sizeof(struct coda_out_hdr);
            break; }
        case CODA_LINK:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_LINK:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_RENAME: {
            struct coda_rename_in *in = (struct coda_rename_in *) buf;
            dav_node *src = *((dav_node **) &(in->sourceFid.opaque[2]));
            dav_node *dst = *((dav_node **) &(in->destFid.opaque[2]));
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_RENAME:");
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  sp %p, %s", src,
                       buf + in->srcname);
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  dp %p, %s", dst,
                       buf + in->destname);
            }
            oh->result = dav_rename(src, buf + in->srcname, dst,
                                    buf + in->destname, ih->uid);
            len = sizeof(struct coda_out_hdr);
            break; }
        case CODA_MKDIR:
            len = coda_mkdir();
            break;
        case CODA_RMDIR: {
            struct coda_rmdir_in *in = (struct coda_rmdir_in *) buf;
            dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_RMDIR:");
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  p %p, %s", node,
                       buf + in->name);
            }
            oh->result = dav_rmdir(node, buf + in->name, ih->uid);
            len = sizeof(struct coda_out_hdr);
            break; }
        case CODA_SYMLINK:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_SYMLINK:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_READLINK:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_READLINK:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_FSYNC: {
            struct coda_fsync_in *in = (struct coda_fsync_in *) buf;
            dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_FSYNC:");
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p", node);
            }
            oh->result = dav_sync(node);
            len = sizeof(struct coda_out_hdr);
            break; }
        case CODA_VGET:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_VGET:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_OPEN_BY_PATH:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                       "CODA_OPEN_BY_PATH:");
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        case CODA_STATFS:
            len = coda_statfs();
            break;
        case CODA_STORE: {
            struct coda_store_in *in = (struct coda_store_in *) buf;
            dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
            if (debug) {
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_STORE:");
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p, f 0x%x",
                       node, in->flags);
            }
            oh->result = dav_sync(node);
            len = sizeof(struct coda_out_hdr);
            break; }
        case CODA_RELEASE:
            len = coda_close();
            last_tidy_cache = 0;
            break;
        default:
            if (debug)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG),
                       "UNKNOWN CODA CALL %u", ih->opcode);
            oh->result = ENOSYS;
            len = sizeof(struct coda_out_hdr);
            break;
        }

        if (debug)
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "RET: %s",
                   strerror(oh->result));

        ssize_t n = 0;
        ssize_t w = 0;
        while (n < len && w >= 0) {
            w = write(device, buf + n, len - n);
            n += w;
        }

        if (time(NULL) < (last_tidy_cache + idle_time)) {
            tv.tv_sec = last_tidy_cache + idle_time - time(NULL);
        } else {
            dav_tidy_cache();
            tv.tv_sec = idle_time;
            last_tidy_cache = time(NULL);
        }

        if (flush) {
            coda_flush(device);
            flush = 0;
        }
    }
}


/* Private functions */
/*===================*/

/* Functions to handle upcalls fromthe kernel module.
   The cache module only uses data types from the C-library. For file access,
   mode and the like it only uses symbolic constants defined in the C-library.
   So the main porpose of this functions is to translate from kernel specific
   types and constants to types and constants from the C-library, and back.
   All of this functions return the amount of data in buf that is to be
   send to the kernel module. */

static uint32_t
coda_access(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_access_in *in = (struct coda_access_in *) buf;
    dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_ACCESS:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p, f %x",
               node, in->flags);
    }

    int how = (in->flags & C_A_R_OK) ? R_OK : 0;
    how |= (in->flags & C_A_W_OK) ? W_OK : 0;
    how |= (in->flags & C_A_X_OK) ? X_OK : 0;
    how |= (in->flags & C_A_F_OK) ? F_OK : 0;
    
    oh->result = dav_access(node, ih->uid, how);

    return sizeof(struct coda_out_hdr);
}


static uint32_t
coda_close(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_close_in *in = (struct coda_close_in *) buf;
    dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    if (debug) {
        if (ih->opcode == CODA_CLOSE) {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_CLOSE:");
        } else {
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_RELEASE:");
        }
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p, f %x",
               node, in->flags);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  pid %i, pgid %i",
               ih->pid, ih->pgid);
    }

    int flags = 0;
    if ((in->flags & C_O_READ) && (in->flags & C_O_WRITE)) {
        flags = O_RDWR;
    } else if (in->flags & C_O_READ) {
        flags = O_RDONLY;
    } else if (in->flags & C_O_WRITE) {
        flags = O_WRONLY;
    }

    oh->result = dav_close(node, 0, flags, ih->pid, ih->pgid);

    return sizeof(struct coda_out_hdr);
}


static uint32_t
coda_create(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_create_in *in = (struct coda_create_in *) buf;
    dav_node *parent = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_create_out *out = (struct coda_create_out *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_CREATE:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  p %p, m %o",
               parent, in->mode);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  %s", buf + in->name);
    }

    dav_node *node = NULL;
    oh->result = dav_create(&node, parent, buf + in->name, ih->uid,
                            in->mode & DAV_A_MASK);

    if (oh->result || !node) {
        if (!oh->result)
            oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    out->VFid.opaque[0] = DAV_VOL;
    out->VFid.opaque[1] = DAV_VNODE;
    out->VFid.opaque[3] = 0;
    *((dav_node **) &(out->VFid.opaque[2])) = node;
    set_attr(&out->attr, node);

    return sizeof(struct coda_create_out);
}


static uint32_t
coda_getattr(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_getattr_in *in = (struct coda_getattr_in *) buf;
    dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_getattr_out *out = (struct coda_getattr_out *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_GETATTR:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p", node);
    }

    oh->result = dav_getattr(node, ih->uid);

    if (oh->result)
        return sizeof(struct coda_out_hdr);

    set_attr(&out->attr, node);

    return sizeof(struct coda_getattr_out);
}


static uint32_t
coda_lookup(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_lookup_in *in = (struct coda_lookup_in *) buf;
    dav_node *parent = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_lookup_out *out = (struct coda_lookup_out *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_LOOKUP:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  p %p, %s", parent,
               buf + in->name);
    }

    dav_node *node = NULL;
    oh->result = dav_lookup(&node, parent, buf + in->name, ih->uid);

    if (oh->result || !node) {
        if (!oh->result)
            oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    out->VFid.opaque[0] = DAV_VOL;
    out->VFid.opaque[1] = DAV_VNODE;
    out->VFid.opaque[3] = 0;
    *((dav_node **) &(out->VFid.opaque[2])) = node;
    out->vtype = (node->mode & S_IFDIR) ? CDT_DIR : CDT_REG;

    return sizeof(struct coda_lookup_out);
}


static uint32_t
coda_mkdir(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_mkdir_in *in = (struct coda_mkdir_in *) buf;
    dav_node *parent = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_mkdir_out *out = (struct coda_mkdir_out *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_MKDIR:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  p %p, %s", parent,
               buf + in->name);
    }

    dav_node *node = NULL;
    oh->result = dav_mkdir(&node, parent, buf + in->name, ih->uid,
                           in->attr.va_mode & DAV_A_MASK);

    if (oh->result || !node) {
        if (!oh->result)
            oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    out->VFid.opaque[0] = DAV_VOL;
    out->VFid.opaque[1] = DAV_VNODE;
    out->VFid.opaque[3] = 0;
    *((dav_node **) &(out->VFid.opaque[2])) = node;
    set_attr(&out->attr, node);

    return sizeof(struct coda_mkdir_out);
}


static uint32_t
coda_open_by_fd(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_open_by_fd_in *in = (struct coda_open_by_fd_in *) buf;
    dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_open_by_fd_out *out = (struct coda_open_by_fd_out *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_OPEN_BY_FD:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p, f %x", node,
               in->flags);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  pid %i, pgid %i",
               ih->pid, ih->pgid);
    }

    int flags = 0;
    if ((in->flags & C_O_READ) && (in->flags & C_O_WRITE)) {
        flags = O_RDWR;
    } else if (in->flags & C_O_READ) {
        flags = O_RDONLY;
    } else if (in->flags & C_O_WRITE) {
        flags = O_WRONLY;
    }
    flags |= (in->flags & C_O_TRUNC) ? O_TRUNC : 0;

    oh->result = dav_open(&out->fd, node, flags, ih->pid, ih->pgid, ih->uid, 0);

    if (oh->result || !out->fd) {
        if (!oh->result)
            oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    return sizeof(struct coda_open_by_fd_out);
}


static uint32_t
coda_root(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_root_out *out = (struct coda_root_out *) buf;
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_ROOT:");

    dav_node *node = NULL;
    oh->result = dav_root(&node, ih->uid);

    if (oh->result || !node) {
        if (!oh->result)
            oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    out->VFid.opaque[0] = DAV_VOL;
    out->VFid.opaque[1] = DAV_VNODE;
    out->VFid.opaque[3] = 0;
    *((dav_node **) &(out->VFid.opaque[2])) = node;

    return sizeof(struct coda_root_out);
}


static uint32_t
coda_setattr(void)
{
    struct coda_in_hdr *ih = (struct coda_in_hdr *) buf;
    struct coda_setattr_in *in = (struct coda_setattr_in *) buf;
    dav_node *node = *((dav_node **) &(in->VFid.opaque[2]));
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    if (debug) {
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_SETATTR:");
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  n %p, m %o", node,
               in->attr.va_mode);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  uid: %i, gid: %i",
               in->attr.va_uid, in->attr.va_gid);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  at %li, mt %li",
               in->attr.va_atime.tv_sec, in->attr.va_mtime.tv_sec);
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  ct %li, sz %llu",
               in->attr.va_ctime.tv_sec, in->attr.va_size);
    }

    oh->result = dav_setattr(node, ih->uid, in->attr.va_mode != USHRT_MAX,
                             in->attr.va_mode & DAV_A_MASK,
                             in->attr.va_uid != UINT32_MAX, in->attr.va_uid,
                             in->attr.va_gid != UINT32_MAX, in->attr.va_gid,
                             in->attr.va_atime.tv_sec != -1,
                             in->attr.va_atime.tv_sec,
                             in->attr.va_mtime.tv_sec != -1,
                             in->attr.va_mtime.tv_sec,
                             in->attr.va_size != UINT64_MAX,
                             in->attr.va_size);

    return sizeof(struct coda_out_hdr);
}


static uint32_t
coda_statfs(void)
{
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    struct coda_statfs_out *out = (struct coda_statfs_out *) buf;
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CODA_STATFS:");

    dav_stat *st = dav_statfs();
    if (!st) {
        oh->result = EIO;
        return sizeof(struct coda_out_hdr);
    }

    out->stat.f_blocks = st->blocks;
    out->stat.f_bfree = st->bavail;
    out->stat.f_bavail = st->bavail;
    out->stat.f_files = st->files;
    out->stat.f_ffree = st->ffree;

    oh->result = 0;
    return sizeof(struct coda_statfs_out);
}


/* Functions that will do a downcall to the kernel module. */

/* Downcall to inform the kernel that nodes have been added or removed. */
static void
coda_flush(int device)
{
    struct coda_out_hdr *oh = (struct coda_out_hdr *) buf;
    if (debug)
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "  CODA_FLUSH:");

    oh->opcode = CODA_FLUSH;
    oh->unique = 0;
    oh->result = 0;

    ssize_t n = 0;
    ssize_t w = 0;
    while (n < sizeof(struct coda_out_hdr) && w >= 0) {
        w = write(device, buf + n, sizeof(struct coda_out_hdr) - n);
        n += w;
    }
}


/* Auxiliary functions. */

/* Writes a struct venus_dirent to file with file descriptor fd.
   fd     : An open file descriptor to write to.
   off    : The current file size.
   name   : File name; if NULL, the last, empty entry is written.
   return value : New size of the file. -1 in case of an error. */
static off_t
write_dir_entry(int fd, off_t off, const dav_node *node, const char *name)
{
    struct venus_dirent entry;
    size_t head = offsetof(struct venus_dirent, d_name);

    if (name) {
        entry.d_fileno = (size_t) node / alignment;
        entry.d_type = (S_ISDIR(node->mode)) ? CDT_DIR : CDT_REG;
        entry.d_namlen = (strlen(name) > CODA_MAXNAMLEN)
                         ? CODA_MAXNAMLEN : strlen(name);
        entry.d_reclen = (head + entry.d_namlen +4) & ~3;
    } else {
        entry.d_fileno = 0;
        entry.d_type = 0;
        entry.d_namlen = 0;
        entry.d_reclen = (head + 4) & ~3;
    }

    size_t size = 0;
    ssize_t ret = 0;
    while (ret >= 0 && size < head) {
        ret = write(fd, (char *) &entry + size, head - size);
        size += ret;
    }
    if (size != head)
        return -1;

    ret = 0;
    while (ret >= 0 && size < (head + entry.d_namlen)) {
        ret = write(fd, name + size - head, entry.d_namlen - size + head);
        size += ret;
    }
    if (size != (head + entry.d_namlen))
        return -1;

    ret = 0;
    while (ret >= 0 && size < entry.d_reclen) {
        ret = write(fd, "\0", 1);
        size += ret;
    }
    if (size != entry.d_reclen)
        return -1;

    return off + entry.d_reclen;
}


/* Translates attribute from node to attr.
   Note: Members va_fileid, v_gen, va_flags, va_rdev and va_filerev have no
   meaning for davfs. va_fileid is treated like d_fileno in struct venus_dirent,
   the other are set to zero. The meaning of va_type is not clear at all.
   Times are only set with 1 second precision, as this is the precision of the
   last-modified time in HTTP. */
static void
set_attr(struct coda_vattr *attr, const dav_node *node)
{
    attr->va_type = 0;
    attr->va_mode = node->mode;
    if (S_ISDIR(node->mode)) {
        attr->va_nlink = node->nref;
    } else {
        attr->va_nlink = 1;
    }
    attr->va_uid = node->uid;
    attr->va_gid = node->gid;
    attr->va_fileid = (size_t) node / alignment;
    attr->va_size = node->size;
    attr->va_blocksize = blocksize;
    attr->va_atime.tv_sec = node->atime;
    attr->va_atime.tv_nsec = 0;
    attr->va_mtime.tv_sec = node->mtime;
    attr->va_mtime.tv_nsec = 0;
    attr->va_ctime.tv_sec = node->ctime;
    attr->va_ctime.tv_nsec = 0;
    attr->va_gen = 0;
    attr->va_flags = 0;
    attr->va_rdev = 0;
    attr->va_bytes = node->size;
    attr->va_filerev = 0;
}
