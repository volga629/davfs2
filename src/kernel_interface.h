/*  kernel_interface.h: interface to fuse and coda kernel mocule.
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


#ifndef DAV_KERNEL_INTERFACE_H
#define DAV_KERNEL_INTERFACE_H


/* Function type definitions */
/*===========================*/

/* Call back function to be passed to dav_init_kernel_interface(). Will be
   called to see whether the file system is still mounted.
   return value : 1 is mounted, 0 is not mounted. */
typedef int (*dav_is_mounted_fn)(void);


/* Typedef of the message loop of the specific kernel interfaces. The real
   function will be returned by dav_init_kernel_interface().
   device          : File descriptor of the open fuse device.
   mpoint          : String with the name of the mount point.
   buf_size        : Size of the buffer for communication with the kernel
                     module.
   idle_t          : Time to wait for upcalls before calling dav_tidy_cache().
   is_mounted_fn   : Call back function to check if still mounted.
   keep_on_running : Pointer to run flag.
   dbg             : send debug messages to syslog if dbg != 0 */
typedef void (*dav_run_msgloop_fn)(int device, char *mpoint, size_t bufsize,
                                   time_t idle_time,
                                   dav_is_mounted_fn is_mounted,
                                   volatile int *keep_on_running, int dbg);


/* Function prototypes */
/*=====================*/

/* Opens the device for communication with the kernel file system, if possible
   mounts the file system and updates the interface data (dev,
   dav_ran_msgloop_fn, mdata, kernel_fs and buf_size).
   In case of an error it prints an error message and terminates the program.
   dev       : File descriptor of the open device for communication with the
               kernel file system.
   msg_loop  : The specific message loop function that will process the kernel
               upcalls.
   mdata     : That mount data that will be passed to the mount function.
   kernel_fs : Type of the kernel file system to us (fuse or coda). If this
               does not work, the other file system will be tried. The name
               of the file system that is really used is returned.
               If NULL, fuse is tried first.
   buf_size  : Size of the buffer for communication with the kernel file system
               (fuse only). The size passed to this function is checked against
               the requirements of the kernel fs and updated if necessary.
   url       : Server url.
   mpoint    : Mount point.
   mopts     : Mount options.
   owner     : The owner of the file system (fuse only).
   group     : Group the file system belongs to (fuse only).
   mode      : Mode of the root node (fuse only).
   return value : 0: the file system has not yet been mounted
                  1: the file system has been mounted successfully. */
int
dav_init_kernel_interface(int *dev, dav_run_msgloop_fn *msg_loop, void **mdata,
                          char **kernel_fs, size_t *buf_size, const char *url,
                          const char *mpoint, const dav_args *args);


/* Message loop for coda kernel module CODA_KERNEL_VERSION 3.
   Parameters see dav_run_msgloop_fn(). */
void dav_coda_loop(int device, char *mpoint, size_t bufsize, time_t idle_time,
                   dav_is_mounted_fn is_mounted,
                   volatile int *keep_on_running, int dbg);


/* Message loop for fuse kernel module with major number 7.
   Parameters see dav_run_msgloop_fn(). */
void
dav_fuse_loop(int device, char *mpoint, size_t bufsize, time_t idle_time,
              dav_is_mounted_fn is_mounted, volatile int *keep_on_running,
              int dbg);


#endif /* DAV_KERNEL_INTERFACE_H */
