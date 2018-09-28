/*  cache.h: directory and file cache.
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


#ifndef DAV_CACHE_H
#define DAV_CACHE_H


/* Constants */
/*===========*/

/* A mask to separate access bits from mode. */
#define DAV_A_MASK (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX)


/* Data Types */
/*============*/

/* File descriptors for open files are stored within a dav_node in a linked
   list. As coda does not return the file descriptor when closing a file,
   this data structure contains additional information to identify the
   appropriate file descriptor. */
typedef struct dav_handle dav_handle;
struct dav_handle {
    dav_handle *next;       /* Next in the list. */
    int fd;                 /* File descriptor of the open file. */
    int flags;              /* Access mode flags only. */
    pid_t pid;              /* id of requesting process. */
    pid_t pgid;             /* Group id of requesting process. */
    uid_t uid;              /* User id of requesting process. */
};


/* A node in the cache. It represents a directory or a regular file.
   Nodes that are direct childs of the same directory-node are linked together
   by the next-pointer to a linked list.
   The hierarchical directory structure is formed by pointers to the parent
   direcotry and to the first member in the linked list of direct childs.
   Nodes are also stored in a hash table. The hash is derived from the nodes
   address. Nodes with the same hash value are linked together by table_next. */
typedef struct dav_node dav_node;
struct dav_node {
    /* The parent directory. */
    dav_node *parent;
    /* The first node in the linked list of childs. Will be NULL for files.*/
    dav_node *childs;
    /* The next node in the linked list of childs. */
    dav_node *next;
    /* The next node in the linked list of nodes with the same hash value. */
    dav_node *table_next;
    /* The unescaped absolute path of the resource on the server. This must
       conform to RFC 2518. For collections it must have a trailing slash, for
       non-collections it must not have one. */
    char *path;
    /* The name of the node (not path) without leading or trailing slash. The
       name of the root node is the empty string. Name may be different from
       the last component of path if the servers uses display-names. */
    char *name;
    /* Path of the file where the contents of the node is cached. These files
       are only created when needed, and they are deleted when there is
       information that the contents is no langer valid.
       So cache_path may be NULL.
       For directories: A file containing the directory entries.
       For regular files: A local copy of the file.
          File times are set according the values from the server when the file
          is downloaded. As long as the file is cached only dav_set_attr() may 
          changed file attributes directly, but they may be changed by open,
          read, write and close. */
    char *cache_path;
    /* Etag from the server. Set when the resource is downloaded. Used for
       conditional GET requests and to detect whether a resource has been
       changed remotely. If present it overrides information from the
       Last-Modified time (smtime). */
    char *etag;
    /* The media-type as in HTTP-header Content-Type. */
    dav_handle *handles;
    /* Size of the contents of the node.
       Files: Initially set to the value of the content-lenght header. When
          the file is open it is updated to the size of the cached file.
       Directories: Size of the file containing the directory entries. */
    off_t size;
    /* Initially set to the value of mtime. Updated by some upcalls
       Files: When a local copy exists its atime is also used for update. */
    time_t atime;
    /* Initially set to the last-modified time from the  server, or the system
       time if created locally.
       Files: When a local cache file exists updated to mtime of this cache file. 
          Used to evaluate whether a file is dirty. */
    time_t mtime;
    /* Initially set to the value of mtime. Updated by dav_setattr(). */
    time_t ctime;
    /* Files: Last-modified time from the server. Like etag frozen when the
              file is opened for writing. Used to check whether the file has
              been changed remotely. */
    time_t smtime;
    /* Time when the node has last been updated from the server. */
    time_t utime;
    /* Files: Time when the lock expires.
              0 if not locked. -1 locked infinitely. */
    time_t lock_expire;
    /* Directories: Number of subdirectories, including "." and "..".
       Files: Allways 1. */
    int nref;
    /* Files: File exists on the server. For locally created files that have
              not been put to the server it will be 0.
        Note: Some server create an empty file when locking. Maybe the RFC will
              be changed this way. */
    int remote_exists;
    /* Files: Dirty flag. Must be set, when a file is opened for writing, and
              reset, when the file is saved back. */
    int dirty;
    /* mode, uid and gid are initially set to the default values, but may be
       changed by dav_setattr(). */
    mode_t mode;
    uid_t uid;
    gid_t gid;
};


/* An item in a linked list. Each item holds a pointer to a dav_node.*/
typedef struct dav_node_item dav_node_list_item;
struct dav_node_item {
    dav_node_list_item *next;
    dav_node *node;
    int attempts;
    time_t save_at;
};


/* Returned by dav_statfs(). */
typedef struct dav_stat dav_stat;
struct dav_stat {
    uint64_t    blocks;
    uint64_t    bavail;
    uint64_t    files;
    uint64_t    ffree;
    uint64_t    n_nodes;
    off_t       bsize;
    off_t       namelen;
    time_t      utime;
};


/* Call back function that writes a directory entry to file descriptor fd.
   fd     : An open file descriptor to write to.
   off    : The current file size.
   node   : The pointer to node is taken as inode/file number (shrinked to
            fit if necessary).
   name   : File name; if NULL, the last, empty entry is written (if the
            kernel file system wants one).
   return value : New size of the file. -1 in case of an error. */
typedef off_t (*dav_write_dir_entry_fn)(int fd, off_t off, const dav_node *node,
                                        const char *name);


/* Function prototypes */
/*=====================*/

/* Initializing and closing the cache. */

/* Sets a lot of private global variables that govern the behaviour of the
   cache, taking the values from parameters.
   It registers dummy functions for the callbacks from kernel interface.
   Creates the root node and restores the nodes from the permanent cache.
   Finally it retrieves the root directory entries from the server.
   If the connection to the server fails because of authentication failure
   it prints an error message and terminates the programm. If the connection
   fails due to other reasons, it will nevertheless return with success, as the
   filesystem can be mounted, but will only get useable when the connection
   comes up.
   paramters: if not self explaining, please see mount_davfs.c, struct args. */
void
dav_init_cache(const dav_args *args, const char *mpoint);


/* Tries to write back to the server all open files that have been changed or
   newly created. If a file from cache can not be stored back to the server,
   a local backup file is created. All local copies of files and the necessary
   directories are stored in the permanent cache. A new index file of the
   permanent cache is created.
   If *got_sigterm is 1, dirty files will not be stored back to the server.
   Finally it frees all nodes. */
void
dav_close_cache(volatile int *got_sigterm);


/* Registers the kernel_interface.
   Sets pointers to the write_dir_entry_fn flush_flag.
   If blksize is not NULL, the preferred bloksize for IO is asigned.
   It returns the value of alignment. */
size_t
dav_register_kernel_interface(dav_write_dir_entry_fn write_fn, int *flush_flag,
                              unsigned int *blksize);


/* Scans the hash table for file nodes to be saved them back on the server,
   locks to be refreshed and locks to be released.
   If maximum cache size is reached, it removes the file with the lowest
   access time from the cache.
   It must be called regularly.
   The return value indicates whether another run would be useful.
   return value: 0 there is nothing left to do.
                 1 another call of dav_tidy_cache would be useful. */
int
dav_tidy_cache(void);


/* Upcalls from the kernel, via the interface module. */

/* All these functions will first check if the node addressed in the
   parameters exists.

   Common parameters (not all of this must be present in one function):
   dav_node **nodep : Used to return a pointer to a node.
   dav_node *node   : A pointer to the node that shall be acted on.
   dav_node *parent : A pointer to the parent directory of the node in question.
   const char *name : Name of the node in question. It's is just one name, not
                      a path, and without any trailing or leading slashes.
   uid_t uid        : ID of the user that requested the operation.

   Common return values:
   0       Success.
   EACCES  Access is denied to user uid according to the acces bits.
   EAGAIN  A temporary failure in the connection to the WebDAV server.
   EBUSY   The action on the node can not be performed, as somebody else uses
           it allready in a way that would collide with the requested action.
   EEXIST  Cration of a new node is requested with flag O_EXCL, but it exists.
   EINVAL  One of the parameters has an invalid value.
   EIO     Error performing I/O-operation. Usually there are problems in the
           communication with the WebDAV server.
   EISDIR  The node is a directory but should not be.
   ENOENT  The file or directory does not exist.
   ENOSPC  There is not enough space on the server.
   ENOTDIR The node is not a directory but the requested action needs it to be.
   EPERM   The reuested action is not allowed to user uid. */


/* Tests whether user uid has access described by how to node.
   int how : A bit mask describing the kind of acces. It may be any combination
             of R_OK, W_OK, X_OK and F_OK. */
int
dav_access(dav_node *node, uid_t uid, int how);


/* Closed file descriptor fd of node.
   Permissions are not checked, but flags are compared to the ones used for
   opening. If fd is 0 (coda), flags, pid and pgid are used to find the best
   matching file descriptor.
   Only access mode bits must be set in flags.*/
int
dav_close(dav_node *node, int fd, int flags, pid_t pid, pid_t pgid);


/* Creates a new file node with name name in directory parent. The file is
   locked on the server. The new node is returned in nodep.
   There must no node with name name allready exist in parent.
   The new node is owned by uid; group is the primary group of uid.  Mode is
   set to mode, but with the bits from file_umask removed.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   well as write permission for parent. */
int
dav_create(dav_node **nodep, dav_node *parent, const char *name, uid_t uid,
           mode_t mode);


/* Checks whether node exists and uid has permissions. The kernel interface
   may then translate attributes from node.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   well as read permission for parent. */
int
dav_getattr(dav_node *node, uid_t uid);


/* Searches for a node with name name in the directory parent and returns the
   node in nodep.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   well as read permission for parent. */
int
dav_lookup(dav_node **nodep, dav_node *parent, const char *name, uid_t uid);


/* Creates a new directory named name in direcotry parent. The directory must
   not yet exist. The new node is returned in nodep.
   Owner will be uid, group the primary group of uid. Mode will be mode with
   the bits from dir_umask removed.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   well as write permission for parent. */
int
dav_mkdir(dav_node **nodep, dav_node *parent, const char *name, uid_t uid,
          mode_t mode);


/* Opens file or directory node according to flags and returns file descriptor
   fd. fd, together with pid, pgid and uid, is stored in node for read, write
   and close operations.
   Only the O_ACCESSMOE, O_APPEND and O_TRUNC bits in flags will be honoured.
   O_CREATE and O_EXCL are not allowed.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   as well as read and/or write permission for node, according to the
   accessmode.
   If open_create is set to 1, permissions will not be checked. This flag must
   only be set when the call to dav_open is part of an open-call with flag
   O_CREATE. It allows dav_open to succeed if when the file mode would not
   allow this.  */
int
dav_open(int *fd, dav_node *node, int flags, pid_t pid, pid_t pgid, uid_t uid,
         int open_create);

/* Reads size bytes from file descriptor fd, starting at position offset
   and copies them into buf.
   The number of bytes read is returned in len.
   The file must be opened readonly or readwrite. */
int
dav_read(ssize_t *len, dav_node * node, int fd, char *buf, size_t size,
         off_t offset);


/* Removes file node name in directory parent from the cache and on the server.
   The file must not be locked by another WebDAV client.
   Permissions:
   uid must have execute permission for parent and all of its ancestors, as
   well as write permission for parent. */
int
dav_remove(dav_node *parent, const char *name, uid_t uid);


/* Moves file or directory src_name from directory src_parent to directory
   dst_parent and renames it to dst_name.
   If dst_name allready exists in dst_parent and is a directory, there must
   be no files opened for writing in it.
   Moves into the backup directory are not allowed.
   Permissions:
   uid must have execute permission for src_parent and dst_parent and all of
   their ancestors, as well as write permission for src_parent and
   dst_parent. */
int
dav_rename(dav_node *src_parent, const char *src_name, dav_node *dst_parent,
           const char *dst_name, uid_t uid);


/* Removes direcotry name in directory parent.
   The directory must be empty and not the local backup directory.
   uid must have execute permission for parent and all of its ancestors, as
   well as write permission for parent. */
int
dav_rmdir(dav_node *parent, const char *name, uid_t uid);


/* Returns a pointer to the root node in nodep.
   Permissions:
   uid must be root, as this function is only called when the file system is
   mounted. */
int
dav_root(dav_node **nodep, uid_t uid);


/* Changes attributes of the node.
   sm, so, ... are flags. A value of 1 indicates that the respective
   attribute is to be changed.
   Permissions:
   uid must have execute permission for parent directory of node and all of
   its ancestors.
   To change mode, owner, or gid, uid must be owner of the node or root.
   To change atime, mtime or size, uid must have write permission for
   node.
   To change gid, uid must be member of the new group or root.
   Note: This attributes, except size and the execute bit of mode, are only
         changed locally and not on the server. */
int
dav_setattr(dav_node *node, uid_t uid, int sm, mode_t mode, int so,
            uid_t owner, int sg, gid_t gid, int sat, time_t atime, int smt,
            time_t mtime, int ssz, off_t size);


/* Returns struct dav_stat. If the server does not provide theinformation
   it will contain fake data.
   No permissions necessary. */
dav_stat *
dav_statfs(void);


/* Calls fsync() for all filedescriptors of node, that are not read only.
   No permissions are checked. */
int
dav_sync(dav_node *node);


/* Writes size bytes from buf to file descriptor fd, starting at position
   offset.
   The number of bytes written is returned in len.
   The file must be opened writeonly or readwrite. */
int
dav_write(size_t *written, dav_node * node, int fd, char *buf, size_t size,
          off_t offset);


#endif /* DAV_CACHE_H */
