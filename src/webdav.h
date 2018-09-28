/*  webdav.h: send requests to the WebDAV server.
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


#ifndef DAV_WEBDAV_H
#define DAV_WEBDAV_H


/* Data Types */
/*============*/

/* This structure holds the properties retrieved from the server.
   Usually a linked list of these is returned by dav_get_collection().
   Unused pointers should be set to NULL, integer types to 0. */
typedef struct dav_props dav_props;
struct dav_props {
    char *path;         /* The unescaped path of the resource. */
    char *name;         /* The name of the file or directory. Only the last
                           component (no path), no slashes. */
    char *etag;         /* The etag string, including quotation characters,
                           but without the mark for weak etags. */
    off_t size;         /* File size in bytes (regular files only). */
    time_t mtime;       /* Date of last modification. */
    int is_dir;         /* Boolean; 1 if a directory. */
    int is_exec;        /* -1 if not specified; 1 is executeable;
                           0 not executeable. */
    dav_props *next;    /* Next in the list. */
};


/* Function prototypes */
/*=====================*/

/* Creates and initializes a neon_session, using configuration information
   given as parameters, and checks the WebDAV class of the server.
   If the server does not support class 2, locking is disabled.
   It must only be initialized once, as it depends on global variables.
   If an error occurs, the program is terminated.
   paramters: if not self explaining, please see mount_davfs.h, struct args. */
void
dav_init_webdav(const dav_args* args);


/* Does an OPTIONS request to check the server capabilities. In case of
   success it will set the global variable initialized. If the server
   does not support locks, it will remove the lockstore and set locks
   to NULL.
   path : Path to the root collection.
   return value : 0 on success or an apropriate error code. */
int
dav_init_connection(const char *path);


/* Releases all locks (if possible) and closes the session.
   Does not free memory held by the session. */
void
dav_close_webdav(void);


/* Converts the character encoding of s from and to the local encoding.
   Converter handles are taken from global variables from_utf_8, to_utf_8,
   from_server_enc and to_server_enc.
   If no conversion is necessary, it just returns a copy of s.
   name : string to be converted.
   return value : the converted string, newly allocated. */
char *
dav_conv_from_utf_8(const char *s);
char *
dav_conv_to_utf_8(const char *s);
char *
dav_conv_from_server_enc(const char *s);
char *
dav_conv_to_server_enc(const char *s);


/* Deletes file path on the server.
   On success locks for this file are removed from the lock store.
   path   : Absolute path of the file.
   expire : If not 0, the resource is assumed to be locked and the lock
            will be removed after successful delete.
   return value : 0 on success; an appropriate file error code otherwise. */
int
dav_delete(const char *path, time_t *expire);


/* Deletes collection path on the server.
   path : Absolute path of the collection.
   return value : 0 on success; an appropriate file error code otherwise. */
int dav_delete_dir(const char *path);


/* Frees any resources held by props and finally frees props. */
void
dav_delete_props(dav_props *props);


/* Retrieves properties for the directory named by path and its
   direct childs (depth 1) from the server.
   The properties are returned as a linked list of dav_props. If successfull,
   this list contains at least one entry (the directory itself; its name is
   the empty string). The calling function is responsible for freeing the list
   and all the strings included.
   path   : The absolute path of the directory with trailing slash.
   *props : Will point to the list of properties on return. NULL in case of
            an error.
   return value : 0 on success; an appropriate file error code otherwise. */
int
dav_get_collection(const char *path, dav_props **props);


/* Fetches file path from the server, stores it in cache_path and updates
   size, etag and mtime.
   If etag and/or mtime are supplied, a conditional GET will be performed.
   If the file has not been modified on the server, size, etag, mtime and
   mime will not be changed.
   If the GET request fails none of size, etag and mtime are changed.
   cache_path : Name of the cache file to store the file in.
   path       : Absolute path of the file on the server.
   size       : Points to the size of the cached file and will be updated if a
                new version of the file is retrieved.
   etag       : Points to the ETag string of the cached version. If a new
                version of the file is retrieved this will be replaced by the
                new ETag value. May be NULL or point to NULL.
   mtime      : Points to the Last-Modified value of the cached version. Will
                be updated if a new version of the file is retrieved.
                May be NULL.
   modified   : Points to a flag that will be set 1 if the file cache_path
                has been replaced by a new version. May be NULL.
   return value : 0 on success; an appropriate file error code otherwise.
                  Not-Modified counts as success. */
int
dav_get_file(const char *path, const char *cache_path, off_t *size,
             char **etag, time_t *mtime, int *modified);


/* Returns the error string from the last WebDAV request.
   Note: This will not be usefull in any case, because the last function
         called may have done more then one request (e.g. an additional
         lock discover. But it is usefull for dav_get_collection(). */
const char *
dav_get_webdav_error(void);


/* Tests for the existence of file path and uptdates etag, mtime and length.
   In case of an error etag and mtime are not changed. If the server does not
   send ETag or Last-Modified the corresponding value will not be changed.
   path  : absolute path of the file on the server.
   etag  : Points to the Etag; will be updated on success. May be NULL.
   length: Points to length; will be updated on success. May be NULL.
   mime  : Points to mime_type; will be updated on success. May be NULL.
   return value : 0 if the file exists; an appropriate file error code
                  otherwise. */
int
dav_head(const char *path, char **etag, time_t *mtime, off_t *length);


/* Locks the file path on the server with an excluse write lock and updates
   expire and exists. If a lock for path allready exists it will be refreshed.
   On success expire will be updated to the time when the lock expires.
   If the file does not yet exist and server creates a new file (as opposed to
   creating a locked-null-resource) exists will be set to 1.
   If the file is already locked, but not by this instance of davfs2, it will
   try if the lock is from the same user using davfs2, and if so, to use this
   lock.
   If it can't get a lock it will return an appropriate error code and set
   expire to 0.
   If the session is initialized with the nolocks option, it does nothing,
   but allways returns success and sets expire to 0.
   path    : absolute path of the file on the server.
   expire  : Points to the time when the lock expires. 0 if not locked.
             Will be updated.
   exists  : Indicates whether the file exists on the server. If the server
             responds with "201 CREATED", it will be set to 1.
   return value : 0 on success; an appropriate file error code
                  otherwise. */
int
dav_lock(const char *path, time_t *expire, int *exists);


/* Refreshes the lock for file path and updates expire.
   If no lock can be found for path expire is set to 0.
   If it can't refresh the lock it will do nothing.
   path   : Absolute path of the file on the server.
   expire : The time when the lock expires, will be updated. */
void dav_lock_refresh(const char *path, time_t *expire);


/* Creates a new collection on the server.
   path : Absolute path of the new collection on the server.
   return value : 0 on success; an appropriate file error code otherwise. */
int
dav_make_collection(const char *path);


/* Moves resource src to the new name/location dst.
   src : Absolute path of the resource on the server.
   dst : New absolute path of the resource on the server.
   return value : 0 on success; an appropriate file error code otherwise. */
int
dav_move(const char *src, const char *dst);


/* Stores the contents of file cache_path on the server location path and
   updates the value of exists, etag and mtime.
   Before uploading the file it tests whether the file on the server has been
   changed (compared to the values of exists, etag and mtime). If it has been
   changed the file will *not* be uploaded and an error returned instead.
   Sometimes a lock may be discovered during dav_put(). In this case expire
   will be updated.
   path       : Absolute path of the file on the server.
   cache_path : Name of the local file to be stored on the server.
   exists     : Indicates whether the file exists on the server. Used to check
                for changes on the server. If the upload is successful it will
                be set to 1.
   etag       : The value of ETag used to check for changes on the server.
                Updated on success. May be NULL.
   mime       : The value of mime_type. Updated on successMay be NULL.
                If a mime_type is set, the Content-Type header will be sent.
   execute    : if 1 set execute property, else no change of execute property.
   return value : 0 on success; an appropriate file error code otherwise. */
int
dav_put(const char *path, const char *cache_path, int *exists, time_t *expire,
        char **etag, time_t *mtime, int execute);

/* Makes a PROPFIND request for path to get quota information (RFC 4331)
   and places them in available and used.
   If quota information is not available, an error is returned and
   available and used are not changed. */ 
int
dav_quota(const char *path, uint64_t *available, uint64_t *used);


/* Sets or resets the execute property of file path.
   path : Absolute path of the file on the server.
   set  : boolean value; 0 reset execute property; 1 set execute property. */
int
dav_set_execute(const char *path, int set);


/* Tells webdav that no more terminal is available, so errors can only
 * be logged. Before this function is invoced webdav tries to 
 * communicate with the user when problems occur. */
void
dav_set_no_terminal(void);


/* Releases the lock on file path on the serverand sets expire to 0.
   path : Absolute path of the file on the server.
   return value : 0 if no error occured; an appropriate file error code
                  otherwise. */
int
dav_unlock(const char *path, time_t *expire);


#endif /* DAV_WEBDAV_H */
