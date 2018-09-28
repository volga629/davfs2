# davfs2 macros
# Copyright (C) 2006, 2007, 2008 Werner Baumann
#
# This file is part of davfs2.
#
# davfs2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# davfs2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with davfs2; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. */


# Check for an external Neon library
# Looks for the binary 'neon-config'. If a directory is given with
# --with-neon=, it looks in the bin-subdirectory of this, else it uses
# AC_PATH_PROG to find 'neon-config'.
# If found, it sets variable NRON_CONFIG and calls NEON_USE_EXTERNAL.
# if not found, or if NEON_USE_EXTERNAL does not set neon_got_library
# to yes, configration is stopped with an error message.

AC_DEFUN([DAV_CHECK_NEON],[

    AC_ARG_WITH(neon,
      [  --with-neon[[=DIR]]       specify location of neon library],
      [case $withval in
          yes|no) neon_ext_path= ;;
          *) neon_ext_path=$withval ;;
      esac;],
      [neon_ext_path=]
    )

    neon_got_library=no
    if test "x$neon_ext_path" = "x"; then
        AC_PATH_PROG([NEON_CONFIG], neon-config, none)
        if test "x${NEON_CONFIG}" = "xnone"; then
            AC_MSG_NOTICE([no external neon library found])
        elif test -x "${NEON_CONFIG}"; then
            NEON_USE_EXTERNAL
        else
            AC_MSG_NOTICE([ignoring non-executable ${NEON_CONFIG}])
        fi
    else
        AC_MSG_CHECKING([for neon library in $neon_ext_path])
        NEON_CONFIG="$neon_ext_path/bin/neon-config"
        if test -x ${NEON_CONFIG}; then
            AC_MSG_RESULT([found])
            NEON_USE_EXTERNAL
        else
            AC_MSG_RESULT([not found])
        fi
    fi

    if test "$neon_got_library" = "no"; then 
        AC_MSG_ERROR(could not find neon)
    fi

    AC_SUBST(NEON_LIBS)
])


# Setting uid and gid, mount.davfs will run as, and some pathes.

AC_DEFUN([DAV_DEFAULTS],[

    AC_ARG_VAR([dav_user],
        [if invoked by root, mount.davfs runs as this user [davfs2]])
    if test -z "$dav_user"; then dav_user="davfs2"; fi

    AC_ARG_VAR([dav_group],
        [the group, the mount.davfs daemon belongs to [davfs2]])
    if test -z "$dav_group"; then dav_group="davfs2"; fi

    AC_ARG_VAR([ssbindir],
        [where mount will search for mount-helpers [/sbin]])
    if test -z "$ssbindir"; then ssbindir="/sbin"; fi

    AC_ARG_VAR([dav_localstatedir],
        [directory to store pid-files in [/var/run]])
    if test -z "$dav_localstatedir"; then dav_localstatedir="/var/run"; fi

    AC_ARG_VAR([dav_syscachedir],
        [cache directory [/var/cache]])
    if test -z "$dav_syscachedir"; then dav_syscachedir="/var/cache"; fi
])


# Select the languages for documentation and messages
# The langusges available for documentation ar taken from man/po4a.conf.
# If variable LINGUAS is set, only languages that are available and
# mentioned in LINGUAS are selected, otherwise all available languages
# are selected. Substitutes $dav_linguas in output files with this value.
# The languages for messages are selected by po.m4 macros, that use the
# same variable LINGUAS.

AC_DEFUN([DAV_LINGUAS],[

    AC_ARG_VAR([LINGUAS],
        [select languages for messages and documentation])
    dav_desired_linguas="${LINGUAS-%UNSET%}"

    dav_all_linguas=
    if test -f "man/po4a.conf"; then
        dav_all_linguas="`cat 'man/po4a.conf' | grep '[po4a_langs]' | sed 's/.po4a_langs.//'`" 
    fi

    dav_linguas=
    if test "$dav_desired_linguas" == "%UNSET%"; then
        dav_linguas="$dav_all_linguas"
    else
        for dav_lingua in $dav_desired_linguas; do
            case "$dav_all_linguas" in
                *"$dav_lingua"*) dav_linguas="$dav_linguas $dav_lingua";;
            esac
        done
    fi

    AC_SUBST([dav_linguas])
])


# If Neon supports large files, it calls AC_SYS_LARGEFILE.
# dav_lfs is set to yes, if neon and the system support large files.

AC_DEFUN([DAV_LFS],[

    AC_REQUIRE([DAV_CHECK_NEON])dnl

    if test "$ne_LFS_message" = "LFS is supported by neon"; then
        AC_SYS_LARGEFILE
    fi

    if test "$ac_cv_sys_file_offset_bits" = "64"; then
        dav_lfs=yes
    else
        dav_lfs=no
    fi
])


# Output summary

AC_DEFUN([DAV_MESSAGE],[

    if test "$USE_NLS" = "yes"; then
        dav_nls=${gt_source}
    else
        dav_nls=no
    fi

cat<<EOF

Configuration for building davfs2 AC_PACKAGE_VERSION:

  Install Prefix:            ${prefix}
  Compiler:                  ${CC}
  Large File Support:        ${dav_lfs}
  Neon Library:              ${neon_library_message}
                             ${ne_SSL_message}
  National Language Support: ${dav_nls}

EOF
])
