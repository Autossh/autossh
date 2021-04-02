#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(autossh, 1.4, [Carson Harding <harding@motd.ca>])
AC_REVISION($Revision: 1.2 $)
AC_CONFIG_SRCDIR([daemon.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
# Add -Wall for gcc
if test "$ac_compiler_gnu" = "yes"; then
	CFLAGS="$CFLAGS -Wall"
fi

AC_ARG_WITH(ssh,
	AC_HELP_STRING([--with-ssh=ARG], [specify path to ssh executable]),
	[ac_cv_path_ssh=$withval], []
)
if test -z "$ac_cv_path_ssh"; then
	AC_PATH_PROG([ssh], [ssh])
fi
if test -n "$ac_cv_path_ssh"; then
	AC_DEFINE_UNQUOTED(
		PATH_SSH, "$ac_cv_path_ssh",
		[Set this to the path to your ssh program.]
	)
else
	AC_MSG_ERROR([ssh program not found! Modify PATH, or use --with-ssh.])
fi
path_ssh="$ac_cv_path_ssh"
AC_SUBST(path_ssh)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h])
AC_CHECK_HEADERS([netinet/in.h paths.h stdlib.h string.h sys/socket.h])
AC_CHECK_HEADERS([sys/time.h syslog.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_VOLATILE
AC_CHECK_TYPE(socklen_t,
	AC_DEFINE(HAVE_SOCKLEN_T, 1, [Define to 1 if you have socklen_t.]),
	[],
	[
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
	]
)
AC_CHECK_TYPE([struct addrinfo],
	AC_DEFINE(HAVE_ADDRINFO, 1,  [Define to 1 if you have struct addrinfo.]),
	[],
	[
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
	]
)
AC_CHECK_TYPE(u_int16_t,
	AC_DEFINE(HAVE_U_INT16_T, 1, [Define to 1 if you have u_int16_t.]),
	[], [
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
]
)
AC_CHECK_TYPE(uint16_t,
	AC_DEFINE(HAVE_UINT16_T, 1, [Define to 1 if you have uint16_t.]),
	[],
	[
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
	]
)
AC_CHECK_DECL(LOG_PERROR,
	AC_DEFINE(HAVE_LOG_PERROR, 1, [Define to 1 if you have LOG_PERROR.]),
	[],
	[
#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif
	]
)


# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm daemon dup2 gethostbyname gettimeofday memmove])
AC_CHECK_FUNCS([memset poll select setproctitle socket strchr strerror])
AC_CHECK_FUNCS([strncasecmp strtoul uname vsyslog])

AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, connect)

# Other checks

# Copyright (c) 1999-2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
AC_CACHE_CHECK([if libc defines __progname], ac_cv_libc_defines___progname, [
	AC_TRY_LINK([],
		[ extern char *__progname; printf("%s", __progname); ],
		[ ac_cv_libc_defines___progname="yes" ],
		[ ac_cv_libc_defines___progname="no" ]
	)
])
if test "x$ac_cv_libc_defines___progname" = "xyes" ; then
	AC_DEFINE(HAVE___PROGNAME, 1, [Define if libc defines __progname])
fi

AC_OUTPUT
