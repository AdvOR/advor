/* orconfig.h.  Generated from orconfig.h.in by configure.  */
/* orconfig.h.in.  Generated from configure.in by autoheader.  */

/* tor's configuration directory */
#define CONFDIR "/usr/local/etc/tor"

/* Enable dmalloc's malloc function check */
/* #undef DMALLOC_FUNC_CHECK */

/* Defined if we try to use freelists for buffer RAM chunks */
#define ENABLE_BUF_FREELISTS 1

/* Defined if we try to use the pool allocator for queued cells */
#define ENABLE_CELL_POOL 1

/* Defined if we try to collect per-country statistics */
/* #undef ENABLE_GEOIP_STATS */

/* Defined if we will try to use multithreading */
#define ENABLE_THREADS 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the <dmalloc.h> header file. */
/* #undef HAVE_DMALLOC_H */

/* Define to 1 if you have the `dmalloc_strdup' function. */
/* #undef HAVE_DMALLOC_STRDUP */

/* Define to 1 if you have the `dmalloc_strndup' function. */
/* #undef HAVE_DMALLOC_STRNDUP */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `event_get_method' function. */
#define HAVE_EVENT_GET_METHOD 1

/* Define to 1 if you have the `event_get_version' function. */
#define HAVE_EVENT_GET_VERSION 1

/* Define to 1 if you have the `event_set_log_callback' function. */
#define HAVE_EVENT_SET_LOG_CALLBACK 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
/* #undef HAVE_FSEEKO */

/* Define to 1 if you have the `ftello' function. */
/* #undef HAVE_FTELLO */

/* Define to 1 if you have the `ftime' function. */
#define HAVE_FTIME 1

/* Define to 1 if you have the `getaddrinfo' function. */
/* #undef HAVE_GETADDRINFO */

/* Define this if you have any gethostbyname_r() */
/* #undef HAVE_GETHOSTBYNAME_R */

/* Define this if gethostbyname_r takes 3 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_3_ARG */

/* Define this if gethostbyname_r takes 5 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_5_ARG */

/* Define this if gethostbyname_r takes 6 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_6_ARG */

/* Define to 1 if you have the `getrlimit' function. */
/* #undef HAVE_GETRLIMIT */

/* Define to 1 if you have the `gettimeofday' function. */
/* #undef HAVE_GETTIMEOFDAY */

/* Define to 1 if you have the `gmtime_r' function. */
/* #undef HAVE_GMTIME_R */

/* Define to 1 if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* Define to 1 if you have the `inet_aton' function. */
/* #undef HAVE_INET_ATON */

/* Define to 1 if you have the `inet_ntop' function. */
/* #undef HAVE_INET_NTOP */

/* Define to 1 if you have the `inet_pton' function. */
/* #undef HAVE_INET_PTON */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/netfilter_ipv4.h> header file. */
/* #undef HAVE_LINUX_NETFILTER_IPV4_H */

/* Define to 1 if you have the <linux/types.h> header file. */
/* #undef HAVE_LINUX_TYPES_H */

/* Define to 1 if you have the `localtime_r' function. */
/* #undef HAVE_LOCALTIME_R */

/* Define to 1 if you have the <machine/limits.h> header file. */
/* #undef HAVE_MACHINE_LIMITS_H */

/* Defined if the compiler supports __FUNCTION__ */
#define HAVE_MACRO__FUNCTION__ 1

/* Defined if the compiler supports __FUNC__ */
/* #undef HAVE_MACRO__FUNC__ */

/* Defined if the compiler supports __func__ */
#define HAVE_MACRO__func__ 1

/* Define to 1 if you have the `mallinfo' function. */
/* #undef HAVE_MALLINFO */

/* Define to 1 if you have the `malloc_good_size' function. */
/* #undef HAVE_MALLOC_GOOD_SIZE */

/* Defined if the prototype for malloc_good_size seems to be present. */
/* #undef HAVE_MALLOC_GOOD_SIZE_PROTOTYPE */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <malloc/malloc.h> header file. */
/* #undef HAVE_MALLOC_MALLOC_H */

/* Define to 1 if you have the `malloc_usable_size' function. */
/* #undef HAVE_MALLOC_USABLE_SIZE */

/* Define to 1 if you have the `memmem' function. */
/* #undef HAVE_MEMMEM */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in6.h> header file. */
/* #undef HAVE_NETINET_IN6_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if you have the <net/if.h> header file. */
/* #undef HAVE_NET_IF_H */

/* Define to 1 if you have the <net/pfvar.h> header file. */
/* #undef HAVE_NET_PFVAR_H */

/* Define to 1 if you have the `pthread_create' function. */
/* #undef HAVE_PTHREAD_CREATE */

/* Define to 1 if you have the <pthread.h> header file. */
/* #undef HAVE_PTHREAD_H */

/* Define to 1 if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define to 1 if you have the `readv' function. */
/* #undef HAVE_READV */

/* Define to 1 if the system has the type `rlim_t'. */
/* #undef HAVE_RLIM_T */

/* Define to 1 if the system has the type `sa_family_t'. */
/* #undef HAVE_SA_FAMILY_T */

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `socketpair' function. */
/* #undef HAVE_SOCKETPAIR */

/* Define to 1 if the system has the type `ssize_t'. */
#define HAVE_SSIZE_T 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strptime' function. */
/* #undef HAVE_STRPTIME */

/* Define to 1 if you have the `strtok_r' function. */
/* #undef HAVE_STRTOK_R */

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if the system has the type `struct in6_addr'. */
#define HAVE_STRUCT_IN6_ADDR 1

/* Define to 1 if `s6_addr16' is member of `struct in6_addr'. */
#define HAVE_STRUCT_IN6_ADDR_S6_ADDR16 1

/* Define to 1 if `s6_addr32' is member of `struct in6_addr'. */
#define HAVE_STRUCT_IN6_ADDR_S6_ADDR32 1

/* Define to 1 if the system has the type `struct sockaddr_in6'. */
#define HAVE_STRUCT_SOCKADDR_IN6 1

/* Define to 1 if the system has the type `struct sockaddr_storage'. */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define to 1 if `tv_sec' is member of `struct timeval'. */
#define HAVE_STRUCT_TIMEVAL_TV_SEC 1

/* Define to 1 if you have the <syslog.h> header file. */
/* #undef HAVE_SYSLOG_H */

/* Define to 1 if you have the <sys/fcntl.h> header file. */
#define HAVE_SYS_FCNTL_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
/* #undef HAVE_SYS_IOCTL_H */

/* Define to 1 if you have the <sys/limits.h> header file. */
/* #undef HAVE_SYS_LIMITS_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
/* #undef HAVE_SYS_RESOURCE_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syslimits.h> header file. */
/* #undef HAVE_SYS_SYSLIMITS_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #undef HAVE_SYS_UIO_H */

/* Define to 1 if you have the <sys/un.h> header file. */
/* #undef HAVE_SYS_UN_H */

/* Define to 1 if you have the <sys/utime.h> header file. */
#define HAVE_SYS_UTIME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
/* #undef HAVE_SYS_WAIT_H */

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if the system has the type `uint'. */
/* #undef HAVE_UINT */

/* Define to 1 if you have the `uname' function. */
/* #undef HAVE_UNAME */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if the system has the type `u_char'. */
/* #undef HAVE_U_CHAR */

/* Define to 1 if you have the `writev' function. */
/* #undef HAVE_WRITEV */

/* Defined if we want to keep track of how much of each kind of resource we
   download. */
/* #undef INSTRUMENT_DOWNLOADS */

/* name of the syslog facility */
#define LOGFACILITY LOG_DAEMON

/* Define to 1 iff malloc(0) returns a pointer */
#define MALLOC_ZERO_WORKS 1

/* Define to 1 if we are building for Windows. */
#define MS_WINDOWS 1

/* Define to 1 iff memset(0) sets pointers to NULL */
#define NULL_REP_IS_ZERO_BYTES 1

/* "Define to handle pf on OpenBSD properly" */
/* #undef OPENBSD */

/* Name of package */
#define PACKAGE "tor"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* The size of `cell_t', as computed by sizeof. */
#define SIZEOF_CELL_T 0

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `int16_t', as computed by sizeof. */
#define SIZEOF_INT16_T 2

/* The size of `int32_t', as computed by sizeof. */
#define SIZEOF_INT32_T 4

/* The size of `int64_t', as computed by sizeof. */
#define SIZEOF_INT64_T 8

/* The size of `int8_t', as computed by sizeof. */
#define SIZEOF_INT8_T 1

/* The size of `intptr_t', as computed by sizeof. */
#define SIZEOF_INTPTR_T 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 4

/* The size of `socklen_t', as computed by sizeof. */
#define SIZEOF_SOCKLEN_T 0

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 4

/* The size of `uint16_t', as computed by sizeof. */
#define SIZEOF_UINT16_T 2

/* The size of `uint32_t', as computed by sizeof. */
#define SIZEOF_UINT32_T 4

/* The size of `uint64_t', as computed by sizeof. */
#define SIZEOF_UINT64_T 8

/* The size of `uint8_t', as computed by sizeof. */
#define SIZEOF_UINT8_T 1

/* The size of `uintptr_t', as computed by sizeof. */
#define SIZEOF_UINTPTR_T 4

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 4

/* The size of `__int64', as computed by sizeof. */
#define SIZEOF___INT64 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 iff time_t is signed */
#define TIME_T_IS_SIGNED 1

/* Debug memory allocation library */
/* #undef USE_DMALLOC */

/* "Define to enable transparent proxy support" */
/* #undef USE_TRANSPARENT */

/* Define to 1 iff we represent negative integers with two's complement */
#define USING_TWOS_COMPLEMENT 1

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define on some platforms to activate x_r() functions in time.h */
/* #undef _REENTRANT */

/* Define to `unsigned short' if <sys/types.h> does not define. */
#define u_int16_t unsigned short

/* Define to `unsigned long' if <sys/types.h> does not define. */
#define u_int32_t unsigned long

/* Define to `unsigned long long' if <sys/types.h> does not define. */
#define u_int64_t unsigned long long

/* Define to `unsigned char' if <sys/types.h> does not define. */
#define u_int8_t unsigned char
#define HAVE_EVENT2_EVENT_H 1
#define HAVE_EVENT_BASE_LOOPEXIT 1
#define HAVE_EVENT2_DNS_H 1
