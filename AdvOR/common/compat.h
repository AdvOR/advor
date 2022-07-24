/* Copyright (c) 2003-2004, Roger Dingledinex
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_COMPAT_H
#define _TOR_COMPAT_H

#include "orconfig.h"
#include "torint.h"
#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x400
#endif
#define WIN32_LEAN_AND_MEAN
#if defined(_MSC_VER) && (_MSC_VER < 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#ifndef _TOR_TLS_C
#include <ws2tcpip.h>
#endif
#endif
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#if defined(HAVE_PTHREAD_H) && !defined(MS_WINDOWS)
#include <pthread.h>
#endif
#include <stdarg.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#ifndef NULL_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent NULL as zero. We can't cope."
#endif

#if 'a'!=97 || 'z'!=122 || 'A'!=65 || ' '!=32
#error "It seems that you encode characters in something other than ASCII."
#endif

/* ===== Compiler compatibility */

/* GCC can check printf types on arbitrary functions. */
/** Expands to a syntactically valid empty statement, explicitly (void)ing its
 * argument. */
#define STMT_VOID(a) while (0) { (void)(a); }
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format(printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif

/* inline is __inline on windows. */
#ifdef MS_WINDOWS
#define INLINE __inline
#else
#define INLINE inline
#endif

/* Try to get a reasonable __func__ substitute in place. */
#if defined(_MSC_VER)
/* MSVC compilers before VC7 don't have __func__ at all; later ones call it
 * __FUNCTION__. */
#if _MSC_VER < 1300
#define __func__ "???"
#else
#define __func__ __FUNCTION__
#endif

#else
/* For platforms where autoconf works, make sure __func__ is defined
 * sanely. */
#ifndef HAVE_MACRO__func__
#ifdef HAVE_MACRO__FUNCTION__
#define __func__ __FUNCTION__
#elif HAVE_MACRO__FUNC__
#define __func__ __FUNC__
#else
#define __func__ "???"
#endif
#endif /* ifndef MAVE_MACRO__func__ */
#endif /* if not windows */

#if defined(_MSC_VER) && (_MSC_VER < 1300)
/* MSVC versions before 7 apparently don't believe that you can cast uint64_t
 * to double and really mean it. */
extern INLINE double U64_TO_DBL(uint64_t x) {
  int64_t i = (int64_t) x;
  return (i < 0) ? ((double) INT64_MAX) : (double) i;
}
#define DBL_TO_U64(x) ((uint64_t)(int64_t) (x))
#else
#define U64_TO_DBL(x) ((double) (x))
#define DBL_TO_U64(x) ((uint64_t) (x))
#endif

/* GCC has several useful attributes. */
#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_PURE __attribute__((pure))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
/* Alas, nonnull is not at present a good idea for us.  We'd like to get
 * warnings when we pass NULL where we shouldn't (which nonnull does, albeit
 * spottily), but we don't want to tell the compiler to make optimizations
 * with the assumption that the argument can't be NULL (since this would make
 * many of our checks go away, and make our code less robust against
 * programming errors).  Unfortunately, nonnull currently does both of these
 * things, and there's no good way to split them up.
 *
 * #define ATTR_NONNULL(x) __attribute__((nonnull x)) */
#define ATTR_NONNULL(x)

/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true.
 *
 * In other words, "if (PREDICT_LIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will be taken most of the
 * time.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_LIKELY(exp) __builtin_expect(!!(exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false.
 *
 * In other words, "if (PREDICT_UNLIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will usually not be
 * taken.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_UNLIKELY(exp) __builtin_expect(!!(exp), 0)
#else
#define ATTR_NORETURN
#define ATTR_PURE
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif

/** Expands to a syntactically valid empty statement.  */
#define STMT_NIL (void)0

#ifdef __GNUC__
/** STMT_BEGIN and STMT_END are used to wrap blocks inside macros so that
 * the macro can be used as if it were a single C statement. */
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif

/* ===== String compatibility */
#ifdef MS_WINDOWS
/* Windows names string functions differently from most other platforms. */
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif

#ifdef _MSC_VER
/** Casts the uint64_t value in <b>a</b> to the right type for an argument
 * to printf. */
#define U64_PRINTF_ARG(a) (a)
/** Casts the uint64_t* value in <b>a</b> to the right type for an argument
 * to scanf. */
#define U64_SCANF_ARG(a) (a)
/** Expands to a literal uint64_t-typed constant for the value <b>n</b>. */
#define U64_LITERAL(n) (n ## ui64)
#define I64_PRINTF_ARG(a) (a)
#define I64_SCANF_ARG(a) (a)
#define I64_LITERAL(n) (n ## i64)
#else
#define U64_PRINTF_ARG(a) ((long long unsigned int)(a))
#define U64_SCANF_ARG(a) ((long long unsigned int*)(a))
#define U64_LITERAL(n) (n ## llu)
#define I64_PRINTF_ARG(a) ((long long signed int)(a))
#define I64_SCANF_ARG(a) ((long long signed int*)(a))
#define I64_LITERAL(n) (n ## ll)
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
/** The formatting string used to put a uint64_t value in a printf() or
 * scanf() function.  See also U64_PRINTF_ARG and U64_SCANF_ARG. */
#define U64_FORMAT "%I64u"
#define I64_FORMAT "%I64d"
#else
#define U64_FORMAT "%llu"
#define I64_FORMAT "%lld"
#endif

int tor_snprintf(char *str, size_t size, const char *format, ...)
  ATTR_NONNULL((1,3));
int tor_vsnprintf(char *str, size_t size, const char *format, va_list args)
  ATTR_NONNULL((1,3));

int tor_asprintf(unsigned char **strp, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 0)));
int tor_vasprintf(unsigned char **strp, const char *fmt, va_list args) __attribute__((__format__ (__printf__, 2, 0)));

const void *tor_memmem(const void *haystack, size_t hlen, const void *needle,
                       size_t nlen)  ATTR_PURE ATTR_NONNULL((1,3));
static const void *tor_memstr(const void *haystack, size_t hlen,
                           const char *needle) ATTR_PURE ATTR_NONNULL((1,3));
static INLINE const void *
tor_memstr(const void *haystack, size_t hlen, const char *needle)
{
  return tor_memmem(haystack, hlen, needle, strlen(needle));
}

/* Much of the time when we're checking ctypes, we're doing spec compliance,
 * which all assumes we're doing ASCII. */
#define DECLARE_CTYPE_FN(name)                                          \
  static int TOR_##name(char c);                                        \
  extern const uint32_t TOR_##name##_TABLE[];                           \
  static INLINE int TOR_##name(char c) {                                \
    uint8_t u = c;                                                      \
    return !!(TOR_##name##_TABLE[(u >> 5) & 7] & (1 << (u & 31)));      \
  }
DECLARE_CTYPE_FN(ISALPHA)
DECLARE_CTYPE_FN(ISALNUM)
DECLARE_CTYPE_FN(ISSPACE)
DECLARE_CTYPE_FN(ISDIGIT)
DECLARE_CTYPE_FN(ISXDIGIT)
DECLARE_CTYPE_FN(ISPRINT)
DECLARE_CTYPE_FN(ISLOWER)
DECLARE_CTYPE_FN(ISUPPER)
extern const char TOR_TOUPPER_TABLE[];
extern const char TOR_TOLOWER_TABLE[];
#define TOR_TOLOWER(c) (TOR_TOLOWER_TABLE[(uint8_t)c])
#define TOR_TOUPPER(c) (TOR_TOUPPER_TABLE[(uint8_t)c])

char *tor_strtok_r_impl(char *str, const char *sep, char **lasts);
#ifdef HAVE_STRTOK_R
#define tor_strtok_r(str, sep, lasts) strtok_r(str, sep, lasts)
#else
#define tor_strtok_r(str, sep, lasts) tor_strtok_r_impl(str, sep, lasts)
#endif

#ifdef MS_WINDOWS
#define _SHORT_FILE_ (tor_fix_source_file(__FILE__))
const char *tor_fix_source_file(const char *fname);
#else
#define _SHORT_FILE_ (__FILE__)
#define tor_fix_source_file(s) (s)
#endif

/* ===== Time compatibility */
#if !defined(HAVE_GETTIMEOFDAY) && !defined(HAVE_STRUCT_TIMEVAL_TV_SEC)
/** Implementation of timeval for platforms that don't have it. */
struct timeval {
  time_t tv_sec;
  unsigned int tv_usec;
};
#endif

void tor_gettimeofday(struct timeval *timeval);

struct tm *tor_localtime_r(const time_t *timep, struct tm *result);
struct tm *tor_gmtime_r(const time_t *timep, struct tm *result);

#ifndef timeradd
/** Replacement for timeradd on platforms that do not have it: sets tvout to
 * the sum of tv1 and tv2. */
#define timeradd(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec; \
    if ((tvout)->tv_usec >= 1000000) {                  \
      (tvout)->tv_usec -= 1000000;                      \
      (tvout)->tv_sec++;                                \
    }                                                   \
  } while (0)
#endif

#ifndef timersub
/** Replacement for timersub on platforms that do not have it: sets tvout to
 * tv1 minus tv2. */
#define timersub(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec; \
    if ((tvout)->tv_usec < 0) {                         \
      (tvout)->tv_usec += 1000000;                      \
      (tvout)->tv_sec--;                                \
    }                                                   \
  } while (0)
#endif

#ifndef timercmp
/** Replacement for timersub on platforms that do not have it: returns true
 * iff the relational operator "op" makes the expression tv1 op tv2 true.
 *
 * Note that while this definition should work for all boolean opeators, some
 * platforms' native timercmp definitions do not support >=, <=, or ==.  So
 * don't use those.
 */
#define timercmp(tv1,tv2,op)                    \
  (((tv1)->tv_sec == (tv2)->tv_sec) ?           \
   ((tv1)->tv_usec op (tv2)->tv_usec) :         \
   ((tv1)->tv_sec op (tv2)->tv_sec))
#endif

/* ===== Net compatibility */

#if (SIZEOF_SOCKLEN_T == 0)
typedef int socklen_t;
#endif

#ifdef MS_WINDOWS
#define tor_socket_t intptr_t
#define SOCKET_OK(s) ((SOCKET)(s) != INVALID_SOCKET)
#else
#define tor_socket_t int
#define SOCKET_OK(s) ((s) >= 0)
#endif

int tor_close_socket(tor_socket_t s);
tor_socket_t tor_open_socket(int domain, int type, int protocol);
tor_socket_t tor_accept_socket(tor_socket_t sockfd, struct sockaddr *addr,socklen_t *len);
int get_n_open_sockets(void);

#define tor_socket_send(s, buf, len, flags) send(s, buf, len, flags)
#define tor_socket_recv(s, buf, len, flags) recv(s, buf, len, flags)

/* Define struct in6_addr on platforms that do not have it.  Generally,
 * these platforms are ones without IPv6 support, but we want to have
 * a working in6_addr there anyway, so we can use it to parse IPv6
 * addresses. */
#if !defined(HAVE_STRUCT_IN6_ADDR)
struct in6_addr
{
  union {
    uint8_t u6_addr8[16];
    uint16_t u6_addr16[8];
    uint32_t u6_addr32[4];
  } in6_u;
#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};
#endif

#if defined(__APPLE__) || defined(__darwin__) || defined(__FreeBSD__) \
    || defined(__NetBSD__) || defined(__OpenBSD__)
/* Many BSD variants seem not to define these. */
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif

#ifndef HAVE_SA_FAMILY_T
typedef uint16_t sa_family_t;
#endif

/* Apparently, MS and Solaris don't define s6_addr16 or s6_addr32. */
#ifdef HAVE_STRUCT_IN6_ADDR_S6_ADDR32
#define S6_ADDR32(x) ((uint32_t*)(x).s6_addr32)
#else
#define S6_ADDR32(x) ((uint32_t*)((char*)&(x).s6_addr))
#endif
#ifdef HAVE_STRUCT_IN6_ADDR_S6_ADDR16
#define S6_ADDR16(x) ((uint16_t*)(x).s6_addr16)
#else
#define S6_ADDR16(x) ((uint16_t*)((char*)&(x).s6_addr))
#endif

/* Define struct sockaddr_in6 on platforms that do not have it. See notes
 * on struct in6_addr. */
#if !defined(HAVE_STRUCT_SOCKADDR_IN6)
struct sockaddr_in6 {
  sa_family_t sin6_family;
  uint16_t sin6_port;
  // uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  // uint32_t sin6_scope_id;
};
#endif

int tor_inet_aton(const char *cp, struct in_addr *addr) ATTR_NONNULL((1,2));
const char *tor_inet_ntop(int af, const void *src, char *dst, size_t len);
int tor_inet_pton(int af, const char *src, void *dst);
int tor_lookup_hostname(const char *name, uint32_t *addr) ATTR_NONNULL((1,2));
void set_socket_nonblocking(tor_socket_t socket);
int tor_socketpair(int type,int protocol,tor_socket_t fd[2]);
int network_init(void);

/* For stupid historical reasons, windows sockets have an independent
 * set of errnos, and an independent way to get them.  Also, you can't
 * always believe WSAEWOULDBLOCK.  Use the macros below to compare
 * errnos against expected values, and use tor_socket_errno to find
 * the actual errno after a socket operation fails.
 */
#if defined(MS_WINDOWS)
/** Return true if e is EAGAIN or the local equivalent. */
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN || (e) == WSAEWOULDBLOCK)
/** Return true if e is EINPROGRESS or the local equivalent. */
#define ERRNO_IS_EINPROGRESS(e)      ((e) == WSAEINPROGRESS)
/** Return true if e is EINPROGRESS or the local equivalent as returned by
 * a call to connect(). */
#define ERRNO_IS_CONN_EINPROGRESS(e) \
  ((e) == WSAEINPROGRESS || (e)== WSAEINVAL || (e) == WSAEWOULDBLOCK)
/** Return true if e is EAGAIN or another error indicating that a call to
 * accept() has no pending connections to return. */
#define ERRNO_IS_ACCEPT_EAGAIN(e)    ERRNO_IS_EAGAIN(e)
/** Return true if e is EMFILE or another error indicating that a call to
 * accept() has failed because we're out of fds or something. */
#define ERRNO_IS_ACCEPT_RESOURCE_LIMIT(e) \
  ((e) == WSAEMFILE || (e) == WSAENOBUFS)
/** Return true if e is EADDRINUSE or the local equivalent. */
#define ERRNO_IS_EADDRINUSE(e)      ((e) == WSAEADDRINUSE)
int tor_socket_errno(tor_socket_t sock);
const char *tor_socket_strerror(int e);
#else
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN)
#define ERRNO_IS_EINPROGRESS(e)      ((e) == EINPROGRESS)
#define ERRNO_IS_CONN_EINPROGRESS(e) ((e) == EINPROGRESS)
#define ERRNO_IS_ACCEPT_EAGAIN(e)    ((e) == EAGAIN || (e) == ECONNABORTED)
#define ERRNO_IS_ACCEPT_RESOURCE_LIMIT(e) \
  ((e) == EMFILE || (e) == ENFILE || (e) == ENOBUFS || (e) == ENOMEM)
#define ERRNO_IS_EADDRINUSE(e)       ((e) == EADDRINUSE)
#define tor_socket_errno(sock)       (errno)
#define tor_socket_strerror(e)       strerror(e)
#endif

/** Specified SOCKS5 status codes. */
typedef enum {
  SOCKS5_SUCCEEDED                  = 0x00,
  SOCKS5_GENERAL_ERROR              = 0x01,
  SOCKS5_NOT_ALLOWED                = 0x02,
  SOCKS5_NET_UNREACHABLE            = 0x03,
  SOCKS5_HOST_UNREACHABLE           = 0x04,
  SOCKS5_CONNECTION_REFUSED         = 0x05,
  SOCKS5_TTL_EXPIRED                = 0x06,
  SOCKS5_COMMAND_NOT_SUPPORTED      = 0x07,
  SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
} socks5_reply_status_t;

/* ===== Insecure rng */
void tor_init_weak_random(unsigned seed);
long tor_weak_random(void);
#define TOR_RAND_MAX (RAND_MAX)

/* ===== OS compatibility */
const char *get_uname(void);

uint16_t get_uint16(const void *cp) ATTR_PURE ATTR_NONNULL((1));
uint32_t get_uint32(const void *cp) ATTR_PURE ATTR_NONNULL((1));
uint64_t get_uint64(const void *cp) ATTR_PURE ATTR_NONNULL((1));
void set_uint16(void *cp, uint16_t v) ATTR_NONNULL((1));
void set_uint32(void *cp, uint32_t v) ATTR_NONNULL((1));
void set_uint64(void *cp, uint64_t v) ATTR_NONNULL((1));

/* These uint8 variants are defined to make the code more uniform. */
#define get_uint8(cp) (*(const uint8_t*)(cp))
static void set_uint8(void *cp, uint8_t v);
static INLINE void
set_uint8(void *cp, uint8_t v)
{
  *(uint8_t*)cp = v;
}

#if !defined(HAVE_RLIM_T)
typedef unsigned long rlim_t;
#endif
int set_max_file_descriptors(rlim_t limit, int *max);
int switch_id(const char *user);
#ifdef HAVE_PWD_H
char *get_user_homedir(const char *username);
#endif

int get_parent_directory(char *fname);
int spawn_func(void (*func)(void *), void *data);
void spawn_exit(void) ATTR_NORETURN;

#if defined(ENABLE_THREADS) && defined(MS_WINDOWS)
#define USE_WIN32_THREADS
#define TOR_IS_MULTITHREADED 1
#elif (defined(ENABLE_THREADS) && defined(HAVE_PTHREAD_H) && \
       defined(HAVE_PTHREAD_CREATE))
#define USE_PTHREADS
#define TOR_IS_MULTITHREADED 1
#else
#undef TOR_IS_MULTITHREADED
#endif

/* Because we use threads instead of processes on most platforms (Windows,
 * Linux, etc), we need locking for them.  On platforms with poor thread
 * support or broken gethostbyname_r, these functions are no-ops. */

/** A generic lock structure for multithreaded builds. */
typedef struct tor_mutex_t {
#if defined(USE_WIN32_THREADS)
  CRITICAL_SECTION mutex;
#elif defined(USE_PTHREADS)
  pthread_mutex_t mutex;
#else
  int _unused;
#endif
} tor_mutex_t;

int tor_mlockall(void);

#ifdef TOR_IS_MULTITHREADED
tor_mutex_t *tor_mutex_new(void);
void tor_mutex_init(tor_mutex_t *m);
void tor_mutex_acquire(tor_mutex_t *m);
void tor_mutex_release(tor_mutex_t *m);
void tor_mutex_free(tor_mutex_t *m);
void tor_mutex_uninit(tor_mutex_t *m);
unsigned long tor_get_thread_id(void);
void tor_threads_init(void);
#else
#define tor_mutex_new() ((tor_mutex_t*)tor_malloc(sizeof(int)))
#define tor_mutex_init(m) STMT_NIL
#define tor_mutex_acquire(m) STMT_VOID(m)
#define tor_mutex_release(m) STMT_NIL
#define tor_mutex_free(m) STMT_BEGIN tor_free(m); STMT_END
#define tor_mutex_uninit(m) STMT_NIL
#define tor_get_thread_id() (1UL)
#define tor_threads_init() STMT_NIL
#endif

#ifdef TOR_IS_MULTITHREADED
#if 0
typedef struct tor_cond_t tor_cond_t;
tor_cond_t *tor_cond_new(void);
void tor_cond_free(tor_cond_t *cond);
int tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex);
void tor_cond_signal_one(tor_cond_t *cond);
void tor_cond_signal_all(tor_cond_t *cond);
#endif
#endif

/** Macros for MIN/MAX.  Never use these when the arguments could have side-effects. {With GCC extensions we could probably define a safer MIN/MAX. But depending on that safety would be dangerous, since not every platform has it.} **/
#ifndef MAX
#define MAX(a,b) ( ((a)<(b)) ? (b) : (a) )
#endif
#ifndef MIN
#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )
#endif

/* Platform-specific helpers. */
#ifdef MS_WINDOWS
char *format_win32_error(DWORD err);
#endif

/*for some reason my compiler doesn't have these version flags defined
  a nice homework assignment for someone one day is to define the rest*/
//these are the values as given on MSDN
#ifdef MS_WINDOWS

#ifndef VER_SUITE_EMBEDDEDNT
#define VER_SUITE_EMBEDDEDNT 0x00000040
#endif

#ifndef VER_SUITE_SINGLEUSERTS
#define VER_SUITE_SINGLEUSERTS 0x00000100
#endif

#endif

#endif

#ifndef _TOR_COMPAT_LIBEVENT_H
#define _TOR_COMPAT_LIBEVENT_H

struct event;
struct event_base;

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/util.h>
#elif !defined(EVUTIL_SOCKET_DEFINED)
#define EVUTIL_SOCKET_DEFINED
#define evutil_socket_t int
#endif

void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);

#ifdef HAVE_EVENT2_EVENT_H
#define tor_event_new     event_new
#define tor_evtimer_new   evtimer_new
#define tor_evsignal_new  evsignal_new
#define tor_event_free    event_free
#define tor_evdns_add_server_port(sock, tcp, cb, data) \
  evdns_add_server_port_with_base(tor_libevent_get_base(), \
  (sock),(tcp),(cb),(data));

#else
struct event *tor_event_new(struct event_base * base, evutil_socket_t sock,
           short what, void (*cb)(evutil_socket_t, short, void *), void *arg);
struct event *tor_evtimer_new(struct event_base * base,
            void (*cb)(evutil_socket_t, short, void *), void *arg);
struct event *tor_evsignal_new(struct event_base * base, int sig,
            void (*cb)(evutil_socket_t, short, void *), void *arg);
void tor_event_free(struct event *ev);
#define tor_evdns_add_server_port evdns_add_server_port
#endif

typedef struct periodic_timer_t periodic_timer_t;

periodic_timer_t *periodic_timer_new(struct event_base *base,
             const struct timeval *tv,
             void (*cb)(periodic_timer_t *timer, void *data),
             void *data);
void periodic_timer_free(periodic_timer_t *);

#ifdef HAVE_EVENT_BASE_LOOPEXIT
#define tor_event_base_loopexit event_base_loopexit
#else
struct timeval;
int tor_event_base_loopexit(struct event_base *base, struct timeval *tv);
#endif

void tor_libevent_initialize(void);
void openssl_init(void);
struct event_base *tor_libevent_get_base(void);
const char *tor_libevent_get_method(void);
void tor_check_libevent_version(const char *m, int server,
                                const char **badness_out);
void tor_check_libevent_header_compatibility(void);
const char *tor_libevent_get_version_str(void);
void set_main_thread(void);
int in_main_thread(void);

void *ev_malloc(size_t sz);
void *ev_realloc(void *ptr, size_t sz);
void ev_free(void *ptr);
void *openssl_malloc(size_t sz);
void *openssl_realloc(void *ptr, size_t sz);
void openssl_free(void *ptr);

#endif
