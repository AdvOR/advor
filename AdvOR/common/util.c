/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util.c
 * \brief Common functions for strings, IO, network, data structures,
 * process control.
 **/

/* This is required on rh7 to make strptime not complain.
 */
#define _GNU_SOURCE

#include <openssl/rsa.h>

#include "orconfig.h"
#include "util.h"
#include "log.h"
#include "crypto.h"
#include "torint.h"
#include "container.h"
#include "address.h"

#include <io.h>
#include <direct.h>
#include <process.h>

#undef log
/* math.h needs this on Linux */
#ifndef __USE_ISOC99
#define __USE_ISOC99 1
#endif
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
#ifdef HAVE_MALLOC_H
#ifndef OPENBSD
/* OpenBSD has a malloc.h, but for our purposes, it only exists in order to
 * scold us for being so stupid as to autodetect its presence.  To be fair,
 * they've done this since 1996, when autoconf was only 5 years old. */
#include <malloc.h>
#endif
#endif
#ifdef HAVE_MALLOC_NP_H
#include <malloc_np.h>
#endif

DWORD *safe_mem_root = NULL;
int next_mem_size = 4096;

DWORD safe_size(void *ptr);

void * __stdcall safe_malloc(unsigned int size)
{	int memsize = size;
	DWORD *next_mem_buf;
	if(memsize >= next_mem_size+8)
	{	next_mem_size = memsize * 2;
	}
	if(safe_mem_root==NULL)
	{	safe_mem_root = (DWORD *)VirtualAlloc(NULL,next_mem_size+16+16,MEM_COMMIT,PAGE_READWRITE|PAGE_NOCACHE);
		safe_mem_root[0] = 0;			// next allocated buffer
		safe_mem_root[1] = 0;			// next offset in buffer
		safe_mem_root[2] = next_mem_size>>2;	// total
		safe_mem_root[3] = next_mem_size>>2;	// available
		safe_mem_root[4] = 0;			// size of buffer
		safe_mem_root[5] = 0;			// bytes used
	}
	size = (size+3)>>2;
	DWORD *alloc_buf;
	unsigned int available;
	next_mem_buf = safe_mem_root;
	while(next_mem_buf)
	{	if(next_mem_buf[3] >= size+2)
		{	alloc_buf = &next_mem_buf[4];
			available = next_mem_buf[3];
			while(alloc_buf[0])
			{	if((alloc_buf[1] == 0) && (alloc_buf[0] >= size))
					return &alloc_buf[2];
				available -= alloc_buf[1] + 2;
				alloc_buf += alloc_buf[0] + 2;
			}
			if(available >= size+2)
			{	alloc_buf[0] = size;
				alloc_buf[1] = memsize;
				next_mem_buf[3] -= size + 2;
				alloc_buf[2+size] = 0;
				alloc_buf[3+size] = 0;
				return &alloc_buf[2];
			}
		}
		next_mem_buf = (DWORD *)next_mem_buf[0];
	}
	next_mem_buf = (DWORD *)VirtualAlloc(NULL,next_mem_size+16+16,MEM_COMMIT,PAGE_READWRITE|PAGE_NOCACHE);
	next_mem_buf[0] = 0;			// next allocated buffer
	next_mem_buf[1] = 0;			// next offset in buffer
	next_mem_buf[2] = next_mem_size>>2;	// total
	next_mem_buf[3] = (next_mem_size>>2) - size - 2;	// available
	next_mem_buf[4] = size;			// size of buffer
	next_mem_buf[5] = memsize;		// bytes used
	next_mem_buf[6+size] = 0;
	next_mem_buf[7+size] = 0;
	DWORD *new_mem_buf = safe_mem_root;
	while(new_mem_buf[0])	new_mem_buf = (DWORD *)new_mem_buf[0];
	new_mem_buf[0] = (DWORD)next_mem_buf;
	return &next_mem_buf[6];
}

DWORD safe_size(void *ptr)
{	DWORD *mem = ptr;
	mem -= 6;
	return mem[5];
}

void __stdcall safe_free(void *buffer)
{	if(safe_mem_root)
	{	DWORD *next_buf = safe_mem_root;
		DWORD *cbuf = buffer;
		while(next_buf)
		{	if(cbuf > next_buf && cbuf < next_buf+next_buf[2])
			{	DWORD *alloc_buf = next_buf+4;
				while(alloc_buf[0])
				{	if(cbuf == alloc_buf + 2)
					{	next_buf[3] += alloc_buf[1];
						alloc_buf[1] = 0;
						alloc_buf = next_buf + 4;
						while(alloc_buf[0])
						{	if(alloc_buf[1] == 0)
							{	cbuf = alloc_buf + alloc_buf[0] + 2;
								if(cbuf[1] == 0 && cbuf[0]!=0)
								{	alloc_buf[0] += cbuf[0] + 2;
									next_buf[3] += 2;
									continue;
								}
							}
							alloc_buf += alloc_buf[0] + 2;
						}
						alloc_buf = next_buf+4;
						if(alloc_buf[1] == 0)
						{	if(alloc_buf[0])	alloc_buf += alloc_buf[0] + 2;
							if(alloc_buf[0]==0)
							{	if(safe_mem_root==next_buf)
								{	safe_mem_root = (DWORD *)next_buf[0];
								}
								else
								{	cbuf = safe_mem_root;
									while(cbuf)
									{	if(cbuf[0] == (DWORD)next_buf)
										{	cbuf[0] = next_buf[0];
											break;
										}
										cbuf = (DWORD *)cbuf[0];
									}
								}
								VirtualFree(next_buf,0,MEM_RELEASE);
							}
						}
						return;
					}
					else if(cbuf < alloc_buf)	tor_assert(0);
					alloc_buf += alloc_buf[0] + 2;
				}
			}
			next_buf = (DWORD *)next_buf[0];
		}
	}
}

/* =====
 * Memory management
 * ===== */
#ifdef DEBUG_MALLOC
//#define ALLOC(x) GlobalAlloc(GPTR,x)
//#define FREE(x) GlobalFree(x)
#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#else
#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#endif

#ifdef USE_DMALLOC
 #undef strndup
 #include <dmalloc.h>
 /* Macro to pass the extra dmalloc args to another function. */
 #define DMALLOC_FN_ARGS , file, line

 #if defined(HAVE_DMALLOC_STRDUP)
 /* the dmalloc_strdup should be fine as defined */
 #elif defined(HAVE_DMALLOC_STRNDUP)
 #define dmalloc_strdup(file, line, string, xalloc_b) \
         dmalloc_strndup(file, line, (string), -1, xalloc_b)
 #else
 #error "No dmalloc_strdup or equivalent"
 #endif

#else /* not using dmalloc */

 #define DMALLOC_FN_ARGS
#endif

/** Allocate a chunk of <b>size</b> bytes of memory, and return a pointer to
 * result.  On error, log and terminate the process.  (Same as malloc(size),
 * but never returns NULL.)
 *
 * <b>file</b> and <b>line</b> are used if dmalloc is enabled, and
 * ignored otherwise.
 */
#ifdef DEBUG_MALLOC
uint32_t *alloc_root = NULL;
uint32_t *alloc_last = NULL;
#ifndef int3
#define int3 asm(".intel_syntax noprefix\nint 3\n.att_syntax prefix");
#endif
#endif

#ifdef DEBUG_MALLOC
void check_mem(void)
{	uint32_t *md;
	uint32_t blocks,size;
	md = alloc_root;
	blocks = size = 0;
	while(md)
	{	size += md[4];
		blocks++;
#ifdef MALLOC_SENTINELS
		unsigned char *c;
		c = (unsigned char *)md;
		c += md[4] + 20;
		if(*(uint32_t *)c != 0x55aa1234)
			int3
#endif
		md = (uint32_t*)md[1];
	}
	log_info(LD_APP,"Allocated memory: %u buffers, %u bytes",blocks,size);
}
#endif

CRITICAL_SECTION allocCriticalSection;

#ifdef DEBUG_MALLOC
void *_tor_malloc(size_t size DMALLOC_PARAMS,const char *file,int line)
#else
void *_tor_malloc(size_t size DMALLOC_PARAMS)
#endif
{
  uint32_t *result;
  tor_assert(size < SIZE_T_CEILING);
  while(!TryEnterCriticalSection(&allocCriticalSection))
  	Sleep(10);
#ifdef DEBUG_MALLOC
	result = ALLOC(size+20
#ifdef MALLOC_SENTINELS
	+4
#endif
	);
	if(result)
	{	if(alloc_root)
		{	result[0] = (uint32_t)alloc_last;
			alloc_last[1] = (uint32_t)result;
			alloc_last = result;
		}
		else
		{
			alloc_root = result;
			alloc_last = result;
			result[0] = (uint32_t)alloc_last;	// previous
		}
		result[1] = 0;		// next
		result[2] = (uint32_t)file;
		result[3] = (uint32_t)line;
		result[4] = size;
		result += 5;
#ifdef MALLOC_SENTINELS
		unsigned char *c;
		c = (unsigned char *)result;
		c += size;
		*(uint32_t *)c = 0x55aa1234;
#endif
	}
#else
	result = ALLOC(size);
#endif
  LeaveCriticalSection(&allocCriticalSection);
  if (PREDICT_UNLIKELY(result == NULL)) {
    log_err(LD_MM,get_lang_str(LANG_LOG_UTIL_OUT_OF_MEMORY));
    /* If these functions die within a worker process, they won't call
     * spawn_exit, but that's ok, since the parent will run out of memory soon
     * anyway. */
    exit(1);
  }
  return (void *)result;
}

#ifdef DEBUG_MALLOC
void _tor_free_(void *p,const char *file,int line)
{
	(void)file;
	(void)line;
	if((uint32_t)p==0xffffffff)
		int3
	if(p)
	{
		while(!TryEnterCriticalSection(&allocCriticalSection))
			Sleep(10);
		uint32_t *next;
		next = (uint32_t *)p;
		next -= 5;
#ifdef MALLOC_SENTINELS
		if(*(uint32_t *)((unsigned char *)p + next[4]) != 0x55aa1234)
			int3
#endif
		if(next == alloc_root)
			alloc_root = (uint32_t *)next[1];
		if(next == alloc_last)
			alloc_last = (uint32_t *)next[0];
		if(next[0])
		{	uint32_t *n;
			n = (uint32_t *)next[0];
			n[1] = next[1];
		}
		if(next[1])
		{	uint32_t *n;
			n = (uint32_t *)next[1];
			n[0] = next[0];
		}
		FREE(next);
		(p) = NULL;
		LeaveCriticalSection(&allocCriticalSection);
	}
}
#else
void _tor_free_(void *p)
{
	if(p)
	{
		while(!TryEnterCriticalSection(&allocCriticalSection))
			Sleep(10);
		FREE(p);
		(p) = NULL;
		LeaveCriticalSection(&allocCriticalSection);
	}
}
#endif

void tor_alloc_init(void)
{
	InitializeCriticalSection(&allocCriticalSection);
#ifdef DEBUG_MALLOC
#endif
}

void tor_alloc_exit(void)
{
	DeleteCriticalSection(&allocCriticalSection);
#ifdef DEBUG_MALLOC
#endif
}

/** Allocate a chunk of <b>size</b> bytes of memory, fill the memory with
 * zero bytes, and return a pointer to the result.  Log and terminate
 * the process on error.  (Same as calloc(size,1), but never returns NULL.)
 */
#ifdef DEBUG_MALLOC
void *_tor_malloc_zero(size_t size DMALLOC_PARAMS,const char *c,int n)
{
  /* You may ask yourself, "wouldn't it be smart to use calloc instead of
   * malloc+memset?  Perhaps libc's calloc knows some nifty optimization trick
   * we don't!"  Indeed it does, but its optimizations are only a big win when
   * we're allocating something very big (it knows if it just got the memory
   * from the OS in a pre-zeroed state).  We don't want to use tor_malloc_zero
   * for big stuff, so we don't bother with calloc. */
  void *result = _tor_malloc(size DMALLOC_FN_ARGS,c,n);
  memset(result, 0, size);
  return result;
}
#else
void *_tor_malloc_zero(size_t size DMALLOC_PARAMS)
{
  void *result = _tor_malloc(size DMALLOC_FN_ARGS);
  memset(result, 0, size);
  return result;
}
#endif

#ifdef DEBUG_MALLOC
uint32_t tor_memsize(void *p)
{	uint32_t *n;
	if(!p)	return 0;
	n = p;
	return n[-1];
}

/** Change the size of the memory block pointed to by <b>ptr</b> to <b>size</b>
 * bytes long; return the new memory block.  On error, log and
 * terminate. (Like realloc(ptr,size), but never returns NULL.)
 */
void *_tor_realloc(void *ptr, size_t size DMALLOC_PARAMS,const char *file,int line)
#else
void *_tor_realloc(void *ptr, size_t size DMALLOC_PARAMS)
#endif
{
  void *result;
#ifdef DEBUG_MALLOC
	result = _tor_malloc(size,file,line);
	size_t i = tor_memsize(ptr);
	if(i > size)	i = size;
	if(result)
		memmove(result,ptr,i);
	_tor_free_(ptr,file,line);
#else
  result = realloc(ptr, size);
#endif
  if (PREDICT_UNLIKELY(result == NULL)) {
    log_err(LD_MM,get_lang_str(LANG_LOG_UTIL_OUT_OF_MEMORY_2));
    exit(1);
  }
  return result;
}

/** Return a newly allocated copy of the NUL-terminated string s. On
 * error, log and terminate.  (Like strdup(s), but never returns
 * NULL.)
 */
#ifdef DEBUG_MALLOC
char *_tor_strdup(const char *s DMALLOC_PARAMS,const char *file,int line)
#else
char *_tor_strdup(const char *s DMALLOC_PARAMS)
#endif
{
  char *dup;
  tor_assert(s);
#ifdef DEBUG_MALLOC
  dup = _tor_malloc(strlen(s)+1,file,line);
#else
  dup = tor_malloc(strlen(s)+1);
#endif
  strcpy(dup,s);
  if (PREDICT_UNLIKELY(dup == NULL)) {
    log_err(LD_MM,get_lang_str(LANG_LOG_UTIL_OUT_OF_MEMORY_3));
    exit(1);
  }
  return dup;
}

/** Allocate and return a new string containing the first <b>n</b>
 * characters of <b>s</b>.  If <b>s</b> is longer than <b>n</b>
 * characters, only the first <b>n</b> are copied.  The result is
 * always NUL-terminated.  (Like strndup(s,n), but never returns
 * NULL.)
 */
#ifdef DEBUG_MALLOC
char *_tor_strndup(const char *s, size_t n DMALLOC_PARAMS,const char *file,int line)
#else
char *_tor_strndup(const char *s, size_t n DMALLOC_PARAMS)
#endif
{
  char *dup;
  tor_assert(s);
  tor_assert(n < SIZE_T_CEILING);
#ifdef DEBUG_MALLOC
  dup = _tor_malloc((n+1) DMALLOC_FN_ARGS,file,line);
#else
  dup = _tor_malloc((n+1) DMALLOC_FN_ARGS);
#endif
  /* Performance note: Ordinarily we prefer strlcpy to strncpy.  But
   * this function gets called a whole lot, and platform strncpy is
   * much faster than strlcpy when strlen(s) is much longer than n.
   */
  strncpy(dup, s, n);
  dup[n]='\0';
  return dup;
}

/** Allocate a chunk of <b>len</b> bytes, with the same contents as the
 * <b>len</b> bytes starting at <b>mem</b>. */
void *
_tor_memdup(const void *mem, size_t len DMALLOC_PARAMS)
{
  char *dup;
  tor_assert(len < SIZE_T_CEILING);
  tor_assert(mem);
#ifdef DEBUG_MALLOC
  dup = _tor_malloc(len DMALLOC_FN_ARGS,__FILE__,__LINE__);
#else
  dup = _tor_malloc(len DMALLOC_FN_ARGS);
#endif
  memcpy(dup, mem, len);
  return dup;
}

#if defined(HAVE_MALLOC_GOOD_SIZE) && !defined(HAVE_MALLOC_GOOD_SIZE_PROTOTYPE)
/* Some version of Mac OSX have malloc_good_size in their libc, but not
 * actually defined in malloc/malloc.h.  We detect this and work around it by
 * prototyping.
 */
extern size_t malloc_good_size(size_t size);
#endif

/** Allocate and return a chunk of memory of size at least *<b>size</b>, using
 * the same resources we would use to malloc *<b>sizep</b>.  Set *<b>sizep</b>
 * to the number of usable bytes in the chunk of memory. */
#ifdef DEBUG_MALLOC
void *_tor_malloc_roundup(size_t *sizep DMALLOC_PARAMS,const char *c,int n)
{
  return _tor_malloc(*sizep DMALLOC_FN_ARGS,c,n);
}
#else
void *_tor_malloc_roundup(size_t *sizep DMALLOC_PARAMS)
{
  return _tor_malloc(*sizep DMALLOC_FN_ARGS);
}
#endif

/** Call the platform malloc info function, and dump the results to the log at
 * level <b>severity</b>.  If no such function exists, do nothing. */
void
tor_log_mallinfo(int severity)
{
#ifdef HAVE_MALLINFO
  struct mallinfo mi;
  memset(&mi, 0, sizeof(mi));
  mi = mallinfo();
  log(severity,LD_MM,get_lang_str(LANG_LOG_UTIL_MALLINFO),mi.arena,mi.ordblks,mi.smblks,mi.hblks,mi.hblkhd,mi.usmblks,mi.fsmblks,mi.uordblks,mi.fordblks,mi.keepcost);
#else
  (void)severity;
#endif
#ifdef USE_DMALLOC
  dmalloc_log_changed(0, /* Since the program started. */
                      1, /* Log info about non-freed pointers. */
                      0, /* Do not log info about freed pointers. */
                      0  /* Do not log individual pointers. */
                      );
#endif
}

/* =====
 * Math
 * ===== */

/** Returns the natural logarithm of d base 2. We define this wrapper here so as to make it easier not to conflict with Tor's log() macro. */
double tor_mathlog(double d)
{	return log(d);
}

/** Return the long integer closest to d.  We define this wrapper here so that not all users of math.h need to use the right incancations to get the c99 functions. */
long tor_lround(double d)
{
#if defined(HAVE_LROUND)
	return lround(d);
#elif defined(HAVE_RINT)
	return (long)rint(d);
#else
	return (long)(d > 0 ? d + 0.5 : ceil(d - 0.5));
#endif
}

/** Returns floor(log2(u64)).  If u64 is 0, (incorrectly) returns 0. */
int
tor_log2(uint64_t u64)
{
  int r = 0;
  if (u64 >= (U64_LITERAL(1)<<32)) {
    u64 >>= 32;
    r = 32;
  }
  if (u64 >= (U64_LITERAL(1)<<16)) {
    u64 >>= 16;
    r += 16;
  }
  if (u64 >= (U64_LITERAL(1)<<8)) {
    u64 >>= 8;
    r += 8;
  }
  if (u64 >= (U64_LITERAL(1)<<4)) {
    u64 >>= 4;
    r += 4;
  }
  if (u64 >= (U64_LITERAL(1)<<2)) {
    u64 >>= 2;
    r += 2;
  }
  if (u64 >= (U64_LITERAL(1)<<1)) {
    u64 >>= 1;
    r += 1;
  }
  return r;
}

/** Return the power of 2 closest to <b>u64</b>. */
uint64_t
round_to_power_of_2(uint64_t u64)
{
  int lg2 = tor_log2(u64);
  uint64_t low = U64_LITERAL(1) << lg2, high = U64_LITERAL(1) << (lg2+1);
  if (high - u64 < u64 - low)
    return high;
  else
    return low;
}

/** Return the lowest x such that x is at least <b>number</b>, and x modulo <b>divisor</b> == 0. */
unsigned round_to_next_multiple_of(unsigned number, unsigned divisor)
{	number += divisor - 1;
	number -= number % divisor;
	return number;
}

/** Return the lowest x such that x is at least <b>number</b>, and x modulo <b>divisor</b> == 0. */
uint32_t round_uint32_to_next_multiple_of(uint32_t number, uint32_t divisor)
{	number += divisor - 1;
	number -= number % divisor;
	return number;
}

/** Return the lowest x such that x is at least <b>number</b>, and x modulo <b>divisor</b> == 0. */
uint64_t round_uint64_to_next_multiple_of(uint64_t number, uint64_t divisor)
{	number += divisor - 1;
	number -= number % divisor;
	return number;
}


/* =====
 * String manipulation
 * ===== */

/** Remove from the string <b>s</b> every character which appears in
 * <b>strip</b>. */
void
tor_strstrip(char *s, const char *strip)
{
  char *read = s;
  while (*read) {
    if (strchr(strip, *read)) {
      ++read;
    } else {
      *s++ = *read++;
    }
  }
  *s = '\0';
}

/** Return a pointer to a NUL-terminated hexadecimal string encoding
 * the first <b>fromlen</b> bytes of <b>from</b>. (fromlen must be \<= 32.) The
 * result does not need to be deallocated, but repeated calls to
 * hex_str will trash old results.
 */
const char *
hex_str(const char *from, size_t fromlen)
{
  static char buf[65];
  if (fromlen>(sizeof(buf)-1)/2)
    fromlen = (sizeof(buf)-1)/2;
  base16_encode(buf,sizeof(buf),from,fromlen);
  return buf;
}

/** Convert all alphabetic characters in the nul-terminated string <b>s</b> to
 * lowercase. */
void
tor_strlower(char *s)
{
  while (*s) {
    *s = TOR_TOLOWER(*s);
    ++s;
  }
}

/** Convert all alphabetic characters in the nul-terminated string <b>s</b> to
 * lowercase. */
void
tor_strupper(char *s)
{
  while (*s) {
    *s = TOR_TOUPPER(*s);
    ++s;
  }
}

/** Return 1 if every character in <b>s</b> is printable, else return 0.
 */
int
tor_strisprint(const char *s)
{
  while (*s) {
    if (!TOR_ISPRINT(*s))
      return 0;
    s++;
  }
  return 1;
}

/** Return 1 if no character in <b>s</b> is uppercase, else return 0.
 */
int
tor_strisnonupper(const char *s)
{
  while (*s) {
    if (TOR_ISUPPER(*s))
      return 0;
    s++;
  }
  return 1;
}

/** Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcmp.
 */
int
strcmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncmp(s1, s2, n);
}

/** Compare the s1_len-byte string <b>s1</b> with <b>s2</b>,
 * without depending on a terminating nul in s1.  Sorting order is first by
 * length, then lexically; return values are as for strcmp.
 */
int
strcmp_len(const char *s1, const char *s2, size_t s1_len)
{
  size_t s2_len = strlen(s2);
  if (s1_len < s2_len)
    return -1;
  if (s1_len > s2_len)
    return 1;
  return fast_memcmp(s1, s2, s2_len);
}

/** Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcasecmp.
 */
int
strcasecmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncasecmp(s1, s2, n);
}

/** Compares the last strlen(s2) characters of s1 with s2.  Returns as for
 * strcmp.
 */
int
strcmpend(const char *s1, const char *s2)
{
  size_t n1 = strlen(s1), n2 = strlen(s2);
  if (n2>n1)
    return strcmp(s1,s2);
  else
    return strncmp(s1+(n1-n2), s2, n2);
}

/** Compares the last strlen(s2) characters of s1 with s2.  Returns as for
 * strcasecmp.
 */
int
strcasecmpend(const char *s1, const char *s2)
{
  size_t n1 = strlen(s1), n2 = strlen(s2);
  if (n2>n1) /* then they can't be the same; figure out which is bigger */
    return strcasecmp(s1,s2);
  else
    return strncasecmp(s1+(n1-n2), s2, n2);
}

int strfind(const char *s1,const char *s2,int s1_len)
{	int i = 0,j = (s1_len?(unsigned int)s1_len:strlen(s1)) -strlen(s2);
	if(j < 0)	return -1;
	while(i <= j)
	{	if(!strcmpstart(s1,s2)) return i;
		i++;
		s1++;
	}
	return -1;
}

int strcasefind(const char *s1,const char *s2,int s1_len)
{	int i = 0,j = (s1_len?s1_len:(int)(strlen(s1) -strlen(s2)));
	if(j < 0)	return -1;
	while(i <= j)
	{	if(!strcasecmpstart(s1,s2)) return i;
		i++;
		s1++;
	}
	return -1;
}

/** Compare the value of the string <b>prefix</b> with the start of the
 * <b>memlen</b>-byte memory chunk at <b>mem</b>.  Return as for strcmp.
 *
 * [As memcmp(mem, prefix, strlen(prefix)) but returns -1 if memlen is less
 * than strlen(prefix).]
 */
int
fast_memcmpstart(const void *mem, size_t memlen,
                const char *prefix)
{
  size_t plen = strlen(prefix);
  if (memlen < plen)
    return -1;
  return fast_memcmp(mem, prefix, plen);
}

/** Return a pointer to the first char of s that is not whitespace and
 * not a comment, or to the terminating NUL if no such character exists.
 */
const char *
eat_whitespace(const char *s)
{
  tor_assert(s);

  while (1) {
    switch (*s) {
    case '\0':
    default:
      return s;
    case ' ':
    case '\t':
    case '\n':
    case '\r':
      ++s;
      break;
    case ';':
      ++s;
      while (*s && *s != '\n')
        ++s;
    }
  }
}

/** Return a pointer to the first char of s that is not whitespace and
 * not a comment, or to the terminating NUL if no such character exists.
 */
const char *
eat_whitespace_eos(const char *s, const char *eos)
{
  tor_assert(s);
  tor_assert(eos && s <= eos);

  while (s < eos) {
    switch (*s) {
    case '\0':
    default:
      return s;
    case ' ':
    case '\t':
    case '\n':
    case '\r':
      ++s;
      break;
    case ';':
      ++s;
      while (s < eos && *s && *s != '\n')
        ++s;
    }
  }
  return s;
}

/** Return a pointer to the first char of s that is not a space or a tab
 * or a \\r, or to the terminating NUL if no such character exists. */
const char *
eat_whitespace_no_nl(const char *s)
{
  while (*s == ' ' || *s == '\t' || *s == '\r')
    ++s;
  return s;
}

/** As eat_whitespace_no_nl, but stop at <b>eos</b> whether we have
 * found a non-whitespace character or not. */
const char *
eat_whitespace_eos_no_nl(const char *s, const char *eos)
{
  while (s < eos && (*s == ' ' || *s == '\t' || *s == '\r'))
    ++s;
  return s;
}

/** Return a pointer to the first char of s that is whitespace or <b>;</b>,
 * or to the terminating NUL if no such character exists.
 */
const char *
find_whitespace(const char *s)
{
  /* tor_assert(s); */
  while (1) {
    switch (*s)
    {
    case '\0':
    case ';':
    case ' ':
    case '\r':
    case '\n':
    case '\t':
      return s;
    default:
      ++s;
    }
  }
}

/** As find_whitespace, but stop at <b>eos</b> whether we have found a
 * whitespace or not. */
const char *
find_whitespace_eos(const char *s, const char *eos)
{
  /* tor_assert(s); */
  while (s < eos) {
    switch (*s)
    {
    case '\0':
    case ';':
    case ' ':
    case '\r':
    case '\n':
    case '\t':
      return s;
    default:
      ++s;
    }
  }
  return s;
}

/** Return the first occurrence of <b>needle</b> in <b>haystack</b> that occurs at the start of a line (that is, at the beginning of <b>haystack</b> or immediately after a newline).  Return NULL if no such string is found. */
const char *find_str_at_start_of_line(const char *haystack, const char *needle)
{	size_t needle_len = strlen(needle);
	do
	{	if(!strncmp(haystack, needle, needle_len))
			return haystack;
		haystack = strchr(haystack, '\n');
		if(!haystack)	return NULL;
		else		++haystack;
	} while (*haystack);
	return NULL;
}


/** Return true iff the 'len' bytes at 'mem' are all zero. */
int
tor_mem_is_zero(const char *mem, size_t len)
{
  static const char ZERO[] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
  };
  while (len >= sizeof(ZERO)) {
    if (fast_memcmp(mem, ZERO, sizeof(ZERO)))
      return 0;
    len -= sizeof(ZERO);
    mem += sizeof(ZERO);
  }
  /* Deal with leftover bytes. */
  if (len)
    return fast_memeq(mem,ZERO,len);
  return 1;
}

/** Return true iff the DIGEST_LEN bytes in digest are all zero. */
int
tor_digest_is_zero(const char *digest)
{
  static const uint8_t ZERO_DIGEST[] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
  };
  return tor_memeq(digest, ZERO_DIGEST, DIGEST_LEN);
}

/** Return true iff the DIGEST256_LEN bytes in digest are all zero. */
int tor_digest256_is_zero(const char *digest)
{	return tor_mem_is_zero(digest, DIGEST256_LEN);
}

#define CHECK_STRTOX_RESULT()                           \
  /* Did an overflow occur? Was at least one character converted? */           \
  if(errno != ERANGE && endptr != s)                    \
  { /* Were there unexpected unconverted characters? */ \
    if (next || !*endptr)                               \
    { /* Is r within limits? */                         \
      if (r >= min && r <= max)                         \
      { if (ok) *ok = 1;                                \
        if (next) *next = endptr;                       \
        return r;                                       \
      }                                                 \
    }                                                   \
  }                                                     \
  if (ok) *ok = 0;                                      \
  if (next) *next = endptr;                             \
  return 0 

/** Extract a long from the start of s, in the given numeric base.  If
 * there is unconverted data and next is provided, set *next to the
 * first unconverted character.  An error has occurred if no characters
 * are converted; or if there are unconverted characters and next is NULL; or
 * if the parsed value is not between min and max.  When no error occurs,
 * return the parsed value and set *ok (if provided) to 1.  When an error
 * occurs, return 0 and set *ok (if provided) to 0.
 */
long tor_parse_long(const char *s, int base, long min, long max,int *ok, char **next)
{	char *endptr;
	long r;
	r = strtol(s, &endptr, base);
	if(next) *next = endptr;
	if(endptr == s || (!next && *endptr) || (r < min || r > max))
	{	if(ok) *ok = 0;
		return 0;
	}
	if(ok) *ok = 1;
	return r;
}

/** As tor_parse_long(), but return an unsigned long. */
unsigned long tor_parse_ulong(const char *s, int base, unsigned long min,unsigned long max, int *ok, char **next)
{	char *endptr;
	unsigned long r;
	errno = 0;
	r = strtoul(s, &endptr, base);
	if(next)	*next = endptr;
	if(endptr == s || (!next && *endptr) || (r < min || r > max))
	{	if(ok) *ok = 0;
		return 0;
	}
	if(ok)	*ok = 1;
	return r;
}

/** As tor_parse_long(), but return a double. */
double tor_parse_double(const char *s, double min, double max, int *ok, char **next)
{	char *endptr;
	double r;
	errno = 0;
	r = strtod(s, &endptr);
	CHECK_STRTOX_RESULT();
}

/** As tor_parse_log, but return a unit64_t.  Only base 10 is guaranteed to
 * work for now. */
uint64_t
tor_parse_uint64(const char *s, int base, uint64_t min,
                 uint64_t max, int *ok, char **next)
{
  char *endptr;
  uint64_t r;

  errno = 0;
#ifdef HAVE_STRTOULL
  r = (uint64_t)strtoull(s, &endptr, base);
#elif defined(MS_WINDOWS)
#if defined(_MSC_VER) && _MSC_VER < 1300
  tor_assert(base <= 10);
  r = (uint64_t)_atoi64(s);
  endptr = (char*)s;
  while (TOR_ISSPACE(*endptr)) endptr++;
  while (TOR_ISDIGIT(*endptr)) endptr++;
#else
  r = (uint64_t)_strtoui64(s, &endptr, base);
#endif
#elif SIZEOF_LONG == 8
  r = (uint64_t)strtoul(s, &endptr, base);
#else
#error "I don't know how to parse 64-bit numbers."
#endif

	if(next)	*next = endptr;
	if(endptr == s || (!next && *endptr) || (r < min || r > max))
	{	if (ok) *ok = 0;
		return 0;
	}
	if(ok)	*ok = 1;
	return r;
}

/** Encode the <b>srclen</b> bytes at <b>src</b> in a NUL-terminated,
 * uppercase hexadecimal string; store it in the <b>destlen</b>-byte buffer
 * <b>dest</b>.
 */
void
base16_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;
  char *cp;

  tor_assert(destlen >= srclen*2+1);
  tor_assert(destlen < SIZE_T_CEILING);

  cp = dest;
  end = src+srclen;
  while (src<end) {
    *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) >> 4 ];
    *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) & 0xf ];
    ++src;
  }
  *cp = '\0';
}

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
static INLINE int
_hex_decode_digit(char c)
{
  switch (c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': case 'a': return 10;
    case 'B': case 'b': return 11;
    case 'C': case 'c': return 12;
    case 'D': case 'd': return 13;
    case 'E': case 'e': return 14;
    case 'F': case 'f': return 15;
    default:
      return -1;
  }
}

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
int
hex_decode_digit(char c)
{
  return _hex_decode_digit(c);
}

/** Given a hexadecimal string of <b>srclen</b> bytes in <b>src</b>, decode it
 * and store the result in the <b>destlen</b>-byte buffer at <b>dest</b>.
 * Return 0 on success, -1 on failure. */
int
base16_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;

  int v1,v2;
  if ((srclen % 2) != 0)
    return -1;
  if (destlen < srclen/2 || destlen > SIZE_T_CEILING)
    return -1;
  end = src+srclen;
  while (src<end) {
    v1 = _hex_decode_digit(*src);
    v2 = _hex_decode_digit(*(src+1));
    if (v1<0||v2<0)
      return -1;
    *(uint8_t*)dest = (v1<<4)|v2;
    ++dest;
    src+=2;
  }
  return 0;
}

/** Allocate and return a new string representing the contents of <b>s</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * Generally, we use this for logging values that come in over the network to
 * keep them from tricking users, and for sending certain values to the
 * controller.
 *
 * We trust values from the resolver, OS, configuration file, and command line
 * to not be maliciously ill-formed.  We validate incoming routerdescs and
 * SOCKS requests and addresses from BEGIN cells as they're parsed;
 * afterwards, we trust them as non-malicious.
 */
char *
esc_for_log(const char *s)
{
  const char *cp;
  char *result, *outp;
  size_t len = 3;
  if (!s) {
    return tor_strdup("");
  }

  for (cp = s; *cp; ++cp) {
    switch (*cp) {
      case '\\':
      case '\"':
      case '\'':
      case '\r':
      case '\n':
      case '\t':
        len += 2;
        break;
      default:
        if (TOR_ISPRINT(*cp) && ((uint8_t)*cp)<127)
          ++len;
        else
          len += 4;
        break;
    }
  }

  result = outp = tor_malloc(len);
  *outp++ = '\"';
  for (cp = s; *cp; ++cp) {
    switch (*cp) {
      case '\\':
      case '\"':
      case '\'':
        *outp++ = '\\';
        *outp++ = *cp;
        break;
      case '\n':
        *outp++ = '\\';
        *outp++ = 'n';
        break;
      case '\t':
        *outp++ = '\\';
        *outp++ = 't';
        break;
      case '\r':
        *outp++ = '\\';
        *outp++ = 'r';
        break;
      default:
        if (TOR_ISPRINT(*cp) && ((uint8_t)*cp)<127) {
          *outp++ = *cp;
        } else {
          tor_snprintf(outp, 5, "\\%03o", (int)(uint8_t) *cp);
          outp += 4;
        }
        break;
    }
  }

  *outp++ = '\"';
  *outp++ = 0;

  return result;
}

/** Rudimentary string wrapping code: given a un-wrapped <b>string</b> (no
 * newlines!), break the string into newline-terminated lines of no more than
 * <b>width</b> characters long (not counting newline) and insert them into
 * <b>out</b> in order.  Precede the first line with prefix0, and subsequent
 * lines with prefixRest.
 */
/* This uses a stupid greedy wrapping algorithm right now:
 *  - For each line:
 *    - Try to fit as much stuff as possible, but break on a space.
 *    - If the first "word" of the line will extend beyond the allowable
 *      width, break the word at the end of the width.
 */
void
wrap_string(smartlist_t *out, const char *string, size_t width,
            const char *prefix0, const char *prefixRest)
{
  size_t p0Len, pRestLen, pCurLen;
  const char *eos, *prefixCur;
  tor_assert(out);
  tor_assert(string);
  tor_assert(width);
  if (!prefix0)
    prefix0 = "";
  if (!prefixRest)
    prefixRest = "";

  p0Len = strlen(prefix0);
  pRestLen = strlen(prefixRest);
  tor_assert(width > p0Len && width > pRestLen);
  eos = strchr(string, '\0');
  tor_assert(eos);
  pCurLen = p0Len;
  prefixCur = prefix0;

  while ((eos-string)+pCurLen > width) {
    const char *eol = string + width - pCurLen;
    while (eol > string && *eol != ' ')
      --eol;
    /* eol is now the last space that can fit, or the start of the string. */
    if (eol > string) {
      size_t line_len = (eol-string) + pCurLen + 3;
      char *line = tor_malloc(line_len);
      memcpy(line, prefixCur, pCurLen);
      memcpy(line+pCurLen, string, eol-string);
      line[line_len-3] = '\r';
      line[line_len-2] = '\n';
      line[line_len-1] = '\0';
      smartlist_add(out, line);
      string = eol + 1;
    } else {
      size_t line_len = width + 3;
      char *line = tor_malloc(line_len);
      memcpy(line, prefixCur, pCurLen);
      memcpy(line+pCurLen, string, width - pCurLen);
      line[line_len-3] = '\r';
      line[line_len-2] = '\n';
      line[line_len-1] = '\0';
      smartlist_add(out, line);
      string += width-pCurLen;
    }
    prefixCur = prefixRest;
    pCurLen = pRestLen;
  }

  if (string < eos) {
    size_t line_len = (eos-string) + pCurLen + 3;
    char *line = tor_malloc(line_len);
    memcpy(line, prefixCur, pCurLen);
    memcpy(line+pCurLen, string, eos-string);
    line[line_len-3] = '\r';
    line[line_len-2] = '\n';
    line[line_len-1] = '\0';
    smartlist_add(out, line);
  }
}

/* =====
 * Time
 * ===== */

/** Converts struct timeval to a double value. Preserves microsecond precision, but just barely. Error is approx +/- 0.1 usec when dealing with epoch values. */
double tv_to_double(const struct timeval *tv)
{	double conv = tv->tv_sec;
	conv += tv->tv_usec/1000000.0;
	return conv;
}

/** Converts timeval to milliseconds. */
int64_t tv_to_msec(const struct timeval *tv)
{	int64_t conv = ((int64_t)tv->tv_sec)*1000L;
	/* Round ghetto-style */
	conv += ((int64_t)tv->tv_usec+500)/1000L;
	return conv;
}

/** Converts timeval to microseconds. */
int64_t tv_to_usec(const struct timeval *tv)
{	int64_t conv = ((int64_t)tv->tv_sec)*1000000L;
	conv += tv->tv_usec;
	return conv;
}


/** Return the number of microseconds elapsed between *start and *end.
 */
long
tv_udiff(const struct timeval *start, const struct timeval *end)
{
  long udiff;
  long secdiff = end->tv_sec - start->tv_sec;

  if (labs(secdiff+1) > LONG_MAX/1000000) {
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_TV_UDIFF));
    return LONG_MAX;
  }

  udiff = secdiff*1000000L + (end->tv_usec - start->tv_usec);
  return udiff;
}

/** Return the number of milliseconds elapsed between *start and *end.
 */
long
tv_mdiff(const struct timeval *start, const struct timeval *end)
{
  long mdiff;
  long secdiff = end->tv_sec - start->tv_sec;

  if (labs(secdiff+1) > LONG_MAX/1000) {
    log_warn(LD_GENERAL, "comparing times on millisecond detail too far "
             "apart: %ld seconds", secdiff);
    return LONG_MAX;
  }

  /* Subtract and round */
  mdiff = secdiff*1000L +
      ((long)end->tv_usec - (long)start->tv_usec + 500L) / 1000L;
  return mdiff;
}

/** Yield true iff <b>y</b> is a leap-year. */
#define IS_LEAPYEAR(y) (!(y % 4) && ((y % 100) || !(y % 400)))
/** Helper: Return the number of leap-days between Jan 1, y1 and Jan 1, y2. */
static int
n_leapdays(int y1, int y2)
{
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}
/** Number of days per month in non-leap year; used by tor_timegm. */
static const int days_per_month[] =
  { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/** Compute a time_t given a struct tm.  The result is given in GMT, and
 * does not account for leap seconds.  Return 0 on success, -1 on failure.
 */
int
tor_timegm(const struct tm *tm, time_t *time_out)
{
  /* This is a pretty ironclad timegm implementation, snarfed from Python2.2.
   * It's way more brute-force than fiddling with tzset().
   */
  time_t year, days, hours, minutes, seconds;
  int i;
  year = tm->tm_year + 1900;
  if (year < 1970 || tm->tm_mon < 0 || tm->tm_mon > 11 ||
      tm->tm_year >= INT32_MAX-1900) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_UTIL_TIMEGM));
    return -1;
  }
  days = 365 * (year-1970) + n_leapdays(1970,(int)year);
  for (i = 0; i < tm->tm_mon; ++i)
    days += days_per_month[i];
  if (tm->tm_mon > 1 && IS_LEAPYEAR(year))
    ++days;
  days += tm->tm_mday - 1;
  hours = days*24 + tm->tm_hour;

  minutes = hours*60 + tm->tm_min;
  seconds = minutes*60 + tm->tm_sec;
  if(time_out)	*time_out = seconds;
  return 0;
}

/* strftime is locale-specific, so we need to replace those parts */

/** A c-locale array of 3-letter names of weekdays, starting with Sun. */
static const char *WEEKDAY_NAMES[] =
  { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
/** A c-locale array of 3-letter names of months, starting with Jan. */
static const char *MONTH_NAMES[] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/** Set <b>buf</b> to the RFC1123 encoding of the GMT value of <b>t</b>.
 * The buffer must be at least RFC1123_TIME_LEN+1 bytes long.
 *
 * (RFC1123 format is Fri, 29 Sep 2006 15:54:20 GMT)
 */
void
format_rfc1123_time(char *buf, time_t t)
{
  struct tm tm;

  tor_gmtime_r(&t, &tm);

  strftime(buf, RFC1123_TIME_LEN+1, "___, %d ___ %Y %H:%M:%S GMT", &tm);
  tor_assert(tm.tm_wday >= 0);
  tor_assert(tm.tm_wday <= 6);
  memcpy(buf, WEEKDAY_NAMES[tm.tm_wday], 3);
  tor_assert(tm.tm_mon >= 0);
  tor_assert(tm.tm_mon <= 11);
  memcpy(buf+8, MONTH_NAMES[tm.tm_mon], 3);
}

/** Parse the the RFC1123 encoding of some time (in GMT) from <b>buf</b>,
 * and store the result in *<b>t</b>.
 *
 * Return 0 on succcess, -1 on failure.
*/
int
parse_rfc1123_time(const char *buf, time_t *t)
{
  struct tm tm;
  char month[4];
  char weekday[4];
  int i, m;
  unsigned tm_mday, tm_year, tm_hour, tm_min, tm_sec;

  if (strlen(buf) != RFC1123_TIME_LEN)
    return -1;
  memset(&tm, 0, sizeof(tm));
  if (tor_sscanf(buf, "%3s, %2u %3s %u %2u:%2u:%2u GMT", weekday,
             &tm_mday, month, &tm_year, &tm_hour,
             &tm_min, &tm_sec) < 7) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME),esc);
    tor_free(esc);
    return -1;
  }
  if (tm_mday < 1 || tm_mday > 31 || tm_hour > 23 || tm_min > 59 ||
      tm_sec > 60 || tm_year >= INT32_MAX || tm_year < 1970) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME),esc);
    tor_free(esc);
    return -1;
  }
  tm.tm_mday = (int)tm_mday;
  tm.tm_year = (int)tm_year;
  tm.tm_hour = (int)tm_hour;
  tm.tm_min = (int)tm_min;
  tm.tm_sec = (int)tm_sec;

  m = -1;
  for (i = 0; i < 12; ++i) {
    if (!strcmp(month, MONTH_NAMES[i])) {
      m = i;
      break;
    }
  }
  if (m<0) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME_2),esc);
    tor_free(esc);
    return -1;
  }
  tm.tm_mon = m;

  if (tm.tm_year < 1970) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME_3),esc);
    tor_free(esc);
    return -1;
  }
  tm.tm_year -= 1900;

  return tor_timegm(&tm, t);
}

/** Set <b>buf</b> to the ISO8601 encoding of the local value of <b>t</b>.
 * The buffer must be at least ISO_TIME_LEN+1 bytes long.
 *
 * (ISO8601 format is 2006-10-29 10:57:20)
 */
void
format_local_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_localtime_r(&t, &tm));
}

/** Set <b>buf</b> to the ISO8601 encoding of the GMT value of <b>t</b>.
 * The buffer must be at least ISO_TIME_LEN+1 bytes long.
 */
void
format_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_gmtime_r(&t, &tm));
}

/** Given an ISO-formatted UTC time value (after the epoch) in <b>cp</b>,
 * parse it and store its value in *<b>t</b>.  Return 0 on success, -1 on
 * failure.  Ignore extraneous stuff in <b>cp</b> separated by whitespace from
 * the end of the time string. */
int
parse_iso_time(const char *cp, time_t *t)
{
  struct tm st_tm;
  unsigned int year=0, month=0, day=0, hour=0, minute=0, second=0;
  if (tor_sscanf(cp, "%u-%2u-%2u %2u:%2u:%2u", &year, &month,
                &day, &hour, &minute, &second) < 6) {
    char *esc = esc_for_log(cp);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME_4),esc);
    tor_free(esc);
    return -1;
  }
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
          hour > 23 || minute > 59 || second > 60 || year >= INT32_MAX) {
    char *esc = esc_for_log(cp);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME_5),esc);
    tor_free(esc);
    return -1;
  }
  st_tm.tm_year = (int)year-1900;
  st_tm.tm_mon = month-1;
  st_tm.tm_mday = day;
  st_tm.tm_hour = hour;
  st_tm.tm_min = minute;
  st_tm.tm_sec = second;

  if (st_tm.tm_year < 70) {
    char *esc = esc_for_log(cp);
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_UTIL_INVALID_TIME_6),esc);
    tor_free(esc);
    return -1;
  }
  return tor_timegm(&st_tm, t);
}

/** Given a <b>date</b> in one of the three formats allowed by HTTP (ugh),
 * parse it into <b>tm</b>.  Return 0 on success, negative on failure. */
int
parse_http_time(const char *date, struct tm *tm)
{
  const char *cp;
  char month[4];
  char wkday[4];
  int i;
  unsigned tm_mday, tm_year, tm_hour, tm_min, tm_sec;

  tor_assert(tm);
  memset(tm, 0, sizeof(*tm));

  /* First, try RFC1123 or RFC850 format: skip the weekday.  */
  if ((cp = strchr(date, ','))) {
    ++cp;
    if (*cp != ' ')
      return -1;
    ++cp;
    if (tor_sscanf(cp, "%2u %3s %4u %2u:%2u:%2u GMT",
               &tm_mday, month, &tm_year,
               &tm_hour, &tm_min, &tm_sec) == 6) {
      /* rfc1123-date */
      tm_year -= 1900;
    } else if (tor_sscanf(cp, "%2u-%3s-%2u %2u:%2u:%2u GMT",
                      &tm_mday, month, &tm_year,
                      &tm_hour, &tm_min, &tm_sec) == 6) {
      /* rfc850-date */
    } else {
      return -1;
    }
  } else {
    /* No comma; possibly asctime() format. */
    if (tor_sscanf(date, "%3s %3s %2u %2u:%2u:%2u %4u",
               wkday, month, &tm_mday,
               &tm_hour, &tm_min, &tm_sec, &tm_year) == 7) {
      tm_year -= 1900;
    } else {
      return -1;
    }
  }
  tm->tm_mday = (int)tm_mday;
  tm->tm_year = (int)tm_year;
  tm->tm_hour = (int)tm_hour;
  tm->tm_min = (int)tm_min;
  tm->tm_sec = (int)tm_sec;

  month[3] = '\0';
  /* Okay, now decode the month. */
  /* set tm->tm_mon to dummy value so the check below fails. */
  tm->tm_mon = -1;
  for (i = 0; i < 12; ++i) {
    if (!strcasecmp(MONTH_NAMES[i], month)) {
      tm->tm_mon = i;
    }
  }

  if (tm->tm_year < 0 ||
      tm->tm_mon < 0  || tm->tm_mon > 11 ||
      tm->tm_mday < 1 || tm->tm_mday > 31 ||
      tm->tm_hour < 0 || tm->tm_hour > 23 ||
      tm->tm_min < 0  || tm->tm_min > 59 ||
      tm->tm_sec < 0  || tm->tm_sec > 60)
    return -1; /* Out of range, or bad month. */

  return 0;
}

/** Given an <b>interval</b> in seconds, try to write it to the
 * <b>out_len</b>-byte buffer in <b>out</b> in a human-readable form.
 * Return 0 on success, -1 on failure.
 */
int
format_time_interval(char *out, size_t out_len, long interval)
{
  /* We only report seconds if there's no hours. */
  long sec = 0, min = 0, hour = 0, day = 0;
  if (interval < 0)
    interval = -interval;

  if (interval >= 86400) {
    day = interval / 86400;
    interval %= 86400;
  }
  if (interval >= 3600) {
    hour = interval / 3600;
    interval %= 3600;
  }
  if (interval >= 60) {
    min = interval / 60;
    interval %= 60;
  }
  sec = interval;

  if (day) {
    return tor_snprintf(out, out_len, "%ld days, %ld hours, %ld minutes",
                        day, hour, min);
  } else if (hour) {
    return tor_snprintf(out, out_len, "%ld hours, %ld minutes", hour, min);
  } else if (min) {
    return tor_snprintf(out, out_len, "%ld minutes, %ld seconds", min, sec);
  } else {
    return tor_snprintf(out, out_len, "%ld seconds", sec);
  }
}

/* =====
 * Cached time
 * ===== */

#ifndef TIME_IS_FAST
/** Cached estimate of the currrent time.  Updated around once per second;
 * may be a few seconds off if we are really busy.  This is a hack to avoid
 * calling time(NULL) (which not everybody has optimized) on critical paths.
 */
static time_t cached_approx_time = 0;

/** Return a cached estimate of the current time from when
 * update_approx_time() was last called.  This is a hack to avoid calling
 * time(NULL) on critical paths: please do not even think of calling it
 * anywhere else. */
time_t
approx_time(void)
{
  return cached_approx_time;
}

/** Update the cached estimate of the current time.  This function SHOULD be
 * called once per second, and MUST be called before the first call to
 * get_approx_time. */
void
update_approx_time(time_t now)
{
  cached_approx_time = now;
}
#endif

/* =====
 * Rate limiting
 * ===== */

/** If the rate-limiter <b>lim</b> is ready at <b>now</b>, return the number of calls to rate_limit_is_ready (including this one!) since the last time rate_limit_is_ready returned nonzero.  Otherwise return 0. */
static int rate_limit_is_ready(ratelim_t *lim, time_t now)
{	if(lim->rate + lim->last_allowed <= now)
	{	int res = lim->n_calls_since_last_time + 1;
		lim->last_allowed = now;
		lim->n_calls_since_last_time = 0;
		return res;
	}
	++lim->n_calls_since_last_time;
	return 0;
}

/** If the rate-limiter <b>lim</b> is ready at <b>now</b>, return a newly allocated string indicating how many messages were suppressed, suitable to append to a log message. Otherwise return NULL. */
char *rate_limit_log(ratelim_t *lim, time_t now)
{	int n;
	if((n = rate_limit_is_ready(lim, now)))
	{	if(n == 1)	return tor_strdup("");
		unsigned char *cp=NULL;
		tor_asprintf(&cp," [%d similar message(s) suppressed in last %d seconds]",n-1, lim->rate);
		return (char *)cp;
	}
	return NULL;
}



#define TOR_ISODIGIT(c) ('0' <= (c) && (c) <= '7')

/** Given a c-style double-quoted escaped string in <b>s</b>, extract and
 * decode its contents into a newly allocated string.  On success, assign this
 * string to *<b>result</b>, assign its length to <b>size_out</b> (if
 * provided), and return a pointer to the position in <b>s</b> immediately
 * after the string.  On failure, return NULL.
 */
static const char *unescape_string(const char *s, char **result, size_t *size_out)
{	const char *cp;
	char *out;
	if(s[0] != '\"')	return NULL;
	cp = s+1;
	while(1)
	{	if(*cp == '\"')	break;
		switch(*cp)
		{	case '\0':
			case '\n':
				return NULL;
			case '\\':
				if(cp[1] == 'x' || cp[1] == 'X')
				{	if(!(TOR_ISXDIGIT(cp[2]) && TOR_ISXDIGIT(cp[3])))
						return NULL;
					cp += 4;
				}
				else if (TOR_ISODIGIT(cp[1]))
				{	cp += 2;
					if(TOR_ISODIGIT(*cp)) ++cp;
					if(TOR_ISODIGIT(*cp)) ++cp;
				}
				else if(cp[1] == 'n' || cp[1] == 'r' || cp[1] == 't' || cp[1] == '"' || cp[1] == '\\' || cp[1] == '\'')
				{	cp += 2;
				}
				else
				{	return NULL;
				}
				break;
			default:
				++cp;
				break;
		}
	}
	out = *result = tor_malloc(cp-s + 1);
	cp = s+1;
	while(1)
	{	switch(*cp)
		{	case '\"':
				*out = '\0';
				if(size_out)	*size_out = out - *result;
				return cp+1;
			case '\0':
				tor_fragile_assert();
				tor_free(*result);
				return NULL;
			case '\\':
				switch(cp[1])
				{	case 'n': *out++ = '\n'; cp += 2; break;
					case 'r': *out++ = '\r'; cp += 2; break;
					case 't': *out++ = '\t'; cp += 2; break;
					case 'x': case 'X':
						{	int x1, x2;
							x1 = hex_decode_digit(cp[2]);
							x2 = hex_decode_digit(cp[3]);
							if(x1 == -1 || x2 == -1)
							{	tor_free(*result);
								return NULL;
							}
							*out++ = ((x1<<4) + x2);
							cp += 4;
						}
						break;
					case '0': case '1': case '2': case '3': case '4': case '5':
					case '6': case '7':
						{	int n = cp[1]-'0';
							cp += 2;
							if(TOR_ISODIGIT(*cp))
							{	n = n*8 + *cp-'0';
								cp++;
							}
							if(TOR_ISODIGIT(*cp))
							{	n = n*8 + *cp-'0';
								cp++;
							}
							if(n > 255)
							{	tor_free(*result);
								return NULL;
							}
							*out++ = (char)n;
						}
						break;
					case '\'':
					case '\"':
					case '\\':
					case '\?':
						*out++ = cp[1];
						cp += 2;
						break;
					default:
						tor_free(*result); return NULL;
				}
				break;
			default:
				*out++ = *cp++;
		}
	}
}

/** Given a string containing part of a configuration file or similar format,
 * advance past comments and whitespace and try to parse a single line.  If we
 * parse a line successfully, set *<b>key_out</b> to a new string holding the
 * key portion and *<b>value_out</b> to a new string holding the value portion
 * of the line, and return a pointer to the start of the next line.  If we run
 * out of data, return a pointer to the end of the string.  If we encounter an
 * error, return NULL.
 */
const char *parse_config_line_from_str(const char *line, char **key_out, char **value_out)
{
  /* I believe the file format here is supposed to be:
     FILE = (EMPTYLINE | LINE)* (EMPTYLASTLINE | LASTLINE)?

     EMPTYLASTLINE = SPACE* | COMMENT
     EMPTYLINE = EMPTYLASTLINE NL
     SPACE = ' ' | '\r' | '\t'
     COMMENT = '#' NOT-NL*
     NOT-NL = Any character except '\n'
     NL = '\n'

     LASTLINE = SPACE* KEY SPACE* VALUES
     LINE = LASTLINE NL
     KEY = KEYCHAR+
     KEYCHAR = Any character except ' ', '\r', '\n', '\t', '#', "\"

     VALUES = QUOTEDVALUE | NORMALVALUE
     QUOTEDVALUE = QUOTE QVITEM* QUOTE EOLSPACE?
     QUOTE = '"'
     QVCHAR = KEYCHAR | ESC ('n' | 't' | 'r' | '"' | ESC |'\'' | OCTAL | HEX)
     ESC = "\\"
     OCTAL = ODIGIT (ODIGIT ODIGIT?)?
     HEX = ('x' | 'X') HEXDIGIT HEXDIGIT
     ODIGIT = '0' .. '7'
     HEXDIGIT = '0'..'9' | 'a' .. 'f' | 'A' .. 'F'
     EOLSPACE = SPACE* COMMENT?

     NORMALVALUE = (VALCHAR | ESC ESC_IGNORE | CONTINUATION)* EOLSPACE?
     VALCHAR = Any character except ESC, '#', and '\n'
     ESC_IGNORE = Any character except '#' or '\n'
     CONTINUATION = ESC NL ( COMMENT NL )*
   */

  const char *key, *val, *cp;
  int continuation = 0;

  tor_assert(key_out);
  tor_assert(value_out);

  *key_out = *value_out = NULL;
  key = val = NULL;
  /* Skip until the first keyword. */
  while (1) {
    while (TOR_ISSPACE(*line))
      ++line;
    if ((*line == ';')) {
      while (*line && *line != '\n')
        ++line;
    } else {
      break;
    }
  }

  if (!*line) { /* End of string? */
    *key_out = *value_out = NULL;
    return line;
  }

  /* Skip until the next space or \ followed by newline. */
  key = line;
  while (*line>32 && *line!='=' && *line != ';' && !(line[0] == '\\' && line[1] == '\n'))
    ++line;
  *key_out = tor_strndup(key, line-key);

  /* Skip until the value. */
  while (*line == ' ' || *line == '\t' || *line == '=')
    ++line;

  val = line;

  /* Find the end of the line. */
  if (*line == '\"') {
    if (!(line = unescape_string(line, value_out, NULL)))
       return NULL;
    while (*line == ' ' || *line == '\t')
      ++line;
    if (*line && *line != ';' && *line != '\n')
      return NULL;
  } else {
	while (*line && *line != '\n' && (*line != ';' || continuation))
	{	if(*line == '\\' && line[1] == '\n')
		{	continuation = 1;
			line += 2;
		}
		else if (*line == ';')
		{	do{	++line;	} while (*line && *line != '\n');
			if(*line == '\n')	++line;
		}
		else	++line;
	}

    if (*line == '\n') {
      cp = line++;
    } else {
      cp = line;
    }
    while (cp>val && TOR_ISSPACE(*(cp-1)))
      --cp;

    tor_assert(cp >= val);
    *value_out = tor_strndup(val, cp-val);
	if(continuation)
	{	char *v_out, *v_in;
		v_out = v_in = *value_out;
		while(*v_in)
		{	if(*v_in == ';')
			{	do{	++v_in;	} while(*v_in && *v_in != '\n');
				if(*v_in == '\n')	++v_in;
			}
			else if(v_in[0] == '\\' && v_in[1] == '\n')
				v_in += 2;
			else	*v_out++ = *v_in++;
		}
		*v_out = '\0';
	}
  }

  if (*line == ';') {
    do {
      ++line;
    } while (*line && *line != '\n');
  }
  while (TOR_ISSPACE(*line)) ++line;

  return line;
}


#define MAX_SCANF_WIDTH 9999

/** DOCDOC */
static int
digit_to_num(char d)
{
  int num = ((int)d) - (int)'0';
  tor_assert(num <= 9 && num >= 0);
  return num;
}

/** DOCDOC */
static int
scan_unsigned(const char **bufp, unsigned *out, int width)
{
  unsigned result = 0;
  int scanned_so_far = 0;
  if (!bufp || !*bufp || !out)
    return -1;
  if (width<0)
    width=MAX_SCANF_WIDTH;

  while (**bufp && TOR_ISDIGIT(**bufp) && scanned_so_far < width) {
    int digit = digit_to_num(*(*bufp)++);
    unsigned new_result = result * 10 + digit;
    if (new_result > UINT32_MAX || new_result < result)
      return -1; /* over/underflow. */
    result = new_result;
    ++scanned_so_far;
  }

  if (!scanned_so_far) /* No actual digits scanned */
    return -1;

  *out = result;
  return 0;
}

/** DOCDOC */
static int
scan_string(const char **bufp, char *out, int width)
{
  int scanned_so_far = 0;
  if (!bufp || !out || width < 0)
    return -1;
  while (**bufp && ! TOR_ISSPACE(**bufp) && scanned_so_far < width) {
    *out++ = *(*bufp)++;
    ++scanned_so_far;
  }
  *out = '\0';
  return 0;
}

/** Locale-independent, minimal, no-surprises scanf variant, accepting only a
 * restricted pattern format.  For more info on what it supports, see
 * tor_sscanf() documentation.  */
int
tor_vsscanf(const char *buf, const char *pattern, va_list ap)
{
  int n_matched = 0;

  while (*pattern) {
    if (*pattern != '%') {
      if (*buf == *pattern) {
        ++buf;
        ++pattern;
        continue;
      } else {
        return n_matched;
      }
    } else {
      int width = -1;
      ++pattern;
      if (TOR_ISDIGIT(*pattern)) {
        width = digit_to_num(*pattern++);
        while (TOR_ISDIGIT(*pattern)) {
          width *= 10;
          width += digit_to_num(*pattern++);
          if (width > MAX_SCANF_WIDTH)
            return -1;
        }
        if (!width) /* No zero-width things. */
          return -1;
      }
      if (*pattern == 'u') {
        unsigned *u = va_arg(ap, unsigned *);
        if (!*buf)
          return n_matched;
        if (scan_unsigned(&buf, u, width)<0)
          return n_matched;
        ++pattern;
        ++n_matched;
      } else if (*pattern == 's') {
        char *s = va_arg(ap, char *);
        if (width < 0)
          return -1;
        if (scan_string(&buf, s, width)<0)
          return n_matched;
        ++pattern;
        ++n_matched;
      } else if (*pattern == 'c') {
        char *ch = va_arg(ap, char *);
        if (width != -1)
          return -1;
        if (!*buf)
          return n_matched;
        *ch = *buf++;
        ++pattern;
        ++n_matched;
      } else if (*pattern == '%') {
        if (*buf != '%')
          return -1;
        ++buf;
        ++pattern;
      } else {
        return -1; /* Unrecognized pattern component. */
      }
    }
  }

  return n_matched;
}

/** Minimal sscanf replacement: parse <b>buf</b> according to <b>pattern</b>
 * and store the results in the corresponding argument fields.  Differs from
 * sscanf in that it: Only handles %u and %Ns.  Does not handle arbitrarily
 * long widths. %u does not consume any space.  Is locale-independent.
 * Returns -1 on malformed patterns. */
int
tor_sscanf(const char *buf, const char *pattern, ...)
{
  int r;
  va_list ap;
  va_start(ap, pattern);
  r = tor_vsscanf(buf, pattern, ap);
  va_end(ap);
  return r;
}


/* =====
 * Process helpers
 * ===== */

void
start_daemon(void)
{
}
void
finish_daemon(const char *cp)
{
  (void)cp;
}

/** Write the current process ID, followed by NL, into <b>filename</b>.
 */
void
write_pidfile(char *filename)
{
  FILE *pidfile;

  if ((pidfile = fopen(filename, "w")) == NULL) {
    log_warn(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_OPENING_FILE_4),filename,strerror(errno));
  } else {
    fprintf(pidfile, "%d\n", (int)_getpid());
    fclose(pidfile);
  }
}
