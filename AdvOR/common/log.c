/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id: log.c 14222 2008-03-27 17:25:49Z weasel $ */
const char log_c_id[] = "$Id: log.c 14222 2008-03-27 17:25:49Z weasel $";

/**
 * \file log.c
 * \brief Functions to send messages to log files or the console.
 **/

#include "orconfig.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "util.h"
#define LOG_PRIVATE
#include "log.h"
#include "container.h"

#include <event.h>

#define TRUNCATED_STR "[...truncated]"
#define TRUNCATED_STR_LEN 14

HWND hdialog=NULL;
HANDLE hfile=NULL;
int lseverity=LOG_WARN;
char *logfilter=NULL,fltlocked=0;
smartlist_t *logcache=NULL;

void cache_log(char *str)
{
	if(logcache==NULL)
	{	logcache = smartlist_create();
	}
	smartlist_add(logcache,tor_strdup(str));
}

void setDialog(HWND hDlg)
{	hdialog=hDlg;
}

HWND getDialog(void)
{	return hdialog;
}

HANDLE open_file(char *fname,DWORD access,DWORD creationDistribution);

void setLog(int severity,char *fname)
{	lseverity=severity;
	if(fname)
	{	hfile=open_file(fname,GENERIC_READ|GENERIC_WRITE,OPEN_ALWAYS);
		if(hfile==INVALID_HANDLE_VALUE) hfile=NULL;
		else SetFilePointer(hfile,0,0,FILE_END);
	}
	else
	{	if(hfile) CloseHandle(hfile);
		hfile=NULL;
	}
}

char *getLogFilter(void)
{	return logfilter;
}

void setLogFilter(char *filter)
{	while(fltlocked) Sleep(10);
	fltlocked++;
	if(logfilter) tor_free(logfilter);
	logfilter=filter;
	fltlocked=0;
}

void setLogging(int severity)
{	lseverity=severity;
//	_log_global_min_severity=severity;
}

#ifndef PBM_SETPOS
#define PBM_SETPOS	(WM_USER+2)
#endif

/** Information for a single logfile; only used in log.c */
typedef struct logfile_t {
  struct logfile_t *next; /**< Next logfile_t in the linked list. */
  char *filename; /**< Filename to open. */
  FILE *file; /**< Stream to receive log messages. */
  int seems_dead; /**< Boolean: true if the stream seems to be kaput. */
  int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
  int is_temporary; /**< Boolean: close after initializing logging subsystem.*/
  int is_syslog; /**< Boolean: send messages to syslog. */
  log_callback callback; /**< If not NULL, send messages to this function. */
  log_severity_list_t *severities; /**< DOCDOC */
} logfile_t;

static void log_free(logfile_t *victim);

/** Helper: map a log severity to descriptive string. */
static INLINE const char *
sev_to_string(int severity)
{
  switch (severity) {
    case LOG_DEBUG:   return get_lang_str(LANG_LOG_LOG__DEBUG);
    case LOG_ADDR:    return get_lang_str(LANG_LOG_LOG__PROXY);
    case LOG_INFO:    return get_lang_str(LANG_LOG_LOG__INFO);
    case LOG_NOTICE:  return get_lang_str(LANG_LOG_LOG__NOTICE);
    case LOG_WARN:    return get_lang_str(LANG_LOG_LOG__WARN);
    case LOG_ERR:     return get_lang_str(LANG_LOG_LOG__ERROR);
    default:          /* Call assert, not tor_assert, since tor_assert
                       * calls log on failure. */
                      tor_assert(0); return get_lang_str(LANG_LOG_LOG__UNKNOWN);
  }
}

/** Helper: decide whether to include the function name in the log message. */
static INLINE int
should_log_function_name(log_domain_mask_t domain, int severity)
{
  switch (severity) {
    case LOG_DEBUG:
    case LOG_INFO:
      /* All debugging messages occur in interesting places. */
      return 1;
    case LOG_NOTICE:
  case LOG_WARN:
    case LOG_ERR:
      /* We care about places where bugs occur. */
      return (domain == LD_BUG);
    default:
      /* Call assert, not tor_assert, since tor_assert calls log on failure. */
      tor_assert_2(0); return 0;
  }
}

/** Linked list of logfile_t. */
static logfile_t *logfiles = NULL;
#ifdef HAVE_SYSLOG_H
static int syslog_count = 0;
#endif

#define LOCK_LOGS() STMT_NIL
#define UNLOCK_LOGS() STMT_NIL

static INLINE char *
format_msg(char *buf, size_t buf_len,
           log_domain_mask_t domain, int severity, const char *funcname,
           const char *format, va_list ap)
  CHECK_PRINTF(6,0);
static void logv(int severity, log_domain_mask_t domain, const char *funcname,
                 const char *format, va_list ap)
  CHECK_PRINTF(4,0);

/* What's the lowest log level anybody cares about? */
//int _log_global_min_severity = LOG_NOTICE;

static void close_log(logfile_t *victim);

/** Name of the application: used to generate the message we write at the
 * start of each new log. */
static char *appname = NULL;

/** Set the "application name" for the logs to <b>name</b>: we'll use this
 * name in the message we write when starting up, and at the start of each new
 * log.
 *
 * Tor uses this string to write the version number to the log file. */
void
log_set_application_name(const char *name)
{
  tor_free(appname);
  appname = name ? tor_strdup(name) : NULL;
}

/** Helper: Write the standard prefix for log lines to a
 * <b>buf_len</b> character buffer in <b>buf</b>.
 */
static INLINE size_t
_log_prefix(char *buf, size_t buf_len, int severity)
{
	SYSTEMTIME t;
	GetLocalTime(&t);
	return tor_snprintf(buf,buf_len,"[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,sev_to_string(severity));
}

/** Helper: Format a log message into a fixed-sized buffer. (This is
 * factored out of <b>logv</b> so that we never format a message more
 * than once.)  Return a pointer to the first character of the message
 * portion of the formatted string.
 */
static INLINE char *
format_msg(char *buf, size_t buf_len,
           log_domain_mask_t domain, int severity, const char *funcname,
           const char *format, va_list ap)
{
  size_t n;
  int r;
  char *end_of_prefix;

  tor_assert_2(buf_len >= 3); /* prevent integer underflow */
  buf_len -= 3; /* subtract 3 characters so we have room for \n\0 */

  n = _log_prefix(buf, buf_len, severity);
  end_of_prefix = buf+n;

  if (funcname && should_log_function_name(domain, severity)) {
    r = tor_snprintf(buf+n, buf_len-n, "%s(): ", funcname);
    if (r<0)
      n = strlen(buf);
    else
      n += r;
  }

  if (domain == LD_BUG && buf_len-n > 6) {
    memcpy(buf+n, "Bug: ", 6);
    n += 5;
  }

  r = tor_vsnprintf(buf+n,buf_len-n,format,ap);
  if (r < 0) {
    /* The message was too long; overwrite the end of the buffer with
     * "[...truncated]" */
    if (buf_len >= TRUNCATED_STR_LEN) {
      size_t offset = buf_len-TRUNCATED_STR_LEN;
      /* We have an extra 3 characters after buf_len to hold the \n\0,
       * so it's safe to add 1 to the size here. */
      strlcpy(buf+offset, TRUNCATED_STR, buf_len-offset+1);
    }
    /* Set 'n' to the end of the buffer, where we'll be writing \n\0.
     * Since we already subtracted 3 from buf_len, this is safe.*/
    n = buf_len;
  } else {
    n += r;
  }
  buf[n++]='\r';
  buf[n]='\n';
  buf[n+1]='\0';
  return end_of_prefix;
}

/** Helper: sends a message to the appropriate logfiles, at loglevel
 * <b>severity</b>.  If provided, <b>funcname</b> is prepended to the
 * message.  The actual message is derived as from tor_snprintf(format,ap).
 */
static void
logv(int severity, log_domain_mask_t domain, const char *funcname,
     const char *format, va_list ap)
{
  char buf[10024];
  int i,j,k;
  unsigned long txtsize = 0;
  if((severity<=lseverity)&&((!fltlocked)||(!logfilter)))
  {
	format_msg(buf, sizeof(buf), domain, severity, funcname, format, ap);
	txtsize=strlen(buf);
  	if((logfilter&&(hfile||hdialog))&&(!fltlocked))
	{
		fltlocked++;
	//	asm(".intel_syntax noprefix\nint 3\n.att_syntax prefix");
		for(j=0;logfilter[j];)
		{	for(i=0;buf[i];i++)
			{
				for(k=0;;k++) if(((unsigned char)buf[k+i]!=(unsigned char)logfilter[k+j])||((unsigned char)logfilter[k+j]<32)||((unsigned char)buf[k+i]<32)) break;
				if((k!=0)&&((unsigned char)logfilter[k+j]<32)){	fltlocked=0;return;}
			}
			while((unsigned char)logfilter[j]>=32)	j++;
			while((logfilter[j]!=0)&&((unsigned char)logfilter[j]<32)) j++;
		}
		fltlocked=0;
	}
	if(hfile!=NULL)	WriteFile(hfile,buf,txtsize,&txtsize,0);
	buf[11]='[';
	if(hdialog!=NULL)	LangReplaceSel(&buf[11],hdialog);
	else if((!hfile)&&(severity<=LOG_ERR)) MessageBox(0,&buf[11+11],"Error",MB_OK);
	else
	{	cache_log(&buf[11]);
	}
  }
}

/** Output a message to the log. */
void
_log(int severity, log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (severity > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(severity, domain, NULL, format, ap);
  va_end(ap);
}

/** Output a message to the log, prefixed with a function name <b>fn</b>. */
#ifdef __GNUC__
void
_log_fn(int severity, log_domain_mask_t domain, const char *fn,
        const char *format, ...)
{
  va_list ap;
/*  if (severity > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(severity, domain, fn, format, ap);
  va_end(ap);
}
#else
const char *_log_fn_function_name=NULL;
void
_log_fn(int severity, log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (severity > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(severity, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_debug(log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
  /* For GCC we do this check in the macro. */
/*  if (PREDICT_LIKELY(LOG_DEBUG > _log_global_min_severity))
    return;*/
  va_start(ap,format);
  logv(LOG_DEBUG, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_info(log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (LOG_INFO > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(LOG_INFO, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_notice(log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (LOG_NOTICE > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(LOG_NOTICE, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_warn(log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (LOG_WARN > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(LOG_WARN, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_err(log_domain_mask_t domain, const char *format, ...)
{
  va_list ap;
/*  if (LOG_ERR > _log_global_min_severity)
    return;*/
  va_start(ap,format);
  logv(LOG_ERR, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
#endif

/** DOCDOC */
static void
log_free(logfile_t *victim)
{
  tor_free(victim->severities);
  tor_free(victim->filename);
  tor_free(victim);
}

/** Close all open log files, and free other static memory. */
void
logs_free_all(void)
{
  logfile_t *victim, *next;
  LOCK_LOGS();
  next = logfiles;
  logfiles = NULL;
  UNLOCK_LOGS();
  while (next) {
    victim = next;
    next = next->next;
    close_log(victim);
    log_free(victim);
  }
  tor_free(appname);
  if(logcache)
  {
    tor_free(logcache);
    logcache = NULL;
  }
}

/** Helper: release system resources (but not memory) held by a single
 * logfile_t. */
static void
close_log(logfile_t *victim)
{
  if (victim->needs_close && victim->file) {
    fclose(victim->file);
  } else if (victim->is_syslog) {
#ifdef HAVE_SYSLOG_H
    if (--syslog_count == 0) {
      /* There are no other syslogs; close the logging facility. */
      closelog();
    }
#endif
  }
}

/** Adjust a log severity configuration in <b>severity_out</b> to contain
 * every domain between <b>loglevelMin</b> and <b>loglevelMax</b>, inclusive.
 */
void
set_log_severity_config(int loglevelMin, int loglevelMax,
                        log_severity_list_t *severity_out)
{
  int i;
  tor_assert(loglevelMin >= loglevelMax);
  tor_assert(loglevelMin >= LOG_ERR && loglevelMin <= LOG_DEBUG);
  tor_assert(loglevelMax >= LOG_ERR && loglevelMax <= LOG_DEBUG);
  memset(severity_out, 0, sizeof(log_severity_list_t));
  for (i = loglevelMin; i >= loglevelMax; --i) {
    severity_out->masks[SEVERITY_MASK_IDX(i)] = ~0u;
  }
}

/** Add a log handler named <b>name</b> to send all messages in <b>severity</b>
 * to <b>stream</b>. Copies <b>severity</b>. Helper: does no locking. */
 /*
static void
add_stream_log_impl(log_severity_list_t *severity,
                    const char *name, FILE *stream)
{
  logfile_t *lf;
  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->filename = tor_strdup(name);
  lf->severities = tor_memdup(severity, sizeof(log_severity_list_t));
  lf->file = stream;
  lf->next = logfiles;

  logfiles = lf;
}*/

/** Add a log handler named <b>name</b> to send all messages in <b>severity</b>
 * to <b>stream</b>. Steals a reference to <b>severity</b>; the caller must
 * not use it after calling this function. */
/*void
add_stream_log(log_severity_list_t *severity,
               const char *name, FILE *stream)
{
  LOCK_LOGS();
  add_stream_log_impl(severity, name, stream);
  UNLOCK_LOGS();
}*/


/** Add a log handler to receive messages during startup (before the real
 * logs are initialized).
 */
/*void
add_temp_log(int min_severity)
{
  log_severity_list_t *s = tor_malloc_zero(sizeof(log_severity_list_t));
  set_log_severity_config(min_severity, LOG_ERR, s);
  LOCK_LOGS();
  add_stream_log_impl(s, "<temp>", stdout);
  tor_free(s);
  logfiles->is_temporary = 1;
  UNLOCK_LOGS();
}*/

/**
 * Add a log handler to send messages in <b>severity</b>
 * to the function <b>cb</b>.
 */
int
add_callback_log(log_severity_list_t *severity, log_callback cb)
{
  logfile_t *lf;
  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->severities = tor_memdup(severity, sizeof(log_severity_list_t));
  lf->filename = tor_strdup("<callback>");
  lf->callback = cb;
  lf->next = logfiles;

  LOCK_LOGS();
  logfiles = lf;
/*  _log_global_min_severity = get_min_log_level();*/
  UNLOCK_LOGS();
  return 0;
}

/** Adjust the configured severity of any logs whose callback function is
 * <b>cb</b>. */
void
change_callback_log_severity(int loglevelMin, int loglevelMax,
                             log_callback cb)
{
  logfile_t *lf;
  log_severity_list_t severities;
  set_log_severity_config(loglevelMin, loglevelMax, &severities);
  LOCK_LOGS();
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->callback == cb) {
      memcpy(lf->severities, &severities, sizeof(severities));
    }
  }
/*  _log_global_min_severity = get_min_log_level();*/
  UNLOCK_LOGS();
}

/** Close any log handlers added by add_temp_log() or marked by
 * mark_logs_temp(). */
void
close_temp_logs(void)
{
  logfile_t *lf, **p;

  LOCK_LOGS();
  for (p = &logfiles; *p; ) {
    if ((*p)->is_temporary) {
      lf = *p;
      /* we use *p here to handle the edge case of the head of the list */
      *p = (*p)->next;
      close_log(lf);
      log_free(lf);
    } else {
      p = &((*p)->next);
    }
  }

/*  _log_global_min_severity = get_min_log_level();*/
  UNLOCK_LOGS();
}

/** Make all currently temporary logs (set to be closed by close_temp_logs)
 * live again, and close all non-temporary logs. */
void
rollback_log_changes(void)
{
  logfile_t *lf;
  LOCK_LOGS();
  for (lf = logfiles; lf; lf = lf->next)
    lf->is_temporary = ! lf->is_temporary;
  UNLOCK_LOGS();
  close_temp_logs();
}

/** Configure all log handles to be closed by close_temp_logs(). */
void
mark_logs_temp(void)
{
  logfile_t *lf;
  LOCK_LOGS();
  for (lf = logfiles; lf; lf = lf->next)
    lf->is_temporary = 1;
  UNLOCK_LOGS();
}

/**
 * Add a log handler to send messages to <b>filename</b>. If opening
 * the logfile fails, -1 is returned and errno is set appropriately
 * (by fopen).
 */
/*int
add_file_log(log_severity_list_t *severity, const char *filename)
{
  FILE *f;
  logfile_t *lf;
  f = fopen(filename, "a");
  if (!f) return -1;
  LOCK_LOGS();
  add_stream_log_impl(severity, filename, f);
  logfiles->needs_close = 1;
  lf = logfiles;
  UNLOCK_LOGS();

  return 0;
}*/

#ifdef HAVE_SYSLOG_H
/**
 * Add a log handler to send messages to they system log facility.
 */
int
add_syslog_log(log_severity_list_t *severity)
{
  logfile_t *lf;
  if (syslog_count++ == 0)
    /* This is the first syslog. */
    openlog("Tor", LOG_PID | LOG_NDELAY, LOGFACILITY);

  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->severities = tor_memdup(severity, sizeof(log_severity_list_t));
  lf->filename = tor_strdup("<syslog>");

  lf->is_syslog = 1;

  LOCK_LOGS();
  lf->next = logfiles;
  logfiles = lf;
/*  _log_global_min_severity = get_min_log_level();*/
  UNLOCK_LOGS();
  return 0;
}
#endif

/** If <b>level</b> is a valid log severity, return the corresponding
 * numeric value.  Otherwise, return -1. */
int
parse_log_level(const char *level)
{
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__ERROR)))
    return LOG_ERR;
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__WARN)))
    return LOG_WARN;
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__NOTICE)))
    return LOG_NOTICE;
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__INFO)))
    return LOG_INFO;
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__PROXY)))
    return LOG_ADDR;
  if (!strcasecmp(level,get_lang_str(LANG_LOG_LOG__DEBUG)))
    return LOG_DEBUG;
  return -1;
}

/** Return the string equivalent of a given log level. */
const char *
log_level_to_string(int level)
{
  return sev_to_string(level);
}


/** Return the least severe log level that any current log is interested in. */
/*int
get_min_log_level(void)
{
  logfile_t *lf;
  int i;
  int min = LOG_ERR;
  for (lf = logfiles; lf; lf = lf->next) {
    for (i = LOG_DEBUG; i > min; --i)
      if (lf->severities->masks[SEVERITY_MASK_IDX(i)])
        min = i;
  }
  return min;
}*/

/** Switch all logs to output at most verbose level. */
void
switch_logs_debug(void)
{
  logfile_t *lf;
  int i;
  LOCK_LOGS();
  for (lf = logfiles; lf; lf=lf->next) {
    for (i = LOG_DEBUG; i >= LOG_ERR; --i)
      lf->severities->masks[SEVERITY_MASK_IDX(i)] = ~0u;
  }
  UNLOCK_LOGS();
}
