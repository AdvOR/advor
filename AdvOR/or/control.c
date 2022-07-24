/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.c
 * \brief Implementation for Tor's control-socket interface.
 *   See doc/spec/control-spec.txt for full details on protocol.
 **/

#define CONTROL_PRIVATE

#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "control.h"
#include "directory.h"
#include "dirserv.h"
#include "dnsserv.h"
#include "geoip.h"
#include "hibernate.h"
#include "main.h"
#include "networkstatus.h"
#include "policies.h"
#include "reasons.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"

#include "procmon.h"

/** Yield true iff <b>s</b> is the state of a control_connection_t that has
 * finished authentication and is accepting commands. */
#define STATE_IS_OPEN(s) ((s) == CONTROL_CONN_STATE_OPEN)

/* Recognized asynchronous event types.  It's okay to expand this list
 * because it is used both as a list of v0 event types, and as indices
 * into the bitfield to determine which controllers want which events.
 */
#define _EVENT_MIN             0x0001
#define EVENT_CIRCUIT_STATUS   0x0001
#define EVENT_STREAM_STATUS    0x0002
#define EVENT_OR_CONN_STATUS   0x0003
#define EVENT_BANDWIDTH_USED   0x0004
#define EVENT_LOG_OBSOLETE     0x0005 /* Can reclaim this. */
#define EVENT_NEW_DESC         0x0006
#define EVENT_DEBUG_MSG        0x0007
#define EVENT_INFO_MSG         0x0008
#define EVENT_NOTICE_MSG       0x0009
#define EVENT_WARN_MSG         0x000A
#define EVENT_ERR_MSG          0x000B
#define EVENT_ADDRMAP          0x000C
// #define EVENT_AUTHDIR_NEWDESCS 0x000D
#define EVENT_DESCCHANGED      0x000E
// #define EVENT_NS               0x000F
#define EVENT_STATUS_CLIENT    0x0010
#define EVENT_STATUS_SERVER    0x0011
#define EVENT_STATUS_GENERAL   0x0012
#define EVENT_GUARD            0x0013
#define EVENT_STREAM_BANDWIDTH_USED   0x0014
#define EVENT_CLIENTS_SEEN     0x0015
#define EVENT_NEWCONSENSUS     0x0016
#define EVENT_BUILDTIMEOUT_SET     0x0017
#define _EVENT_MAX             0x0017
/* If _EVENT_MAX ever hits 0x0020, we need to make the mask wider. */

/** Bitfield: The bit 1&lt;&lt;e is set if <b>any</b> open control
 * connection is interested in events of type <b>e</b>.  We use this
 * so that we can decide to skip generating event messages that nobody
 * has interest in without having to walk over the global connection
 * list to find out.
 **/
typedef uint32_t event_mask_t;

/** An event mask of all the events that any controller is interested in
 * receiving. */
static event_mask_t global_event_mask = 0;

/** True iff we have disabled log messages from being sent to the controller */
static int disable_log_messages = 0;

/** Macro: true if any control connection is interested in events of type
 * <b>e</b>. */
#define EVENT_IS_INTERESTING(e) \
  (global_event_mask & (1<<(e)))

/** If we're using cookie-type authentication, how long should our cookies be?
 */
#define AUTHENTICATION_COOKIE_LEN 32

/** If true, we've set authentication_cookie to a secret code and
 * stored it to disk. */
static int authentication_cookie_is_set = 0;
/** If authentication_cookie_is_set, a secret cookie that we've stored to disk
 * and which we're using to authenticate controllers.  (If the controller can
 * read it off disk, it has permission to connect. */
static char authentication_cookie[AUTHENTICATION_COOKIE_LEN];

#define SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT \
  "Tor safe cookie authentication server-to-controller hash"
#define SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT \
  "Tor safe cookie authentication controller-to-server hash"
#define SAFECOOKIE_SERVER_NONCE_LEN DIGEST256_LEN

/** A sufficiently large size to record the last bootstrap phase string. */
#define BOOTSTRAP_MSG_LEN 1024

/** What was the last bootstrap phase message we sent? We keep track
 * of this so we can respond to getinfo status/bootstrap-phase queries. */
static char last_sent_bootstrap_message[BOOTSTRAP_MSG_LEN];

static int num_controllers = 0;

/** Flag for event_format_t.  Indicates that we should use the one standard
    format.
 */
#define ALL_FORMATS 1

/** Bit field of flags to select how to format a controller event.  Recognized
 * flags are SHORT_NAMES, LONG_NAMES, EXTENDED_FORMAT, NONEXTENDED_FORMAT. */
typedef int event_format_t;

static void connection_printf_to_buf(control_connection_t *conn,
                                     const char *format, ...)
  CHECK_PRINTF(2,3);
static void send_control_event_impl(uint16_t event, event_format_t which,
                                    const char *format, va_list ap)
  CHECK_PRINTF(3,0);
static int control_event_status(int type, int severity, const char *format,
                                va_list args)
  CHECK_PRINTF(3,0);

static void send_control_done(control_connection_t *conn);
static void send_control_event(uint16_t event, event_format_t which,
                               const char *format, ...)
  CHECK_PRINTF(3,4);
static int getinfo_helper_listeners(control_connection_t *control_conn, const char *question, char **answer, const char **errmsg);
static int handle_control_setconf(control_connection_t *conn, uint32_t len,
                                  char *body);
static int handle_control_resetconf(control_connection_t *conn, uint32_t len,char *body);
static int handle_control_getconf(control_connection_t *conn, uint32_t len,
                                  const char *body) __attribute__ ((format(printf, 3, 0)));
static int handle_control_loadconf(control_connection_t *conn, uint32_t len,
                                  const char *body) __attribute__ ((format(printf, 3, 0)));
static int handle_control_setevents(control_connection_t *conn, uint32_t len,
                                    const char *body);
static int handle_control_authenticate(control_connection_t *conn,
                                       uint32_t len,
                                       const char *body);
static int handle_control_signal(control_connection_t *conn, uint32_t len,
                                 const char *body);
static int handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                                     const char *body);
static char *list_getinfo_options(void);
static int handle_control_getinfo(control_connection_t *conn, uint32_t len,
                                  const char *body);
static int handle_control_extendcircuit(control_connection_t *conn,
                                        uint32_t len,
                                        const char *body);
static int handle_control_setcircuitpurpose(control_connection_t *conn,
                                            uint32_t len, const char *body);
static int handle_control_attachstream(control_connection_t *conn,
                                       uint32_t len,
                                        const char *body);
static int handle_control_postdescriptor(control_connection_t *conn,
                                         uint32_t len,
                                         const char *body);
static int handle_control_redirectstream(control_connection_t *conn,
                                         uint32_t len,
                                         const char *body);
static int handle_control_closestream(control_connection_t *conn, uint32_t len,
                                      const char *body);
static int handle_control_closecircuit(control_connection_t *conn,
                                       uint32_t len,
                                       const char *body);
static int handle_control_resolve(control_connection_t *conn, uint32_t len,char *body);
static int handle_control_usefeature(control_connection_t *conn,
                                     uint32_t len,
                                     const char *body);
static int write_stream_target_to_buf(edge_connection_t *conn, char *buf,
                                      size_t len);
static void orconn_target_get_name(char *buf, size_t len,
                                   or_connection_t *conn);
static char *get_cookie_file(void);

int register_controller(void)
{
	num_controllers++;
	return 1;
}


/** Given a control event code for a message event, return the corresponding
 * log severity. */
static INLINE int
event_to_log_severity(int event)
{
  switch (event) {
    case EVENT_DEBUG_MSG: return LOG_DEBUG;
    case EVENT_INFO_MSG: return LOG_INFO;
    case EVENT_NOTICE_MSG: return LOG_NOTICE;
    case EVENT_WARN_MSG: return LOG_WARN;
    case EVENT_ERR_MSG: return LOG_ERR;
    default: return -1;
  }
}

/** Given a log severity, return the corresponding control event code. */
static INLINE int
log_severity_to_event(int severity)
{
  switch (severity) {
    case LOG_DEBUG: return EVENT_DEBUG_MSG;
    case LOG_INFO: return EVENT_INFO_MSG;
    case LOG_NOTICE: return EVENT_NOTICE_MSG;
    case LOG_WARN: return EVENT_WARN_MSG;
    case LOG_ERR: return EVENT_ERR_MSG;
    default: return -1;
  }
}

/** Set <b>global_event_mask*</b> to the bitwise OR of each live control
 * connection's event_mask field. */
void
control_update_global_event_mask(void)
{
  if(!num_controllers)	return;
  smartlist_t *conns = get_connection_array();
  event_mask_t old_mask, new_mask;
  old_mask = global_event_mask;

  global_event_mask = 0;
  SMARTLIST_FOREACH(conns, connection_t *, _conn,
  {
    if (_conn->type == CONN_TYPE_CONTROL &&
        STATE_IS_OPEN(_conn->state)) {
      control_connection_t *conn = TO_CONTROL_CONN(_conn);
      global_event_mask |= conn->event_mask;
    }
  });

  new_mask = global_event_mask;

  /* Handle the aftermath.  Set up the log callback to tell us only what
   * we want to hear...*/
  control_adjust_event_log_severity();

  /* ...then, if we've started logging stream bw, clear the appropriate
   * fields. */
  if (! (old_mask & EVENT_STREAM_BANDWIDTH_USED) &&
      (new_mask & EVENT_STREAM_BANDWIDTH_USED)) {
    SMARTLIST_FOREACH(conns, connection_t *, conn,
    {
      if (conn->type == CONN_TYPE_AP) {
        edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
        edge_conn->n_written = edge_conn->n_read = 0;
      }
    });
  }
}

/** Adjust the log severities that result in control_event_logmsg being called
 * to match the severity of log messages that any controllers are interested
 * in. */
void
control_adjust_event_log_severity(void)
{
  int i;
  int min_log_event=EVENT_ERR_MSG, max_log_event=EVENT_DEBUG_MSG;

  for (i = EVENT_DEBUG_MSG; i <= EVENT_ERR_MSG; ++i) {
    if (EVENT_IS_INTERESTING(i)) {
      min_log_event = i;
      break;
    }
  }
  for (i = EVENT_ERR_MSG; i >= EVENT_DEBUG_MSG; --i) {
    if (EVENT_IS_INTERESTING(i)) {
      max_log_event = i;
      break;
    }
  }
  if (EVENT_IS_INTERESTING(EVENT_LOG_OBSOLETE) ||
      EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL)) {
    if (min_log_event > EVENT_NOTICE_MSG)
      min_log_event = EVENT_NOTICE_MSG;
    if (max_log_event < EVENT_ERR_MSG)
      max_log_event = EVENT_ERR_MSG;
  }
  if (min_log_event <= max_log_event)
    change_callback_log_severity(event_to_log_severity(min_log_event),
                                 event_to_log_severity(max_log_event),
                                 control_event_logmsg);
  else
    change_callback_log_severity(LOG_ERR, LOG_ERR,
                                 control_event_logmsg);
}

/** Return true iff the event with code <b>c</b> is being sent to any current
 * control connection.  This is useful if the amount of work needed to prepare
 * to call the appropriate control_event_...() function is high.
 */
int
control_event_is_interesting(int event)
{
  return EVENT_IS_INTERESTING(event);
}

/** Append a NUL-terminated string <b>s</b> to the end of
 * <b>conn</b>-\>outbuf.
 */
static INLINE void
connection_write_str_to_buf(const char *s, control_connection_t *conn)
{
  size_t len = strlen(s);
  connection_write_to_buf(s, len, TO_CONN(conn));
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy the
 * contents of <b>data</b> into *<b>out</b>, adding a period before any period
 * that that appears at the start of a line, and adding a period-CRLF line at
 * the end. Replace all LF characters sequences with CRLF.  Return the number
 * of bytes in *<b>out</b>.
 */
/* static */ size_t
write_escaped_data(const char *data, size_t len, char **out)
{
  size_t sz_out = len+8;
  char *outp;
  const char *start = data, *end;
  int i;
  int start_of_line;
  for (i=0; i<(int)len; ++i) {
    if (data[i]== '\n')
      sz_out += 2; /* Maybe add a CR; maybe add a dot. */
  }
  *out = outp = tor_malloc(sz_out+1);
  end = data+len;
  start_of_line = 1;
  while (data < end) {
    if (*data == '\n') {
      if (data > start && data[-1] != '\r')
        *outp++ = '\r';
      start_of_line = 1;
    } else if (*data == '.') {
      if (start_of_line) {
        start_of_line = 0;
        *outp++ = '.';
      }
    } else {
      start_of_line = 0;
    }
    *outp++ = *data++;
  }
  if (outp < *out+2 || fast_memcmp(outp-2, "\r\n", 2)) {
    *outp++ = '\r';
    *outp++ = '\n';
  }
  *outp++ = '.';
  *outp++ = '\r';
  *outp++ = '\n';
  *outp = '\0'; /* NUL-terminate just in case. */
  tor_assert((outp - *out) <= (int)sz_out);
  return outp - *out;
}

/** Given a <b>len</b>-character string in <b>data</b>, made of lines
 * terminated by CRLF, allocate a new string in *<b>out</b>, and copy
 * the contents of <b>data</b> into *<b>out</b>, removing any period
 * that appears at the start of a line, and replacing all CRLF sequences
 * with LF.   Return the number of
 * bytes in *<b>out</b>. */
/* static */ size_t
read_escaped_data(const char *data, size_t len, char **out)
{
  char *outp;
  const char *next;
  const char *end;

  *out = outp = tor_malloc(len+1);

  end = data+len;

  while (data < end) {
    /* we're at the start of a line. */
    if (*data == '.')
      ++data;
    next = memchr(data, '\n', end-data);
    if (next) {
      size_t n_to_copy = next-data;
      /* Don't copy a CR that precedes this LF. */
      if (n_to_copy && *(next-1) == '\r')
        --n_to_copy;
      memcpy(outp, data, n_to_copy);
      outp += n_to_copy;
      data = next+1; /* This will point at the start of the next line,
                      * or the end of the string, or a period. */
    } else {
      memcpy(outp, data, end-data);
      outp += (end-data);
      *outp = '\0';
      return outp - *out;
    }
    *outp++ = '\n';
  }

  *outp = '\0';
  return outp - *out;
}

/** If the first <b>in_len_max</b> characters in <b>start</b> contain a
 * double-quoted string with escaped characters, return the length of that
 * string (as encoded, including quotes).  Otherwise return -1. */
static INLINE int
get_escaped_string_length(const char *start, size_t in_len_max,
                          int *chars_out)
{
  const char *cp, *end;
  int chars = 0;

  if (*start != '\"')
    return -1;

  cp = start+1;
  end = start+in_len_max;

  /* Calculate length. */
  while (1) {
    if (cp >= end) {
      return -1; /* Too long. */
    } else if (*cp == '\\') {
      if (++cp == end)
        return -1; /* Can't escape EOS. */
      ++cp;
      ++chars;
    } else if (*cp == '\"') {
      break;
    } else {
      ++cp;
      ++chars;
    }
  }
  if (chars_out)
    *chars_out = chars;
  return (int)(cp - start+1);
}

/** As decode_escaped_string, but does not decode the string: copies the
 * entire thing, including quotation marks. */
static const char *
extract_escaped_string(const char *start, size_t in_len_max,
                       char **out, size_t *out_len)
{
  int length = get_escaped_string_length(start, in_len_max, NULL);
  if (length<0)
    return NULL;
  *out_len = length;
  *out = tor_strndup(start, *out_len);
  return start+length;
}

/** Given a pointer to a string starting at <b>start</b> containing
 * <b>in_len_max</b> characters, decode a string beginning with one double
 * quote, containing any number of non-quote characters or characters escaped
 * with a backslash, and ending with a final double quote.  Place the resulting
 * string (unquoted, unescaped) into a newly allocated string in *<b>out</b>;
 * store its length in <b>out_len</b>.  On success, return a pointer to the
 * character immediately following the escaped string.  On failure, return
 * NULL. */
static const char *
decode_escaped_string(const char *start, size_t in_len_max,
                   char **out, size_t *out_len)
{
  const char *cp, *end;
  char *outp;
  int len, n_chars = 0;

  len = get_escaped_string_length(start, in_len_max, &n_chars);
  if (len<0)
    return NULL;

  end = start+len-1; /* Index of last quote. */
  tor_assert(*end == '\"');
  outp = *out = tor_malloc(len+1);
  *out_len = n_chars;

  cp = start+1;
  while (cp < end) {
    if (*cp == '\\')
      ++cp;
    *outp++ = *cp++;
  }
  *outp = '\0';
  tor_assert((outp - *out) == (int)*out_len);

  return end+1;
}

/** Acts like sprintf, but writes its formatted string to the end of
 * <b>conn</b>-\>outbuf.  The message may be truncated if it is too long,
 * but it will always end with a CRLF sequence.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending CR LF NUL ("\\r\\n\\0"). */
static void
connection_printf_to_buf(control_connection_t *conn, const char *format, ...)
{
  va_list ap;
  unsigned char *buf = NULL;
  int len;

  va_start(ap,format);
  len = tor_vasprintf(&buf, format, ap);
  va_end(ap);

  if (len < 0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_STRING_FORMAT_ERROR));
    return;
  }
  connection_write_to_buf((char *)buf, (size_t)len, TO_CONN(conn));
  tor_free(buf);
}

/** Write all of the open control ports to ControlPortWriteToFile */
void control_ports_write_to_file(void)
{	smartlist_t *lines;
	char *joined = NULL;
	or_options_t *options = get_options();
	if(!options->ControlPortWriteToFile)	return;
	lines = smartlist_create();
	SMARTLIST_FOREACH_BEGIN(get_connection_array(), const connection_t *, conn)
	{	unsigned char *port_str = NULL;
		if(conn->type != CONN_TYPE_CONTROL_LISTENER || conn->marked_for_close)
			continue;
		tor_asprintf(&port_str, "PORT=%s:%d\n", conn->address, conn->port);
		smartlist_add(lines, port_str);
	} SMARTLIST_FOREACH_END(conn);
	joined = smartlist_join_strings(lines, "", 0, NULL);
	if(write_buf_to_file(options->ControlPortWriteToFile,joined,strlen(joined)) < 0)
		log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_WRITE_FAILED),options->ControlPortWriteToFile, strerror(errno));
	tor_free(joined);
	SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
	smartlist_free(lines);
}

/** Send a "DONE" message down the control connection <b>conn</b>. */
static void
send_control_done(control_connection_t *conn)
{
  connection_write_str_to_buf("250 OK\r\n", conn);
}

/** Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is given by <b>msg</b>.
 *
 * If <b>which</b> & SHORT_NAMES, the event contains short-format names: send
 * it to controllers that haven't enabled the VERBOSE_NAMES feature.  If
 * <b>which</b> & LONG_NAMES, the event contains long-format names: send it
 * to contollers that <em>have</em> enabled VERBOSE_NAMES.
 *
 * The EXTENDED_FORMAT and NONEXTENDED_FORMAT flags behave similarly with
 * respect to the EXTENDED_EVENTS feature. */
static void
send_control_event_string(uint16_t event, event_format_t which,
                          const char *msg)
{
  if(!num_controllers)	return;
  smartlist_t *conns = get_connection_array();
  (void)which;
  tor_assert(event >= _EVENT_MIN && event <= _EVENT_MAX);

  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn)
  {
    if (conn->type == CONN_TYPE_CONTROL &&
        !conn->marked_for_close &&
        conn->state == CONTROL_CONN_STATE_OPEN) {
      control_connection_t *control_conn = TO_CONTROL_CONN(conn);
      if (control_conn->event_mask & (1<<event)) {
        int is_err = 0;
        connection_write_to_buf(msg, strlen(msg), TO_CONN(control_conn));
        if (event == EVENT_ERR_MSG)
          is_err = 1;
        else if (event == EVENT_STATUS_GENERAL)
          is_err = !strcmpstart(msg, "STATUS_GENERAL ERR ");
        else if (event == EVENT_STATUS_CLIENT)
          is_err = !strcmpstart(msg, "STATUS_CLIENT ERR ");
        else if (event == EVENT_STATUS_SERVER)
          is_err = !strcmpstart(msg, "STATUS_SERVER ERR ");
        if (is_err)
          connection_handle_write(TO_CONN(control_conn), 1);
      }
    }
  } SMARTLIST_FOREACH_END(conn);
}

/** Helper for send_control1_event and send_control1_event_extended:
 * Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided.
 *
 * If <b>extended</b> is true, and the format contains a single '@' character,
 * it will be replaced with a space and all text after that character will be
 * sent only to controllers that have enabled extended events.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \\r\\n\\0). */
static void
send_control_event_impl(uint16_t event, event_format_t which,
                         const char *format, va_list ap)
{
  unsigned char *buf = NULL;
  int len;

  len = tor_vasprintf(&buf, format, ap);
  if (len < 0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_EVENT_FORMAT_ERROR));
    return;
  }

  send_control_event_string(event, which|ALL_FORMATS, (char *)buf);

  tor_free(buf);
}

/** Send an event to all v1 controllers that are listening for code
 * <b>event</b>.  The event's body is created by the printf-style format in
 * <b>format</b>, and other arguments as provided.
 *
 * Currently the length of the message is limited to 1024 (including the
 * ending \\n\\r\\0. */
static void
send_control_event(uint16_t event, event_format_t which,
                   const char *format, ...)
{
  if(!num_controllers)
  	return;
  va_list ap;
  va_start(ap, format);
  send_control_event_impl(event, which, format, ap);
  va_end(ap);
}

/** Given a text circuit <b>id</b>, return the corresponding circuit. */
static origin_circuit_t *
get_circ(const char *id)
{
  uint32_t n_id;
  int ok;
  n_id = (uint32_t) tor_parse_ulong(id, 10, 0, UINT32_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  return circuit_get_by_global_id(n_id);
}

/** Given a text stream <b>id</b>, return the corresponding AP connection. */
static edge_connection_t *
get_stream(const char *id)
{
  uint64_t n_id;
  int ok;
  connection_t *conn;
  n_id = tor_parse_uint64(id, 10, 0, UINT64_MAX, &ok, NULL);
  if (!ok)
    return NULL;
  conn = connection_get_by_global_id(n_id);
  if (!conn || conn->type != CONN_TYPE_AP || conn->marked_for_close)
    return NULL;
  return TO_EDGE_CONN(conn);
}

/** Helper for setconf and resetconf. Acts like setconf, except
 * it passes <b>use_defaults</b> on to options_trial_assign().  Modifies the
 * contents of body.
 */
static int
control_setconf_helper(control_connection_t *conn, uint32_t len, char *body,
                       int use_defaults)
{
  setopt_err_t opt_err;
  config_line_t *lines=NULL;
  char *start = body;
  unsigned char *errstring = NULL;
  const int clear_first = 1;

  char *config;
  smartlist_t *entries = smartlist_create();

  /* We have a string, "body", of the format '(key(=val|="val")?)' entries
   * separated by space.  break it into a list of configuration entries. */
  while (*body) {
    char *eq = body;
    char *key;
    char *entry;
    while (!TOR_ISSPACE(*eq) && *eq != '=')
      ++eq;
    key = tor_strndup(body, eq-body);
    body = eq+1;
    if (*eq == '=') {
      char *val=NULL;
      size_t val_len=0;
      size_t ent_len;
      if (*body != '\"') {
        char *val_start = body;
        while (!TOR_ISSPACE(*body))
          body++;
        val = tor_strndup(val_start, body-val_start);
        val_len = strlen(val);
      } else {
        body = (char*)extract_escaped_string(body, (len - (body-start)),
                                             &val, &val_len);
        if (!body) {
          connection_write_str_to_buf("551 Couldn't parse string\r\n", conn);
          SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
          smartlist_free(entries);
          tor_free(key);
          return 0;
        }
      }
      ent_len = strlen(key)+val_len+3;
      entry = tor_malloc(ent_len+1);
      tor_snprintf(entry, ent_len, "%s %s", key, val);
      tor_free(key);
      tor_free(val);
    } else {
      entry = key;
    }
    smartlist_add(entries, entry);
    while (TOR_ISSPACE(*body))
      ++body;
  }

  smartlist_add(entries, tor_strdup(""));
  config = smartlist_join_strings(entries, "\n", 0, NULL);
  SMARTLIST_FOREACH(entries, char *, cp, tor_free(cp));
  smartlist_free(entries);

  if (config_get_lines(config, &lines) < 0) {
    log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_CONFIG_FORMAT_ERROR));
    connection_write_str_to_buf("551 Couldn't parse configuration\r\n",
                                conn);
    tor_free(config);
    return 0;
  }
  tor_free(config);

  opt_err = options_trial_assign(lines, use_defaults, clear_first, &errstring);
  {
    const char *msg;
    switch (opt_err) {
      case SETOPT_ERR_MISC:
        msg = "552 Unrecognized option";
        break;
      case SETOPT_ERR_PARSE:
        msg = "513 Unacceptable option value";
        break;
      case SETOPT_ERR_TRANSITION:
        msg = "553 Transition not allowed";
        break;
      case SETOPT_ERR_SETTING:
      default:
        msg = "553 Unable to set option";
        break;
      case SETOPT_OK:
        config_free_lines(lines);
        send_control_done(conn);
        return 0;
    }
    log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_CONFIG_DID_NOT_VALIDATE),errstring);
    connection_printf_to_buf(conn, "%s: %s\r\n", msg, errstring);
    config_free_lines(lines);
    tor_free(errstring);
    return 0;
  }
}

/** Called when we receive a SETCONF message: parse the body and try
 * to update our configuration.  Reply with a DONE or ERROR message.
 * Modifies the contents of body.*/
static int
handle_control_setconf(control_connection_t *conn, uint32_t len, char *body)
{
  return control_setconf_helper(conn, len, body, 0);
}

/** Called when we receive a RESETCONF message: parse the body and try
 * to update our configuration.  Reply with a DONE or ERROR message.
 * Modifies the contents of body. */
static int
handle_control_resetconf(control_connection_t *conn, uint32_t len, char *body)
{
  return control_setconf_helper(conn, len, body, 1);
}

/** Called when we receive a GETCONF message.  Parse the request, and
 * reply with a CONFVALUE or an ERROR message */
static int handle_control_getconf(control_connection_t *conn, uint32_t body_len, const char *body)
{
  smartlist_t *questions = smartlist_create();
  smartlist_t *answers = smartlist_create();
  smartlist_t *unrecognized = smartlist_create();
  char *msg = NULL;
  size_t msg_len;
  or_options_t *options = get_options();
  int i, len;

  (void) body_len; /* body is nul-terminated; so we can ignore len. */
  smartlist_split_string(questions, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(questions, const char *, q,
  {
    if (!option_is_recognized(q)) {
      smartlist_add(unrecognized, (char*) q);
    } else {
      config_line_t *answer = option_get_assignment(options,q);
      if (!answer) {
        const char *name = option_get_canonical_name(q);
        size_t alen = strlen(name)+8;
        char *astr = tor_malloc(alen);
        tor_snprintf(astr, alen, "250-%s\r\n", name);
        smartlist_add(answers, astr);
      }

      while (answer) {
        config_line_t *next;
        size_t alen = strlen((char *)answer->key)+strlen((char *)answer->value)+8;
        char *astr = tor_malloc(alen);
        tor_snprintf(astr, alen, "250-%s=%s\r\n",
                     answer->key, answer->value);
        smartlist_add(answers, astr);

        next = answer->next;
        tor_free(answer->key);
        tor_free(answer->value);
        tor_free(answer);
        answer = next;
      }
    }
  });

  if ((len = smartlist_len(unrecognized))) {
    for (i=0; i < len-1; ++i)
      connection_printf_to_buf(conn,
                               "552-Unrecognized configuration key \"%s\"\r\n",
                               (char*)smartlist_get(unrecognized, i));
    connection_printf_to_buf(conn,
                             "552 Unrecognized configuration key \"%s\"\r\n",
                             (char*)smartlist_get(unrecognized, len-1));
  } else if ((len = smartlist_len(answers))) {
    char *tmp = smartlist_get(answers, len-1);
    tor_assert(strlen(tmp)>4);
    tmp[3] = ' ';
    msg = smartlist_join_strings(answers, "", 0, &msg_len);
    connection_write_to_buf(msg, msg_len, TO_CONN(conn));
  } else {
    connection_write_str_to_buf("250 OK\r\n", conn);
  }

  SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
  smartlist_free(answers);
  SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
  smartlist_free(questions);
  smartlist_free(unrecognized);

  tor_free(msg);

  return 0;
}

/** Called when we get a +LOADCONF message. */
static int handle_control_loadconf(control_connection_t *conn, uint32_t len, const char *body)
{
  setopt_err_t retval;
  unsigned char *errstring = NULL;
  const char *msg = NULL;
  (void) len;

  retval = options_init_from_string(body, CMD_RUN_TOR, NULL, &errstring);

  if (retval != SETOPT_OK) {
    log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_CONFIG_FILE_DID_NOT_VALIDATE),errstring);
    switch (retval) {
      case SETOPT_ERR_PARSE:
        msg = "552 Invalid config file";
        break;
      case SETOPT_ERR_TRANSITION:
        msg = "553 Transition not allowed";
        break;
      case SETOPT_ERR_SETTING:
        msg = "553 Unable to set option";
        break;
      case SETOPT_ERR_MISC:
      default:
        msg = "550 Unable to load config";
        break;
      case SETOPT_OK:
        tor_fragile_assert();
        break;
    }
    if(msg && errstring)
      connection_printf_to_buf(conn, "%s: %s\r\n", msg, errstring);
    else
      connection_printf_to_buf(conn, "%s\r\n", msg);
  } else {
    send_control_done(conn);
  }
  tor_free(errstring);
  return 0;
}

/** Called when we get a SETEVENTS message: update conn->event_mask,
 * and reply with DONE or ERROR. */
static int
handle_control_setevents(control_connection_t *conn, uint32_t len,
                         const char *body)
{
  uint16_t event_code;
  uint32_t event_mask = 0;
  smartlist_t *events = smartlist_create();

  (void) len;

  smartlist_split_string(events, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(events, const char *, ev)
    {
      if (!strcasecmp(ev, "EXTENDED")) {
        continue;
      } else if (!strcasecmp(ev, "CIRC"))
        event_code = EVENT_CIRCUIT_STATUS;
      else if (!strcasecmp(ev, "STREAM"))
        event_code = EVENT_STREAM_STATUS;
      else if (!strcasecmp(ev, "ORCONN"))
        event_code = EVENT_OR_CONN_STATUS;
      else if (!strcasecmp(ev, "BW"))
        event_code = EVENT_BANDWIDTH_USED;
      else if (!strcasecmp(ev, "DEBUG"))
        event_code = EVENT_DEBUG_MSG;
      else if (!strcasecmp(ev, "INFO"))
        event_code = EVENT_INFO_MSG;
      else if (!strcasecmp(ev, "NOTICE"))
        event_code = EVENT_NOTICE_MSG;
      else if (!strcasecmp(ev, "WARN"))
        event_code = EVENT_WARN_MSG;
      else if (!strcasecmp(ev, "ERR"))
        event_code = EVENT_ERR_MSG;
      else if (!strcasecmp(ev, "NEWDESC"))
        event_code = EVENT_NEW_DESC;
      else if (!strcasecmp(ev, "ADDRMAP"))
        event_code = EVENT_ADDRMAP;
      else if (!strcasecmp(ev, "AUTHDIR_NEWDESCS"))
        event_code = EVENT_AUTHDIR_NEWDESCS;
      else if (!strcasecmp(ev, "DESCCHANGED"))
        event_code = EVENT_DESCCHANGED;
      else if (!strcasecmp(ev, "NS"))
        event_code = EVENT_NS;
      else if (!strcasecmp(ev, "STATUS_GENERAL"))
        event_code = EVENT_STATUS_GENERAL;
      else if (!strcasecmp(ev, "STATUS_CLIENT"))
        event_code = EVENT_STATUS_CLIENT;
      else if (!strcasecmp(ev, "STATUS_SERVER"))
        event_code = EVENT_STATUS_SERVER;
      else if (!strcasecmp(ev, "GUARD"))
        event_code = EVENT_GUARD;
      else if (!strcasecmp(ev, "STREAM_BW"))
        event_code = EVENT_STREAM_BANDWIDTH_USED;
      else if (!strcasecmp(ev, "CLIENTS_SEEN"))
        event_code = EVENT_CLIENTS_SEEN;
      else if (!strcasecmp(ev, "NEWCONSENSUS"))
        event_code = EVENT_NEWCONSENSUS;
      else if (!strcasecmp(ev, "BUILDTIMEOUT_SET"))
        event_code = EVENT_BUILDTIMEOUT_SET;
      else {
        connection_printf_to_buf(conn, "552 Unrecognized event \"%s\"\r\n",
                                 ev);
        SMARTLIST_FOREACH(events, char *, e, tor_free(e));
        smartlist_free(events);
        return 0;
      }
      event_mask |= (1 << event_code);
    }
  SMARTLIST_FOREACH_END(ev);
  SMARTLIST_FOREACH(events, char *, e, tor_free(e));
  smartlist_free(events);

  conn->event_mask = event_mask;

  control_update_global_event_mask();
  send_control_done(conn);
  return 0;
}

/** Decode the hashed, base64'd passwords stored in <b>passwords</b>.
 * Return a smartlist of acceptable passwords (unterminated strings of
 * length S2K_SPECIFIER_LEN+DIGEST_LEN) on success, or NULL on failure.
 */
smartlist_t *decode_hashed_passwords(config_line_t *passwords)
{	char decoded[64];
	config_line_t *cl;
	smartlist_t *sl = smartlist_create();
	tor_assert(passwords);
	for(cl = passwords; cl; cl = cl->next)
	{	const char *hashed = (char *)cl->value;
		if(!strcmpstart(hashed, "16:") && (base16_decode(decoded, sizeof(decoded), hashed+3, strlen(hashed+3))<0 || strlen(hashed+3) != (S2K_SPECIFIER_LEN+DIGEST_LEN)*2))
			break;
		else if(base64_decode(decoded, sizeof(decoded), hashed, strlen(hashed)) != S2K_SPECIFIER_LEN+DIGEST_LEN)
			break;
		smartlist_add(sl, tor_memdup(decoded, S2K_SPECIFIER_LEN+DIGEST_LEN));
	}
	if(cl)
	{	SMARTLIST_FOREACH(sl, char*, cp, tor_free(cp));
		smartlist_free(sl);
		return NULL;
	}
	return sl;
}

/** Called when we get an AUTHENTICATE message.  Check whether the
 * authentication is valid, and if so, update the connection's state to
 * OPEN.  Reply with DONE or ERROR.
 */
static int handle_control_authenticate(control_connection_t *conn, uint32_t len,const char *body)
{	int used_quoted_string = 0;
	or_options_t *options = get_options();
	const char *errstr = NULL;
	char *password;
	size_t password_len;
	const char *cp;
	int i;
	int bad_cookie=0,bad_password=0;
	smartlist_t *sl = NULL;
	if(TOR_ISXDIGIT(body[0]))
	{	cp = body;
		while(TOR_ISXDIGIT(*cp))	++cp;
		i = (int)(cp - body);
		tor_assert(i>0);
		password_len = i/2;
		password = tor_malloc(password_len + 1);
		if(base16_decode(password, password_len+1, body, i)<0)
		{	connection_write_str_to_buf("551 Invalid hexadecimal encoding.  Maybe you tried a plain text password?  If so, the standard requires that you put it in double quotes.\r\n", conn);
			connection_mark_for_close(TO_CONN(conn));
			tor_free(password);
			return 0;
		}
	}
	else if(TOR_ISSPACE(body[0]))
	{	password = tor_strdup("");
		password_len = 0;
	}
	else
	{	if(!decode_escaped_string(body, len, &password, &password_len))
		{	connection_write_str_to_buf("551 Invalid quoted string.  You need to put the password in double quotes.\r\n", conn);
			connection_mark_for_close(TO_CONN(conn));
			return 0;
		}
		used_quoted_string = 1;
	}
	if(conn->safecookie_client_hash != NULL)
	{	/* The controller has chosen safe cookie authentication; the only acceptable authentication value is the controller-to-server response. */
		tor_assert(authentication_cookie_is_set);
		if(password_len != DIGEST256_LEN)
		{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_SAFE_COOKIE_WITH_WRONG_LENGTH),(int)password_len);
			errstr = "Wrong length for safe cookie response.";
			bad_cookie = 1;
		}
		if(tor_memneq(conn->safecookie_client_hash, password, DIGEST256_LEN))
		{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_INCORRECT_SAFE_COOKIE_AUTH_RESPONSE));
			errstr = "Safe cookie response did not match expected value.";
			bad_cookie = 1;
		}
		tor_free(conn->safecookie_client_hash);
	}
	else if(options->CookieAuthentication || options->HashedControlPassword || options->HashedControlSessionPassword)	/* if Tor doesn't demand any stronger authentication, then the controller can get in with anything. */
	{	bad_cookie = 1;
		int also_password = options->HashedControlPassword != NULL || options->HashedControlSessionPassword != NULL;
		if(options->CookieAuthentication)
		{	if(password_len != AUTHENTICATION_COOKIE_LEN)
			{	if(!also_password)
				{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_AUTH_COOKIE_ERROR_1),(int)password_len);
					errstr = "Wrong length on authentication cookie.";
				}
			}
			else if(tor_memneq(authentication_cookie, password, password_len))
			{	if(!also_password)
				{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_AUTH_COOKIE_ERROR_2));
					errstr = "Authentication cookie did not match expected value.";
				}
			}
			else	bad_cookie = 0;
		}
		if(bad_cookie && also_password)
		{	int bad = 0;
			smartlist_t *sl_tmp;
			char received[DIGEST_LEN];
			int also_cookie = options->CookieAuthentication;
			sl = smartlist_create();
			if(options->HashedControlPassword)
			{	sl_tmp = decode_hashed_passwords(options->HashedControlPassword);
				if(!sl_tmp)	bad = 1;
				else
				{	smartlist_add_all(sl, sl_tmp);
					smartlist_free(sl_tmp);
				}
			}
			if(options->HashedControlSessionPassword)
			{	sl_tmp = decode_hashed_passwords(options->HashedControlSessionPassword);
				if(!sl_tmp)	bad = 1;
				else
				{	smartlist_add_all(sl, sl_tmp);
					smartlist_free(sl_tmp);
				}
			}
			bad_password = 1;
			if(bad)
			{	if(!also_cookie)
				{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_HASHEDCONTROLPASSWORD_ERROR));
					errstr="Couldn't decode HashedControlPassword value in configuration.";
				}
			}
			else
			{	SMARTLIST_FOREACH(sl, char *, expected,
				{	secret_to_key(received,DIGEST_LEN,password,password_len,expected);
					if(tor_memeq(expected+S2K_SPECIFIER_LEN, received, DIGEST_LEN))
					{	bad_password = 0;
						bad_cookie = 0;
						break;
					}
				});
				if(bad_password)
				{	if(used_quoted_string)	errstr = "Password did not match HashedControlPassword value from configuration";
					else	errstr = "Password did not match HashedControlPassword value from configuration. Maybe you tried a plain text password? If so, the standard requires that you put it in double quotes.";
				}
			}
			SMARTLIST_FOREACH(sl, char *, cp_, tor_free(cp_));
			smartlist_free(sl);
			if(bad_password && bad_cookie)
			{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_BAD_PASSWORD));
				errstr = "Password did not match HashedControlPassword *or* authentication cookie.";
			}
		}
	}
	if(bad_password || bad_cookie)
	{	tor_free(password);
		connection_printf_to_buf(conn, "515 Authentication failed: %s\r\n",errstr ? errstr : "Unknown reason.");
		connection_mark_for_close(TO_CONN(conn));
		return 0;
	}
	log_info(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_AUTHENTICATED),conn->_base.s);
	send_control_done(conn);
	conn->_base.state = CONTROL_CONN_STATE_OPEN;
	tor_free(password);
	return 0;
}

/** Called when we get a SAVECONF command. Try to flush the current options to
 * disk, and report success or failure. */
static int
handle_control_saveconf(control_connection_t *conn, uint32_t len,
                        const char *body)
{
  (void) len;
  (void) body;
  if (options_save_current()<0) {
    connection_write_str_to_buf(
      "551 Unable to write configuration to disk.\r\n", conn);
  } else {
    send_control_done(conn);
  }
  return 0;
}

/** Called when we get a SIGNAL command. React to the provided signal, and
 * report success or failure. (If the signal results in a shutdown, success
 * may not be reported.) */
static int
handle_control_signal(control_connection_t *conn, uint32_t len,
                      const char *body)
{
  int sig;
  int n = 0;
  char *s;

  (void) len;

  while (body[n] && ! TOR_ISSPACE(body[n]))
    ++n;
  s = tor_strndup(body, n);
  if (!strcasecmp(s, "RELOAD") || !strcasecmp(s, "HUP"))
    sig = SIGHUP;
  else if (!strcasecmp(s, "SHUTDOWN") || !strcasecmp(s, "INT"))
    sig = SIGINT;
  else if (!strcasecmp(s, "DUMP") || !strcasecmp(s, "USR1"))
    sig = SIGUSR1;
  else if (!strcasecmp(s, "DEBUG") || !strcasecmp(s, "USR2"))
    sig = SIGUSR2;
  else if (!strcasecmp(s, "HALT") || !strcasecmp(s, "TERM"))
    sig = SIGTERM;
  else if (!strcasecmp(s, "NEWNYM"))
    sig = SIGNEWNYM;
  else if (!strcasecmp(s, "CLEARDNSCACHE"))
    sig = SIGCLEARDNSCACHE;
  else {
    connection_printf_to_buf(conn, "552 Unrecognized signal code \"%s\"\r\n",
                             s);
    sig = -1;
  }
  tor_free(s);
  if (sig<0)
    return 0;

  send_control_done(conn);
  /* Flush the "done" first if the signal might make us shut down. */
  if (sig == SIGTERM || sig == SIGINT)
    connection_handle_write(TO_CONN(conn), 1);
  process_signal(sig);
  return 0;
}

/** Called when we get a TAKEOWNERSHIP command.  Mark this connection
 * as an owning connection, so that we will exit if the connection
 * closes. */
static int
handle_control_takeownership(control_connection_t *conn, uint32_t len,
                             const char *body)
{
  (void)len;
  (void)body;

  conn->is_owning_control_connection = 1;

  log_info(LD_CONTROL, get_lang_str(LANG_LOG_CONTROL_TAKE_OWNERSHIP),
           (int)(conn->_base.s));

  send_control_done(conn);
  return 0;
}

/** Called when we get a MAPADDRESS command; try to bind all listed addresses,
 * and report success or failrue. */
static int
handle_control_mapaddress(control_connection_t *conn, uint32_t len,
                          const char *body)
{
  smartlist_t *elts;
  smartlist_t *lines;
  smartlist_t *reply;
  char *r;
  size_t sz;
  (void) len; /* body is nul-terminated, so it's safe to ignore the length. */

  lines = smartlist_create();
  elts = smartlist_create();
  reply = smartlist_create();
  smartlist_split_string(lines, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(lines, char *, line,
  {
    tor_strlower(line);
    smartlist_split_string(elts, line, "=", 0, 2);
    if (smartlist_len(elts) == 2) {
      char *from = smartlist_get(elts,0);
      char *to = smartlist_get(elts,1);
      size_t anslen = strlen(line)+512;
      char *ans = tor_malloc(anslen);
      if (address_is_invalid_destination(to, 1)) {
        tor_snprintf(ans, anslen,
                     "512-syntax error: invalid address '%s'", to);
        smartlist_add(reply, ans);
        log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONFIG_INVALID_MAPADDRESS_ARGUMENT),to);
      } else if (!strcmp(from, ".") || !strcmp(from, "0.0.0.0")) {
        const char *address = addressmap_register_virtual_address(
              !strcmp(from,".") ? RESOLVED_TYPE_HOSTNAME : RESOLVED_TYPE_IPV4,
               tor_strdup(to));
        if (!address) {
          tor_snprintf(ans, anslen,
                       "451-resource exhausted: skipping '%s'", line);
          smartlist_add(reply, ans);
          log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_MAPADDRESS_ALLOCATION_ERROR),safe_str_client(line));
        } else {
          tor_snprintf(ans, anslen, "250-%s=%s", address, to);
          smartlist_add(reply, ans);
        }
      } else {
        addressmap_register(from, tor_strdup(to), 1, ADDRMAPSRC_CONTROLLER);
        tor_snprintf(ans, anslen, "250-%s", line);
        smartlist_add(reply, ans);
      }
    } else {
      size_t anslen = strlen(line)+256;
      char *ans = tor_malloc(anslen);
      tor_snprintf(ans, anslen, "512-syntax error: mapping '%s' is "
                   "not of expected form 'foo=bar'.", line);
      smartlist_add(reply, ans);
      log_info(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_MAPADDRESS_WRONG_NUMBER_OF_ITEMS),safe_str_client(line));
    }
    SMARTLIST_FOREACH(elts, char *, cp, tor_free(cp));
    smartlist_clear(elts);
  });
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  smartlist_free(elts);

  if (smartlist_len(reply)) {
    ((char*)smartlist_get(reply,smartlist_len(reply)-1))[3] = ' ';
    r = smartlist_join_strings(reply, "\r\n", 1, &sz);
    connection_write_to_buf(r, sz, TO_CONN(conn));
    tor_free(r);
  } else {
    const char *response =
      "512 syntax error: not enough arguments to mapaddress.\r\n";
    connection_write_to_buf(response, strlen(response), TO_CONN(conn));
  }

  SMARTLIST_FOREACH(reply, char *, cp, tor_free(cp));
  smartlist_free(reply);
  return 0;
}

/** Implementation helper for GETINFO: knows the answers for various
 * trivial-to-implement questions. */
static int
getinfo_helper_misc(control_connection_t *conn, const char *question,
                    char **answer, const char **errmsg)
{
  (void) conn;
  if (!strcmp(question, "version")) {
    *answer = tor_strdup(get_version());
  } else if (!strcmp(question, "config-file")) {
    *answer = tor_strdup(get_torrc_fname());
  } else if (!strcmp(question, "config-text")) {
    *answer = options_dump(get_options(), 1);
  } else if (!strcmp(question, "info/names")) {
    *answer = list_getinfo_options();
  } else if (!strcmp(question, "events/names")) {
    *answer = tor_strdup("CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR "
                         "NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED "
                         "NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER "
                         "GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS "
                         "BUILDTIMEOUT_SET");
  } else if (!strcmp(question, "features/names")) {
    *answer = tor_strdup("VERBOSE_NAMES EXTENDED_EVENTS");
  } else if (!strcmp(question, "address")) {
    uint32_t addr;
    if (router_pick_published_address(get_options(), &addr) < 0) {
      *errmsg = "Address unknown";
      return -1;
    }
    *answer = tor_dup_ip(addr);
  } else if (!strcmp(question, "dir-usage")) {
    *answer = directory_dump_request_log();
  } else if (!strcmp(question, "fingerprint")) {
    crypto_pk_env_t *server_key;
    if (!server_mode(get_options())) {
      *errmsg = "Not running in server mode";
      return -1;
    }
    server_key = get_server_identity_key();
    *answer = tor_malloc(HEX_DIGEST_LEN+1);
    crypto_pk_get_fingerprint(server_key, *answer, 0);
  }
  return 0;
}

/** Awful hack: return a newly allocated string based on a routerinfo and
 * (possibly) an extrainfo, sticking the read-history and write-history from
 * <b>ei</b> into the resulting string.  The thing you get back won't
 * necessarily have a valid signature.
 *
 * New code should never use this; it's for backward compatibility.
 *
 * NOTE: <b>ri_body</b> is as returned by signed_descriptor_get_body: it might
 * not be NUL-terminated. */
static char *munge_extrainfo_into_routerinfo(const char *ri_body, signed_descriptor_t *ri,signed_descriptor_t *ei)
{	char *out = NULL, *outp;
	int i;
	const char *router_sig;
	const char *ei_body = signed_descriptor_get_body(ei);
	size_t ri_len = ri->signed_descriptor_len;
	size_t ei_len = ei->signed_descriptor_len;
	if(ei_body)
	{	outp = out = tor_malloc(ri_len+ei_len+1);
		router_sig = tor_memstr(ri_body, ri_len, "\nrouter-signature");
		if(router_sig)
		{	++router_sig;
			memcpy(out, ri_body, router_sig-ri_body);
			outp += router_sig-ri_body;
			for(i=0; i < 2; ++i)
			{	const char *kwd = i?"\nwrite-history ":"\nread-history ";
				const char *cp, *eol;
				if(!(cp = tor_memstr(ei_body, ei_len, kwd)))	continue;
				++cp;
				eol = memchr(cp, '\n', ei_len - (cp-ei_body));
				memcpy(outp, cp, eol-cp+1);
				outp += eol-cp+1;
			}
			memcpy(outp, router_sig, ri_len - (router_sig-ri_body));
			*outp++ = '\0';
			tor_assert(outp-out < (int)(ri_len+ei_len+1));
			return out;
		}
	}
	tor_free(out);
	return tor_strndup(ri_body, ri->signed_descriptor_len);
}

/** Implementation helper for GETINFO: answers requests for information about
 * which ports are bound. */
static int getinfo_helper_listeners(control_connection_t *control_conn, const char *question, char **answer, const char **errmsg)
{
  int type;
  smartlist_t *res;

  (void)control_conn;
  (void)errmsg;

  if (!strcmp(question, "net/listeners/or"))
    type = CONN_TYPE_OR_LISTENER;
  else if (!strcmp(question, "net/listeners/dir"))
    type = CONN_TYPE_DIR_LISTENER;
  else if (!strcmp(question, "net/listeners/socks"))
    type = CONN_TYPE_AP_LISTENER;
  else if (!strcmp(question, "net/listeners/trans"))
    type = CONN_TYPE_AP_TRANS_LISTENER;
  else if (!strcmp(question, "net/listeners/natd"))
    type = CONN_TYPE_AP_NATD_LISTENER;
  else if (!strcmp(question, "net/listeners/dns"))
    type = CONN_TYPE_AP_DNS_LISTENER;
  else if (!strcmp(question, "net/listeners/control"))
    type = CONN_TYPE_CONTROL_LISTENER;
  else
    return 0; /* unknown key */

  res = smartlist_create();
  SMARTLIST_FOREACH_BEGIN(get_connection_array(), connection_t *, conn) {
    unsigned char *addr;
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);

    if (conn->type != type || conn->marked_for_close || !SOCKET_OK(conn->s))
      continue;

    if (getsockname(conn->s, (struct sockaddr *)&ss, &ss_len) < 0) {
      tor_asprintf(&addr, "%s:%d", conn->address, (int)conn->port);
    } else {
      char *tmp = tor_sockaddr_to_str((struct sockaddr *)&ss);
      addr = (unsigned char *)esc_for_log(tmp);
      tor_free(tmp);
    }
    if (addr)
      smartlist_add(res, addr);
  } SMARTLIST_FOREACH_END(conn);

  *answer = smartlist_join_strings(res, " ", 0, NULL);

  SMARTLIST_FOREACH(res, char *, cp, tor_free(cp));
  smartlist_free(res);
  return 0;
}

/** Implementation helper for GETINFO: knows the answers for questions about
 * directory information. */
static int
getinfo_helper_dir(control_connection_t *control_conn,
                   const char *question, char **answer,
                   const char **errmsg)
{
  (void) control_conn;
  (void) errmsg;
  if (!strcmpstart(question, "desc/id/")) {
    routerinfo_t *ri = router_get_by_hexdigest(question+strlen("desc/id/"));
    if (ri) {
      const char *body = signed_descriptor_get_body(&ri->cache_info);
      if (body)
        *answer = tor_strndup(body, ri->cache_info.signed_descriptor_len);
    }
  } else if (!strcmpstart(question, "desc/name/")) {
    routerinfo_t *ri = router_get_by_nickname(question+strlen("desc/name/"),1);
    if (ri) {
      const char *body = signed_descriptor_get_body(&ri->cache_info);
      if (body)
        *answer = tor_strndup(body, ri->cache_info.signed_descriptor_len);
    }
  } else if (!strcmp(question, "desc/all-recent")) {
    routerlist_t *routerlist = router_get_routerlist();
    smartlist_t *sl = smartlist_create();
    if (routerlist && routerlist->routers) {
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
      {
        const char *body = signed_descriptor_get_body(&ri->cache_info);
        if (body)
          smartlist_add(sl,
                  tor_strndup(body, ri->cache_info.signed_descriptor_len));
      });
    }
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  } else if (!strcmp(question, "desc/all-recent-extrainfo-hack")) {
    /* XXXX Remove this once Torstat asks for extrainfos. */
    routerlist_t *routerlist = router_get_routerlist();
    smartlist_t *sl = smartlist_create();
    if (routerlist && routerlist->routers) {
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
      {
        const char *body = signed_descriptor_get_body(&ri->cache_info);
        signed_descriptor_t *ei = extrainfo_get_by_descriptor_digest(
                                     ri->cache_info.extra_info_digest);
        if (ei && body) {
          smartlist_add(sl, munge_extrainfo_into_routerinfo(body,
                                                        &ri->cache_info, ei));
        } else if (body) {
          smartlist_add(sl,
                  tor_strndup(body, ri->cache_info.signed_descriptor_len));
        }
      });
    }
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  } else if (!strcmpstart(question, "desc-annotations/id/")) {
    routerinfo_t *ri = router_get_by_hexdigest(question+
                                               strlen("desc-annotations/id/"));
    if (ri) {
      const char *annotations =
        signed_descriptor_get_annotations(&ri->cache_info);
      if (annotations)
        *answer = tor_strndup(annotations,
                              ri->cache_info.annotations_len);
    }
  } else if (!strcmpstart(question, "dir/server/")) {
    size_t answer_len = 0, url_len = strlen(question)+2;
    char *url = tor_malloc(url_len);
    smartlist_t *descs = smartlist_create();
    const char *msg;
    int res;
    char *cp;
    tor_snprintf(url, url_len, "/tor/%s", question+4);
    res = dirserv_get_routerdescs(descs, url, &msg);
    if (res) {
      log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_GETINFO),question,msg);
      smartlist_free(descs);
      return -1;
    }
    SMARTLIST_FOREACH(descs, signed_descriptor_t *, sd,
                      answer_len += sd->signed_descriptor_len);
    cp = *answer = tor_malloc(answer_len+1);
    SMARTLIST_FOREACH(descs, signed_descriptor_t *, sd,
                      {
                        memcpy(cp, signed_descriptor_get_body(sd),
                               sd->signed_descriptor_len);
                        cp += sd->signed_descriptor_len;
                      });
    *cp = '\0';
    tor_free(url);
    smartlist_free(descs);
  } else if (!strcmpstart(question, "dir/status/")) {
    if (directory_permits_controller_requests(get_options())) {
      size_t len=0;
      char *cp;
      smartlist_t *status_list = smartlist_create();
      dirserv_get_networkstatus_v2(status_list,
                                   question+strlen("dir/status/"));
      SMARTLIST_FOREACH(status_list, cached_dir_t *, d, len += d->dir_len);
      cp = *answer = tor_malloc(len+1);
      SMARTLIST_FOREACH(status_list, cached_dir_t *, d, {
          memcpy(cp, d->dir, d->dir_len);
          cp += d->dir_len;
        });
      *cp = '\0';
      smartlist_free(status_list);
    } else {
      smartlist_t *fp_list = smartlist_create();
      smartlist_t *status_list = smartlist_create();
      dirserv_get_networkstatus_v2_fingerprints(
                             fp_list, question+strlen("dir/status/"));
      SMARTLIST_FOREACH(fp_list, const char *, fp, {
          char *s;
          char *fname = networkstatus_get_cache_filename(fp);
          s = read_file_to_str(fname, 0, NULL);
          if (s)
            smartlist_add(status_list, s);
          tor_free(fname);
        });
      SMARTLIST_FOREACH(fp_list, char *, fp, tor_free(fp));
      smartlist_free(fp_list);
      *answer = smartlist_join_strings(status_list, "", 0, NULL);
      SMARTLIST_FOREACH(status_list, char *, s, tor_free(s));
      smartlist_free(status_list);
    }
  } else if (!strcmp(question, "dir/status-vote/current/consensus")) { /* v3 */
    if (directory_caches_dir_info(get_options())) {
      const cached_dir_t *consensus = dirserv_get_consensus("ns");
      if (consensus)
        *answer = tor_strdup(consensus->dir);
    }
    if (!*answer) { /* try loading it from disk */
      char *filename = get_datadir_fname(DATADIR_CACHED_CONSENSUS);
      *answer = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
      tor_free(filename);
    }
  } else if (!strcmp(question, "network-status")) { /* v1 */
    routerlist_t *routerlist = router_get_routerlist();
    if (!routerlist || !routerlist->routers ||
        list_server_status_v1(routerlist->routers, answer,1) < 0) {
      return -1;
    }
  } else if (!strcmpstart(question, "extra-info/digest/")) {
    question += strlen("extra-info/digest/");
    if (strlen(question) == HEX_DIGEST_LEN) {
      char d[DIGEST_LEN];
      signed_descriptor_t *sd = NULL;
      if (base16_decode(d, sizeof(d), question, strlen(question))==0) {
        /* XXXX this test should move into extrainfo_get_by_descriptor_digest,
         * but I don't want to risk affecting other parts of the code,
         * especially since the rules for using our own extrainfo (including
         * when it might be freed) are different from those for using one
         * we have downloaded. */
        if (router_extrainfo_digest_is_me(d))
          sd = &(router_get_my_extrainfo()->cache_info);
        else
          sd = extrainfo_get_by_descriptor_digest(d);
      }
      if (sd) {
        const char *body = signed_descriptor_get_body(sd);
        if (body)
          *answer = tor_strndup(body, sd->signed_descriptor_len);
      }
    }
  }

  return 0;
}

/** Implementation helper for GETINFO: knows how to generate summaries of the
 * current states of things we send events about. */
static int
getinfo_helper_events(control_connection_t *control_conn,
                      const char *question, char **answer,
                      const char **errmsg)
{
  (void) control_conn;
  if (!strcmp(question, "circuit-status")) {
    circuit_t *circ;
    smartlist_t *status = smartlist_create();
    for (circ = _circuit_get_global_list(); circ; circ = circ->next) {
      char *s, *path;
      size_t slen;
      const char *state;
      const char *purpose;
      if (! CIRCUIT_IS_ORIGIN(circ) || circ->marked_for_close)
        continue;
      path = circuit_list_path_for_controller(TO_ORIGIN_CIRCUIT(circ));
      if (circ->state == CIRCUIT_STATE_OPEN)
        state = "BUILT";
      else if (strlen(path))
        state = "EXTENDED";
      else
        state = "LAUNCHED";

      purpose = circuit_purpose_to_controller_string(circ->purpose);
      slen = strlen(path)+strlen(state)+strlen(purpose)+30;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%lu %s%s%s PURPOSE=%s",
                   (unsigned long)TO_ORIGIN_CIRCUIT(circ)->global_identifier,
                   state, *path ? " " : "", path, purpose);
      smartlist_add(status, s);
      tor_free(path);
    }
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
  } else if (!strcmp(question, "stream-status")) {
    smartlist_t *conns = get_connection_array();
    smartlist_t *status = smartlist_create();
    char buf[256];
    SMARTLIST_FOREACH_BEGIN(conns, connection_t *, base_conn) {
      const char *state;
      edge_connection_t *conn;
      char *s;
      size_t slen;
      circuit_t *circ;
      origin_circuit_t *origin_circ = NULL;
      if (base_conn->type != CONN_TYPE_AP ||
          base_conn->marked_for_close ||
          base_conn->state == AP_CONN_STATE_SOCKS_WAIT ||
          base_conn->state == AP_CONN_STATE_NATD_WAIT)
        continue;
      conn = TO_EDGE_CONN(base_conn);
      switch (conn->_base.state)
        {
        case AP_CONN_STATE_CONTROLLER_WAIT:
        case AP_CONN_STATE_CIRCUIT_WAIT:
          if (conn->socks_request &&
              SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command))
            state = "NEWRESOLVE";
          else
            state = "NEW";
          break;
        case AP_CONN_STATE_RENDDESC_WAIT:
        case AP_CONN_STATE_CONNECT_WAIT:
          state = "SENTCONNECT"; break;
        case AP_CONN_STATE_RESOLVE_WAIT:
          state = "SENTRESOLVE"; break;
        case AP_CONN_STATE_OPEN:
          state = "SUCCEEDED"; break;
        default:
          log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_STREAM_IN_UNKNOWN_STATE),conn->_base.state);
          continue;
        }
      circ = circuit_get_by_edge_conn(conn);
      if (circ && CIRCUIT_IS_ORIGIN(circ))
        origin_circ = TO_ORIGIN_CIRCUIT(circ);
      write_stream_target_to_buf(conn, buf, sizeof(buf));
      slen = strlen(buf)+strlen(state)+32;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%lu %s %lu %s",
                   (unsigned long) conn->_base.global_identifier,state,
                   origin_circ?
                         (unsigned long)origin_circ->global_identifier : 0ul,
                   buf);
      smartlist_add(status, s);
    } SMARTLIST_FOREACH_END(base_conn);
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
  } else if (!strcmp(question, "orconn-status")) {
    smartlist_t *conns = get_connection_array();
    smartlist_t *status = smartlist_create();
    SMARTLIST_FOREACH_BEGIN(conns, connection_t *, base_conn)
    {
      const char *state;
      char *s;
      char name[128];
      size_t slen;
      or_connection_t *conn;
      if (base_conn->type != CONN_TYPE_OR || base_conn->marked_for_close)
        continue;
      conn = TO_OR_CONN(base_conn);
      if (conn->_base.state == OR_CONN_STATE_OPEN)
        state = "CONNECTED";
      else if (conn->nickname)
        state = "LAUNCHED";
      else
        state = "NEW";
      orconn_target_get_name(name, sizeof(name), conn);
      slen = strlen(name)+strlen(state)+2;
      s = tor_malloc(slen+1);
      tor_snprintf(s, slen, "%s %s", name, state);
      smartlist_add(status, s);
    } SMARTLIST_FOREACH_END(base_conn);
    *answer = smartlist_join_strings(status, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(status, char *, cp, tor_free(cp));
    smartlist_free(status);
  } else if (!strcmpstart(question, "address-mappings/")) {
    time_t min_e, max_e;
    smartlist_t *mappings;
    question += strlen("address-mappings/");
    if (!strcmp(question, "all")) {
      min_e = 0; max_e = TIME_MAX;
    } else if (!strcmp(question, "cache")) {
      min_e = 2; max_e = TIME_MAX;
    } else if (!strcmp(question, "config")) {
      min_e = 0; max_e = 0;
    } else if (!strcmp(question, "control")) {
      min_e = 1; max_e = 1;
    } else {
      return 0;
    }
    mappings = smartlist_create();
    addressmap_get_mappings(mappings, min_e, max_e, 1);
    *answer = smartlist_join_strings(mappings, "\r\n", 0, NULL);
    SMARTLIST_FOREACH(mappings, char *, cp, tor_free(cp));
    smartlist_free(mappings);
  } else if (!strcmpstart(question, "status/")) {
    /* Note that status/ is not a catch-all for events; there's only supposed
     * to be a status GETINFO if there's a corresponding STATUS event. */
    if (!strcmp(question, "status/circuit-established")) {
      *answer = tor_strdup(can_complete_circuit ? "1" : "0");
    } else if (!strcmp(question, "status/enough-dir-info")) {
      *answer = tor_strdup(router_have_minimum_dir_info() ? "1" : "0");
    } else if (!strcmp(question, "status/good-server-descriptor")) {
      *answer = tor_strdup(directories_have_accepted_server_descriptor()
                           ? "1" : "0");
    } else if (!strcmp(question, "status/reachability-succeeded/or")) {
      *answer = tor_strdup(check_whether_orport_reachable() ? "1" : "0");
    } else if (!strcmp(question, "status/reachability-succeeded/dir")) {
      *answer = tor_strdup(check_whether_dirport_reachable() ? "1" : "0");
    } else if (!strcmp(question, "status/reachability-succeeded")) {
      *answer = tor_malloc(16);
      tor_snprintf(*answer, 16, "OR=%d DIR=%d",
                   check_whether_orport_reachable() ? 1 : 0,
                   check_whether_dirport_reachable() ? 1 : 0);
    } else if (!strcmp(question, "status/bootstrap-phase")) {
      *answer = tor_strdup(last_sent_bootstrap_message);
    } else if (!strcmpstart(question, "status/version/")) {
      int is_server = server_mode(get_options());
      networkstatus_t *c = networkstatus_get_latest_consensus();
      version_status_t status;
      const char *recommended;
      if (c) {
        recommended = is_server ? c->server_versions : c->client_versions;
        status = tor_version_is_obsolete(get_options()->torver, recommended);
      } else {
        recommended = "?";
        status = VS_UNKNOWN;
      }

      if (!strcmp(question, "status/version/recommended")) {
        *answer = tor_strdup(recommended);
        return 0;
      }
      if (!strcmp(question, "status/version/current")) {
        switch (status)
          {
          case VS_RECOMMENDED: *answer = tor_strdup("recommended"); break;
          case VS_OLD: *answer = tor_strdup("obsolete"); break;
          case VS_NEW: *answer = tor_strdup("new"); break;
          case VS_NEW_IN_SERIES: *answer = tor_strdup("new in series"); break;
          case VS_UNRECOMMENDED: *answer = tor_strdup("unrecommended"); break;
          case VS_EMPTY: *answer = tor_strdup("none recommended"); break;
          case VS_UNKNOWN: *answer = tor_strdup("unknown"); break;
          default: tor_fragile_assert();
          }
      } else if (!strcmp(question, "status/version/num-versioning") ||
                 !strcmp(question, "status/version/num-concurring")) {
        char s[33];
        tor_snprintf(s, sizeof(s), "%d", get_n_authorities(V3_AUTHORITY));
        *answer = tor_strdup(s);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_CONTROL_DEPRECATED),question);
      }
    } else if (!strcmp(question, "status/clients-seen")) {
      char *bridge_stats = geoip_get_bridge_stats_controller(get_time(NULL));
      if (!bridge_stats) {
        *errmsg = "No bridge-client stats available";
        return -1;
      }
      *answer = bridge_stats;
    } else {
      return 0;
    }
  }
  return 0;
}

/** Callback function for GETINFO: on a given control connection, try to
 * answer the question <b>q</b> and store the newly-allocated answer in
 * *<b>a</b>.  If there's no answer, or an error occurs, just don't set
 * <b>a</b>.  Return 0.
 */
typedef int (*getinfo_helper_t)(control_connection_t *,
                                const char *q, char **a,
                                const char **error_out);

/** A single item for the GETINFO question-to-answer-function table. */
typedef struct getinfo_item_t {
  const char *varname; /**< The value (or prefix) of the question. */
  getinfo_helper_t fn; /**< The function that knows the answer: NULL if
                        * this entry is documentation-only. */
  const char *desc; /**< Description of the variable. */
  int is_prefix; /** Must varname match exactly, or must it be a prefix? */
} getinfo_item_t;

#define ITEM(name, fn, desc) { name, getinfo_helper_##fn, desc, 0 }
#define PREFIX(name, fn, desc) { name, getinfo_helper_##fn, desc, 1 }
#define DOC(name, desc) { name, NULL, desc, 0 }

/** Table mapping questions accepted by GETINFO to the functions that know how
 * to answer them. */
static const getinfo_item_t getinfo_items[] = {
  ITEM("version", misc, "The current version of Tor."),
  ITEM("config-file", misc, "Current location of the \"torrc\" file."),
  ITEM("config-text", misc,
       "Return the string that would be written by a saveconf command."),
  ITEM("accounting/bytes", accounting,
       "Number of bytes read/written so far in the accounting interval."),
  ITEM("accounting/bytes-left", accounting,
      "Number of bytes left to write/read so far in the accounting interval."),
  ITEM("accounting/enabled", accounting, "Is accounting currently enabled?"),
  ITEM("accounting/hibernating", accounting, "Are we hibernating or awake?"),
  ITEM("accounting/interval-start", accounting,
       "Time when the accounting period starts."),
  ITEM("accounting/interval-end", accounting,
       "Time when the accounting period ends."),
  ITEM("accounting/interval-wake", accounting,
       "Time to wake up in this accounting period."),
  ITEM("helper-nodes", entry_guards, NULL), /* deprecated */
  ITEM("entry-guards", entry_guards,
       "Which nodes are we using as entry guards?"),
  ITEM("fingerprint", misc, NULL),
  PREFIX("config/", config, "Current configuration values."),
  DOC("config/names",
      "List of configuration options, types, and documentation."),
  ITEM("info/names", misc,
       "List of GETINFO options, types, and documentation."),
  ITEM("events/names", misc,
       "Events that the controller can ask for with SETEVENTS."),
  ITEM("features/names", misc, "What arguments can USEFEATURE take?"),
  PREFIX("desc/id/", dir, "Router descriptors by ID."),
  PREFIX("desc/name/", dir, "Router descriptors by nickname."),
  ITEM("desc/all-recent", dir,
       "All non-expired, non-superseded router descriptors."),
  ITEM("desc/all-recent-extrainfo-hack", dir, NULL), /* Hack. */
  PREFIX("extra-info/digest/", dir, "Extra-info documents by digest."),
  PREFIX("net/listeners/", listeners, "Bound addresses by type"),
  ITEM("ns/all", networkstatus,
       "Brief summary of router status (v2 directory format)"),
  PREFIX("ns/id/", networkstatus,
         "Brief summary of router status by ID (v2 directory format)."),
  PREFIX("ns/name/", networkstatus,
         "Brief summary of router status by nickname (v2 directory format)."),
  PREFIX("ns/purpose/", networkstatus,
         "Brief summary of router status by purpose (v2 directory format)."),

  ITEM("network-status", dir,
       "Brief summary of router status (v1 directory format)"),
  ITEM("circuit-status", events, "List of current circuits originating here."),
  ITEM("stream-status", events,"List of current streams."),
  ITEM("orconn-status", events, "A list of current OR connections."),
  PREFIX("address-mappings/", events, NULL),
  DOC("address-mappings/all", "Current address mappings."),
  DOC("address-mappings/cache", "Current cached DNS replies."),
  DOC("address-mappings/config",
      "Current address mappings from configuration."),
  DOC("address-mappings/control", "Current address mappings from controller."),
  PREFIX("status/", events, NULL),
  DOC("status/circuit-established",
      "Whether we think client functionality is working."),
  DOC("status/enough-dir-info",
      "Whether we have enough up-to-date directory information to build "
      "circuits."),
  DOC("status/bootstrap-phase",
      "The last bootstrap phase status event that Tor sent."),
  DOC("status/clients-seen",
      "Breakdown of client countries seen by a bridge."),
  DOC("status/version/recommended", "List of currently recommended versions."),
  DOC("status/version/current", "Status of the current version."),
  DOC("status/version/num-versioning", "Number of versioning authorities."),
  DOC("status/version/num-concurring",
      "Number of versioning authorities agreeing on the status of the "
      "current version"),
  ITEM("address", misc, "IP address of this Tor host, if we can guess it."),
  ITEM("dir-usage", misc, "Breakdown of bytes transferred over DirPort."),
  PREFIX("desc-annotations/id/", dir, "Router annotations by hexdigest."),
  PREFIX("dir/server/", dir,"Router descriptors as retrieved from a DirPort."),
  PREFIX("dir/status/", dir,
         "v2 networkstatus docs as retrieved from a DirPort."),
  ITEM("dir/status-vote/current/consensus", dir,
       "v3 Networkstatus consensus as retrieved from a DirPort."),
  ITEM("exit-policy/default", policies,
       "The default value appended to the configured exit policy."),
  PREFIX("ip-to-country/", geoip, "Perform a GEOIP lookup"),
  { NULL, NULL, NULL, 0 }
};

/** Allocate and return a list of recognized GETINFO options. */
static char *list_getinfo_options(void)
{
  int i;
  unsigned char *buf=NULL;
  smartlist_t *lines = smartlist_create();
  char *ans;
  for (i = 0; getinfo_items[i].varname; ++i) {
    if (!getinfo_items[i].desc)
      continue;

    tor_asprintf(&buf,"%s%s -- %s\n",
                 getinfo_items[i].varname,
                 getinfo_items[i].is_prefix ? "*" : "",
                 getinfo_items[i].desc);
    smartlist_add(lines, buf);
  }
  smartlist_sort_strings(lines);

  ans = smartlist_join_strings(lines, "", 0, NULL);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);

  return ans;
}

/** Lookup the 'getinfo' entry <b>question</b>, and return
 * the answer in <b>*answer</b> (or NULL if key not recognized).
 * Return 0 if success or unrecognized, or -1 if recognized but
 * internal error. */
static int handle_getinfo_helper(control_connection_t *control_conn, const char *question, char **answer, const char **err_out)
{
  int i;
  *answer = NULL; /* unrecognized key by default */

  for (i = 0; getinfo_items[i].varname; ++i) {
    int match;
    if (getinfo_items[i].is_prefix)
      match = !strcmpstart(question, getinfo_items[i].varname);
    else
      match = !strcmp(question, getinfo_items[i].varname);
    if (match) {
      tor_assert(getinfo_items[i].fn);
      return getinfo_items[i].fn(control_conn, question, answer, err_out);
    }
  }

  return 0; /* unrecognized */
}

/** Called when we receive a GETINFO command.  Try to fetch all requested
 * information, and reply with information or error message. */
static int handle_control_getinfo(control_connection_t *conn, uint32_t len,const char *body)
{	smartlist_t *questions = smartlist_create();
	smartlist_t *answers = smartlist_create();
	smartlist_t *unrecognized = smartlist_create();
	char *ans = NULL;
	int i = 0;
	(void) len; /* body is nul-terminated, so it's safe to ignore the length. */

	smartlist_split_string(questions, body, " ",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	SMARTLIST_FOREACH_BEGIN(questions, const char *, q)
	{	const char *errmsg = NULL;
		if(handle_getinfo_helper(conn, q, &ans,&errmsg) < 0)
		{	if(!errmsg)	errmsg = "Internal error";
			connection_printf_to_buf(conn, "551 %s\r\n", errmsg);
			i++;
			break;
		}
		if(!ans)
		{	smartlist_add(unrecognized, (char*)q);
		}
		else
		{	smartlist_add(answers, tor_strdup(q));
			smartlist_add(answers, ans);
		}
	} SMARTLIST_FOREACH_END(q);
	if(!i)
	{	if(smartlist_len(unrecognized))
		{	for(i=0; i < smartlist_len(unrecognized)-1; ++i)
				connection_printf_to_buf(conn,"552-Unrecognized key \"%s\"\r\n",(char*)smartlist_get(unrecognized, i));
			connection_printf_to_buf(conn,"552 Unrecognized key \"%s\"\r\n",(char*)smartlist_get(unrecognized, i));
		}
		else
		{	for(i = 0; i < smartlist_len(answers); i += 2)
			{	char *k = smartlist_get(answers, i);
				char *v = smartlist_get(answers, i+1);
				if(!strchr(v, '\n') && !strchr(v, '\r'))
				{	connection_printf_to_buf(conn, "250-%s=", k);
					connection_write_str_to_buf(v, conn);
					connection_write_str_to_buf("\r\n", conn);
				}
				else
				{	char *esc = NULL;
					size_t esc_len;
					esc_len = write_escaped_data(v, strlen(v), &esc);
					connection_printf_to_buf(conn, "250+%s=\r\n", k);
					connection_write_to_buf(esc, esc_len, TO_CONN(conn));
					tor_free(esc);
				}
			}
			connection_write_str_to_buf("250 OK\r\n", conn);
		}
	}
	SMARTLIST_FOREACH(answers, char *, cp, tor_free(cp));
	smartlist_free(answers);
	SMARTLIST_FOREACH(questions, char *, cp, tor_free(cp));
	smartlist_free(questions);
	smartlist_free(unrecognized);
	return 0;
}

/** Given a string, convert it to a circuit purpose. */
static uint8_t
circuit_purpose_from_string(const char *string)
{
  if (!strcasecmpstart(string, "purpose="))
    string += strlen("purpose=");

  if (!strcasecmp(string, "general"))
    return CIRCUIT_PURPOSE_C_GENERAL;
  else if (!strcasecmp(string, "controller"))
    return CIRCUIT_PURPOSE_CONTROLLER;
  else
    return CIRCUIT_PURPOSE_UNKNOWN;
}

/** Return a newly allocated smartlist containing the arguments to the command
 * waiting in <b>body</b>. If there are fewer than <b>min_args</b> arguments,
 * or if <b>max_args</b> is nonnegative and there are more than
 * <b>max_args</b> arguments, send a 512 error to the controller, using
 * <b>command</b> as the command name in the error message. */
static smartlist_t *getargs_helper(const char *command, control_connection_t *conn,const char *body, int min_args, int max_args)
{	smartlist_t *args = smartlist_create();
	smartlist_split_string(args, body, " ",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	if(smartlist_len(args) < min_args)
		connection_printf_to_buf(conn, "512 Missing argument to %s\r\n",command);
	else if(max_args >= 0 && smartlist_len(args) > max_args)
		connection_printf_to_buf(conn, "512 Too many arguments to %s\r\n",command);
	else	return args;
	SMARTLIST_FOREACH(args, char *, s, tor_free(s));
	smartlist_free(args);
	return NULL;
}

/** Helper.  Return the first element of <b>sl</b> at index <b>start_at</b> or higher that starts with <b>prefix</b>, case-insensitive.  Return NULL if no such element exists. */
static const char *find_element_starting_with(smartlist_t *sl, int start_at, const char *prefix)
{	int i;
	for(i = start_at; i < smartlist_len(sl); ++i)
	{	const char *elt = smartlist_get(sl, i);
		if(!strcasecmpstart(elt, prefix))
			return elt;
	}
	return NULL;
}

/** Helper.  Return true iff s is an argument that we should treat as a key-value pair. */
static int is_keyval_pair(const char *s)
{	/* An argument is a key-value pair if it has an =, and it isn't of the form $fingeprint=name */
	return strchr(s, '=') && s[0] != '$';
}

/** Called when we get an EXTENDCIRCUIT message.  Try to extend the listed
 * circuit, and report success or failure. */
static int handle_control_extendcircuit(control_connection_t *conn, uint32_t len,const char *body)
{	smartlist_t *router_nicknames=NULL, *routers=NULL;
	origin_circuit_t *circ = NULL;
	int zero_circ;
	uint8_t intended_purpose = CIRCUIT_PURPOSE_C_GENERAL;
	smartlist_t *args;
	(void) len;

	router_nicknames = smartlist_create();
	args = getargs_helper("EXTENDCIRCUIT", conn, body, 1, -1);
	if(args)
	{	zero_circ = !strcmp("0", (char*)smartlist_get(args,0));
		if(!zero_circ && !(circ = get_circ(smartlist_get(args,0))))
		{	connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",(char*)smartlist_get(args, 0));
		}
		smartlist_split_string(router_nicknames, smartlist_get(args,1), ",", 0, 0);
		if(zero_circ && smartlist_len(args)>2 && ((intended_purpose = circuit_purpose_from_string(smartlist_get(args,2))) == CIRCUIT_PURPOSE_UNKNOWN))
			connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n",(char*)smartlist_get(args,2));
		else if(zero_circ || circ)
		{	int err_reason = 0;
			routers = smartlist_create();
			SMARTLIST_FOREACH(router_nicknames, const char *, n,
			{	routerinfo_t *r = router_get_by_nickname(n, 1);
				if(!r)
				{	connection_printf_to_buf(conn, "552 No such router \"%s\"\r\n", n);
					err_reason++;
					break;
				}
				smartlist_add(routers, r);
			});
			if(!err_reason)
			{	if(!smartlist_len(routers))	connection_write_str_to_buf("512 No router names provided\r\n", conn);
				else
				{	if(zero_circ)	/* start a new circuit */
						circ = origin_circuit_init(intended_purpose, 0);
					/* now circ refers to something that is ready to be extended */
					SMARTLIST_FOREACH(routers, routerinfo_t *, r,
					{	extend_info_t *info = extend_info_from_router(r);
						circuit_append_new_exit(circ, info);
						extend_info_free(info);
					});
					/* now that we've populated the cpath, start extending */
					if(zero_circ)
					{	if((err_reason = circuit_handle_first_hop(circ)) < 0)
						{	circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
							connection_write_str_to_buf("551 Couldn't start circuit\r\n", conn);
						}
					}
					else
					{	if(circ->_base.state == CIRCUIT_STATE_OPEN)
						{	circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
							if((err_reason = circuit_send_next_onion_skin(circ)) < 0)
							{	log_info(LD_CONTROL,get_lang_str(LANG_LOG_CIRCUITBUILD_SEND_NEXT_ONIONSKIN_FAILED));
								circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
								connection_write_str_to_buf("551 Couldn't send onion skin\r\n", conn);
							}
						}
					}
					if(err_reason >= 0)
					{	connection_printf_to_buf(conn, "250 EXTENDED %lu\r\n",(unsigned long)circ->global_identifier);
						if(zero_circ)	/* send a 'launched' event, for completeness */
						control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED, 0);
					}
				}
			}
		}
		SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
		smartlist_free(args);
	}
	SMARTLIST_FOREACH(router_nicknames, char *, n, tor_free(n));
	smartlist_free(router_nicknames);
	if(routers)	smartlist_free(routers);
	return 0;
}

/** Called when we get a SETCIRCUITPURPOSE message. If we can find the
 * circuit and it's a valid purpose, change it. */
static int handle_control_setcircuitpurpose(control_connection_t *conn,uint32_t len, const char *body)
{	origin_circuit_t *circ = NULL;
	uint8_t new_purpose;
	smartlist_t *args;
	(void) len; /* body is nul-terminated, so it's safe to ignore the length. */

	args = getargs_helper("SETCIRCUITPURPOSE", conn, body, 2, -1);
	if(args)
	{	if(!(circ = get_circ(smartlist_get(args,0))))
			connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",(char*)smartlist_get(args, 0));
		else
		{	const char *purp = find_element_starting_with(args,1,"PURPOSE=");
			new_purpose = circuit_purpose_from_string(purp);
			if(!purp)
				connection_write_str_to_buf("552 No purpose given\r\n", conn);
			else if(new_purpose == CIRCUIT_PURPOSE_UNKNOWN)
				connection_printf_to_buf(conn, "552 Unknown purpose \"%s\"\r\n", purp);
			else
			{	circ->_base.purpose = new_purpose;
				tree_set_circ(TO_CIRCUIT(circ));
				connection_write_str_to_buf("250 OK\r\n", conn);
			}
		}
		SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
		smartlist_free(args);
	}
	return 0;
}

/** Called when we get an ATTACHSTREAM message.  Try to attach the requested
 * stream, and report success or failure. */
static int
handle_control_attachstream(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  edge_connection_t *ap_conn = NULL;
  origin_circuit_t *circ = NULL;
  int zero_circ;
  smartlist_t *args;
  crypt_path_t *cpath=NULL;
  int hop=0, hop_line_ok=1;
  (void) len;

  args = getargs_helper("ATTACHSTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  zero_circ = !strcmp("0", (char*)smartlist_get(args,1));

  if (!(ap_conn = get_stream(smartlist_get(args, 0)))) {
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  } else if (!zero_circ && !(circ = get_circ(smartlist_get(args, 1)))) {
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 1));
  } else if (circ) {
    const char *hopstring = find_element_starting_with(args,2,"HOP=");
    if (hopstring) {
      hopstring += strlen("HOP=");
      hop = (int) tor_parse_ulong(hopstring, 10, 0, INT_MAX,
                                  &hop_line_ok, NULL);
      if (!hop_line_ok) { /* broken hop line */
        connection_printf_to_buf(conn, "552 Bad value hop=%s\r\n", hopstring);
      }
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!ap_conn || (!zero_circ && !circ) || !hop_line_ok)
    return 0;

  if (ap_conn->_base.state != AP_CONN_STATE_CONTROLLER_WAIT &&
      ap_conn->_base.state != AP_CONN_STATE_CONNECT_WAIT &&
      ap_conn->_base.state != AP_CONN_STATE_RESOLVE_WAIT) {
    connection_write_str_to_buf(
                    "555 Connection is not managed by controller.\r\n",
                    conn);
    return 0;
  }

  /* Do we need to detach it first? */
  if (ap_conn->_base.state != AP_CONN_STATE_CONTROLLER_WAIT) {
    circuit_t *tmpcirc = circuit_get_by_edge_conn(ap_conn);
    connection_edge_end(ap_conn, END_STREAM_REASON_TIMEOUT);
    /* Un-mark it as ending, since we're going to reuse it. */
    ap_conn->edge_has_sent_end = 0;
    ap_conn->end_reason = 0;
    if (tmpcirc)
      circuit_detach_stream(tmpcirc,ap_conn);
    ap_conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
  }

  if (circ && (circ->_base.state != CIRCUIT_STATE_OPEN)) {
    connection_write_str_to_buf(
                    "551 Can't attach stream to non-open origin circuit\r\n",
                    conn);
    return 0;
  }
  /* Is this a single hop circuit? */
  if (circ && (circuit_get_cpath_len(circ)<2 || hop==1)) {
    routerinfo_t *r = NULL;
    char* exit_digest;
    if (circ->build_state &&
        circ->build_state->chosen_exit &&
        !tor_digest_is_zero(circ->build_state->chosen_exit->identity_digest)) {
      exit_digest = circ->build_state->chosen_exit->identity_digest;
      r = router_get_by_digest(exit_digest);
    }
    /* Do both the client and relay allow one-hop exit circuits? */
    if (!r || !r->allow_single_hop_exits ||
        !get_options()->AllowSingleHopCircuits) {
      connection_write_str_to_buf(
      "551 Can't attach stream to this one-hop circuit.\r\n", conn);
      return 0;
    }
    ap_conn->chosen_exit_name = tor_strdup(hex_str(exit_digest, DIGEST_LEN));
  }

  if (circ && hop>0) {
    /* find this hop in the circuit, and set cpath */
    cpath = circuit_get_cpath_hop(circ, hop);
    if (!cpath) {
      connection_printf_to_buf(conn,
                               "551 Circuit doesn't have %d hops.\r\n", hop);
      return 0;
    }
  }
  if (connection_ap_handshake_rewrite_and_attach(ap_conn, circ, cpath) < 0) {
    connection_write_str_to_buf("551 Unable to attach stream\r\n", conn);
    return 0;
  }
  send_control_done(conn);
  return 0;
}

/** Called when we get a POSTDESCRIPTOR message.  Try to learn the provided
 * descriptor, and report success or failure. */
static int handle_control_postdescriptor(control_connection_t *conn, uint32_t len,const char *body)
{	char *desc;
	const char *msg=NULL;
	uint8_t purpose = ROUTER_PURPOSE_GENERAL;
	int cache = 0; /* eventually, we may switch this to 1 */

	char *cp = memchr(body, '\n', len);
	smartlist_t *args = smartlist_create();
	tor_assert(cp);
	*cp++ = '\0';

	smartlist_split_string(args, body," ",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	SMARTLIST_FOREACH(args, char *, option,
	{	if(!strcasecmpstart(option, "purpose="))
		{	option += strlen("purpose=");
			purpose = router_purpose_from_string(option);
			if(purpose == ROUTER_PURPOSE_UNKNOWN)
			{	connection_printf_to_buf(conn,"552 Unknown purpose \"%s\"\r\n",option);
				break;
			}
		}
		else if(!strcasecmpstart(option, "cache="))
		{	option += strlen("cache=");
			if (!strcasecmp(option, "no"))		cache = 0;
			else if (!strcasecmp(option, "yes"))	cache = 1;
			else
			{	connection_printf_to_buf(conn, "552 Unknown cache request \"%s\"\r\n",option);
				purpose = ROUTER_PURPOSE_UNKNOWN;
				break;
			}
		}
		else	/* unrecognized argument? */
		{	connection_printf_to_buf(conn,"512 Unexpected argument \"%s\" to postdescriptor\r\n",option);
			purpose = ROUTER_PURPOSE_UNKNOWN;
			break;
		}
	});
	if(purpose != ROUTER_PURPOSE_UNKNOWN)
	{	read_escaped_data(cp, len-(cp-body), &desc);
		switch(router_load_single_router(desc, purpose, cache, &msg))
		{	case -1:
				if(!msg) msg = "Could not parse descriptor";
				connection_printf_to_buf(conn, "554 %s\r\n", msg);
				break;
			case 0:
				if(!msg) msg = "Descriptor not added";
				connection_printf_to_buf(conn, "251 %s\r\n",msg);
				break;
			case 1:
				send_control_done(conn);
				break;
		}
		tor_free(desc);
	}
	SMARTLIST_FOREACH(args, char *, arg, tor_free(arg));
	smartlist_free(args);
	return 0;
}

/** Called when we receive a REDIRECTSTERAM command.  Try to change the target
 * address of the named AP stream, and report success or failure. */
static int
handle_control_redirectstream(control_connection_t *conn, uint32_t len,
                              const char *body)
{
  edge_connection_t *ap_conn = NULL;
  char *new_addr = NULL;
  uint16_t new_port = 0;
  smartlist_t *args;
  (void) len;

  args = getargs_helper("REDIRECTSTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  if (!(ap_conn = get_stream(smartlist_get(args, 0)))
           || !ap_conn->socks_request) {
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  } else {
    int ok = 1;
    if (smartlist_len(args) > 2) { /* they included a port too */
      new_port = (uint16_t) tor_parse_ulong(smartlist_get(args, 2),
                                            10, 1, 65535, &ok, NULL);
    }
    if (!ok) {
      connection_printf_to_buf(conn, "512 Cannot parse port \"%s\"\r\n",
                               (char*)smartlist_get(args, 2));
    } else {
      new_addr = tor_strdup(smartlist_get(args, 1));
    }
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!new_addr)
    return 0;

  if(ap_conn->socks_request->address)
  	tor_free(ap_conn->socks_request->address);
  if(ap_conn->socks_request->original_address)
  	tor_free(ap_conn->socks_request->original_address);
  ap_conn->socks_request->address = tor_strdup(new_addr);
  ap_conn->socks_request->original_address = tor_strdup(new_addr);
  if (new_port)
    ap_conn->socks_request->port = new_port;
  tor_free(new_addr);
  send_control_done(conn);
  return 0;
}

/** Called when we get a CLOSESTREAM command; try to close the named stream
 * and report success or failure. */
static int
handle_control_closestream(control_connection_t *conn, uint32_t len,
                           const char *body)
{
  edge_connection_t *ap_conn=NULL;
  uint8_t reason=0;
  smartlist_t *args;
  int ok;
  (void) len;

  args = getargs_helper("CLOSESTREAM", conn, body, 2, -1);
  if (!args)
    return 0;

  else if (!(ap_conn = get_stream(smartlist_get(args, 0))))
    connection_printf_to_buf(conn, "552 Unknown stream \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  else {
    reason = (uint8_t) tor_parse_ulong(smartlist_get(args,1), 10, 0, 255,
                                       &ok, NULL);
    if (!ok) {
      connection_printf_to_buf(conn, "552 Unrecognized reason \"%s\"\r\n",
                               (char*)smartlist_get(args, 1));
      ap_conn = NULL;
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!ap_conn)
    return 0;

  connection_mark_unattached_ap(ap_conn, reason);
  send_control_done(conn);
  return 0;
}

/** Called when we get a CLOSECIRCUIT command; try to close the named circuit
 * and report success or failure. */
static int
handle_control_closecircuit(control_connection_t *conn, uint32_t len,
                            const char *body)
{
  origin_circuit_t *circ = NULL;
  int safe = 0;
  smartlist_t *args;
  (void) len;

  args = getargs_helper("CLOSECIRCUIT", conn, body, 1, -1);
  if (!args)
    return 0;

  if (!(circ=get_circ(smartlist_get(args, 0))))
    connection_printf_to_buf(conn, "552 Unknown circuit \"%s\"\r\n",
                             (char*)smartlist_get(args, 0));
  else {
    int i;
    for (i=1; i < smartlist_len(args); ++i) {
      if (!strcasecmp(smartlist_get(args, i), "IfUnused"))
        safe = 1;
      else
        log_info(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_UNKNOWN_OPTION),(char*)smartlist_get(args,i));
    }
  }
  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  if (!circ)
    return 0;

  if (!safe || !circ->p_streams) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_REQUESTED);
  }

  send_control_done(conn);
  return 0;
}

/** Called when we get a RESOLVE command: start trying to resolve
 * the listed addresses. */
static int handle_control_resolve(control_connection_t *conn, uint32_t len,char *body)
{
  smartlist_t *args, *failed;
  int is_reverse = 0;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */

  if (!(conn->event_mask & (1L<<EVENT_ADDRMAP))) {
    log_warn(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_RESOLVE_WITHOUT_ADDRMAP));
  }
  args = smartlist_create();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  {
    const char *modearg = find_element_starting_with(args, 0, "mode=");
    if (modearg && !strcasecmp(modearg, "mode=reverse"))
      is_reverse = 1;
  }
  failed = smartlist_create();
  SMARTLIST_FOREACH(args, const char *, arg, {
      if (!is_keyval_pair(arg)) {
          if (dnsserv_launch_request(arg, is_reverse)<0)
            smartlist_add(failed, (char*)arg);
      }
  });

  send_control_done(conn);
  SMARTLIST_FOREACH(failed, char *, arg, {
      control_event_address_mapped(arg, &arg, get_time(NULL),
                                   "Unable to launch resolve request");
  });

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  smartlist_free(failed);
  return 0;
}

/** Called when we get a PROTOCOLINFO command: send back a reply. */
static int handle_control_protocolinfo(control_connection_t *conn, uint32_t len,const char *body)
{	const char *bad_arg = NULL;
	smartlist_t *args;
	(void)len;

	conn->have_sent_protocolinfo = 1;
	args = smartlist_create();
	smartlist_split_string(args, body," ",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	SMARTLIST_FOREACH(args, const char *, arg,
	{	int ok;
		tor_parse_long(arg, 10, 0, LONG_MAX, &ok, NULL);
		if(!ok)
		{	bad_arg = arg;
			break;
		}
	});
	if(bad_arg)
	{	char *esc_l = esc_for_log(bad_arg);
		connection_printf_to_buf(conn,"513 No such version %s\r\n",esc_l);
		tor_free(esc_l);
		/* Don't tolerate bad arguments when not authenticated. */
		if(!STATE_IS_OPEN(TO_CONN(conn)->state))	connection_mark_for_close(TO_CONN(conn));
	}
	else
	{	or_options_t *options = get_options();
		int cookies = options->CookieAuthentication;
		char *cfile = get_cookie_file();
		char *esc_cfile = esc_for_log(cfile);
		char *methods;
		int passwd = (options->HashedControlPassword != NULL || options->HashedControlSessionPassword != NULL);
		smartlist_t *mlist = smartlist_create();
		if(cookies)
		{	smartlist_add(mlist, (char*)"COOKIE");
			smartlist_add(mlist, (char*)"SAFECOOKIE");
		}
		if(passwd)	smartlist_add(mlist, (char*)"HASHEDPASSWORD");
		if(!cookies && !passwd)	smartlist_add(mlist, (char*)"NULL");
		methods = smartlist_join_strings(mlist, ",", 0, NULL);
		smartlist_free(mlist);
		char *esc_l = esc_for_log(options->torver);
		connection_printf_to_buf(conn,"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=%s%s%s\r\n250-VERSION Tor=%s\r\n250 OK\r\n",methods,cookies?" COOKIEFILE=":"",cookies?esc_cfile:"",esc_l);
		tor_free(esc_l);
		tor_free(methods);
		tor_free(cfile);
		tor_free(esc_cfile);
	}
	SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
	smartlist_free(args);
	return 0;
}

/** Called when we get an AUTHCHALLENGE command. */
static int handle_control_authchallenge(control_connection_t *conn,uint32_t len,const char *body)
{	const char *cp = body;
	char *client_nonce;
	size_t client_nonce_len;
	char server_hash[DIGEST256_LEN];
	char server_hash_encoded[HEX_DIGEST256_LEN+1];
	char server_nonce[SAFECOOKIE_SERVER_NONCE_LEN];
	char server_nonce_encoded[(2*SAFECOOKIE_SERVER_NONCE_LEN) + 1];
	cp += strspn(cp, " \t\n\r");
	if(!strcasecmpstart(cp,"SAFECOOKIE"))
		cp += strlen("SAFECOOKIE");
	else
	{	connection_write_str_to_buf("513 AUTHCHALLENGE only supports SAFECOOKIE authentication\r\n",conn);
		connection_mark_for_close(TO_CONN(conn));
		return -1;
	}
	if(!authentication_cookie_is_set)
	{	connection_write_str_to_buf("515 Cookie authentication is disabled\r\n",conn);
		connection_mark_for_close(TO_CONN(conn));
		return -1;
	}
	cp += strspn(cp," \t\n\r");
	if(*cp == '"')
	{	const char *newcp = decode_escaped_string(cp,len - (cp - body),&client_nonce,&client_nonce_len);
		if(newcp == NULL)
		{	connection_write_str_to_buf("513 Invalid quoted client nonce\r\n",conn);
			connection_mark_for_close(TO_CONN(conn));
			return -1;
		}
		cp = newcp;
	}
	else
	{	size_t client_nonce_encoded_len = strspn(cp,"0123456789ABCDEFabcdef");
		client_nonce_len = client_nonce_encoded_len / 2;
		client_nonce = tor_malloc_zero(client_nonce_len);
		if(base16_decode(client_nonce,client_nonce_len,cp,client_nonce_encoded_len) < 0)
		{	connection_write_str_to_buf("513 Invalid base16 client nonce\r\n",conn);
			connection_mark_for_close(TO_CONN(conn));
			return -1;
		}
		cp += client_nonce_encoded_len;
	}
	cp += strspn(cp," \t\n\r");
	if(*cp != '\0' || cp != body + len)
	{	connection_write_str_to_buf("513 Junk at end of AUTHCHALLENGE command\r\n",conn);
		connection_mark_for_close(TO_CONN(conn));
		tor_free(client_nonce);
		return -1;
	}
	tor_assert(!crypto_rand(server_nonce, SAFECOOKIE_SERVER_NONCE_LEN));
	/* Now compute and send the server-to-controller response, and the server's nonce. */
	tor_assert(authentication_cookie != NULL);
	{	size_t tmp_len = (AUTHENTICATION_COOKIE_LEN + client_nonce_len + SAFECOOKIE_SERVER_NONCE_LEN);
		char *tmp = tor_malloc_zero(tmp_len);
		char *client_hash = tor_malloc_zero(DIGEST256_LEN);
		memcpy(tmp, authentication_cookie, AUTHENTICATION_COOKIE_LEN);
		memcpy(tmp + AUTHENTICATION_COOKIE_LEN, client_nonce, client_nonce_len);
		memcpy(tmp + AUTHENTICATION_COOKIE_LEN + client_nonce_len,server_nonce,SAFECOOKIE_SERVER_NONCE_LEN);
		crypto_hmac_sha256(server_hash,SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT,strlen(SAFECOOKIE_SERVER_TO_CONTROLLER_CONSTANT),tmp,tmp_len);
		crypto_hmac_sha256(client_hash,SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT,strlen(SAFECOOKIE_CONTROLLER_TO_SERVER_CONSTANT),tmp,tmp_len);
		conn->safecookie_client_hash = client_hash;
		tor_free(tmp);
	}
	base16_encode(server_hash_encoded, sizeof(server_hash_encoded),server_hash, sizeof(server_hash));
	base16_encode(server_nonce_encoded, sizeof(server_nonce_encoded),server_nonce, sizeof(server_nonce));
	connection_printf_to_buf(conn,"250 AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s\r\n",server_hash_encoded,server_nonce_encoded);
	return 0;
}

/** Called when we get a USEFEATURE command: parse the feature list, and
 * set up the control_connection's options properly. */
static int
handle_control_usefeature(control_connection_t *conn,
                          uint32_t len,
                          const char *body)
{
  smartlist_t *args;
  int bad = 0;
  (void) len; /* body is nul-terminated; it's safe to ignore the length */
  args = smartlist_create();
  smartlist_split_string(args, body, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(args, const char *, arg, {
      if (!strcasecmp(arg, "VERBOSE_NAMES"))
        ;
      else if (!strcasecmp(arg, "EXTENDED_EVENTS"))
        ;
      else {
        connection_printf_to_buf(conn, "552 Unrecognized feature \"%s\"\r\n",
                                 arg);
        bad = 1;
        break;
      }
    });

  if (!bad) {
    send_control_done(conn);
  }

  SMARTLIST_FOREACH(args, char *, cp, tor_free(cp));
  smartlist_free(args);
  return 0;
}

/** Called when <b>conn</b> has no more bytes left on its outbuf. */
int
connection_control_finished_flushing(control_connection_t *conn)
{
  tor_assert(conn);

  connection_stop_writing(TO_CONN(conn));
  return 0;
}

/** Called when <b>conn</b> has gotten its socket closed. */
int
connection_control_reached_eof(control_connection_t *conn)
{
  tor_assert(conn);

  log_info(LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_CONTROLLER_EOF));
  connection_mark_for_close(TO_CONN(conn));
  return 0;
}

/** Shut down this Tor instance in the same way that SIGINT would, but with a log message appropriate for the loss of an owning controller. */
static void lost_owning_controller(const char *owner_type, const char *loss_manner)
{	int shutdown_slowly = server_mode(get_options());
	log_notice(LD_CONTROL,shutdown_slowly ? get_lang_str(LANG_LOG_CONTROL_SHUTDOWN_1):get_lang_str(LANG_LOG_CONTROL_SHUTDOWN_2),owner_type, loss_manner);
	/* XXXX Perhaps this chunk of code should be a separate function, called here and by process_signal(SIGINT). */
	if(!shutdown_slowly)
	{	tor_cleanup();
		exit(0);
	}
	/* XXXX This will close all listening sockets except control-port listeners. Perhaps we should close those too. */
	hibernate_begin_shutdown();
}

/** Called when <b>conn</b> is being freed. */
void connection_control_closed(control_connection_t *conn)
{	tor_assert(conn);
	tor_assert(num_controllers);
	num_controllers--;
	conn->event_mask = 0;
	control_update_global_event_mask();
	if(conn->is_owning_control_connection)
		lost_owning_controller("connection", "closed");
}

/** Return true iff <b>cmd</b> is allowable (or at least forgivable) at this
 * stage of the protocol. */
static int
is_valid_initial_command(control_connection_t *conn, const char *cmd)
{
  if (conn->_base.state == CONTROL_CONN_STATE_OPEN)
    return 1;
  if (!strcasecmp(cmd, "PROTOCOLINFO"))
    return (!conn->have_sent_protocolinfo &&
            conn->safecookie_client_hash == NULL);
  if (!strcasecmp(cmd, "AUTHCHALLENGE"))
    return (conn->safecookie_client_hash == NULL);
  if (!strcasecmp(cmd, "AUTHENTICATE") ||
      !strcasecmp(cmd, "QUIT"))
    return 1;
  return 0;
}

/** Do not accept any control command of more than 1MB in length.  Anything
 * that needs to be anywhere near this long probably means that one of our
 * interfaces is broken. */
#define MAX_COMMAND_LINE_LENGTH (1024*1024)

/** Called when data has arrived on a v1 control connection: Try to fetch
 * commands from conn->inbuf, and execute them.
 */
int connection_control_process_inbuf(control_connection_t *conn)
{	size_t data_len;
	uint32_t cmd_data_len;
	int cmd_len;
	char *args;

	tor_assert(conn);
	tor_assert(conn->_base.state == CONTROL_CONN_STATE_OPEN || conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH);
	if(!conn->incoming_cmd)
	{	conn->incoming_cmd = tor_malloc(1024);
		conn->incoming_cmd_len = 1024;
		conn->incoming_cmd_cur_len = 0;
	}
	if(conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH && peek_buf_has_control0_command(conn->_base.inbuf))	/* Detect v0 commands and send a "no more v0" message. */
	{	size_t body_len;
		char buf[128];
		set_uint16(buf+2, htons(0x0000)); /* type == error */
		set_uint16(buf+4, htons(0x0001)); /* code == internal error */
		strlcpy(buf+6, "The v0 control protocol is not supported by Tor 0.1.2.17 and later; upgrade your controller.",sizeof(buf)-6);
		body_len = 2+strlen(buf+6)+2; /* code, msg, nul. */
		set_uint16(buf+0, htons(body_len));
		connection_write_to_buf(buf, 4+body_len, TO_CONN(conn));
		connection_mark_for_close(TO_CONN(conn));
		conn->_base.hold_open_until_flushed = 1;
		return 0;
	}
	while(1)
	{	while(1)
		{	size_t last_idx;
			int r;
			/* First, fetch a line. */
			do
			{	data_len = conn->incoming_cmd_len - conn->incoming_cmd_cur_len;
				r = fetch_from_buf_line(conn->_base.inbuf,conn->incoming_cmd+conn->incoming_cmd_cur_len,&data_len);
				if(r == 0)	return 0;	/* Line not all here yet. Wait. */
				else if(r == -1)
				{	if(data_len + conn->incoming_cmd_cur_len > MAX_COMMAND_LINE_LENGTH)
					{	connection_write_str_to_buf("500 Line too long.\r\n", conn);
						connection_stop_reading(TO_CONN(conn));
						connection_mark_for_close(TO_CONN(conn));
						conn->_base.hold_open_until_flushed = 1;
					}
					while (conn->incoming_cmd_len < data_len+conn->incoming_cmd_cur_len)
						conn->incoming_cmd_len *= 2;
					conn->incoming_cmd = tor_realloc(conn->incoming_cmd,conn->incoming_cmd_len);
				}
			} while (r != 1);
			tor_assert(data_len);
			last_idx = conn->incoming_cmd_cur_len;
			conn->incoming_cmd_cur_len += (int)data_len;
			/* We have appended a line to incoming_cmd.  Is the command done? */
			if(last_idx == 0 && *conn->incoming_cmd != '+')	break;	/* One line command, didn't start with '+'. */
			/* XXXX this code duplication is kind of dumb. */
			if(last_idx+3 == conn->incoming_cmd_cur_len && tor_memeq(conn->incoming_cmd + last_idx, ".\r\n", 3))	/* Just appended ".\r\n"; we're done. Remove it. */
			{	conn->incoming_cmd[last_idx] = '\0';
				conn->incoming_cmd_cur_len -= 3;
				break;
			}
			else if(last_idx+2 == conn->incoming_cmd_cur_len && tor_memeq(conn->incoming_cmd + last_idx, ".\n", 2))	/* Just appended ".\n"; we're done. Remove it. */
			{	conn->incoming_cmd[last_idx] = '\0';
				conn->incoming_cmd_cur_len -= 2;
				break;
			}	/* Otherwise, read another line. */
		}
		data_len = conn->incoming_cmd_cur_len;
		/* Okay, we now have a command sitting on conn->incoming_cmd. See if we recognize it. */
		cmd_len = 0;
		while((size_t)cmd_len < data_len && !TOR_ISSPACE(conn->incoming_cmd[cmd_len]))
			++cmd_len;
		conn->incoming_cmd[cmd_len]='\0';
		args = conn->incoming_cmd+cmd_len+1;
		tor_assert(data_len>(size_t)cmd_len);
		data_len -= (cmd_len+1);	/* skip the command and NUL we added after it */
		while(*args == ' ' || *args == '\t')
		{	++args;
			--data_len;
		}
		if(!strcasecmp(conn->incoming_cmd, "QUIT"))	/* Quit is always valid. */
		{	connection_write_str_to_buf("250 closing connection\r\n", conn);
			connection_mark_for_close(TO_CONN(conn));
			return 0;
		}
		if(conn->_base.state == CONTROL_CONN_STATE_NEEDAUTH && !is_valid_initial_command(conn, conn->incoming_cmd))
		{	connection_write_str_to_buf("514 Authentication required.\r\n", conn);
			connection_mark_for_close(TO_CONN(conn));
			return 0;
		}
		if(data_len >= UINT32_MAX)
		{	connection_write_str_to_buf("500 A 4GB command? Nice try.\r\n", conn);
				connection_mark_for_close(TO_CONN(conn));
			return 0;
		}
		cmd_data_len = (uint32_t)data_len;
		if(!strcasecmp(conn->incoming_cmd, "SETCONF"))
		{	if(handle_control_setconf(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "RESETCONF"))
		{	if(handle_control_resetconf(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "GETCONF"))
		{	if(handle_control_getconf(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "+LOADCONF"))
		{	if(handle_control_loadconf(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "SETEVENTS"))
		{	if(handle_control_setevents(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "AUTHENTICATE"))
		{	if(handle_control_authenticate(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "SAVECONF"))
		{	if(handle_control_saveconf(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "SIGNAL"))
		{	if(handle_control_signal(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "TAKEOWNERSHIP"))
		{	if(handle_control_takeownership(conn,cmd_data_len,args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "MAPADDRESS"))
		{	if(handle_control_mapaddress(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "GETINFO"))
		{	if(handle_control_getinfo(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "EXTENDCIRCUIT"))
		{	if(handle_control_extendcircuit(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "SETCIRCUITPURPOSE"))
		{	if(handle_control_setcircuitpurpose(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "SETROUTERPURPOSE"))
		{	connection_write_str_to_buf("511 SETROUTERPURPOSE is obsolete.\r\n", conn);
		}
		else if(!strcasecmp(conn->incoming_cmd, "ATTACHSTREAM"))
		{	if(handle_control_attachstream(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "+POSTDESCRIPTOR"))
		{	if(handle_control_postdescriptor(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "REDIRECTSTREAM"))
		{	if(handle_control_redirectstream(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "CLOSESTREAM"))
		{	if(handle_control_closestream(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "CLOSECIRCUIT"))
		{	if(handle_control_closecircuit(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "USEFEATURE"))
		{	if(handle_control_usefeature(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "RESOLVE"))
		{	if(handle_control_resolve(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "PROTOCOLINFO"))
		{	if(handle_control_protocolinfo(conn, cmd_data_len, args))	return -1;
		}
		else if(!strcasecmp(conn->incoming_cmd, "AUTHCHALLENGE"))
		{	if(handle_control_authchallenge(conn, cmd_data_len, args))	return -1;
		}
		else
		{	connection_printf_to_buf(conn, "510 Unrecognized command \"%s\"\r\n",conn->incoming_cmd);
		}
		conn->incoming_cmd_cur_len = 0;
	}
}

/** Something has happened to circuit <b>circ</b>: tell any interested
 * control connections. */
int
control_event_circuit_status(origin_circuit_t *circ, circuit_status_event_t tp,
                             int reason_code)
{
  const char *status;
  char extended_buf[96];
  if (!EVENT_IS_INTERESTING(EVENT_CIRCUIT_STATUS))
    return 0;
  tor_assert(circ);

  switch (tp)
    {
    case CIRC_EVENT_LAUNCHED: status = "LAUNCHED"; break;
    case CIRC_EVENT_BUILT: status = "BUILT"; break;
    case CIRC_EVENT_EXTENDED: status = "EXTENDED"; break;
    case CIRC_EVENT_FAILED: status = "FAILED"; break;
    case CIRC_EVENT_CLOSED: status = "CLOSED"; break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_UNRECOGNIZED_STATUS_CODE),(int)tp);
      return 0;
    }

  tor_snprintf(extended_buf, sizeof(extended_buf), "PURPOSE=%s",
               circuit_purpose_to_controller_string(circ->_base.purpose));

  if (tp == CIRC_EVENT_FAILED || tp == CIRC_EVENT_CLOSED) {
    const char *reason_str = circuit_end_reason_to_control_string(reason_code);
    char *reason = NULL;
    size_t n=strlen(extended_buf);
    if (!reason_str) {
      reason = tor_malloc(16);
      tor_snprintf(reason, 16, "UNKNOWN_%d", reason_code);
      reason_str = reason;
    }
    if (reason_code > 0 && reason_code & END_CIRC_REASON_FLAG_REMOTE) {
      tor_snprintf(extended_buf+n, sizeof(extended_buf)-n,
                   " REASON=DESTROYED REMOTE_REASON=%s", reason_str);
    } else {
      tor_snprintf(extended_buf+n, sizeof(extended_buf)-n,
                   " REASON=%s", reason_str);
    }
    tor_free(reason);
  }

  {
    char *vpath = circuit_list_path_for_controller(circ);
    const char *sp = strlen(vpath) ? " " : "";
    send_control_event(EVENT_CIRCUIT_STATUS, ALL_FORMATS,
                                "650 CIRC %lu %s%s%s %s\r\n",
                                (unsigned long)circ->global_identifier,
                                status, sp, vpath, extended_buf);
    tor_free(vpath);
  }

  return 0;
}

/** Given an AP connection <b>conn</b> and a <b>len</b>-character buffer
 * <b>buf</b>, determine the address:port combination requested on
 * <b>conn</b>, and write it to <b>buf</b>.  Return 0 on success, -1 on
 * failure. */
static int
write_stream_target_to_buf(edge_connection_t *conn, char *buf, size_t len)
{
  char buf2[256];
  if (conn->chosen_exit_name)
    if (tor_snprintf(buf2, sizeof(buf2), ".%s.exit", conn->chosen_exit_name)<0)
      return -1;
  if (!conn->socks_request)
    return -1;
  if (tor_snprintf(buf, len, "%s%s%s:%d",
               conn->socks_request->address?conn->socks_request->address:"",
               conn->chosen_exit_name ? buf2 : "",
               !conn->chosen_exit_name &&
                 connection_edge_is_rendezvous_stream(conn) ? ".onion" : "",
               conn->socks_request->port)<0)
    return -1;
  return 0;
}

/** Something has happened to the stream associated with AP connection
 * <b>conn</b>: tell any interested control connections. */
int
control_event_stream_status(edge_connection_t *conn, stream_status_event_t tp,
                            int reason_code)
{
  char reason_buf[64];
  char addrport_buf[64];
  const char *status;
  circuit_t *circ;
  origin_circuit_t *origin_circ = NULL;
  char buf[256];
  const char *purpose = "";

  if (!EVENT_IS_INTERESTING(EVENT_STREAM_STATUS))
    return 0;

  tor_assert(conn->socks_request);
  if (tp == STREAM_EVENT_CLOSED &&
      (reason_code & END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED))
    return 0;

  write_stream_target_to_buf(conn, buf, sizeof(buf));

  reason_buf[0] = '\0';
  switch (tp)
    {
    case STREAM_EVENT_SENT_CONNECT: status = "SENTCONNECT"; break;
    case STREAM_EVENT_SENT_RESOLVE: status = "SENTRESOLVE"; break;
    case STREAM_EVENT_SUCCEEDED: status = "SUCCEEDED"; break;
    case STREAM_EVENT_FAILED: status = "FAILED"; break;
    case STREAM_EVENT_CLOSED: status = "CLOSED"; break;
    case STREAM_EVENT_NEW: status = "NEW"; break;
    case STREAM_EVENT_NEW_RESOLVE: status = "NEWRESOLVE"; break;
    case STREAM_EVENT_FAILED_RETRIABLE: status = "DETACHED"; break;
    case STREAM_EVENT_REMAP: status = "REMAP"; break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_UNRECOGNIZED_STATUS_CODE),(int)tp);
      return 0;
    }
  if (reason_code && (tp == STREAM_EVENT_FAILED ||
                      tp == STREAM_EVENT_CLOSED ||
                      tp == STREAM_EVENT_FAILED_RETRIABLE)) {
    const char *reason_str = stream_end_reason_to_control_string(reason_code);
    char *r = NULL;
    if (!reason_str) {
      r = tor_malloc(16);
      tor_snprintf(r, 16, " UNKNOWN_%d", reason_code);
      reason_str = r;
    }
    if (reason_code & END_STREAM_REASON_FLAG_REMOTE)
      tor_snprintf(reason_buf, sizeof(reason_buf),
                   " REASON=END REMOTE_REASON=%s", reason_str);
    else
      tor_snprintf(reason_buf, sizeof(reason_buf),
                   " REASON=%s", reason_str);
    tor_free(r);
  } else if (reason_code && tp == STREAM_EVENT_REMAP) {
    switch (reason_code) {
    case REMAP_STREAM_SOURCE_CACHE:
      strlcpy(reason_buf, " SOURCE=CACHE", sizeof(reason_buf));
      break;
    case REMAP_STREAM_SOURCE_EXIT:
      strlcpy(reason_buf, " SOURCE=EXIT", sizeof(reason_buf));
      break;
    default:
      tor_snprintf(reason_buf, sizeof(reason_buf), " REASON=UNKNOWN_%d",
                   reason_code);
      /* XXX do we want SOURCE=UNKNOWN_%d above instead? -RD */
      break;
    }
  }

  if (tp == STREAM_EVENT_NEW) {
    tor_snprintf(addrport_buf,sizeof(addrport_buf), " SOURCE_ADDR=%s:%d",
                 TO_CONN(conn)->address, TO_CONN(conn)->port );
  } else {
    addrport_buf[0] = '\0';
  }

  if (tp == STREAM_EVENT_NEW_RESOLVE) {
    purpose = " PURPOSE=DNS_REQUEST";
  } else if (tp == STREAM_EVENT_NEW) {
    if (conn->is_dns_request ||
        (conn->socks_request &&
         SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command)))
      purpose = " PURPOSE=DNS_REQUEST";
    else if (conn->use_begindir) {
      connection_t *linked = TO_CONN(conn)->linked_conn;
      int linked_dir_purpose = -1;
      if (linked && linked->type == CONN_TYPE_DIR)
        linked_dir_purpose = linked->purpose;
      if (DIR_PURPOSE_IS_UPLOAD(linked_dir_purpose))
        purpose = " PURPOSE=DIR_UPLOAD";
      else
        purpose = " PURPOSE=DIR_FETCH";
    } else
      purpose = " PURPOSE=USER";
  }

  circ = circuit_get_by_edge_conn(conn);
  if (circ && CIRCUIT_IS_ORIGIN(circ))
    origin_circ = TO_ORIGIN_CIRCUIT(circ);
  send_control_event(EVENT_STREAM_STATUS, ALL_FORMATS,
                        "650 STREAM "U64_FORMAT" %s %lu %s%s%s%s\r\n",
                        U64_PRINTF_ARG(conn->_base.global_identifier), status,
                        origin_circ?
                           (unsigned long)origin_circ->global_identifier : 0ul,
                        buf, reason_buf, addrport_buf, purpose);

  /* XXX need to specify its intended exit, etc? */

  return 0;
}

/** Figure out the best name for the target router of an OR connection
 * <b>conn</b>, and write it into the <b>len</b>-character buffer
 * <b>name</b>.  Use verbose names if <b>long_names</b> is set. */
static void
orconn_target_get_name(char *name, size_t len, or_connection_t *conn)
{
  routerinfo_t *ri = router_get_by_digest(conn->identity_digest);
  if (ri) {
    tor_assert(len > MAX_VERBOSE_NICKNAME_LEN);
    router_get_verbose_nickname(name, ri);
  } else if (! tor_digest_is_zero(conn->identity_digest)) {
    name[0] = '$';
    base16_encode(name+1, len-1, conn->identity_digest,
                  DIGEST_LEN);
  } else {
    tor_snprintf(name, len, "%s:%d",
                 conn->_base.address, conn->_base.port);
  }
}

/** Called when the status of an OR connection <b>conn</b> changes: tell any
 * interested control connections. <b>tp</b> is the new status for the
 * connection.  If <b>conn</b> has just closed or failed, then <b>reason</b>
 * may be the reason why.
 */
int
control_event_or_conn_status(or_connection_t *conn, or_conn_status_event_t tp,
                             int reason)
{
  int ncircs = 0;
  const char *status;
  char name[128];
  char ncircs_buf[32] = {0}; /* > 8 + log10(2^32)=10 + 2 */

  if (!EVENT_IS_INTERESTING(EVENT_OR_CONN_STATUS))
    return 0;

  switch (tp)
    {
    case OR_CONN_EVENT_LAUNCHED: status = "LAUNCHED"; break;
    case OR_CONN_EVENT_CONNECTED: status = "CONNECTED"; break;
    case OR_CONN_EVENT_FAILED: status = "FAILED"; break;
    case OR_CONN_EVENT_CLOSED: status = "CLOSED"; break;
    case OR_CONN_EVENT_NEW: status = "NEW"; break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_UNRECOGNIZED_STATUS_CODE),(int)tp);
      return 0;
    }
  ncircs = circuit_count_pending_on_or_conn(conn);
  ncircs += conn->n_circuits;
  if (ncircs && (tp == OR_CONN_EVENT_FAILED || tp == OR_CONN_EVENT_CLOSED)) {
    tor_snprintf(ncircs_buf, sizeof(ncircs_buf), "%sNCIRCS=%d",
                 reason ? " " : "", ncircs);
  }

  orconn_target_get_name(name, sizeof(name), conn);
  send_control_event(EVENT_OR_CONN_STATUS, ALL_FORMATS,
                              "650 ORCONN %s %s %s%s%s\r\n",
                              name, status,
                              reason ? "REASON=" : "",
                              orconn_end_reason_to_control_string(reason),
                              ncircs_buf);

  return 0;
}

/** A second or more has elapsed: tell any interested control
 * connections how much bandwidth streams have used. */
int
control_event_stream_bandwidth_used(void)
{
  if (EVENT_IS_INTERESTING(EVENT_STREAM_BANDWIDTH_USED)) {
    smartlist_t *conns = get_connection_array();
    edge_connection_t *edge_conn;

    SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn)
    {
        if (conn->type != CONN_TYPE_AP)
          continue;
        edge_conn = TO_EDGE_CONN(conn);
        if (!edge_conn->n_read && !edge_conn->n_written)
          continue;

        send_control_event(EVENT_STREAM_BANDWIDTH_USED, ALL_FORMATS,
                           "650 STREAM_BW "U64_FORMAT" %lu %lu\r\n",
                           U64_PRINTF_ARG(edge_conn->_base.global_identifier),
                           (unsigned long)edge_conn->n_read,
                           (unsigned long)edge_conn->n_written);

        edge_conn->n_written = edge_conn->n_read = 0;
    }
    SMARTLIST_FOREACH_END(conn);
  }

  return 0;
}

/** A second or more has elapsed: tell any interested control
 * connections how much bandwidth we used. */
int
control_event_bandwidth_used(uint32_t n_read, uint32_t n_written)
{
  if (EVENT_IS_INTERESTING(EVENT_BANDWIDTH_USED)) {
    send_control_event(EVENT_BANDWIDTH_USED, ALL_FORMATS,
                       "650 BW %lu %lu\r\n",
                       (unsigned long)n_read,
                       (unsigned long)n_written);
  }

  return 0;
}

/** Called when we are sending a log message to the controllers: suspend
 * sending further log messages to the controllers until we're done.  Used by
 * CONN_LOG_PROTECT. */
void
disable_control_logging(void)
{
  ++disable_log_messages;
}

/** We're done sending a log message to the controllers: re-enable controller
 * logging.  Used by CONN_LOG_PROTECT. */
void
enable_control_logging(void)
{
  if (--disable_log_messages < 0)
    tor_assert(0);
}

/** We got a log message: tell any interested control connections. */
void
control_event_logmsg(int severity, uint32_t domain, const char *msg)
{
  int event;

  if (!num_controllers || disable_log_messages)
    return;

  if (domain == LD_BUG && EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL) &&
      severity <= LOG_NOTICE) {
    char *esc = esc_for_log(msg);
    ++disable_log_messages;
    control_event_general_status(severity, "BUG REASON=\"%s\"", esc);
    --disable_log_messages;
    tor_free(esc);
  }

  event = log_severity_to_event(severity);
  if (event >= 0 && EVENT_IS_INTERESTING(event)) {
    char *b = NULL;
    const char *s;
    if (strchr(msg, '\n')) {
      char *cp;
      b = tor_strdup(msg);
      for (cp = b; *cp; ++cp)
        if (*cp == '\r' || *cp == '\n')
          *cp = ' ';
    }
    switch (severity) {
      case LOG_DEBUG: s = "DEBUG"; break;
      case LOG_INFO: s = "INFO"; break;
      case LOG_NOTICE: s = "NOTICE"; break;
      case LOG_WARN: s = "WARN"; break;
      case LOG_ERR: s = "ERR"; break;
      default: s = "UnknownLogSeverity"; break;
    }
    ++disable_log_messages;
    send_control_event(event, ALL_FORMATS, "650 %s %s\r\n", s, b?b:msg);
    --disable_log_messages;
    tor_free(b);
  }
}

/** Called whenever we receive new router descriptors: tell any
 * interested control connections.  <b>routers</b> is a list of
 * routerinfo_t's.
 */
int
control_event_descriptors_changed(smartlist_t *routers)
{
  char *msg;

  if (!EVENT_IS_INTERESTING(EVENT_NEW_DESC))
    return 0;
  {
    smartlist_t *names = smartlist_create();
    char *ids;
    size_t names_len;
    SMARTLIST_FOREACH(routers, routerinfo_t *, ri, {
        char *b = tor_malloc(MAX_VERBOSE_NICKNAME_LEN+1);
        router_get_verbose_nickname(b, ri);
        smartlist_add(names, b);
      });
    ids = smartlist_join_strings(names, " ", 0, &names_len);
    names_len = strlen(ids)+32;
    msg = tor_malloc(names_len);
    tor_snprintf(msg, names_len, "650 NEWDESC %s\r\n", ids);
    send_control_event_string(EVENT_NEW_DESC, ALL_FORMATS, msg);
    tor_free(ids);
    tor_free(msg);
    SMARTLIST_FOREACH(names, char *, cp, tor_free(cp));
    smartlist_free(names);
  }
  return 0;
}

int plugins_remap(edge_connection_t *conn,char **address,char *original_address,BOOL is_error);

/** Called when an address mapping on <b>from</b> from changes to <b>to</b>.
 * <b>expires</b> values less than 3 are special; see connection_edge.c.  If
 * <b>error</b> is non-NULL, it is an error code describing the failure
 * mode of the mapping.
 */
int control_event_address_mapped(char *from,char **to, time_t expires,const char *error)
{
  plugins_remap(NULL,to,from,(error!=NULL));
  if (!EVENT_IS_INTERESTING(EVENT_ADDRMAP))
    return 0;

  if (expires < 3 || expires == TIME_MAX)
    send_control_event(EVENT_ADDRMAP, ALL_FORMATS,
                                "650 ADDRMAP %s %s NEVER %s\r\n", from, *to,
                                error?error:"");
  else {
    char buf[ISO_TIME_LEN+1];
    char buf2[ISO_TIME_LEN+1];
    format_local_iso_time(buf,expires);
    format_iso_time(buf2,expires);
    send_control_event(EVENT_ADDRMAP, ALL_FORMATS,
                                "650 ADDRMAP %s %s \"%s\""
                                " %s%sEXPIRES=\"%s\"\r\n",
                                from, *to, buf,
                                error?error:"", error?" ":"",
                                buf2);
  }

  return 0;
}

/** The authoritative dirserver has received a new descriptor that
 * has passed basic syntax checks and is properly self-signed.
 *
 * Notify any interested party of the new descriptor and what has
 * been done with it, and also optionally give an explanation/reason. */
int
control_event_or_authdir_new_descriptor(const char *action,
                                        const char *desc, size_t desclen,
                                        const char *msg)
{
  char firstline[1024];
  char *buf;
  size_t totallen;
  char *esc = NULL;
  size_t esclen;

  if (!EVENT_IS_INTERESTING(EVENT_AUTHDIR_NEWDESCS))
    return 0;

  tor_snprintf(firstline, sizeof(firstline),
               "650+AUTHDIR_NEWDESC=\r\n%s\r\n%s\r\n",
               action,
               msg ? msg : "");

  /* Escape the server descriptor properly */
  esclen = write_escaped_data(desc, desclen, &esc);

  totallen = strlen(firstline) + esclen + 1;
  buf = tor_malloc(totallen);
  strlcpy(buf, firstline, totallen);
  strlcpy(buf+strlen(firstline), esc, totallen);
  send_control_event_string(EVENT_AUTHDIR_NEWDESCS, ALL_FORMATS,
                            buf);
  send_control_event_string(EVENT_AUTHDIR_NEWDESCS, ALL_FORMATS,
                            "650 OK\r\n");
  tor_free(esc);
  tor_free(buf);

  return 0;
}

void plugins_routerchanged(uint32_t addr,char *digest);
/** Helper function for NS-style events. Constructs and sends an event
 * of type <b>event</b> with string <b>event_string</b> out of the set of
 * networkstatuses <b>statuses</b>. Currently it is used for NS events
 * and NEWCONSENSUS events. */
static int
control_event_networkstatus_changed_helper(smartlist_t *statuses,
                                           uint16_t event,
                                           const char *event_string)
{
  smartlist_t *strs;
  char *s, *esc = NULL;
  if (!EVENT_IS_INTERESTING(event) || !smartlist_len(statuses))
    return 0;

  strs = smartlist_create();
  smartlist_add(strs, tor_strdup("650+"));
  smartlist_add(strs, tor_strdup(event_string));
  smartlist_add(strs, tor_strdup("\r\n"));
  SMARTLIST_FOREACH(statuses, routerstatus_t *, rs,
    { plugins_routerchanged(rs->addr,rs->identity_digest);
      s = networkstatus_getinfo_helper_single(rs);
      if (!s) continue;
      smartlist_add(strs, s);
    });

  s = smartlist_join_strings(strs, "", 0, NULL);
  write_escaped_data(s, strlen(s), &esc);
  SMARTLIST_FOREACH(strs, char *, cp, tor_free(cp));
  smartlist_free(strs);
  tor_free(s);
  send_control_event_string(event, ALL_FORMATS, esc);
  send_control_event_string(event, ALL_FORMATS,
                            "650 OK\r\n");

  tor_free(esc);
  return 0;
}

/** Called when the routerstatus_ts <b>statuses</b> have changed: sends
 * an NS event to any controller that cares. */
int
control_event_networkstatus_changed(smartlist_t *statuses)
{
  return control_event_networkstatus_changed_helper(statuses, EVENT_NS, "NS");
}

/** Called when we get a new consensus networkstatus. Sends a NEWCONSENSUS
 * event consisting of an NS-style line for each relay in the consensus. */
int
control_event_newconsensus(const networkstatus_t *consensus)
{
  if (!control_event_is_interesting(EVENT_NEWCONSENSUS))
    return 0;
  return control_event_networkstatus_changed_helper(
           consensus->routerstatus_list, EVENT_NEWCONSENSUS, "NEWCONSENSUS");
}

/** Called when we compute a new circuitbuildtimeout */	///
int control_event_buildtimeout_set(const circuit_build_times_t *cbt,buildtimeout_set_event_t type)
{	const char *type_string = NULL;
	double qnt = circuit_build_times_quantile_cutoff();
	if(!control_event_is_interesting(EVENT_BUILDTIMEOUT_SET))
		return 0;
	switch(type)
	{	case BUILDTIMEOUT_SET_EVENT_COMPUTED:
			type_string = "COMPUTED";
			break;
		case BUILDTIMEOUT_SET_EVENT_RESET:
			type_string = "RESET";
			qnt = 1.0;
			break;
		case BUILDTIMEOUT_SET_EVENT_SUSPENDED:
			type_string = "SUSPENDED";
			qnt = 1.0;
			break;
		case BUILDTIMEOUT_SET_EVENT_DISCARD:
			type_string = "DISCARD";
			qnt = 1.0;
			break;
		case BUILDTIMEOUT_SET_EVENT_RESUME:
			type_string = "RESUME";
			break;
		default:
			type_string = "UNKNOWN";
			break;
	}
	send_control_event(EVENT_BUILDTIMEOUT_SET, ALL_FORMATS,"650 BUILDTIMEOUT_SET %s TOTAL_TIMES=%lu TIMEOUT_MS=%lu XM=%lu ALPHA=%f CUTOFF_QUANTILE=%f TIMEOUT_RATE=%f CLOSE_MS=%lu CLOSE_RATE=%f\r\n",type_string, (unsigned long)cbt->total_build_times,(unsigned long)cbt->timeout_ms,(unsigned long)cbt->Xm, cbt->alpha, qnt,circuit_build_times_timeout_rate(cbt),(unsigned long)cbt->close_ms,circuit_build_times_close_rate(cbt));
	return 0;
}

/** Called when a single local_routerstatus_t has changed: Sends an NS event
 * to any countroller that cares. */
int
control_event_networkstatus_changed_single(routerstatus_t *rs)
{
  smartlist_t *statuses;
  int r;

  if (!EVENT_IS_INTERESTING(EVENT_NS))
    return 0;

  statuses = smartlist_create();
  smartlist_add(statuses, rs);
  r = control_event_networkstatus_changed(statuses);
  smartlist_free(statuses);
  return r;
}

/** Our own router descriptor has changed; tell any controllers that care.
 */
int
control_event_my_descriptor_changed(void)
{
  send_control_event(EVENT_DESCCHANGED, ALL_FORMATS, "650 DESCCHANGED\r\n");
  return 0;
}

/** Helper: sends a status event where <b>type</b> is one of
 * EVENT_STATUS_{GENERAL,CLIENT,SERVER}, where <b>severity</b> is one of
 * LOG_{NOTICE,WARN,ERR}, and where <b>format</b> is a printf-style format
 * string corresponding to <b>args</b>. */
static int
control_event_status(int type, int severity, const char *format, va_list args)
{
  unsigned char *user_buf = NULL;
  char format_buf[160];
  const char *status, *sev;

  switch (type) {
    case EVENT_STATUS_GENERAL:
      status = "STATUS_GENERAL";
      break;
    case EVENT_STATUS_CLIENT:
      status = "STATUS_CLIENT";
      break;
    case EVENT_STATUS_SERVER:
      status = "STATUS_SERVER";
      break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_UNRECOGNIZED_STATUS_TYPE),type);
      return -1;
  }
  switch (severity) {
    case LOG_NOTICE:
      sev = "NOTICE";
      break;
    case LOG_WARN:
      sev = "WARN";
      break;
    case LOG_ERR:
      sev = "ERR";
      break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_UNRECOGNIZED_STATUS_SEVERITY),severity);
      return -1;
  }
  if (tor_snprintf(format_buf, sizeof(format_buf), "650 %s %s",
                   status, sev)<0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONTROL_FORMAT_STRING_TOO_LONG));
    return -1;
  }

  tor_vasprintf(&user_buf, format, args);

  send_control_event(type, ALL_FORMATS, "%s %s\r\n", format_buf, user_buf);
  tor_free(user_buf);
  return 0;
}

/** Format and send an EVENT_STATUS_GENERAL event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_general_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_GENERAL))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_GENERAL, severity, format, ap);
  va_end(ap);
  return r;
}

/** Format and send an EVENT_STATUS_CLIENT event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_client_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_CLIENT))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_CLIENT, severity, format, ap);
  va_end(ap);
  return r;
}

/** Format and send an EVENT_STATUS_SERVER event whose main text is obtained
 * by formatting the arguments using the printf-style <b>format</b>. */
int
control_event_server_status(int severity, const char *format, ...)
{
  va_list ap;
  int r;
  if (!EVENT_IS_INTERESTING(EVENT_STATUS_SERVER))
    return 0;

  va_start(ap, format);
  r = control_event_status(EVENT_STATUS_SERVER, severity, format, ap);
  va_end(ap);
  return r;
}

/** Called when the status of an entry guard with the given <b>nickname</b>
 * and identity <b>digest</b> has changed to <b>status</b>: tells any
 * controllers that care. */
int
control_event_guard(const char *nickname, const char *digest,
                    const char *status)
{
  char hbuf[HEX_DIGEST_LEN+1];
  if (!EVENT_IS_INTERESTING(EVENT_GUARD))
    return 0;
  base16_encode(hbuf, sizeof(hbuf), digest, DIGEST_LEN);

  {
    char buf[MAX_VERBOSE_NICKNAME_LEN+1];
    routerinfo_t *ri = router_get_by_digest(digest);
    if (ri) {
      router_get_verbose_nickname(buf, ri);
    } else {
      tor_snprintf(buf, sizeof(buf), "$%s~%s", hbuf, nickname);
    }
    send_control_event(EVENT_GUARD, ALL_FORMATS,
                       "650 GUARD ENTRY %s %s\r\n", buf, status);
  }
  return 0;
}

/** Helper: Return a newly allocated string containing a path to the
 * file where we store our authentication cookie. */
static char *
get_cookie_file(void)
{
  or_options_t *options = get_options();
  if (options->CookieAuthFile && strlen(options->CookieAuthFile)) {
    return tor_strdup(options->CookieAuthFile);
  } else {
    return get_datadir_fname(DATADIR_CONTROL_AUTH_COOKIE);
  }
}

/** Choose a random authentication cookie and write it to disk.
 * Anybody who can read the cookie from disk will be considered
 * authorized to use the control connection. Return -1 if we can't
 * write the file, or 0 on success. */
int
init_cookie_authentication(int enabled)
{
  char *fname;
  if (!enabled) {
    authentication_cookie_is_set = 0;
    return 0;
  }

  /* We don't want to generate a new cookie every time we call
   * options_act(). One should be enough. */
  if (authentication_cookie_is_set)
    return 0; /* all set */

  fname = get_cookie_file();
  crypto_rand(authentication_cookie, AUTHENTICATION_COOKIE_LEN);
  authentication_cookie_is_set = 1;
  if (write_buf_to_file(fname,authentication_cookie,AUTHENTICATION_COOKIE_LEN)) {
    char *esc_l = esc_for_log(fname);
    log_warn(LD_FS,get_lang_str(LANG_LOG_CONTROL_ERROR_WRITING_AUTH_COOKIE),esc_l);
    tor_free(esc_l);
    tor_free(fname);
    return -1;
  }

  tor_free(fname);
  return 0;
}

static char *owning_controller_process_spec = NULL;				/** A copy of the process specifier of Tor's owning controller, or NULL if this Tor instance is not currently owned by a process. */
static tor_process_monitor_t *owning_controller_process_monitor = NULL;		/** A process-termination monitor for Tor's owning controller, or NULL if this Tor instance is not currently owned by a process. */

/** Process-termination monitor callback for Tor's owning controller process. */
static void owning_controller_procmon_cb(void *unused)
{	(void)unused;
	lost_owning_controller("process", "vanished");
}

/** Set <b>process_spec</b> as Tor's owning controller process. Exit on failure. */
void monitor_owning_controller_process(const char *process_spec)
{	const char *msg;
	tor_assert((owning_controller_process_spec == NULL) == (owning_controller_process_monitor == NULL));
	if(owning_controller_process_spec != NULL)
	{	if((process_spec != NULL) && !strcmp(process_spec,owning_controller_process_spec))	/* Same process -- return now, instead of disposing of and recreating the process-termination monitor. */
			return;
		/* We are currently owned by a process, and we should no longer be owned by it. Free the process-termination monitor. */
		tor_process_monitor_free(owning_controller_process_monitor);
		owning_controller_process_monitor = NULL;
		tor_free(owning_controller_process_spec);
		owning_controller_process_spec = NULL;
	}
	tor_assert((owning_controller_process_spec == NULL) && (owning_controller_process_monitor == NULL));
	if(process_spec == NULL)	return;
	owning_controller_process_spec = tor_strdup(process_spec);
	owning_controller_process_monitor = tor_process_monitor_new(tor_libevent_get_base(),owning_controller_process_spec,LD_CONTROL,owning_controller_procmon_cb,NULL,&msg);
	if(owning_controller_process_monitor == NULL)
	{	log_err(LD_BUG,get_lang_str(LANG_LOG_CONTROL_ERROR_MONITORING_PROCESS),msg);
		owning_controller_process_spec = NULL;
		tor_cleanup();
		exit(0);
	}
}

/** Convert the name of a bootstrapping phase <b>s</b> into strings
 * <b>tag</b> and <b>summary</b> suitable for display by the controller. */
static int
bootstrap_status_to_string(bootstrap_status_t s, const char **tag,
                           const char **summary)
{
  switch (s) {
    case BOOTSTRAP_STATUS_UNDEF:
      *tag = "undef";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_UNDEFINED);
      break;
    case BOOTSTRAP_STATUS_STARTING:
      *tag = "starting";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_STARTING);
      break;
    case BOOTSTRAP_STATUS_CONN_DIR:
      *tag = "conn_dir";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_CONN_DIR);
      break;
    case BOOTSTRAP_STATUS_HANDSHAKE:
      *tag = "status_handshake";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_FINISHING_HANDSHAKE);
      break;
    case BOOTSTRAP_STATUS_HANDSHAKE_DIR:
      *tag = "handshake_dir";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_FINISHING_DIR_HANDSHAKE);
      break;
    case BOOTSTRAP_STATUS_ONEHOP_CREATE:
      *tag = "onehop_create";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_ESTABLISHING_ENCRYPTED_DIR_CONN);
      break;
    case BOOTSTRAP_STATUS_REQUESTING_STATUS:
      *tag = "requesting_status";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_ASKING_FOR_CONSENSUS);
      break;
    case BOOTSTRAP_STATUS_LOADING_STATUS:
      *tag = "loading_status";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_LOADING_CONSENSUS);
      break;
    case BOOTSTRAP_STATUS_LOADING_KEYS:
      *tag = "loading_keys";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_LOADING_CERTS);
      break;
    case BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS:
      *tag = "requesting_descriptors";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_ASKING_FOR_DESCRIPTORS);
      break;
    case BOOTSTRAP_STATUS_LOADING_DESCRIPTORS:
      *tag = "loading_descriptors";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_LOADING_DESCRIPTORS);
      break;
    case BOOTSTRAP_STATUS_CONN_OR:
      *tag = "conn_or";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_CONNECTING);
      break;
    case BOOTSTRAP_STATUS_HANDSHAKE_OR:
      *tag = "handshake_or";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_HANDSHAKE_FIRST_HOP);
      break;
    case BOOTSTRAP_STATUS_CIRCUIT_CREATE:
      *tag = "circuit_create";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_ESTABLISHING_CIRCUIT);
      break;
    case BOOTSTRAP_STATUS_STARTED:
      *tag = "done";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_STARTED); 
      break;
    case BOOTSTRAP_STATUS_DONE:
      *tag = "done";
      *summary = get_lang_str(LANG_LOG_CONTROL_BS_CONNECTED); 
      break;
    default:
//      log_warn(LD_BUG, "Unrecognized bootstrap status code %d", s);
      *tag = *summary = "unknown";
      return -1;
  }
  return 0;
}

/** What percentage through the bootstrap process are we? We remember
 * this so we can avoid sending redundant bootstrap status events, and
 * so we can guess context for the bootstrap messages which are
 * ambiguous. It starts at 'undef', but gets set to 'starting' while
 * Tor initializes. */
int bootstrap_percent = BOOTSTRAP_STATUS_UNDEF;

/** How many problems have we had getting to the next bootstrapping phase?
 * These include failure to establish a connection to a Tor relay,
 * failures to finish the TLS handshake, failures to validate the
 * consensus document, etc. */
static int bootstrap_problems = 0;

/* We only tell the controller once we've hit a threshold of problems
 * for the current phase. */
#define BOOTSTRAP_PROBLEM_THRESHOLD 10

/** Called when Tor has made progress at bootstrapping its directory
 * information and initial circuits.
 *
 * <b>status</b> is the new status, that is, what task we will be doing
 * next. <b>percent</b> is zero if we just started this task, else it
 * represents progress on the task. */
void
control_event_bootstrap(bootstrap_status_t status, int progress)
{
  const char *tag, *summary;
  char buf[BOOTSTRAP_MSG_LEN];

  if (bootstrap_percent == BOOTSTRAP_STATUS_DONE)
    return; /* already bootstrapped; nothing to be done here. */

  /* special case for handshaking status, since our TLS handshaking code
   * can't distinguish what the connection is going to be for. */
  if (status == BOOTSTRAP_STATUS_HANDSHAKE) {
    if (bootstrap_percent < BOOTSTRAP_STATUS_CONN_OR) {
      status =  BOOTSTRAP_STATUS_HANDSHAKE_DIR;
    } else {
      status = BOOTSTRAP_STATUS_HANDSHAKE_OR;
    }
  }

  if (status > bootstrap_percent ||
      (progress && progress > bootstrap_percent)) {
    bootstrap_status_to_string(status, &tag, &summary);
    progressLog(progress ? progress : status,summary);
    if(status==BOOTSTRAP_STATUS_STARTED) status=BOOTSTRAP_STATUS_DONE;
    log(status ? LOG_NOTICE : LOG_INFO, LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_BOOTSTRAPPED),progress ? progress : status, summary);
    if(num_controllers)
    {
      tor_snprintf(buf, sizeof(buf),
          "BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=\"%s\"",
          progress ? progress : status, tag, summary);
      tor_snprintf(last_sent_bootstrap_message,
                   sizeof(last_sent_bootstrap_message),
                   "NOTICE %s", buf);
      control_event_client_status(LOG_NOTICE, "%s", buf);
    }
    if (status > bootstrap_percent) {
      bootstrap_percent = status; /* new milestone reached */
    }
    if (progress > bootstrap_percent) {
      /* incremental progress within a milestone */
      bootstrap_percent = progress;
      bootstrap_problems = 0; /* Progress! Reset our problem counter. */
    }
  }
}

/** Called when Tor has failed to make bootstrapping progress in a way
 * that indicates a problem. <b>warn</b> gives a hint as to why, and
 * <b>reason</b> provides an "or_conn_end_reason" tag.
 */
void
control_event_bootstrap_problem(const char *warn, int reason)
{
  int status = bootstrap_percent;
  const char *tag, *summary;
  char buf[BOOTSTRAP_MSG_LEN];
  const char *recommendation = "ignore";

  tor_assert(status >= 0);
  if (bootstrap_percent == 100)
    return; /* already bootstrapped; nothing to be done here. */

  bootstrap_problems++;

  if (bootstrap_problems >= BOOTSTRAP_PROBLEM_THRESHOLD)
    recommendation = "warn";

  if (reason == END_OR_CONN_REASON_NO_ROUTE)
    recommendation = "warn";

  if (get_options()->UseBridges &&
      !any_bridge_descriptors_known() &&
      !any_pending_bridge_descriptor_fetches())
    recommendation = "warn";

  while (status>=0 && bootstrap_status_to_string(status, &tag, &summary) < 0)
    status--; /* find a recognized status string based on current progress */
  status = bootstrap_percent; /* set status back to the actual number */

  log_fn(!strcmp(recommendation, "warn") ? LOG_WARN : LOG_INFO,LD_CONTROL,get_lang_str(LANG_LOG_CONTROL_BOOTSTRAPPING_STUCK),status,summary,warn,orconn_end_reason_to_control_string(reason),bootstrap_problems, recommendation);
  if(num_controllers)
  {
    tor_snprintf(buf, sizeof(buf),
        "BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=\"%s\" WARNING=\"%s\" REASON=%s "
        "COUNT=%d RECOMMENDATION=%s",
        bootstrap_percent, tag, summary, warn,
        orconn_end_reason_to_control_string(reason), bootstrap_problems,
        recommendation);
    tor_snprintf(last_sent_bootstrap_message,
                 sizeof(last_sent_bootstrap_message),
                 "WARN %s", buf);
    control_event_client_status(LOG_WARN, "%s", buf);
  }
}

/** We just generated a new summary of which countries we've seen clients
 * from recently. Send a copy to the controller in case it wants to
 * display it for the user. */
void
control_event_clients_seen(const char *controller_str)
{
  send_control_event(EVENT_CLIENTS_SEEN, 0,
    "650 CLIENTS_SEEN %s\r\n", controller_str);
}

