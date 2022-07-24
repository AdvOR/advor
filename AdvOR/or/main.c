/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file main.c
 * \brief Toplevel module. Handles signals, multiplexes between
 * connections, implements main loop, and drives scheduled events.
 **/

#define MAIN_PRIVATE
#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "command.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "cpuworker.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "dns.h"
#include "dnsserv.h"
#include "geoip.h"
#include "hibernate.h"
#include "main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "ntmain.h"
#include "onion.h"
#include "policies.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "seh.h"
#ifdef USE_DMALLOC
#include <dmalloc.h>
#include <openssl/crypto.h>
#endif
#include "memarea.h"

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#include <event2/event_compat.h>
#else
#include <event.h>
#endif

void evdns_shutdown(int);
#include <winsock2.h>
#include <commctrl.h>
#include <commdlg.h>
#include "plugins.h"

/********* PROTOTYPES **********/

static void dumpmemusage(int severity);
static void conn_read_callback(evutil_socket_t fd, short event, void *_conn);
static void conn_write_callback(evutil_socket_t fd, short event, void *_conn);
static void second_elapsed_callback(periodic_timer_t *timer, void *args);
static int conn_close_if_marked(int i);
static void connection_start_reading_from_linked_conn(connection_t *conn);
static int connection_should_read_from_linked_conn(connection_t *conn);
void dlgAuthorities_initDirServers(config_line_t **option);
int plugin_notify_service(rend_service_t *service,int added,connection_t *conn,int port);
int __stdcall dlgfunc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void signewnym_impl(time_t now,int msgshow);
void signewnym_scheduled_tasks(void);
void identity_auto_change(time_t now);
void connection_read_event(connection_t *conn);
void connection_write_event(connection_t *conn);
void tor_end(void) __attribute__((noreturn));

/********* START VARIABLES **********/

int global_read_bucket; /**< Max number of bytes I can read this second. */
int global_write_bucket; /**< Max number of bytes I can write this second. */

/** Max number of relayed (bandwidth class 1) bytes I can read this second. */
int global_relayed_read_bucket;
/** Max number of relayed (bandwidth class 1) bytes I can write this second. */
int global_relayed_write_bucket;

/** What was the read bucket before the last second_elapsed_callback() call?
 * (used to determine how many bytes we've read). */
static int stats_prev_global_read_bucket;
/** What was the write bucket before the last second_elapsed_callback() call?
 * (used to determine how many bytes we've written). */
static int stats_prev_global_write_bucket;
/* XXX we might want to keep stats about global_relayed_*_bucket too. Or not.*/
/** How many bytes have we read since we started the process? */
static uint64_t stats_n_bytes_read = 0;
/** How many bytes have we written since we started the process? */
static uint64_t stats_n_bytes_written = 0;
/** What time did this process start up? */
time_t time_of_process_start = 0;
/** How many seconds have we been running? */
long stats_n_seconds_working = 0;
/** When do we next launch DNS wildcarding checks? */
static time_t time_to_check_for_correct_dns = 0;

/** Smartlist of all open connections. */
static smartlist_t *connection_array = NULL;
/** List of connections that have been marked for close and need to be freed
 * and removed from connection_array. */
static smartlist_t *closeable_connection_lst = NULL;
/** List of linked connections that are currently reading data into their
 * inbuf from their partner's outbuf. */
static smartlist_t *active_linked_connection_lst = NULL,*plugin_connection_lst=NULL;
/** Flag: Set to true iff we entered the current libevent main loop via
 * <b>loop_once</b>. If so, there's no need to trigger a loopexit in order
 * to handle linked connections. */
static int called_loop_once = 0;
or_options_t *tmpOptions=NULL;
extern int signewnym_pending;


/** We set this to 1 when we've opened a circuit, so we can print a log
 * entry to inform the user that Tor is working.  We set it to 0 when
 * we think the fact that we once opened a circuit doesn't mean we can do so
 * any longer (a big time jump happened, when we notice our directory is
 * heinously out-of-date, etc.
 */
int can_complete_circuit=0;

/** How often do we check for router descriptors that we should download
 * when we have too little directory info? */
#define GREEDY_DESCRIPTOR_RETRY_INTERVAL (10)
/** How often do we check for router descriptors that we should download
 * when we have enough directory info? */
#define LAZY_DESCRIPTOR_RETRY_INTERVAL (60)
/** How often do we 'forgive' undownloadable router descriptors and attempt
 * to download them again? */
#define DESCRIPTOR_FAILURE_RESET_INTERVAL (60*60)
/** How long do we let a directory connection stall before expiring it? */
#define DIR_CONN_MAX_STALL (5*60)

/** How long do we let OR connections handshake before we decide that
 * they are obsolete? */
#define TLS_HANDSHAKE_TIMEOUT (60)

char	last_dir_status[256];
char	fullpath[MAX_PATH+1];
char	exename[MAX_PATH+1];
char	config_file_name[MAX_PATH+1];
char	pipeName[50];
long	delta_t=0;
long	best_delta_t=0;

/********* END VARIABLES ************/

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* variables (which are global within this file and unavailable outside it).
*
****************************************************************************/

/** Add <b>conn</b> to the array of connections that we can poll on.  The
 * connection's socket must be set; the connection starts out
 * non-reading and non-writing.
 */
int
connection_add(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(SOCKET_OK(conn->s) ||
             conn->linked ||
	     conn->hs_plugin ||
             (conn->type == CONN_TYPE_AP &&
              TO_EDGE_CONN(conn)->is_dns_request));

  tor_assert(conn->conn_array_index == -1); /* can only connection_add once */
  if(plugins_connection_add(conn)==-1) return -1;

  conn->conn_array_index = smartlist_len(connection_array);
  smartlist_add(connection_array, conn);

  if (SOCKET_OK(conn->s) || conn->linked || conn->hs_plugin) {
    conn->read_event = tor_event_new(tor_libevent_get_base(),
         conn->s, EV_READ|EV_PERSIST, conn_read_callback, conn);
    conn->write_event = tor_event_new(tor_libevent_get_base(),
         conn->s, EV_WRITE|EV_PERSIST, conn_write_callback, conn);
  }

  log_debug(LD_NET,get_lang_str(LANG_LOG_MAIN_CONNECTION_ADD),conn_type_to_string(conn->type),conn->s,conn->address,smartlist_len(connection_array));

  return 0;
}

/** Remove the connection from the global list, and remove the
 * corresponding poll entry.  Calling this function will shift the last
 * connection (if any) into the position occupied by conn.
 */
int
connection_remove(connection_t *conn)
{
  int current_index;
  connection_t *tmp;

  tor_assert(conn);

  log_debug(LD_NET,get_lang_str(LANG_LOG_MAIN_CONNECTION_REMOVE),conn->s,conn_type_to_string(conn->type),smartlist_len(connection_array));

  tor_assert(conn->conn_array_index >= 0);
  current_index = conn->conn_array_index;
  connection_unregister_events(conn); /* This is redundant, but cheap. */
  if (current_index == smartlist_len(connection_array)-1) { /* at the end */
    smartlist_del(connection_array, current_index);
    return 0;
  }

  /* replace this one with the one at the end */
  smartlist_del(connection_array, current_index);
  tmp = smartlist_get(connection_array, current_index);
  tmp->conn_array_index = current_index;

  return 0;
}

/** If <b>conn</b> is an edge conn, remove it from the list
 * of conn's on this circuit. If it's not on an edge,
 * flush and send destroys for all circuits on this conn.
 *
 * Remove it from connection_array (if applicable) and
 * from closeable_connection_list.
 *
 * Then free it.
 */
static void
connection_unlink(connection_t *conn)
{
  connection_about_to_close_connection(conn);
  if (conn->conn_array_index >= 0) {
    connection_remove(conn);
  }
  if (conn->linked_conn) {
    conn->linked_conn->linked_conn = NULL;
    if (! conn->linked_conn->marked_for_close &&
        conn->linked_conn->reading_from_linked_conn)
      connection_start_reading(conn->linked_conn);
    conn->linked_conn = NULL;
  }
  smartlist_remove(closeable_connection_lst, conn);
  smartlist_remove(active_linked_connection_lst, conn);
  smartlist_remove(plugin_connection_lst,conn);
  if (conn->type == CONN_TYPE_EXIT) {
    assert_connection_edge_not_dns_pending(TO_EDGE_CONN(conn));
  }
  if (conn->type == CONN_TYPE_OR) {
    if (!tor_digest_is_zero(TO_OR_CONN(conn)->identity_digest))
      connection_or_remove_from_identity_map(TO_OR_CONN(conn));
  }
  connection_free(conn);
}

/** Schedule <b>conn</b> to be closed. **/
void
add_connection_to_closeable_list(connection_t *conn)
{
  tor_assert(!smartlist_isin(closeable_connection_lst, conn));
  tor_assert(conn->marked_for_close);
  assert_connection_ok(conn, get_time(NULL));
  smartlist_add(closeable_connection_lst, conn);
}

/** Return 1 if conn is on the closeable list, else return 0. */
int
connection_is_on_closeable_list(connection_t *conn)
{
  return smartlist_isin(closeable_connection_lst, conn);
}

/** Return true iff conn is in the current poll array. */
int
connection_in_array(connection_t *conn)
{
  return smartlist_isin(connection_array, conn);
}

/** Set <b>*array</b> to an array of all connections, and <b>*n</b>
 * to the length of the array. <b>*array</b> and <b>*n</b> must not
 * be modified.
 */
smartlist_t *
get_connection_array(void)
{
  if (!connection_array)
    connection_array = smartlist_create();
  return connection_array;
}

/** Set the event mask on <b>conn</b> to <b>events</b>.  (The event
 * mask is a bitmask whose bits are EV_READ and EV_WRITE.)
 */
void
connection_watch_events(connection_t *conn, watchable_events_t events)
{
  if (events & READ_EVENT)
    connection_start_reading(conn);
  else
    connection_stop_reading(conn);

  if (events & WRITE_EVENT)
    connection_start_writing(conn);
  else
    connection_stop_writing(conn);
}

/** Return true iff <b>conn</b> is listening for read events. */
int
connection_is_reading(connection_t *conn)
{
  tor_assert(conn);

  return conn->reading_from_linked_conn ||
    (conn->read_event && event_pending(conn->read_event, EV_READ, NULL));
}

/** Tell the main loop to stop notifying <b>conn</b> of any read events. */
void
connection_stop_reading(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->read_event);

  if (conn->linked) {
    conn->reading_from_linked_conn = 0;
    connection_stop_reading_from_linked_conn(conn);
  } else {
    if (event_del(conn->read_event))
      log_warn(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_ERROR),(int)conn->s,tor_socket_strerror(tor_socket_errno(conn->s)));
  }
}

/** Tell the main loop to start notifying <b>conn</b> of any read events. */
void
connection_start_reading(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->read_event);

  if (conn->linked) {
    conn->reading_from_linked_conn = 1;
    if (connection_should_read_from_linked_conn(conn))
      connection_start_reading_from_linked_conn(conn);
  } else {
    if (event_add(conn->read_event, NULL))
      log_warn(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_ERROR_2),(int)conn->s,tor_socket_strerror(tor_socket_errno(conn->s)));
  }
}

/** Return true iff <b>conn</b> is listening for write events. */
int
connection_is_writing(connection_t *conn)
{
  tor_assert(conn);

  return conn->writing_to_linked_conn ||
    (conn->write_event && event_pending(conn->write_event, EV_WRITE, NULL));
}

/** Tell the main loop to stop notifying <b>conn</b> of any write events. */
void
connection_stop_writing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->write_event);

  if (conn->linked) {
    conn->writing_to_linked_conn = 0;
    if (conn->linked_conn)
      connection_stop_reading_from_linked_conn(conn->linked_conn);
  } else {
    if (event_del(conn->write_event))
      log_warn(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_ERROR_3),(int)conn->s,tor_socket_strerror(tor_socket_errno(conn->s)));
  }
}

/** Tell the main loop to start notifying <b>conn</b> of any write events. */
void
connection_start_writing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->write_event);

  if (conn->linked) {
    conn->writing_to_linked_conn = 1;
    if (conn->linked_conn &&
        connection_should_read_from_linked_conn(conn->linked_conn))
      connection_start_reading_from_linked_conn(conn->linked_conn);
  } else {
    if (event_add(conn->write_event, NULL))
      log_warn(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_ERROR_4),(int)conn->s,tor_socket_strerror(tor_socket_errno(conn->s)));
  }
}

/** Return true iff <b>conn</b> is linked conn, and reading from the conn
 * linked to it would be good and feasible.  (Reading is "feasible" if the
 * other conn exists and has data in its outbuf, and is "good" if we have our
 * reading_from_linked_conn flag set and the other conn has its
 * writing_to_linked_conn flag set.)*/
static int
connection_should_read_from_linked_conn(connection_t *conn)
{
  if (conn->linked && conn->reading_from_linked_conn) {
    if (! conn->linked_conn ||
        (conn->linked_conn->writing_to_linked_conn &&
         buf_datalen(conn->linked_conn->outbuf)))
      return 1;
  }
  return 0;
}

/** Helper: Tell the main loop to begin reading bytes into <b>conn</b> from
 * its linked connection, if it is not doing so already.  Called by
 * connection_start_reading and connection_start_writing as appropriate. */
static void
connection_start_reading_from_linked_conn(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->linked == 1);

  if (!conn->active_on_link) {
    conn->active_on_link = 1;
    smartlist_add(active_linked_connection_lst, conn);
    if (!called_loop_once) {
      /* This is the first event on the list; we won't be in LOOP_ONCE mode,
       * so we need to make sure that the event_loop() actually exits at the
       * end of its run through the current connections and
       * lets us activate read events for linked connections. */
      struct timeval tv = { 0, 0 };
      tor_event_base_loopexit(tor_libevent_get_base(), &tv);
    }
  } else {
    tor_assert(smartlist_isin(active_linked_connection_lst, conn));
  }
}

void connection_read_event(connection_t *conn)
{	if (!conn->plugin_read)
	{	conn->plugin_read = 1;
		smartlist_add(plugin_connection_lst,conn);
		struct timeval tv = { 0, 0 };
		event_loopexit(&tv);
	}
}

void connection_write_event(connection_t *conn)
{	if (!conn->plugin_write)
	{	conn->plugin_write = 1;
		smartlist_add(plugin_connection_lst,conn);
		struct timeval tv = { 0, 0 };
		event_loopexit(&tv);
	}
}

/** Tell the main loop to stop reading bytes into <b>conn</b> from its linked
 * connection, if is currently doing so.  Called by connection_stop_reading,
 * connection_stop_writing, and connection_read. */
void
connection_stop_reading_from_linked_conn(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->linked == 1);

  if (conn->active_on_link) {
    conn->active_on_link = 0;
    /* FFFF We could keep an index here so we can smartlist_del
     * cleanly.  On the other hand, this doesn't show up on profiles,
     * so let's leave it alone for now. */
    smartlist_remove(active_linked_connection_lst, conn);
  } else {
    tor_assert(!smartlist_isin(active_linked_connection_lst, conn));
  }
}

/** Close all connections that have been scheduled to get closed. */
static void
close_closeable_connections(void)
{
  int i;
  for (i = 0; i < smartlist_len(closeable_connection_lst); ) {
    connection_t *conn = smartlist_get(closeable_connection_lst, i);
    if (conn->conn_array_index < 0) {
      connection_unlink(conn); /* blow it away right now */
    } else {
      if (!conn_close_if_marked(conn->conn_array_index))
        ++i;
    }
  }
}

/** Libevent callback: this gets invoked when (connection_t*)<b>conn</b> has
 * some data to read. */
static void
conn_read_callback(evutil_socket_t fd, short event, void *_conn)
{
  connection_t *conn = _conn;
  (void)fd;
  (void)event;

  log_debug(LD_NET,get_lang_str(LANG_LOG_MAIN_READ_EVENT),(int)conn->s);

//  assert_connection_ok(conn, get_time(NULL));

  if (connection_handle_read(conn) < 0) {
    if (!conn->marked_for_close) {
#ifndef MS_WINDOWS
      log_warn(LD_BUG,get_lang_str(LANG_LOG_MAIN_READ_ERROR),conn_type_to_string(conn->type), (int)conn->s);
      tor_fragile_assert();
#endif
      if (CONN_IS_EDGE(conn))
        connection_edge_end_errno(TO_EDGE_CONN(conn));
      connection_mark_for_close(conn);
    }
  }
//  assert_connection_ok(conn, get_time(NULL));

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

/** Libevent callback: this gets invoked when (connection_t*)<b>conn</b> has
 * some data to write. */
static void
conn_write_callback(evutil_socket_t fd, short events, void *_conn)
{
  connection_t *conn = _conn;
  (void)fd;
  (void)events;

  LOG_FN_CONN(conn,(LOG_DEBUG,LD_NET,get_lang_str(LANG_LOG_MAIN_WRITE_EVENT),(int)conn->s));

//  assert_connection_ok(conn, get_time(NULL));

  if (connection_handle_write(conn, 0) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,LD_BUG,get_lang_str(LANG_LOG_MAIN_WRITE_ERROR),conn_type_to_string(conn->type), (int)conn->s);
      tor_fragile_assert();
      if (CONN_IS_EDGE(conn)) {
        /* otherwise we cry wolf about duplicate close */
        edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
        if (!edge_conn->end_reason)
          edge_conn->end_reason = END_STREAM_REASON_INTERNAL;
        edge_conn->edge_has_sent_end = 1;
      }
      connection_close_immediate(conn); /* So we don't try to flush. */
      connection_mark_for_close(conn);
    }
  }
//  assert_connection_ok(conn, get_time(NULL));

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

/** If the connection at connection_array[i] is marked for close, then:
 *    - If it has data that it wants to flush, try to flush it.
 *    - If it _still_ has data to flush, and conn->hold_open_until_flushed is
 *      true, then leave the connection open and return.
 *    - Otherwise, remove the connection from connection_array and from
 *      all other lists, close it, and free it.
 * Returns 1 if the connection was closed, 0 otherwise.
 */
static int
conn_close_if_marked(int i)
{
  connection_t *conn;
  int retval;
  time_t now;

  conn = smartlist_get(connection_array, i);
  if (!conn->marked_for_close)
    return 0; /* nothing to see here, move along */
  now = get_time(NULL);
  assert_connection_ok(conn, now);
//  assert_all_pending_dns_resolves_ok();

  log_debug(LD_NET,get_lang_str(LANG_LOG_MAIN_CONN_CLEANUP),(int)conn->s);
  if ((SOCKET_OK(conn->s) || conn->linked_conn)
      && connection_wants_to_flush(conn)) {
    /* s == -1 means it's an incomplete edge connection, or that the socket
     * has already been closed as unflushable. */
    ssize_t sz = connection_bucket_write_limit(conn, now);
    if (!conn->hold_open_until_flushed)
    { char *esc_l = escaped_safe_str_client(conn->address);
      log_info(LD_NET,get_lang_str(LANG_LOG_MAIN_CONN_FLUSH),esc_l,(int)conn->s,conn_type_to_string(conn->type),conn->state,(int)conn->outbuf_flushlen,conn->marked_for_close_file,conn->marked_for_close);
      tor_free(esc_l);
    }
    if (conn->linked_conn) {
      retval = move_buf_to_buf(conn->linked_conn->inbuf, conn->outbuf,
                               &conn->outbuf_flushlen);
      if (retval >= 0) {
        /* The linked conn will notice that it has data when it notices that
         * we're gone. */
        connection_start_reading_from_linked_conn(conn->linked_conn);
      }
      log_debug(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_CONN_FLUSH_2),retval,(int)buf_datalen(conn->outbuf),(int)conn->outbuf_flushlen,connection_wants_to_flush(conn));
    } else if (connection_speaks_cells(conn)) {
      if (conn->state == OR_CONN_STATE_OPEN) {
        retval = flush_buf_tls(TO_OR_CONN(conn)->tls, conn->outbuf, sz,
                               &conn->outbuf_flushlen);
      } else
        retval = -1; /* never flush non-open broken tls connections */
    } else {
      retval = flush_buf(conn->s, conn->outbuf, sz, &conn->outbuf_flushlen);
    }
    if (retval >= 0 && /* Technically, we could survive things like
                          TLS_WANT_WRITE here. But don't bother for now. */
        conn->hold_open_until_flushed && connection_wants_to_flush(conn)) {
      if (retval > 0) {
        LOG_FN_CONN(conn,(LOG_INFO,LD_NET,get_lang_str(LANG_LOG_MAIN_CONN_FLUSH_3),(int)conn->s));
        conn->timestamp_lastwritten = now; /* reset so we can flush more */
      }
      return 0;
    }
    if (connection_wants_to_flush(conn)) {
      int severity;
      if (conn->type == CONN_TYPE_EXIT ||
          (conn->type == CONN_TYPE_OR && server_mode(get_options())) ||
          (conn->type == CONN_TYPE_DIR && conn->purpose == DIR_PURPOSE_SERVER))
        severity = LOG_INFO;
      else
        severity = LOG_NOTICE;
      /* XXXX Maybe allow this to happen a certain amount per hour; it usually
       * is meaningless. */
      char *esc_l = escaped_safe_str_client(conn->address);
      log_fn(severity,LD_NET,get_lang_str(LANG_LOG_MAIN_WE_STALLED_TOO_MUCH),(int)buf_datalen(conn->outbuf),esc_l,(int)conn->s,conn_type_to_string(conn->type),conn->state,conn->marked_for_close_file,conn->marked_for_close);
      tor_free(esc_l);
    }
  }
  if(conn->hs_plugin)	plugin_notify_service(NULL,HIDDENSERVICE_UNREGISTER_CLIENT,conn,conn->port);
  if(plugins_connection_remove(conn)==-1) return 0;
  connection_unlink(conn); /* unlink, remove, free */
  return 1;
}

/** We've just tried every dirserver we know about, and none of
 * them were reachable. Assume the network is down. Change state
 * so next time an application connection arrives we'll delay it
 * and try another directory fetch. Kill off all the circuit_wait
 * streams that are waiting now, since they will all timeout anyway.
 */
void
directory_all_unreachable(time_t now)
{
  connection_t *conn;
  (void)now;

  stats_n_seconds_working=0; /* reset it */

  while ((conn = connection_get_by_type_state(CONN_TYPE_AP,
                                              AP_CONN_STATE_CIRCUIT_WAIT))) {
    edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
    log_notice(LD_NET,get_lang_str(LANG_LOG_MAIN_NETDOWN),safe_str_client(edge_conn->socks_request->address),edge_conn->socks_request->port);
    connection_mark_unattached_ap(edge_conn,
                                  END_STREAM_REASON_NET_UNREACHABLE);
  }
  control_event_general_status(LOG_ERR, "DIR_ALL_UNREACHABLE");
}

/** This function is called whenever we successfully pull down some new
 * network statuses or server descriptors. */
void
directory_info_has_arrived(time_t now, int from_cache)
{
  or_options_t *options = get_options();

  if (!router_have_minimum_dir_info()) {
    int quiet = directory_too_idle_to_fetch_descriptors(options, now);
    log(quiet ? LOG_INFO : LOG_NOTICE, LD_DIR,get_lang_str(LANG_LOG_MAIN_DIR_INFO),get_dir_info_status_string());
    update_router_descriptor_downloads(now);
    return;
  } else {
    if (directory_fetches_from_authorities(options))
      update_router_descriptor_downloads(now);

    /* if we have enough dir info, then update our guard status with
     * whatever we just learned. */
    entry_guards_compute_status(options, now);
    /* Don't even bother trying to get extrainfo until the rest of our
     * directory info is up-to-date */
    if (options->DownloadExtraInfo)
      update_extrainfo_downloads(now);
  }

  if (server_mode(options) && !we_are_hibernating() && !from_cache &&
      (can_complete_circuit || !any_predicted_circuits(now)))
    consider_testing_reachability(1, 1);
}


/** How long do we wait before killing OR connections with no circuits?
 * In Tor versions up to 0.2.1.25 and 0.2.2.12-alpha, we waited 15 minutes
 * before cancelling these connections, which caused fast relays to accrue
 * many many idle connections. Hopefully 3 minutes is low enough that
 * it kills most idle connections, without being so low that we cause
 * clients to bounce on and off.
 */
#define IDLE_OR_CONN_TIMEOUT 180

/** Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_scheduled_events.
 */
static void
run_connection_housekeeping(int i, time_t now)
{
  cell_t cell;
  connection_t *conn = smartlist_get(connection_array, i);
  or_options_t *options = get_options();
  or_connection_t *or_conn;
  int past_keepalive =
    now >= conn->timestamp_lastwritten + options->KeepalivePeriod;

  if (conn->outbuf && !buf_datalen(conn->outbuf) && conn->type == CONN_TYPE_OR)
    TO_OR_CONN(conn)->timestamp_lastempty = now;

  if (conn->marked_for_close) {
    /* nothing to do here */
    return;
  }

  /* Expire any directory connections that haven't been active (sent
   * if a server or received if a client) for 5 min */
  if (conn->type == CONN_TYPE_DIR &&
      ((DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastwritten + DIR_CONN_MAX_STALL < now) ||
       (!DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastread + DIR_CONN_MAX_STALL < now))) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_MAIN_DIR_CONN_EXPIRE),(int)conn->s,conn->purpose);
    /* This check is temporary; it's to let us know whether we should consider
     * parsing partial serverdesc responses. */
    if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        buf_datalen(conn->inbuf)>=1024) {
      log_info(LD_DIR,get_lang_str(LANG_LOG_MAIN_DIR_INFO_FROM_WEDGED_SERVER));
      connection_dir_reached_eof(TO_DIR_CONN(conn));
    } else {
      connection_mark_for_close(conn);
    }
    return;
  }

  if (!connection_speaks_cells(conn))
    return; /* we're all done here, the rest is just for OR conns */

  or_conn = TO_OR_CONN(conn);

  if (or_conn->is_bad_for_new_circs && !or_conn->n_circuits) {
    /* It's bad for new circuits, and has no unmarked circuits on it:
     * mark it now. */
    log_info(LD_OR,get_lang_str(LANG_LOG_MAIN_EXPIRE_OLD_CONN),(int)conn->s,conn->address,conn->port);
    if (conn->state == OR_CONN_STATE_CONNECTING)
      connection_or_connect_failed(TO_OR_CONN(conn),
                                   END_OR_CONN_REASON_TIMEOUT,
                                   "Tor gave up on the connection");
    connection_mark_for_close(conn);
    conn->hold_open_until_flushed = 1;
  } else if (!connection_state_is_open(conn)) {
    if(past_keepalive) {
    /* We never managed to actually get this connection open and happy. */
    log_info(LD_OR,get_lang_str(LANG_LOG_MAIN_EXPIRE_NON_OPEN_CONN),(int)conn->s,conn->address, conn->port);
    connection_mark_for_close(conn);
    }
  } else if (we_are_hibernating() && !or_conn->n_circuits &&
             !buf_datalen(conn->outbuf)) {
    /* We're hibernating, there's no circuits, and nothing to flush.*/
    log_info(LD_OR,get_lang_str(LANG_LOG_MAIN_EXPIRE_NON_USED_CONN),(int)conn->s,conn->address,conn->port);
    connection_mark_for_close(conn);
    conn->hold_open_until_flushed = 1;
  } else if (!or_conn->n_circuits &&
             now >= or_conn->timestamp_last_added_nonpadding +
                                         IDLE_OR_CONN_TIMEOUT) {
    log_info(LD_OR,get_lang_str(LANG_LOG_MAIN_EXPIRE_NON_USED_CONN_2),(int)conn->s,conn->address,conn->port,(int)(now - or_conn->timestamp_last_added_nonpadding));
    connection_mark_for_close(conn);
    conn->hold_open_until_flushed = 1;
  } else if (
      now >= or_conn->timestamp_lastempty + options->KeepalivePeriod*10 &&
      now >= conn->timestamp_lastwritten + options->KeepalivePeriod*10) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,get_lang_str(LANG_LOG_MAIN_EXPIRE_STUCK_CONN),(int)conn->s,conn->address,conn->port,(int)buf_datalen(conn->outbuf),(int)(now-conn->timestamp_lastwritten));
    connection_mark_for_close(conn);
  } else if (past_keepalive && !buf_datalen(conn->outbuf)) {
    /* send a padding cell */
    log_fn(LOG_DEBUG,LD_OR,get_lang_str(LANG_LOG_MAIN_SEND_KEEPALIVE),conn->address,conn->port);
    memset(&cell,0,sizeof(cell_t));
    cell.command = CELL_PADDING;
    connection_or_write_cell_to_buf(&cell, or_conn);
//    }
  }
}

time_t time_to_check_listeners = 0;
time_t time_to_change_identity = 0;
/** Perform regular maintenance tasks.  This function gets run once per
 * second by second_elapsed_callback().
 */
static void
run_scheduled_events(time_t now)
{
  static time_t last_rotated_x509_certificate = 0;
  static time_t time_to_check_v3_certificate = 0;
  static time_t time_to_check_descriptor = 0;
  static time_t time_to_check_ipaddress = 0;
  static time_t time_to_shrink_memory = 0;
  static time_t time_to_try_getting_descriptors = 0;
  static time_t time_to_reset_descriptor_failures = 0;
  static time_t time_to_add_entropy = 0;
  static time_t time_to_write_bridge_status_file = 0;
  static time_t time_to_downrate_stability = 0;
  static time_t time_to_save_stability = 0;
  static time_t time_to_clean_caches = 0;
  static time_t time_to_recheck_bandwidth = 0;
  static time_t time_to_check_for_expired_networkstatus = 0;
  static time_t time_to_write_stats_files = 0;
  static time_t time_to_write_bridge_stats = 0;
  static time_t time_to_launch_reachability_tests = 0;
  static int should_init_bridge_stats = 1;
  static time_t time_to_retry_dns_init = 0;
  or_options_t *options = get_options();
  int is_server = server_mode(options);
  int i;
  int have_dir_info;

  /** 0. See if we've been asked to shut down and our timeout has
   * expired; or if our bandwidth limits are exhausted and we
   * should hibernate; or if it's time to wake up from hibernation.
   */
	consider_hibernation(now);
	if(options->IdentityAutoChange && time_to_change_identity < now)
	{
		identity_auto_change(now);
		time_to_change_identity = now + options->IdentityAutoChange;
	}
	else if(signewnym_pending)	signewnym_scheduled_tasks();

  /* 0c. If we've deferred log messages for the controller, handle them now */
//  flush_pending_log_callbacks();

  /** 1a. Every MIN_ONION_KEY_LIFETIME seconds, rotate the onion keys,
   *  shut down and restart all cpuworkers, and update the directory if
   *  necessary.
   */
  if (is_server &&
      get_onion_key_set_at()+MIN_ONION_KEY_LIFETIME < now) {
    log_info(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_ROTATING_ONION_KEY));
    rotate_onion_key();
    cpuworkers_rotate();
    if (router_rebuild_descriptor(1)<0) {
      log_info(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_ROUTER_DESC_REBUILD_ERROR));
    }
    if (advertised_server_mode())
      router_upload_dir_desc_to_dirservers(0);
  }

  if (time_to_try_getting_descriptors < now) {
    update_router_descriptor_downloads(get_time(NULL));
    update_extrainfo_downloads(now);
    if (router_have_minimum_dir_info())
      time_to_try_getting_descriptors = now + LAZY_DESCRIPTOR_RETRY_INTERVAL;
    else
      time_to_try_getting_descriptors = now + GREEDY_DESCRIPTOR_RETRY_INTERVAL;
  }

  if (time_to_reset_descriptor_failures < now) {
    router_reset_descriptor_download_failures();
    time_to_reset_descriptor_failures =
      now + DESCRIPTOR_FAILURE_RESET_INTERVAL;
  }

  if (options->UseBridges)
    fetch_bridge_descriptors(options, now);

  /** 1b. Every MAX_SSL_KEY_LIFETIME seconds, we change our TLS context. */
  if (!last_rotated_x509_certificate)
    last_rotated_x509_certificate = now;
  if (last_rotated_x509_certificate+MAX_SSL_KEY_LIFETIME_INTERNAL < now) {
    log_info(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_ROTATING_TLS_CONTEXT));
    if (tor_tls_context_init(public_server_mode(options),
                             get_tlsclient_identity_key(),
                             is_server ? get_server_identity_key() : NULL,
                             MAX_SSL_KEY_LIFETIME_ADVERTISED) < 0) {
      log_warn(LD_BUG,get_lang_str(LANG_LOG_MAIN_TLS_REINIT_ERROR));
      /* XXX is it a bug here, that we just keep going? -RD */
    }
    last_rotated_x509_certificate = now;
    /* We also make sure to rotate the TLS connections themselves if they've
     * been up for too long -- but that's done via is_bad_for_new_circs in
     * connection_run_housekeeping() above. */
  }

  if (time_to_add_entropy < now) {
    if (time_to_add_entropy) {
      /* We already seeded once, so don't die on failure. */
      crypto_seed_rng(0);
    }
/** How often do we add more entropy to OpenSSL's RNG pool? */
#define ENTROPY_INTERVAL (60*60)
    time_to_add_entropy = now + ENTROPY_INTERVAL;
  }

  /** 1c. If we have to change the accounting interval or record
   * bandwidth used in this accounting interval, do so. */
  if (accounting_is_enabled(options))
    accounting_run_housekeeping(now);

  if (time_to_launch_reachability_tests < now &&
      (authdir_mode_tests_reachability(options)) &&
       !we_are_hibernating()) {
    time_to_launch_reachability_tests = now + REACHABILITY_TEST_INTERVAL;
    /* try to determine reachability of the other Tor relays */
    dirserv_test_reachability(now);
  }

  /** 1d. Periodically, we discount older stability information so that new
   * stability info counts more, and save the stability information to disk as
   * appropriate. */
  if (time_to_downrate_stability < now)
    time_to_downrate_stability = rep_hist_downrate_old_runs(now);
  if (authdir_mode_tests_reachability(options)) {
    if (time_to_save_stability < now) {
      if (time_to_save_stability && rep_hist_record_mtbf_data(now,1)<0) {
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_MTBF_WRITE_ERROR));
      }
#define SAVE_STABILITY_INTERVAL (30*60)
      time_to_save_stability = now + SAVE_STABILITY_INTERVAL;
    }
  }

  /* 1e. Periodicaly, if we're a v3 authority, we check whether our cert is
   * close to expiring and warn the admin if it is. */
  if (time_to_check_v3_certificate < now) {
    v3_authority_check_key_expiry();
#define CHECK_V3_CERTIFICATE_INTERVAL (5*60)
    time_to_check_v3_certificate = now + CHECK_V3_CERTIFICATE_INTERVAL;
  }

  /* 1f. Check whether our networkstatus has expired.
   */
  if ((!(options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE))&&(time_to_check_for_expired_networkstatus < now)) {
    networkstatus_t *ns = networkstatus_get_latest_consensus();
    /*XXXX RD: This value needs to be the same as REASONABLY_LIVE_TIME in
     * networkstatus_get_reasonably_live_consensus(), but that value is way
     * way too high.  Arma: is the bridge issue there resolved yet? -NM */
#define NS_EXPIRY_SLOP (24*60*60)
    if (ns && ns->valid_until < now+NS_EXPIRY_SLOP &&
        router_have_minimum_dir_info()) {
      router_dir_info_changed();
    }
#define CHECK_EXPIRED_NS_INTERVAL (2*60)
    time_to_check_for_expired_networkstatus = now + CHECK_EXPIRED_NS_INTERVAL;
  }

  /* 1g. Check whether we should write statistics to disk.
   */
  if (time_to_write_stats_files < now) {
#define CHECK_WRITE_STATS_INTERVAL (60*60)
    time_t next_time_to_write_stats_files = (time_to_write_stats_files > 0 ?
           time_to_write_stats_files : now) + CHECK_WRITE_STATS_INTERVAL;
    if (options->CellStatistics) {
      time_t next_write =
          rep_hist_buffer_stats_write(time_to_write_stats_files);
      if (next_write && next_write < next_time_to_write_stats_files)
        next_time_to_write_stats_files = next_write;
    }
    if (options->DirReqStatistics) {
      time_t next_write = geoip_dirreq_stats_write(time_to_write_stats_files);
      if (next_write && next_write < next_time_to_write_stats_files)
        next_time_to_write_stats_files = next_write;
    }
    if (options->EntryStatistics) {
      time_t next_write = geoip_entry_stats_write(time_to_write_stats_files);
      if (next_write && next_write < next_time_to_write_stats_files)
        next_time_to_write_stats_files = next_write;
    }
    if (options->ExitPortStatistics) {
      time_t next_write = rep_hist_exit_stats_write(time_to_write_stats_files);
      if (next_write && next_write < next_time_to_write_stats_files)
        next_time_to_write_stats_files = next_write;
    }
    time_to_write_stats_files = next_time_to_write_stats_files;
  }

  /* 1h. Check whether we should write bridge statistics to disk.
   */
  if (should_record_bridge_info(options)) {
    if (time_to_write_bridge_stats < now) {
      if (should_init_bridge_stats) {
        /* (Re-)initialize bridge statistics. */
        geoip_bridge_stats_init(now);
        time_to_write_bridge_stats = now + WRITE_STATS_INTERVAL;
        should_init_bridge_stats = 0;
      } else {
        /* Possibly write bridge statistics to disk and ask when to write
         * them next time. */
        time_to_write_bridge_stats = geoip_bridge_stats_write(
                                           time_to_write_bridge_stats);
      }
    }
  } else if (!should_init_bridge_stats) {
    /* Bridge mode was turned off. Ensure that stats are re-initialized
     * next time bridge mode is turned on. */
    should_init_bridge_stats = 1;
  }

  /* Remove old information from rephist and the rend cache. */
  if (time_to_clean_caches < now) {
    rep_history_clean(now - options->RephistTrackTime);
    rend_cache_clean();
    rend_cache_clean_v2_descs_as_dir();
    if (authdir_mode_v3(options))
      microdesc_cache_rebuild(NULL, 0);
#define CLEAN_CACHES_INTERVAL (30*60)
    time_to_clean_caches = now + CLEAN_CACHES_INTERVAL;
  }

#define RETRY_DNS_INTERVAL (10*60)
  /* If we're a server and initializing dns failed, retry periodically. */
  if (time_to_retry_dns_init < now) {
    time_to_retry_dns_init = now + RETRY_DNS_INTERVAL;
    if (server_mode(options) && has_dns_init_failed())
      dns_init();
  }
  dlgServerUpdate();

  /** 2. Periodically, we consider force-uploading our descriptor
   * (if we've passed our internal checks). */

/** How often do we check whether part of our router info has changed in a way
 * that would require an upload? */
#define CHECK_DESCRIPTOR_INTERVAL (60)
/** How often do we (as a router) check whether our IP address has changed? */
#define CHECK_IPADDRESS_INTERVAL (15*60)

  /* 2b. Once per minute, regenerate and upload the descriptor if the old
   * one is inaccurate. */
  if (time_to_check_descriptor < now) {
    static int dirport_reachability_count = 0;
    time_to_check_descriptor = now + CHECK_DESCRIPTOR_INTERVAL;
    check_descriptor_bandwidth_changed(now);
    if (time_to_check_ipaddress < now) {
      time_to_check_ipaddress = now + CHECK_IPADDRESS_INTERVAL;
      check_descriptor_ipaddress_changed(now);
    }
/** If our router descriptor ever goes this long without being regenerated
 * because something changed, we force an immediate regenerate-and-upload. */
#define FORCE_REGENERATE_DESCRIPTOR_INTERVAL (18*60*60)
    mark_my_descriptor_dirty_if_older_than(
                                  now - FORCE_REGENERATE_DESCRIPTOR_INTERVAL);
    consider_publishable_server(0);
    /* also, check religiously for reachability, if it's within the first
     * 20 minutes of our uptime. */
    if (server_mode(options) &&
        (can_complete_circuit || !any_predicted_circuits(now)) &&
        !we_are_hibernating()) {
      if (stats_n_seconds_working < TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT) {
        consider_testing_reachability(1, dirport_reachability_count==0);
        if (++dirport_reachability_count > 5)
          dirport_reachability_count = 0;
      } else if (time_to_recheck_bandwidth < now) {
        /* If we haven't checked for 12 hours and our bandwidth estimate is
         * low, do another bandwidth test. This is especially important for
         * bridges, since they might go long periods without much use. */
        routerinfo_t *me = router_get_my_routerinfo();
        if (time_to_recheck_bandwidth && me &&
            me->bandwidthcapacity < me->bandwidthrate &&
            me->bandwidthcapacity < 51200) {
          reset_bandwidth_test();
        }
#define BANDWIDTH_RECHECK_INTERVAL (12*60*60)
        time_to_recheck_bandwidth = now + BANDWIDTH_RECHECK_INTERVAL;
      }
    }

    /* If any networkstatus documents are no longer recent, we need to
     * update all the descriptors' running status. */
    /* purge obsolete entries */
    networkstatus_v2_list_clean(now);
    /* Remove dead routers. */
    routerlist_remove_old_routers();

    /* Also, once per minute, check whether we want to download any
     * networkstatus documents.
     */
    update_networkstatus_downloads(now);
  }

  /** 2c. Let directory voting happen. */
  if (authdir_mode_v3(options))
    dirvote_act(options, now);

  /** 3a. Every second, we examine pending circuits and prune the
   *    ones which have been pending for more than a few seconds.
   *    We do this before step 4, so it can try building more if
   *    it's not comfortable with the number of available circuits.
   */
  circuit_expire_building();

  /** 3b. Also look at pending streams and prune the ones that 'began'
   *     a long time ago but haven't gotten a 'connected' yet.
   *     Do this before step 4, so we can put them back into pending
   *     state to be picked up by the new circuit.
   */
  connection_ap_expire_beginning();

  /** 3c. And expire connections that we've held open for too long.
   */
  connection_expire_held_open();

  /** 3d. And every 60 seconds, we relaunch listeners if any died. */
  if (!we_are_hibernating() && time_to_check_listeners < now) {
    retry_all_listeners(NULL, NULL);
    time_to_check_listeners = now+60;
  }

  /** 4. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than MaxCircuitDirtiness seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  have_dir_info = router_have_minimum_dir_info();
  if (have_dir_info && !we_are_hibernating())
    circuit_build_needed_circs(now);

  /* every 10 seconds, but not at the same second as other such events */
//  if (now % 10 == 5)
  //  circuit_expire_old_circuits_serverside(now);

  /** 5. We do housekeeping for each connection... */
  connection_or_set_bad_connections(NULL, 0);
  for (i=0;i<smartlist_len(connection_array);i++) {
    run_connection_housekeeping(i, now);
  }
  if (time_to_shrink_memory < now) {
    SMARTLIST_FOREACH(connection_array, connection_t *, conn, {
        if (conn->outbuf)
          buf_shrink(conn->outbuf);
        if (conn->inbuf)
          buf_shrink(conn->inbuf);
      });
    clean_cell_pool();
    buf_shrink_freelists(0);
/** How often do we check buffers and pools for empty space that can be
 * deallocated? */
#define MEM_SHRINK_INTERVAL (60)
    time_to_shrink_memory = now + MEM_SHRINK_INTERVAL;
  }

  /** 6. And remove any marked circuits... */
  circuit_close_all_marked();

  /** 7. And upload service descriptors if necessary. */
  if (can_complete_circuit && !we_are_hibernating()) {
    rend_consider_services_upload(now);
    rend_consider_descriptor_republication();
  }

  /** 8. and blow away any connections that need to die. have to do this now,
   * because if we marked a conn for close and left its socket -1, then
   * we'll pass it to poll/select and bad things will happen.
   */
  close_closeable_connections();

  /** 9. and if we're a server, check whether our DNS is telling stories to
   * us. */
  if (public_server_mode(options) && time_to_check_for_correct_dns < now) {
    if (!time_to_check_for_correct_dns) {
      time_to_check_for_correct_dns = now + 60 + crypto_rand_int(120);
    } else {
      dns_launch_correctness_checks();
      time_to_check_for_correct_dns = now + 12*3600 +
        crypto_rand_int(12*3600);
    }
  }

  /** 10b. write bridge networkstatus file to disk */
  if (options->BridgeAuthoritativeDir &&
      time_to_write_bridge_status_file < now) {
    networkstatus_dump_bridge_status_to_file(now);
#define BRIDGE_STATUSFILE_INTERVAL (30*60)
    time_to_write_bridge_status_file = now+BRIDGE_STATUSFILE_INTERVAL;
  }
}

/** Timer: used to invoke second_elapsed_callback() once per second. */
static periodic_timer_t *second_timer = NULL;
/** Number of libevent errors in the last second: we die if we get too many. */
static int n_libevent_errors = 0;

/** Libevent callback: invoked once every second. */
static void
second_elapsed_callback(periodic_timer_t *timer, void *arg)
{
  /* XXXX This could be sensibly refactored into multiple callbacks, and we
   * could use libevent's timers for this rather than checking the current
   * time against a bunch of timeouts every second. */
  static time_t current_second = 0;
  time_t now;
  size_t bytes_written;
  size_t bytes_read;
  int seconds_elapsed;
  or_options_t *options = get_options();
  (void)timer;
  (void)arg;

  n_libevent_errors = 0;

  /* log_fn(LOG_NOTICE, "Tick."); */
  now = get_time(NULL);
  update_approx_time(now);

  /* the second has rolled over. check more stuff. */
  bytes_written = stats_prev_global_write_bucket - global_write_bucket;
  bytes_read = stats_prev_global_read_bucket - global_read_bucket;
  seconds_elapsed = current_second ? (int)(now - current_second) : 0;
  dlgUpdateRWStats(seconds_elapsed,bytes_read,bytes_written);
  stats_n_bytes_read += bytes_read;
  stats_n_bytes_written += bytes_written;
  if (accounting_is_enabled(options) && seconds_elapsed >= 0)
    accounting_add_bytes(bytes_read, bytes_written, seconds_elapsed);
  control_event_bandwidth_used((uint32_t)bytes_read,(uint32_t)bytes_written);
  control_event_stream_bandwidth_used();

  if (seconds_elapsed > 0)
    connection_bucket_refill(seconds_elapsed, now);
  stats_prev_global_read_bucket = global_read_bucket;
  stats_prev_global_write_bucket = global_write_bucket;

  if (server_mode(options) &&
      !we_are_hibernating() &&
      seconds_elapsed > 0 &&
      can_complete_circuit &&
      stats_n_seconds_working / TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT !=
      (stats_n_seconds_working+seconds_elapsed) /
        TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT) {
    /* every 20 minutes, check and complain if necessary */
    routerinfo_t *me = router_get_my_routerinfo();
    if (me && !check_whether_orport_reachable())
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_OR_PORT_UNREACHABLE),me->address,me->or_port);
    if (me && !check_whether_dirport_reachable())
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_DIR_PORT_UNREACHABLE),me->address,me->dir_port);
  }

/** If more than this many seconds have elapsed, probably the clock
 * jumped: doesn't count. */
#define NUM_JUMPED_SECONDS_BEFORE_WARN 100
  if (seconds_elapsed < -NUM_JUMPED_SECONDS_BEFORE_WARN ||
      seconds_elapsed >= NUM_JUMPED_SECONDS_BEFORE_WARN) {
    circuit_note_clock_jumped(seconds_elapsed);
    /* XXX if the time jumps *back* many months, do our events in
     * run_scheduled_events() recover? I don't think they do. -RD */
  } else if (seconds_elapsed > 0)
    stats_n_seconds_working += seconds_elapsed;

  run_scheduled_events(now);

  current_second = now; /* remember which second it is, for next time */
}

#ifndef MS_WINDOWS
/** Called when a possibly ignorable libevent error occurs; ensures that we
 * don't get into an infinite loop by ignoring too many errors from
 * libevent. */
static int
got_libevent_error(void)
{
  if (++n_libevent_errors > 8) {
    log_err(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_TOO_MANY_ERRORS));
    return -1;
  }
  return 0;
}
#endif

#define UPTIME_CUTOFF_FOR_NEW_BANDWIDTH_TEST (6*60*60)

/** Called when our IP address seems to have changed. <b>at_interface</b>
 * should be true if we detected a change in our interface, and false if we
 * detected a change in our published address. */
void
ip_address_changed(int at_interface)
{
  int server = server_mode(get_options());

  if (at_interface) {
    if (! server) {
      /* Okay, change our keys. */
      if (init_keys()<0)
        log_warn(LD_GENERAL, get_lang_str(LANG_LOG_MAIN_ERROR_ROTATING_KEYS));
    }
  } else {
    if (server) {
      if (stats_n_seconds_working > UPTIME_CUTOFF_FOR_NEW_BANDWIDTH_TEST)
        reset_bandwidth_test();
      stats_n_seconds_working = 0;
      router_reset_reachability();
      mark_my_descriptor_dirty("IP address changed");
    }
  }

  dns_servers_relaunch_checks();
}

/** Forget what we've learned about the correctness of our DNS servers, and
 * start learning again. */
void
dns_servers_relaunch_checks(void)
{
  if (server_mode(get_options())) {
    dns_reset_correctness_checks();
    time_to_check_for_correct_dns = 0;
  }
}

/** Called when we get a SIGHUP: reload configuration files and keys,
 * retry all connections, and so on. */
static int
do_hup(void)
{
  or_options_t *options = get_options();

#ifdef USE_DMALLOC
  dmalloc_log_stats();
  dmalloc_log_changed(0, 1, 0, 0);
#endif

  log_notice(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_SIGHUP));
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(get_time(NULL), get_or_state());

  router_reset_warnings();
  routerlist_reset_warnings();
  /* first, reload config variables, in case they've changed */
  if (options->ReloadTorrcOnSIGHUP) {
    /* no need to provide argc/v, they've been cached in init_from_config */
    if (options_init_from_torrc(0, NULL) < 0) {
      log_err(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_CONFIG_READ_ERROR));
      return -1;
    }
    options = get_options(); /* they have changed now */
  } else {
    log_notice(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_CONFIG_NOT_RELOADED));
  }
  if (authdir_mode_handles_descs(options, -1)) {
    /* reload the approved-routers file */
    if (dirserv_load_fingerprint_file() < 0) {
      /* warnings are logged from dirserv_load_fingerprint_file() directly */
      log_info(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_FINGERPRINTS_RELOAD_ERROR));
    }
  }

  /* Rotate away from the old dirty circuits. This has to be done
   * after we've read the new options, but before we start using
   * circuits for directory fetches. */
  circuit_expire_all_dirty_circs();

  /* retry appropriate downloads */
  router_reset_status_download_failures();
  router_reset_descriptor_download_failures();
  update_networkstatus_downloads(get_time(NULL));

  /* We'll retry routerstatus downloads in about 10 seconds; no need to
   * force a retry there. */

  if (server_mode(options)) {
    /* Restart cpuworker and dnsworker processes, so they get up-to-date
     * configuration options. */
    cpuworkers_rotate();
    dns_reset();
  }
  return 0;
}


#ifndef MS_WINDOWS /* Only called when we're willing to use signals */
/** Libevent callback: invoked when we get a signal.
 */
static void
signal_callback(int fd, short events, void *arg)
{
  uintptr_t sig = (uintptr_t)arg;
  (void)fd;
  (void)events;
  process_signal(sig);
}
#endif

/** Do the work of acting on a signal received in <b>sig</b> */
void
process_signal(uintptr_t sig)
{
  switch (sig)
    {
    case SIGTERM:
      log_notice(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_SIGTERM));
      tor_cleanup();
      break;
    case SIGINT:
      if (!server_mode(get_options())) { /* do it now */
        log_notice(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_SIGINT));
        tor_cleanup();
      }
      hibernate_begin_shutdown();
      break;
#ifdef SIGPIPE
    case SIGPIPE:
      log_debug(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_SIGPIPE));
      break;
#endif
    case SIGUSR1:
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(LOG_INFO);
      break;
    case SIGUSR2:
      switch_logs_debug();
      log_debug(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_SIGUSR2));
      break;
    case SIGHUP:
      if (do_hup() < 0) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_CONFIG_ERROR));
        tor_cleanup();
      }
      break;
#ifdef SIGCHLD
    case SIGCHLD:
      while (waitpid(-1,NULL,WNOHANG) > 0) ; /* keep reaping until no more
                                                zombies */
      break;
#endif
    case SIGNEWNYM:
      signewnym_impl(get_time(NULL),0);
      break;
    case SIGCLEARDNSCACHE:
      addressmap_clear_transient();
      break;
  }
}

extern uint64_t rephist_total_alloc;
extern uint32_t rephist_total_num;

/**
 * Write current memory usage information to the log.
 */
static void
dumpmemusage(int severity)
{
  connection_dump_buffer_mem_stats(severity);
  log(severity, LD_GENERAL,get_lang_str(LANG_LOG_MAIN_REPHIST_STATS),U64_PRINTF_ARG(rephist_total_alloc),rephist_total_num);
  dump_routerlist_mem_usage(severity);
  dump_cell_pool_usage(severity);
  dump_dns_mem_usage(severity);
  buf_dump_freelist_sizes(severity);
  tor_log_mallinfo(severity);
}

/** Write all statistics to the log, with log level 'severity'.  Called
 * in response to a SIGUSR1. */
void dumpstats(int severity)
{
  time_t now = get_time(NULL);
  time_t elapsed;
  size_t rbuf_cap, wbuf_cap, rbuf_len, wbuf_len;

  log(severity,LD_GENERAL,get_lang_str(LANG_LOG_MAIN_DUMPING_STATS));

  SMARTLIST_FOREACH(connection_array, connection_t *, conn,
  {
    int i = conn_sl_idx;
    log(severity, LD_GENERAL,get_lang_str(LANG_LOG_MAIN_STATS_CONN),i,(int)conn->s,conn->type,conn_type_to_string(conn->type),conn->state,conn_state_to_string(conn->type,conn->state),(int)(now - conn->timestamp_created));
    if (!connection_is_listener(conn)) {
      log(severity,LD_GENERAL,get_lang_str(LANG_LOG_MAIN_STATS_CONN_2),i,safe_str_client(conn->address),conn->port);
      log(severity,LD_GENERAL,get_lang_str(LANG_LOG_MAIN_STATS_CONN_3),i,(int)buf_datalen(conn->inbuf),(int)buf_allocation(conn->inbuf),(int)(now - conn->timestamp_lastread));
      log(severity,LD_GENERAL,get_lang_str(LANG_LOG_MAIN_STATS_CONN_4),i,(int)buf_datalen(conn->outbuf),(int)buf_allocation(conn->outbuf),(int)(now - conn->timestamp_lastwritten));
      if (conn->type == CONN_TYPE_OR) {
        or_connection_t *or_conn = TO_OR_CONN(conn);
        if (or_conn->tls) {
          tor_tls_get_buffer_sizes(or_conn->tls, &rbuf_cap, &rbuf_len,
                                   &wbuf_cap, &wbuf_len);
          log(severity, LD_GENERAL,get_lang_str(LANG_LOG_MAIN_STATS_CONN_5),i,rbuf_len,rbuf_cap,wbuf_len,wbuf_cap);
        }
      }
    }
    circuit_dump_by_conn(conn, severity); /* dump info about all the circuits
                                           * using this conn */
  });
  log(severity,LD_NET,get_lang_str(LANG_LOG_MAIN_CELL_STATS),U64_PRINTF_ARG(stats_n_padding_cells_processed),U64_PRINTF_ARG(stats_n_create_cells_processed),U64_PRINTF_ARG(stats_n_created_cells_processed),U64_PRINTF_ARG(stats_n_relay_cells_processed),U64_PRINTF_ARG(stats_n_relay_cells_relayed),U64_PRINTF_ARG(stats_n_relay_cells_delivered),U64_PRINTF_ARG(stats_n_destroy_cells_processed));
  if (stats_n_data_cells_packaged)
    log(severity,LD_NET,get_lang_str(LANG_LOG_MAIN_CELL_STATS_2),100*(U64_TO_DBL(stats_n_data_bytes_packaged)/U64_TO_DBL(stats_n_data_cells_packaged*RELAY_PAYLOAD_SIZE)) );
  if (stats_n_data_cells_received)
    log(severity,LD_NET,get_lang_str(LANG_LOG_MAIN_CELL_STATS_3),100*(U64_TO_DBL(stats_n_data_bytes_received)/U64_TO_DBL(stats_n_data_cells_received*RELAY_PAYLOAD_SIZE)) );

  if (now - time_of_process_start >= 0)
    elapsed = now - time_of_process_start;
  else
    elapsed = 0;

  if (elapsed) {
    log(severity, LD_NET,get_lang_str(LANG_LOG_MAIN_BW_STATS),U64_PRINTF_ARG(stats_n_bytes_read),(int)elapsed,(int) (stats_n_bytes_read/elapsed));
    log(severity, LD_NET,get_lang_str(LANG_LOG_MAIN_BW_STATS_2),U64_PRINTF_ARG(stats_n_bytes_written),(int)elapsed,(int) (stats_n_bytes_written/elapsed));
  }

  log(severity,LD_NET,get_lang_str(LANG_LOG_MAIN_MEM_STATS));
  dumpmemusage(severity);

  rep_hist_dump_stats(now,severity);
  rend_service_dump_stats(severity);
  dump_pk_ops(severity);
  dump_distinct_digest_count(severity);
}

connection_t *get_connection_by_addr(uint32_t ip,int port,connection_t *after)
{	SMARTLIST_FOREACH(connection_array, connection_t *, conn,
	{	if(after && conn==after) after=NULL;
		else if(after==NULL)
		{	if((tor_addr_to_ipv4n(&conn->addr)==ip)&&(conn->port==port))	return conn;
		}
	});
	return NULL;
}


/** Set up the signal handlers for either parent or child. */
void
handle_signals(int is_parent)
{
  (void)is_parent;
}


/** Free all memory that we might have allocated somewhere.
 * If <b>postfork</b>, we are a worker process and we want to free
 * only the parts of memory that we won't touch. If !<b>postfork</b>,
 * Tor is shutting down and we should free everything.
 *
 * Helps us find the real leaks with dmalloc and the like. Also valgrind
 * should then report 0 reachable in its leak report (in an ideal world --
 * in practice libevent, ssl, libc etc never quite free everything). */
void
tor_free_all(int postfork)
{
  if (!postfork) {
    evdns_shutdown(1);
  }
  geoip_free_all();
  dirvote_free_all();
  routerlist_free_all();
  networkstatus_free_all();
  addressmap_free_all();
  dirserv_free_all();
  rend_service_free_all();
  rend_cache_free_all();
  rend_service_authorization_free_all();
  rep_hist_free_all();
  dns_free_all();
  clear_pending_onions();
  circuit_free_all();
  entry_guards_free_all();
  connection_free_all();
  buf_shrink_freelists(1);
  memarea_clear_freelist();
  microdesc_free_all();
  if (!postfork) {
    config_free_all();
    router_free_all();
    policies_free_all();
  }
  free_cell_pool();
  if (!postfork) {
    tor_tls_free_all();
  }
  /* stuff in main.c */
  if (connection_array)
    smartlist_free(connection_array);
  if (closeable_connection_lst)
    smartlist_free(closeable_connection_lst);
  if (active_linked_connection_lst)
    smartlist_free(active_linked_connection_lst);
  if(plugin_connection_lst)
    smartlist_free(plugin_connection_lst);
  periodic_timer_free(second_timer);
  /* Stuff in util.c and address.c*/
  if (!postfork) {
    esc_router_info(NULL);
    logs_free_all(); /* free log strings. do this last so logs keep working. */
  }
}

/** Do whatever cleanup is necessary before shutting Tor down. */
void
tor_cleanup(void)
{
  or_options_t *options = get_options();
  /* Remove our pid file. We don't care if there was an error when we
   * unlink, nothing we could do about it anyways. */
  if (options->command == CMD_RUN_TOR) {
    time_t now = get_time(NULL);
    if (options->PidFile)
      unlink(options->PidFile);
    if (options->ControlPortWriteToFile)
      unlink(options->ControlPortWriteToFile);
    if (accounting_is_enabled(options))
      accounting_record_bandwidth_usage(get_time(NULL), get_or_state());
    if (authdir_mode_tests_reachability(options))
      rep_hist_record_mtbf_data(now, 0);
  }
#ifdef USE_DMALLOC
  dmalloc_log_stats();
#endif
  tor_free_all(0); /* We could move tor_free_all back into the ifdef below
                      later, if it makes shutdown unacceptably slow.  But for
                      now, leave it here: it's helped us catch bugs in the
                      past. */
  crypto_global_cleanup();
#ifdef USE_DMALLOC
  dmalloc_log_unfreed();
  dmalloc_shutdown();
#endif
}

/** Read/create keys as needed, and echo our fingerprint to stdout. */
/* static */ int
do_list_fingerprint(void)
{
  char buf[FINGERPRINT_LEN+1];
  crypto_pk_env_t *k;
  const char *nickname = get_options()->Nickname;
  if (!server_mode(get_options())) {
    log_err(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_CLIENT_KEY));
    return -1;
  }
  tor_assert(nickname);
  if (init_keys() < 0) {
    log_err(LD_BUG,get_lang_str(LANG_LOG_MAIN_INIT_KEYS_ERROR));
    return -1;
  }
  if (!(k = get_server_identity_key())) {
    log_err(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_MISSING_KEY));
    return -1;
  }
  if (crypto_pk_get_fingerprint(k, buf, 1)<0) {
    log_err(LD_BUG,get_lang_str(LANG_LOG_DIRSERV_FINGERPRINT_CREATE_FAILED));
    return -1;
  }
  printf("%s %s\n", nickname, buf);
  return 0;
}

/** Entry point for password hashing: take the desired password from
 * the command line, and print its salted hash to stdout. **/
/* static */ void
do_hash_password(void)
{

  char output[256];
  char key[S2K_SPECIFIER_LEN+DIGEST_LEN];

  crypto_rand(key, S2K_SPECIFIER_LEN-1);
  key[S2K_SPECIFIER_LEN-1] = (uint8_t)96; /* Hash 64 K of data. */
  secret_to_key(key+S2K_SPECIFIER_LEN, DIGEST_LEN,
                get_options()->command_arg, strlen(get_options()->command_arg),
                key);
  base16_encode(output, sizeof(output), key, sizeof(key));
  printf("16:%s\n",output);
}

int tor_init(int argc, char *argv[])
{
  char buf[256];
  int i, quiet = 0;
  time_of_process_start = get_time(NULL);
  if (!connection_array)
    connection_array = smartlist_create();
  if (!closeable_connection_lst)
    closeable_connection_lst = smartlist_create();
  if (!active_linked_connection_lst)
    active_linked_connection_lst = smartlist_create();
  if (!plugin_connection_lst)
    plugin_connection_lst = smartlist_create();
  /* Have the log set up with our application name. */
  tor_snprintf(buf, sizeof(buf), "Tor %s", get_version());
  log_set_application_name(buf);
  /* Initialize the history structures. */
  rep_hist_init();
  /* Initialize the service cache. */
  rend_cache_init();
  addressmap_init(); /* Init the client dns cache. Do it always, since it's
                      * cheap. */

  /* We search for the "quiet" option first, since it decides whether we
   * will log anything at all to the command line. */
  for (i=1;i<argc;++i) {
    if (!strcmp(argv[i], "--hush"))
      quiet = 1;
    if (!strcmp(argv[i], "--quiet"))
      quiet = 2;
  }
 /* give it somewhere to log to initially */
  switch (quiet) {
    case 2:
      /* no initial logging */
      break;
    case 1:
   //   add_temp_log(LOG_WARN);
      break;
    default:
   //   add_temp_log(LOG_NOTICE);
        break;
  }

  if (network_init()<0) {
    log_err(LD_BUG,get_lang_str(LANG_LOG_MAIN_NET_INIT_ERROR));
    return -1;
  }
//  atexit(exit_function);

  if (options_init_from_torrc(argc,argv) < 0) {
    log_err(LD_CONFIG,get_lang_str(LANG_LOG_MAIN_CONFIG_READ_ERROR));
    return -1;
  }

  if (crypto_global_init())
  {
    log_err(LD_BUG,get_lang_str(LANG_LOG_MAIN_OPENSSL_INIT_ERROR));
    return -1;
  }

  return 0;
} 

HINSTANCE hInstance;
BOOL showlog=0, autorefresh=0, started=0;
int __stdcall tor_thread(LPARAM) __attribute__((noreturn));
DWORD thread_id;
HANDLE hThread;
HANDLE hDialog=NULL;

const char *versions[] = {
	"-",
	"Darwin i386",
	"Darwin x86_64",
	"Darwin Power Macintosh",
	"DragonFly i386",
	"FreeBSD amd64",
	"FreeBSD i386",
	"FreeBSD sparc64",
	"Linux i586",
	"Linux i686",
	"Linux x86_64",
	"Linux armv5tel",
	"Linux mips",
	"Linux ppc",
	"Linux sparc",
	"Linux sparc64",
	"NetBSD i386",
	"OpenBSD amd64",
	"OpenBSD i386",
	"SunOS i86pc",
	"Windows 2000 Service Pack 4 [workstation]",
	"Windows 2000 Service Pack 4 [server] {enterprise} {terminal services, single user} {terminal services}",
	"Windows XP Service Pack 1 [workstation] {terminal services, single user}",
	"Windows XP Service Pack 2 [workstation] {terminal services, single user}",
	"Windows XP Service Pack 3 [workstation] {terminal services, single user}",
	"Windows XP Service Pack 3 [workstation] {personal} {terminal services, single user}",
	"Windows Server 2003 Service Pack 1 [server] {enterprise} {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 1 [domain controller] {enterprise} {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 2 [server] {enterprise} {terminal services}",
	"Windows Server 2003 Service Pack 2 [server] {\"blade\" (2003, web edition)} {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 2 [server] {enterprise} {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 2 [server] {datacenter} {enterprise} {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 2 [server] {terminal services, single user} {terminal services}",
	"Windows Server 2003 Service Pack 2 [domain controller] {enterprise} {terminal services, single user} {terminal services}",
	"Windows \"Longhorn\"  [workstation] {terminal services, single user}",
	"Windows \"Longhorn\" Service Pack 1 [workstation] {terminal services, single user}",
	"Windows \"Longhorn\" Service Pack 1 [server] {datacenter} {terminal services, single user} {terminal services}",
	"Windows \"Longhorn\" Service Pack 1 [server] {terminal services, single user} {terminal services}",
	"Windows \"Longhorn\" Service Pack 2 [workstation] {personal} {terminal services, single user}",
	"Windows \"Longhorn\" Service Pack 2 [server] {\"blade\" (2003, web edition)} {terminal services, single user} {terminal services}",
	"Very recent version of Windows [major=6,minor=1]  [workstation] {terminal services, single user}"};
int selectedVer=-1;

const char *
get_winver(void)
{	char *tmp;int oldSel=selectedVer;
	or_options_t *opts=get_options();
	if(versions[0][0]=='-') versions[0]=(char *)get_uname();
	if(selectedVer==-1) selectedVer=crypto_rand_int(41);
	if(opts->winver==NULL) opts->winver=tor_strdup("<< Random >>");
	if((opts->winver==NULL)||(opts->winver[0]=='<')) tmp=tor_strdup(versions[selectedVer]);
	else tmp=tor_strdup(opts->winver);
	if((oldSel!=selectedVer)&&(opts->winver!=NULL)&&(opts->winver[0]=='<')) log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_MAIN_RANDOM_OS),safe_str(tmp));
	return tmp;
}

time_t get_time(time_t *newtime)
{
	time_t result=time(newtime);
	result+=best_delta_t;
	return result;
}

time_t update_time(time_t newtime)
{
	time_t result=newtime;
	result+=best_delta_t;
	return result;
}

void update_best_delta_t(long t)
{	if(connection_array)
	{	time_t delta = t - best_delta_t;
		SMARTLIST_FOREACH(connection_array, connection_t *, conn,
		{	conn->timestamp_lastwritten += delta;
			conn->timestamp_lastread += delta;
			conn->timestamp_created += delta;
		});
	}
	best_delta_t = t;
}

time_t set_new_time(time_t newtime)
{	or_options_t *opts=get_options();
	if((!(opts->DirFlags&DIR_FLAG_FAKE_LOCAL_TIME))||(!(opts->DirFlags&DIR_FLAG_USE_ROUTER_TIME))) return get_time(NULL);
	time_t oldtime=time(NULL);
	time_t result=newtime;
	if(best_delta_t==delta_t)
	{	update_best_delta_t(newtime-oldtime);
		opts->BestTimeDelta=best_delta_t;
		log(LOG_INFO,LD_CONTROL,get_lang_str(LANG_LOG_MAIN_NEW_TIMESTAMP_DELTA), best_delta_t);
	}
	return result+best_delta_t;
}

void adjust_time(int seconds)
{	or_options_t *opts=get_options();
	update_best_delta_t(best_delta_t-seconds);
	delta_t-=seconds;
	if(opts) opts->BestTimeDelta=best_delta_t;
}

/** Return the current Tor version, possibly */
const char *
get_version(void)
{
	or_options_t *opts=get_options();
	if(!opts) _version=tor_strdup(FAKE_TOR_VER);
	else if(opts->torver)	_version=tor_strdup(opts->torver);
	else if (_version == NULL)
		_version = tor_strdup(opts->torver);
	return _version;
}

void tor_end(void)
{	started=0;
	SetDlgItemText(getDialog(),1,"&Start");
	CloseHandle(hThread);ExitThread(0);
}

char *get_default_conf_file(void)
{
	return	config_file_name;
}

int tor_main(int argc, char *argv[])
{
	WSADATA	WSAData;
	int i,j;
	HANDLE hMutex=NULL;
	char mutexName[40];

	_version=NULL;
	hInstance=GetModuleHandle(0);
	WSAStartup(0x101,&WSAData);
	InitCommonControls();
	get_exe_name(fullpath);
	strcpy(mutexName,"AdvOR_");
	for(i=0;fullpath[i];i++) ;
	i=(i<30)?0:i-30;
	for(j=0;fullpath[i+j];j++)
	{	if(((fullpath[i+j]>='a')&&(fullpath[i+j]<='z'))||((fullpath[i+j]>='A')&&(fullpath[i+j]<='Z'))||((fullpath[i+j]>='0')&&(fullpath[i+j]<='9')))
			mutexName[j+6]=fullpath[i+j];
		else mutexName[j+6]='_';
	}
	mutexName[j+6]=0;
	strcpy(pipeName,"\\\\.\\pipe\\");strcat(pipeName,mutexName);
	if((hMutex=OpenMutex(MUTEX_ALL_ACCESS,0,mutexName))!=NULL)
	{	CloseHandle(hMutex);
		FILE *f = NULL;
		i = 1;j = 0;
		while(i < argc)
		{	if(!strcmp(argv[i],"--exec") || !strcmp(argv[i],"-e"))
			{	if(argc>i)
				{	char *s=tor_malloc(512);
					tor_snprintf(s,511,"EXEC %s",argv[i+1]);
					f=fopen(pipeName,"wb");
					if(f)
					{	fprintf(f,"%s",s);
						fclose(f);
					}
					tor_free(s);
					i++;j++;
					if(!f)	break;
				}
			}
			i++;
		}
		if(!j)
		{	f=fopen(pipeName,"wb");
			if(f)
			{	fprintf(f,"SHOW");fclose(f);
				fclose(f);
			}
		}
		ExitProcess(0);
	}
	else
	{	hMutex=CreateMutex(0,1,mutexName);
	}
	for(j=0,i=0;fullpath[j];j++) if(fullpath[j]=='\\') i=j;
	fullpath[i]=0;
	LPWSTR dirstr = get_unicode(fullpath);
	SetCurrentDirectoryW(dirstr);
	tor_free(dirstr);
	for(j=i+1;fullpath[j];j++)
	{	exename[j-i-1]=fullpath[j];
	}
	exename[j-i-1]=0;j=0;
	for(i=0;exename[i];i++) if(exename[i]=='.') j=i;
	if(j) exename[j]=0;
	for(i=0;fullpath[i];i++);
	if(i) fullpath[i++]='\\';
	fullpath[i]=0;
	strcat(&fullpath[i],exename);
	strcpy(config_file_name,fullpath);strcat(config_file_name,".ini");
	init_seh();
	HMODULE hMod = GetModuleHandleA("Kernel32.dll");
	if(hMod)
	{	typedef BOOL (WINAPI *PSETDEP)(DWORD);
		PSETDEP setdeppolicy = (PSETDEP)GetProcAddress(hMod,"SetProcessDEPPolicy");
		if(setdeppolicy) setdeppolicy(1); /* PROCESS_DEP_ENABLE */
	}
	if (!connection_array)	connection_array = smartlist_create();
	if (!closeable_connection_lst)	closeable_connection_lst = smartlist_create();
	if (!active_linked_connection_lst)	active_linked_connection_lst = smartlist_create();
	if (!plugin_connection_lst)	plugin_connection_lst = smartlist_create();
//	tor_snprintf(buf, sizeof(buf), "Tor %s", get_version());
//	log_set_application_name(buf);
	read_configuration_data();
	rep_hist_init();
	rend_cache_init();
	options_init_from_torrc(argc,argv);
	tmpOptions=get_options();
	dlgAuthorities_initDirServers(&tmpOptions->DirServers);
	if(tmpOptions->Language && tmpOptions->Language[0]!='<')
	{	char *fname=getLanguageFileName(tmpOptions->Language);
		load_lng(fname);
		tor_free(fname);
	}
	crypto_global_init();
	if(crypto_seed_rng(1)){LangMessageBox(0,get_lang_str(LANG_MB_ERROR_SEED),LANG_MB_ERROR,0);ExitProcess(0);}
	if(tmpOptions->DirFlags&DIR_FLAG_FAKE_LOCAL_TIME)
	{	update_best_delta_t(tmpOptions->BestTimeDelta);
		delta_t=best_delta_t;
		if((tmpOptions->BestTimeDelta)&&(tmpOptions->DirFlags&DIR_FLAG_USE_ROUTER_TIME)) delta_t=tmpOptions->BestTimeDelta;
		else delta_t=crypto_rand_int(tmpOptions->MaxTimeDelta*2)-tmpOptions->MaxTimeDelta;
		update_best_delta_t(delta_t);
	}
//	options->logging=0xc000|LOG_DEBUG;
	get_winver();
	LangInitCriticalSection();
	iplist_init();
	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1000),0,&dlgfunc,0);
	remove_plugins();
	options_save_current();
	flush_configuration_data();
	unload_all_files();
	WSACleanup();
	unload_languages();
	LangDeleteCriticalSection();
	restore_seh();
	iplist_free();
	if(hMutex) CloseHandle(hMutex);
	tor_alloc_exit();
	// ExitProcess no longer works with some OpenSSL setups
	TerminateProcess(GetCurrentProcess(),0);
	ExitProcess(0);
}

int tor_is_started(void)
{	return started==1;
}

int __stdcall tor_thread(LPARAM lParam)
{
	int	loop_result;
	time_t	now;
	(void)lParam;

	time_of_process_start = get_time(NULL);
	addressmap_init(); /* Init the client dns cache. Do it always, since it's cheap. */
//	add_temp_log(LOG_NOTICE);
	if(dns_init() < 0)
	{	log_err(LD_GENERAL,get_lang_str(LANG_LOG_MAIN_DNS_INIT_ERROR));
	//	while(dns_reset()<0)	Sleep(1000);
	}
	if((! client_identity_key_is_set())&&(init_keys() < 0))
	{	log_err(LD_BUG,get_lang_str(LANG_LOG_MAIN_KEYS_INIT_ERROR));tor_end();}
	init_cell_pool();
	connection_bucket_init();
	stats_prev_global_read_bucket = global_read_bucket;
	stats_prev_global_write_bucket = global_write_bucket;
	control_event_bootstrap(BOOTSTRAP_STATUS_STARTING, 0);
	if(trusted_dirs_reload_certs())    log_warn(LD_DIR,get_lang_str(LANG_LOG_MAIN_ERROR_LOADING_V3_CERTS));
	if(router_reload_v2_networkstatus())	tor_end();
	if(router_reload_consensus_networkstatus())	tor_end();
	if(router_reload_router_list())	tor_end();
	now = get_time(NULL);
	directory_info_has_arrived(now, 1);
//	if(authdir_mode_tests_reachability(get_options()))	dirserv_test_reachability(now, 1);	/* the directory is already here, run startup things */
	if(server_mode(get_options()))	cpu_init();	/* launch cpuworkers. Need to do this *after* we've read the onion key. */
	if(! second_timer)	/* set up once-a-second callback. */
	{	struct timeval one_second;
		one_second.tv_sec = 1;
		one_second.tv_usec = 0;
		second_timer = periodic_timer_new(tor_libevent_get_base(),&one_second,second_elapsed_callback,NULL);
		tor_assert(second_timer);
	}
	config_register_addressmaps(get_options());
	parse_virtual_addr_network(get_options()->VirtualAddrNetwork,0,0);
	while(started)
	{	//if(nt_service_is_stopping())	return 0;
		SMARTLIST_FOREACH(active_linked_connection_lst, connection_t *, conn,event_active(conn->read_event, EV_READ, 1)); /* All active linked conns should get their read events activated. */
		SMARTLIST_FOREACH(plugin_connection_lst,connection_t *,conn,
		{	if(conn->plugin_read)	event_active(conn->read_event,EV_READ,1);
			if(conn->plugin_write)	event_active(conn->read_event,EV_WRITE,1);
		});
		smartlist_clear(plugin_connection_lst);
		called_loop_once = smartlist_len(active_linked_connection_lst) ? 1 : 0;
		/* poll until we have an event, or the second ends, or until we have some active linked connections to trigger events for. */
		loop_result = event_base_loop(tor_libevent_get_base(),called_loop_once ? EVLOOP_ONCE : 0);
		/* let catch() handle things like ^c, and otherwise don't worry about it */
		if(loop_result < 0)
		{	int e = tor_socket_errno(-1);
			/* let the program survive things like ^z */
			if (e != EINTR && !ERRNO_IS_EINPROGRESS(e))
			{	log_err(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_CALL_FAILED),tor_socket_strerror(e), e);
				tor_end();
			}
			else
			{	if(ERRNO_IS_EINPROGRESS(e))	log_warn(LD_BUG,get_lang_str(LANG_LOG_MAIN_LIBEVENT_CALL_FAILED_2));
				log_debug(LD_NET,get_lang_str(LANG_LOG_MAIN_LIBEVENT_CALL_FAILED_3));
				/* You can't trust the results of this poll(). Go back to the top of the big for loop. */
				continue;
			}
		}
	}
	tor_cleanup();
	SetDlgItemText(getDialog(),1,"&Start");
	tor_end();
	ExitThread(0);
}
