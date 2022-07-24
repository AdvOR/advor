/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file reasons.c
 * \brief Convert circuit, stream, and orconn error reasons to and/or from
 * strings and errno values.
 **/

#include "or.h"
#include "config.h"
#include "reasons.h"

/***************************** Edge (stream) reasons **********************/

/** Convert the reason for ending a stream <b>reason</b> into the format used
 * in STREAM events. Return NULL if the reason is unrecognized. */
const char *
stream_end_reason_to_control_string(int reason)
{
  reason &= END_STREAM_REASON_MASK;
  switch (reason) {
    case END_STREAM_REASON_MISC: return "MISC";
    case END_STREAM_REASON_RESOLVEFAILED: return "RESOLVEFAILED";
    case END_STREAM_REASON_CONNECTREFUSED: return "CONNECTREFUSED";
    case END_STREAM_REASON_EXITPOLICY: return "EXITPOLICY";
    case END_STREAM_REASON_DESTROY: return "DESTROY";
    case END_STREAM_REASON_DONE: return "DONE";
    case END_STREAM_REASON_TIMEOUT: return "TIMEOUT";
    case END_STREAM_REASON_NOROUTE:        return "NOROUTE";
    case END_STREAM_REASON_HIBERNATING: return "HIBERNATING";
    case END_STREAM_REASON_INTERNAL: return "INTERNAL";
    case END_STREAM_REASON_RESOURCELIMIT: return "RESOURCELIMIT";
    case END_STREAM_REASON_CONNRESET: return "CONNRESET";
    case END_STREAM_REASON_TORPROTOCOL: return "TORPROTOCOL";
    case END_STREAM_REASON_NOTDIRECTORY: return "NOTDIRECTORY";

    case END_STREAM_REASON_CANT_ATTACH: return "CANT_ATTACH";
    case END_STREAM_REASON_NET_UNREACHABLE: return "NET_UNREACHABLE";
    case END_STREAM_REASON_SOCKSPROTOCOL: return "SOCKS_PROTOCOL";
    case END_STREAM_REASON_PRIVATE_ADDR: return "PRIVATE_ADDR";

    default: return NULL;
  }
}

/** Translate <b>reason</b>, which came from a relay 'end' cell,
 * into a static const string describing why the stream is closing.
 * <b>reason</b> is -1 if no reason was provided.
 */
const char *
stream_end_reason_to_string(int reason)
{
  switch (reason) {
    case -1:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_REASONS_END_CELL_WITH_LENGTH_0));
      return get_lang_str(LANG_LOG_REASONS__MALFORMED);
    case END_STREAM_REASON_MISC:           return get_lang_str(LANG_LOG_REASONS__MISC_ERROR);
    case END_STREAM_REASON_RESOLVEFAILED:  return get_lang_str(LANG_LOG_REASONS__RESOLVE_FAILED);
    case END_STREAM_REASON_CONNECTREFUSED: return get_lang_str(LANG_LOG_REASONS__CONNECTION_REFUSED);
    case END_STREAM_REASON_EXITPOLICY:     return get_lang_str(LANG_LOG_REASONS__EXIT_POLICY_FAILED);
    case END_STREAM_REASON_DESTROY:        return get_lang_str(LANG_LOG_REASONS__DESTROYED);
    case END_STREAM_REASON_DONE:           return get_lang_str(LANG_LOG_REASONS__CLOSED_NORMALLY);
    case END_STREAM_REASON_TIMEOUT:        return get_lang_str(LANG_LOG_REASONS__TIMEOUT);
    case END_STREAM_REASON_NOROUTE:        return get_lang_str(LANG_LOG_REASONS__NOROUTE);
    case END_STREAM_REASON_HIBERNATING:    return get_lang_str(LANG_LOG_REASONS__HIBERNATING);
    case END_STREAM_REASON_INTERNAL:       return get_lang_str(LANG_LOG_REASONS__INTERNAL_ERROR);
    case END_STREAM_REASON_RESOURCELIMIT:  return get_lang_str(LANG_LOG_REASONS__RESOURCELIMIT);
    case END_STREAM_REASON_CONNRESET:      return get_lang_str(LANG_LOG_REASONS__CONNRESET);
    case END_STREAM_REASON_TORPROTOCOL:    return get_lang_str(LANG_LOG_REASONS__PROTOCOL);
    case END_STREAM_REASON_NOTDIRECTORY:   return get_lang_str(LANG_LOG_REASONS__NOTDIRECTORY);
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_REASONS_NOT_RECOGNIZED),reason);
      return get_lang_str(LANG_LOG_REASONS__UNKNOWN);
  }
}

/** Translate <b>reason</b> (as from a relay 'end' cell) into an
 * appropriate SOCKS5 reply code.
 *
 * A reason of 0 means that we're not actually expecting to send
 * this code back to the socks client; we just call it 'succeeded'
 * to keep things simple.
 */
socks5_reply_status_t
stream_end_reason_to_socks5_response(int reason)
{
  switch (reason & END_STREAM_REASON_MASK) {
    case 0:
      return SOCKS5_SUCCEEDED;
    case END_STREAM_REASON_MISC:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_RESOLVEFAILED:
      return SOCKS5_HOST_UNREACHABLE;
    case END_STREAM_REASON_CONNECTREFUSED:
      return SOCKS5_CONNECTION_REFUSED;
    case END_STREAM_REASON_ENTRYPOLICY:
      return SOCKS5_NOT_ALLOWED;
    case END_STREAM_REASON_EXITPOLICY:
      return SOCKS5_NOT_ALLOWED;
    case END_STREAM_REASON_DESTROY:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_DONE:
      return SOCKS5_SUCCEEDED;
    case END_STREAM_REASON_TIMEOUT:
      return SOCKS5_TTL_EXPIRED;
    case END_STREAM_REASON_NOROUTE:
      return SOCKS5_HOST_UNREACHABLE;
    case END_STREAM_REASON_RESOURCELIMIT:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_HIBERNATING:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_INTERNAL:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_CONNRESET:
      return SOCKS5_CONNECTION_REFUSED;
    case END_STREAM_REASON_TORPROTOCOL:
      return SOCKS5_GENERAL_ERROR;

    case END_STREAM_REASON_CANT_ATTACH:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_NET_UNREACHABLE:
      return SOCKS5_NET_UNREACHABLE;
    case END_STREAM_REASON_SOCKSPROTOCOL:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_PRIVATE_ADDR:
      return SOCKS5_GENERAL_ERROR;
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_REASONS_NOT_RECOGNIZED_2),reason);
      return SOCKS5_GENERAL_ERROR;
  }
}

/* We need to use a few macros to deal with the fact that Windows
 * decided that their sockets interface should be a permakludge.
 * E_CASE is for errors where windows has both a EFOO and a WSAEFOO
 * version, and S_CASE is for errors where windows has only a WSAEFOO
 * version.  (The E is for 'error', the S is for 'socket'). */
#ifdef MS_WINDOWS
#define E_CASE(s) case s: case WSA ## s
#define S_CASE(s) case WSA ## s
#else
#define E_CASE(s) case s
#define S_CASE(s) case s
#endif

/** Given an errno from a failed exit connection, return a reason code
 * appropriate for use in a RELAY END cell. */
uint8_t
errno_to_stream_end_reason(int e)
{
  /* To add new errors here, find out if they exist on Windows, and if a WSA*
   * equivalent exists on windows. Add a case, an S_CASE, or an E_CASE as
   * appropriate. */
  switch (e) {
    case EPIPE:
      return END_STREAM_REASON_DONE;
    E_CASE(EBADF):
    E_CASE(EFAULT):
    E_CASE(EINVAL):
    S_CASE(EISCONN):
    S_CASE(ENOTSOCK):
    S_CASE(EPROTONOSUPPORT):
    S_CASE(EAFNOSUPPORT):
    E_CASE(EACCES):
    S_CASE(ENOTCONN):
    S_CASE(ENETUNREACH):
      return END_STREAM_REASON_INTERNAL;
    S_CASE(EHOSTUNREACH):
      return END_STREAM_REASON_NOROUTE;
    S_CASE(ECONNREFUSED):
      return END_STREAM_REASON_CONNECTREFUSED;
    S_CASE(ECONNRESET):
      return END_STREAM_REASON_CONNRESET;
    S_CASE(ETIMEDOUT):
      return END_STREAM_REASON_TIMEOUT;
    S_CASE(ENOBUFS):
    case ENOMEM:
    case ENFILE:
    E_CASE(EMFILE):
      return END_STREAM_REASON_RESOURCELIMIT;
    default:
      log_info(LD_EXIT,get_lang_str(LANG_LOG_REASONS_ERRNO_NOT_RECOGNIZED),e,tor_socket_strerror(e));
      return END_STREAM_REASON_MISC;
  }
}

/***************************** ORConn reasons *****************************/

/** Convert the reason for ending an OR connection <b>r</b> into the format
 * used in ORCONN events. Return "UNKNOWN" if the reason is unrecognized. */
const char *
orconn_end_reason_to_control_string(int r)
{
  /* To add new errors here, find out if they exist on Windows, and if a WSA*
   * equivalent exists on windows. Add a case, an S_CASE, or an E_CASE as
   * appropriate. */
  switch (r) {
    case END_OR_CONN_REASON_DONE:
      return "DONE";
    case END_OR_CONN_REASON_REFUSED:
      return "CONNECTREFUSED";
    case END_OR_CONN_REASON_OR_IDENTITY:
      return "IDENTITY";
    case END_OR_CONN_REASON_CONNRESET:
      return "CONNECTRESET";
    case END_OR_CONN_REASON_TIMEOUT:
      return "TIMEOUT";
    case END_OR_CONN_REASON_NO_ROUTE:
      return "NOROUTE";
    case END_OR_CONN_REASON_IO_ERROR:
      return "IOERROR";
    case END_OR_CONN_REASON_RESOURCE_LIMIT:
      return "RESOURCELIMIT";
    case END_OR_CONN_REASON_MISC:
      return "MISC";
    case 0:
      return "";
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_REASONS_NOT_RECOGNIZED_3),r);
      return "UNKNOWN";
  }
}

/** Convert a TOR_TLS_* error code into an END_OR_CONN_* reason. */
int
tls_error_to_orconn_end_reason(int e)
{
  switch (e) {
    case TOR_TLS_ERROR_IO:
      return END_OR_CONN_REASON_IO_ERROR;
    case TOR_TLS_ERROR_CONNREFUSED:
      return END_OR_CONN_REASON_REFUSED;
    case TOR_TLS_ERROR_CONNRESET:
      return END_OR_CONN_REASON_CONNRESET;
    case TOR_TLS_ERROR_NO_ROUTE:
      return END_OR_CONN_REASON_NO_ROUTE;
    case TOR_TLS_ERROR_TIMEOUT:
      return END_OR_CONN_REASON_TIMEOUT;
    case TOR_TLS_WANTREAD:
    case TOR_TLS_WANTWRITE:
    case TOR_TLS_CLOSE:
    case TOR_TLS_DONE:
      return END_OR_CONN_REASON_DONE;
    default:
      return END_OR_CONN_REASON_MISC;
  }
}

/** Given an errno from a failed ORConn connection, return a reason code
 * appropriate for use in the controller orconn events. */
int
errno_to_orconn_end_reason(int e)
{
  switch (e) {
    case EPIPE:
      return END_OR_CONN_REASON_DONE;
    S_CASE(ENOTCONN):
    S_CASE(ENETUNREACH):
    S_CASE(ENETDOWN):
    S_CASE(EHOSTUNREACH):
      return END_OR_CONN_REASON_NO_ROUTE;
    S_CASE(ECONNREFUSED):
      return END_OR_CONN_REASON_REFUSED;
    S_CASE(ECONNRESET):
      return END_OR_CONN_REASON_CONNRESET;
    S_CASE(ETIMEDOUT):
      return END_OR_CONN_REASON_TIMEOUT;
    S_CASE(ENOBUFS):
    case ENOMEM:
    case ENFILE:
    E_CASE(EMFILE):
    E_CASE(EACCES):
    E_CASE(EBADF):
    E_CASE(EFAULT):
    E_CASE(EINVAL):
      return END_OR_CONN_REASON_RESOURCE_LIMIT;
    default:
      log_info(LD_OR,get_lang_str(LANG_LOG_REASONS_ERRNO_NOT_RECOGNIZED_2),e,tor_socket_strerror(e));
      return END_OR_CONN_REASON_MISC;
  }
}

/***************************** Circuit reasons *****************************/

/** Convert a numeric reason for destroying a circuit into a string for a
 * CIRCUIT event. */
const char *
circuit_end_reason_to_control_string(int reason)
{
  if (reason >= 0 && reason & END_CIRC_REASON_FLAG_REMOTE)
    reason &= ~END_CIRC_REASON_FLAG_REMOTE;
  switch (reason) {
    case END_CIRC_AT_ORIGIN:
      /* This shouldn't get passed here; it's a catch-all reason. */
      return "ORIGIN";
    case END_CIRC_REASON_NONE:
      /* This shouldn't get passed here; it's a catch-all reason. */
      return "NONE";
    case END_CIRC_REASON_TORPROTOCOL:
      return "TORPROTOCOL";
    case END_CIRC_REASON_INTERNAL:
      return "INTERNAL";
    case END_CIRC_REASON_REQUESTED:
      return "REQUESTED";
    case END_CIRC_REASON_HIBERNATING:
      return "HIBERNATING";
    case END_CIRC_REASON_RESOURCELIMIT:
      return "RESOURCELIMIT";
    case END_CIRC_REASON_CONNECTFAILED:
      return "CONNECTFAILED";
    case END_CIRC_REASON_OR_IDENTITY:
      return "OR_IDENTITY";
    case END_CIRC_REASON_OR_CONN_CLOSED:
      return "OR_CONN_CLOSED";
    case END_CIRC_REASON_FINISHED:
      return "FINISHED";
    case END_CIRC_REASON_TIMEOUT:
      return "TIMEOUT";
    case END_CIRC_REASON_DESTROYED:
      return "DESTROYED";
    case END_CIRC_REASON_NOPATH:
      return "NOPATH";
    case END_CIRC_REASON_NOSUCHSERVICE:
      return "NOSUCHSERVICE";
    case END_CIRC_REASON_MEASUREMENT_EXPIRED:
      return "MEASUREMENT_EXPIRED";
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_REASONS_NOT_RECOGNIZED_4),(int)reason);
      return NULL;
  }
}

/** Return a string corresponding to a bandwidht_weight_rule_t */
const char *
bandwidth_weight_rule_to_string(bandwidth_weight_rule_t rule)
{
  switch (rule)
    {
    case NO_WEIGHTING:
      return "no weighting";
    case WEIGHT_FOR_EXIT:
      return "weight as exit";
    case WEIGHT_FOR_MID:
      return "weight as middle node";
    case WEIGHT_FOR_GUARD:
      return "weight as guard";
    case WEIGHT_FOR_DIR:
      return "weight as directory";
    default:
      return "unknown rule";
  }
}
