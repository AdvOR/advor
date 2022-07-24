/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file command.c
 * \brief Functions for processing incoming cells.
 **/

/* In-points to command.c:
 *
 * - command_process_cell(), called from
 *   connection_or_process_cells_from_inbuf() in connection_or.c
 */

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "command.h"
#include "connection.h"
#include "connection_or.h"
#include "config.h"
#include "control.h"
#include "cpuworker.h"
#include "hibernate.h"
#include "onion.h"
#include "relay.h"
#include "router.h"
#include "routerlist.h"
#include "main.h"

/** How many CELL_PADDING cells have we received, ever? */
uint64_t stats_n_padding_cells_processed = 0;
/** How many CELL_CREATE cells have we received, ever? */
uint64_t stats_n_create_cells_processed = 0;
/** How many CELL_CREATED cells have we received, ever? */
uint64_t stats_n_created_cells_processed = 0;
/** How many CELL_RELAY cells have we received, ever? */
uint64_t stats_n_relay_cells_processed = 0;
/** How many CELL_DESTROY cells have we received, ever? */
uint64_t stats_n_destroy_cells_processed = 0;
/** How many CELL_VERSIONS cells have we received, ever? */
uint64_t stats_n_versions_cells_processed = 0;
/** How many CELL_NETINFO cells have we received, ever? */
uint64_t stats_n_netinfo_cells_processed = 0;

/* These are the main functions for processing cells */
static void command_process_create_cell(cell_t *cell, or_connection_t *conn);
static void command_process_created_cell(cell_t *cell, or_connection_t *conn);
static void command_process_relay_cell(cell_t *cell, or_connection_t *conn);
static void command_process_destroy_cell(cell_t *cell, or_connection_t *conn);
static void command_process_versions_cell(var_cell_t *cell,
                                          or_connection_t *conn);
static void command_process_netinfo_cell(cell_t *cell, or_connection_t *conn);

#ifdef KEEP_TIMING_STATS
/** This is a wrapper function around the actual function that processes the
 * <b>cell</b> that just arrived on <b>conn</b>. Increment <b>*time</b>
 * by the number of microseconds used by the call to <b>*func(cell, conn)</b>.
 */
static void
command_time_process_cell(cell_t *cell, or_connection_t *conn, int *time,
                               void (*func)(cell_t *, or_connection_t *))
{
  struct timeval start, end;
  long time_passed;

  tor_gettimeofday(&start);

  (*func)(cell, conn);

  tor_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 10000) { /* more than 10ms */
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_CALL_DURATION),time_passed/1000);
  }
  if (time_passed < 0) {
    log_info(LD_GENERAL,get_lang_str(LANG_LOG_COMMAND_TIME_MACHINE));
    time_passed = 0;
  }
  *time += time_passed;
}
#endif

/** Process a <b>cell</b> that was just received on <b>conn</b>. Keep internal
 * statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.
 */
void
command_process_cell(cell_t *cell, or_connection_t *conn)
{
  int handshaking = (conn->_base.state == OR_CONN_STATE_OR_HANDSHAKING);
#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_create=0, num_created=0, num_relay=0, num_destroy=0;
  /* how long has it taken to process each type of cell? */
  static int create_time=0, created_time=0, relay_time=0, destroy_time=0;
  static time_t current_second = 0; /* from previous calls to time */

  time_t now = get_time(NULL);

  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_STATS_SECOND),num_create, create_time/1000,num_created, created_time/1000,num_relay, relay_time/1000,num_destroy, destroy_time/1000);

    /* zero out stats */
    num_create = num_created = num_relay = num_destroy = 0;
    create_time = created_time = relay_time = destroy_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

#ifdef KEEP_TIMING_STATS
#define PROCESS_CELL(tp, cl, cn) STMT_BEGIN {                   \
    ++num ## tp;                                                \
    command_time_process_cell(cl, cn, & tp ## time ,            \
                              command_process_ ## tp ## _cell);  \
  } STMT_END
#else
#define PROCESS_CELL(tp, cl, cn) command_process_ ## tp ## _cell(cl, cn)
#endif

  if (conn->_base.marked_for_close)
    return;

  /* Reject all but VERSIONS and NETINFO when handshaking. */
  if (handshaking && cell->command != CELL_VERSIONS &&
      cell->command != CELL_NETINFO)
    return;

  switch (cell->command) {
    case CELL_PADDING:
      ++stats_n_padding_cells_processed;
      /* do nothing */
      break;
    case CELL_CREATE:
    case CELL_CREATE_FAST:
      ++stats_n_create_cells_processed;
      PROCESS_CELL(create, cell, conn);
      break;
    case CELL_CREATED:
    case CELL_CREATED_FAST:
      ++stats_n_created_cells_processed;
      PROCESS_CELL(created, cell, conn);
      break;
    case CELL_RELAY:
    case CELL_RELAY_EARLY:
      ++stats_n_relay_cells_processed;
      PROCESS_CELL(relay, cell, conn);
      break;
    case CELL_DESTROY:
      ++stats_n_destroy_cells_processed;
      PROCESS_CELL(destroy, cell, conn);
      break;
    case CELL_VERSIONS:
      tor_fragile_assert();
      break;
    case CELL_NETINFO:
      ++stats_n_netinfo_cells_processed;
      PROCESS_CELL(netinfo, cell, conn);
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_UNKNOWN_CELL_TYPE), cell->command);
      break;
  }
}

/** Process a <b>cell</b> that was just received on <b>conn</b>. Keep internal
 * statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.
 */
void
command_process_var_cell(var_cell_t *cell, or_connection_t *conn)
{
#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_versions=0, num_cert=0;

  time_t now = get_time(NULL);

  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_STATS_SECOND_VERSIONS),num_versions, versions_time/1000,cert, cert_time/1000);

    num_versions = num_cert = 0;
    versions_time = cert_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

  if (conn->_base.marked_for_close)
    return;

  /* reject all when not handshaking. */
  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING)
    return;

  switch (cell->command) {
    case CELL_VERSIONS:
      ++stats_n_versions_cells_processed;
      PROCESS_CELL(versions, cell, conn);
      break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_COMMAND_UNKNOWN_CELL_TYPE_VAR_LENGTH),cell->command);
      tor_fragile_assert();
      break;
  }
}

/** Process a 'create' <b>cell</b> that just arrived from <b>conn</b>. Make a
 * new circuit with the p_circ_id specified in cell. Put the circuit in state
 * onionskin_pending, and pass the onionskin to the cpuworker. Circ will get
 * picked up again when the cpuworker finishes decrypting it.
 */
static void
command_process_create_cell(cell_t *cell, or_connection_t *conn)
{
  or_circuit_t *circ;
  or_options_t *options = get_options();
  int id_is_high;

  if (we_are_hibernating()) {
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_CREATE_ON_SHUTDOWN));
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_HIBERNATING);
    return;
  }

  if (!server_mode(options) || (!public_server_mode(options) && conn->is_outgoing)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_CLIENT_RECEIVED_CREATE_CELL),(int)cell->command, conn->_base.address, conn->_base.port);
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  /* If the high bit of the circuit ID is not as expected, close the
   * circ. */
  id_is_high = cell->circ_id & (1<<15);
  if ((id_is_high && conn->circ_id_type == CIRC_ID_TYPE_HIGHER) ||
      (!id_is_high && conn->circ_id_type == CIRC_ID_TYPE_LOWER)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_RECEIVED_CREATE_WITH_UNEXPECTED_CIRC_ID),cell->circ_id);
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (circuit_id_in_use_on_orconn(cell->circ_id, conn)) {
    routerinfo_t *router = router_get_by_digest(conn->identity_digest);
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_RECEIVED_CREATE_FOR_KNOWN_CIRC),cell->circ_id, (int)(get_time(NULL) - conn->_base.timestamp_created));
    if (router)
    { char *esc_l = esc_for_log(router->platform);
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_ROUTER_DETAILS),router->nickname, esc_l);
      tor_free(esc_l);
    }
    return;
  }

  circ = or_circuit_new(cell->circ_id, conn);
  circ->_base.purpose = CIRCUIT_PURPOSE_OR;
  tree_set_circ(TO_CIRCUIT(circ));
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_ONIONSKIN_PENDING);
  if (cell->command == CELL_CREATE) {
    char *onionskin = tor_malloc(ONIONSKIN_CHALLENGE_LEN);
    memcpy(onionskin, cell->payload, ONIONSKIN_CHALLENGE_LEN);

    /* hand it off to the cpuworkers, and then return. */
    if (assign_onionskin_to_cpuworker(NULL, circ, onionskin) < 0) {
#define WARN_HANDOFF_FAILURE_INTERVAL (6*60*60)
      static ratelim_t handoff_warning =
        RATELIM_INIT(WARN_HANDOFF_FAILURE_INTERVAL);
      char *m;
      if ((m = rate_limit_log(&handoff_warning, approx_time()))) {
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_COMMAND_FAILED_TO_HAND_OFF_ONIONSKIN));
        tor_free(m);
      }
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_SUCCESS_HANDED_OFF_ONIONSKIN));
  } else {
    /* This is a CREATE_FAST cell; we can handle it immediately without using
     * a CPU worker. */
    char keys[CPATH_KEY_MATERIAL_LEN];
    char reply[DIGEST_LEN*2];
    tor_assert(cell->command == CELL_CREATE_FAST);

    /* Make sure we never try to use the OR connection on which we
     * received this cell to satisfy an EXTEND request,  */
    conn->is_connection_with_client = 1;

    if (fast_server_handshake(cell->payload, (uint8_t*)reply, (uint8_t*)keys, sizeof(keys))<0) {
      log_warn(LD_OR,get_lang_str(LANG_LOG_COMMAND_FAILED_TO_GENERATE_KEY_MATERIAL));
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
    if (onionskin_answer(circ, CELL_CREATED_FAST, reply, keys)<0) {
      log_warn(LD_OR,get_lang_str(LANG_LOG_COMMAND_FAILED_TO_REPLY_TO_CREATE_FAST));
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
  }
}

/** Process a 'created' <b>cell</b> that just arrived from <b>conn</b>.
 * Find the circuit
 * that it's intended for. If we're not the origin of the circuit, package
 * the 'created' cell in an 'extended' relay cell and pass it back. If we
 * are the origin of the circuit, send it to circuit_finish_handshake() to
 * finish processing keys, and then call circuit_send_next_onion_skin() to
 * extend to the next hop in the circuit if necessary.
 */
static void
command_process_created_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);

  if (!circ) {
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_UNKNOWN_CIRCID), cell->circ_id);
    return;
  }

  if (circ->n_circ_id != cell->circ_id) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_GOT_CREATED_FROM_CLIENT));
    circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (CIRCUIT_IS_ORIGIN(circ)) { /* we're the OP. Handshake this. */
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    int err_reason = 0;
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_AT_OP_FINISHING_HANDSHAKE));
    if ((err_reason = circuit_finish_handshake(origin_circ, cell->command,
                                 cell->payload)) < 0) {
      log_warn(LD_OR,get_lang_str(LANG_LOG_COMMAND_CIRCUIT_HANDSHAKE_FAILED));
      circuit_mark_for_close(circ, -err_reason);
      return;
    }
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_MOVING_TO_NEXT_SKIN));
    if ((err_reason = circuit_send_next_onion_skin(origin_circ)) < 0) {
      log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_CIRCUIT_SEND_NEXT_ONIONSKIN_FAILED));
      /* XXX push this circuit_close lower */
      circuit_mark_for_close(circ, -err_reason);
      return;
    }
  } else { /* pack it into an extended relay cell, and send it. */
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_CONVERTING_CREATED_TO_EXTENDED));
    relay_send_command_from_edge(0, circ, RELAY_COMMAND_EXTENDED,
                                 (char*)cell->payload, ONIONSKIN_REPLY_LEN,
                                 NULL);
  }
}

/** Process a 'relay' or 'relay_early' <b>cell</b> that just arrived from
 * <b>conn</b>. Make sure it came in with a recognized circ_id. Pass it on to
 * circuit_receive_relay_cell() for actual processing.
 */
static void
command_process_relay_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;
  int reason, direction;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);

  if (!circ) {
    log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_UNKNOWN_CIRC_ON_CONN),cell->circ_id, conn->_base.address, conn->_base.port);
    return;
  }

  if (circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_CIRCUIT_IN_CREATE_WAIT));
    circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* if we're a relay and treating connections with recent local
     * traffic better, then this is one of them. */
    conn->client_used = get_time(NULL);
  }

  if (!CIRCUIT_IS_ORIGIN(circ) &&
      cell->circ_id == TO_OR_CIRCUIT(circ)->p_circ_id)
    direction = CELL_DIRECTION_OUT;
  else
    direction = CELL_DIRECTION_IN;

  /* If we have a relay_early cell, make sure that it's outbound, and we've
   * gotten no more than MAX_RELAY_EARLY_CELLS_PER_CIRCUIT of them. */
  if (cell->command == CELL_RELAY_EARLY) {
    if (direction == CELL_DIRECTION_IN) {
      log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_INBOUND_RELAY_EARLY),cell->circ_id, conn->_base.address, conn->_base.port);
      circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
      return;
    } else {
      or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
      if (or_circ->remaining_relay_early_cells == 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_TOO_MANY_RELAY_EARLY),cell->circ_id, safe_str(conn->_base.address), conn->_base.port);
        circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
        return;
      }
      --or_circ->remaining_relay_early_cells;
    }
  }

  if ((reason = circuit_receive_relay_cell(cell, circ, direction)) < 0) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,get_lang_str(LANG_LOG_COMMAND_CIRCUIT_RECEIVE_RELAY_CELL_FAILED),direction==CELL_DIRECTION_OUT?"forward":"backward");
    circuit_mark_for_close(circ, -reason);
  }
}

/** Process a 'destroy' <b>cell</b> that just arrived from
 * <b>conn</b>. Find the circ that it refers to (if any).
 *
 * If the circ is in state
 * onionskin_pending, then call onion_pending_remove() to remove it
 * from the pending onion list (note that if it's already being
 * processed by the cpuworker, it won't be in the list anymore; but
 * when the cpuworker returns it, the circuit will be gone, and the
 * cpuworker response will be dropped).
 *
 * Then mark the circuit for close (which marks all edges for close,
 * and passes the destroy cell onward if necessary).
 */
static void
command_process_destroy_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;
  int reason;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);
  reason = (uint8_t)cell->payload[0];
  if (!circ) {
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_UNKNOWN_CIRC_ON_CONN),cell->circ_id, conn->_base.address, conn->_base.port);
    return;
  }
  log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_FOR_CIRCID),cell->circ_id);

  if (!CIRCUIT_IS_ORIGIN(circ) &&
      cell->circ_id == TO_OR_CIRCUIT(circ)->p_circ_id) {
    /* the destroy came from behind */
    circuit_set_p_circid_orconn(TO_OR_CIRCUIT(circ), 0, NULL);
    circuit_mark_for_close(circ, reason|END_CIRC_REASON_FLAG_REMOTE);
  } else { /* the destroy came from ahead */
    circuit_set_n_circid_orconn(circ, 0, NULL);
    if (CIRCUIT_IS_ORIGIN(circ)) {
      circuit_mark_for_close(circ, reason|END_CIRC_REASON_FLAG_REMOTE);
    } else {
      char payload[1];
      log_debug(LD_OR,get_lang_str(LANG_LOG_COMMAND_DELIVERING_TRUNCATED_BACK));
      payload[0] = (char)reason;
      relay_send_command_from_edge(0, circ, RELAY_COMMAND_TRUNCATED,
                                   payload, sizeof(payload), NULL);
    }
  }
}

/** Process a 'versions' cell.  The current link protocol version must be 0
 * to indicate that no version has yet been negotiated.  We compare the
 * versions in the cell to the list of versions we support, pick the
 * highest version we have in common, and continue the negotiation from
 * there.
 */
static void
command_process_versions_cell(var_cell_t *cell, or_connection_t *conn)
{
  int highest_supported_version = 0;
  const uint8_t *cp, *end;
  if (conn->link_proto != 0 ||
      conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING ||
      (conn->handshake_state && conn->handshake_state->received_versions)) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_VERSIONS_TWICE), (int) conn->link_proto);
    return;
  }
  tor_assert(conn->handshake_state);
  end = cell->payload + cell->payload_len;
  for (cp = cell->payload; cp+1 < end; ++cp) {
    uint16_t v = ntohs(get_uint16(cp));
    if (is_or_protocol_version_known(v) && v > highest_supported_version)
      highest_supported_version = v;
  }
  if (!highest_supported_version) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_NO_COMMON_VERSION));
    connection_mark_for_close(TO_CONN(conn));
    return;
  } else if (highest_supported_version == 1) {
    /* Negotiating version 1 makes no sense, since version 1 has no VERSIONS
     * cells. */
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_VERSIONS_FOR_V1));
    connection_mark_for_close(TO_CONN(conn));
    return;
  }
  conn->link_proto = highest_supported_version;
  conn->handshake_state->received_versions = 1;

  log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_NEGOTIATED_VERSION),highest_supported_version, safe_str(conn->_base.address),conn->_base.port);
  tor_assert(conn->link_proto >= 2);

  if (connection_or_send_netinfo(conn) < 0) {
    connection_mark_for_close(TO_CONN(conn));
    return;
  }
}

/** Process a 'netinfo' cell: read and act on its contents, and set the
 * connection state to "open". */
static void
command_process_netinfo_cell(cell_t *cell, or_connection_t *conn)
{
  time_t timestamp;
  uint8_t my_addr_type;
  uint8_t my_addr_len;
  const uint8_t *my_addr_ptr;
  const uint8_t *cp, *end;
  uint8_t n_other_addrs;
  time_t now = get_time(NULL);

  long apparent_skew = 0;
  uint32_t my_apparent_addr = 0;

  if (conn->link_proto < 2) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_NETINFO),conn->link_proto == 0 ? "non-versioned" : "a v1");
    return;
  }
  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_RECEIVED_NETINFO_ON_NON_HANDSHAKING));
    return;
  }
  tor_assert(conn->handshake_state &&
             conn->handshake_state->received_versions);
  /* Decode the cell. */
  timestamp = ntohl(get_uint32(cell->payload));
  now=set_new_time(timestamp);
  if (labs(now - conn->handshake_state->sent_versions_at) < 180) {
    apparent_skew = now - timestamp;
  }

  my_addr_type = (uint8_t) cell->payload[4];
  my_addr_len = (uint8_t) cell->payload[5];
  my_addr_ptr = (uint8_t*) cell->payload + 6;
  end = cell->payload + CELL_PAYLOAD_SIZE;
  cp = cell->payload + 6 + my_addr_len;
  if (cp >= end) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,get_lang_str(LANG_LOG_COMMAND_NETINFO_ADDRESSES_TOO_LONG));
    connection_mark_for_close(TO_CONN(conn));
    return;
  } else if (my_addr_type == RESOLVED_TYPE_IPV4 && my_addr_len == 4) {
    my_apparent_addr = ntohl(get_uint32(my_addr_ptr));
  }

  n_other_addrs = (uint8_t) *cp++;
  while (n_other_addrs && cp < end-2) {
    /* Consider all the other addresses; if any matches, this connection is
     * "canonical." */
    tor_addr_t addr;
    const uint8_t *next = decode_address_from_payload(&addr, cp, (int)(end-cp));
    if (next == NULL) {
      log_fn(LOG_PROTOCOL_WARN,  LD_OR,get_lang_str(LANG_LOG_COMMAND_NETINFO_BAD_ADDRESS));
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    if (tor_addr_eq(&addr, &conn->real_addr)) {
      conn->is_canonical = 1;
      break;
    }
    cp = next;
    --n_other_addrs;
  }

  /* Act on apparent skew. */
  /** Warn when we get a netinfo skew with at least this value. */
#define NETINFO_NOTICE_SKEW 3600
  if (labs(apparent_skew) > NETINFO_NOTICE_SKEW &&
      router_get_by_digest(conn->identity_digest)!=NULL && ((get_options()->DirFlags&DIR_FLAG_FAKE_LOCAL_TIME) == 0)) {
    char dbuf[64];
    int severity;
    /*XXXX be smarter about when everybody says we are skewed. */
    if (router_digest_is_trusted_dir(conn->identity_digest))
      severity = LOG_WARN;
    else
      severity = LOG_INFO;
    format_time_interval(dbuf, sizeof(dbuf), apparent_skew);
    log_fn(severity, LD_GENERAL,get_lang_str(LANG_LOG_COMMAND_NETINFO_SKEWED_TIME),conn->_base.address, (int)conn->_base.port,apparent_skew>0 ? get_lang_str(LANG_LOG_COMMAND__AHEAD) : get_lang_str(LANG_LOG_COMMAND__BEHIND), dbuf,apparent_skew>0 ? get_lang_str(LANG_LOG_COMMAND__BEHIND) : get_lang_str(LANG_LOG_COMMAND__AHEAD));
    control_event_general_status(LOG_WARN,
                        "CLOCK_SKEW SKEW=%ld SOURCE=OR:%s:%d",
                        apparent_skew, conn->_base.address, conn->_base.port);
  }

  /* XXX maybe act on my_apparent_addr, if the source is sufficiently
   * trustworthy. */
  (void)my_apparent_addr;

  if (connection_or_set_state_open(conn)<0)
    connection_mark_for_close(TO_CONN(conn));
  else
    log_info(LD_OR,get_lang_str(LANG_LOG_COMMAND_NETINFO_CELL_GOOD),safe_str(conn->_base.address), conn->_base.port,(int)conn->link_proto);
  assert_connection_ok(TO_CONN(conn),get_time(NULL));
}

