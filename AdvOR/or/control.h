/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.h
 * \brief Header file for control.c.
 **/

#ifndef _TOR_CONTROL_H
#define _TOR_CONTROL_H

void control_update_global_event_mask(void);
void control_adjust_event_log_severity(void);

void control_ports_write_to_file(void);

/** Log information about the connection <b>conn</b>, protecting it as with
 * CONN_LOG_PROTECT. Example:
 *
 * LOG_FN_CONN(conn, (LOG_DEBUG, "Socket %d wants to write", conn->s));
 **/
#define LOG_FN_CONN(conn, args)                 \
  CONN_LOG_PROTECT(conn, log_fn args)

int connection_control_finished_flushing(control_connection_t *conn);
int connection_control_reached_eof(control_connection_t *conn);
void connection_control_closed(control_connection_t *conn);

int connection_control_process_inbuf(control_connection_t *conn);

#define EVENT_AUTHDIR_NEWDESCS 0x000D
#define EVENT_NS 0x000F
int control_event_is_interesting(int event);

int control_event_circuit_status(origin_circuit_t *circ,
                                 circuit_status_event_t e, int reason);
int control_event_stream_status(edge_connection_t *conn,
                                stream_status_event_t e,
                                int reason);
int control_event_or_conn_status(or_connection_t *conn,
                                 or_conn_status_event_t e, int reason);
int control_event_bandwidth_used(uint32_t n_read, uint32_t n_written);
int control_event_stream_bandwidth(edge_connection_t *edge_conn);
int control_event_stream_bandwidth_used(void);
void control_event_logmsg(int severity, unsigned int domain, const char *msg);
int control_event_descriptors_changed(smartlist_t *routers);
int control_event_address_mapped(char *from, char **to,
                                 time_t expires, const char *error);
int control_event_or_authdir_new_descriptor(const char *action,
                                            const char *desc,
                                            size_t desclen,
                                            const char *msg);
int control_event_my_descriptor_changed(void);
int control_event_networkstatus_changed(smartlist_t *statuses);

int control_event_newconsensus(const networkstatus_t *consensus);
int control_event_networkstatus_changed_single(routerstatus_t *rs);
int control_event_general_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_client_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_server_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_guard(const char *nickname, const char *digest,
                        const char *status);
int control_event_buildtimeout_set(const circuit_build_times_t *cbt,
                                   buildtimeout_set_event_t type);

int init_cookie_authentication(int enabled);
smartlist_t *decode_hashed_passwords(config_line_t *passwords);
void disable_control_logging(void);
void enable_control_logging(void);

void monitor_owning_controller_process(const char *process_spec);

void control_event_bootstrap(bootstrap_status_t status, int progress);
void control_event_bootstrap_problem(const char *warn, int reason);

void control_event_clients_seen(const char *controller_str);

#ifdef CONTROL_PRIVATE
/* Used only by control.c and test.c */
size_t write_escaped_data(const char *data, size_t len, char **out);
size_t read_escaped_data(const char *data, size_t len, char **out);
#endif
int register_controller(void);

#endif

