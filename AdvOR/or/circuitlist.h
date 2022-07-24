/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitlist.h
 * \brief Header file for circuitlist.c.
 **/

#ifndef _TOR_CIRCUITLIST_H
#define _TOR_CIRCUITLIST_H

circuit_t * _circuit_get_global_list(void);
const char *circuit_state_to_string(int state);
const char *circuit_purpose_to_controller_string(uint8_t purpose);
const char *circuit_purpose_to_string(uint8_t purpose);
void circuit_dump_by_conn(connection_t *conn, int severity);
void circuit_set_p_circid_orconn(or_circuit_t *circ, circid_t id,
                                 or_connection_t *conn);
void circuit_set_n_circid_orconn(circuit_t *circ, circid_t id,
                                 or_connection_t *conn);
void circuit_set_state(circuit_t *circ, uint8_t state);
void circuit_close_all_marked(void);
int32_t circuit_initial_package_window(void);
origin_circuit_t *origin_circuit_new(void);
or_circuit_t *or_circuit_new(circid_t p_circ_id, or_connection_t *p_conn);
circuit_t *circuit_get_by_circid_orconn(circid_t circ_id,
                                        or_connection_t *conn);
int circuit_id_in_use_on_orconn(circid_t circ_id, or_connection_t *conn);
circuit_t *circuit_get_by_edge_conn(edge_connection_t *conn);
void circuit_unlink_all_from_or_conn(or_connection_t *conn, int reason);
origin_circuit_t *circuit_get_by_global_id(uint32_t id);
origin_circuit_t *circuit_get_by_rend_query_and_purpose(const char *rend_query,
                                                        uint8_t purpose);
origin_circuit_t *circuit_get_next_by_pk_and_purpose(origin_circuit_t *start,
                                         const char *digest, uint8_t purpose);
or_circuit_t *circuit_get_rendezvous(const char *cookie);
or_circuit_t *circuit_get_intro_point(const char *digest);
origin_circuit_t *circuit_find_to_cannibalize(uint8_t purpose,
                                              extend_info_t *info, int flags);
void circuit_mark_all_unused_circs(void);
void circuit_expire_all_dirty_circs(void);
void circuit_expire_all_circs(DWORD exclKey);
void circuit_expire_all_circuits(void);
void _circuit_mark_for_close(circuit_t *circ, int reason,
                             int line, const char *file);
int circuit_get_cpath_len(origin_circuit_t *circ);
crypt_path_t *circuit_get_cpath_hop(origin_circuit_t *circ, int hopnum);
void circuit_get_all_pending_on_or_conn(smartlist_t *out,
                                        or_connection_t *or_conn);
int circuit_count_pending_on_or_conn(or_connection_t *or_conn);

#define circuit_mark_for_close(c, reason)                               \
  _circuit_mark_for_close((c), (reason), __LINE__, _SHORT_FILE_)

void assert_cpath_layer_ok(const crypt_path_t *cp);
void assert_circuit_ok(const circuit_t *c);
void circuit_free_all(void);
char *circuit_find_most_recent_exit(char *address);
void circuit_tree_add_circs(void);
circuit_t *get_circuit_by_hitem(HTREEITEM hItem);
char *circuit_dump(circuit_t *circ);

#endif

