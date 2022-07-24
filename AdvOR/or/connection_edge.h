/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file connection_edge.h
 * \brief Header file for connection_edge.c.
 **/

#ifndef _TOR_CONNECTION_EDGE_H
#define _TOR_CONNECTION_EDGE_H

#define connection_mark_unattached_ap(conn, endreason) \
  _connection_mark_unattached_ap((conn), (endreason), __LINE__, _SHORT_FILE_)

void _connection_mark_unattached_ap(edge_connection_t *conn, int endreason,
                                    int line, const char *file);
int connection_edge_reached_eof(edge_connection_t *conn);
int connection_edge_process_inbuf(edge_connection_t *conn,
                                  int package_partial);
int connection_edge_destroy(circid_t circ_id, edge_connection_t *conn);
int connection_edge_end(edge_connection_t *conn, uint8_t reason);
int connection_edge_end_errno(edge_connection_t *conn);
int connection_edge_flushed_some(edge_connection_t *conn);
int connection_edge_finished_flushing(edge_connection_t *conn);
int connection_edge_finished_connecting(edge_connection_t *conn);

int connection_ap_handshake_send_begin(edge_connection_t *ap_conn);
int connection_ap_handshake_send_resolve(edge_connection_t *ap_conn);

edge_connection_t  *connection_ap_make_link(char *address, uint16_t port,
                                            const char *digest,
                                            int use_begindir, int want_onehop);
void connection_ap_handshake_socks_reply(edge_connection_t *conn, char *reply,
                                         size_t replylen,
                                         int endreason);
void connection_ap_handshake_socks_resolved(edge_connection_t *conn,
                                            int answer_type,
                                            size_t answer_len,
                                            const uint8_t *answer,
                                            int ttl,
                                            time_t expires);

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
int connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ);
void connection_exit_connect(edge_connection_t *conn);
int connection_edge_is_rendezvous_stream(edge_connection_t *conn);
int connection_ap_can_use_exit(edge_connection_t *conn, routerinfo_t *exit);
void connection_ap_expire_beginning(void);
void connection_ap_attach_pending(void);
void connection_ap_fail_onehop(const char *failed_digest,
                               cpath_build_state_t *build_state);
void circuit_discard_optional_exit_enclaves(extend_info_t *info);
int connection_ap_detach_retriable(edge_connection_t *conn,
                                   origin_circuit_t *circ,
                                   int reason);
int connection_ap_process_transparent(edge_connection_t *conn);

int address_is_invalid_destination(const char *address, int client);

void addressmap_init(void);
void addressmap_clear_excluded_trackexithosts(or_options_t *options);
void addressmap_clear_invalid_automaps(or_options_t *options);
void addressmap_clean(time_t now);
void addressmap_clear_configured(void);
void addressmap_clear_transient(void);
void addressmap_free_all(void);
int addressmap_rewrite(char **address, time_t *expires_out);
int addressmap_have_mapping(const char *address, int update_timeout);

void addressmap_register(char *address, char *new_address,
                         time_t expires, addressmap_entry_source_t source);
int parse_virtual_addr_network(const char *val, int validate_only,
                               char **msg);
int client_dns_incr_failures(const char *address);
void client_dns_clear_failures(const char *address);
void client_dns_set_addressmap(const char *address, uint32_t val,
                               const char *exitname, int ttl) __attribute__ ((format(ms_printf, 1, 0)));
const char *addressmap_register_virtual_address(int type, char *new_address);
void addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                             time_t max_expires, int want_expiry);
int connection_ap_rewrite_and_attach_if_allowed(edge_connection_t *conn,
                                                origin_circuit_t *circ,
                                                crypt_path_t *cpath);
int connection_ap_handshake_rewrite_and_attach(edge_connection_t *conn,
                                               origin_circuit_t *circ,
                                               crypt_path_t *cpath);

/** Possible return values for parse_extended_hostname. */
typedef enum hostname_type_t {
  NORMAL_HOSTNAME, ONION_HOSTNAME, EXIT_HOSTNAME, BAD_HOSTNAME
} hostname_type_t;
hostname_type_t parse_extended_hostname(char *address, int allowdotexit);

BOOL is_banned(const char *_addr);
char *find_address(char *address);
void proxy_handle_client_data(edge_connection_t *conn);
int proxy_handle_server_data(connection_t *conn,const char *string,int len);

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_PFVAR_H)
int get_pf_socket(void);
#endif

#endif

