/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file router.h
 * \brief Header file for router.c.
 **/

#ifndef _TOR_ROUTER_H
#define _TOR_ROUTER_H

crypto_pk_env_t *get_onion_key(void);
time_t get_onion_key_set_at(void);
void set_server_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_server_identity_key(void);
int server_identity_key_is_set(void);
void set_client_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_tlsclient_identity_key(void);
int client_identity_key_is_set(void);
authority_cert_t *get_my_v3_authority_cert(void);
crypto_pk_env_t *get_my_v3_authority_signing_key(void);
authority_cert_t *get_my_v3_legacy_cert(void);
crypto_pk_env_t *get_my_v3_legacy_signing_key(void);
void dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last);
void rotate_onion_key(void);
crypto_pk_env_t *init_key_from_file(char *fname, int generate,
                                    int severity);
void v3_authority_check_key_expiry(void);

int init_keys(void);

int check_whether_orport_reachable(void);
int check_whether_dirport_reachable(void);
void consider_testing_reachability(int test_or, int test_dir);
void router_orport_found_reachable(void);
void router_dirport_found_reachable(void);
void router_perform_bandwidth_test(int num_circs, time_t now);

int authdir_mode(or_options_t *options);
int authdir_mode_v1(or_options_t *options);
int authdir_mode_v2(or_options_t *options);
int authdir_mode_v3(or_options_t *options);
int authdir_mode_any_main(or_options_t *options);
int authdir_mode_any_nonhidserv(or_options_t *options);
int authdir_mode_handles_descs(or_options_t *options, int purpose);
int authdir_mode_publishes_statuses(or_options_t *options);
int authdir_mode_tests_reachability(or_options_t *options);
int authdir_mode_bridge(or_options_t *options);

uint16_t router_get_advertised_or_port(or_options_t *options);
uint16_t router_get_advertised_dir_port(or_options_t *options,
                                        uint16_t dirport);

int server_mode(or_options_t *options);
int public_server_mode(or_options_t *options);
int advertised_server_mode(void);
int proxy_mode(or_options_t *options);
void consider_publishable_server(int force);
int should_refuse_unknown_exits(or_options_t *options);

void router_upload_dir_desc_to_dirservers(int force);
void mark_my_descriptor_dirty_if_older_than(time_t when);
void mark_my_descriptor_dirty(const char *reason);
void check_descriptor_bandwidth_changed(time_t now);
void check_descriptor_ipaddress_changed(time_t now);
void router_new_address_suggestion(const char *suggestion,
                                   const dir_connection_t *d_conn);
int router_compare_to_my_exit_policy(edge_connection_t *conn);
int router_my_exit_policy_is_reject_star(void);
routerinfo_t *router_get_my_routerinfo(void);
extrainfo_t *router_get_my_extrainfo(void);
const char *router_get_my_descriptor(void);
int router_digest_is_me(const char *digest);
int router_extrainfo_digest_is_me(const char *digest);
int router_is_me(routerinfo_t *router);
int router_fingerprint_is_me(const char *fp);
int router_pick_published_address(or_options_t *options, uint32_t *addr);
int router_rebuild_descriptor(int force);
int router_dump_router_to_string(char *s, size_t maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key);
int extrainfo_dump_to_string(char **s, extrainfo_t *extrainfo,
                             crypto_pk_env_t *ident_key);
int is_legal_nickname(const char *s);
int is_legal_nickname_or_hexdigest(const char *s);
int is_legal_hexdigest(const char *s);

/**
 * Longest allowed output of format_node_description, plus 1 character for
 * NUL.  This allows space for:
 * "$FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF~xxxxxxxxxxxxxxxxxxx at"
 * " [ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]"
 * plus a terminating NUL.
 */
#define NODE_DESC_BUF_LEN (MAX_VERBOSE_NICKNAME_LEN+4+TOR_ADDR_BUF_LEN)
const char *format_node_description(char *buf,
                                    const char *id_digest,
                                    int is_named,
                                    const char *nickname,
                                    const tor_addr_t *addr,
                                    uint32_t addr32h);
const char *router_get_description(char *buf, const routerinfo_t *ri);
const char *routerstatus_get_description(char *buf, const routerstatus_t *rs);
const char *extend_info_get_description(char *buf, const extend_info_t *ei);
const char *router_describe(const routerinfo_t *ri);
const char *routerstatus_describe(const routerstatus_t *ri);
const char *extend_info_describe(const extend_info_t *ei);

void router_get_verbose_nickname(char *buf, const routerinfo_t *router);
void routerstatus_get_verbose_nickname(char *buf,
                                       const routerstatus_t *router);
void router_reset_warnings(void);
void router_reset_reachability(void);
void router_free_all(void);

const char *router_purpose_to_string(uint8_t p);
uint8_t router_purpose_from_string(const char *s);

#ifdef ROUTER_PRIVATE
/* Used only by router.c and test.c */
void get_platform_str(char *platform, size_t len);
#endif

#endif

