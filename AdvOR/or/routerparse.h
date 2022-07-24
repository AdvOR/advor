/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerparse.h
 * \brief Header file for routerparse.c.
 **/

#ifndef _TOR_ROUTERPARSE_H
#define _TOR_ROUTERPARSE_H

int router_get_router_hash(const char *s, size_t s_len, char *digest);
int router_get_dir_hash(const char *s, char *digest);
int router_get_runningrouters_hash(const char *s, char *digest);
int router_get_networkstatus_v2_hash(const char *s, char *digest);
int router_get_networkstatus_v3_hash(const char *s, char *digest,
                                     digest_algorithm_t algorithm);
int router_get_networkstatus_v3_hashes(const char *s, digests_t *digests);
int router_get_extrainfo_hash(const char *s, char *digest);
#define DIROBJ_MAX_SIG_LEN 256
int router_append_dirobj_signature(char *buf, size_t buf_len,
                                   const char *digest,
                                   size_t digest_len,
                                   crypto_pk_env_t *private_key);
int router_parse_list_from_string(const char **s, const char *eos,
                                  smartlist_t *dest,
                                  saved_location_t saved_location,
                                  int is_extrainfo,
                                  int allow_annotations,
                                  const char *prepend_annotations);
int router_parse_runningrouters(const char *str);
int router_parse_directory(const char *str);

routerinfo_t *router_parse_entry_from_string(const char *s, const char *end,
                                             int cache_copy,
                                             int allow_annotations,
                                             const char *prepend_annotations);
extrainfo_t *extrainfo_parse_entry_from_string(const char *s, const char *end,int cache_copy, struct digest_ri_map_t *routermap);
addr_policy_t *router_parse_addr_policy_item_from_string(const char *s,
                                                  int assume_action);
version_status_t tor_version_is_obsolete(const char *myversion,
                                         const char *versionlist);
int tor_version_parse(const char *s, tor_version_t *out);
int tor_version_as_new_as(const char *platform, const char *cutoff);
int tor_version_compare(tor_version_t *a, tor_version_t *b);
int tor_version_same_series(tor_version_t *a, tor_version_t *b);
void sort_version_list(smartlist_t *lst, int remove_duplicates);
void assert_addr_policy_ok(smartlist_t *t);
void dump_distinct_digest_count(int severity);

int compare_routerstatus_entries(const void **_a, const void **_b);
networkstatus_v2_t *networkstatus_v2_parse_from_string(const char *s);
int networkstatus_verify_bw_weights(networkstatus_t *ns);
networkstatus_t *networkstatus_parse_vote_from_string(const char *s,
                                                 const char **eos_out,
                                                 networkstatus_type_t ns_type);
ns_detached_signatures_t *networkstatus_parse_detached_signatures(
                                          const char *s, const char *eos);

smartlist_t *microdescs_parse_from_string(const char *s, const char *eos,
                                          int allow_annotations,
                                          int copy_body);

authority_cert_t *authority_cert_parse_from_string(const char *s,
                                                   const char **end_of_string);
int rend_parse_v2_service_descriptor(rend_service_descriptor_t **parsed_out,
                                     char *desc_id_out,
                                     char **intro_points_encrypted_out,
                                     size_t *intro_points_encrypted_size_out,
                                     size_t *encoded_size_out,
                                     const char **next_out, const char *desc);
int rend_decrypt_introduction_points(char **ipos_decrypted,
                                     size_t *ipos_decrypted_size,
                                     const char *descriptor_cookie,
                                     const char *ipos_encrypted,
                                     size_t ipos_encrypted_size);
int rend_parse_introduction_points(rend_service_descriptor_t *parsed,
                                   const char *intro_points_encoded,
                                   size_t intro_points_encoded_size);
int rend_parse_client_keys(strmap_t *parsed_clients, const char *str);
void set_router_id(routerinfo_t *router);
#endif

