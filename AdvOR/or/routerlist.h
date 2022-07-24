/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerlist.h
 * \brief Header file for routerlist.c.
 **/

#ifndef _TOR_ROUTERLIST_H
#define _TOR_ROUTERLIST_H

int get_n_authorities(authority_type_t type);
int trusted_dirs_reload_certs(void);
int trusted_dirs_load_certs_from_string(const char *contents, int from_store,
                                        int flush);
void trusted_dirs_flush_certs_to_disk(void);
authority_cert_t *authority_cert_get_newest_by_id(const char *id_digest);
authority_cert_t *authority_cert_get_by_sk_digest(const char *sk_digest);
authority_cert_t *authority_cert_get_by_digests(const char *id_digest,
                                                const char *sk_digest);
void authority_cert_get_all(smartlist_t *certs_out);
void authority_cert_dl_failed(const char *id_digest, int status);
void authority_certs_fetch_missing(networkstatus_t *status, time_t now);
int router_reload_router_list(void);
int authority_cert_dl_looks_uncertain(const char *id_digest);
smartlist_t *router_get_trusted_dir_servers(void);

routerstatus_t *router_pick_directory_server(authority_type_t type, int flags);
trusted_dir_server_t *router_get_trusteddirserver_by_digest(const char *d);
trusted_dir_server_t *trusteddirserver_get_by_v3_auth_digest(const char *d);
routerstatus_t *router_pick_trusteddirserver(authority_type_t type, int flags);
int router_get_my_share_of_directory_requests(double *v2_share_out,
                                              double *v3_share_out);
void router_reset_status_download_failures(void);
void routerlist_add_family(smartlist_t *sl, routerinfo_t *router);
int routers_in_same_family(routerinfo_t *r1, routerinfo_t *r2);
int routers_have_same_or_addr(const routerinfo_t *r1, const routerinfo_t *r2);
void add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                                    int must_be_running);
int router_nickname_is_in_list(routerinfo_t *router, const char *list);
routerinfo_t *routerlist_find_my_routerinfo(void);
routerinfo_t *router_find_exact_exit_enclave(const char *address,
                                             uint16_t port);
int router_is_unreliable(routerinfo_t *router, int need_uptime,
                         int need_capacity, int need_guard);
uint32_t router_get_advertised_bandwidth(routerinfo_t *router);
uint32_t router_get_advertised_bandwidth_capped(routerinfo_t *router);

routerinfo_t *routerlist_sl_choose_by_bandwidth(smartlist_t *sl,
                                                bandwidth_weight_rule_t rule);
routerstatus_t *routerstatus_sl_choose_by_bandwidth(smartlist_t *sl,
                                                bandwidth_weight_rule_t rule);

routerinfo_t *router_choose_random_node(smartlist_t *excludedsmartlist,
                                        struct routerset_t *excludedset,
                                        router_crn_flags_t flags);

routerinfo_t *router_get_by_nickname(const char *nickname,
                                     int warn_if_unnamed);
int router_digest_version_as_new_as(const char *digest, const char *cutoff);
int router_digest_is_trusted_dir_type(const char *digest,
                                      authority_type_t type);
#define router_digest_is_trusted_dir(d) \
  router_digest_is_trusted_dir_type((d), NO_AUTHORITY)

int router_addr_is_trusted_dir(uint32_t addr);
int hexdigest_to_digest(const char *hexdigest, char *digest);
routerinfo_t *router_get_by_hexdigest(const char *hexdigest);
routerinfo_t *router_get_by_digest(const char *digest);
signed_descriptor_t *router_get_by_descriptor_digest(const char *digest);
signed_descriptor_t *router_get_by_extrainfo_digest(const char *digest);
signed_descriptor_t *extrainfo_get_by_descriptor_digest(const char *digest);
const char *signed_descriptor_get_body(signed_descriptor_t *desc);
const char *signed_descriptor_get_annotations(signed_descriptor_t *desc);
routerlist_t *router_get_routerlist(void);
void routerinfo_free(routerinfo_t *router);
#ifdef DEBUG_MALLOC
void extrainfo_free(extrainfo_t *extrainfo,const char *,int);
#define EXTRAINFO_FREE(n) extrainfo_free(n,__FILE__,__LINE__)
#else
void extrainfo_free(extrainfo_t *extrainfo);
#define EXTRAINFO_FREE(n) extrainfo_free(n)
#endif
void routerlist_free(routerlist_t *rl);
void dump_routerlist_mem_usage(int severity);
void routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int make_old,
                       time_t now);
void routerlist_free_all(void);
void routerlist_reset_warnings(void);
void router_set_status(const char *digest, int up);

static int WRA_WAS_ADDED(was_router_added_t s);
static int WRA_WAS_OUTDATED(was_router_added_t s);
static int WRA_WAS_REJECTED(was_router_added_t s);
/** Return true iff the descriptor was added. It might still be necessary to
 * check whether the descriptor generator should be notified.
 */
static INLINE int
WRA_WAS_ADDED(was_router_added_t s) {
  return s == ROUTER_ADDED_SUCCESSFULLY || s == ROUTER_ADDED_NOTIFY_GENERATOR;
}
/** Return true iff the descriptor was not added because it was either:
 * - not in the consensus
 * - neither in the consensus nor in any networkstatus document
 * - it was outdated.
 */
static INLINE int WRA_WAS_OUTDATED(was_router_added_t s)
{
  return (s == ROUTER_WAS_NOT_NEW ||
          s == ROUTER_NOT_IN_CONSENSUS ||
          s == ROUTER_NOT_IN_CONSENSUS_OR_NETWORKSTATUS);
}
static INLINE int WRA_WAS_REJECTED(was_router_added_t s)
{
  return (s == ROUTER_AUTHDIR_REJECTS);
}
was_router_added_t router_add_to_routerlist(routerinfo_t *router,
                                            const char **msg,
                                            int from_cache,
                                            int from_fetch);
was_router_added_t router_add_extrainfo_to_routerlist(
                                        extrainfo_t *ei, const char **msg,
                                        int from_cache, int from_fetch);
void routerlist_descriptors_added(smartlist_t *sl, int from_cache);
void routerlist_remove_old_routers(void);
int router_load_single_router(const char *s, uint8_t purpose, int cache,
                              const char **msg);
int router_load_routers_from_string(const char *s, const char *eos,
                                     saved_location_t saved_location,
                                     smartlist_t *requested_fingerprints,
                                     int descriptor_digests,
                                     const char *prepend_annotations);
void router_load_extrainfo_from_string(const char *s, const char *eos,
                                       saved_location_t saved_location,
                                       smartlist_t *requested_fingerprints,
                                       int descriptor_digests);

void routerlist_retry_directory_downloads(time_t now);
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime);
int router_exit_policy_rejects_all(routerinfo_t *router);
trusted_dir_server_t *add_trusted_dir_server(const char *nickname,
                           const char *address,
                           uint16_t dir_port, uint16_t or_port,
                           const char *digest, const char *v3_auth_digest,
                           authority_type_t type);
void authority_cert_free(authority_cert_t *cert);
void clear_trusted_dir_servers(void);
int any_trusted_dir_is_v1_authority(void);
void update_consensus_router_descriptor_downloads(time_t now, int is_vote,
                                                  networkstatus_t *consensus);
void update_router_descriptor_downloads(time_t now);
void update_extrainfo_downloads(time_t now);
int router_have_minimum_dir_info(void);
void router_dir_info_changed(void);
const char *get_dir_info_status_string(void);
int count_loading_descriptors_progress(void);
void router_reset_descriptor_download_failures(void);
int router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2);
int routerinfo_incompatible_with_extrainfo(routerinfo_t *ri, extrainfo_t *ei,
                                           signed_descriptor_t *sd,
                                           const char **msg);

void routerlist_assert_ok(routerlist_t *rl);
const char *esc_router_info(routerinfo_t *router);
void routers_sort_by_identity(smartlist_t *routers);

routerset_t *routerset_new(void);
int routerset_parse(routerset_t *target, const char *s,
                    const char *description);
void routerset_union(routerset_t *target, const routerset_t *source);
int routerset_is_list(const routerset_t *set);
int routerset_needs_geoip(const routerset_t *set);
int routerset_is_empty(const routerset_t *set);
int routerset_contains_router(const routerset_t *set, routerinfo_t *ri);
int routerset_contains_routerstatus(const routerset_t *set,
                                    routerstatus_t *rs);
int routerset_contains_extendinfo(const routerset_t *set,
                                  const extend_info_t *ei);
void routerset_get_all_routers(smartlist_t *out, const routerset_t *routerset,
                               const routerset_t *excludeset,
                               int running_only);
void routersets_get_disjunction(smartlist_t *target, const smartlist_t *source,
                                const routerset_t *include,
                                const routerset_t *exclude, int running_only);
void routerset_subtract_routers(smartlist_t *out,
                                const routerset_t *routerset);
char *routerset_to_string(const routerset_t *routerset);
void routerset_refresh_countries(routerset_t *target);
int routerset_equal(const routerset_t *old, const routerset_t *new);
void routerset_free(routerset_t *routerset);
void routerinfo_set_country(routerinfo_t *ri);
void routerlist_refresh_countries(void);
void refresh_all_country_info(void);

int hid_serv_get_responsible_directories(smartlist_t *responsible_dirs,
                                         const char *id);
int hid_serv_acting_as_directory(void);
int hid_serv_responsible_for_desc_id(const char *id);

int get_country_sel(void);
void set_country_sel(int newSel,int showlog);
uint32_t get_router_sel(void);
void set_router_sel(uint32_t newSel,int showlog);
uint32_t get_router_id_sel(void);
void set_router_id_sel(uint32_t newSel,int showlog);
void getRandomExitNode(unsigned char scope_id,unsigned char circuit_pos,char *country,uint32_t ip_range_low,uint32_t ip_range_high,uint32_t bandwidth,char *router_digest,char *reply);
uint32_t routerlist_reindex(void);
char *print_router_sel(void);

void add_all_routers_to_list(HWND hDlg,int selType,int last_country_sel);
routerinfo_t *get_router(uint32_t i);
BOOL is_selected_router(uint32_t addr,uint32_t routerid,DWORD exclKey);
char *find_router_by_ip(uint32_t addr);
routerinfo_t *get_router_by_ip(uint32_t addr);
char *find_router_by_index(int idx);
routerinfo_t *get_router_by_index(int idx);
char *find_router_by_ip_port(uint32_t addr,int port);
routerinfo_t *find_routerinfo_by_ip_port(uint32_t addr,int port);
char *get_router_name(routerinfo_t *router);
void add_routers_to_menu(HMENU hMenu1);
void add_favorite_entries_to_menu(HMENU hMenu1);
uint32_t get_menu_selection(int sel);
int get_random_router_index(int selType,int last_country_sel);
routerinfo_t *find_identity_hash(const routerlist_t *rl,const char *digest);
routerinfo_t *set_identity_hash(const routerlist_t *rl,routerinfo_t *r);
void routerlist_refresh_iplist(void);

#endif

