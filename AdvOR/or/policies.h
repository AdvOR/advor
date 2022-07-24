/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file policies.h
 * \brief Header file for policies.c.
 **/

#ifndef _TOR_POLICIES_H
#define _TOR_POLICIES_H

/* (length of "accept 255.255.255.255/255.255.255.255:65535-65535\n" plus a
 * NUL.)
 */
#define POLICY_BUF_LEN 52

int firewall_is_fascist_or(void);
int fascist_firewall_allows_address_or(const tor_addr_t *addr, uint16_t port);
int fascist_firewall_allows_or(routerinfo_t *ri);
int fascist_firewall_allows_address_dir(const tor_addr_t *addr, uint16_t port);
int dir_policy_permits_address(const tor_addr_t *addr);
int socks_policy_permits_address(const tor_addr_t *addr);
int authdir_policy_permits_address(uint32_t addr, uint16_t port);
int authdir_policy_valid_address(uint32_t addr, uint16_t port);
int authdir_policy_baddir_address(uint32_t addr, uint16_t port);
int authdir_policy_badexit_address(uint32_t addr, uint16_t port);

int validate_addr_policies(or_options_t *options, unsigned char **msg);
void policy_expand_private(smartlist_t **policy);
int policies_parse_from_options(or_options_t *options);

addr_policy_t *addr_policy_get_canonical_entry(addr_policy_t *ent);
int cmp_addr_policies(smartlist_t *a, smartlist_t *b);
addr_policy_result_t compare_tor_addr_to_addr_policy(const tor_addr_t *addr,
                              uint16_t port, const smartlist_t *policy);
addr_policy_result_t compare_addr_to_addr_policy(uint32_t addr,
                              uint16_t port, const smartlist_t *policy);
int policies_parse_exit_policy(config_line_t *cfg, smartlist_t **dest,
                               int rejectprivate, const char *local_address,
                               int add_default_policy);
void policies_exit_policy_append_reject_star(smartlist_t **dest);
void policies_set_router_exitpolicy_to_reject_all(routerinfo_t *exitrouter);
int exit_policy_is_general_exit(smartlist_t *policy);
int policy_is_reject_star(const smartlist_t *policy);
int getinfo_helper_policies(control_connection_t *conn,
                            const char *question, char **answer,
                            const char **errmsg);
int policy_write_item(char *buf, size_t buflen, addr_policy_t *item,
                      int format_for_desc);

void addr_policy_list_free(smartlist_t *p);
void addr_policy_free(addr_policy_t *p);
void policies_free_all(void);

char *policy_summarize(smartlist_t *policy);

#endif

