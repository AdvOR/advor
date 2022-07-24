/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dirvote.h
 * \brief Header file for dirvote.c.
 **/

#ifndef _TOR_DIRVOTE_H
#define _TOR_DIRVOTE_H

/** Lowest allowable value for VoteSeconds. */
#define MIN_VOTE_SECONDS 20
/** Lowest allowable value for DistSeconds. */
#define MIN_DIST_SECONDS 20
/** Smallest allowable voting interval. */
#define MIN_VOTE_INTERVAL 300

void dirvote_free_all(void);

/* vote manipulation */
char *networkstatus_compute_consensus(smartlist_t *votes,
                                      int total_authorities,
                                      crypto_pk_env_t *identity_key,
                                      crypto_pk_env_t *signing_key,
                                      const char *legacy_identity_key_digest,
                                      crypto_pk_env_t *legacy_signing_key,
                                      consensus_flavor_t flavor) __attribute__ ((format(printf, 5, 0)));
int networkstatus_add_detached_signatures(networkstatus_t *target,
                                          ns_detached_signatures_t *sigs,
                                          const char **msg_out);
char *networkstatus_get_detached_signatures(smartlist_t *consensuses);
void ns_detached_signatures_free(ns_detached_signatures_t *s);

/* cert manipulation */
authority_cert_t *authority_cert_dup(authority_cert_t *cert);

/* vote scheduling */
void dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out);
time_t dirvote_get_start_of_next_interval(time_t now, int interval);
void dirvote_recalculate_timing(or_options_t *options, time_t now);
void dirvote_act(or_options_t *options, time_t now);

/* invoked on timers and by outside triggers. */
struct pending_vote_t * dirvote_add_vote(const char *vote_body,
                                         const char **msg_out,
                                         int *status_out);
int dirvote_add_signatures(const char *detached_signatures_body,
                           const char *source,
                           const char **msg_out);

/* Item access */
const char *dirvote_get_pending_consensus(consensus_flavor_t flav);
const char *dirvote_get_pending_detached_signatures(void);
#define DGV_BY_ID 1
#define DGV_INCLUDE_PENDING 2
#define DGV_INCLUDE_PREVIOUS 4
const cached_dir_t *dirvote_get_vote(const char *fp, int flags);
void set_routerstatus_from_routerinfo(routerstatus_t *rs,
                                      routerinfo_t *ri, time_t now,
                                      int naming, int listbadexits,
                                      int listbaddirs, int vote_on_hsdirs);
void router_clear_status_flags(routerinfo_t *ri);
networkstatus_t *
dirserv_generate_networkstatus_vote_obj(crypto_pk_env_t *private_key,
                                        authority_cert_t *cert);

microdesc_t *dirvote_create_microdescriptor(const routerinfo_t *ri);
ssize_t dirvote_format_microdesc_vote_line(char *out, size_t out_len,
                                       const microdesc_t *md);

int vote_routerstatus_find_microdesc_hash(char *digest256_out,
                                          const vote_routerstatus_t *vrs,
                                          int method,
                                          digest_algorithm_t alg);
document_signature_t *voter_get_sig_by_algorithm(
                           const networkstatus_voter_info_t *voter,
                           digest_algorithm_t alg);

#ifdef DIRVOTE_PRIVATE
char *format_networkstatus_vote(crypto_pk_env_t *private_key,
                                 networkstatus_t *v3_ns);
char *dirvote_compute_params(smartlist_t *votes);
#endif

#endif

