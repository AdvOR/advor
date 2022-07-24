/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendservice.h
 * \brief Header file for rendservice.c.
 **/

#ifndef _TOR_RENDSERVICE_H
#define _TOR_RENDSERVICE_H

/** Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struct rend_service_port_config_t {
  uint16_t virtual_port;
  uint16_t real_port;
  tor_addr_t real_addr;
} rend_service_port_config_t;

/** Represents a single hidden service running at this OP. */
typedef struct rend_service_t {
  /* Fields specified in config file */
  char *directory; /**< where in the filesystem it stores it */
  smartlist_t *ports; /**< List of rend_service_port_config_t */
  rend_auth_type_t auth_type; /**< Client authorization type or 0 if no client
                               * authorization is performed. */
  smartlist_t *clients; /**< List of rend_authorized_client_t's of
                         * clients that may access our service. Can be NULL
                         * if no client authorization is performed. */
  /* Other fields */
  crypto_pk_env_t *private_key; /**< Permanent hidden-service key. */
  char plugin[MAX_PATH+1];
  char service_id[REND_SERVICE_ID_LEN_BASE32+1]; /**< Onion address without
                                                  * '.onion' */
  char pk_digest[DIGEST_LEN]; /**< Hash of permanent hidden-service key. */
  smartlist_t *intro_nodes; /**< List of rend_intro_point_t's we have,
                             * or are trying to establish. */
  time_t intro_period_started; /**< Start of the current period to build
                                * introduction points. */
  int n_intro_circuits_launched; /**< Count of intro circuits we have
                                  * established in this period. */
  rend_service_descriptor_t *desc; /**< Current hidden service descriptor. */
  time_t desc_is_dirty; /**< Time at which changes to the hidden service
                         * descriptor content occurred, or 0 if it's
                         * up-to-date. */
  time_t next_upload_time; /**< Scheduled next hidden service descriptor
                            * upload time. */
  /** Map from digests of Diffie-Hellman values INTRODUCE2 to time_t of when
   * they were received; used to prevent replays. */
  digestmap_t *accepted_intros;
  int disabled;
  /** Time at which we last removed expired values from accepted_intros. */
  time_t last_cleaned_accepted_intros;
} rend_service_t;


int num_rend_services(void);
int rend_config_services(or_options_t *options, int validate_only);
int rend_service_load_keys(void);
void rend_services_introduce(void);
void rend_consider_services_upload(time_t now);
void rend_hsdir_routers_changed(void);
void rend_consider_descriptor_republication(void);

void rend_service_intro_has_opened(origin_circuit_t *circuit);
int rend_service_intro_established(origin_circuit_t *circuit,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_service_rendezvous_has_opened(origin_circuit_t *circuit);
int rend_service_introduce(origin_circuit_t *circuit, const uint8_t *request,
                           size_t request_len);
void rend_service_relaunch_rendezvous(origin_circuit_t *oldcirc);
int rend_service_set_connection_addr_port(edge_connection_t *conn,
                                          origin_circuit_t *circ);
void rend_service_dump_stats(int severity);
void rend_service_free_all(void);
long rend_add_new_service(char *realPorts,char *virtualPorts,char *hostname,char *onionAddress);
rend_service_t* find_service_by_key(unsigned long key);
void insert_services(void);
void insertService(rend_service_t *ptr);
void set_publish_time(unsigned long key);
BOOL delete_service(unsigned long key);
void getHSKey(rend_service_t *service);
void genHSKey(rend_service_t *service,char **prefix);
void set_hs_key(char *keystr,rend_service_t *service);
void rend_service_disable(unsigned long serviceKey);
void rend_service_enable(unsigned long serviceKey);

#endif

