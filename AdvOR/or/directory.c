/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "control.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "geoip.h"
#include "main.h"
#include "networkstatus.h"
#include "policies.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "connection_proxy.h"

#if defined(EXPORTMALLINFO) && defined(HAVE_MALLOC_H) && defined(HAVE_MALLINFO)
#ifndef OPENBSD
#include <malloc.h>
#endif
#endif

/**
 * \file directory.c
 * \brief Code to send and fetch directories and router
 * descriptors via HTTP.  Directories use dirserv.c to generate the
 * results; clients use routers.c to parse them.
 **/

/* In-points to directory.c:
 *
 * - directory_post_to_dirservers(), called from
 *   router_upload_dir_desc_to_dirservers() in router.c
 *   upload_service_descriptor() in rendservice.c
 * - directory_get_from_dirserver(), called from
 *   rend_client_refetch_renddesc() in rendclient.c
 *   run_scheduled_events() in main.c
 *   do_hup() in main.c
 * - connection_dir_process_inbuf(), called from
 *   connection_process_inbuf() in connection.c
 * - connection_dir_finished_flushing(), called from
 *   connection_finished_flushing() in connection.c
 * - connection_dir_finished_connecting(), called from
 *   connection_finished_connecting() in connection.c
 */
static void directory_send_command(dir_connection_t *conn,
                             int purpose, int direct, const char *resource,
                             const char *payload, size_t payload_len,
                             int supports_conditional_consensus,
                             time_t if_modified_since) __attribute__ ((format(printf, 4, 0)));
static int directory_handle_command(dir_connection_t *conn);
static int body_is_plausible(const char *body, size_t body_len, int purpose);
static int purpose_needs_anonymity(uint8_t dir_purpose,
                                   uint8_t router_purpose);
static char *http_get_header(const char *headers, const char *which);
static void http_set_address_origin(const char *headers, connection_t *conn);
static void connection_dir_download_v2_networkstatus_failed(
                               dir_connection_t *conn, int status_code);
static void connection_dir_download_routerdesc_failed(dir_connection_t *conn);
static void connection_dir_bridge_routerdesc_failed(dir_connection_t *conn);
static void connection_dir_download_cert_failed(
                               dir_connection_t *conn, int status_code);
static void connection_dir_retry_bridges(smartlist_t *descs);
static void dir_networkstatus_download_failed(smartlist_t *failed,
                                              int status_code);
static void dir_routerdesc_download_failed(smartlist_t *failed,
                                           int status_code,
                                           int router_purpose,
                                           int was_extrainfo,
                                           int was_descriptor_digests);
static void note_client_request(int purpose, int compressed, size_t bytes);
static int client_likes_consensus(networkstatus_t *v, const char *want_url);

static void directory_initiate_command_rend(const char *address,
                                            const tor_addr_t *addr,
                                            uint16_t or_port,
                                            uint16_t dir_port,
                                            int supports_conditional_consensus,
                                            int supports_begindir,
                                            const char *digest,
                                            uint8_t dir_purpose,
                                            uint8_t router_purpose,
                                            int anonymized_connection,
                                            const char *resource,
                                            const char *payload,
                                            size_t payload_len,
                                            time_t if_modified_since,
                                            const rend_data_t *rend_query) __attribute__ ((format(printf, 1, 0)));

/********* START VARIABLES **********/

/** How far in the future do we allow a directory server to tell us it is
 * before deciding that one of us has the wrong time? */
#define ALLOW_DIRECTORY_TIME_SKEW (30*60)

#define X_ADDRESS_HEADER "X-Your-Address-Is: "

/** HTTP cache control: how long do we tell proxies they can cache each
 * kind of document we serve? */
#define FULL_DIR_CACHE_LIFETIME (60*60)
#define RUNNINGROUTERS_CACHE_LIFETIME (20*60)
#define DIRPORTFRONTPAGE_CACHE_LIFETIME (20*60)
#define NETWORKSTATUS_CACHE_LIFETIME (5*60)
#define ROUTERDESC_CACHE_LIFETIME (30*60)
#define ROUTERDESC_BY_DIGEST_CACHE_LIFETIME (48*60*60)
#define ROBOTS_CACHE_LIFETIME (24*60*60)
#define MICRODESC_CACHE_LIFETIME (48*60*60)

/********* END VARIABLES ************/

/** Return true iff the directory purpose 'purpose' must use an
 * anonymous connection to a directory. */
static int
purpose_needs_anonymity(uint8_t dir_purpose, uint8_t router_purpose)
{
  if (get_options()->AllDirActionsPrivate)
    return 1;
  if (router_purpose == ROUTER_PURPOSE_BRIDGE && can_complete_circuit)
    return 1; /* if no circuits yet, we may need this info to bootstrap. */
  if (dir_purpose == DIR_PURPOSE_UPLOAD_DIR ||
      dir_purpose == DIR_PURPOSE_UPLOAD_VOTE ||
      dir_purpose == DIR_PURPOSE_UPLOAD_SIGNATURES ||
      dir_purpose == DIR_PURPOSE_FETCH_V2_NETWORKSTATUS ||
      dir_purpose == DIR_PURPOSE_FETCH_STATUS_VOTE ||
      dir_purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES ||
      dir_purpose == DIR_PURPOSE_FETCH_CONSENSUS ||
      dir_purpose == DIR_PURPOSE_FETCH_CERTIFICATE ||
      dir_purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
      dir_purpose == DIR_PURPOSE_FETCH_EXTRAINFO)
    return 0;
  return 1;
}

/** Return a newly allocated string describing <b>auth</b>. */
char *
authority_type_to_string(authority_type_t auth)
{
  char *result;
  smartlist_t *lst = smartlist_create();
  if (auth & V1_AUTHORITY)
    smartlist_add(lst, (void*)"V1");
  if (auth & V2_AUTHORITY)
    smartlist_add(lst, (void*)"V2");
  if (auth & V3_AUTHORITY)
    smartlist_add(lst, (void*)"V3");
  if (auth & BRIDGE_AUTHORITY)
    smartlist_add(lst, (void*)"Bridge");
  if (auth & HIDSERV_AUTHORITY)
    smartlist_add(lst, (void*)"Hidden service");
  if (smartlist_len(lst)) {
    result = smartlist_join_strings(lst, ", ", 0, NULL);
  } else {
    result = tor_strdup("[Not an authority]");
  }
  smartlist_free(lst);
  return result;
}

/** Return a string describing a given directory connection purpose. */
const char *dir_conn_purpose_to_string(int purpose)
{
  switch (purpose)
    {
    case DIR_PURPOSE_FETCH_RENDDESC:
      return get_lang_str(LANG_LOG_DIR_P_HS_FETCH);
    case DIR_PURPOSE_UPLOAD_DIR:
      return get_lang_str(LANG_LOG_DIR_P_DESCRIPTOR_UPLOAD);
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      return get_lang_str(LANG_LOG_DIR_P_HS_DESC_UPLOAD);
    case DIR_PURPOSE_UPLOAD_VOTE:
      return get_lang_str(LANG_LOG_DIR_P_VOTE_UPLOAD);
    case DIR_PURPOSE_UPLOAD_SIGNATURES:
      return get_lang_str(LANG_LOG_DIR_P_CONSENSUS_SIGNATURE_UPLOAD);
    case DIR_PURPOSE_FETCH_V2_NETWORKSTATUS:
      return get_lang_str(LANG_LOG_DIR_P_NETWORKSTATUS_FETCH);
    case DIR_PURPOSE_FETCH_SERVERDESC:
      return get_lang_str(LANG_LOG_DIR_P_SERVER_DESC_FETCH);
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      return get_lang_str(LANG_LOG_DIR_P_EXTRA_INFO_FETCH);
    case DIR_PURPOSE_FETCH_CONSENSUS:
      return get_lang_str(LANG_LOG_DIR_P_CONSENSUS_NETWORKSTATUS_FETCH);
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      return get_lang_str(LANG_LOG_DIR_P_AUTH_CERT_FETCH);
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
      return get_lang_str(LANG_LOG_DIR_P_STATUS_VOTE_FETCH);
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
      return get_lang_str(LANG_LOG_DIR_P_CONSENSUS_SIGNATURE_FETCH);
    case DIR_PURPOSE_FETCH_RENDDESC_V2:
      return get_lang_str(LANG_LOG_DIR_P_HSV2_DESC_FETCH);
    case DIR_PURPOSE_UPLOAD_RENDDESC_V2:
      return get_lang_str(LANG_LOG_DIR_P_HSV2_DESC_UPLOAD);
    }

  log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_UNKNOWN_PURPOSE),purpose);
  return get_lang_str(LANG_LOG_DIR_P_UNKNOWN);
}

/** Return true iff <b>identity_digest</b> is the digest of a router we
 * believe to support extrainfo downloads.  (If <b>is_authority</b> we do
 * additional checking that's only valid for authorities.) */
int
router_supports_extrainfo(const char *identity_digest, int is_authority)
{
  routerinfo_t *ri = router_get_by_digest(identity_digest);

  if (ri) {
    if (ri->caches_extra_info)
      return 1;
    if (is_authority && ri->platform &&
        tor_version_as_new_as(ri->platform, "Tor 0.2.0.0-alpha-dev (r10070)"))
      return 1;
  }
  if (is_authority) {
    routerstatus_t *rs = router_get_consensus_status_by_id(identity_digest);
    if (rs && rs->version_supports_extrainfo_upload)
      return 1;
  }
  return 0;
}

/** Return true iff any trusted directory authority has accepted our
 * server descriptor.
 *
 * We consider any authority sufficient because waiting for all of
 * them means it never happens while any authority is down; we don't
 * go for something more complex in the middle (like \>1/3 or \>1/2 or
 * \>=1/2) because that doesn't seem necessary yet.
 */
int
directories_have_accepted_server_descriptor(void)
{
  smartlist_t *servers = router_get_trusted_dir_servers();
  or_options_t *options = get_options();
  SMARTLIST_FOREACH(servers, trusted_dir_server_t *, d, {
    if ((d->type & options->_PublishServerDescriptor) &&
        d->has_accepted_serverdesc) {
      return 1;
    }
  });
  return 0;
}

/** Start a connection to every suitable directory authority, using
 * connection purpose 'purpose' and uploading the payload 'payload'
 * (length 'payload_len').  The purpose should be one of
 * 'DIR_PURPOSE_UPLOAD_DIR' or 'DIR_PURPOSE_UPLOAD_RENDDESC'.
 *
 * <b>type</b> specifies what sort of dir authorities (V1, V2,
 * HIDSERV, BRIDGE) we should upload to.
 *
 * If <b>extrainfo_len</b> is nonzero, the first <b>payload_len</b> bytes of
 * <b>payload</b> hold a router descriptor, and the next <b>extrainfo_len</b>
 * bytes of <b>payload</b> hold an extra-info document.  Upload the descriptor
 * to all authorities, and the extra-info document to all authorities that
 * support it.
 */
void
directory_post_to_dirservers(uint8_t dir_purpose, uint8_t router_purpose,
                             authority_type_t type,
                             const char *payload,
                             size_t payload_len, size_t extrainfo_len)
{
  or_options_t *options = get_options();
  int post_via_tor;
  smartlist_t *dirservers = router_get_trusted_dir_servers();
  int found = 0;
  const int exclude_self = (dir_purpose == DIR_PURPOSE_UPLOAD_VOTE ||
                            dir_purpose == DIR_PURPOSE_UPLOAD_SIGNATURES);
  tor_assert(dirservers);
  /* This tries dirservers which we believe to be down, but ultimately, that's
   * harmless, and we may as well err on the side of getting things uploaded.
   */
  SMARTLIST_FOREACH_BEGIN(dirservers, trusted_dir_server_t *, ds) {
      routerstatus_t *rs = &(ds->fake_status);
      size_t upload_len = payload_len;
      tor_addr_t ds_addr;

      if ((type & ds->type) == 0)
        continue;

      if (exclude_self && router_digest_is_me(ds->digest))
        continue;

      if (options->ExcludeNodes &&
          routerset_contains_routerstatus(options->ExcludeNodes, rs)) {
        log_warn(LD_DIR,get_lang_str(LANG_LOG_DIRECTORY_AUTHORITY_BANNED),ds->nickname,dir_conn_purpose_to_string(dir_purpose));
        continue;
      }

      found = 1; /* at least one authority of this type was listed */
      if (dir_purpose == DIR_PURPOSE_UPLOAD_DIR)
        ds->has_accepted_serverdesc = 0;

      if (extrainfo_len && router_supports_extrainfo(ds->digest, 1)) {
        upload_len += extrainfo_len;
        log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_UPLOADING_EXTRAINFO),(int) extrainfo_len);
      }
      tor_addr_from_ipv4h(&ds_addr, ds->addr);
      post_via_tor = purpose_needs_anonymity(dir_purpose, router_purpose) ||
        !fascist_firewall_allows_address_dir(&ds_addr, ds->dir_port);
      directory_initiate_command_routerstatus(rs, dir_purpose,
                                              router_purpose,
                                              post_via_tor,
                                              NULL, payload, upload_len, 0);
  } SMARTLIST_FOREACH_END(ds);
  if (!found) {
    char *s = authority_type_to_string(type);
    log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_NO_AUTH_SUPPORT),s);
    tor_free(s);
  }
}

/** Start a connection to a random running directory server, using
 * connection purpose <b>dir_purpose</b>, intending to fetch descriptors
 * of purpose <b>router_purpose</b>, and requesting <b>resource</b>.
 * Use <b>pds_flags</b> as arguments to router_pick_directory_server()
 * or router_pick_trusteddirserver().
 */
void
directory_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                             const char *resource, int pds_flags)
{
  routerstatus_t *rs = NULL;
  or_options_t *options = get_options();
  int prefer_authority = directory_fetches_from_authorities(options);
  int get_via_tor = purpose_needs_anonymity(dir_purpose, router_purpose);
  authority_type_t type;
  time_t if_modified_since = 0;

  /* FFFF we could break this switch into its own function, and call
   * it elsewhere in directory.c. -RD */
  switch (dir_purpose) {
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      type = EXTRAINFO_CACHE |
             (router_purpose == ROUTER_PURPOSE_BRIDGE ? BRIDGE_AUTHORITY :
                                                        V3_AUTHORITY);
      break;
    case DIR_PURPOSE_FETCH_V2_NETWORKSTATUS:
      type = V2_AUTHORITY;
      prefer_authority = 1; /* Only v2 authorities have these anyway. */
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      type = (router_purpose == ROUTER_PURPOSE_BRIDGE ? BRIDGE_AUTHORITY :
                                                        V3_AUTHORITY);
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      type = HIDSERV_AUTHORITY;
      break;
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
      type = V3_AUTHORITY;
      break;
    case DIR_PURPOSE_FETCH_CONSENSUS:
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      type = V3_AUTHORITY;
      break;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_UNEXPECTED_PURPOSE),(int)dir_purpose);
      return;
  }

  if (dir_purpose == DIR_PURPOSE_FETCH_CONSENSUS) {
    networkstatus_t *v = networkstatus_get_latest_consensus();
    if (v)
      if_modified_since = v->valid_after + 180;
  }

  if (!options->FetchServerDescriptors && type != HIDSERV_AUTHORITY)
    return;

  if (!get_via_tor) {
    if (options->UseBridges && type != BRIDGE_AUTHORITY) {
      /* want to ask a running bridge for which we have a descriptor. */
      /* XXX022 we assume that all of our bridges can answer any
       * possible directory question. This won't be true forever. -RD */
      /* It certainly is not true with conditional consensus downloading,
       * so, for now, never assume the server supports that. */
      routerinfo_t *ri = choose_random_entry(NULL);
      if (ri) {
        tor_addr_t addr;
        tor_addr_from_ipv4h(&addr, ri->addr);
        directory_initiate_command(ri->address, &addr,
                                   ri->or_port, 0,
                                   0, /* don't use conditional consensus url */
                                   1, ri->cache_info.identity_digest,
                                   dir_purpose,
                                   router_purpose,
                                   0, resource, NULL, 0, if_modified_since);
      } else
        log_notice(LD_DIR,get_lang_str(LANG_LOG_DIR_NO_BRIDGE_NODES_AVAIL));
      return;
    } else {
      if (prefer_authority || type == BRIDGE_AUTHORITY) {
        /* only ask authdirservers, and don't ask myself */
        rs = router_pick_trusteddirserver(type, pds_flags);
        if (rs == NULL && (pds_flags & PDS_NO_EXISTING_SERVERDESC_FETCH)) {
          /* We don't want to fetch from any authorities that we're currently
           * fetching server descriptors from, and we got no match.  Did we
           * get no match because all the authorities have connections
           * fetching server descriptors (in which case we should just
           * return,) or because all the authorities are down or on fire or
           * unreachable or something (in which case we should go on with
           * our fallback code)? */
          pds_flags &= ~PDS_NO_EXISTING_SERVERDESC_FETCH;
          rs = router_pick_trusteddirserver(type, pds_flags);
          if (rs) {
            log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_ALL_AUTHORITIES_IN_USE));
            return;
          }
        }
      }
      if (!rs && type != BRIDGE_AUTHORITY) {
        /* anybody with a non-zero dirport will do */
        rs = router_pick_directory_server(type, pds_flags);
        if (!rs) {
          log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_NO_ROUTER_FOUND),dir_conn_purpose_to_string(dir_purpose));
          rs = router_pick_trusteddirserver(type, pds_flags);
          if (!rs)
            get_via_tor = 1; /* last resort: try routing it via Tor */
        }
      }
    }
  } else { /* get_via_tor */
    /* Never use fascistfirewall; we're going via Tor. */
    if (dir_purpose == DIR_PURPOSE_FETCH_RENDDESC) {
      /* only ask hidserv authorities, any of them will do */
      pds_flags |= PDS_IGNORE_FASCISTFIREWALL|PDS_ALLOW_SELF;
      rs = router_pick_trusteddirserver(HIDSERV_AUTHORITY, pds_flags);
    } else {
      /* anybody with a non-zero dirport will do. Disregard firewalls. */
      pds_flags |= PDS_IGNORE_FASCISTFIREWALL;
      rs = router_pick_directory_server(type, pds_flags);
      /* If we have any hope of building an indirect conn, we know some router
       * descriptors.  If (rs==NULL), we can't build circuits anyway, so
       * there's no point in falling back to the authorities in this case. */
    }
  }

  if (rs)
    directory_initiate_command_routerstatus(rs, dir_purpose,
                                            router_purpose,
                                            get_via_tor,
                                            resource, NULL, 0,
                                            if_modified_since);
  else {
    log_notice(LD_DIR,get_lang_str(LANG_LOG_DIR_NO_RUNNING_DIRSERVERS),dir_purpose);
    if (!purpose_needs_anonymity(dir_purpose, router_purpose)) {
      /* remember we tried them all and failed. */
      directory_all_unreachable(get_time(NULL));
    }
  }
}

/** As directory_get_from_dirserver, but initiates a request to <i>every</i>
 * directory authority other than ourself.  Only for use by authorities when
 * searching for missing information while voting. */
void
directory_get_from_all_authorities(uint8_t dir_purpose,
                                   uint8_t router_purpose,
                                   const char *resource)
{
  tor_assert(dir_purpose == DIR_PURPOSE_FETCH_STATUS_VOTE ||
             dir_purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES);

  SMARTLIST_FOREACH(router_get_trusted_dir_servers(),
                    trusted_dir_server_t *, ds,
    {
      routerstatus_t *rs;
      if (router_digest_is_me(ds->digest))
        continue;
      if (!(ds->type & V3_AUTHORITY))
        continue;
      rs = &ds->fake_status;
      directory_initiate_command_routerstatus(rs, dir_purpose, router_purpose,
                                              0, resource, NULL, 0, 0);
    });
}

/** Same as directory_initiate_command_routerstatus(), but accepts
 * rendezvous data to fetch a hidden service descriptor. */
void
directory_initiate_command_routerstatus_rend(routerstatus_t *status,
                                             uint8_t dir_purpose,
                                             uint8_t router_purpose,
                                             int anonymized_connection,
                                             const char *resource,
                                             const char *payload,
                                             size_t payload_len,
                                             time_t if_modified_since,
                                             const rend_data_t *rend_query)
{
  or_options_t *options = get_options();
  routerinfo_t *router;
  char address_buf[INET_NTOA_BUF_LEN+1];
  struct in_addr in;
  const char *address;
  tor_addr_t addr;
  router = router_get_by_digest(status->identity_digest);
  if (!router && anonymized_connection) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_NOT_ANONYMIZED),routerstatus_describe(status));
    return;
  } else if (router) {
    address = router->address;
  } else {
    in.s_addr = htonl(status->addr);
    tor_inet_ntoa(&in, address_buf, sizeof(address_buf));
    address = address_buf;
  }
  tor_addr_from_ipv4h(&addr, status->addr);
  if (options->ExcludeNodes && routerset_contains_routerstatus(options->ExcludeNodes, status)) {
    log_warn(LD_DIR,get_lang_str(LANG_LOG_DIRECTORY_MIRROR_BANNED),routerstatus_describe(status),dir_conn_purpose_to_string(dir_purpose));
    return;
  }

  directory_initiate_command_rend(address, &addr,
                             status->or_port, status->dir_port,
                             status->version_supports_conditional_consensus,
                             status->version_supports_begindir,
                             status->identity_digest,
                             dir_purpose, router_purpose,
                             anonymized_connection, resource,
                             payload, payload_len, if_modified_since,
                             rend_query);
}

/** Launch a new connection to the directory server <b>status</b> to
 * upload or download a server or rendezvous
 * descriptor. <b>dir_purpose</b> determines what
 * kind of directory connection we're launching, and must be one of
 * DIR_PURPOSE_{FETCH|UPLOAD}_{DIR|RENDDESC|RENDDESC_V2}. <b>router_purpose</b>
 * specifies the descriptor purposes we have in mind (currently only
 * used for FETCH_DIR).
 *
 * When uploading, <b>payload</b> and <b>payload_len</b> determine the content
 * of the HTTP post.  Otherwise, <b>payload</b> should be NULL.
 *
 * When fetching a rendezvous descriptor, <b>resource</b> is the service ID we
 * want to fetch.
 */
void
directory_initiate_command_routerstatus(routerstatus_t *status,
                                        uint8_t dir_purpose,
                                        uint8_t router_purpose,
                                        int anonymized_connection,
                                        const char *resource,
                                        const char *payload,
                                        size_t payload_len,
                                        time_t if_modified_since)
{
  directory_initiate_command_routerstatus_rend(status, dir_purpose,
                                          router_purpose,
                                          anonymized_connection, resource,
                                          payload, payload_len,
                                          if_modified_since, NULL);
}

/** Return true iff <b>conn</b> is the client side of a directory connection
 * we launched to ourself in order to determine the reachability of our
 * dir_port. */
static int
directory_conn_is_self_reachability_test(dir_connection_t *conn)
{
  if (conn->requested_resource &&
      !strcmpstart(conn->requested_resource,"authority")) {
    routerinfo_t *me = router_get_my_routerinfo();
    if (me &&
        router_digest_is_me(conn->identity_digest) &&
        tor_addr_eq_ipv4h(&conn->_base.addr, me->addr) && /*XXXX prop 118*/
        me->dir_port == conn->_base.port)
      return 1;
  }
  return 0;
}

/** Called when we are unable to complete the client's request to a directory
 * server due to a network error: Mark the router as down and try again if
 * possible.
 */
void
connection_dir_request_failed(dir_connection_t *conn)
{
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_NET_ERROR),conn->_base.address?conn->_base.address:"");updateDirStatus();
  if (directory_conn_is_self_reachability_test(conn)) {
    return; /* this was a test fetch. don't retry. */
  }
  if (!entry_list_is_constrained(get_options()))
    router_set_status(conn->identity_digest, 0); /* don't try him again */
  if (conn->_base.purpose == DIR_PURPOSE_FETCH_V2_NETWORKSTATUS) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_FAILED_1),conn->_base.address);
    connection_dir_download_v2_networkstatus_failed(conn, -1);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
             conn->_base.purpose == DIR_PURPOSE_FETCH_EXTRAINFO) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_FAILED_1),conn->_base.address);
    if (conn->router_purpose == ROUTER_PURPOSE_BRIDGE)
      connection_dir_bridge_routerdesc_failed(conn);
    connection_dir_download_routerdesc_failed(conn);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_CONSENSUS) {
    networkstatus_consensus_download_failed(0);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_CERTIFICATE) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_FAILED_1),conn->_base.address);
    connection_dir_download_cert_failed(conn, 0);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_FAILED_2),conn->_base.address);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_STATUS_VOTE) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_REQUEST_FAILED_3),conn->_base.address);
  }
}

/** Called when an attempt to download one or more network status
 * documents on connection <b>conn</b> failed. Decide whether to
 * retry the fetch now, later, or never.
 */
static void
connection_dir_download_v2_networkstatus_failed(dir_connection_t *conn,
                                             int status_code)
{
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_DL_ERROR),conn->_base.address?conn->_base.address:"");updateDirStatus();
  if (!conn->requested_resource) {
    /* We never reached directory_send_command, which means that we never
     * opened a network connection.  Either we're out of sockets, or the
     * network is down.  Either way, retrying would be pointless. */
    return;
  }
  if (!strcmpstart(conn->requested_resource, "all")) {
    /* We're a non-authoritative directory cache; try again. Ignore status
     * code, since we don't want to keep trying forever in a tight loop
     * if all the authorities are shutting us out. */
    smartlist_t *trusted_dirs = router_get_trusted_dir_servers();
    SMARTLIST_FOREACH(trusted_dirs, trusted_dir_server_t *, ds,
                      download_status_failed(&ds->v2_ns_dl_status, 0));
    directory_get_from_dirserver(conn->_base.purpose, conn->router_purpose,
                                 "all.z", 0 /* don't retry_if_no_servers */);
  } else if (!strcmpstart(conn->requested_resource, "fp/")) {
    /* We were trying to download by fingerprint; mark them all as having
     * failed, and possibly retry them later.*/
    smartlist_t *failed = smartlist_create();
    dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                         failed, NULL, 0);
    if (smartlist_len(failed)) {
      dir_networkstatus_download_failed(failed, status_code);
      SMARTLIST_FOREACH(failed, char *, cp, tor_free(cp));
    }
    smartlist_free(failed);
  }
}

/** Helper: Attempt to fetch directly the descriptors of each bridge listed in <b>failed</b>. */
static void connection_dir_retry_bridges(smartlist_t *descs)
{	char digest[DIGEST_LEN];
	SMARTLIST_FOREACH(descs, const char *, cp,
	{	if(base16_decode(digest, DIGEST_LEN, cp, strlen(cp))<0)
		{	char *esc_l = esc_for_log(cp);
			log_warn(LD_BUG,get_lang_str(LANG_LOG_DIRECTORY_MALFORMED_BRIDGE_FINGERPRINT),esc_l);
			tor_free(esc_l);
			continue;
		}
		retry_bridge_descriptor_fetch_directly(digest);
	});
}

/** Called when an attempt to download one or more router descriptors
 * or extra-info documents on connection <b>conn</b> failed.
 */
static void
connection_dir_download_routerdesc_failed(dir_connection_t *conn)
{
  /* No need to increment the failure count for routerdescs, since
   * it's not their fault. */
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_DESC_DL_ERROR),conn->_base.address?conn->_base.address:"");updateDirStatus();

  /* No need to relaunch descriptor downloads here: we already do it
   * every 10 or 60 seconds (FOO_DESCRIPTOR_RETRY_INTERVAL) in main.c. */
  tor_assert(conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
             conn->_base.purpose == DIR_PURPOSE_FETCH_EXTRAINFO);

  (void) conn;
}

/** Called when an attempt to download a bridge's routerdesc from one of the authorities failed due to a network error. If possible attempt to download descriptors from the bridge directly. */
static void connection_dir_bridge_routerdesc_failed(dir_connection_t *conn)
{	smartlist_t *which = NULL;
	/* Requests for bridge descriptors are in the form 'fp/', so ignore anything else. */
	if(!conn->requested_resource || strcmpstart(conn->requested_resource,"fp/"))
		return;
	which = smartlist_create();
	dir_split_resource_into_fingerprints(conn->requested_resource + strlen("fp/"),which, NULL, 0);
	tor_assert(conn->_base.purpose != DIR_PURPOSE_FETCH_EXTRAINFO);
	if(smartlist_len(which))
	{	connection_dir_retry_bridges(which);
		SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
	}
	smartlist_free(which);
}

/** Called when an attempt to fetch a certificate fails. */
static void
connection_dir_download_cert_failed(dir_connection_t *conn, int status)
{
  smartlist_t *failed;
  tor_assert(conn->_base.purpose == DIR_PURPOSE_FETCH_CERTIFICATE);
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_CERT_DL_ERROR),conn->_base.address?conn->_base.address:"");updateDirStatus();

  if (!conn->requested_resource)
    return;
  failed = smartlist_create();
  dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                       failed, NULL, DSR_HEX);
  SMARTLIST_FOREACH(failed, char *, cp,
  {
    authority_cert_dl_failed(cp, status);
    tor_free(cp);
  });
  smartlist_free(failed);

  update_certificate_downloads(get_time(NULL));
}

/** Evaluate the situation and decide if we should use an encrypted
 * "begindir-style" connection for this directory request.
 * 1) If or_port is 0, or it's a direct conn and or_port is firewalled
 *    or we're a dir mirror, no.
 * 2) If we prefer to avoid begindir conns, and we're not fetching or
 * publishing a bridge relay descriptor, no.
 * 3) Else yes.
 */
static int
directory_command_should_use_begindir(or_options_t *options,
                                      const tor_addr_t *addr,
                                      int or_port, uint8_t router_purpose,
                                      int anonymized_connection)
{
  if (!or_port)
    return 0; /* We don't know an ORPort -- no chance. */
  if (!anonymized_connection)
    if (!fascist_firewall_allows_address_or(addr, or_port) ||
        directory_fetches_from_authorities(options))
      return 0; /* We're firewalled or are acting like a relay -- also no. */
  if (!options->TunnelDirConns &&
      router_purpose != ROUTER_PURPOSE_BRIDGE)
    return 0; /* We prefer to avoid using begindir conns. Fine. */
  return 1;
}

/** Helper for directory_initiate_command_routerstatus: send the
 * command to a server whose address is <b>address</b>, whose IP is
 * <b>addr</b>, whose directory port is <b>dir_port</b>, whose tor version
 * <b>supports_begindir</b>, and whose identity key digest is
 * <b>digest</b>. */
void
directory_initiate_command(const char *address, const tor_addr_t *_addr,
                           uint16_t or_port, uint16_t dir_port,
                           int supports_conditional_consensus,
                           int supports_begindir, const char *digest,
                           uint8_t dir_purpose, uint8_t router_purpose,
                           int anonymized_connection, const char *resource,
                           const char *payload, size_t payload_len,
                           time_t if_modified_since)
{
  directory_initiate_command_rend(address, _addr, or_port, dir_port,
                             supports_conditional_consensus,
                             supports_begindir, digest, dir_purpose,
                             router_purpose, anonymized_connection,
                             resource, payload, payload_len,
                             if_modified_since, NULL);
}

/** Same as directory_initiate_command(), but accepts rendezvous data to
 * fetch a hidden service descriptor. */
static void
directory_initiate_command_rend(const char *address, const tor_addr_t *_addr,
                                uint16_t or_port, uint16_t dir_port,
                                int supports_conditional_consensus,
                                int supports_begindir, const char *digest,
                                uint8_t dir_purpose, uint8_t router_purpose,
                                int anonymized_connection,
                                const char *resource,
                                const char *payload, size_t payload_len,
                                time_t if_modified_since,
                                const rend_data_t *rend_query)
{
  dir_connection_t *conn;
  or_options_t *options = get_options();
  int socket_error = 0;
  int use_begindir = supports_begindir &&
                     directory_command_should_use_begindir(options, _addr,
                       or_port, router_purpose, anonymized_connection);
  tor_addr_t addr;

  tor_assert(address);
  tor_assert(_addr);
  tor_assert(or_port || dir_port);
  tor_assert(digest);

  tor_addr_copy(&addr, _addr);

  log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_CONN_INIT),anonymized_connection,use_begindir,dir_conn_purpose_to_string(dir_purpose));

  conn = dir_connection_new(AF_INET);

  /* set up conn so it's got all the data we need to remember */
  tor_addr_copy(&conn->_base.addr, &addr);
  conn->_base.port = use_begindir ? or_port : dir_port;
  conn->_base.address = tor_strdup(address);
  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  conn->_base.purpose = dir_purpose;
  conn->router_purpose = router_purpose;

  /* give it an initial state */
  conn->_base.state = DIR_CONN_STATE_CONNECTING;

  /* decide whether we can learn our IP address from this conn */
  conn->dirconn_direct = !anonymized_connection;

  /* copy rendezvous data, if any */
  if (rend_query)
    conn->rend_data = rend_data_dup(rend_query);

  if (!anonymized_connection && !use_begindir) {
    /* then we want to connect to dirport directly */

    if ((options->DirFlags & DIR_FLAG_NTLM_PROXY) && options->CorporateProxy) {
      tor_addr_copy(&addr, &options->CorporateProxyAddr);
      dir_port = options->CorporateProxyPort;
    }
    else if ((options->DirFlags & DIR_FLAG_HTTP_PROXY) && options->DirProxy) {
      tor_addr_copy(&addr, &options->DirProxyAddr);
      dir_port = options->DirProxyPort;
    }

    switch (connection_connect(TO_CONN(conn), conn->_base.address, &addr,
                               dir_port, &socket_error)) {
      case -1:
        connection_dir_request_failed(conn); /* retry if we want */
        /* XXX we only pass 'conn' above, not 'resource', 'payload',
         * etc. So in many situations it can't retry! -RD */
        connection_free(TO_CONN(conn));
        return;
      case 1:
        /* start flushing conn */
        conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING;
	tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_SEND_REQUEST),conn->_base.address?conn->_base.address:"");updateDirStatus();
        /* fall through */
      case 0:
        /* queue the command on the outbuf */
        directory_send_command(conn, dir_purpose, 1, resource,
                               payload, payload_len,
                               supports_conditional_consensus,
                               if_modified_since);
        connection_watch_events(TO_CONN(conn), READ_EVENT | WRITE_EVENT);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via a tor connection */
    edge_connection_t *linked_conn;

    /* If it's an anonymized connection, remember the fact that we
     * wanted it for later: maybe we'll want it again soon. */
    if (anonymized_connection && use_begindir)
      rep_hist_note_used_internal(get_time(NULL), 0, 1);
    else if (anonymized_connection && !use_begindir)
      rep_hist_note_used_port(get_time(NULL), conn->_base.port);

    /* make an AP connection
     * populate it and add it at the right state
     * hook up both sides
     */
    linked_conn =
      connection_ap_make_link(conn->_base.address, conn->_base.port,
                              digest, use_begindir, conn->dirconn_direct);
    if (!linked_conn) {
      log_warn(LD_NET,get_lang_str(LANG_LOG_DIR_TUNNEL_TO_DIRSERVER_FAILED));
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    connection_link_connections(TO_CONN(conn), TO_CONN(linked_conn));

    if (connection_add(TO_CONN(conn)) < 0) {
      log_warn(LD_NET,get_lang_str(LANG_LOG_DIR_UNABLE_TO_ADD_CONNECTION));
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING;
    /* queue the command on the outbuf */
    directory_send_command(conn, dir_purpose, 0, resource,
                           payload, payload_len,
                           supports_conditional_consensus,
                           if_modified_since);
    connection_watch_events(TO_CONN(conn), READ_EVENT|WRITE_EVENT);
    connection_start_reading(TO_CONN(linked_conn));
  }
}

/** Return true iff anything we say on <b>conn</b> is being encrypted before
 * we send it to the client/server. */
int
connection_dir_is_encrypted(dir_connection_t *conn)
{
  /* Right now it's sufficient to see if conn is or has been linked, since
   * the only thing it could be linked to is an edge connection on a
   * circuit, and the only way it could have been unlinked is at the edge
   * connection getting closed.
   */
  return TO_CONN(conn)->linked;
}

/** Helper for sorting
 *
 * sort strings alphabetically
 */
static int
_compare_strs(const void **a, const void **b)
{
  const char *s1 = *a, *s2 = *b;
  return strcmp(s1, s2);
}

#define CONDITIONAL_CONSENSUS_FPR_LEN 3
#if (CONDITIONAL_CONSENSUS_FPR_LEN > DIGEST_LEN)
#error "conditional consensus fingerprint length is larger than digest length"
#endif

/** Return the URL we should use for a consensus download.
 *
 * This url depends on whether or not the server we go to
 * is sufficiently new to support conditional consensus downloading,
 * i.e. GET .../consensus/<b>fpr</b>+<b>fpr</b>+<b>fpr</b>
 */
static char *
directory_get_consensus_url(int supports_conditional_consensus)
{
  char *url;
  size_t len;

  if (supports_conditional_consensus) {
    char *authority_id_list;
    smartlist_t *authority_digests = smartlist_create();

    SMARTLIST_FOREACH(router_get_trusted_dir_servers(),
                      trusted_dir_server_t *, ds,
      {
        char *hex;
        if (!(ds->type & V3_AUTHORITY))
          continue;

        hex = tor_malloc(2*CONDITIONAL_CONSENSUS_FPR_LEN+1);
        base16_encode(hex, 2*CONDITIONAL_CONSENSUS_FPR_LEN+1,
                      ds->v3_identity_digest, CONDITIONAL_CONSENSUS_FPR_LEN);
        smartlist_add(authority_digests, hex);
      });
    smartlist_sort(authority_digests, _compare_strs);
    authority_id_list = smartlist_join_strings(authority_digests,
                                               "+", 0, NULL);

    len = strlen(authority_id_list)+64;
    url = tor_malloc(len);
    tor_snprintf(url, len, "/tor/status-vote/current/consensus/%s.z",
                 authority_id_list);

    SMARTLIST_FOREACH(authority_digests, char *, cp, tor_free(cp));
    smartlist_free(authority_digests);
    tor_free(authority_id_list);
  } else {
    url = tor_strdup("/tor/status-vote/current/consensus.z");
  }
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_URL),url);updateDirStatus();
  return url;
}

/** Queue an appropriate HTTP command on conn-\>outbuf.  The other args
 * are as in directory_initiate_command.
 */
static void
directory_send_command(dir_connection_t *conn,
                       int purpose, int direct, const char *resource,
                       const char *payload, size_t payload_len,
                       int supports_conditional_consensus,
                       time_t if_modified_since)
{
  char proxystring[256];
  char proxyauthstring[256];
  char hoststring[128];
  char imsstring[RFC1123_TIME_LEN+32];
  char *url;
  unsigned char *request;
  const char *httpcommand = NULL;
  size_t len;

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  tor_free(conn->requested_resource);
  if (resource)
    conn->requested_resource = tor_strdup(resource);

  /* come up with a string for which Host: we want */
  if (conn->_base.port == 80) {
    strlcpy(hoststring, conn->_base.address, sizeof(hoststring));
  } else {
    tor_snprintf(hoststring, sizeof(hoststring),"%s:%d",
                 conn->_base.address, conn->_base.port);
  }

  /* Format if-modified-since */
  if (!if_modified_since) {
    imsstring[0] = '\0';
  } else {
    char b[RFC1123_TIME_LEN+1];
    format_rfc1123_time(b, if_modified_since);
    tor_snprintf(imsstring, sizeof(imsstring), "\r\nIf-Modified-Since: %s", b);
  }

  /* come up with some proxy lines, if we're using one. */
  if (direct && (get_options()->DirFlags & DIR_FLAG_HTTP_PROXY) && get_options()->DirProxy && get_options()->DirProxyProtocol==PROXY_HTTP) {
    char *base64_authenticator=NULL;
    const char *authenticator = get_options()->DirProxyAuthenticator;

    tor_snprintf(proxystring, sizeof(proxystring),"http://%s", hoststring);
    if ((get_options()->DirFlags & DIR_FLAG_HTTP_AUTH) && authenticator) {
      base64_authenticator = alloc_http_authenticator(authenticator);
      if (!base64_authenticator)
        log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_HTTP_ENCODING_FAILED));
    }
    if (base64_authenticator) {
      tor_snprintf(proxyauthstring, sizeof(proxyauthstring),
                   "\r\nProxy-Authorization: Basic %s",
                   base64_authenticator);
      tor_free(base64_authenticator);
    } else {
      proxyauthstring[0] = 0;
    }
  } else {
    proxystring[0] = 0;
    proxyauthstring[0] = 0;
  }

  switch (purpose) {
    case DIR_PURPOSE_FETCH_V2_NETWORKSTATUS:
      tor_assert(resource);
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/status/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_CONSENSUS:
      tor_assert(!resource);
      tor_assert(!payload);
      httpcommand = "GET";
      url = directory_get_consensus_url(supports_conditional_consensus);
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_DOWNLOADING_CONSENSUS),hoststring,url);
      break;
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      tor_assert(resource);
      tor_assert(!payload);
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/keys/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
      tor_assert(resource);
      tor_assert(!payload);
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/status-vote/next/%s.z", resource);
      break;
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
      tor_assert(!resource);
      tor_assert(!payload);
      httpcommand = "GET";
      url = tor_strdup("/tor/status-vote/next/consensus-signatures.z");
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      tor_assert(resource);
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/server/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      tor_assert(resource);
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/extra/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/");
      break;
    case DIR_PURPOSE_UPLOAD_VOTE:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/post/vote");
      break;
    case DIR_PURPOSE_UPLOAD_SIGNATURES:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/post/consensus-signature");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      tor_assert(resource);
      tor_assert(!payload);

      /* this must be true or we wouldn't be doing the lookup */
      tor_assert(strlen(resource) <= REND_SERVICE_ID_LEN_BASE32);
      /* This breaks the function abstraction. */
      conn->rend_data = tor_malloc_zero(sizeof(rend_data_t));
      strlcpy(conn->rend_data->onion_address, resource,
              sizeof(conn->rend_data->onion_address));

      httpcommand = "GET";
      /* Request the most recent versioned descriptor. */
      // (XXXX We were going to switch this to fetch rendezvous1 descriptors,
      // but that never got testing, and it wasn't a good design.)
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/rendezvous/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_RENDDESC_V2:
      tor_assert(resource);
      tor_assert(strlen(resource) <= REND_DESC_ID_V2_LEN_BASE32);
      tor_assert(!payload);
    //  conn->rend_data->rend_desc_version = 2;
      httpcommand = "GET";
      len = strlen(resource) + 32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/rendezvous2/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/rendezvous/publish");
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC_V2:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/rendezvous2/publish");
      break;
    default:
      tor_assert(0);
      return;
  }

  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_DOWNLOADING),conn->_base.address?conn->_base.address:"",url);updateDirStatus();
  if (strlen(proxystring) + strlen(url) >= 4096) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_URL_TOO_BIG),(int)(strlen(proxystring) + strlen(url)), proxystring, url);
  }

  if (!strcmp(httpcommand, "GET") && !payload) {
    tor_asprintf(&request,
                 "%s %s%s HTTP/1.0\r\nHost: %s%s%s\r\n\r\n",
		 httpcommand, proxystring,url,
                 hoststring,
                 imsstring,
                 proxyauthstring);
  } else {
    tor_asprintf(&request,
                 "%s %s%s HTTP/1.0\r\nContent-Length: %lu\r\nHost: %s%s%s\r\n\r\n",
		 httpcommand, proxystring,url,
                 payload ? (unsigned long)payload_len : 0,
                 hoststring,
                 imsstring,
                 proxyauthstring);
  }
  tor_free(url);
  if((((get_options()->DirFlags & DIR_FLAG_HTTP_PROXY) && get_options()->DirProxy && get_options()->DirProxyProtocol!=PROXY_HTTP) || ((get_options()->DirFlags & DIR_FLAG_NTLM_PROXY) && get_options()->CorporateProxy)) && TO_CONN(conn)->proxy_state != PROXY_CONNECTED)
  {	int i = strlen((char *)request);
  	conn->orig_request_len = i + (payload?payload_len:0) + 1;
  	if(conn->orig_request)	tor_free(conn->orig_request);
  	conn->orig_request = tor_malloc(conn->orig_request_len);
	memcpy(conn->orig_request,request,i);
	if(payload)	memcpy(conn->orig_request + i,payload,payload_len);
  }
  else
  {	connection_write_to_buf((char *)request, strlen((char *)request), TO_CONN(conn));
	if (payload) {
	/* then send the payload afterwards too */
	connection_write_to_buf(payload, payload_len, TO_CONN(conn));
	}
  }
  tor_free(request);
}

/** Parse an HTTP request string <b>headers</b> of the form
 * \verbatim
 * "\%s [http[s]://]\%s HTTP/1..."
 * \endverbatim
 * If it's well-formed, strdup the second \%s into *<b>url</b>, and
 * nul-terminate it. If the url doesn't start with "/tor/", rewrite it
 * so it does. Return 0.
 * Otherwise, return -1.
 */
static int
parse_http_url(const char *headers, char **url)
{
  char *s, *start, *tmp;

  s = (char *)eat_whitespace_no_nl(headers);
  if (!*s) return -1;
  s = (char *)find_whitespace(s); /* get past GET/POST */
  if (!*s) return -1;
  s = (char *)eat_whitespace_no_nl(s);
  if (!*s) return -1;
  start = s; /* this is it, assuming it's valid */
  s = (char *)find_whitespace(start);
  if (!*s) return -1;

  /* tolerate the http[s] proxy style of putting the hostname in the url */
  if (s-start >= 4 && !strcmpstart(start,"http")) {
    tmp = start + 4;
    if (*tmp == 's')
      tmp++;
    if (s-tmp >= 3 && !strcmpstart(tmp,"://")) {
      tmp = strchr(tmp+3, '/');
      if (tmp && tmp < s) {
        log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_SKIPPING_OVER_HOSTNAME_STRING));
        start = tmp;
      }
    }
  }

  if (s-start < 5 || strcmpstart(start,"/tor/")) { /* need to rewrite it */
    *url = tor_malloc(s - start + 5);
    strlcpy(*url,"/tor", s-start+5);
    strlcat((*url)+4, start, s-start+1);
  } else {
    *url = tor_strndup(start, s-start);
  }
  return 0;
}

/** Return a copy of the first HTTP header in <b>headers</b> whose key is
 * <b>which</b>.  The key should be given with a terminating colon and space;
 * this function copies everything after, up to but not including the
 * following \\r\\n. */
static char *
http_get_header(const char *headers, const char *which)
{
  const char *cp = headers;
  while (cp) {
    if (!strcasecmpstart(cp, which)) {
      char *eos;
      cp += strlen(which);
      if ((eos = strchr(cp,'\r')))
        return tor_strndup(cp, eos-cp);
      else
        return tor_strdup(cp);
    }
    cp = strchr(cp, '\n');
    if (cp)
      ++cp;
  }
  return NULL;
}

/** If <b>headers</b> indicates that a proxy was involved, then rewrite
 * <b>conn</b>-\>address to describe our best guess of the address that
 * originated this HTTP request. */
static void
http_set_address_origin(const char *headers, connection_t *conn)
{
  char *fwd=NULL;
  char *esc_l;

  fwd = http_get_header(headers, "Forwarded-For: ");
  if (!fwd)
    fwd = http_get_header(headers, "X-Forwarded-For: ");
  if (fwd) {
    struct in_addr in;
    if (!tor_inet_aton(fwd, &in) || is_internal_IP(ntohl(in.s_addr), 0)) {
      esc_l = esc_for_log(fwd);
      log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_IGNORING_UNRECOGNIZED_IP),esc_l);
      tor_free(esc_l);
      tor_free(fwd);
      return;
    }
    tor_free(conn->address);
    conn->address = tor_strdup(fwd);
    tor_free(fwd);
  }
}

/** Parse an HTTP response string <b>headers</b> of the form
 * \verbatim
 * "HTTP/1.\%d \%d\%s\r\n...".
 * \endverbatim
 *
 * If it's well-formed, assign the status code to *<b>code</b> and
 * return 0.  Otherwise, return -1.
 *
 * On success: If <b>date</b> is provided, set *date to the Date
 * header in the http headers, or 0 if no such header is found.  If
 * <b>compression</b> is provided, set *<b>compression</b> to the
 * compression method given in the Content-Encoding header, or 0 if no
 * such header is found, or -1 if the value of the header is not
 * recognized.  If <b>reason</b> is provided, strdup the reason string
 * into it.
 */
int
parse_http_response(const char *headers, int *code, time_t *date,
                    compress_method_t *compression, char **reason)
{
  unsigned n1, n2;
  char datestr[RFC1123_TIME_LEN+1];
  smartlist_t *parsed_headers;
  char *esc_l;
  tor_assert(headers);
  tor_assert(code);

  while (TOR_ISSPACE(*headers)) headers++; /* tolerate leading whitespace */

  if (tor_sscanf(headers, "HTTP/1.%u %u", &n1, &n2) < 2 ||
      (n1 != 0 && n1 != 1) ||
      (n2 < 100 || n2 >= 600)) {
    esc_l = esc_for_log(headers);
    log_warn(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_HEADER_PARSE_FAILED),esc_l);
    tor_free(esc_l);
    return -1;
  }
  *code = n2;

  parsed_headers = smartlist_create();
  smartlist_split_string(parsed_headers, headers, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (reason) {
    smartlist_t *status_line_elements = smartlist_create();
    tor_assert(smartlist_len(parsed_headers));
    smartlist_split_string(status_line_elements,
                           smartlist_get(parsed_headers, 0),
                           " ", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 3);
    tor_assert(smartlist_len(status_line_elements) <= 3);
    if (smartlist_len(status_line_elements) == 3) {
      *reason = smartlist_get(status_line_elements, 2);
      smartlist_set(status_line_elements, 2, NULL); /* Prevent free */
    }
    SMARTLIST_FOREACH(status_line_elements, char *, cp, tor_free(cp));
    smartlist_free(status_line_elements);
  }
  if (date) {
    *date = 0;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Date: ")) {
        strlcpy(datestr, s+6, sizeof(datestr));
        /* This will do nothing on failure, so we don't need to check
           the result.   We shouldn't warn, since there are many other valid
           date formats besides the one we use. */
        parse_rfc1123_time(datestr, date);
        break;
      });
  }
  if (compression) {
    const char *enc = NULL;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Content-Encoding: ")) {
        enc = s+18; break;
      });
    if (!enc || !strcmp(enc, "identity")) {
      *compression = NO_METHOD;
    } else if (!strcmp(enc, "deflate") || !strcmp(enc, "x-deflate")) {
      *compression = ZLIB_METHOD;
    } else if (!strcmp(enc, "gzip") || !strcmp(enc, "x-gzip")) {
      *compression = GZIP_METHOD;
    } else {
      esc_l = esc_for_log(enc);
      log_info(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_UNRECOGNIZED_ENCODING),esc_l);
      tor_free(esc_l);
      *compression = UNKNOWN_METHOD;
    }
  }
  SMARTLIST_FOREACH(parsed_headers, char *, s, tor_free(s));
  smartlist_free(parsed_headers);

  return 0;
}

/** Return true iff <b>body</b> doesn't start with a plausible router or
 * running-list or directory opening.  This is a sign of possible compression.
 **/
static int
body_is_plausible(const char *body, size_t len, int purpose)
{
  int i;
  if (len == 0)
    return 1; /* empty bodies don't need decompression */
  if (len < 32)
    return 0;
  if (purpose != DIR_PURPOSE_FETCH_RENDDESC) {
    if (!strcmpstart(body,"router") ||
        !strcmpstart(body,"signed-directory") ||
        !strcmpstart(body,"network-status") ||
        !strcmpstart(body,"running-routers"))
    return 1;
    for (i=0;i<32;++i) {
      if (!TOR_ISPRINT(body[i]) && !TOR_ISSPACE(body[i]))
        return 0;
    }
    return 1;
  } else {
    return 1;
  }
}

/** Called when we've just fetched a bunch of router descriptors in
 * <b>body</b>.  The list <b>which</b>, if present, holds digests for
 * descriptors we requested: descriptor digests if <b>descriptor_digests</b>
 * is true, or identity digests otherwise.  Parse the descriptors, validate
 * them, and annotate them as having purpose <b>purpose</b> and as having been
 * downloaded from <b>source</b>.
 *
 * Return the number of routers actually added. */
static int
load_downloaded_routers(const char *body, smartlist_t *which,
                        int descriptor_digests,
                        int router_purpose,
                        const char *source)
{
  char buf[256];
  char time_buf[ISO_TIME_LEN+1];
  char *esc_l;
  int added = 0;
  int general = router_purpose == ROUTER_PURPOSE_GENERAL;
  format_iso_time(time_buf, get_time(NULL));
  tor_assert(source);

  esc_l = esc_for_log(source);
  if (tor_snprintf(buf, sizeof(buf),
                   "@downloaded-at %s\n"
                   "@source %s\n"
                   "%s%s%s", time_buf, esc_l,
                   !general ? "@purpose " : "",
                   !general ? router_purpose_to_string(router_purpose) : "",
                   !general ? "\n" : "")<0)
  { tor_free(esc_l);
    return added;
  }
  tor_free(esc_l);

  added = router_load_routers_from_string(body, NULL, SAVED_NOWHERE, which,
                                  descriptor_digests, buf);
  control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_DESCRIPTORS,
                          count_loading_descriptors_progress());
  return added;
}

/** We are a client, and we've finished reading the server's
 * response. Parse it and act appropriately.
 *
 * If we're still happy with using this directory server in the future, return
 * 0. Otherwise return -1; and the caller should consider trying the request
 * again.
 *
 * The caller will take care of marking the connection for close.
 */
static int
connection_dir_client_reached_eof(dir_connection_t *conn)
{
  char *body;
  char *headers;
  char *reason = NULL;
  char *esc_l;
  size_t body_len=0, orig_len=0;
  int status_code;
  time_t date_header=0;
  long delta;
  compress_method_t compression;
  int plausible;
  int skewed=0;
  int allow_partial = (conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
                       conn->_base.purpose == DIR_PURPOSE_FETCH_EXTRAINFO);
  int was_compressed=0;
  time_t now = get_time(NULL);

  switch (fetch_from_buf_http(conn->_base.inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_DIR_DL_SIZE,
                              allow_partial)) {
    case -1: /* overflow */
      log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_DIR_FETCH_RESPONSE_TOO_LARGE),conn->_base.address,conn->_base.port);
      return -1;
    case 0:
      log_info(LD_HTTP,get_lang_str(LANG_LOG_DIR_FETCH_RESPONSE_INCOMPLETE));
      return -1;
    /* case 1, fall through */
  }
  orig_len = body_len;

  if (parse_http_response(headers, &status_code, &date_header,
                          &compression, &reason) < 0) {
    log_warn(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_UNPARSEABLE_HEADERS),conn->_base.address,conn->_base.port);
    tor_free(body); tor_free(headers);
    return -1;
  }
  if (!reason) reason = tor_strdup("[no reason given]");

  esc_l = esc_for_log(reason);
  log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_RESPONSE_RECEIVED),conn->_base.address,conn->_base.port,status_code,esc_l);
  tor_free(esc_l);

  /* now check if it's got any hints for us about our IP address. */
  if (conn->dirconn_direct) {
    char *guess = http_get_header(headers, X_ADDRESS_HEADER);
    if (guess) {
      router_new_address_suggestion(guess, conn);
      tor_free(guess);
    }
  }

  if (date_header > 0) {
    /* The date header was written very soon after we sent our request,
     * so compute the skew as the difference between sending the request
     * and the date header.  (We used to check now-date_header, but that's
     * inaccurate if we spend a lot of time downloading.)
     */
    delta = conn->_base.timestamp_lastwritten - date_header;
    if(get_options()->DirFlags&DIR_FLAG_FAKE_LOCAL_TIME)
    {	if (labs(delta)>ALLOW_DIRECTORY_TIME_SKEW)
    	{	delta_t=date_header-get_time(NULL)+crypto_rand_int(40*60)-20*60;
		update_best_delta_t(delta_t);
		get_options()->BestTimeDelta=best_delta_t;
		log(LOG_INFO,LD_CONTROL,get_lang_str(LANG_LOG_DIR_NEW_TIMESTAMP_DELTA), best_delta_t);
		delta=0;
	}
    }
    else if (labs(delta)>ALLOW_DIRECTORY_TIME_SKEW) {
      char dbuf[64];
      int trusted = router_digest_is_trusted_dir(conn->identity_digest);
      format_time_interval(dbuf, sizeof(dbuf), delta);
      log_fn(trusted ? LOG_WARN : LOG_INFO,LD_HTTP,get_lang_str(LANG_LOG_DIR_RECEIVED_SKEWED_TIME),conn->_base.address,conn->_base.port,delta>0 ? get_lang_str(LANG_LOG_COMMAND__AHEAD) : get_lang_str(LANG_LOG_COMMAND__BEHIND),dbuf,delta>0 ? get_lang_str(LANG_LOG_COMMAND__BEHIND) : get_lang_str(LANG_LOG_COMMAND__AHEAD));
      skewed = 1; /* don't check the recommended-versions line */
      if (trusted)
        control_event_general_status(LOG_WARN,
                               "CLOCK_SKEW SKEW=%ld SOURCE=DIRSERV:%s:%d",
                               delta, conn->_base.address, conn->_base.port);
    } else {
      log_debug(LD_HTTP,get_lang_str(LANG_LOG_DIR_RECEIVED_SKEWED_TIME_2),delta);
    }
  }
  (void) skewed; /* skewed isn't used yet. */

  if (status_code == 503) {
    routerstatus_t *rs;
    trusted_dir_server_t *ds;
    esc_l = esc_for_log(reason);
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR),status_code,esc_l,conn->_base.address,conn->_base.port);
    tor_free(esc_l);
    if ((rs = router_get_consensus_status_by_id(conn->identity_digest)))
      rs->last_dir_503_at = now;
    if ((ds = router_get_trusteddirserver_by_digest(conn->identity_digest)))
      ds->fake_status.last_dir_503_at = now;

    tor_free(body); tor_free(headers); tor_free(reason);
    return -1;
  }

  plausible = body_is_plausible(body, body_len, conn->_base.purpose);
  if (compression != NO_METHOD || !plausible) {
    char *new_body = NULL;
    size_t new_len = 0;
    compress_method_t guessed = detect_compression_method(body, body_len);
    if (compression == UNKNOWN_METHOD || guessed != compression) {
      /* Tell the user if we don't believe what we're told about compression.*/
      const char *description1, *description2;
      if (compression == ZLIB_METHOD)
        description1 = get_lang_str(LANG_LOG_DIR_E_DEFLATED);
      else if (compression == GZIP_METHOD)
        description1 = get_lang_str(LANG_LOG_DIR_E_GZIPPED);
      else if (compression == NO_METHOD)
        description1 = get_lang_str(LANG_LOG_DIR_E_UNCOMPRESSED);
      else
        description1 = get_lang_str(LANG_LOG_DIR_E_UNKNOWN);
      if (guessed == ZLIB_METHOD)
        description2 = get_lang_str(LANG_LOG_DIR_E1_DEFLATED);
      else if (guessed == GZIP_METHOD)
        description2 = get_lang_str(LANG_LOG_DIR_E1_GZIPPED);
      else if (!plausible)
        description2 = get_lang_str(LANG_LOG_DIR_E1_UNKNOWN);
      else
        description2 = get_lang_str(LANG_LOG_DIR_E1_UNCOMPRESSED);

      log_info(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_COMPRESSION_MISMATCH),conn->_base.address,conn->_base.port,description1,description2,(compression>0 && guessed>0)?get_lang_str(LANG_LOG_DIR_E_TRYING_BOTH):"");
    }
    /* Try declared compression first if we can. */
    if (compression == GZIP_METHOD  || compression == ZLIB_METHOD)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, compression,
                          !allow_partial, LOG_PROTOCOL_WARN);
    /* Okay, if that didn't work, and we think that it was compressed
     * differently, try that. */
    if (!new_body &&
        (guessed == GZIP_METHOD || guessed == ZLIB_METHOD) &&
        compression != guessed)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, guessed,
                          !allow_partial, LOG_PROTOCOL_WARN);
    /* If we're pretty sure that we have a compressed directory, and
     * we didn't manage to uncompress it, then warn and bail. */
    if (!plausible && !new_body) {
      log_fn(LOG_PROTOCOL_WARN, LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_DECOMPRESS_FAILED),conn->_base.address,conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (new_body) {
      tor_free(body);
      body = new_body;
      body_len = new_len;
      was_compressed = 1;
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_V2_NETWORKSTATUS) {
    smartlist_t *which = NULL;
    v2_networkstatus_source_t source;
    char *cp;
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_NETWORKSTATUS),(int) body_len, conn->_base.address, conn->_base.port);
    if (status_code != 200) {
      static ratelim_t warning_limit = RATELIM_INIT(3600);
      char *m;
      if ((m = rate_limit_log(&warning_limit, now))) {
        esc_l = esc_for_log(reason);
        log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_2),status_code,esc_l,conn->_base.address,conn->_base.port,conn->requested_resource);
	tor_free(esc_l);
        tor_free(m);
      }
      tor_free(body); tor_free(headers); tor_free(reason);
      connection_dir_download_v2_networkstatus_failed(conn, status_code);
      return -1;
    }
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"fp/")) {
      source = NS_FROM_DIR_BY_FP;
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                           which, NULL, 0);
    } else if (conn->requested_resource &&
               !strcmpstart(conn->requested_resource, "all")) {
      source = NS_FROM_DIR_ALL;
      which = smartlist_create();
      SMARTLIST_FOREACH(router_get_trusted_dir_servers(),
                        trusted_dir_server_t *, ds,
        {
          char *hex = tor_malloc(HEX_DIGEST_LEN+1);
          base16_encode(hex, HEX_DIGEST_LEN+1, ds->digest, DIGEST_LEN);
          smartlist_add(which, hex);
        });
    } else {
      /* XXXX Can we even end up here? -- weasel*/
      source = NS_FROM_DIR_BY_FP;
      log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_RECEIVED_UNREQUESTED_NETWORKSTATUS));
    }
    cp = body;
    while (*cp) {
      char *next = strstr(cp, "\nnetwork-status-version");
      if (next)
        next[1] = '\0';
      /* learn from it, and then remove it from 'which' */
      if (router_set_networkstatus_v2(cp, now, source, which)<0)
        break;
      if (next) {
        next[1] = 'n';
        cp = next+1;
      } else
        break;
    }
    /* launches router downloads as needed */
    routers_update_all_from_networkstatus(now, 2);
    directory_info_has_arrived(now, 0);
    if (which) {
      if (smartlist_len(which)) {
        dir_networkstatus_download_failed(which, status_code);
      }
      SMARTLIST_FOREACH(which, char *, s, tor_free(s));
      smartlist_free(which);
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_CONSENSUS) {
    int r;
    if (status_code != 200) {
      int severity = (status_code == 304) ? LOG_INFO : LOG_WARN;
      char *esc_l1 = esc_for_log(reason);
      log(severity, LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_3),status_code,esc_l1,conn->_base.address,conn->_base.port);
      tor_free(esc_l1);
      tor_free(body); tor_free(headers); tor_free(reason);
      networkstatus_consensus_download_failed(status_code);
      return -1;
    }
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_CONSENSUS),(int) body_len, conn->_base.address, conn->_base.port);
    if ((r=networkstatus_set_current_consensus(body,"ns", 0))<0) {
      log_fn(r<-1?LOG_WARN:LOG_INFO, LD_DIR,get_lang_str(LANG_LOG_DIR_CONSENSUS_LOAD_ERROR),conn->_base.address,conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      networkstatus_consensus_download_failed(0);
      return -1;
    }
    /* launches router downloads as needed */
    routers_update_all_from_networkstatus(now, 3);
    directory_info_has_arrived(now, 0);
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_CONSENSUS_LOAD_OK));
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_CERTIFICATE) {
    if (status_code != 200) {
      esc_l = esc_for_log(reason);
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_4),status_code,esc_l,conn->_base.address,conn->_base.port,conn->requested_resource);
      connection_dir_download_cert_failed(conn, status_code);
      tor_free(esc_l);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_CERTS),(int) body_len,conn->_base.address,conn->_base.port);
    if (trusted_dirs_load_certs_from_string(body, 0, 1)<0) {
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_CERT_PARSE_FAILED));
      connection_dir_download_cert_failed(conn, status_code);
    } else {
      directory_info_has_arrived(now, 0);
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_CERTS_LOADED));
    }
  }
  if (conn->_base.purpose == DIR_PURPOSE_FETCH_STATUS_VOTE) {
    const char *msg;
    int st;
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_VOTES),(int) body_len,conn->_base.address,conn->_base.port);
    if (status_code != 200) {
      esc_l = esc_for_log(reason);
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_5),status_code,esc_l,conn->_base.address,conn->_base.port,conn->requested_resource);
      tor_free(esc_l);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    dirvote_add_vote(body, &msg, &st);
    if (st > 299) {
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_VOTE_ADD_ERROR), msg);
    } else {
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_VOTE_ADD_OK),msg);
    }
  }
  if (conn->_base.purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES) {
    const char *msg = NULL;
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_SIGNATURES),(int) body_len,conn->_base.address,conn->_base.port);
    if (status_code != 200) {
      esc_l = esc_for_log(reason);
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_6),status_code,esc_l,conn->_base.address,conn->_base.port);
      tor_free(esc_l);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (dirvote_add_signatures(body, conn->_base.address, &msg)<0) {
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_SIGNATURES_ADD_ERROR),conn->_base.address,conn->_base.port, msg?msg:"???");
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
      conn->_base.purpose == DIR_PURPOSE_FETCH_EXTRAINFO) {
    int was_ei = conn->_base.purpose == DIR_PURPOSE_FETCH_EXTRAINFO;
    smartlist_t *which = NULL;
    int n_asked_for = 0;
    int descriptor_digests = conn->requested_resource &&
                             !strcmpstart(conn->requested_resource,"d/");
    log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_INFO),was_ei ? "extra server info" : "server info",(int)body_len,conn->_base.address,conn->_base.port);
    if (conn->requested_resource &&
        (!strcmpstart(conn->requested_resource,"d/") ||
         !strcmpstart(conn->requested_resource,"fp/"))) {
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource +
                                             (descriptor_digests ? 2 : 3),
                                           which, NULL, 0);
      n_asked_for = smartlist_len(which);
    }
    if (status_code != 200) {
      int dir_okay = status_code == 404 ||
        (status_code == 400 && !strcmp(reason, "Servers unavailable."));
      /* 404 means that it didn't have them; no big deal.
       * Older (pre-0.1.1.8) servers said 400 Servers unavailable instead. */
      char *esc_l1 = esc_for_log(reason);
      log_fn(dir_okay ? LOG_INFO : LOG_WARN, LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_7),status_code,esc_l1,conn->_base.address,conn->_base.port,conn->requested_resource);
      tor_free(esc_l1);
      if (!which) {
        connection_dir_download_routerdesc_failed(conn);
      } else {
        dir_routerdesc_download_failed(which, status_code,
                                       conn->router_purpose,
                                       was_ei, descriptor_digests);
        SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
        smartlist_free(which);
      }
      tor_free(body); tor_free(headers); tor_free(reason);
      return dir_okay ? 0 : -1;
    }
    /* Learn the routers, assuming we requested by fingerprint or "all"
     * or "authority".
     *
     * We use "authority" to fetch our own descriptor for
     * testing, and to fetch bridge descriptors for bootstrapping. Ignore
     * the output of "authority" requests unless we are using bridges,
     * since otherwise they'll be the response from reachability tests,
     * and we don't really want to add that to our routerlist. */
    if (which || (conn->requested_resource &&
                  (!strcmpstart(conn->requested_resource, "all") ||
                   (!strcmpstart(conn->requested_resource, "authority") &&
                    get_options()->UseBridges)))) {
      /* as we learn from them, we remove them from 'which' */
      if (was_ei) {
        router_load_extrainfo_from_string(body, NULL, SAVED_NOWHERE, which,
                                          descriptor_digests);
      } else {
        //router_load_routers_from_string(body, NULL, SAVED_NOWHERE, which,
        //                       descriptor_digests, conn->router_purpose);
        if (load_downloaded_routers(body, which, descriptor_digests,
                                conn->router_purpose,
                                conn->_base.address))
          directory_info_has_arrived(now, 0);
      }
    }
    if (which) { /* mark remaining ones as failed */
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_RECEIVED_DESC),n_asked_for-smartlist_len(which),n_asked_for,was_ei ? "extra-info documents" : "router descriptors",conn->_base.address,(int)conn->_base.port);
      if (smartlist_len(which)) {
        dir_routerdesc_download_failed(which, status_code,
                                       conn->router_purpose,
                                       was_ei, descriptor_digests);
      }
      SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
      smartlist_free(which);
    }
    if (directory_conn_is_self_reachability_test(conn))
      router_dirport_found_reachable();
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_DIR) {
    switch (status_code) {
      case 200: {
          trusted_dir_server_t *ds =
            router_get_trusteddirserver_by_digest(conn->identity_digest);
          char *rejected_hdr = http_get_header(headers,
                                               "X-Descriptor-Not-New: ");
          if (rejected_hdr) {
            if (!strcmp(rejected_hdr, "Yes")) {
              log_info(LD_GENERAL,get_lang_str(LANG_LOG_DIR_DESCRIPTOR_REJECTED),ds->nickname);
              /* XXXX use this information; be sure to upload next one
               * sooner. -NM */
              /* XXXX021 On further thought, the task above implies that we're
               * basing our regenerate-descriptor time on when we uploaded the
               * last descriptor, not on the published time of the last
               * descriptor.  If those are different, that's a bad thing to
               * do. -NM */
            }
            tor_free(rejected_hdr);
          }
          log_info(LD_GENERAL,get_lang_str(LANG_LOG_DIR_DESCRIPTOR_ACCEPTED));
          control_event_server_status(
                      LOG_NOTICE, "ACCEPTED_SERVER_DESCRIPTOR DIRAUTH=%s:%d",
                      conn->_base.address, conn->_base.port);

          ds->has_accepted_serverdesc = 1;
          if (directories_have_accepted_server_descriptor())
            control_event_server_status(LOG_NOTICE, "GOOD_SERVER_DESCRIPTOR");
        }
        break;
      case 400:
        esc_l = esc_for_log(reason);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_8),esc_l,conn->_base.address,conn->_base.port);
        control_event_server_status(LOG_WARN,
                      "BAD_SERVER_DESCRIPTOR DIRAUTH=%s:%d REASON=\"%s\"",
                      conn->_base.address, conn->_base.port, esc_l);
	tor_free(esc_l);
        break;
      default:
        esc_l = esc_for_log(reason);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_9),status_code,esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
    }
    /* return 0 in all cases, since we don't want to mark any
     * dirservers down just because they don't like us. */
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_VOTE) {
    switch (status_code) {
      case 200: {
        log_notice(LD_DIR,get_lang_str(LANG_LOG_DIR_VOTE_UPLOADED),conn->_base.address,conn->_base.port);
        }
        break;
      case 400:
        esc_l = esc_for_log(reason);
        log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_10),esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
      default:
        esc_l = esc_for_log(reason);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_11),status_code,esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
    }
    /* return 0 in all cases, since we don't want to mark any
     * dirservers down just because they don't like us. */
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_SIGNATURES) {
    switch (status_code) {
      case 200: {
        log_notice(LD_DIR,get_lang_str(LANG_LOG_DIR_SIGNATURE_UPLOADED),conn->_base.address,conn->_base.port);
        }
        break;
      case 400:
        esc_l = esc_for_log(reason);
        log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_12),esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
      default:
        esc_l = esc_for_log(reason);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_13),status_code,esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
    }
    /* return 0 in all cases, since we don't want to mark any
     * dirservers down just because they don't like us. */
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_RENDDESC) {
    tor_assert(conn->rend_data);
    esc_l = esc_for_log(reason);
    log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_RECEIVED),(int)body_len,status_code,esc_l);
    tor_free(esc_l);
    switch (status_code) {
      case 200:
        if (rend_cache_store(body, body_len, 0,conn->rend_data->onion_address) < -1) {
          log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_PARSE_FAILED));
          /* Any pending rendezvous attempts will notice when
           * connection_about_to_close_connection()
           * cleans this dir conn up. */
          /* We could retry. But since v0 descriptors are going out of
           * style, it isn't worth the hassle. We'll do better in v2. */
        } else {
          /* Success, or at least there's a v2 descriptor already
           * present. Notify pending connections about this. */
          conn->_base.purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
          rend_client_desc_trynow(conn->rend_data->onion_address);
        }
        break;
      case 404:
        /* Not there. Pending connections will be notified when
         * connection_about_to_close_connection() cleans this conn up. */
        break;
      case 400:
        esc_l = esc_for_log(reason);
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_14),esc_l);
	tor_free(esc_l);
        break;
      default:
      	esc_l = esc_for_log(reason);
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_15),status_code,esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_RENDDESC_V2) {
    tor_assert(conn->rend_data);
    esc_l = esc_for_log(reason);
    log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_RECEIVED),(int)body_len,status_code,esc_l);
    tor_free(esc_l);
    switch (status_code) {
      case 200:
        switch (rend_cache_store_v2_desc_as_client(body, conn->rend_data)) {
          case -2:
            log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_REND_FETCH_FAILED));
            /* We'll retry when connection_about_to_close_connection()
             * cleans this dir conn up. */
            break;
          case -1:
            /* We already have a v0 descriptor here. Ignoring this one
             * and _not_ performing another request. */
            log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_V2_RECEIVED_1));
            conn->_base.purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
            break;
          default:
            /* success. notify pending connections about this. */
            log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_V2_RECEIVED_2));
            conn->_base.purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
            rend_client_desc_trynow(conn->rend_data->onion_address);
            break;
        }
        break;
      case 404:
        /* Not there. We'll retry when
         * connection_about_to_close_connection() cleans this conn up. */
        log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_FETCH_FAILED));
        break;
      case 400:
        esc_l = esc_for_log(reason);
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_16),esc_l);
	tor_free(esc_l);
        break;
      default:
        esc_l = esc_for_log(reason);
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_17),status_code,esc_l,conn->_base.address,conn->_base.port);
	tor_free(esc_l);
        break;
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_RENDDESC ||
      conn->_base.purpose == DIR_PURPOSE_UPLOAD_RENDDESC_V2) {
    esc_l = esc_for_log(reason);
    log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_UPLOADED),status_code,esc_l);
    switch (status_code) {
      case 200:
        log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REND_DESC_UPLOADED_OK),esc_l);
        break;
      case 400:
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_18),esc_l,conn->_base.address,conn->_base.port);
        break;
      default:
        log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_HTTP_ERROR_20),status_code,esc_l,conn->_base.address,conn->_base.port);
        break;
    }
    tor_free(esc_l);
  }
  note_client_request(conn->_base.purpose, was_compressed, orig_len);
  tor_free(body); tor_free(headers); tor_free(reason);
  return 0;
}

/** Called when a directory connection reaches EOF. */
int
connection_dir_reached_eof(dir_connection_t *conn)
{
  int retval;
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_EOF),conn->_base.address?conn->_base.address:"");updateDirStatus();
  if (conn->_base.state != DIR_CONN_STATE_CLIENT_READING) {
    log_info(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_EOF),conn->_base.state);
    connection_close_immediate(TO_CONN(conn)); /* error: give up on flushing */
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }

  retval = connection_dir_client_reached_eof(conn);
  if (retval == 0) /* success */
    conn->_base.state = DIR_CONN_STATE_CLIENT_FINISHED;
  connection_mark_for_close(TO_CONN(conn));
  return retval;
}

/** If any directory object is arriving, and it's over 10MB large, we're
 * getting DoS'd.  (As of 0.1.2.x, raw directories are about 1MB, and we never
 * ask for more than 96 router descriptors at a time.)
 */
#define MAX_DIRECTORY_OBJECT_SIZE (10*(1<<20))

/** Read handler for directory connections.  (That's connections <em>to</em>
 * directory servers and connections <em>at</em> directory servers.)
 */
int
connection_dir_process_inbuf(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  /* Directory clients write, then read data until they receive EOF;
   * directory servers read data until they get an HTTP command, then
   * write their response (when it's finished flushing, they mark for
   * close).
   */
  if(conn->_base.state == DIR_CONN_STATE_PROXY_HANDSHAKING)
  {	int ret = dir_read_proxy_handshake(TO_CONN(conn));
  	if(ret < 0)	connection_mark_for_close(TO_CONN(conn));
	return ret;
  }

  /* If we're on the dirserver side, look for a command. */
  if (conn->_base.state == DIR_CONN_STATE_SERVER_COMMAND_WAIT) {
    if (directory_handle_command(conn) < 0) {
      connection_mark_for_close(TO_CONN(conn));
      return -1;
    }
    return 0;
  }

  if (buf_datalen(conn->_base.inbuf) > MAX_DIRECTORY_OBJECT_SIZE) {
    log_warn(LD_HTTP,get_lang_str(LANG_LOG_DIR_RECEIVED_TOO_MUCH));
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }

  if (!conn->_base.inbuf_reached_eof)
    log_debug(LD_HTTP,get_lang_str(LANG_LOG_DIR_RECEIVED_DATA));
  return 0;
}

/** Create an http response for the client <b>conn</b> out of
 * <b>status</b> and <b>reason_phrase</b>. Write it to <b>conn</b>.
 */
static void
write_http_status_line(dir_connection_t *conn, int status,
                       const char *reason_phrase)
{
  char buf[256];
  if (tor_snprintf(buf, sizeof(buf), "HTTP/1.0 %d %s\r\n\r\n",
      status, reason_phrase ? reason_phrase : "OK") < 0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_STATUS_LINE_TOO_LONG));
    return;
  }
  connection_write_to_buf(buf, strlen(buf), TO_CONN(conn));
}

/** Write the header for an HTTP/1.0 response onto <b>conn</b>-\>outbuf,
 * with <b>type</b> as the Content-Type.
 *
 * If <b>length</b> is nonnegative, it is the Content-Length.
 * If <b>encoding</b> is provided, it is the Content-Encoding.
 * If <b>cache_lifetime</b> is greater than 0, the content may be cached for
 * up to cache_lifetime seconds.  Otherwise, the content may not be cached. */
static void
write_http_response_header_impl(dir_connection_t *conn, ssize_t length,
                           const char *type, const char *encoding,
                           const char *extra_headers,
                           long cache_lifetime)
{
  char date[RFC1123_TIME_LEN+1];
  char tmp[1024];
  char *cp;
  time_t now = get_time(NULL);

  tor_assert(conn);

  format_rfc1123_time(date, now);
  cp = tmp;
  tor_snprintf(cp, sizeof(tmp),
               "HTTP/1.0 200 OK\r\nDate: %s\r\n",
               date);
  cp += strlen(tmp);
  if (type) {
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp), "Content-Type: %s\r\n", type);
    cp += strlen(cp);
  }
  if (!is_local_addr(&conn->_base.addr)) {
    /* Don't report the source address for a nearby/private connection.
     * Otherwise we tend to mis-report in cases where incoming ports are
     * being forwarded to a Tor server running behind the firewall. */
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 X_ADDRESS_HEADER "%s\r\n", conn->_base.address);
    cp += strlen(cp);
  }
  if (encoding) {
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Content-Encoding: %s\r\n", encoding);
    cp += strlen(cp);
  }
  if (length >= 0) {
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Content-Length: %ld\r\n", (long)length);
    cp += strlen(cp);
  }
  if (cache_lifetime > 0) {
    char expbuf[RFC1123_TIME_LEN+1];
    format_rfc1123_time(expbuf, now + cache_lifetime);
    /* We could say 'Cache-control: max-age=%d' here if we start doing
     * http/1.1 */
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Expires: %s\r\n", expbuf);
    cp += strlen(cp);
  } else if (cache_lifetime == 0) {
    /* We could say 'Cache-control: no-cache' here if we start doing
     * http/1.1 */
    strlcpy(cp, "Pragma: no-cache\r\n", sizeof(tmp)-(cp-tmp));
    cp += strlen(cp);
  }
  if (extra_headers) {
    strlcpy(cp, extra_headers, sizeof(tmp)-(cp-tmp));
    cp += strlen(cp);
  }
  if (sizeof(tmp)-(cp-tmp) > 3)
    memcpy(cp, "\r\n", 3);
  else
    tor_assert(0);
  connection_write_to_buf(tmp, strlen(tmp), TO_CONN(conn));
}

/** As write_http_response_header_impl, but sets encoding and content-typed
 * based on whether the response will be <b>compressed</b> or not. */
static void
write_http_response_header(dir_connection_t *conn, ssize_t length,
                           int compressed, long cache_lifetime)
{
  write_http_response_header_impl(conn, length,
                          compressed?"application/octet-stream":"text/plain",
                          compressed?"deflate":"identity",
                             NULL,
                             cache_lifetime);
}

#ifdef INSTRUMENT_DOWNLOADS
typedef struct request_t {
  uint64_t bytes; /**< How many bytes have we transferred? */
  uint64_t count; /**< How many requests have we made? */
} request_t;

/** Map used to keep track of how much data we've up/downloaded in what kind
 * of request.  Maps from request type to pointer to request_t. */
static strmap_t *request_map = NULL;

/** Record that a client request of <b>purpose</b> was made, and that
 * <b>bytes</b> bytes of possibly <b>compressed</b> data were sent/received.
 * Used to keep track of how much we've up/downloaded in what kind of
 * request. */
static void
note_client_request(int purpose, int compressed, size_t bytes)
{
  char *key;
  const char *kind = NULL;
  switch (purpose) {
    case DIR_PURPOSE_FETCH_V2_NETWORKSTATUS: kind = "dl/status"; break;
    case DIR_PURPOSE_FETCH_CONSENSUS:     kind = "dl/consensus"; break;
    case DIR_PURPOSE_FETCH_CERTIFICATE:   kind = "dl/cert"; break;
    case DIR_PURPOSE_FETCH_STATUS_VOTE:   kind = "dl/vote"; break;
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES: kind = "dl/detached_sig";
         break;
    case DIR_PURPOSE_FETCH_SERVERDESC:    kind = "dl/server"; break;
    case DIR_PURPOSE_FETCH_EXTRAINFO:     kind = "dl/extra"; break;
    case DIR_PURPOSE_UPLOAD_DIR:          kind = "dl/ul-dir"; break;
    case DIR_PURPOSE_UPLOAD_VOTE:         kind = "dl/ul-vote"; break;
    case DIR_PURPOSE_UPLOAD_SIGNATURES:   kind = "dl/ul-sig"; break;
    case DIR_PURPOSE_FETCH_RENDDESC:      kind = "dl/rend"; break;
    case DIR_PURPOSE_FETCH_RENDDESC_V2:   kind = "dl/rend2"; break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:     kind = "dl/ul-rend"; break;
    case DIR_PURPOSE_UPLOAD_RENDDESC_V2:  kind = "dl/ul-rend2"; break;
  }
  if (kind) {
    key = tor_malloc(256);
    tor_snprintf(key, 256, "%s%s", kind, compressed?".z":"");
  } else {
    key = tor_malloc(256);
    tor_snprintf(key, 256, "unknown purpose (%d)%s",
                 purpose, compressed?".z":"");
  }
  note_request(key, bytes);
  tor_free(key);
}

/** Helper: initialize the request map to instrument downloads. */
static void
ensure_request_map_initialized(void)
{
  if (!request_map)
    request_map = strmap_new();
}

/** Called when we just transmitted or received <b>bytes</b> worth of data
 * because of a request of type <b>key</b> (an arbitrary identifier): adds
 * <b>bytes</b> to the total associated with key. */
void
note_request(const char *key, size_t bytes)
{
  request_t *r;
  ensure_request_map_initialized();

  r = strmap_get(request_map, key);
  if (!r) {
    r = tor_malloc_zero(sizeof(request_t));
    strmap_set(request_map, key, r);
  }
  r->bytes += bytes;
  r->count++;
}

/** Return a newly allocated string holding a summary of bytes used per
 * request type. */
char *
directory_dump_request_log(void)
{
  smartlist_t *lines;
  char tmp[256];
  char *result;
  strmap_iter_t *iter;

  ensure_request_map_initialized();

  lines = smartlist_create();

  for (iter = strmap_iter_init(request_map);
       !strmap_iter_done(iter);
       iter = strmap_iter_next(request_map, iter)) {
    const char *key;
    void *val;
    request_t *r;
    strmap_iter_get(iter, &key, &val);
    r = val;
    tor_snprintf(tmp, sizeof(tmp), "%s  "U64_FORMAT"  "U64_FORMAT"\n",
                 key, U64_PRINTF_ARG(r->bytes), U64_PRINTF_ARG(r->count));
    smartlist_add(lines, tor_strdup(tmp));
  }
  smartlist_sort_strings(lines);
  result = smartlist_join_strings(lines, "", 0, NULL);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  return result;
}
#else
static void
note_client_request(int purpose, int compressed, size_t bytes)
{
  (void)purpose;
  (void)compressed;
  (void)bytes;
}

void
note_request(const char *key, size_t bytes)
{
  (void)key;
  (void)bytes;
}

char *
directory_dump_request_log(void)
{
  return tor_strdup("Not supported.");
}
#endif

/** Decide whether a client would accept the consensus we have
 *
 * Clients can say they only want a consensus if it's signed by more
 * than half the authorities in a list.  They pass this list in
 * the url as "...consensus/<b>fpr</b>+<b>fpr</b>+<b>fpr</b>".
 *
 * <b>fpr</b> may be an abbreviated fingerprint, i.e. only a left substring
 * of the full authority identity digest. (Only strings of even length,
 * i.e. encodings of full bytes, are handled correctly.  In the case
 * of an odd number of hex digits the last one is silently ignored.)
 *
 * Returns 1 if more than half of the requested authorities signed the
 * consensus, 0 otherwise.
 */
int
client_likes_consensus(networkstatus_t *v, const char *want_url)
{
  smartlist_t *want_authorities = smartlist_create();
  int need_at_least;
  int have = 0;

  dir_split_resource_into_fingerprints(want_url, want_authorities, NULL, 0);
  need_at_least = smartlist_len(want_authorities)/2+1;
  SMARTLIST_FOREACH_BEGIN(want_authorities, const char *, d) {
    char want_digest[DIGEST_LEN];
    size_t want_len = strlen(d)/2;
    if (want_len > DIGEST_LEN)
      want_len = DIGEST_LEN;

    if (base16_decode(want_digest, DIGEST_LEN, d, want_len*2) < 0) {
      log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_AUTH_DIGEST_DECODE_FAILED),d);
      continue;
    };

    SMARTLIST_FOREACH_BEGIN(v->voters, networkstatus_voter_info_t *, vi) {
      if (smartlist_len(vi->sigs) &&
          tor_memeq(vi->identity_digest, want_digest, want_len)) {
        have++;
        break;
      };
    } SMARTLIST_FOREACH_END(vi);

    /* early exit, if we already have enough */
    if (have >= need_at_least)
      break;
  } SMARTLIST_FOREACH_END(d);

  SMARTLIST_FOREACH(want_authorities, char *, d, tor_free(d));
  smartlist_free(want_authorities);
  return (have >= need_at_least);
}

/** Helper function: called when a dirserver gets a complete HTTP GET
 * request.  Look for a request for a directory or for a rendezvous
 * service descriptor.  On finding one, write a response into
 * conn-\>outbuf.  If the request is unrecognized, send a 400.
 * Always return 0. */
static int directory_handle_command_get(dir_connection_t *conn, const char *headers,const char *body, size_t body_len)
{	size_t dlen;
	char *url, *url_mem, *header;
	or_options_t *options = get_options();
	time_t if_modified_since = 0;
	int compressed;
	size_t url_len;

	/* We ignore the body of a GET request. */
	(void)body;
	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_RECEIVED_GET));
	conn->_base.state = DIR_CONN_STATE_SERVER_WRITING;
	if(parse_http_url(headers, &url) < 0)
	{	write_http_status_line(conn, 400, "Bad request");
		return 0;
	}
	if((header = http_get_header(headers, "If-Modified-Since: ")))
	{	struct tm tm;
		if(parse_http_time(header, &tm) == 0 && tor_timegm(&tm,&if_modified_since)<0)	if_modified_since = 0;
		/* The correct behavior on a malformed If-Modified-Since header is to act as if no If-Modified-Since header had been given. */
		tor_free(header);
	}
	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_URL_REWRITTEN),url);
	url_mem = url;
	url_len = strlen(url);
	compressed = url_len > 2 && !strcmp(url+url_len-2, ".z");
	if(compressed)
	{	url[url_len-2] = '\0';
		url_len -= 2;
	}
	if(!strcmp(url,"/tor/"))
	{	const char *frontpage = get_dirportfrontpage();
		if(frontpage)
		{	dlen = strlen(frontpage);
			/* Let's return a disclaimer page (users shouldn't use V1 anymore, and caches don't fetch '/', so this is safe). */
			/* [We don't check for write_bucket_low here, since we want to serve  this page no matter what.] */
			note_request(url, dlen);
			write_http_response_header_impl(conn, dlen, "text/html", "identity",NULL, DIRPORTFRONTPAGE_CACHE_LIFETIME);
			connection_write_to_buf(frontpage, dlen, TO_CONN(conn));
			tor_free(url_mem);
			return 0;
		}	/* if no disclaimer file, fall through and continue */
	}
	if(!strcmp(url,"/tor/") || !strcmp(url,"/tor/dir"))	/* v1 dir fetch */
	{	cached_dir_t *d = dirserv_get_directory();
		if(!d)
		{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503));
			write_http_status_line(conn, 503, "Directory unavailable");
		}
		else if(d->published < if_modified_since)
			write_http_status_line(conn, 304, "Not modified");
		else
		{	dlen = compressed ? d->dir_z_len : d->dir_len;
			if(global_write_bucket_low(TO_CONN(conn), dlen, 1))
			{	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503_BUSY));
				write_http_status_line(conn, 503, "Directory busy, try again later");
			}
			else
			{	note_request(url, dlen);
				log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_DIR),compressed?get_lang_str(LANG_LOG_DIR_COMPRESSED):"");
				write_http_response_header(conn, dlen, compressed,FULL_DIR_CACHE_LIFETIME);
				conn->cached_dir = d;
				conn->cached_dir_offset = 0;
				if(!compressed)	conn->zlib_state = tor_zlib_new(0, ZLIB_METHOD);
				++d->refcnt;
				/* Prime the connection with some data. */
				conn->dir_spool_src = DIR_SPOOL_CACHED_DIR;
				connection_dirserv_flushed_some(conn);
			}
		}
	}
	else if(!strcmp(url,"/tor/running-routers"))	/* running-routers fetch */
	{	cached_dir_t *d = dirserv_get_runningrouters();
		if(!d)						write_http_status_line(conn, 503, "Directory unavailable");
		else if(d->published < if_modified_since)	write_http_status_line(conn, 304, "Not modified");
		else
		{	dlen = compressed ? d->dir_z_len : d->dir_len;
			if(global_write_bucket_low(TO_CONN(conn), dlen, 1))
			{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503_3));
				write_http_status_line(conn, 503, "Directory busy, try again later");
			}
			else
			{	note_request(url, dlen);
				write_http_response_header(conn, dlen, compressed,RUNNINGROUTERS_CACHE_LIFETIME);
				connection_write_to_buf(compressed ? d->dir_z : d->dir, dlen,TO_CONN(conn));
			}
		}
	}
	if(!strcmpstart(url,"/tor/status/") || !strcmpstart(url, "/tor/status-vote/current/consensus"))	/* v2 or v3 network status fetch. */
	{	smartlist_t *dir_fps = smartlist_create();
		int is_v3 = !strcmpstart(url, "/tor/status-vote");
		geoip_client_action_t act = is_v3 ? GEOIP_CLIENT_NETWORKSTATUS : GEOIP_CLIENT_NETWORKSTATUS_V2;
		const char *request_type = NULL;
		const char *key = url + strlen("/tor/status/");
		long lifetime = NETWORKSTATUS_CACHE_LIFETIME;
		if(!is_v3)
		{	dirserv_get_networkstatus_v2_fingerprints(dir_fps, key);
			if(!strcmpstart(key, "fp/"))		request_type = compressed?"/tor/status/fp.z":"/tor/status/fp";
			else if(!strcmpstart(key, "authority"))	request_type = compressed?"/tor/status/authority.z":"/tor/status/authority";
			else if(!strcmpstart(key, "all"))	request_type = compressed?"/tor/status/all.z":"/tor/status/all";
			else					request_type = "/tor/status/?";
			is_v3++;
		}
		else
		{	networkstatus_t *v = networkstatus_get_latest_consensus();
			time_t now = get_time(NULL);
			const char *want_fps = NULL;
			char *flavor = NULL;
			#define CONSENSUS_URL_PREFIX "/tor/status-vote/current/consensus/"
			#define CONSENSUS_FLAVORED_PREFIX "/tor/status-vote/current/consensus-"
			/* figure out the flavor if any, and who we wanted to sign the thing */
			if(!strcmpstart(url, CONSENSUS_FLAVORED_PREFIX))
			{	const char *f, *cp;
				f = url + strlen(CONSENSUS_FLAVORED_PREFIX);
				cp = strchr(f, '/');
				if(cp)
				{	want_fps = cp+1;
					flavor = tor_strndup(f, cp-f);
				}
				else	flavor = tor_strdup(f);
			}
			else
			{	if(!strcmpstart(url, CONSENSUS_URL_PREFIX))
					want_fps = url+strlen(CONSENSUS_URL_PREFIX);
			}
			/* XXXX MICRODESC NM NM should check document of correct flavor */
			if(v && want_fps && !client_likes_consensus(v, want_fps))
			{	write_http_status_line(conn, 404, "Consensus not signed by sufficient number of requested authorities");
				smartlist_free(dir_fps);
				geoip_note_ns_response(act, GEOIP_REJECT_NOT_ENOUGH_SIGS);
				tor_free(flavor);
				is_v3 = 0;
			}
			else
			{	char *fp = tor_malloc_zero(DIGEST_LEN);
				if(flavor)	strlcpy(fp, flavor, DIGEST_LEN);
				tor_free(flavor);
				smartlist_add(dir_fps, fp);
				request_type = compressed?"v3.z":"v3";
				lifetime = (v && v->fresh_until > now) ? v->fresh_until - now : 0;
			}
		}
		if(is_v3)
		{	if(!smartlist_len(dir_fps))	/* we failed to create/cache cp */
			{	write_http_status_line(conn, 503, "Network status object unavailable");
				smartlist_free(dir_fps);
				geoip_note_ns_response(act, GEOIP_REJECT_UNAVAILABLE);
			}
			else if(!dirserv_remove_old_statuses(dir_fps, if_modified_since))
			{	write_http_status_line(conn, 404, "Not found");
				SMARTLIST_FOREACH(dir_fps, char *, cp, tor_free(cp));
				smartlist_free(dir_fps);
				geoip_note_ns_response(act, GEOIP_REJECT_NOT_FOUND);
			}
		/*	else if(!smartlist_len(dir_fps))
			{	write_http_status_line(conn, 304, "Not modified");
				SMARTLIST_FOREACH(dir_fps, char *, cp, tor_free(cp));
				smartlist_free(dir_fps);
				geoip_note_ns_response(act, GEOIP_REJECT_NOT_MODIFIED);
			} */
			else
			{	dlen = dirserv_estimate_data_size(dir_fps, 0, compressed);
				if(global_write_bucket_low(TO_CONN(conn), dlen, 2))
				{	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503_4));
					write_http_status_line(conn, 503, "Directory busy, try again later");
					SMARTLIST_FOREACH(dir_fps, char *, fp, tor_free(fp));
					smartlist_free(dir_fps);
					geoip_note_ns_response(act, GEOIP_REJECT_BUSY);
				}
				else
				{	struct in_addr in;
					if(tor_inet_aton((TO_CONN(conn))->address, &in))
					{	geoip_note_client_seen(act, ntohl(in.s_addr), get_time(NULL));
						geoip_note_ns_response(act, GEOIP_SUCCESS);
						/* Note that a request for a network status has started, so that we can measure the download time later on. */
						if(TO_CONN(conn)->dirreq_id)	geoip_start_dirreq(TO_CONN(conn)->dirreq_id, dlen, act,DIRREQ_TUNNELED);
						else				geoip_start_dirreq(TO_CONN(conn)->global_identifier, dlen, act,DIRREQ_DIRECT);
					}
					(void) request_type;	// note_request(request_type,dlen);
					write_http_response_header(conn, -1, compressed,smartlist_len(dir_fps) == 1 ? lifetime : 0);
					conn->fingerprint_stack = dir_fps;
					if(! compressed)	conn->zlib_state = tor_zlib_new(0, ZLIB_METHOD);
					/* Prime the connection with some data. */
					conn->dir_spool_src = DIR_SPOOL_NETWORKSTATUS;
					connection_dirserv_flushed_some(conn);
				}
			}
		}
	}
	else if(!strcmpstart(url,"/tor/status-vote/current/") || !strcmpstart(url,"/tor/status-vote/next/"))
	{	/* XXXX If-modified-since is only implemented for the current consensus: that's probably fine, since it's the only vote document people fetch much. */
		int current;
		body_len = 0;
		ssize_t estimated_len = 0;
		smartlist_t *items = smartlist_create();
		smartlist_t *dir_items = smartlist_create();
		int lifetime = 60; /* XXXX022 should actually use vote intervals. */
		url += strlen("/tor/status-vote/");
		current = !strcmpstart(url, "current/");
		url = strchr(url, '/');
		tor_assert(url);
		++url;
		if(!strcmp(url, "consensus"))
		{	const char *item;
			tor_assert(!current); /* we handle current consensus specially above, since it wants to be spooled. */
			if((item = dirvote_get_pending_consensus(FLAV_NS)))	smartlist_add(items, (char*)item);
		}
		else if(!current && !strcmp(url, "consensus-signatures"))
		{	/* XXXX the spec says that we should implement current/consensus-signatures too.  It doesn't seem to be needed, though. */
			const char *item;
			if((item=dirvote_get_pending_detached_signatures()))	smartlist_add(items, (char*)item);
		}
		else if(!strcmp(url, "authority"))
		{	const cached_dir_t *d;
			int flags = DGV_BY_ID | (current ? DGV_INCLUDE_PREVIOUS : DGV_INCLUDE_PENDING);
			if((d=dirvote_get_vote(NULL, flags)))	smartlist_add(dir_items, (cached_dir_t*)d);
		}
		else
		{	const cached_dir_t *d;
			smartlist_t *fps = smartlist_create();
			int flags;
			if(!strcmpstart(url, "d/"))
			{	url += 2;
				flags = DGV_INCLUDE_PENDING | DGV_INCLUDE_PREVIOUS;
			}
			else	flags = DGV_BY_ID | (current ? DGV_INCLUDE_PREVIOUS : DGV_INCLUDE_PENDING);
			dir_split_resource_into_fingerprints(url, fps, NULL,DSR_HEX|DSR_SORT_UNIQ);
			SMARTLIST_FOREACH(fps, char *, fp,
			{	if((d = dirvote_get_vote(fp, flags)))	smartlist_add(dir_items, (cached_dir_t*)d);
				tor_free(fp);
			});
			smartlist_free(fps);
		}
		if(!smartlist_len(dir_items) && !smartlist_len(items))
			write_http_status_line(conn, 404, "Not found");
		else
		{	SMARTLIST_FOREACH(dir_items, cached_dir_t *, d,
			{	body_len += compressed ? d->dir_z_len : d->dir_len;
			});
			estimated_len += body_len;
			SMARTLIST_FOREACH(items, const char *, item,
			{	size_t ln = strlen(item);
				if(compressed)	estimated_len += ln/2;
				else
				{	body_len += ln; estimated_len += ln;
				}
			});
			if(global_write_bucket_low(TO_CONN(conn), estimated_len, 2))
				write_http_status_line(conn, 503, "Directory busy, try again later.");
			else
			{	write_http_response_header(conn, body_len ? (int)body_len : -1, compressed,lifetime);
				if(smartlist_len(items))
				{	if(compressed)
					{	conn->zlib_state = tor_zlib_new(1, ZLIB_METHOD);
						SMARTLIST_FOREACH(items, const char *, c,
						{	connection_write_to_buf_zlib(c, strlen(c), conn, 0);
						});
						connection_write_to_buf_zlib("", 0, conn, 1);
					}
					else
					{	SMARTLIST_FOREACH(items, const char *, c,
						{	connection_write_to_buf(c, strlen(c), TO_CONN(conn));
						});
					}
				}
				else
				{	SMARTLIST_FOREACH(dir_items, cached_dir_t *, d,
					{	connection_write_to_buf(compressed ? d->dir_z : d->dir,compressed ? d->dir_z_len : d->dir_len,TO_CONN(conn));
					});
				}
			}
		}
		smartlist_free(items);
		smartlist_free(dir_items);
	}
	else if(!strcmpstart(url,"/tor/micro/d/"))
	{	smartlist_t *fps = smartlist_create();
		dir_split_resource_into_fingerprints(url+strlen("/tor/micro/d/"),fps,NULL,DSR_DIGEST256|DSR_BASE64|DSR_SORT_UNIQ);
		if(!dirserv_have_any_microdesc(fps))
		{	write_http_status_line(conn, 404, "Not found");
			SMARTLIST_FOREACH(fps, char *, fp, tor_free(fp));
			smartlist_free(fps);
		}
		else
		{	dlen = dirserv_estimate_microdesc_size(fps, compressed);
			if(global_write_bucket_low(TO_CONN(conn), dlen, 2))
			{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503_5));
				write_http_status_line(conn, 503, "Directory busy, try again later");
				SMARTLIST_FOREACH(fps, char *, fp, tor_free(fp));
				smartlist_free(fps);
			}
			else
			{	write_http_response_header(conn, -1, compressed, MICRODESC_CACHE_LIFETIME);
				conn->dir_spool_src = DIR_SPOOL_MICRODESC;
				conn->fingerprint_stack = fps;
				if(compressed)	conn->zlib_state = tor_zlib_new(1, ZLIB_METHOD);
				connection_dirserv_flushed_some(conn);
			}
		}
	}
	else if(!strcmpstart(url,"/tor/server/") || (!options->BridgeAuthoritativeDir && !options->BridgeRelay && !strcmpstart(url,"/tor/extra/")))
	{	int res;
		const char *msg;
		const char *request_type = NULL;
		int cache_lifetime = 0;
		int is_extra = !strcmpstart(url,"/tor/extra/");
		url += is_extra ? strlen("/tor/extra/") : strlen("/tor/server/");
		conn->fingerprint_stack = smartlist_create();
		res = dirserv_get_routerdesc_fingerprints(conn->fingerprint_stack, url,&msg,!connection_dir_is_encrypted(conn),is_extra);
		if(!strcmpstart(url, "fp/"))
		{	request_type = compressed?"/tor/server/fp.z":"/tor/server/fp";
			if(smartlist_len(conn->fingerprint_stack) == 1)	cache_lifetime = ROUTERDESC_CACHE_LIFETIME;
		}
		else if(!strcmpstart(url, "authority"))
		{	request_type = compressed?"/tor/server/authority.z":"/tor/server/authority";
			cache_lifetime = ROUTERDESC_CACHE_LIFETIME;
		}
		else if(!strcmpstart(url, "all"))
		{	request_type = compressed?"/tor/server/all.z":"/tor/server/all";
			cache_lifetime = FULL_DIR_CACHE_LIFETIME;
		}
		else if(!strcmpstart(url, "d/"))
		{	request_type = compressed?"/tor/server/d.z":"/tor/server/d";
			if(smartlist_len(conn->fingerprint_stack) == 1)	cache_lifetime = ROUTERDESC_BY_DIGEST_CACHE_LIFETIME;
		}
		else	request_type = "/tor/server/?";
		(void) request_type; /* usable for note_request. */
		if(!strcmpstart(url, "d/"))	conn->dir_spool_src = is_extra ? DIR_SPOOL_EXTRA_BY_DIGEST : DIR_SPOOL_SERVER_BY_DIGEST;
		else				conn->dir_spool_src = is_extra ? DIR_SPOOL_EXTRA_BY_FP : DIR_SPOOL_SERVER_BY_FP;
		if(!dirserv_have_any_serverdesc(conn->fingerprint_stack,conn->dir_spool_src))
		{	res = -1;
			msg = "Not found";
		}
		if(res < 0)	write_http_status_line(conn, 404, msg);
		else
		{	dlen = dirserv_estimate_data_size(conn->fingerprint_stack,1, compressed);
			if(global_write_bucket_low(TO_CONN(conn), dlen, 2))
			{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_HTTP_SEND_503_5));
				write_http_status_line(conn, 503, "Directory busy, try again later");
				conn->dir_spool_src = DIR_SPOOL_NONE;
			}
			else
			{	write_http_response_header(conn, -1, compressed, cache_lifetime);
				if(compressed)	conn->zlib_state = tor_zlib_new(1, ZLIB_METHOD);
				/* Prime the connection with some data. */
				connection_dirserv_flushed_some(conn);
			}
		}
	}
	else if(!strcmpstart(url,"/tor/keys/"))
	{	smartlist_t *certs = smartlist_create();
		ssize_t len = -1;
		if(!strcmp(url, "/tor/keys/all"))	authority_cert_get_all(certs);
		else if(!strcmp(url, "/tor/keys/authority"))
		{	authority_cert_t *cert = get_my_v3_authority_cert();
			if(cert)	smartlist_add(certs, cert);
		}
		else if(!strcmpstart(url, "/tor/keys/fp/"))
		{	smartlist_t *fps = smartlist_create();
			dir_split_resource_into_fingerprints(url+strlen("/tor/keys/fp/"),fps, NULL,DSR_HEX|DSR_SORT_UNIQ);
			SMARTLIST_FOREACH(fps, char *, d,
			{	authority_cert_t *c = authority_cert_get_newest_by_id(d);
				if(c)	smartlist_add(certs, c);
				tor_free(d);
			});
			smartlist_free(fps);
		}
		else if(!strcmpstart(url, "/tor/keys/sk/"))
		{	smartlist_t *fps = smartlist_create();
			dir_split_resource_into_fingerprints(url+strlen("/tor/keys/sk/"),fps, NULL,DSR_HEX|DSR_SORT_UNIQ);
			SMARTLIST_FOREACH(fps, char *, d,
			{	authority_cert_t *c = authority_cert_get_by_sk_digest(d);
				if(c)	smartlist_add(certs, c);
				tor_free(d);
			});
			smartlist_free(fps);
		}
		else if(!strcmpstart(url, "/tor/keys/fp-sk/"))
		{	smartlist_t *fp_sks = smartlist_create();
			dir_split_resource_into_fingerprint_pairs(url+strlen("/tor/keys/fp-sk/"),fp_sks);
			SMARTLIST_FOREACH(fp_sks, fp_pair_t *, pair,
			{	authority_cert_t *c = authority_cert_get_by_digests(pair->first,pair->second);
				if(c)	smartlist_add(certs, c);
				tor_free(pair);
			});
			smartlist_free(fp_sks);
		}
		else	len = 0;
		if(!len)			write_http_status_line(conn, 400, "Bad request");
		if(!smartlist_len(certs))	write_http_status_line(conn, 404, "Not found");
		else
		{	SMARTLIST_FOREACH(certs, authority_cert_t *, c,
			{	if(c->cache_info.published_on < if_modified_since)	SMARTLIST_DEL_CURRENT(certs, c);
			});
			if(!smartlist_len(certs))	write_http_status_line(conn, 304, "Not modified");
			else
			{	len = 0;
				SMARTLIST_FOREACH(certs, authority_cert_t *, c,
				{	len += c->cache_info.signed_descriptor_len;
				});
				if(global_write_bucket_low(TO_CONN(conn), compressed?len/2:len, 2))
					write_http_status_line(conn, 503, "Directory busy, try again later.");
				else
				{	write_http_response_header(conn, compressed?-1:len, compressed, 60*60);
					if(compressed)
					{	conn->zlib_state = tor_zlib_new(1, ZLIB_METHOD);
						SMARTLIST_FOREACH(certs, authority_cert_t *, c,
						{	connection_write_to_buf_zlib(c->cache_info.signed_descriptor_body,c->cache_info.signed_descriptor_len,conn,0);
						});
						connection_write_to_buf_zlib("", 0, conn, 1);
					}
					else
					{	SMARTLIST_FOREACH(certs, authority_cert_t *, c,
						{	connection_write_to_buf(c->cache_info.signed_descriptor_body,c->cache_info.signed_descriptor_len,TO_CONN(conn));
						});
					}
				}
			}
		}
		smartlist_free(certs);
	}
	else if(options->HidServDirectoryV2 && !strcmpstart(url,"/tor/rendezvous2/"))	/* Handle v2 rendezvous descriptor fetch request. */
	{	const char *descp;
		const char *query = url + strlen("/tor/rendezvous2/");
		if(strlen(query) == REND_DESC_ID_V2_LEN_BASE32)
		{	log_info(LD_REND,get_lang_str(LANG_LOG_DIR_RECEIVED_REND_V2_REQUEST),safe_str(query));
			switch (rend_cache_lookup_v2_desc_as_dir(query, &descp))
			{	case 1: /* valid */
					write_http_response_header(conn, strlen(descp), 0, 0);
					connection_write_to_buf(descp, strlen(descp), TO_CONN(conn));
					break;
				case 0: /* well-formed but not present */
					write_http_status_line(conn, 404, "Not found");
					break;
				case -1: /* not well-formed */
					write_http_status_line(conn, 400, "Bad request");
					break;
			}
		}
		else	write_http_status_line(conn, 400, "Bad request");	/* not well-formed */
	}
	else if(options->HSAuthoritativeDir && !strcmpstart(url,"/tor/rendezvous/"))	/* rendezvous descriptor fetch */
	{	const char *descp;
		size_t desc_len;
		const char *query = url+strlen("/tor/rendezvous/");
		log_info(LD_REND,get_lang_str(LANG_LOG_DIR_HANDLING_REND_GET));
		switch(rend_cache_lookup_desc(query, 0, &descp, &desc_len))
		{	case 1: /* valid */
				write_http_response_header_impl(conn, desc_len,"application/octet-stream",NULL,NULL,0);
				note_request("/tor/rendezvous?/", desc_len);
				/* need to send descp separately, because it may include NULs */
				connection_write_to_buf(descp, desc_len, TO_CONN(conn));
				break;
			case 0: /* well-formed but not present */
				write_http_status_line(conn, 404, "Not found");
				break;
			case -1: /* not well-formed */
				write_http_status_line(conn, 400, "Bad request");
				break;
		}
	}
	else if(options->BridgeAuthoritativeDir && options->_BridgePassword_AuthDigest && connection_dir_is_encrypted(conn) && !strcmp(url,"/tor/networkstatus-bridges"))
	{	char *status;
		char digest[DIGEST256_LEN];
		header = http_get_header(headers, "Authorization: Basic ");
		if(header)	crypto_digest256(digest,header,strlen(header),DIGEST_SHA256);
		/* now make sure the password is there and right */
		if(!header || tor_memneq(digest,options->_BridgePassword_AuthDigest,DIGEST256_LEN))
			write_http_status_line(conn, 404, "Not found");
		else	/* all happy now. send an answer. */
		{	status = networkstatus_getinfo_by_purpose("bridge", get_time(NULL));
			dlen = strlen(status);
			write_http_response_header(conn, dlen, 0, 0);
			connection_write_to_buf(status, dlen, TO_CONN(conn));
			tor_free(status);
		}
		tor_free(header);
	}
/*	else if(!strcmpstart(url,"/tor/bytes.txt"))
	{	char *bytes = directory_dump_request_log();
		size_t len = strlen(bytes);
		write_http_response_header(conn, len, 0, 0);
		connection_write_to_buf(bytes, len, TO_CONN(conn));
		tor_free(bytes);
	}*/
	else if(!strcmp(url,"/tor/robots.txt"))	/* /robots.txt will have been rewritten to /tor/robots.txt */
	{	char robots[] = "User-agent: *\r\nDisallow: /\r\n";
		size_t len = strlen(robots);
		write_http_response_header(conn, len, 0, ROBOTS_CACHE_LIFETIME);
		connection_write_to_buf(robots, len, TO_CONN(conn));
	}
/*	else if(!strcmp(url,"/tor/dbg-stability.txt"))
	{	const char *stability;
		size_t len;
		if(options->BridgeAuthoritativeDir || ! authdir_mode_tests_reachability(options) || ! (stability = rep_hist_get_router_stability_doc(get_time(NULL))))
			write_http_status_line(conn, 404, "Not found.");
		else
		{	len = strlen(stability);
			write_http_response_header(conn, len, 0, 0);
			connection_write_to_buf(stability, len, TO_CONN(conn));
		}
	}*/
	/*	#if defined(EXPORTMALLINFO) && defined(HAVE_MALLOC_H) && defined(HAVE_MALLINFO)
		#define ADD_MALLINFO_LINE(x) do {	tor_snprintf(tmp, sizeof(tmp), "%s %d\n", #x, mi.x); smartlist_add(lines, tor_strdup(tmp));}while(0);
	else if(!strcmp(url,"/tor/mallinfo.txt") && (tor_addr_eq_ipv4h(&conn->_base.addr, 0x7f000001ul)))
	{	char *result;
		size_t len;
		struct mallinfo mi;
		smartlist_t *lines;
		char tmp[256];
		memset(&mi, 0, sizeof(mi));
		mi = mallinfo();
		lines = smartlist_create();
		ADD_MALLINFO_LINE(arena)
		ADD_MALLINFO_LINE(ordblks)
		ADD_MALLINFO_LINE(smblks)
		ADD_MALLINFO_LINE(hblks)
		ADD_MALLINFO_LINE(hblkhd)
		ADD_MALLINFO_LINE(usmblks)
		ADD_MALLINFO_LINE(fsmblks)
		ADD_MALLINFO_LINE(uordblks)
		ADD_MALLINFO_LINE(fordblks)
		ADD_MALLINFO_LINE(keepcost)
		result = smartlist_join_strings(lines, "", 0, NULL);
		SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
		smartlist_free(lines);
		len = strlen(result);
		write_http_response_header(conn, len, 0, 0);
		connection_write_to_buf(result, len, TO_CONN(conn));
		tor_free(result);
	}
		#endif
	*/
	else	write_http_status_line(conn, 404, "Not found");		/* we didn't recognize the url */
	tor_free(url_mem);
	return 0;
}

/** Helper function: called when a dirserver gets a complete HTTP POST
 * request.  Look for an uploaded server descriptor or rendezvous
 * service descriptor.  On finding one, process it and write a
 * response into conn-\>outbuf.  If the request is unrecognized, send a
 * 400.  Always return 0. */
static int directory_handle_command_post(dir_connection_t *conn, const char *headers,const char *body, size_t body_len)
{	char *url = NULL;
	or_options_t *options = get_options();
	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_RECEIVED_POST));
	conn->_base.state = DIR_CONN_STATE_SERVER_WRITING;
	if(parse_http_url(headers, &url) < 0)
	{	write_http_status_line(conn, 400, "Bad request");
		return 0;
	}
	log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_URL_REWRITTEN), url);
	/* Handle v2 rendezvous service publish request. */
	if(options->HidServDirectoryV2 && !strcmpstart(url,"/tor/rendezvous2/publish"))
	{	switch(rend_cache_store_v2_desc_as_dir(body))
		{	case -2:
				log_info(LD_REND,get_lang_str(LANG_LOG_DIR_REJECT_REND_V2),(int)body_len,conn->_base.address);
				write_http_status_line(conn, 503, "Currently not acting as v2 hidden service directory");
				break;
			case -1:
				log_warn(LD_REND,get_lang_str(LANG_LOG_DIR_REJECT_REND_V2_2),(int)body_len,conn->_base.address);
				write_http_status_line(conn, 400,"Invalid v2 service descriptor rejected");
				break;
			default:
				write_http_status_line(conn, 200, "Service descriptor (v2) stored");
				log_info(LD_REND,get_lang_str(LANG_LOG_DIR_ACCEPT_REND_POST));
		}
	}
	else if(!authdir_mode(options))	/* we just provide cached directories; we don't want to receive anything. */
		write_http_status_line(conn, 400, "Nonauthoritative directory does not accept posted server descriptors");
	else if(authdir_mode_handles_descs(options, -1) && !strcmp(url,"/tor/"))	/* server descriptor post */
	{	const char *msg = "[None]";
		uint8_t purpose = authdir_mode_bridge(options) ? ROUTER_PURPOSE_BRIDGE : ROUTER_PURPOSE_GENERAL;
		was_router_added_t r = dirserv_add_multiple_descriptors(body, purpose,conn->_base.address, &msg);
		tor_assert(msg);
		if(WRA_WAS_ADDED(r))	dirserv_get_directory(); /* rebuild and write to disk */
		if(r == ROUTER_ADDED_NOTIFY_GENERATOR)	/* Accepted with a message. */
		{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_ROUTER_DESC_ERROR),conn->_base.address,msg);
			write_http_status_line(conn, 400, msg);
		}
		else if(r == ROUTER_ADDED_SUCCESSFULLY)
			write_http_status_line(conn, 200, msg);
		else if(WRA_WAS_OUTDATED(r))
			write_http_response_header_impl(conn, -1, NULL, NULL,"X-Descriptor-Not-New: Yes\r\n", -1);
		else
		{	log_info(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_REJECT_ROUTER_DESC),conn->_base.address,msg);
			write_http_status_line(conn, 400, msg);
		}
	}
	else if(options->HSAuthoritativeDir && !strcmpstart(url,"/tor/rendezvous/publish"))	/* rendezvous descriptor post */
	{	log_info(LD_REND,get_lang_str(LANG_LOG_DIR_HANDLING_REND_POST));
		if(rend_cache_store(body, body_len, 1,NULL) < 0)
		{	log_fn(LOG_PROTOCOL_WARN, LD_DIRSERV,get_lang_str(LANG_LOG_DIR_REJECT_REND_DESC),(int)body_len, conn->_base.address);
			write_http_status_line(conn, 400,"Invalid v0 service descriptor rejected");
		}
		else	write_http_status_line(conn, 200, "Service descriptor (v0) stored");
	}
	else if(authdir_mode_v3(options) && !strcmp(url,"/tor/post/vote"))	/* v3 networkstatus vote */
	{	const char *msg = "OK";
		int status;
		if(dirvote_add_vote(body, &msg, &status))
			write_http_status_line(conn, status, "Vote stored");
		else
		{	tor_assert(msg);
			log_warn(LD_DIRSERV,get_lang_str(LANG_LOG_DIRECTORY_REJECT_VOTE),conn->_base.address,msg);
			write_http_status_line(conn, status, msg);
		}
	}
	else if(authdir_mode_v3(options) && !strcmp(url,"/tor/post/consensus-signature"))	/* sigs on consensus. */
	{	const char *msg = NULL;
		if(dirvote_add_signatures(body, conn->_base.address, &msg)>=0)
			write_http_status_line(conn, 200, msg?msg:"Signatures stored");
		else
		{	log_warn(LD_DIR,get_lang_str(LANG_LOG_DIR_SIGNATURE_STORE_FAILED),conn->_base.address,msg?msg:"???");
			write_http_status_line(conn, 400, msg?msg:"Unable to store signatures");
		}
	}
	else	write_http_status_line(conn, 404, "Not found");		/* we didn't recognize the url */

	tor_free(url);
	return 0;
}

/** Called when a dirserver receives data on a directory connection;
 * looks for an HTTP request.  If the request is complete, remove it
 * from the inbuf, try to process it; otherwise, leave it on the
 * buffer.  Return a 0 on success, or -1 on error.
 */
static int
directory_handle_command(dir_connection_t *conn)
{
  char *headers=NULL, *body=NULL;
  size_t body_len=0;
  int r;

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  switch (fetch_from_buf_http(conn->_base.inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_DIR_UL_SIZE, 0)) {
    case -1: /* overflow */
      log_warn(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_INVALID_INPUT),conn->_base.address);
      return -1;
    case 0:
      log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_COMMAND_INCOMPLETE));
      return 0;
    /* case 1, fall through */
  }

  http_set_address_origin(headers, TO_CONN(conn));
  //log_debug(LD_DIRSERV,"headers %s, body %s.", headers, body);

  if (!strncasecmp(headers,"GET",3))
    r = directory_handle_command_get(conn, headers, body, body_len);
  else if (!strncasecmp(headers,"POST",4))
    r = directory_handle_command_post(conn, headers, body, body_len);
  else {
    char *esc_l = esc_for_log(headers);
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_DIR_HTTP_UNKNOWN_COMMAND),esc_l);
    tor_free(esc_l);
    r = -1;
  }

  tor_free(headers); tor_free(body);
  return r;
}

/** Write handler for directory connections; called when all data has
 * been flushed.  Close the connection or wait for a response as
 * appropriate.
 */
int
connection_dir_finished_flushing(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  /* Note that we have finished writing the directory response. For direct
   * connections this means we're done, for tunneled connections its only
   * an intermediate step. */
  if (TO_CONN(conn)->dirreq_id)
    geoip_change_dirreq_state(TO_CONN(conn)->dirreq_id, DIRREQ_TUNNELED,
                              DIRREQ_FLUSHING_DIR_CONN_FINISHED);
  else
    geoip_change_dirreq_state(TO_CONN(conn)->global_identifier,
                              DIRREQ_DIRECT,
                              DIRREQ_FLUSHING_DIR_CONN_FINISHED);
  switch (conn->_base.state) {
    case DIR_CONN_STATE_PROXY_HANDSHAKING:
      connection_stop_writing(TO_CONN(conn));
      return 0;
    case DIR_CONN_STATE_CLIENT_SENDING:
      log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_CLIENT_FINISHED_SENDING_COMMAND));
      conn->_base.state = DIR_CONN_STATE_CLIENT_READING;
      connection_stop_writing(TO_CONN(conn));
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      log_debug(LD_DIRSERV,get_lang_str(LANG_LOG_DIR_FINISHED_WRITING_SERVER_RESPONSE));
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_UNEXPECTED_STATE),conn->_base.state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for directory connections: begin sending data to the
 * server */
int
connection_dir_finished_connecting(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);
  tor_assert(conn->_base.state == DIR_CONN_STATE_CONNECTING);

  log_debug(LD_HTTP,get_lang_str(LANG_LOG_DIR_CONNECTION_ESTABLISHED),conn->_base.address,conn->_base.port);
  tor_snprintf(last_dir_status,256,get_lang_str(LANG_LOG_DIR_STATUS_CONN_ESTABLISHED),conn->_base.address?conn->_base.address:"");updateDirStatus();
	if(get_options()->DirFlags&DIR_FLAG_NTLM_PROXY && get_options()->CorporateProxy)
	{	connection_t *c = TO_CONN(conn);
		if(dir_proxy_connect(c,1) < 0)
		{	connection_mark_for_close(c);
			return -1;
		}
		connection_start_reading(c);
		c->state = DIR_CONN_STATE_PROXY_HANDSHAKING;
		return 0;
	}
	else if(get_options()->DirFlags&DIR_FLAG_HTTP_PROXY && get_options()->DirProxy && get_options()->DirProxyProtocol != PROXY_HTTP)
	{	connection_t *c = TO_CONN(conn);
		if(dir_proxy_connect(c,0) < 0)
		{	connection_mark_for_close(c);
			return -1;
		}
		connection_start_reading(c);
		c->state = DIR_CONN_STATE_PROXY_HANDSHAKING;
		return 0;
	}
  conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
  return 0;
}

/** Called when one or more networkstatus fetches have failed (with uppercase
 * fingerprints listed in <b>failed</b>).  Mark those fingerprints as having
 * failed once, unless they failed with status code 503. */
static void
dir_networkstatus_download_failed(smartlist_t *failed, int status_code)
{
  if (status_code == 503)
    return;
  SMARTLIST_FOREACH(failed, const char *, fp,
  {
    char digest[DIGEST_LEN];
    trusted_dir_server_t *dir;
    if (base16_decode(digest, DIGEST_LEN, fp, strlen(fp))<0) {
      char *esc_l = esc_for_log(fp);
      log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT),esc_l);
      tor_free(esc_l);
      continue;
    }
    dir = router_get_trusteddirserver_by_digest(digest);

    if (dir)
      download_status_failed(&dir->v2_ns_dl_status, status_code);
  });
}

/** Schedule for when servers should download things in general. */
static const int server_dl_schedule[] = {
  0, 0, 0, 60, 60, 60*2, 60*5, 60*15, INT_MAX
};
/** Schedule for when clients should download things in general. */
static const int client_dl_schedule[] = {
  0, 0, 60, 60*5, 60*10, INT_MAX
};
/** Schedule for when servers should download consensuses. */
static const int server_consensus_dl_schedule[] = {
  0, 0, 60, 60*5, 60*10, 60*30, 60*30, 60*30, 60*30, 60*30, 60*60, 60*60*2
};
/** Schedule for when clients should download consensuses. */
static const int client_consensus_dl_schedule[] = {
  0, 0, 60, 60*5, 60*10, 60*30, 60*60, 60*60, 60*60, 60*60*3, 60*60*6, 60*60*12
};
/** Schedule for when clients should download bridge descriptors. */
static const int bridge_dl_schedule[] = {
  60*60, 15*60, 15*60, 60*60
};

/** Decide which download schedule we want to use, and then return a
 * pointer to it along with a pointer to its length. Helper function for
 * download_status_increment_failure() and download_status_reset(). */
static void
find_dl_schedule_and_len(download_status_t *dls, int server,
                         const int **schedule, size_t *schedule_len)
{
  switch (dls->schedule) {
    case DL_SCHED_GENERIC:
      if (server) {
        *schedule = server_dl_schedule;
        *schedule_len = sizeof(server_dl_schedule)/sizeof(int);
      } else {
        *schedule = client_dl_schedule;
        *schedule_len = sizeof(client_dl_schedule)/sizeof(int);
      }
      break;
    case DL_SCHED_CONSENSUS:
      if (server) {
        *schedule = server_consensus_dl_schedule;
        *schedule_len = sizeof(server_consensus_dl_schedule)/sizeof(int);
      } else {
        *schedule = client_consensus_dl_schedule;
        *schedule_len = sizeof(client_consensus_dl_schedule)/sizeof(int);
      }
      break;
    case DL_SCHED_BRIDGE:
      *schedule = bridge_dl_schedule;
      *schedule_len = sizeof(bridge_dl_schedule)/sizeof(int);
      break;
    default:
      tor_assert(0);
  }
}

/** Called when an attempt to download <b>dls</b> has failed with HTTP status
 * <b>status_code</b>.  Increment the failure count (if the code indicates a
 * real failure) and set <b>dls</b>-\>next_attempt_at to an appropriate time
 * in the future. */
time_t
download_status_increment_failure(download_status_t *dls, int status_code,
                                  const char *item, int server, time_t now)
{
  const int *schedule;
  size_t schedule_len;
  int increment;
  tor_assert(dls);
  if (status_code != 503 || server) {
    if (dls->n_download_failures < IMPOSSIBLE_TO_DOWNLOAD-1)
      ++dls->n_download_failures;
  }

  find_dl_schedule_and_len(dls, server, &schedule, &schedule_len);

  if (dls->n_download_failures < schedule_len)
    increment = schedule[dls->n_download_failures];
  else if (dls->n_download_failures == IMPOSSIBLE_TO_DOWNLOAD)
    increment = INT_MAX;
  else
    increment = schedule[schedule_len-1];

  if (increment < INT_MAX)
    dls->next_attempt_at = now+increment;
  else
    dls->next_attempt_at = TIME_MAX;

  if (item) {
    if (increment == 0)
      log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_INCREMENT_FAILURES_1),item,(int)dls->n_download_failures);
    else if (dls->next_attempt_at < TIME_MAX)
      log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_INCREMENT_FAILURES_2),item,(int)dls->n_download_failures,(int)(dls->next_attempt_at-now));
    else
      log_debug(LD_DIR,get_lang_str(LANG_LOG_DIR_INCREMENT_FAILURES_3),item,(int)dls->n_download_failures);
  }
  return dls->next_attempt_at;
}

/** Reset <b>dls</b> so that it will be considered downloadable
 * immediately, and/or to show that we don't need it anymore.
 *
 * (We find the zeroth element of the download schedule, and set
 * next_attempt_at to be the appropriate offset from 'now'. In most
 * cases this means setting it to 'now', so the item will be immediately
 * downloadable; in the case of bridge descriptors, the zeroth element
 * is an hour from now.) */
void
download_status_reset(download_status_t *dls)
{
  const int *schedule;
  size_t schedule_len;

  find_dl_schedule_and_len(dls, get_options()->DirPort,
                           &schedule, &schedule_len);

  dls->n_download_failures = 0;
  dls->next_attempt_at = get_time(NULL) + schedule[0];
}

/** Return the number of failures on <b>dls</b> since the last success (if
 * any). */
int
download_status_get_n_failures(const download_status_t *dls)
{
  return dls->n_download_failures;
}

/** Called when one or more routerdesc (or extrainfo, if <b>was_extrainfo</b>)
 * fetches have failed (with uppercase fingerprints listed in <b>failed</b>,
 * either as descriptor digests or as identity digests based on
 * <b>was_descriptor_digests</b>).
 */
static void
dir_routerdesc_download_failed(smartlist_t *failed, int status_code,
                               int router_purpose,
                               int was_extrainfo, int was_descriptor_digests)
{
  char digest[DIGEST_LEN];
  time_t now = get_time(NULL);
  int server = directory_fetches_from_authorities(get_options());
  if (!was_descriptor_digests) {
    if (router_purpose == ROUTER_PURPOSE_BRIDGE) {
      tor_assert(!was_extrainfo);
      connection_dir_retry_bridges(failed);
    }
    return; /* FFFF should implement for other-than-router-purpose someday */
  }
  SMARTLIST_FOREACH(failed, const char *, cp,
  {
    download_status_t *dls = NULL;
    if (base16_decode(digest, DIGEST_LEN, cp, strlen(cp)) < 0) {
      char *esc_l = esc_for_log(cp);
      log_warn(LD_BUG,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_2),esc_l);
      tor_free(esc_l);
      continue;
    }
    if (was_extrainfo) {
      signed_descriptor_t *sd =
        router_get_by_extrainfo_digest(digest);
      if (sd)
        dls = &sd->ei_dl_status;
    } else {
      dls = router_get_dl_status_by_descriptor_digest(digest);
    }
    if (!dls || dls->n_download_failures >= (get_options()->MaxDlFailures?get_options()->MaxDlFailures:32767))
      continue;
    download_status_increment_failure(dls, status_code, cp, server, now);
  });

  /* No need to relaunch descriptor downloads here: we already do it
   * every 10 or 60 seconds (FOO_DESCRIPTOR_RETRY_INTERVAL) in main.c. */
}

/** Helper.  Compare two fp_pair_t objects, and return -1, 0, or 1 as
 * appropriate. */
static int
_compare_pairs(const void **a, const void **b)
{
  const fp_pair_t *fp1 = *a, *fp2 = *b;
  int r;
  if ((r = fast_memcmp(fp1->first, fp2->first, DIGEST_LEN)))
    return r;
  else
    return fast_memcmp(fp1->second, fp2->second, DIGEST_LEN);
}

/** Divide a string <b>res</b> of the form FP1-FP2+FP3-FP4...[.z], where each
 * FP is a hex-encoded fingerprint, into a sequence of distinct sorted
 * fp_pair_t. Skip malformed pairs. On success, return 0 and add those
 * fp_pair_t into <b>pairs_out</b>.  On failure, return -1. */
int
dir_split_resource_into_fingerprint_pairs(const char *res,
                                          smartlist_t *pairs_out)
{
  smartlist_t *pairs_tmp = smartlist_create();
  smartlist_t *pairs_result = smartlist_create();
  char *esc_l;

  smartlist_split_string(pairs_tmp, res, "+", 0, 0);
  if (smartlist_len(pairs_tmp)) {
    char *last = smartlist_get(pairs_tmp,smartlist_len(pairs_tmp)-1);
    size_t last_len = strlen(last);
    if (last_len > 2 && !strcmp(last+last_len-2, ".z")) {
      last[last_len-2] = '\0';
    }
  }
  SMARTLIST_FOREACH_BEGIN(pairs_tmp, char *, cp) {
    if (strlen(cp) != HEX_DIGEST_LEN*2+1) {
      esc_l = esc_for_log(cp);
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_3),esc_l);
      tor_free(esc_l);
    } else if (cp[HEX_DIGEST_LEN] != '-') {
      esc_l = esc_for_log(cp);
      log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_4),esc_l);
      tor_free(esc_l);
    } else {
      fp_pair_t pair;
      if (base16_decode(pair.first, DIGEST_LEN, cp, HEX_DIGEST_LEN)<0 ||
          base16_decode(pair.second,
                        DIGEST_LEN, cp+HEX_DIGEST_LEN+1, HEX_DIGEST_LEN)<0) {
	esc_l = esc_for_log(cp);
        log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_5),esc_l);
	tor_free(esc_l);
      } else {
        smartlist_add(pairs_result, tor_memdup(&pair, sizeof(pair)));
      }
    }
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(pairs_tmp);

  /* Uniq-and-sort */
  smartlist_sort(pairs_result, _compare_pairs);
  smartlist_uniq(pairs_result, _compare_pairs, _tor_free_);

  smartlist_add_all(pairs_out, pairs_result);
  smartlist_free(pairs_result);
  return 0;
}

/** Given a directory <b>resource</b> request, containing zero
 * or more strings separated by plus signs, followed optionally by ".z", store
 * the strings, in order, into <b>fp_out</b>.  If <b>compressed_out</b> is
 * non-NULL, set it to 1 if the resource ends in ".z", else set it to 0.  If
 * decode_hex is true, then delete all elements that aren't hex digests, and
 * decode the rest.  If sort_uniq is true, then sort the list and remove
 * all duplicates.
 */
int dir_split_resource_into_fingerprints(const char *resource,smartlist_t *fp_out, int *compressed_out,int flags)
{	const int decode_hex = flags & DSR_HEX;
	const int decode_base64 = flags & DSR_BASE64;
	const int digests_are_256 = flags & DSR_DIGEST256;
	const int sort_uniq = flags & DSR_SORT_UNIQ;
	const int digest_len = digests_are_256 ? DIGEST256_LEN : DIGEST_LEN;
	const int hex_digest_len = digests_are_256 ? HEX_DIGEST256_LEN : HEX_DIGEST_LEN;
	const int base64_digest_len = digests_are_256 ? BASE64_DIGEST256_LEN : BASE64_DIGEST_LEN;
	smartlist_t *fp_tmp = smartlist_create();

	tor_assert(!(decode_hex && decode_base64));
	tor_assert(fp_out);
	smartlist_split_string(fp_tmp, resource, decode_base64?"-":"+", 0, 0);

	if(compressed_out)	*compressed_out = 0;
	if(smartlist_len(fp_tmp))
	{	char *last = smartlist_get(fp_tmp,smartlist_len(fp_tmp)-1);
		size_t last_len = strlen(last);
		if(last_len > 2 && !strcmp(last+last_len-2, ".z"))
		{	last[last_len-2] = '\0';
			if(compressed_out)	*compressed_out = 1;
		}
	}
	if(decode_hex || decode_base64)
	{	const size_t encoded_len = decode_hex ? hex_digest_len : base64_digest_len;
		int i;
		char *cp, *d = NULL;
		for(i = 0; i < smartlist_len(fp_tmp); ++i)
		{	cp = smartlist_get(fp_tmp, i);
			if(strlen(cp) != encoded_len)
			{	char *esc_l = esc_for_log(cp);
				log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_6),esc_l);
				tor_free(esc_l);
				smartlist_del_keeporder(fp_tmp, i--);
			}
			else
			{	d = tor_malloc_zero(digest_len);
				if(decode_hex ? (base16_decode(d, digest_len, cp, hex_digest_len)<0) : (base64_decode(d, digest_len, cp, base64_digest_len)<0))
				{	char *esc_l = esc_for_log(cp);
					log_info(LD_DIR,get_lang_str(LANG_LOG_DIR_BAD_FINGERPRINT_7),esc_l);
					tor_free(esc_l);
					smartlist_del_keeporder(fp_tmp, i--);
				}
				else
				{	smartlist_set(fp_tmp, i, d);
					d = NULL;
				}
			}
			tor_free(cp);
		}
	}
	if(sort_uniq)
	{	if(decode_hex || decode_base64)
		{	if(digests_are_256)
			{	smartlist_sort_digests256(fp_tmp);
				smartlist_uniq_digests256(fp_tmp);
			}
			else
			{	smartlist_sort_digests(fp_tmp);
				smartlist_uniq_digests(fp_tmp);
			}
		}
		else
		{	smartlist_sort_strings(fp_tmp);
			smartlist_uniq_strings(fp_tmp);
		}
	}
	smartlist_add_all(fp_out, fp_tmp);
	smartlist_free(fp_tmp);
	return 0;
}
