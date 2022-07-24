/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerlist.c
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

#include "or.h"
#include "circuitbuild.h"
#include "config.h"
#include "connection.h"
#include "control.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "geoip.h"
#include "hibernate.h"
#include "main.h"
#include "networkstatus.h"
#include "policies.h"
#include "reasons.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include <commctrl.h>

extern or_options_t *tmpOptions;

// #define DEBUG_ROUTERLIST
void plugins_routerchanged(uint32_t addr,char *digest,int changed);
int dlgBypassBlacklists_isRecent(uint32_t addr,routerinfo_t *router,time_t now);
void insert_router_1(HWND hDlg,uint32_t lParam1,const char *country,const char *address,const char *rname,const char *bw,const char *is_exit);

/****************************************************************************/

/* static function prototypes */
static routerstatus_t *router_pick_directory_server_impl(
                                           authority_type_t auth, int flags);
static routerstatus_t *router_pick_trusteddirserver_impl(
                          authority_type_t auth, int flags, int *n_busy_out);
static void mark_all_trusteddirservers_up(void);
static int router_nickname_matches(routerinfo_t *router, const char *nickname);
static void trusted_dir_server_free(trusted_dir_server_t *ds);
static void launch_router_descriptor_downloads(smartlist_t *downloadable,
                                               routerstatus_t *source,
                                               time_t now);
static int signed_desc_digest_is_recognized(signed_descriptor_t *desc);
static void update_router_have_minimum_dir_info(void);
static char *signed_descriptor_get_body_impl(signed_descriptor_t *desc,
                                                   int with_annotations);
static void list_pending_downloads(digestmap_t *result,
                                   int purpose, const char *prefix);
void next_router_from_sorted_exits(void);
DWORD __stdcall plugin_choose_exit(DWORD flags,DWORD after,DWORD ip_range_low,DWORD ip_range_high,unsigned long bandwidth_rate_min,const char *country_id,DWORD connection_id,char *buffer);
void fill_router_info(router_info_t *rinfo,routerinfo_t *orig_info,int index);
BOOL __stdcall plugin_get_router_info(int index,DWORD router_ip,char *nickname,router_info_t *router_info);
int __stdcall plugin_is_router_banned(DWORD router_ip,char *nickname);
char *get_router_digest(routerinfo_t *router);
int __stdcall plugin_ban_router(DWORD router_ip,int ban_type,BOOL is_banned);

DECLARE_TYPED_DIGESTMAP_FNS(sdmap_, digest_sd_map_t, signed_descriptor_t)
DECLARE_TYPED_DIGESTMAP_FNS(rimap_, digest_ri_map_t, routerinfo_t)
DECLARE_TYPED_DIGESTMAP_FNS(eimap_, digest_ei_map_t, extrainfo_t)
#define SDMAP_FOREACH(map, keyvar, valvar)                              \
  DIGESTMAP_FOREACH(sdmap_to_digestmap(map), keyvar, signed_descriptor_t *, \
                    valvar)
#define RIMAP_FOREACH(map, keyvar, valvar) \
  DIGESTMAP_FOREACH(rimap_to_digestmap(map), keyvar, routerinfo_t *, valvar)
#define EIMAP_FOREACH(map, keyvar, valvar) \
  DIGESTMAP_FOREACH(eimap_to_digestmap(map), keyvar, extrainfo_t *, valvar)

/****************************************************************************/

/** Global list of a trusted_dir_server_t object for each trusted directory
 * server. */
static smartlist_t *trusted_dir_servers = NULL;

/** List of for a given authority, and download status for latest certificate.
 */
typedef struct cert_list_t {
  download_status_t dl_status;
  smartlist_t *certs;
} cert_list_t;
/** Map from v3 identity key digest to cert_list_t. */
static digestmap_t *trusted_dir_certs = NULL;
/** True iff any key certificate in at least one member of
 * <b>trusted_dir_certs</b> has changed since we last flushed the
 * certificates to disk. */
static int trusted_dir_servers_certs_changed = 0;

/** Global list of all of the routers that we know about. */
static routerlist_t *routerlist = NULL;

/** List of strings for nicknames we've already warned about and that are
 * still unknown / unavailable. */
static smartlist_t *warned_nicknames = NULL;

/** The last time we tried to download any routerdesc, or 0 for "never".  We
 * use this to rate-limit download attempts when the number of routerdescs to
 * download is low. */
time_t last_routerdesc_download_attempted = 0;

/** When we last computed the weights to use for bandwidths on directory
 * requests, what were the total weighted bandwidth, and our share of that
 * bandwidth?  Used to determine what fraction of directory requests we should
 * expect to see. */
static uint64_t sl_last_total_weighted_bw = 0,
  sl_last_weighted_bw_of_me = 0;

static int country_sel=0x200;
static uint32_t router_sel=0;
static uint32_t router_id_sel=0;

/** Return the number of directory authorities whose type matches some bit set
 * in <b>type</b>  */
int
get_n_authorities(authority_type_t type)
{
  int n = 0;
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                    if (ds->type & type)
                      ++n);
  return n;
}

#define get_n_v2_authorities() get_n_authorities(V2_AUTHORITY)

/** Helper: Return the cert_list_t for an authority whose authority ID is
 * <b>id_digest</b>, allocating a new list if necessary. */
static cert_list_t *
get_cert_list(const char *id_digest)
{
  cert_list_t *cl;
  if (!trusted_dir_certs)
    trusted_dir_certs = digestmap_new();
  cl = digestmap_get(trusted_dir_certs, id_digest);
  if (!cl) {
    cl = tor_malloc_zero(sizeof(cert_list_t));
    cl->dl_status.schedule = DL_SCHED_CONSENSUS;
    cl->certs = smartlist_create();
    digestmap_set(trusted_dir_certs, id_digest, cl);
  }
  return cl;
}

/** Reload the cached v3 key certificates from the cached-certs file in
 * the data directory. Return 0 on success, -1 on failure. */
int
trusted_dirs_reload_certs(void)
{
  char *filename;
  char *contents;
  int r;

  filename = get_datadir_fname(DATADIR_CACHED_CERTS);
  contents = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  tor_free(filename);
  if (!contents)
    return 0;
  r = trusted_dirs_load_certs_from_string(contents, 1, 1);
  tor_free(contents);
  return r;
}

/** Helper: return true iff we already have loaded the exact cert
 * <b>cert</b>. */
static INLINE int
already_have_cert(authority_cert_t *cert)
{
  cert_list_t *cl = get_cert_list(cert->cache_info.identity_digest);

  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, c,
  {
    if (tor_memeq(c->cache_info.signed_descriptor_digest,
                cert->cache_info.signed_descriptor_digest,
                DIGEST_LEN))
      return 1;
  });
  return 0;
}

/** Load a bunch of new key certificates from the string <b>contents</b>.  If
 * <b>from_store</b> is true, the certificates are from the cache, and we
 * don't need to flush them to disk.  If <b>from_store</b> is false, we need
 * to flush any changed certificates to disk.  Return 0 on success, -1 on
 * failure. */
int
trusted_dirs_load_certs_from_string(const char *contents, int from_store,
                                    int flush)
{
  trusted_dir_server_t *ds;
  const char *s, *eos;
  int failure_code = 0;

  for (s = contents; *s; s = eos) {
    authority_cert_t *cert = authority_cert_parse_from_string(s, &eos);
    cert_list_t *cl;
    if (!cert) {
      failure_code = -1;
      break;
    }
    ds = trusteddirserver_get_by_v3_auth_digest(
                                       cert->cache_info.identity_digest);
    log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_PARSED_CERT),ds ? ds->nickname : get_lang_str(LANG_LOG_ROUTERLIST_UNKNOWN_AUTHORITY));

    if (already_have_cert(cert)) {
      /* we already have this one. continue. */
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ALREADY_HAVE),from_store ? get_lang_str(LANG_LOG_ROUTERLIST_SKIPPING_CACHED_CERT) : get_lang_str(LANG_LOG_ROUTERLIST_SKIPPING_DOWNLOADED_CERT),ds ? ds->nickname : "??");

      /* a duplicate on a download should be treated as a failure, since it
       * probably means we wanted a different secret key or we are trying to
       * replace an expired cert that has not in fact been updated. */
      if (!from_store) {
        log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ALREADY_HAVE_2),ds ? ds->nickname : "??");
        authority_cert_dl_failed(cert->cache_info.identity_digest, 404);
      }

      authority_cert_free(cert);
      continue;
    }

    if (ds) {
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ADDING_CERT),from_store ? get_lang_str(LANG_LOG_ROUTERLIST_ADDING_CACHED_CERT) : get_lang_str(LANG_LOG_ROUTERLIST_ADDING_DOWNLOADED_CERT),ds->nickname,hex_str(cert->signing_key_digest,DIGEST_LEN));
    } else {
      int adding = directory_caches_dir_info(get_options());
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_UNRECOGNIZED_AUTHORITY),adding ? get_lang_str(LANG_LOG_ROUTERLIST__ADDING) : get_lang_str(LANG_LOG_ROUTERLIST__NOT_ADDING),from_store ? get_lang_str(LANG_LOG_ROUTERLIST__CACHED_CERT) : get_lang_str(LANG_LOG_ROUTERLIST__DOWNLOADED_CERT),hex_str(cert->signing_key_digest,DIGEST_LEN));
      if (!adding) {
        authority_cert_free(cert);
        continue;
      }
    }

    cl = get_cert_list(cert->cache_info.identity_digest);
    smartlist_add(cl->certs, cert);
    if (ds && cert->cache_info.published_on > ds->addr_current_at) {
      /* Check to see whether we should update our view of the authority's
       * address. */
      if (cert->addr && cert->dir_port &&
          (ds->addr != cert->addr ||
           ds->dir_port != cert->dir_port)) {
        char *a = tor_dup_ip(cert->addr);
        log_notice(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_UPDATING_ADDR_FOR_AUTHORITY),ds->nickname,ds->address,(int)ds->dir_port,a,cert->dir_port);
        tor_free(a);
        ds->addr = cert->addr;
        ds->dir_port = cert->dir_port;
      }
      ds->addr_current_at = cert->cache_info.published_on;
    }

    if (!from_store)
      trusted_dir_servers_certs_changed = 1;
  }

  if (flush)
    trusted_dirs_flush_certs_to_disk();

  networkstatus_note_certs_arrived();
  return failure_code;
}

/** Save all v3 key certificates to the cached-certs file. */
void
trusted_dirs_flush_certs_to_disk(void)
{
  char *filename;
  smartlist_t *chunks;

  if (!trusted_dir_servers_certs_changed || !trusted_dir_certs)
    return;

  chunks = smartlist_create();
  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
          {
            sized_chunk_t *c = tor_malloc(sizeof(sized_chunk_t));
            c->bytes = cert->cache_info.signed_descriptor_body;
            c->len = cert->cache_info.signed_descriptor_len;
            smartlist_add(chunks, c);
          });
  } DIGESTMAP_FOREACH_END;

  filename = get_datadir_fname(DATADIR_CACHED_CERTS);
  if (write_chunks_to_file(filename, chunks, 0)) {
    log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_WRITING_CERTS));
  }
  tor_free(filename);
  SMARTLIST_FOREACH(chunks, sized_chunk_t *, c, tor_free(c));
  smartlist_free(chunks);

  trusted_dir_servers_certs_changed = 0;
}

/** Remove all v3 authority certificates that have been superseded for more
 * than 48 hours.  (If the most recent cert was published more than 48 hours
 * ago, then we aren't going to get any consensuses signed with older
 * keys.) */
static void
trusted_dirs_remove_old_certs(void)
{
  if(get_options()->DirFlags&DIR_FLAG_NO_AUTO_UPDATE) return;
  time_t now = get_time(NULL);
#define DEAD_CERT_LIFETIME (2*24*60*60)
#define OLD_CERT_LIFETIME (7*24*60*60)
  if (!trusted_dir_certs)
    return;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    authority_cert_t *newest = NULL;
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
          if (!newest || (cert->cache_info.published_on >
                          newest->cache_info.published_on))
            newest = cert);
    if (newest) {
      const time_t newest_published = newest->cache_info.published_on;
      SMARTLIST_FOREACH_BEGIN(cl->certs, authority_cert_t *, cert) {
        int expired;
        time_t cert_published;
        if (newest == cert)
          continue;
        expired = now > cert->expires;
        cert_published = cert->cache_info.published_on;
        /* Store expired certs for 48 hours after a newer arrives;
         */
        if (expired ?
            (newest_published + DEAD_CERT_LIFETIME < now) :
            (cert_published + OLD_CERT_LIFETIME < newest_published)) {
          SMARTLIST_DEL_CURRENT(cl->certs, cert);
          authority_cert_free(cert);
          trusted_dir_servers_certs_changed = 1;
        }
      } SMARTLIST_FOREACH_END(cert);
    }
  } DIGESTMAP_FOREACH_END;
#undef OLD_CERT_LIFETIME

  trusted_dirs_flush_certs_to_disk();
}

/** Return the newest v3 authority certificate whose v3 authority identity key
 * has digest <b>id_digest</b>.  Return NULL if no such authority is known,
 * or it has no certificate. */
authority_cert_t *
authority_cert_get_newest_by_id(const char *id_digest)
{
  cert_list_t *cl;
  authority_cert_t *best = NULL;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return NULL;

  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
  {
    if (!best || cert->cache_info.published_on > best->cache_info.published_on)
      best = cert;
  });
  return best;
}

/** Return the newest v3 authority certificate whose directory signing key has
 * digest <b>sk_digest</b>. Return NULL if no such certificate is known.
 */
authority_cert_t *
authority_cert_get_by_sk_digest(const char *sk_digest)
{
  authority_cert_t *c;
  if (!trusted_dir_certs)
    return NULL;

  if ((c = get_my_v3_authority_cert()) &&
      tor_memeq(c->signing_key_digest, sk_digest, DIGEST_LEN))
    return c;
  if ((c = get_my_v3_legacy_cert()) &&
      tor_memeq(c->signing_key_digest, sk_digest, DIGEST_LEN))
    return c;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
    {
      if (tor_memeq(cert->signing_key_digest, sk_digest, DIGEST_LEN))
        return cert;
    });
  } DIGESTMAP_FOREACH_END;
  return NULL;
}

/** Return the v3 authority certificate with signing key matching
 * <b>sk_digest</b>, for the authority with identity digest <b>id_digest</b>.
 * Return NULL if no such authority is known. */
authority_cert_t *
authority_cert_get_by_digests(const char *id_digest,
                              const char *sk_digest)
{
  cert_list_t *cl;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return NULL;
  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
    if (tor_memeq(cert->signing_key_digest, sk_digest, DIGEST_LEN))
      return cert; );

  return NULL;
}

/** Add every known authority_cert_t to <b>certs_out</b>. */
void
authority_cert_get_all(smartlist_t *certs_out)
{
  tor_assert(certs_out);
  if (!trusted_dir_certs)
    return;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, c,
                      smartlist_add(certs_out, c));
  } DIGESTMAP_FOREACH_END;
}

/** Called when an attempt to download a certificate with the authority with
 * ID <b>id_digest</b> fails with HTTP response code <b>status</b>: remember
 * the failure, so we don't try again immediately. */
void
authority_cert_dl_failed(const char *id_digest, int status)
{
  cert_list_t *cl;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return;

  download_status_failed(&cl->dl_status, status);
}

/** Return true iff when we've been getting enough failures when trying to
 * download the certificate with ID digest <b>id_digest</b> that we're willing
 * to start bugging the user about it. */
int
authority_cert_dl_looks_uncertain(const char *id_digest)
{
#define N_AUTH_CERT_DL_FAILURES_TO_BUG_USER 2
  cert_list_t *cl;
  int n_failures;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return 0;

  n_failures = download_status_get_n_failures(&cl->dl_status);
  return n_failures >= N_AUTH_CERT_DL_FAILURES_TO_BUG_USER;
}

/** How many times will we try to fetch a certificate before giving up? */
//#define MAX_CERT_DL_FAILURES 8

/** Try to download any v3 authority certificates that we may be missing.  If
 * <b>status</b> is provided, try to get all the ones that were used to sign
 * <b>status</b>.  Additionally, try to have a non-expired certificate for
 * every V3 authority in trusted_dir_servers.  Don't fetch certificates we
 * already have.
 **/
void authority_certs_fetch_missing(networkstatus_t *status, time_t now)
{	digestmap_t *pending;
	authority_cert_t *cert;
	smartlist_t *missing_digests;
	char *resource = NULL;
	cert_list_t *cl;
	const int cache = directory_caches_dir_info(get_options());
	or_options_t *options = get_options();
	if(should_delay_dir_fetches(get_options()))	return;
	pending = digestmap_new();
	missing_digests = smartlist_create();
	list_pending_downloads(pending, DIR_PURPOSE_FETCH_CERTIFICATE, "fp/");
	if(status)
	{	SMARTLIST_FOREACH_BEGIN(status->voters, networkstatus_voter_info_t *, voter)
		{
			if(!smartlist_len(voter->sigs))
				continue;		/* This authority never signed this consensus, so don't go looking for a cert with key digest 0000000000. */
			if(!cache && !trusteddirserver_get_by_v3_auth_digest(voter->identity_digest))
				continue;		/* We are not a cache, and we don't know this authority.*/
			cl = get_cert_list(voter->identity_digest);
			SMARTLIST_FOREACH_BEGIN(voter->sigs, document_signature_t *, sig)
			{	cert = authority_cert_get_by_digests(voter->identity_digest,sig->signing_key_digest);
				if(cert)
				{	if((now < cert->expires)||(options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE))
						download_status_reset(&cl->dl_status);
					continue;
				}
				if(download_status_is_ready(&cl->dl_status, now,options->MaxDlFailures?options->MaxDlFailures:32767) && !digestmap_get(pending, voter->identity_digest))
				{	log_notice(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MISSING_CERT),hex_str(sig->signing_key_digest,DIGEST_LEN));
					smartlist_add(missing_digests, voter->identity_digest);
				}
			} SMARTLIST_FOREACH_END(sig);
		} SMARTLIST_FOREACH_END(voter);
	}
	SMARTLIST_FOREACH_BEGIN(trusted_dir_servers, trusted_dir_server_t *, ds)
	{	int found = 0;
		if(!(ds->type & V3_AUTHORITY))
			continue;
		if(smartlist_digest_isin(missing_digests, ds->v3_identity_digest))
			continue;
		cl = get_cert_list(ds->v3_identity_digest);
		SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert2,
		{	if(now < cert2->expires)		/* It's not expired, and we weren't looking for something to verify a consensus with. Call it done. */
			{	download_status_reset(&cl->dl_status);
				found = 1;
				break;
			}
		});
		if(!found && download_status_is_ready(&cl->dl_status, now,options->MaxDlFailures?options->MaxDlFailures:32767) && !digestmap_get(pending, ds->v3_identity_digest))
		{	log_notice(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MISSING_CERT_2),ds->nickname);
			smartlist_add(missing_digests, ds->v3_identity_digest);
		}
	} SMARTLIST_FOREACH_END(ds);
	if(smartlist_len(missing_digests))
	{	smartlist_t *fps = smartlist_create();
		smartlist_add(fps, tor_strdup("fp/"));
		SMARTLIST_FOREACH(missing_digests, const char *, d,
		{	char *fp;
			if(digestmap_get(pending, d))
				continue;
			fp = tor_malloc(HEX_DIGEST_LEN+2);
			base16_encode(fp, HEX_DIGEST_LEN+1, d, DIGEST_LEN);
			fp[HEX_DIGEST_LEN] = '+';
			fp[HEX_DIGEST_LEN+1] = '\0';
			smartlist_add(fps, fp);
		});
		if(smartlist_len(fps) >= 1)
		{	resource = smartlist_join_strings(fps, "", 0, NULL);
			resource[strlen(resource)-1] = '\0';
			directory_get_from_dirserver(DIR_PURPOSE_FETCH_CERTIFICATE,0,resource,PDS_RETRY_IF_NO_SERVERS);
		}
		SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
		smartlist_free(fps);
	}
	tor_free(resource);
	smartlist_free(missing_digests);
	digestmap_free(pending, NULL);
}

/* Router descriptor storage.
 *
 * Routerdescs are stored in a big file, named "cached-descriptors".  As new
 * routerdescs arrive, we append them to a journal file named
 * "cached-descriptors.new".
 *
 * From time to time, we replace "cached-descriptors" with a new file
 * containing only the live, non-superseded descriptors, and clear
 * cached-routers.new.
 *
 * On startup, we read both files.
 */

/** Helper: return 1 iff the router log is so big we want to rebuild the
 * store. */
static int
router_should_rebuild_store(desc_store_t *store)
{
  if (store->store_len > (1<<16))
    return (store->journal_len > store->store_len / 2 ||
            store->bytes_dropped > store->store_len / 2);
  else
    return store->journal_len > (1<<15);
}

/** Return the desc_store_t in <b>rl</b> that should be used to store
 * <b>sd</b>. */
static INLINE desc_store_t *
desc_get_store(routerlist_t *rl, signed_descriptor_t *sd)
{
  if (sd->is_extrainfo)
    return &rl->extrainfo_store;
  else
    return &rl->desc_store;
}

/** Add the signed_descriptor_t in <b>desc</b> to the router
 * journal; change its saved_location to SAVED_IN_JOURNAL and set its
 * offset appropriately. */
static int
signed_desc_append_to_journal(signed_descriptor_t *desc,
                              desc_store_t *store)
{
  char *fname = get_datadir_fname_suffix(store->fname_base,".new");
  char *body = signed_descriptor_get_body_impl(desc,1);
  size_t len = desc->signed_descriptor_len + desc->annotations_len;

  if (append_bytes_to_file(fname, body, len, 1)) {
    log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_WRITING_DESC));
    tor_free(fname);
    return -1;
  }
  desc->saved_location = SAVED_IN_JOURNAL;
  tor_free(fname);

  desc->saved_offset = store->journal_len;
  store->journal_len += len;

  return 0;
}

/** Sorting helper: return &lt;0, 0, or &gt;0 depending on whether the
 * signed_descriptor_t* in *<b>a</b> is older, the same age as, or newer than
 * the signed_descriptor_t* in *<b>b</b>. */
static int _compare_signed_descriptors_by_age(const void **_a, const void **_b)
{	const signed_descriptor_t *r1 = *_a, *r2 = *_b;
	return (int)(r1->published_on - r2->published_on);
}

#define RRS_FORCE 1
#define RRS_DONT_REMOVE_OLD 2

/** If the journal of <b>store</b> is too long, or if RRS_FORCE is set in
 * <b>flags</b>, then atomically replace the saved router store with the
 * routers currently in our routerlist, and clear the journal.  Unless
 * RRS_DONT_REMOVE_OLD is set in <b>flags</b>, delete expired routers before
 * rebuilding the store.  Return 0 on success, -1 on failure.
 */
static int router_rebuild_store(int flags, desc_store_t *store)
{	smartlist_t *chunk_list = NULL;
	char *fname = NULL, *fname_tmp = NULL;
	int r = -1;
	off_t offset = 0;
	smartlist_t *signed_descriptors = NULL;
	int nocache=0;
	size_t total_expected_len = 0;
	int had_any;
	int force = flags & RRS_FORCE;
	if((!force && !router_should_rebuild_store(store)) || (!routerlist))
		r = 0;
	else
	{	if(store->type == EXTRAINFO_STORE)	had_any = !eimap_isempty(routerlist->extra_info_map);
		else					had_any = (smartlist_len(routerlist->routers)+smartlist_len(routerlist->old_routers))>0;
		/* Don't save deadweight. */
		if(!(flags & RRS_DONT_REMOVE_OLD)&&!(get_options()->DirFlags&DIR_FLAG_NO_AUTO_UPDATE))
			routerlist_remove_old_routers();
		log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_REBUILDING_CACHE),store->description);
		fname = get_datadir_fname(store->fname_base);
		fname_tmp = get_datadir_fname_suffix(store->fname_base,".tmp");
		chunk_list = smartlist_create();

		/* We sort the routers by age to enhance locality on disk. */
		signed_descriptors = smartlist_create();
		if(store->type == EXTRAINFO_STORE)
		{	eimap_iter_t *iter;
			for(iter = eimap_iter_init(routerlist->extra_info_map);!eimap_iter_done(iter);iter = eimap_iter_next(routerlist->extra_info_map, iter))
			{	const char *key;
				extrainfo_t *ei;
				eimap_iter_get(iter, &key, &ei);
				smartlist_add(signed_descriptors, &ei->cache_info);
			}
		}
		else
		{	SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
			{	smartlist_add(signed_descriptors, sd);
			});
			SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
			{	smartlist_add(signed_descriptors, &ri->cache_info);
			});
		}
		smartlist_sort(signed_descriptors, _compare_signed_descriptors_by_age);

		/* Now, add the appropriate members to chunk_list */
		SMARTLIST_FOREACH(signed_descriptors, signed_descriptor_t *, sd,
		{	sized_chunk_t *c;
			const char *body = signed_descriptor_get_body_impl(sd, 1);
			if(!body)
			{	log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_NO_DESC_AVAILABLE));
				r = -2;
				break;
			}
			if(sd->do_not_cache)
			{	++nocache;
				continue;
			}
			c = tor_malloc(sizeof(sized_chunk_t));
			c->bytes = body;
			c->len = sd->signed_descriptor_len + sd->annotations_len;
			total_expected_len += c->len;
			smartlist_add(chunk_list, c);
		});
		if(r==-2)	r = -1;
		else
		{	if(write_chunks_to_file(fname_tmp, chunk_list, 1)<0)
				log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_WRITING_STORE));
			else
			{	/* Our mmap is now invalid. */
				if(store->mmap)
				{	tor_munmap_file(store->mmap);
					store->mmap = NULL;
				}
				if(replace_file(fname_tmp, fname)<0)
					log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_REPLACING_STORE),strerror(errno));
				else
				{	errno = 0;
					store->mmap = tor_mmap_file(fname);
					if(! store->mmap)
					{	if(errno == ERANGE)	/* empty store.*/
						{	if(total_expected_len)
								log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_WRITING_DESC_2),fname);
							else if(had_any)
								log_info(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_REMOVED_ALL_DESCS),fname);
						}
						else	log_warn(LD_FS,get_lang_str(LANG_LOG_ROUTERLIST_MMAP_ERROR),fname);
					}
					log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_RECONSTRUCTING_POINTERS));

					offset = 0;
					SMARTLIST_FOREACH(signed_descriptors, signed_descriptor_t *, sd,
					{	if(sd->do_not_cache)	continue;
						sd->saved_location = SAVED_IN_CACHE;
						if(store->mmap)
						{	tor_free(sd->signed_descriptor_body); // sets it to null
							sd->saved_offset = offset;
						}
						offset += sd->signed_descriptor_len + sd->annotations_len;
						signed_descriptor_get_body(sd); /* reconstruct and assert */
					});
					tor_free(fname);
					fname = get_datadir_fname_suffix(store->fname_base,".new");
					write_buf_to_file(fname,"",0);
					r = 0;
					store->store_len = (size_t) offset;
					store->journal_len = 0;
					store->bytes_dropped = 0;
				}
			}
		}
		smartlist_free(signed_descriptors);
		if(chunk_list)
		{	SMARTLIST_FOREACH(chunk_list, sized_chunk_t *, c, tor_free(c));
			smartlist_free(chunk_list);
		}
		tor_free(fname);
		tor_free(fname_tmp);
	}
	return r;
}

/** Helper: Reload a cache file and its associated journal, setting metadata
 * appropriately.  If <b>extrainfo</b> is true, reload the extrainfo store;
 * else reload the router descriptor store. */
static int
router_reload_router_list_impl(desc_store_t *store)
{
  char *fname = NULL, *altname = NULL, *contents = NULL;
  struct stat st;
  int read_from_old_location = 0;
  int extrainfo = (store->type == EXTRAINFO_STORE);
  time_t now = get_time(NULL);
  store->journal_len = store->store_len = 0;

  fname = get_datadir_fname(store->fname_base);
  if (store->fname_alt_base)
    altname = get_datadir_fname(store->fname_alt_base);

  if (store->mmap) /* get rid of it first */
    tor_munmap_file(store->mmap);
  store->mmap = NULL;

  store->mmap = tor_mmap_file(fname);
  if (!store->mmap && altname && file_status(altname) == FN_FILE) {
    read_from_old_location = 1;
    log_notice(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_READING_FILE),fname,altname);
    if ((store->mmap = tor_mmap_file(altname)))
      read_from_old_location = 1;
  }
  if (altname && !read_from_old_location) {
    remove_file_if_very_old(altname, now);
  }
  if (store->mmap) {
    store->store_len = store->mmap->size;
    if (extrainfo)
      router_load_extrainfo_from_string(get_mmap_data(store->mmap),
                                        get_mmap_data(store->mmap)+store->mmap->size,
                                        SAVED_IN_CACHE, NULL, 0);
    else
      router_load_routers_from_string(get_mmap_data(store->mmap),
                                      get_mmap_data(store->mmap)+store->mmap->size,
                                      SAVED_IN_CACHE, NULL, 0, NULL);
  }

  tor_free(fname);
  fname = get_datadir_fname_suffix(store->fname_base,".new");
  if (file_status(fname) == FN_FILE)
    contents = read_file_to_str(fname, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
  if (read_from_old_location) {
    tor_free(altname);
    altname = get_datadir_fname_suffix(store->fname_alt_base,".new");
    if (!contents)
      contents = read_file_to_str(altname, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
    else
      remove_file_if_very_old(altname, now);
  }
  if (contents) {
    if (extrainfo)
      router_load_extrainfo_from_string(contents, NULL,SAVED_IN_JOURNAL,
                                        NULL, 0);
    else
      router_load_routers_from_string(contents, NULL, SAVED_IN_JOURNAL,
                                      NULL, 0, NULL);
    store->journal_len = (size_t) st.st_size;
    tor_free(contents);
  }

  tor_free(fname);
  tor_free(altname);

  if (store->journal_len || read_from_old_location) {
    /* Always clear the journal on startup.*/
    router_rebuild_store(RRS_FORCE, store);
  } else if (!extrainfo) {
    /* Don't cache expired routers. (This is in an else because
     * router_rebuild_store() also calls remove_old_routers().) */
    routerlist_remove_old_routers();
  }

  return 0;
}

/** Load all cached router descriptors and extra-info documents from the
 * store. Return 0 on success and -1 on failure.
 */
int
router_reload_router_list(void)
{
  routerlist_t *rl = router_get_routerlist();
  if (router_reload_router_list_impl(&rl->desc_store))
    return -1;
  if (router_reload_router_list_impl(&rl->extrainfo_store))
    return -1;
  plugins_routerchanged(0,NULL,3);
  return 0;
}

/** Return a smartlist containing a list of trusted_dir_server_t * for all
 * known trusted dirservers.  Callers must not modify the list or its
 * contents.
 */
smartlist_t *
router_get_trusted_dir_servers(void)
{
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  return trusted_dir_servers;
}

/** Try to find a running dirserver that supports operations of <b>type</b>.
 *
 * If there are no running dirservers in our routerlist and the
 * <b>PDS_RETRY_IF_NO_SERVERS</b> flag is set, set all the authoritative ones
 * as running again, and pick one.
 *
 * If the <b>PDS_IGNORE_FASCISTFIREWALL</b> flag is set, then include
 * dirservers that we can't reach.
 *
 * If the <b>PDS_ALLOW_SELF</b> flag is not set, then don't include ourself
 * (if we're a dirserver).
 *
 * Don't pick an authority if any non-authority is viable; try to avoid using
 * servers that have returned 503 recently.
 */
routerstatus_t *
router_pick_directory_server(authority_type_t type, int flags)
{
  routerstatus_t *choice;
  if ((get_options()->TunnelDirConns & 2) != 0)
    flags |= _PDS_PREFER_TUNNELED_DIR_CONNS;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(type, flags);
  if (choice || !(flags & PDS_RETRY_IF_NO_SERVERS))
    return choice;

  log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_NO_REACHABLE_ROUTERS));
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(type, flags);
  return choice;
}

/** Try to determine which fraction of v2 and v3 directory requests aimed at
 * caches will be sent to us. Set *<b>v2_share_out</b> and
 * *<b>v3_share_out</b> to the fractions of v2 and v3 protocol shares we
 * expect to see, respectively.  Return 0 on success, negative on failure. */
int
router_get_my_share_of_directory_requests(double *v2_share_out,
                                          double *v3_share_out)
{
  routerinfo_t *me = router_get_my_routerinfo();
  routerstatus_t *rs;
  const int pds_flags = PDS_ALLOW_SELF|PDS_IGNORE_FASCISTFIREWALL;
  *v2_share_out = *v3_share_out = 0.0;
  if (!me)
    return -1;
  rs = router_get_consensus_status_by_id(me->cache_info.identity_digest);
  if (!rs)
    return -1;

  /* Calling for side effect */
  /* XXXX This is a bit of a kludge */
  if (rs->is_v2_dir) {
    sl_last_total_weighted_bw = 0;
    router_pick_directory_server(V2_AUTHORITY, pds_flags);
    if (sl_last_total_weighted_bw != 0) {
      *v2_share_out = U64_TO_DBL(sl_last_weighted_bw_of_me) /
        U64_TO_DBL(sl_last_total_weighted_bw);
    }
  }

  if (rs->version_supports_v3_dir) {
    sl_last_total_weighted_bw = 0;
    router_pick_directory_server(V3_AUTHORITY, pds_flags);
    if (sl_last_total_weighted_bw != 0) {
      *v3_share_out = U64_TO_DBL(sl_last_weighted_bw_of_me) /
        U64_TO_DBL(sl_last_total_weighted_bw);
    }
  }

  return 0;
}

/** Return the trusted_dir_server_t for the directory authority whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
trusted_dir_server_t *
router_get_trusteddirserver_by_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       if (tor_memeq(ds->digest, digest, DIGEST_LEN))
         return ds;
     });

  return NULL;
}

/** Return the trusted_dir_server_t for the directory authority whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
trusted_dir_server_t *
trusteddirserver_get_by_v3_auth_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       if (tor_memeq(ds->v3_identity_digest, digest, DIGEST_LEN) &&
           (ds->type & V3_AUTHORITY))
         return ds;
     });

  return NULL;
}

/** Try to find a running trusted dirserver.  Flags are as for
 * router_pick_directory_server.
 */
routerstatus_t *
router_pick_trusteddirserver(authority_type_t type, int flags)
{
  routerstatus_t *choice;
  int busy = 0;
  if ((get_options()->TunnelDirConns & 2) != 0)
    flags |= _PDS_PREFER_TUNNELED_DIR_CONNS;

  choice = router_pick_trusteddirserver_impl(type, flags, &busy);
  if (choice || !(flags & PDS_RETRY_IF_NO_SERVERS))
    return choice;
  if (busy) {
    /* If the reason that we got no server is that servers are "busy",
     * we must be excluding good servers because we already have serverdesc
     * fetches with them.  Do not mark down servers up because of this. */
    tor_assert((flags & PDS_NO_EXISTING_SERVERDESC_FETCH));
    return NULL;
  }

  log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_NO_REACHABLE_DIRS));
  mark_all_trusteddirservers_up();
  return router_pick_trusteddirserver_impl(type, flags, NULL);
}

/** How long do we avoid using a directory server after it's given us a 503? */
#define DIR_503_TIMEOUT (60*60)

/** Pick a random running valid directory server/mirror from our
 * routerlist.  Arguments are as for router_pick_directory_server(), except
 * that RETRY_IF_NO_SERVERS is ignored, and:
 *
 * If the _PDS_PREFER_TUNNELED_DIR_CONNS flag is set, prefer directory servers
 * that we can use with BEGINDIR.
 */
static routerstatus_t *
router_pick_directory_server_impl(authority_type_t type, int flags)
{
  or_options_t *options = get_options();
  routerstatus_t *result;
  smartlist_t *direct, *tunnel;
  smartlist_t *trusted_direct, *trusted_tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  time_t now = get_time(NULL);
  const networkstatus_t *consensus = networkstatus_get_latest_consensus();
  int requireother = ! (flags & PDS_ALLOW_SELF);
  int fascistfirewall = ! (flags & PDS_IGNORE_FASCISTFIREWALL);
  int prefer_tunnel = (flags & _PDS_PREFER_TUNNELED_DIR_CONNS);
  int try_excluding = 1, n_excluded = 0;

  if (!consensus)
    return NULL;

  direct = smartlist_create();
  tunnel = smartlist_create();
  trusted_direct = smartlist_create();
  trusted_tunnel = smartlist_create();
  overloaded_direct = smartlist_create();
  overloaded_tunnel = smartlist_create();

  /* Find all the running dirservers we know about. */
  SMARTLIST_FOREACH_BEGIN(consensus->routerstatus_list, routerstatus_t *,
                          status) {
    int is_trusted;
    int is_overloaded = status->last_dir_503_at + DIR_503_TIMEOUT > now;
    tor_addr_t addr;
    if (!status->is_running || !status->dir_port || !status->is_valid)
      continue;
    if (status->is_bad_directory)
      continue;
    if (requireother && router_digest_is_me(status->identity_digest))
      continue;
    if (type & V3_AUTHORITY) {
      if (!(status->version_supports_v3_dir ||
            router_digest_is_trusted_dir_type(status->identity_digest,
                                              V3_AUTHORITY)))
        continue;
    }
    is_trusted = router_digest_is_trusted_dir(status->identity_digest);
    if ((type & V2_AUTHORITY) && !(status->is_v2_dir || is_trusted))
      continue;
    if ((type & EXTRAINFO_CACHE) &&
        !router_supports_extrainfo(status->identity_digest, 0))
      continue;
    if (try_excluding && options->ExcludeNodes &&
        routerset_contains_routerstatus(options->ExcludeNodes, status)) {
      ++n_excluded;
      continue;
    }

    /* XXXX IP6 proposal 118 */
    tor_addr_from_ipv4h(&addr, status->addr);

    if (prefer_tunnel &&
        status->version_supports_begindir &&
        (!fascistfirewall ||
         fascist_firewall_allows_address_or(&addr, status->or_port)))
      smartlist_add(is_trusted ? trusted_tunnel :
                      is_overloaded ? overloaded_tunnel : tunnel, status);
    else if (!fascistfirewall ||
             fascist_firewall_allows_address_dir(&addr, status->dir_port))
      smartlist_add(is_trusted ? trusted_direct :
                      is_overloaded ? overloaded_direct : direct, status);
  } SMARTLIST_FOREACH_END(status);

  if (smartlist_len(tunnel)) {
    result = routerstatus_sl_choose_by_bandwidth(tunnel, WEIGHT_FOR_DIR);
  } else if (smartlist_len(overloaded_tunnel)) {
    result = routerstatus_sl_choose_by_bandwidth(overloaded_tunnel,
                                                 WEIGHT_FOR_DIR);
  } else if (smartlist_len(trusted_tunnel)) {
    /* FFFF We don't distinguish between trusteds and overloaded trusteds
     * yet. Maybe one day we should. */
    /* FFFF We also don't load balance over authorities yet. I think this
     * is a feature, but it could easily be a bug. -RD */
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(trusted_tunnel):smartlist_get(trusted_tunnel,0);
  } else if (smartlist_len(direct)) {
    result = routerstatus_sl_choose_by_bandwidth(direct, WEIGHT_FOR_DIR);
  } else if (smartlist_len(overloaded_direct)) {
    result = routerstatus_sl_choose_by_bandwidth(overloaded_direct,
                                                 WEIGHT_FOR_DIR);
  } else {
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(trusted_direct):smartlist_get(trusted_direct,0);
  }
  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(trusted_direct);
  smartlist_free(trusted_tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);
  return result;
}

/** Choose randomly from among the trusted dirservers that are up.  Flags
 * are as for router_pick_directory_server_impl().
 */
static routerstatus_t *
router_pick_trusteddirserver_impl(authority_type_t type, int flags,
                                  int *n_busy_out)
{
  or_options_t *options = get_options();
  smartlist_t *direct, *tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  routerinfo_t *me = router_get_my_routerinfo();
  routerstatus_t *result;
  time_t now = get_time(NULL);
  const int requireother = ! (flags & PDS_ALLOW_SELF);
  const int fascistfirewall = ! (flags & PDS_IGNORE_FASCISTFIREWALL);
  const int prefer_tunnel = (flags & _PDS_PREFER_TUNNELED_DIR_CONNS);
  const int no_serverdesc_fetching =(flags & PDS_NO_EXISTING_SERVERDESC_FETCH);
  int n_busy = 0;
  int try_excluding = 1, n_excluded = 0;

  if (!trusted_dir_servers)
    return NULL;

  direct = smartlist_create();
  tunnel = smartlist_create();
  overloaded_direct = smartlist_create();
  overloaded_tunnel = smartlist_create();

  SMARTLIST_FOREACH_BEGIN(trusted_dir_servers, trusted_dir_server_t *, d)
    {
      int is_overloaded =
          d->fake_status.last_dir_503_at + DIR_503_TIMEOUT > now;
      tor_addr_t addr;
      if (!d->is_running) continue;
      if ((type & d->type) == 0)
        continue;
      if ((type & EXTRAINFO_CACHE) &&
          !router_supports_extrainfo(d->digest, 1))
        continue;
      if (requireother && me && router_digest_is_me(d->digest))
          continue;
      if (try_excluding && options->ExcludeNodes &&
          routerset_contains_routerstatus(options->ExcludeNodes,
                                          &d->fake_status)) {
        ++n_excluded;
        continue;
      }

      /* XXXX IP6 proposal 118 */
      tor_addr_from_ipv4h(&addr, d->addr);

      if (no_serverdesc_fetching) {
        if (connection_get_by_type_addr_port_purpose(
            CONN_TYPE_DIR, &addr, d->dir_port, DIR_PURPOSE_FETCH_SERVERDESC)
         || connection_get_by_type_addr_port_purpose(
             CONN_TYPE_DIR, &addr, d->dir_port, DIR_PURPOSE_FETCH_EXTRAINFO)) {
          //log_debug(LD_DIR, "We have an existing connection to fetch "
          //           "descriptor from %s; delaying",d->description);
          ++n_busy;
          continue;
        }
      }

      if (prefer_tunnel &&
          d->or_port &&
          (!fascistfirewall ||
           fascist_firewall_allows_address_or(&addr, d->or_port)))
        smartlist_add(is_overloaded ? overloaded_tunnel : tunnel,
                      &d->fake_status);
      else if (!fascistfirewall ||
               fascist_firewall_allows_address_dir(&addr, d->dir_port))
        smartlist_add(is_overloaded ? overloaded_direct : direct,
                      &d->fake_status);
    }
  SMARTLIST_FOREACH_END(d);

  if (smartlist_len(tunnel)) {
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(tunnel):smartlist_get(tunnel,0);
  } else if (smartlist_len(overloaded_tunnel)) {
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(overloaded_tunnel):smartlist_get(overloaded_tunnel,0);
  } else if (smartlist_len(direct)) {
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(direct):smartlist_get(direct,0);
  } else {
    result = get_options()->DirFlags&DIR_FLAG_RANDOM_AUTHORITY?smartlist_choose(overloaded_direct):smartlist_get(overloaded_direct,0);
  }

  if (n_busy_out)
    *n_busy_out = n_busy;

  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);
  return result;
}

/** Go through and mark the authoritative dirservers as up. */
static void
mark_all_trusteddirservers_up(void)
{
  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
       if (router_digest_is_trusted_dir(router->cache_info.identity_digest) &&
         router->dir_port > 0) {
         router->is_running = 1;
       });
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
    {
      routerstatus_t *rs;
      dir->is_running = 1;
      download_status_reset(&dir->v2_ns_dl_status);
      rs = router_get_consensus_status_by_id(dir->digest);
      if (rs && !rs->is_running) {
        rs->is_running = 1;
        rs->last_dir_503_at = 0;
        control_event_networkstatus_changed_single(rs);
      }
    });
  }
  router_dir_info_changed();
}

/** Return true iff r1 and r2 have the same address and OR port. */
int
routers_have_same_or_addr(const routerinfo_t *r1, const routerinfo_t *r2)
{
  return r1->addr == r2->addr && r1->or_port == r2->or_port;
}

/** Reset all internal variables used to count failed downloads of network
 * status objects. */
void
router_reset_status_download_failures(void)
{
  mark_all_trusteddirservers_up();
}

/** Return true iff router1 and router2 have the same /16 network. */
static INLINE int
routers_in_same_network_family(routerinfo_t *r1, routerinfo_t *r2)
{
  return (r1->addr & 0xffff0000) == (r2->addr & 0xffff0000);
}

static INLINE int
routers_in_same_country(routerinfo_t *r1, routerinfo_t *r2)
{
  return (r1->country) == (r2->country);
}

/** Look through the routerlist and identify routers that
 * advertise the same /16 network address as <b>router</b>.
 * Add each of them to <b>sl</b>.
 */
static void
routerlist_add_network_family(smartlist_t *sl, routerinfo_t *router)
{
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
  {
    if (router != r && routers_in_same_network_family(router, r))
      smartlist_add(sl, r);
  });
}

static void
routerlist_add_same_country(smartlist_t *sl, routerinfo_t *router)
{
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
  {
    if (router != r && routers_in_same_country(router, r))
      smartlist_add(sl, r);
  });
}

/** Add all the family of <b>router</b> to the smartlist <b>sl</b>.
 * This is used to make sure we don't pick siblings in a single path,
 * or pick more than one relay from a family for our entry guard list.
 */
void
routerlist_add_family(smartlist_t *sl, routerinfo_t *router)
{
  routerinfo_t *r;
  config_line_t *cl;
  or_options_t *options = get_options();

  /* First, add any routers with similar network addresses. */
  if((options->EnforceDistinctSubnets&1)!=0)
    routerlist_add_network_family(sl, router);
  else if((options->EnforceDistinctSubnets&2)!=0)
    routerlist_add_same_country(sl, router);

  if (router->declared_family) {
    /* Add every r such that router declares familyness with r, and r
     * declares familyhood with router. */
    SMARTLIST_FOREACH(router->declared_family, const char *, n,
      {
        if (!(r = router_get_by_nickname(n, 0)))
          continue;
        if (!r->declared_family)
          continue;
        SMARTLIST_FOREACH(r->declared_family, const char *, n2,
          {
            if (router_nickname_matches(router, n2))
              smartlist_add(sl, r);
          });
      });
  }

  /* If the user declared any families locally, honor those too. */
  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (router_nickname_is_in_list(router, (char *)cl->value)) {
      add_nickname_list_to_smartlist(sl, (char *)cl->value, 0);
    }
  }
}

/** Return true iff r is named by some nickname in <b>lst</b>. */
static INLINE int
router_in_nickname_smartlist(smartlist_t *lst, routerinfo_t *r)
{
  if (!lst) return 0;
  SMARTLIST_FOREACH(lst, const char *, name,
    if (router_nickname_matches(r, name))
      return 1;);
  return 0;
}

/** Return true iff r1 and r2 are in the same family, but not the same
 * router. */
int
routers_in_same_family(routerinfo_t *r1, routerinfo_t *r2)
{
  or_options_t *options = get_options();
  config_line_t *cl;

  if (((options->EnforceDistinctSubnets & 1) != 0) && routers_in_same_network_family(r1,r2))
    return 1;
  if (((options->EnforceDistinctSubnets & 2) != 0) && routers_in_same_country(r1,r2))
    return 1;

  if (router_in_nickname_smartlist(r1->declared_family, r2) &&
      router_in_nickname_smartlist(r2->declared_family, r1))
    return 1;

  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (router_nickname_is_in_list(r1, (char *)cl->value) &&
        router_nickname_is_in_list(r2, (char *)cl->value))
      return 1;
  }
  return 0;
}

/** Given a (possibly NULL) comma-and-whitespace separated list of nicknames,
 * see which nicknames in <b>list</b> name routers in our routerlist, and add
 * the routerinfos for those routers to <b>sl</b>.  If <b>must_be_running</b>,
 * only include routers that we think are running.
 * Warn if any non-Named routers are specified by nickname.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                               int must_be_running)
{
  routerinfo_t *router;
  smartlist_t *nickname_list;
  int have_dir_info = router_have_minimum_dir_info();

  if (!list)
    return; /* nothing to do */
  tor_assert(sl);

  nickname_list = smartlist_create();
  if (!warned_nicknames)
    warned_nicknames = smartlist_create();

  smartlist_split_string(nickname_list, list, ",",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

  SMARTLIST_FOREACH(nickname_list, const char *, nick, {
    int warned;
    if (!is_legal_nickname_or_hexdigest(nick)) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_INVALID_NICKNAME),nick);
      continue;
    }
    router = router_get_by_nickname(nick, 1);
    warned = smartlist_string_isin(warned_nicknames, nick);
    if (router) {
      if (!must_be_running || router->is_running) {
        smartlist_add(sl,router);
      }
    } else if (!router_get_consensus_status_by_nickname(nick,1)) {
      if (!warned) {
        log_fn(have_dir_info ? LOG_WARN : LOG_INFO, LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_INVALID_NICKLIST_ENTRY),nick);
        smartlist_add(warned_nicknames, tor_strdup(nick));
      }
    }
  });
  SMARTLIST_FOREACH(nickname_list, char *, nick, tor_free(nick));
  smartlist_free(nickname_list);
}

/** Return 1 iff any member of the (possibly NULL) comma-separated list
 * <b>list</b> is an acceptable nickname or hexdigest for <b>router</b>.  Else
 * return 0.
 */
int
router_nickname_is_in_list(routerinfo_t *router, const char *list)
{
  smartlist_t *nickname_list;
  int v = 0;

  if (!list)
    return 0; /* definitely not */
  tor_assert(router);

  nickname_list = smartlist_create();
  smartlist_split_string(nickname_list, list, ",",
    SPLIT_SKIP_SPACE|SPLIT_STRIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(nickname_list, const char *, cp,
                    if (router_nickname_matches(router, cp)) {v=1;break;});
  SMARTLIST_FOREACH(nickname_list, char *, cp, tor_free(cp));
  smartlist_free(nickname_list);
  return v;
}

/** Add every suitable router from our routerlist to <b>sl</b>, so that
 * we can pick a node for a circuit.
 */
static void
router_add_running_routers_to_smartlist(smartlist_t *sl, int allow_invalid,
                                        int need_uptime, int need_capacity,
                                        int need_guard)
{
  if (!routerlist)
    return;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        router->purpose == ROUTER_PURPOSE_GENERAL &&
        (router->is_valid || allow_invalid) &&
        !router_is_unreliable(router, need_uptime,
                              need_capacity, need_guard)) {
      /* If it's running, and it's suitable according to the
       * other flags we had in mind */
      smartlist_add(sl, router);
    }
  });
}

/** Look through the routerlist until we find a router that has my key.
 Return it. */
routerinfo_t *
routerlist_find_my_routerinfo(void)
{
  if (!routerlist)
    return NULL;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router_is_me(router))
      return router;
  });
  return NULL;
}

/** Find a router that's up, that has this IP address, and
 * that allows exit to this address:port, or return NULL if there
 * isn't a good one.
 */
routerinfo_t *
router_find_exact_exit_enclave(const char *address, uint16_t port)
{
  uint32_t addr;
  struct in_addr in;
  tor_addr_t a;
  or_options_t *options = get_options();

  if (!tor_inet_aton(address, &in))
    return NULL; /* it's not an IP already */
  addr = ntohl(in.s_addr);

  tor_addr_from_ipv4h(&a, addr);

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->addr == addr &&
        router->is_running &&
        compare_tor_addr_to_addr_policy(&a, port, router->exit_policy) ==
          ADDR_POLICY_ACCEPTED &&
        !routerset_contains_router(options->_ExcludeExitNodesUnion, router))
      return router;
  });
  return NULL;
}

/** Return 1 if <b>router</b> is not suitable for these parameters, else 0.
 * If <b>need_uptime</b> is non-zero, we require a minimum uptime.
 * If <b>need_capacity</b> is non-zero, we require a minimum advertised
 * bandwidth.
 * If <b>need_guard</b>, we require that the router is a possible entry guard.
 */
int
router_is_unreliable(routerinfo_t *router, int need_uptime,
                     int need_capacity, int need_guard)
{
  if (need_uptime && !router->is_stable)
    return 1;
  if (need_capacity && !router->is_fast)
    return 1;
  if (need_guard && !router->is_possible_guard)
    return 1;
  if(tmpOptions->CircuitBandwidthRate && (router->bandwidthcapacity < tmpOptions->CircuitBandwidthRate))
    return 1;
  if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_ENABLED && !dlgBypassBlacklists_isRecent(geoip_reverse(router->addr),router,get_time(NULL)))
    return 1;
  return 0;
}

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity. */
uint32_t
router_get_advertised_bandwidth(routerinfo_t *router)
{
  if (router->bandwidthcapacity < router->bandwidthrate)
    return router->bandwidthcapacity;
  return router->bandwidthrate;
}

/** Do not weight any declared bandwidth more than this much when picking
 * routers by bandwidth. */
#define DEFAULT_MAX_BELIEVABLE_BANDWIDTH 10000000 /* 10 MB/sec */

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity, capped by max-believe-bw. */
uint32_t
router_get_advertised_bandwidth_capped(routerinfo_t *router)
{
  uint32_t result = router->bandwidthcapacity;
  if (result > router->bandwidthrate)
    result = router->bandwidthrate;
  if (result > DEFAULT_MAX_BELIEVABLE_BANDWIDTH)
    result = DEFAULT_MAX_BELIEVABLE_BANDWIDTH;
  return result;
}

/** When weighting bridges, enforce these values as lower and upper
 * bound for believable bandwidth, because there is no way for us
 * to verify a bridge's bandwidth currently. */
#define BRIDGE_MIN_BELIEVABLE_BANDWIDTH 20000  /* 20 kB/sec */
#define BRIDGE_MAX_BELIEVABLE_BANDWIDTH 100000 /* 100 kB/sec */

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity, making sure to stay within the
 * interval between bridge-min-believe-bw and
 * bridge-max-believe-bw. */
static uint32_t
bridge_get_advertised_bandwidth_bounded(routerinfo_t *router)
{
  uint32_t result = router->bandwidthcapacity;
  if (result > router->bandwidthrate)
    result = router->bandwidthrate;
  if (result > BRIDGE_MAX_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MAX_BELIEVABLE_BANDWIDTH;
  else if (result < BRIDGE_MIN_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MIN_BELIEVABLE_BANDWIDTH;
  return result;
}

/** Return bw*1000, unless bw*1000 would overflow, in which case return
 * INT32_MAX. */
static INLINE int32_t
kb_to_bytes(uint32_t bw)
{
  return (bw > (INT32_MAX/1000)) ? INT32_MAX : bw*1000;
}

/** Helper function:
 * choose a random element of smartlist <b>sl</b>, weighted by
 * the advertised bandwidth of each element using the consensus
 * bandwidth weights.
 *
 * If <b>statuses</b> is zero, then <b>sl</b> is a list of
 * routerinfo_t's. Otherwise it's a list of routerstatus_t's.
 *
 * If <b>rule</b>==WEIGHT_FOR_EXIT. we're picking an exit node: consider all
 * nodes' bandwidth equally regardless of their Exit status, since there may
 * be some in the list because they exit to obscure ports. If
 * <b>rule</b>==NO_WEIGHTING, we're picking a non-exit node: weight
 * exit-node's bandwidth less depending on the smallness of the fraction of
 * Exit-to-total bandwidth.  If <b>rule</b>==WEIGHT_FOR_GUARD, we're picking a
 * guard node: consider all guard's bandwidth equally. Otherwise, weight
 * guards proportionally less.
 */
static void *
smartlist_choose_by_bandwidth_weights(smartlist_t *sl,
                                      bandwidth_weight_rule_t rule,
                                      int statuses)
{
  int64_t weight_scale;
  int64_t rand_bw;
  double Wg = -1, Wm = -1, We = -1, Wd = -1;
  double Wgb = -1, Wmb = -1, Web = -1, Wdb = -1;
  double weighted_bw = 0;
  double *bandwidths;
  double tmp = 0;
  unsigned int i;
  unsigned int i_chosen;
  unsigned int i_has_been_chosen;
  int have_unknown = 0; /* true iff sl contains element not in consensus. */

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD ||
             rule == WEIGHT_FOR_MID ||
             rule == WEIGHT_FOR_DIR);

  if (smartlist_len(sl) == 0) {
    log_info(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_EMPTY_ROUTERLIST),bandwidth_weight_rule_to_string(rule));
    return NULL;
  }

  weight_scale = circuit_build_times_get_bw_scale(NULL);

  if (rule == WEIGHT_FOR_GUARD) {
    Wg = networkstatus_get_bw_weight(NULL, "Wgg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wgm", -1); /* Bridges */
    We = 0;
    Wd = networkstatus_get_bw_weight(NULL, "Wgd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_MID) {
    Wg = networkstatus_get_bw_weight(NULL, "Wmg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wmm", -1);
    We = networkstatus_get_bw_weight(NULL, "Wme", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wmd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_EXIT) {
    // Guards CAN be exits if they have weird exit policies
    // They are d then I guess...
    We = networkstatus_get_bw_weight(NULL, "Wee", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wem", -1); /* Odd exit policies */
    Wd = networkstatus_get_bw_weight(NULL, "Wed", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Weg", -1); /* Odd exit policies */

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_DIR) {
    We = networkstatus_get_bw_weight(NULL, "Wbe", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wbm", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wbd", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Wbg", -1);

    Wgb = Wmb = Web = Wdb = weight_scale;
  } else if (rule == NO_WEIGHTING) {
    Wg = Wm = We = Wd = weight_scale;
    Wgb = Wmb = Web = Wdb = weight_scale;
  }

  if (Wg < 0 || Wm < 0 || We < 0 || Wd < 0 || Wgb < 0 || Wmb < 0 || Wdb < 0
      || Web < 0) {
    log_debug(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_NEGATIVE_BW_WEIGHTS));
    return NULL; // Use old algorithm.
  }

  Wg /= weight_scale;
  Wm /= weight_scale;
  We /= weight_scale;
  Wd /= weight_scale;

  Wgb /= weight_scale;
  Wmb /= weight_scale;
  Web /= weight_scale;
  Wdb /= weight_scale;

  bandwidths = tor_malloc_zero(sizeof(double)*smartlist_len(sl));

  // Cycle through smartlist and total the bandwidth.
  for (i = 0; i < (unsigned)smartlist_len(sl); ++i) {
    int is_exit = 0, is_guard = 0, is_dir = 0, this_bw = 0, is_me = 0;
    double weight = 1;
    if (statuses) {
      routerstatus_t *status = smartlist_get(sl, i);
      is_exit = status->is_exit && !status->is_bad_exit;
      is_guard = status->is_possible_guard;
      is_dir = (status->dir_port != 0);
      if (!status->has_bandwidth) {
        tor_free(bandwidths);
        /* This should never happen, unless all the authorites downgrade to 0.2.0 or rogue routerstatuses get inserted into our consensus. */
        log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_CONSENSUS_NOT_LISTING_BW));
        return NULL;
      }
      this_bw = kb_to_bytes(status->bandwidth);
      if (router_digest_is_me(status->identity_digest))
        is_me = 1;
    } else {
      routerstatus_t *rs;
      routerinfo_t *router = smartlist_get(sl, i);
      rs = router_get_consensus_status_by_id(
             router->cache_info.identity_digest);
      is_exit = router->is_exit && !router->is_bad_exit;
      is_guard = router->is_possible_guard;
      is_dir = (router->dir_port != 0);
      if (rs && rs->has_bandwidth) {
        this_bw = kb_to_bytes(rs->bandwidth);
      } else { /* bridge or other descriptor not in our consensus */
        this_bw = bridge_get_advertised_bandwidth_bounded(router);
        have_unknown = 1;
      }
      if (router_digest_is_me(router->cache_info.identity_digest))
        is_me = 1;
    }
    if (is_guard && is_exit) {
      weight = (is_dir ? Wdb*Wd : Wd);
    } else if (is_guard) {
      weight = (is_dir ? Wgb*Wg : Wg);
    } else if (is_exit) {
      weight = (is_dir ? Web*We : We);
    } else { // middle
      weight = (is_dir ? Wmb*Wm : Wm);
    }

    bandwidths[i] = weight*this_bw;
    weighted_bw += weight*this_bw;
    if (is_me)
      sl_last_weighted_bw_of_me = tor_lround(weight)*this_bw;
  }

  /* XXXX023 this is a kludge to expose these values. */
  sl_last_total_weighted_bw = tor_lround(weighted_bw);

  log_debug(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_CHOOSING_NODE),bandwidth_weight_rule_to_string(rule),Wg,Wm,We,Wd,weighted_bw);

  /* If there is no bandwidth, choose at random */
  if (DBL_TO_U64(weighted_bw) == 0) {
    /* Don't warn when using bridges/relays not in the consensus */
    if (!have_unknown)
      log_warn(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_WEIGHTED_BW),weighted_bw,bandwidth_weight_rule_to_string(rule));
    tor_free(bandwidths);
    return smartlist_choose(sl);
  }

  rand_bw = crypto_rand_uint64(DBL_TO_U64(weighted_bw));
  rand_bw++; /* crypto_rand_uint64() counts from 0, and we need to count
              * from 1 below. See bug 1203 for details. */

  /* Last, count through sl until we get to the element we picked */
  i_chosen = (unsigned)smartlist_len(sl);
  i_has_been_chosen = 0;
  tmp = 0.0;
  for (i=0; i < (unsigned)smartlist_len(sl); i++) {
    tmp += bandwidths[i];
    if (tmp >= rand_bw && !i_has_been_chosen) {
      i_chosen = i;
      i_has_been_chosen = 1;
    }
  }
  i = i_chosen;

  if (i == (unsigned)smartlist_len(sl)) {
    /* This was once possible due to round-off error, but shouldn't be able
     * to occur any longer. */
    tor_fragile_assert();
    --i;
    log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_ROUND_OFF_ERROR), tmp, U64_PRINTF_ARG(rand_bw),
             weighted_bw);
  }
  tor_free(bandwidths);
  return smartlist_get(sl, i);
}

/** Helper function:
 * choose a random element of smartlist <b>sl</b>, weighted by
 * the advertised bandwidth of each element.
 *
 * If <b>statuses</b> is zero, then <b>sl</b> is a list of
 * routerinfo_t's. Otherwise it's a list of routerstatus_t's.
 *
 * If <b>rule</b>==WEIGHT_FOR_EXIT. we're picking an exit node: consider all
 * nodes' bandwidth equally regardless of their Exit status, since there may
 * be some in the list because they exit to obscure ports. If
 * <b>rule</b>==NO_WEIGHTING, we're picking a non-exit node: weight
 * exit-node's bandwidth less depending on the smallness of the fraction of
 * Exit-to-total bandwidth.  If <b>rule</b>==WEIGHT_FOR_GUARD, we're picking a
 * guard node: consider all guard's bandwidth equally. Otherwise, weight
 * guards proportionally less.
 */
static void *
smartlist_choose_by_bandwidth(smartlist_t *sl, bandwidth_weight_rule_t rule,
                              int statuses)
{
  unsigned int i;
  unsigned int i_chosen;
  unsigned int i_has_been_chosen;
  routerinfo_t *router;
  routerstatus_t *status=NULL;
  int32_t *bandwidths;
  int is_exit;
  int is_guard;
  uint64_t total_nonexit_bw = 0, total_exit_bw = 0, total_bw = 0;
  uint64_t total_nonguard_bw = 0, total_guard_bw = 0;
  uint64_t rand_bw, tmp;
  double exit_weight;
  double guard_weight;
  int n_unknown = 0;
  bitarray_t *exit_bits;
  bitarray_t *guard_bits;
  int me_idx = -1;

  // This function does not support WEIGHT_FOR_DIR
  // or WEIGHT_FOR_MID
  if (rule == WEIGHT_FOR_DIR || rule == WEIGHT_FOR_MID) {
    rule = NO_WEIGHTING;
  }

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD);

  if (smartlist_len(sl) == 0) {
    log_info(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_EMPTY_ROUTERLIST_2),bandwidth_weight_rule_to_string(rule));
    return NULL;
  }

  /* First count the total bandwidth weight, and make a list
   * of each value.  <0 means "unknown; no routerinfo."  We use the
   * bits of negative values to remember whether the router was fast (-x)&1
   * and whether it was an exit (-x)&2 or guard (-x)&4.  Yes, it's a hack. */
  bandwidths = tor_malloc(sizeof(int32_t)*smartlist_len(sl));
  exit_bits = bitarray_init_zero(smartlist_len(sl));
  guard_bits = bitarray_init_zero(smartlist_len(sl));

  /* Iterate over all the routerinfo_t or routerstatus_t, and */
  for (i = 0; i < (unsigned)smartlist_len(sl); ++i) {
    /* first, learn what bandwidth we think i has */
    int is_known = 1;
    int32_t flags = 0;
    uint32_t this_bw = 0;
    if (statuses) {
      status = smartlist_get(sl, i);
      if (router_digest_is_me(status->identity_digest))
        me_idx = i;
      router = router_get_by_digest(status->identity_digest);
      is_exit = status->is_exit;
      is_guard = status->is_possible_guard;
      if (status->has_bandwidth) {
        this_bw = kb_to_bytes(status->bandwidth);
      } else { /* guess */
        /* XXX022 once consensuses always list bandwidths, we can take
         * this guessing business out. -RD */
        is_known = 0;
        flags = status->is_fast ? 1 : 0;
        flags |= is_exit ? 2 : 0;
        flags |= is_guard ? 4 : 0;
      }
    } else {
      routerstatus_t *rs;
      router = smartlist_get(sl, i);
      rs = router_get_consensus_status_by_id(
             router->cache_info.identity_digest);
      if (router_digest_is_me(router->cache_info.identity_digest))
        me_idx = i;
      is_exit = router->is_exit;
      is_guard = router->is_possible_guard;
      if (rs && rs->has_bandwidth) {
        this_bw = kb_to_bytes(rs->bandwidth);
      } else if (rs) { /* guess; don't trust the descriptor */
        /* XXX022 once consensuses always list bandwidths, we can take
         * this guessing business out. -RD */
        is_known = 0;
        flags = router->is_fast ? 1 : 0;
        flags |= is_exit ? 2 : 0;
        flags |= is_guard ? 4 : 0;
      } else /* bridge or other descriptor not in our consensus */
        this_bw = bridge_get_advertised_bandwidth_bounded(router);
    }
    if (is_exit)
      bitarray_set(exit_bits, i);
    if (is_guard)
      bitarray_set(guard_bits, i);
    if (is_known) {
      bandwidths[i] = (int32_t) this_bw; // safe since MAX_BELIEVABLE<INT32_MAX
      tor_assert(bandwidths[i] >= 0);
      if (is_guard)
        total_guard_bw += this_bw;
      else
        total_nonguard_bw += this_bw;
      if (is_exit)
        total_exit_bw += this_bw;
      else
        total_nonexit_bw += this_bw;
    } else {
      ++n_unknown;
      bandwidths[i] = -flags;
    }
  }

  /* Now, fill in the unknown values. */
  if (n_unknown) {
    int32_t avg_fast, avg_slow;
    if (total_exit_bw+total_nonexit_bw) {
      /* if there's some bandwidth, there's at least one known router,
       * so no worries about div by 0 here */
      int n_known = smartlist_len(sl)-n_unknown;
      avg_fast = avg_slow = (int32_t)
        ((total_exit_bw+total_nonexit_bw)/((uint64_t) n_known));
    } else {
      avg_fast = 40000;
      avg_slow = 20000;
    }
    for (i=0; i<(unsigned)smartlist_len(sl); ++i) {
      int32_t bw = bandwidths[i];
      if (bw>=0)
        continue;
      is_exit = ((-bw)&2);
      is_guard = ((-bw)&4);
      bandwidths[i] = ((-bw)&1) ? avg_fast : avg_slow;
      if (is_exit)
        total_exit_bw += bandwidths[i];
      else
        total_nonexit_bw += bandwidths[i];
      if (is_guard)
        total_guard_bw += bandwidths[i];
      else
        total_nonguard_bw += bandwidths[i];
    }
  }

  /* If there's no bandwidth at all, pick at random. */
  if (!(total_exit_bw+total_nonexit_bw)) {
    tor_free(bandwidths);
    tor_free(exit_bits);
    tor_free(guard_bits);
    return smartlist_choose(sl);
  }

  /* Figure out how to weight exits and guards */
  {
    double all_bw = U64_TO_DBL(total_exit_bw+total_nonexit_bw);
    double exit_bw = U64_TO_DBL(total_exit_bw);
    double guard_bw = U64_TO_DBL(total_guard_bw);
    /*
     * For detailed derivation of this formula, see
     *   http://archives.seul.org/or/dev/Jul-2007/msg00056.html
     */
    if (rule == WEIGHT_FOR_EXIT || !total_exit_bw)
      exit_weight = 1.0;
    else
      exit_weight = 1.0 - all_bw/(3.0*exit_bw);

    if (rule == WEIGHT_FOR_GUARD || !total_guard_bw)
      guard_weight = 1.0;
    else
      guard_weight = 1.0 - all_bw/(3.0*guard_bw);

    if (exit_weight <= 0.0)
      exit_weight = 0.0;

    if (guard_weight <= 0.0)
      guard_weight = 0.0;

    total_bw = 0;
    sl_last_weighted_bw_of_me = 0;
    for (i=0; i < (unsigned)smartlist_len(sl); i++) {
      uint64_t bw;
      is_exit = bitarray_is_set(exit_bits, i);
      is_guard = bitarray_is_set(guard_bits, i);
      if (is_exit && is_guard)
        bw = ((uint64_t)(bandwidths[i] * exit_weight * guard_weight));
      else if (is_guard)
        bw = ((uint64_t)(bandwidths[i] * guard_weight));
      else if (is_exit)
        bw = ((uint64_t)(bandwidths[i] * exit_weight));
      else
        bw = bandwidths[i];
      total_bw += bw;
      if (i == (unsigned) me_idx)
        sl_last_weighted_bw_of_me = bw;
    }
  }

  /* XXXX022 this is a kludge to expose these values. */
  sl_last_total_weighted_bw = total_bw;

  log_debug(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_BW_STATS),U64_PRINTF_ARG(total_bw),U64_PRINTF_ARG(total_exit_bw),U64_PRINTF_ARG(total_nonexit_bw),exit_weight,(int)(rule == WEIGHT_FOR_EXIT),U64_PRINTF_ARG(total_guard_bw),U64_PRINTF_ARG(total_nonguard_bw),guard_weight,(int)(rule == WEIGHT_FOR_GUARD));

  /* Almost done: choose a random value from the bandwidth weights. */
  rand_bw = crypto_rand_uint64(total_bw);
  rand_bw++; /* crypto_rand_uint64() counts from 0, and we need to count
              * from 1 below. See bug 1203 for details. */

  /* Last, count through sl until we get to the element we picked */
  tmp = 0;
  i_chosen = (unsigned)smartlist_len(sl);
  i_has_been_chosen = 0;
  for (i=0; i < (unsigned)smartlist_len(sl); i++) {
    is_exit = bitarray_is_set(exit_bits, i);
    is_guard = bitarray_is_set(guard_bits, i);

    /* Weights can be 0 if not counting guards/exits */
    if (is_exit && is_guard)
      tmp += ((uint64_t)(bandwidths[i] * exit_weight * guard_weight));
    else if (is_guard)
      tmp += ((uint64_t)(bandwidths[i] * guard_weight));
    else if (is_exit)
      tmp += ((uint64_t)(bandwidths[i] * exit_weight));
    else
      tmp += bandwidths[i];

    if (tmp >= rand_bw && !i_has_been_chosen) {
      i_chosen = i;
      i_has_been_chosen = 1;
    }
  }
  i = i_chosen;
  if (i == (unsigned)smartlist_len(sl)) {
    /* This was once possible due to round-off error, but shouldn't be able
     * to occur any longer. */
    tor_fragile_assert();
    --i;
    log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_COMPUTING_BW),U64_PRINTF_ARG(tmp),U64_PRINTF_ARG(rand_bw),U64_PRINTF_ARG(total_bw));
  }
  tor_free(bandwidths);
  tor_free(exit_bits);
  tor_free(guard_bits);
  return smartlist_get(sl, i);
}

/** Choose a random element of router list <b>sl</b>, weighted by
 * the advertised bandwidth of each router.
 */
routerinfo_t *
routerlist_sl_choose_by_bandwidth(smartlist_t *sl,
                                  bandwidth_weight_rule_t rule)
{
  routerinfo_t *ret;
  if ((ret = smartlist_choose_by_bandwidth_weights(sl, rule, 0))) {
    return ret;
  } else {
    return smartlist_choose_by_bandwidth(sl, rule, 0);
  }
}

/** Choose a random element of status list <b>sl</b>, weighted by
 * the advertised bandwidth of each status.
 */
routerstatus_t *
routerstatus_sl_choose_by_bandwidth(smartlist_t *sl,
                                    bandwidth_weight_rule_t rule)
{
  /* We are choosing neither exit nor guard here. Weight accordingly. */
  routerstatus_t *ret;
  if ((ret = smartlist_choose_by_bandwidth_weights(sl, rule, 1))) {
    return ret;
  } else {
    return smartlist_choose_by_bandwidth(sl, rule, 1);
  }
}

/** Return a random running router from the routerlist.  If any node
 * named in <b>preferred</b> is available, pick one of those.  Never
 * pick a node whose routerinfo is in
 * <b>excludedsmartlist</b>, or whose routerinfo matches <b>excludedset</b>,
 * even if they are the only nodes
 * available.  If <b>CRN_STRICT_PREFERRED</b> is set in flags, never pick
 * any node besides those in <b>preferred</b>.
 * If <b>CRN_NEED_UPTIME</b> is set in flags and any router has more than
 * a minimum uptime, return one of those.
 * If <b>CRN_NEED_CAPACITY</b> is set in flags, weight your choice by the
 * advertised capacity of each router.
 * If <b>CRN_ALLOW_INVALID</b> is not set in flags, consider only Valid
 * routers.
 * If <b>CRN_NEED_GUARD</b> is set in flags, consider only Guard routers.
 * If <b>CRN_WEIGHT_AS_EXIT</b> is set in flags, we weight bandwidths as if
 * picking an exit node, otherwise we weight bandwidths for picking a relay
 * node (that is, possibly discounting exit nodes).
 */
routerinfo_t *
router_choose_random_node(smartlist_t *excludedsmartlist,
                          routerset_t *excludedset,
                          router_crn_flags_t flags)
{
  const int need_uptime = (flags & CRN_NEED_UPTIME) != 0;
  const int need_capacity = (flags & CRN_NEED_CAPACITY) != 0;
  const int need_guard = (flags & CRN_NEED_GUARD) != 0;
  const int allow_invalid = (flags & CRN_ALLOW_INVALID) != 0;
  const int weight_for_exit = (flags & CRN_WEIGHT_AS_EXIT) != 0;

  smartlist_t *sl=smartlist_create(),
              *excludednodes=smartlist_create();
  routerinfo_t *choice = NULL, *r;
  bandwidth_weight_rule_t rule;

  tor_assert(!(weight_for_exit && need_guard));
  rule = weight_for_exit ? WEIGHT_FOR_EXIT :
    (need_guard ? WEIGHT_FOR_GUARD : WEIGHT_FOR_MID);

  /* Exclude relays that allow single hop exit circuits, if the user
   * wants to (such relays might be risky) */
  if ((get_options()->ExcludeSingleHopRelays) && (get_options()->CircuitPathLength>1)) {
    routerlist_t *rl = router_get_routerlist();
    SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r2,
      if (r2->allow_single_hop_exits) {
        smartlist_add(excludednodes, r2);
      });
  }

  if ((r = routerlist_find_my_routerinfo())) {
    smartlist_add(excludednodes, r);
    routerlist_add_family(excludednodes, r);
  }

  router_add_running_routers_to_smartlist(sl, allow_invalid,
                                          need_uptime, need_capacity,
                                          need_guard);
  smartlist_subtract(sl,excludednodes);
  if (excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
  if (excludedset)
    routerset_subtract_routers(sl,excludedset);

  // Always weight by bandwidth
  choice = routerlist_sl_choose_by_bandwidth(sl, rule);

  smartlist_free(sl);
  if (!choice && (need_uptime || need_capacity || need_guard)) {
    /* try once more -- recurse but with fewer restrictions. */
    log_info(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_NO_LIVE_ROUTERS),
             need_capacity?", fast":"",
             need_uptime?", stable":"",
             need_guard?", guard":"");
    flags &= ~ (CRN_NEED_UPTIME|CRN_NEED_CAPACITY|CRN_NEED_GUARD);
    choice = router_choose_random_node(
                     excludedsmartlist, excludedset, flags);
  }
  smartlist_free(excludednodes);
  if (!choice)
	log_warn(LD_CIRC,get_lang_str(LANG_LOG_ROUTERLIST_NO_LIVE_ROUTERS_3));
  return choice;
}

/** Helper: Return true iff the <b>identity_digest</b> and <b>nickname</b>
 * combination of a router, encoded in hexadecimal, matches <b>hexdigest</b>
 * (which is optionally prefixed with a single dollar sign).  Return false if
 * <b>hexdigest</b> is malformed, or it doesn't match.  */
static INLINE int
hex_digest_matches(const char *hexdigest, const char *identity_digest,
                   const char *nickname, int is_named)
{
  char digest[DIGEST_LEN];
  size_t len;
  tor_assert(hexdigest);
  if (hexdigest[0] == '$')
    ++hexdigest;

  len = strlen(hexdigest);
  if (len < HEX_DIGEST_LEN)
    return 0;
  else if (len > HEX_DIGEST_LEN &&
           (hexdigest[HEX_DIGEST_LEN] == '=' ||
            hexdigest[HEX_DIGEST_LEN] == '~')) {
    if (strcasecmp(hexdigest+HEX_DIGEST_LEN+1, nickname))
      return 0;
    if (hexdigest[HEX_DIGEST_LEN] == '=' && !is_named)
      return 0;
  }

  if (base16_decode(digest, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0)
    return 0;
  return (tor_memeq(digest, identity_digest, DIGEST_LEN));
}

/** Return true iff the digest of <b>router</b>'s identity key,
 * encoded in hexadecimal, matches <b>hexdigest</b> (which is
 * optionally prefixed with a single dollar sign).  Return false if
 * <b>hexdigest</b> is malformed, or it doesn't match.  */
static INLINE int
router_hex_digest_matches(routerinfo_t *router, const char *hexdigest)
{
  return hex_digest_matches(hexdigest, router->cache_info.identity_digest,
                            router->nickname, router->is_named);
}

/** Return true if <b>router</b>'s nickname matches <b>nickname</b>
 * (case-insensitive), or if <b>router's</b> identity key digest
 * matches a hexadecimal value stored in <b>nickname</b>.  Return
 * false otherwise. */
static int
router_nickname_matches(routerinfo_t *router, const char *nickname)
{
  if (nickname[0]!='$' && !strcasecmp(router->nickname, nickname))
    return 1;
  return router_hex_digest_matches(router, nickname);
}

/** Return the router in our routerlist whose (case-insensitive)
 * nickname or (case-sensitive) hexadecimal key digest is
 * <b>nickname</b>.  Return NULL if no such router is known.
 */
routerinfo_t *
router_get_by_nickname(const char *nickname, int warn_if_unnamed)
{
  int maybedigest;
  char digest[DIGEST_LEN];
  routerinfo_t *best_match=NULL;
  int n_matches = 0;
  const char *named_digest = NULL;

  tor_assert(nickname);
  if (!routerlist)
    return NULL;
  if (nickname[0] == '$')
    return router_get_by_hexdigest(nickname);
  if (!strcasecmp(nickname, UNNAMED_ROUTER_NICKNAME))
    return NULL;

  maybedigest = (strlen(nickname) >= HEX_DIGEST_LEN) &&
    (base16_decode(digest,DIGEST_LEN,nickname,HEX_DIGEST_LEN) == 0);

  if ((named_digest = networkstatus_get_router_digest_by_nickname(nickname))) {
    return rimap_get(routerlist->identity_map, named_digest);
  }
  if (networkstatus_nickname_is_unnamed(nickname))
    return NULL;

  /* If we reach this point, there's no canonical value for the nickname. */

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (!strcasecmp(router->nickname, nickname)) {
      ++n_matches;
      if (n_matches <= 1 || router->is_running)
        best_match = router;
    } else if (maybedigest &&
               tor_memeq(digest, router->cache_info.identity_digest,
                         DIGEST_LEN)) {
      if (router_hex_digest_matches(router, nickname))
        return router;
      /* If we reach this point, we have a ID=name syntax that matches the
       * identity but not the name. That isn't an acceptable match. */
    }
  });

  if (best_match) {
    if (warn_if_unnamed && n_matches > 1) {
      smartlist_t *fps = smartlist_create();
      int any_unwarned = 0;
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
        {
          routerstatus_t *rs;
          char *desc;
          size_t dlen;
          char fp[HEX_DIGEST_LEN+1];
          if (strcasecmp(router->nickname, nickname))
            continue;
          rs = router_get_consensus_status_by_id(
                                          router->cache_info.identity_digest);
          if (rs && !rs->name_lookup_warned) {
            rs->name_lookup_warned = 1;
            any_unwarned = 1;
          }
          base16_encode(fp, sizeof(fp),
                        router->cache_info.identity_digest, DIGEST_LEN);
          dlen = 32 + HEX_DIGEST_LEN + strlen(router->address);
          desc = tor_malloc(dlen);
          tor_snprintf(desc, dlen, "\"$%s\" for the one at %s:%d",
                       fp, router->address, router->or_port);
          smartlist_add(fps, desc);
        });
      if (any_unwarned) {
        char *alternatives = smartlist_join_strings(fps, "; ",0,NULL);
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_MULTIPLE_NICKNAME_MATCHES),nickname,alternatives);
        tor_free(alternatives);
      }
      SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
      smartlist_free(fps);
    } else if (warn_if_unnamed) {
      routerstatus_t *rs = router_get_consensus_status_by_id(
          best_match->cache_info.identity_digest);
      if (rs && !rs->name_lookup_warned) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp),
                      best_match->cache_info.identity_digest, DIGEST_LEN);
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_NICKNAME_GIVEN),nickname,fp);
        rs->name_lookup_warned = 1;
      }
    }
    return best_match;
  }

  return NULL;
}

/** Try to find a routerinfo for <b>digest</b>. If we don't have one,
 * return 1. If we do, ask tor_version_as_new_as() for the answer.
 */
int
router_digest_version_as_new_as(const char *digest, const char *cutoff)
{
  routerinfo_t *router = router_get_by_digest(digest);
  if (!router)
    return 1;
  return tor_version_as_new_as(router->platform, cutoff);
}

/** Return true iff <b>digest</b> is the digest of the identity key of a
 * trusted directory matching at least one bit of <b>type</b>.  If <b>type</b>
 * is zero, any authority is okay. */
int
router_digest_is_trusted_dir_type(const char *digest, authority_type_t type)
{
  if (!trusted_dir_servers)
    return 0;
  if (authdir_mode(get_options()) && router_digest_is_me(digest))
    return 1;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
    if (tor_memeq(digest, ent->digest, DIGEST_LEN)) {
      return (!type) || ((type & ent->type) != 0);
    });
  return 0;
}

/** Return true iff <b>addr</b> is the address of one of our trusted
 * directory authorities. */
int
router_addr_is_trusted_dir(uint32_t addr)
{
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
    if (ent->addr == addr)
      return 1;
    );
  return 0;
}

/** If hexdigest is correctly formed, base16_decode it into
 * digest, which must have DIGEST_LEN space in it.
 * Return 0 on success, -1 on failure.
 */
int
hexdigest_to_digest(const char *hexdigest, char *digest)
{
  if (hexdigest[0]=='$')
    ++hexdigest;
  if (strlen(hexdigest) < HEX_DIGEST_LEN ||
      base16_decode(digest,DIGEST_LEN,hexdigest,HEX_DIGEST_LEN) < 0)
    return -1;
  return 0;
}

/** Return the router in our routerlist whose hexadecimal key digest
 * is <b>hexdigest</b>.  Return NULL if no such router is known. */
routerinfo_t *
router_get_by_hexdigest(const char *hexdigest)
{
  char digest[DIGEST_LEN];
  size_t len;
  routerinfo_t *ri;

  tor_assert(hexdigest);
  if (!routerlist)
    return NULL;
  if (hexdigest[0]=='$')
    ++hexdigest;
  len = strlen(hexdigest);
  if (hexdigest_to_digest(hexdigest, digest) < 0)
    return NULL;

  ri = router_get_by_digest(digest);

  if (ri && len > HEX_DIGEST_LEN) {
    if (hexdigest[HEX_DIGEST_LEN] == '=') {
      if (strcasecmp(ri->nickname, hexdigest+HEX_DIGEST_LEN+1) ||
          !ri->is_named)
        return NULL;
    } else if (hexdigest[HEX_DIGEST_LEN] == '~') {
      if (strcasecmp(ri->nickname, hexdigest+HEX_DIGEST_LEN+1))
        return NULL;
    } else {
      return NULL;
    }
  }

  return ri;
}

/** Return the router in our routerlist whose 20-byte key digest
 * is <b>digest</b>.  Return NULL if no such router is known. */
routerinfo_t *
router_get_by_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  // routerlist_assert_ok(routerlist);

  return rimap_get(routerlist->identity_map, digest);
}

/** Return the router in our routerlist whose 20-byte descriptor
 * is <b>digest</b>.  Return NULL if no such router is known. */
signed_descriptor_t *
router_get_by_descriptor_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_digest_map, digest);
}

/** Return the signed descriptor for the router in our routerlist whose
 * 20-byte extra-info digest is <b>digest</b>.  Return NULL if no such router
 * is known. */
signed_descriptor_t *
router_get_by_extrainfo_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_by_eid_map, digest);
}

/** Return the signed descriptor for the extrainfo_t in our routerlist whose
 * extra-info-digest is <b>digest</b>. Return NULL if no such extra-info
 * document is known. */
signed_descriptor_t *
extrainfo_get_by_descriptor_digest(const char *digest)
{
  extrainfo_t *ei;
  tor_assert(digest);
  if (!routerlist) return NULL;
  ei = eimap_get(routerlist->extra_info_map, digest);
  return ei ? &ei->cache_info : NULL;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * If <b>with_annotations</b> is set, the returned string will include
 * the annotations
 * (if any) preceding the descriptor.  This will increase the length of the
 * string by desc-\>annotations_len.
 *
 * The caller must not free the string returned.
 */
static char *
signed_descriptor_get_body_impl(signed_descriptor_t *desc,
                                int with_annotations)
{
  char *r = NULL;
  size_t len = desc->signed_descriptor_len;
  off_t offset = desc->saved_offset;
  if (with_annotations)
    len += desc->annotations_len;
  else
    offset += desc->annotations_len;

  tor_assert(len > 32);
  if (desc->saved_location == SAVED_IN_CACHE && routerlist) {
    desc_store_t *store = desc_get_store(router_get_routerlist(), desc);
    if (store && store->mmap) {
      r = get_mmap_data(store->mmap) + offset;
      tor_assert(desc->saved_offset + len <= store->mmap->size);
    } else if (store) {
      log_err(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_READING_DESC));
      exit(1);
    }
  }
  if (!r) /* no mmap, or not in cache. */
    r = desc->signed_descriptor_body +
      (with_annotations ? 0 : desc->annotations_len);

  tor_assert(r);
  if (!with_annotations) {
    if (fast_memcmp("router ", r, 7) && fast_memcmp("extra-info ", r, 11)) {
      char *cp = tor_strndup(r, 64);
      char *esc_l = esc_for_log(cp);
      log_err(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_READING_DESC_2),desc,esc_l);
      tor_free(esc_l);
      tor_free(cp);
      //exit(1);
    }
  }

  return r;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * The caller must not free the string returned.
 */
const char *
signed_descriptor_get_body(signed_descriptor_t *desc)
{
  return signed_descriptor_get_body_impl(desc, 0);
}

/** As signed_descriptor_get_body(), but points to the beginning of the
 * annotations section rather than the beginning of the descriptor. */
const char *
signed_descriptor_get_annotations(signed_descriptor_t *desc)
{
  return signed_descriptor_get_body_impl(desc, 1);
}

/** Return the current list of all known routers. */
routerlist_t *
router_get_routerlist(void)
{
  if (PREDICT_UNLIKELY(!routerlist)) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_create();
    routerlist->old_routers = smartlist_create();
    routerlist->identity_map = rimap_new();
    routerlist->desc_digest_map = sdmap_new();
    routerlist->desc_by_eid_map = sdmap_new();
    routerlist->extra_info_map = eimap_new();

    routerlist->desc_store.fname_base = DATADIR_CACHED_DESCRIPTORS;
    routerlist->desc_store.fname_alt_base = DATADIR_CACHED_ROUTERS;
    routerlist->extrainfo_store.fname_base = DATADIR_CACHED_EXTRAINFO;

    routerlist->desc_store.type = ROUTER_STORE;
    routerlist->extrainfo_store.type = EXTRAINFO_STORE;

    routerlist->desc_store.description = "router descriptors";
    routerlist->extrainfo_store.description = "extra-info documents";
  }
  return routerlist;
}

/** Free all storage held by <b>router</b>. */
void
routerinfo_free(routerinfo_t *router)
{
  if (!router)
    return;

  tor_free(router->cache_info.signed_descriptor_body);
  tor_free(router->address);
  tor_free(router->nickname);
  tor_free(router->platform);
  tor_free(router->contact_info);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if (router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  if (router->declared_family) {
    SMARTLIST_FOREACH(router->declared_family, char *, s, tor_free(s));
    smartlist_free(router->declared_family);
  }
  addr_policy_list_free(router->exit_policy);

  /* XXXX Remove if this turns out to affect performance. */
  memset(router, 77, sizeof(routerinfo_t));

  tor_free(router);
}

#ifdef DEBUG_MALLOC
/** Release all storage held by <b>extrainfo</b> */
void
extrainfo_free(extrainfo_t *extrainfo,const char *c,int n)
{
  if (!extrainfo)
    return;
  _tor_free_(extrainfo->cache_info.signed_descriptor_body,c,n);
  _tor_free_(extrainfo->pending_sig,c,n);

  /* XXXX remove this if it turns out to slow us down. */
  memset(extrainfo, 88, sizeof(extrainfo_t)); /* debug bad memory usage */
  _tor_free_(extrainfo,c,n);
}
#else
/** Release all storage held by <b>extrainfo</b> */
void
extrainfo_free(extrainfo_t *extrainfo)
{
  if (!extrainfo)
    return;
  tor_free(extrainfo->cache_info.signed_descriptor_body);
  tor_free(extrainfo->pending_sig);

  /* XXXX remove this if it turns out to slow us down. */
  memset(extrainfo, 88, sizeof(extrainfo_t)); /* debug bad memory usage */
  tor_free(extrainfo);
}
#endif

/** Release storage held by <b>sd</b>. */
static void
signed_descriptor_free(signed_descriptor_t *sd)
{
  if (!sd)
    return;
  tor_free(sd->signed_descriptor_body);

  /* XXXX remove this once more bugs go away. */
  memset(sd, 99, sizeof(signed_descriptor_t)); /* Debug bad mem usage */
  tor_free(sd);
}

/** Extract a signed_descriptor_t from a routerinfo, and free the routerinfo.
 */
static signed_descriptor_t *
signed_descriptor_from_routerinfo(routerinfo_t *ri)
{
  signed_descriptor_t *sd;
  tor_assert(ri->purpose == ROUTER_PURPOSE_GENERAL);
  sd = tor_malloc_zero(sizeof(signed_descriptor_t));
  memcpy(sd, &(ri->cache_info), sizeof(signed_descriptor_t));
  sd->routerlist_index = -1;
  ri->cache_info.signed_descriptor_body = NULL;
  routerinfo_free(ri);
  return sd;
}

#ifdef DEBUG_MALLOC
/** Helper: free the storage held by the extrainfo_t in <b>e</b>. */
static void
_extrainfo_free(void *e,const char *c,int n)
{
  extrainfo_free(e,c,n);
}
#else
/** Helper: free the storage held by the extrainfo_t in <b>e</b>. */
static void
_extrainfo_free(void *e)
{
  extrainfo_free(e);
}
#endif

/** Free all storage held by a routerlist <b>rl</b>. */
void
routerlist_free(routerlist_t *rl)
{
  if (!rl)
    return;
  rimap_free(rl->identity_map, NULL);
  sdmap_free(rl->desc_digest_map, NULL);
  sdmap_free(rl->desc_by_eid_map, NULL);
  eimap_free(rl->extra_info_map, _extrainfo_free);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
                    signed_descriptor_free(sd));
  smartlist_free(rl->routers);
  smartlist_free(rl->old_routers);
  if (routerlist->desc_store.mmap)
    tor_munmap_file(routerlist->desc_store.mmap);
  if (routerlist->extrainfo_store.mmap)
    tor_munmap_file(routerlist->extrainfo_store.mmap);
  tor_free(rl);

  router_dir_info_changed();
}

/** Log information about how much memory is being used for routerlist,
 * at log level <b>severity</b>. */
void
dump_routerlist_mem_usage(int severity)
{
  uint64_t livedescs = 0;
  uint64_t olddescs = 0;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
                    livedescs += r->cache_info.signed_descriptor_len);
  SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
                    olddescs += sd->signed_descriptor_len);

  log(severity, LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MEM_STATS),smartlist_len(routerlist->routers), U64_PRINTF_ARG(livedescs),smartlist_len(routerlist->old_routers), U64_PRINTF_ARG(olddescs));

#if 0
  {
    const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();
    networkstatus_t *consensus = networkstatus_get_latest_consensus();
    log(severity,LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MEM_STATS_2));
    SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd, {
        int in_v2 = 0;
        int in_v3 = 0;
        char published[ISO_TIME_LEN+1];
        char last_valid_until[ISO_TIME_LEN+1];
        char last_served_at[ISO_TIME_LEN+1];
        char id[HEX_DIGEST_LEN+1];
        routerstatus_t *rs;
        format_iso_time(published, sd->published_on);
        format_iso_time(last_valid_until, sd->last_listed_as_valid_until);
        format_iso_time(last_served_at, sd->last_served_at);
        base16_encode(id, sizeof(id), sd->identity_digest, DIGEST_LEN);
        SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
          {
            rs = networkstatus_v2_find_entry(ns, sd->identity_digest);
            if (rs && !memcmp(rs->descriptor_digest,
                              sd->signed_descriptor_digest, DIGEST_LEN)) {
              in_v2 = 1; break;
            }
          });
        if (consensus) {
          rs = networkstatus_vote_find_entry(consensus, sd->identity_digest);
          if (rs && !memcmp(rs->descriptor_digest,
                            sd->signed_descriptor_digest, DIGEST_LEN))
            in_v3 = 1;
        }
        log(severity, LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MEM_STATS_3),id,published, in_v2 ? get_lang_str(LANG_LOG_ROUTERLIST__IN_V2_NS) : get_lang_str(LANG_LOG_ROUTERLIST__NOT_IN_V2_NS), in_v3 ? get_lang_str(LANG_LOG_ROUTERLIST__IN_V3_CONSENSUS) : get_lang_str(LANG_LOG_ROUTERLIST__NOT_IN_V3_CONSENSUS),last_valid_until,last_served_at);
    });
  }
#endif
}

/** Debugging helper: If <b>idx</b> is nonnegative, assert that <b>ri</b> is
 * in <b>sl</b> at position <b>idx</b>. Otherwise, search <b>sl</b> for
 * <b>ri</b>.  Return the index of <b>ri</b> in <b>sl</b>, or -1 if <b>ri</b>
 * is not in <b>sl</b>. */
static INLINE int
_routerlist_find_elt(smartlist_t *sl, void *ri, int idx)
{
  if (idx < 0) {
    idx = -1;
    SMARTLIST_FOREACH(sl, routerinfo_t *, r,
                      if (r == ri) {
                        idx = r_sl_idx;
                        break;
                      });
  } else {
    tor_assert(idx < smartlist_len(sl));
    tor_assert(smartlist_get(sl, idx) == ri);
  };
  return idx;
}

/** Insert an item <b>ri</b> into the routerlist <b>rl</b>, updating indices
 * as needed.  There must be no previous member of <b>rl</b> with the same
 * identity digest as <b>ri</b>: If there is, call routerlist_replace
 * instead.
 */
static void
routerlist_insert(routerlist_t *rl, routerinfo_t *ri)
{
  routerinfo_t *ri_old;
  signed_descriptor_t *sd_old;
  {
    /* XXXX Remove if this slows us down. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->cache_info.routerlist_index == -1);

  ri_old = rimap_set(rl->identity_map, ri->cache_info.identity_digest, ri);
  tor_assert(!ri_old);
  sd_old = sdmap_set(rl->desc_digest_map,
                     ri->cache_info.signed_descriptor_digest,
                     &(ri->cache_info));
  if (sd_old) {
    int idx = sd_old->routerlist_index;
    sd_old->routerlist_index = -1;
    smartlist_del(rl->old_routers, idx);
    if (idx < smartlist_len(rl->old_routers)) {
       signed_descriptor_t *d = smartlist_get(rl->old_routers, idx);
       d->routerlist_index = idx;
    }
    rl->desc_store.bytes_dropped += sd_old->signed_descriptor_len;
    sdmap_remove(rl->desc_by_eid_map, sd_old->extra_info_digest);
    signed_descriptor_free(sd_old);
  }

  if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
    sdmap_set(rl->desc_by_eid_map, ri->cache_info.extra_info_digest,
              &ri->cache_info);
  smartlist_add(rl->routers, ri);
  ri->cache_info.routerlist_index = smartlist_len(rl->routers) - 1;
  router_dir_info_changed();
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Adds the extrainfo_t <b>ei</b> to the routerlist <b>rl</b>, if there is a
 * corresponding router in rl-\>routers or rl-\>old_routers.  Return true iff
 * we actually inserted <b>ei</b>.  Free <b>ei</b> if it isn't inserted. */
static int extrainfo_insert(routerlist_t *rl, extrainfo_t *ei)
{	int r = 0;
	routerinfo_t *ri = rimap_get(rl->identity_map,ei->cache_info.identity_digest);
	signed_descriptor_t *sd = sdmap_get(rl->desc_by_eid_map, ei->cache_info.signed_descriptor_digest);
	extrainfo_t *ei_tmp;

	if(ri && !routerinfo_incompatible_with_extrainfo(ri, ei, sd, NULL))
	{	/* Okay, if we make it here, we definitely have a router corresponding to this extrainfo. */
		ei_tmp = eimap_set(rl->extra_info_map,ei->cache_info.signed_descriptor_digest,ei);
		r = 1;
		if(ei_tmp)
		{	rl->extrainfo_store.bytes_dropped += ei_tmp->cache_info.signed_descriptor_len;
			EXTRAINFO_FREE(ei_tmp);
		}
	}
	else	EXTRAINFO_FREE(ei);
	return r;
}

#define should_cache_old_descriptors() \
  directory_caches_dir_info(get_options())

/** If we're a directory cache and routerlist <b>rl</b> doesn't have
 * a copy of router <b>ri</b> yet, add it to the list of old (not
 * recommended but still served) descriptors. Else free it. */
static void
routerlist_insert_old(routerlist_t *rl, routerinfo_t *ri)
{
  {
    /* XXXX remove this code if it slows us down. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->cache_info.routerlist_index == -1);

  if (should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL &&
      !sdmap_get(rl->desc_digest_map,
                 ri->cache_info.signed_descriptor_digest)) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri);
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    smartlist_add(rl->old_routers, sd);
    sd->routerlist_index = smartlist_len(rl->old_routers)-1;
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove an item <b>ri</b> from the routerlist <b>rl</b>, updating indices
 * as needed. If <b>idx</b> is nonnegative and smartlist_get(rl-&gt;routers,
 * idx) == ri, we don't need to do a linear search over the list to decide
 * which to remove.  We fill the gap in rl-&gt;routers with a later element in
 * the list, if any exists. <b>ri</b> is freed.
 *
 * If <b>make_old</b> is true, instead of deleting the router, we try adding
 * it to rl-&gt;old_routers. */
void
routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int make_old, time_t now)
{
  routerinfo_t *ri_tmp;
  extrainfo_t *ei_tmp;
  int idx = ri->cache_info.routerlist_index;
  tor_assert(0 <= idx && idx < smartlist_len(rl->routers));
  tor_assert(smartlist_get(rl->routers, idx) == ri);
  /* make sure the rephist module knows that it's not running */
  rep_hist_note_router_unreachable(ri->cache_info.identity_digest, now);

  ri->cache_info.routerlist_index = -1;
  smartlist_del(rl->routers, idx);
  if (idx < smartlist_len(rl->routers)) {
    routerinfo_t *r = smartlist_get(rl->routers, idx);
    r->cache_info.routerlist_index = idx;
  }
  plugins_routerchanged(ri->addr,ri->cache_info.identity_digest,0);

  ri_tmp = rimap_remove(rl->identity_map, ri->cache_info.identity_digest);
  router_dir_info_changed();
  tor_assert(ri_tmp == ri);

  if (make_old && should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL) {
    signed_descriptor_t *sd;
    sd = signed_descriptor_from_routerinfo(ri);
    smartlist_add(rl->old_routers, sd);
    sd->routerlist_index = smartlist_len(rl->old_routers)-1;
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    signed_descriptor_t *sd_tmp;
    sd_tmp = sdmap_remove(rl->desc_digest_map,
                          ri->cache_info.signed_descriptor_digest);
    tor_assert(sd_tmp == &(ri->cache_info));
    rl->desc_store.bytes_dropped += ri->cache_info.signed_descriptor_len;
    ei_tmp = eimap_remove(rl->extra_info_map,
                          ri->cache_info.extra_info_digest);
    if (ei_tmp) {
      rl->extrainfo_store.bytes_dropped +=
        ei_tmp->cache_info.signed_descriptor_len;
      EXTRAINFO_FREE(ei_tmp);
    }
    if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
      sdmap_remove(rl->desc_by_eid_map, ri->cache_info.extra_info_digest);
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove a signed_descriptor_t <b>sd</b> from <b>rl</b>-\>old_routers, and
 * adjust <b>rl</b> as appropriate.  <b>idx</b> is -1, or the index of
 * <b>sd</b>. */
static void
routerlist_remove_old(routerlist_t *rl, signed_descriptor_t *sd, int idx)
{
  signed_descriptor_t *sd_tmp;
  extrainfo_t *ei_tmp;
  desc_store_t *store;
  if (idx == -1) {
    idx = sd->routerlist_index;
  }
  tor_assert(0 <= idx && idx < smartlist_len(rl->old_routers));
  /* XXXX edmanm's bridge relay triggered the following assert while
   * running 0.2.0.12-alpha.  If anybody triggers this again, see if we
   * can get a backtrace. */
  tor_assert(smartlist_get(rl->old_routers, idx) == sd);
  tor_assert(idx == sd->routerlist_index);

  sd->routerlist_index = -1;
  smartlist_del(rl->old_routers, idx);
  if (idx < smartlist_len(rl->old_routers)) {
    signed_descriptor_t *d = smartlist_get(rl->old_routers, idx);
    d->routerlist_index = idx;
  }
  sd_tmp = sdmap_remove(rl->desc_digest_map,
                        sd->signed_descriptor_digest);
  tor_assert(sd_tmp == sd);
  store = desc_get_store(rl, sd);
  if (store)
    store->bytes_dropped += sd->signed_descriptor_len;

  ei_tmp = eimap_remove(rl->extra_info_map,
                        sd->extra_info_digest);
  if (ei_tmp) {
    rl->extrainfo_store.bytes_dropped +=
      ei_tmp->cache_info.signed_descriptor_len;
    EXTRAINFO_FREE(ei_tmp);
  }
  if (!tor_digest_is_zero(sd->extra_info_digest))
    sdmap_remove(rl->desc_by_eid_map, sd->extra_info_digest);

  signed_descriptor_free(sd);
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove <b>ri_old</b> from the routerlist <b>rl</b>, and replace it with
 * <b>ri_new</b>, updating all index info.  If <b>idx</b> is nonnegative and
 * smartlist_get(rl-&gt;routers, idx) == ri, we don't need to do a linear
 * search over the list to decide which to remove.  We put ri_new in the same
 * index as ri_old, if possible.  ri is freed as appropriate.
 *
 * If should_cache_descriptors() is true, instead of deleting the router,
 * we add it to rl-&gt;old_routers. */
static void
routerlist_replace(routerlist_t *rl, routerinfo_t *ri_old,
                   routerinfo_t *ri_new)
{
  int idx;
  int same_descriptors;

  routerinfo_t *ri_tmp;
  extrainfo_t *ei_tmp;
  {
    /* XXXX Remove this if it turns out to slow us down. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri_new);
  }
  tor_assert(ri_old != ri_new);
  tor_assert(ri_new->cache_info.routerlist_index == -1);

  idx = ri_old->cache_info.routerlist_index;
  tor_assert(0 <= idx && idx < smartlist_len(rl->routers));
  tor_assert(smartlist_get(rl->routers, idx) == ri_old);

  router_dir_info_changed();
  if (idx >= 0) {
    smartlist_set(rl->routers, idx, ri_new);
    ri_new->router_id = ri_old->router_id;
    ri_old->cache_info.routerlist_index = -1;
    ri_new->cache_info.routerlist_index = idx;
    /* Check that ri_old is not in rl->routers anymore: */
    tor_assert( _routerlist_find_elt(rl->routers, ri_old, -1) == -1 );
  } else {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_ROUTERLIST_REPLACE_APPEND_ENTRY));
    routerlist_insert(rl, ri_new);
    return;
  }
  if (tor_memneq(ri_old->cache_info.identity_digest,
             ri_new->cache_info.identity_digest, DIGEST_LEN)) {
    /* digests don't match; digestmap_set won't replace */
    rimap_remove(rl->identity_map, ri_old->cache_info.identity_digest);
  }
  ri_tmp = rimap_set(rl->identity_map,
                     ri_new->cache_info.identity_digest, ri_new);
  tor_assert(!ri_tmp || ri_tmp == ri_old);
  sdmap_set(rl->desc_digest_map,
            ri_new->cache_info.signed_descriptor_digest,
            &(ri_new->cache_info));

  if (!tor_digest_is_zero(ri_new->cache_info.extra_info_digest)) {
    sdmap_set(rl->desc_by_eid_map, ri_new->cache_info.extra_info_digest,
              &ri_new->cache_info);
  }

  same_descriptors = tor_memeq(ri_old->cache_info.signed_descriptor_digest,
                              ri_new->cache_info.signed_descriptor_digest,
                              DIGEST_LEN);

  if (should_cache_old_descriptors() &&
      ri_old->purpose == ROUTER_PURPOSE_GENERAL &&
      !same_descriptors) {
    /* ri_old is going to become a signed_descriptor_t and go into
     * old_routers */
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri_old);
    smartlist_add(rl->old_routers, sd);
    sd->routerlist_index = smartlist_len(rl->old_routers)-1;
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    /* We're dropping ri_old. */
    if (!same_descriptors) {
      /* digests don't match; The sdmap_set above didn't replace */
      sdmap_remove(rl->desc_digest_map,
                   ri_old->cache_info.signed_descriptor_digest);

      if (tor_memneq(ri_old->cache_info.extra_info_digest,
                 ri_new->cache_info.extra_info_digest, DIGEST_LEN)) {
        ei_tmp = eimap_remove(rl->extra_info_map,
                              ri_old->cache_info.extra_info_digest);
        if (ei_tmp) {
          rl->extrainfo_store.bytes_dropped +=
            ei_tmp->cache_info.signed_descriptor_len;
          EXTRAINFO_FREE(ei_tmp);
        }
      }

      if (!tor_digest_is_zero(ri_old->cache_info.extra_info_digest)) {
        sdmap_remove(rl->desc_by_eid_map,
                     ri_old->cache_info.extra_info_digest);
      }
    }
    rl->desc_store.bytes_dropped += ri_old->cache_info.signed_descriptor_len;
    routerinfo_free(ri_old);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Extract the descriptor <b>sd</b> from old_routerlist, and re-parse
 * it as a fresh routerinfo_t. */
static routerinfo_t *
routerlist_reparse_old(routerlist_t *rl, signed_descriptor_t *sd)
{
  routerinfo_t *ri;
  const char *body;

  body = signed_descriptor_get_annotations(sd);

  ri = router_parse_entry_from_string(body,
                         body+sd->signed_descriptor_len+sd->annotations_len,
                         0, 1, NULL);
  if (!ri)
    return NULL;
  memcpy(&ri->cache_info, sd, sizeof(signed_descriptor_t));
  sd->signed_descriptor_body = NULL; /* Steal reference. */
  ri->cache_info.routerlist_index = -1;

  routerlist_remove_old(rl, sd, -1);

  return ri;
}

/** Free all memory held by the routerlist module. */
void
routerlist_free_all(void)
{
  if (routerlist)
    routerlist_free(routerlist);
  routerlist = NULL;
  if (warned_nicknames) {
    SMARTLIST_FOREACH(warned_nicknames, char *, cp, tor_free(cp));
    smartlist_free(warned_nicknames);
    warned_nicknames = NULL;
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      trusted_dir_server_free(ds));
    smartlist_free(trusted_dir_servers);
    trusted_dir_servers = NULL;
  }
  if (trusted_dir_certs) {
    DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
      SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
                        authority_cert_free(cert));
      smartlist_free(cl->certs);
      tor_free(cl);
    } DIGESTMAP_FOREACH_END;
    digestmap_free(trusted_dir_certs, NULL);
    trusted_dir_certs = NULL;
  }
}

/** Forget that we have issued any router-related warnings, so that we'll
 * warn again if we see the same errors. */
void
routerlist_reset_warnings(void)
{
  if (!warned_nicknames)
    warned_nicknames = smartlist_create();
  SMARTLIST_FOREACH(warned_nicknames, char *, cp, tor_free(cp));
  smartlist_clear(warned_nicknames); /* now the list is empty. */

  networkstatus_reset_warnings();
}

/** Mark the router with ID <b>digest</b> as running or non-running
 * in our routerlist. */
void
router_set_status(const char *digest, int up)
{
  routerinfo_t *router;
  routerstatus_t *status;
  tor_assert(digest);

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
                    if (tor_memeq(d->digest, digest, DIGEST_LEN))
                      d->is_running = up);

  router = router_get_by_digest(digest);
  if (router) {
    log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MARKING_ROUTER),router->nickname,router->address,up ? get_lang_str(LANG_LOG_ROUTERLIST__AS_UP) : get_lang_str(LANG_LOG_ROUTERLIST__AS_DOWN));
    if (!up && router_is_me(router) && !we_are_hibernating())
      log_warn(LD_NET,get_lang_str(LANG_LOG_ROUTERLIST_MARKING_ROUTER_2));
    router->is_running = up;
  }
  status = router_get_consensus_status_by_id(digest);
  if (status && status->is_running != up) {
    status->is_running = up;
    control_event_networkstatus_changed_single(status);
  }
  router_dir_info_changed();
}

/** Add <b>router</b> to the routerlist, if we don't already have it.  Replace
 * older entries (if any) with the same key.  Note: Callers should not hold
 * their pointers to <b>router</b> if this function fails; <b>router</b>
 * will either be inserted into the routerlist or freed. Similarly, even
 * if this call succeeds, they should not hold their pointers to
 * <b>router</b> after subsequent calls with other routerinfo's -- they
 * might cause the original routerinfo to get freed.
 *
 * Returns the status for the operation. Might set *<b>msg</b> if it wants
 * the poster of the router to know something.
 *
 * If <b>from_cache</b>, this descriptor came from our disk cache. If
 * <b>from_fetch</b>, we received it in response to a request we made.
 * (If both are false, that means it was uploaded to us as an auth dir
 * server or via the controller.)
 *
 * This function should be called *after*
 * routers_update_status_from_consensus_networkstatus; subsequently, you
 * should call router_rebuild_store and routerlist_descriptors_added.
 */
was_router_added_t
router_add_to_routerlist(routerinfo_t *router, const char **msg,
                         int from_cache, int from_fetch)
{
  const char *id_digest;
  or_options_t *options = get_options();
  int authdir = authdir_mode_handles_descs(options, router->purpose);
  int authdir_believes_valid = 0;
  routerinfo_t *old_router;
  networkstatus_t *consensus = networkstatus_get_latest_consensus();
  const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();
  int in_consensus = 0;

  tor_assert(msg);

  if (!routerlist)
    router_get_routerlist();

  id_digest = router->cache_info.identity_digest;

  old_router = router_get_by_digest(id_digest);

  /* Make sure that we haven't already got this exact descriptor. */
  if (sdmap_get(routerlist->desc_digest_map,
                router->cache_info.signed_descriptor_digest)) {
    /* If we have this descriptor already and the new descriptor is a bridge
     * descriptor, replace it. If we had a bridge descriptor before and the
     * new one is not a bridge descriptor, don't replace it. */

    /* Only members of routerlist->identity_map can be bridges; we don't
     * put bridges in old_routers. */
    const int was_bridge = old_router &&
      old_router->purpose == ROUTER_PURPOSE_BRIDGE;

    if (routerinfo_is_a_configured_bridge(router) &&
        router->purpose == ROUTER_PURPOSE_BRIDGE &&
        !was_bridge) {
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_REPLACING_NON_BRIDGE_DESC),router_describe(router));
    } else {
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DESC_ALREADY_HAVE),router_describe(router));
      *msg = get_lang_str(LANG_LOG_ROUTERLIST__DESC_NOT_NEW);
      routerinfo_free(router);
      return ROUTER_WAS_NOT_NEW;
    }
  }

  if (authdir) {
    if (authdir_wants_to_reject_router(router, msg,
                                       !from_cache && !from_fetch)) {
      tor_assert(*msg);
      routerinfo_free(router);
      return ROUTER_AUTHDIR_REJECTS;
    }
    authdir_believes_valid = router->is_valid;
  } else if (from_fetch) {
    /* Only check the descriptor digest against the network statuses when
     * we are receiving in response to a fetch. */

    if (!signed_desc_digest_is_recognized(&router->cache_info) &&
        !routerinfo_is_a_configured_bridge(router)) {
      /* We asked for it, so some networkstatus must have listed it when we
       * did.  Save it if we're a cache in case somebody else asks for it. */
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_UNRECOGNIZED_DESC),router->nickname);
      *msg = get_lang_str(LANG_LOG_ROUTERLIST__DESC_NOT_IN_NS);

      /* Only journal this desc if we'll be serving it. */
      if (!from_cache && should_cache_old_descriptors())
        signed_desc_append_to_journal(&router->cache_info,
                                      &routerlist->desc_store);
      routerlist_insert_old(routerlist, router);
      return ROUTER_NOT_IN_CONSENSUS_OR_NETWORKSTATUS;
    }
  }

  /* We no longer need a router with this descriptor digest. */
  SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
  {
    routerstatus_t *rs =
      networkstatus_v2_find_entry(ns, id_digest);
    if (rs && tor_memeq(rs->descriptor_digest,
                      router->cache_info.signed_descriptor_digest,
                      DIGEST_LEN))
      rs->need_to_mirror = 0;
  });
  if (consensus) {
    routerstatus_t *rs = networkstatus_vote_find_entry(consensus, id_digest);
    if (rs && tor_memeq(rs->descriptor_digest,
                      router->cache_info.signed_descriptor_digest,
                      DIGEST_LEN)) {
      in_consensus = 1;
      rs->need_to_mirror = 0;
    }
  }

  if (router->purpose == ROUTER_PURPOSE_GENERAL &&
      consensus && !in_consensus && !authdir) {
    /* If it's a general router not listed in the consensus, then don't
     * consider replacing the latest router with it. */
    if (!from_cache && should_cache_old_descriptors())
      signed_desc_append_to_journal(&router->cache_info,
                                    &routerlist->desc_store);
    routerlist_insert_old(routerlist, router);
    *msg = get_lang_str(LANG_LOG_ROUTERLIST__DESC_NOT_IN_CONSENSUS);
    return ROUTER_NOT_IN_CONSENSUS;
  }

  /* If we're reading a bridge descriptor from our cache, and we don't
   * recognize it as one of our currently configured bridges, drop the
   * descriptor. Otherwise we could end up using it as one of our entry
   * guards even if it isn't in our Bridge config lines. */
  if (router->purpose == ROUTER_PURPOSE_BRIDGE && from_cache &&
      !authdir_mode_bridge(options) &&
      !routerinfo_is_a_configured_bridge(router)) {
    log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DROPPING_BRIDGE_DESC),
             safe_str_client(router_describe(router)));
    *msg = get_lang_str(LANG_LOG_ROUTERLIST_DESC_NOT_A_BRIDGE);
    routerinfo_free(router);
    return ROUTER_WAS_NOT_WANTED;
  }

  /* If we have a router with the same identity key, choose the newer one. */
  if (old_router) {
    if (!in_consensus && (router->cache_info.published_on <=
                          old_router->cache_info.published_on)) {
      /* Same key, but old.  This one is not listed in the consensus. */
      log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DESC_NOT_NEW),router->nickname);
      /* Only journal this desc if we'll be serving it. */
      if (!from_cache && should_cache_old_descriptors())
        signed_desc_append_to_journal(&router->cache_info,
                                      &routerlist->desc_store);
      plugins_routerchanged(router->addr,router->cache_info.identity_digest,2);
      routerlist_insert_old(routerlist, router);
      *msg = get_lang_str(LANG_LOG_ROUTERLIST__DESC_NOT_NEW);
      return ROUTER_WAS_NOT_NEW;
    } else {
      /* Same key, and either new, or listed in the consensus. */
      log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_REPLACING_ENTRY),router->nickname,old_router->nickname,hex_str(id_digest,DIGEST_LEN));
      if (routers_have_same_or_addr(router, old_router)) {
        /* these carry over when the address and orport are unchanged. */
        router->last_reachable = old_router->last_reachable;
        router->testing_since = old_router->testing_since;
      }
      routerlist_replace(routerlist, old_router, router);
      if (!from_cache) {
        signed_desc_append_to_journal(&router->cache_info,
                                      &routerlist->desc_store);
      }
      directory_set_dirty();
      *msg = authdir_believes_valid ? get_lang_str(LANG_LOG_ROUTERLIST__VALID_SERVER) :get_lang_str(LANG_LOG_ROUTERLIST__INVALID_SERVER);
      plugins_routerchanged(router->addr,router->cache_info.identity_digest,1);
      return ROUTER_ADDED_SUCCESSFULLY;
    }
  }

  if (!in_consensus && from_cache &&
      router->cache_info.published_on < get_time(NULL) - OLD_ROUTER_DESC_MAX_AGE) {
    *msg = get_lang_str(LANG_LOG_ROUTERLIST__DESC_TOO_OLD);
    plugins_routerchanged(router->addr,router->cache_info.identity_digest,2);
    routerinfo_free(router);
    return ROUTER_WAS_NOT_NEW;
  }

  /* We haven't seen a router with this identity before. Add it to the end of
   * the list. */
  routerlist_insert(routerlist, router);
  if (!from_cache)
    signed_desc_append_to_journal(&router->cache_info,
                                  &routerlist->desc_store);
  directory_set_dirty();
  plugins_routerchanged(router->addr,router->cache_info.identity_digest,1);
  return ROUTER_ADDED_SUCCESSFULLY;
}

/** Insert <b>ei</b> into the routerlist, or free it. Other arguments are
 * as for router_add_to_routerlist().  Return ROUTER_ADDED_SUCCESSFULLY iff
 * we actually inserted it, ROUTER_BAD_EI otherwise.
 */
was_router_added_t
router_add_extrainfo_to_routerlist(extrainfo_t *ei, const char **msg,
                                   int from_cache, int from_fetch)
{
  int inserted;
  (void)from_fetch;
  if (msg) *msg = NULL;
  /*XXXX022 Do something with msg */

  inserted = extrainfo_insert(router_get_routerlist(), ei);

  if (inserted && !from_cache)
    signed_desc_append_to_journal(&ei->cache_info,
                                  &routerlist->extrainfo_store);

  if (inserted)
    return ROUTER_ADDED_SUCCESSFULLY;
  else
    return ROUTER_BAD_EI;
}

/** Sorting helper: return &lt;0, 0, or &gt;0 depending on whether the
 * signed_descriptor_t* in *<b>a</b> has an identity digest preceding, equal
 * to, or later than that of *<b>b</b>. */
static int
_compare_old_routers_by_identity(const void **_a, const void **_b)
{
  int i;
  const signed_descriptor_t *r1 = *_a, *r2 = *_b;
  if ((i = fast_memcmp(r1->identity_digest, r2->identity_digest, DIGEST_LEN)))
    return i;
  return (int)(r1->published_on - r2->published_on);
}

/** Internal type used to represent how long an old descriptor was valid,
 * where it appeared in the list of old descriptors, and whether it's extra
 * old. Used only by routerlist_remove_old_cached_routers_with_id(). */
struct duration_idx_t {
  int duration;
  int idx;
  int old;
};

/** Sorting helper: compare two duration_idx_t by their duration. */
static int
_compare_duration_idx(const void *_d1, const void *_d2)
{
  const struct duration_idx_t *d1 = _d1;
  const struct duration_idx_t *d2 = _d2;
  return d1->duration - d2->duration;
}

/** The range <b>lo</b> through <b>hi</b> inclusive of routerlist->old_routers
 * must contain routerinfo_t with the same identity and with publication time
 * in ascending order.  Remove members from this range until there are no more
 * than max_descriptors_per_router() remaining.  Start by removing the oldest
 * members from before <b>cutoff</b>, then remove members which were current
 * for the lowest amount of time.  The order of members of old_routers at
 * indices <b>lo</b> or higher may be changed.
 */
static void
routerlist_remove_old_cached_routers_with_id(time_t now,
                                             time_t cutoff, int lo, int hi,
                                             digestset_t *retain)
{
  int i, n = hi-lo+1;
  unsigned n_extra, n_rmv = 0;
  struct duration_idx_t *lifespans;
  uint8_t *rmv, *must_keep;
  smartlist_t *lst = routerlist->old_routers;
#if 1
  const char *ident;
  tor_assert(hi < smartlist_len(lst));
  tor_assert(lo <= hi);
  ident = ((signed_descriptor_t*)smartlist_get(lst, lo))->identity_digest;
  for (i = lo+1; i <= hi; ++i) {
    signed_descriptor_t *r = smartlist_get(lst, i);
    tor_assert(tor_memeq(ident, r->identity_digest, DIGEST_LEN));
  }
#endif
  /* Check whether we need to do anything at all. */
  {
    int mdpr = directory_caches_dir_info(get_options()) ? 2 : 1;
    if (n <= mdpr)
      return;
    n_extra = n - mdpr;
  }

  lifespans = tor_malloc_zero(sizeof(struct duration_idx_t)*n);
  rmv = tor_malloc_zero(sizeof(uint8_t)*n);
  must_keep = tor_malloc_zero(sizeof(uint8_t)*n);
  /* Set lifespans to contain the lifespan and index of each server. */
  /* Set rmv[i-lo]=1 if we're going to remove a server for being too old. */
  for (i = lo; i <= hi; ++i) {
    signed_descriptor_t *r = smartlist_get(lst, i);
    signed_descriptor_t *r_next;
    lifespans[i-lo].idx = i;
    if (r->last_listed_as_valid_until >= now ||
        (retain && digestset_isin(retain, r->signed_descriptor_digest))) {
      must_keep[i-lo] = 1;
    }
    if (i < hi) {
      r_next = smartlist_get(lst, i+1);
      tor_assert(r->published_on <= r_next->published_on);
      lifespans[i-lo].duration = (int)(r_next->published_on - r->published_on);
    } else {
      r_next = NULL;
      lifespans[i-lo].duration = INT_MAX;
    }
    if (!must_keep[i-lo] && r->published_on < cutoff && n_rmv < n_extra) {
      ++n_rmv;
      lifespans[i-lo].old = 1;
      rmv[i-lo] = 1;
    }
  }

  if (n_rmv < n_extra) {
    /**
     * We aren't removing enough servers for being old.  Sort lifespans by
     * the duration of liveness, and remove the ones we're not already going to
     * remove based on how long they were alive.
     **/
    qsort(lifespans, n, sizeof(struct duration_idx_t), _compare_duration_idx);
    for (i = 0; i < n && n_rmv < n_extra; ++i) {
      if (!must_keep[lifespans[i].idx-lo] && !lifespans[i].old) {
        rmv[lifespans[i].idx-lo] = 1;
        ++n_rmv;
      }
    }
  }

  i = hi;
  do {
    if (rmv[i-lo])
      routerlist_remove_old(routerlist, smartlist_get(lst, i), i);
  } while (--i >= lo);
  tor_free(must_keep);
  tor_free(rmv);
  tor_free(lifespans);
}

/** Deactivate any routers from the routerlist that are more than
 * ROUTER_MAX_AGE seconds old and not recommended by any networkstatuses;
 * remove old routers from the list of cached routers if we have too many.
 */
void routerlist_remove_old_routers(void)
{	if(get_options()->DirFlags&DIR_FLAG_NO_AUTO_UPDATE) return;
	int i, hi=-1;
	const char *cur_id = NULL;
	time_t now = get_time(NULL);
	time_t cutoff;
	routerinfo_t *router;
	signed_descriptor_t *sd;
	digestset_t *retain;
	int caches = directory_caches_dir_info(get_options());
	const networkstatus_t *consensus = networkstatus_get_latest_consensus();
	const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();
	int have_enough_v2;

	trusted_dirs_remove_old_certs();
	if(!routerlist || !consensus)	return;

	/* We need to guess how many router descriptors we will wind up wanting to retain, so that we can be sure to allocate a large enough Bloom filter to hold the digest set.  Overestimating is fine; underestimating is bad. */
	/* We'll probably retain everything in the consensus. */
	int n_max_retain = smartlist_len(consensus->routerstatus_list);
	if(caches && networkstatus_v2_list)	/* If we care about v2 statuses, we'll retain at most as many as are listed any of the v2 statues.  This will be at least the length of the largest v2 networkstatus, and in the worst case, this set will be equal to the sum of the lengths of all v2 consensuses. Take the worst case. */
	{	SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
		{	n_max_retain += smartlist_len(ns->entries);
		});
	}
	retain = digestset_new(n_max_retain);

	cutoff = now - OLD_ROUTER_DESC_MAX_AGE;
	/* Build a list of all the descriptors that _anybody_ lists. */
	if(caches && networkstatus_v2_list)
	{	SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
		{	/* XXXX The inner loop here gets pretty expensive, and actually shows up on some profiles.  It may be the reason digestmap_set shows up in profiles too.  If instead we kept a per-descriptor digest count of how many networkstatuses recommended each descriptor, and changed that only when the networkstatuses changed, that would be a speed improvement, possibly 1-4% if it also removes digestmap_set from the profile.  Not worth it for 0.1.2.x, though.  The new directory system will obsolete this whole thing in 0.2.0.x. */
			SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
			{	if(rs->published_on >= cutoff)
					digestset_add(retain, rs->descriptor_digest);
			});
		});
	}

	/* Retain anything listed in the consensus. */
	if(consensus)
	{	SMARTLIST_FOREACH(consensus->routerstatus_list, routerstatus_t *, rs,
		{	if(rs->published_on >= cutoff)
				digestset_add(retain, rs->descriptor_digest);
		});
	}

	/* If we have a consensus, and nearly as many v2 networkstatuses as we want, we should consider pruning current routers that are too old and that nobody recommends.  (If we don't have a consensus or enough v2 networkstatuses, then we should get more before we decide to kill routers.) We set this to true iff we don't care about v2 info, or we have enough. */
	have_enough_v2 = !caches || (networkstatus_v2_list && smartlist_len(networkstatus_v2_list) > get_n_v2_authorities() / 2);
	if(have_enough_v2 && consensus)
	{	cutoff = now - ROUTER_MAX_AGE;
		/* Remove too-old unrecommended members of routerlist->routers. */
		for(i = 0; i < smartlist_len(routerlist->routers); ++i)
		{	router = smartlist_get(routerlist->routers, i);
			if(router->cache_info.published_on <= cutoff && router->cache_info.last_listed_as_valid_until < now && !digestset_isin(retain,router->cache_info.signed_descriptor_digest))
			{	/* Too old: remove it.  (If we're a cache, just move it into old_routers.) */
				log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ROUTERINFO_TOO_OLD),router->nickname);
				routerlist_remove(routerlist, router, 1, now);
				i--;
			}
		}
	}

	/* Remove far-too-old members of routerlist->old_routers. */
	cutoff = now - OLD_ROUTER_DESC_MAX_AGE;
	for(i = 0; i < smartlist_len(routerlist->old_routers); ++i)
	{	sd = smartlist_get(routerlist->old_routers, i);
		if(sd->published_on <= cutoff && sd->last_listed_as_valid_until < now && !digestset_isin(retain, sd->signed_descriptor_digest))
		{	/* Too old. Remove it. */
			routerlist_remove_old(routerlist, sd, i--);
		}
	}
	log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ROUTER_STATS),smartlist_len(routerlist->routers),smartlist_len(routerlist->old_routers));

	/* Now we might have to look at routerlist->old_routers for extraneous members. (We'd keep all the members if we could, but we need to save space.) First, check whether we have too many router descriptors, total. We're okay with having too many for some given router, so long as the total number doesn't approach max_descriptors_per_router()*len(router). */
	if(smartlist_len(routerlist->old_routers) >= smartlist_len(routerlist->routers))
	{	/* Sort by identity, then fix indices. */
		smartlist_sort(routerlist->old_routers, _compare_old_routers_by_identity);
		/* Fix indices. */
		for(i = 0; i < smartlist_len(routerlist->old_routers); ++i)
		{	signed_descriptor_t *r = smartlist_get(routerlist->old_routers, i);
			r->routerlist_index = i;
		}
		/* Iterate through the list from back to front, so when we remove descriptors we don't mess up groups we haven't gotten to. */
		for(i = smartlist_len(routerlist->old_routers)-1; i >= 0; --i)
		{	signed_descriptor_t *r = smartlist_get(routerlist->old_routers, i);
			if(!cur_id)
			{	cur_id = r->identity_digest;
				hi = i;
			}
			if(tor_memneq(cur_id, r->identity_digest, DIGEST_LEN))
			{	routerlist_remove_old_cached_routers_with_id(now,cutoff,i+1,hi,retain);
				cur_id = r->identity_digest;
				hi = i;
			}
		}
		if(hi>=0)	routerlist_remove_old_cached_routers_with_id(now,cutoff,0,hi,retain);
	}
	digestset_free(retain);
	router_rebuild_store(RRS_DONT_REMOVE_OLD, &routerlist->desc_store);
	router_rebuild_store(RRS_DONT_REMOVE_OLD,&routerlist->extrainfo_store);
}

/** We just added a new set of descriptors. Take whatever extra steps
 * we need. */
void
routerlist_descriptors_added(smartlist_t *sl, int from_cache)
{
  tor_assert(sl);
  control_event_descriptors_changed(sl);
  SMARTLIST_FOREACH_BEGIN(sl, routerinfo_t *, ri) {
    if (ri->purpose == ROUTER_PURPOSE_BRIDGE)
      learned_bridge_descriptor(ri, from_cache);
    if (ri->needs_retest_if_added) {
      ri->needs_retest_if_added = 0;
      dirserv_single_reachability_test(approx_time(), ri);
    }
  } SMARTLIST_FOREACH_END(ri);
}

/**
 * Code to parse a single router descriptor and insert it into the
 * routerlist.  Return -1 if the descriptor was ill-formed; 0 if the
 * descriptor was well-formed but could not be added; and 1 if the
 * descriptor was added.
 *
 * If we don't add it and <b>msg</b> is not NULL, then assign to
 * *<b>msg</b> a static string describing the reason for refusing the
 * descriptor.
 *
 * This is used only by the controller.
 */
int
router_load_single_router(const char *s, uint8_t purpose, int cache,
                          const char **msg)
{
  routerinfo_t *ri;
  was_router_added_t r;
  smartlist_t *lst;
  char annotation_buf[ROUTER_ANNOTATION_BUF_LEN];
  tor_assert(msg);
  *msg = NULL;

  tor_snprintf(annotation_buf, sizeof(annotation_buf),
               "@source controller\n"
               "@purpose %s\n", router_purpose_to_string(purpose));

  if (!(ri = router_parse_entry_from_string(s, NULL, 1, 0, annotation_buf))) {
    log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_PARSING_DESC));
    *msg = "Couldn't parse router descriptor.";
    return -1;
  }
  tor_assert(ri->purpose == purpose);
  if (router_is_me(ri)) {
    log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_KEY_MISMATCH));
    *msg = "Router's identity key matches mine.";
    routerinfo_free(ri);
    return 0;
  }

  if (!cache) /* obey the preference of the controller */
    ri->cache_info.do_not_cache = 1;

  lst = smartlist_create();
  smartlist_add(lst, ri);
  routers_update_status_from_consensus_networkstatus(lst, 0);

  r = router_add_to_routerlist(ri, msg, 0, 0);
  if (!WRA_WAS_ADDED(r)) {
    /* we've already assigned to *msg now, and ri is already freed */
    tor_assert(*msg);
    if (r == ROUTER_AUTHDIR_REJECTS)
      log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ERROR_ADDING_ROUTER),*msg);
    smartlist_free(lst);
    return 0;
  } else {
    routerlist_descriptors_added(lst, 0);
    smartlist_free(lst);
    log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ROUTER_ADDED));
    return 1;
  }
}

/** Given a string <b>s</b> containing some routerdescs, parse it and put the
 * routers into our directory.  If saved_location is SAVED_NOWHERE, the routers
 * are in response to a query to the network: cache them by adding them to
 * the journal.
 *
 * Return the number of routers actually added.
 *
 * If <b>requested_fingerprints</b> is provided, it must contain a list of
 * uppercased fingerprints.  Do not update any router whose
 * fingerprint is not on the list; after updating a router, remove its
 * fingerprint from the list.
 *
 * If <b>descriptor_digests</b> is non-zero, then the requested_fingerprints
 * are descriptor digests. Otherwise they are identity digests.
 */
int
router_load_routers_from_string(const char *s, const char *eos,
                                saved_location_t saved_location,
                                smartlist_t *requested_fingerprints,
                                int descriptor_digests,
                                const char *prepend_annotations)
{
  smartlist_t *routers = smartlist_create(), *changed = smartlist_create();
  char fp[HEX_DIGEST_LEN+1];
  const char *msg;
  int from_cache = (saved_location != SAVED_NOWHERE);
  int allow_annotations = (saved_location != SAVED_NOWHERE);
  int any_changed = 0;

  router_parse_list_from_string(&s, eos, routers, saved_location, 0,
                                allow_annotations, prepend_annotations);

  routers_update_status_from_consensus_networkstatus(routers, !from_cache);

  log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_TO_ADD),smartlist_len(routers));

  SMARTLIST_FOREACH_BEGIN(routers, routerinfo_t *, ri) {
    was_router_added_t r;
    char d[DIGEST_LEN];
    if (requested_fingerprints) {
      base16_encode(fp, sizeof(fp), descriptor_digests ?
                      ri->cache_info.signed_descriptor_digest :
                      ri->cache_info.identity_digest,
                    DIGEST_LEN);
      if (smartlist_string_isin(requested_fingerprints, fp)) {
        smartlist_string_remove(requested_fingerprints, fp);
      } else {
        char *requested =
          smartlist_join_strings(requested_fingerprints," ",0,NULL);
        log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_UNREQUESTED_DESC),fp,requested);
        tor_free(requested);
        routerinfo_free(ri);
        continue;
      }
    }

    memcpy(d, ri->cache_info.signed_descriptor_digest, DIGEST_LEN);
    r = router_add_to_routerlist(ri, &msg, from_cache, !from_cache);
    if (WRA_WAS_ADDED(r)) {
      any_changed++;
      smartlist_add(changed, ri);
      routerlist_descriptors_added(changed, from_cache);
      smartlist_clear(changed);
    } else if (WRA_WAS_REJECTED(r)) {
      download_status_t *dl_status;
      dl_status = router_get_dl_status_by_descriptor_digest(d);
      if (dl_status) {
        log_info(LD_GENERAL,get_lang_str(LANG_LOG_ROUTERLIST_MARKING_ROUTER_3),hex_str(d,DIGEST_LEN));
        download_status_mark_impossible(dl_status);
      }
    }
  } SMARTLIST_FOREACH_END(ri);

  routerlist_assert_ok(routerlist);

  if (any_changed)
    router_rebuild_store(0, &routerlist->desc_store);

  smartlist_free(routers);
  smartlist_free(changed);

  return any_changed;
}

/** Parse one or more extrainfos from <b>s</b> (ending immediately before
 * <b>eos</b> if <b>eos</b> is present).  Other arguments are as for
 * router_load_routers_from_string(). */
void
router_load_extrainfo_from_string(const char *s, const char *eos,
                                  saved_location_t saved_location,
                                  smartlist_t *requested_fingerprints,
                                  int descriptor_digests)
{
  smartlist_t *extrainfo_list = smartlist_create();
  const char *msg;
  int from_cache = (saved_location != SAVED_NOWHERE);

  router_parse_list_from_string(&s, eos, extrainfo_list, saved_location, 1, 0,
                                NULL);

  log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_TO_ADD),smartlist_len(extrainfo_list));

  SMARTLIST_FOREACH(extrainfo_list, extrainfo_t *, ei, {
      was_router_added_t added =
        router_add_extrainfo_to_routerlist(ei, &msg, from_cache, !from_cache);
      if (WRA_WAS_ADDED(added) && requested_fingerprints) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp), descriptor_digests ?
                        ei->cache_info.signed_descriptor_digest :
                        ei->cache_info.identity_digest,
                      DIGEST_LEN);
        smartlist_string_remove(requested_fingerprints, fp);
        /* We silently let people stuff us with extrainfos we didn't ask for,
         * so long as we would have wanted them anyway.  Since we always fetch
         * all the extrainfos we want, and we never actually act on them
         * inside Tor, this should be harmless. */
      }
    });

  routerlist_assert_ok(routerlist);
  router_rebuild_store(0, &router_get_routerlist()->extrainfo_store);

  smartlist_free(extrainfo_list);
}

/** Return true iff any networkstatus includes a descriptor whose digest
 * is that of <b>desc</b>. */
static int
signed_desc_digest_is_recognized(signed_descriptor_t *desc)
{
  routerstatus_t *rs;
  networkstatus_t *consensus = networkstatus_get_latest_consensus();
  int caches = directory_caches_dir_info(get_options());
  const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();

  if (consensus) {
    rs = networkstatus_vote_find_entry(consensus, desc->identity_digest);
    if (rs && tor_memeq(rs->descriptor_digest,
                      desc->signed_descriptor_digest, DIGEST_LEN))
      return 1;
  }
  if (caches && networkstatus_v2_list) {
    SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
    {
      if (!(rs = networkstatus_v2_find_entry(ns, desc->identity_digest)))
        continue;
      if (tor_memeq(rs->descriptor_digest,
                  desc->signed_descriptor_digest, DIGEST_LEN))
        return 1;
    });
  }
  return 0;
}

/** Clear all our timeouts for fetching v2 and v3 directory stuff, and then
 * give it all a try again. */
void
routerlist_retry_directory_downloads(time_t now)
{
  router_reset_status_download_failures();
  router_reset_descriptor_download_failures();
  update_networkstatus_downloads(now);
  update_router_descriptor_downloads(now);
}

/** Return 1 if all running sufficiently-stable routers will reject
 * addr:port, return 0 if any might accept it. */
int
router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime)
{
  addr_policy_result_t r;
  if (!routerlist) return 1;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        !router_is_unreliable(router, need_uptime, 0, 0)) {
      r = compare_addr_to_addr_policy(addr, port, router->exit_policy);
      if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
        return 0; /* this one could be ok. good enough. */
    }
  });
  return 1; /* all will reject. */
}

/** Return true iff <b>router</b> does not permit exit streams.
 */
int
router_exit_policy_rejects_all(routerinfo_t *router)
{
  return router->policy_is_reject_star;
}

/** Add to the list of authoritative directory servers one at
 * <b>address</b>:<b>port</b>, with identity key <b>digest</b>.  If
 * <b>address</b> is NULL, add ourself.  Return the new trusted directory
 * server entry on success or NULL if we couldn't add it. */
trusted_dir_server_t *
add_trusted_dir_server(const char *nickname, const char *address,
                       uint16_t dir_port, uint16_t or_port,
                       const char *digest, const char *v3_auth_digest,
                       authority_type_t type)
{
  trusted_dir_server_t *ent;
  uint32_t a;
  char *hostname = NULL;
  size_t dlen;
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  if (!address) { /* The address is us; we should guess. */
    if (resolve_my_address(LOG_WARN, get_options(), &a, &hostname) < 0) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_RESOLVE_ERROR));
      return NULL;
    }
  } else {
    if (tor_lookup_hostname(address, &a)) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_RESOLVE_ERROR_2),address);
      return NULL;
    }
    hostname = tor_strdup(address);
  }

  ent = tor_malloc_zero(sizeof(trusted_dir_server_t));
  ent->nickname = nickname ? tor_strdup(nickname) : NULL;
  ent->address = hostname;
  ent->addr = a;
  ent->dir_port = dir_port;
  ent->or_port = or_port;
  ent->is_running = 1;
  ent->type = type;
  memcpy(ent->digest, digest, DIGEST_LEN);
  if (v3_auth_digest && (type & V3_AUTHORITY))
    memcpy(ent->v3_identity_digest, v3_auth_digest, DIGEST_LEN);

  dlen = 64 + strlen(hostname) + (nickname?strlen(nickname):0);
  ent->description = tor_malloc(dlen);
  if (nickname)
    tor_snprintf(ent->description, dlen, "directory server \"%s\" at %s:%d",
                 nickname, hostname, (int)dir_port);
  else
    tor_snprintf(ent->description, dlen, "directory server at %s:%d",
                 hostname, (int)dir_port);

  ent->fake_status.addr = ent->addr;
  memcpy(ent->fake_status.identity_digest, digest, DIGEST_LEN);
  if (nickname)
    strlcpy(ent->fake_status.nickname, nickname,
            sizeof(ent->fake_status.nickname));
  else
    ent->fake_status.nickname[0] = '\0';
  ent->fake_status.dir_port = ent->dir_port;
  ent->fake_status.or_port = ent->or_port;

  if (ent->or_port)
    ent->fake_status.version_supports_begindir = 1;
  ent->fake_status.version_supports_conditional_consensus = 1;

  smartlist_add(trusted_dir_servers, ent);
  router_dir_info_changed();
  return ent;
}

/** Free storage held in <b>cert</b>. */
void
authority_cert_free(authority_cert_t *cert)
{
  if (!cert)
    return;

  tor_free(cert->cache_info.signed_descriptor_body);
  if (cert->signing_key)
    crypto_free_pk_env(cert->signing_key);
  if (cert->identity_key)
    crypto_free_pk_env(cert->identity_key);

  tor_free(cert);
}

/** Free storage held in <b>ds</b>. */
static void
trusted_dir_server_free(trusted_dir_server_t *ds)
{
  if (!ds)
    return;
  tor_free(ds->nickname);
  tor_free(ds->description);
  tor_free(ds->address);
  tor_free(ds);
}

/** Remove all members from the list of trusted dir servers. */
void
clear_trusted_dir_servers(void)
{
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                      trusted_dir_server_free(ent));
    smartlist_clear(trusted_dir_servers);
  } else {
    trusted_dir_servers = smartlist_create();
  }
  router_dir_info_changed();
}

/** Return 1 if any trusted dir server supports v1 directories,
 * else return 0. */
int
any_trusted_dir_is_v1_authority(void)
{
  if (trusted_dir_servers)
    return get_n_authorities(V1_AUTHORITY) > 0;

  return 0;
}

/** For every current directory connection whose purpose is <b>purpose</b>,
 * and where the resource being downloaded begins with <b>prefix</b>, split
 * rest of the resource into base16 fingerprints, decode them, and set the
 * corresponding elements of <b>result</b> to a nonzero value. */
static void
list_pending_downloads(digestmap_t *result,
                       int purpose, const char *prefix)
{
  const size_t p_len = strlen(prefix);
  smartlist_t *tmp = smartlist_create();
  smartlist_t *conns = get_connection_array();

  tor_assert(result);

  SMARTLIST_FOREACH(conns, connection_t *, conn,
  {
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == purpose &&
        !conn->marked_for_close) {
      const char *resource = TO_DIR_CONN(conn)->requested_resource;
      if (!strcmpstart(resource, prefix))
        dir_split_resource_into_fingerprints(resource + p_len,
                                             tmp, NULL, DSR_HEX);
    }
  });
  SMARTLIST_FOREACH(tmp, char *, d,
                    {
                      digestmap_set(result, d, (void*)1);
                      tor_free(d);
                    });
  smartlist_free(tmp);
}

/** For every router descriptor (or extra-info document if <b>extrainfo</b> is
 * true) we are currently downloading by descriptor digest, set result[d] to
 * (void*)1. */
static void
list_pending_descriptor_downloads(digestmap_t *result, int extrainfo)
{
  int purpose =
    extrainfo ? DIR_PURPOSE_FETCH_EXTRAINFO : DIR_PURPOSE_FETCH_SERVERDESC;
  list_pending_downloads(result, purpose, "d/");
}

/** Launch downloads for all the descriptors whose digests are listed
 * as digests[i] for lo <= i < hi.  (Lo and hi may be out of range.)
 * If <b>source</b> is given, download from <b>source</b>; otherwise,
 * download from an appropriate random directory server.
 */
static void
initiate_descriptor_downloads(routerstatus_t *source,
                              int purpose,
                              smartlist_t *digests,
                              int lo, int hi, int pds_flags)
{
  int i, n = hi-lo;
  char *resource, *cp;
  size_t r_len;
  if (n <= 0)
    return;
  if (lo < 0)
    lo = 0;
  if (hi > smartlist_len(digests))
    hi = smartlist_len(digests);

  r_len = 8 + (HEX_DIGEST_LEN+1)*n;
  cp = resource = tor_malloc(r_len);
  memcpy(cp, "d/", 2);
  cp += 2;
  for (i = lo; i < hi; ++i) {
    base16_encode(cp, r_len-(cp-resource),
                  smartlist_get(digests,i), DIGEST_LEN);
    cp += HEX_DIGEST_LEN;
    *cp++ = '+';
  }
  memcpy(cp-1, ".z", 3);

  if (source) {
    /* We know which authority we want. */
    directory_initiate_command_routerstatus(source, purpose,
                                            ROUTER_PURPOSE_GENERAL,
                                            0, /* not private */
                                            resource, NULL, 0, 0);
  } else {
    directory_get_from_dirserver(purpose, ROUTER_PURPOSE_GENERAL, resource,
                                 pds_flags);
  }
  tor_free(resource);
}

/** Return 0 if this routerstatus is obsolete, too new, isn't
 * running, or otherwise not a descriptor that we would make any
 * use of even if we had it. Else return 1. */
static INLINE int
client_would_use_router(routerstatus_t *rs, time_t now, or_options_t *options)
{
  if (!rs->is_running && !options->FetchUselessDescriptors) {
    /* If we had this router descriptor, we wouldn't even bother using it.
     * But, if we want to have a complete list, fetch it anyway. */
    return 0;
  }
  if (rs->published_on + options->TestingEstimatedDescriptorPropagationTime
      > now) {
    /* Most caches probably don't have this descriptor yet. */
    return 0;
  }
  if (rs->published_on + OLD_ROUTER_DESC_MAX_AGE < now) {
    /* We'd drop it immediately for being too old. */
    return 0;
  }
  return 1;
}

/** Max amount of hashes to download per request.
 * Since squid does not like URLs >= 4096 bytes we limit it to 96.
 *   4096 - strlen(http://255.255.255.255/tor/server/d/.z) == 4058
 *   4058/41 (40 for the hash and 1 for the + that separates them) => 98
 *   So use 96 because it's a nice number.
 */
#define MAX_DL_PER_REQUEST 96
/** Don't split our requests so finely that we are requesting fewer than
 * this number per server. */
#define MIN_DL_PER_REQUEST 4
/** To prevent a single screwy cache from confusing us by selective reply,
 * try to split our requests into at least this this many requests. */
#define MIN_REQUESTS 3
/** If we want fewer than this many descriptors, wait until we
 * want more, or until MAX_CLIENT_INTERVAL_WITHOUT_REQUEST has
 * passed. */
#define MAX_DL_TO_DELAY 16
/** When directory clients have only a few servers to request, they batch
 * them until they have more, or until this amount of time has passed. */
#define MAX_CLIENT_INTERVAL_WITHOUT_REQUEST (10*60)

/** Given a list of router descriptor digests in <b>downloadable</b>, decide
 * whether to delay fetching until we have more.  If we don't want to delay,
 * launch one or more requests to the appropriate directory authorities. */
static void
launch_router_descriptor_downloads(smartlist_t *downloadable,
                                   routerstatus_t *source, time_t now)
{
  int should_delay = 0, n_downloadable;
  or_options_t *options = get_options();

  n_downloadable = smartlist_len(downloadable);
  if (!directory_fetches_dir_info_early(options)) {
    if (n_downloadable >= MAX_DL_TO_DELAY) {
      log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ENOUGH_ROUTERDESCS_FOR_REQUESTS));
      should_delay = 0;
    } else {
      should_delay = (last_routerdesc_download_attempted +
                      MAX_CLIENT_INTERVAL_WITHOUT_REQUEST) > now;
      if (!should_delay && n_downloadable) {
        if (last_routerdesc_download_attempted) {
          log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DOWNLOAD_DESCS),(int)(now-last_routerdesc_download_attempted));
        } else {
          log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DOWNLOAD_DESCS_2));
        }
      }
    }
  }
  /* XXX should we consider having even the dir mirrors delay
   * a little bit, so we don't load the authorities as much? -RD
   * I don't think so.  If we do, clients that want those descriptors may
   * not actually find them if the caches haven't got them yet. -NM
   */

  if ((! should_delay || options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE) && n_downloadable) {
    int i, n_per_request;
    const char *req_plural = "", *rtr_plural = "";
    int pds_flags = PDS_RETRY_IF_NO_SERVERS;
    if (! authdir_mode_any_nonhidserv(options)) {
      /* If we wind up going to the authorities, we want to only open one
       * connection to each authority at a time, so that we don't overload
       * them.  We do this by setting PDS_NO_EXISTING_SERVERDESC_FETCH
       * regardless of whether we're a cache or not; it gets ignored if we're
       * not calling router_pick_trusteddirserver.
       *
       * Setting this flag can make initiate_descriptor_downloads() ignore
       * requests.  We need to make sure that we do in fact call
       * update_router_descriptor_downloads() later on, once the connections
       * have succeeded or failed.
       */
      pds_flags |= PDS_NO_EXISTING_SERVERDESC_FETCH;
    }

    n_per_request = CEIL_DIV(n_downloadable, MIN_REQUESTS);
    if (n_per_request > MAX_DL_PER_REQUEST)
      n_per_request = MAX_DL_PER_REQUEST;
    if (n_per_request < MIN_DL_PER_REQUEST)
      n_per_request = MIN_DL_PER_REQUEST;

    if (n_downloadable > n_per_request)
      req_plural = rtr_plural = "s";
    else if (n_downloadable > 1)
      rtr_plural = "s";

    log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DOWNLOAD_DESCS_3),(n_downloadable+n_per_request-1)/n_per_request,req_plural,n_downloadable,rtr_plural,n_per_request);
    smartlist_sort_digests(downloadable);
    for (i=0; i < n_downloadable; i += n_per_request) {
      initiate_descriptor_downloads(source, DIR_PURPOSE_FETCH_SERVERDESC,
                                    downloadable, i, i+n_per_request,
                                    pds_flags);
    }
    last_routerdesc_download_attempted = now;
  }
}

/** Launch downloads for router status as needed, using the strategy used by
 * authorities and caches: based on the v2 networkstatuses we have, download
 * every descriptor we don't have but would serve, from a random authority
 * that lists it. */
static void
update_router_descriptor_cache_downloads_v2(time_t now)
{
  smartlist_t **downloadable; /* For each authority, what can we dl from it? */
  smartlist_t **download_from; /*          ... and, what will we dl from it? */
  digestmap_t *map; /* Which descs are in progress, or assigned? */
  int i, j, n;
  int n_download;
  or_options_t *options = get_options();
  const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();

  if (! directory_fetches_dir_info_early(options)) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_WRONG_DIR_MIRROR));
  }

  if (!networkstatus_v2_list || !smartlist_len(networkstatus_v2_list))
    return;

  map = digestmap_new();
  n = smartlist_len(networkstatus_v2_list);

  downloadable = tor_malloc_zero(sizeof(smartlist_t*) * n);
  download_from = tor_malloc_zero(sizeof(smartlist_t*) * n);

  /* Set map[d]=1 for the digest of every descriptor that we are currently
   * downloading. */
  list_pending_descriptor_downloads(map, 0);

  /* For the digest of every descriptor that we don't have, and that we aren't
   * downloading, add d to downloadable[i] if the i'th networkstatus knows
   * about that descriptor, and we haven't already failed to get that
   * descriptor from the corresponding authority.
   */
  n_download = 0;
  SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
    {
      trusted_dir_server_t *ds;
      smartlist_t *dl;
      dl = downloadable[ns_sl_idx] = smartlist_create();
      download_from[ns_sl_idx] = smartlist_create();
      if (ns->published_on + MAX_NETWORKSTATUS_AGE+10*60 < now) {
        /* Don't download if the networkstatus is almost ancient. */
        /* Actually, I suspect what's happening here is that we ask
         * for the descriptor when we have a given networkstatus,
         * and then we get a newer networkstatus, and then we receive
         * the descriptor. Having a networkstatus actually expire is
         * probably a rare event, and we'll probably be happiest if
         * we take this clause out. -RD */
        continue;
      }

      /* Don't try dirservers that we think are down -- we might have
       * just tried them and just marked them as down. */
      ds = router_get_trusteddirserver_by_digest(ns->identity_digest);
      if (ds && !ds->is_running)
        continue;

      SMARTLIST_FOREACH(ns->entries, routerstatus_t * , rs,
        {
          if (!rs->need_to_mirror)
            continue;
          if (router_get_by_descriptor_digest(rs->descriptor_digest)) {
            log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_NEED_TO_MIRROR));
            rs->need_to_mirror = 0;
            continue;
          }
          if (authdir_mode(options) && dirserv_would_reject_router(rs)) {
            rs->need_to_mirror = 0;
            continue;
          }
          if (digestmap_get(map, rs->descriptor_digest)) {
            /* We're downloading it already. */
            continue;
          } else {
            /* We could download it from this guy. */
            smartlist_add(dl, rs->descriptor_digest);
            ++n_download;
          }
        });
    });

  /* At random, assign descriptors to authorities such that:
   * - if d is a member of some downloadable[x], d is a member of some
   *   download_from[y].  (Everything we want to download, we try to download
   *   from somebody.)
   * - If d is a member of download_from[y], d is a member of downloadable[y].
   *   (We only try to download descriptors from authorities who claim to have
   *   them.)
   * - No d is a member of download_from[x] and download_from[y] s.t. x != y.
   *   (We don't try to download anything from two authorities concurrently.)
   */
  while (n_download) {
    int which_ns = crypto_rand_int(n);
    smartlist_t *dl = downloadable[which_ns];
    int idx;
    char *d;
    if (!smartlist_len(dl))
      continue;
    idx = crypto_rand_int(smartlist_len(dl));
    d = smartlist_get(dl, idx);
    if (! digestmap_get(map, d)) {
      smartlist_add(download_from[which_ns], d);
      digestmap_set(map, d, (void*) 1);
    }
    smartlist_del(dl, idx);
    --n_download;
  }

  /* Now, we can actually launch our requests. */
  for (i=0; i<n; ++i) {
    networkstatus_v2_t *ns = smartlist_get(networkstatus_v2_list, i);
    trusted_dir_server_t *ds =
      router_get_trusteddirserver_by_digest(ns->identity_digest);
    smartlist_t *dl = download_from[i];
    int pds_flags = PDS_RETRY_IF_NO_SERVERS;
    if (! authdir_mode_any_nonhidserv(options))
      pds_flags |= PDS_NO_EXISTING_SERVERDESC_FETCH; /* XXXX ignored*/

    if (!ds) {
      log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_NS_WITHOUT_AUTHORITY));
      continue;
    }
    if (! smartlist_len(dl))
      continue;
    log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DOWNLOAD_DESCS_4),smartlist_len(dl),ds->nickname);
    for (j=0; j < smartlist_len(dl); j += MAX_DL_PER_REQUEST) {
      initiate_descriptor_downloads(&(ds->fake_status),
                                    DIR_PURPOSE_FETCH_SERVERDESC, dl, j,
                                    j+MAX_DL_PER_REQUEST, pds_flags);
    }
  }

  for (i=0; i<n; ++i) {
    smartlist_free(download_from[i]);
    smartlist_free(downloadable[i]);
  }
  tor_free(download_from);
  tor_free(downloadable);
  digestmap_free(map,NULL);
}

/** For any descriptor that we want that's currently listed in the live
 * consensus, download it as appropriate. */
void update_consensus_router_descriptor_downloads(time_t now,int is_vote,networkstatus_t *consensus)
{	or_options_t *options = get_options();
	digestmap_t *map = NULL;
	int authdir = authdir_mode(options);
	routerstatus_t *source = NULL;
	int n_delayed=0, n_have=0, n_would_reject=0, n_wouldnt_use=0,n_inprogress=0, n_in_oldrouters=0;
	if(directory_too_idle_to_fetch_descriptors(options, now))
		return;
	if(!consensus)
		return;
	smartlist_t *no_longer_old = smartlist_create();
	smartlist_t *downloadable = smartlist_create();
	if(is_vote)	/* where's it from, so we know whom to ask for descriptors */
	{	trusted_dir_server_t *ds;
		networkstatus_voter_info_t *voter = smartlist_get(consensus->voters, 0);
		tor_assert(voter);
		ds = trusteddirserver_get_by_v3_auth_digest(voter->identity_digest);
		if(ds)	source = &(ds->fake_status);
		else	log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_NO_SOURCE_FROM_VOTE));
	}
	map = digestmap_new();
	list_pending_descriptor_downloads(map,0);
	SMARTLIST_FOREACH(consensus->routerstatus_list, void *, rsp,
	{	routerstatus_t *rs = is_vote ? &(((vote_routerstatus_t *)rsp)->status) : rsp;
		signed_descriptor_t *sd;
		if((sd = router_get_by_descriptor_digest(rs->descriptor_digest)))
		{	routerinfo_t *ri;
			++n_have;
			if(!(ri = router_get_by_digest(rs->identity_digest)) || tor_memneq(ri->cache_info.signed_descriptor_digest,sd->signed_descriptor_digest,DIGEST_LEN))
			{	/* We have a descriptor with this digest, but either there is no entry in routerlist with the same ID (!ri), or there is one, but the identity digest differs (memcmp). */
				smartlist_add(no_longer_old, sd);
				++n_in_oldrouters; /* We have it in old_routers. */
			}
			continue; /* We have it already. */
		}
		if(digestmap_get(map, rs->descriptor_digest))
		{	++n_inprogress;
			continue;	/* We have an in-progress download. */
		}
		if(!download_status_is_ready(&rs->dl_status, now,options->MaxDlFailures?options->MaxDlFailures:32767))
		{	++n_delayed; /* Not ready for retry. */
			continue;
		}
		if(authdir && dirserv_would_reject_router(rs))
		{	++n_would_reject;
			continue; /* We would throw it out immediately. */
		}
		if((options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE)==0 && !directory_caches_dir_info(options) && !client_would_use_router(rs, now, options))
		{	++n_wouldnt_use;
			continue; /* We would never use it ourself. */
		}
		if(is_vote && source)
		{	char time_bufnew[ISO_TIME_LEN+1];
			char time_bufold[ISO_TIME_LEN+1];
			routerinfo_t *oldrouter = router_get_by_digest(rs->identity_digest);
			format_iso_time(time_bufnew, rs->published_on);
			if(oldrouter)	format_iso_time(time_bufold, oldrouter->cache_info.published_on);
			log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_LEARNED_FROM_VOTE),routerstatus_describe(rs),time_bufnew,oldrouter ? time_bufold : "none",source->nickname, oldrouter ? "known" : "unknown");
		}
		smartlist_add(downloadable, rs->descriptor_digest);
	});

	if(!authdir_mode_handles_descs(options, ROUTER_PURPOSE_GENERAL) && smartlist_len(no_longer_old))
	{	routerlist_t *rl = router_get_routerlist();
		log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_MARKING_ROUTER_4),smartlist_len(no_longer_old));
		SMARTLIST_FOREACH(no_longer_old, signed_descriptor_t *, sd,
		{	const char *msg;
			was_router_added_t r;
			routerinfo_t *ri = routerlist_reparse_old(rl, sd);
			if(!ri)
			{	log_warn(LD_BUG,get_lang_str(LANG_LOG_ROUTERLIST_REPARSE_ERROR));
				continue;
			}
			r = router_add_to_routerlist(ri, &msg, 1, 0);
			if(WRA_WAS_OUTDATED(r))
				log_warn(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_REPARSE_ERROR_2),msg?msg:"???");
		});
		routerlist_assert_ok(rl);
	}
	log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ROUTER_STATS_2),smartlist_len(downloadable),n_delayed,n_have,n_in_oldrouters,n_would_reject,n_wouldnt_use,n_inprogress);
	launch_router_descriptor_downloads(downloadable, source, now);
	digestmap_free(map,NULL);
	smartlist_free(downloadable);
	smartlist_free(no_longer_old);
}

/** How often should we launch a server/authority request to be sure of getting
 * a guess for our IP? */
/*XXXX021 this info should come from netinfo cells or something, or we should
 * do this only when we aren't seeing incoming data. see bug 652. */
#define DUMMY_DOWNLOAD_INTERVAL (20*60)

/** Launch downloads for router status as needed. */
extern uint32_t last_guessed_ip;
void
update_router_descriptor_downloads(time_t now)
{
  or_options_t *options = get_options();
  static time_t last_dummy_download = 0;
  if (should_delay_dir_fetches(options))
    return;
  if (directory_fetches_dir_info_early(options)) {
    update_router_descriptor_cache_downloads_v2(now);
  }
  update_consensus_router_descriptor_downloads(now,0,networkstatus_get_reasonably_live_consensus(now));

  /* XXXX021 we could be smarter here; see notes on bug 652. */
  /* If we're a server that doesn't have a configured address, we rely on
   * directory fetches to learn when our address changes.  So if we haven't
   * tried to get any routerdescs in a long time, try a dummy fetch now. */
  if (((!options->Address && server_mode(options))||((options->EnforceDistinctSubnets&4)!=0 && !last_guessed_ip)) && last_routerdesc_download_attempted + DUMMY_DOWNLOAD_INTERVAL < now && last_dummy_download + DUMMY_DOWNLOAD_INTERVAL < now && !(options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE)) {
    last_dummy_download = now;
    directory_get_from_dirserver(DIR_PURPOSE_FETCH_SERVERDESC,
                                 ROUTER_PURPOSE_GENERAL, "authority.z",
                                 PDS_RETRY_IF_NO_SERVERS);
  }
}

/** Launch extrainfo downloads as needed. */
void
update_extrainfo_downloads(time_t now)
{
  or_options_t *options = get_options();
  routerlist_t *rl;
  smartlist_t *wanted;
  digestmap_t *pending;
  int old_routers, i;
  int n_no_ei = 0, n_pending = 0, n_have = 0, n_delay = 0;
  if (! options->DownloadExtraInfo)
    return;
  if (should_delay_dir_fetches(options))
    return;
  if (!router_have_minimum_dir_info())
    return;

  pending = digestmap_new();
  list_pending_descriptor_downloads(pending, 1);
  rl = router_get_routerlist();
  wanted = smartlist_create();
  for (old_routers = 0; old_routers < 2; ++old_routers) {
    smartlist_t *lst = old_routers ? rl->old_routers : rl->routers;
    for (i = 0; i < smartlist_len(lst); ++i) {
      signed_descriptor_t *sd;
      char *d;
      if (old_routers)
        sd = smartlist_get(lst, i);
      else
        sd = &((routerinfo_t*)smartlist_get(lst, i))->cache_info;
      if (sd->is_extrainfo)
        continue; /* This should never happen. */
      if (old_routers && !router_get_by_digest(sd->identity_digest))
        continue; /* Couldn't check the signature if we got it. */
      if (sd->extrainfo_is_bogus)
        continue;
      d = sd->extra_info_digest;
      if (tor_digest_is_zero(d)) {
        ++n_no_ei;
        continue;
      }
      if (eimap_get(rl->extra_info_map, d)) {
        ++n_have;
        continue;
      }
      if (!download_status_is_ready(&sd->ei_dl_status, now,
                                    options->MaxDlFailures?options->MaxDlFailures:32767)) {
        ++n_delay;
        continue;
      }
      if (digestmap_get(pending, d)) {
        ++n_pending;
        continue;
      }
      smartlist_add(wanted, d);
    }
  }
  digestmap_free(pending, NULL);

  log_info(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DOWNLOAD_STATS),n_no_ei,n_have,n_delay,n_pending,smartlist_len(wanted));

  smartlist_shuffle(wanted);
  for (i = 0; i < smartlist_len(wanted); i += MAX_DL_PER_REQUEST) {
    initiate_descriptor_downloads(NULL, DIR_PURPOSE_FETCH_EXTRAINFO,
                                  wanted, i, i + MAX_DL_PER_REQUEST,
                PDS_RETRY_IF_NO_SERVERS|PDS_NO_EXISTING_SERVERDESC_FETCH);
  }

  smartlist_free(wanted);
}

/** True iff, the last time we checked whether we had enough directory info
 * to build circuits, the answer was "yes". */
static int have_min_dir_info = 0;
/** True iff enough has changed since the last time we checked whether we had
 * enough directory info to build circuits that our old answer can no longer
 * be trusted. */
static int need_to_update_have_min_dir_info = 1;
/** String describing what we're missing before we have enough directory
 * info. */
static char dir_info_status[128] = "";

/** Return true iff we have enough networkstatus and router information to
 * start building circuits.  Right now, this means "more than half the
 * networkstatus documents, and at least 1/4 of expected routers." */
//XXX should consider whether we have enough exiting nodes here.
int
router_have_minimum_dir_info(void)
{
  if (PREDICT_UNLIKELY(need_to_update_have_min_dir_info)) {
    update_router_have_minimum_dir_info();
    need_to_update_have_min_dir_info = 0;
  }
  return have_min_dir_info;
}

/** Called when our internal view of the directory has changed.  This can be
 * when the authorities change, networkstatuses change, the list of routerdescs
 * changes, or number of running routers changes.
 */
void
router_dir_info_changed(void)
{
  need_to_update_have_min_dir_info = 1;
  rend_hsdir_routers_changed();
}

/** Return a string describing what we're missing before we have enough
 * directory info. */
const char *
get_dir_info_status_string(void)
{
  return dir_info_status;
}

/** Iterate over the servers listed in <b>consensus</b>, and count how many of
 * them seem like ones we'd use, and how many of <em>those</em> we have
 * descriptors for.  Store the former in *<b>num_usable</b> and the latter in
 * *<b>num_present</b>.  */
static void
count_usable_descriptors(int *num_present, int *num_usable,
                         const networkstatus_t *consensus,
                         or_options_t *options, time_t now,
                         routerset_t *in_set, int exit_only)
{
	*num_present = 0, *num_usable=0;
	if(!(options->DirFlags&DIR_FLAG_NO_AUTO_UPDATE))
	{	SMARTLIST_FOREACH(consensus->routerstatus_list, routerstatus_t *, rs,
		{
			if(exit_only && ! rs->is_exit)
				continue;
			if(in_set && ! routerset_contains_routerstatus(in_set, rs))
				continue;
			if (client_would_use_router(rs, now, options))
			{	++*num_usable; /* the consensus says we want it. */
				if (router_get_by_descriptor_digest(rs->descriptor_digest))
				{	/* we have the descriptor listed in the consensus. */
					++*num_present;
				}
			}
		});
	}
	else
	{	SMARTLIST_FOREACH(consensus->routerstatus_list, routerstatus_t *, rs,
		{	++*num_usable; /* the consensus says we want it. */
			if (router_get_by_descriptor_digest(rs->descriptor_digest))
			{	/* we have the descriptor listed in the consensus. */
				++*num_present;
			}
		});
	}
	log_debug(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_ROUTER_STATS_3),*num_usable,*num_present);
}

/** We just fetched a new set of descriptors. Compute how far through
 * the "loading descriptors" bootstrapping phase we are, so we can inform
 * the controller of our progress. */
int
count_loading_descriptors_progress(void)
{
  int num_present = 0, num_usable=0;
  time_t now = get_time(NULL);
  const networkstatus_t *consensus =
    networkstatus_get_reasonably_live_consensus(now);
  double fraction;

  if (!consensus)
    return 0; /* can't count descriptors if we have no list of them */

  count_usable_descriptors(&num_present, &num_usable,
                           consensus, get_options(), now, NULL,0);

  if (num_usable == 0)
    return 0; /* don't div by 0 */
  fraction = num_present / ((get_options()->DirFlags&DIR_FLAG_WAIT_MORE_DESCRIPTORS?3:1)*num_usable/4.);
  if (fraction > 1.0)
    return 0; /* it's not the number of descriptors holding us back */
  return BOOTSTRAP_STATUS_LOADING_DESCRIPTORS + (int)
    (fraction*(BOOTSTRAP_STATUS_CONN_OR-1 -
               BOOTSTRAP_STATUS_LOADING_DESCRIPTORS));
}

/** Change the value of have_min_dir_info, setting it true iff we have enough
 * network and router information to build circuits.  Clear the value of
 * need_to_update_have_min_dir_info. */
static void update_router_have_minimum_dir_info(void)
{	int num_present = 0, num_usable=0;
	int num_exit_present = 0, num_exit_usable = 0;
	time_t now = get_time(NULL);
	int res;
	or_options_t *options = get_options();
	const networkstatus_t *consensus = networkstatus_get_reasonably_live_consensus(now);
	if(!consensus)
	{	if(!networkstatus_get_latest_consensus())
			strlcpy(dir_info_status,get_lang_str(LANG_LOG_ROUTERLIST_NO_NS_CONSENSUS),sizeof(dir_info_status));
		else
			strlcpy(dir_info_status,get_lang_str(LANG_LOG_ROUTERLIST_NO_RECENT_NS_CONSENSUS),sizeof(dir_info_status));
		res = 0;
	}
	else if(should_delay_dir_fetches(get_options()))
	{	log_notice(LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_NO_BRIDGES));
		strlcpy(dir_info_status,get_lang_str(LANG_LOG_ROUTERLIST_NO_LIVE_BRIDGE_DESCS),sizeof(dir_info_status));
		res = 0;
	}
	else
	{	count_usable_descriptors(&num_present,&num_usable,consensus,options,now,NULL,0);
		count_usable_descriptors(&num_exit_present,&num_exit_usable,consensus,options,now, options->ExitNodes,1);
		if(num_present < (options->DirFlags&DIR_FLAG_WAIT_MORE_DESCRIPTORS?3:1)*num_usable/4)
		{	tor_snprintf(dir_info_status, sizeof(dir_info_status),get_lang_str(LANG_LOG_ROUTERLIST_WE_HAVE_ONLY),num_present,num_usable);
			res = 0;
			control_event_bootstrap(BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS, 0);
		}
		else if(num_present < 2)
		{	tor_snprintf(dir_info_status,sizeof(dir_info_status),get_lang_str(LANG_LOG_ROUTERLIST_REACHABLE_DESCS),num_present,num_present ? "" : "s");
			res = 0;
		}
		else if(num_exit_present < num_exit_usable / 3)
		{	tor_snprintf(dir_info_status, sizeof(dir_info_status),get_lang_str(LANG_LOG_ROUTERLIST_NOT_ENOUGH_EXIT_DESCS),num_exit_present,num_exit_usable);
			res = 0;
			control_event_bootstrap(BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS, 0);
		}
		else	/* Check for entry nodes. */
		{	if(options->EntryNodes)
			{	count_usable_descriptors(&num_present,&num_usable,consensus,options,now,options->EntryNodes,0);
				if(!num_usable || !num_present)
				{	tor_snprintf(dir_info_status, sizeof(dir_info_status),"We have only %d/%d usable entry node descriptors.",num_present,num_usable);
					res = 0;
				}
				else	res = 1;
			}
			else res = 1;
		}
	}
	if(res && !have_min_dir_info)
	{	log(LOG_NOTICE, LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DIR_INFO));
		control_event_client_status(LOG_NOTICE, "ENOUGH_DIR_INFO");
		control_event_bootstrap(BOOTSTRAP_STATUS_CONN_OR, 0);
	}
	if(!res && have_min_dir_info)
	{	int quiet = directory_too_idle_to_fetch_descriptors(options, now);
		log(quiet ? LOG_INFO : LOG_NOTICE,LD_DIR,get_lang_str(LANG_LOG_ROUTERLIST_DIR_INFO_TOO_OLD),dir_info_status);
		can_complete_circuit = 0;
		control_event_client_status(LOG_NOTICE, "NOT_ENOUGH_DIR_INFO");
	}
	have_min_dir_info = res;
	need_to_update_have_min_dir_info = 0;
}

/** Reset the descriptor download failure count on all routers, so that we
 * can retry any long-failed routers immediately.
 */
void
router_reset_descriptor_download_failures(void)
{
  networkstatus_reset_download_failures();
  last_routerdesc_download_attempted = 0;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
  {
    download_status_reset(&ri->cache_info.ei_dl_status);
  });
  SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
  {
    download_status_reset(&sd->ei_dl_status);
  });
}

/** Any changes in a router descriptor's publication time larger than this are
 * automatically non-cosmetic. */
#define ROUTER_MAX_COSMETIC_TIME_DIFFERENCE (12*60*60)

/** We allow uptime to vary from how much it ought to be by this much. */
#define ROUTER_ALLOW_UPTIME_DRIFT (6*60*60)

/** Return true iff the only differences between r1 and r2 are such that
 * would not cause a recent (post 0.1.1.6) dirserver to republish.
 */
int
router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2)
{
  time_t r1pub, r2pub;
  long time_difference;
  tor_assert(r1 && r2);

  /* r1 should be the one that was published first. */
  if (r1->cache_info.published_on > r2->cache_info.published_on) {
    routerinfo_t *ri_tmp = r2;
    r2 = r1;
    r1 = ri_tmp;
  }

  /* If any key fields differ, they're different. */
  if (strcasecmp(r1->address, r2->address) ||
      strcasecmp(r1->nickname, r2->nickname) ||
      r1->or_port != r2->or_port ||
      r1->dir_port != r2->dir_port ||
      r1->purpose != r2->purpose ||
      crypto_pk_cmp_keys(r1->onion_pkey, r2->onion_pkey) ||
      crypto_pk_cmp_keys(r1->identity_pkey, r2->identity_pkey) ||
      strcasecmp(r1->platform, r2->platform) ||
      (r1->contact_info && !r2->contact_info) || /* contact_info is optional */
      (!r1->contact_info && r2->contact_info) ||
      (r1->contact_info && r2->contact_info &&
       strcasecmp(r1->contact_info, r2->contact_info)) ||
      r1->is_hibernating != r2->is_hibernating ||
      r1->has_old_dnsworkers != r2->has_old_dnsworkers ||
      cmp_addr_policies(r1->exit_policy, r2->exit_policy))
    return 0;
  if ((r1->declared_family == NULL) != (r2->declared_family == NULL))
    return 0;
  if (r1->declared_family && r2->declared_family) {
    int i, n;
    if (smartlist_len(r1->declared_family)!=smartlist_len(r2->declared_family))
      return 0;
    n = smartlist_len(r1->declared_family);
    for (i=0; i < n; ++i) {
      if (strcasecmp(smartlist_get(r1->declared_family, i),
                     smartlist_get(r2->declared_family, i)))
        return 0;
    }
  }

  /* Did bandwidth change a lot? */
  if ((r1->bandwidthcapacity < r2->bandwidthcapacity/2) ||
      (r2->bandwidthcapacity < r1->bandwidthcapacity/2))
    return 0;

  /* Did the bandwidthrate or bandwidthburst change? */
  if ((r1->bandwidthrate != r2->bandwidthrate) ||
      (r1->bandwidthburst != r2->bandwidthburst))
    return 0;

  /* Did more than 12 hours pass? */
  if (r1->cache_info.published_on + ROUTER_MAX_COSMETIC_TIME_DIFFERENCE
      < r2->cache_info.published_on)
    return 0;

  /* Did uptime fail to increase by approximately the amount we would think,
   * give or take some slop? */
  r1pub = r1->cache_info.published_on;
  r2pub = r2->cache_info.published_on;
  time_difference = labs(r2->uptime - (r1->uptime + (r2pub - r1pub)));
  if (time_difference > ROUTER_ALLOW_UPTIME_DRIFT &&
      time_difference > r1->uptime * .05 &&
      time_difference > r2->uptime * .05)
    return 0;

  /* Otherwise, the difference is cosmetic. */
  return 1;
}

/** Check whether <b>ri</b> (a.k.a. sd) is a router compatible with the
 * extrainfo document
 * <b>ei</b>.  If no router is compatible with <b>ei</b>, <b>ei</b> should be
 * dropped.  Return 0 for "compatible", return 1 for "reject, and inform
 * whoever uploaded <b>ei</b>, and return -1 for "reject silently.".  If
 * <b>msg</b> is present, set *<b>msg</b> to a description of the
 * incompatibility (if any).
 **/
int routerinfo_incompatible_with_extrainfo(routerinfo_t *ri, extrainfo_t *ei,signed_descriptor_t *sd,const char **msg)
{	int digest_matches, r=1;
	tor_assert(ri);
	tor_assert(ei);
	if(!sd)	sd = &ri->cache_info;
	if(ei->bad_sig)
	{	if (msg) *msg = "Extrainfo signature was bad, or signed with wrong key.";
		return 1;
	}
	digest_matches = tor_memeq(ei->cache_info.signed_descriptor_digest,sd->extra_info_digest, DIGEST_LEN);

	/* The identity must match exactly to have been generated at the same time by the same router. */
	if(tor_memneq(ri->cache_info.identity_digest, ei->cache_info.identity_digest,DIGEST_LEN))
	{	if(msg) *msg = "Extrainfo nickname or identity did not match routerinfo";	/* different servers */
	}
	else
	{	if(ei->pending_sig)
		{	char signed_digest[128];
			if(crypto_pk_public_checksig(ri->identity_pkey,signed_digest, sizeof(signed_digest),ei->pending_sig,ei->pending_sig_len) != DIGEST_LEN || tor_memneq(signed_digest, ei->cache_info.signed_descriptor_digest,DIGEST_LEN))
			{	ei->bad_sig = 1;	/* Bad signature, or no match. */
				tor_free(ei->pending_sig);
				if(msg) *msg = "Extrainfo signature bad, or signed with wrong key";
			}
			else
			{	ei->cache_info.send_unencrypted = ri->cache_info.send_unencrypted;
				tor_free(ei->pending_sig);
			}
		}
		if(!ei->bad_sig)
		{	if(ei->cache_info.published_on < sd->published_on)
			{	if(msg) *msg = "Extrainfo published time did not match routerdesc";
			}
			else if(ei->cache_info.published_on > sd->published_on)
			{	if(msg) *msg = "Extrainfo published time did not match routerdesc";
				r = -1;
			}
			else if(!digest_matches)	/* Digest doesn't match declared value. */
			{	if(msg) *msg = "Extrainfo digest did not match value from routerdesc";
			}
			else return 0;
		}
	}
	if(digest_matches)	/* This signature was okay, and the digest was right: This is indeed the corresponding extrainfo. But insanely, it doesn't match the routerinfo that lists it. Don't try to fetch this one again. */
		sd->extrainfo_is_bogus = 1;
	return r;
}

/** Assert that the internal representation of <b>rl</b> is
 * self-consistent. */
void
routerlist_assert_ok(routerlist_t *rl)
{
  routerinfo_t *r2;
  signed_descriptor_t *sd2;
  if (!rl)
    return;
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
  {
    r2 = rimap_get(rl->identity_map, r->cache_info.identity_digest);
    tor_assert(r == r2);
    sd2 = sdmap_get(rl->desc_digest_map,
                    r->cache_info.signed_descriptor_digest);
    tor_assert(&(r->cache_info) == sd2);
    tor_assert(r->cache_info.routerlist_index == r_sl_idx);
    /* XXXX
     *
     *   Hoo boy.  We need to fix this one, and the fix is a bit tricky, so
     * commenting this out is just a band-aid.
     *
     *   The problem is that, although well-behaved router descriptors
     * should never have the same value for their extra_info_digest, it's
     * possible for ill-behaved routers to claim whatever they like there.
     *
     *   The real answer is to trash desc_by_eid_map and instead have
     * something that indicates for a given extra-info digest we want,
     * what its download status is.  We'll do that as a part of routerlist
     * refactoring once consensus directories are in.  For now,
     * this rep violation is probably harmless: an adversary can make us
     * reset our retry count for an extrainfo, but that's not the end
     * of the world.  Changing the representation in 0.2.0.x would just
     * destabilize the codebase.
    if (!tor_digest_is_zero(r->cache_info.extra_info_digest)) {
      signed_descriptor_t *sd3 =
        sdmap_get(rl->desc_by_eid_map, r->cache_info.extra_info_digest);
      tor_assert(sd3 == &(r->cache_info));
    }
    */
  });
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
  {
    r2 = rimap_get(rl->identity_map, sd->identity_digest);
    tor_assert(sd != &(r2->cache_info));
    sd2 = sdmap_get(rl->desc_digest_map, sd->signed_descriptor_digest);
    tor_assert(sd == sd2);
    tor_assert(sd->routerlist_index == sd_sl_idx);
    /* XXXX see above.
    if (!tor_digest_is_zero(sd->extra_info_digest)) {
      signed_descriptor_t *sd3 =
        sdmap_get(rl->desc_by_eid_map, sd->extra_info_digest);
      tor_assert(sd3 == sd);
    }
    */
  });

  RIMAP_FOREACH(rl->identity_map, d, r) {
    tor_assert(tor_memeq(r->cache_info.identity_digest, d, DIGEST_LEN));
  } DIGESTMAP_FOREACH_END;
  SDMAP_FOREACH(rl->desc_digest_map, d, sd) {
    tor_assert(tor_memeq(sd->signed_descriptor_digest, d, DIGEST_LEN));
  } DIGESTMAP_FOREACH_END;
  SDMAP_FOREACH(rl->desc_by_eid_map, d, sd) {
    tor_assert(!tor_digest_is_zero(d));
    tor_assert(sd);
    tor_assert(tor_memeq(sd->extra_info_digest, d, DIGEST_LEN));
  } DIGESTMAP_FOREACH_END;
  EIMAP_FOREACH(rl->extra_info_map, d, ei) {
    signed_descriptor_t *sd;
    tor_assert(tor_memeq(ei->cache_info.signed_descriptor_digest,
                       d, DIGEST_LEN));
    sd = sdmap_get(rl->desc_by_eid_map,
                   ei->cache_info.signed_descriptor_digest);
    // tor_assert(sd); // XXXX see above
    if (sd) {
      tor_assert(tor_memeq(ei->cache_info.signed_descriptor_digest,
                         sd->extra_info_digest, DIGEST_LEN));
    }
  } DIGESTMAP_FOREACH_END;
}

/** Allocate and return a new string representing the contact info
 * and platform string for <b>router</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * THIS FUNCTION IS NOT REENTRANT.  Don't call it from outside the main
 * thread.  Also, each call invalidates the last-returned value, so don't
 * try log_warn(LD_GENERAL, "%s %s", esc_router_info(a), esc_router_info(b));
 *
 * If <b>router</b> is NULL, it just frees its internal memory and returns.
 */
const char *
esc_router_info(routerinfo_t *router)
{
  static char *info=NULL;
  char *esc_contact, *esc_platform;
  size_t len;
  if (info)
    tor_free(info);
  if (!router)
    return NULL; /* we're exiting; just free the memory we use */

  esc_contact = esc_for_log(router->contact_info);
  esc_platform = esc_for_log(router->platform);

  len = strlen(esc_contact)+strlen(esc_platform)+32;
  info = tor_malloc(len);
  tor_snprintf(info, len, "Contact %s, Platform %s", esc_contact,
               esc_platform);
  tor_free(esc_contact);
  tor_free(esc_platform);

  return info;
}

/** Helper for sorting: compare two routerinfos by their identity
 * digest. */
static int
_compare_routerinfo_by_id_digest(const void **a, const void **b)
{
  routerinfo_t *first = *(routerinfo_t **)a, *second = *(routerinfo_t **)b;
  return fast_memcmp(first->cache_info.identity_digest,
                second->cache_info.identity_digest,
                DIGEST_LEN);
}

/** Sort a list of routerinfo_t in ascending order of identity digest. */
void
routers_sort_by_identity(smartlist_t *routers)
{
  smartlist_sort(routers, _compare_routerinfo_by_id_digest);
}

/** A routerset specifies constraints on a set of possible routerinfos, based
 * on their names, identities, or addresses.  It is optimized for determining
 * whether a router is a member or not, in O(1+P) time, where P is the number
 * of address policy constraints. */
struct routerset_t {
  /** A list of strings for the elements of the policy.  Each string is either
   * a nickname, a hexadecimal identity fingerprint, or an address policy.  A
   * router belongs to the set if its nickname OR its identity OR its address
   * matches an entry here. */
  smartlist_t *list;
  /** A map from lowercase nicknames of routers in the set to (void*)1 */
  strmap_t *names;
  /** A map from identity digests routers in the set to (void*)1 */
  digestmap_t *digests;
  /** An address policy for routers in the set.  For implementation reasons,
   * a router belongs to the set if it is _rejected_ by this policy. */
  smartlist_t *policies;

  /** A human-readable description of what this routerset is for.  Used in
   * log messages. */
  char *description;

  /** A list of the country codes in this set. */
  smartlist_t *country_names;
  /** Total number of countries we knew about when we built <b>countries</b>.*/
  int n_countries;
  /** Bit array mapping the return value of geoip_get_country() to 1 iff the
   * country is a member of this routerset.  Note that we MUST call
   * routerset_refresh_countries() whenever the geoip country list is
   * reloaded. */
  bitarray_t *countries;
};

/** Return a new empty routerset. */
routerset_t *
routerset_new(void)
{
  routerset_t *result = tor_malloc_zero(sizeof(routerset_t));
  result->list = smartlist_create();
  result->names = strmap_new();
  result->digests = digestmap_new();
  result->policies = smartlist_create();
  result->country_names = smartlist_create();
  return result;
}

/** If <b>c</b> is a country code in the form {cc}, return a newly allocated
 * string holding the "cc" part.  Else, return NULL. */
static char *
routerset_get_countryname(const char *c)
{
  char *country;

  if (strlen(c) < 4 || c[0] !='{' || c[3] !='}')
    return NULL;

  country = tor_strndup(c+1, 2);
  tor_strlower(country);
  return country;
}

#if 0
/** Add the GeoIP database's integer index (+1) of a valid two-character
 * country code to the routerset's <b>countries</b> bitarray. Return the
 * integer index if the country code is valid, -1 otherwise.*/
static int
routerset_add_country(const char *c)
{
  char country[3];
  country_t cc;

  /* XXXX: Country codes must be of the form \{[a-z\?]{2}\} but this accepts
     \{[.]{2}\}. Do we need to be strict? -RH */
  /* Nope; if the country code is bad, we'll get 0 when we look it up. */

  memcpy(country, c+1, 2);
  country[2] = '\0';
  tor_strlower(country);

  if ((cc=geoip_get_country(country))==-1) {
    log(LOG_WARN,LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_INVALID_COUNTRY_CODE),country);
  }
  return cc;
}
#endif

/** Update the routerset's <b>countries</b> bitarray_t. Called whenever
 * the GeoIP database is reloaded.
 */
void
routerset_refresh_countries(routerset_t *target)
{
  int cc;
  if (target->countries) {
    bitarray_free(target->countries);
  }
  target->n_countries = geoip_get_n_countries();
  target->countries = bitarray_init_zero(target->n_countries);
  SMARTLIST_FOREACH_BEGIN(target->country_names, const char *, country) {
    cc = geoip_get_country(country);
    if (cc >= 0) {
      tor_assert(cc < target->n_countries);
      bitarray_set(target->countries, cc);
    } else {
      log(LOG_WARN,LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_INVALID_COUNTRY_CODE_2),country);
    }
  } SMARTLIST_FOREACH_END(country);
}

/** Parse the string <b>s</b> to create a set of routerset entries, and add
 * them to <b>target</b>.  In log messages, refer to the string as
 * <b>description</b>.  Return 0 on success, -1 on failure.
 *
 * Three kinds of elements are allowed in routersets: nicknames, IP address
 * patterns, and fingerprints.  They may be surrounded by optional space, and
 * must be separated by commas.
 */
int
routerset_parse(routerset_t *target, const char *s, const char *description)
{
  int r = 0;
  int added_countries = 0;
  char *countryname;
  smartlist_t *list = smartlist_create();
  smartlist_split_string(list, s, ",",
                         SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(list, char *, nick) {
      addr_policy_t *p;
      if (is_legal_hexdigest(nick)) {
        char d[DIGEST_LEN];
        if (*nick == '$')
          ++nick;
        log_debug(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_ADDING_IDENTITY),nick,description);
        base16_decode(d, sizeof(d), nick, HEX_DIGEST_LEN);
        digestmap_set(target->digests, d, (void*)1);
      } else if (is_legal_nickname(nick)) {
        log_debug(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_ADDING_NICKNAME),nick,description);
        strmap_set_lc(target->names, nick, (void*)1);
      } else if ((countryname = routerset_get_countryname(nick)) != NULL) {
        log_debug(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_ADDING_COUNTRY),nick,description);
        smartlist_add(target->country_names, countryname);
        added_countries = 1;
      } else if ((strchr(nick,'.') || strchr(nick, '*')) &&
                 (p = router_parse_addr_policy_item_from_string(
                                     nick, ADDR_POLICY_REJECT))) {
        log_debug(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_ADDING_ADDRESS),nick,description);
        smartlist_add(target->policies, p);
      } else {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_ROUTERLIST_INVALID_ENTRY),nick,description);
        r = -1;
        tor_free(nick);
        SMARTLIST_DEL_CURRENT(list, nick);
      }
  } SMARTLIST_FOREACH_END(nick);
  smartlist_add_all(target->list, list);
  smartlist_free(list);
  if (added_countries)
    routerset_refresh_countries(target);
  return r;
}

/** DOCDOC */
void
refresh_all_country_info(void)
{
  or_options_t *options = get_options();

  if (options->EntryNodes)
    routerset_refresh_countries(options->EntryNodes);
  if (options->ExitNodes)
    routerset_refresh_countries(options->ExitNodes);
  if (options->ExcludeNodes)
    routerset_refresh_countries(options->ExcludeNodes);
  if (options->ExcludeExitNodes)
    routerset_refresh_countries(options->ExcludeExitNodes);
  if (options->_ExcludeExitNodesUnion)
    routerset_refresh_countries(options->_ExcludeExitNodesUnion);

  routerlist_refresh_countries();
}

/** Add all members of the set <b>source</b> to <b>target</b>. */
void
routerset_union(routerset_t *target, const routerset_t *source)
{
  char *s;
  tor_assert(target);
  if (!source || !source->list)
    return;
  s = routerset_to_string(source);
  routerset_parse(target, s, "other routerset");
  tor_free(s);
}

/** Return true iff <b>set</b> lists only nicknames and digests, and includes
 * no IP ranges or countries. */
int
routerset_is_list(const routerset_t *set)
{
  return smartlist_len(set->country_names) == 0 &&
    smartlist_len(set->policies) == 0;
}

/** Return true iff we need a GeoIP IP-to-country database to make sense of
 * <b>set</b>. */
int
routerset_needs_geoip(const routerset_t *set)
{
  return set && smartlist_len(set->country_names);
}

/** Return true iff there are no entries in <b>set</b>. */
int
routerset_is_empty(const routerset_t *set)
{
  return !set || smartlist_len(set->list) == 0;
}

/** Helper.  Return true iff <b>set</b> contains a router based on the other
 * provided fields.  Return higher values for more specific subentries: a
 * single router is more specific than an address range of routers, which is
 * more specific in turn than a country code.
 *
 * (If country is -1, then we take the country
 * from addr.) */
static int
routerset_contains(const routerset_t *set, const tor_addr_t *addr,
                   uint16_t orport,
                   const char *nickname, const char *id_digest, int is_named,
                   country_t country)
{
  if (!set || !set->list) return 0;
  (void) is_named; /* not supported */
  if (nickname)
  {	if(strmap_get_lc(set->names, nickname))	return 4;
  }
  if (id_digest && digestmap_get(set->digests, id_digest))
    return 5;
  if (addr && compare_tor_addr_to_addr_policy(addr, orport, set->policies)
      == ADDR_POLICY_REJECTED)
    return 3;
/*  char *cname=(char*)geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(tor_addr_to_ipv4h(addr))&0xff));
  SMARTLIST_FOREACH(set->list, const char *, name, {
  	if(name[0]=='{' && ((name[1]|0x20)==(cname[0]|0x20))&&((name[2]|0x20)==(cname[1]|0x20)))
		return 4;
  });*/

  if (set->countries) {
    if (country < 0 && addr)
      country = geoip_get_country_by_ip(geoip_reverse(tor_addr_to_ipv4h(addr)))&0xff;

    if (country >= 0 && country < set->n_countries &&
        bitarray_is_set(set->countries, country))
      return 2;
  }
  return 0;
}

/** Return true iff we can tell that <b>ei</b> is a member of <b>set</b>. */
int
routerset_contains_extendinfo(const routerset_t *set, const extend_info_t *ei)
{
  return routerset_contains(set,
                            &ei->addr,
                            ei->port,
                            ei->nickname,
                            ei->identity_digest,
                            -1, /*is_named*/
                            -1 /*country*/);
}

/** Return true iff <b>ri</b> is in <b>set</b>. */
int
routerset_contains_router(const routerset_t *set, routerinfo_t *ri)
{
  tor_addr_t addr;
  tor_addr_from_ipv4h(&addr, ri->addr);
  return routerset_contains(set,
                            &addr,
                            ri->or_port,
                            ri->nickname,
                            ri->cache_info.identity_digest,
                            ri->is_named,
                            ri->country);
}

/** Return true iff <b>rs</b> is in <b>set</b>. */
int
routerset_contains_routerstatus(const routerset_t *set, routerstatus_t *rs)
{
  tor_addr_t addr;
  tor_addr_from_ipv4h(&addr, rs->addr);
  return routerset_contains(set,
                            &addr,
                            rs->or_port,
                            rs->nickname,
                            rs->identity_digest,
                            rs->is_named,
                            -1);
}

/** Add every known routerinfo_t that is a member of <b>routerset</b> to
 * <b>out</b>.  If <b>running_only</b>, only add the running ones. */
void
routerset_get_all_routers(smartlist_t *out, const routerset_t *routerset,
                          const routerset_t *excludeset, int running_only)
{
  //int country=-1;
  tor_assert(out);
  if (!routerset || !routerset->list)
    return;
  if (!warned_nicknames)
    warned_nicknames = smartlist_create();
  if (routerset_is_list(routerset)) {

    /* No routers are specified by type; all are given by name or digest.
     * we can do a lookup in O(len(list)). */
    SMARTLIST_FOREACH(routerset->list, const char *, name, {
  /*  	if(name[0]=='{')
	{	country=geoip_get_country(&name[1]);
		if(country!=-1 && routerlist)
		{	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
			{	if(router->country==country && (!running_only || router->is_running))	smartlist_add(out, router);
			});
		}
	}
	else
	{*/
		routerinfo_t *router = router_get_by_nickname(name, 1);
		if (router)
		{	if(!running_only || router->is_running)
				if(!routerset_contains_router(excludeset, router))	smartlist_add(out, router);
		}
//	}
    });
  } else {
    /* We need to iterate over the routerlist to get all the ones of the
     * right kind. */
    routerlist_t *rl = router_get_routerlist();
    SMARTLIST_FOREACH(rl->routers, routerinfo_t *, router, {
        if (running_only && !router->is_running)
          continue;
        if (routerset_contains_router(routerset, router) &&
            !routerset_contains_router(excludeset, router))
          smartlist_add(out, router);
    });
  }
}

/** Add to <b>target</b> every routerinfo_t from <b>source</b> that is in
 * <b>include</b>, but not excluded in a more specific fashion by
 * <b>exclude</b>.  If <b>running_only</b>, only include running routers.
 */
void
routersets_get_disjunction(smartlist_t *target,
                           const smartlist_t *source,
                           const routerset_t *include,
                           const routerset_t *exclude, int running_only)
{
  SMARTLIST_FOREACH(source, routerinfo_t *, router, {
    int include_result;
    if (running_only && !router->is_running)
      continue;
    if (!routerset_is_empty(include))
      include_result = routerset_contains_router(include, router);
    else
      include_result = 1;

    if (include_result) {
      int exclude_result = routerset_contains_router(exclude, router);
      if (include_result > exclude_result) smartlist_add(target, router);
    }
  });
}

/** Remove every routerinfo_t from <b>lst</b> that is in <b>routerset</b>. */
void
routerset_subtract_routers(smartlist_t *lst, const routerset_t *routerset)
{
  tor_assert(lst);
  if (!routerset)
    return;
  SMARTLIST_FOREACH(lst, routerinfo_t *, r, {
      if (routerset_contains_router(routerset, r)) {
        //log_debug(LD_DIR, "Subtracting %s",r->nickname);
        SMARTLIST_DEL_CURRENT(lst, r);
      }
    });
}

/** Return a new string that when parsed by routerset_parse_string() will
 * yield <b>set</b>. */
char *
routerset_to_string(const routerset_t *set)
{
  if (!set || !set->list)
    return tor_strdup("");
  return smartlist_join_strings(set->list, ",", 0, NULL);
}

/** Helper: return true iff old and new are both NULL, or both non-NULL
 * equal routersets. */
int
routerset_equal(const routerset_t *old, const routerset_t *new)
{
  if (routerset_is_empty(old) && routerset_is_empty(new)) {
    /* Two empty sets are equal */
    return 1;
  } else if (routerset_is_empty(old) || routerset_is_empty(new)) {
    /* An empty set is equal to nothing else. */
    return 0;
  }
  tor_assert(old != NULL);
  tor_assert(new != NULL);

  if (smartlist_len(old->list) != smartlist_len(new->list))
    return 0;

  SMARTLIST_FOREACH(old->list, const char *, cp1, {
    const char *cp2 = smartlist_get(new->list, cp1_sl_idx);
    if (strcmp(cp1, cp2))
      return 0;
  });

  return 1;

#if 0
  /* XXXX: This won't work if the names/digests are identical but in a
     different order. Checking for exact equality would be heavy going,
     is it worth it? -RH*/
  /* This code is totally bogus; sizeof doesn't work even remotely like this
   * code seems to think.  Let's revert to a string-based comparison for
   * now. -NM*/
  if (sizeof(old->names) != sizeof(new->names))
    return 0;

  if (memcmp(old->names,new->names,sizeof(new->names)))
    return 0;
  if (sizeof(old->digests) != sizeof(new->digests))
    return 0;
  if (memcmp(old->digests,new->digests,sizeof(new->digests)))
    return 0;
  if (sizeof(old->countries) != sizeof(new->countries))
    return 0;
  if (memcmp(old->countries,new->countries,sizeof(new->countries)))
    return 0;
  return 1;
#endif
}

/** Free all storage held in <b>routerset</b>. */
void
routerset_free(routerset_t *routerset)
{
  if (!routerset)
    return;
  SMARTLIST_FOREACH(routerset->list, char *, cp, tor_free(cp));
  smartlist_free(routerset->list);
  SMARTLIST_FOREACH(routerset->policies, addr_policy_t *, p,
                    addr_policy_free(p));
  smartlist_free(routerset->policies);
  SMARTLIST_FOREACH(routerset->country_names, char *, cp, tor_free(cp));
  smartlist_free(routerset->country_names);

  strmap_free(routerset->names, NULL);
  digestmap_free(routerset->digests, NULL);
  if (routerset->countries)
    bitarray_free(routerset->countries);
  tor_free(routerset);
}

/** Refresh the country code of <b>ri</b>.  This function MUST be called on
 * each router when the GeoIP database is reloaded, and on all new routers. */
void
routerinfo_set_country(routerinfo_t *ri)
{
  ri->country = geoip_get_country_by_ip(geoip_reverse(ri->addr))&0xff;
}

/** Set the country code of all routers in the routerlist. */
void
routerlist_refresh_countries(void)
{
  routerlist_t *rl = router_get_routerlist();
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, ri,
                    routerinfo_set_country(ri));
}

/** Determine the routers that are responsible for <b>id</b> (binary) and
 * add pointers to those routers' routerstatus_t to <b>responsible_dirs</b>.
 * Return -1 if we're returning an empty smartlist, else return 0.
 */
int
hid_serv_get_responsible_directories(smartlist_t *responsible_dirs,
                                     const char *id)
{
  int start, found, n_added = 0, i;
  networkstatus_t *c = networkstatus_get_latest_consensus();
  if (!c || !smartlist_len(c->routerstatus_list)) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_ROUTERLIST_NO_CONSENSUS));
    return -1;
  }
  tor_assert(id);
  start = networkstatus_vote_find_entry_idx(c, id, &found);
  if (start == smartlist_len(c->routerstatus_list)) start = 0;
  i = start;
  do {
    routerstatus_t *r = smartlist_get(c->routerstatus_list, i);
    if (r->is_hs_dir) {
      smartlist_add(responsible_dirs, r);
      if (++n_added == REND_NUMBER_OF_CONSECUTIVE_REPLICAS)
        return 0;
    }
    if (++i == smartlist_len(c->routerstatus_list))
      i = 0;
  } while (i != start);

  /* Even though we don't have the desired number of hidden service
   * directories, be happy if we got any. */
  return smartlist_len(responsible_dirs) ? 0 : -1;
}

/** Return true if this node is currently acting as hidden service
 * directory, false otherwise. */
int
hid_serv_acting_as_directory(void)
{
  routerinfo_t *me = router_get_my_routerinfo();
  if (!me)
    return 0;
  if (!get_options()->HidServDirectoryV2) {
    log_info(LD_REND,get_lang_str(LANG_LOG_ROUTERLIST_NOT_HS_DIR));
    return 0;
  }
  return 1;
}

/** Return true if this node is responsible for storing the descriptor ID
 * in <b>query</b> and false otherwise. */
int
hid_serv_responsible_for_desc_id(const char *query)
{
  routerinfo_t *me;
  routerstatus_t *last_rs;
  const char *my_id, *last_id;
  int result;
  smartlist_t *responsible;
  if (!hid_serv_acting_as_directory())
    return 0;
  if (!(me = router_get_my_routerinfo()))
    return 0; /* This is redundant, but let's be paranoid. */
  my_id = me->cache_info.identity_digest;
  responsible = smartlist_create();
  if (hid_serv_get_responsible_directories(responsible, query) < 0) {
    smartlist_free(responsible);
    return 0;
  }
  last_rs = smartlist_get(responsible, smartlist_len(responsible)-1);
  last_id = last_rs->identity_digest;
  result = rend_id_is_in_interval(my_id, query, last_id);
  smartlist_free(responsible);
  return result;
}

int get_country_sel(void)
{	return country_sel;
}

void set_country_sel(int newSel,int showlog)
{	if(showlog)
	{	if(newSel==0x200)	log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_RANDOM_COUNTRY));
		else	log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_COUNTRY),GeoIP_getfullname(newSel),geoip_get_country_name(newSel));
	}
	country_sel=newSel;
}

uint32_t get_router_sel(void)
{	if(router_id_sel)
	{	routerinfo_t *r=get_router_by_index(router_id_sel);
		if(r)	return r->addr;
		else return 0;
	}
	return router_sel;
}

uint32_t get_router_id_sel(void)
{	return router_id_sel;
}

void set_router_sel(uint32_t newSel,int showlog)
{	if(showlog)
	{	if(newSel==0x0100007f)	log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_NOEXIT));
		else if(newSel==0)	log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_RANDOM_ROUTER));
		else
		{	uint32_t raddr=geoip_reverse(newSel);
			log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_ROUTER),raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
		}
		if(newSel==0 && ((get_options()->IdentityFlags&IDENTITY_FLAG_LIST_SELECTION)!=0))
		{	next_router_from_sorted_exits();
			return;
		}
		else router_id_sel = 0;
	}
	router_sel=newSel;
}

void set_router_id_sel(uint32_t newSel,int showlog)
{	if(showlog)
	{	routerinfo_t *r=get_router_by_index(newSel);
		if(r)
		{	uint32_t raddr=geoip_reverse(r->addr);
			log(LOG_NOTICE,LD_APP,get_lang_str(LANG_LOG_SELECT_ROUTER),raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
		}
	}
	router_id_sel=newSel;
}

char *print_router_sel(void)
{	char *str;
	if(router_id_sel)
	{	str = tor_malloc(256);
		routerinfo_t *r=get_router_by_index(router_id_sel);
		if(r)
		{	uint32_t raddr=geoip_reverse(r->addr);
			tor_snprintf(str,255,get_lang_str(LANG_LOG_SELECT_ROUTER),raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
		}
		else	return tor_strdup(get_lang_str(LANG_MB_IDENTITY_DIFFERENT_IP));
		return str;
	}
	else if(router_sel)
	{	if(router_sel==0x0100007f)	return tor_strdup(get_lang_str(LANG_LOG_SELECT_NOEXIT));
		uint32_t raddr=geoip_reverse(router_sel);
		str = tor_malloc(256);
		tor_snprintf(str,255,get_lang_str(LANG_LOG_SELECT_ROUTER),raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
		return str;
	}
	else if(country_sel != 0x200)
	{	if(country_sel==0x1ff)	return tor_strdup(get_lang_str(LANG_LOG_SELECT_NOEXIT));
		str = tor_malloc(256);
		tor_snprintf(str,255,get_lang_str(LANG_LOG_SELECT_COUNTRY),GeoIP_getfullname(country_sel),geoip_get_country_name(country_sel));
		return str;
	}
	return tor_strdup(get_lang_str(LANG_MB_IDENTITY_DIFFERENT_IP));
}

const char contry_all[]="*";
const char addr_all[]="*:*";
const char name_all[]="<< Random router >>";
LV_ITEM lvit;

void insert_router_1(HWND hDlg,uint32_t lParam1,const char *country,const char *address,const char *rname,const char *bw,const char *is_exit)
{	int lvErr;
	lvit.lParam=lParam1;
	lvit.mask=LVIF_TEXT|LVIF_PARAM;
	lvit.iSubItem=0;
	lvit.pszText=(char *)country;
	lvit.cchTextMax=3;
	lvErr=SendDlgItemMessage(hDlg,400,LVM_INSERTITEM,0,(LPARAM)&lvit);
	if(lvErr!=-1) lvit.iItem=lvErr;
	lvit.mask=LVIF_TEXT;
	lvit.lParam=0;
	lvit.iSubItem++;
	lvit.pszText=(char *)address;
	lvit.cchTextMax=100;
	SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
	lvit.iSubItem++;
	lvit.pszText=(char *)rname;
	SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
	lvit.iSubItem++;
	lvit.pszText=(char *)bw;
	SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
	if(is_exit)
	{	lvit.iSubItem++;
		lvit.pszText=(char *)is_exit;
		SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
	}
	lvit.iItem++;
}


void add_all_routers_to_list(HWND hDlg,int selType,int last_country_sel)
{	or_options_t *options=get_options();
	time_t now = get_time(NULL);
	lvit.iItem=0;
	lvit.state=0;
	lvit.stateMask=0;
	lvit.iImage=0;
	char is_exit[3],*s1;
	if(last_country_sel==0x200)	insert_router_1(hDlg,0,"ANY","<< Random >>","<< Random router >>","*",NULL);
	else if(last_country_sel==0x1ff)
	{	insert_router_1(hDlg,1,"NONE","<< localhost >>","<< No exit >>","-",NULL);return;}
	else	insert_router_1(hDlg,0,(char *)geoip_get_country_name(last_country_sel),"<< Random >>","<< Random router >>","*",NULL);
	if(selType==SELECT_EXIT && router_sel==0)
	{	lvit.mask=LVIF_STATE;
		lvit.iSubItem=0;
		lvit.stateMask=LVIS_SELECTED;
		lvit.state=LVIS_SELECTED;
		lvit.iItem--;
		SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
		lvit.iItem++;
	}
	if(!routerlist)	return;
	char *raddress=tor_malloc(100);
	char *rbw=tor_malloc(100);
	double bandwidthrate;
	uint32_t raddr;
	int i=0,j;
	char country_name[5];
	int country;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((selType==SELECT_EXIT&&router->is_exit)||(selType==SELECT_ENTRY&&router->is_possible_guard)||(selType==SELECT_ANY))
		{	raddr=geoip_reverse(router->addr);
			if((last_country_sel==0x200)||(last_country_sel==(geoip_get_country_by_ip(raddr)&0xff)))
			{	if(selType!=SELECT_EXIT || !(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_ENABLED) || dlgBypassBlacklists_isRecent(raddr,router,now))
				{
					tor_snprintf(raddress,100,"%d.%d.%d.%d:%d",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,router->or_port);
					j = (selType==SELECT_EXIT&&(routerset_contains_router(options->_ExcludeExitNodesUnion,router))) || routerset_contains_router(options->ExcludeNodes,router);
					if(j)	tor_snprintf(rbw,100,"--------");
					else if(router->bandwidthcapacity>1024)
					{	bandwidthrate=(double)router->bandwidthcapacity/1024;
						if(bandwidthrate>1024)
						{	bandwidthrate/=1024;
							if(bandwidthrate>1024)
							{	bandwidthrate/=1024;
								tor_snprintf(rbw,100,"%s%.2f GB",(router->is_running && router->is_valid && !router->is_bad_exit)?"":"[?] ",bandwidthrate);
							}
							else tor_snprintf(rbw,100,"%s%.2f MB",(router->is_running && router->is_valid && !router->is_bad_exit)?"":"[?] ",bandwidthrate);
						}
						else tor_snprintf(rbw,100,"%s%.2f kB",(router->is_running && router->is_valid && !router->is_bad_exit)?"":"[?] ",bandwidthrate);
					}
					else tor_snprintf(rbw,100,"%s%d B",(router->is_running && router->is_valid && !router->is_bad_exit)?"":"[?] ",router->bandwidthcapacity);
					country = geoip_get_country_by_ip(raddr);
					tor_snprintf(country_name,4,"%s%s",(char *)geoip_get_country_name(country&0xff),country>0xff?"*":"");
					if(selType==SELECT_ANY)
					{	s1=&is_exit[0];
						if(router->is_possible_guard) *s1++='E';
						if(router->is_exit) *s1++='X';
						*s1=0;
						insert_router_1(hDlg,j?-(router->router_id):(router->router_id),&country_name[0],raddress,router->nickname,rbw,is_exit);
					}
					else	insert_router_1(hDlg,j?-(router->router_id):(router->router_id),&country_name[0],raddress,router->nickname,rbw,NULL);
					if(selType==SELECT_EXIT && ((router_id_sel && router->router_id==router_id_sel) || router->addr==router_sel))
					{	lvit.mask=LVIF_STATE;
						lvit.iSubItem=0;
						lvit.stateMask=LVIS_SELECTED;
						lvit.state=LVIS_SELECTED;
						lvit.iItem--;
						SendDlgItemMessage(hDlg,400,LVM_SETITEM,0,(LPARAM)&lvit);
						lvit.iItem++;
					}
				}
			}
		}
		i++;
	});
	tor_free(raddress);tor_free(rbw);
}

routerinfo_t *get_router(uint32_t i)
{	if(!routerlist)	return NULL;
	if(i&0x80000000) i = -i;
	i -= 1024;
	if(i < (uint32_t)smartlist_len(routerlist->routers))	return smartlist_get(routerlist->routers,i);
	return NULL;
//	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
//	{	if(router->router_id==i)	return router;
//	});
//	return NULL;
}

#define MAX_TRAY_IP_LIST 30

uint32_t iplist[MAX_TRAY_IP_LIST];

void add_routers_to_menu(HMENU hMenu1)
{	or_options_t *options=get_options();
	int routerCount=0;
	int country;
	if(!routerlist)	return;
	char *raddress=tor_malloc(100);
	uint32_t raddr;
	if(options->ExitNodes)
	{	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
		{	if((routerCount<MAX_TRAY_IP_LIST)&&(router->is_exit)&&(!routerset_contains_router(options->_ExcludeExitNodesUnion,router))&&routerset_contains_router(options->ExitNodes,router))
			{	raddr=geoip_reverse(router->addr);
				country = geoip_get_country_by_ip(raddr);
				if((country_sel==0x200)||(country_sel==(country&0xff)))
				{	tor_snprintf(raddress,100,"[%s%s] %d.%d.%d.%d (%s)",geoip_get_country_name(geoip_get_country_by_ip(raddr)),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,router->nickname);
					iplist[routerCount]=router->addr;
					AppendMenu(hMenu1,MF_STRING|((router_sel==router->addr)?MF_CHECKED:0),20200+routerCount,raddress);
					routerCount++;
				}
			}
		});
	}
	if(routerCount && routerCount<MAX_TRAY_IP_LIST)	AppendMenu(hMenu1,MF_SEPARATOR,0,0);
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((routerCount<MAX_TRAY_IP_LIST)&&(router->is_exit)&&(!routerset_contains_router(options->_ExcludeExitNodesUnion,router))&&(!options->ExitNodes || !routerset_contains_router(options->ExitNodes,router)) && (router->is_running) && (router->is_valid) && (!router->is_bad_exit))
		{	raddr=geoip_reverse(router->addr);
			country = geoip_get_country_by_ip(raddr);
			if((country_sel==0x200)||(country_sel==(country&0xff)))
			{	tor_snprintf(raddress,100,"[%s%s] %d.%d.%d.%d (%s)",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,router->nickname);
				iplist[routerCount]=router->addr;
				AppendMenu(hMenu1,MF_STRING|((router_sel==router->addr)?MF_CHECKED:0),20200+routerCount,raddress);
				routerCount++;
			}
		}
	});
	tor_free(raddress);
}

extern smartlist_t *entry_guards;
void add_favorite_entries_to_menu(HMENU hMenu1)
{	or_options_t *options=get_options();
	int routerCount=0;
	int country;
	if(!routerlist)	return;
	char *raddress=tor_malloc(100);
	uint32_t raddr;
	int i=0;
	if(options->EntryNodes)
	{	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
		{	if((routerCount<MAX_TRAY_IP_LIST)&&(router->is_possible_guard)&&(!routerset_contains_router(options->ExcludeNodes,router))&&routerset_contains_router(options->EntryNodes,router))
			{	raddr=geoip_reverse(router->addr);
				country = geoip_get_country_by_ip(raddr);
				tor_snprintf(raddress,100,"[%s%s] %d.%d.%d.%d (%s)",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,router->nickname);
				iplist[routerCount]=i+1024;
				AppendMenu(hMenu1,MF_STRING,20100+routerCount,raddress);
				routerCount++;
			}
			i++;
		});
	}
	if(routerCount && entry_guards)	AppendMenu(hMenu1,MF_SEPARATOR,0,0);
	tor_free(raddress);
}

uint32_t get_menu_selection(int sel)
{	if(sel>MAX_TRAY_IP_LIST) sel=0;
	return iplist[sel];
}

char *find_router_by_ip(uint32_t addr)
{	if(!routerlist)	return NULL;
	char *retd,*ret1,*ret2;int i;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((router->is_exit)&&(addr==router->addr))
		{	retd=tor_malloc(DIGEST_LEN*2+2);
			ret2=retd;ret1=router->cache_info.identity_digest;
			for(i=0;i<DIGEST_LEN;i++)
			{	*ret2=(*ret1&0xf0)>>4;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
				*ret2=*ret1++&0x0f;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
			}
			*ret2=0;
			return retd;
		}
	});
	return NULL;
}

routerinfo_t *get_router_by_ip(uint32_t addr)
{	if(!routerlist)	return NULL;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((router->is_exit)&&(addr==router->addr))
			return router;
	});
	return NULL;
}

char *find_router_by_index(int idx)
{	if(!routerlist)	return NULL;
	char *retd,*ret1,*ret2;int i;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if(router->router_id==(unsigned int)idx)
		{	retd=tor_malloc(DIGEST_LEN*2+2);
			ret2=retd;ret1=router->cache_info.identity_digest;
			for(i=0;i<DIGEST_LEN;i++)
			{	*ret2=(*ret1&0xf0)>>4;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
				*ret2=*ret1++&0x0f;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
			}
			*ret2=0;
			return retd;
		}
	});
	return NULL;
}

routerinfo_t *get_router_by_index(int idx)
{	if(!routerlist)	return NULL;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if(router->router_id==(unsigned int)idx)
			return router;
	});
	return NULL;
}

uint32_t routerlist_reindex(void)
{	uint32_t i=1024;
	if(!routerlist) return i;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	router->router_id=i++;
	});
	return i;
}

int get_random_router_index(int selType,int last_country_sel)
{	if(!routerlist)	return -1;
	uint32_t raddr;
	int i=0,j=0;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((selType==SELECT_EXIT&&router->is_exit)||(selType==SELECT_ENTRY&&router->is_possible_guard)||(selType==SELECT_ANY))
		{	raddr=geoip_reverse(router->addr);
			if((last_country_sel==0x200)||(last_country_sel==(geoip_get_country_by_ip(raddr)&0xff)))
				j++;
		}
		i++;
	});
	if(!j) return -1;
	j=crypto_rand_int(j);
	i=0;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((selType==SELECT_EXIT&&router->is_exit)||(selType==SELECT_ENTRY&&router->is_possible_guard)||(selType==SELECT_ANY))
		{	raddr=geoip_reverse(router->addr);
			if((last_country_sel==0x200)||(last_country_sel==(geoip_get_country_by_ip(raddr)&0xff)))
			{	if(j==0) return router->router_id;
				j--;
			}
		}
		i++;
	});
	return -1;
}


char *find_router_by_ip_port(uint32_t addr,int port)
{	if(!routerlist)	return NULL;
	char *retd,*ret1,*ret2;int i;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((addr==router->addr)&&((port==router->or_port)||(port==router->dir_port)))
		{	retd=tor_malloc(DIGEST_LEN*2+2);
			ret2=retd;ret1=router->cache_info.identity_digest;
			for(i=0;i<DIGEST_LEN;i++)
			{	*ret2=(*ret1&0xf0)>>4;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
				*ret2=*ret1++&0x0f;
				*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
			}
			*ret2=0;
			return retd;
		}
	});
	return NULL;
}

routerinfo_t *find_routerinfo_by_ip_port(uint32_t addr,int port)
{	if(!routerlist)	return NULL;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if((addr==router->addr)&&((port==router->or_port)||(port==router->dir_port)))
			return router;
	});
	return NULL;
}

BOOL is_selected_router(uint32_t addr,uint32_t router_id,DWORD exclKey)
{	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_AVOID_GEOIP_BANS)
		if(geoip_get_country_by_ip(geoip_reverse(addr))>0xff)
			return 0;
	if(router_id_sel) return (router_id_sel==router_id)?((exclKey&0xfffffffe)==0):((exclKey&0xfffffffe)!=0);
	else if(router_sel) return (router_sel==addr)?((exclKey&0xfffffffe)==0):((exclKey&0xfffffffe)!=0);
	else if(country_sel==0x200)	return 1;
	else if((geoip_get_country_by_ip(geoip_reverse(addr))&0xff)==country_sel)	return 1;
	return 0;
}

void routerlist_refresh_iplist(void)
{
	if(routerlist)
	{	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
		{	dlgBypassBlacklists_getLongevity(router);
		});
	}
}

void getRandomExitNode(unsigned char scope_id,unsigned char circuit_pos,char *country,uint32_t ip_range_low,uint32_t ip_range_high,uint32_t bandwidth,char *router_digest,char *reply)
{	(void) scope_id;
	(void) circuit_pos;
	*reply++=5;
	if(routerlist)
	{	int rcountry=geoip_get_country(country);
		int num_routers=0;
		char *ret1,*ret2;int i;
		uint32_t raddr;
		ip_range_low=geoip_reverse(ip_range_low);
		ip_range_high=geoip_reverse(ip_range_high);
		SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
		{	if((router->is_exit)&&(router->bandwidthrate>=bandwidth))
			{	raddr=router->addr;
				if(((rcountry==-1)||(rcountry==(geoip_get_country_by_ip(raddr)&0xff)))&&(raddr>=ip_range_low)&&(raddr<=ip_range_high))
				{	num_routers++;
				}
			}
		});
		if(num_routers)
		{	num_routers=crypto_rand_int(num_routers);
			SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
			{	if((router->is_exit)&&(router->bandwidthrate>=bandwidth))
				{	raddr=router->addr;
					if(((rcountry==-1)||(rcountry==(geoip_get_country_by_ip(raddr)&0xff)))&&(raddr>=ip_range_low)&&(raddr<=ip_range_high))
					{	if(num_routers) num_routers--;
						else
						{	raddr=geoip_reverse(router->addr);
							if(router_digest)
							{	ret2=router_digest;ret1=router->cache_info.identity_digest;
								for(i=0;i<DIGEST_LEN;i++)
								{	*ret2=(*ret1&0xf0)>>4;
									*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
									*ret2=*ret1++&0x0f;
									*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
								}
								*ret2=0;
							}
							*reply++=0;		//success
							*reply++=0xff;
							*reply++=(char)get_options()->CircuitPathLength;
							ret1=(char*)geoip_get_country_name(geoip_get_country_by_ip(raddr)&0xff);
							if(ret1)
							{	*reply++=*ret1++;*reply++=*ret1;
							}
							else
							{	*reply++='?';*reply++='?';
							}
							ret1=(char*)&raddr;
							*reply++=*ret1++;*reply++=*ret1++;*reply++=*ret1++;*reply++=*ret1;
							ret1=(char*)&router->bandwidthrate;
							*reply++=*ret1++;*reply++=*ret1++;*reply++=*ret1++;*reply++=*ret1;
							return;
						}
					}
				}
			});
		}
	}
	if(router_digest)
		*router_digest=0;
	*reply++=0xff;	//fail
	*reply++=0xff;
	*reply++=(char)get_options()->CircuitPathLength;
	*reply++=0;*reply++=0;	//country
	*reply++=0xff;*reply++=0xff;*reply++=0xff;*reply++=0xff;	//ip
	*reply++=0;*reply++=0;*reply++=0;*reply++=0;			//bandwidth
	return;
}

#define EXIT_SELECT_USE_IP_RANGE 1
#define EXIT_SELECT_USE_BANDWIDTH 2
#define EXIT_SELECT_USE_COUNTRY 4
#define EXIT_SELECT_SET_CONNECTION 8
#define EXIT_SELECT_GET_NICKNAME 16
edge_connection_t *find_connection_by_id(DWORD connection_id);

DWORD __stdcall plugin_choose_exit(DWORD flags,DWORD after,DWORD ip_range_low,DWORD ip_range_high,unsigned long bandwidth_rate_min,const char *country_id,DWORD connection_id,char *buffer)
{
	if(routerlist)
	{	int rcountry=-1;
		if(country_id && flags&EXIT_SELECT_USE_COUNTRY)	rcountry=geoip_get_country(country_id);
		uint32_t raddr;
		if(!(flags&EXIT_SELECT_USE_IP_RANGE))
		{	ip_range_low=0;
			ip_range_high=0xffffffff;
		}
		else
		{	ip_range_low=geoip_reverse(ip_range_low);
			ip_range_high=geoip_reverse(ip_range_high);
		}
		if(!(flags&EXIT_SELECT_USE_BANDWIDTH))	bandwidth_rate_min=0;
		SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
		{	if((router->is_exit)&&(router->bandwidthrate>=bandwidth_rate_min))
			{	raddr=router->addr;
				if(((rcountry==-1)||(rcountry==(geoip_get_country_by_ip(raddr)&0xff)))&&(raddr>=ip_range_low)&&(raddr<=ip_range_high))
				{	raddr=geoip_reverse(router->addr);
					if(after && raddr==after)	after=0;
					else if(after==0)
					{	if(flags&EXIT_SELECT_SET_CONNECTION)
						{	edge_connection_t *conn=find_connection_by_id(connection_id);
							char *s=NULL;
							if(conn)
							{	if(router->nickname && router_get_by_nickname(router->nickname,0))
								{	if(conn->chosen_exit_name)	s=conn->chosen_exit_name;
									conn->chosen_exit_name=tor_strdup(router->nickname);
									if(s)	tor_free(s);
								}
								else
								{	char *s1=tor_malloc(HEX_DIGEST_LEN+10);
									s1[0]='$';base16_encode(s1+1,HEX_DIGEST_LEN+1,router->cache_info.identity_digest,DIGEST_LEN);s1[HEX_DIGEST_LEN+1]=0;
									if(conn->chosen_exit_name)	s=conn->chosen_exit_name;
									conn->chosen_exit_name=s1;
									if(s)	tor_free(s);
								}
							}
						}
						if(flags&EXIT_SELECT_GET_NICKNAME && buffer!=NULL)
						{	if(router->nickname && router_get_by_nickname(router->nickname,0))
								tor_snprintf(buffer,100,router->nickname);
							else
							{	char *s1=tor_malloc(HEX_DIGEST_LEN+10);
								s1[0]='$';base16_encode(s1+1,HEX_DIGEST_LEN+1,router->cache_info.identity_digest,DIGEST_LEN);s1[HEX_DIGEST_LEN+1]=0;
								tor_snprintf(buffer,100,s1);
								tor_free(s1);
							}
						}
						return raddr;
					}
				}
			}
		});
	}
	return 0;
}


void fill_router_info(router_info_t *rinfo,routerinfo_t *orig_info,int index)
{	rinfo->index=index;
	rinfo->address=orig_info->address;
	rinfo->nickname=orig_info->nickname;
	memcpy(rinfo->identity_digest,orig_info->cache_info.identity_digest,DIGEST_LEN);
	rinfo->published_on=orig_info->cache_info.published_on;
	rinfo->addr=geoip_reverse(orig_info->addr);
	rinfo->or_port=orig_info->or_port;
	rinfo->dir_port=orig_info->dir_port;
	rinfo->platform=orig_info->platform;
	rinfo->bandwidthrate=orig_info->bandwidthrate;
	rinfo->bandwidthburst=orig_info->bandwidthburst;
	rinfo->bandwidthcapacity=orig_info->bandwidthcapacity;
	rinfo->exit_policy=orig_info->exit_policy;
	rinfo->uptime=orig_info->uptime;
	rinfo->declared_family=orig_info->declared_family;
	rinfo->contact_info=orig_info->contact_info;
	rinfo->is_hibernating=orig_info->is_hibernating;
	rinfo->allow_single_hop_exits=orig_info->allow_single_hop_exits;
	rinfo->is_running=orig_info->is_running;
	rinfo->is_valid=orig_info->is_valid;
	rinfo->is_fast=orig_info->is_fast;
	rinfo->is_stable=orig_info->is_stable;
	rinfo->is_possible_guard=orig_info->is_possible_guard;
	rinfo->is_exit=orig_info->is_exit;
	rinfo->is_bad_exit=orig_info->is_bad_exit;
	rinfo->is_bad_directory=orig_info->is_bad_directory;
	rinfo->wants_to_be_hs_dir=orig_info->wants_to_be_hs_dir;
	rinfo->is_hs_dir=orig_info->is_hs_dir;
	rinfo->policy_is_reject_star=orig_info->policy_is_reject_star;
}

BOOL __stdcall plugin_get_router_info(int index,DWORD router_ip,char *nickname,router_info_t *router_info)
{	uint32_t raddr;
	int i=0;
	if(router_info->cbSize != sizeof(router_info_t)) return 0;
	if(!routerlist) return 0;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if(index==0)
		{	if(router_ip)
			{	raddr=geoip_reverse(router->addr);
				if(raddr==router_ip)
				{	if(!nickname || router_get_by_nickname(nickname,0)==router)
					{	fill_router_info(router_info,router,i);
						return 1;
					}
				}
			}
			else if(nickname)
			{	if(router_get_by_nickname(nickname,0)==router)
				{	fill_router_info(router_info,router,i);
					return 1;
				}
			}
			else
			{	fill_router_info(router_info,router,i);
				return 1;
			}
		}
		else index--;
		i++;
	});
	return 0;
}

int __stdcall plugin_is_router_banned(DWORD router_ip,char *nickname)
{	uint32_t raddr;
	or_options_t *options=get_options();
	int i=-1;
	if(!routerlist || (!nickname && !router_ip)) return 0;
	if(!router_ip && nickname)
	{	routerinfo_t *router=router_get_by_nickname(nickname,0);
		if(router)
		{	if(options->_ExcludeExitNodesUnion && routerset_contains_router(options->_ExcludeExitNodesUnion,router)) return 1;
			return 0;
		}
		return -1;
	}
	else if(!router_ip) return -1;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	raddr=geoip_reverse(router->addr);
		if(raddr==router_ip)
		{	if(!nickname || router_get_by_nickname(nickname,0)==router)
			{	i=0;
				if(options->_ExcludeExitNodesUnion && routerset_contains_router(options->_ExcludeExitNodesUnion,router)) return 1;
			}
		}
	});
	return i;
}

char *get_router_digest(routerinfo_t *router)
{	char *retd,*ret1,*ret2;int i;
	retd=tor_malloc(DIGEST_LEN*2+2);
	ret2=retd;ret1=router->cache_info.identity_digest;
	for(i=0;i<DIGEST_LEN;i++)
	{	*ret2=(*ret1&0xf0)>>4;
		*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
		*ret2=*ret1++&0x0f;
		*ret2=*ret2>9?*ret2+7:*ret2;*ret2++ += 0x30;
	}
	*ret2=0;
	return retd;
}

void show_bans(void);
void add_router_to_banlist(HWND hDlg,char *router,char bantype);

#define BAN_EXIT 'X'
#define BAN_GENERAL 0

int __stdcall plugin_ban_router(DWORD router_ip,int ban_type,BOOL is_banned)
{	uint32_t raddr=geoip_reverse(router_ip);
	or_options_t *options=get_options();
	int i=0,j;
	routerset_t *r1,*r2;
	char *tmphash;
	if(!routerlist) return 0;
	SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
	{	if(raddr==router->addr)
		{	j = ban_type?(options->ExcludeExitNodes && routerset_contains_router(options->ExcludeExitNodes,router)):(options->ExcludeNodes && routerset_contains_router(options->ExcludeNodes,router));
			if(j)
			{	if(!is_banned)
				{	if(ban_type)	r1 = options->ExcludeExitNodes;
					else	r1 = options->ExcludeNodes;
					if(r1)
					{	SMARTLIST_FOREACH(r1->list,routerinfo_t *,r,{
							if(router==r)	SMARTLIST_DEL_CURRENT(r1->list, r);
						});
					}
					if(options->ExcludeExitNodes || options->ExcludeNodes)
					{	r2 = options->_ExcludeExitNodesUnion;
						r1 = routerset_new();
						routerset_union(r1,options->ExcludeExitNodes);
						routerset_union(r1,options->ExcludeNodes);
						options->_ExcludeExitNodesUnion = r1;
						if(r2)	routerset_free(r2);
					}
					show_bans();
					i++;
				}
			}
			else
			{	if(is_banned)
				{	entry_guard_t *entry = is_an_entry_guard(router->cache_info.identity_digest);
					if (entry)
					{	entry->made_contact=0;
						entry_guard_register_connect_status(router->cache_info.identity_digest,0,0,get_time(NULL));
					}
					tmphash=get_router_digest(router);
					add_router_to_banlist(0,tmphash,ban_type);
					tor_free(tmphash);
					i++;
				}
			}
		}
	});
	return i;
}
