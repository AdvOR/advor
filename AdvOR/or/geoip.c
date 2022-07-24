/* Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file geoip.c
 * \brief Functions related to maintaining an IP-to-country database and to
 *    summarizing client connections by country.
 */

#define GEOIP_PRIVATE
#include "or.h"
#include "ht.h"
#include "config.h"
#include "control.h"
#include "dnsserv.h"
#include "geoip.h"
#include "routerlist.h"

/** An entry from the GeoIP file: maps an IP range to a country. */
typedef struct geoip_entry_t {
  uint32_t ip_low; /**< The lowest IP in the range, in host order */
  uint32_t ip_high; /**< The highest IP in the range, in host order */
  intptr_t country; /**< An index into geoip_countries */
} geoip_entry_t;

/** A per-country record for GeoIP request history. */
typedef struct geoip_country_t {
  char countrycode[3];
  uint32_t n_v2_ns_requests;
  uint32_t n_v3_ns_requests;
} geoip_country_t;

/** A list of geoip_country_t */
static smartlist_t *geoip_countries = NULL;


/** Return 1 if we should collect geoip stats on bridge users, and
 * include them in our extrainfo descriptor. Else return 0. */
int
should_record_bridge_info(or_options_t *options)
{
  return options->BridgeRelay && options->BridgeRecordUsageByCountry;
}


/** Entry in a map from IP address to the last time we've seen an incoming
 * connection from that IP address. Used by bridges only, to track which
 * countries have them blocked. */
typedef struct clientmap_entry_t {
  HT_ENTRY(clientmap_entry_t) node;
  uint32_t ipaddr;
  /** Time when we last saw this IP address, in MINUTES since the epoch.
   *
   * (This will run out of space around 4011 CE.  If Tor is still in use around
   * 4000 CE, please remember to add more bits to last_seen_in_minutes.) */
  unsigned int last_seen_in_minutes:30;
  unsigned int action:2;
} clientmap_entry_t;

/** Largest allowable value for last_seen_in_minutes.  (It's a 30-bit field,
 * so it can hold up to (1u<<30)-1, or 0x3fffffffu.
 */
#define MAX_LAST_SEEN_IN_MINUTES 0X3FFFFFFFu

/** Map from client IP address to last time seen. */
static HT_HEAD(clientmap, clientmap_entry_t) client_history =
     HT_INITIALIZER();

/** Hashtable helper: compute a hash of a clientmap_entry_t. */
static INLINE unsigned
clientmap_entry_hash(const clientmap_entry_t *a)
{
  return ht_improve_hash((unsigned) a->ipaddr);
}
/** Hashtable helper: compare two clientmap_entry_t values for equality. */
static INLINE int
clientmap_entries_eq(const clientmap_entry_t *a, const clientmap_entry_t *b)
{
  return a->ipaddr == b->ipaddr && a->action == b->action;
}

HT_PROTOTYPE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
             clientmap_entries_eq);
HT_GENERATE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
            clientmap_entries_eq, 0.6);

/** Clear history of connecting clients used by entry and bridge stats. */
static void client_history_clear(void)
{	clientmap_entry_t **ent, **next, *this;
	for(ent = HT_START(clientmap, &client_history); ent != NULL;ent = next)
	{	if((*ent)->action == GEOIP_CLIENT_CONNECT)
		{	this = *ent;
			next = HT_NEXT_RMV(clientmap, &client_history, ent);
			tor_free(this);
		}
		else	next = HT_NEXT(clientmap, &client_history, ent);
	}
}


#define REQUEST_SHARE_INTERVAL (15 * 60)		/** How often do we update our estimate which share of v2 and v3 directory requests is sent to us? We could as well trigger updates of shares from network status updates, but that means adding a lot of calls into code that is independent from geoip stats (and keeping them up-to-date). We are perfectly fine with an approximation of 15-minute granularity. */

static time_t last_time_determined_shares = 0;		/** When did we last determine which share of v2 and v3 directory requests is sent to us? */
static double v2_share_times_seconds;			/** Sum of products of v2 shares times the number of seconds for which we consider these shares as valid. */
static double v3_share_times_seconds;			/** Sum of products of v3 shares times the number of seconds for which we consider these shares as valid. */
static int share_seconds;				/** Number of seconds we are determining v2 and v3 shares. */

/** Try to determine which fraction of v2 and v3 directory requests aimed at caches will be sent to us at time <b>now</b> and store that value in order to take a mean value later on. */
static void geoip_determine_shares(time_t now)
{	double v2_share = 0.0, v3_share = 0.0;
	if(router_get_my_share_of_directory_requests(&v2_share, &v3_share) < 0)
		return;
	if(last_time_determined_shares)
	{	v2_share_times_seconds += v2_share * ((double) (now - last_time_determined_shares));
		v3_share_times_seconds += v3_share * ((double) (now - last_time_determined_shares));
		share_seconds += (int)(now - last_time_determined_shares);
	}
	last_time_determined_shares = now;
}

/** Calculate which fraction of v2 and v3 directory requests aimed at caches have been sent to us since the last call of this function up to time <b>now</b>. Set *<b>v2_share_out</b> and *<b>v3_share_out</b> to the fractions of v2 and v3 protocol shares we expect to have seen. Reset counters afterwards. Return 0 on success, -1 on failure (e.g. when zero seconds have passed since the last call).*/
static int geoip_get_mean_shares(time_t now,double *v2_share_out,double *v3_share_out)
{	geoip_determine_shares(now);
	if(!share_seconds)	return -1;
	*v2_share_out = v2_share_times_seconds / ((double) share_seconds);
	*v3_share_out = v3_share_times_seconds / ((double) share_seconds);
	v2_share_times_seconds = v3_share_times_seconds = 0.0;
	share_seconds = 0;
	return 0;
}

/** Note that we've seen a client connect from the IP <b>addr</b> (host order)
 * at time <b>now</b>. Ignored by all but bridges. */
void
geoip_note_client_seen(geoip_client_action_t action,
                       uint32_t addr, time_t now)
{
  or_options_t *options = get_options();
  clientmap_entry_t lookup, *ent;
  if (action == GEOIP_CLIENT_CONNECT) {
    /* Only remember statistics as entry guard or as bridge. */
    if (!options->EntryStatistics &&
        (!(options->BridgeRelay && options->BridgeRecordUsageByCountry)))
      return;
  } else {
    if (options->BridgeRelay || options->BridgeAuthoritativeDir ||
        !options->DirReqStatistics)
      return;
  }

  lookup.ipaddr = addr;
  lookup.action = (int)action;
  ent = HT_FIND(clientmap, &client_history, &lookup);
  if (! ent) {
    ent = tor_malloc_zero(sizeof(clientmap_entry_t));
    ent->ipaddr = addr;
    ent->action = (int)action;
    HT_INSERT(clientmap, &client_history, ent);
  }
  if (now / 60 <= (int)MAX_LAST_SEEN_IN_MINUTES && now >= 0)
    ent->last_seen_in_minutes = (unsigned)(now/60);
  else
    ent->last_seen_in_minutes = 0;

  if (action == GEOIP_CLIENT_NETWORKSTATUS ||
      action == GEOIP_CLIENT_NETWORKSTATUS_V2) {
    int country_idx = geoip_get_country_by_ip(addr)&0xff;
    if (country_idx < 0)
      country_idx = 0; /** unresolved requests are stored at index 0. */
    if (country_idx >= 0 && country_idx < smartlist_len(geoip_countries)) {
      geoip_country_t *country = smartlist_get(geoip_countries, country_idx);
      if (action == GEOIP_CLIENT_NETWORKSTATUS)
        ++country->n_v3_ns_requests;
      else
        ++country->n_v2_ns_requests;
    }

    /* Periodically determine share of requests that we should see */
    if (last_time_determined_shares + REQUEST_SHARE_INTERVAL < now)
      geoip_determine_shares(now);
  }
}

/** HT_FOREACH helper: remove a clientmap_entry_t from the hashtable if it's
 * older than a certain time. */
static int
_remove_old_client_helper(struct clientmap_entry_t *ent, void *_cutoff)
{
  time_t cutoff = *(time_t*)_cutoff / 60;
  if (ent->last_seen_in_minutes < cutoff) {
    tor_free(ent);
    return 1;
  } else {
    return 0;
  }
}

/** Forget about all clients that haven't connected since <b>cutoff</b>.
 * If <b>cutoff</b> is in the future, clients won't be added to the history
 * until this time is reached. This is useful to prevent relays that switch
 * to bridges from reporting unbelievable numbers of clients. */
void
geoip_remove_old_clients(time_t cutoff)
{
  clientmap_HT_FOREACH_FN(&client_history,
                          _remove_old_client_helper,
                          &cutoff);
}

static uint32_t ns_v2_responses[GEOIP_NS_RESPONSE_NUM];		/** How many responses are we giving to clients requesting v2 network statuses? */
static uint32_t ns_v3_responses[GEOIP_NS_RESPONSE_NUM];		/** How many responses are we giving to clients requesting v3 network statuses? */

/** Note that we've rejected a client's request for a v2 or v3 network status, encoded in <b>action</b> for reason <b>reason</b> at time <b>now</b>. */
void geoip_note_ns_response(geoip_client_action_t action,geoip_ns_response_t response)
{	static int arrays_initialized = 0;
	if(!get_options()->DirReqStatistics)	return;
	if(!arrays_initialized)
	{	memset(ns_v2_responses, 0, sizeof(ns_v2_responses));
		memset(ns_v3_responses, 0, sizeof(ns_v3_responses));
		arrays_initialized = 1;
	}
	tor_assert(action == GEOIP_CLIENT_NETWORKSTATUS || action == GEOIP_CLIENT_NETWORKSTATUS_V2);
	tor_assert(response < GEOIP_NS_RESPONSE_NUM);
	if(action == GEOIP_CLIENT_NETWORKSTATUS)	ns_v3_responses[response]++;
	else						ns_v2_responses[response]++;
}

/** Do not mention any country from which fewer than this number of IPs have
 * connected.  This conceivably avoids reporting information that could
 * deanonymize users, though analysis is lacking. */
#define MIN_IPS_TO_NOTE_COUNTRY 1
/** Do not report any geoip data at all if we have fewer than this number of
 * IPs to report about. */
#define MIN_IPS_TO_NOTE_ANYTHING 1
/** When reporting geoip data about countries, round up to the nearest
 * multiple of this value. */
#define IP_GRANULARITY 8

/** Helper type: used to sort per-country totals by value. */
typedef struct c_hist_t {
  char country[3]; /**< Two-letter country code. */
  unsigned total; /**< Total IP addresses seen in this country. */
} c_hist_t;

/** Sorting helper: return -1, 1, or 0 based on comparison of two
 * geoip_entry_t.  Sort in descending order of total, and then by country
 * code. */
static int
_c_hist_compare(const void **_a, const void **_b)
{
  const c_hist_t *a = *_a, *b = *_b;
  if (a->total > b->total)
    return -1;
  else if (a->total < b->total)
    return 1;
  else
    return strcmp(a->country, b->country);
}

#define DIRREQ_TIMEOUT (10*60)		/** When there are incomplete directory requests at the end of a 24-hour period, consider those requests running for longer than this timeout as failed, the others as still running. */

/** Entry in a map from either conn->global_identifier for direct requests or a unique circuit identifier for tunneled requests to request time, response size, and completion time of a network status request. Used to measure download times of requests to derive average client bandwidths. */
typedef struct dirreq_map_entry_t
{	HT_ENTRY(dirreq_map_entry_t) node;
	uint64_t dirreq_id;			/** Unique identifier for this network status request; this is either the conn->global_identifier of the dir conn (direct request) or a new locally unique identifier of a circuit (tunneled request). This ID is only unique among other direct or tunneled requests, respectively. */
	unsigned int state:3;			/**< State of this directory request. */
	unsigned int type:1;			/**< Is this a direct or a tunneled request? */
	unsigned int completed:1;		/**< Is this request complete? */
	unsigned int action:2;			/**< Is this a v2 or v3 request? */
	struct timeval request_time;		/** When did we receive the request and started sending the response? */
	size_t response_size;			/**< What is the size of the response in bytes? */
	struct timeval completion_time;		/**< When did the request succeed? */
} dirreq_map_entry_t;

/** Map of all directory requests asking for v2 or v3 network statuses in the current geoip-stats interval. Values are of type *<b>dirreq_map_entry_t</b>. */
static HT_HEAD(dirreqmap, dirreq_map_entry_t) dirreq_map = HT_INITIALIZER();

static int dirreq_map_ent_eq(const dirreq_map_entry_t *a,const dirreq_map_entry_t *b)
{	return a->dirreq_id == b->dirreq_id && a->type == b->type;
}

static unsigned dirreq_map_ent_hash(const dirreq_map_entry_t *entry)
{	unsigned u = (unsigned) entry->dirreq_id;
	u += entry->type << 20;
	return u;
}

HT_PROTOTYPE(dirreqmap, dirreq_map_entry_t, node, dirreq_map_ent_hash,dirreq_map_ent_eq);
HT_GENERATE(dirreqmap, dirreq_map_entry_t, node, dirreq_map_ent_hash,dirreq_map_ent_eq, 0.6);

/** Helper: Put <b>entry</b> into map of directory requests using <b>type</b> and <b>dirreq_id</b> as key parts. If there is already an entry for that key, print out a BUG warning and return. */
static void _dirreq_map_put(dirreq_map_entry_t *entry, dirreq_type_t type,uint64_t dirreq_id)
{	dirreq_map_entry_t *old_ent;
	tor_assert(entry->type == type);
	tor_assert(entry->dirreq_id == dirreq_id);
	/* XXXX we could switch this to HT_INSERT some time, since it seems that this bug doesn't happen. But since this function doesn't seem to be critical-path, it's sane to leave it alone. */
	old_ent = HT_REPLACE(dirreqmap, &dirreq_map, entry);
	if(old_ent && old_ent != entry)
	{	log_warn(LD_BUG,get_lang_str(LANG_LOG_GEOIP_DUPLICATE_REQUEST_ID));
    return;
  }
}

/** Helper: Look up and return an entry in the map of directory requests using <b>type</b> and <b>dirreq_id</b> as key parts. If there is no such entry, return NULL. */
static dirreq_map_entry_t *_dirreq_map_get(dirreq_type_t type, uint64_t dirreq_id)
{	dirreq_map_entry_t lookup;
	lookup.type = type;
	lookup.dirreq_id = dirreq_id;
	return HT_FIND(dirreqmap, &dirreq_map, &lookup);
}

/** Note that an either direct or tunneled (see <b>type</b>) directory request for a network status with unique ID <b>dirreq_id</b> of size <b>response_size</b> and action <b>action</b> (either v2 or v3) has started. */
void geoip_start_dirreq(uint64_t dirreq_id, size_t response_size,geoip_client_action_t action, dirreq_type_t type)
{	dirreq_map_entry_t *ent;
	if(!get_options()->DirReqStatistics)	return;
	ent = tor_malloc_zero(sizeof(dirreq_map_entry_t));
	ent->dirreq_id = dirreq_id;
	tor_gettimeofday(&ent->request_time);
	ent->response_size = response_size;
	ent->action = action;
	ent->type = type;
	_dirreq_map_put(ent, type, dirreq_id);
}

/** Change the state of the either direct or tunneled (see <b>type</b>) directory request with <b>dirreq_id</b> to <b>new_state</b> and possibly mark it as completed. If no entry can be found for the given key parts (e.g., if this is a directory request that we are not measuring, or one that was started in the previous measurement period), or if the state cannot be advanced to <b>new_state</b>, do nothing. */
void geoip_change_dirreq_state(uint64_t dirreq_id, dirreq_type_t type,dirreq_state_t new_state)
{	dirreq_map_entry_t *ent;
	if(!get_options()->DirReqStatistics)			return;
	ent = _dirreq_map_get(type, dirreq_id);
	if(!ent)						return;
	if(new_state == DIRREQ_IS_FOR_NETWORK_STATUS)		return;
	if(new_state - 1 != ent->state)				return;
	ent->state = new_state;
	if((type == DIRREQ_DIRECT && new_state == DIRREQ_FLUSHING_DIR_CONN_FINISHED) || (type == DIRREQ_TUNNELED && new_state == DIRREQ_OR_CONN_BUFFER_FLUSHED))
	{	tor_gettimeofday(&ent->completion_time);
		ent->completed = 1;
	}
}

#define DIR_REQ_GRANULARITY 4
#define MIN_DIR_REQ_RESPONSES 16

/** Return a newly allocated comma-separated string containing statistics on network status downloads. The string contains the number of completed requests, timeouts, and still running requests as well as the download times by deciles and quartiles. Return NULL if we have not observed requests for long enough. */
static char *geoip_get_dirreq_history(geoip_client_action_t action,dirreq_type_t type)
{	char *result = NULL;
	smartlist_t *dirreq_completed = NULL;
	uint32_t complete = 0, timeouts = 0, running = 0;
	int bufsize = 1024, written;
	dirreq_map_entry_t **ptr, **next, *ent;
	struct timeval now;
	tor_gettimeofday(&now);
	if(action != GEOIP_CLIENT_NETWORKSTATUS && action != GEOIP_CLIENT_NETWORKSTATUS_V2)
		return NULL;
	dirreq_completed = smartlist_create();
	for(ptr = HT_START(dirreqmap, &dirreq_map); ptr; ptr = next)
	{	ent = *ptr;
		if(ent->action != action || ent->type != type)
		{	next = HT_NEXT(dirreqmap, &dirreq_map, ptr);
			continue;
		}
		else
		{	if(ent->completed)
			{	smartlist_add(dirreq_completed, ent);
				complete++;
				next = HT_NEXT_RMV(dirreqmap, &dirreq_map, ptr);
			}
			else
			{	if(tv_mdiff(&ent->request_time, &now) / 1000 > DIRREQ_TIMEOUT)
					timeouts++;
				else	running++;
				next = HT_NEXT_RMV(dirreqmap, &dirreq_map, ptr);
				tor_free(ent);
			}
		}
	}
	complete = round_uint32_to_next_multiple_of(complete,DIR_REQ_GRANULARITY);
	timeouts = round_uint32_to_next_multiple_of(timeouts,DIR_REQ_GRANULARITY);
	running = round_uint32_to_next_multiple_of(running,DIR_REQ_GRANULARITY);
	result = tor_malloc_zero(bufsize);
	written = tor_snprintf(result, bufsize, "complete=%u,timeout=%u,running=%u", complete, timeouts, running);
	if(written < 0)
		tor_free(result);
	else
	{	if(complete >= MIN_DIR_REQ_RESPONSES)
		{	uint32_t *dltimes;
			/* We may have rounded 'completed' up.  Here we want to use the real value. */
			complete = smartlist_len(dirreq_completed);
			dltimes = tor_malloc_zero(sizeof(uint32_t) * complete);
			SMARTLIST_FOREACH_BEGIN(dirreq_completed, dirreq_map_entry_t *, ent2)
			{	uint32_t bytes_per_second;
				uint32_t time_diff = (uint32_t) tv_mdiff(&ent2->request_time,&ent2->completion_time);
				if(time_diff == 0)	time_diff = 1;	/* Avoid DIV/0; "instant" answers are impossible by law of nature or something, but a milisecond is a bit greater than "instantly" */
				bytes_per_second = (uint32_t)(1000 * ent2->response_size / time_diff);
				dltimes[ent2_sl_idx] = bytes_per_second;
			} SMARTLIST_FOREACH_END(ent2);
			median_uint32(dltimes, complete); /* sorts as a side effect. */
			written = tor_snprintf(result + written, bufsize - written,",min=%u,d1=%u,d2=%u,q1=%u,d3=%u,d4=%u,md=%u,d6=%u,d7=%u,q3=%u,d8=%u,d9=%u,max=%u",dltimes[0],dltimes[1*complete/10-1],dltimes[2*complete/10-1],dltimes[1*complete/4-1],dltimes[3*complete/10-1],dltimes[4*complete/10-1],dltimes[5*complete/10-1],dltimes[6*complete/10-1],dltimes[7*complete/10-1],dltimes[3*complete/4-1],dltimes[8*complete/10-1],dltimes[9*complete/10-1],dltimes[complete-1]);
			if(written<0)	tor_free(result);
			tor_free(dltimes);
		}
	}
	SMARTLIST_FOREACH(dirreq_completed, dirreq_map_entry_t *, ent2,tor_free(ent2));
	smartlist_free(dirreq_completed);
	return result;
}

/** Return a newly allocated comma-separated string containing entries for all
 * the countries from which we've seen enough clients connect. The entry
 * format is cc=num where num is the number of IPs we've seen connecting from
 * that country, and cc is a lowercased country code. Returns NULL if we don't
 * want to export geoip data yet. */
char *geoip_get_client_history(geoip_client_action_t action)
{	char *result = NULL;
	unsigned granularity = IP_GRANULARITY;
	smartlist_t *chunks = NULL;
	smartlist_t *entries = NULL;
	int n_countries = geoip_get_n_countries();
	int i;
	clientmap_entry_t **ent;
	unsigned *counts = NULL;
	unsigned total = 0;
	counts = tor_malloc_zero(sizeof(unsigned)*n_countries);
	HT_FOREACH(ent, clientmap, &client_history)
	{	int country;
		if((*ent)->action != (int)action)
			continue;
		country = geoip_get_country_by_ip((*ent)->ipaddr)&0xff;
		if(country < 0)
			country = 0; /** unresolved requests are stored at index 0. */
		tor_assert(0 <= country && country < n_countries);
		++counts[country];
		++total;
	}
	/* Don't record anything if we haven't seen enough IPs. */
	if(total >= MIN_IPS_TO_NOTE_ANYTHING)
	{	/* Make a list of c_hist_t */
		entries = smartlist_create();
		for(i = 0; i < n_countries; ++i)
		{	unsigned c = counts[i];
			const char *countrycode;
			c_hist_t *ent2;
			/* Only report a country if it has a minimum number of IPs. */
			if(c >= MIN_IPS_TO_NOTE_COUNTRY)
			{	c = round_to_next_multiple_of(c, granularity);
				countrycode = geoip_get_country_name(i);
				ent2 = tor_malloc(sizeof(c_hist_t));
				strlcpy(ent2->country, countrycode, sizeof(ent2->country));
				ent2->total = c;
				smartlist_add(entries, ent2);
			}
		}
		/* Sort entries. Note that we must do this _AFTER_ rounding, or else the sort order could leak info. */
		smartlist_sort(entries, _c_hist_compare);
		/* Build the result. */
		chunks = smartlist_create();
		SMARTLIST_FOREACH(entries, c_hist_t *, ch,
		{	unsigned char *buf=NULL;
			tor_asprintf(&buf, "%s=%u", ch->country, ch->total);
			smartlist_add(chunks, buf);
		});
		result = smartlist_join_strings(chunks, ",", 0, NULL);
		SMARTLIST_FOREACH(entries, c_hist_t *, c, tor_free(c));
		smartlist_free(entries);
		SMARTLIST_FOREACH(chunks, char *, c, tor_free(c));
		smartlist_free(chunks);
	}
	tor_free(counts);
	return result;
}

/** Return a newly allocated string holding the per-country request history
 * for <b>action</b> in a format suitable for an extra-info document, or NULL
 * on failure. */
char *
geoip_get_request_history(geoip_client_action_t action)
{
  smartlist_t *entries, *strings;
  char *result;
  unsigned granularity = IP_GRANULARITY;

  if (action != GEOIP_CLIENT_NETWORKSTATUS &&
      action != GEOIP_CLIENT_NETWORKSTATUS_V2)
    return NULL;
  if (!geoip_countries)
    return NULL;

  entries = smartlist_create();
  SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c, {
      uint32_t tot = 0;
      c_hist_t *ent;
      tot = (action == GEOIP_CLIENT_NETWORKSTATUS) ?
            c->n_v3_ns_requests : c->n_v2_ns_requests;
      if (!tot)
        continue;
      ent = tor_malloc_zero(sizeof(c_hist_t));
      strlcpy(ent->country, c->countrycode, sizeof(ent->country));
      ent->total = round_to_next_multiple_of(tot, granularity);
      smartlist_add(entries, ent);
  });
  smartlist_sort(entries, _c_hist_compare);

  strings = smartlist_create();
  SMARTLIST_FOREACH(entries, c_hist_t *, ent, {
      unsigned char *buf = NULL;
      tor_asprintf(&buf, "%s=%u", ent->country, ent->total);
      smartlist_add(strings, buf);
    });
  result = smartlist_join_strings(strings, ",", 0, NULL);
  SMARTLIST_FOREACH(strings, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(entries, c_hist_t *, ent, tor_free(ent));
  smartlist_free(strings);
  smartlist_free(entries);
  return result;
}

static time_t start_of_dirreq_stats_interval;		/** Start time of directory request stats or 0 if we're not collecting directory request statistics. */

/** Initialize directory request stats. */
void geoip_dirreq_stats_init(time_t now)
{	start_of_dirreq_stats_interval = now;
}

/** Stop collecting directory request stats in a way that we can re-start doing so in geoip_dirreq_stats_init(). */
void geoip_dirreq_stats_term(void)
{	SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c,
	{	c->n_v2_ns_requests = c->n_v3_ns_requests = 0;
	});
	{	clientmap_entry_t **ent, **next, *this;
		for(ent = HT_START(clientmap, &client_history); ent != NULL;ent = next)
		{	if((*ent)->action == GEOIP_CLIENT_NETWORKSTATUS || (*ent)->action == GEOIP_CLIENT_NETWORKSTATUS_V2)
			{	this = *ent;
				next = HT_NEXT_RMV(clientmap, &client_history, ent);
				tor_free(this);
			}
			else	next = HT_NEXT(clientmap, &client_history, ent);
		}
	}
	v2_share_times_seconds = v3_share_times_seconds = 0.0;
	last_time_determined_shares = 0;
	share_seconds = 0;
	memset(ns_v2_responses, 0, sizeof(ns_v2_responses));
	memset(ns_v3_responses, 0, sizeof(ns_v3_responses));
	dirreq_map_entry_t **ent, **next, *this;
	for(ent = HT_START(dirreqmap, &dirreq_map); ent != NULL; ent = next)
	{	this = *ent;
		next = HT_NEXT_RMV(dirreqmap, &dirreq_map, ent);
		tor_free(this);
	}
	start_of_dirreq_stats_interval = 0;
}

#define RESPONSE_GRANULARITY 8
/** Write dirreq statistics to $DATADIR/stats/dirreq-stats and return when we would next want to write. */
time_t geoip_dirreq_stats_write(time_t now)
{	char *data_v2 = NULL, *data_v3 = NULL;
	char written[ISO_TIME_LEN+1];
	double v2_share = 0.0, v3_share = 0.0;
	open_file_t *open_file = NULL;
	int i;
	if(!start_of_dirreq_stats_interval)	return 0; /* Not initialized. */
	if(start_of_dirreq_stats_interval + WRITE_STATS_INTERVAL <= now)
	{	/* Discard all items in the client history that are too old. */
		geoip_remove_old_clients(start_of_dirreq_stats_interval);
		char *filename = get_datadir_fname(DATADIR_GEOIP_DIRREQ_STATS);
		data_v2 = geoip_get_client_history(GEOIP_CLIENT_NETWORKSTATUS_V2);
		data_v3 = geoip_get_client_history(GEOIP_CLIENT_NETWORKSTATUS);
		format_iso_time(written, now);
		if(start_writing_to_file(filename,&open_file))
		{	unsigned char *str=NULL;
			tor_asprintf(&str,"dirreq-stats-end %s (%d s)\ndirreq-v3-ips %s\ndirreq-v2-ips %s\n",written,(unsigned) (now - start_of_dirreq_stats_interval),data_v3 ? data_v3 : "", data_v2 ? data_v2 : "");
			write_string_to_file(open_file,(char *)str);tor_free(str);
			tor_free(data_v2);
			tor_free(data_v3);
			data_v2 = geoip_get_request_history(GEOIP_CLIENT_NETWORKSTATUS_V2);
			data_v3 = geoip_get_request_history(GEOIP_CLIENT_NETWORKSTATUS);
			tor_asprintf(&str,"dirreq-v3-reqs %s\ndirreq-v2-reqs %s\n",data_v3 ? data_v3 : "", data_v2 ? data_v2 : "");
			write_string_to_file(open_file,(char *)str);tor_free(str);
			tor_free(data_v2);
			tor_free(data_v3);
			SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c,
			{	c->n_v2_ns_requests = c->n_v3_ns_requests = 0;
			});
			for(i = 0; i < GEOIP_NS_RESPONSE_NUM; i++)
			{	ns_v2_responses[i] = round_uint32_to_next_multiple_of(ns_v2_responses[i], RESPONSE_GRANULARITY);
				ns_v3_responses[i] = round_uint32_to_next_multiple_of(ns_v3_responses[i], RESPONSE_GRANULARITY);
			}
			tor_asprintf(&str,"dirreq-v3-resp ok=%u,not-enough-sigs=%u,unavailable=%u,not-found=%u,not-modified=%u,busy=%u\ndirreq-v2-resp ok=%u,unavailable=%u,not-found=%u,not-modified=%u,busy=%u\n",ns_v3_responses[GEOIP_SUCCESS],ns_v3_responses[GEOIP_REJECT_NOT_ENOUGH_SIGS],ns_v3_responses[GEOIP_REJECT_UNAVAILABLE],ns_v3_responses[GEOIP_REJECT_NOT_FOUND],ns_v3_responses[GEOIP_REJECT_NOT_MODIFIED],ns_v3_responses[GEOIP_REJECT_BUSY],ns_v2_responses[GEOIP_SUCCESS],ns_v2_responses[GEOIP_REJECT_UNAVAILABLE],ns_v2_responses[GEOIP_REJECT_NOT_FOUND],ns_v2_responses[GEOIP_REJECT_NOT_MODIFIED],ns_v2_responses[GEOIP_REJECT_BUSY]);
			write_string_to_file(open_file,(char *)str);tor_free(str);
			memset(ns_v2_responses, 0, sizeof(ns_v2_responses));
			memset(ns_v3_responses, 0, sizeof(ns_v3_responses));
			if(!geoip_get_mean_shares(now, &v2_share, &v3_share))
			{	tor_asprintf(&str,"dirreq-v2-share %0.2lf%%\ndirreq-v3-share %0.2lf%%\n", v2_share*100,v3_share*100);
				write_string_to_file(open_file,(char *)str);tor_free(str);
			}
			data_v2 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS_V2,DIRREQ_DIRECT);
			data_v3 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS,DIRREQ_DIRECT);
			tor_asprintf(&str,"dirreq-v3-direct-dl %s\ndirreq-v2-direct-dl %s\n",data_v3 ? data_v3 : "", data_v2 ? data_v2 : "");
			write_string_to_file(open_file,(char *)str);tor_free(str);
			tor_free(data_v2);
			tor_free(data_v3);
			data_v2 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS_V2,DIRREQ_TUNNELED);
			data_v3 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS,DIRREQ_TUNNELED);
			tor_asprintf(&str,"dirreq-v3-tunneled-dl %s\ndirreq-v2-tunneled-dl %s\n",data_v3 ? data_v3 : "", data_v2 ? data_v2 : "");
			write_string_to_file(open_file,(char *)str);tor_free(str);
		}
		if(open_file)	finish_writing_to_file(open_file,1);
		tor_free(filename);
		tor_free(data_v2);
		tor_free(data_v3);
	}
	start_of_dirreq_stats_interval = now;
	return start_of_dirreq_stats_interval + WRITE_STATS_INTERVAL;
}
#undef RESPONSE_GRANULARITY

static time_t start_of_bridge_stats_interval;		/** Start time of bridge stats or 0 if we're not collecting bridge statistics. */

/** Initialize bridge stats. */
void geoip_bridge_stats_init(time_t now)
{	start_of_bridge_stats_interval = now;
}

/** Stop collecting bridge stats in a way that we can re-start doing so in geoip_bridge_stats_init(). */
void geoip_bridge_stats_term(void)
{	client_history_clear();
	start_of_bridge_stats_interval = 0;
}

/** Validate a bridge statistics string as it would be written to a current extra-info descriptor. Return 1 if the string is valid and recent enough, or 0 otherwise. */
static int validate_bridge_stats(const char *stats_str, time_t now)
{	char stats_end_str[ISO_TIME_LEN+1], stats_start_str[ISO_TIME_LEN+1],*eos;
	const char *BRIDGE_STATS_END = "bridge-stats-end ";
	const char *BRIDGE_IPS = "bridge-ips ";
	const char *BRIDGE_IPS_EMPTY_LINE = "bridge-ips\n";
	const char *tmp;
	time_t stats_end_time;
	int seconds;
	tor_assert(stats_str);
	/* Parse timestamp and number of seconds from "bridge-stats-end YYYY-MM-DD HH:MM:SS (N s)" */
	tmp = find_str_at_start_of_line(stats_str, BRIDGE_STATS_END);
	if(!tmp)	return 0;
	tmp += strlen(BRIDGE_STATS_END);
	if(strlen(tmp) < ISO_TIME_LEN + 6)	return 0;
	strlcpy(stats_end_str, tmp, sizeof(stats_end_str));
	if(parse_iso_time(stats_end_str, &stats_end_time) < 0)	return 0;
	if(stats_end_time < now - (25*60*60) || stats_end_time > now + (1*60*60))	return 0;
	seconds = (int)strtol(tmp + ISO_TIME_LEN + 2, &eos, 10);
	if(!eos || seconds < 23*60*60)	return 0;
	format_iso_time(stats_start_str, stats_end_time - seconds);
	/* Parse: "bridge-ips CC=N,CC=N,..." */
	tmp = find_str_at_start_of_line(stats_str, BRIDGE_IPS);
	if(!tmp)	/* Look if there is an empty "bridge-ips" line */
	{	tmp = find_str_at_start_of_line(stats_str, BRIDGE_IPS_EMPTY_LINE);
		if(!tmp)	return 0;
	}
	return 1;
}

static char *bridge_stats_extrainfo = NULL;		/** Most recent bridge statistics formatted to be written to extra-info descriptors. */

/** Return a newly allocated string holding our bridge usage stats by country in a format suitable for inclusion in an extrainfo document. Return NULL on failure.  */
static char *format_bridge_stats_extrainfo(time_t now)
{	char *out = NULL, *data = NULL;
	long duration = now - start_of_bridge_stats_interval;
	char written[ISO_TIME_LEN+1];
	if(duration < 0)	return NULL;
	format_iso_time(written, now);
	data = geoip_get_client_history(GEOIP_CLIENT_CONNECT);
	if(!data)	data = tor_malloc_zero(10);
	tor_asprintf((unsigned char **)&out,"bridge-stats-end %s (%ld s)\nbridge-ips %s\n",written,duration,data);
	tor_free(data);
	return out;
}

/** Return a newly allocated string holding our bridge usage stats by country in a format suitable for the answer to a controller request. Return NULL on failure.  */
static char *format_bridge_stats_controller(time_t now)
{	char *out = NULL, *data = NULL;
	char started[ISO_TIME_LEN+1];
	(void) now;
	format_iso_time(started, start_of_bridge_stats_interval);
	data = geoip_get_client_history(GEOIP_CLIENT_CONNECT);
	if(!data)	data = tor_malloc_zero(10);
	tor_asprintf((unsigned char **)&out,"TimeStarted=\"%s\" CountrySummary=%s",started, data);
	tor_free(data);
	return out;
}

/** Write bridge statistics to $DATADIR/stats/bridge-stats and return when we should next try to write statistics. */
time_t geoip_bridge_stats_write(time_t now)
{	char *filename = NULL, *val = NULL;
	/* Check if 24 hours have passed since starting measurements. */
	if(now < start_of_bridge_stats_interval + WRITE_STATS_INTERVAL)
		return start_of_bridge_stats_interval + WRITE_STATS_INTERVAL;
	/* Discard all items in the client history that are too old. */
	geoip_remove_old_clients(start_of_bridge_stats_interval);
	/* Generate formatted string */
	val = format_bridge_stats_extrainfo(now);
	if(val)
	{	/* Update the stored value. */
		tor_free(bridge_stats_extrainfo);
		bridge_stats_extrainfo = val;
		start_of_bridge_stats_interval = now;
		/* Write it to disk. */
		filename = get_datadir_fname(DATADIR_GEOIP_BRIDGE_STATS);
		append_bytes_to_file(filename, bridge_stats_extrainfo, strlen(bridge_stats_extrainfo),0);
		/* Tell the controller, "hey, there are clients!" */
		char *controller_str = format_bridge_stats_controller(now);
		if(controller_str)
		{	control_event_clients_seen(controller_str);
			tor_free(controller_str);
		}
		tor_free(filename);
	}
	return start_of_bridge_stats_interval + WRITE_STATS_INTERVAL;
}

/** Try to load the most recent bridge statistics from disk, unless we have finished a measurement interval lately, and check whether they are still recent enough. */
static void load_bridge_stats(time_t now)
{	char *fname, *contents;
	if(bridge_stats_extrainfo)	return;
	fname = get_datadir_fname(DATADIR_GEOIP_BRIDGE_STATS);
	contents = read_file_to_str(fname, RFTS_IGNORE_MISSING, NULL);
	if(contents && validate_bridge_stats(contents, now))
		bridge_stats_extrainfo = contents;
	tor_free(fname);
}

/** Return most recent bridge statistics for inclusion in extra-info descriptors, or NULL if we don't have recent bridge statistics. */
const char *geoip_get_bridge_stats_extrainfo(time_t now)
{	load_bridge_stats(now);
	return bridge_stats_extrainfo;
}

/** Return a new string containing the recent bridge statistics to be returned to controller clients, or NULL if we don't have any bridge statistics. */
char *geoip_get_bridge_stats_controller(time_t now)
{	return format_bridge_stats_controller(now);
}

static time_t start_of_entry_stats_interval;		/** Start time of entry stats or 0 if we're not collecting entry statistics. */

/** Initialize entry stats. */
void geoip_entry_stats_init(time_t now)
{	start_of_entry_stats_interval = now;
}

/** Stop collecting entry stats in a way that we can re-start doing so in geoip_entry_stats_init(). */
void geoip_entry_stats_term(void)
{	client_history_clear();
	start_of_entry_stats_interval = 0;
}

/** Write entry statistics to $DATADIR/stats/entry-stats and return time when we would next want to write. */
time_t geoip_entry_stats_write(time_t now)
{	char *filename = NULL;
	char *data = NULL;
	char written[ISO_TIME_LEN+1];
	if(!start_of_entry_stats_interval)	return 0; /* Not initialized. */
	if(start_of_entry_stats_interval + WRITE_STATS_INTERVAL <= now)
	{	/* Discard all items in the client history that are too old. */
		geoip_remove_old_clients(start_of_entry_stats_interval);
		filename = get_datadir_fname(DATADIR_GEOIP_ENTRY_STATS);
		data = geoip_get_client_history(GEOIP_CLIENT_CONNECT);
		format_iso_time(written, now);
		unsigned char *str;
		tor_asprintf(&str,"entry-stats-end %s (%u s)\nentry-ips %s\n",written, (unsigned) (now - start_of_entry_stats_interval),data ? data : "");
		append_bytes_to_file(filename, (char *)str, strlen((char *)str),0);
		tor_free(str);
		start_of_entry_stats_interval = now;
		tor_free(filename);
		tor_free(data);
	}
	return start_of_entry_stats_interval + WRITE_STATS_INTERVAL;
}

/** Helper used to implement GETINFO ip-to-country/... controller command. */
int
getinfo_helper_geoip(control_connection_t *control_conn,
                     const char *question, char **answer,
                     const char **errmsg)
{
  (void)control_conn;
  (void)errmsg;
  if (!strcmpstart(question, "ip-to-country/")) {
    int c;
    uint32_t ip;
    struct in_addr in;
    question += strlen("ip-to-country/");
    if (tor_inet_aton(question, &in) != 0) {
      ip = ntohl(in.s_addr);
      c = geoip_get_country_by_ip(ip)&0xff;
      *answer = tor_strdup(geoip_get_country_name(c));
    }
  }
  return 0;
}

/** Release all storage held in this file. */
void
geoip_free_all(void)
{
    clientmap_entry_t **ent, **next, *this;
    for (ent = HT_START(clientmap, &client_history); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(clientmap, &client_history, ent);
      tor_free(this);
    }
    {
      HT_CLEAR(clientmap, &client_history);
      dirreq_map_entry_t **ent2, **next2, *this2;
      for (ent2 = HT_START(dirreqmap, &dirreq_map); ent2 != NULL; ent2 = next2) {
	      this2 = *ent2;
	      next2 = HT_NEXT_RMV(dirreqmap, &dirreq_map, ent2);
	      tor_free(this2);
      }
      HT_CLEAR(dirreqmap, &dirreq_map);
   }
  geoip_countries=NULL;
}
