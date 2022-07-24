/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hibernate.c
 * \brief Functions to close listeners, stop allowing new circuits,
 * etc in preparation for closing down or going dormant; and to track
 * bandwidth and time intervals to know when to hibernate and when to
 * stop hibernating.
 **/

/*
hibernating, phase 1:
  - send destroy in response to create cells
  - send end (policy failed) in response to begin cells
  - close an OR conn when it has no circuits

hibernating, phase 2:
  (entered when bandwidth hard limit reached)
  - close all OR/AP/exit conns)
*/

#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "hibernate.h"
#include "main.h"
#include "router.h"

/** Possible values of hibernate_state */
typedef enum {
  /** We are running normally. */
  HIBERNATE_STATE_LIVE=1,
  /** We're trying to shut down cleanly, and we'll kill all active connections
   * at shutdown_time. */
  HIBERNATE_STATE_EXITING=2,
  /** We're running low on allocated bandwidth for this period, so we won't
   * accept any new connections. */
  HIBERNATE_STATE_LOWBANDWIDTH=3,
  /** We are hibernating, and we won't wake up till there's more bandwidth to
   * use. */
  HIBERNATE_STATE_DORMANT=4
} hibernate_state_t;

extern long stats_n_seconds_working; /* published uptime */

/** Are we currently awake, asleep, running out of bandwidth, or shutting
 * down? */
static hibernate_state_t hibernate_state = HIBERNATE_STATE_LIVE;
/** If are hibernating, when do we plan to wake up? Set to 0 if we
 * aren't hibernating. */
static time_t hibernate_end_time = 0;
/** If we are shutting down, when do we plan finally exit? Set to 0 if
 * we aren't shutting down. */
static time_t shutdown_time = 0;

/** Possible accounting periods. */
typedef enum {
  UNIT_MONTH=1, UNIT_WEEK=2, UNIT_DAY=3,
} time_unit_t;

/* Fields for accounting logic.  Accounting overview:
 *
 * Accounting is designed to ensure that no more than N bytes are sent in
 * either direction over a given interval (currently, one month, one week, or
 * one day) We could
 * try to do this by choking our bandwidth to a trickle, but that
 * would make our streams useless.  Instead, we estimate what our
 * bandwidth usage will be, and guess how long we'll be able to
 * provide that much bandwidth before hitting our limit.  We then
 * choose a random time within the accounting interval to come up (so
 * that we don't get 50 Tors running on the 1st of the month and none
 * on the 30th).
 *
 * Each interval runs as follows:
 *
 * 1. We guess our bandwidth usage, based on how much we used
 *     last time.  We choose a "wakeup time" within the interval to come up.
 * 2. Until the chosen wakeup time, we hibernate.
 * 3. We come up at the wakeup time, and provide bandwidth until we are
 *    "very close" to running out.
 * 4. Then we go into low-bandwidth mode, and stop accepting new
 *    connections, but provide bandwidth until we run out.
 * 5. Then we hibernate until the end of the interval.
 *
 * If the interval ends before we run out of bandwidth, we go back to
 * step one.
 */

/** How many bytes have we read in this accounting interval? */
static uint64_t n_bytes_read_in_interval = 0;
/** How many bytes have we written in this accounting interval? */
static uint64_t n_bytes_written_in_interval = 0;
/** How many seconds have we been running this interval? */
static uint32_t n_seconds_active_in_interval = 0;
/** How many seconds were we active in this interval before we hit our soft
 * limit? */
static int n_seconds_to_hit_soft_limit = 0;
/** When in this interval was the soft limit hit. */
static time_t soft_limit_hit_at = 0;
/** How many bytes had we read/written when we hit the soft limit? */
static uint64_t n_bytes_at_soft_limit = 0;
/** When did this accounting interval start? */
static time_t interval_start_time = 0;
/** When will this accounting interval end? */
static time_t interval_end_time = 0;
/** How far into the accounting interval should we hibernate? */
static time_t interval_wakeup_time = 0;
/** How much bandwidth do we 'expect' to use per minute?  (0 if we have no
 * info from the last period.) */
static uint64_t expected_bandwidth_usage = 0;
/** What unit are we using for our accounting? */
static time_unit_t cfg_unit = UNIT_MONTH;

/** How many days,hours,minutes into each unit does our accounting interval
 * start? */
static int cfg_start_day = 0,
           cfg_start_hour = 0,
           cfg_start_min = 0;

static void reset_accounting(time_t now);
static int read_bandwidth_usage(void);
static time_t start_of_accounting_period_after(time_t now);
static time_t start_of_accounting_period_containing(time_t now);
static void accounting_set_wakeup_time(void);

/* ************
 * Functions for bandwidth accounting.
 * ************/

/** Configure accounting start/end time settings based on
 * options->AccountingStart.  Return 0 on success, -1 on failure. If
 * <b>validate_only</b> is true, do not change the current settings. */
int accounting_parse_options(or_options_t *options, int validate_only)
{	time_unit_t unit=UNIT_DAY;
	int ok, idx;
	long d=0,h,m;
	smartlist_t *items;
	const char *v = options->AccountingStart;
	const char *s;
	char *cp;
	if(!v)
	{	if(!validate_only)
		{	cfg_unit = UNIT_MONTH;
			cfg_start_day = 1;
			cfg_start_hour = 0;
			cfg_start_min = 0;
		}
		return 0;
	}
	items = smartlist_create();
	smartlist_split_string(items, v, NULL,SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK,0);
	if(smartlist_len(items)<2)
		log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTINGSTART_ERROR));
	else
	{	s = smartlist_get(items,0);
		ok = 1;
		if(0==strcasecmp(s, "month"))
		{	unit = UNIT_MONTH;
			d = tor_parse_long(smartlist_get(items,1), 10, 1, 28, &ok, NULL);
			if(!ok)	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_MONTH_ERROR));
		}
		else if(0==strcasecmp(s, "week"))
		{	unit = UNIT_WEEK;
			d = tor_parse_long(smartlist_get(items,1), 10, 1, 7, &ok, NULL);
			if(!ok)	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_DAY_ERROR));
		}
		else if(0==strcasecmp(s, "day"))
		{	unit = UNIT_DAY;
			d = 0;
		}
		else
		{	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_UNRECOGNIZED_UNIT),s);
			ok = 0;
		}
		if(ok)
		{	idx = unit==UNIT_DAY?1:2;
			if(smartlist_len(items) != (idx+1))
				log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_UNIT_ERROR),s,idx,(idx>1)?get_lang_str(LANG_LOG_HIBERNATE__ARGUMENTS):get_lang_str(LANG_LOG_HIBERNATE__ARGUMENT));
			else
			{	s = smartlist_get(items, idx);
				h = tor_parse_long(s, 10, 0, 23, &ok, &cp);
				if(!ok)				log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_HOUR_ERROR));
				else if(!cp || *cp!=':')	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_TIME_ERROR));
				else
				{	m = tor_parse_long(cp+1, 10, 0, 59, &ok, &cp);
					if(!ok)				log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_MINUTE_ERROR));
					else if(!cp || *cp!='\0')	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_TIME_ERROR));
					else
					{	if(!validate_only)
						{	cfg_unit = unit;
							cfg_start_day = (int)d;
							cfg_start_hour = (int)h;
							cfg_start_min = (int)m;
						}
						SMARTLIST_FOREACH(items, char *, item, tor_free(item));
						smartlist_free(items);
						return 0;
					}
				}
			}
		}
	}
	SMARTLIST_FOREACH(items, char *, item, tor_free(item));
	smartlist_free(items);
	return -1;
}

/** If we want to manage the accounting system and potentially
 * hibernate, return 1, else return 0.
 */
int
accounting_is_enabled(or_options_t *options)
{
  if (options->AccountingMax)
    return 1;
  return 0;
}

/** Called from main.c to tell us that <b>seconds</b> seconds have
 * passed, <b>n_read</b> bytes have been read, and <b>n_written</b>
 * bytes have been written. */
void
accounting_add_bytes(size_t n_read, size_t n_written, int seconds)
{
  n_bytes_read_in_interval += n_read;
  n_bytes_written_in_interval += n_written;
  /* If we haven't been called in 10 seconds, we're probably jumping
   * around in time. */
  n_seconds_active_in_interval += (seconds < 10) ? seconds : 0;
}

/** If get_end, return the end of the accounting period that contains
 * the time <b>now</b>.  Else, return the start of the accounting
 * period that contains the time <b>now</b> */
static time_t
edge_of_accounting_period_containing(time_t now, int get_end)
{
  int before;
  struct tm tm;
  tor_localtime_r(&now, &tm);

  /* Set 'before' to true iff the current time is before the hh:mm
   * changeover time for today. */
  before = tm.tm_hour < cfg_start_hour ||
    (tm.tm_hour == cfg_start_hour && tm.tm_min < cfg_start_min);

  /* Dispatch by unit.  First, find the start day of the given period;
   * then, if get_end is true, increment to the end day. */
  switch (cfg_unit)
    {
    case UNIT_MONTH: {
      /* If this is before the Nth, we want the Nth of last month. */
      if (tm.tm_mday < cfg_start_day ||
          (tm.tm_mday < cfg_start_day && before)) {
        --tm.tm_mon;
      }
      /* Otherwise, the month is correct. */
      tm.tm_mday = cfg_start_day;
      if (get_end)
        ++tm.tm_mon;
      break;
    }
    case UNIT_WEEK: {
      /* What is the 'target' day of the week in struct tm format? (We
         say Sunday==7; struct tm says Sunday==0.) */
      int wday = cfg_start_day % 7;
      /* How many days do we subtract from today to get to the right day? */
      int delta = (7+tm.tm_wday-wday)%7;
      /* If we are on the right day, but the changeover hasn't happened yet,
       * then subtract a whole week. */
      if (delta == 0 && before)
        delta = 7;
      tm.tm_mday -= delta;
      if (get_end)
        tm.tm_mday += 7;
      break;
    }
    case UNIT_DAY:
      if (before)
        --tm.tm_mday;
      if (get_end)
        ++tm.tm_mday;
      break;
    default:
      tor_assert(0);
  }

  tm.tm_hour = cfg_start_hour;
  tm.tm_min = cfg_start_min;
  tm.tm_sec = 0;
  tm.tm_isdst = -1; /* Autodetect DST */
  return mktime(&tm);
}

/** Return the start of the accounting period containing the time
 * <b>now</b>. */
static time_t
start_of_accounting_period_containing(time_t now)
{
  return edge_of_accounting_period_containing(now, 0);
}

/** Return the start of the accounting period that comes after the one
 * containing the time <b>now</b>. */
static time_t
start_of_accounting_period_after(time_t now)
{
  return edge_of_accounting_period_containing(now, 1);
}

/** Return the length of the accounting period containing the time
 * <b>now</b>. */
static long
length_of_accounting_period_containing(time_t now)
{
  return edge_of_accounting_period_containing(now, 1) -
    edge_of_accounting_period_containing(now, 0);
}

/** Initialize the accounting subsystem. */
void
configure_accounting(time_t now)
{
  time_t s_now;
  /* Try to remember our recorded usage. */
  if (!interval_start_time)
    read_bandwidth_usage(); /* If we fail, we'll leave values at zero, and
                             * reset below.*/
  s_now = start_of_accounting_period_containing(now);

  if (!interval_start_time) {
    /* We didn't have recorded usage; Start a new interval. */
    log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_START));
    reset_accounting(now);
  } else if (s_now == interval_start_time) {
    log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_CONTINUE));
    /* We are in the interval we thought we were in. Do nothing.*/
    interval_end_time = start_of_accounting_period_after(interval_start_time);
  } else {
    long duration =
      length_of_accounting_period_containing(interval_start_time);
    double delta = ((double)(s_now - interval_start_time)) / duration;
    if (-0.50 <= delta && delta <= 0.50) {
      /* The start of the period is now a little later or earlier than we
       * remembered.  That's fine; we might lose some bytes we could otherwise
       * have written, but better to err on the side of obeying people's
       * accounting settings. */
      log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACC_INTERVAL_MOVED), delta*100);
      interval_end_time = start_of_accounting_period_after(now);
    } else if (delta >= 0.99) {
      /* This is the regular time-moved-forward case; don't be too noisy
       * about it or people will complain */
      log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACC_ELAPSED));
      reset_accounting(now);
    } else {
      log_warn(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_MISMATCHED_INTERVAL));
      reset_accounting(now);
    }
  }
  accounting_set_wakeup_time();
}

/** Set expected_bandwidth_usage based on how much we sent/received
 * per minute last interval (if we were up for at least 30 minutes),
 * or based on our declared bandwidth otherwise. */
static void
update_expected_bandwidth(void)
{
  uint64_t expected;
  or_options_t *options= get_options();
  uint64_t max_configured = (options->RelayBandwidthRate > 0 ?
                             options->RelayBandwidthRate :
                             options->BandwidthRate) * 60;

#define MIN_TIME_FOR_MEASUREMENT (1800)

  if (soft_limit_hit_at > interval_start_time && n_bytes_at_soft_limit &&
      (soft_limit_hit_at - interval_start_time) > MIN_TIME_FOR_MEASUREMENT) {
    /* If we hit our soft limit last time, only count the bytes up to that
     * time. This is a better predictor of our actual bandwidth than
     * considering the entirety of the last interval, since we likely started
     * using bytes very slowly once we hit our soft limit. */
    expected = n_bytes_at_soft_limit /
      (soft_limit_hit_at - interval_start_time);
    expected /= 60;
  } else if (n_seconds_active_in_interval >= MIN_TIME_FOR_MEASUREMENT) {
    /* Otherwise, we either measured enough time in the last interval but
     * never hit our soft limit, or we're using a state file from a Tor that
     * doesn't know to store soft-limit info.  Just take rate at which
     * we were reading/writing in the last interval as our expected rate.
     */
    uint64_t used = MAX(n_bytes_written_in_interval,
                        n_bytes_read_in_interval);
    expected = used / (n_seconds_active_in_interval / 60);
  } else {
    /* If we haven't gotten enough data last interval, set 'expected'
     * to 0.  This will set our wakeup to the start of the interval.
     * Next interval, we'll choose our starting time based on how much
     * we sent this interval.
     */
    expected = 0;
  }
  if (expected > max_configured)
    expected = max_configured;
  expected_bandwidth_usage = expected;
}

/** Called at the start of a new accounting interval: reset our
 * expected bandwidth usage based on what happened last time, set up
 * the start and end of the interval, and clear byte/time totals.
 */
static void
reset_accounting(time_t now)
{
  log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_START));
  update_expected_bandwidth();
  interval_start_time = start_of_accounting_period_containing(now);
  interval_end_time = start_of_accounting_period_after(interval_start_time);
  n_bytes_read_in_interval = 0;
  n_bytes_written_in_interval = 0;
  n_seconds_active_in_interval = 0;
  n_bytes_at_soft_limit = 0;
  soft_limit_hit_at = 0;
  n_seconds_to_hit_soft_limit = 0;
}

/** Return true iff we should save our bandwidth usage to disk. */
static INLINE int
time_to_record_bandwidth_usage(time_t now)
{
  /* Note every 600 sec */
#define NOTE_INTERVAL (600)
  /* Or every 20 megabytes */
#define NOTE_BYTES 20*(1024*1024)
  static uint64_t last_read_bytes_noted = 0;
  static uint64_t last_written_bytes_noted = 0;
  static time_t last_time_noted = 0;

  if (last_time_noted + NOTE_INTERVAL <= now ||
      last_read_bytes_noted + NOTE_BYTES <= n_bytes_read_in_interval ||
      last_written_bytes_noted + NOTE_BYTES <= n_bytes_written_in_interval ||
      (interval_end_time && interval_end_time <= now)) {
    last_time_noted = now;
    last_read_bytes_noted = n_bytes_read_in_interval;
    last_written_bytes_noted = n_bytes_written_in_interval;
    return 1;
  }
  return 0;
}

/** Invoked once per second.  Checks whether it is time to hibernate,
 * record bandwidth used, etc.  */
void
accounting_run_housekeeping(time_t now)
{
  if (now >= interval_end_time) {
    configure_accounting(now);
  }
  if (time_to_record_bandwidth_usage(now)) {
    if (accounting_record_bandwidth_usage(now, get_or_state())) {
      log_warn(LD_FS,get_lang_str(LANG_LOG_HIBERNATE_BW_HIST_WRITE_ERROR));
    }
  }
}

/** When we have no idea how fast we are, how long do we assume it will take
 * us to exhaust our bandwidth? */
#define GUESS_TIME_TO_USE_BANDWIDTH (24*60*60)

/** Based on our interval and our estimated bandwidth, choose a
 * deterministic (but random-ish) time to wake up. */
static void
accounting_set_wakeup_time(void)
{
  char digest[DIGEST_LEN];
  crypto_digest_env_t *d_env;
  int time_in_interval;
  uint64_t time_to_exhaust_bw;
  int time_to_consider;

  if (! server_identity_key_is_set()) {
    if (init_keys() < 0) {
      log_err(LD_BUG,get_lang_str(LANG_LOG_HIBERNATE_KEYS_INIT_ERROR));
      tor_assert(0);
    }
  }

  if (server_identity_key_is_set()) {
    char buf[ISO_TIME_LEN+1];
    format_iso_time(buf, interval_start_time);

    crypto_pk_get_digest(get_server_identity_key(), digest);

    d_env = crypto_new_digest_env();
    crypto_digest_add_bytes(d_env, buf, ISO_TIME_LEN);
    crypto_digest_add_bytes(d_env, digest, DIGEST_LEN);
    crypto_digest_get_digest(d_env, digest, DIGEST_LEN);
    crypto_free_digest_env(d_env);
  } else {
    crypto_rand(digest, DIGEST_LEN);
  }

  if (!expected_bandwidth_usage) {
    char buf1[ISO_TIME_LEN+1];
    char buf2[ISO_TIME_LEN+1];
    format_local_iso_time(buf1, interval_start_time);
    format_local_iso_time(buf2, interval_end_time);
    interval_wakeup_time = interval_start_time;

    log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_CONFIGURED),buf1,buf2);
    return;
  }

  time_in_interval = (int)(interval_end_time - interval_start_time);

  time_to_exhaust_bw =
    (get_options()->AccountingMax/expected_bandwidth_usage)*60;
  if (time_to_exhaust_bw > INT_MAX) {
    time_to_exhaust_bw = INT_MAX;
    time_to_consider = 0;
  } else {
    time_to_consider = time_in_interval - (int)time_to_exhaust_bw;
  }

  if (time_to_consider<=0) {
    interval_wakeup_time = interval_start_time;
  } else {
    /* XXX can we simplify this just by picking a random (non-deterministic)
     * time to be up? If we go down and come up, then we pick a new one. Is
     * that good enough? -RD */

    /* This is not a perfectly unbiased conversion, but it is good enough:
     * in the worst case, the first half of the day is 0.06 percent likelier
     * to be chosen than the last half. */
    interval_wakeup_time = interval_start_time +
      (get_uint32(digest) % time_to_consider);
  }

  {
    char buf1[ISO_TIME_LEN+1];
    char buf2[ISO_TIME_LEN+1];
    char buf3[ISO_TIME_LEN+1];
    char buf4[ISO_TIME_LEN+1];
    time_t down_time;
    if (interval_wakeup_time+time_to_exhaust_bw > TIME_MAX)
      down_time = TIME_MAX;
    else
      down_time = (time_t)(interval_wakeup_time+time_to_exhaust_bw);
    if (down_time>interval_end_time)
      down_time = interval_end_time;
    format_local_iso_time(buf1, interval_start_time);
    format_local_iso_time(buf2, interval_wakeup_time);
    format_local_iso_time(buf3, down_time);
    format_local_iso_time(buf4, interval_end_time);

    log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_CONFIGURED_2),buf1,get_time(NULL)<interval_wakeup_time?get_lang_str(LANG_LOG_HIBERNATE__WAKE_UP_TIME_IS):get_lang_str(LANG_LOG_HIBERNATE__WAKE_UP_TIME_WAS), buf2,get_time(NULL)<down_time?get_lang_str(LANG_LOG_HIBERNATE__WE_EXPECT):get_lang_str(LANG_LOG_HIBERNATE__WE_EXPECTED),buf3,buf4);
  }
}

/* This rounds 0 up to 1000, but that's actually a feature. */
#define ROUND_UP(x) (((x) + 0x3ff) & ~0x3ff)
/** Save all our bandwidth tracking information to disk. Return 0 on
 * success, -1 on failure. */
int
accounting_record_bandwidth_usage(time_t now, or_state_t *state)
{
  /* Just update the state */
  state->AccountingIntervalStart = interval_start_time;
  state->AccountingBytesReadInInterval = ROUND_UP(n_bytes_read_in_interval);
  state->AccountingBytesWrittenInInterval =
    ROUND_UP(n_bytes_written_in_interval);
  state->AccountingSecondsActive = n_seconds_active_in_interval;
  state->AccountingExpectedUsage = expected_bandwidth_usage;

  state->AccountingSecondsToReachSoftLimit = n_seconds_to_hit_soft_limit;
  state->AccountingSoftLimitHitAt = soft_limit_hit_at;
  state->AccountingBytesAtSoftLimit = n_bytes_at_soft_limit;

  or_state_mark_dirty(state,
                      now+(get_options()->AvoidDiskWrites ? 7200 : 60));

  return 0;
}
#undef ROUND_UP

/** Read stored accounting information from disk. Return 0 on success;
 * return -1 and change nothing on failure. */
static int read_bandwidth_usage(void)
{	or_state_t *state = get_or_state();
//	remove_datadir_file(DATADIR_BW_ACCOUNTING);

  if (!state)
    return -1;

  /* Okay; it looks like the state file is more up-to-date than the
   * bw_accounting file, or the bw_accounting file is nonexistant,
   * or the bw_accounting file is corrupt.
   */
  log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_BW_HIST_READ));
  n_bytes_read_in_interval = state->AccountingBytesReadInInterval;
  n_bytes_written_in_interval = state->AccountingBytesWrittenInInterval;
  n_seconds_active_in_interval = state->AccountingSecondsActive;
  interval_start_time = state->AccountingIntervalStart;
  expected_bandwidth_usage = state->AccountingExpectedUsage;

  /* Older versions of Tor (before 0.2.2.17-alpha or so) didn't generate these
   * fields. If you switch back and forth, you might get an
   * AccountingSoftLimitHitAt value from long before the most recent
   * interval_start_time.  If that's so, then ignore the softlimit-related
   * values. */
  if (state->AccountingSoftLimitHitAt > interval_start_time) {
    soft_limit_hit_at =  state->AccountingSoftLimitHitAt;
    n_bytes_at_soft_limit = state->AccountingBytesAtSoftLimit;
    n_seconds_to_hit_soft_limit = state->AccountingSecondsToReachSoftLimit;
  } else {
    soft_limit_hit_at = 0;
    n_bytes_at_soft_limit = 0;
    n_seconds_to_hit_soft_limit = 0;
  }

  {
    char tbuf1[ISO_TIME_LEN+1];
    char tbuf2[ISO_TIME_LEN+1];
    format_iso_time(tbuf1, state->LastWritten);
    format_iso_time(tbuf2, state->AccountingIntervalStart);

    log_info(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_BW_HIST_READ_OK),tbuf1,tbuf2,(unsigned long)n_seconds_active_in_interval,(unsigned long)(expected_bandwidth_usage*1024/60),U64_PRINTF_ARG(n_bytes_read_in_interval),U64_PRINTF_ARG(n_bytes_written_in_interval));
  }

  return 0;
}

/** Return true iff we have sent/received all the bytes we are willing
 * to send/receive this interval. */
static int
hibernate_hard_limit_reached(void)
{
  uint64_t hard_limit = get_options()->AccountingMax;
  if (!hard_limit)
    return 0;
  return n_bytes_read_in_interval >= hard_limit
    || n_bytes_written_in_interval >= hard_limit;
}

/** Return true iff we have sent/received almost all the bytes we are willing
 * to send/receive this interval. */
static int
hibernate_soft_limit_reached(void)
{
  const uint64_t acct_max = get_options()->AccountingMax;
#define SOFT_LIM_PCT (.95)
#define SOFT_LIM_BYTES (500*1024*1024)
#define SOFT_LIM_MINUTES (3*60)
  /* The 'soft limit' is a fair bit more complicated now than once it was.
   * We want to stop accepting connections when ALL of the following are true:
   *   - We expect to use up the remaining bytes in under 3 hours
   *   - We have used up 95% of our bytes.
   *   - We have less than 500MB of bytes left.
   */
  uint64_t soft_limit = DBL_TO_U64(U64_TO_DBL(acct_max) * SOFT_LIM_PCT);
  if (acct_max > SOFT_LIM_BYTES && acct_max - SOFT_LIM_BYTES > soft_limit) {
    soft_limit = acct_max - SOFT_LIM_BYTES;
  }
  if (expected_bandwidth_usage) {
    const uint64_t expected_usage =
      expected_bandwidth_usage * SOFT_LIM_MINUTES;
    if (acct_max > expected_usage && acct_max - expected_usage > soft_limit)
      soft_limit = acct_max - expected_usage;
  }
  if (!soft_limit)
    return 0;
  return n_bytes_read_in_interval >= soft_limit
    || n_bytes_written_in_interval >= soft_limit;
}

/** Called when we get a SIGINT, or when bandwidth soft limit is
 * reached. Puts us into "loose hibernation": we don't accept new
 * connections, but we continue handling old ones. */
static void
hibernate_begin(hibernate_state_t new_state, time_t now)
{
  connection_t *conn;
  or_options_t *options = get_options();

  if (new_state == HIBERNATE_STATE_EXITING &&
      hibernate_state != HIBERNATE_STATE_LIVE) {
    log_notice(LD_GENERAL,get_lang_str(LANG_LOG_HIBERNATE_SIGINT_RECEIVED_A),hibernate_state == HIBERNATE_STATE_EXITING ?get_lang_str(LANG_LOG_HIBERNATE_SIGINT_RECEIVED_B) : get_lang_str(LANG_LOG_HIBERNATE_SIGINT_RECEIVED_C));
    tor_cleanup();
    exit(0);
  }

  if (new_state == HIBERNATE_STATE_LOWBANDWIDTH &&
      hibernate_state == HIBERNATE_STATE_LIVE) {
    soft_limit_hit_at = now;
    n_seconds_to_hit_soft_limit = n_seconds_active_in_interval;
    n_bytes_at_soft_limit = MAX(n_bytes_read_in_interval,
                                n_bytes_written_in_interval);
  }

  /* close listeners. leave control listener(s). */
  while ((conn = connection_get_by_type(CONN_TYPE_OR_LISTENER)) ||
         (conn = connection_get_by_type(CONN_TYPE_AP_LISTENER)) ||
         (conn = connection_get_by_type(CONN_TYPE_AP_TRANS_LISTENER)) ||
         (conn = connection_get_by_type(CONN_TYPE_AP_DNS_LISTENER)) ||
         (conn = connection_get_by_type(CONN_TYPE_AP_NATD_LISTENER)) ||
         (conn = connection_get_by_type(CONN_TYPE_DIR_LISTENER))) {
    log_info(LD_NET,get_lang_str(LANG_LOG_HIBERNATE_CLOSING_LISTENER),conn->type);
    connection_mark_for_close(conn);
  }

  /* XXX kill intro point circs */
  /* XXX upload rendezvous service descriptors with no intro points */

  if (new_state == HIBERNATE_STATE_EXITING) {
    log_notice(LD_GENERAL,get_lang_str(LANG_LOG_HIBERNATE_INTERRUPT),options->ShutdownWaitLength);
    shutdown_time = get_time(NULL) + options->ShutdownWaitLength;
  } else { /* soft limit reached */
    hibernate_end_time = interval_end_time;
  }

  hibernate_state = new_state;
  accounting_record_bandwidth_usage(now, get_or_state());

  or_state_mark_dirty(get_or_state(),
                      get_options()->AvoidDiskWrites ? now+600 : 0);
}

extern time_t time_to_check_listeners;
/** Called when we've been hibernating and our timeout is reached. */
static void
hibernate_end(hibernate_state_t new_state)
{
  tor_assert(hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH ||
             hibernate_state == HIBERNATE_STATE_DORMANT);

  /* listeners will be relaunched in run_scheduled_events() in main.c */
  log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_PERIOD_ENDED));

  hibernate_state = new_state;
  hibernate_end_time = 0; /* no longer hibernating */
  stats_n_seconds_working = 0; /* reset published uptime */
  time_to_check_listeners = 0;
}

/** A wrapper around hibernate_begin, for when we get SIGINT. */
void
hibernate_begin_shutdown(void)
{
  hibernate_begin(HIBERNATE_STATE_EXITING, get_time(NULL));
}

/** Return true iff we are currently hibernating. */
int
we_are_hibernating(void)
{
  return hibernate_state != HIBERNATE_STATE_LIVE;
}

/** If we aren't currently dormant, close all connections and become
 * dormant. */
void hibernate_go_dormant(time_t now)
{
  connection_t *conn;

  if (hibernate_state == HIBERNATE_STATE_DORMANT)
    return;
  else if (hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH)
    hibernate_state = HIBERNATE_STATE_DORMANT;
  else
    hibernate_begin(HIBERNATE_STATE_DORMANT, now);

  log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_PERIOD_STARTED));

  /* Close all OR/AP/exit conns. Leave dir conns because we still want
   * to be able to upload server descriptors so people know we're still
   * running, and download directories so we can detect if we're obsolete.
   * Leave control conns because we still want to be controllable.
   */
  while ((conn = connection_get_by_type(CONN_TYPE_OR)) ||
         (conn = connection_get_by_type(CONN_TYPE_AP)) ||
	 (conn = connection_get_by_type(CONN_TYPE_DIR)) ||
         (conn = connection_get_by_type(CONN_TYPE_EXIT))) {
    if (CONN_IS_EDGE(conn))
      connection_edge_end(TO_EDGE_CONN(conn), END_STREAM_REASON_HIBERNATING);
    log_info(LD_NET,get_lang_str(LANG_LOG_HIBERNATE_CLOSING_CONN),conn->type);
    if (conn->type == CONN_TYPE_AP) /* send socks failure if needed */
      connection_mark_unattached_ap(TO_EDGE_CONN(conn),
                                    END_STREAM_REASON_HIBERNATING);
    else
      connection_mark_for_close(conn);
  }

  if (now < interval_wakeup_time)
    hibernate_end_time = interval_wakeup_time;
  else
    hibernate_end_time = interval_end_time;

  accounting_record_bandwidth_usage(now, get_or_state());

  or_state_mark_dirty(get_or_state(),
                      get_options()->AvoidDiskWrites ? now+600 : 0);
}

/** Called when hibernate_end_time has arrived. */
void hibernate_end_time_elapsed(time_t now)
{
  char buf[ISO_TIME_LEN+1];

  /* The interval has ended, or it is wakeup time.  Find out which. */
  accounting_run_housekeeping(now);
  if (interval_wakeup_time <= now) {
    /* The interval hasn't changed, but interval_wakeup_time has passed.
     * It's time to wake up and start being a server. */
     if(tor_is_started())
	hibernate_end(HIBERNATE_STATE_LIVE);
    return;
  } else {
    /* The interval has changed, and it isn't time to wake up yet. */
    hibernate_end_time = interval_wakeup_time;
    format_iso_time(buf,interval_wakeup_time);
    if (hibernate_state != HIBERNATE_STATE_DORMANT) {
      /* We weren't sleeping before; we should sleep now. */
      log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_PERIOD_ENDED),buf);
      hibernate_go_dormant(now);
    } else {
      log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_ACCOUNTING_PERIOD_ENDED_2),buf);
    }
  }
}

/** Consider our environment and decide if it's time
 * to start/stop hibernating.
 */
void
consider_hibernation(time_t now)
{
  int accounting_enabled = get_options()->AccountingMax != 0;
  char buf[ISO_TIME_LEN+1];

  /* If we're in 'exiting' mode, then we just shut down after the interval
   * elapses. */
  if (hibernate_state == HIBERNATE_STATE_EXITING) {
    tor_assert(shutdown_time);
    if (shutdown_time <= now) {
      log_notice(LD_GENERAL,get_lang_str(LANG_LOG_HIBERNATE_CLEAN_SHUTDOWN));
      tor_cleanup();
      exit(0);
    }
    return; /* if exiting soon, don't worry about bandwidth limits */
  }

  if (hibernate_state == HIBERNATE_STATE_DORMANT) {
    /* We've been hibernating because of bandwidth accounting. */
    if(!tor_is_started()) return;
    if(!hibernate_end_time) return;
    if (hibernate_end_time > now && accounting_enabled) {
      /* If we're hibernating, don't wake up until it's time, regardless of
       * whether we're in a new interval. */
      return ;
    } else {
      hibernate_end_time_elapsed(now);
    }
  }

  /* Else, we aren't hibernating. See if it's time to start hibernating, or to
   * go dormant. */
  if (hibernate_state == HIBERNATE_STATE_LIVE) {
    if (hibernate_soft_limit_reached()) {
      log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_BW_LIMIT_REACHED));
      hibernate_begin(HIBERNATE_STATE_LOWBANDWIDTH, now);
    } else if (accounting_enabled && now < interval_wakeup_time) {
      format_local_iso_time(buf,interval_wakeup_time);
      log_notice(LD_ACCT,get_lang_str(LANG_LOG_HIBERNATE_STARTED),buf);
      hibernate_go_dormant(now);
    }
  }

  if (hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH) {
    if (!accounting_enabled) {
      hibernate_end_time_elapsed(now);
    } else if (hibernate_hard_limit_reached()) {
      hibernate_go_dormant(now);
    } else if (hibernate_end_time <= now) {
      /* The hibernation period ended while we were still in lowbandwidth.*/
      hibernate_end_time_elapsed(now);
    }
  }
}

/** Helper function: called when we get a GETINFO request for an
 * accounting-related key on the control connection <b>conn</b>.  If we can
 * answer the request for <b>question</b>, then set *<b>answer</b> to a newly
 * allocated string holding the result.  Otherwise, set *<b>answer</b> to
 * NULL. */
int
getinfo_helper_accounting(control_connection_t *conn,
                          const char *question, char **answer,
                          const char **errmsg)
{
  (void) conn;
  (void) errmsg;
  if (!strcmp(question, "accounting/enabled")) {
    *answer = tor_strdup(accounting_is_enabled(get_options()) ? "1" : "0");
  } else if (!strcmp(question, "accounting/hibernating")) {
    if (hibernate_state == HIBERNATE_STATE_DORMANT)
      *answer = tor_strdup("hard");
    else if (hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH)
      *answer = tor_strdup("soft");
    else
      *answer = tor_strdup("awake");
  } else if (!strcmp(question, "accounting/bytes")) {
    *answer = tor_malloc(32);
    tor_snprintf(*answer, 32, U64_FORMAT" "U64_FORMAT,
                 U64_PRINTF_ARG(n_bytes_read_in_interval),
                 U64_PRINTF_ARG(n_bytes_written_in_interval));
  } else if (!strcmp(question, "accounting/bytes-left")) {
    uint64_t limit = get_options()->AccountingMax;
    uint64_t read_left = 0, write_left = 0;
    if (n_bytes_read_in_interval < limit)
      read_left = limit - n_bytes_read_in_interval;
    if (n_bytes_written_in_interval < limit)
      write_left = limit - n_bytes_written_in_interval;
    *answer = tor_malloc(64);
    tor_snprintf(*answer, 64, U64_FORMAT" "U64_FORMAT,
                 U64_PRINTF_ARG(read_left), U64_PRINTF_ARG(write_left));
  } else if (!strcmp(question, "accounting/interval-start")) {
    *answer = tor_malloc(ISO_TIME_LEN+1);
    format_iso_time(*answer, interval_start_time);
  } else if (!strcmp(question, "accounting/interval-wake")) {
    *answer = tor_malloc(ISO_TIME_LEN+1);
    format_iso_time(*answer, interval_wakeup_time);
  } else if (!strcmp(question, "accounting/interval-end")) {
    *answer = tor_malloc(ISO_TIME_LEN+1);
    format_iso_time(*answer, interval_end_time);
  } else {
    *answer = NULL;
  }
  return 0;
}
