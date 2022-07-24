/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file policies.c
 * \brief Code to parse and use address policies and exit policies.
 **/

#include "or.h"
#include "config.h"
#include "dirserv.h"
#include "policies.h"
#include "routerparse.h"
#include "ht.h"

/** Policy that addresses for incoming SOCKS connections must match. */
static smartlist_t *socks_policy = NULL;
/** Policy that addresses for incoming directory connections must match. */
static smartlist_t *dir_policy = NULL;
/** Policy that addresses for incoming router descriptors must match in order
 * to be published by us. */
static smartlist_t *authdir_reject_policy = NULL;
/** Policy that addresses for incoming router descriptors must match in order
 * to be marked as valid in our networkstatus. */
static smartlist_t *authdir_invalid_policy = NULL;
/** Policy that addresses for incoming router descriptors must <b>not</b>
 * match in order to not be marked as BadDirectory. */
static smartlist_t *authdir_baddir_policy = NULL;
/** Policy that addresses for incoming router descriptors must <b>not</b>
 * match in order to not be marked as BadExit. */
static smartlist_t *authdir_badexit_policy = NULL;
addr_policy_t *policy_list = NULL;
addr_policy_t *last_policy = NULL;

/** Parsed addr_policy_t describing which addresses we believe we can start
 * circuits at. */
static smartlist_t *reachable_or_addr_policy = NULL;
/** Parsed addr_policy_t describing which addresses we believe we can connect
 * to directories at. */
static smartlist_t *reachable_dir_addr_policy = NULL;

/** Element of an exit policy summary */
typedef struct policy_summary_item_t {
    uint16_t prt_min; /**< Lowest port number to accept/reject. */
    uint16_t prt_max; /**< Highest port number to accept/reject. */
    uint64_t reject_count; /**< Number of IP-Addresses that are rejected to
                                this portrange. */
    unsigned int accepted:1; /** Has this port already been accepted */
} policy_summary_item_t;

/** Private networks.  This list is used in two places, once to expand the
 *  "private" keyword when parsing our own exit policy, secondly to ignore
 *  just such networks when building exit policy summaries.  It is important
 *  that all authorities agree on that list when creating summaries, so don't
 *  just change this without a proper migration plan and a proposal and stuff.
 */
static const char *private_nets[] = {
  "0.0.0.0/8", "169.254.0.0/16",
  "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
  // "fc00::/7", "fe80::/10", "fec0::/10", "::/127",
  NULL };

/** Replace all "private" entries in *<b>policy</b> with their expanded
 * equivalents. */
void
policy_expand_private(smartlist_t **policy)
{
  uint16_t port_min, port_max;

  int i;
  smartlist_t *tmp;

  if (!*policy) /*XXXX disallow NULL policies? */
    return;

  tmp = smartlist_create();

  SMARTLIST_FOREACH(*policy, addr_policy_t *, p,
  {
     if (! p->is_private) {
       smartlist_add(tmp, p);
       continue;
     }
     for (i = 0; private_nets[i]; ++i) {
       addr_policy_t policy2;
       memcpy(&policy2, p, sizeof(addr_policy_t));
       policy2.is_private = 0;
       policy2.is_canonical = 0;
       if (tor_addr_parse_mask_ports(private_nets[i], &policy2.addr,
                                  &policy2.maskbits, &port_min, &port_max)<0) {
         tor_assert(0);
       }
       smartlist_add(tmp, addr_policy_get_canonical_entry(&policy2));
     }
     addr_policy_free(p);
  });

  smartlist_free(*policy);
  *policy = tmp;
}

/**
 * Given a linked list of config lines containing "allow" and "deny"
 * tokens, parse them and append the result to <b>dest</b>. Return -1
 * if any tokens are malformed (and don't append any), else return 0.
 *
 * If <b>assume_action</b> is nonnegative, then insert its action
 * (ADDR_POLICY_ACCEPT or ADDR_POLICY_REJECT) for items that specify no
 * action.
 */
static int
parse_addr_policy(config_line_t *cfg, smartlist_t **dest,
                  int assume_action)
{
  smartlist_t *result;
  smartlist_t *entries;
  addr_policy_t *item;
  int r = 0;

  if (!cfg)
    return 0;

  result = smartlist_create();
  entries = smartlist_create();
  for (; cfg; cfg = cfg->next) {
    smartlist_split_string(entries, (char *)cfg->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH(entries, const char *, ent,
    {
      log_debug(LD_CONFIG,get_lang_str(LANG_LOG_POLICIES_NEW_ENTRY),ent);
      item = router_parse_addr_policy_item_from_string(ent, assume_action);
      if (item) {
        smartlist_add(result, item);
      } else {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_POLICIES_MALFORMED_POLICY),ent);
        r = -1;
      }
    });
    SMARTLIST_FOREACH(entries, char *, ent, tor_free(ent));
    smartlist_clear(entries);
  }
  smartlist_free(entries);
  if (r == -1) {
    addr_policy_list_free(result);
  } else {
    policy_expand_private(&result);

    if (*dest) {
      smartlist_add_all(*dest, result);
      smartlist_free(result);
    } else {
      *dest = result;
    }
  }

  return r;
}

/** Helper: parse the Reachable(Dir|OR)?Addresses fields into
 * reachable_(or|dir)_addr_policy.  The options should already have
 * been validated by validate_addr_policies.
 */
static int
parse_reachable_addresses(void)
{
  or_options_t *options = get_options();
  int ret = 0;

  addr_policy_list_free(reachable_or_addr_policy);
  reachable_or_addr_policy = NULL;
  if (parse_addr_policy(options->ReachableAddresses,
                        &reachable_or_addr_policy, ADDR_POLICY_ACCEPT)) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_POLICIES_REACHABLEADDRESSES_PARSE_ERROR));
    ret = -1;
  }

  addr_policy_list_free(reachable_dir_addr_policy);
  reachable_dir_addr_policy = NULL;
  if (parse_addr_policy(options->ReachableAddresses,
                        &reachable_dir_addr_policy, ADDR_POLICY_ACCEPT)) {
    ret = -1;
  }
  return ret;
}

/** Return true iff the firewall options might block any address:port
 * combination.
 */
int
firewall_is_fascist_or(void)
{
  return reachable_or_addr_policy != NULL;
}

/** Return true iff <b>policy</b> (possibly NULL) will allow a
 * connection to <b>addr</b>:<b>port</b>.
 */
static int
addr_policy_permits_tor_addr(const tor_addr_t *addr, uint16_t port,
                            smartlist_t *policy)
{
  addr_policy_result_t p;
  p = compare_tor_addr_to_addr_policy(addr, port, policy);
  switch (p) {
    case ADDR_POLICY_PROBABLY_ACCEPTED:
    case ADDR_POLICY_ACCEPTED:
      return 1;
    case ADDR_POLICY_PROBABLY_REJECTED:
    case ADDR_POLICY_REJECTED:
      return 0;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_POLICIES_UNEXPECTED_RESULT),(int)p);
      return 0;
  }
}

/** Return true iff <b> policy</b> (possibly NULL) will allow a connection to
 * <b>addr</b>:<b>port</b>.  <b>addr</b> is an IPv4 address given in host
 * order. */
/* XXXX deprecate when possible. */
static int
addr_policy_permits_address(uint32_t addr, uint16_t port,
                            smartlist_t *policy)
{
  tor_addr_t a;
  tor_addr_from_ipv4h(&a, addr);
  return addr_policy_permits_tor_addr(&a, port, policy);
}

/** Return true iff we think our firewall will let us make an OR connection to
 * addr:port. */
int
fascist_firewall_allows_address_or(const tor_addr_t *addr, uint16_t port)
{
  return addr_policy_permits_tor_addr(addr, port,
                                     reachable_or_addr_policy);
}

/** Return true iff we think our firewall will let us make an OR connection to
 * <b>ri</b>. */
int
fascist_firewall_allows_or(routerinfo_t *ri)
{
  /* XXXX proposal 118 */
  tor_addr_t addr;
  tor_addr_from_ipv4h(&addr, ri->addr);
  return fascist_firewall_allows_address_or(&addr, ri->or_port);
}

/** Return true iff we think our firewall will let us make a directory
 * connection to addr:port. */
int
fascist_firewall_allows_address_dir(const tor_addr_t *addr, uint16_t port)
{
  return addr_policy_permits_tor_addr(addr, port,
                                      reachable_dir_addr_policy);
}

/** Return 1 if <b>addr</b> is permitted to connect to our dir port,
 * based on <b>dir_policy</b>. Else return 0.
 */
int
dir_policy_permits_address(const tor_addr_t *addr)
{
  return addr_policy_permits_tor_addr(addr, 1, dir_policy);
}

/** Return 1 if <b>addr</b> is permitted to connect to our socks port,
 * based on <b>socks_policy</b>. Else return 0.
 */
int
socks_policy_permits_address(const tor_addr_t *addr)
{
  return addr_policy_permits_tor_addr(addr, 1, socks_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> is permitted to publish to our
 * directory, based on <b>authdir_reject_policy</b>. Else return 0.
 */
int
authdir_policy_permits_address(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port, authdir_reject_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> is considered valid in our
 * directory, based on <b>authdir_invalid_policy</b>. Else return 0.
 */
int
authdir_policy_valid_address(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port, authdir_invalid_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> should be marked as a bad dir,
 * based on <b>authdir_baddir_policy</b>. Else return 0.
 */
int
authdir_policy_baddir_address(uint32_t addr, uint16_t port)
{
  return ! addr_policy_permits_address(addr, port, authdir_baddir_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> should be marked as a bad exit,
 * based on <b>authdir_badexit_policy</b>. Else return 0.
 */
int
authdir_policy_badexit_address(uint32_t addr, uint16_t port)
{
  return ! addr_policy_permits_address(addr, port, authdir_badexit_policy);
}

/** Config helper: If there's any problem with the policy configuration
 * options in <b>options</b>, return -1 and set <b>msg</b> to a newly
 * allocated description of the error. Else return 0. */
int validate_addr_policies(or_options_t *options, unsigned char **msg)
{	/* XXXX Maybe merge this into parse_policies_from_options, to make sure that the two can't go out of sync. */
	smartlist_t *addr_policy=NULL;
	*msg = NULL;
	if (policies_parse_exit_policy(options->ExitPolicy,&addr_policy,options->ExitPolicyRejectPrivate,NULL,!options->BridgeRelay))
		*msg = (unsigned char *)tor_strdup("Error in ExitPolicy entry.");
	/* The rest of these calls *append* to addr_policy. So don't actually use the results for anything other than checking if they parse! */
	else if (parse_addr_policy(options->DirPolicy, &addr_policy, -1))
		*msg = (unsigned char *)tor_strdup("Error in DirPolicy entry.");
	else if (parse_addr_policy(options->SocksPolicy, &addr_policy, -1))
		*msg = (unsigned char *)tor_strdup("Error in SocksPolicy entry.");
	else if (parse_addr_policy(options->AuthDirReject, &addr_policy,ADDR_POLICY_REJECT))
		*msg = (unsigned char *)tor_strdup("Error in AuthDirReject entry.");
	else if (parse_addr_policy(options->AuthDirInvalid, &addr_policy,ADDR_POLICY_REJECT))
		*msg = (unsigned char *)tor_strdup("Error in AuthDirInvalid entry.");
	else if (parse_addr_policy(options->AuthDirBadDir, &addr_policy,ADDR_POLICY_REJECT))
		*msg = (unsigned char *)tor_strdup("Error in AuthDirBadDir entry.");
	else if (parse_addr_policy(options->AuthDirBadExit, &addr_policy,ADDR_POLICY_REJECT))
		*msg = (unsigned char *)tor_strdup("Error in AuthDirBadExit entry.");
	else if (parse_addr_policy(options->ReachableAddresses, &addr_policy,ADDR_POLICY_ACCEPT))
		*msg = (unsigned char *)tor_strdup("Error in ReachableAddresses entry.");
	addr_policy_list_free(addr_policy);
	return *msg ? -1 : 0;
}

/** Parse <b>string</b> in the same way that the exit policy
 * is parsed, and put the processed version in *<b>policy</b>.
 * Ignore port specifiers.
 */
static int
load_policy_from_option(config_line_t *config, smartlist_t **policy,
                        int assume_action)
{
  int r;
  addr_policy_list_free(*policy);
  *policy = NULL;
  r = parse_addr_policy(config, policy, assume_action);
  if (r < 0) {
    return -1;
  }
  if (*policy) {
    SMARTLIST_FOREACH_BEGIN(*policy, addr_policy_t *, n) {
      /* ports aren't used in these. */
      if (n->prt_min > 1 || n->prt_max != 65535) {
        addr_policy_t newp, *c;
        memcpy(&newp, n, sizeof(newp));
        newp.prt_min = 1;
//	newp.is_cannonical = 0;
        newp.prt_max = 65535;
        c = addr_policy_get_canonical_entry(&newp);
        SMARTLIST_REPLACE_CURRENT(*policy, n, c);
        addr_policy_free(n);
      }
    } SMARTLIST_FOREACH_END(n);
  }
  return 0;
}

/** Set all policies based on <b>options</b>, which should have been validated
 * first by validate_addr_policies. */
int
policies_parse_from_options(or_options_t *options)
{
  int ret = 0;
  if (load_policy_from_option(options->SocksPolicy, &socks_policy, -1) < 0)
    ret = -1;
  if (load_policy_from_option(options->DirPolicy, &dir_policy, -1) < 0)
    ret = -1;
  if (load_policy_from_option(options->AuthDirReject,
                              &authdir_reject_policy, ADDR_POLICY_REJECT) < 0)
    ret = -1;
  if (load_policy_from_option(options->AuthDirInvalid,
                              &authdir_invalid_policy, ADDR_POLICY_REJECT) < 0)
    ret = -1;
  if (load_policy_from_option(options->AuthDirBadDir,
                              &authdir_baddir_policy, ADDR_POLICY_REJECT) < 0)
    ret = -1;
  if (load_policy_from_option(options->AuthDirBadExit,
                              &authdir_badexit_policy, ADDR_POLICY_REJECT) < 0)
    ret = -1;
  if (parse_reachable_addresses() < 0)
    ret = -1;
  return ret;
}

/** Compare two provided address policy items, and return -1, 0, or 1
 * if the first is less than, equal to, or greater than the second. */
static int
cmp_single_addr_policy(addr_policy_t *a, addr_policy_t *b)
{
  int r;
  if ((r=((int)a->policy_type - (int)b->policy_type)))
    return r;
  if ((r=((int)a->is_private - (int)b->is_private)))
    return r;
  if ((r=tor_addr_compare(&a->addr, &b->addr, CMP_EXACT)))
    return r;
  if ((r=((int)a->maskbits - (int)b->maskbits)))
    return r;
  if ((r=((int)a->prt_min - (int)b->prt_min)))
    return r;
  if ((r=((int)a->prt_max - (int)b->prt_max)))
    return r;
  return 0;
}

/** Like cmp_single_addr_policy() above, but looks at the
 * whole set of policies in each case. */
int
cmp_addr_policies(smartlist_t *a, smartlist_t *b)
{
  int r, i;
  int len_a = a ? smartlist_len(a) : 0;
  int len_b = b ? smartlist_len(b) : 0;

  for (i = 0; i < len_a && i < len_b; ++i) {
    if ((r = cmp_single_addr_policy(smartlist_get(a, i), smartlist_get(b, i))))
      return r;
  }
  if (i == len_a && i == len_b)
    return 0;
  if (i < len_a)
    return -1;
  else
    return 1;
}

/** Return a hashcode for <b>ent</b> */
static void policy_hash(addr_policy_t *ent)
{	uint32_t r;
	if(ent->is_private)
		r = 0x1234abcd;
	else	r = tor_addr_hash(&ent->addr);
	r += ent->prt_min << 8;
	r += ent->prt_max << 16;
	r += ent->maskbits;
	if(ent->policy_type == ADDR_POLICY_REJECT)
		r ^= 0xffffffff;
	ent->hash = r;
}

/** Given a pointer to an addr_policy_t, return a copy of the pointer to the
 * "canonical" copy of that addr_policy_t; the canonical copy is a single
 * reference-counted object. */
addr_policy_t *addr_policy_get_canonical_entry(addr_policy_t *e)
{	addr_policy_t *found;
	if(e->is_canonical)
		return e;
	policy_hash(e);
	for(found = policy_list;found;found = found->next)
	{	if(e->hash == found->hash)
		{	if(cmp_single_addr_policy(e,found) == 0)
				break;
		}
	}
	if(!found)
	{	found = tor_memdup(e, sizeof(addr_policy_t));
		found->is_canonical = 1;
		found->refcnt = 0;
		if(policy_list)
		{	last_policy->next = found;
			last_policy = found;
		}
		else
		{	policy_list = found;
			last_policy = found;
		}
	}
	++found->refcnt;
	return found;
}

/** As compare_tor_addr_to_addr_policy, but instead of a tor_addr_t, takes
 * in host order. */
addr_policy_result_t
compare_addr_to_addr_policy(uint32_t addr, uint16_t port,
                            const smartlist_t *policy)
{
  /*XXXX deprecate this function when possible. */
  tor_addr_t a;
  tor_addr_from_ipv4h(&a, addr);
  return compare_tor_addr_to_addr_policy(&a, port, policy);
}

/** Helper for compare_tor_addr_to_addr_policy.  Implements the case where
 * addr and port are both known. */
static addr_policy_result_t
compare_known_tor_addr_to_addr_policy(const tor_addr_t *addr, uint16_t port,
                                      const smartlist_t *policy)
{
  /* We know the address and port, and we know the policy, so we can just
   * compute an exact match. */
  SMARTLIST_FOREACH_BEGIN(policy, addr_policy_t *, tmpe) {
    /* Address is known */
    if (!tor_addr_compare_masked(addr, &tmpe->addr, tmpe->maskbits,
                                 CMP_EXACT)) {
      if (port >= tmpe->prt_min && port <= tmpe->prt_max) {
        /* Exact match for the policy */
        return tmpe->policy_type == ADDR_POLICY_ACCEPT ?
          ADDR_POLICY_ACCEPTED : ADDR_POLICY_REJECTED;
      }
    }
  } SMARTLIST_FOREACH_END(tmpe);

  /* accept all by default. */
  return ADDR_POLICY_ACCEPTED;
}

/** Helper for compare_tor_addr_to_addr_policy.  Implements the case where
 * addr is known but port is not. */
static addr_policy_result_t
compare_known_tor_addr_to_addr_policy_noport(const tor_addr_t *addr,
                                             const smartlist_t *policy)
{
  /* We look to see if there's a definite match.  If so, we return that
     match's value, unless there's an intervening possible match that says
     something different. */
  int maybe_accept = 0, maybe_reject = 0;

  SMARTLIST_FOREACH_BEGIN(policy, addr_policy_t *, tmpe) {
    if (!tor_addr_compare_masked(addr, &tmpe->addr, tmpe->maskbits,
                                 CMP_EXACT)) {
      if (tmpe->prt_min <= 1 && tmpe->prt_max >= 65535) {
        /* Definitely matches, since it covers all ports. */
        if (tmpe->policy_type == ADDR_POLICY_ACCEPT) {
          /* If we already hit a clause that might trigger a 'reject', than we
           * can't be sure of this certain 'accept'.*/
          return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED :
            ADDR_POLICY_ACCEPTED;
        } else {
          return maybe_accept ? ADDR_POLICY_PROBABLY_REJECTED :
            ADDR_POLICY_REJECTED;
        }
      } else {
        /* Might match. */
        if (tmpe->policy_type == ADDR_POLICY_REJECT)
          maybe_reject = 1;
        else
          maybe_accept = 1;
      }
    }
  } SMARTLIST_FOREACH_END(tmpe);

  /* accept all by default. */
  return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED : ADDR_POLICY_ACCEPTED;
}

/** Helper for compare_tor_addr_to_addr_policy.  Implements the case where
 * port is known but address is not. */
static addr_policy_result_t
compare_unknown_tor_addr_to_addr_policy(uint16_t port,
                                        const smartlist_t *policy)
{
  /* We look to see if there's a definite match.  If so, we return that
     match's value, unless there's an intervening possible match that says
     something different. */
  int maybe_accept = 0, maybe_reject = 0;

  SMARTLIST_FOREACH_BEGIN(policy, addr_policy_t *, tmpe) {
    if (tmpe->prt_min <= port && port <= tmpe->prt_max) {
       if (tmpe->maskbits == 0) {
        /* Definitely matches, since it covers all addresses. */
        if (tmpe->policy_type == ADDR_POLICY_ACCEPT) {
          /* If we already hit a clause that might trigger a 'reject', than we
           * can't be sure of this certain 'accept'.*/
          return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED :
            ADDR_POLICY_ACCEPTED;
        } else {
          return maybe_accept ? ADDR_POLICY_PROBABLY_REJECTED :
            ADDR_POLICY_REJECTED;
        }
      } else {
        /* Might match. */
        if (tmpe->policy_type == ADDR_POLICY_REJECT)
          maybe_reject = 1;
        else
          maybe_accept = 1;
      }
    }
  } SMARTLIST_FOREACH_END(tmpe);

  /* accept all by default. */
  return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED : ADDR_POLICY_ACCEPTED;
}

/** Decide whether a given addr:port is definitely accepted,
 * definitely rejected, probably accepted, or probably rejected by a
 * given policy.  If <b>addr</b> is 0, we don't know the IP of the
 * target address.  If <b>port</b> is 0, we don't know the port of the
 * target address.  (At least one of <b>addr</b> and <b>port</b> must be
 * provided.  If you want to know whether a policy would definitely reject
 * an unknown address:port, use policy_is_reject_star().)
 *
 * We could do better by assuming that some ranges never match typical
 * addresses (127.0.0.1, and so on).  But we'll try this for now.
 */
addr_policy_result_t
compare_tor_addr_to_addr_policy(const tor_addr_t *addr, uint16_t port,
                                const smartlist_t *policy)
{
  if (!policy) {
    /* no policy? accept all. */
    return ADDR_POLICY_ACCEPTED;
  } else if (tor_addr_is_null(addr)) {
    if (port == 0) {
      log_info(LD_BUG,get_lang_str(LANG_LOG_POLICIES_REJECTING_NULL_ADDRESS),addr ? tor_addr_family(addr) : -1);
      return ADDR_POLICY_REJECTED;
    }
    return compare_unknown_tor_addr_to_addr_policy(port, policy);
  } else if (port == 0) {
    return compare_known_tor_addr_to_addr_policy_noport(addr, policy);
  } else {
    return compare_known_tor_addr_to_addr_policy(addr, port, policy);
  }
}

/** Return true iff the address policy <b>a</b> covers every case that
 * would be covered by <b>b</b>, so that a,b is redundant. */
static int
addr_policy_covers(addr_policy_t *a, addr_policy_t *b)
{
  /* We can ignore accept/reject, since "accept *:80, reject *:80" reduces
   * to "accept *:80". */
  if (a->maskbits > b->maskbits) {
    /* a has more fixed bits than b; it can't possibly cover b. */
    return 0;
  }
  if (tor_addr_compare_masked(&a->addr, &b->addr, a->maskbits, CMP_EXACT)) {
    /* There's a fixed bit in a that's set differently in b. */
    return 0;
  }
  return (a->prt_min <= b->prt_min && a->prt_max >= b->prt_max);
}

/** Return true iff the address policies <b>a</b> and <b>b</b> intersect,
 * that is, there exists an address/port that is covered by <b>a</b> that
 * is also covered by <b>b</b>.
 */
static int
addr_policy_intersects(addr_policy_t *a, addr_policy_t *b)
{
  maskbits_t minbits;
  /* All the bits we care about are those that are set in both
   * netmasks.  If they are equal in a and b's networkaddresses
   * then the networks intersect.  If there is a difference,
   * then they do not. */
  if (a->maskbits < b->maskbits)
    minbits = a->maskbits;
  else
    minbits = b->maskbits;
  if (tor_addr_compare_masked(&a->addr, &b->addr, minbits, CMP_EXACT))
    return 0;
  if (a->prt_max < b->prt_min || b->prt_max < a->prt_min)
    return 0;
  return 1;
}

/** Add the exit policy described by <b>more</b> to <b>policy</b>.
 */
static void
append_exit_policy_string(smartlist_t **policy, const char *more)
{
  config_line_t tmp;

  tmp.key = NULL;
  tmp.value = (unsigned char*) more;
  tmp.next = NULL;
  if (parse_addr_policy(&tmp, policy, -1)<0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_POLICIES_PARSE_ERROR),more);
  }
}

/** Detect and excise "dead code" from the policy *<b>dest</b>. */
static void
exit_policy_remove_redundancies(smartlist_t *dest)
{
  addr_policy_t *ap, *tmp, *victim;
  int i, j;

  /* Step one: find a *:* entry and cut off everything after it. */
  for (i = 0; i < smartlist_len(dest); ++i) {
    ap = smartlist_get(dest, i);
    if (ap->maskbits == 0 && ap->prt_min <= 1 && ap->prt_max >= 65535) {
      /* This is a catch-all line -- later lines are unreachable. */
      while (i+1 < smartlist_len(dest)) {
        victim = smartlist_get(dest, i+1);
        smartlist_del(dest, i+1);
        addr_policy_free(victim);
      }
      break;
    }
  }

  /* Step two: for every entry, see if there's a redundant entry
   * later on, and remove it. */
  for (i = 0; i < smartlist_len(dest)-1; ++i) {
    ap = smartlist_get(dest, i);
    for (j = i+1; j < smartlist_len(dest); ++j) {
      tmp = smartlist_get(dest, j);
      tor_assert(j > i);
      if (addr_policy_covers(ap, tmp)) {
        char p1[POLICY_BUF_LEN], p2[POLICY_BUF_LEN];
        policy_write_item(p1, sizeof(p1), tmp, 0);
        policy_write_item(p2, sizeof(p2), ap, 0);
        log(LOG_DEBUG, LD_CONFIG,get_lang_str(LANG_LOG_POLICIES_REMOVE_EXIT_POLICY),p1,j,p2,i);
        smartlist_del_keeporder(dest, j--);
        addr_policy_free(tmp);
      }
    }
  }

  /* Step three: for every entry A, see if there's an entry B making this one
   * redundant later on.  This is the case if A and B are of the same type
   * (accept/reject), A is a subset of B, and there is no other entry of
   * different type in between those two that intersects with A.
   *
   * Anybody want to doublecheck the logic here? XXX
   */
  for (i = 0; i < smartlist_len(dest)-1; ++i) {
    ap = smartlist_get(dest, i);
    for (j = i+1; j < smartlist_len(dest); ++j) {
      // tor_assert(j > i); // j starts out at i+1; j only increases; i only
      //                    // decreases.
      tmp = smartlist_get(dest, j);
      if (ap->policy_type != tmp->policy_type) {
        if (addr_policy_intersects(ap, tmp))
          break;
      } else { /* policy_types are equal. */
        if (addr_policy_covers(tmp, ap)) {
          char p1[POLICY_BUF_LEN], p2[POLICY_BUF_LEN];
          policy_write_item(p1, sizeof(p1), ap, 0);
          policy_write_item(p2, sizeof(p2), tmp, 0);
          log(LOG_DEBUG, LD_CONFIG,get_lang_str(LANG_LOG_POLICIES_REMOVE_EXIT_POLICY_2),p1,p2);
          smartlist_del_keeporder(dest, i--);
          addr_policy_free(ap);
          break;
        }
      }
    }
  }
}

#ifndef int3
#define DEFAULT_EXIT_POLICY                                         \
  "reject *:25,reject *:119,reject *:135-139,reject *:445,"         \
  "reject *:563,reject *:1214,reject *:4661-4666,"                  \
  "reject *:6346-6429,reject *:6699,reject *:6881-6999,accept *:*"
#else
	#define DEFAULT_EXIT_POLICY "accept *:*"
#endif

/** Parse the exit policy <b>cfg</b> into the linked list *<b>dest</b>. If
 * cfg doesn't end in an absolute accept or reject, add the default exit
 * policy afterwards. If <b>rejectprivate</b> is true, prepend
 * "reject private:*" to the policy. Return -1 if we can't parse cfg,
 * else return 0.
 */
int
policies_parse_exit_policy(config_line_t *cfg, smartlist_t **dest,
                           int rejectprivate, const char *local_address,
                           int add_default_policy)
{
  if (rejectprivate) {
    append_exit_policy_string(dest, "reject private:*");
    if (local_address) {
      char buf[POLICY_BUF_LEN];
      tor_snprintf(buf, sizeof(buf), "reject %s:*", local_address);
      append_exit_policy_string(dest, buf);
    }
  }
  if (parse_addr_policy(cfg, dest, -1))
    return -1;
  if (add_default_policy)
    append_exit_policy_string(dest, DEFAULT_EXIT_POLICY);
  else
    append_exit_policy_string(dest, "reject *:*");
  exit_policy_remove_redundancies(*dest);

  return 0;
}

/** Add "reject *:*" to the end of the policy in *<b>dest</b>, allocating
 * *<b>dest</b> as needed. */
void
policies_exit_policy_append_reject_star(smartlist_t **dest)
{
  append_exit_policy_string(dest, "reject *:*");
}

/** Replace the exit policy of <b>r</b> with reject *:*. */
void
policies_set_router_exitpolicy_to_reject_all(routerinfo_t *r)
{
  addr_policy_t *item;
  addr_policy_list_free(r->exit_policy);
  r->exit_policy = smartlist_create();
  item = router_parse_addr_policy_item_from_string("reject *:*", -1);
  smartlist_add(r->exit_policy, item);
}

/** Return 1 if there is at least one /8 subnet in <b>policy</b> that
 * allows exiting to <b>port</b>.  Otherwise, return 0. */
static int
exit_policy_is_general_exit_helper(smartlist_t *policy, int port)
{
  uint32_t mask, ip, i;
  /* Is this /8 rejected (1), or undecided (0)? */
  char subnet_status[256];

  memset(subnet_status, 0, sizeof(subnet_status));
  SMARTLIST_FOREACH(policy, addr_policy_t *, p, {
    if (tor_addr_family(&p->addr) != AF_INET)
      continue; /* IPv4 only for now */
    if (p->prt_min > port || p->prt_max < port)
      continue; /* Doesn't cover our port. */
    mask = 0;
    tor_assert(p->maskbits <= 32);

    if (p->maskbits)
      mask = UINT32_MAX<<(32-p->maskbits);
    ip = tor_addr_to_ipv4h(&p->addr);

    /* Calculate the first and last subnet that this exit policy touches
     * and set it as loop boundaries. */
    for (i = ((mask & ip)>>24); i <= (~((mask & ip) ^ mask)>>24); ++i) {
      tor_addr_t addr;
      if (subnet_status[i] != 0)
        continue; /* We already reject some part of this /8 */
      tor_addr_from_ipv4h(&addr, i<<24);
      if (tor_addr_is_internal(&addr, 0))
        continue; /* Local or non-routable addresses */
      if (p->policy_type == ADDR_POLICY_ACCEPT) {
        if (p->maskbits > 8)
          continue; /* Narrower than a /8. */
        /* We found an allowed subnet of at least size /8. Done
         * for this port! */
        return 1;
      } else if (p->policy_type == ADDR_POLICY_REJECT) {
        subnet_status[i] = 1;
      }
    }
  });
  return 0;
}

/** Return true iff <b>ri</b> is "useful as an exit node", meaning
 * it allows exit to at least one /8 address space for at least
 * two of ports 80, 443, and 6667. */
int
exit_policy_is_general_exit(smartlist_t *policy)
{
  static const int ports[] = { 80, 443, 6667 };
  int n_allowed = 0;
  int i;
  if (!policy) /*XXXX disallow NULL policies? */
    return 0;

  for (i = 0; i < 3; ++i) {
    n_allowed += exit_policy_is_general_exit_helper(policy, ports[i]);
  }
  return n_allowed >= 2;
}

/** Return false if <b>policy</b> might permit access to some addr:port;
 * otherwise if we are certain it rejects everything, return true. */
int
policy_is_reject_star(const smartlist_t *policy)
{
  if (!policy) /*XXXX disallow NULL policies? */
    return 1;
  SMARTLIST_FOREACH(policy, addr_policy_t *, p, {
    if (p->policy_type == ADDR_POLICY_ACCEPT)
      return 0;
    else if (p->policy_type == ADDR_POLICY_REJECT &&
             p->prt_min <= 1 && p->prt_max == 65535 &&
             p->maskbits == 0)
      return 1;
  });
  return 1;
}

/** Write a single address policy to the buf_len byte buffer at buf.  Return
 * the number of characters written, or -1 on failure. */
int
policy_write_item(char *buf, size_t buflen, addr_policy_t *policy,
                  int format_for_desc)
{
  size_t written = 0;
  char addrbuf[TOR_ADDR_BUF_LEN];
  const char *addrpart;
  int result;
  const int is_accept = policy->policy_type == ADDR_POLICY_ACCEPT;
  const int is_ip6 = tor_addr_family(&policy->addr) == AF_INET6;

  tor_addr_to_str(addrbuf, &policy->addr, sizeof(addrbuf), 1);

  /* write accept/reject 1.2.3.4 */
  if (policy->is_private)
    addrpart = "private";
  else if (policy->maskbits == 0)
    addrpart = "*";
  else
    addrpart = addrbuf;

  result = tor_snprintf(buf, buflen, "%s%s%s %s",
                        (is_ip6&&format_for_desc)?"opt ":"",
                        is_accept ? "accept" : "reject",
                        (is_ip6&&format_for_desc)?"6":"",
                        addrpart);
  if (result < 0)
    return -1;
  written += strlen(buf);
  /* If the maskbits is 32 we don't need to give it.  If the mask is 0,
   * we already wrote "*". */
  if (policy->maskbits < 32 && policy->maskbits > 0) {
    if (tor_snprintf(buf+written, buflen-written, "/%d", policy->maskbits)<0)
      return -1;
    written += strlen(buf+written);
  }
  if (policy->prt_min <= 1 && policy->prt_max == 65535) {
    /* There is no port set; write ":*" */
    if (written+4 > buflen)
      return -1;
    strlcat(buf+written, ":*", buflen-written);
    written += 2;
  } else if (policy->prt_min == policy->prt_max) {
    /* There is only one port; write ":80". */
    result = tor_snprintf(buf+written, buflen-written, ":%d", policy->prt_min);
    if (result<0)
      return -1;
    written += result;
  } else {
    /* There is a range of ports; write ":79-80". */
    result = tor_snprintf(buf+written, buflen-written, ":%d-%d",
                          policy->prt_min, policy->prt_max);
    if (result<0)
      return -1;
    written += result;
  }
  if (written < buflen)
    buf[written] = '\0';
  else
    return -1;

  return (int)written;
}

/** Create a new exit policy summary, initially only with a single
 *  port 1-64k item */
/* XXXX This entire thing will do most stuff in O(N^2), or worse.  Use an
 *      RB-tree if that turns out to matter. */
static smartlist_t *
policy_summary_create(void)
{
  smartlist_t *summary;
  policy_summary_item_t* item;

  item = tor_malloc_zero(sizeof(policy_summary_item_t));
  item->prt_min = 1;
  item->prt_max = 65535;
  item->reject_count = 0;
  item->accepted = 0;

  summary = smartlist_create();
  smartlist_add(summary, item);

  return summary;
}

/** Split the summary item in <b>item</b> at the port <b>new_starts</b>.
 * The current item is changed to end at new-starts - 1, the new item
 * copies reject_count and accepted from the old item,
 * starts at new_starts and ends at the port where the original item
 * previously ended.
 */
static policy_summary_item_t*
policy_summary_item_split(policy_summary_item_t* old, uint16_t new_starts)
{
  policy_summary_item_t* new;

  new = tor_malloc_zero(sizeof(policy_summary_item_t));
  new->prt_min = new_starts;
  new->prt_max = old->prt_max;
  new->reject_count = old->reject_count;
  new->accepted = old->accepted;

  old->prt_max = new_starts-1;

  tor_assert(old->prt_min <= old->prt_max);
  tor_assert(new->prt_min <= new->prt_max);
  return new;
}

/* XXXX Nick says I'm going to hell for this.  If he feels charitably towards
 * my immortal soul, he can clean it up himself. */
#define AT(x) ((policy_summary_item_t*)smartlist_get(summary, x))

#define REJECT_CUTOFF_COUNT (1<<25)
/** Split an exit policy summary so that prt_min and prt_max
 * fall at exactly the start and end of an item respectively.
 */
static int
policy_summary_split(smartlist_t *summary,
                     uint16_t prt_min, uint16_t prt_max)
{
  int start_at_index;

  int i = 0;
  /* XXXX Do a binary search if run time matters */
  while (AT(i)->prt_max < prt_min)
    i++;
  if (AT(i)->prt_min != prt_min) {
    policy_summary_item_t* new_item;
    new_item = policy_summary_item_split(AT(i), prt_min);
    smartlist_insert(summary, i+1, new_item);
    i++;
  }
  start_at_index = i;

  while (AT(i)->prt_max < prt_max)
    i++;
  if (AT(i)->prt_max != prt_max) {
    policy_summary_item_t* new_item;
    new_item = policy_summary_item_split(AT(i), prt_max+1);
    smartlist_insert(summary, i+1, new_item);
  }

  return start_at_index;
}

/** Mark port ranges as accepted if they are below the reject_count */
static void
policy_summary_accept(smartlist_t *summary,
                      uint16_t prt_min, uint16_t prt_max)
{
  int i = policy_summary_split(summary, prt_min, prt_max);
  while (i < smartlist_len(summary) &&
         AT(i)->prt_max <= prt_max) {
    if (!AT(i)->accepted &&
        AT(i)->reject_count <= REJECT_CUTOFF_COUNT)
      AT(i)->accepted = 1;
    i++;
  }
  tor_assert(i < smartlist_len(summary) || prt_max==65535);
}

/** Count the number of addresses in a network with prefixlen maskbits
 * against the given portrange. */
static void
policy_summary_reject(smartlist_t *summary,
                      maskbits_t maskbits,
                      uint16_t prt_min, uint16_t prt_max)
{
  int i = policy_summary_split(summary, prt_min, prt_max);
  /* XXX: ipv4 specific */
  uint64_t count = (U64_LITERAL(1) << (32-maskbits));
  while (i < smartlist_len(summary) &&
         AT(i)->prt_max <= prt_max) {
    AT(i)->reject_count += count;
    i++;
  }
  tor_assert(i < smartlist_len(summary) || prt_max==65535);
}

/** Add a single exit policy item to our summary:
 *  If it is an accept ignore it unless it is for all IP addresses
 *  ("*"), i.e. it's prefixlen/maskbits is 0, else call
 *  policy_summary_accept().
 *  If it's a reject ignore it if it is about one of the private
 *  networks, else call policy_summary_reject().
 */
static void
policy_summary_add_item(smartlist_t *summary, addr_policy_t *p)
{
  if (p->policy_type == ADDR_POLICY_ACCEPT) {
    if (p->maskbits == 0) {
      policy_summary_accept(summary, p->prt_min, p->prt_max);
    }
  } else if (p->policy_type == ADDR_POLICY_REJECT) {

     int is_private = 0;
     int i;
     for (i = 0; private_nets[i]; ++i) {
       tor_addr_t addr;
       maskbits_t maskbits;
       if (tor_addr_parse_mask_ports(private_nets[i], &addr,
                                  &maskbits, NULL, NULL)<0) {
         tor_assert(0);
       }
       if (tor_addr_compare(&p->addr, &addr, CMP_EXACT) == 0 &&
           p->maskbits == maskbits) {
         is_private = 1;
         break;
       }
     }

     if (!is_private) {
       policy_summary_reject(summary, p->maskbits, p->prt_min, p->prt_max);
     }
  } else
    tor_assert(0);
}

/** Create a string representing a summary for an exit policy.
 * The summary will either be an "accept" plus a comma-seperated list of port
 * ranges or a "reject" plus portranges, depending on which is shorter.
 *
 * If no exits are allowed at all then NULL is returned, if no ports
 * are blocked instead of "reject " we return "accept 1-65535" (this
 * is an exception to the shorter-representation-wins rule).
 */
char *policy_summarize(smartlist_t *policy)
{	smartlist_t *summary = policy_summary_create();
	smartlist_t *accepts, *rejects;
	int i, last, start_prt;
	size_t accepts_len, rejects_len, shorter_len, final_size;
	char *accepts_str = NULL, *rejects_str = NULL, *shorter_str, *result;
	const char *prefix;
	tor_assert(policy);

	/* Create the summary list */
	SMARTLIST_FOREACH(policy, addr_policy_t *, p,
	{	policy_summary_add_item(summary, p);
	});
	/* Now create two lists of strings, one for accepted and one for rejected ports.  We take care to merge ranges so that we avoid getting stuff like "1-4,5-9,10", instead we want "1-10" */
	i = 0;
	start_prt = 1;
	accepts = smartlist_create();
	rejects = smartlist_create();
	while(1)
	{	last = i == smartlist_len(summary)-1;
		if(last || AT(i)->accepted != AT(i+1)->accepted)
		{	char buf[POLICY_BUF_LEN];
			if(start_prt == AT(i)->prt_max)	tor_snprintf(buf, sizeof(buf), "%d", start_prt);
			else	tor_snprintf(buf, sizeof(buf), "%d-%d", start_prt, AT(i)->prt_max);
			if(AT(i)->accepted)	smartlist_add(accepts, tor_strdup(buf));
			else	smartlist_add(rejects, tor_strdup(buf));
			if(last)	break;
			start_prt = AT(i+1)->prt_min;
		};
		i++;
	};

	/* Figure out which of the two stringlists will be shorter and use that to build the result */
	if(smartlist_len(accepts) == 0)	/* no exits at all */
		result = tor_strdup("reject 1-65535");
	else if(smartlist_len(rejects) == 0)	/* no rejects at all */
		result = tor_strdup("accept 1-65535");
	else
	{	accepts_str = smartlist_join_strings(accepts, ",", 0, &accepts_len);
		rejects_str = smartlist_join_strings(rejects, ",", 0, &rejects_len);
		if(rejects_len > MAX_EXITPOLICY_SUMMARY_LEN-strlen("reject")-1 && accepts_len > MAX_EXITPOLICY_SUMMARY_LEN-strlen("accept")-1)
		{	char *c;
			shorter_str = accepts_str;
			prefix = "accept";
			c = shorter_str + (MAX_EXITPOLICY_SUMMARY_LEN-strlen(prefix)-1);
			while(*c != ',' && c >= shorter_str)	c--;
			tor_assert(c >= shorter_str);
			tor_assert(*c == ',');
			*c = '\0';
			shorter_len = strlen(shorter_str);
		}
		else if(rejects_len < accepts_len)
		{	shorter_str = rejects_str;
			shorter_len = rejects_len;
			prefix = "reject";
		}
		else
		{	shorter_str = accepts_str;
			shorter_len = accepts_len;
			prefix = "accept";
		}
		final_size = strlen(prefix)+1+shorter_len+1;
		tor_assert(final_size <= MAX_EXITPOLICY_SUMMARY_LEN+1);
		result = tor_malloc(final_size);
		tor_snprintf(result, final_size, "%s %s", prefix, shorter_str);
	}
	/* cleanup */
	SMARTLIST_FOREACH(summary, policy_summary_item_t *, s, tor_free(s));
	smartlist_free(summary);
	tor_free(accepts_str);
	SMARTLIST_FOREACH(accepts, char *, s, tor_free(s));
	smartlist_free(accepts);
	tor_free(rejects_str);
	SMARTLIST_FOREACH(rejects, char *, s, tor_free(s));
	smartlist_free(rejects);
	return result;
}

/** Implementation for GETINFO control command: knows the answer for questions
 * about "exit-policy/..." */
int
getinfo_helper_policies(control_connection_t *conn,
                        const char *question, char **answer,
                        const char **errmsg)
{
  (void) conn;
  (void) question;
  (void) answer;
  (void) errmsg;
#ifndef int3
  (void) conn;
  (void) errmsg;
  if (!strcmp(question, "exit-policy/default")) {
    *answer = tor_strdup(DEFAULT_EXIT_POLICY);
  }
#endif
  return 0;
}

/** Release all storage held by <b>p</b>. */
void
addr_policy_list_free(smartlist_t *lst)
{
  if (!lst) return;
  SMARTLIST_FOREACH(lst, addr_policy_t *, policy, addr_policy_free(policy));
  smartlist_free(lst);
}

/** Release all storage held by <b>p</b>. */
void
addr_policy_free(addr_policy_t *p)
{
	if(!p)
		return;
	if(--p->refcnt <= 0)
	{	addr_policy_t *pol;
		if(policy_list == p)
		{	policy_list = p->next;
			if(last_policy==p)
				last_policy = p->next;
		}
		else if(policy_list)
		{	for(pol=policy_list;pol;pol = pol->next)
			{	if(pol->next == p)
				{	pol->next = p->next;
					if(last_policy == p)
						last_policy = pol;
					break;
				}
			}
		}
		tor_free(p);
	}
}

/** Release all storage held by policy variables. */
void
policies_free_all(void)
{
  addr_policy_list_free(reachable_or_addr_policy);
  reachable_or_addr_policy = NULL;
  addr_policy_list_free(reachable_dir_addr_policy);
  reachable_dir_addr_policy = NULL;
  addr_policy_list_free(socks_policy);
  socks_policy = NULL;
  addr_policy_list_free(dir_policy);
  dir_policy = NULL;
  addr_policy_list_free(authdir_reject_policy);
  authdir_reject_policy = NULL;
  addr_policy_list_free(authdir_invalid_policy);
  authdir_invalid_policy = NULL;
  addr_policy_list_free(authdir_baddir_policy);
  authdir_baddir_policy = NULL;
  addr_policy_list_free(authdir_badexit_policy);
  authdir_badexit_policy = NULL;

  addr_policy_t *pol;
  while(policy_list)
  {	pol = policy_list->next;
  	tor_free(pol);
	policy_list = pol;
  }
  last_policy = NULL;
}

