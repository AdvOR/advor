/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address.h
 * \brief Headers for address.h
 **/

#ifndef _TOR_ADDRESS_H
#define _TOR_ADDRESS_H

#include "orconfig.h"
#include "torint.h"
#include "compat.h"

/** The number of bits from an address to consider while doing a masked
 * comparison. */
typedef uint8_t maskbits_t;

struct in_addr;
/** Holds an IPv4 or IPv6 address.  (Uses less memory than struct
 * sockaddr_storage.) */
typedef struct tor_addr_t
{
  sa_family_t family;
  union {
    struct in_addr in_addr;
    struct in6_addr in6_addr;
  } addr;
} tor_addr_t;

static INLINE const struct in6_addr *tor_addr_to_in6(const tor_addr_t *a);
static INLINE uint32_t tor_addr_to_ipv4n(const tor_addr_t *a);
static INLINE uint32_t tor_addr_to_ipv4h(const tor_addr_t *a);
static INLINE uint32_t tor_addr_to_mapped_ipv4h(const tor_addr_t *a);
static INLINE sa_family_t tor_addr_family(const tor_addr_t *a);
static INLINE const struct in_addr *tor_addr_to_in(const tor_addr_t *a);
static INLINE int tor_addr_eq_ipv4h(const tor_addr_t *a, uint32_t u);

socklen_t tor_addr_to_sockaddr(const tor_addr_t *a, uint16_t port,
                               struct sockaddr *sa_out, socklen_t len);
int tor_addr_from_sockaddr(tor_addr_t *a, const struct sockaddr *sa,
                           uint16_t *port_out);
void tor_addr_make_unspec(tor_addr_t *a);
char *tor_sockaddr_to_str(const struct sockaddr *sa);

/** Return an in6_addr* equivalent to <b>a</b>, or NULL if <b>a</b> is not
 * an IPv6 address. */
static INLINE const struct in6_addr *
tor_addr_to_in6(const tor_addr_t *a)
{
  return a->family == AF_INET6 ? &a->addr.in6_addr : NULL;
}

#define tor_addr_to_in6_addr8(x) tor_addr_to_in6(x)->s6_addr
#define tor_addr_to_in6_addr16(x) S6_ADDR16(*tor_addr_to_in6(x))
#define tor_addr_to_in6_addr32(x) S6_ADDR32(*tor_addr_to_in6(x))

/** Return an IPv4 address in network order for <b>a</b>, or 0 if
 * <b>a</b> is not an IPv4 address. */
static INLINE uint32_t
tor_addr_to_ipv4n(const tor_addr_t *a)
{
  return a->family == AF_INET ? a->addr.in_addr.s_addr : 0;
}
/** Return an IPv4 address in host order for <b>a</b>, or 0 if
 * <b>a</b> is not an IPv4 address. */
static INLINE uint32_t
tor_addr_to_ipv4h(const tor_addr_t *a)
{
  return ntohl(tor_addr_to_ipv4n(a));
}
/* Given an IPv6 address, return its mapped IPv4 address in host order, or
 * 0 if <b>a</b> is not an IPv6 address.
 *
 * (Does not check whether the address is really a mapped address */
static INLINE uint32_t
tor_addr_to_mapped_ipv4h(const tor_addr_t *a)
{
  if (a->family == AF_INET6) {
    uint32_t *addr32 = NULL;
    // Work around an incorrect NULL pointer dereference warning in
    // "clang --analyze" due to limited analysis depth
    addr32 = tor_addr_to_in6_addr32(a);
    return ntohl(addr32[3]);
  } else {
    return 0;
  }
}
/** Return the address family of <b>a</b>.  Possible values are:
 * AF_INET6, AF_INET, AF_UNSPEC. */
static INLINE sa_family_t
tor_addr_family(const tor_addr_t *a)
{
  return a->family;
}
/** Return an in_addr* equivalent to <b>a</b>, or NULL if <b>a</b> is not
 * an IPv4 address. */
static INLINE const struct in_addr *
tor_addr_to_in(const tor_addr_t *a)
{
  return a->family == AF_INET ? &a->addr.in_addr : NULL;
}
/** Return true iff <b>a</b> is an IPv4 address equal to the host-ordered
 * address in <b>u</b>. */
static INLINE int
tor_addr_eq_ipv4h(const tor_addr_t *a, uint32_t u)
{
  return a->family == AF_INET ? (tor_addr_to_ipv4h(a) == u) : 0;
}

#define TOR_ADDR_BUF_LEN 48 /* [ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]
                             */

int tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr_out);
char *tor_dup_addr(const tor_addr_t *addr) ATTR_MALLOC;
const char *fmt_addr(const tor_addr_t *addr);
int get_interface_address6(int severity, sa_family_t family, tor_addr_t *addr);

/** Flag to specify how to do a comparison between addresses.  In an "exact"
 * comparison, addresses are equivalent only if they are in the same family
 * with the same value.  In a "semantic" comparison, IPv4 addresses match all
 * IPv6 encodings of those addresses. */
typedef enum {
  CMP_EXACT,
  CMP_SEMANTIC,
} tor_addr_comparison_t;

int tor_addr_compare(const tor_addr_t *addr1, const tor_addr_t *addr2,
                     tor_addr_comparison_t how);
int tor_addr_compare_masked(const tor_addr_t *addr1, const tor_addr_t *addr2,
                            maskbits_t mask, tor_addr_comparison_t how);
/** Return true iff a and b are the same address.  The comparison is done
 * "exactly". */
#define tor_addr_eq(a,b) (0==tor_addr_compare((a),(b),CMP_EXACT))

unsigned int tor_addr_hash(const tor_addr_t *addr);
int tor_addr_is_v4(const tor_addr_t *addr);
int tor_addr_is_internal(const tor_addr_t *ip, int for_listening) ATTR_PURE;

/** Longest length that can be required for a reverse lookup name. */
/* 32 nybbles, 32 dots, 8 characters of "ip6.arpa", 1 NUL: 73 characters. */
#define REVERSE_LOOKUP_NAME_BUF_LEN 73
int tor_addr_to_reverse_lookup_name(char *out, size_t outlen,
                                    const tor_addr_t *addr);
int tor_addr_parse_reverse_lookup_name(tor_addr_t *result, const char *address,
                                       int family, int accept_regular);

int tor_addr_port_parse(const char *s, tor_addr_t *addr_out,
                        uint16_t *port_out);
int tor_addr_parse_mask_ports(const char *s,
                              tor_addr_t *addr_out, maskbits_t *mask_out,
                              uint16_t *port_min_out, uint16_t *port_max_out);
const char * tor_addr_to_str(char *dest, const tor_addr_t *addr, int len,
                             int decorate);
int tor_addr_from_str(tor_addr_t *addr, const char *src);
void tor_addr_copy(tor_addr_t *dest, const tor_addr_t *src);
void tor_addr_from_ipv4n(tor_addr_t *dest, uint32_t v4addr);
/** Set <b>dest</b> to the IPv4 address encoded in <b>v4addr</b> in host
 * order. */
#define tor_addr_from_ipv4h(dest, v4addr)       \
  tor_addr_from_ipv4n((dest), htonl(v4addr))
void tor_addr_from_ipv6_bytes(tor_addr_t *dest, const char *bytes);
#define tor_addr_from_in(dest, in) \
  tor_addr_from_ipv4n((dest), (in)->s_addr);
void tor_addr_from_in6(tor_addr_t *dest, const struct in6_addr *in6);
int tor_addr_is_null(const tor_addr_t *addr);
int tor_addr_is_loopback(const tor_addr_t *addr);

/* IPv4 helpers */
int is_internal_IP(uint32_t ip, int for_listening) ATTR_PURE;
int parse_addr_port(int severity, const char *addrport, char **address,
                    uint32_t *addr, uint16_t *port_out);
int parse_port_range(const char *port, uint16_t *port_min_out,
                     uint16_t *port_max_out);
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                              maskbits_t *maskbits_out, uint16_t *port_min_out,
                              uint16_t *port_max_out);
int addr_mask_get_bits(uint32_t mask);
int addr_mask_cmp_bits(uint32_t a1, uint32_t a2, maskbits_t bits);
/** Length of a buffer to allocate to hold the results of tor_inet_ntoa.*/
#define INET_NTOA_BUF_LEN 16
int tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len);
char *tor_dup_ip(uint32_t addr) ATTR_MALLOC;
int get_interface_address(int severity, uint32_t *addr);

#endif

