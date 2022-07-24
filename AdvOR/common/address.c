/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address.c
 * \brief Functions to use and manipulate the tor_addr_t structure.
 **/

#include "orconfig.h"
#include "compat.h"
#include "util.h"
#include "address.h"
#include "log.h"

#ifdef MS_WINDOWS
#include <process.h>
#include <windows.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Convert the tor_addr_t in <b>a</b>, with port in <b>port</b>, into a
 * socklen object in *<b>sa_out</b> of object size <b>len</b>.  If not enough
 * room is free, or on error, return -1.  Else return the length of the
 * sockaddr. */
/* XXXX021 This returns socklen_t.  socklen_t is sometimes unsigned.  This
 *   function claims to return -1 sometimes.  Problematic! */
socklen_t
tor_addr_to_sockaddr(const tor_addr_t *a,
                     uint16_t port,
                     struct sockaddr *sa_out,
                     socklen_t len)
{
  sa_family_t family = tor_addr_family(a);
  if (family == AF_INET) {
    struct sockaddr_in *sin;
    if (len < (int)sizeof(struct sockaddr_in))
      return 0;
    sin = (struct sockaddr_in *)sa_out;
    memset(sin, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sin->sin_len = sizeof(struct sockaddr_in);
#endif
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = tor_addr_to_ipv4n(a);
    return sizeof(struct sockaddr_in);
  } else if (family == AF_INET6) {
    struct sockaddr_in6 *sin6;
    if (len < (int)sizeof(struct sockaddr_in6))
      return 0;
    sin6 = (struct sockaddr_in6 *)sa_out;
    memset(sin6, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    memcpy(&sin6->sin6_addr, tor_addr_to_in6(a), sizeof(struct in6_addr));
    return sizeof(struct sockaddr_in6);
  } else {
    return 0;
  }
}


/** Return a newly allocated string holding the address described in <b>sa</b>.  AF_UNIX, AF_UNSPEC, AF_INET, and AF_INET6 are supported. */
char *tor_sockaddr_to_str(const struct sockaddr *sa)
{	char address[TOR_ADDR_BUF_LEN];
	unsigned char *result;
	tor_addr_t addr;
	uint16_t port;
#ifdef HAVE_SYS_UN_H
	if(sa->sa_family == AF_UNIX)
	{	struct sockaddr_un *s_un = (struct sockaddr_un *)sa;
		tor_asprintf(&result, "unix:%s", s_un->sun_path);
		return result;
	}
#endif
	if(sa->sa_family == AF_UNSPEC)				return tor_strdup("unspec");
	if(tor_addr_from_sockaddr(&addr, sa, &port) < 0)	return NULL;
	if(! tor_addr_to_str(address,&addr,sizeof(address),1))	return NULL;
	tor_asprintf(&result, "%s:%d", address, (int)port);
	return (char *)result;
}

/** Set the tor_addr_t in <b>a</b> to contain the socket address contained in
 * <b>sa</b>. */
int
tor_addr_from_sockaddr(tor_addr_t *a, const struct sockaddr *sa,
                       uint16_t *port_out)
{
  tor_assert(a);
  tor_assert(sa);
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    tor_addr_from_ipv4n(a, sin->sin_addr.s_addr);
    if (port_out)
      *port_out = ntohs(sin->sin_port);
  } else if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
    tor_addr_from_in6(a, &sin6->sin6_addr);
    if (port_out)
      *port_out = ntohs(sin6->sin6_port);
  } else {
    tor_addr_make_unspec(a);
    return -1;
  }
  return 0;
}

/** Set address <b>a</b> to the unspecified address.  This address belongs to
 * no family. */
void
tor_addr_make_unspec(tor_addr_t *a)
{
  memset(a, 0, sizeof(*a));
  a->family = AF_UNSPEC;
}

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address and family. The <b>family</b>
 * argument (which must be AF_INET, AF_INET6, or AF_UNSPEC) declares a
 * <i>preferred</i> family, though another one may be returned if only one
 * family is implemented for this address.
 *
 * Return 0 on success, -1 on failure; 1 on transient failure.
 */
int
tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr)
{
  /* Perhaps eventually this should be replaced by a tor_getaddrinfo or
   * something.
   */
  struct in_addr iaddr;
  struct in6_addr iaddr6;
  tor_assert(name);
  tor_assert(addr);
  tor_assert(family == AF_INET || family == AF_INET6 || family == AF_UNSPEC);
  if (!*name) {
    /* Empty address is an error. */
    return -1;
  } else if (tor_inet_pton(AF_INET, name, &iaddr)) {
    /* It's an IPv4 IP. */
    if (family == AF_INET6)
      return -1;
    tor_addr_from_in(addr, &iaddr);
    return 0;
  } else if (tor_inet_pton(AF_INET6, name, &iaddr6)) {
    if (family == AF_INET)
      return -1;
    tor_addr_from_in6(addr, &iaddr6);
    return 0;
  } else {
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo *res=NULL, *res_p;
    struct addrinfo *best=NULL;
    struct addrinfo hints;
    int result = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(name, NULL, &hints, &res);
    if (!err) {
      best = NULL;
      for (res_p = res; res_p; res_p = res_p->ai_next) {
        if (family == AF_UNSPEC) {
          if (res_p->ai_family == AF_INET) {
            best = res_p;
            break;
          } else if (res_p->ai_family == AF_INET6 && !best) {
            best = res_p;
          }
        } else if (family == res_p->ai_family) {
          best = res_p;
          break;
        }
      }
      if (!best)
        best = res;
      if (best->ai_family == AF_INET) {
        tor_addr_from_in(addr,
                         &((struct sockaddr_in*)best->ai_addr)->sin_addr);
        result = 0;
      } else if (best->ai_family == AF_INET6) {
        tor_addr_from_in6(addr,
                          &((struct sockaddr_in6*)best->ai_addr)->sin6_addr);
        result = 0;
      }
      freeaddrinfo(res);
      return result;
    }
    return (err == EAI_AGAIN) ? 1 : -1;
#else
    struct hostent *ent;
    int err;
#ifdef HAVE_GETHOSTBYNAME_R_6_ARG
    char buf[2048];
    struct hostent hostent;
    int r;
    r = gethostbyname_r(name, &hostent, buf, sizeof(buf), &ent, &err);
#elif defined(HAVE_GETHOSTBYNAME_R_5_ARG)
    char buf[2048];
    struct hostent hostent;
    ent = gethostbyname_r(name, &hostent, buf, sizeof(buf), &err);
#elif defined(HAVE_GETHOSTBYNAME_R_3_ARG)
    struct hostent_data data;
    struct hostent hent;
    memset(&data, 0, sizeof(data));
    err = gethostbyname_r(name, &hent, &data);
    ent = err ? NULL : &hent;
#else
    ent = gethostbyname(name);
#ifdef MS_WINDOWS
    err = WSAGetLastError();
#else
    err = h_errno;
#endif
#endif /* endif HAVE_GETHOSTBYNAME_R_6_ARG. */
    if (ent) {
      if (ent->h_addrtype == AF_INET) {
        tor_addr_from_in(addr, (struct in_addr*) ent->h_addr);
      } else if (ent->h_addrtype == AF_INET6) {
        tor_addr_from_in6(addr, (struct in6_addr*) ent->h_addr);
      } else {
        tor_assert(0); /* gethostbyname() returned a bizarre addrtype */
      }
      return 0;
    }
#ifdef MS_WINDOWS
    return (err == WSATRY_AGAIN) ? 1 : -1;
#else
    return (err == TRY_AGAIN) ? 1 : -1;
#endif
#endif
  }
}

/** Return true iff <b>ip</b> is an IP reserved to localhost or local networks
 * in RFC1918 or RFC4193 or RFC4291. (fec0::/10, deprecated by RFC3879, is
 * also treated as internal for now.)
 */
int
tor_addr_is_internal(const tor_addr_t *addr, int for_listening)
{
  uint32_t iph4 = 0;
  uint32_t iph6[4];
  sa_family_t v_family;
  v_family = tor_addr_family(addr);

  if (v_family == AF_INET) {
    iph4 = tor_addr_to_ipv4h(addr);
  } else if (v_family == AF_INET6) {
    if (tor_addr_is_v4(addr)) { /* v4-mapped */
      v_family = AF_INET;
      uint32_t *addr32 = NULL;
      addr32 = tor_addr_to_in6_addr32(addr);
      iph4 = ntohl(addr32[3]);
    }
  }

  if (v_family == AF_INET6) {
    const uint32_t *a32 = tor_addr_to_in6_addr32(addr);
    iph6[0] = ntohl(a32[0]);
    iph6[1] = ntohl(a32[1]);
    iph6[2] = ntohl(a32[2]);
    iph6[3] = ntohl(a32[3]);
    if (for_listening && !iph6[0] && !iph6[1] && !iph6[2] && !iph6[3]) /* :: */
      return 0;

    if (((iph6[0] & 0xfe000000) == 0xfc000000) || /* fc00/7  - RFC4193 */
        ((iph6[0] & 0xffc00000) == 0xfe800000) || /* fe80/10 - RFC4291 */
        ((iph6[0] & 0xffc00000) == 0xfec00000))   /* fec0/10 D- RFC3879 */
      return 1;

    if (!iph6[0] && !iph6[1] && !iph6[2] &&
        ((iph6[3] & 0xfffffffe) == 0x00000000))  /* ::/127 */
      return 1;

    return 0;
  } else if (v_family == AF_INET) {
    if (for_listening && !iph4) /* special case for binding to 0.0.0.0 */
      return 0;
    if (((iph4 & 0xff000000) == 0x0a000000) || /*       10/8 */
        ((iph4 & 0xff000000) == 0x00000000) || /*        0/8 */
        ((iph4 & 0xff000000) == 0x7f000000) || /*      127/8 */
        ((iph4 & 0xffff0000) == 0xa9fe0000) || /* 169.254/16 */
        ((iph4 & 0xfff00000) == 0xac100000) || /*  172.16/12 */
        ((iph4 & 0xffff0000) == 0xc0a80000))   /* 192.168/16 */
      return 1;
    return 0;
  }

  /* unknown address family... assume it's not safe for external use */
  /* rather than tor_assert(0) */
  log_warn(LD_BUG,get_lang_str(LANG_LOG_ADDRESS_TOR_ADDR_IS_INTERNAL_CALLED_WITH_NON_IP));
  return 1;
}

/** Convert a tor_addr_t <b>addr</b> into a string, and store it in
 *  <b>dest</b> of size <b>len</b>.  Returns a pointer to dest on success,
 *  or NULL on failure.  If <b>decorate</b>, surround IPv6 addresses with
 *  brackets.
 */
const char *
tor_addr_to_str(char *dest, const tor_addr_t *addr, int len, int decorate)
{
  const char *ptr;
  tor_assert(addr && dest);

  switch (tor_addr_family(addr)) {
    case AF_INET:
      if (len<3)
        return NULL;
        ptr = tor_inet_ntop(AF_INET, &addr->addr.in_addr, dest, len);
      break;
    case AF_INET6:
      if (decorate)
        ptr = tor_inet_ntop(AF_INET6, &addr->addr.in6_addr, dest+1, len-2);
      else
        ptr = tor_inet_ntop(AF_INET6, &addr->addr.in6_addr, dest, len);
      if (ptr && decorate) {
        *dest = '[';
        memcpy(dest+strlen(dest), "]", 2);
        tor_assert(ptr == dest+1);
        ptr = dest;
      }
      break;
    default:
      return NULL;
  }
  return ptr;
}

/** Parse an .in-addr.arpa or .ip6.arpa address from <b>address</b>.  Return 0
 * if this is not an .in-addr.arpa address or an .ip6.arpa address.  Return -1
 * if this is an ill-formed .in-addr.arpa address or an .ip6.arpa address.
 * Also return -1 if <b>family</b> is not AF_UNSPEC, and the parsed address
 * family does not match <b>family</b>.  On success, return 1, and store the
 * result, if any, into <b>result</b>, if provided.
 *
 * If <b>accept_regular</b> is set and the address is in neither recognized
 * reverse lookup hostname format, try parsing the address as a regular
 * IPv4 or IPv6 address too.
 */
int
tor_addr_parse_reverse_lookup_name(tor_addr_t *result, const char *address,
                                   int family, int accept_regular)
{
  if (!strcasecmpend(address, ".in-addr.arpa")) {
    /* We have an in-addr.arpa address. */
    char buf[INET_NTOA_BUF_LEN];
    size_t len;
    struct in_addr inaddr;
    if (family == AF_INET6)
      return -1;

    len = strlen(address) - strlen(".in-addr.arpa");
    if (len >= INET_NTOA_BUF_LEN)
      return -1; /* Too long. */

    memcpy(buf, address, len);
    buf[len] = '\0';
    if (tor_inet_aton(buf, &inaddr) == 0)
      return -1; /* malformed. */

    /* reverse the bytes */
    inaddr.s_addr = (((inaddr.s_addr & 0x000000fful) << 24)
                     |((inaddr.s_addr & 0x0000ff00ul) << 8)
                     |((inaddr.s_addr & 0x00ff0000ul) >> 8)
                     |((inaddr.s_addr & 0xff000000ul) >> 24));

    if (result) {
      tor_addr_from_in(result, &inaddr);
    }
    return 1;
  }

  if (!strcasecmpend(address, ".ip6.arpa")) {
    const char *cp;
    int i;
    int n0, n1;
    struct in6_addr in6;

    if (family == AF_INET)
      return -1;

    cp = address;
    for (i = 0; i < 16; ++i) {
      n0 = hex_decode_digit(*cp++); /* The low-order nybble appears first. */
      if (*cp++ != '.') return -1;  /* Then a dot. */
      n1 = hex_decode_digit(*cp++); /* The high-order nybble appears first. */
      if (*cp++ != '.') return -1;  /* Then another dot. */
      if (n0<0 || n1 < 0) /* Both nybbles must be hex. */
        return -1;

      /* We don't check the length of the string in here.  But that's okay,
       * since we already know that the string ends with ".ip6.arpa", and
       * there is no way to frameshift .ip6.arpa so it fits into the pattern
       * of hexdigit, period, hexdigit, period that we enforce above.
       */

      /* Assign from low-byte to high-byte. */
      in6.s6_addr[15-i] = n0 | (n1 << 4);
    }
    if (strcasecmp(cp, "ip6.arpa"))
      return -1;

    if (result) {
      tor_addr_from_in6(result, &in6);
    }
    return 1;
  }

  if (accept_regular) {
    tor_addr_t tmp;
    int r = tor_addr_from_str(&tmp, address);
    if (r < 0)
      return 0;
    if (r != family && family != AF_UNSPEC)
      return -1;

    if (result)
      memcpy(result, &tmp, sizeof(tor_addr_t));

    return 1;
  }

  return 0;
}

/** Convert <b>addr</b> to an in-addr.arpa name or a .ip6.arpa name, and store
 * the result in the <b>outlen</b>-byte buffer at <b>out</b>.  Return 0 on
 * success, -1 on failure. */
int
tor_addr_to_reverse_lookup_name(char *out, size_t outlen,
                                const tor_addr_t *addr)
{
  if (addr->family == AF_INET) {
    uint32_t a = tor_addr_to_ipv4h(addr);

    return tor_snprintf(out, outlen, "%d.%d.%d.%d.in-addr.arpa",
                        (int)(uint8_t)((a    )&0xff),
                        (int)(uint8_t)((a>>8 )&0xff),
                        (int)(uint8_t)((a>>16)&0xff),
                        (int)(uint8_t)((a>>24)&0xff));
  } else if (addr->family == AF_INET6) {
    int i;
    char *cp = out;
    const uint8_t *bytes = tor_addr_to_in6_addr8(addr);
    if (outlen < REVERSE_LOOKUP_NAME_BUF_LEN)
      return -1;
    for (i = 15; i >= 0; --i) {
      uint8_t byte = bytes[i];
      *cp++ = "0123456789abcdef"[byte & 0x0f];
      *cp++ = '.';
      *cp++ = "0123456789abcdef"[byte >> 4];
      *cp++ = '.';
    }
    memcpy(cp, "ip6.arpa", 9); /* 8 characters plus nul */
    return 0;
  }
  return -1;
}

/** Parse a string <b>s</b> containing an IPv4/IPv6 address, and possibly
 *  a mask and port or port range.  Store the parsed address in
 *  <b>addr_out</b>, a mask (if any) in <b>mask_out</b>, and port(s) (if any)
 *  in <b>port_min_out</b> and <b>port_max_out</b>.
 *
 * The syntax is:
 *   Address OptMask OptPortRange
 *   Address ::= IPv4Address / "[" IPv6Address "]" / "*"
 *   OptMask ::= "/" Integer /
 *   OptPortRange ::= ":*" / ":" Integer / ":" Integer "-" Integer /
 *
 *  - If mask, minport, or maxport are NULL, we do not want these
 *    options to be set; treat them as an error if present.
 *  - If the string has no mask, the mask is set to /32 (IPv4) or /128 (IPv6).
 *  - If the string has one port, it is placed in both min and max port
 *    variables.
 *  - If the string has no port(s), port_(min|max)_out are set to 1 and 65535.
 *
 *  Return an address family on success, or -1 if an invalid address string is
 *  provided.
 */
int tor_addr_parse_mask_ports(const char *s, tor_addr_t *addr_out,maskbits_t *maskbits_out,uint16_t *port_min_out, uint16_t *port_max_out)
{	char *base = NULL, *address, *mask = NULL, *port = NULL, *rbracket = NULL;
	char *endptr;
	char *esc_l;
	int any_flag=0, v4map=0;
	int r = 0;
	sa_family_t family = AF_UNSPEC;
	struct in6_addr in6_tmp;
	struct in_addr in_tmp;
	tor_assert(s);
	tor_assert(addr_out);

  /* IP, [], /mask, ports */
#define MAX_ADDRESS_LENGTH (TOR_ADDR_BUF_LEN+2+(1+INET_NTOA_BUF_LEN)+12+1)

	if(strlen(s) > MAX_ADDRESS_LENGTH)
	{	esc_l = esc_for_log(s);
		log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_IP_TOO_LONG),esc_l);
		tor_free(esc_l);
		return -1;
	}
	base = tor_strdup(s);
	/* Break 'base' into separate strings. */
	address = base;
	if(*address == '[')	/* Probably IPv6 */
	{	address++;
		rbracket = strchr(address, ']');
		if(!rbracket)
		{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_IPV6));
			r = -1;
		}
	}
	if(!r)
	{	mask = strchr((rbracket?rbracket:address),'/');
		port = strchr((mask?mask:(rbracket?rbracket:address)), ':');
		if(port)		*port++ = '\0';
		if(mask)		*mask++ = '\0';
		if(rbracket)		*rbracket = '\0';
		if(port && mask)	tor_assert(port > mask);
		if(mask && rbracket)	tor_assert(mask > rbracket);
		/* Now "address" is the a.b.c.d|'*'|abcd::1 part... "mask" is the Mask|Maskbits part... and "port" is the *|port|min-max part. */
		/* Process the address portion */
		memset(addr_out, 0, sizeof(tor_addr_t));

		if(!strcmp(address, "*"))
		{	family = AF_INET; /* AF_UNSPEC ???? XXXX_IP6 */
			tor_addr_from_ipv4h(addr_out, 0);
			any_flag = 1;
		}
		else if(tor_inet_pton(AF_INET6, address, &in6_tmp) > 0)
		{	family = AF_INET6;
			tor_addr_from_in6(addr_out, &in6_tmp);
		}
		else if(tor_inet_pton(AF_INET, address, &in_tmp) > 0)
		{	family = AF_INET;
			tor_addr_from_in(addr_out, &in_tmp);
		}
		else
		{	esc_l = esc_for_log(address);
			log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_IP),esc_l);
			tor_free(esc_l);
			r = -1;
		}
		v4map = tor_addr_is_v4(addr_out);

		/* Parse mask */
		if(!r)
		{	if(maskbits_out)
			{	int bits = 0;
				struct in_addr v4mask;
				if(mask)	/* the caller (tried to) specify a mask */
				{	bits = (int) strtol(mask, &endptr, 10);
					if(!*endptr)	/* strtol converted everything, so it was an integer */
					{	if((bits<0 || bits>128) || (family == AF_INET && bits > 32))
						{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_BIT_MASK),bits);
							r = -1;
						}
					}
					else	/* mask might still be an address-style mask */
					{	if(tor_inet_pton(AF_INET, mask, &v4mask) > 0)
						{	bits = addr_mask_get_bits(ntohl(v4mask.s_addr));
							if(bits < 0)
							{	esc_l = esc_for_log(mask);
								log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_IPV4_MASK),esc_l);
								tor_free(esc_l);
								r = -1;
							}
						}
						else	/* Not IPv4; we don't do address-style IPv6 masks. */
						{	esc_l = esc_for_log(s);
							log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK),esc_l);
							tor_free(esc_l);
							r = -1;
						}
					}
					if(family == AF_INET6 && v4map)
					{	if(bits > 32 && bits < 96)	/* Crazy */
						{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK_2),bits);
							r = -1;
						}
						/* XXXX_IP6 is this really what we want? */
						else	bits = 96 + bits%32;	/* map v4-mapped masks onto 96-128 bits */
					}
				}
				else	/* pick an appropriate mask, as none was given */
				{	if(any_flag)					bits = 0;  /* This is okay whether it's V6 or V4 (FIX V4-mapped V6!) */
					else if(tor_addr_family(addr_out) == AF_INET)	bits = 32;
					else if(tor_addr_family(addr_out) == AF_INET6)	bits = 128;
				}
				*maskbits_out = (maskbits_t) bits;
			}
			else
			{	if(mask)
				{	esc_l = esc_for_log(s);
					log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK_3),esc_l);
					tor_free(esc_l);
					r = -1;
				}
			}

			if(!r)
			{	/* Parse port(s) */
				if(port_min_out)
				{	uint16_t port2;
					if(!port_max_out) /* caller specified one port; fake the second one */
						port_max_out = &port2;
					if(parse_port_range(port, port_min_out, port_max_out) < 0)
						r = -1;
					else if((*port_min_out != *port_max_out) && port_max_out == &port2)
					{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK_4));
						port_max_out = NULL;  /* caller specified one port, so set this back */
						r = -1;
					}
				}
				else
				{	if(port)
					{	esc_l = esc_for_log(s);
						log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_PORT),esc_l);
						tor_free(esc_l);
						r = -1;
					}
				}
			}
		}
	}
	tor_free(base);
 	if(!r)	return tor_addr_family(addr_out);
	return -1;
}

/** Determine whether an address is IPv4, either native or ipv4-mapped ipv6.
 * Note that this is about representation only, as any decent stack will
 * reject ipv4-mapped addresses received on the wire (and won't use them
 * on the wire either).
 */
int
tor_addr_is_v4(const tor_addr_t *addr)
{
  tor_assert(addr);

  if (tor_addr_family(addr) == AF_INET)
    return 1;

  if (tor_addr_family(addr) == AF_INET6) {
    /* First two don't need to be ordered */
    uint32_t *a32 = tor_addr_to_in6_addr32(addr);
    if (a32[0] == 0 && a32[1] == 0 && ntohl(a32[2]) == 0x0000ffffu)
      return 1;
  }

  return 0; /* Not IPv4 - unknown family or a full-blood IPv6 address */
}

/** Determine whether an address <b>addr</b> is null, either all zeroes or
 *  belonging to family AF_UNSPEC.
 */
int
tor_addr_is_null(const tor_addr_t *addr)
{
  tor_assert(addr);

  switch (tor_addr_family(addr)) {
    case AF_INET6: {
      uint32_t *a32 = tor_addr_to_in6_addr32(addr);
      return (a32[0] == 0) && (a32[1] == 0) && (a32[2] == 0) && (a32[3] == 0);
    }
    case AF_INET:
      return (tor_addr_to_ipv4n(addr) == 0);
    case AF_UNSPEC:
      return 1;
    default:
      log_warn(LD_BUG,get_lang_str(LANG_LOG_ADDRESS_INVALID_AF),(int)tor_addr_family(addr));
      return 0;
  }
  //return 1;
}

/** Return true iff <b>addr</b> is a loopback address */
int
tor_addr_is_loopback(const tor_addr_t *addr)
{
  tor_assert(addr);
  switch (tor_addr_family(addr)) {
    case AF_INET6: {
      /* ::1 */
      uint32_t *a32 = tor_addr_to_in6_addr32(addr);
      return (a32[0] == 0) && (a32[1] == 0) && (a32[2] == 0) && (a32[3] == 1);
    }
    case AF_INET:
      /* 127.0.0.1 */
      return (tor_addr_to_ipv4h(addr) & 0xff000000) == 0x7f000000;
    case AF_UNSPEC:
      return 0;
    default:
      tor_fragile_assert();
      return 0;
  }
}

/** Set <b>dest</b> to equal the IPv4 address in <b>v4addr</b> (given in
 * network order. */
void
tor_addr_from_ipv4n(tor_addr_t *dest, uint32_t v4addr)
{
  tor_assert(dest);
  memset(dest, 0, sizeof(tor_addr_t));
  dest->family = AF_INET;
  dest->addr.in_addr.s_addr = v4addr;
}

/** Set <b>dest</b> to equal the IPv6 address in the 16 bytes at
 * <b>ipv6_bytes</b>. */
void
tor_addr_from_ipv6_bytes(tor_addr_t *dest, const char *ipv6_bytes)
{
  tor_assert(dest);
  tor_assert(ipv6_bytes);
  memset(dest, 0, sizeof(tor_addr_t));
  dest->family = AF_INET6;
  memcpy(dest->addr.in6_addr.s6_addr, ipv6_bytes, 16);
}

/** Set <b>dest</b> equal to the IPv6 address in the in6_addr <b>in6</b>. */
void
tor_addr_from_in6(tor_addr_t *dest, const struct in6_addr *in6)
{
  tor_addr_from_ipv6_bytes(dest, (const char*)in6->s6_addr);
}

/** Copy a tor_addr_t from <b>src</b> to <b>dest</b>.
 */
void
tor_addr_copy(tor_addr_t *dest, const tor_addr_t *src)
{
	if(src == dest)	return;
	tor_assert(src);
	tor_assert(dest);
	memcpy(dest, src, sizeof(tor_addr_t));
}

/** Given two addresses <b>addr1</b> and <b>addr2</b>, return 0 if the two
 * addresses are equivalent under the mask mbits, less than 0 if addr1
 * preceeds addr2, and greater than 0 otherwise.
 *
 * Different address families (IPv4 vs IPv6) are always considered unequal if
 * <b>how</b> is CMP_EXACT; otherwise, IPv6-mapped IPv4 addresses are
 * cosidered equivalent to their IPv4 equivalents.
 */
int
tor_addr_compare(const tor_addr_t *addr1, const tor_addr_t *addr2,
                 tor_addr_comparison_t how)
{
  return tor_addr_compare_masked(addr1, addr2, 128, how);
}

/** As tor_addr_compare(), but only looks at the first <b>mask</b> bits of
 * the address.
 *
 * Reduce over-specific masks (>128 for ipv6, >32 for ipv4) to 128 or 32.
 *
 * The mask is interpreted relative to <b>addr1</b>, so that if a is
 * ::ffff:1.2.3.4, and b is 3.4.5.6,
 * tor_addr_compare_masked(a,b,100,CMP_SEMANTIC) is the same as
 * -tor_addr_compare_masked(b,a,4,CMP_SEMANTIC).
 *
 * We guarantee that the ordering from tor_addr_compare_masked is a total
 * order on addresses, but not that it is any particular order, or that it
 * will be the same from one version to the next.
 */
int
tor_addr_compare_masked(const tor_addr_t *addr1, const tor_addr_t *addr2,
                        maskbits_t mbits, tor_addr_comparison_t how)
{
#define TRISTATE(a,b) (((a)<(b))?-1: (((a)==(b))?0:1))
  sa_family_t family1, family2, v_family1, v_family2;

  tor_assert(addr1 && addr2);

  v_family1 = family1 = tor_addr_family(addr1);
  v_family2 = family2 = tor_addr_family(addr2);

  if (family1==family2) {
    /* When the families are the same, there's only one way to do the
     * comparison: exactly. */
    int r;
    switch (family1) {
      case AF_UNSPEC:
        return 0; /* All unspecified addresses are equal */
      case AF_INET: {
        uint32_t a1 = tor_addr_to_ipv4h(addr1);
        uint32_t a2 = tor_addr_to_ipv4h(addr2);
        if (mbits <= 0)
          return 0;
        if (mbits > 32)
          mbits = 32;
        a1 >>= (32-mbits);
        a2 >>= (32-mbits);
        r = TRISTATE(a1, a2);
        return r;
      }
      case AF_INET6: {
        const uint8_t *a1 = tor_addr_to_in6_addr8(addr1);
        const uint8_t *a2 = tor_addr_to_in6_addr8(addr2);
        const int bytes = mbits >> 3;
        const int leftover_bits = mbits & 7;
        if (bytes && (r = tor_memcmp(a1, a2, bytes))) {
          return r;
        } else if (leftover_bits) {
          uint8_t b1 = a1[bytes] >> (8-leftover_bits);
          uint8_t b2 = a2[bytes] >> (8-leftover_bits);
          return TRISTATE(b1, b2);
        } else {
          return 0;
        }
      }
      default:
        tor_fragile_assert();
        return 0;
    }
  } else if (how == CMP_EXACT) {
    /* Unequal families and an exact comparison?  Stop now! */
    return TRISTATE(family1, family2);
  }

  if (mbits == 0)
    return 0;

  if (family1 == AF_INET6 && tor_addr_is_v4(addr1))
    v_family1 = AF_INET;
  if (family2 == AF_INET6 && tor_addr_is_v4(addr2))
    v_family2 = AF_INET;
  if (v_family1 == v_family2) {
    /* One or both addresses are a mapped ipv4 address. */
    uint32_t a1, a2;
    if (family1 == AF_INET6) {
      a1 = tor_addr_to_mapped_ipv4h(addr1);
      if (mbits <= 96)
        return 0;
      mbits -= 96; /* We just decided that the first 96 bits of a1 "match". */
    } else {
      a1 = tor_addr_to_ipv4h(addr1);
    }
    if (family2 == AF_INET6) {
      a2 = tor_addr_to_mapped_ipv4h(addr2);
    } else {
      a2 = tor_addr_to_ipv4h(addr2);
    }
    if (mbits <= 0) return 0;
    if (mbits > 32) mbits = 32;
    a1 >>= (32-mbits);
    a2 >>= (32-mbits);
    return TRISTATE(a1, a2);
  } else {
    /* Unequal families, and semantic comparison, and no semantic family
     * matches. */
    return TRISTATE(family1, family2);
  }
}

/** Return a hash code based on the address addr */
unsigned int
tor_addr_hash(const tor_addr_t *addr)
{
  switch (tor_addr_family(addr)) {
  case AF_INET:
    return tor_addr_to_ipv4h(addr);
  case AF_UNSPEC:
    return 0x4e4d5342;
  case AF_INET6: {
    const uint32_t *u = tor_addr_to_in6_addr32(addr);
    return u[0] + u[1] + u[2] + u[3];
    }
  default:
    tor_fragile_assert();
    return 0;
  }
}

/** Return a newly allocated string with a representation of <b>addr</b>. */
char *tor_dup_addr(const tor_addr_t *addr)
{	char buf[TOR_ADDR_BUF_LEN];
	if(tor_addr_to_str(buf, addr, sizeof(buf), 0))
		return tor_strdup(buf);
	return tor_strdup("<unknown address type>");
}

/** Return a string representing the address <b>addr</b>.  This string is statically allocated, and must not be freed.  Each call to <b>fmt_addr</b> invalidates the last result of the function. This function is not thread-safe. */
const char *fmt_addr(const tor_addr_t *addr)
{	static char buf[TOR_ADDR_BUF_LEN];
	if(!addr)	return "<null>";
	if(!tor_addr_to_str(buf, addr, sizeof(buf), 0))
		return "???";
	return buf;
}

/** Convert the string in <b>src</b> to a tor_addr_t <b>addr</b>.  The string
 * may be an IPv4 address, an IPv6 address, or an IPv6 address surrounded by
 * square brackets.
 *
 *  Return an address family on success, or -1 if an invalid address string is
 *  provided. */
int
tor_addr_from_str(tor_addr_t *addr, const char *src)
{
  char *tmp = NULL; /* Holds substring if we got a dotted quad. */
  int result;
  struct in_addr in_tmp;
  struct in6_addr in6_tmp;
  tor_assert(addr && src);
  if (src[0] == '[' && src[1])
    src = tmp = tor_strndup(src+1, strlen(src)-2);

  if (tor_inet_pton(AF_INET6, src, &in6_tmp) > 0) {
    result = AF_INET6;
    tor_addr_from_in6(addr, &in6_tmp);
  } else if (tor_inet_pton(AF_INET, src, &in_tmp) > 0) {
    result = AF_INET;
    tor_addr_from_in(addr, &in_tmp);
  } else {
    result = -1;
  }

  tor_free(tmp);
  return result;
}

/** Parse an address or address-port combination from <b>s</b>, resolve the
 * address as needed, and put the result in <b>addr_out</b> and (optionally)
 * <b>port_out</b>.  Return 0 on success, negative on failure. */
int tor_addr_port_parse(const char *s, tor_addr_t *addr_out, uint16_t *port_out)
{	const char *port;
	tor_addr_t addr;
	uint16_t portval;
	char *tmp = NULL;
	tor_assert(s);
	tor_assert(addr_out);

	s = eat_whitespace(s);
	if(*s == '[')
	{	port = strstr(s, "]");
		if(!port)
			return -1;
		else
		{	tmp = tor_strndup(s+1, port-(s+1));
			port = port+1;
			if(*port == ':')	port++;
			else			port = NULL;
		}
	}
	else
	{	port = strchr(s, ':');
		if(port)	tmp = tor_strndup(s, port-s);
		else		tmp = tor_strdup(s);
		if(port)	++port;
	}
	if(tor_addr_lookup(tmp, AF_UNSPEC, &addr) == 0)
	{	tor_free(tmp);
		if(port)
		{	portval = (int) tor_parse_long(port, 10, 1, 65535, NULL, NULL);
			if(!portval)
				return -1;
		}
		else	portval = 0;
		if(port_out)	*port_out = portval;
		tor_addr_copy(addr_out, &addr);
		return 0;
	}
	tor_free(tmp);
	return -1;
}

/** Set *<b>addr</b> to the IP address (if any) of whatever interface
 * connects to the internet.  This address should only be used in checking
 * whether our address has changed.  Return 0 on success, -1 on failure.
 */
int get_interface_address6(int severity, sa_family_t family, tor_addr_t *addr)
{	int sock=-1, r=-1;
	struct sockaddr_storage my_addr, target_addr;
	socklen_t addr_len;
	tor_assert(addr);

	memset(addr, 0, sizeof(tor_addr_t));
	/* Don't worry: no packets are sent. We just need to use a real address on the actual internet. */
	if(family == AF_INET6)
	{	struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&target_addr;
		sin6->sin6_port = htons(9);	/* Use the "discard" service port */
		sock = tor_open_socket(PF_INET6,SOCK_DGRAM,IPPROTO_UDP);
		addr_len = (socklen_t)sizeof(struct sockaddr_in6);
		sin6->sin6_family = AF_INET6;
		S6_ADDR16(sin6->sin6_addr)[0] = htons(0x2002); /* 2002:: */
	}
	else if(family == AF_INET)
	{	struct sockaddr_in *sin = (struct sockaddr_in*)&target_addr;
		sin->sin_port = htons(9);	/* Use the "discard" service port */
		sock = tor_open_socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
		addr_len = (socklen_t)sizeof(struct sockaddr_in);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(0x12000001); /* 18.0.0.1 */
	}
	else	return -1;
	if(sock < 0)
	{	int e = tor_socket_errno(-1);
		log_fn(severity,LD_NET,get_lang_str(LANG_LOG_ADDRESS_ERROR_CREATING_SOCKET),tor_socket_strerror(e));
		return -1;
	}
	if(connect(sock,(struct sockaddr *)&target_addr,addr_len)<0)
	{	int e = tor_socket_errno(sock);
		log_fn(severity,LD_NET,get_lang_str(LANG_LOG_ADDRESS_CONNECT_FAILED),tor_socket_strerror(e));
	}
	else if(getsockname(sock,(struct sockaddr*)&my_addr, &addr_len))
	{	int e = tor_socket_errno(sock);
		log_fn(severity,LD_NET,get_lang_str(LANG_LOG_ADDRESS_GETSOCKNAME_FAILED),tor_socket_strerror(e));
	}
	else
	{	tor_addr_from_sockaddr(addr, (struct sockaddr*)&my_addr, NULL);
		r=0;
	}
	tor_close_socket(sock);
	return r;
}

/* ======
 * IPv4 helpers
 * XXXX022 IPv6 deprecate some of these.
 */

/** Return true iff <b>ip</b> (in host order) is an IP reserved to localhost,
 * or reserved for local networks by RFC 1918.
 */
int
is_internal_IP(uint32_t ip, int for_listening)
{
  tor_addr_t myaddr;
  myaddr.family = AF_INET;
  myaddr.addr.in_addr.s_addr = htonl(ip);

  return tor_addr_is_internal(&myaddr, for_listening);
}

/** Parse a string of the form "host[:port]" from <b>addrport</b>.  If
 * <b>address</b> is provided, set *<b>address</b> to a copy of the
 * host portion of the string.  If <b>addr</b> is provided, try to
 * resolve the host portion of the string and store it into
 * *<b>addr</b> (in host byte order).  If <b>port_out</b> is provided,
 * store the port number into *<b>port_out</b>, or 0 if no port is given.
 * If <b>port_out</b> is NULL, then there must be no port number in
 * <b>addrport</b>.
 * Return 0 on success, -1 on failure.
 */
int
parse_addr_port(int severity, const char *addrport, char **address,
                uint32_t *addr, uint16_t *port_out)
{
  const char *colon;
  char *_address = NULL;
  int _port;
  int ok = 1;

  tor_assert(addrport);

  colon = strchr(addrport, ':');
  if (colon) {
    _address = tor_strndup(addrport, colon-addrport);
    _port = (int) tor_parse_long(colon+1,10,1,65535,NULL,NULL);
    if (!_port) {
      char *esc_l = esc_for_log(colon+1);
      log_fn(severity,LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_PORT_2),esc_l);
      tor_free(esc_l);
      ok = 0;
    }
    if (!port_out) {
      char *esc_addrport = esc_for_log(addrport);
      char *esc_l = esc_for_log(colon+1);
      log_fn(severity,LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_UNEXPECTED_PORT),esc_l,esc_addrport);
      tor_free(esc_addrport);
      tor_free(esc_l);
      ok = 0;
    }
  } else {
    _address = tor_strdup(addrport);
    _port = 0;
  }

  if (addr) {
    /* There's an addr pointer, so we need to resolve the hostname. */
    if (tor_lookup_hostname(_address,addr)) {
      char *esc_l = esc_for_log(_address);
      log_fn(severity,LD_NET,get_lang_str(LANG_LOG_ADDRESS_LOOKUP_ERROR),esc_l);
      tor_free(esc_l);
      ok = 0;
      *addr = 0;
    }
  }

  if (address && ok) {
    *address = _address;
  } else {
    if (address)
      *address = NULL;
    tor_free(_address);
  }
  if (port_out)
    *port_out = ok ? ((uint16_t) _port) : 0;

  return ok ? 0 : -1;
}

/** If <b>mask</b> is an address mask for a bit-prefix, return the number of
 * bits.  Otherwise, return -1. */
int
addr_mask_get_bits(uint32_t mask)
{
  int i;
  if (mask == 0)
    return 0;
  if (mask == 0xFFFFFFFFu)
    return 32;
  for (i=0; i<=32; ++i) {
    if (mask == (uint32_t) ~((1u<<(32-i))-1)) {
      return i;
    }
  }
  return -1;
}

/** Compare two addresses <b>a1</b> and <b>a2</b> for equality under a
 * netmask of <b>mbits</b> bits.  Return -1, 0, or 1.
 *
 * XXXX_IP6 Temporary function to allow masks as bitcounts everywhere.  This
 * will be replaced with an IPv6-aware version as soon as 32-bit addresses are
 * no longer passed around.
 */
int
addr_mask_cmp_bits(uint32_t a1, uint32_t a2, maskbits_t bits)
{
  if (bits > 32)
    bits = 32;
  else if (bits == 0)
    return 0;

  a1 >>= (32-bits);
  a2 >>= (32-bits);

  if (a1 < a2)
    return -1;
  else if (a1 > a2)
    return 1;
  else
    return 0;
}

/** Parse a string <b>s</b> in the format of (*|port(-maxport)?)?, setting the
 * various *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_port_range(const char *port, uint16_t *port_min_out,
                 uint16_t *port_max_out)
{
  int port_min, port_max, ok;
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  if (!port || *port == '\0' || strcmp(port, "*") == 0) {
    port_min = 1;
    port_max = 65535;
  } else {
    char *endptr = NULL;
    char *esc_l;
    port_min = (int)tor_parse_long(port, 10, 0, 65535, &ok, &endptr);
    if (!ok) {
      esc_l = esc_for_log(port);
      log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_PORT_3),esc_l);
      tor_free(esc_l);
      return -1;
    } else if (endptr && *endptr == '-') {
      port = endptr+1;
      endptr = NULL;
      port_max = (int)tor_parse_long(port, 10, 1, 65536, &ok, &endptr);
      if (!ok) {
        esc_l = esc_for_log(port);
        log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_PORT_3),esc_l);
	tor_free(esc_l);
        return -1;
      }
    } else {
      port_max = port_min;
    }
    if (port_min > port_max) {
      log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_PORT_RANGE));
      return -1;
    }
  }

  if (port_min < 1)
    port_min = 1;
  if (port_max > 65535)
    port_max = 65535;

  *port_min_out = (uint16_t) port_min;
  *port_max_out = (uint16_t) port_max;

  return 0;
}

/** Parse a string <b>s</b> in the format of
 * (IP(/mask|/mask-bits)?|*)(:(*|port(-maxport))?)?, setting the various
 * *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,maskbits_t *maskbits_out, uint16_t *port_min_out,uint16_t *port_max_out)
{	char *address;
	char *mask, *port, *endptr,*esc_l;
	struct in_addr in;
	int bits;
	int r = 0;
	tor_assert(s);
	tor_assert(addr_out);
	tor_assert(maskbits_out);
	tor_assert(port_min_out);
	tor_assert(port_max_out);

	address = tor_strdup(s);
	/* Break 'address' into separate strings. */
	mask = strchr(address,'/');
	port = strchr(mask?mask:address,':');
	if(mask)	*mask++ = '\0';
	if(port)	*port++ = '\0';
	/* Now "address" is the IP|'*' part... "mask" is the Mask|Maskbits part... and "port" is the *|port|min-max part. */
	if(strcmp(address,"*")==0)			*addr_out = 0;
	else if(tor_inet_aton(address, &in) != 0)	*addr_out = ntohl(in.s_addr);
	else
	{	esc_l = esc_for_log(address);
		log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_IP),esc_l);
		tor_free(esc_l);
		r = -1;
	}
	if(!r)
	{	if(!mask)
		{	if(strcmp(address,"*")==0)	*maskbits_out = 0;
			else				*maskbits_out = 32;
		}
		else
		{	endptr = NULL;
			bits = (int) strtol(mask, &endptr, 10);
			if(!*endptr)	/* strtol handled the whole mask. */
			{	if(bits < 0 || bits > 32)
				{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_BIT_MASK_2));
					r = -1;
				}
				else *maskbits_out = bits;
			}
			else if(tor_inet_aton(mask, &in) != 0)
			{	bits = addr_mask_get_bits(ntohl(in.s_addr));
				if(bits < 0)
				{	esc_l = esc_for_log(mask);
					log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK_5),esc_l);
					tor_free(esc_l);
					r = -1;
				}
				else *maskbits_out = bits;
			}
			else
			{	esc_l = esc_for_log(mask);
				log_warn(LD_GENERAL,get_lang_str(LANG_LOG_ADDRESS_INVALID_MASK_6),esc_l);
				tor_free(esc_l);
				r = -1;
			}
		}
		if(!r && parse_port_range(port, port_min_out, port_max_out)<0)
			r = -1;
	}
	tor_free(address);
	return r;
}

/** Given an IPv4 in_addr struct *<b>in</b> (in network order, as usual),
 *  write it as a string into the <b>buf_len</b>-byte buffer in
 *  <b>buf</b>.
 */
int
tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len)
{
  uint32_t a = ntohl(in->s_addr);
  return tor_snprintf(buf, buf_len, "%d.%d.%d.%d",
                      (int)(uint8_t)((a>>24)&0xff),
                      (int)(uint8_t)((a>>16)&0xff),
                      (int)(uint8_t)((a>>8 )&0xff),
                      (int)(uint8_t)((a    )&0xff));
}

/** Given a host-order <b>addr</b>, call tor_inet_ntop() on it
 *  and return a strdup of the resulting address.
 */
char *
tor_dup_ip(uint32_t addr)
{
  char buf[TOR_ADDR_BUF_LEN];
  struct in_addr in;

  in.s_addr = htonl(addr);
  tor_inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return tor_strdup(buf);
}

/**
 * Set *<b>addr</b> to the host-order IPv4 address (if any) of whatever
 * interface connects to the internet.  This address should only be used in
 * checking whether our address has changed.  Return 0 on success, -1 on
 * failure.
 */
int
get_interface_address(int severity, uint32_t *addr)
{
  tor_addr_t local_addr;
  int r;

  r = get_interface_address6(severity, AF_INET, &local_addr);
  if (r>=0)
    *addr = tor_addr_to_ipv4h(&local_addr);
  return r;
}
