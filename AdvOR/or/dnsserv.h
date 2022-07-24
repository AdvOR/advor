/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dnsserv.h
 * \brief Header file for dnsserv.c.
 **/

#ifndef _TOR_DNSSERV_H
#define _TOR_DNSSERV_H

void dnsserv_configure_listener(connection_t *conn);
void dnsserv_close_listener(connection_t *conn);
void dnsserv_resolved(edge_connection_t *conn,
                      int answer_type,
                      size_t answer_len,
                      const char *answer,
                      int ttl);
void dnsserv_reject_request(edge_connection_t *conn);
int dnsserv_launch_request(const char *name, int is_reverse);

#endif

