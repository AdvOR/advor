/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hibernate.h
 * \brief Header file for hibernate.c.
 **/

#ifndef _TOR_HIBERNATE_H
#define _TOR_HIBERNATE_H

int accounting_parse_options(or_options_t *options, int validate_only);
int accounting_is_enabled(or_options_t *options);
void configure_accounting(time_t now);
void accounting_run_housekeeping(time_t now);
void accounting_add_bytes(size_t n_read, size_t n_written, int seconds);
int accounting_record_bandwidth_usage(time_t now, or_state_t *state);
void hibernate_begin_shutdown(void);
int we_are_hibernating(void);
void consider_hibernation(time_t now);
int getinfo_helper_accounting(control_connection_t *conn,
                              const char *question, char **answer,
                              const char **errmsg);
void hibernate_go_dormant(time_t now);
void hibernate_end_time_elapsed(time_t now);

#endif

