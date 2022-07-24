/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file config.h
 * \brief Header file for config.c.
 **/

#ifndef _TOR_CONFIG_H
#define _TOR_CONFIG_H

const char *get_dirportfrontpage(void);
or_options_t *get_options(void);
int set_options(or_options_t *new_val, unsigned char **msg);
void config_free_all(void);
const char *safe_str_client(const char *address);
const char *safe_str(const char *address);
char *escaped_safe_str_client(const char *address);
char *escaped_safe_str(const char *address);
const char *get_version(void);
const char *get_winver(void);

int config_get_lines(const char *string, config_line_t **result);
void config_free_lines(config_line_t *front);
setopt_err_t options_trial_assign(config_line_t *list, int use_defaults,
                                  int clear_first, unsigned char **msg);
int resolve_my_address(int warn_severity, or_options_t *options,
                       uint32_t *addr, char **hostname_out);
int is_local_addr(const tor_addr_t *addr) ATTR_PURE;
void options_init(or_options_t *options);
char *options_dump(or_options_t *options, int minimal);
int options_init_from_torrc(int argc, char **argv);
setopt_err_t options_init_from_string(const char *cf,
                            int command, const char *command_arg, unsigned char **msg) __attribute__ ((format(printf, 1, 0)));
int option_is_recognized(const char *key);
const char *option_get_canonical_name(const char *key);
config_line_t *option_get_assignment(or_options_t *options,
                                     const char *key) __attribute__ ((format(printf, 2, 0)));
int options_save_current(void);
const char *get_torrc_fname(void);

or_state_t *get_or_state(void);
int did_last_state_file_write_fail(void);
int or_state_save(time_t now);

int options_need_geoip_info(or_options_t *options, const char **reason_out);
int getinfo_helper_config(control_connection_t *conn,
                          const char *question, char **answer,
                          const char **errmsg);

const char *tor_get_digests(void);
uint32_t get_effective_bwrate(or_options_t *options);
uint32_t get_effective_bwburst(or_options_t *options);
int parse_dir_server_line(const char *line,authority_type_t required_type,int validate_only);
int parse_bridge_line(const char *line, int validate_only);
void config_register_addressmaps(or_options_t *options);

#ifdef CONFIG_PRIVATE
/* Used only by config.c and test.c */
or_options_t *options_new(void);
#endif

#endif

