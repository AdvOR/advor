/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file directory.h
 * \brief Header file for directory.c.
 **/

#ifndef _TOR_DIRECTORY_H
#define _TOR_DIRECTORY_H

int directories_have_accepted_server_descriptor(void);
char *authority_type_to_string(authority_type_t auth);
void directory_post_to_dirservers(uint8_t dir_purpose, uint8_t router_purpose,
                                  authority_type_t type, const char *payload,
                                  size_t payload_len, size_t extrainfo_len) __attribute__ ((format(printf, 4, 0)));
void directory_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                                  const char *resource,
                                  int pds_flags);
void directory_get_from_all_authorities(uint8_t dir_purpose,
                                        uint8_t router_purpose,
                                        const char *resource) __attribute__ ((format(printf, 3, 0)));
void directory_initiate_command_routerstatus(routerstatus_t *status,
                                             uint8_t dir_purpose,
                                             uint8_t router_purpose,
                                             int anonymized_connection,
                                             const char *resource,
                                             const char *payload,
                                             size_t payload_len,
                                             time_t if_modified_since);
void directory_initiate_command_routerstatus_rend(routerstatus_t *status,
                                                  uint8_t dir_purpose,
                                                  uint8_t router_purpose,
                                                  int anonymized_connection,
                                                  const char *resource,
                                                  const char *payload,
                                                  size_t payload_len,
                                                  time_t if_modified_since,
                                                const rend_data_t *rend_query) __attribute__ ((format(printf, 5, 0)));

int parse_http_response(const char *headers, int *code, time_t *date,
                        compress_method_t *compression, char **response);

int connection_dir_is_encrypted(dir_connection_t *conn);
int connection_dir_reached_eof(dir_connection_t *conn);
int connection_dir_process_inbuf(dir_connection_t *conn);
int connection_dir_finished_flushing(dir_connection_t *conn);
int connection_dir_finished_connecting(dir_connection_t *conn);
void connection_dir_request_failed(dir_connection_t *conn);
void directory_initiate_command(const char *address, const tor_addr_t *addr,
                                uint16_t or_port, uint16_t dir_port,
                                int supports_conditional_consensus,
                                int supports_begindir, const char *digest,
                                uint8_t dir_purpose, uint8_t router_purpose,
                                int anonymized_connection,
                                const char *resource,
                                const char *payload, size_t payload_len,
                                time_t if_modified_since) __attribute__ ((format(printf, 1, 0)));

#define DSR_HEX       (1<<0)
#define DSR_BASE64    (1<<1)
#define DSR_DIGEST256 (1<<2)
#define DSR_SORT_UNIQ (1<<3)
int dir_split_resource_into_fingerprints(const char *resource,
                                     smartlist_t *fp_out, int *compressed_out,
                                     int flags);

int dir_split_resource_into_fingerprint_pairs(const char *res,
                                              smartlist_t *pairs_out);
char *directory_dump_request_log(void);
void note_request(const char *key, size_t bytes);
int router_supports_extrainfo(const char *identity_digest, int is_authority);

time_t download_status_increment_failure(download_status_t *dls,
                                         int status_code, const char *item,
                                         int server, time_t now);
/** Increment the failure count of the download_status_t <b>dls</b>, with
 * the optional status code <b>sc</b>. */
#define download_status_failed(dls, sc)                                 \
  download_status_increment_failure((dls), (sc), NULL,                  \
                                    get_options()->DirPort, get_time(NULL))

void download_status_reset(download_status_t *dls);
static int download_status_is_ready(download_status_t *dls, time_t now,
                                    int max_failures);
/** Return true iff, as of <b>now</b>, the resource tracked by <b>dls</b> is
 * ready to get its download reattempted. */
static INLINE int
download_status_is_ready(download_status_t *dls, time_t now,
                         int max_failures)
{
  return (dls->n_download_failures <= max_failures
          && dls->next_attempt_at <= now);
}

static void download_status_mark_impossible(download_status_t *dl);
/** Mark <b>dl</b> as never downloadable. */
static INLINE void
download_status_mark_impossible(download_status_t *dl)
{
  dl->n_download_failures = IMPOSSIBLE_TO_DOWNLOAD;
}

int download_status_get_n_failures(const download_status_t *dls);
const char *dir_conn_purpose_to_string(int purpose);

#endif

