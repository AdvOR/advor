/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_TORTLS_H
#define _TOR_TORTLS_H

/**
 * \file tortls.h
 * \brief Headers for tortls.c
 **/

//#include "crypto.h"
//#include "compat.h"

/* Opaque structure to hold a TLS connection. */
typedef struct tor_tls_t tor_tls_t;

/* Possible return values for most tor_tls_* functions. */
#define _MIN_TOR_TLS_ERROR_VAL     -9
#define TOR_TLS_ERROR_MISC         -9
/* Rename to unexpected close or something. XXXX */
#define TOR_TLS_ERROR_IO           -8
#define TOR_TLS_ERROR_CONNREFUSED  -7
#define TOR_TLS_ERROR_CONNRESET    -6
#define TOR_TLS_ERROR_NO_ROUTE     -5
#define TOR_TLS_ERROR_TIMEOUT      -4
#define TOR_TLS_CLOSE              -3
#define TOR_TLS_WANTREAD           -2
#define TOR_TLS_WANTWRITE          -1
#define TOR_TLS_DONE                0

/** Collection of case statements for all TLS errors that are not due to
 * underlying IO failure. */
#define CASE_TOR_TLS_ERROR_ANY_NONIO            \
  case TOR_TLS_ERROR_MISC:                      \
  case TOR_TLS_ERROR_CONNREFUSED:               \
  case TOR_TLS_ERROR_CONNRESET:                 \
  case TOR_TLS_ERROR_NO_ROUTE:                  \
  case TOR_TLS_ERROR_TIMEOUT

/** Use this macro in a switch statement to catch _any_ TLS error.  That way,
 * if more errors are added, your switches will still work. */
#define CASE_TOR_TLS_ERROR_ANY                  \
  CASE_TOR_TLS_ERROR_ANY_NONIO:                 \
  case TOR_TLS_ERROR_IO

#define TOR_TLS_IS_ERROR(rv) ((rv) < TOR_TLS_CLOSE)
const char *tor_tls_err_to_string(int err);

void tor_tls_free_all(void);
int tor_tls_context_init(int is_public_server,crypto_pk_env_t *client_identity,crypto_pk_env_t *server_identity,unsigned int key_lifetime);
int tor_tls_context_init_(int is_public_server,crypto_pk_env_t *client_identity,crypto_pk_env_t *server_identity,unsigned int key_lifetime);
tor_tls_t *tor_tls_new(int sock, int is_server);
void tor_tls_set_logged_address(tor_tls_t *tls, const char *address);
void tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                      void (*cb)(tor_tls_t *, void *arg),
                                      void *arg);
int tor_tls_is_server(tor_tls_t *tls);
void tor_tls_free(tor_tls_t *tls);
int tor_tls_peer_has_cert(tor_tls_t *tls);
int tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_env_t **identity);
int tor_tls_check_lifetime(tor_tls_t *tls, int tolerance);
int tor_tls_read(tor_tls_t *tls, char *cp, size_t len);
int tor_tls_write(tor_tls_t *tls, const char *cp, size_t n);
int tor_tls_handshake(tor_tls_t *tls);
int tor_tls_renegotiate(tor_tls_t *tls);
void tor_tls_block_renegotiation(tor_tls_t *tls);
int tor_tls_shutdown(tor_tls_t *tls);
int tor_tls_get_pending_bytes(tor_tls_t *tls);
size_t tor_tls_get_forced_write_size(tor_tls_t *tls);

void tor_tls_get_n_raw_bytes(tor_tls_t *tls,
                             size_t *n_read, size_t *n_written);

void tor_tls_get_buffer_sizes(tor_tls_t *tls,
                              size_t *rbuf_capacity, size_t *rbuf_bytes,
                              size_t *wbuf_capacity, size_t *wbuf_bytes);

int tor_tls_used_v1_handshake(tor_tls_t *tls);

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define check_no_tls_errors() _check_no_tls_errors(__FILE__,__LINE__)

void _check_no_tls_errors(const char *fname, int line);

/* The main body of this file was mechanically generated with this
   perl script:

   my %keys = ();
   for $fn (@ARGV) {
       open(F, $fn);
       while (<F>) {
           next unless /^#define ((?:SSL|DTLS)\w*_ST_\w*)/;
           $keys{$1} = 1;
       }
       close(F);
   }
   for $k (sort keys %keys) {
       print "#ifdef $k\n  S($k),\n#endif\n"
   }
*/

/** Mapping from allowed value of SSL.state to the name of C macro for that
 * state.  Used for debugging an openssl connection. */
static const struct { int state; const char *name; } state_map[] = {
#define S(state) { state, #state }
#ifdef DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A
  S(DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A),
#endif
#ifdef DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B
  S(DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B),
#endif
#ifdef DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A
  S(DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A),
#endif
#ifdef DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B
  S(DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B),
#endif
#ifdef SSL23_ST_CR_SRVR_HELLO_A
  S(SSL23_ST_CR_SRVR_HELLO_A),
#endif
#ifdef SSL23_ST_CR_SRVR_HELLO_B
  S(SSL23_ST_CR_SRVR_HELLO_B),
#endif
#ifdef SSL23_ST_CW_CLNT_HELLO_A
  S(SSL23_ST_CW_CLNT_HELLO_A),
#endif
#ifdef SSL23_ST_CW_CLNT_HELLO_B
  S(SSL23_ST_CW_CLNT_HELLO_B),
#endif
#ifdef SSL23_ST_SR_CLNT_HELLO_A
  S(SSL23_ST_SR_CLNT_HELLO_A),
#endif
#ifdef SSL23_ST_SR_CLNT_HELLO_B
  S(SSL23_ST_SR_CLNT_HELLO_B),
#endif
#ifdef SSL2_ST_CLIENT_START_ENCRYPTION
  S(SSL2_ST_CLIENT_START_ENCRYPTION),
#endif
#ifdef SSL2_ST_GET_CLIENT_FINISHED_A
  S(SSL2_ST_GET_CLIENT_FINISHED_A),
#endif
#ifdef SSL2_ST_GET_CLIENT_FINISHED_B
  S(SSL2_ST_GET_CLIENT_FINISHED_B),
#endif
#ifdef SSL2_ST_GET_CLIENT_HELLO_A
  S(SSL2_ST_GET_CLIENT_HELLO_A),
#endif
#ifdef SSL2_ST_GET_CLIENT_HELLO_B
  S(SSL2_ST_GET_CLIENT_HELLO_B),
#endif
#ifdef SSL2_ST_GET_CLIENT_HELLO_C
  S(SSL2_ST_GET_CLIENT_HELLO_C),
#endif
#ifdef SSL2_ST_GET_CLIENT_MASTER_KEY_A
  S(SSL2_ST_GET_CLIENT_MASTER_KEY_A),
#endif
#ifdef SSL2_ST_GET_CLIENT_MASTER_KEY_B
  S(SSL2_ST_GET_CLIENT_MASTER_KEY_B),
#endif
#ifdef SSL2_ST_GET_SERVER_FINISHED_A
  S(SSL2_ST_GET_SERVER_FINISHED_A),
#endif
#ifdef SSL2_ST_GET_SERVER_FINISHED_B
  S(SSL2_ST_GET_SERVER_FINISHED_B),
#endif
#ifdef SSL2_ST_GET_SERVER_HELLO_A
  S(SSL2_ST_GET_SERVER_HELLO_A),
#endif
#ifdef SSL2_ST_GET_SERVER_HELLO_B
  S(SSL2_ST_GET_SERVER_HELLO_B),
#endif
#ifdef SSL2_ST_GET_SERVER_VERIFY_A
  S(SSL2_ST_GET_SERVER_VERIFY_A),
#endif
#ifdef SSL2_ST_GET_SERVER_VERIFY_B
  S(SSL2_ST_GET_SERVER_VERIFY_B),
#endif
#ifdef SSL2_ST_SEND_CLIENT_CERTIFICATE_A
  S(SSL2_ST_SEND_CLIENT_CERTIFICATE_A),
#endif
#ifdef SSL2_ST_SEND_CLIENT_CERTIFICATE_B
  S(SSL2_ST_SEND_CLIENT_CERTIFICATE_B),
#endif
#ifdef SSL2_ST_SEND_CLIENT_CERTIFICATE_C
  S(SSL2_ST_SEND_CLIENT_CERTIFICATE_C),
#endif
#ifdef SSL2_ST_SEND_CLIENT_CERTIFICATE_D
  S(SSL2_ST_SEND_CLIENT_CERTIFICATE_D),
#endif
#ifdef SSL2_ST_SEND_CLIENT_FINISHED_A
  S(SSL2_ST_SEND_CLIENT_FINISHED_A),
#endif
#ifdef SSL2_ST_SEND_CLIENT_FINISHED_B
  S(SSL2_ST_SEND_CLIENT_FINISHED_B),
#endif
#ifdef SSL2_ST_SEND_CLIENT_HELLO_A
  S(SSL2_ST_SEND_CLIENT_HELLO_A),
#endif
#ifdef SSL2_ST_SEND_CLIENT_HELLO_B
  S(SSL2_ST_SEND_CLIENT_HELLO_B),
#endif
#ifdef SSL2_ST_SEND_CLIENT_MASTER_KEY_A
  S(SSL2_ST_SEND_CLIENT_MASTER_KEY_A),
#endif
#ifdef SSL2_ST_SEND_CLIENT_MASTER_KEY_B
  S(SSL2_ST_SEND_CLIENT_MASTER_KEY_B),
#endif
#ifdef SSL2_ST_SEND_REQUEST_CERTIFICATE_A
  S(SSL2_ST_SEND_REQUEST_CERTIFICATE_A),
#endif
#ifdef SSL2_ST_SEND_REQUEST_CERTIFICATE_B
  S(SSL2_ST_SEND_REQUEST_CERTIFICATE_B),
#endif
#ifdef SSL2_ST_SEND_REQUEST_CERTIFICATE_C
  S(SSL2_ST_SEND_REQUEST_CERTIFICATE_C),
#endif
#ifdef SSL2_ST_SEND_REQUEST_CERTIFICATE_D
  S(SSL2_ST_SEND_REQUEST_CERTIFICATE_D),
#endif
#ifdef SSL2_ST_SEND_SERVER_FINISHED_A
  S(SSL2_ST_SEND_SERVER_FINISHED_A),
#endif
#ifdef SSL2_ST_SEND_SERVER_FINISHED_B
  S(SSL2_ST_SEND_SERVER_FINISHED_B),
#endif
#ifdef SSL2_ST_SEND_SERVER_HELLO_A
  S(SSL2_ST_SEND_SERVER_HELLO_A),
#endif
#ifdef SSL2_ST_SEND_SERVER_HELLO_B
  S(SSL2_ST_SEND_SERVER_HELLO_B),
#endif
#ifdef SSL2_ST_SEND_SERVER_VERIFY_A
  S(SSL2_ST_SEND_SERVER_VERIFY_A),
#endif
#ifdef SSL2_ST_SEND_SERVER_VERIFY_B
  S(SSL2_ST_SEND_SERVER_VERIFY_B),
#endif
#ifdef SSL2_ST_SEND_SERVER_VERIFY_C
  S(SSL2_ST_SEND_SERVER_VERIFY_C),
#endif
#ifdef SSL2_ST_SERVER_START_ENCRYPTION
  S(SSL2_ST_SERVER_START_ENCRYPTION),
#endif
#ifdef SSL2_ST_X509_GET_CLIENT_CERTIFICATE
  S(SSL2_ST_X509_GET_CLIENT_CERTIFICATE),
#endif
#ifdef SSL2_ST_X509_GET_SERVER_CERTIFICATE
  S(SSL2_ST_X509_GET_SERVER_CERTIFICATE),
#endif
#ifdef SSL3_ST_CR_CERT_A
  S(SSL3_ST_CR_CERT_A),
#endif
#ifdef SSL3_ST_CR_CERT_B
  S(SSL3_ST_CR_CERT_B),
#endif
#ifdef SSL3_ST_CR_CERT_REQ_A
  S(SSL3_ST_CR_CERT_REQ_A),
#endif
#ifdef SSL3_ST_CR_CERT_REQ_B
  S(SSL3_ST_CR_CERT_REQ_B),
#endif
#ifdef SSL3_ST_CR_CERT_STATUS_A
  S(SSL3_ST_CR_CERT_STATUS_A),
#endif
#ifdef SSL3_ST_CR_CERT_STATUS_B
  S(SSL3_ST_CR_CERT_STATUS_B),
#endif
#ifdef SSL3_ST_CR_CHANGE_A
  S(SSL3_ST_CR_CHANGE_A),
#endif
#ifdef SSL3_ST_CR_CHANGE_B
  S(SSL3_ST_CR_CHANGE_B),
#endif
#ifdef SSL3_ST_CR_FINISHED_A
  S(SSL3_ST_CR_FINISHED_A),
#endif
#ifdef SSL3_ST_CR_FINISHED_B
  S(SSL3_ST_CR_FINISHED_B),
#endif
#ifdef SSL3_ST_CR_KEY_EXCH_A
  S(SSL3_ST_CR_KEY_EXCH_A),
#endif
#ifdef SSL3_ST_CR_KEY_EXCH_B
  S(SSL3_ST_CR_KEY_EXCH_B),
#endif
#ifdef SSL3_ST_CR_SESSION_TICKET_A
  S(SSL3_ST_CR_SESSION_TICKET_A),
#endif
#ifdef SSL3_ST_CR_SESSION_TICKET_B
  S(SSL3_ST_CR_SESSION_TICKET_B),
#endif
#ifdef SSL3_ST_CR_SRVR_DONE_A
  S(SSL3_ST_CR_SRVR_DONE_A),
#endif
#ifdef SSL3_ST_CR_SRVR_DONE_B
  S(SSL3_ST_CR_SRVR_DONE_B),
#endif
#ifdef SSL3_ST_CR_SRVR_HELLO_A
  S(SSL3_ST_CR_SRVR_HELLO_A),
#endif
#ifdef SSL3_ST_CR_SRVR_HELLO_B
  S(SSL3_ST_CR_SRVR_HELLO_B),
#endif
#ifdef SSL3_ST_CW_CERT_A
  S(SSL3_ST_CW_CERT_A),
#endif
#ifdef SSL3_ST_CW_CERT_B
  S(SSL3_ST_CW_CERT_B),
#endif
#ifdef SSL3_ST_CW_CERT_C
  S(SSL3_ST_CW_CERT_C),
#endif
#ifdef SSL3_ST_CW_CERT_D
  S(SSL3_ST_CW_CERT_D),
#endif
#ifdef SSL3_ST_CW_CERT_VRFY_A
  S(SSL3_ST_CW_CERT_VRFY_A),
#endif
#ifdef SSL3_ST_CW_CERT_VRFY_B
  S(SSL3_ST_CW_CERT_VRFY_B),
#endif
#ifdef SSL3_ST_CW_CHANGE_A
  S(SSL3_ST_CW_CHANGE_A),
#endif
#ifdef SSL3_ST_CW_CHANGE_B
  S(SSL3_ST_CW_CHANGE_B),
#endif
#ifdef SSL3_ST_CW_CLNT_HELLO_A
  S(SSL3_ST_CW_CLNT_HELLO_A),
#endif
#ifdef SSL3_ST_CW_CLNT_HELLO_B
  S(SSL3_ST_CW_CLNT_HELLO_B),
#endif
#ifdef SSL3_ST_CW_FINISHED_A
  S(SSL3_ST_CW_FINISHED_A),
#endif
#ifdef SSL3_ST_CW_FINISHED_B
  S(SSL3_ST_CW_FINISHED_B),
#endif
#ifdef SSL3_ST_CW_FLUSH
  S(SSL3_ST_CW_FLUSH),
#endif
#ifdef SSL3_ST_CW_KEY_EXCH_A
  S(SSL3_ST_CW_KEY_EXCH_A),
#endif
#ifdef SSL3_ST_CW_KEY_EXCH_B
  S(SSL3_ST_CW_KEY_EXCH_B),
#endif
#ifdef SSL3_ST_SR_CERT_A
  S(SSL3_ST_SR_CERT_A),
#endif
#ifdef SSL3_ST_SR_CERT_B
  S(SSL3_ST_SR_CERT_B),
#endif
#ifdef SSL3_ST_SR_CERT_VRFY_A
  S(SSL3_ST_SR_CERT_VRFY_A),
#endif
#ifdef SSL3_ST_SR_CERT_VRFY_B
  S(SSL3_ST_SR_CERT_VRFY_B),
#endif
#ifdef SSL3_ST_SR_CHANGE_A
  S(SSL3_ST_SR_CHANGE_A),
#endif
#ifdef SSL3_ST_SR_CHANGE_B
  S(SSL3_ST_SR_CHANGE_B),
#endif
#ifdef SSL3_ST_SR_CLNT_HELLO_A
  S(SSL3_ST_SR_CLNT_HELLO_A),
#endif
#ifdef SSL3_ST_SR_CLNT_HELLO_B
  S(SSL3_ST_SR_CLNT_HELLO_B),
#endif
#ifdef SSL3_ST_SR_CLNT_HELLO_C
  S(SSL3_ST_SR_CLNT_HELLO_C),
#endif
#ifdef SSL3_ST_SR_FINISHED_A
  S(SSL3_ST_SR_FINISHED_A),
#endif
#ifdef SSL3_ST_SR_FINISHED_B
  S(SSL3_ST_SR_FINISHED_B),
#endif
#ifdef SSL3_ST_SR_KEY_EXCH_A
  S(SSL3_ST_SR_KEY_EXCH_A),
#endif
#ifdef SSL3_ST_SR_KEY_EXCH_B
  S(SSL3_ST_SR_KEY_EXCH_B),
#endif
#ifdef SSL3_ST_SW_CERT_A
  S(SSL3_ST_SW_CERT_A),
#endif
#ifdef SSL3_ST_SW_CERT_B
  S(SSL3_ST_SW_CERT_B),
#endif
#ifdef SSL3_ST_SW_CERT_REQ_A
  S(SSL3_ST_SW_CERT_REQ_A),
#endif
#ifdef SSL3_ST_SW_CERT_REQ_B
  S(SSL3_ST_SW_CERT_REQ_B),
#endif
#ifdef SSL3_ST_SW_CERT_STATUS_A
  S(SSL3_ST_SW_CERT_STATUS_A),
#endif
#ifdef SSL3_ST_SW_CERT_STATUS_B
  S(SSL3_ST_SW_CERT_STATUS_B),
#endif
#ifdef SSL3_ST_SW_CHANGE_A
  S(SSL3_ST_SW_CHANGE_A),
#endif
#ifdef SSL3_ST_SW_CHANGE_B
  S(SSL3_ST_SW_CHANGE_B),
#endif
#ifdef SSL3_ST_SW_FINISHED_A
  S(SSL3_ST_SW_FINISHED_A),
#endif
#ifdef SSL3_ST_SW_FINISHED_B
  S(SSL3_ST_SW_FINISHED_B),
#endif
#ifdef SSL3_ST_SW_FLUSH
  S(SSL3_ST_SW_FLUSH),
#endif
#ifdef SSL3_ST_SW_HELLO_REQ_A
  S(SSL3_ST_SW_HELLO_REQ_A),
#endif
#ifdef SSL3_ST_SW_HELLO_REQ_B
  S(SSL3_ST_SW_HELLO_REQ_B),
#endif
#ifdef SSL3_ST_SW_HELLO_REQ_C
  S(SSL3_ST_SW_HELLO_REQ_C),
#endif
#ifdef SSL3_ST_SW_KEY_EXCH_A
  S(SSL3_ST_SW_KEY_EXCH_A),
#endif
#ifdef SSL3_ST_SW_KEY_EXCH_B
  S(SSL3_ST_SW_KEY_EXCH_B),
#endif
#ifdef SSL3_ST_SW_SESSION_TICKET_A
  S(SSL3_ST_SW_SESSION_TICKET_A),
#endif
#ifdef SSL3_ST_SW_SESSION_TICKET_B
  S(SSL3_ST_SW_SESSION_TICKET_B),
#endif
#ifdef SSL3_ST_SW_SRVR_DONE_A
  S(SSL3_ST_SW_SRVR_DONE_A),
#endif
#ifdef SSL3_ST_SW_SRVR_DONE_B
  S(SSL3_ST_SW_SRVR_DONE_B),
#endif
#ifdef SSL3_ST_SW_SRVR_HELLO_A
  S(SSL3_ST_SW_SRVR_HELLO_A),
#endif
#ifdef SSL3_ST_SW_SRVR_HELLO_B
  S(SSL3_ST_SW_SRVR_HELLO_B),
#endif
#ifdef SSL_ST_ACCEPT
  S(SSL_ST_ACCEPT),
#endif
#ifdef SSL_ST_BEFORE
  S(SSL_ST_BEFORE),
#endif
#ifdef SSL_ST_CONNECT
  S(SSL_ST_CONNECT),
#endif
#ifdef SSL_ST_INIT
  S(SSL_ST_INIT),
#endif
#ifdef SSL_ST_MASK
  S(SSL_ST_MASK),
#endif
#ifdef SSL_ST_OK
  S(SSL_ST_OK),
#endif
#ifdef SSL_ST_READ_BODY
  S(SSL_ST_READ_BODY),
#endif
#ifdef SSL_ST_READ_DONE
  S(SSL_ST_READ_DONE),
#endif
#ifdef SSL_ST_READ_HEADER
  S(SSL_ST_READ_HEADER),
#endif
#ifdef SSL_ST_RENEGOTIATE
  S(SSL_ST_RENEGOTIATE),
#endif
  { 0, NULL }
};

#endif

