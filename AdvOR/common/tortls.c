/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tortls.c
 * \brief Wrapper functions to present a consistent interface to
 * TLS, SSL, and X.509 functions from OpenSSL.
 **/

/* (Unlike other tor functions, these
 * are prefixed with tor_ in order to avoid conflicting with OpenSSL
 * functions and variables.)
 */
#define _TOR_TLS_C

#include "orconfig.h"

#ifdef MS_WINDOWS /*wrkard for dtls1.h >= 0.9.8m of "#include <winsock.h>"*/
 #define WIN32_WINNT 0x400
 #define _WIN32_WINNT 0x400
 #define WIN32_LEAN_AND_MEAN
 #if defined(_MSC_VER) && (_MSC_VER < 1300)
    #include <winsock.h>
 #else
    #include <winsock2.h>
    #include <ws2tcpip.h>
 #endif
#endif
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x00907000l
#error "We require OpenSSL >= 0.9.7"
#endif

#define CRYPTO_PRIVATE /* to import prototypes from crypto.h */

#include "crypto.h"
#include "tortls.h"
#include "util.h"
#include "log.h"
#include "container.h"
#include "ht.h"
#include <string.h>

/* Enable the "v2" TLS handshake.
 */
#define V2_HANDSHAKE_SERVER
#define V2_HANDSHAKE_CLIENT

/* Copied from or.h */
#define LEGAL_NICKNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/** How long do identity certificates live? (sec) */
#define IDENTITY_CERT_LIFETIME  (365*24*60*60)

#define ADDR(tls) (((tls) && (tls)->address) ? tls->address : "peer")

#if (OPENSSL_VERSION_NUMBER  <  0x0090813fL ||    \
     (OPENSSL_VERSION_NUMBER >= 0x00909000L &&    \
      OPENSSL_VERSION_NUMBER <  0x1000006fL))
/* This is a version of OpenSSL before 0.9.8s/1.0.0f. It does not have
 * the CVE-2011-4576 fix, and as such it can't use RELEASE_BUFFERS and
 * SSL3 safely at the same time.
 */
#define DISABLE_SSL3_HANDSHAKE
#endif

/* We redefine these so that we can run correctly even if the vendor gives us
 * a version of OpenSSL that does not match its header files.  (Apple: I am
 * looking at you.)
 */
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x00040000L
#endif
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x0010
#endif

time_t get_time(time_t*);

/** Does the run-time openssl version look like we need
 * SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_op = 0;
/** Does the run-time openssl version look like we need
 * SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_flag = 0;

#define  N_COMMON_DIGEST_ALGORITHMS (DIGEST_SHA256+1)

/** A set of all the digests we commonly compute, taken on a single
 * string.  Any digests that are shorter than 512 bits are right-padded
 * with 0 bits.
 *
 * Note that this representation wastes 44 bytes for the SHA1 case, so
 * don't use it for anything where we need to allocate a whole bunch at
 * once.
 **/
typedef struct {
  char d[N_COMMON_DIGEST_ALGORITHMS][DIGEST256_LEN];
} common_digests_t; 

/** Structure that we use for a single certificate. */
typedef struct {
  X509 *cert;
  uint8_t *encoded;
  size_t encoded_len;
  unsigned pkey_digests_set : 1;
  common_digests_t cert_digests;
  common_digests_t pkey_digests;
} tor_x509_cert_t ;

/** Holds a SSL_CTX object and related state used to configure TLS
 * connections.
 */
typedef struct tor_tls_context_t {
  int refcnt;
  SSL_CTX *ctx;
  tor_x509_cert_t *my_link_cert;
  tor_x509_cert_t *my_id_cert;
  tor_x509_cert_t *my_auth_cert;
  crypto_pk_env_t *link_key;
  crypto_pk_env_t *auth_key;
} tor_tls_context_t;

/** Holds a SSL object and its associated data.  Members are only
 * accessed from within tortls.c.
 */
struct tor_tls_t {
  HT_ENTRY(tor_tls_t) node;
  tor_tls_context_t *context; /** A link to the context object for this tls. */
  SSL *ssl; /**< An OpenSSL SSL object. */
  int socket; /**< The underlying file descriptor for this TLS connection. */
  char *address; /**< An address to log when describing this connection. */
  enum {
    TOR_TLS_ST_HANDSHAKE, TOR_TLS_ST_OPEN, TOR_TLS_ST_GOTCLOSE,
    TOR_TLS_ST_SENTCLOSE, TOR_TLS_ST_CLOSED, TOR_TLS_ST_RENEGOTIATE,
  } state : 3; /**< The current SSL state, depending on which operations have
                * completed successfully. */
  unsigned int isServer:1; /**< True iff this is a server-side connection */
  unsigned int wasV2Handshake:1; /**< True iff the original handshake for
                                  * this connection used the updated version
                                  * of the connection protocol (client sends
                                  * different cipher list, server sends only
                                  * one certificate). */
 /** True iff we should call negotiated_callback when we're done reading. */
  unsigned int got_renegotiate:1;
  size_t wantwrite_n; /**< 0 normally, >0 if we returned wantwrite last
                       * time. */
  /** Last values retrieved from BIO_number_read()/write(); see
   * tor_tls_get_n_raw_bytes() for usage.
   */
  unsigned long last_write_count;
  unsigned long last_read_count;
  /** If set, a callback to invoke whenever the client tries to renegotiate
   * the handshake. */
  void (*negotiated_callback)(tor_tls_t *tls, void *arg);
  /** Argument to pass to negotiated_callback. */
  void *callback_arg;
};

#ifdef V2_HANDSHAKE_CLIENT
/** An array of fake SSL_CIPHER objects that we use in order to trick OpenSSL
 * in client mode into advertising the ciphers we want.  See
 * rectify_client_ciphers() for details. */
static SSL_CIPHER *CLIENT_CIPHER_DUMMIES = NULL;
/** A stack of SSL_CIPHER objects, some real, some fake.
 * See rectify_client_ciphers() for details. */
static STACK_OF(SSL_CIPHER) *CLIENT_CIPHER_STACK = NULL;
#endif

void crypto_pk_free(crypto_pk_env_t *env);
int crypto_common_digests(common_digests_t *ds_out, const char *m, size_t len);
int crypto_pk_get_common_digests(crypto_pk_env_t *pk, common_digests_t *digests_out);
tor_x509_cert_t *tor_x509_cert_new(X509 *x509_cert);
crypto_pk_env_t *crypto_pk_new(void);
crypto_pk_env_t *crypto_new_pk_from_rsa_(RSA *rsa);
void tor_x509_cert_free(tor_x509_cert_t *cert);

/** Helper: compare tor_tls_t objects by its SSL. */
static INLINE int
tor_tls_entries_eq(const tor_tls_t *a, const tor_tls_t *b)
{
  return a->ssl == b->ssl;
}

/** Helper: return a hash value for a tor_tls_t by its SSL. */
static INLINE unsigned int
tor_tls_entry_hash(const tor_tls_t *a)
{
#if SIZEOF_INT == SIZEOF_VOID_P
  return ((unsigned int)(uintptr_t)a->ssl);
#else
  return (unsigned int) ((((uint64_t)a->ssl)>>2) & UINT_MAX);
#endif
}

/** Map from SSL* pointers to tor_tls_t objects using those pointers.
 */
static HT_HEAD(tlsmap, tor_tls_t) tlsmap_root = HT_INITIALIZER();

HT_PROTOTYPE(tlsmap, tor_tls_t, node, tor_tls_entry_hash,
             tor_tls_entries_eq)
HT_GENERATE(tlsmap, tor_tls_t, node, tor_tls_entry_hash,
            tor_tls_entries_eq, 0.6)

/** Helper: given a SSL* pointer, return the tor_tls_t object using that
 * pointer. */
static INLINE tor_tls_t *
tor_tls_get_by_ssl(const SSL *ssl)
{
  tor_tls_t search, *result;
  memset(&search, 0, sizeof(search));
  search.ssl = (SSL*)ssl;
  result = HT_FIND(tlsmap, &tlsmap_root, &search);
  return result;
}

static void tor_tls_context_decref(tor_tls_context_t *ctx);
static void tor_tls_context_incref(tor_tls_context_t *ctx);
static void tor_tls_unblock_renegotiation(tor_tls_t *tls);
static int tor_tls_context_init_one(tor_tls_context_t **ppcontext,
                                    crypto_pk_env_t *identity,
                                    unsigned int key_lifetime,
                                    int is_client);
static tor_tls_context_t *tor_tls_context_new(crypto_pk_env_t *identity,
                                              unsigned int key_lifetime,
                                              int is_client);

/** Global TLS contexts. We keep them here because nobody else needs
 * to touch them. */
static tor_tls_context_t *server_tls_context = NULL;
static tor_tls_context_t *client_tls_context = NULL;

/** True iff tor_tls_init() has been called. */
static int tls_library_is_initialized = 0;

/* Module-internal error codes. */
#define _TOR_TLS_SYSCALL    (_MIN_TOR_TLS_ERROR_VAL - 2)
#define _TOR_TLS_ZERORETURN (_MIN_TOR_TLS_ERROR_VAL - 1)

/** Log all pending tls errors at level <b>severity</b>.  Use
 * <b>doing</b> to describe our current activities.
 */
static void
tls_log_errors(tor_tls_t *tls, int severity, int domain, const char *doing)
{
//  int st;
  unsigned long err;
  const char *msg, *lib, *func, *addr;
  addr = tls ? tls->address : NULL;
//  st = (tls && tls->ssl) ? tls->ssl->state : -1;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (doing) {
      log(severity,domain,get_lang_str(LANG_LOG_TLS_ERROR),doing,addr?get_lang_str(LANG_LOG_TLS__WITH):"", addr?addr:"",msg,lib,func);
    } else {
      log(severity, domain, get_lang_str(LANG_LOG_TLS_ERROR_2),addr?get_lang_str(LANG_LOG_TLS__WITH):"", addr?addr:"",msg,lib,func);
    }
  }
}

/** Convert an errno (or a WSAerrno on windows) into a TOR_TLS_* error
 * code. */
static int
tor_errno_to_tls_error(int e)
{
#if defined(MS_WINDOWS)
  switch (e) {
    case WSAECONNRESET: // most common
      return TOR_TLS_ERROR_CONNRESET;
    case WSAETIMEDOUT:
      return TOR_TLS_ERROR_TIMEOUT;
    case WSAENETUNREACH:
    case WSAEHOSTUNREACH:
      return TOR_TLS_ERROR_NO_ROUTE;
    case WSAECONNREFUSED:
      return TOR_TLS_ERROR_CONNREFUSED; // least common
    default:
      return TOR_TLS_ERROR_MISC;
  }
#else
  switch (e) {
    case ECONNRESET: // most common
      return TOR_TLS_ERROR_CONNRESET;
    case ETIMEDOUT:
      return TOR_TLS_ERROR_TIMEOUT;
    case EHOSTUNREACH:
    case ENETUNREACH:
      return TOR_TLS_ERROR_NO_ROUTE;
    case ECONNREFUSED:
      return TOR_TLS_ERROR_CONNREFUSED; // least common
    default:
      return TOR_TLS_ERROR_MISC;
  }
#endif
}

/** Given a TOR_TLS_* error code, return a string equivalent. */
const char *
tor_tls_err_to_string(int err)
{
  if (err >= 0)
    return "[Not an error.]";
  switch (err) {
    case TOR_TLS_ERROR_MISC: return "misc error";
    case TOR_TLS_ERROR_IO: return "unexpected close";
    case TOR_TLS_ERROR_CONNREFUSED: return "connection refused";
    case TOR_TLS_ERROR_CONNRESET: return "connection reset";
    case TOR_TLS_ERROR_NO_ROUTE: return "host unreachable";
    case TOR_TLS_ERROR_TIMEOUT: return "connection timed out";
    case TOR_TLS_CLOSE: return "closed";
    case TOR_TLS_WANTREAD: return "want to read";
    case TOR_TLS_WANTWRITE: return "want to write";
    default: return "(unknown error code)";
  }
}

#define CATCH_SYSCALL 1
#define CATCH_ZERO    2

/** Given a TLS object and the result of an SSL_* call, use
 * SSL_get_error to determine whether an error has occurred, and if so
 * which one.  Return one of TOR_TLS_{DONE|WANTREAD|WANTWRITE|ERROR}.
 * If extra&CATCH_SYSCALL is true, return _TOR_TLS_SYSCALL instead of
 * reporting syscall errors.  If extra&CATCH_ZERO is true, return
 * _TOR_TLS_ZERORETURN instead of reporting zero-return errors.
 *
 * If an error has occurred, log it at level <b>severity</b> and describe the
 * current action as <b>doing</b>.
 */
static int tor_tls_get_error(tor_tls_t *tls,int r,int extra,const char *doing,int severity,int domain)
{
  int err = SSL_get_error(tls->ssl, r);
  int tor_error = TOR_TLS_ERROR_MISC;
  switch (err) {
    case SSL_ERROR_NONE:
      return TOR_TLS_DONE;
    case SSL_ERROR_WANT_READ:
      return TOR_TLS_WANTREAD;
    case SSL_ERROR_WANT_WRITE:
      return TOR_TLS_WANTWRITE;
    case SSL_ERROR_SYSCALL:
      if (extra&CATCH_SYSCALL)
        return _TOR_TLS_SYSCALL;
      if (r == 0) {
        log(severity,domain,get_lang_str(LANG_LOG_TLS_UNEXPECTED_CLOSE),doing);
        tor_error = TOR_TLS_ERROR_IO;
      } else {
        int e = tor_socket_errno(tls->socket);
        log(severity,domain,get_lang_str(LANG_LOG_TLS_SYSCALL_ERROR),doing,e,tor_socket_strerror(e));
        tor_error = tor_errno_to_tls_error(e);
      }
      tls_log_errors(tls, severity, domain, doing);
      return tor_error;
    case SSL_ERROR_ZERO_RETURN:
      if (extra&CATCH_ZERO)
        return _TOR_TLS_ZERORETURN;
      log(severity,domain,get_lang_str(LANG_LOG_TLS_CONNECTION_CLOSED),doing);
      tls_log_errors(tls, severity, domain, doing);
      return TOR_TLS_CLOSE;
    default:
      tls_log_errors(tls, severity, domain, doing);
      return TOR_TLS_ERROR_MISC;
  }
}

/** Initialize OpenSSL, unless it has already been initialized.
 */
static void
tor_tls_init(void)
{
  if (!tls_library_is_initialized) {
    long version;
    SSL_library_init();
    SSL_load_error_strings();
    crypto_global_init();

    version = SSLeay();

    /* OpenSSL 0.9.8l introdeced SSL3_FLAGS_ALLOW_UNSAGE_LEGACY_RENEGOTIATION
     * here, but without thinking too hard about it: it turns out that the
     * flag in question needed to be set at the last minute, and that it
     * conflicted with an existing flag number that had already been added
     * in the OpenSSL 1.0.0 betas.  OpenSSL 0.9.8m thoughtfully replaced
     * the flag with an option and (it seems) broke anything that used
     * SSL3_FLAGS_* for the purpose.  So we need to know how to do both,
     * and we mustn't use the SSL3_FLAGS option with anything besides
     * OpenSSL 0.9.8l.
     *
     * No, we can't just set flag 0x0010 everywhere.  It breaks Tor with
     * OpenSSL 1.0.0beta3 and later.  On the other hand, we might be able to
     * set option 0x00040000L everywhere.
     *
     * No, we can't simply detect whether the flag or the option is present
     * in the headers at build-time: some vendors (notably Apple) like to
     * leave their headers out of sync with their libraries.
     *
     * Yes, it _is_ almost as if the OpenSSL developers decided that no
     * program should be allowed to use renegotiation its first passed an
     * test of intelligence and determination.
     */
    if (version >= 0x009080c0L && version < 0x009080d0L) {
      log_notice(LD_GENERAL,get_lang_str(LANG_LOG_TLS_OPENSSL),SSLeay_version(SSLEAY_VERSION));
      use_unsafe_renegotiation_flag = 1;
      use_unsafe_renegotiation_op = 1;
    } else if (version >= 0x009080d0L) {
/*      log_notice(LD_GENERAL, "OpenSSL %s looks like version 0.9.8m or later; "
                 "I will try SSL_OP to enable renegotiation",
                 SSLeay_version(SSLEAY_VERSION));*/
      use_unsafe_renegotiation_op = 1;
    } else if (version < 0x009080c0L) {
      log_notice(LD_GENERAL,get_lang_str(LANG_LOG_TLS_OPENSSL_2),SSLeay_version(SSLEAY_VERSION),version);
      use_unsafe_renegotiation_flag = 1;
      use_unsafe_renegotiation_op = 1;
    } else {
      log_info(LD_GENERAL,get_lang_str(LANG_LOG_TLS_OPENSSL_3),SSLeay_version(SSLEAY_VERSION),version);
    }

    tls_library_is_initialized = 1;
  }
}

/** Free all global TLS structures. */
void tor_tls_free_all(void)
{	if(server_tls_context)
	{	tor_tls_context_t *ctx = server_tls_context;
		server_tls_context = NULL;
		tor_tls_context_decref(ctx);
	}
	if(client_tls_context)
	{	tor_tls_context_t *ctx = client_tls_context;
		client_tls_context = NULL;
		tor_tls_context_decref(ctx);
	}
	if(!HT_EMPTY(&tlsmap_root))
		log_warn(LD_MM,get_lang_str(LANG_LOG_TLS_TLSMAP));
	HT_CLEAR(tlsmap, &tlsmap_root);
#ifdef V2_HANDSHAKE_CLIENT
	if(CLIENT_CIPHER_DUMMIES)
		tor_free(CLIENT_CIPHER_DUMMIES);
	if(CLIENT_CIPHER_STACK)
		sk_SSL_CIPHER_free(CLIENT_CIPHER_STACK);
#endif
}

/** We need to give OpenSSL a callback to verify certificates. This is
 * it: We always accept peer certs and complete the handshake.  We
 * don't validate them until later.
 */
static int
always_accept_verify_cb(int preverify_ok,
                        X509_STORE_CTX *x509_ctx)
{
  (void) preverify_ok;
  (void) x509_ctx;
  return 1;
}

/** Release a reference to an asymmetric key; when all the references
 * are released, free the key.
 */
void crypto_pk_free(crypto_pk_env_t *env)
{
  if (!env)
    return;

  if (--env->refs > 0)
    return;
  tor_assert(env->refs == 0);

  if (env->key)
    RSA_free(env->key);

  tor_free(env);
}

/** Set the common_digests_t in <b>ds_out</b> to contain every digest on the
 * <b>len</b> bytes in <b>m</b> that we know how to compute.  Return 0 on
 * success, -1 on failure. */
int crypto_common_digests(common_digests_t *ds_out, const char *m, size_t len)
{
  tor_assert(ds_out);
  memset(ds_out, 0, sizeof(*ds_out));
  if (crypto_digest(ds_out->d[DIGEST_SHA1], m, len) < 0)
    return -1;
  if (crypto_digest256(ds_out->d[DIGEST_SHA256], m, len, DIGEST_SHA256) < 0)
    return -1;

  return 0;
}

crypto_pk_env_t *crypto_new_pk_from_rsa_(RSA *rsa)
{
  crypto_pk_env_t *env;
  tor_assert(rsa);
  env = tor_malloc(sizeof(crypto_pk_env_t));
  env->refs = 1;
  env->key = rsa;
  return env;
}

/** Compute all digests of the DER encoding of <b>pk</b>, and store them
 * in <b>digests_out</b>.  Return 0 on success, -1 on failure. */
int crypto_pk_get_common_digests(crypto_pk_env_t *pk, common_digests_t *digests_out)
{
  unsigned char *buf = NULL;
  int len;

  len = i2d_RSAPublicKey(pk->key, &buf);
  if (len < 0 || buf == NULL)
    return -1;
  if (crypto_common_digests(digests_out, (char*)buf, len) < 0) {
    OPENSSL_free(buf);
    return -1;
  }
  OPENSSL_free(buf);
  return 0;
}

/**
 * Allocate a new tor_x509_cert_t to hold the certificate "x509_cert".
 *
 * Steals a reference to x509_cert.
 */
tor_x509_cert_t *tor_x509_cert_new(X509 *x509_cert)
{
  tor_x509_cert_t *cert;
  EVP_PKEY *pkey;
  RSA *rsa;
  int length;
  unsigned char *buf = NULL;

  if (!x509_cert)
    return NULL;

  length = i2d_X509(x509_cert, &buf);
  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  if (length <= 0 || buf == NULL) {
    /* LCOV_EXCL_START for the same reason as the exclusion above */
    tor_free(cert);
    log_err(LD_CRYPTO, "Couldn't get length of encoded x509 certificate");
    X509_free(x509_cert);
    return NULL;
    /* LCOV_EXCL_STOP */
  }
  cert->encoded_len = (size_t) length;
  cert->encoded = tor_malloc(length);
  memcpy(cert->encoded, buf, length);
  OPENSSL_free(buf);

  cert->cert = x509_cert;

  crypto_common_digests(&cert->cert_digests,
                    (char*)cert->encoded, cert->encoded_len);

  if ((pkey = X509_get_pubkey(x509_cert)) &&
      (rsa = EVP_PKEY_get1_RSA(pkey))) {
    crypto_pk_env_t *pk = crypto_new_pk_from_rsa_(rsa);
    crypto_pk_get_common_digests(pk, &cert->pkey_digests);
    cert->pkey_digests_set = 1;
    crypto_pk_free(pk);
    EVP_PKEY_free(pkey);
  }

  return cert;
}

/** Free all storage held in <b>cert</b> */
void tor_x509_cert_free(tor_x509_cert_t *cert)
{
  if (! cert)
    return;
  if (cert->cert)
    X509_free(cert->cert);
  tor_free(cert->encoded);
  /* LCOV_EXCL_BR_START since cert will never be NULL here */
  tor_free(cert);
  /* LCOV_EXCL_BR_STOP */
}

/** Return a newly allocated X509 name with commonName <b>cname</b>. */
static X509_NAME *tor_x509_name_new(const char *cname)
{	int nid;
	X509_NAME *name;
	if(!(name = X509_NAME_new()))
		return NULL;
	if(((nid = OBJ_txt2nid("commonName")) == NID_undef) || (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,(unsigned char*)cname, -1, -1, 0))))
	{	X509_NAME_free(name);
		return NULL;
	}
	return name;
}

/** Generate and sign an X509 certificate with the public key <b>rsa</b>,
 * signed by the private key <b>rsa_sign</b>.  The commonName of the
 * certificate will be <b>cname</b>; the commonName of the issuer will be
 * <b>cname_sign</b>. The cert will be valid for <b>cert_lifetime</b> seconds
 * starting from now.  Return a certificate on success, NULL on
 * failure.
 */
static X509 *tor_tls_create_certificate(crypto_pk_env_t *rsa,crypto_pk_env_t *rsa_sign,const char *cname,const char *cname_sign,unsigned int cert_lifetime)
{	time_t start_time, end_time;
	EVP_PKEY *sign_pkey = NULL, *pkey=NULL;
	X509 *x509 = NULL;
	X509_NAME *name = NULL, *name_issuer=NULL;
	tor_tls_init();
	start_time = get_time(NULL);
	tor_assert(rsa);
	tor_assert(cname);
	tor_assert(rsa_sign);
	tor_assert(cname_sign);
	if((sign_pkey = crypto_pk_get_evp_pkey_(rsa_sign,1)) && (pkey = crypto_pk_get_evp_pkey_(rsa,0)) && (x509 = X509_new()))
	{	if((!(X509_set_version(x509, 2))) || (!(ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)start_time))) || (!(name = tor_x509_name_new(cname))) || (!(X509_set_subject_name(x509, name))) || (!(name_issuer = tor_x509_name_new(cname_sign))) || (!(X509_set_issuer_name(x509, name_issuer))) || (!X509_time_adj(X509_get_notBefore(x509),0,&start_time)))
		{	X509_free(x509);
			x509 = NULL;
		}
		else
		{	end_time = start_time + cert_lifetime;
			if((!X509_time_adj(X509_get_notAfter(x509),0,&end_time)) || (!X509_set_pubkey(x509, pkey)) || (!X509_sign(x509, sign_pkey, EVP_sha1())))
			{	X509_free(x509);
				x509 = NULL;
			}
		}
	}
	tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_GENERATING_CERT));
	if(sign_pkey)	EVP_PKEY_free(sign_pkey);
	if(pkey)	EVP_PKEY_free(pkey);
	if(name)	X509_NAME_free(name);
	if(name_issuer)	X509_NAME_free(name_issuer);
	return x509;
}

/** List of ciphers that servers should select from.*/
#define SERVER_CIPHER_LIST                         \
  (TLS1_TXT_DHE_RSA_WITH_AES_256_SHA ":"           \
   TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":"           \
   SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA)
/* Note: for setting up your own private testing network with link crypto
 * disabled, set the cipher lists to your cipher list to
 * SSL3_TXT_RSA_NULL_SHA.  If you do this, you won't be able to communicate
 * with any of the "real" Tors, though. */

#ifdef V2_HANDSHAKE_CLIENT
#define CIPHER(id, name) name ":"
#define XCIPHER(id, name)
/** List of ciphers that clients should advertise, omitting items that
 * our OpenSSL doesn't know about. */
static const char CLIENT_CIPHER_LIST[] =
#include "./ciphers.inc"
  ;
#undef CIPHER
#undef XCIPHER

/** Holds a cipher that we want to advertise, and its 2-byte ID. */
typedef struct cipher_info_t { unsigned id; const char *name; } cipher_info_t;
/** A list of all the ciphers that clients should advertise, including items
 * that OpenSSL might not know about. */
static const cipher_info_t CLIENT_CIPHER_INFO_LIST[] = {
#define CIPHER(id, name) { id, name },
#define XCIPHER(id, name) { id, #name },
#include "./ciphers.inc"
#undef CIPHER
#undef XCIPHER
};

/** The length of CLIENT_CIPHER_INFO_LIST and CLIENT_CIPHER_DUMMIES. */
static const int N_CLIENT_CIPHERS =
  sizeof(CLIENT_CIPHER_INFO_LIST)/sizeof(CLIENT_CIPHER_INFO_LIST[0]);
#endif

#ifndef V2_HANDSHAKE_CLIENT
#undef CLIENT_CIPHER_LIST
#define CLIENT_CIPHER_LIST  (TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":"      \
                             SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA)
#endif

crypto_pk_env_t *crypto_pk_new(void)
{
  RSA *rsa;

  rsa = RSA_new();
  tor_assert(rsa);
  return crypto_new_pk_from_rsa_(rsa);
}


/** Remove a reference to <b>ctx</b>, and free it if it has no more
 * references. */
static void
tor_tls_context_decref(tor_tls_context_t *ctx)
{
  tor_assert(ctx);
  if (--ctx->refcnt == 0) {
    SSL_CTX_free(ctx->ctx);
    tor_x509_cert_free(ctx->my_link_cert);
    tor_x509_cert_free(ctx->my_auth_cert);
    tor_x509_cert_free(ctx->my_id_cert);
    crypto_pk_free(ctx->link_key);
    crypto_pk_free(ctx->auth_key);
    tor_free(ctx);
  }
}

/** Increase the reference count of <b>ctx</b>. */
static void
tor_tls_context_incref(tor_tls_context_t *ctx)
{
  ++ctx->refcnt;
}

/** Create new global client and server TLS contexts.
 * If <b>server_identity</b> is NULL, this will not generate a server TLS context. If <b>is_public_server</b> is non-zero, this will use the same TLS context for incoming and outgoing connections, and ignore <b>client_identity</b>. */
int tor_tls_context_init(int is_public_server,crypto_pk_env_t *client_identity,crypto_pk_env_t *server_identity,unsigned int key_lifetime)
{	int rv1 = 0;
	int rv2 = 0;
	if(is_public_server)
	{	tor_tls_context_t *new_ctx;
		tor_tls_context_t *old_ctx;
		tor_assert(server_identity != NULL);
		rv1 = tor_tls_context_init_one(&server_tls_context,server_identity,key_lifetime,0);
		if(rv1 >= 0)
		{	new_ctx = server_tls_context;
			tor_tls_context_incref(new_ctx);
			old_ctx = client_tls_context;
			client_tls_context = new_ctx;
			if(old_ctx != NULL)		tor_tls_context_decref(old_ctx);
		}
	}
	else
	{	if(server_identity != NULL)
			rv1 = tor_tls_context_init_one(&server_tls_context,server_identity,key_lifetime,0);
		else
		{	tor_tls_context_t *old_ctx = server_tls_context;
			server_tls_context = NULL;
			if(old_ctx != NULL)
				tor_tls_context_decref(old_ctx);
		}
		rv2 = tor_tls_context_init_one(&client_tls_context,client_identity,key_lifetime,1);
	}
	return MIN(rv1, rv2);
}

/** Create a new global TLS context.
 * You can call this function multiple times.  Each time you call it, it generates new certificates; all new connections will use the new SSL context. */
static int tor_tls_context_init_one(tor_tls_context_t **ppcontext,crypto_pk_env_t *identity,unsigned int key_lifetime,int is_client)
{	tor_tls_context_t *new_ctx = tor_tls_context_new(identity,key_lifetime,is_client);
	tor_tls_context_t *old_ctx = *ppcontext;
	if(new_ctx != NULL)
	{	*ppcontext = new_ctx;
		/* Free the old context if one existed. */
		if(old_ctx != NULL)	/* This is safe even if there are open connections: we reference-count tor_tls_context_t objects. */
			tor_tls_context_decref(old_ctx);
	}
	return ((new_ctx != NULL) ? 0 : -1);
}


/** Create a new TLS context for use with Tor TLS handshakes.
 * <b>identity</b> should be set to the identity key used to sign the
 * certificate, and <b>nickname</b> set to the nickname to use.
 *
 * You can call this function multiple times.  Each time you call it,
 * it generates new certificates; all new connections will use
 * the new SSL context.
 */
static tor_tls_context_t *tor_tls_context_new(crypto_pk_env_t *identity, unsigned int key_lifetime,int is_client)
{	crypto_pk_env_t *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	tor_tls_context_t *result = NULL;
	X509 *cert = NULL, *idcert = NULL,*authcert=NULL;
	char *nickname = NULL, *nn2 = NULL;
	int e = 0;
	tor_tls_init();
	nickname = crypto_random_hostname(8, 20, "www.", ".net");
	nn2 = crypto_random_hostname(8, 20, "www.", ".net");

	/* Generate short-term RSA key. */
	if((rsa = crypto_pk_new()))
	{	if(crypto_pk_generate_key(rsa)>=0)
		{	if(!is_client)	/* Create certificate signed by identity key. */
			{	cert = tor_tls_create_certificate(rsa,identity,nickname,nn2,key_lifetime);
				/* Create self-signed certificate for identity key. */
				idcert = tor_tls_create_certificate(identity,identity,nn2,nn2,IDENTITY_CERT_LIFETIME);
			//	authcert = tor_tls_create_certificate(rsa_auth, identity, nickname, nn2,key_lifetime);
				if(!cert || !idcert)
					log(LOG_WARN, LD_CRYPTO, "Error creating certificate");
			}
			if(is_client || (cert && idcert))
			{	result = tor_malloc_zero(sizeof(tor_tls_context_t));
				result->refcnt = 1;
				if(!is_client)
				{	result->my_link_cert = tor_x509_cert_new(X509_dup(cert));
					result->my_id_cert = tor_x509_cert_new(X509_dup(idcert));
			//		result->my_auth_cert = tor_x509_cert_new(X509_dup(authcert));
					result->link_key = crypto_pk_dup_key(rsa);
				}
//#ifdef EVERYONE_HAS_AES
#if 0
				/* Tell OpenSSL to only use TLS1 */
				if((result->ctx = SSL_CTX_new(TLSv1_method())))
				{
#endif
				/* Tell OpenSSL to use SSL3 or TLS1 but not SSL2. */
				if((result->ctx = SSL_CTX_new(SSLv23_method())))
				{	SSL_CTX_set_options(result->ctx, SSL_OP_NO_SSLv2);
					/* Disable TLS1.1 and TLS1.2 if they exist. We need to do this to workaround a bug present in all OpenSSL 1.0.1 versions (as of 1 June 2012), wherein renegotiating while using one of these TLS protocols will cause the client to send a TLS 1.0 ServerHello rather than a ServerHello written with the appropriate protocol version. Once some version of OpenSSL does TLS1.1 and TLS1.2 renegotiation properly, we can turn them back on when built with that version. */
#ifdef SSL_OP_NO_TLSv1_2
					SSL_CTX_set_options(result->ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_1
					SSL_CTX_set_options(result->ctx, SSL_OP_NO_TLSv1_1);
#endif
					if(
#ifdef DISABLE_SSL3_HANDSHAKE
					1 ||
#endif
					SSLeay()  <  0x0090813fL || (SSLeay() >= 0x00909000L && SSLeay() <  0x1000006fL))
					{	/* And not SSL3 if it's subject to CVE-2011-4576. */
						log_info(LD_NET,"Disabling SSLv3 because this OpenSSL version might otherwise be vulnerable to CVE-2011-4576 (compile-time version %08lx (%s); runtime version %08lx (%s))",(unsigned long)OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT,(unsigned long)SSLeay(),SSLeay_version(SSLEAY_VERSION));
						SSL_CTX_set_options(result->ctx, SSL_OP_NO_SSLv3);
					}
					SSL_CTX_set_options(result->ctx, SSL_OP_SINGLE_DH_USE);
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
					SSL_CTX_set_options(result->ctx,SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
					/* Yes, we know what we are doing here. No, we do not treat a renegotiation as authenticating any earlier-received data. */
					if(use_unsafe_renegotiation_op)
						SSL_CTX_set_options(result->ctx,SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
					/* Don't actually allow compression; it uses ram and time, but the data we transmit is all encrypted anyway. */
					//if(result->ctx->comp_methods)	result->ctx->comp_methods = NULL;
#ifdef SSL_MODE_RELEASE_BUFFERS
					SSL_CTX_set_mode(result->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
					if(!is_client)
					{	if(cert && !SSL_CTX_use_certificate(result->ctx,cert))
							e = 1;
						else
						{	X509_free(cert); /* We just added a reference to cert. */
							cert=NULL;
							if(idcert)
							{	X509_STORE *s = SSL_CTX_get_cert_store(result->ctx);
								tor_assert(s);
								X509_STORE_add_cert(s, idcert);
								X509_free(idcert); /* The context now owns the reference to idcert */
								idcert = NULL;
							}
						}
					}
					if(!e)
					{	SSL_CTX_set_session_cache_mode(result->ctx, SSL_SESS_CACHE_OFF);
						if(!is_client)
						{	tor_assert(rsa);
							if(!(pkey = crypto_pk_get_evp_pkey_(rsa,1)))
								e = 1;
							else if(!SSL_CTX_use_PrivateKey(result->ctx, pkey))
								e = 1;
							else
							{	EVP_PKEY_free(pkey);
								pkey = NULL;
								if(!SSL_CTX_check_private_key(result->ctx))
									e = 1;
							}
						}
					}
					if(!e)
					{	crypto_dh_env_t *dh = crypto_dh_new(DH_TYPE_TLS);
						tor_assert(dh);
						SSL_CTX_set_tmp_dh(result->ctx, _crypto_dh_env_get_dh(dh));
						crypto_dh_free(dh);
						SSL_CTX_set_verify(result->ctx,SSL_VERIFY_PEER,always_accept_verify_cb);
						/* let us realloc bufs that we're writing from */
						SSL_CTX_set_mode(result->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
						if(rsa)	crypto_pk_free(rsa);
						tor_free(nickname);
						tor_free(nn2);
						return result;
					}
					if(pkey)	EVP_PKEY_free(pkey);
				}
				tor_tls_context_decref(result);
			}
			if(cert)	X509_free(cert);
			if(idcert)	X509_free(idcert);
			if(authcert)	X509_free(authcert);
		}
		if(rsa)	crypto_pk_free(rsa);
	}
 	tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_CREATING_TLS_CONTEXT));
	tor_free(nickname);
	tor_free(nn2);
	return NULL;
}


#ifdef V2_HANDSHAKE_SERVER
/** Return true iff the cipher list suggested by the client for <b>ssl</b> is
 * a list that indicates that the client knows how to do the v2 TLS connection
 * handshake. */
static int tor_tls_client_is_using_v2_ciphers(const SSL *ssl, const char *address)
{	int i;
	SSL_SESSION *session;
	STACK_OF(SSL_CIPHER) *ciphers;
	/* If we reached this point, we just got a client hello.  See if there is a cipher list. */
	if(!(session = SSL_get_session((SSL *)ssl)))
	{	log_info(LD_NET,get_lang_str(LANG_LOG_TLS_NO_SESSION));
		return 0;
	}
	ciphers = SSL_get_client_ciphers(ssl);
	if(!ciphers)
	{	log_info(LD_NET,get_lang_str(LANG_LOG_TLS_NO_CIPHERS_ON_SESSION));
		return 0;
	}
	/* Now we need to see if there are any ciphers whose presence means we're dealing with an updated Tor. */
	for(i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i)
	{	const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
		const char *ciphername = SSL_CIPHER_get_name(cipher);
		if(strcmp(ciphername, TLS1_TXT_DHE_RSA_WITH_AES_128_SHA) && strcmp(ciphername, TLS1_TXT_DHE_RSA_WITH_AES_256_SHA) && strcmp(ciphername, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA) && strcmp(ciphername, "(NONE)"))
		{	log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_NON_V1_CIPHER),ciphername);
			smartlist_t *elts = smartlist_create();
			char *s;
			for(i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i)
			{	const SSL_CIPHER *cipher_ = sk_SSL_CIPHER_value(ciphers, i);
				const char *ciphername_ = SSL_CIPHER_get_name(cipher_);
				smartlist_add(elts, (char*)ciphername_);
			}
			s = smartlist_join_strings(elts, ":", 0, NULL);
			log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_NON_V1_CIPHER_2),address,s);
			tor_free(s);
			smartlist_free(elts);
			return 1;
		}
	}
	return 0;
}

#ifndef SSL3_ST_SW_SRVR_HELLO_A
#define SSL3_ST_SW_SRVR_HELLO_A		(0x130|SSL_ST_ACCEPT)
#define SSL3_ST_SW_SRVR_HELLO_B		(0x131|SSL_ST_ACCEPT)
#endif

#define STATE_IS_SW_SERVER_HELLO(st)       \
  (((st) == SSL3_ST_SW_SRVR_HELLO_A) ||    \
   ((st) == SSL3_ST_SW_SRVR_HELLO_B))

/** Invoked when we're accepting a connection on <b>ssl</b>, and the connection
 * changes state. We use this:
 * <ul><li>To alter the state of the handshake partway through, so we
 *         do not send or request extra certificates in v2 handshakes.</li>
 * <li>To detect renegotiation</li></ul>
 */
static void
tor_tls_server_info_callback(const SSL *ssl, int type, int val)
{
  tor_tls_t *tls;
  (void) val;
  if (type != SSL_CB_ACCEPT_LOOP)
    return;
  OSSL_HANDSHAKE_STATE ssl_state = SSL_get_state(ssl);
  if (!STATE_IS_SW_SERVER_HELLO(ssl_state))
    return;

  tls = tor_tls_get_by_ssl(ssl);
  if (tls) {
    /* Check whether we're watching for renegotiates.  If so, this is one! */
    if (tls->negotiated_callback)
      tls->got_renegotiate = 1;
  } else {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_TLS_LOOKUP_ERROR));
  }

  /* Now check the cipher list. */
  if (tor_tls_client_is_using_v2_ciphers(ssl, ADDR(tls))) {
    /*XXXX_TLS keep this from happening more than once! */

    /* Yes, we're casting away the const from ssl.  This is very naughty of us.
     * Let's hope openssl doesn't notice! */

    /* Set SSL_MODE_NO_AUTO_CHAIN to keep from sending back any extra certs. */
    SSL_set_mode((SSL*) ssl, SSL_MODE_NO_AUTO_CHAIN);
    /* Don't send a hello request. */
    SSL_set_verify((SSL*) ssl, SSL_VERIFY_NONE, NULL);

    if (tls) {
      tls->wasV2Handshake = 1;
    } else {
      log_warn(LD_BUG,get_lang_str(LANG_LOG_TLS_LOOKUP_ERROR));
    }
  }
}
#endif

/** Replace *<b>ciphers</b> with a new list of SSL ciphersuites: specifically,
 * a list designed to mimic a common web browser.  Some of the ciphers in the
 * list won't actually be implemented by OpenSSL: that's okay so long as the
 * server doesn't select them, and the server won't select anything besides
 * what's in SERVER_CIPHER_LIST.
 *
 * [If the server <b>does</b> select a bogus cipher, we won't crash or
 * anything; we'll just fail later when we try to look up the cipher in
 * ssl->cipher_list_by_id.]
 */
/* static void rectify_client_ciphers(STACK_OF(SSL_CIPHER) **ciphers)
{
#ifdef V2_HANDSHAKE_CLIENT
  if (PREDICT_UNLIKELY(!CLIENT_CIPHER_STACK)) {
    int i = 0, j = 0;

    CLIENT_CIPHER_DUMMIES =
      tor_malloc_zero(sizeof(SSL_CIPHER) * N_CLIENT_CIPHERS);
    for (i=0; i < N_CLIENT_CIPHERS; ++i) {
      CLIENT_CIPHER_DUMMIES[i].valid = 1;
      CLIENT_CIPHER_DUMMIES[i].id = CLIENT_CIPHER_INFO_LIST[i].id | (3<<24);
      CLIENT_CIPHER_DUMMIES[i].name = CLIENT_CIPHER_INFO_LIST[i].name;
    }

    CLIENT_CIPHER_STACK = sk_SSL_CIPHER_new_null();
    tor_assert(CLIENT_CIPHER_STACK);

    log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_LIST_WAS),CLIENT_CIPHER_LIST);
    for (j = 0; j < sk_SSL_CIPHER_num(*ciphers); ++j) {
      SSL_CIPHER *cipher = sk_SSL_CIPHER_value(*ciphers, j);
      log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_CIPHER),j,cipher->id,cipher->name);
    }

    j=0;
    for (i = 0; i < N_CLIENT_CIPHERS; ) {
      SSL_CIPHER *cipher = NULL;
      if (j < sk_SSL_CIPHER_num(*ciphers))
        cipher = sk_SSL_CIPHER_value(*ciphers, j);
      if (cipher && ((cipher->id >> 24) & 0xff) != 3) {
        log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_SKIPPING_V2_CIPHER),cipher->name);
        ++j;
      } else if (cipher &&
                 (cipher->id & 0xffff) == CLIENT_CIPHER_INFO_LIST[i].id) {
        log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_FOUND_CIPHER),cipher->name);
        sk_SSL_CIPHER_push(CLIENT_CIPHER_STACK, cipher);
        ++j;
        ++i;
      } else {
        log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_INSERTING_FAKE),CLIENT_CIPHER_DUMMIES[i].name);
        sk_SSL_CIPHER_push(CLIENT_CIPHER_STACK, &CLIENT_CIPHER_DUMMIES[i]);
        ++i;
      }
    }
  }

  sk_SSL_CIPHER_free(*ciphers);
  *ciphers = sk_SSL_CIPHER_dup(CLIENT_CIPHER_STACK);
  tor_assert(*ciphers);

#else
    (void)ciphers;
#endif
}
*/

/** Create a new TLS object from a file descriptor, and a flag to
 * determine whether it is functioning as a server.
 */
tor_tls_t *
tor_tls_new(int sock, int isServer)
{
  BIO *bio = NULL;
  tor_tls_t *result = tor_malloc_zero(sizeof(tor_tls_t));

  tor_tls_context_t *context = isServer ? server_tls_context :
    client_tls_context;

  tor_assert(context); /* make sure somebody made it first */
  if (!(result->ssl = SSL_new(context->ctx))) {
    tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_GENERATING_TLS_CONTEXT));
    tor_free(result);
    return NULL;
  }

#ifdef SSL_set_tlsext_host_name
  /* Browsers use the TLS hostname extension, so we should too. */
  if (!isServer) {
    char *fake_hostname = crypto_random_hostname(4,25, "www.",".com");
    SSL_set_tlsext_host_name(result->ssl, fake_hostname);
    tor_free(fake_hostname);
  }
#endif

  if (!SSL_set_cipher_list(result->ssl,
                     isServer ? SERVER_CIPHER_LIST : CLIENT_CIPHER_LIST)) {
    tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_SETTING_CIPHERS));
#ifdef SSL_set_tlsext_host_name
    SSL_set_tlsext_host_name(result->ssl, NULL);
#endif
    SSL_free(result->ssl);
    tor_free(result);
    return NULL;
  }
/*  if (!isServer)
    rectify_client_ciphers(&result->ssl->cipher_list);*/
  result->socket = sock;
  bio = BIO_new_socket(sock, BIO_NOCLOSE);
  if (! bio) {
    tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_OPENING_BIO));
#ifdef SSL_set_tlsext_host_name
    SSL_set_tlsext_host_name(result->ssl, NULL);
#endif
    SSL_free(result->ssl);
    tor_free(result);
    return NULL;
  }
  HT_INSERT(tlsmap, &tlsmap_root, result);
  SSL_set_bio(result->ssl, bio, bio);
  tor_tls_context_incref(context);
  result->context = context;
  result->state = TOR_TLS_ST_HANDSHAKE;
  result->isServer = isServer;
  result->wantwrite_n = 0;
  result->last_write_count = BIO_number_written(bio);
  result->last_read_count = BIO_number_read(bio);
  if (result->last_write_count || result->last_read_count) {
    log_warn(LD_NET,get_lang_str(LANG_LOG_TLS_BIO_STATS),result->last_read_count,result->last_write_count);
  }
#ifdef V2_HANDSHAKE_SERVER
  if (isServer) {
    SSL_set_info_callback(result->ssl, tor_tls_server_info_callback);
  }
#endif

  /* Not expected to get called. */
  tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_GENERATING_TLS_CONTEXT));
  return result;
}

/** Make future log messages about <b>tls</b> display the address
 * <b>address</b>.
 */
void
tor_tls_set_logged_address(tor_tls_t *tls, const char *address)
{
  tor_assert(tls);
  tor_free(tls->address);
  tls->address = tor_strdup(address);
}

/** Set <b>cb</b> to be called with argument <b>arg</b> whenever <b>tls</b>
 * next gets a client-side renegotiate in the middle of a read.  Do not
 * invoke this function until <em>after</em> initial handshaking is done!
 */
void
tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                 void (*cb)(tor_tls_t *, void *arg),
                                 void *arg)
{
  tls->negotiated_callback = cb;
  tls->callback_arg = arg;
  tls->got_renegotiate = 0;
#ifdef V2_HANDSHAKE_SERVER
  if (cb) {
    SSL_set_info_callback(tls->ssl, tor_tls_server_info_callback);
  } else {
    SSL_set_info_callback(tls->ssl, NULL);
  }
#endif
}

/** If this version of openssl requires it, turn on renegotiation on
 * <b>tls</b>.
 */
static void
tor_tls_unblock_renegotiation(tor_tls_t *tls)
{
  /* Yes, we know what we are doing here.  No, we do not treat a renegotiation
   * as authenticating any earlier-received data. */
  SSL_set_options(tls->ssl,
                  SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
}

/** If this version of openssl supports it, turn off renegotiation on
 * <b>tls</b>.  (Our protocol never requires this for security, but it's nice
 * to use belt-and-suspenders here.)
 */
void
tor_tls_block_renegotiation(tor_tls_t *tls)
{
#ifdef SUPPORT_UNSAFE_RENEGOTIATION_FLAG
  tls->ssl->s3->flags &= ~SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#else
  (void) tls;
#endif
}

/** Return whether this tls initiated the connect (client) or
 * received it (server). */
int
tor_tls_is_server(tor_tls_t *tls)
{
  tor_assert(tls);
  return tls->isServer;
}

/** Release resources associated with a TLS object.  Does not close the
 * underlying file descriptor.
 */
void
tor_tls_free(tor_tls_t *tls)
{
  tor_tls_t *removed;
  if(!tls)	return;
  tor_assert(tls->ssl);
  removed = HT_REMOVE(tlsmap, &tlsmap_root, tls);
  if (!removed) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_TLS_FREEING_TLS));
  }
#ifdef SSL_set_tlsext_host_name
  SSL_set_tlsext_host_name(tls->ssl, NULL);
#endif
  SSL_free(tls->ssl);
  tls->ssl = NULL;
  tls->negotiated_callback = NULL;
  if (tls->context)
    tor_tls_context_decref(tls->context);
  tor_free(tls->address);
  tor_free(tls);
}

/** Underlying function for TLS reading.  Reads up to <b>len</b>
 * characters from <b>tls</b> into <b>cp</b>.  On success, returns the
 * number of characters read.  On failure, returns TOR_TLS_ERROR,
 * TOR_TLS_CLOSE, TOR_TLS_WANTREAD, or TOR_TLS_WANTWRITE.
 */
int
tor_tls_read(tor_tls_t *tls, char *cp, size_t len)
{
  int r, err;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_OPEN);
  tor_assert(len<INT_MAX);
  r = SSL_read(tls->ssl, cp, (int)len);
  if (r > 0) {
#ifdef V2_HANDSHAKE_SERVER
    if (tls->got_renegotiate) {
      /* Renegotiation happened! */
      log_info(LD_NET,get_lang_str(LANG_LOG_TLS_TLS_RENEGOTIATION),ADDR(tls));
      if (tls->negotiated_callback)
        tls->negotiated_callback(tls, tls->callback_arg);
      tls->got_renegotiate = 0;
    }
#endif
    return r;
  }
  err = tor_tls_get_error(tls, r, CATCH_ZERO, "reading", LOG_DEBUG,LD_NET);
  if (err == _TOR_TLS_ZERORETURN || err == TOR_TLS_CLOSE) {
    log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_TLS_CLOSED),r);
    tls->state = TOR_TLS_ST_CLOSED;
    return TOR_TLS_CLOSE;
  } else {
    tor_assert(err != TOR_TLS_DONE);
    log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_TLS_CLOSED_2),r,err);
    return err;
  }
}

/** Underlying function for TLS writing.  Write up to <b>n</b>
 * characters from <b>cp</b> onto <b>tls</b>.  On success, returns the
 * number of characters written.  On failure, returns TOR_TLS_ERROR,
 * TOR_TLS_WANTREAD, or TOR_TLS_WANTWRITE.
 */
int
tor_tls_write(tor_tls_t *tls, const char *cp, size_t n)
{
  int r, err;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_OPEN);
  tor_assert(n < INT_MAX);
  if (n == 0)
    return 0;
  if (tls->wantwrite_n) {
    /* if WANTWRITE last time, we must use the _same_ n as before */
    tor_assert(n >= tls->wantwrite_n);
    log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_RESUME),(int)n,(int)tls->wantwrite_n);
    n = tls->wantwrite_n;
    tls->wantwrite_n = 0;
  }
  r = SSL_write(tls->ssl, cp, (int)n);
  err = tor_tls_get_error(tls, r, 0, "writing", LOG_INFO,LD_NET);
  if (err == TOR_TLS_DONE) {
    return r;
  }
  if (err == TOR_TLS_WANTWRITE || err == TOR_TLS_WANTREAD) {
    tls->wantwrite_n = n;
  }
  return err;
}

/** Perform initial handshake on <b>tls</b>.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_handshake(tor_tls_t *tls)
{
  int r;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_HANDSHAKE);
  check_no_tls_errors();
  if (tls->isServer) {
    r = SSL_accept(tls->ssl);
  } else {
    r = SSL_connect(tls->ssl);
  }
  /* We need to call this here and not earlier, since OpenSSL has a penchant
   * for clearing its flags when you say accept or connect. */
  tor_tls_unblock_renegotiation(tls);
  r = tor_tls_get_error(tls,r,0, "handshaking", LOG_INFO,LD_HANDSHAKE);
  if (ERR_peek_error() != 0) {
    tls_log_errors(tls, tls->isServer ? LOG_INFO : LOG_WARN,LD_HANDSHAKE,
                   "handshaking");
    return TOR_TLS_ERROR_MISC;
  }
  if (r == TOR_TLS_DONE) {
    tls->state = TOR_TLS_ST_OPEN;
    if (tls->isServer) {
      SSL_set_info_callback(tls->ssl, NULL);
      SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, always_accept_verify_cb);
      SSL_clear_mode(tls->ssl, SSL_MODE_NO_AUTO_CHAIN);
#ifdef V2_HANDSHAKE_SERVER
      if (tor_tls_client_is_using_v2_ciphers(tls->ssl, ADDR(tls))) {
        /* This check is redundant, but back when we did it in the callback,
         * we might have not been able to look up the tor_tls_t if the code
         * was buggy.  Fixing that. */
        if (!tls->wasV2Handshake) {
          log_warn(LD_BUG,get_lang_str(LANG_LOG_TLS_WASV2HANDSHAKE_NOT_SET));
        }
        tls->wasV2Handshake = 1;
        log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_COMPLETED_V2_HANDSHAKE));
      } else {
        tls->wasV2Handshake = 0;
      }
#endif
    } else {
#ifdef V2_HANDSHAKE_CLIENT
      /* If we got no ID cert, we're a v2 handshake. */
      X509 *cert = SSL_get_peer_certificate(tls->ssl);
      STACK_OF(X509) *chain = SSL_get_peer_cert_chain(tls->ssl);
      int n_certs = sk_X509_num(chain);
      if (n_certs > 1 || (n_certs == 1 && cert != sk_X509_value(chain, 0)))
        tls->wasV2Handshake = 0;
      else {
        log_debug(LD_NET,get_lang_str(LANG_LOG_TLS_SINGLE_CERT),tls);
        tls->wasV2Handshake = 1;
      }
      if (cert)
        X509_free(cert);
#endif
      if (SSL_set_cipher_list(tls->ssl, SERVER_CIPHER_LIST) == 0) {
        tls_log_errors(NULL,LOG_WARN,LD_HANDSHAKE,get_lang_str(LANG_LOG_TLS_RESETTING_CIPHERS));
        r = TOR_TLS_ERROR_MISC;
      }
    }
  }
  return r;
}

/** Client only: Renegotiate a TLS session.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD, or
 * TOR_TLS_WANTWRITE.
 */
int
tor_tls_renegotiate(tor_tls_t *tls)
{
  int r;
  tor_assert(tls);
  /* We could do server-initiated renegotiation too, but that would be tricky.
   * Instead of "SSL_renegotiate, then SSL_do_handshake until done" */
  tor_assert(!tls->isServer);
  if (tls->state != TOR_TLS_ST_RENEGOTIATE) {
    r = SSL_renegotiate(tls->ssl);
    if (r <= 0) {
      return tor_tls_get_error(tls, r, 0, "renegotiating", LOG_WARN,LD_HANDSHAKE);
    }
    tls->state = TOR_TLS_ST_RENEGOTIATE;
  }
  r = SSL_do_handshake(tls->ssl);
  if (r == 1) {
    tls->state = TOR_TLS_ST_OPEN;
    return TOR_TLS_DONE;
  } else
    return tor_tls_get_error(tls, r, 0, "renegotiating handshake", LOG_INFO,LD_HANDSHAKE);
}

/** Shut down an open tls connection <b>tls</b>.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_shutdown(tor_tls_t *tls)
{
  int r, err;
  char buf[128];
  tor_assert(tls);
  tor_assert(tls->ssl);

  while (1) {
    if (tls->state == TOR_TLS_ST_SENTCLOSE) {
      /* If we've already called shutdown once to send a close message,
       * we read until the other side has closed too.
       */
      do {
        r = SSL_read(tls->ssl, buf, 128);
      } while (r>0);
      err = tor_tls_get_error(tls,r,CATCH_ZERO,get_lang_str(LANG_LOG_TLS_READING_TO_SHUT_DOWN),LOG_INFO,LD_HANDSHAKE);
      if (err == _TOR_TLS_ZERORETURN) {
        tls->state = TOR_TLS_ST_GOTCLOSE;
        /* fall through... */
      } else {
        return err;
      }
    }

    r = SSL_shutdown(tls->ssl);
    if (r == 1) {
      /* If shutdown returns 1, the connection is entirely closed. */
      tls->state = TOR_TLS_ST_CLOSED;
      return TOR_TLS_DONE;
    }
    err = tor_tls_get_error(tls, r, CATCH_SYSCALL|CATCH_ZERO, "shutting down",LOG_INFO,LD_NET);
    if (err == _TOR_TLS_SYSCALL) {
      /* The underlying TCP connection closed while we were shutting down. */
      tls->state = TOR_TLS_ST_CLOSED;
      return TOR_TLS_DONE;
    } else if (err == _TOR_TLS_ZERORETURN) {
      /* The TLS connection says that it sent a shutdown record, but
       * isn't done shutting down yet.  Make sure that this hasn't
       * happened before, then go back to the start of the function
       * and try to read.
       */
      if (tls->state == TOR_TLS_ST_GOTCLOSE ||
         tls->state == TOR_TLS_ST_SENTCLOSE) {
        log(LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_HALF_CLOSED));
        return TOR_TLS_ERROR_MISC;
      }
      tls->state = TOR_TLS_ST_SENTCLOSE;
      /* fall through ... */
    } else {
      return err;
    }
  } /* end loop */
}

/** Return true iff this TLS connection is authenticated.
 */
int
tor_tls_peer_has_cert(tor_tls_t *tls)
{
  X509 *cert;
  cert = SSL_get_peer_certificate(tls->ssl);
  tls_log_errors(tls,LOG_WARN,LD_HANDSHAKE,get_lang_str(LANG_LOG_TLS_GETTING_PEER_CERT));
  if (!cert)
    return 0;
  X509_free(cert);
  return 1;
}

/** Warn that a certificate lifetime extends through a certain range. */
static void log_cert_lifetime(X509 *cert, const char *problem)
{	BIO *bio = NULL;
	BUF_MEM *buf;
	char *s1=NULL, *s2=NULL;
	char mytime[33];
	time_t now = get_time(NULL);
	struct tm tm;
	if(problem)
		log_warn(LD_GENERAL,get_lang_str(LANG_LOG_TLS_TIME_SKEW),problem);
	if(!(bio = BIO_new(BIO_s_mem())))
		log_warn(LD_GENERAL,get_lang_str(LANG_LOG_TLS_BIO_ALLOCATION_ERROR));
	else if(!(ASN1_TIME_print(bio, X509_get_notBefore(cert))))
		tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_CERT_LIFETIME));
	else
	{	BIO_get_mem_ptr(bio, &buf);
		s1 = tor_strndup(buf->data, buf->length);
		(void)BIO_reset(bio);
		if(!(ASN1_TIME_print(bio, X509_get_notAfter(cert))))
			tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_CERT_LIFETIME));
		else
		{	BIO_get_mem_ptr(bio, &buf);
			s2 = tor_strndup(buf->data, buf->length);
			strftime(mytime, 32, "%b %d %H:%M:%S %Y GMT", tor_gmtime_r(&now, &tm));
			log_warn(LD_GENERAL,get_lang_str(LANG_LOG_TLS_CERT_LIFETIME_2),s1,s2,mytime);
			tor_free(s2);
		}
		if(s1)	tor_free(s1);
	}
	/* Not expected to get invoked */
	tls_log_errors(NULL,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_GETTING_CERT_LIFETIME));
	if(bio)	BIO_free(bio);
}

/** Helper function: try to extract a link certificate and an identity
 * certificate from <b>tls</b>, and store them in *<b>cert_out</b> and
 * *<b>id_cert_out</b> respectively.  Log all messages at level
 * <b>severity</b>.
 *
 * Note that a reference is added to cert_out, so it needs to be
 * freed. id_cert_out doesn't. */
static void
try_to_extract_certs_from_tls(int severity, tor_tls_t *tls,
                              X509 **cert_out, X509 **id_cert_out)
{
  X509 *cert = NULL, *id_cert = NULL;
  STACK_OF(X509) *chain = NULL;
  int num_in_chain, i;
  *cert_out = *id_cert_out = NULL;

  if (!(cert = SSL_get_peer_certificate(tls->ssl)))
    return;
  *cert_out = cert;
  if (!(chain = SSL_get_peer_cert_chain(tls->ssl)))
    return;
  num_in_chain = sk_X509_num(chain);
  /* 1 means we're receiving (server-side), and it's just the id_cert.
   * 2 means we're connecting (client-side), and it's both the link
   * cert and the id_cert.
   */
  if (num_in_chain < 1) {
    log_fn(severity,LD_PROTOCOL,get_lang_str(LANG_LOG_TLS_UNEXPECTED_NUMBER_OF_CERTS),num_in_chain);
    return;
  }
  for (i=0; i<num_in_chain; ++i) {
    id_cert = sk_X509_value(chain, i);
    if (X509_cmp(id_cert, cert) != 0)
      break;
  }
  *id_cert_out = id_cert;
}

/** If the provided tls connection is authenticated and has a
 * certificate chain that is currently valid and signed, then set
 * *<b>identity_key</b> to the identity certificate's key and return
 * 0.  Else, return -1 and log complaints with log-level <b>severity</b>.
 */
int tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_env_t **identity_key)
{	X509 *cert = NULL, *id_cert = NULL;
	EVP_PKEY *id_pkey = NULL;
	RSA *rsa;
	int r = -1;
	*identity_key = NULL;

	try_to_extract_certs_from_tls(severity, tls, &cert, &id_cert);
	if(cert)
	{	if(!id_cert)
		{	log_fn(severity,LD_PROTOCOL,get_lang_str(LANG_LOG_TLS_NO_CERT_FOUND));
		}
		else if(!(id_pkey = X509_get_pubkey(id_cert)) || X509_verify(cert, id_pkey) <= 0)
		{	log_fn(severity,LD_PROTOCOL,get_lang_str(LANG_LOG_TLS_CERT_ERROR));
			tls_log_errors(tls, severity,LD_HANDSHAKE,"verifying certificate");
		}
		else if((rsa = EVP_PKEY_get1_RSA(id_pkey)))
		{	*identity_key = _crypto_new_pk_env_rsa(rsa);
			r = 0;
		}
	}
	if(cert)	X509_free(cert);
	if(id_pkey)	EVP_PKEY_free(id_pkey);
	/* This should never get invoked, but let's make sure in case OpenSSL acts unexpectedly. */
	tls_log_errors(tls,LOG_WARN,LD_HANDSHAKE,get_lang_str(LANG_LOG_TLS_FINISHING_TOR_TLS_VERIFY));
	return r;
}

/** Check whether the certificate set on the connection <b>tls</b> is
 * expired or not-yet-valid, give or take <b>tolerance</b>
 * seconds. Return 0 for valid, -1 for failure.
 *
 * NOTE: you should call tor_tls_verify before tor_tls_check_lifetime.
 */
int tor_tls_check_lifetime(tor_tls_t *tls, int tolerance)
{	time_t now, t;
	X509 *cert;
	int r = -1;
	now = get_time(NULL);
	if((cert = SSL_get_peer_certificate(tls->ssl)))
	{	t = now + tolerance;
		if(X509_cmp_time(X509_get_notBefore(cert), &t) > 0)
			log_cert_lifetime(cert,get_lang_str(LANG_LOG_TLS__NOT_YET_VALID));
		else
		{	t = now - tolerance;
			if(X509_cmp_time(X509_get_notAfter(cert), &t) < 0)
				log_cert_lifetime(cert,get_lang_str(LANG_LOG_TLS__ALREADY_EXPIRED));
			else	r = 0;
		}
	}
	if(cert)	X509_free(cert);
	/* Not expected to get invoked */
	tls_log_errors(tls,LOG_WARN,LD_NET,get_lang_str(LANG_LOG_TLS_CHECKING_CERT_LIFETIME));
	return r;
}

/** Return the number of bytes available for reading from <b>tls</b>.
 */
int
tor_tls_get_pending_bytes(tor_tls_t *tls)
{
  tor_assert(tls);
  return SSL_pending(tls->ssl);
}

/** If <b>tls</b> requires that the next write be of a particular size,
 * return that size.  Otherwise, return 0. */
size_t
tor_tls_get_forced_write_size(tor_tls_t *tls)
{
  return tls->wantwrite_n;
}

/** Sets n_read and n_written to the number of bytes read and written,
 * respectively, on the raw socket used by <b>tls</b> since the last time this
 * function was called on <b>tls</b>. */
void
tor_tls_get_n_raw_bytes(tor_tls_t *tls, size_t *n_read, size_t *n_written)
{
  BIO *wbio, *tmpbio;
  unsigned long r, w;
  r = BIO_number_read(SSL_get_rbio(tls->ssl));
  /* We want the number of bytes actually for real written.  Unfortunately,
   * sometimes OpenSSL replaces the wbio on tls->ssl with a buffering bio,
   * which makes the answer turn out wrong.  Let's cope with that.  Note
   * that this approach will fail if we ever replace tls->ssl's BIOs with
   * buffering bios for reasons of our own.  As an alternative, we could
   * save the original BIO for  tls->ssl in the tor_tls_t structure, but
   * that would be tempting fate. */
  wbio = SSL_get_wbio(tls->ssl);
  if(BIO_method_type(wbio) == BIO_TYPE_BUFFER && (tmpbio = BIO_next(wbio)) != NULL)
    wbio = tmpbio;
  w = BIO_number_written(wbio);

  /* We are ok with letting these unsigned ints go "negative" here:
   * If we wrapped around, this should still give us the right answer, unless
   * we wrapped around by more than ULONG_MAX since the last time we called
   * this function.
   */
  *n_read = (size_t)(r - tls->last_read_count);
  *n_written = (size_t)(w - tls->last_write_count);
  if (*n_read > INT_MAX || *n_written > INT_MAX) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_TLS_TOR_TLS_GET_N_RAW_BYTES),r,tls->last_read_count,w,tls->last_write_count);
  }
  tls->last_read_count = r;
  tls->last_write_count = w;
}

/** Implement check_no_tls_errors: If there are any pending OpenSSL
 * errors, log an error message. */
void
_check_no_tls_errors(const char *fname, int line)
{
  if (ERR_peek_error() == 0)
    return;
  log(LOG_WARN,LD_CRYPTO,get_lang_str(LANG_LOG_TLS_OPENSSL_ERROR),tor_fix_source_file(fname),line);
  tls_log_errors(NULL,LOG_WARN,LD_NET,NULL);
}

/** Return true iff the initial TLS connection at <b>tls</b> did not use a v2
 * TLS handshake. Output is undefined if the handshake isn't finished. */
int
tor_tls_used_v1_handshake(tor_tls_t *tls)
{
  if (tls->isServer) {
#ifdef V2_HANDSHAKE_SERVER
    return ! tls->wasV2Handshake;
#endif
  } else {
#ifdef V2_HANDSHAKE_CLIENT
    return ! tls->wasV2Handshake;
#endif
  }
  return 1;
}

/** Examine the amount of memory used and available for buffers in <b>tls</b>.
 * Set *<b>rbuf_capacity</b> to the amount of storage allocated for the read
 * buffer and *<b>rbuf_bytes</b> to the amount actually used.
 * Set *<b>wbuf_capacity</b> to the amount of storage allocated for the write
 * buffer and *<b>wbuf_bytes</b> to the amount actually used. */
void
tor_tls_get_buffer_sizes(tor_tls_t *tls,
                         size_t *rbuf_capacity, size_t *rbuf_bytes,
                         size_t *wbuf_capacity, size_t *wbuf_bytes)
{
  (void)tls;
  (void)rbuf_capacity;
  (void)rbuf_bytes;
  (void)wbuf_capacity;
  (void)wbuf_bytes;

/*  if (tls->ssl->s3->rbuf.buf)
    *rbuf_capacity = tls->ssl->s3->rbuf.len;
  else
    *rbuf_capacity = 0;
  if (tls->ssl->s3->wbuf.buf)
    *wbuf_capacity = tls->ssl->s3->wbuf.len;
  else
    *wbuf_capacity = 0;
  *rbuf_bytes = tls->ssl->s3->rbuf.left;
  *wbuf_bytes = tls->ssl->s3->wbuf.left;*/
}

#undef _TOR_TLS_C
