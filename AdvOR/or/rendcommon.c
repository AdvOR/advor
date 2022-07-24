/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendcommon.c
 * \brief Rendezvous implementation: shared code between
 * introducers, services, clients, and rendezvous points.
 **/

#include "or.h"
#include "circuitbuild.h"
#include "config.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendmid.h"
#include "rendservice.h"
#include "rephist.h"
#include "routerlist.h"
#include "routerparse.h"
#include "main.h"

void rend_cache_entry_free(rend_cache_entry_t *e,const char *c,int n);

/** Return 0 if one and two are the same service ids, else -1 or 1 */
int
rend_cmp_service_ids(const char *one, const char *two)
{
  return strcasecmp(one,two);
}

/** Free the storage held by the service descriptor <b>desc</b>.
 */
void
rend_service_descriptor_free(rend_service_descriptor_t *desc)
{
  if (!desc)
    return;
  if (desc->pk)
    crypto_free_pk_env(desc->pk);
  if (desc->intro_nodes) {
    SMARTLIST_FOREACH(desc->intro_nodes, rend_intro_point_t *, intro,
      rend_intro_point_free(intro););
    smartlist_free(desc->intro_nodes);
  }
  if (desc->successful_uploads) {
    SMARTLIST_FOREACH(desc->successful_uploads, char *, c, tor_free(c););
    smartlist_free(desc->successful_uploads);
  }
  tor_free(desc);
}

/** Length of the descriptor cookie that is used for versioned hidden
 * service descriptors. */
#define REND_DESC_COOKIE_LEN 16

/** Length of the replica number that is used to determine the secret ID
 * part of versioned hidden service descriptors. */
#define REND_REPLICA_LEN 1

/** Compute the descriptor ID for <b>service_id</b> of length
 * <b>REND_SERVICE_ID_LEN</b> and <b>secret_id_part</b> of length
 * <b>DIGEST_LEN</b>, and write it to <b>descriptor_id_out</b> of length
 * <b>DIGEST_LEN</b>. */
void
rend_get_descriptor_id_bytes(char *descriptor_id_out,
                             const char *service_id,
                             const char *secret_id_part)
{
  crypto_digest_env_t *digest = crypto_new_digest_env();
  crypto_digest_add_bytes(digest, service_id, REND_SERVICE_ID_LEN);
  crypto_digest_add_bytes(digest, secret_id_part, DIGEST_LEN);
  crypto_digest_get_digest(digest, descriptor_id_out, DIGEST_LEN);
  crypto_free_digest_env(digest);
}

/** Compute the secret ID part for time_period,
 * a <b>descriptor_cookie</b> of length
 * <b>REND_DESC_COOKIE_LEN</b> which may also be <b>NULL</b> if no
 * descriptor_cookie shall be used, and <b>replica</b>, and write it to
 * <b>secret_id_part</b> of length DIGEST_LEN. */
static void
get_secret_id_part_bytes(char *secret_id_part, uint32_t time_period,
                         const char *descriptor_cookie, uint8_t replica)
{
  crypto_digest_env_t *digest = crypto_new_digest_env();
  time_period = htonl(time_period);
  crypto_digest_add_bytes(digest, (char*)&time_period, sizeof(uint32_t));
  if (descriptor_cookie) {
    crypto_digest_add_bytes(digest, descriptor_cookie,
                            REND_DESC_COOKIE_LEN);
  }
  crypto_digest_add_bytes(digest, (const char *)&replica, REND_REPLICA_LEN);
  crypto_digest_get_digest(digest, secret_id_part, DIGEST_LEN);
  crypto_free_digest_env(digest);
}

/** Return the time period for time <b>now</b> plus a potentially
 * intended <b>deviation</b> of one or more periods, based on the first byte
 * of <b>service_id</b>. */
static uint32_t
get_time_period(time_t now, uint8_t deviation, const char *service_id)
{
  /* The time period is the number of REND_TIME_PERIOD_V2_DESC_VALIDITY
   * intervals that have passed since the epoch, offset slightly so that
   * each service's time periods start and end at a fraction of that
   * period based on their first byte. */
  return (uint32_t)
    (now + ((uint8_t) *service_id) * REND_TIME_PERIOD_V2_DESC_VALIDITY / 256)
    / REND_TIME_PERIOD_V2_DESC_VALIDITY + deviation;
}

/** Compute the time in seconds that a descriptor that is generated
 * <b>now</b> for <b>service_id</b> will be valid. */
static uint32_t
get_seconds_valid(time_t now, const char *service_id)
{
  uint32_t result = REND_TIME_PERIOD_V2_DESC_VALIDITY -
    ((uint32_t)
     (now + ((uint8_t) *service_id) * REND_TIME_PERIOD_V2_DESC_VALIDITY / 256)
     % REND_TIME_PERIOD_V2_DESC_VALIDITY);
  return result;
}

/** Compute the binary <b>desc_id_out</b> (DIGEST_LEN bytes long) for a given
 * base32-encoded <b>service_id</b> and optional unencoded
 * <b>descriptor_cookie</b> of length REND_DESC_COOKIE_LEN,
 * at time <b>now</b> for replica number
 * <b>replica</b>. <b>desc_id</b> needs to have <b>DIGEST_LEN</b> bytes
 * free. Return 0 for success, -1 otherwise. */
int
rend_compute_v2_desc_id(char *desc_id_out, const char *service_id,
                        const char *descriptor_cookie, time_t now,
                        uint8_t replica)
{
  char service_id_binary[REND_SERVICE_ID_LEN];
  char secret_id_part[DIGEST_LEN];
  uint32_t time_period;
  if (!service_id ||
      strlen(service_id) != REND_SERVICE_ID_LEN_BASE32) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ILLEGAL_SERVICE_ID),safe_str_client(service_id));
    return -1;
  }
  if (replica >= REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_REPLICA_OUT_OF_RANGE),replica);
    return -1;
  }
  /* Convert service ID to binary. */
  if (base32_decode(service_id_binary, REND_SERVICE_ID_LEN,
                    service_id, REND_SERVICE_ID_LEN_BASE32) < 0) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ILLEGAL_CHARACTERS_IN_SERVICE_ID),safe_str(service_id));
    return -1;
  }
  /* Calculate current time-period. */
  time_period = get_time_period(now, 0, service_id_binary);
  /* Calculate secret-id-part = h(time-period + replica). */
  get_secret_id_part_bytes(secret_id_part, time_period, descriptor_cookie,
                           replica);
  /* Calculate descriptor ID. */
  rend_get_descriptor_id_bytes(desc_id_out, service_id_binary, secret_id_part);
  return 0;
}

/** Encode the introduction points in <b>desc</b> and write the result to a
 * newly allocated string pointed to by <b>encoded</b>. Return 0 for
 * success, -1 otherwise. */
static int rend_encode_v2_intro_points(char **encoded, rend_service_descriptor_t *desc)
{	size_t unenc_len;
	char *unenc = NULL;
	size_t unenc_written = 0;
	int i;
	/* Assemble unencrypted list of introduction points. */
	unenc_len = smartlist_len(desc->intro_nodes) * 1000; /* too long, but ok. */
	unenc = tor_malloc_zero(unenc_len);
	for(i = 0; i < smartlist_len(desc->intro_nodes); i++)
	{	char id_base32[REND_INTRO_POINT_ID_LEN_BASE32 + 1];
		char *onion_key = NULL;
		size_t onion_key_len;
		crypto_pk_env_t *intro_key;
		char *service_key = NULL;
		char *address = NULL;
		size_t service_key_len;
		int res;
		rend_intro_point_t *intro = smartlist_get(desc->intro_nodes, i);
		/* Obtain extend info with introduction point details. */
		extend_info_t *info = intro->extend_info;
		/* Encode introduction point ID. */
		base32_encode(id_base32, sizeof(id_base32),info->identity_digest, DIGEST_LEN);
		/* Encode onion key. */
		if(crypto_pk_write_public_key_to_string(info->onion_key, &onion_key,&onion_key_len) < 0)
		{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_WRITING_ONION_KEY));
			break;
		}
		/* Encode intro key. */
		intro_key = intro->intro_key;
		if(!intro_key || crypto_pk_write_public_key_to_string(intro_key, &service_key,&service_key_len) < 0)
		{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_WRITING_INTRO_KEY));
			tor_free(onion_key);
			break;
		}
		/* Assemble everything for this introduction point. */
		address = tor_dup_addr(&info->addr);
		res = tor_snprintf(unenc + unenc_written, unenc_len - unenc_written,"introduction-point %s\nip-address %s\nonion-port %d\nonion-key\n%sservice-key\n%s",id_base32,address,info->port,onion_key,service_key);
		tor_free(address);
		tor_free(onion_key);
		tor_free(service_key);
		if(res < 0)
		{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_BUFFER_TOO_SMALL));
			break;
		}
		/* Update total number of written bytes for unencrypted intro points. */
		unenc_written += res;
	}
	if(i >= smartlist_len(desc->intro_nodes))
	{	/* Finalize unencrypted introduction points. */
		if(unenc_len < unenc_written + 2)
			log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_BUFFER_TOO_SMALL_2));
		else
		{	unenc[unenc_written++] = '\n';
			unenc[unenc_written++] = 0;
			*encoded = unenc;
			return 0;
		}
	}
	tor_free(unenc);
	return -1;
}

/** Encrypt the encoded introduction points in <b>encoded</b> using
 * authorization type  'basic' with <b>client_cookies</b> and write the
 * result to a newly allocated string pointed to by <b>encrypted_out</b> of
 * length <b>encrypted_len_out</b>. Return 0 for success, -1 otherwise. */
static int rend_encrypt_v2_intro_points_basic(char **encrypted_out,size_t *encrypted_len_out,const char *encoded,smartlist_t *client_cookies)
{	int r = -1, i, pos, enclen, client_blocks;
	size_t len, client_entries_len;
	char *enc = NULL, iv[CIPHER_IV_LEN], *client_part = NULL,session_key[CIPHER_KEY_LEN];
	smartlist_t *encrypted_session_keys = NULL;
	crypto_digest_env_t *digest;
	crypto_cipher_env_t *cipher;
	tor_assert(encoded);
	tor_assert(client_cookies && smartlist_len(client_cookies) > 0);
	/* Generate session key. */
	if(crypto_rand(session_key, CIPHER_KEY_LEN) < 0)
		log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_GENERATING_SESSION_KEY));
	else	/* Determine length of encrypted introduction points including session keys. */
	{	client_blocks = 1 + ((smartlist_len(client_cookies) - 1) / REND_BASIC_AUTH_CLIENT_MULTIPLE);
		client_entries_len = client_blocks * REND_BASIC_AUTH_CLIENT_MULTIPLE * REND_BASIC_AUTH_CLIENT_ENTRY_LEN;
		len = 2 + client_entries_len + CIPHER_IV_LEN + strlen(encoded);
		if(client_blocks >= 256)
			log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_TOO_MANY_CLIENTS));
		else
		{	enc = tor_malloc_zero(len);
			enc[0] = 0x01; /* type of authorization. */
			enc[1] = (uint8_t)client_blocks;
			/* Encrypt with random session key. */
			cipher = crypto_create_init_cipher(session_key, 1);
			enclen = crypto_cipher_encrypt_with_iv(cipher,enc + 2 + client_entries_len,CIPHER_IV_LEN + strlen(encoded), encoded, strlen(encoded));
			crypto_free_cipher_env(cipher);
			if(enclen < 0)
				log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCRYPTING_INTRO_POINT));
			else
			{	memcpy(iv, enc + 2 + client_entries_len, CIPHER_IV_LEN);
				/* Encrypt session key for cookies, determine client IDs, and put both in a smartlist. */
				encrypted_session_keys = smartlist_create();
				SMARTLIST_FOREACH_BEGIN(client_cookies, const char *, cookie)
				{	client_part = tor_malloc_zero(REND_BASIC_AUTH_CLIENT_ENTRY_LEN);
					/* Encrypt session key. */
					cipher = crypto_create_init_cipher(cookie, 1);
					if(crypto_cipher_encrypt(cipher, client_part + REND_BASIC_AUTH_CLIENT_ID_LEN,session_key, CIPHER_KEY_LEN) < 0)
					{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCRYPTING_SESSION_KEY));
						crypto_free_cipher_env(cipher);
						tor_free(client_part);
						enclen = -1;
						break;
					}
					crypto_free_cipher_env(cipher);
					/* Determine client ID. */
					digest = crypto_new_digest_env();
					crypto_digest_add_bytes(digest, cookie, REND_DESC_COOKIE_LEN);
					crypto_digest_add_bytes(digest, iv, CIPHER_IV_LEN);
					crypto_digest_get_digest(digest, client_part,REND_BASIC_AUTH_CLIENT_ID_LEN);
					crypto_free_digest_env(digest);
					/* Put both together. */
					smartlist_add(encrypted_session_keys, client_part);
				} SMARTLIST_FOREACH_END(cookie);
				if(enclen >= 0)
				{	/* Add some fake client IDs and encrypted session keys. */
					for(i = (smartlist_len(client_cookies) - 1) % REND_BASIC_AUTH_CLIENT_MULTIPLE;i < REND_BASIC_AUTH_CLIENT_MULTIPLE - 1; i++)
					{	client_part = tor_malloc_zero(REND_BASIC_AUTH_CLIENT_ENTRY_LEN);
						if(crypto_rand(client_part, REND_BASIC_AUTH_CLIENT_ENTRY_LEN) < 0)
						{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_GENERATING_FAKE_CLIENT_ENTRY));
							tor_free(client_part);
							break;
						}
						smartlist_add(encrypted_session_keys, client_part);
					}
					if(i >= REND_BASIC_AUTH_CLIENT_MULTIPLE - 1)
					{	/* Sort smartlist and put elements in result in order. */
						smartlist_sort_digests(encrypted_session_keys);
						pos = 2;
						SMARTLIST_FOREACH(encrypted_session_keys, const char *, entry,
						{	memcpy(enc + pos, entry, REND_BASIC_AUTH_CLIENT_ENTRY_LEN);
							pos += REND_BASIC_AUTH_CLIENT_ENTRY_LEN;
						});
						*encrypted_out = enc;
						*encrypted_len_out = len;
						enc = NULL; /* prevent free. */
						r = 0;
					}
				}
			}
		}
	}
	tor_free(enc);
	if(encrypted_session_keys)
	{	SMARTLIST_FOREACH(encrypted_session_keys, char *, d, tor_free(d););
		smartlist_free(encrypted_session_keys);
	}
	return r;
}

/** Encrypt the encoded introduction points in <b>encoded</b> using
 * authorization type 'stealth' with <b>descriptor_cookie</b> of length
 * REND_DESC_COOKIE_LEN and write the result to a newly allocated string
 * pointed to by <b>encrypted_out</b> of length <b>encrypted_len_out</b>.
 * Return 0 for success, -1 otherwise. */
static int rend_encrypt_v2_intro_points_stealth(char **encrypted_out,size_t *encrypted_len_out,const char *encoded,const char *descriptor_cookie)
{	int r = -1, enclen;
	crypto_cipher_env_t *cipher;
	char *enc;
	tor_assert(encoded);
	tor_assert(descriptor_cookie);
	enc = tor_malloc_zero(1 + CIPHER_IV_LEN + strlen(encoded));
	enc[0] = 0x02; /* Auth type */
	cipher = crypto_create_init_cipher(descriptor_cookie, 1);
	enclen = crypto_cipher_encrypt_with_iv(cipher, enc + 1,CIPHER_IV_LEN+strlen(encoded),encoded, strlen(encoded));
	crypto_free_cipher_env(cipher);
	if(enclen < 0)
		log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCRYPTING_INTRO_POINT));
	else
	{	*encrypted_out = enc;
		*encrypted_len_out = enclen;
		enc = NULL; /* prevent free */
		r = 0;
	}
	tor_free(enc);
	return r;
}

/** Attempt to parse the given <b>desc_str</b> and return true if this
 * succeeds, false otherwise. */
static int
rend_desc_v2_is_parsable(rend_encoded_v2_service_descriptor_t *desc)
{
  rend_service_descriptor_t *test_parsed = NULL;
  char test_desc_id[DIGEST_LEN];
  char *test_intro_content = NULL;
  size_t test_intro_size;
  size_t test_encoded_size;
  const char *test_next;
  int res = rend_parse_v2_service_descriptor(&test_parsed, test_desc_id,
                                         &test_intro_content,
                                         &test_intro_size,
                                         &test_encoded_size,
                                         &test_next, desc->desc_str);
  rend_service_descriptor_free(test_parsed);
  tor_free(test_intro_content);
  return (res >= 0);
}

/** Free the storage held by an encoded v2 service descriptor. */
void
rend_encoded_v2_service_descriptor_free(
  rend_encoded_v2_service_descriptor_t *desc)
{
  if (!desc)
    return;
  tor_free(desc->desc_str);
  tor_free(desc);
}

/** Free the storage held by an introduction point info. */
void
rend_intro_point_free(rend_intro_point_t *intro)
{
  if (!intro)
    return;
  if (intro->extend_info)
    extend_info_free(intro->extend_info);
  if (intro->intro_key)
    crypto_free_pk_env(intro->intro_key);
  tor_free(intro);
}

/** Encode a set of rend_encoded_v2_service_descriptor_t's for <b>desc</b>
 * at time <b>now</b> using <b>service_key</b>, depending on
 * <b>auth_type</b> a <b>descriptor_cookie</b> and a list of
 * <b>client_cookies</b> (which are both <b>NULL</b> if no client
 * authorization is performed), and <b>period</b> (e.g. 0 for the current
 * period, 1 for the next period, etc.) and add them to the existing list
 * <b>descs_out</b>; return the number of seconds that the descriptors will
 * be found by clients, or -1 if the encoding was not successful. */
int rend_encode_v2_descriptors(smartlist_t *descs_out,rend_service_descriptor_t *desc, time_t now,uint8_t period, rend_auth_type_t auth_type,crypto_pk_env_t *client_key,smartlist_t *client_cookies)
{	char service_id[DIGEST_LEN];
	uint32_t time_period;
	char *ipos_base64 = NULL, *ipos = NULL, *ipos_encrypted = NULL,*descriptor_cookie = NULL;
	size_t ipos_len = 0, ipos_encrypted_len = 0;
	int k;
	uint32_t seconds_valid;
	crypto_pk_env_t *service_key;
	if(!desc)
	{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCODING_V2_DESCRIPTOR));
		return -1;
	}
	service_key = (auth_type == REND_STEALTH_AUTH) ? client_key : desc->pk;
	tor_assert(service_key);
	if(auth_type == REND_STEALTH_AUTH)
	{	descriptor_cookie = smartlist_get(client_cookies, 0);
		tor_assert(descriptor_cookie);
	}
	/* Obtain service_id from public key. */
	crypto_pk_get_digest(service_key, service_id);
	/* Calculate current time-period. */
	time_period = get_time_period(now, period, service_id);
	/* Determine how many seconds the descriptor will be valid. */
	seconds_valid = period * REND_TIME_PERIOD_V2_DESC_VALIDITY + get_seconds_valid(now, service_id);
	/* Assemble, possibly encrypt, and encode introduction points. */
	if(smartlist_len(desc->intro_nodes) > 0)
	{	if(rend_encode_v2_intro_points(&ipos, desc) < 0)
		{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCODING_INTRO_POINTS));
			return -1;
		}
		switch(auth_type)
		{	case REND_NO_AUTH:
				ipos_len = strlen(ipos);
				break;
			case REND_BASIC_AUTH:
				if(rend_encrypt_v2_intro_points_basic(&ipos_encrypted,&ipos_encrypted_len, ipos,client_cookies) < 0)
				{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCRYPTING_INTRO_POINTS));
					tor_free(ipos);
					return -1;
				}
				tor_free(ipos);
				ipos = ipos_encrypted;
				ipos_len = ipos_encrypted_len;
				break;
			case REND_STEALTH_AUTH:
				if(rend_encrypt_v2_intro_points_stealth(&ipos_encrypted,&ipos_encrypted_len, ipos,descriptor_cookie) < 0)
				{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCRYPTING_INTRO_POINTS));
					tor_free(ipos);
					return -1;
				}
				tor_free(ipos);
				ipos = ipos_encrypted;
				ipos_len = ipos_encrypted_len;
				break;
			default:
				log_warn(LD_REND|LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_UNRECOGNIZED_AUTH_TYPE),(int)auth_type);
				tor_free(ipos);
				return -1;
		}
		/* Base64-encode introduction points. */
		ipos_base64 = tor_malloc_zero(ipos_len * 2);
		if(base64_encode(ipos_base64, ipos_len * 2, ipos, ipos_len,BASE64_ENCODE_MULTILINE)<0)
		{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_ENCODING_INTRO_POINTS_2),(int)ipos_len);
			tor_free(ipos_base64);
			tor_free(ipos);
			return -1;
		}
		tor_free(ipos);
	}
	/* Encode REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS descriptors. */
	for(k = 0; k < REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS; k++)
	{	char secret_id_part[DIGEST_LEN];
		char secret_id_part_base32[REND_SECRET_ID_PART_LEN_BASE32 + 1];
		char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
		char *permanent_key = NULL;
		size_t permanent_key_len;
		char published[ISO_TIME_LEN+1];
		int i;
		char protocol_versions_string[16]; /* max len: "0,1,2,3,4,5,6,7\0" */
		size_t protocol_versions_written;
		size_t desc_len;
		char *desc_str = NULL;
		int result = 0;
		size_t written = 0;
		char desc_digest[DIGEST_LEN];
		rend_encoded_v2_service_descriptor_t *enc = tor_malloc_zero(sizeof(rend_encoded_v2_service_descriptor_t));
		/* Calculate secret-id-part = h(time-period + cookie + replica). */
		get_secret_id_part_bytes(secret_id_part, time_period, descriptor_cookie,k);
		base32_encode(secret_id_part_base32,sizeof(secret_id_part_base32),secret_id_part,DIGEST_LEN);
		/* Calculate descriptor ID. */
		rend_get_descriptor_id_bytes(enc->desc_id, service_id, secret_id_part);
		base32_encode(desc_id_base32,sizeof(desc_id_base32),enc->desc_id,DIGEST_LEN);
		/* PEM-encode the public key */
		if(crypto_pk_write_public_key_to_string(service_key, &permanent_key,&permanent_key_len) < 0)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_WRITING_PUBLIC_KEY));
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		/* Encode timestamp. */
		format_iso_time(published, desc->timestamp);
		/* Write protocol-versions bitmask to comma-separated value string. */
		protocol_versions_written = 0;
		for(i = 0; i < 8; i++)
		{	if(desc->protocols & 1 << i)
			{	tor_snprintf(protocol_versions_string + protocol_versions_written,16 - protocol_versions_written, "%d,", i);
				protocol_versions_written += 2;
			}
		}
		if(protocol_versions_written)	protocol_versions_string[protocol_versions_written - 1] = '\0';
		else				protocol_versions_string[0]= '\0';
		/* Assemble complete descriptor. */
		desc_len = 2000 + smartlist_len(desc->intro_nodes) * 1000; /* far too long, but okay.*/
		enc->desc_str = desc_str = tor_malloc_zero(desc_len);
		result = tor_snprintf(desc_str, desc_len,"rendezvous-service-descriptor %s\nversion 2\npermanent-key\n%ssecret-id-part %s\npublication-time %s\nprotocol-versions %s\n",desc_id_base32,permanent_key,secret_id_part_base32,published,protocol_versions_string);
		tor_free(permanent_key);
		if(result < 0)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_BUFFER_TOO_SMALL_3));
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		written = result;
		/* Add introduction points. */
		if(ipos_base64)
		{	result = tor_snprintf(desc_str + written, desc_len - written,"introduction-points\n-----BEGIN MESSAGE-----\n%s-----END MESSAGE-----\n",ipos_base64);
			if(result < 0)
			{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_WRITING_INTRO_POINTS));
				rend_encoded_v2_service_descriptor_free(enc);
				break;
			}
			written += result;
		}
		/* Add signature. */
		strlcpy(desc_str + written, "signature\n", desc_len - written);
		written += strlen(desc_str + written);
		if(crypto_digest(desc_digest, desc_str, written) < 0)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_CREATING_DIGEST));
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		if(router_append_dirobj_signature(desc_str + written,desc_len - written,desc_digest,DIGEST_LEN,service_key) < 0)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_SIGNING_DESC));
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		written += strlen(desc_str+written);
		if(written+2 > desc_len)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_FINISHING_DESC));
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		desc_str[written++] = '\n';
		desc_str[written++] = 0;
		/* Check if we can parse our own descriptor. */
		if(!rend_desc_v2_is_parsable(enc))
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_PARSING_OWN_DESCRIPTOR),desc_str);
			rend_encoded_v2_service_descriptor_free(enc);
			break;
		}
		smartlist_add(descs_out, enc);
	}
	if(k < REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS)
	{	SMARTLIST_FOREACH(descs_out, rend_encoded_v2_service_descriptor_t *, d,
		{	rend_encoded_v2_service_descriptor_free(d);
		});
		smartlist_clear(descs_out);
		seconds_valid = -1;
	}
	else	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_V2_DESCRIPTOR_OK));
	tor_free(ipos_base64);
	return seconds_valid;
}

/** Parse a service descriptor at <b>str</b> (<b>len</b> bytes).  On
 * success, return a newly alloced service_descriptor_t.  On failure,
 * return NULL.
 */
rend_service_descriptor_t *rend_parse_service_descriptor(const char *str, size_t len)
{	rend_service_descriptor_t *result = NULL;
	int i, n_intro_points;
	size_t keylen, asn1len;
	const char *end, *cp, *eos;
	rend_intro_point_t *intro;

	result = tor_malloc_zero(sizeof(rend_service_descriptor_t));
	cp = str;
	end = str+len;
	result->version = 0;
	if(end-cp >= 2)
	{	asn1len = ntohs(get_uint16(cp));
		cp += 2;
		if((size_t)(end-cp) >= asn1len)
		{	result->pk = crypto_pk_asn1_decode(cp, asn1len);
			if(result->pk && (size_t)(end-cp) >= asn1len+4+2)
			{	cp += asn1len;
				result->timestamp = (time_t) ntohl(get_uint32(cp));
				cp += 4;
				result->protocols = 1<<2; /* always use intro format 2 */
				n_intro_points = ntohs(get_uint16(cp));
				cp += 2;

				result->intro_nodes = smartlist_create();
				for(i=0;i<n_intro_points;++i)
				{	if(end-cp < 2)	break;
					eos = (const char *)memchr(cp,'\0',end-cp);
					if(!eos)	break;
					/* Write nickname to extend info, but postpone the lookup whether we know that router. It's not part of the parsing process. */
					intro = tor_malloc_zero(sizeof(rend_intro_point_t));
					intro->extend_info = tor_malloc_zero(sizeof(extend_info_t));
					strlcpy(intro->extend_info->nickname, cp,sizeof(intro->extend_info->nickname));
					smartlist_add(result->intro_nodes, intro);
					cp = eos+1;
				}
				if(i >= n_intro_points)
				{	keylen = crypto_pk_keysize(result->pk);
					tor_assert(end-cp >= 0);
					if((size_t)(end-cp) >= keylen)
					{	if((size_t)(end-cp) > keylen)
							log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDCOMMON_SIGNATURE_TOO_LONG),(int)((size_t)(end-cp) - keylen));
						else
						{	note_crypto_pk_op(REND_CLIENT);
							if(crypto_pk_public_checksig_digest(result->pk,(char*)str,cp-str,(char*)cp,end-cp)<0)
								log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDCOMMON_BAD_SIGNATURE));
							else	return result;
						}
						rend_service_descriptor_free(result);
						return NULL;
					}
				}
			}
		}
	}
	log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDCOMMON_TRUNCATED_DESCRIPTOR));
	rend_service_descriptor_free(result);
	return NULL;
}

/** Sets <b>out</b> to the first 10 bytes of the digest of <b>pk</b>,
 * base32 encoded.  NUL-terminates out.  (We use this string to
 * identify services in directory requests and .onion URLs.)
 */
int
rend_get_service_id(crypto_pk_env_t *pk, char *out)
{
  char buf[DIGEST_LEN];
  tor_assert(pk);
  if (crypto_pk_get_digest(pk, buf) < 0)
    return -1;
  base32_encode(out, REND_SERVICE_ID_LEN_BASE32+1, buf, REND_SERVICE_ID_LEN);
  return 0;
}

/* ==== Rendezvous service descriptor cache. */

/** How old do we let hidden service descriptors get before discarding
 * them as too old? */
#define REND_CACHE_MAX_AGE (2*24*60*60)
/** How wrong do we assume our clock may be when checking whether hidden
 * services are too old or too new? */
#define REND_CACHE_MAX_SKEW (24*60*60)

/** Map from service id (as generated by rend_get_service_id) to
 * rend_cache_entry_t. */
static strmap_t *rend_cache = NULL;

/** Map from descriptor id to rend_cache_entry_t; only for hidden service
 * directories. */
static digestmap_t *rend_cache_v2_dir = NULL;

/** Initializes the service descriptor cache.
 */
void
rend_cache_init(void)
{
  rend_cache = strmap_new();
  rend_cache_v2_dir = digestmap_new();
}

/** Helper: free storage held by a single service descriptor cache entry. */
#ifdef DEBUG_MALLOC
void rend_cache_entry_free(rend_cache_entry_t *e,const char *c,int n)
{
  if (!e)
    return;
  rend_service_descriptor_free(e->parsed);
  _tor_free_(e->desc,c,n);
  tor_free(e);
}

static void
_rend_cache_entry_free(void *p,const char *c,int n)
{
  rend_cache_entry_free(p,c,n);
}
#else
void rend_cache_entry_free(rend_cache_entry_t *e)
{
  if (!e)
    return;
  rend_service_descriptor_free(e->parsed);
  tor_free(e->desc);
  tor_free(e);
}

static void
_rend_cache_entry_free(void *p)
{
  rend_cache_entry_free(p);
}
#endif

/** Free all storage held by the service descriptor cache. */
void
rend_cache_free_all(void)
{
  if (rend_cache)
    strmap_free(rend_cache, _rend_cache_entry_free);
  if (rend_cache_v2_dir)
    digestmap_free(rend_cache_v2_dir, _rend_cache_entry_free);
  rend_cache = NULL;
  rend_cache_v2_dir = NULL;
}

/** Removes all old entries from the service descriptor cache.
 */
void
rend_cache_clean(void)
{
  strmap_iter_t *iter;
  const char *key;
  void *val;
  rend_cache_entry_t *ent;
  time_t cutoff;
  cutoff = get_time(NULL) - REND_CACHE_MAX_AGE - REND_CACHE_MAX_SKEW;
  for (iter = strmap_iter_init(rend_cache); !strmap_iter_done(iter); ) {
    strmap_iter_get(iter, &key, &val);
    ent = (rend_cache_entry_t*)val;
    if (ent->parsed->timestamp < cutoff) {
      iter = strmap_iter_next_rmv(rend_cache, iter);
#ifdef DEBUG_MALLOC
      rend_cache_entry_free(ent,__FILE__,__LINE__);
#else
      rend_cache_entry_free(ent);
#endif
    } else {
      iter = strmap_iter_next(rend_cache, iter);
    }
  }
}

/** Remove ALL entries from the rendezvous service descriptor cache.
 */
void
rend_cache_purge(void)
{
  if (rend_cache) {
    log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_PURGING_DESCRIPTOR_CACHE));
    strmap_free(rend_cache, _rend_cache_entry_free);
  }
  rend_cache = strmap_new();
}

/** Remove all old v2 descriptors and those for which this hidden service
 * directory is not responsible for any more. */
void
rend_cache_clean_v2_descs_as_dir(void)
{
  digestmap_iter_t *iter;
  time_t cutoff = get_time(NULL) - REND_CACHE_MAX_AGE - REND_CACHE_MAX_SKEW;
  for (iter = digestmap_iter_init(rend_cache_v2_dir);
       !digestmap_iter_done(iter); ) {
    const char *key;
    void *val;
    rend_cache_entry_t *ent;
    digestmap_iter_get(iter, &key, &val);
    ent = val;
    if (ent->parsed->timestamp < cutoff ||
        !hid_serv_responsible_for_desc_id(key)) {
      char key_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
      base32_encode(key_base32, sizeof(key_base32), key, DIGEST_LEN);
      log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_REMOVING_DESCRIPTOR),safe_str_client(key_base32));
      iter = digestmap_iter_next_rmv(rend_cache_v2_dir, iter);
#ifdef DEBUG_MALLOC
      rend_cache_entry_free(ent,__FILE__,__LINE__);
#else
      rend_cache_entry_free(ent);
#endif
    } else {
      iter = digestmap_iter_next(rend_cache_v2_dir, iter);
    }
  }
}

/** Determines whether <b>a</b> is in the interval of <b>b</b> (excluded) and
 * <b>c</b> (included) in a circular digest ring; returns 1 if this is the
 * case, and 0 otherwise.
 */
int
rend_id_is_in_interval(const char *a, const char *b, const char *c)
{
  int a_b, b_c, c_a;
  tor_assert(a);
  tor_assert(b);
  tor_assert(c);

  /* There are five cases in which a is outside the interval ]b,c]: */
  a_b = tor_memcmp(a,b,DIGEST_LEN);
  if (a_b == 0)
    return 0; /* 1. a == b (b is excluded) */
  b_c = tor_memcmp(b,c,DIGEST_LEN);
  if (b_c == 0)
    return 0; /* 2. b == c (interval is empty) */
  else if (a_b <= 0 && b_c < 0)
    return 0; /* 3. a b c */
  c_a = tor_memcmp(c,a,DIGEST_LEN);
  if (c_a < 0 && a_b <= 0)
    return 0; /* 4. c a b */
  else if (b_c < 0 && c_a < 0)
    return 0; /* 5. b c a */

  /* In the other cases (a c b; b a c; c b a), a is inside the interval. */
  return 1;
}

/** Return true iff <b>query</b> is a syntactically valid service ID (as
 * generated by rend_get_service_id).  */
int
rend_valid_service_id(const char *query)
{
  if (strlen(query) != REND_SERVICE_ID_LEN_BASE32)
    return 0;

  if (strspn(query, BASE32_CHARS) != REND_SERVICE_ID_LEN_BASE32)
    return 0;

  return 1;
}

/** If we have a cached rend_cache_entry_t for the service ID <b>query</b>
 * with <b>version</b>, set *<b>e</b> to that entry and return 1.
 * Else return 0. If <b>version</b> is nonnegative, only return an entry
 * in that descriptor format version. Otherwise (if <b>version</b> is
 * negative), return the most recent format we have.
 */
int
rend_cache_lookup_entry(const char *query, int version, rend_cache_entry_t **e)
{
  char key[REND_SERVICE_ID_LEN_BASE32+2]; /* <version><query>\0 */
  tor_assert(rend_cache);
  if (!rend_valid_service_id(query))
    return -1;
  *e = NULL;
  if (version != 0) {
    tor_snprintf(key, sizeof(key), "2%s", query);
    *e = strmap_get_lc(rend_cache, key);
  }
  if (!*e && version != 2) {
    tor_snprintf(key, sizeof(key), "0%s", query);
    *e = strmap_get_lc(rend_cache, key);
  }
  if (!*e)
    return 0;
  tor_assert((*e)->parsed && (*e)->parsed->intro_nodes);
  /* XXX023 hack for now, to return "not found" if there are no intro
   * points remaining. See bug 997. */
  if (! rend_client_any_intro_points_usable(*e))
    return 0;
  return 1;
}

/** <b>query</b> is a base-32'ed service id. If it's malformed, return -1.
 * Else look it up.
 *   - If it is found, point *desc to it, and write its length into
 *     *desc_len, and return 1.
 *   - If it is not found, return 0.
 * Note: calls to rend_cache_clean or rend_cache_store may invalidate
 * *desc.
 */
int
rend_cache_lookup_desc(const char *query, int version, const char **desc,
                       size_t *desc_len)
{
  rend_cache_entry_t *e;
  int r;
  r = rend_cache_lookup_entry(query,version,&e);
  if (r <= 0) return r;
  *desc = e->desc;
  *desc_len = e->len;
  return 1;
}

/** Lookup the v2 service descriptor with base32-encoded <b>desc_id</b> and
 * copy the pointer to it to *<b>desc</b>.  Return 1 on success, 0 on
 * well-formed-but-not-found, and -1 on failure.
 */
int
rend_cache_lookup_v2_desc_as_dir(const char *desc_id, const char **desc)
{
  rend_cache_entry_t *e;
  char desc_id_digest[DIGEST_LEN];
  tor_assert(rend_cache_v2_dir);
  if (base32_decode(desc_id_digest, DIGEST_LEN,
                    desc_id, REND_DESC_ID_V2_LEN_BASE32) < 0) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ILLEGAL_CHARACTERS_IN_DESCRIPTOR),safe_str(desc_id));
    return -1;
  }
  /* Lookup descriptor and return. */
  e = digestmap_get(rend_cache_v2_dir, desc_id_digest);
  if (e) {
    *desc = e->desc;
    return 1;
  }
  return 0;
}

/** Parse *desc, calculate its service id, and store it in the cache.
 * If we have a newer v0 descriptor with the same ID, ignore this one.
 * If we have an older descriptor with the same ID, replace it.
 * If we are acting as client due to the published flag and have any v2
 * descriptor with the same ID, reject this one in order to not get
 * confused with having both versions for the same service.
 *
 * Return -2 if it's malformed or otherwise rejected; return -1 if we
 * already have a v2 descriptor here; return 0 if it's the same or older
 * than one we've already got; return 1 if it's novel.
 *
 * The published flag tells us if we store the descriptor
 * in our role as directory (1) or if we cache it as client (0).
 */
int
rend_cache_store(const char *desc, size_t desc_len, int published,const char *service_id)
{
  rend_cache_entry_t *e;
  rend_service_descriptor_t *parsed;
  char query[REND_SERVICE_ID_LEN_BASE32+1];
  char key[REND_SERVICE_ID_LEN_BASE32+2]; /* 0<query>\0 */
  time_t now;
  tor_assert(rend_cache);
  parsed = rend_parse_service_descriptor(desc,desc_len);
  if (!parsed) {
    log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_PARSING_SERVICE_DESCRIPTOR));
    return -2;
  }
  if (rend_get_service_id(parsed->pk, query)<0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_COMPUTING_SERVICE_ID));
    rend_service_descriptor_free(parsed);
    return -2;
  }
  if ((service_id != NULL) && strcmp(query, service_id)) {
    log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_RECEIVED_DIFFERENT_DESCRIPTOR),query,safe_str(service_id));
    rend_service_descriptor_free(parsed);
    return -2;
  }
  now = get_time(NULL);
  if (parsed->timestamp < now-REND_CACHE_MAX_AGE-REND_CACHE_MAX_SKEW) {
    log_fn(LOG_PROTOCOL_WARN,LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_OLD),safe_str(query));
    rend_service_descriptor_free(parsed);
    return -2;
  }
  if (parsed->timestamp > now+REND_CACHE_MAX_SKEW) {
    log_fn(LOG_PROTOCOL_WARN,LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_NEW),safe_str(query));
    rend_service_descriptor_free(parsed);
    return -2;
  }
  /* Do we have a v2 descriptor and fetched this descriptor as a client? */
  tor_snprintf(key, sizeof(key), "2%s", query);
  if (!published && strmap_get_lc(rend_cache, key)) {
    log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE),safe_str(query));
    rend_service_descriptor_free(parsed);
    return -1;
  }
  tor_snprintf(key, sizeof(key), "0%s", query);
  e = (rend_cache_entry_t*) strmap_get_lc(rend_cache, key);
  if (e && e->parsed->timestamp > parsed->timestamp) {
    log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_2),safe_str(query));
    rend_service_descriptor_free(parsed);
    return 0;
  }
  if (e && e->len == desc_len && tor_memeq(desc,e->desc,desc_len)) {
    log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_3),safe_str(query));
    e->received = get_time(NULL);
    rend_service_descriptor_free(parsed);
    return 0;
  }
  if (!e) {
    e = tor_malloc_zero(sizeof(rend_cache_entry_t));
    strmap_set_lc(rend_cache, key, e);
  } else {
    rend_service_descriptor_free(e->parsed);
    tor_free(e->desc);
  }
  e->received = get_time(NULL);
  e->parsed = parsed;
  e->len = desc_len;
  e->desc = tor_malloc(desc_len);
  memcpy(e->desc, desc, desc_len);

  log_debug(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_STORED_SUCCESSFULLY),safe_str(query),(int)desc_len);
  return 1;
}

/** Parse the v2 service descriptor(s) in <b>desc</b> and store it/them to the
 * local rend cache. Don't attempt to decrypt the included list of introduction
 * points (as we don't have a descriptor cookie for it).
 *
 * If we have a newer descriptor with the same ID, ignore this one.
 * If we have an older descriptor with the same ID, replace it.
 * Return -2 if we are not acting as hidden service directory;
 * return -1 if the descriptor(s) were not parsable; return 0 if all
 * descriptors are the same or older than those we've already got;
 * return a positive number for the number of novel stored descriptors.
 */
int rend_cache_store_v2_desc_as_dir(const char *desc)
{	rend_service_descriptor_t *parsed;
	char desc_id[DIGEST_LEN];
	char *intro_content;
	size_t intro_size;
	size_t encoded_size;
	int r;
	char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
	int number_parsed = 0, number_stored = 0;
	const char *current_desc = desc;
	const char *next_desc;
	rend_cache_entry_t *e;
	time_t now = get_time(NULL);
	tor_assert(rend_cache_v2_dir);
	tor_assert(desc);
	if(!hid_serv_acting_as_directory())	/* Cannot store descs, because we are (currently) not acting as hidden service directory. */
	{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_CANNOT_STORE_DESCS));
		return -2;
	}
	while(rend_parse_v2_service_descriptor(&parsed, desc_id, &intro_content,&intro_size, &encoded_size,&next_desc, current_desc) >= 0)
	{	number_parsed++;
		r = 0;
		/* We don't care about the introduction points. */
		tor_free(intro_content);
		/* For pretty log statements. */
		base32_encode(desc_id_base32, sizeof(desc_id_base32),desc_id, DIGEST_LEN);
		/* Is desc ID in the range that we are (directly or indirectly) responsible for? */
		if(!hid_serv_responsible_for_desc_id(desc_id))
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_NOT_IN_OUR_INTERVAL),safe_str_client(desc_id_base32));
			r++;
		}
		else if(parsed->timestamp < now - REND_CACHE_MAX_AGE-REND_CACHE_MAX_SKEW)	/* Is descriptor too old? */
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_OLD),safe_str(desc_id_base32));
			r++;
		}
		else if(parsed->timestamp > now + REND_CACHE_MAX_SKEW)	/* Is descriptor too far in the future? */
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_NEW),safe_str(desc_id_base32));
			r++;
		}
		else if((e = digestmap_get(rend_cache_v2_dir, desc_id)) && e->parsed->timestamp > parsed->timestamp)	/* Do we already have a newer descriptor? */
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_2),safe_str(desc_id_base32));
			r++;
		}
		else if(e && !strcmp(desc, e->desc))	/* Do we already have this descriptor? */
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_3), safe_str(desc_id_base32));
			e->received = get_time(NULL);
			r++;
		}
		else
		{	/* Store received descriptor. */
			if(!e)
			{	e = tor_malloc_zero(sizeof(rend_cache_entry_t));
				digestmap_set(rend_cache_v2_dir, desc_id, e);
			}
			else
			{	rend_service_descriptor_free(e->parsed);
				tor_free(e->desc);
			}
			e->received = get_time(NULL);
			e->parsed = parsed;
			e->desc = tor_strndup(current_desc, encoded_size);
			e->len = encoded_size;
			log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_STORED_SUCCESSFULLY_2),safe_str(desc_id_base32),(int)encoded_size);
			number_stored++;
		}
		if(r)	rend_service_descriptor_free(parsed);
		/* advance to next descriptor, if available. */
		current_desc = next_desc;
		/* check if there is a next descriptor. */
		if(!current_desc || strcmpstart(current_desc, "rendezvous-service-descriptor "))
			break;
	}
	if(!number_parsed)
	{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_COULD_NOT_PARSE_ANY_DESCRIPTOR));
		return -1;
	}
	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_PARSED_AND_ADDED),number_parsed,number_stored,number_stored != 1 ? "s" : "");
	return number_stored;
}

/** Parse the v2 service descriptor in <b>desc</b>, decrypt the included list
 * of introduction points with <b>descriptor_cookie</b> (which may also be
 * <b>NULL</b> if decryption is not necessary), and store the descriptor to
 * the local cache under its version and service id.
 *
 * If we have a newer v2 descriptor with the same ID, ignore this one.
 * If we have an older descriptor with the same ID, replace it.
 * If we have any v0 descriptor with the same ID, reject this one in order
 * to not get confused with having both versions for the same service.
 * Return -2 if it's malformed or otherwise rejected; return -1 if we
 * already have a v0 descriptor here; return 0 if it's the same or older
 * than one we've already got; return 1 if it's novel.
 */
int rend_cache_store_v2_desc_as_client(const char *desc,const rend_data_t *rend_query)
{	/*XXXX this seems to have a bit of duplicate code with rend_cache_store_v2_desc_as_dir().  Fix that. */
	/* Though having similar elements, both functions were separated on purpose:
		- dirs don't care about encoded/encrypted introduction points, clients do.
		- dirs store descriptors in a separate cache by descriptor ID, whereas clients store them by service ID; both caches are different data structures and have different access methods.
		- dirs store a descriptor only if they are responsible for its ID, clients do so in every way (because they have requested it before).
		- dirs can process multiple concatenated descriptors which is required for replication, whereas clients only accept a single descriptor.
	Thus, combining both methods would result in a lot of if statements which probably would not improve, but worsen code readability. -KL */

	rend_service_descriptor_t *parsed = NULL;
	char desc_id[DIGEST_LEN];
	char *intro_content = NULL;
	size_t intro_size;
	size_t encoded_size;
	const char *next_desc;
	time_t now = get_time(NULL);
	char key[REND_SERVICE_ID_LEN_BASE32+2];
	char service_id[REND_SERVICE_ID_LEN_BASE32+1];
	rend_cache_entry_t *e;
	int retval=0;
	tor_assert(rend_cache);
	tor_assert(desc);
	if(rend_parse_v2_service_descriptor(&parsed, desc_id, &intro_content,&intro_size, &encoded_size,&next_desc, desc) < 0)	/* Parse the descriptor. */
	{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_PARSING_SERVICE_DESCRIPTOR));
		retval = -2;
	}
	else if(rend_get_service_id(parsed->pk, service_id)<0)	/* Compute service ID from public key. */
	{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_ERROR_COMPUTING_SERVICE_ID));
		retval = -2;
	}
	else if(strcmp(rend_query->onion_address, service_id))
	{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_RECEIVED_DIFFERENT_DESCRIPTOR),service_id, safe_str(rend_query->onion_address));
		retval = -2;
	}
	else
	{	if(intro_content)	/* Decode/decrypt introduction points. */
		{	if(rend_query->auth_type != REND_NO_AUTH && !tor_mem_is_zero(rend_query->descriptor_cookie,sizeof(rend_query->descriptor_cookie)))
			{	char *ipos_decrypted = NULL;
				size_t ipos_decrypted_size;
				if(rend_decrypt_introduction_points(&ipos_decrypted,&ipos_decrypted_size,rend_query->descriptor_cookie,intro_content,intro_size) < 0)
					log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_FAILED_TO_DECRYPT_INTRO_POINTS));
				else	/* Replace encrypted with decrypted introduction points. */
				{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_INTRO_POINTS_DECRYPTED));
					tor_free(intro_content);
					intro_content = ipos_decrypted;
					intro_size = ipos_decrypted_size;
				}
			}
			if(rend_parse_introduction_points(parsed, intro_content,intro_size) <= 0)
			{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_FAILED_TO_PARSE_INTRO_POINTS));
				retval = -2;
			}
		}
		else
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_WITHOUT_INTRO_POINTS));
			parsed->intro_nodes = smartlist_create();
		}
		if(!retval)
		{	/* We don't need the encoded/encrypted introduction points any longer. */
			tor_free(intro_content);
			if(parsed->timestamp < now - REND_CACHE_MAX_AGE-REND_CACHE_MAX_SKEW)	/* Is descriptor too old? */
			{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_OLD),safe_str_client(service_id));
				retval = -2;
			}
			else if(parsed->timestamp > now + REND_CACHE_MAX_SKEW)	/* Is descriptor too far in the future? */
			{	log_warn(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_TOO_NEW),safe_str_client(service_id));
				retval = -2;
			}
			else
			{	tor_snprintf(key, sizeof(key), "0%s", service_id);
				if(strmap_get_lc(rend_cache, key))	/* Do we have a v0 descriptor? */
				{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_4),safe_str_client(service_id));
					retval = -1;
				}
				else
				{	/* Do we already have a newer descriptor? */
					tor_snprintf(key, sizeof(key), "2%s", service_id);
					e = (rend_cache_entry_t*) strmap_get_lc(rend_cache, key);
					if(e && e->parsed->timestamp > parsed->timestamp)
					{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_2),safe_str_client(service_id));
						retval = 0;
					}
					else if(e && !strcmp(desc, e->desc))	/* Do we already have this descriptor? */
					{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_ALREADY_HAVE_3),safe_str_client(service_id));
						e->received = get_time(NULL);
						retval = 0;
					}
					else
					{	if(!e)
						{	e = tor_malloc_zero(sizeof(rend_cache_entry_t));
							strmap_set_lc(rend_cache, key, e);
						}
						else
						{	rend_service_descriptor_free(e->parsed);
							tor_free(e->desc);
						}
						e->received = get_time(NULL);
						e->parsed = parsed;
						e->desc = tor_malloc_zero(encoded_size + 1);
						strlcpy(e->desc, desc, encoded_size + 1);
						e->len = encoded_size;
						log_debug(LD_REND,get_lang_str(LANG_LOG_RENDCOMMON_DESCRIPTOR_STORED_SUCCESSFULLY),safe_str(service_id),(int)encoded_size);
						return 1;
					}
				}
			}
		}
	}
	if(parsed)	rend_service_descriptor_free(parsed);
	tor_free(intro_content);
	return retval;
}

/** Called when we get a rendezvous-related relay cell on circuit
 * <b>circ</b>.  Dispatch on rendezvous relay command. */
void
rend_process_relay_cell(circuit_t *circ, const crypt_path_t *layer_hint,
                        int command, size_t length,
                        const uint8_t *payload)
{
  or_circuit_t *or_circ = NULL;
  origin_circuit_t *origin_circ = NULL;
  int r = -2;
  if (CIRCUIT_IS_ORIGIN(circ)) {
    origin_circ = TO_ORIGIN_CIRCUIT(circ);
    if (!layer_hint || layer_hint != origin_circ->cpath->prev) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP,get_lang_str(LANG_LOG_RENDCOMMON_RELAY_CEL_FROM_WRONG_HOP),command);
      origin_circ = NULL;
    }
  } else {
    or_circ = TO_OR_CIRCUIT(circ);
  }

  switch (command) {
    case RELAY_COMMAND_ESTABLISH_INTRO:
      if (or_circ)
        r = rend_mid_establish_intro(or_circ,payload,length);
      break;
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      if (or_circ)
        r = rend_mid_establish_rendezvous(or_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE1:
      if (or_circ)
        r = rend_mid_introduce(or_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE2:
      if (origin_circ)
        r = rend_service_introduce(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE_ACK:
      if (origin_circ)
        r = rend_client_introduction_acked(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS1:
      if (or_circ)
        r = rend_mid_rendezvous(or_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS2:
      if (origin_circ)
        r = rend_client_receive_rendezvous(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      if (origin_circ)
        r = rend_service_intro_established(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      if (origin_circ)
        r = rend_client_rendezvous_acked(origin_circ,payload,length);
      break;
    default:
      tor_fragile_assert();
  }

  if (r == -2)
    log_info(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDCOMMON_CELL_FOR_WRONG_CIRC_TYPE),command);
}

/** Return the number of entries in our rendezvous descriptor cache. */
int
rend_cache_size(void)
{
  return strmap_size(rend_cache);
}

/** Allocate and return a new rend_data_t with the same
 * contents as <b>query</b>. */
rend_data_t *
rend_data_dup(const rend_data_t *data)
{
  tor_assert(data);
  return tor_memdup(data, sizeof(rend_data_t));
}
