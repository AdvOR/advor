/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendmid.c
 * \brief Implement introductions points and rendezvous points.
 **/

#include "or.h"
#include "circuitlist.h"
#include "config.h"
#include "relay.h"
#include "rendmid.h"
#include "rephist.h"
#include "main.h"

/** Respond to an ESTABLISH_INTRO cell by checking the signed data and
 * setting the circuit's purpose and service pk digest.
 */
int rend_mid_establish_intro(or_circuit_t *circ, const uint8_t *request,size_t request_len)
{	crypto_pk_env_t *pk = NULL;
	char buf[DIGEST_LEN+9];
	char expected_digest[DIGEST_LEN];
	char pk_digest[DIGEST_LEN];
	size_t asn1len;
	or_circuit_t *c;
	char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
	int reason = END_CIRC_REASON_INTERNAL;

	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_ESTABLISH_INTRO),circ->p_circ_id);
	asn1len = ntohs(get_uint16(request));	/* First 2 bytes: length of asn1-encoded key. */
	if(circ->_base.purpose != CIRCUIT_PURPOSE_OR || circ->_base.n_conn)
	{	log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_REJECTING_ESTABLISH_INTRO));
		reason = END_CIRC_REASON_TORPROTOCOL;
	}
	else if((request_len < 2+DIGEST_LEN) || (request_len < 2+DIGEST_LEN+asn1len))	/* Next asn1len bytes: asn1-encoded key. */
	{	log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_ESTABLISH_INTRO_TRUNCATED));
		reason = END_CIRC_REASON_TORPROTOCOL;
	}
	else
	{	pk = crypto_pk_asn1_decode((char*)(request+2), asn1len);
		if(!pk)
		{	reason = END_CIRC_REASON_TORPROTOCOL;
			log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_ERROR_DECODING_PUBLIC_KEY));
		}
		else	/* Next 20 bytes: Hash of handshake_digest | "INTRODUCE" */
		{	memcpy(buf, circ->handshake_digest, DIGEST_LEN);
			memcpy(buf+DIGEST_LEN, "INTRODUCE", 9);
			if(crypto_digest(expected_digest, buf, DIGEST_LEN+9) < 0)
				log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDMID_INTERNAL_ERROR));
			else if(tor_memneq(expected_digest, request+2+asn1len, DIGEST_LEN))
			{	log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_UNEXPECTED_HASH));
				reason = END_CIRC_REASON_TORPROTOCOL;
			}
			else
			{	/* Rest of body: signature of previous data */
				note_crypto_pk_op(REND_MID);
				if(crypto_pk_public_checksig_digest(pk, (char*)request, 2+asn1len+DIGEST_LEN,(char*)(request+2+DIGEST_LEN+asn1len),request_len-(2+DIGEST_LEN+asn1len))<0)
				{	log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_INCORRECT_SIGNATURE_ON_ESTABLISH_INTRO));
					reason = END_CIRC_REASON_TORPROTOCOL;
				}
				else if(crypto_pk_get_digest(pk, pk_digest)<0)	/* The request is valid.  First, compute the hash of Bob's PK.*/
					log_warn(LD_BUG,get_lang_str(LANG_LOG_RENDMID_INTERNAL_ERROR_2));
				else
				{	crypto_free_pk_env(pk); /* don't need it anymore */
					pk = NULL; /* so we don't free it again if err */
					base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,pk_digest, REND_SERVICE_ID_LEN);

					/* Close any other intro circuits with the same pk. */
					c = NULL;
					while((c = circuit_get_intro_point(pk_digest)))
					{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_REPLACING_OLD_CIRCUIT),safe_str(serviceid));
						circuit_mark_for_close(TO_CIRCUIT(c), END_CIRC_REASON_FINISHED);	/* Now it's marked, and it won't be returned next time. */
					}
					/* Acknowledge the request. */
					if(relay_send_command_from_edge(0, TO_CIRCUIT(circ),RELAY_COMMAND_INTRO_ESTABLISHED,"", 0, NULL)<0)
					{	log_info(LD_GENERAL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_INTRO_ESTABLISHED));
					}
					else	/* Now, set up this circuit. */
					{	circ->_base.purpose = CIRCUIT_PURPOSE_INTRO_POINT;
						tree_set_circ(TO_CIRCUIT(circ));
						memcpy(circ->rend_token, pk_digest, DIGEST_LEN);
						log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_INTRO_POINT_ESTABLISHED),circ->p_circ_id,safe_str(serviceid));
						return 0;
					}
				}
			}
			crypto_free_pk_env(pk);
		}
	}
	circuit_mark_for_close(TO_CIRCUIT(circ), reason);
	return -1;
}

/** Process an INTRODUCE1 cell by finding the corresponding introduction
 * circuit, and relaying the body of the INTRODUCE1 cell inside an
 * INTRODUCE2 cell.
 */
int rend_mid_introduce(or_circuit_t *circ, const uint8_t *request, size_t request_len)
{	or_circuit_t *intro_circ;
	char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
	char nak_body[1];

	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_INTRODUCE1_RECEIVED),circ->p_circ_id);
	if(circ->_base.purpose != CIRCUIT_PURPOSE_OR || circ->_base.n_conn)
		log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_INTRODUCE1_REJECTED),circ->p_circ_id);
	else if(request_len < (DIGEST_LEN+(MAX_NICKNAME_LEN+1)+REND_COOKIE_LEN+DH_KEY_LEN+CIPHER_KEY_LEN+PKCS1_OAEP_PADDING_OVERHEAD))	/* We could change this to MAX_HEX_NICKNAME_LEN now that 0.0.9.x is obsolete; however, there isn't much reason to do so, and we're going to revise this protocol anyway. */
		log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_INTRODUCE1_TOO_SHORT),circ->p_circ_id);
	else
	{	base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,(char*)request, REND_SERVICE_ID_LEN);
		/* The first 20 bytes are all we look at: they have a hash of Bob's PK. */
		intro_circ = circuit_get_intro_point((char*)request);
		if(!intro_circ)
			log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_NO_INTRO_CIRC_FOR_INTRODUCE1),safe_str(serviceid),circ->p_circ_id);
		else
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_SENDING_INTRO_FOR_SERVICE),safe_str(serviceid),circ->p_circ_id,intro_circ->p_circ_id);
			/* Great.  Now we just relay the cell down the circuit. */
			if(relay_send_command_from_edge(0, TO_CIRCUIT(intro_circ),RELAY_COMMAND_INTRODUCE2,(char*)request, request_len, NULL))
				log_warn(LD_GENERAL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_INTRODUCE2));
			else
			{	/* And sent an ack down Alice's circuit.  Empty body means succeeded. */
				if(relay_send_command_from_edge(0,TO_CIRCUIT(circ),RELAY_COMMAND_INTRODUCE_ACK,NULL,0,NULL))
				{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_INTRODUCE_ACK));
					circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
					return -1;
				}
				return 0;
			}
		}
	}
	/* Send the client an NACK */
	nak_body[0] = 1;
	if(relay_send_command_from_edge(0,TO_CIRCUIT(circ),RELAY_COMMAND_INTRODUCE_ACK,nak_body, 1, NULL))
	{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_NAK));
		/* Is this right? */
		circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
	}
	return -1;
}

/** Process an ESTABLISH_RENDEZVOUS cell by setting the circuit's purpose and
 * rendezvous cookie.
 */
int rend_mid_establish_rendezvous(or_circuit_t *circ, const uint8_t *request,size_t request_len)
{	char hexid[9];
	int reason = END_CIRC_REASON_TORPROTOCOL;
	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_ESTABLISH_RENDEZVOUS),circ->p_circ_id);
	if(circ->_base.purpose != CIRCUIT_PURPOSE_OR || circ->_base.n_conn)
		log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_UNEXPECTED_REND));
	else if(request_len != REND_COOKIE_LEN)
		log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_ESTABLISH_RENDEZVOUS_INVALID_LENGTH));
	else if(circuit_get_rendezvous((char*)request))
		log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_ESTABLISH_RENDEZVOUS_DUPLICATE_COOKIE));
	else if(relay_send_command_from_edge(0,TO_CIRCUIT(circ),RELAY_COMMAND_RENDEZVOUS_ESTABLISHED,"", 0, NULL)<0)	/* Acknowledge the request. */
	{	log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_RENDEZVOUS_ESTABLISHED));
		reason = END_CIRC_REASON_INTERNAL;
	}
	else
	{	circ->_base.purpose = CIRCUIT_PURPOSE_REND_POINT_WAITING;
		tree_set_circ(TO_CIRCUIT(circ));
		memcpy(circ->rend_token, request, REND_COOKIE_LEN);
		base16_encode(hexid,9,(char*)request,4);
		log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_REND_ESTABLISHED),circ->p_circ_id,hexid);
		return 0;
	}
	circuit_mark_for_close(TO_CIRCUIT(circ), reason);
	return -1;
}

/** Process a RENDEZVOUS1 cell by looking up the correct rendezvous
 * circuit by its relaying the cell's body in a RENDEZVOUS2 cell, and
 * connecting the two circuits.
 */
int rend_mid_rendezvous(or_circuit_t *circ, const uint8_t *request,size_t request_len)
{	or_circuit_t *rend_circ;
	char hexid[9];
	int reason = END_CIRC_REASON_INTERNAL;
	base16_encode(hexid,9,(char*)request,request_len<4?request_len:4);
	if(request_len>=4)
		log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_GOT_REND_REQUEST_FROM_CIRC),circ->p_circ_id,hexid);
	if(circ->_base.purpose != CIRCUIT_PURPOSE_OR || circ->_base.n_conn)
	{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_UNEXPECTED_REND_2),circ->p_circ_id);
		reason = END_CIRC_REASON_TORPROTOCOL;
	}
	else if(request_len != REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN)
	{	log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_RENDEZVOUS1_WITH_BAD_LENGTH),(int)request_len,circ->p_circ_id);
		reason = END_CIRC_REASON_TORPROTOCOL;
	}
	else
	{	rend_circ = circuit_get_rendezvous((char*)request);
		if(!rend_circ)
		{	log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_RENDMID_RENDEZVOUS1_REJECTED),hexid);
			reason = END_CIRC_REASON_TORPROTOCOL;
		}
		else if(relay_send_command_from_edge(0, TO_CIRCUIT(rend_circ),RELAY_COMMAND_RENDEZVOUS2,(char*)(request+REND_COOKIE_LEN),request_len-REND_COOKIE_LEN, NULL))	/* Send the RENDEZVOUS2 cell to Alice. */
		{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_RENDMID_ERROR_SENDING_RENDEZVOUS2),rend_circ->p_circ_id);
		}
		else	/* Join the circuits. */
		{	log_info(LD_REND,get_lang_str(LANG_LOG_RENDMID_COMPLETING_REND),circ->p_circ_id,rend_circ->p_circ_id,hexid);
			circ->_base.purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
			tree_set_circ(TO_CIRCUIT(circ));
			rend_circ->_base.purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
			tree_set_circ(TO_CIRCUIT(rend_circ));
			memset(circ->rend_token, 0, REND_COOKIE_LEN);
			rend_circ->rend_splice = circ;
			circ->rend_splice = rend_circ;
			return 0;
		}
	}
	circuit_mark_for_close(TO_CIRCUIT(circ), reason);
	return -1;
}
