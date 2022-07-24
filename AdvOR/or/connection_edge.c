/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file connection_edge.c
 * \brief Handle edge streams.
 **/

#include "or.h"
#include "buffers.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "dns.h"
#include "dnsserv.h"
#include "dirserv.h"
#include "hibernate.h"
#include "main.h"
#include "policies.h"
#include "reasons.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <linux/netfilter_ipv4.h>
#define TRANS_NETFILTER
#endif

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_PFVAR_H)
#include <net/if.h>
#include <net/pfvar.h>
#define TRANS_PF
#endif

#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91

/** How long after we receive a hidden service descriptor do we consider
 * it valid? */
#define NUM_SECONDS_BEFORE_HS_REFETCH (60*15)

extern circuit_t *global_circuitlist;

int connection_ap_handshake_process_socks(edge_connection_t *conn);
static int connection_ap_process_natd(edge_connection_t *conn);
static int connection_exit_connect_dir(edge_connection_t *exitconn);
static int address_is_in_virtual_range(const char *addr);
static int consider_plaintext_ports(edge_connection_t *conn, uint16_t port);
static void clear_trackexithost_mappings(const char *exitname);
int plugins_remap(edge_connection_t *conn,char **address,char *original_address,BOOL is_error);
char *onionptr(char *address);
static void client_dns_set_addressmap_impl(const char *address, const char *name,const char *exitname,int ttl) __attribute__ ((format(ms_printf, 1, 0)));
static void client_dns_set_reverse_addressmap(const char *address, const char *v, const char *exitname, int ttl) __attribute__ ((format(ms_printf, 1, 0)));


/** An AP stream has failed/finished. If it hasn't already sent back a socks reply, send one now (based on endreason). Also set has_sent_end to 1, and mark the conn. */
void _connection_mark_unattached_ap(edge_connection_t *conn, int endreason,int line, const char *file)
{	tor_assert(conn->_base.type == CONN_TYPE_AP);
	conn->edge_has_sent_end = 1; /* no circ yet */
	if(conn->_base.marked_for_close)	/* This call will warn as appropriate. */
	{	_connection_mark_for_close(TO_CONN(conn), line, file);
		return;
	}
	if(!conn->socks_request->has_finished)
	{	if(endreason & END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED)
			log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_TWO_SOCKS_REPLIES),file,line);
		if(SOCKS_COMMAND_IS_CONNECT(conn->socks_request->command))
			connection_ap_handshake_socks_reply(conn, NULL, 0, endreason);
		else if (SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command))
			connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR_TRANSIENT,0,NULL,-1,-1);
		else /* unknown or no handshake at all. send no response. */
			conn->socks_request->has_finished = 1;
	}
	_connection_mark_for_close(TO_CONN(conn), line, file);
	conn->_base.hold_open_until_flushed = 1;
	conn->end_reason = endreason;
}

/** There was an EOF. Send an end and mark the connection for close. */
int connection_edge_reached_eof(edge_connection_t *conn)
{	if(buf_datalen(conn->_base.inbuf) && connection_state_is_open(TO_CONN(conn)))	/* it still has stuff to process. don't let it die yet. */
		return 0;
	log_info(LD_EDGE,get_lang_str(LANG_LOG_EDGE_CONN_REACHED_EOF),conn->_base.s);
	if(!conn->_base.marked_for_close)					/* only mark it if not already marked. it's possible to get the 'end' right around when the client hangs up on us. */
	{	connection_edge_end(conn, END_STREAM_REASON_DONE);
		if(conn->socks_request)	conn->socks_request->has_finished = 1;	/* eof, so don't send a socks reply back */
		connection_mark_for_close(TO_CONN(conn));
	}
	return 0;
}

/** Handle new bytes on conn->inbuf based on state:
 *   - If it's waiting for socks info, try to read another step of the socks handshake out of conn->inbuf.
 *   - If it's waiting for the original destination, fetch it.
 *   - If it's open, then package more relay cells from the stream.
 *   - Else, leave the bytes on inbuf alone for now.
 * Mark and return -1 if there was an unexpected error with the conn, else return 0. */
int connection_edge_process_inbuf(edge_connection_t *conn, int package_partial)
{	tor_assert(conn);
	switch(conn->_base.state)
	{	case AP_CONN_STATE_SOCKS_WAIT:
			if(connection_ap_handshake_process_socks(conn) < 0)	/* already marked */
			{	return -1;
			}
			return 0;
		case AP_CONN_STATE_NATD_WAIT:
			if(connection_ap_process_natd(conn) < 0)	/* already marked */
			{	return -1;
			}
			return 0;
		case AP_CONN_STATE_OPEN:
		case EXIT_CONN_STATE_OPEN:
			if(connection_edge_package_raw_inbuf(conn, package_partial,NULL) < 0)	/* (We already sent an end cell if possible) */
			{	connection_mark_for_close(TO_CONN(conn));
				return -1;
			}
			return 0;
		case EXIT_CONN_STATE_CONNECTING:
		case AP_CONN_STATE_RENDDESC_WAIT:
		case AP_CONN_STATE_CIRCUIT_WAIT:
		case AP_CONN_STATE_CONNECT_WAIT:
		case AP_CONN_STATE_RESOLVE_WAIT:
		case AP_CONN_STATE_CONTROLLER_WAIT:
			log_info(LD_EDGE,get_lang_str(LANG_LOG_EDGE_RECEIVED_DATA_IN_UNEXPECTED_STATE),conn_state_to_string(conn->_base.type, conn->_base.state));
			return 0;
	}
	log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_UNEXPECTED_STATE),conn->_base.state);
	tor_fragile_assert();
	connection_edge_end(conn, END_STREAM_REASON_INTERNAL);
	connection_mark_for_close(TO_CONN(conn));
	return -1;
}

/** This edge needs to be closed, because its circuit has closed. Mark it for close and return 0. */
int connection_edge_destroy(circid_t circ_id, edge_connection_t *conn)
{	if(!conn->_base.marked_for_close)
	{	log_info(LD_EDGE,get_lang_str(LANG_LOG_EDGE_CIRCID_AT_AN_EDGE),circ_id);
		if(conn->_base.type == CONN_TYPE_AP)
		{	connection_mark_unattached_ap(conn, END_STREAM_REASON_DESTROY);
			control_event_stream_status(conn, STREAM_EVENT_CLOSED,END_STREAM_REASON_DESTROY);
			conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
		}
		else	/* closing the circuit, nothing to send an END to */
		{	conn->edge_has_sent_end = 1;
			conn->end_reason = END_STREAM_REASON_DESTROY;
			conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
			connection_mark_for_close(TO_CONN(conn));
			conn->_base.hold_open_until_flushed = 1;
		}
	}
	conn->cpath_layer = NULL;
	conn->on_circuit = NULL;
	return 0;
}

/** Send a raw end cell to the stream with ID <b>stream_id</b> out over the <b>circ</b> towards the hop identified with <b>cpath_layer</b>. If this is not a client connection, set the relay end cell's reason for closing as <b>reason</b> */
static int relay_send_end_cell_from_edge(streamid_t stream_id, circuit_t *circ,uint8_t reason, crypt_path_t *cpath_layer)
{	char payload[1];
	if(CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose))	/* Never send the server an informative reason code; it doesn't need to know why the client stream is failing. */
		reason = END_STREAM_REASON_MISC;
	payload[0] = (char) reason;
	return relay_send_command_from_edge(stream_id, circ, RELAY_COMMAND_END,payload, 1, cpath_layer);
}

/** Send a relay end cell from stream <b>conn</b> down conn's circuit, and remember that we've done so.  If this is not a client connection, set the relay end cell's reason for closing as <b>reason</b>.
 * Return -1 if this function has already been called on this conn, else return 0. */
int connection_edge_end(edge_connection_t *conn, uint8_t reason)
{	char payload[RELAY_PAYLOAD_SIZE];
	size_t payload_len=1;
	circuit_t *circ;
	uint8_t control_reason = reason;
	if(conn->edge_has_sent_end)
	{	log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_CONNECTION_EDGE_END_ON_ALREADY_ENDED), reason);
		tor_fragile_assert();
		return -1;
	}
	if(conn->_base.marked_for_close)
	{	log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_CALLED_ON_CONN_MARKED_FOR_CLOSE),conn->_base.marked_for_close_file,conn->_base.marked_for_close);
		return 0;
	}
	circ = circuit_get_by_edge_conn(conn);
	if(circ && CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose))	/* If this is a client circuit, don't send the server an informative reason code; it doesn't need to know why the client stream is failing. */
		reason = END_STREAM_REASON_MISC;
	payload[0] = (char)reason;
	if(reason == END_STREAM_REASON_EXITPOLICY && !connection_edge_is_rendezvous_stream(conn))
	{	int addrlen;
		if(tor_addr_family(&conn->_base.addr) == AF_INET)
		{	set_uint32(payload+1, tor_addr_to_ipv4n(&conn->_base.addr));
			addrlen = 4;
		}
		else
		{	memcpy(payload+1, tor_addr_to_in6_addr8(&conn->_base.addr), 16);
			addrlen = 16;
		}
		set_uint32(payload+1+addrlen, htonl(dns_clip_ttl(conn->address_ttl)));
		payload_len += 4+addrlen;
	}
	if(circ && !circ->marked_for_close)
	{	log_debug(LD_EDGE,get_lang_str(LANG_LOG_EDGE_SENDING_END_ON_CONN),conn->_base.s);
		connection_edge_send_command(conn, RELAY_COMMAND_END,payload, payload_len);
	}
	else	log_debug(LD_EDGE,get_lang_str(LANG_LOG_EDGE_NO_CIRC_TO_SEND_END),conn->_base.s);
	conn->edge_has_sent_end = 1;
	conn->end_reason = control_reason;
	return 0;
}

/** An error has just occured on an operation on an edge connection <b>conn</b>.  Extract the errno; convert it to an end reason, and send an appropriate relay end cell to the other end of the connection's circuit. **/
int connection_edge_end_errno(edge_connection_t *conn)
{	uint8_t reason;
	tor_assert(conn);
	reason = errno_to_stream_end_reason(tor_socket_errno(conn->_base.s));
	return connection_edge_end(conn, reason);
}

/** We just wrote some data to <b>conn</b>; act appropriately.
 *
 * (That is, if it's open, consider sending a stream-level sendme cell if we
 * have just flushed enough.)
 */
int
connection_edge_flushed_some(edge_connection_t *conn)
{
  switch (conn->_base.state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_edge_consider_sending_sendme(conn);
      break;
  }
  return 0;
}

/** Connection <b>conn</b> has finished writing and has no bytes left on its outbuf.
 * If it's in state 'open', stop writing, consider responding with a sendme, and return.
 * Otherwise, stop writing and return.
 * If <b>conn</b> is broken, mark it for close and return -1, else return 0. */
int connection_edge_finished_flushing(edge_connection_t *conn)
{	tor_assert(conn);
	switch(conn->_base.state)
	{	case AP_CONN_STATE_OPEN:
		case EXIT_CONN_STATE_OPEN:
			connection_stop_writing(TO_CONN(conn));
			connection_edge_consider_sending_sendme(conn);
			return 0;
		case AP_CONN_STATE_SOCKS_WAIT:
		case AP_CONN_STATE_NATD_WAIT:
		case AP_CONN_STATE_RENDDESC_WAIT:
		case AP_CONN_STATE_CIRCUIT_WAIT:
		case AP_CONN_STATE_CONNECT_WAIT:
		case AP_CONN_STATE_CONTROLLER_WAIT:
			connection_stop_writing(TO_CONN(conn));
			return 0;
		default:
			log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_CALLED_IN_UNEXPECTED_STATE),conn->_base.state);
			tor_fragile_assert();
			return -1;
	}
	return 0;
}

/** Connected handler for exit connections: start writing pending data, deliver 'CONNECTED' relay cells as appropriate, and check any pending data that may have been received. */
int connection_edge_finished_connecting(edge_connection_t *edge_conn)
{	connection_t *conn;
	tor_assert(edge_conn);
	tor_assert(edge_conn->_base.type == CONN_TYPE_EXIT);
	conn = TO_CONN(edge_conn);
	tor_assert(conn->state == EXIT_CONN_STATE_CONNECTING);
	char *esc_l = escaped_safe_str(conn->address);
	log_info(LD_EXIT,get_lang_str(LANG_LOG_EDGE_EXIT_CONNECTION_ESTABLISHED),esc_l,conn->port,safe_str(fmt_addr(&conn->addr)));
	tor_free(esc_l);
	rep_hist_note_exit_stream_opened(conn->port);
	conn->state = EXIT_CONN_STATE_OPEN;
	connection_watch_events(conn,READ_EVENT); /* stop writing, continue reading */
	if (connection_wants_to_flush(conn))	connection_start_writing(conn);	/* in case there are any queued relay cells */
	/* deliver a 'connected' relay cell back through the circuit. */
	if(connection_edge_is_rendezvous_stream(edge_conn))
	{	if(connection_edge_send_command(edge_conn,RELAY_COMMAND_CONNECTED, NULL, 0) < 0)	return 0; /* circuit is closed, don't continue */
	}
	else
	{	char connected_payload[20];
		int connected_payload_len;
		if(tor_addr_family(&conn->addr) == AF_INET)
		{	set_uint32(connected_payload, tor_addr_to_ipv4n(&conn->addr));
			set_uint32(connected_payload+4,htonl(dns_clip_ttl(edge_conn->address_ttl)));
			connected_payload_len = 8;
		}
		else
		{	memcpy(connected_payload, tor_addr_to_in6_addr8(&conn->addr), 16);
			set_uint32(connected_payload+16,htonl(dns_clip_ttl(edge_conn->address_ttl)));
			connected_payload_len = 20;
		}
		if(connection_edge_send_command(edge_conn,RELAY_COMMAND_CONNECTED,connected_payload, connected_payload_len) < 0)
			return 0; /* circuit is closed, don't continue */
	}
	tor_assert(edge_conn->package_window > 0);
	return connection_edge_process_inbuf(edge_conn, 1);	/* in case the server has written anything */
}

/** Define a schedule for how long to wait between retrying application connections. Rather than waiting a fixed amount of time between each retry, we wait 10 seconds each for the first two tries, and 15 seconds for each retry after that. Hopefully this will improve the expected user experience. */
static int compute_retry_timeout(edge_connection_t *conn)
{	int timeout = get_options()->CircuitStreamTimeout;
	if(timeout)	return timeout;	/* if our config options override the default, use them */
	if(conn->num_socks_retries < 2)	return 10;	/* try 0 and try 1 */
	return 15;
}

/** Find all general-purpose AP streams waiting for a response that sent their begin/resolve cell >=15 seconds ago. Detach from their current circuit, and mark their current circuit as unsuitable for new streams. Then call connection_ap_handshake_attach_circuit() to attach to a new circuit (if available) or launch a new one.
 * For rendezvous streams, simply give up after SocksTimeout seconds (with no retry attempt). */
void connection_ap_expire_beginning(void)
{	edge_connection_t *conn;
	circuit_t *circ;
	time_t now = get_time(NULL);
	or_options_t *options = get_options();
	int severity;
	int cutoff;
	int seconds_idle, seconds_since_born;
	smartlist_t *conns = get_connection_array();
	SMARTLIST_FOREACH_BEGIN(conns, connection_t *, c)
	{	if(c->type != CONN_TYPE_AP || c->marked_for_close)
			continue;
		conn = TO_EDGE_CONN(c);
		if(get_router_sel()==0x100007f)
		{	connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
			continue;
		}
		/* if it's an internal linked connection, don't yell its status. */
		severity = (tor_addr_is_null(&conn->_base.addr) && !conn->_base.port) ? LOG_INFO : LOG_NOTICE;
		seconds_idle = (int)( now - conn->_base.timestamp_lastread );
		seconds_since_born = (int)( now - conn->_base.timestamp_created );
		if(conn->_base.state == AP_CONN_STATE_OPEN)	continue;
		/* We already consider SocksTimeout in connection_ap_handshake_attach_circuit(), but we need to consider it here too because controllers that put streams in controller_wait state never ask Tor to attach the circuit. */
		if(AP_CONN_STATE_IS_UNATTACHED(conn->_base.state))
		{	if(seconds_since_born >= options->SocksTimeout)
			{	log_fn(severity, LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECTION_TIMEOUT),seconds_since_born, safe_str_client(conn->socks_request->address),conn->socks_request->port,conn_state_to_string(CONN_TYPE_AP, conn->_base.state));
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
			}
			continue;
		}
		/* We're in state connect_wait or resolve_wait now -- waiting for a reply to our relay cell. See if we want to retry/give up. */
		cutoff = compute_retry_timeout(conn);
		if(seconds_idle < cutoff)	continue;
		circ = circuit_get_by_edge_conn(conn);
		if(!circ)	/* it's vanished? */
		{	log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_CONN_LOST_CIRC),safe_str_client(conn->socks_request->address));
			connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
			continue;
		}
		if(circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED)
		{	if(seconds_idle >= options->SocksTimeout)
			{	log_fn(severity, LD_REND,get_lang_str(LANG_LOG_EDGE_REND_TIMEOUT),seconds_idle,safe_str_client(conn->socks_request->address));
				connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
			}
			continue;
		}
		tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
		log_fn(cutoff < 15 ? LOG_INFO : severity, LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECTION_TIMEOUT_2),seconds_idle, safe_str_client(conn->socks_request->address),conn->cpath_layer ?extend_info_describe(conn->cpath_layer->extend_info) : "*unnamed*");
		/* send an end down the circuit */
		connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
		/* un-mark it as ending, since we're going to reuse it */
		conn->edge_has_sent_end = 0;
		conn->end_reason = 0;
		/* kludge to make us not try this circuit again, yet to allow current streams on it to survive if they can: make it unattractive to use for new streams */
		if(options->MaxCircuitDirtiness)
			circ->timestamp_dirty -= options->MaxCircuitDirtiness;
		/* give our stream another 'cutoff' seconds to try */
		conn->_base.timestamp_lastread += cutoff;
		if(conn->num_socks_retries < 250)	conn->num_socks_retries++;	/* avoid overflow */
		/* move it back into 'pending' state, and try to attach. */
		if(connection_ap_detach_retriable(conn, TO_ORIGIN_CIRCUIT(circ),END_STREAM_REASON_TIMEOUT)<0)
		{	if(!conn->_base.marked_for_close)
				connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
		}
	} SMARTLIST_FOREACH_END(conn);
}

/** Tell any AP streams that are waiting for a new circuit to try again, either attaching to an available circ or launching a new one. */
void connection_ap_attach_pending(void)
{	edge_connection_t *edge_conn;
	smartlist_t *conns = get_connection_array();
	SMARTLIST_FOREACH(conns, connection_t *, conn,
	{	if(conn->marked_for_close || conn->type != CONN_TYPE_AP || conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
			continue;
		edge_conn = TO_EDGE_CONN(conn);
		if(connection_ap_handshake_attach_circuit(edge_conn) < 0)
		{	if(!edge_conn->_base.marked_for_close)
				connection_mark_unattached_ap(edge_conn,END_STREAM_REASON_CANT_ATTACH);
		}
	});
}

/** Tell any AP streams that are waiting for a onehop tunnel to <b>failed_digest</b> that they are going to fail. */
/* XXX022 We should get rid of this function, and instead attach onehop streams to circ->p_streams so they get marked in circuit_mark_for_close like normal p_streams. */
void connection_ap_fail_onehop(const char *failed_digest,cpath_build_state_t *build_state)
{	edge_connection_t *edge_conn;
	char digest[DIGEST_LEN];
	smartlist_t *conns = get_connection_array();
	SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn)
	{	if(conn->marked_for_close || conn->type != CONN_TYPE_AP || conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
			continue;
		edge_conn = TO_EDGE_CONN(conn);
		if(!edge_conn->want_onehop)
			continue;
		if(hexdigest_to_digest(edge_conn->chosen_exit_name, digest) < 0 || tor_memneq(digest, failed_digest, DIGEST_LEN))
			continue;
		if(tor_digest_is_zero(digest))	/* we don't know the digest; have to compare addr:port */
		{	tor_addr_t addr;
			if(!build_state || !build_state->chosen_exit || !edge_conn->socks_request || !edge_conn->socks_request->address)
				continue;
			if(tor_addr_from_str(&addr, edge_conn->socks_request->address)<0 || !tor_addr_eq(&build_state->chosen_exit->addr, &addr) || build_state->chosen_exit->port != edge_conn->socks_request->port)
				continue;
		}
		log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_CLOSING_STREAM_FAILED),edge_conn->chosen_exit_name,edge_conn->socks_request->address);
		connection_mark_unattached_ap(edge_conn, END_STREAM_REASON_TIMEOUT);
	} SMARTLIST_FOREACH_END(conn);
}

/** A circuit failed to finish on its last hop <b>info</b>. If there are any streams waiting with this exit node in mind, but they don't absolutely require it, make them give up on it. */
void circuit_discard_optional_exit_enclaves(extend_info_t *info)
{	edge_connection_t *edge_conn;
	routerinfo_t *r1, *r2;
	smartlist_t *conns = get_connection_array();
	SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn)
	{	if(conn->marked_for_close || conn->type != CONN_TYPE_AP || conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
			continue;
		edge_conn = TO_EDGE_CONN(conn);
		if(!edge_conn->chosen_exit_optional && !edge_conn->chosen_exit_retries)
			continue;
		r1 = router_get_by_nickname(edge_conn->chosen_exit_name, 0);
		r2 = router_get_by_digest(info->identity_digest);
		if(!r1 || !r2 || r1 != r2)
			continue;
		tor_assert(edge_conn->socks_request);
		if(edge_conn->chosen_exit_optional)
		{	char *esc_l = escaped_safe_str_client(edge_conn->socks_request->address);
			log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_GIVING_UP_ON_ENCLAVE_EXIT),safe_str_client(edge_conn->chosen_exit_name),esc_l);
			tor_free(esc_l);
			edge_conn->chosen_exit_optional = 0;
			tor_free(edge_conn->chosen_exit_name); /* clears it */
			/* if this port is dangerous, warn or reject it now that we don't think it'll be using an enclave. */
			consider_plaintext_ports(edge_conn, edge_conn->socks_request->port);
		}
		if(edge_conn->chosen_exit_retries)
		{	if(--edge_conn->chosen_exit_retries == 0)	/* give up! */
			{	clear_trackexithost_mappings(edge_conn->chosen_exit_name);
				tor_free(edge_conn->chosen_exit_name); /* clears it */
				/* if this port is dangerous, warn or reject it now that we don't think it'll be using an enclave. */
				consider_plaintext_ports(edge_conn, edge_conn->socks_request->port);
			}
		}
	} SMARTLIST_FOREACH_END(conn);
}

/** The AP connection <b>conn</b> has just failed while attaching or sending a BEGIN or resolving on <b>circ</b>, but another circuit might work. Detach the circuit, and either reattach it, launch a new circuit, tell the controller, or give up as a appropriate.
 * Returns -1 on err, 1 on success, 0 on not-yet-sure. */
int connection_ap_detach_retriable(edge_connection_t *conn, origin_circuit_t *circ,int reason)
{	control_event_stream_status(conn, STREAM_EVENT_FAILED_RETRIABLE, reason);
	conn->_base.timestamp_lastread = get_time(NULL);
	if(!get_options()->LeaveStreamsUnattached || conn->use_begindir)
	{	/* If we're attaching streams ourself, or if this connection is a tunneled directory connection, then just attach it. */
		conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
		circuit_detach_stream(TO_CIRCUIT(circ),conn);
		return connection_ap_handshake_attach_circuit(conn);
	}
	else
	{	conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
		circuit_detach_stream(TO_CIRCUIT(circ),conn);
		return 0;
	}
}

/** A client-side struct to remember requests to rewrite addresses
 * to new addresses. These structs are stored in the hash table
 * "addressmap" below.
 *
 * There are 5 ways to set an address mapping:
 * - A MapAddress command from the controller [permanent]
 * - An AddressMap directive in the torrc [permanent]
 * - When a TrackHostExits torrc directive is triggered [temporary]
 * - When a DNS resolve succeeds [temporary]
 * - When a DNS resolve fails [temporary]
 *
 * When an addressmap request is made but one is already registered,
 * the new one is replaced only if the currently registered one has
 * no "new_address" (that is, it's in the process of DNS resolve),
 * or if the new one is permanent (expires==0 or 1).
 *
 * (We overload the 'expires' field, using "0" for mappings set via
 * the configuration file, "1" for mappings set from the control
 * interface, and other values for DNS and TrackHostExit mappings that can
 * expire.)
 */
typedef struct {
  char *new_address;
  time_t expires;
  addressmap_entry_source_t source:3;
  short num_resolve_failures;
} addressmap_entry_t;

/** Entry for mapping addresses to which virtual address we mapped them to. */
typedef struct {
  char *ipv4_address;
  char *hostname_address;
} virtaddress_entry_t;
 
/** A hash table to store client-side address rewrite instructions. */
static strmap_t *addressmap=NULL;
/** Table mapping addresses to which virtual address, if any, we assigned them to.
 *  We maintain the following invariant: if [A,B] is in virtaddress_reversemap, then B must be a virtual address, and [A,B] must be in addressmap. We do not require that the converse hold: if it fails, then we could end up mapping two virtual addresses to the same address, which is no disaster. **/
static strmap_t *virtaddress_reversemap=NULL;

/** Initialize addressmap. */
void addressmap_init(void)
{	addressmap = strmap_new();
	virtaddress_reversemap = strmap_new();
}

/** Free the memory associated with the addressmap entry <b>_ent</b>. */
#ifdef DEBUG_MALLOC
static void addressmap_ent_free(void *_ent,const char *c,int n)
{	addressmap_entry_t *ent;
	if(!_ent)	return;
	ent = _ent;
	_tor_free_(ent->new_address,c,n);
	tor_free(ent);
}
#else
static void addressmap_ent_free(void *_ent)
{	addressmap_entry_t *ent;
	if(!_ent)	return;
	ent = _ent;
	_tor_free_(ent->new_address);
	tor_free(ent);
}
#endif

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
#ifdef DEBUG_MALLOC
static void addressmap_virtaddress_ent_free(void *_ent,const char *c,int n)
{	virtaddress_entry_t *ent;
	if(!_ent)	return;
	ent = _ent;
	_tor_free_(ent->ipv4_address,c,n);
	_tor_free_(ent->hostname_address,c,n);
	tor_free(ent);
}
#else
static void addressmap_virtaddress_ent_free(void *_ent)
{	virtaddress_entry_t *ent;
	if(!_ent)	return;
	ent = _ent;
	_tor_free_(ent->ipv4_address);
	_tor_free_(ent->hostname_address);
	tor_free(ent);
}
#endif

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
static void addressmap_virtaddress_remove(const char *address, addressmap_entry_t *ent)
{	if(ent && ent->new_address && address_is_in_virtual_range(ent->new_address))
	{	virtaddress_entry_t *ve = strmap_get(virtaddress_reversemap, ent->new_address);
		/*log_fn(LOG_NOTICE,"remove reverse mapping for %s",ent->new_address);*/
		if(ve)
		{	if(!strcmp(address, ve->ipv4_address))
				tor_free(ve->ipv4_address);
			if(!strcmp(address, ve->hostname_address))
				tor_free(ve->hostname_address);
			if(!ve->ipv4_address && !ve->hostname_address)
			{	tor_free(ve);
				strmap_remove(virtaddress_reversemap, ent->new_address);
			}
		}
	}
}

/** Remove <b>ent</b> (which must be mapped to by <b>address</b>) from the client address maps. */
static void addressmap_ent_remove(const char *address, addressmap_entry_t *ent)
{	addressmap_virtaddress_remove(address, ent);
#ifdef DEBUG_MALLOC
	addressmap_ent_free(ent,__FILE__,__LINE__);
#else
	addressmap_ent_free(ent);
#endif
}

/** Unregister all TrackHostExits mappings from any address to *.exitname.exit. */
static void clear_trackexithost_mappings(const char *exitname)
{	char *suffix;
	size_t suffix_len;
	if(!addressmap || !exitname)	return;
	suffix_len = strlen(exitname) + 16;
	suffix = tor_malloc(suffix_len);
	tor_snprintf(suffix, suffix_len, ".%s.exit", exitname);
	tor_strlower(suffix);
	log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_TRACKHOSTEXITS_CLEAR_ENTRY),safe_str(exitname));
	STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent)
	{	if(ent->source == ADDRMAPSRC_TRACKEXIT && !strcmpend(ent->new_address, suffix))
		{	addressmap_ent_remove(address, ent);
			MAP_DEL_CURRENT(address);
		}
	} STRMAP_FOREACH_END;
	tor_free(suffix);
}

/** Remove all TRACKEXIT mappings from the addressmap for which the target host is unknown or no longer allowed, or for which the source address is no longer in trackexithosts. */
void addressmap_clear_excluded_trackexithosts(or_options_t *options)
{	const routerset_t *allow_nodes = options->ExitNodes;
	const routerset_t *exclude_nodes = options->_ExcludeExitNodesUnion;
	if(!addressmap)				return;
	if(routerset_is_empty(allow_nodes))	allow_nodes = NULL;
	if(allow_nodes == NULL && routerset_is_empty(exclude_nodes))
		return;
	STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent)
	{	size_t len;
		const char *target = ent->new_address, *dot;
		char *nodename;
		routerinfo_t *ri; /* XXX023 Use node_t. */
		if(!target)					continue;	/* DNS resolving in progress */
		else if(strcmpend(target, ".exit"))		continue;	/* Not a .exit mapping */
		else if (ent->source != ADDRMAPSRC_TRACKEXIT)	continue;	/* Not a trackexit mapping. */
		len = strlen(target);
		if(len < 6)					continue;	/* malformed. */
		dot = target + len - 6; /* dot now points to just before .exit */
		while(dot > target && *dot != '.')		dot--;
		if(*dot == '.')					dot++;
		nodename = tor_strndup(dot, len-5-(dot-target));
		ri = router_get_by_nickname(nodename, 0);
		tor_free(nodename);
		if(!ri || (allow_nodes && !routerset_contains_router(allow_nodes, ri)) || routerset_contains_router(exclude_nodes, ri) || !hostname_in_track_host_exits(options, address))
		{	addressmap_ent_remove(address, ent);	/* We don't know this one, or we want to be rid of it. */
			MAP_DEL_CURRENT(address);
		}
	} STRMAP_FOREACH_END;
}

/** Remove all AUTOMAP mappings from the addressmap for which the source address no longer matches AutomapHostsSuffixes, which is no longer allowed by AutomapHostsOnResolve, or for which the target address is no longer in the virtual network. */
void addressmap_clear_invalid_automaps(or_options_t *options)
{	int clear_all = !options->AutomapHostsOnResolve;
	const smartlist_t *suffixes = options->AutomapHostsSuffixes;
	if(!addressmap)		return;
	if(!suffixes)		clear_all = 1;	/* This should be impossible, but let's be sure. */
	STRMAP_FOREACH_MODIFY(addressmap, src_address, addressmap_entry_t *, ent)
	{	int remove = clear_all;
		if(ent->source == ADDRMAPSRC_AUTOMAP)
		{	if(!remove)
			{	int suffix_found = 0;
				SMARTLIST_FOREACH(suffixes, const char *, suffix,
				{	if(!strcasecmpend(src_address, suffix))
					{	suffix_found = 1;
						break;
					}
				});
				if(!suffix_found)	remove = 1;
			}
			if(remove || !address_is_in_virtual_range(ent->new_address))
			{	addressmap_ent_remove(src_address, ent);
				MAP_DEL_CURRENT(src_address);
			}
		}
	} STRMAP_FOREACH_END;
}

/** Remove all entries from the addressmap that were set via the configuration file or the command line. */
void addressmap_clear_configured(void)
{	addressmap_get_mappings(NULL, 0, 0, 0);
}

/** Remove all entries from the addressmap that are set to expire, ever. */
void addressmap_clear_transient(void)
{	addressmap_get_mappings(NULL, 2, TIME_MAX, 0);
}

/** Clean out entries from the addressmap cache that were added long enough ago that they are no longer valid. */
void addressmap_clean(time_t now)
{	addressmap_get_mappings(NULL, 2, now, 0);
}

/** Free all the elements in the addressmap, and free the addressmap itself. */
void addressmap_free_all(void)
{	if(addressmap)
	{	strmap_free(addressmap, addressmap_ent_free);
		addressmap = NULL;
	}
	if(virtaddress_reversemap)
	{	strmap_free(virtaddress_reversemap, addressmap_virtaddress_ent_free);
		virtaddress_reversemap = NULL;
	}
}

/** Look at address, and rewrite it until it doesn't want any more rewrites; but don't get into an infinite loop. Don't write more than maxlen chars into address. Return true if the address changed; false otherwise. Set *<b>expires_out</b> to the expiry time of the result, or to <b>time_max</b> if the result does not expire. */
int addressmap_rewrite(char **address, time_t *expires_out)
{	addressmap_entry_t *ent;
	int rewrites;
	char *cp,*esc_l;
	time_t expires = TIME_MAX;
	for(rewrites = 0; rewrites < 16; rewrites++)
	{	ent = strmap_get(addressmap, *address);
		if(!ent || !ent->new_address)
		{	if(expires_out)	*expires_out = expires;
			return (rewrites > 0); /* done, no rewrite needed */
		}
		cp = escaped_safe_str_client(ent->new_address);
		esc_l = escaped_safe_str_client(*address);
		log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_REWRITE_ADDRESS),esc_l, cp);
		if(ent->expires > 1 && ent->expires < expires)	expires = ent->expires;
		tor_free(cp);
		tor_free(esc_l);
		if(*address)	tor_free(*address);
		*address = tor_strdup(ent->new_address);
	}
	esc_l = escaped_safe_str_client(*address);
	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_REWRITTEN_TOO_MUCH),esc_l);
	tor_free(esc_l);
	/* it's fine to rewrite a rewrite, but don't loop forever */
	if(expires_out)	*expires_out = TIME_MAX;
	return 1;
}

/** If we have a cached reverse DNS entry for the address stored in the <b>maxlen</b>-byte buffer <b>address</b> (typically, a dotted quad) then rewrite to the cached value and return 1. Otherwise return 0. Set *<b>expires_out</b> to the expiry time of the result, or to <b>time_max</b> if the result does not expire. */
static int addressmap_rewrite_reverse(char **address,time_t *expires_out)
{	unsigned char *s, *cp,*esc_l;
	addressmap_entry_t *ent;
	int r = 0;
	tor_asprintf(&s,"REVERSE[%s]",*address);
	ent = strmap_get(addressmap, (char *)s);
	if(ent)
	{	cp = (unsigned char *)escaped_safe_str_client(ent->new_address);
		esc_l = (unsigned char *)escaped_safe_str_client((char *)s);
		log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_REWRITE_REVDNS),esc_l,cp);
		tor_free(cp);
		tor_free(esc_l);
		tor_free(*address);
		*address = tor_strdup(ent->new_address);
		r = 1;
	}
	if(expires_out)	*expires_out = (ent && ent->expires > 1) ? ent->expires : TIME_MAX;
	tor_free(s);
	return r;
}

/** Return 1 if <b>address</b> is already registered, else return 0. If address is already registered, and <b>update_expires</b> is non-zero, then update the expiry time on the mapping with update_expires if it is a mapping created by TrackHostExits. */
int addressmap_have_mapping(const char *address, int update_expiry)
{	addressmap_entry_t *ent;
	if(!(ent=strmap_get_lc(addressmap, address)))
		return 0;
	if(update_expiry && ent->source==ADDRMAPSRC_TRACKEXIT)
		ent->expires=get_time(NULL) + update_expiry;
	return 1;
}

/** Register a request to map <b>address</b> to <b>new_address</b>, which will expire on <b>expires</b> (or 0 if never expires from config file, 1 if never expires from controller, 2 if never expires (virtual address mapping) from the controller.)
 * <b>new_address</b> should be a newly dup'ed string, which we'll use or free as appropriate. We will leave address alone. If <b>new_address</b> is NULL, or equal to <b>address</b>, remove any mappings that exist from <b>address</b>. */
void addressmap_register(char *address, char *new_address, time_t expires,addressmap_entry_source_t source)
{	addressmap_entry_t *ent;
	ent = strmap_get(addressmap, address);
	if(!new_address || !strcasecmp(address,new_address))	/* Remove the mapping, if any. */
	{	tor_free(new_address);
		if(ent)
		{	addressmap_ent_remove(address,ent);
			strmap_remove(addressmap, address);
		}
		return;
	}
	if(!ent)	/* make a new one and register it */
	{	ent = tor_malloc_zero(sizeof(addressmap_entry_t));
		strmap_set(addressmap, address, ent);
	}
	else if(ent->new_address)	/* we need to clean up the old mapping. */
	{	if(expires > 1)
		{	log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_ADDR_ALREADY_MAPPED),safe_str_client(address), safe_str_client(new_address), safe_str_client(ent->new_address));
			tor_free(new_address);
			return;
		}
		if(address_is_in_virtual_range(ent->new_address) && expires != 2)	/* XXX This isn't the perfect test; we want to avoid removing mappings set from the control interface _as virtual mapping */
			addressmap_virtaddress_remove(address, ent);
		tor_free(ent->new_address);
	} /* else { we have an in-progress resolve with no mapping. } */
	ent->new_address = new_address;
	ent->expires = expires==2 ? 1 : expires;
	ent->num_resolve_failures = 0;
	ent->source = source;
	log_info(LD_CONFIG,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_REMAPPED_ADDR),safe_str_client(address), safe_str_client(ent->new_address));
	control_event_address_mapped(address, &ent->new_address, expires, NULL);
}

/** An attempt to resolve <b>address</b> failed at some OR.
 * Increment the number of resolve failures we have on record
 * for it, and then return that number.
 */
int
client_dns_incr_failures(const char *address)
{
  addressmap_entry_t *ent = strmap_get(addressmap, address);
  if (!ent) {
    ent = tor_malloc_zero(sizeof(addressmap_entry_t));
    ent->expires = get_time(NULL) + MAX_DNS_ENTRY_AGE;
    strmap_set(addressmap,address,ent);
  }
  if (ent->num_resolve_failures < SHORT_MAX)
    ++ent->num_resolve_failures; /* don't overflow */
  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESS_HAS_RESOLVE_FAILURES),safe_str_client(address),ent->num_resolve_failures);
  return ent->num_resolve_failures;
}

/** If <b>address</b> is in the client dns addressmap, reset
 * the number of resolve failures we have on record for it.
 * This is used when we fail a stream because it won't resolve:
 * otherwise future attempts on that address will only try once.
 */
void
client_dns_clear_failures(const char *address)
{
  addressmap_entry_t *ent = strmap_get(addressmap, address);
  if (ent)
    ent->num_resolve_failures = 0;
}

/** Record the fact that <b>address</b> resolved to <b>name</b>.
 * We can now use this in subsequent streams via addressmap_rewrite()
 * so we can more correctly choose an exit that will allow <b>address</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
static void client_dns_set_addressmap_impl(const char *address, const char *name,const char *exitname,int ttl)
{	unsigned char *extendedaddress;	/* <address>.<hex or nickname>.exit\0  or just  <address>\0 */
	unsigned char *extendedval;	/* 123.123.123.123.<hex or nickname>.exit\0  or just  123.123.123.123\0 */
	tor_assert(address);
	tor_assert(name);
	if(ttl<0)	ttl = DEFAULT_DNS_TTL;
	else		ttl = dns_clip_ttl(ttl);

	if(exitname)	/* XXXX fails to ever get attempts to get an exit address of google.com.digest[=~]nickname.exit; we need a syntax for this that won't make strict RFC952-compliant applications (like us) barf. */
	{	tor_asprintf(&extendedaddress,"%s.%s.exit", address, exitname);
		tor_asprintf(&extendedval,"%s.%s.exit", name, exitname);
	}
	else
	{	extendedaddress = (unsigned char *)tor_strdup(address);
		extendedval = (unsigned char *)tor_strdup(name);
	}
	addressmap_register((char *)extendedaddress,(char *)extendedval,get_time(NULL) + ttl,ADDRMAPSRC_DNS);
	tor_free(extendedaddress);
}

/** Record the fact that <b>address</b> resolved to <b>val</b>.
 * We can now use this in subsequent streams via addressmap_rewrite()
 * so we can more correctly choose an exit that will allow <b>address</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
void client_dns_set_addressmap(const char *address, uint32_t val, const char *exitname, int ttl)
{
  struct in_addr in;
  char valbuf[INET_NTOA_BUF_LEN];

  tor_assert(address);

  if (tor_inet_aton(address, &in))
    return; /* If address was an IP address already, don't add a mapping. */
  in.s_addr = htonl(val);
  tor_inet_ntoa(&in,valbuf,sizeof(valbuf));

  client_dns_set_addressmap_impl(address, valbuf, exitname, ttl);
}

/** Add a cache entry noting that <b>address</b> (ordinarily a dotted quad)
 * resolved via a RESOLVE_PTR request to the hostname <b>v</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
static void client_dns_set_reverse_addressmap(const char *address, const char *v, const char *exitname, int ttl)
{
  size_t len = strlen(address) + 16;
  char *s = tor_malloc(len);
  tor_snprintf(s, len, "REVERSE[%s]", address);
  client_dns_set_addressmap_impl(s, v, exitname, ttl);
  tor_free(s);
}

/* By default, we hand out 127.192.0.1 through 127.254.254.254.
 * These addresses should map to localhost, so even if the
 * application accidentally tried to connect to them directly (not
 * via Tor), it wouldn't get too far astray.
 *
 * These options are configured by parse_virtual_addr_network().
 */
/** Which network should we use for virtual IPv4 addresses?  Only the first
 * bits of this value are fixed. */
static uint32_t virtual_addr_network = 0x7fc00000u;
/** How many bits of <b>virtual_addr_network</b> are fixed? */
static maskbits_t virtual_addr_netmask_bits = 10;
/** What's the next virtual address we will hand out? */
static uint32_t next_virtual_addr    = 0x7fc00000u;

/** Read a netmask of the form 127.192.0.0/10 from "val", and check whether
 * it's a valid set of virtual addresses to hand out in response to MAPADDRESS
 * requests.  Return 0 on success; set *msg (if provided) to a newly allocated
 * string and return -1 on failure.  If validate_only is false, sets the
 * actual virtual address range to the parsed value. */
int
parse_virtual_addr_network(const char *val, int validate_only,
                           char **msg)
{
  uint32_t addr;
  uint16_t port_min, port_max;
  maskbits_t bits;

  if (parse_addr_and_port_range(val, &addr, &bits, &port_min, &port_max)) {
    if (msg) *msg = tor_strdup("Error parsing VirtualAddressNetwork");
    return -1;
  }

  if (port_min != 1 || port_max != 65535) {
    if (msg) *msg = tor_strdup("Can't specify ports on VirtualAddressNetwork");
    return -1;
  }

  if (bits > 16) {
    if (msg) *msg = tor_strdup("VirtualAddressNetwork expects a /16 "
                               "network or larger");
    return -1;
  }

  if (validate_only)
    return 0;

  virtual_addr_network = (uint32_t)( addr & (0xfffffffful << (32-bits)) );
  virtual_addr_netmask_bits = bits;

  if (addr_mask_cmp_bits(next_virtual_addr, addr, bits))
    next_virtual_addr = addr;

  return 0;
}

/**
 * Return true iff <b>addr</b> is likely to have been returned by
 * client_dns_get_unused_address.
 **/
static int
address_is_in_virtual_range(const char *address)
{
  struct in_addr in;
  tor_assert(address);
  if (!strcasecmpend(address, ".virtual")) {
    return 1;
  } else if (tor_inet_aton(address, &in)) {
    uint32_t addr = ntohl(in.s_addr);
    if (!addr_mask_cmp_bits(addr, virtual_addr_network,
                            virtual_addr_netmask_bits))
      return 1;
  }
  return 0;
}


/** Increment the value of next_virtual_addr; reset it to the start of the
 * virtual address range if it wraps around.
 */
static INLINE void
increment_virtual_addr(void)
{
  ++next_virtual_addr;
  if (addr_mask_cmp_bits(next_virtual_addr, virtual_addr_network,
                         virtual_addr_netmask_bits))
    next_virtual_addr = virtual_addr_network;
}

/** Return a newly allocated string holding an address of <b>type</b>
 * (one of RESOLVED_TYPE_{IPV4|HOSTNAME}) that has not yet been mapped,
 * and that is very unlikely to be the address of any real host.
 */
static char *
addressmap_get_virtual_address(int type)
{
  char buf[64];
  struct in_addr in;
  tor_assert(addressmap);

  if (type == RESOLVED_TYPE_HOSTNAME) {
    char rand[10];
    do {
      crypto_rand(rand, sizeof(rand));
      base32_encode(buf,sizeof(buf),rand,sizeof(rand));
      strlcat(buf, ".virtual", sizeof(buf));
    } while (strmap_get(addressmap, buf));
    return tor_strdup(buf);
  } else if (type == RESOLVED_TYPE_IPV4) {
    // This is an imperfect estimate of how many addresses are available, but
    // that's ok.
    uint32_t available = 1u << (32-virtual_addr_netmask_bits);
    while (available) {
      /* Don't hand out any .0 or .255 address. */
      while ((next_virtual_addr & 0xff) == 0 ||
             (next_virtual_addr & 0xff) == 0xff) {
        increment_virtual_addr();
        if (! --available) {
          log_warn(LD_CONFIG,get_lang_str(LANG_LOG_EDGE_OUT_OF_VIRTUAL_ADDRESSES));
          return NULL;
        }
      }
      in.s_addr = htonl(next_virtual_addr);
      tor_inet_ntoa(&in, buf, sizeof(buf));
      if (!strmap_get(addressmap, buf)) {
        increment_virtual_addr();
        break;
      }

      increment_virtual_addr();
      --available;
//      log_info(LD_CONFIG,get_lang_str(LANG_LOG_EDGE_ADDRS_AVAILABLE),(int)available);
      if (!available) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_EDGE_OUT_OF_VIRTUAL_ADDRESSES));
        return NULL;
      }
    }
    return tor_strdup(buf);
  } else {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_UNSUPPORTED_ADDRESS_TYPE),type);
    return NULL;
  }
}

/** A controller has requested that we map some address of type
 * <b>type</b> to the address <b>new_address</b>.  Choose an address
 * that is unlikely to be used, and map it, and return it in a newly
 * allocated string.  If another address of the same type is already
 * mapped to <b>new_address</b>, try to return a copy of that address.
 *
 * The string in <b>new_address</b> may be freed, or inserted into a map
 * as appropriate.
 **/
const char *
addressmap_register_virtual_address(int type, char *new_address)
{
  char **addrp;
  virtaddress_entry_t *vent;
  int vent_needs_to_be_added = 0;

  tor_assert(new_address);
  tor_assert(addressmap);
  tor_assert(virtaddress_reversemap);

  vent = strmap_get(virtaddress_reversemap, new_address);
  if (!vent) {
    vent = tor_malloc_zero(sizeof(virtaddress_entry_t));
    vent_needs_to_be_added = 1;
  }

  addrp = (type == RESOLVED_TYPE_IPV4) ?
    &vent->ipv4_address : &vent->hostname_address;
  if (*addrp) {
    addressmap_entry_t *ent = strmap_get(addressmap, *addrp);
    if (ent && ent->new_address &&
        !strcasecmp(new_address, ent->new_address)) {
      tor_free(new_address);
      tor_assert(!vent_needs_to_be_added);
      return tor_strdup(*addrp);
    } else
      log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_INTERNAL_CONFUSION),safe_str_client(new_address), safe_str_client(*addrp), safe_str_client(*addrp),ent?safe_str_client(ent->new_address):"(nothing)");
  }

  tor_free(*addrp);
  *addrp = addressmap_get_virtual_address(type);
  if (!*addrp) {
    tor_free(vent);
    tor_free(new_address);
    return NULL;
  }
  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_REGISTERING_NEW),*addrp,new_address);
  if (vent_needs_to_be_added)
    strmap_set(virtaddress_reversemap, new_address, vent);
  addressmap_register(*addrp, new_address, 2, ADDRMAPSRC_CONTROLLER);

//#if 0
  {
    /* Try to catch possible bugs */
    addressmap_entry_t *ent;
    ent = strmap_get(addressmap, *addrp);
    tor_assert(ent);
    tor_assert(!strcasecmp(ent->new_address,new_address));
    vent = strmap_get(virtaddress_reversemap, new_address);
    tor_assert(vent);
    tor_assert(!strcasecmp(*addrp,
                           (type == RESOLVED_TYPE_IPV4) ?
                           vent->ipv4_address : vent->hostname_address));
    log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_MAP_OK),safe_str_client(*addrp),safe_str_client(new_address));
  }
//#endif

  return *addrp;
}

/** Return 1 if <b>address</b> has funny characters in it like colons. Return
 * 0 if it's fine, or if we're configured to allow it anyway.  <b>client</b>
 * should be true if we're using this address as a client; false if we're
 * using it as a server.
 */
int
address_is_invalid_destination(const char *address, int client)
{
  if (client) {
    if (get_options()->AllowNonRFC953Hostnames)
      return 0;
  } else {
    if (get_options()->ServerDNSAllowNonRFC953Hostnames)
      return 0;
  }

  while (*address) {
    if (TOR_ISALNUM(*address) ||
        *address == '-' ||
        *address == '.' ||
        *address == '_') /* Underscore is not allowed, but Windows does it
                          * sometimes, just to thumb its nose at the IETF. */
      ++address;
    else
      return 1;
  }
  return 0;
}

/** Iterate over all address mappings which have expiry times between
 * min_expires and max_expires, inclusive.  If sl is provided, add an
 * "old-addr new-addr expiry" string to sl for each mapping, omitting
 * the expiry time if want_expiry is false. If sl is NULL, remove the
 * mappings.
 */
void addressmap_get_mappings(smartlist_t *sl, time_t min_expires,time_t max_expires, int want_expiry)
{	strmap_iter_t *iter;
	const char *key;
	void *_val;
	addressmap_entry_t *val;

	if(!addressmap)
		addressmap_init();
	for(iter = strmap_iter_init(addressmap);!strmap_iter_done(iter);)
	{	strmap_iter_get(iter, &key, &_val);
		val = _val;
		if(val->expires >= min_expires && val->expires <= max_expires)
		{	if(!sl)
			{	iter = strmap_iter_next_rmv(addressmap,iter);
				addressmap_ent_remove(key, val);
				continue;
			}
			else if(val->new_address)
			{	size_t len = strlen(key)+strlen(val->new_address)+ISO_TIME_LEN+5;
				char *line = tor_malloc(len);
				if(want_expiry)
				{	if(val->expires < 3 || val->expires == TIME_MAX)
						tor_snprintf(line,len, "%s %s NEVER", key, val->new_address);
					else
					{	char time[ISO_TIME_LEN+1];
						format_iso_time(time, val->expires);
						tor_snprintf(line, len, "%s %s \"%s\"", key, val->new_address,time);
					}
				}
				else	tor_snprintf(line, len, "%s %s", key, val->new_address);
				smartlist_add(sl, line);
			}
		}
		iter = strmap_iter_next(addressmap,iter);
	}
}

/** Check if <b>conn</b> is using a dangerous port. Then warn and/or
 * reject depending on our config options. */
static int
consider_plaintext_ports(edge_connection_t *conn, uint16_t port)
{
  or_options_t *options = get_options();
  int reject = smartlist_string_num_isin(options->RejectPlaintextPorts, port);

  if (smartlist_string_num_isin(options->WarnPlaintextPorts, port)) {
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_UNENCRYPTED_PROTOCOL), port, reject ? get_lang_str(LANG_LOG_EDGE_CLOSING) : "");
    control_event_client_status(LOG_WARN, "DANGEROUS_PORT PORT=%d RESULT=%s",
                                port, reject ? "REJECT" : "WARN");
  }

  if (reject) {
    log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_REJECTPLAINTEXTPORTS),port);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_ENTRYPOLICY);
    return -1;
  }

  return 0;
}

/** How many times do we try connecting with an exit configured via
 * TrackHostExits before concluding that it won't work any more and trying a
 * different one? */
#define TRACKHOSTEXITS_RETRIES (unsigned int)10

/** Call connection_ap_handshake_rewrite_and_attach() unless a controller asked us to leave streams unattached. Return 0 in that case.
 *  See connection_ap_handshake_rewrite_and_attach()'s documentation for arguments and return value. */
int connection_ap_rewrite_and_attach_if_allowed(edge_connection_t *conn,origin_circuit_t *circ,crypt_path_t *cpath)
{	or_options_t *options = get_options();
	if(options->LeaveStreamsUnattached)
	{	conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
		return 0;
	}
	return connection_ap_handshake_rewrite_and_attach(conn, circ, cpath);
}

/** Connection <b>conn</b> just finished its socks handshake, or the controller asked us to take care of it. If <b>circ</b> is defined, then that's where we'll want to attach it. Otherwise we have to figure it out ourselves.
 * First, parse whether it's a .exit address, remap it, and so on. Then if it's for a general circuit, try to attach it to a circuit (or launch one as needed), else if it's for a rendezvous circuit, fetch a rendezvous descriptor first (or attach/launch a circuit if the rendezvous descriptor is already here and fresh enough).
 * The stream will exit from the hop indicated by <b>cpath</b>, or from the last hop in circ's cpath if <b>cpath</b> is NULL. */
int connection_ap_handshake_rewrite_and_attach(edge_connection_t *conn,origin_circuit_t *circ,crypt_path_t *cpath)
{	socks_request_t *socks = conn->socks_request;
	hostname_type_t addresstype;
	or_options_t *options = get_options();
	struct in_addr addr_tmp;
	int automap = 0;
	char *orig_address;
	time_t map_expires = TIME_MAX;
	int remapped_to_exit = 0;
	time_t now = get_time(NULL);
	int started_without_chosen_exit = strcasecmpend(socks->address, ".exit");

	orig_address = tor_strdup(socks->address);
	tor_strlower(socks->address); /* normalize it */
	if(addressmap_rewrite(&socks->address,&map_expires)) control_event_stream_status(conn, STREAM_EVENT_REMAP,REMAP_STREAM_SOURCE_CACHE);
	if(!plugins_remap(conn,&socks->address,socks->original_address,0))
	{	conn->_base.state = AP_CONN_STATE_CONNECT_WAIT;
		connection_ap_handshake_socks_reply(conn, NULL, 0,END_STREAM_REASON_SOCKSPROTOCOL);
		connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL |END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
		tor_free(orig_address);
		return -1;
	}
	if(is_banned(socks->address))
	{	conn->_base.state = AP_CONN_STATE_CONNECT_WAIT;
		log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_BANNED_ADDRESS),safe_str_client(socks->address),socks->port);
		connection_ap_handshake_socks_reply(conn, NULL, 0,END_STREAM_REASON_SOCKSPROTOCOL);
		connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL |END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
		tor_free(orig_address);
		return -1;
	}
	if(socks->command == SOCKS_COMMAND_RESOLVE && !tor_inet_aton(socks->address, &addr_tmp) && options->AutomapHostsOnResolve && options->AutomapHostsSuffixes)
	{	SMARTLIST_FOREACH(options->AutomapHostsSuffixes, const char *, cp,
		{	if(!strcasecmpend(socks->address, cp))
			{	automap = 1;
				break;
			}
		});
		if(automap)
		{	const char *new_addr;
			char *esc_l;
			new_addr = addressmap_register_virtual_address(RESOLVED_TYPE_IPV4, tor_strdup(socks->address));
			if(! new_addr)
			{	esc_l = escaped_safe_str(socks->address);
				log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_UNABLE_TO_AUTOMAP),esc_l);
				tor_free(esc_l);
				connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
				tor_free(orig_address);
				return -1;
			}
			esc_l = escaped_safe_str_client(socks->address);
			log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_AUTOMAPPING),esc_l, safe_str_client(new_addr));
			tor_free(esc_l);
			tor_free(socks->address);
			socks->address = tor_strdup(new_addr);
		}
	}
	if(socks->command == SOCKS_COMMAND_RESOLVE_PTR)
	{	if(addressmap_rewrite_reverse(&socks->address,&map_expires))
		{	char *result = tor_strdup(socks->address);
			/* remember _what_ is supposed to have been resolved. */
			tor_snprintf(socks->address, sizeof(socks->address), "REVERSE[%s]",orig_address);
			connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_HOSTNAME,strlen(result), (uint8_t*)result, -1,map_expires);
			connection_mark_unattached_ap(conn,END_STREAM_REASON_DONE | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
			tor_free(orig_address);
			return 0;
		}
		if(options->ClientDNSRejectInternalAddresses)	/* Don't let people try to do a reverse lookup on 10.0.0.1. */
		{	tor_addr_t addr;
			int ok;
			ok = tor_addr_parse_reverse_lookup_name(&addr, socks->address, AF_UNSPEC, 1);
			if(ok == 1 && tor_addr_is_internal(&addr, 0))
			{	connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_ERROR,0, NULL, -1, TIME_MAX);
				connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
				tor_free(orig_address);
				return -1;
			}
		}
	}
	else if(!automap)
	{	/* For address map controls, remap the address. */
		if(addressmap_rewrite(&socks->address,&map_expires))
		{	control_event_stream_status(conn, STREAM_EVENT_REMAP,REMAP_STREAM_SOURCE_CACHE);
		}
	}
	if(started_without_chosen_exit && !strcasecmpend(socks->address, ".exit"))
		remapped_to_exit = ALLOW_DOT_EXIT;
	conn->_base.state = AP_CONN_STATE_SOCKS_WAIT;
	if(!automap && address_is_in_virtual_range(socks->address))
	{	/* This address was probably handed out by client_dns_get_unmapped_address, but the mapping was discarded for some reason.  We *don't* want to send the address through Tor; that's likely to fail, and may leak information. */
		log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESSMAP_MISSING_MAPPING),socks->address); /* don't safe_str() this yet. */
		connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
		tor_free(orig_address);
		return -1;
	}
	/* Parse the address provided by SOCKS.  Modify it in-place if it specifies a hidden-service (.onion) or particular exit node (.exit). */
	addresstype = parse_extended_hostname(socks->address,remapped_to_exit | options->AllowTorHosts);
	if(addresstype == BAD_HOSTNAME)
	{	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_INVALID_HOSTNAME), safe_str_client(socks->address));
		char *esc_l = esc_for_log(socks->address);
		control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",esc_l);
		connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
		tor_free(esc_l);
		tor_free(orig_address);
		return -1;
	}
	if(addresstype == EXIT_HOSTNAME)	/* foo.exit -- modify conn->chosen_exit_node to specify the exit node, and conn->address to hold only the address portion.*/
	{	char *s = strrchr(socks->address,'.');
		tor_assert(!automap);
		if(s)
		{	if(s[1] != '\0')
			{	conn->chosen_exit_name = tor_strdup(s+1);
				if(remapped_to_exit) /* 5 tries before it expires the addressmap */
					conn->chosen_exit_retries = TRACKHOSTEXITS_RETRIES;
				*s = 0;
			}
			else
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_MALFORMED_EXIT),safe_str(socks->address));
				char *esc_l = esc_for_log(socks->address);
				control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",esc_l);
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
				tor_free(esc_l);
				tor_free(orig_address);
				return -1;
			}
		}
		else
		{	routerinfo_t *r;
			conn->chosen_exit_name = tor_strdup(socks->address);
			r = router_get_by_nickname(conn->chosen_exit_name, 1);
			socks->address[0] = 0;
			if(r)
			{	tor_free(socks->address);
				socks->address = tor_strdup(r->address);
			}
			else
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_UNRECOGNIZED_EXIT),safe_str(socks->address));
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
				tor_free(orig_address);
				return -1;
			}
		}
		if(conn->chosen_exit_name)
		{	routerinfo_t *r=router_get_by_nickname(conn->chosen_exit_name,1);
			if(r && (routerset_contains_router(options->_ExcludeExitNodesUnion, r)))
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_CONNECTION_BANNED_EXIT),safe_str_client(socks->address),socks->port,safe_str_client(conn->chosen_exit_name));
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
				tor_free(orig_address);
				return -1;
			}
		}
	}

	if(addresstype != ONION_HOSTNAME)	/* not a hidden-service request (i.e. normal or .exit) */
	{	if(address_is_invalid_destination(socks->address, 1))
		{	char *esc_l = esc_for_log(socks->address);
			control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",esc_l);
			log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_INVALID_HOSTNAME_2),safe_str(socks->address));
			connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
			tor_free(esc_l);
			tor_free(orig_address);
			return -1;
		}
		if(socks->command == SOCKS_COMMAND_RESOLVE)
		{	uint32_t answer;
			struct in_addr in;
			/* Reply to resolves immediately if we can. */
			if(tor_inet_aton(socks->address, &in))	/* see if it's an IP already */
			{	/* leave it in network order */
				answer = in.s_addr;
				/* remember _what_ is supposed to have been resolved. */
				tor_free(socks->address);
				socks->address = orig_address;
				connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_IPV4,4,(uint8_t*)&answer,-1,map_expires);
				connection_mark_unattached_ap(conn,END_STREAM_REASON_DONE | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
				return 0;
			}
			if(strlen(socks->address) > RELAY_PAYLOAD_SIZE)
			{	char *esc_l = esc_for_log(socks->address);
				log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_ADDRESS_TOO_LARGE));
				control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",esc_l);
				connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR_TRANSIENT,0,NULL,-1,TIME_MAX);
				connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
				tor_free(orig_address);
				tor_free(esc_l);
				return -1;
			}
			tor_assert(!automap);
			rep_hist_note_used_resolve(now); /* help predict this next time */
		}
		else if(socks->command == SOCKS_COMMAND_CONNECT)
		{	tor_assert(!automap);
			if(socks->port == 0)
			{	log_notice(LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECT_TO_PORT_0));
				connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
				tor_free(orig_address);
				return -1;
			}
			if(options->ClientRejectInternalAddresses && !conn->use_begindir && !conn->chosen_exit_name && !circ)
			{	tor_addr_t addr;
				if(tor_addr_from_str(&addr, socks->address) >= 0 && tor_addr_is_internal(&addr, 0))
				{	/* If this is an explicit private address with no chosen exit node, then we really don't want to try to connect to it.  That's probably an error. */
					if(conn->is_transparent_ap)
						log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_EDGE_REJECT_PRIVATE_ADDRESS_1),safe_str_client(socks->address));
					else
						log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_EDGE_REJECT_PRIVATE_ADDRESS_2), safe_str_client(socks->address));
					connection_mark_unattached_ap(conn, END_STREAM_REASON_PRIVATE_ADDR);
					tor_free(orig_address);
					return -1;
				}
			}
			if(!conn->use_begindir && !conn->chosen_exit_name && !circ)
			{	/* see if we can find a suitable enclave exit */
				routerinfo_t *r = router_find_exact_exit_enclave(socks->address, socks->port);
				if(r)
				{	log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_REDIRECTING_TO_EXIT),safe_str_client(socks->address), r->nickname);
					/* use the hex digest, not nickname, in case there are two routers with this nickname */
					conn->chosen_exit_name = tor_strdup(hex_str(r->cache_info.identity_digest, DIGEST_LEN));
					conn->chosen_exit_optional = 1;
				}
			}
			/* warn or reject if it's using a dangerous port */
			if(!conn->use_begindir && !conn->chosen_exit_name && !circ)
				if(consider_plaintext_ports(conn, socks->port) < 0)
				{	tor_free(orig_address);
					return -1;
				}
			if(!conn->use_begindir)	/* help predict this next time */
				rep_hist_note_used_port(now, socks->port);
		}
		else if(socks->command == SOCKS_COMMAND_RESOLVE_PTR)
			rep_hist_note_used_resolve(now); /* help predict this next time */
		else{	tor_fragile_assert();}

		conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
		if((circ && connection_ap_handshake_attach_chosen_circuit(conn, circ, cpath) < 0) || (!circ && connection_ap_handshake_attach_circuit(conn) < 0))
		{	if(!conn->_base.marked_for_close)
				connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
			tor_free(orig_address);
			return -1;
		}
	}
	else	/* it's a hidden-service request */
	{	rend_cache_entry_t *entry;
		int r;
		rend_service_authorization_t *client_auth;
		tor_assert(!automap);
		if(SOCKS_COMMAND_IS_RESOLVE(socks->command))	/* if it's a resolve request, fail it right now, rather than building all the circuits and then realizing it won't work. */
		{	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_RESOLVE_TO_HIDDEN_SERVICE));
			connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,0,NULL,-1,TIME_MAX);
			connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
			tor_free(orig_address);
			return -1;
		}
		if(circ)
		{	log_warn(LD_CONTROL,get_lang_str(LANG_LOG_EDGE_ATTACHSTREAM_NOT_SUPPORTED_FOR_ONION));
			connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
			tor_free(orig_address);
			return -1;
		}

		conn->rend_data = tor_malloc_zero(sizeof(rend_data_t));
		strlcpy(conn->rend_data->onion_address, onionptr(socks->address),sizeof(conn->rend_data->onion_address));
		log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_HS_REQUEST),safe_str_client(conn->rend_data->onion_address));
		/* see if we already have it cached */
		r = rend_cache_lookup_entry(conn->rend_data->onion_address, -1, &entry);
		if(r<0)
		{	log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_INVALID_HS_NAME),safe_str_client(conn->rend_data->onion_address));
			connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
			tor_free(orig_address);
			return -1;
		}
		/* Help predict this next time. We're not sure if it will need a stable circuit yet, but we know we'll need *something*. */
		rep_hist_note_used_internal(now, 0, 1);
		/* Look up if we have client authorization for it. */
		client_auth = rend_client_lookup_service_authorization(conn->rend_data->onion_address);
		if(client_auth)
		{	log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_USING_PREVIOUS_AUTH));
			memcpy(conn->rend_data->descriptor_cookie,client_auth->descriptor_cookie, REND_DESC_COOKIE_LEN);
			conn->rend_data->auth_type = client_auth->auth_type;
		}
		if(r==0)
		{	conn->_base.state = AP_CONN_STATE_RENDDESC_WAIT;
			log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_FETCHING_UNKNOWN_DESCRIPTOR),safe_str_client(conn->rend_data->onion_address));
			/* Fetch both, v0 and v2 rend descriptors in parallel. Use whichever arrives first. Exception: When using client authorization, only fetch v2 descriptors.*/
			rend_client_refetch_v2_renddesc(conn->rend_data);
		//	if(conn->rend_data->auth_type == REND_NO_AUTH)
		//		rend_client_refetch_renddesc(conn->rend_data->onion_address);
		}
		else	/* r > 0 */
		{
			conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
			log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_DESCRIPTOR_NEW));
			if(connection_ap_handshake_attach_circuit(conn) < 0)
			{	if(!conn->_base.marked_for_close)
					connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
				tor_free(orig_address);
				return -1;
			}
		}
	}
	tor_free(orig_address);
	return 0;
}


/** Fetch the original destination address and port from a
 * system-specific interface and put them into a
 * socks_request_t as if they came from a socks request.
 *
 * Return -1 if an error prevents fetching the destination,
 * else return 0.
 */
static int
connection_ap_get_original_destination(edge_connection_t *conn,
                                       socks_request_t *req)
{
  (void)conn;
  (void)req;
  log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_CONNECTION_AP_GET_ORIGINAL_DESTINATION));
  return -1;
}


/** connection_init_accepted_conn() found a new trans AP conn.
 * Get the original destination and send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
int
connection_ap_process_transparent(edge_connection_t *conn)
{
  socks_request_t *socks;
  or_options_t *options = get_options();

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  /* pretend that a socks handshake completed so we don't try to
   * send a socks reply down a transparent conn */
  socks->command = SOCKS_COMMAND_CONNECT;
  socks->has_finished = 1;

  log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECTION_AP_PROCESS_TRANSPARENT));

  if (connection_ap_get_original_destination(conn, socks) < 0) {
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_FETCHING_ORIGINAL_DESTINATION_FAILED));
    connection_mark_unattached_ap(conn,
                               END_STREAM_REASON_CANT_FETCH_ORIG_DEST);
    return -1;
  }
  /* we have the original destination */

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  if (options->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  return connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
}

/** connection_edge_process_inbuf() found a conn in state natd_wait. See if
 * conn-\>inbuf has the right bytes to proceed.  See FreeBSD's libalias(3) and
 * ProxyEncodeTcpStream() in src/lib/libalias/alias_proxy.c for the encoding
 * form of the original destination.
 *
 * If the original destination is complete, send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
static int
connection_ap_process_natd(edge_connection_t *conn)
{
  char tmp_buf[36], *tbuf, *daddr;
  size_t tlen = 30;
  int err, port_ok;
  socks_request_t *socks;
  or_options_t *options = get_options();
  char *esc_l;

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->_base.state == AP_CONN_STATE_NATD_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECTION_AP_PROCESS_NATD));

  /* look for LF-terminated "[DEST ip_addr port]"
   * where ip_addr is a dotted-quad and port is in string form */
  err = fetch_from_buf_line(conn->_base.inbuf, tmp_buf, &tlen);
  if (err == 0)
    return 0;
  if (err < 0) {
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_NATD_HANDSHAKE_FAILED));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  if (strcmpstart(tmp_buf, "[DEST ")) {
    esc_l = esc_for_log(tmp_buf);
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_NATD_HANDSHAKE_FAILED_2),esc_l);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    tor_free(esc_l);
    return -1;
  }

  daddr = tbuf = &tmp_buf[0] + 6; /* after end of "[DEST " */
  if (!(tbuf = strchr(tbuf, ' '))) {
    esc_l = esc_for_log(tmp_buf);
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_NATD_HANDSHAKE_FAILED_2),esc_l);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    tor_free(esc_l);
    return -1;
  }
  *tbuf++ = '\0';

  /* pretend that a socks handshake completed so we don't try to
   * send a socks reply down a natd conn */
  tor_free(socks->address);
  socks->address = tor_strdup(daddr);
  socks->port = (uint16_t)
    tor_parse_long(tbuf, 10, 1, 65535, &port_ok, &daddr);
  if (!port_ok) {
    esc_l = esc_for_log(tbuf);
    log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_NATD_HANDSHAKE_FAILED_3),esc_l);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    tor_free(esc_l);
    return -1;
  }

  socks->command = SOCKS_COMMAND_CONNECT;
  socks->has_finished = 1;

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  if (options->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;

  return connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
}

/** Iterate over the two bytes of stream_id until we get one that is not
 * already in use; return it. Return 0 if can't get a unique stream_id.
 */
static streamid_t get_unique_stream_id_by_circ(origin_circuit_t *circ)
{	edge_connection_t *tmpconn;
	streamid_t test_stream_id;
	uint32_t attempts=0;
	while(++attempts < (1<<16))
	{	test_stream_id = circ->next_stream_id++;
		if(test_stream_id)
		{	for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
			{	if(tmpconn->stream_id == test_stream_id)	break;
			}
			if(!tmpconn)	return test_stream_id;
		}
	}
	/* Make sure we don't loop forever if all stream_id's are used. */
	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_NO_UNUSED_STREAM_ID));
	return 0;
}

/** Write a relay begin cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_begin(edge_connection_t *ap_conn)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;
  int begin_type;
  origin_circuit_t *circ;
  tor_assert(ap_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(ap_conn->on_circuit);

  tor_assert(ap_conn->_base.type == CONN_TYPE_AP);
  tor_assert(ap_conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(SOCKS_COMMAND_IS_CONNECT(ap_conn->socks_request->command));

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    tor_assert(circ->_base.timestamp_dirty);
    circ->_base.timestamp_dirty -= get_options()->MaxCircuitDirtiness;
    return -1;
  }

  tor_snprintf(payload,RELAY_PAYLOAD_SIZE, "%s:%d",
               (circ->_base.purpose == CIRCUIT_PURPOSE_C_GENERAL) ?
                 ap_conn->socks_request->address : "",
               ap_conn->socks_request->port);
  payload_len = (int)strlen(payload)+1;

  log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_BEGIN_STREAM),ap_conn->stream_id);

  begin_type = ap_conn->use_begindir ?
                 RELAY_COMMAND_BEGIN_DIR : RELAY_COMMAND_BEGIN;
  if (begin_type == RELAY_COMMAND_BEGIN) {
    tor_assert(circ->build_state->onehop_tunnel == 0);
  }

  if (connection_edge_send_command(ap_conn, begin_type,
                  begin_type == RELAY_COMMAND_BEGIN ? payload : NULL,
                  begin_type == RELAY_COMMAND_BEGIN ? payload_len : 0) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->_base.state = AP_CONN_STATE_CONNECT_WAIT;
  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_HANDSHAKE_ADDR_SENT),ap_conn->_base.s, circ->_base.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_CONNECT, 0);
  return 0;
}

/** Write a relay resolve cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_resolve(edge_connection_t *ap_conn)
{
  int payload_len, command;
  const char *string_addr;
  char inaddr_buf[REVERSE_LOOKUP_NAME_BUF_LEN];
  origin_circuit_t *circ;
  tor_assert(ap_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(ap_conn->on_circuit);

  tor_assert(ap_conn->_base.type == CONN_TYPE_AP);
  tor_assert(ap_conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(circ->_base.purpose == CIRCUIT_PURPOSE_C_GENERAL);

  command = ap_conn->socks_request->command;
  tor_assert(SOCKS_COMMAND_IS_RESOLVE(command));

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    tor_assert(circ->_base.timestamp_dirty);
    circ->_base.timestamp_dirty -= get_options()->MaxCircuitDirtiness;
    return -1;
  }

  if (command == SOCKS_COMMAND_RESOLVE) {
    string_addr = ap_conn->socks_request->address;
    payload_len = (int)strlen(string_addr)+1;
  } else {
    /* command == SOCKS_COMMAND_RESOLVE_PTR */
    const char *a = ap_conn->socks_request->address;
    tor_addr_t addr;
    int r;

    /* We're doing a reverse lookup.  The input could be an IP address, or
     * could be an .in-addr.arpa or .ip6.arpa address */
    r = tor_addr_parse_reverse_lookup_name(&addr, a, AF_INET, 1);
    if (r <= 0) {
      log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_INVALID_REVDNS),safe_str_client(a));
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
      return -1;
    }

    r = tor_addr_to_reverse_lookup_name(inaddr_buf, sizeof(inaddr_buf), &addr);
    if (r < 0) {
      log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_REVDNS_ERROR),safe_str_client(a));
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
      return -1;
    }

    string_addr = inaddr_buf;
    payload_len = (int)strlen(inaddr_buf)+1;
    tor_assert(payload_len <= (int)sizeof(inaddr_buf));
  }

  if (payload_len > RELAY_PAYLOAD_SIZE) {
    /* This should be impossible: we don't accept addresses this big. */
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    return -1;
  }

  log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_BEGIN_STREAM),ap_conn->stream_id);

  if (connection_edge_send_command(ap_conn,
                           RELAY_COMMAND_RESOLVE,
                           string_addr, payload_len) < 0)
    return -1; /* circuit is closed, don't continue */

  tor_free(ap_conn->_base.address); /* Maybe already set by dnsserv. */
  ap_conn->_base.address = tor_strdup("(Tor_internal)");
  ap_conn->_base.exclKey = EXCLUSIVITY_INTERNAL;
  ap_conn->_base.state = AP_CONN_STATE_RESOLVE_WAIT;
  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_REVDNS_ADDR_SENT),ap_conn->_base.s,circ->_base.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_NEW, 0);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_RESOLVE, 0);
  return 0;
}

/** Make an AP connection_t, make a new linked connection pair, and attach
 * one side to the conn, connection_add it, initialize it to circuit_wait,
 * and call connection_ap_handshake_attach_circuit(conn) on it.
 *
 * Return the other end of the linked connection pair, or -1 if error.
 */
edge_connection_t *
connection_ap_make_link(char *address, uint16_t port,
                        const char *digest, int use_begindir, int want_onehop)
{
  edge_connection_t *conn;

  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_MAKE_INTERNAL_TUNNEL),want_onehop ? get_lang_str(LANG_LOG_EDGE_DIRECT) : get_lang_str(LANG_LOG_EDGE_ANONYMIZED) , safe_str_client(address),port);

  conn = edge_connection_new(CONN_TYPE_AP, AF_INET);
  conn->_base.linked = 1; /* so that we can add it safely below. */

  /* populate conn->socks_request */

  /* leave version at zero, so the socks_reply is empty */
  conn->socks_request->socks_version = 0;
  conn->socks_request->has_finished = 0; /* waiting for 'connected' */
  conn->socks_request->address = tor_strdup(address);
  conn->socks_request->port = port;
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  conn->want_onehop = want_onehop;
  conn->use_begindir = use_begindir;
  if (use_begindir) {
    conn->chosen_exit_name = tor_malloc(HEX_DIGEST_LEN+2);
    conn->chosen_exit_name[0] = '$';
    tor_assert(digest);
    base16_encode(conn->chosen_exit_name+1,HEX_DIGEST_LEN+1,
                  digest, DIGEST_LEN);
  }

  conn->_base.address = tor_strdup("(Tor_internal)");
  conn->_base.exclKey = EXCLUSIVITY_INTERNAL;
  tor_addr_make_unspec(&conn->_base.addr);
  conn->_base.port = 0;

  if (connection_add(TO_CONN(conn)) < 0) { /* no space, forget it */
    connection_free(TO_CONN(conn));
    return NULL;
  }

  conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    if (!conn->_base.marked_for_close)
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    return NULL;
  }

  log_info(LD_APP,get_lang_str(LANG_LOG_EDGE_AP_CONN_CREATED));
  return conn;
}

/** Notify any interested controller connections about a new hostname resolve
 * or resolve error.  Takes the same arguments as does
 * connection_ap_handshake_socks_resolved(). */
static void tell_controller_about_resolved_result(edge_connection_t *conn,int answer_type,size_t answer_len,const char *answer,int ttl,time_t expires)
{	if(ttl >= 0 && (answer_type == RESOLVED_TYPE_IPV4 || answer_type == RESOLVED_TYPE_HOSTNAME))
		return; /* we already told the controller. */
	char *buf = tor_malloc(1024);
	if(answer_type == RESOLVED_TYPE_IPV4 && answer_len >= 4)
	{	struct in_addr in;
		in.s_addr = get_uint32(answer);
		tor_inet_ntoa(&in,buf,INET_NTOA_BUF_LEN);
		control_event_address_mapped(conn->socks_request->address,&buf,expires,NULL);
	}
	else if(answer_type == RESOLVED_TYPE_HOSTNAME)
	{	tor_snprintf(buf,1023,"%s",answer);
		control_event_address_mapped(conn->socks_request->address,&buf,expires,NULL);
	}
	else
	{	strcpy(buf,"<error>");
		control_event_address_mapped(conn->socks_request->address,&buf,get_time(NULL)+ttl,"error=yes");
	}
	tor_free(buf);
}

/** Send an answer to an AP connection that has requested a DNS lookup via
 * SOCKS.  The type should be one of RESOLVED_TYPE_(IPV4|IPV6|HOSTNAME) or -1
 * for unreachable; the answer should be in the format specified in the socks
 * extensions document.  <b>ttl</b> is the ttl for the answer, or -1 on
 * certain errors or for values that didn't come via DNS.  <b>expires</b> is
 * a time when the answer expires, or -1 or TIME_MAX if there's a good TTL.
 **/
/* XXXX022 the use of the ttl and expires fields is nutty.  Let's make this
 * interface and those that use it less ugly. */
void
connection_ap_handshake_socks_resolved(edge_connection_t *conn,
                                       int answer_type,
                                       size_t answer_len,
                                       const uint8_t *answer,
                                       int ttl,
                                       time_t expires)
{
  char buf[384];
  size_t replylen;

  if (ttl >= 0) {
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      uint32_t a = ntohl(get_uint32(answer));
      if (a)
        client_dns_set_addressmap(conn->socks_request->address, a,
                                  conn->chosen_exit_name, ttl);
    } else if (answer_type == RESOLVED_TYPE_HOSTNAME) {
      char *cp = tor_strndup((char*)answer, answer_len);
      client_dns_set_reverse_addressmap(conn->socks_request->address,
                                        cp,
                                        conn->chosen_exit_name, ttl);
      tor_free(cp);
    }
  }

  if (conn->is_dns_request) {
    if (conn->dns_server_request) {
      /* We had a request on our DNS port: answer it. */
      dnsserv_resolved(conn, answer_type, answer_len, (char*)answer, ttl);
      conn->socks_request->has_finished = 1;
      return;
    } else {
      /* This must be a request from the controller. We already sent
       * a mapaddress if there's a ttl. */
      tell_controller_about_resolved_result(conn, answer_type, answer_len,
                                            (char*)answer, ttl, expires);
      conn->socks_request->has_finished = 1;
      return;
    }
    /* We shouldn't need to free conn here; it gets marked by the caller. */
  }

  if (conn->socks_request->socks_version == 4) {
    buf[0] = 0x00; /* version */
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      buf[1] = SOCKS4_GRANTED;
      set_uint16(buf+2, 0);
      memcpy(buf+4, answer, 4); /* address */
      replylen = SOCKS4_NETWORK_LEN;
    } else { /* "error" */
      buf[1] = SOCKS4_REJECT;
      memset(buf+2, 0, 6);
      replylen = SOCKS4_NETWORK_LEN;
    }
  } else if (conn->socks_request->socks_version == 5) {
    /* SOCKS5 */
    buf[0] = 0x05; /* version */
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x01; /* IPv4 address type */
      memcpy(buf+4, answer, 4); /* address */
      set_uint16(buf+8, 0); /* port == 0. */
      replylen = 10;
    } else if (answer_type == RESOLVED_TYPE_IPV6 && answer_len == 16) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x04; /* IPv6 address type */
      memcpy(buf+4, answer, 16); /* address */
      set_uint16(buf+20, 0); /* port == 0. */
      replylen = 22;
    } else if (answer_type == RESOLVED_TYPE_HOSTNAME && answer_len < 256) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x03; /* Domainname address type */
      buf[4] = (char)answer_len;
      memcpy(buf+5, answer, answer_len); /* address */
      set_uint16(buf+5+answer_len, 0); /* port == 0. */
      replylen = 5+answer_len+2;
    } else {
      buf[1] = SOCKS5_HOST_UNREACHABLE;
      memset(buf+2, 0, 8);
      replylen = 10;
    }
  } else {
    /* no socks version info; don't send anything back */
    return;
  }
  connection_ap_handshake_socks_reply(conn, buf, replylen,
          (answer_type == RESOLVED_TYPE_IPV4 ||
           answer_type == RESOLVED_TYPE_IPV6 ||
           answer_type == RESOLVED_TYPE_HOSTNAME) ?
                                      0 : END_STREAM_REASON_RESOLVEFAILED);
}

/** Send a socks reply to stream <b>conn</b>, using the appropriate
 * socks version, etc, and mark <b>conn</b> as completed with SOCKS
 * handshaking.
 *
 * If <b>reply</b> is defined, then write <b>replylen</b> bytes of it to conn
 * and return, else reply based on <b>endreason</b> (one of
 * END_STREAM_REASON_*). If <b>reply</b> is undefined, <b>endreason</b> can't
 * be 0 or REASON_DONE.  Send endreason to the controller, if appropriate.
 */
void
connection_ap_handshake_socks_reply(edge_connection_t *conn, char *reply,
                                    size_t replylen, int endreason)
{
  char buf[256];
  socks5_reply_status_t status =
    stream_end_reason_to_socks5_response(endreason);

  tor_assert(conn->socks_request); /* make sure it's an AP stream */

  control_event_stream_status(conn,
     status==SOCKS5_SUCCEEDED ? STREAM_EVENT_SUCCEEDED : STREAM_EVENT_FAILED,
                              endreason);

  if (conn->socks_request->has_finished) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_DUPLICATE_HANDSHAKE_SOCKS_REPLY));
    return;
  }
  if (replylen) { /* we already have a reply in mind */
    connection_write_to_buf(reply, replylen, TO_CONN(conn));
    conn->socks_request->has_finished = 1;
    return;
  }
  if (conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
    buf[1] = (status==SOCKS5_SUCCEEDED ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, TO_CONN(conn));
  } else if (conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
    buf[1] = (char)status;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,TO_CONN(conn));
  }
  /* If socks_version isn't 4 or 5, don't send anything.
   * This can happen in the case of AP bridges. */
  conn->socks_request->has_finished = 1;
  return;
}

/** A relay 'begin' or 'begin_dir' cell has arrived, and either we are
 * an exit hop for the circuit, or we are the origin and it is a
 * rendezvous begin.
 *
 * Launch a new exit connection and initialize things appropriately.
 *
 * If it's a rendezvous stream, call connection_exit_connect() on
 * it.
 *
 * For general streams, call dns_resolve() on it first, and only call
 * connection_exit_connect() if the dns answer is already known.
 *
 * Note that we don't call connection_add() on the new stream! We wait
 * for connection_exit_connect() to do that.
 *
 * Return -(some circuit end reason) if we want to tear down <b>circ</b>.
 * Else return 0.
 */
int
connection_exit_begin_conn(cell_t *cell, circuit_t *circ)
{
  edge_connection_t *n_stream;
  relay_header_t rh;
  char *address=NULL;
  uint16_t port;
  or_circuit_t *or_circ = NULL;
  or_options_t *options = get_options();

  assert_circuit_ok(circ);
  if (!CIRCUIT_IS_ORIGIN(circ))
    or_circ = TO_OR_CIRCUIT(circ);

  relay_header_unpack(&rh, cell->payload);
  if (rh.length > RELAY_PAYLOAD_SIZE)
    return -1;

  /* Note: we have to use relay_send_command_from_edge here, not
   * connection_edge_end or connection_edge_send_command, since those require
   * that we have a stream connected to a circuit, and we don't connect to a
   * circuit until we have a pending/successful resolve. */

  if (!server_mode(options) &&
      circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_EDGE_RELAY_BEGIN_AT_NON_SERVER));
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_EXITPOLICY, NULL);
    return 0;
  }

  if (rh.command == RELAY_COMMAND_BEGIN) {
    if (!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_EDGE_RELAY_BEGIN_ERROR));
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      return 0;
    }
    if (parse_addr_port(LOG_PROTOCOL_WARN, (char*)(cell->payload+RELAY_HEADER_SIZE),
                        &address,NULL,&port)<0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_EDGE_RELAY_BEGIN_ERROR_2));
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      return 0;
    }
    if (port==0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_EDGE_RELAY_BEGIN_ERROR_3));
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      tor_free(address);
      return 0;
    }
    if (or_circ && or_circ->p_conn && !options->AllowSingleHopExits &&
        (or_circ->is_first_hop ||
         (!connection_or_digest_is_known_relay(
                                       or_circ->p_conn->identity_digest) &&
          should_refuse_unknown_exits(options)))) {
      /* Don't let clients use us as a single-hop proxy, unless the user
       * has explicitly allowed that in the config.  It attracts attackers
       * and users who'd be better off with, well, single-hop proxies.
       */
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,get_lang_str(LANG_LOG_EDGE_OPEN_STREAM_ON_FIRST_HOP));
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    or_circ->is_first_hop ?
                                      END_STREAM_REASON_TORPROTOCOL :
                                      END_STREAM_REASON_MISC,
                                    NULL);
      tor_free(address);
      return 0;
    }
  } else if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    if (!directory_permits_begindir_requests(options) ||
        circ->purpose != CIRCUIT_PURPOSE_OR) {
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_NOTDIRECTORY, NULL);
      return 0;
    }
    if (or_circ && or_circ->p_conn && or_circ->p_conn->_base.address)
      address = tor_strdup(or_circ->p_conn->_base.address);
    else
      address = tor_strdup("127.0.0.1");
    port = 1; /* XXXX This value is never actually used anywhere, and there
               * isn't "really" a connection here.  But we
               * need to set it to something nonzero. */
  } else {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_UNEXPECTED_COMMAND),(int)rh.command);
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_INTERNAL, NULL);
    return 0;
  }

  log_debug(LD_EXIT,get_lang_str(LANG_LOG_EDGE_EXIT_CONNECTION_NEW));
  n_stream = edge_connection_new(CONN_TYPE_EXIT, AF_INET);
  /* Remember the tunneled request ID in the new edge connection, so that
   * we can measure download times. */
  TO_CONN(n_stream)->dirreq_id = circ->dirreq_id;
  n_stream->_base.purpose = EXIT_PURPOSE_CONNECT;

  n_stream->stream_id = rh.stream_id;
  n_stream->_base.port = port;
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;

  if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_REND_CONFIGURING_STREAM));
    n_stream->_base.address = tor_strdup("(rendezvous)");
    n_stream->_base.state = EXIT_CONN_STATE_CONNECTING;
    n_stream->rend_data = rend_data_dup(origin_circ->rend_data);
    tor_assert(connection_edge_is_rendezvous_stream(n_stream));
    assert_circuit_ok(circ);
    if (rend_service_set_connection_addr_port(n_stream, origin_circ) < 0) {
      log_info(LD_REND,get_lang_str(LANG_LOG_EDGE_REND_SERVICE_NOT_FOUND),n_stream->_base.port);
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_EXITPOLICY,
                                    origin_circ->cpath->prev);
      connection_free(TO_CONN(n_stream));
      tor_free(address);
      return 0;
    }
    assert_circuit_ok(circ);
    log_debug(LD_REND,get_lang_str(LANG_LOG_EDGE_FINISHED_ASSIGNING_ADDR_PORT));
    n_stream->cpath_layer = origin_circ->cpath->prev; /* link it */

    /* add it into the linked list of n_streams on this circuit */
    add_all_streams(circ->hItem,n_stream);
    n_stream->next_stream = origin_circ->p_streams;
    n_stream->on_circuit = circ;
    origin_circ->p_streams = n_stream;
    assert_circuit_ok(circ);

    connection_exit_connect(n_stream);
    tor_free(address);
    return 0;
  }
  tor_strlower(address);
  n_stream->_base.address = address;
  n_stream->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  if (we_are_hibernating()) {
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_HIBERNATING, NULL);
    connection_free(TO_CONN(n_stream));
    return 0;
  }

  n_stream->on_circuit = circ;

  if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    tor_assert(or_circ);
    if (or_circ->p_conn && !tor_addr_is_null(&or_circ->p_conn->_base.addr))
      tor_addr_copy(&n_stream->_base.addr, &or_circ->p_conn->_base.addr);
    return connection_exit_connect_dir(n_stream);
  }

  log_debug(LD_EXIT,get_lang_str(LANG_LOG_EDGE_STARTING_DNS_RESOLVE));

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(n_stream)) {
    case 1: /* resolve worked; now n_stream is attached to circ. */
      assert_circuit_ok(circ);
      log_debug(LD_EXIT,get_lang_str(LANG_LOG_EDGE_CONNECTION_EXIT_CONNECT));
      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_RESOLVEFAILED, NULL);
      /* n_stream got freed. don't touch it. */
      break;
    case 0: /* resolve added to pending list */
      assert_circuit_ok(circ);
      break;
  }
  return 0;
}

/**
 * Called when we receive a RELAY_COMMAND_RESOLVE cell 'cell' along the
 * circuit <b>circ</b>;
 * begin resolving the hostname, and (eventually) reply with a RESOLVED cell.
 */
int
connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ)
{
  edge_connection_t *dummy_conn;
  relay_header_t rh;

  assert_circuit_ok(TO_CIRCUIT(circ));
  relay_header_unpack(&rh, cell->payload);
  if (rh.length > RELAY_PAYLOAD_SIZE)
    return -1;

  /* This 'dummy_conn' only exists to remember the stream ID
   * associated with the resolve request; and to make the
   * implementation of dns.c more uniform.  (We really only need to
   * remember the circuit, the stream ID, and the hostname to be
   * resolved; but if we didn't store them in a connection like this,
   * the housekeeping in dns.c would get way more complicated.)
   */
  dummy_conn = edge_connection_new(CONN_TYPE_EXIT, AF_INET);
  dummy_conn->stream_id = rh.stream_id;
  dummy_conn->_base.address = tor_strndup((char*)cell->payload+RELAY_HEADER_SIZE,
                                          rh.length);
  dummy_conn->_base.port = 0;
  dummy_conn->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
  dummy_conn->_base.purpose = EXIT_PURPOSE_RESOLVE;

  dummy_conn->on_circuit = TO_CIRCUIT(circ);

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(dummy_conn)) {
    case -1: /* Impossible to resolve; a resolved cell was sent. */
      /* Connection freed; don't touch it. */
      return 0;
    case 1: /* The result was cached; a resolved cell was sent. */
      if (!dummy_conn->_base.marked_for_close)
        connection_free(TO_CONN(dummy_conn));
      return 0;
    case 0: /* resolve added to pending list */
      assert_circuit_ok(TO_CIRCUIT(circ));
      break;
  }
  return 0;
}

void connection_read_event(connection_t *conn);
void connection_write_event(connection_t *conn);
int connection_finished_connecting(connection_t *conn);
/** Connect to conn's specified addr and port. If it worked, conn
 * has now been added to the connection_array.
 *
 * Send back a connected cell. Include the resolved IP of the destination
 * address, but <em>only</em> if it's a general exit stream. (Rendezvous
 * streams must not reveal what IP they connected to.)
 */
void
connection_exit_connect(edge_connection_t *edge_conn)
{
  const tor_addr_t *addr;
  uint16_t port;
  connection_t *conn = TO_CONN(edge_conn);
  int socket_error = 0;

  if (!connection_edge_is_rendezvous_stream(edge_conn) &&
      router_compare_to_my_exit_policy(edge_conn)) {
    char *esc_l = escaped_safe_str(conn->address);
    log_info(LD_EXIT,get_lang_str(LANG_LOG_EDGE_EXIT_POLICY),esc_l, conn->port);
    connection_edge_end(edge_conn, END_STREAM_REASON_EXITPOLICY);
    circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
    connection_free(conn);
    tor_free(esc_l);
    return;
  }

  addr = &conn->addr;
  port = conn->port;

  log_debug(LD_EXIT,get_lang_str(LANG_LOG_EDGE_CONNECTING));
  if(!conn->hs_plugin)
  {
    switch (connection_connect(conn, conn->address, addr, port, &socket_error)) {
      case -1:
      {	int reason = errno_to_stream_end_reason(socket_error);
	connection_edge_end(edge_conn, reason);
        circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
        connection_free(conn);
        return;
      }
      case 0:
        conn->state = EXIT_CONN_STATE_CONNECTING;

        connection_watch_events(conn, READ_EVENT | WRITE_EVENT);
        /* writable indicates finish;
         * readable/error indicates broken link in windowsland. */
        return;
      /* case 1: fall through */
    }
  }
  else
  {	conn->s = tor_open_socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  	conn->state = EXIT_CONN_STATE_OPEN;
	set_socket_nonblocking(conn->s);
	connection_add(conn);
  }

  conn->state = EXIT_CONN_STATE_OPEN;
  if (connection_wants_to_flush(conn)) {
    /* in case there are any queued data cells */
    log_warn(LD_BUG,get_lang_str(LANG_LOG_EDGE_NEW_CONNECTION_HAD_DATA));
//    connection_start_writing(conn);
  }
  connection_watch_events(conn, READ_EVENT);

  /* also, deliver a 'connected' cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(edge_conn)) {
    /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 NULL, 0);
  } else { /* normal stream */
    char connected_payload[20];
    int connected_payload_len;
    if (tor_addr_family(&conn->addr) == AF_INET) {
      set_uint32(connected_payload, tor_addr_to_ipv4n(&conn->addr));
      connected_payload_len = 4;
    } else {
      memcpy(connected_payload, tor_addr_to_in6_addr8(&conn->addr), 16);
      connected_payload_len = 16;
    }
    set_uint32(connected_payload+connected_payload_len,
               htonl(dns_clip_ttl(edge_conn->address_ttl)));
    connected_payload_len += 4;
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 connected_payload, connected_payload_len);
  }
}

/** Given an exit conn that should attach to us as a directory server, open a
 * bridge connection with a linked connection pair, create a new directory
 * conn, and join them together.  Return 0 on success (or if there was an
 * error we could send back an end cell for).  Return -(some circuit end
 * reason) if the circuit needs to be torn down.  Either connects
 * <b>exitconn</b>, frees it, or marks it, as appropriate.
 */
static int
connection_exit_connect_dir(edge_connection_t *exitconn)
{
  dir_connection_t *dirconn = NULL;
  or_circuit_t *circ = TO_OR_CIRCUIT(exitconn->on_circuit);

  log_info(LD_EXIT,get_lang_str(LANG_LOG_EDGE_DIR_EXIT_NEW_CONN));

  exitconn->_base.state = EXIT_CONN_STATE_OPEN;

  dirconn = dir_connection_new(AF_INET);

  dirconn->_base.addr = exitconn->_base.addr;
  dirconn->_base.port = 0;
  dirconn->_base.address = tor_strdup(circ->p_conn->_base.address);
  dirconn->_base.type = CONN_TYPE_DIR;
  dirconn->_base.purpose = DIR_PURPOSE_SERVER;
  dirconn->_base.state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;

  /* Note that the new dir conn belongs to the same tunneled request as
   * the edge conn, so that we can measure download times. */
  TO_CONN(dirconn)->dirreq_id = TO_CONN(exitconn)->dirreq_id;

  connection_link_connections(TO_CONN(dirconn), TO_CONN(exitconn));

  if (connection_add(TO_CONN(exitconn))<0) {
    connection_edge_end(exitconn, END_STREAM_REASON_RESOURCELIMIT);
    connection_free(TO_CONN(exitconn));
    connection_free(TO_CONN(dirconn));
    return 0;
  }

  /* link exitconn to circ, now that we know we can use it. */
  add_all_streams(circ->_base.hItem,exitconn);
  exitconn->next_stream = circ->n_streams;
  circ->n_streams = exitconn;

  if (connection_add(TO_CONN(dirconn))<0) {
    connection_edge_end(exitconn, END_STREAM_REASON_RESOURCELIMIT);
    connection_close_immediate(TO_CONN(exitconn));
    connection_mark_for_close(TO_CONN(exitconn));
    connection_free(TO_CONN(dirconn));
    return 0;
  }

  connection_start_reading(TO_CONN(dirconn));
  connection_start_reading(TO_CONN(exitconn));

  if (connection_edge_send_command(exitconn,
                                   RELAY_COMMAND_CONNECTED, NULL, 0) < 0) {
    connection_mark_for_close(TO_CONN(exitconn));
    connection_mark_for_close(TO_CONN(dirconn));
    return 0;
  }

  return 0;
}

/** Return 1 if <b>conn</b> is a rendezvous stream, or 0 if
 * it is a general stream.
 */
int
connection_edge_is_rendezvous_stream(edge_connection_t *conn)
{
  tor_assert(conn);
  if (conn->rend_data)
    return 1;
  return 0;
}

/** Return 1 if router <b>exit</b> is likely to allow stream <b>conn</b>
 * to exit from it, or 0 if it probably will not allow it.
 * (We might be uncertain if conn's destination address has not yet been
 * resolved.)
 */
int
connection_ap_can_use_exit(edge_connection_t *conn, routerinfo_t *exit)
{
  or_options_t *options = get_options();
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);
  tor_assert(exit);

  circuit_t *circ;
  for(circ=global_circuitlist;circ;circ = circ->next)
  {	if(CIRCUIT_IS_ORIGIN(circ))
  	{	if(TO_ORIGIN_CIRCUIT(circ)->build_state && TO_ORIGIN_CIRCUIT(circ)->build_state->chosen_exit && tor_addr_to_ipv4n(&(TO_ORIGIN_CIRCUIT(circ)->build_state->chosen_exit->addr))==exit->addr)
		{	if(circ->exclKey && circ->exclKey!=conn->_base.exclKey) return 0;
		}
	}
  }

  /* If a particular exit node has been requested for the new connection,
   * make sure the exit node of the existing circuit matches exactly.
   */
  if (conn->chosen_exit_name) {
    routerinfo_t *chosen_exit =
      router_get_by_nickname(conn->chosen_exit_name, 1);
    if (!chosen_exit || tor_memneq(chosen_exit->cache_info.identity_digest,
                               exit->cache_info.identity_digest, DIGEST_LEN)) {
      /* doesn't match */
//      log_debug(LD_APP,"Requested node '%s', considering node '%s'. No.",
//                conn->chosen_exit_name, exit->nickname);
      return 0;
    }
  }

  if (conn->socks_request->command == SOCKS_COMMAND_CONNECT &&
      !conn->use_begindir) {
    struct in_addr in;
    uint32_t addr = 0;
    addr_policy_result_t r;
    if (tor_inet_aton(conn->socks_request->address, &in))
      addr = ntohl(in.s_addr);
    r = compare_addr_to_addr_policy(addr, conn->socks_request->port,
                                    exit->exit_policy);
    if (r == ADDR_POLICY_REJECTED)
      return 0; /* We know the address, and the exit policy rejects it. */
    if (r == ADDR_POLICY_PROBABLY_REJECTED && !conn->chosen_exit_name)
      return 0; /* We don't know the addr, but the exit policy rejects most
                 * addresses with this port. Since the user didn't ask for
                 * this node, err on the side of caution. */
  } else if (SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command)) {
    /* Can't support reverse lookups without eventdns. */
    if (conn->socks_request->command == SOCKS_COMMAND_RESOLVE_PTR &&
        exit->has_old_dnsworkers)
      return 0;

    /* Don't send DNS requests to non-exit servers by default. */
    if (!conn->chosen_exit_name && policy_is_reject_star(exit->exit_policy))
      return 0;
  }
  if (options->_ExcludeExitNodesUnion &&
      routerset_contains_router(options->_ExcludeExitNodesUnion, exit)) {
    /* Not a suitable exit. Refuse it. */
    return 0;
  }
  return 1;
}

char *onionptr(char *address)
{	char *s1,*s2;
	s2 = address;
	while(1)
	{	s1 = strchr(s2,'.');
		if(!s1)
			break;
		s2 = s1+1;
	}
	return s2;
}

/** If address is of the form "y.onion" with a well-formed handle y:
 *     Put a NUL after y, lower-case it, and return ONION_HOSTNAME.
 *
 * If address is of the form "y.exit":
 *     Put a NUL after y and return EXIT_HOSTNAME.
 *
 * Otherwise:
 *     Return NORMAL_HOSTNAME and change nothing.
 */
hostname_type_t parse_extended_hostname(char *address, int allowdotexit)
{	char *s;
	char query[REND_SERVICE_ID_LEN_BASE32+1];
	s = strrchr(address,'.');
	if(!s)	return NORMAL_HOSTNAME; /* no dot, thus normal */
	if(!strcmp(s+1,"exit"))
	{	if((allowdotexit & ALLOW_DOT_EXIT) != 0)
		{	*s = 0; /* NUL-terminate it */
			return EXIT_HOSTNAME; /* .exit */
		}
		else
		{	log_warn(LD_APP,get_lang_str(LANG_LOG_CONNECTION_EDGE_NO_DOT_EXIT));
			/* FFFF send a controller event too to notify Vidalia users */
			return BAD_HOSTNAME;
		}
	}
	if(strcmp(s+1,"onion"))	return NORMAL_HOSTNAME; /* neither .exit nor .onion, thus normal */
	/* so it is .onion */
	if((allowdotexit & ALLOW_DOT_ONION) == 0)
	{	log_warn(LD_APP,get_lang_str(LANG_LOG_CONNECTION_EDGE_NO_DOT_ONION));
		return BAD_HOSTNAME;
	}
	*s = 0; /* nul-terminate it */
	if((strlcpy(query, onionptr(address), REND_SERVICE_ID_LEN_BASE32+1) < REND_SERVICE_ID_LEN_BASE32+1) && rend_valid_service_id(query))
		return ONION_HOSTNAME; /* success */
	/* otherwise, return to previous state and return 0 */
	*s = '.';
	return BAD_HOSTNAME;
}

char *find_address(char *address)
{	char	*res1=NULL;
	int	i,j;
	addressmap_entry_t	*ent = strmap_get(addressmap, address);
	if(ent&&ent->new_address)
	{	res1=tor_strdup(ent->new_address);
		for(i=0;res1[i];i++);
		for(;i&&(res1[i]!='.');i--);
		if(res1[i]=='.')	i--;
		for(;i&&(res1[i]!='.');i--);
		if(res1[i]=='.')	i++;
		for(j=0;(res1[i+j]!=0)&&(res1[i+j]!='.');j++)	res1[j]=res1[i+j];
		res1[j]=0;
		if(strlen(res1)<DIGEST_LEN) tor_free(res1);
		else return res1;
	}
	return NULL;
}
