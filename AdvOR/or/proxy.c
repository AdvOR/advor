#include "or.h"
#include "buffers.h"
#include "proxy.h"
#include "main.h"
#include "config.h"
#include "routerlist.h"
#include "connection_edge.h"
#include "connection.h"
#include "control.h"

extern or_options_t *tmpOptions;

int connection_ap_handshake_process_socks(edge_connection_t *conn);
int remove_unprocessed_data(connection_t *conn,int amount);
int remove_unprocessed_headers(connection_t *conn,int amount);
int remove_incoming_data(connection_t *conn,int amount);

/** connection_edge_process_inbuf() found a conn in state socks_wait. See if conn->inbuf has the right bytes to proceed with the socks handshake.
 * If the handshake is complete, send it to connection_ap_handshake_rewrite_and_attach().
 * Return -1 if an unexpected error with conn occurs (and mark it for close), else return 0. */
int connection_ap_handshake_process_socks(edge_connection_t *conn)
{	socks_request_t *socks;
	int sockshere;
	or_options_t *options = get_options();
	tor_assert(conn);
	tor_assert(conn->_base.type == CONN_TYPE_AP);
	tor_assert(conn->socks_request);
	tor_assert(conn->_base.state == AP_CONN_STATE_SOCKS_WAIT);

	socks = conn->socks_request;

	log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_CONNECTION_AP_PROCESS_SOCKS));
	sockshere = fetch_from_buf_socks(conn->_base.inbuf, socks,options->TestSocks, options->SafeSocks);
	if(socks->address && socks->address[0] && (!socks->original_address || !socks->original_address[0]))
	{	if(socks->original_address)	tor_free(socks->original_address);
		socks->original_address = tor_strdup(socks->address);
	}
	if(sockshere == 0)
	{	if(socks->command==SOCKS_COMMAND_SELECT_ROUTER)
		{	if(socks->address)
				conn->chosen_exit_name=tor_strdup(socks->address);
			tor_free(socks->address);
		}
		if(socks->replylen)
		{	connection_write_to_buf(socks->reply, socks->replylen, TO_CONN(conn));
			/* zero it out so we can do another round of negotiation */
			socks->replylen = 0;
		}
		else	log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_HANDSHAKE_INCOMPLETE));
		return 0;
	}
	else if(sockshere == -1)
	{	if(socks->replylen)	/* we should send reply back */
		{	log_debug(LD_APP,get_lang_str(LANG_LOG_EDGE_SOCKS_USING_REPLY));
			connection_ap_handshake_socks_reply(conn, socks->reply, socks->replylen,END_STREAM_REASON_SOCKSPROTOCOL);
		}
		else
		{	log_warn(LD_APP,get_lang_str(LANG_LOG_EDGE_SOCKS_HANDSHAKE_FAILED));
			connection_ap_handshake_socks_reply(conn, NULL, 0, END_STREAM_REASON_SOCKSPROTOCOL);
		}
		connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL | END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
		return -1;
	} /* else socks handshake is done, continue processing */
	else if(socks->address && is_banned(socks->address))
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_BANNED_ADDRESS),safe_str(socks->address),socks->port);
		connection_ap_handshake_socks_reply(conn, NULL, 0,END_STREAM_REASON_SOCKSPROTOCOL);
		connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL |END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
		return -1;
	}
	else if(get_router_sel()==0x0100007f)
	{	connection_ap_handshake_socks_reply(conn, NULL, 0,END_STREAM_REASON_SOCKSPROTOCOL);
		connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL |END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
		return -1;
	}
	else if(socks->address && (tmpOptions->AllowTorHosts != (ALLOW_DOT_EXIT | ALLOW_DOT_ONION)))
	{	int i,j=0;
		while(1)
		{	i = strfind(&socks->address[j],".",0);
			if(i >= 0 && socks->address[i+j+1]!=0)	j += i + 1;
			else break;
		}
		if((((tmpOptions->AllowTorHosts & ALLOW_DOT_EXIT) == 0) && !strcasecmpstart(&socks->address[j],"exit")) || (((tmpOptions->AllowTorHosts & ALLOW_DOT_ONION) == 0) && !strcasecmpstart(&socks->address[j],"onion")))
		{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_BANNED_ADDRESS),safe_str(socks->address),socks->port);
			connection_ap_handshake_socks_reply(conn, NULL, 0,END_STREAM_REASON_SOCKSPROTOCOL);
			connection_mark_unattached_ap(conn,END_STREAM_REASON_SOCKSPROTOCOL |END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
			return -1;
		}
	}
	if(SOCKS_COMMAND_IS_CONNECT(socks->command))
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_CONNECTION_REQUEST),safe_str(socks->address),socks->port);
		proxy_handle_client_data(conn);
		if(socks->replylen){    connection_write_to_buf(socks->reply, socks->replylen, TO_CONN(conn)); socks->replylen = 0;}
		control_event_stream_status(conn, STREAM_EVENT_NEW, 0);
	}
	else
	{	if(socks->port) log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_RESOLVE_REQUEST),safe_str(socks->address),socks->port);
		else log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_RESOLVE_REQUEST_2),safe_str(socks->address));
		control_event_stream_status(conn, STREAM_EVENT_NEW_RESOLVE, 0);
	}
	if(options->LeaveStreamsUnattached)
	{	conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
		return 0;
	}
	return connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
}

int fetch_from_buf_socks(buf_t *buf, socks_request_t *req, int log_sockstype, int safe_socks)
{	size_t len,i,j;
	int http_hdr;
	char *esc_l;
	char tmpbuf[TOR_ADDR_BUF_LEN+1];
	tor_addr_t destaddr;
	uint32_t destip,destipH,bw;
	uint8_t socksver;
	enum {socks4, socks4a} socks4_prot = socks4a;
	char *next, *startaddr,*tmp;
	struct in_addr in;

	/* If the user connects with socks4 or the wrong variant of socks5, then log a warning to let him know that it might be unwise. */
	static int have_warned_about_unsafe_socks = 0;

	if(buf->datalen < 2)	return 0;	/* version and another byte */
	buf_pullup(buf, 256);
	tor_assert(buf->head && buf->head->datalen >= 2);

	socksver = *buf->head->data;
	if((req->socks_version==0x50 || req->socks_version==5) && socksver==1)
	{	socksver=5;
		req->socks_version=0x50;
	}
	switch(socksver)	/* which version of socks? */
	{	case 5: /* socks5 */
			if(req->socks_version == 0x50)
			{	size_t ulen = buf->head->data[1],ulen1;
				if(buf->head->datalen < ulen+3)
					return 0;
				if(!tmpOptions->SocksAuthenticator || !(tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH))
				{	int dlen = buf->head->datalen;
					char *dtmp=&buf->head->data[0];
					char *user,*pass;
					if(dlen<3)
						return 0;
					if(dtmp[0]!=1)
					{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_UNKNOWN_LOGIN_VERSION));
						req->replylen = 2; /* 2 bytes of response */
						req->reply[0] = 5;
						req->reply[1] = '\xFF'; /* reject all methods */
						return -1;
					}
					dlen--;
					dtmp++;
					if(dtmp[0]>=dlen+1)
						return 0;
					user=dtmp;
					dlen -= dtmp[0]+1;
					dtmp += dtmp[0]+1;
					pass=dtmp;
					if(dtmp[0]>=dlen+1)
						return 0;
					dlen=user[0];
					user=tor_memdup(user+1,dlen+1);
					user[dlen]=0;
					dlen=pass[0];
					pass=tor_memdup(pass+1,dlen+1);
					pass[dlen]=0;
					log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_UNRECOGNIZED_LOGIN),user,pass);
					tor_free(user);tor_free(pass);
					//log_info(LD_APP,get_lang_str(LANG_LOG_BUFFERS_RECEIVED_AUTH));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 1;
					req->reply[1] = 0; /* reject all methods */
					dtmp += dtmp[0]+1;
					dlen = dtmp-&buf->head->data[0];
					buf_remove_from_front(buf,dlen);
					req->socks_version=5;
					return 0;
				}
				len = strlen(tmpOptions->SocksAuthenticator);
				if(len<ulen || (tmpOptions->SocksAuthenticator[ulen]!=':' && tmpOptions->SocksAuthenticator[ulen]!=0))
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_INVALID_USERNAME));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 5;
					req->reply[1] = '\xFF'; /* reject all methods */
					return -1;
				}
				for(i=0;i<ulen;i++)
				{	if((buf->head->data[i+2]|0x20)!=(tmpOptions->SocksAuthenticator[i]|0x20))
						break;
				}
				if(tmpOptions->SocksAuthenticator[ulen]==0)
				{	//log_info(LD_APP,get_lang_str(LANG_LOG_BUFFERS_RECEIVED_AUTH));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 5;
					req->reply[1] = 0; /* reject all methods */
					buf_clear(buf);
					req->socks_version=5;
					return 0;
				}
				if(i!=ulen)
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_INVALID_USERNAME));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 5;
					req->reply[1] = '\xFF'; /* reject all methods */
					return -1;
				}
				ulen1 = buf->head->data[2+ulen];
				for(i=0;i<ulen1;i++)
				{	if(buf->head->data[3+ulen+i]!=tmpOptions->SocksAuthenticator[ulen+i+1])
						break;
				}
				if(i!=ulen1 || tmpOptions->SocksAuthenticator[ulen+i+1])
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_INVALID_PASSWORD));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 5;
					req->reply[1] = '\xFF'; /* reject all methods */
					return -1;
				}
				//log_info(LD_APP,get_lang_str(LANG_LOG_BUFFERS_RECEIVED_AUTH));
				req->replylen = 2; /* 2 bytes of response */
				req->reply[0] = 5;
				req->reply[1] = 0; /* reject all methods */
				buf_clear(buf);
				req->socks_version=5;
				return 0;
			}
			else if(req->socks_version != 5)	/* we need to negotiate a method */
			{	unsigned char nummethods = (unsigned char)*(buf->head->data+1);
				tor_assert(!req->socks_version);
				if(buf->datalen < 2u+nummethods)
					return 0;
				buf_pullup(buf, 2u+nummethods);
				if(nummethods)
				{	if(tmpOptions->SocksAuthenticator && (tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH) && (!memchr(buf->head->data+2,2,nummethods)))
						nummethods = 0;
					if((!memchr(buf->head->data+2, 0, nummethods) && !memchr(buf->head->data+2, 2, nummethods) && !memchr(buf->head->data+2, 0xE0, nummethods)))
						nummethods = 0;
				}
				if(!nummethods)
				{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_NO_METHODS));
					req->replylen = 2; /* 2 bytes of response */
					req->reply[0] = 5;
					req->reply[1] = '\xFF'; /* reject all methods */
					return -1;
				}
				req->replylen = 2; /* 2 bytes of response */
				req->reply[0] = 5; /* socks5 reply */
				if(tmpOptions->SocksAuthenticator && (tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH))
				{	req->reply[1] = 2;
					//log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_METHOD_02));
					req->socks_version = 0x50;
				}
				else
				{	if(memchr(buf->head->data+2, 0xE0, nummethods)!=NULL)
					{	req->reply[1] = 0xE0;
						log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_METHOD_E0));
					}
					else if(memchr(buf->head->data+2, 2, nummethods)!=NULL)
					{	req->reply[1] = 2;
						req->socks_version = 0x50;
					}
					else
					{	req->reply[1] = 0; /* tell client to use "none" auth method */
						log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_METHOD_00));
					}
					req->socks_version = 5; /* remember we've already negotiated auth */
				}
				/* remove packet from buf. also remove any other extraneous bytes, to support broken socks clients. */
				buf_clear(buf);
				return 0;
			}
			/* we know the method; read in the request */
			log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_CHECKING_REQUEST));
			if(buf->datalen < 8)	/* basic info plus >=2 for addr plus 2 for port */
				return 0; /* not yet */
			tor_assert(buf->head->datalen >= 8);
			req->command = (unsigned char) *(buf->head->data+1);
			if(req->command == SOCKS_COMMAND_SELECT_ROUTER)
			{	if(buf->head->datalen >= 18)
				{	tmpbuf[0]=*(buf->head->data+4);tmpbuf[1]=*(buf->head->data+5);tmpbuf[2]=0;
					destip = *(uint32_t*)(buf->head->data+6);
					destipH = *(uint32_t*)(buf->head->data+10);
					bw = ntohl(*(uint32_t*)(buf->head->data+14));
					getRandomExitNode(*(buf->head->data+2),*(buf->head->data+3),tmpbuf,destip,destipH,bw,NULL,(char*)&req->reply);
					req->replylen=14;
					buf_remove_from_front(buf,18);
				}
				return 0;
			}
			if(req->command != SOCKS_COMMAND_CONNECT && req->command != SOCKS_COMMAND_RESOLVE && req->command != SOCKS_COMMAND_RESOLVE_PTR)	/* not a connect or resolve or a resolve_ptr? we don't support it. */
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_UNKNOWN_COMMAND),req->command);
				return -1;
			}
			switch(*(buf->head->data+3))	/* address type */
			{	case 1: /* IPv4 address */
				case 4: /* IPv6 address */
				{	const int is_v6 = *(buf->head->data+3) == 4;
					const unsigned addrlen = is_v6 ? 16 : 4;
					log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_IPV4));
					if(buf->datalen < 6+addrlen) /* ip/port there? */
						return 0; /* not yet */
					if(is_v6)
						tor_addr_from_ipv6_bytes(&destaddr, buf->head->data+4);
					else
						tor_addr_from_ipv4n(&destaddr, get_uint32(buf->head->data+4));
					tor_addr_to_str(tmpbuf, &destaddr, sizeof(tmpbuf), 1);
					if(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN)
					{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_IP_BUFFER_ERROR),(int)strlen(tmpbuf)+1,(int)MAX_SOCKS_ADDR_LEN);
						return -1;
					}
					req->address = tor_strdup(tmpbuf);
					req->port = ntohs(get_uint16(buf->head->data+4+addrlen));
					buf_remove_from_front(buf, 6+addrlen);
					if(req->command != SOCKS_COMMAND_RESOLVE_PTR && !addressmap_have_mapping(req->address,0) && !have_warned_about_unsafe_socks)
					{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_IP_WARN), req->port,safe_socks ? " Rejecting." : "");
						/*have_warned_about_unsafe_socks = 1;*/
						/*(for now, warn every time)*/
						control_event_client_status(LOG_WARN,"DANGEROUS_SOCKS PROTOCOL=SOCKS5 ADDRESS=%s:%d",req->address, req->port);
						if(safe_socks)	return -1;
					}
					return 1;
				}
				case 3: /* fqdn */
					log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_FQDN));
					if(req->command == SOCKS_COMMAND_RESOLVE_PTR)
					{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_RESOLVE_PTR_HOSTNAME));
						return -1;
					}
					len = (unsigned char)*(buf->head->data+4);
					if(buf->datalen < 7+len) /* addr/port there? */
						return 0; /* not yet */
					buf_pullup(buf, 7+len);
					tor_assert(buf->head->datalen >= 7+len);
					req->address = tor_malloc(len+2);
					memcpy(req->address,buf->head->data+5,len);
					req->address[len] = 0;
					req->port = ntohs(get_uint16(buf->head->data+5+len));
					buf_remove_from_front(buf, 5+len+2);
					if(!tor_strisprint(req->address) || strchr(req->address,'\"'))
					{	esc_l = esc_for_log(req->address);
						log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_BUFFERS_SOCKS_MALFORMED_HOSTNAME),req->port, esc_l);
						tor_free(esc_l);
						return -1;
					}
					if(log_sockstype)
						log_notice(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_HOSTNAME_OK), req->port);
					return 1;
				default: /* unsupported */
					log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_UNSUPPORTED_ADDR),(int) *(buf->head->data+3));
					return -1;
			}
			tor_assert(0);
		case 4: /* socks4 */
			/* http://archive.socks.permeo.com/protocol/socks4.protocol */
			/* http://archive.socks.permeo.com/protocol/socks4a.protocol */
			req->socks_version = 4;
			if(buf->datalen < SOCKS4_NETWORK_LEN) /* basic info available? */
				return 0; /* not yet */
			buf_pullup(buf, 1280);
			req->command = (unsigned char) *(buf->head->data+1);
			if(req->command != SOCKS_COMMAND_CONNECT && req->command != SOCKS_COMMAND_RESOLVE)
			{	/* not a connect or resolve? we don't support it. (No resolve_ptr with socks4.) */
				log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_INVALID_COMMAND),req->command);
				return -1;
			}
			req->port = ntohs(*(uint16_t*)(buf->head->data+2));
			destip = ntohl(*(uint32_t*)(buf->head->data+4));
			if((!req->port && req->command!=SOCKS_COMMAND_RESOLVE) || !destip)
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_INVALID_ADDR));
				return -1;
			}
			if(destip >> 8)
			{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTIP));
				in.s_addr = htonl(destip);
				tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
				if(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN)
				{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_ADDR_TOO_LONG),(int)strlen(tmpbuf));
					return -1;
				}
				log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTIP_SUCCESS), safe_str(tmpbuf));
				socks4_prot = socks4;
			}
			next = memchr(buf->head->data+SOCKS4_NETWORK_LEN, 0, buf->head->datalen-SOCKS4_NETWORK_LEN);
			if(!next)
			{	if(buf->head->datalen >= 1024)
				{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_UNAME_TOO_LONG));
					return -1;
				}
				log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_UNAME_INCOMPLETE));
				return 0;
			}
			if(tmpOptions->SocksAuthenticator && (tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH))
			{	if(strcmp(tmpOptions->SocksAuthenticator,buf->head->data+SOCKS4_NETWORK_LEN))
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_INVALID_USERNAME));
					return -1;
				}
				else
				//log_info(LD_APP,get_lang_str(LANG_LOG_BUFFERS_RECEIVED_AUTH))
				{	;}
			}
			tor_assert(next < CHUNK_WRITE_PTR(buf->head));
			startaddr = NULL;
			if(socks4_prot != socks4a && !addressmap_have_mapping(tmpbuf,0) && !have_warned_about_unsafe_socks)
			{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_IP_WARN), req->port,safe_socks ? " Rejecting." : "");
				/*have_warned_about_unsafe_socks = 1;*/  /*(for now, warn every time)*/
				control_event_client_status(LOG_WARN,"DANGEROUS_SOCKS PROTOCOL=SOCKS4 ADDRESS=%s:%d",tmpbuf, req->port);
				if(safe_socks)	return -1;
			}
			if(socks4_prot == socks4a)
			{	if(next+1 == CHUNK_WRITE_PTR(buf->head))
				{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_INCOMPLETE_DESTADDR));
					return 0;
				}
				startaddr = next+1;
				next = memchr(startaddr, 0, CHUNK_WRITE_PTR(buf->head)-startaddr);
				if(!next)
				{	if(buf->head->datalen >= 1024)
					{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTADDR_TOO_LONG));
						return -1;
					}
					log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTADDR_INCOMPLETE));
					return 0;
				}
				if(MAX_SOCKS_ADDR_LEN <= next-startaddr)
				{	log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTADDR_TOO_LONG_2));
					return -1;
				}
			//	tor_assert(next < buf->cur+buf->datalen);
				if(log_sockstype)
					log_notice(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_HOSTNAME_OK), req->port);
			}
			log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_SUCCESS));
			if(startaddr)
			{	len = strlen(startaddr);
				req->address = tor_malloc(len+2);
				strlcpy(req->address,startaddr,len+1);
			}
			else
			{	len = strlen(tmpbuf);
				req->address = tor_malloc(len+2);
				strlcpy(req->address,tmpbuf,len+1);
			}
			if(!tor_strisprint(req->address) || strchr(req->address,'\"'))
			{	esc_l = esc_for_log(req->address);
				log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_MALFORMED_HOSTNAME),req->port,esc_l);
				tor_free(esc_l);
				return -1;
			}
			/* next points to the final \0 on inbuf */
			buf_remove_from_front(buf, next - buf->head->data + 1);
			return 1;
		case 'C': // CONNECT
		case 'G': // GET
		case 'H': // HEAD
		case 'O': // OPTIONS
		case 'P': // PUT, POST
			if(buf->datalen < 10 || (strcasecmpstart(buf->head->data,"GET ")&&strcasecmpstart(buf->head->data,"HEAD ")&&strcasecmpstart(buf->head->data,"PUT ")&&strcasecmpstart(buf->head->data,"POST ")&&strcasecmpstart(buf->head->data,"OPTIONS ")&&strcasecmpstart(buf->head->data,"CONNECT ")))	return 0;
			http_hdr = buf_find_string_offset(buf, "\r\n\r\n", 4);
			if(http_hdr < 0)
			{	log_debug(LD_HTTP,get_lang_str(LANG_LOG_BUFFERS_HTTP_HEADERS_INCOMPLETE));
				return 0;
			}
			http_hdr += 4;
			if((int)buf->head->datalen < http_hdr)	buf_pullup(buf,http_hdr);
			tmp = (char *)eat_whitespace_no_nl(buf->head->data);
			if(*tmp)
			{	tmp = (char *)find_whitespace(tmp);
				if(*tmp)
				{	tmp = (char *)eat_whitespace_no_nl(tmp);
					if(*tmp)
					{	req->port=80;req->socks_version='G';
						if(buf->head->data[0]=='C'){	req->socks_version='C';}
						else if(!strcasecmpstart(tmp,"http://"))	;
						else if(!strcasecmpstart(tmp,"https://")){	req->port=443;}
						else if(!strcasecmpstart(tmp,"dchub://")){	req->socks_version='C';req->port=411;}
						else if(!strcasecmpstart(tmp,"ftp://")){	req->socks_version='C';req->port=21;}
						else if(!strcasecmpstart(tmp,"irc://")){	req->socks_version='C';req->port=6667;}
						else
						{	while(tmp)
							{	if(!strcasecmpstart(tmp,"host:"))
								{	tmp = (char *)eat_whitespace_no_nl(tmp+5);
									break;
								}
								tmp = strchr(tmp,10);
								if(tmp)
								{	if(*tmp==10) tmp++;
									if(*tmp<32) tmp=NULL;
								}
							}
							req->socks_version='X';
						}
						if(tmp)
						{	{ for(i=0;tmp[i]>32 && tmp[i]!=':';i++)	; }
							if(tmp[i]==':' && tmp[i+1]=='/'  && tmp[i+2]=='/')	tmp += i + 3;
						}
					}
				}
			}
			if(!tmp || !*tmp)
			{	tmp = tor_strndup(buf->head->data, 100);
				for(len=0;len<strlen(tmp);len++) if(*(tmp+len)<32) *(tmp+len)=32;
				log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_NOT_A_PROXY_REQUEST),tmp);
				esc_l = esc_for_log(tmp);
				control_event_client_status(LOG_WARN,"SOCKS_UNKNOWN_PROTOCOL DATA=\"%s\"",esc_l);
				tor_free(esc_l);
				tor_free(tmp);
				return -1;
			}
			if(tmpOptions->SocksAuthenticator && (tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH))
			{	i = strcasefind(buf->head->data,"\r\nproxy-authorization:",http_hdr);
				if((int)i > 0)
				{	i += 22;
					while(buf->head->data[i]==32)	i++;
					if(strcasecmpstart(&buf->head->data[i],"basic "))
					{	i += 6;
						while(buf->head->data[i]==32)	i++;
					}
					else i = -1;
				}
				if((int)i < 0)
				{	i = strcasefind(buf->head->data,"\r\nauthorization:",http_hdr);
					if((int)i > 0)
					{	i += 16;
						while(buf->head->data[i]==32)	i++;
						if(strcasecmpstart(&buf->head->data[i],"basic "))
						{	i += 6;
							while(buf->head->data[i]==32)	i++;
						}
						else i = -1;
					}
				}
				if((int)i < 0)
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_MISSING_PROXY_AUTHENTICATOR),tmp);
					return -1;
				}
				char *tmpb64 = tor_malloc(1024);
				for(j=i;buf->head->data[j]>=32;j++);
				j = base64_decode(tmpb64,1023,&buf->head->data[0],j);
				if((int)j>0)
				{	tmpb64[j] = 0;
					if(strcmp(tmpb64,tmpOptions->SocksAuthenticator))
					{	//log_warn(LD_APP,get_lang_str(LANG_LOG_INVALID_PROXY_AUTHENTICATOR),tmp);
						return -1;
					}
				}
				else
				{	//log_warn(LD_APP,get_lang_str(LANG_LOG_MISSING_PROXY_AUTHENTICATOR),tmp);
					tor_free(tmpb64);
					return -1;
				}
				//log_info(LD_APP,get_lang_str(LANG_LOG_BUFFERS_RECEIVED_AUTH));
			}
			req->command = SOCKS_COMMAND_CONNECT;
			for(i=0;tmp[i]>32 && tmp[i]!=':' && tmp[i]!='/' && tmp[i]!='\\';i++)	;
			req->address = tor_malloc(i+2);
			memcpy(req->address,tmp,i);req->address[i]=0;
			if(tmp[i]==':')
			{	if((tmp[i+1]>='0')&&(tmp[i+1]<='9'))
				{	j = 0;i++;
					while((tmp[i]>='0')&&(tmp[i]<='9')){	j = j * 10 + tmp[i]-'0';i++;}
					if(j)	req->port = j;
				}
			}
			if(req->socks_version=='C')
			{	buf_remove_from_front(buf,http_hdr);
				strlcpy(req->reply,"HTTP/1.0 200 Connection established\r\nContent-Length: 0\r\n\r\n",MAX_SOCKS_REPLY_LEN);
				req->replylen=strlen(req->reply);
			}
	/*		else
			{	tmp = buf->head->data;i=0;j=0;
				if(req->socks_version!='X')
				{	while(tmp[i]>32)	tmp[j++]=tmp[i++];
					while(tmp[i]==32)	tmp[j++]=tmp[i++];
					while(tmp[i]!='/')	i++;
					while(tmp[i]=='/')	i++;
					while(tmp[i]!='/' && tmp[i]>32)	i++;
				}
				else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_BUFFERS_FROM_HTTP_HOST),req->address);
				while(i<http_hdr)
				{	len=strchr(tmp+i,10)-tmp-i+1;
					if(len<0) break;
					if(!strcasecmpstart(tmp+i,"proxy-connection"))	i+=6;
					if(!strcasecmpstart(tmp+i,"connection:") && len > 19)
					{	tor_snprintf(tmp+j,20,"Connection: Close\r\n");
						j += 19;
						i += len;
					}
					else if(!strcasecmpstart(tmp+i,"proxy")||!strcasecmpstart(tmp+i,"via")||!strcasecmpstart(tmp+i,"from")||!strcasecmpstart(tmp+i,"x-forwarded")||!strcasecmpstart(tmp+i,"keep-alive")) i += len;
					else
					{	memcpy(tmp+j,tmp+i,len);
						i += len;j += len;
					}
				}
				while(i < buf->head->datalen)	tmp[j++]=tmp[i++];
				buf->head->datalen -= i - j;
				buf->datalen -= i - j;
			}*/
			return 1;
		/* fall through */
		default: /* version is not socks4 or socks5 */
			tmp = tor_malloc(256);
			for(i=0;(i<255)&&(i<buf->head->datalen);i++)
			{	*(tmp+i) = *(buf->head->data+i);
				if(*(tmp+i)==0) *(tmp+i) = ' ';
			}
			*(tmp+i)=0;
			log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_VERSION_ERROR),*(buf->head->data),tmp);
			esc_l = esc_for_log(tmp);
			control_event_client_status(LOG_WARN,"SOCKS_UNKNOWN_PROTOCOL DATA=\"%s\"",esc_l);
			tor_free(esc_l);
			tor_free(tmp);
			return -1;
	}
}

int remove_unprocessed_data(connection_t *conn,int amount)
{	if((tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUESTS) && (tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUEST_HEADERS) && ((tmpOptions->logging&0xff) >= LOG_INFO))
		http_log(LOG_INFO,LANG_LOG_HTTP_SENT_TRAFFIC,conn->unprocessed,amount,conn);
	if(conn->unprocessed_len > amount)
	{	conn->unprocessed_len -= amount;
		memcpy(conn->unprocessed,conn->unprocessed + amount,conn->unprocessed_len);
	}
	else	conn->unprocessed_len = 0;
	return conn->unprocessed_len;
}

int remove_unprocessed_headers(connection_t *conn,int amount)
{	if(conn->unprocessed_len > amount)
	{	conn->unprocessed_len -= amount;
		memcpy(conn->unprocessed,conn->unprocessed + amount,conn->unprocessed_len);
	}
	else	conn->unprocessed_len = 0;
	return conn->unprocessed_len;
}

int remove_incoming_data(connection_t *conn,int amount)
{	if((tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_STATUS) && (tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_TRAFFIC) && ((tmpOptions->logging&0xff) >= LOG_INFO))
		http_log(LOG_INFO,LANG_LOG_HTTP_RESPONSE_TRAFFIC,conn->incoming,amount,conn);
	if(conn->incoming_len > amount)
	{	conn->incoming_len -= amount;
		memcpy(conn->incoming,conn->incoming + amount,conn->incoming_len);
	}
	else	conn->incoming_len = 0;
	return conn->incoming_len;
}

void http_log(int severity,int lang_id,char *httpdata,int len,connection_t *conn)
{	char *tmp=tor_malloc(len*4+4);
	int i,j=0;
	for(i=0;(i<len) && (j<len*4);i++)
	{	if((unsigned char)httpdata[i]<32 && httpdata[i]!=13 && httpdata[i]!=10)
		{	tmp[j++] = '\\';tmp[j++]='x';
			tmp[j] = ((httpdata[i]>>4) & 0x0f) | 0x30;tmp[j] = (tmp[j] > '9') ? tmp[j]+7 : tmp[j];j++;
			tmp[j] = (httpdata[i] & 0x0f) | 0x30;tmp[j] = (tmp[j] > '9') ? tmp[j]+7 : tmp[j];j++;
		}
		else	tmp[j++] = httpdata[i];
	}
	tmp[j] = 0;
	char *tmp1 = tor_malloc(200);
	getProcessName(tmp1,199,conn->pid);
	i = strlen(tmp1);
	tor_snprintf(tmp1+i,199-i," PID: %u, ID: %x",(uint32_t)conn->pid,conn->s);
	log(severity,LD_APP,get_lang_str(lang_id),tmp1,tmp);
	tor_free(tmp1);
	tor_free(tmp);
}

void proxy_handle_client_data(edge_connection_t *conn)
{	if(conn->_base.mode == (unsigned int)CONNECTION_MODE_OTHER)	return;
	buf_t *buf=conn->_base.inbuf;
	chunk_t *dest;
	char *startaddr,*next,*newhdrs;
	unsigned int i = conn->_base.processed_from_inbuf;
	if(i >= buf->datalen) return;
	int http_hdr;
	buf_pullup(buf,buf->datalen);
	dest = buf->head;
	if(dest)
	{	int j = dest->datalen - i;
		tor_assert(j >= 0);
		if(j)
		{	if(!conn->_base.unprocessed)
			{	conn->_base.unprocessed = tor_malloc(conn->_base.unprocessed_len+j+16);
				conn->_base.unprocessed_len = 0;
			}
			else
			{	char *tmp = conn->_base.unprocessed;
				conn->_base.unprocessed = tor_malloc(conn->_base.unprocessed_len+j+16);
				memcpy(conn->_base.unprocessed,tmp,conn->_base.unprocessed_len);
				tor_free(tmp);
			}
		}
		else return;
		memcpy(conn->_base.unprocessed+conn->_base.unprocessed_len,dest->data+i,j);
		conn->_base.unprocessed_len += j;
		buf->datalen = i;
		dest->datalen = i;
		i = conn->_base.unprocessed_len;
		if(i >= MAX_HTTP_REQUEST_LEN)
		{	conn->_base.mode = CONNECTION_MODE_OTHER;
			conn->_base.processed_from_inbuf += dest->datalen-i;
			write_to_buf(conn->_base.unprocessed,conn->_base.unprocessed_len,buf);
			conn->_base.processed_from_inbuf += conn->_base.unprocessed_len;
			conn->_base.unprocessed_len = 0;
			conn->_base.processed_from_inbuf = buf->datalen;
			return;
		}
		if((conn->_base.mode <= CONNECTION_MODE_UNKNOWN) || (conn->_base.mode == CONNECTION_MODE_SOCKS5_NEGOTIATE))
		{	identity_add_process(conn->_base.pid);
			while(i)
			{	switch(conn->_base.unprocessed[0])
				{	case 4:		// socks4
						if(i<SOCKS4_NETWORK_LEN) return;
						conn->_base.mode = CONNECTION_MODE_UNKNOWN;
						if((unsigned char)conn->_base.unprocessed[1] != SOCKS_COMMAND_CONNECT && (unsigned char)conn->_base.unprocessed[1] != SOCKS_COMMAND_RESOLVE)
						{	i = remove_unprocessed_data(TO_CONN(conn),4);
							log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_INVALID_COMMAND),(unsigned char)conn->_base.unprocessed[1]);
						}
						else
						{	if(ntohl(*(uint32_t*)(&conn->_base.unprocessed[4])) >> 8)
							{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTIP));
								next = memchr(&conn->_base.unprocessed[0]+SOCKS4_NETWORK_LEN,0,conn->_base.unprocessed_len-SOCKS4_NETWORK_LEN);
								if(!next)
								{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_UNAME_INCOMPLETE));
									return;
								}
							}
							else
							{	next = memchr(&conn->_base.unprocessed[0]+SOCKS4_NETWORK_LEN,0,conn->_base.unprocessed_len-SOCKS4_NETWORK_LEN);
								if(!next)
								{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_UNAME_INCOMPLETE));
									return;
								}
								startaddr = NULL;
								if(next+1 == conn->_base.unprocessed + conn->_base.unprocessed_len)
								{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_INCOMPLETE_DESTADDR));
									return;
								}
								startaddr = next+1;
								next = memchr(startaddr,0,conn->_base.unprocessed+conn->_base.unprocessed_len - startaddr);
								if(!next)
								{	log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_DESTADDR_INCOMPLETE));
									return;
								}
								log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS4_SUCCESS));
							}
							write_to_buf(conn->_base.unprocessed,next - conn->_base.unprocessed + 1,buf);
							conn->_base.processed_from_inbuf += next - conn->_base.unprocessed + 1;
							i = remove_unprocessed_data(TO_CONN(conn),next - conn->_base.unprocessed + 1);
						}
						break;
					case 5:		// socks5
						if(i<2)	return;
						if(conn->_base.mode != CONNECTION_MODE_SOCKS5_NEGOTIATE)
						{	unsigned char nummethods = (unsigned char)*(&conn->_base.unprocessed[0]+1);
							if(conn->_base.unprocessed_len < 2u+nummethods)
								return;
							write_to_buf(conn->_base.unprocessed,2u + nummethods,buf);
							conn->_base.processed_from_inbuf += 2u + nummethods;
							conn->_base.expecting_data = 2;
							conn->_base.unprocessed_len = 0;
							conn->_base.mode = CONNECTION_MODE_SOCKS5_NEGOTIATE;
							return;
						}
						log_debug(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_CHECKING_REQUEST));
						if(conn->_base.unprocessed_len < 8)	/* basic info plus >=2 for addr plus 2 for port */
							return; /* not yet */
						http_hdr = (unsigned char) conn->_base.unprocessed[1];
						if(http_hdr == SOCKS_COMMAND_SELECT_ROUTER)
						{	if(buf->head->datalen >= 18)
							{	conn->_base.expecting_data = 14;
								write_to_buf(conn->_base.unprocessed,18,buf);
								conn->_base.processed_from_inbuf += 18;
								i = remove_unprocessed_data(TO_CONN(conn),18);
							}
							else return;
						}
						else
						{	if(http_hdr != SOCKS_COMMAND_CONNECT && http_hdr != SOCKS_COMMAND_RESOLVE && http_hdr != SOCKS_COMMAND_RESOLVE_PTR)	/* not a connect or resolve or a resolve_ptr? we don't support it. */
							{	conn->_base.unprocessed_len = 0;
								return;
							}
							switch(conn->_base.unprocessed[3])	/* address type */
							{	case 1: /* IPv4 address */
								case 4: /* IPv6 address */
								{	const int is_v6 = *(buf->head->data+3) == 4;
									const unsigned addrlen = is_v6 ? 16 : 4;
									if(buf->datalen < 6+addrlen) /* ip/port there? */
										return; /* not yet */
									write_to_buf(conn->_base.unprocessed,6+addrlen,buf);
									conn->_base.processed_from_inbuf += 6+addrlen;
									i = remove_unprocessed_data(TO_CONN(conn),6+addrlen);
									conn->_base.mode = CONNECTION_MODE_UNKNOWN;
									break;
								}
								case 3: /* fqdn */
									http_hdr = (unsigned char)conn->_base.unprocessed[4];
									if(conn->_base.unprocessed_len < 7+http_hdr) /* addr/port there? */
										return; /* not yet */
									write_to_buf(conn->_base.unprocessed,5+http_hdr+2,buf);
									conn->_base.processed_from_inbuf += 5+http_hdr+2;
									i = remove_unprocessed_data(TO_CONN(conn),5+http_hdr+2);
									conn->_base.mode = CONNECTION_MODE_UNKNOWN;
									break;
								default: /* unsupported */
									log_warn(LD_APP,get_lang_str(LANG_LOG_BUFFERS_SOCKS_UNSUPPORTED_ADDR),(int) *(buf->head->data+3));
									conn->_base.unprocessed_len = 0;
									conn->_base.mode = CONNECTION_MODE_UNKNOWN;
									return;
							}
						}
						break;
			//		case '$'	// NMDC
			//			break;
					case 'C':	// HTTP CONNECT
						if(conn->_base.unprocessed_len < 10 || strcasecmpstart(conn->_base.unprocessed,"CONNECT "))	return;
						conn->_base.mode = CONNECTION_MODE_UNKNOWN;
						i = 0;
						break;
					case 'G':	// HTTP GET
						if(i<4 || strcasecmpstart(conn->_base.unprocessed,"GET ")) return;
						if(conn->_base.mode == CONNECTION_MODE_UNKNOWN)	conn->_base.mode = CONNECTION_MODE_HTTP_FROM_CHAIN;
						else						conn->_base.mode = CONNECTION_MODE_HTTP_SIMPLE;
						i = 0;
						identity_add_process(conn->_base.pid);
						break;
					case 'H':	// HTTP HEAD
						if(i<5 || strcasecmpstart(conn->_base.unprocessed,"HEAD ")) return;
						if(conn->_base.mode == CONNECTION_MODE_UNKNOWN)	conn->_base.mode = CONNECTION_MODE_HTTP_FROM_CHAIN;
						else						conn->_base.mode = CONNECTION_MODE_HTTP_SIMPLE;
						i = 0;
						break;
					case 'O':	// OPTIONS
						if(i<8 || strcasecmpstart(conn->_base.unprocessed,"OPTIONS ")) return;
						if(conn->_base.mode == CONNECTION_MODE_UNKNOWN)	conn->_base.mode = CONNECTION_MODE_HTTP_FROM_CHAIN;
						else						conn->_base.mode = CONNECTION_MODE_HTTP_SIMPLE;
						i = 0;
						break;
					case 'P':	// HTTP PUT / POST
						if(i<5 || (strcasecmpstart(conn->_base.unprocessed,"PUT ")&&strcasecmpstart(conn->_base.unprocessed,"POST "))) return;
						if(conn->_base.mode == CONNECTION_MODE_UNKNOWN)	conn->_base.mode = CONNECTION_MODE_HTTP_FROM_CHAIN;
						else						conn->_base.mode = CONNECTION_MODE_HTTP_SIMPLE;
						i = 0;
						break;
			//		case 'U':	// FTP / IRC
			//			break;
			//		case 'N':	// IRC
			//			break;
					default:
						conn->_base.mode = CONNECTION_MODE_OTHER;
						conn->_base.processed_from_inbuf += dest->datalen-i;
						write_to_buf(conn->_base.unprocessed,conn->_base.unprocessed_len,buf);
						conn->_base.processed_from_inbuf += conn->_base.unprocessed_len;
						conn->_base.unprocessed_len = 0;
						conn->_base.processed_from_inbuf = buf->datalen;
						return;
				}
			}
		}
		while(conn->_base.unprocessed_len)
		{	if(conn->_base.need_data)
			{	if(conn->_base.need_data < conn->_base.unprocessed_len)
				{	if(conn->_base.need_data < 0)
					{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_PROXY_INVALID_CHUNK_SIZE_2),conn->socks_request->original_address,conn->_base.need_data);
						connection_mark_for_close(TO_CONN(conn));
						return;
					}
					write_to_buf(conn->_base.unprocessed,conn->_base.need_data,buf);
					conn->_base.processed_from_inbuf += conn->_base.need_data;
					remove_unprocessed_data(TO_CONN(conn),conn->_base.need_data);
					conn->_base.need_data = 0;
					log(LOG_DEBUG,LD_APP,"Remaining chunk: %x",(uint32_t)conn->_base.need_data);
				}
				else
				{	write_to_buf(conn->_base.unprocessed,conn->_base.unprocessed_len,buf);
					conn->_base.processed_from_inbuf += conn->_base.unprocessed_len;
					conn->_base.need_data -= conn->_base.unprocessed_len;
					remove_unprocessed_data(TO_CONN(conn),conn->_base.unprocessed_len);
					conn->_base.unprocessed_len = 0;
					log(LOG_DEBUG,LD_APP,"Remaining chunk: %x",(uint32_t)conn->_base.need_data);
					return;
				}
			}
			if(conn->_base.need_trailers & EXPECTING_CHUNK)
			{	http_hdr = strfind(conn->_base.unprocessed,"\r\n",conn->_base.unprocessed_len);
				if(http_hdr >= 0)
				{	conn->_base.need_data = 0;
					i = 0;
					while((i < conn->_base.unprocessed_len) && ((conn->_base.unprocessed[i]>='0' && conn->_base.unprocessed[i]<='9') || (conn->_base.unprocessed[i]>='A' && conn->_base.unprocessed[i]<='F') || (conn->_base.unprocessed[i]>='a' && conn->_base.unprocessed[i]<='f')))
					{	j = conn->_base.unprocessed[i];
						if(j > 'F')	j -= 0x20;
						j -= 0x30;
						if(j > 9)	j -= 7;
						conn->_base.need_data = (conn->_base.need_data<<4) + j;
						i++;
					}
					if(conn->_base.need_data < 0)
					{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_PROXY_INVALID_CHUNK_SIZE_2),conn->socks_request->original_address,conn->_base.need_data);
						connection_mark_for_close(TO_CONN(conn));
						return;
					}
					write_to_buf(conn->_base.unprocessed,http_hdr+2,buf);
					conn->_base.processed_from_inbuf += http_hdr+2;
					log(LOG_DEBUG,LD_APP,"Trailer: %x",(uint32_t)conn->_base.need_data);
					remove_unprocessed_data(TO_CONN(conn),http_hdr+2);
					if(conn->_base.need_data)
					{	conn->_base.need_data += 2;
						continue;
					}
					conn->_base.need_trailers = 0;
				}
				else return;
			}
			else if(conn->_base.need_trailers & EXPECTING_BOUNDARY)
			{	http_hdr = strfind(conn->_base.unprocessed,"--",conn->_base.unprocessed_len);
				if(http_hdr >= 0)
				{	while(1)
					{	if(http_hdr)
						{	write_to_buf(conn->_base.unprocessed,http_hdr,buf);
							conn->_base.processed_from_inbuf += http_hdr;
							remove_unprocessed_data(TO_CONN(conn),http_hdr);
						}
						if(conn->_base.unprocessed_len < 2 || strfind(conn->_base.unprocessed+2,"--",conn->_base.unprocessed_len-2)<0)	return;
						i = 0;
						http_hdr = 2;
						while(http_hdr < conn->_base.unprocessed_len)
						{	i = i * 3 + conn->_base.unprocessed[http_hdr];
							http_hdr++;
							if(conn->_base.unprocessed[http_hdr]=='-' && conn->_base.unprocessed[http_hdr+1]=='-')	break;
						}
						if(http_hdr < conn->_base.unprocessed_len)
						{	if(conn->_base.need_boundary == (int)i)
							{	write_to_buf(conn->_base.unprocessed,http_hdr+2,buf);
								conn->_base.processed_from_inbuf += http_hdr+2;
								remove_unprocessed_data(TO_CONN(conn),http_hdr+2);
								break;
							}
						}
						else	return;
						write_to_buf(conn->_base.unprocessed,http_hdr,buf);
						conn->_base.processed_from_inbuf += http_hdr;
						remove_unprocessed_data(TO_CONN(conn),http_hdr);
					}
					conn->_base.need_trailers = 0;
				}
				else
				{	if(conn->_base.unprocessed_len > 2)
					{	write_to_buf(conn->_base.unprocessed,conn->_base.unprocessed_len-2,buf);
						conn->_base.processed_from_inbuf += conn->_base.unprocessed_len-2;
						remove_unprocessed_data(TO_CONN(conn),conn->_base.unprocessed_len-2);
					}
					return;
				}
			}
			else if(conn->_base.need_trailers & EXPECTING_CLOSE)
			{	write_to_buf(conn->_base.unprocessed,conn->_base.unprocessed_len,buf);
				conn->_base.processed_from_inbuf += conn->_base.unprocessed_len;
				remove_unprocessed_data(TO_CONN(conn),conn->_base.unprocessed_len);
				return;
			}
			else
			{	http_hdr = strfind(conn->_base.unprocessed,"\r\n\r\n",conn->_base.unprocessed_len);
				if(http_hdr==0)	remove_unprocessed_data(TO_CONN(conn),4);
				else
				{	i = 4;
					if(http_hdr < 0)
					{	http_hdr = strfind(conn->_base.unprocessed,"\n\n",conn->_base.unprocessed_len);
						if(http_hdr==0)
						{	remove_unprocessed_data(TO_CONN(conn),2);
							continue;
						}
						else if(http_hdr < 0)	return;
						i = 2;
					}
					if((tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUESTS) && (tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUEST_HEADERS) && ((tmpOptions->logging&0xff) >= LOG_INFO))
						http_log(LOG_INFO,LANG_LOG_HTTP_REQUEST_HEADERS,conn->_base.unprocessed,http_hdr+i,TO_CONN(conn));
					newhdrs = parse_request_headers(conn->_base.unprocessed,TO_CONN(conn));
					remove_unprocessed_headers(TO_CONN(conn),http_hdr+i);
					if(newhdrs)
					{	http_hdr = strlen(newhdrs);
						if(!strcasecmpstart(newhdrs,"head "))
						{	conn->_base.expecting_trailers |= EXPECTING_NO_DATA;
							conn->_base.expecting_no_data++;
						}
						if((tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUESTS) && (tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUEST_HEADERS))
							http_log(LOG_NOTICE,LANG_LOG_HTTP_REQUEST_MODIFIED,newhdrs,http_hdr,TO_CONN(conn));
						write_to_buf(newhdrs,http_hdr,buf);
						conn->_base.processed_from_inbuf += http_hdr;
						tor_free(newhdrs);
					}
				}
			}
		}
	}
}

int proxy_handle_server_data(connection_t *conn,const char *string,int len)
{	int r = conn->outbuf->datalen;
	if((conn->mode == CONNECTION_MODE_HTTP_SIMPLE || conn->mode == CONNECTION_MODE_HTTP_FROM_CHAIN) && (TO_EDGE_CONN(conn)->socks_request->has_finished))
	{	if(!conn->incoming)
			conn->incoming = tor_malloc(conn->incoming_len+len+16);
		else
		{	char *tmp = conn->incoming;
			conn->incoming = tor_malloc(conn->incoming_len+len+16);
			memcpy(conn->incoming,tmp,conn->incoming_len);
			tor_free(tmp);
		}
		memcpy(conn->incoming+conn->incoming_len,string,len);
		conn->incoming_len += len;
		while(conn->incoming_len)
		{	if(conn->expecting_data)
			{	if(conn->expecting_data < conn->incoming_len)
				{	if(conn->expecting_data < 0)
					{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_PROXY_INVALID_CHUNK_SIZE_1),TO_EDGE_CONN(conn)->socks_request->original_address,conn->need_data);
						return -1;
					}
					r = write_to_buf(conn->incoming,conn->expecting_data,conn->outbuf);
					remove_incoming_data(conn,conn->expecting_data);
					conn->expecting_data = 0;
					log(LOG_DEBUG,LD_APP,"Remaining chunk: %x",(uint32_t)conn->expecting_data);
				}
				else
				{	r = write_to_buf(conn->incoming,conn->incoming_len,conn->outbuf);
					conn->expecting_data -= conn->incoming_len;
					remove_incoming_data(conn,conn->incoming_len);
					conn->incoming_len = 0;
					log(LOG_DEBUG,LD_APP,"Remaining chunk: %x",(uint32_t)conn->expecting_data);
					return r;
				}
			}
			int http_hdr;
			if(conn->expecting_trailers & EXPECTING_CHUNK)
			{	http_hdr = strfind(conn->incoming,"\r\n",conn->incoming_len);
				if(http_hdr >= 0)
				{	conn->expecting_data = 0;
					int i = 0,j;
					while((i < conn->incoming_len) && ((conn->incoming[i]>='0' && conn->incoming[i]<='9') || (conn->incoming[i]>='A' && conn->incoming[i]<='F') || (conn->incoming[i]>='a' && conn->incoming[i]<='f')))
					{	j = conn->incoming[i];
						if(j > 'F')	j -= 0x20;
						j -= 0x30;
						if(j > 9)	j -= 7;
						conn->expecting_data = (conn->expecting_data<<4) + j;
						i++;
					}
					if(conn->expecting_data < 0)
					{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_PROXY_INVALID_CHUNK_SIZE_1),TO_EDGE_CONN(conn)->socks_request->original_address,conn->need_data);
						return -1;
					}
					r = write_to_buf(conn->incoming,http_hdr+2,conn->outbuf);
					log(LOG_DEBUG,LD_APP,"Trailer: %x",(uint32_t)conn->expecting_data);
					remove_incoming_data(conn,http_hdr+2);
					if(conn->expecting_data)
					{	conn->expecting_data += 2;
						continue;
					}
					conn->expecting_trailers = 0;
				}
				else return r;
			}
			else if(conn->expecting_trailers & EXPECTING_BOUNDARY)
			{	http_hdr = strfind(conn->incoming,"--",conn->incoming_len);
				if(http_hdr >= 0)
				{	int i;
					while(1)
					{	if(http_hdr)
						{	r = write_to_buf(conn->incoming,http_hdr,conn->outbuf);
							remove_incoming_data(conn,http_hdr);
						}
						if(conn->incoming_len < 2 || strfind(conn->incoming+2,"--",conn->incoming_len-2)<0)	return r;
						i = 0;
						http_hdr = 2;
						while(http_hdr < conn->incoming_len)
						{	i = i * 3 + conn->incoming[http_hdr];
							http_hdr++;
							if(conn->incoming[http_hdr]=='-' && conn->incoming[http_hdr+1]=='-')	break;
						}
						if(http_hdr < conn->incoming_len)
						{	if(conn->last_boundary == i)
							{	r = write_to_buf(conn->incoming,http_hdr+2,conn->outbuf);
								remove_incoming_data(conn,http_hdr+2);
								break;
							}
						}
						else	return r;
						r = write_to_buf(conn->incoming,http_hdr,conn->outbuf);
						remove_incoming_data(conn,http_hdr);
					}
					conn->expecting_trailers = 0;
				//	conn->expecting_data += 2;
				}
				else
				{	if(conn->incoming_len > 2)
					{	r = write_to_buf(conn->incoming,conn->incoming_len-2,conn->outbuf);
						remove_incoming_data(conn,conn->incoming_len-2);
					}
					return r;
				}
			}
			else if(conn->expecting_trailers & EXPECTING_CLOSE)
			{	r = write_to_buf(conn->incoming,conn->incoming_len,conn->outbuf);
				remove_incoming_data(conn,conn->incoming_len);
				return r;
			}
			else
			{	http_hdr = strfind(conn->incoming,"\r\n\r\n",conn->incoming_len);
				if(http_hdr == 0)
				{	r = write_to_buf("\r\n\r\n",4,conn->outbuf);
					remove_incoming_data(conn,4);
				}
				else if(http_hdr < 0)
				{	http_hdr = strfind(conn->incoming,"\r\n",conn->incoming_len);
					if(http_hdr == 0)
					{	r = write_to_buf(conn->incoming,2,conn->outbuf);
						remove_incoming_data(conn,2);
					}
					return r;
				}
				else
				{	http_hdr += 4;
					char *tmp = parse_response_headers(conn,conn->incoming,http_hdr);
					remove_incoming_data(conn,http_hdr);
					if(conn->expecting_trailers & EXPECTING_NO_DATA)
					{	conn->expecting_trailers = 0;
						conn->expecting_data = 0;
						conn->expecting_no_data--;
						if(conn->expecting_no_data > 0)
							conn->expecting_trailers |= EXPECTING_NO_DATA;
					}
					if(!tmp)	return -1;
					r = write_to_buf(tmp,strlen(tmp),conn->outbuf);
					if((tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_STATUS) && (tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_TRAFFIC))
						http_log(LOG_NOTICE,LANG_LOG_HTTP_RESPONSE_HEADERS,tmp,strlen(tmp),conn);
					tor_free(tmp);
				}
			}
		}
	}
	else r = write_to_buf(string,len,conn->outbuf);
	return r;
}
