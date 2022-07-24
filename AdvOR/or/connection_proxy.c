#include "or.h"
#include "buffers.h"
#include "config.h"
#include "connection.h"
#include "directory.h"
#include "main.h"
#include "connection_proxy.h"
#include <ntlm.h>

const char *socks4_response_code_to_string(uint8_t code);
const char *socks5_response_code_to_string(uint8_t code);
int fetch_from_buf_socks_client(buf_t *buf, int state, char **reason);

/** Convert state number to string representation for logging purposes.
 */
static const char *connection_proxy_state_to_string(int state)
{	static const char *unknown = "???";
	static const char *states[] = {
			"PROXY_NONE",
			"PROXY_HTTPS_WANT_CONNECT_OK",
			"PROXY_SOCKS4_WANT_CONNECT_OK",
			"PROXY_SOCKS5_WANT_AUTH_METHOD_NONE",
			"PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929",
			"PROXY_SOCKS5_WANT_AUTH_RFC1929_OK",
			"PROXY_SOCKS5_WANT_CONNECT_OK",
			"PROXY_NTLM_WANT_CONNECT_OK",
			"PROXY_CONNECTED"};
	if(state < PROXY_NONE || state > PROXY_CONNECTED)
		return unknown;
	return states[state];
}

/** Return a string corresponding to a SOCKS4 reponse code. */
const char *socks4_response_code_to_string(uint8_t code)
{
  switch (code) {
    case 0x5a:
      return "connection accepted";
    case 0x5b:
      return "server rejected connection";
    case 0x5c:
      return "server cannot connect to identd on this client";
    case 0x5d:
      return "user id does not match identd";
    default:
      return "invalid SOCKS 4 response code";
  }
}

/** Return a string corresponding to a SOCKS5 reponse code. */
const char *socks5_response_code_to_string(uint8_t code)
{
  switch (code) {
    case 0x00:
      return "connection accepted";
    case 0x01:
      return "general SOCKS server failure";
    case 0x02:
      return "connection not allowed by ruleset";
    case 0x03:
      return "Network unreachable";
    case 0x04:
      return "Host unreachable";
    case 0x05:
      return "Connection refused";
    case 0x06:
      return "TTL expired";
    case 0x07:
      return "Command not supported";
    case 0x08:
      return "Address type not supported";
    default:
      return "unknown reason";
  }
}

#define MAX_SOCKS_MESSAGE_LEN 512
/** Inspect a reply from SOCKS server stored in <b>buf</b> according to <b>state</b>, removing the protocol data upon success. Return 0 on incomplete response, 1 on success and -1 on error, in which case <b>reason</b> is set to a descriptive message (free() when finished with it).
 * As a special case, 2 is returned when user/pass is required during SOCKS5 handshake and user/pass is configured. */
int fetch_from_buf_socks_client(buf_t *buf, int state, char **reason)
{	unsigned char *data;
	size_t addrlen;
	if(buf->datalen < 2)	return 0;
	buf_pullup(buf, MAX_SOCKS_MESSAGE_LEN);
	tor_assert(buf->head && buf->head->datalen >= 2);
	data = (unsigned char *) buf->head->data;
	switch(state)
	{	case PROXY_SOCKS4_WANT_CONNECT_OK:	/* Wait for the complete response */
			if(buf->head->datalen < 8)	return 0;
			if(data[1] != 0x5a)
			{	*reason = tor_strdup(socks4_response_code_to_string(data[1]));
				return -1;
			}
			buf_remove_from_front(buf, 8);	/* Success */
			return 1;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_NONE:	/* we don't have any credentials */
			if(data[1] != 0x00)
			{	*reason = tor_strdup("server doesn't support any of our available authentication methods");
				return -1;
			}
			log_info(LD_NET, get_lang_str(LANG_LOG_BUFFERS_SOCKS5_WITHOUT_AUTHENTICATION));
			buf_clear(buf);
			return 1;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929:	/* we have a username and password. return 1 if we can proceed without providing authentication, or 2 otherwise. */
			switch(data[1])
			{	case 0x00:
					log_info(LD_NET, get_lang_str(LANG_LOG_BUFFERS_SOCKS5_NO_AUTHENTICATION));
					buf_clear(buf);
					return 1;
				case 0x02:
					log_info(LD_NET, get_lang_str(LANG_LOG_BUFFERS_SOCKS5_NEED_AUTHENTICATION));
					buf_clear(buf);
					return 2;
			}	/* fall through */
			*reason = tor_strdup("server doesn't support any of our available authentication methods");
			return -1;
		case PROXY_SOCKS5_WANT_AUTH_RFC1929_OK:	/* handle server reply to rfc1929 authentication */
			if(data[1] != 0x00)
			{	*reason = tor_strdup("authentication failed");
				return -1;
			}
			log_info(LD_NET, get_lang_str(LANG_LOG_BUFFERS_SOCKS5_AUTHENTICATION_SUCCESSFULL));
			buf_clear(buf);
			return 1;
		case PROXY_SOCKS5_WANT_CONNECT_OK:	/* response is variable length. BND.ADDR, etc, isn't needed (don't bother with buf_pullup()), but make sure to eat all the data used */
			if(buf->datalen < 4)	return 0;	/* wait for address type field to arrive */
			switch(data[3])
			{	case 0x01: /* ip4 */
					addrlen = 4;
					break;
				case 0x04: /* ip6 */
					addrlen = 16;
					break;
				case 0x03: /* fqdn (can this happen here?) */
					if(buf->datalen < 5)	return 0;
					addrlen = 1 + data[4];
					break;
				default:
					*reason = tor_strdup("invalid response to connect request");
					return -1;
			}
			if(buf->datalen < 6 + addrlen)	return 0;	/* wait for address and port */
			if(data[1] != 0x00)
			{	*reason = tor_strdup(socks5_response_code_to_string(data[1]));
				return -1;
			}
			buf_remove_from_front(buf, 6 + addrlen);
			return 1;
	}
	/* shouldn't get here... */
	tor_assert(0);
	return -1;
}

/** Write a proxy request of <b>type</b> (socks4, socks5, https) to conn for conn->addr:conn->port, authenticating with the auth details given in the configuration (if available). SOCKS 5 and HTTP CONNECT proxies support authentication.
 * Returns -1 if conn->addr is incompatible with the proxy protocol, and 0 otherwise.
 * Use connection_read_proxy_handshake() to complete the handshake. */
int connection_proxy_connect(connection_t *conn,int ntlm)
{	or_options_t *options;
	tor_assert(conn);
	options = get_options();
	if(ntlm)
	{	unsigned char *buf;
		if(options->DirFlags&DIR_FLAG_HTTPS_PROXY && options->ORProxy)
			tor_asprintf(&buf,"CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&options->ORProxyAddr), conn->port);
		else	tor_asprintf(&buf,"CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&conn->addr), conn->port);
		connection_write_to_buf((char *)buf,strlen((char *)buf), conn);
		tor_free(buf);
		conn->proxy_state = PROXY_NTLM_WANT_CONNECT_OK;
	}
	else
	{	int type = options->ORProxyProtocol;
		switch(type)
		{	case PROXY_CONNECT:
			{	char buf[1024];
				char *base64_authenticator=NULL;
				const char *authenticator = options->ORProxyAuthenticator;
				/* Send HTTP CONNECT and authentication (if available) in one request */
				if(authenticator)
				{	base64_authenticator = alloc_http_authenticator(authenticator);
					if(!base64_authenticator)	log_warn(LD_OR,get_lang_str(LANG_LOG_CONNECTION_ENCODING_HTTPS_AUTH_FAILED));
				}
				if(base64_authenticator)
				{	tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",fmt_addr(&conn->addr),conn->port,fmt_addr(&conn->addr),conn->port,base64_authenticator);
					tor_free(base64_authenticator);
				}
				else
					tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&conn->addr), conn->port);
				connection_write_to_buf(buf, strlen(buf), conn);
				conn->proxy_state = PROXY_HTTPS_WANT_CONNECT_OK;
				break;
			}
			case PROXY_SOCKS4:
			{	unsigned char buf[9];
				uint16_t portn;
				uint32_t ip4addr;
				/* Send a SOCKS4 connect request with empty user id */
				if(tor_addr_family(&conn->addr) != AF_INET)
				{	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_SOCKS4_IPV6));
					return -1;
				}
				ip4addr = tor_addr_to_ipv4n(&conn->addr);
				portn = htons(conn->port);
				buf[0] = 4; /* version */
				buf[1] = SOCKS_COMMAND_CONNECT; /* command */
				memcpy(buf + 2, &portn, 2); /* port */
				memcpy(buf + 4, &ip4addr, 4); /* addr */
				buf[8] = 0; /* userid (empty) */
				connection_write_to_buf((char *)buf, sizeof(buf), conn);
				conn->proxy_state = PROXY_SOCKS4_WANT_CONNECT_OK;
				break;
			}
			case PROXY_SOCKS5:
			{	unsigned char buf[4]; /* fields: vers, num methods, method list */
				/* Send a SOCKS5 greeting (connect request must wait) */
				buf[0] = 5; /* version */
				/* number of auth methods */
				if(options->ORProxyAuthenticator)
				{	buf[1] = 2;
					buf[2] = 0x00; /* no authentication */
					buf[3] = 0x02; /* rfc1929 Username/Passwd auth */
					conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929;
				}
				else
				{	buf[1] = 1;
					buf[2] = 0x00; /* no authentication */
					conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_METHOD_NONE;
				}
				connection_write_to_buf((char *)buf, 2 + buf[1], conn);
				break;
			}
			default:
				log_err(LD_BUG,get_lang_str(LANG_LOG_CONNECTION_INVALID_PROXY_PROTOCOL), type);
				tor_fragile_assert();
				return -1;
		}
	}
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_SET_STATE),connection_proxy_state_to_string(conn->proxy_state));
	return 0;
}

int dir_proxy_connect(connection_t *conn,int ntlm)
{	or_options_t *options;
	tor_assert(conn);
	options = get_options();
	if(ntlm)
	{	unsigned char *buf;
		if(options->DirFlags&DIR_FLAG_HTTP_PROXY && options->DirProxy)
			tor_asprintf(&buf,"CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&options->DirProxyAddr), conn->port);
		else	tor_asprintf(&buf,"CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&conn->addr), conn->port);
		connection_write_to_buf((char *)buf,strlen((char *)buf), conn);
		tor_free(buf);
		conn->proxy_state = PROXY_NTLM_WANT_CONNECT_OK;
	}
	else
	{	int type = options->DirProxyProtocol;
		switch(type)
		{	case PROXY_CONNECT:
			{	char buf[1024];
				char *base64_authenticator=NULL;
				const char *authenticator = options->DirProxyAuthenticator;
				/* Send HTTP CONNECT and authentication (if available) in one request */
				if(authenticator)
				{	base64_authenticator = alloc_http_authenticator(authenticator);
					if(!base64_authenticator)	log_warn(LD_OR,get_lang_str(LANG_LOG_CONNECTION_ENCODING_HTTPS_AUTH_FAILED));
				}
				if(base64_authenticator)
				{	tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n",fmt_addr(&conn->addr),conn->port, base64_authenticator);
					tor_free(base64_authenticator);
				}
				else
					tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n\r\n",fmt_addr(&conn->addr), conn->port);
				connection_write_to_buf(buf, strlen(buf), conn);
				conn->proxy_state = PROXY_HTTPS_WANT_CONNECT_OK;
				break;
			}
			case PROXY_SOCKS4:
			{	unsigned char buf[9];
				uint16_t portn;
				uint32_t ip4addr;
				/* Send a SOCKS4 connect request with empty user id */
				if(tor_addr_family(&conn->addr) != AF_INET)
				{	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_SOCKS4_IPV6));
					return -1;
				}
				ip4addr = tor_addr_to_ipv4n(&conn->addr);
				portn = htons(conn->port);
				buf[0] = 4; /* version */
				buf[1] = SOCKS_COMMAND_CONNECT; /* command */
				memcpy(buf + 2, &portn, 2); /* port */
				memcpy(buf + 4, &ip4addr, 4); /* addr */
				buf[8] = 0; /* userid (empty) */
				connection_write_to_buf((char *)buf, sizeof(buf), conn);
				conn->proxy_state = PROXY_SOCKS4_WANT_CONNECT_OK;
				break;
			}
			case PROXY_SOCKS5:
			{	unsigned char buf[4]; /* fields: vers, num methods, method list */
				/* Send a SOCKS5 greeting (connect request must wait) */
				buf[0] = 5; /* version */
				/* number of auth methods */
				if(options->DirProxyAuthenticator)
				{	buf[1] = 2;
					buf[2] = 0x00; /* no authentication */
					buf[3] = 0x02; /* rfc1929 Username/Passwd auth */
					conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929;
				}
				else
				{	buf[1] = 1;
					buf[2] = 0x00; /* no authentication */
					conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_METHOD_NONE;
				}
				connection_write_to_buf((char *)buf, 2 + buf[1], conn);
				break;
			}
			default:
				log_err(LD_BUG,get_lang_str(LANG_LOG_CONNECTION_INVALID_PROXY_PROTOCOL), type);
				tor_fragile_assert();
				return -1;
		}
	}
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_SET_STATE),connection_proxy_state_to_string(conn->proxy_state));
	return 0;
}

/** Send SOCKS5 CONNECT command to <b>conn</b>, copying <b>conn->addr</b> and <b>conn->port</b> into the request. */
static void connection_send_socks5_connect(connection_t *conn)
{	unsigned char buf[1024];
	size_t reqsize = 6;
	uint16_t port = htons(conn->port);
	buf[0] = 5; /* version */
	buf[1] = SOCKS_COMMAND_CONNECT; /* command */
	buf[2] = 0; /* reserved */
	if(tor_addr_family(&conn->addr) == AF_INET)
	{	uint32_t addr = tor_addr_to_ipv4n(&conn->addr);
		buf[3] = 1;
		reqsize += 4;
		memcpy(buf + 4, &addr, 4);
		memcpy(buf + 8, &port, 2);
	}
	else	/* AF_INET6 */
	{	buf[3] = 4;
		reqsize += 16;
		memcpy(buf + 4, tor_addr_to_in6(&conn->addr), 16);
		memcpy(buf + 20, &port, 2);
	}
	connection_write_to_buf((char *)buf, reqsize, conn);
	conn->proxy_state = PROXY_SOCKS5_WANT_CONNECT_OK;
}

/** Read conn's inbuf. If the http response from the proxy is all here, make sure it's good news, then return 1. If it's bad news, return -1. Else return 0 and hope for better luck next time. */
static int connection_read_https_proxy_response(connection_t *conn)
{	char *headers;
	char *reason=NULL;
	char *esc_l;
	int status_code;
	time_t date_header;
	switch(fetch_from_buf_http(conn->inbuf,&headers, MAX_HEADERS_SIZE,NULL, NULL, 10000, 0))
	{	case -1: /* overflow */
			log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_CONNECTION_OVERSIZED_HTTPS_RESPONSE));
			return -1;
		case 0:
			log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_INCOMPLETE_HTTPS_RESPONSE));
			return 0;
		/* case 1, fall through */
	}
	if(parse_http_response(headers, &status_code, &date_header,NULL, &reason) < 0)
	{	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNPARSEABLE_PROXY_HEADERS),conn->address);
		tor_free(headers);
		return -1;
	}
	tor_free(headers);
	if(!reason)	reason = tor_strdup("[no reason given]");
	if(status_code == 200)
	{	esc_l = esc_for_log(reason);
		log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_HTTPS_CONNECT_SUCCESS),conn->address,esc_l);
		tor_free(esc_l);
		tor_free(reason);
		return 1;
	}
	/* else, bad news on the status code */
	switch(status_code)
	{	case 403:
			esc_l = esc_for_log(reason);
			log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_HTTPS_PROXY_REFUSE),conn->address, status_code,esc_l);
			tor_free(esc_l);
			break;
		default:
			esc_l = esc_for_log(reason);
			log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNEXPECTED_HTTPS_STATUS),status_code,esc_l);
			tor_free(esc_l);
			break;
	}
	tor_free(reason);
	return -1;
}

static int connection_read_ntlm_proxy_response(connection_t *conn,int isdir)
{	char *headers;
	int status_code;
	unsigned int n1,n2;
	char *workstation,*domain;
	int i,j;
	smartlist_t *parsed_headers;
	or_options_t *options = get_options();
	switch(fetch_from_buf_http(conn->inbuf,&headers, MAX_HEADERS_SIZE,NULL, NULL, 10000, 0))
	{	case -1: /* overflow */
			log_warn(LD_PROTOCOL,get_lang_str(LANG_LOG_CONNECTION_OVERSIZED_HTTPS_RESPONSE));
			return -1;
		case 0:
			log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_INCOMPLETE_HTTPS_RESPONSE));
			return 0;
		/* case 1, fall through */
	}
	while(TOR_ISSPACE(*headers)) headers++; /* tolerate leading whitespace */
	if(tor_sscanf(headers, "HTTP/1.%u %u", &n1, &n2) < 2 || (n1 != 0 && n1 != 1) || (n2 < 100 || n2 >= 600))
	{	char *esc_l = esc_for_log(headers);
		log_warn(LD_HTTP,get_lang_str(LANG_LOG_DIR_HTTP_HEADER_PARSE_FAILED),esc_l);
		tor_free(esc_l);
		return -1;
	}
	status_code = n2;
	parsed_headers = smartlist_create();
	smartlist_split_string(parsed_headers, headers, "\n",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
	tor_free(headers);
	if(status_code == 200)
	{	log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_NTLM_CONNECT_SUCCESS),conn->address);
		status_code = 1;
	}
	else if(status_code >= 400 && status_code < 500)
	{	status_code = -1;
		SMARTLIST_FOREACH(parsed_headers,char *, s,
		{	if(!strcasecmpstart(s, "www-authenticate:"))
			{	headers = s + 17;
				while(*headers==32)	headers++;
				if(!strcasecmpstart(headers,"ntlm"))
				{	tSmbNtlmAuthRequest request;
					headers += 4;
					while(*headers==32)	headers++;
					char *requeststr = tor_malloc_zero(1024);
					if(headers[0] > 32)
					{	log(LOG_DEBUG,LD_APP,get_lang_str(LANG_LOG_NTLM_CHALLENGE),headers);
						tSmbNtlmAuthChallenge challenge;
						tSmbNtlmAuthResponse  response;
						base64_decode((char *)&challenge,sizeof(tSmbNtlmAuthChallenge),(const char *)headers,strlen(headers));
						char *user = tor_malloc(256);
						char *pass = tor_malloc(256);
						user[0] = pass[0] = 0;
						if(options->CorporateProxyAuthenticator)
						{	for(i=0;options->CorporateProxyAuthenticator[i] && options->CorporateProxyAuthenticator[i]!=':' && i<255;i++)
								user[i] = options->CorporateProxyAuthenticator[i];
							user[i] = 0;
							if(options->CorporateProxyAuthenticator[i]==':')	i++;
							for(j=0;options->CorporateProxyAuthenticator[i+j] && j < 255;j++)
								pass[j] = options->CorporateProxyAuthenticator[i+j];
							pass[j] = 0;
						}
						buildSmbNtlmAuthResponse(&challenge,&response,user,pass);
						tor_free(user);tor_free(pass);
						base64_encode(requeststr,1023,(char *)&response,SmbLength(&response),0);
					}
					else
					{	log(LOG_DEBUG,LD_APP,get_lang_str(LANG_LOG_NTLM_MESSAGE_TYPE_1));
						workstation=NULL;
						domain=NULL;
						if(options->CorporateProxyDomain)
						{	workstation = tor_malloc(256);
							domain = tor_malloc(256);
							for(i=0;options->CorporateProxyDomain[i] && options->CorporateProxyDomain[i]!='@' && i < 255;i++)
							{	workstation[i] = options->CorporateProxyDomain[i];
							}
							workstation[i] = 0;
							if(options->CorporateProxyDomain[i])
							{	i++;
								for(j=0;j<255;j++)
								{	domain[j] = options->CorporateProxyDomain[i+j];
								}
							}
							else
							{	strcpy(domain,workstation);
								gethostname(workstation,255);
							}
						}
						else
						{	workstation = tor_malloc(256);
							gethostname(workstation,255);
						}
						if(workstation)	tor_strupper(workstation);
						if(domain)	tor_strupper(domain);
						buildSmbNtlmAuthRequest(&request,workstation,domain);
						if(workstation)	tor_free(workstation);
						if(domain)	tor_free(domain);
						base64_encode(requeststr,1023,(char *)&request,SmbLength(&request),0);
					}
					j=0;
					for(i=0;requeststr[i];i++)
					{	if(requeststr[i]!=13 && requeststr[i]!=10)
						{	requeststr[j] = requeststr[i];
							j++;
						}
					}
					requeststr[j] = 0;
					tor_addr_t *addr = &conn->addr;
					int port = conn->port;
					if(isdir)
					{	if((options->DirFlags&DIR_FLAG_HTTP_PROXY) && options->DirProxy)
						{	addr = &options->DirProxyAddr;
							port = options->DirProxyPort;
						}
					}
					else
					{	if((options->DirFlags&DIR_FLAG_HTTPS_PROXY) && options->ORProxy)
						{	addr = &options->ORProxyAddr;
							port = options->ORProxyPort;
						}
					}
					unsigned char *buf;
					tor_asprintf(&buf,"CONNECT %s:%d HTTP/1.0\r\nAuthorization: NTLM %s\r\n\r\n",fmt_addr(addr),port,requeststr);
					connection_write_to_buf((char *)buf,strlen((char *)buf),conn);
					tor_free(buf);
					tor_free(requeststr);
					status_code = 0;
				}
				else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_NTLM_UNSUPPORTED_AUTH));
				break;
			}
		});
	}
	else
	{	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNEXPECTED_NTLM_STATUS),status_code);
		status_code = -1;
	}
	SMARTLIST_FOREACH(parsed_headers, char *, s, tor_free(s));
	smartlist_free(parsed_headers);
	return status_code;
}

/** Call this from connection_*_process_inbuf() to advance the proxy handshake.
 * No matter what proxy protocol is used, if this function returns 1, the handshake is complete, and the data remaining on inbuf may contain the start of the communication with the requested server.
 * Returns 0 if the current buffer contains an incomplete response, and -1 on error. */
int connection_read_proxy_handshake(connection_t *conn)
{	int ret = 0;
	char *reason = NULL;
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_ENTER_STATE),connection_proxy_state_to_string(conn->proxy_state));
	switch(conn->proxy_state)
	{	case PROXY_NTLM_WANT_CONNECT_OK:
			ret = connection_read_ntlm_proxy_response(conn,0);
			if(ret == 1)
			{	if(get_options()->DirFlags&DIR_FLAG_HTTPS_PROXY && get_options()->ORProxy)
					return connection_proxy_connect(conn,0);
				conn->proxy_state = PROXY_CONNECTED;
			}
			break;
		case PROXY_HTTPS_WANT_CONNECT_OK:
			ret = connection_read_https_proxy_response(conn);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		case PROXY_SOCKS4_WANT_CONNECT_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_NONE:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* no auth needed, do connect */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* send auth if needed, otherwise do connect */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			else if(ret == 2)
			{	unsigned char buf[1024];
				char *auth = get_options()->ORProxyAuthenticator;
				unsigned char i,j;
				buf[0] = 1; /* negotiation version */
				for(i=0;auth[i] && auth[i]!=':';i++)	buf[2+i] = auth[i];
				buf[1] = i;
				j = i;
				for(;auth[i];i++)	buf[2+i] = auth[i];
				buf[2+j] = i - j - (i>j);
				connection_write_to_buf((char *)buf, 2+i, conn);
				conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_RFC1929_OK;
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_AUTH_RFC1929_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* send the connect request */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_CONNECT_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		default:
			log_err(LD_BUG,get_lang_str(LANG_LOG_CONNECTION_INVALID_PROXY_STATE),conn->proxy_state);
			tor_fragile_assert();
			ret = -1;
			break;
	}
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_LEAVING_STATE),connection_proxy_state_to_string(conn->proxy_state));
	if(ret < 0)
	{	if(reason)
		{	char *esc_l = esc_for_log(reason);
			log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNABLE_TO_CONNECT_1),conn->address, conn->port,esc_l);
			tor_free(esc_l);
			tor_free(reason);
		}
		else	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNABLE_TO_CONNECT_2),conn->address, conn->port);
	}
	else if (ret == 1)
		log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_CONN_SUCCESSFULL),conn->address, conn->port);
	return ret;
}

int dir_read_proxy_handshake(connection_t *conn)
{	int ret = 0;
	char *reason = NULL;
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_ENTER_STATE),connection_proxy_state_to_string(conn->proxy_state));
	switch(conn->proxy_state)
	{	case PROXY_NTLM_WANT_CONNECT_OK:
			ret = connection_read_ntlm_proxy_response(conn,1);
			if(ret == 1)
			{	if((get_options()->DirFlags & DIR_FLAG_HTTP_PROXY) && get_options()->DirProxy)
					return dir_proxy_connect(conn,0);
				conn->proxy_state = PROXY_CONNECTED;
			}
			break;
		case PROXY_HTTPS_WANT_CONNECT_OK:
			ret = connection_read_https_proxy_response(conn);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		case PROXY_SOCKS4_WANT_CONNECT_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_NONE:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* no auth needed, do connect */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* send auth if needed, otherwise do connect */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			else if(ret == 2)
			{	unsigned char buf[1024];
				char *auth = get_options()->DirProxyAuthenticator;
				unsigned char i,j;
				buf[0] = 1; /* negotiation version */
				for(i=0;auth[i] && auth[i]!=':';i++)	buf[2+i] = auth[i];
				buf[1] = i;
				j = i;
				for(;auth[i];i++)	buf[2+i] = auth[i];
				buf[2+j] = i - j - (i>j);
				connection_write_to_buf((char *)buf, 2+i, conn);
				conn->proxy_state = PROXY_SOCKS5_WANT_AUTH_RFC1929_OK;
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_AUTH_RFC1929_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			/* send the connect request */
			if(ret == 1)
			{	connection_send_socks5_connect(conn);
				ret = 0;
			}
			break;
		case PROXY_SOCKS5_WANT_CONNECT_OK:
			ret = fetch_from_buf_socks_client(conn->inbuf,conn->proxy_state,&reason);
			if(ret == 1)	conn->proxy_state = PROXY_CONNECTED;
			break;
		default:
			log_err(LD_BUG,get_lang_str(LANG_LOG_CONNECTION_INVALID_PROXY_STATE),conn->proxy_state);
			tor_fragile_assert();
			ret = -1;
			break;
	}
	log_debug(LD_NET,get_lang_str(LANG_LOG_CONNECTION_LEAVING_STATE),connection_proxy_state_to_string(conn->proxy_state));
	if(ret < 0)
	{	if(reason)
		{	char *esc_l = esc_for_log(reason);
			log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNABLE_TO_CONNECT_1),conn->address, conn->port,esc_l);
			tor_free(esc_l);
			tor_free(reason);
		}
		else	log_warn(LD_NET,get_lang_str(LANG_LOG_CONNECTION_UNABLE_TO_CONNECT_2),conn->address, conn->port);
	}
	else if(ret == 0)	connection_start_writing(conn);
	else if (ret == 1)
	{	log_info(LD_NET,get_lang_str(LANG_LOG_CONNECTION_CONN_SUCCESSFULL),conn->address, conn->port);
		dir_connection_t *c = TO_DIR_CONN(conn);
		if(c->orig_request)
		{	connection_write_to_buf(c->orig_request,c->orig_request_len,conn);
			tor_free(c->orig_request);c->orig_request=NULL;
		}
		conn->state = DIR_CONN_STATE_CLIENT_SENDING;
	}
	return ret;
}
