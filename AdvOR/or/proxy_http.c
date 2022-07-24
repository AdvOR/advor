#include "or.h"
#include "proxy.h"
#include "proxy_http.h"
#include "geoip.h"
#include "connection.h"
#include "connection_edge.h"

cookie_info *cookies = NULL;

void http_show_warning(char *headers,connection_t *conn,DWORD warn_type);
int is_header_dangerous(char *headers,connection_t *conn);
char *header_to_domain(char *tmp);
char *url_to_domain(char *tmp);
int is_header_banned(const char *name);
void append_header(char *response,int *written,const char *hdrname,const char *hdrval);
void regen_googlebot(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_bingbot(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_yandex(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_yahoo(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_utorrent(http_headers *hdrs,connection_t *conn,char *result,int *written);
void write_accept_language(http_headers *hdrs,connection_t *conn,char *result,int *written,int browser_type);
void append_lang_string(char *response,int *written,http_headers *hdrs,connection_t *conn,int lang_type);
void append_os_string(char *response,int *written,int osindex,int browser);
void append_ff_byte(char *response,int *written,int rv,int dot);
void append_google_toolbar(char *agent,int *agent_max);
void set_browser_version(http_headers *hdrs);
void write_user_agent(http_headers *hdrs,connection_t *conn,char *result,int *written,int browser_type);
void regen_chrome(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_firefox(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_ie(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_opera(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_safari(http_headers *hdrs,connection_t *conn,char *result,int *written);
void regen_any(http_headers *hdrs,connection_t *conn,char *result,int *written);
int number_from_string(char *str);
void set_version(http_headers *hdrs,char *useragent,int default_ver_0,int default_ver_1,int default_ver_2,int default_ver_3);
void set_version_2(http_headers *hdrs,char *useragent,int default_ver_0,int default_ver_1,int default_ver_2,int default_ver_3);
void free_cookie(cookie_info *c);

// When Opera Turbo is enabled we send fake screen attributes to Opera servers (the exit node can see this information in plain text)
// The current fake resolution is (identity_seed1 % NUM_SCREEN_RESOLUTIONS)
// HTTP header:
// X-Opera-Info: ID=%[request_id], p=0, f=%[(identity_seed1 & 3) + 7], sw=%[screen_width], sh=%[screen_height-taskbar_height]
// Example:
// X-Opera-Info: ID=2, p=0, f=9, sw=1280, sh=996
#define NUM_SCREEN_RESOLUTIONS 21
#define TASKBAR_HEIGHT 28	// Windows XP Classic style
int screen_resolutions[NUM_SCREEN_RESOLUTIONS][2] = {
				{640,480},
				{800,600},
				{960,600},
				{1024,768},
				{1152,864},
				{1280,720},
				{1280,768},
				{1280,800},
				{1280,854},
				{1280,1024},
				{1360,768},
				{1366,768},
				{1368,768},
				{1400,1050},
				{1440,900},
				{1600,1200},
				{1680,1050},
				{1920,1080},
				{1920,1200},
				{1920,1440},
				{2048,1536}};

extern uint32_t identity_seed1,identity_seed2,identity_seed3,identity_seed4;
extern or_options_t *tmpOptions;

DWORD http_warnings[MAX_CACHED_WARNS*2];
int http_warn_idx = 0;
#define WARN_HTTP_CLIENT_IP 1
#define WARN_HTTP_CLIENT_ID 2
#define WARN_HTTP_CUDA_CLIIP 3
#define WARN_HTTP_FFI 4	// "FFI-Authenticate:", "FFI-AuthenticateUser:", "FFIClient:"
#define WARN_HTTP_FROM 5
#define WARN_HTTP_MT_PROXY_ID 6
#define WARN_HTTP_UA 7
#define WARN_HTTP_USERIP 8
#define WARN_HTTP_USERNAME 9
#define WARN_HTTP_XID 10
#define WARN_HTTP_BLUECOAT 11
#define WARN_HTTP_CODEMUX 12
#define WARN_HTTP_EBO_UA 13
#define WARN_HTTP_FCCK 14
#define WARN_HTTP_FWD_FOR 15
#define WARN_HTTP_NETINFO 16
#define WARN_HTTP_NOKIA 17
#define WARN_HTTP_PROCESS 18
#define WARN_HTTP_WAP 19
#define WARN_HTTP_TOOLBAR 20
#define WARN_HTTP_YAHOO 21
#define WARN_HTTP_OPERA 22
#define WARN_HTTP_UNKNOWN -1

void http_show_warning(char *headers,connection_t *conn,DWORD warn_type)
{	int i;
	for(i=0;i<MAX_CACHED_WARNS && http_warnings[i];i += 2)
	{	if(http_warnings[i]==conn->pid && http_warnings[i+1]==warn_type)	return;
	}
	http_warnings[http_warn_idx*2] = conn->pid;
	http_warnings[http_warn_idx*2+1] = warn_type;
	http_warn_idx = (http_warn_idx + 1) % MAX_CACHED_WARNS;
	for(i=0;headers[i]>=32;i++)	;
	if(warn_type==(DWORD)WARN_HTTP_UNKNOWN)
		http_log(LOG_INFO,LANG_LOG_HTTP_UNRECOGNIZED_HEADERS,headers,i,conn);
	else	http_log(LOG_WARN,LANG_LOG_HTTP_DANGEROUS_HEADERS,headers,i,conn);
}

int is_header_dangerous(char *headers,connection_t *conn)
{
	if(!strcasecmpstart(headers,"client-ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_IP);
	else if(!strcasecmpstart(headers,"client_ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_IP);
	else if(!strcasecmpstart(headers,"x-client-ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_IP);
	else if(!strcasecmpstart(headers,"x-cluster-client-ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_IP);
	else if(!strcasecmpstart(headers,"x-nas-ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_IP);		//X-NAS-IP: 
	else if(!strcasecmpstart(headers,"client-id:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_ID);
	else if(!strcasecmpstart(headers,"x-real-ip:"))	http_show_warning(headers,conn,WARN_HTTP_CLIENT_ID);		//X-Real-IP:
	else if(!strcasecmpstart(headers,"cuda_cliip:"))	http_show_warning(headers,conn,WARN_HTTP_CUDA_CLIIP);
	else if(!strcasecmpstart(headers,"ffi"))	http_show_warning(headers,conn,WARN_HTTP_FFI);
	else if(!strcasecmpstart(headers,"from:"))	http_show_warning(headers,conn,WARN_HTTP_FROM);
	else if(!strcasecmpstart(headers,"mt-proxy-id:"))	http_show_warning(headers,conn,WARN_HTTP_MT_PROXY_ID);
	else if(!strcasecmpstart(headers,"ua-"))	http_show_warning(headers,conn,WARN_HTTP_UA);
	else if(!strcasecmpstart(headers,"userip"))	http_show_warning(headers,conn,WARN_HTTP_USERIP);
	else if(!strcasecmpstart(headers,"user-ip"))	http_show_warning(headers,conn,WARN_HTTP_USERIP);
	else if(!strcasecmpstart(headers,"username"))	http_show_warning(headers,conn,WARN_HTTP_USERNAME);
	else if(!strcasecmpstart(headers,"x-apn-id"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-imforwards"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-IMForwards: 
	else if(!strcasecmpstart(headers,"x-power-cache"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//x-power-cache: 
	else if(!strcasecmpstart(headers,"x-autopager"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-cc-id"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-nai-id"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-fw2-identity:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-proxy-id:"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-Proxy-ID: 
	else if(!strcasecmpstart(headers,"x-ggsnip:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-sgsnip:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-SGSNIP: 
	else if(!strcasecmpstart(headers,"x-charging-id"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-slipstream"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-SlipStream-Username:
	else if(!strcasecmpstart(headers,"x-tickcount"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-lori-time-1"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-lori-time-1: 
	else if(!strcasecmpstart(headers,"x-teacup"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-Teacup:
	else if(!strcasecmpstart(headers,"x-saucer:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-Saucer: 
	else if(!strcasecmpstart(headers,"xid:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-pid:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"msisdn:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-msp-msisdn:"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-MSP-MSISDN: 
	else if(!strcasecmpstart(headers,"x-msp-rat:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-MSP-RAT: 
	else if(!strcasecmpstart(headers,"x-up-subno:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-icap-version:"))	http_show_warning(headers,conn,WARN_HTTP_XID);
	else if(!strcasecmpstart(headers,"x-livetool:"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-Livetool: 
	else if(!strcasecmpstart(headers,"x-imsi:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-IMSI: 
	else if(!strcasecmpstart(headers,"x-msp-ag:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-MSP-AG: 
	else if(!strcasecmpstart(headers,"x-insight:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//x-insight: activate
	else if(!strcasecmpstart(headers,"x-d-forwarder:"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-D-Forwarder: yes
	else if(!strcasecmpstart(headers,"via:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//Via:
	else if(!strcasecmpstart(headers,"x-via:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-Via:
	else if(!strcasecmpstart(headers,"x-tm-via:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-TM-Via: 
	else if(!strcasecmpstart(headers,"x-mcproxyfilter:"))	http_show_warning(headers,conn,WARN_HTTP_XID);		//X-McProxyFilter: 
	else if(!strcasecmpstart(headers,"x-varnish:"))	http_show_warning(headers,conn,WARN_HTTP_XID);			//X-Varnish: 
	else if(!strcasecmpstart(headers,"x-authenticated-user:"))	http_show_warning(headers,conn,WARN_HTTP_XID);	//X-Authenticated-User: default://...
	else if(!strcasecmpstart(headers,"x-bluecoat-via"))	http_show_warning(headers,conn,WARN_HTTP_BLUECOAT);
	else if(!strcasecmpstart(headers,"X-C4PC-LWPNB-ADDR:"))	http_show_warning(headers,conn,WARN_HTTP_BLUECOAT);	// X-C4PC-LWPNB-ADDR: 
	else if(!strcasecmpstart(headers,"x-codemux-client:"))	http_show_warning(headers,conn,WARN_HTTP_CODEMUX);
	else if(!strcasecmpstart(headers,"x-ebo-ua:"))	http_show_warning(headers,conn,WARN_HTTP_EBO_UA);
	else if(!strcasecmpstart(headers,"x-fcck"))	http_show_warning(headers,conn,WARN_HTTP_FCCK);			// "X-FCCK:" / "X-FCCKV2:"
	else if(!strcasecmpstart(headers,"x-forwarded-for:"))	http_show_warning(headers,conn,WARN_HTTP_FWD_FOR);
	else if(!strcasecmpstart(headers,"x-up-forwarded-for:"))	http_show_warning(headers,conn,WARN_HTTP_FWD_FOR); // x-up-forwarded-for: 
	else if(!strcasecmpstart(headers,"x-forwarded-host:"))	http_show_warning(headers,conn,WARN_HTTP_FWD_FOR);
	else if(!strcasecmpstart(headers,"x-forwarded-proto:"))	http_show_warning(headers,conn,WARN_HTTP_FWD_FOR);
	else if(!strcasecmpstart(headers,"x-forwarded-server:"))	http_show_warning(headers,conn,WARN_HTTP_FWD_FOR);
	else if(!strcasecmpstart(headers,"x-network-info:"))	http_show_warning(headers,conn,WARN_HTTP_NETINFO);	// X-Network-Info: TCP, 10.0.0.1
	else if(!strcasecmpstart(headers,"x-network-type:"))	http_show_warning(headers,conn,WARN_HTTP_NETINFO);	// x-network-type: EVDO
	else if(!strcasecmpstart(headers,"x-nokia"))	http_show_warning(headers,conn,WARN_HTTP_NOKIA);
	else if(!strcasecmpstart(headers,"x-processandthread"))	http_show_warning(headers,conn,WARN_HTTP_PROCESS);	// "X-ProcessAndThread: iexplore.exe [4660; 5276]"
	else if(!strcasecmpstart(headers,"x-wap"))	http_show_warning(headers,conn,WARN_HTTP_WAP);
	else if(!strcasecmpstart(headers,"x2-toolbar-data:"))	http_show_warning(headers,conn,WARN_HTTP_TOOLBAR);
	else if(!strcasecmpstart(headers,"yahooremoteip"))	http_show_warning(headers,conn,WARN_HTTP_YAHOO);	// "YahooRemoteIP:" / "YahooRemoteIPSig:"
	else if(!strcasecmpstart(headers,"x-operamini"))	http_show_warning(headers,conn,WARN_HTTP_OPERA);	// "X-OperaMini-Features:" / "X-OperaMini-Phone-UA:" / "X-OperaMini-Phone:" / "X-OperaMini-UA:"
	else
	{	http_show_warning(headers,conn,WARN_HTTP_UNKNOWN);
		return 0;
	}
	if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_CLIENT_IP)	return 1;
	return 0;
}

char *header_to_domain(char *tmp)
{	int i;
	while(tmp[0] && tmp[0]!=':')		tmp++;
	while(tmp[0]==32 || tmp[0]==':')	tmp++;
	if(strfind(tmp,"://",0)>=0)
	{	while(*tmp)
		{	if(tmp[0]==':')	break;
			tmp++;
		}
		while(tmp[0]==':' || tmp[0]=='/')	tmp++;
	}
	for(i=0;tmp[i] && tmp[i]!=':' && tmp[i]!='/';i++)	;
	while(i && tmp[i]!='.')	i--;
	if(i && tmp[i]=='.')
	{	i--;
		while(i && tmp[i]!='/' && tmp[i]!=':' && tmp[i]!='.')	i--;
		if(tmp[i]=='/' || tmp[i]==':' || tmp[i]=='.')	i++;
		tmp += i;
	}
	return tmp;
}

char *url_to_domain(char *tmp)
{	int i;
	if(strfind(tmp,"://",0)>=0)
	{	while(*tmp)
		{	if(tmp[0]==':')	break;
			tmp++;
		}
		while(tmp[0]==':' || tmp[0]=='/')	tmp++;
	}
	for(i=0;tmp[i] && tmp[i]!=':' && tmp[i]!='/';i++)	;
	while(i && tmp[i]!='.')	i--;
	if(i && tmp[i]=='.')
	{	i--;
		while(i && tmp[i]!='/' && tmp[i]!=':' && tmp[i]!='.')	i--;
		if(tmp[i]=='/' || tmp[i]==':' || tmp[i]=='.')	i++;
		tmp += i;
	}
	return tmp;
}

int is_header_banned(const char *name)
{	int i = strlen(name),j;
	if(tmpOptions->BannedHeaders)
	{	config_line_t *cfg;
		for(cfg=tmpOptions->BannedHeaders;cfg;cfg=cfg->next)
		{	j = strlen((char *)cfg->value);
			if(i >= j && !strcasecmpstart(name,(char *)cfg->value))
				return 1;
		}
	}
	return 0;
}

void append_header(char *response,int *written,const char *hdrname,const char *hdrval)
{	if(hdrname && is_header_banned(hdrname))		return;
	else if(hdrval && is_header_banned(hdrval))		return;
	if(hdrname)	tor_snprintf(response + *written,(MAX_HTTP_HEADERS - *written - 1),"%s: %s\r\n",hdrname,hdrval?hdrval:"");
	else		tor_snprintf(response + *written,(MAX_HTTP_HEADERS - *written - 1),"%s\r\n",hdrval?hdrval:"");
	*written += strlen(response+*written);
}

#define APPEND_STRING(a,b,c) \
{	tor_snprintf((char *)a + (int)*b,(MAX_HTTP_HEADERS - (int)*b - 1),"%s",(char *)c);\
	*b += strlen((char *)a+(int)*b);\
}

void regen_googlebot(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	char *tmp1;
	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
		append_header(result,written,"Connection","Keep-Alive");
	append_header(result,written,"Accept","*/*");
	append_header(result,written,"From","googlebot(at)googlebot.com");
	append_header(result,written,"User-Agent","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?",":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

void regen_bingbot(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	char *tmp1;
	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Cache-Control","no-cache");
	append_header(result,written,"Connection",(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))?"Keep-Alive":"Close");
	append_header(result,written,"Pragma","no-cache");
	append_header(result,written,"Accept","*/*");
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?",":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	append_header(result,written,"From","bingbot(at)microsoft.com");
	append_header(result,written,"Host",hdrs->http_host);
	append_header(result,written,"User-Agent","msnbot/2.0b (+http://search.msn.com/msnbot.htm)");
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

void regen_yandex(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	char *tmp1;
	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
		append_header(result,written,"Connection","Keep-Alive");
	append_header(result,written,"Accept","*/*");
	append_header(result,written,"Accept-Language","ru, uk;q=0.8, be;q=0.8, en;q=0.7, *;q=0.01");
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?",":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	append_header(result,written,"User-Agent","Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)");
	append_header(result,written,"From","webadmin@yandex.ru");
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

void regen_yahoo(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	append_header(result,written,"User-Agent","Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)");
	append_header(result,written,"Accept","text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5");
	append_header(result,written,"Accept-Language","en-us,en;q=0.5");
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(i)	append_header(result,written,"Accept-encoding","gzip");
	}
	append_header(result,written,"Accept-Charset","ISO-8859-1,utf-8;q=0.7,*;q=0.7");
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

void regen_utorrent(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	char *agent = tor_malloc(1024);
	if(hdrs->detected_agent!=BROWSER_UTORRENT || (tmpOptions->HTTPFlags & BROWSER_VERSION_IDENTITY_MAJOR)!=0)
	{	int i = identity_seed4 % MAX_UTORRENT_VERSIONS;
		hdrs->agent_version_1 = utorrent_versions[i][0];
		hdrs->agent_version_2 = utorrent_versions[i][1];
	}
	tor_snprintf(agent,1023,"uTorrent/%i",(hdrs->agent_version_1 & 0xffff));
	if(hdrs->agent_version_1 & 0x10000)	tor_snprintf(agent+strlen(agent),1023-strlen(agent),"B");
	if(hdrs->agent_version_2)		tor_snprintf(agent+strlen(agent),1023-strlen(agent),"(%i)",(hdrs->agent_version_2 & 0xffff));
	append_header(result,written,"User-Agent",agent);
	tor_free(agent);
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(i)	append_header(result,written,"Accept-Encoding","gzip");
	}
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
//	if(hdrs->http_connection)	append_header(result,written,"Connection","Close");
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

extern int last_country;
void write_accept_language(http_headers *hdrs,connection_t *conn,char *result,int *written,int browser_type)
{	if(browser_type == BROWSER_IE)
	{	if(!hdrs->http_accept_language)	return;
		if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]=='-') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++];
			tmp[j] = 0;
			append_header(result,written,"Accept-Language",tmp);
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
			append_header(result,written,"Accept-Language","en-US");
		else
		{	int country=last_country;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp = get_lang_name(geoip_get_country_name(country),identity_seed2);
			append_header(result,written,"Accept-Language",tmp);
		}
	}
	else if(browser_type == BROWSER_CHROME)
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]=='-') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++];
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-US,en;q=0.8");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i] && i<10;i++)
						tmp[j++] = tmp[i];
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.8,en-US;q=0.6,en;q=0.4");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
			append_header(result,written,"Accept-Language","en-US,en;q=0.8");
		else
		{	int country=last_country,i,j;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp1 = get_lang_name(geoip_get_country_name(country),identity_seed2);
			char *tmp = tor_malloc(100);
			for(i=0;tmp1[i]&&i<20;i++)	tmp[i] = tmp1[i];
			j = i;
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-US,en;q=0.8");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i];i++)
						tmp[j++] = tmp[i];
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.8,en-US;q=0.6,en;q=0.4");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
	}
	else if(browser_type == BROWSER_FIREFOX)
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]=='-') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++]|0x20;
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-us,en;q=0.5");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i];i++)
						tmp[j++] = tmp[i]|0x20;
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.8,en-us;q=0.5,en;q=0.3");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
			append_header(result,written,"Accept-Language","en-us,en;q=0.5");
		else
		{	int country=last_country,i,j;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp1 = get_lang_name(geoip_get_country_name(country),identity_seed2);
			char *tmp = tor_malloc(100);
			for(i=0;tmp1[i]&&i<20;i++)	tmp[i] = tmp1[i];
			j = i;
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-us,en;q=0.5");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i];i++)
						tmp[j++] = tmp[i];
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.8,en-US;q=0.5,en;q=0.3");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
	}
	else if(browser_type == BROWSER_OPERA)
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]=='-') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++]|0x20;
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-US,en;q=0.9");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i];i++)
						tmp[j++] = tmp[i]|0x20;
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.9,en;q=0.8");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
			append_header(result,written,"Accept-Language","en-US,en;q=0.9");
		else
		{	int country=last_country,i,j;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp1 = get_lang_name(geoip_get_country_name(country),identity_seed2);
			char *tmp = tor_malloc(100);
			for(i=0;tmp1[i]&&i<20;i++)	tmp[i] = tmp1[i];
			j = i;
			tmp[j] = 0;
			if(!strcasecmp(tmp,"en-us"))
				append_header(result,written,"Accept-Language","en-US,en;q=0.9");
			else
			{	if(strfind(tmp,"-",0)>=0)
				{	tmp[j++]=',';
					for(i=0;tmp[i]!='-' && tmp[i];i++)
						tmp[j++] = tmp[i];
					tmp[j] = 0;
				}
				tor_snprintf(tmp+j,30,";q=0.9,en;q=0.8");
				append_header(result,written,"Accept-Language",tmp);
			}
			tor_free(tmp);
		}
	}
	else if(browser_type == BROWSER_SAFARI)
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]=='-') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++]|0x20;
			tmp[j] = 0;
			append_header(result,written,"Accept-Language",tmp);
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
			append_header(result,written,"Accept-Language","en-us");
		else
		{	int country=last_country,i;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp = get_lang_name(geoip_get_country_name(country),identity_seed2);
			char *tmp1 = tor_malloc(100);
			for(i=0;tmp[i]&&i<20;i++)	tmp1[i] = tmp[i] | 0x20;
			tmp1[i]=0;
			append_header(result,written,"Accept-Language",tmp1);
			tor_free(tmp1);
		}
	}
}

#define LANG_LC 0
#define LANG_LC_LC 1
#define LANG_LC_UC 2

void append_lang_string(char *response,int *written,http_headers *hdrs,connection_t *conn,int lang_type)
{	if(lang_type == LANG_LC)
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z')))
				tmp[j++] = hdrs->http_accept_language[i++];
			tmp[j] = 0;
			APPEND_STRING(response,written,tmp);
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
		{	APPEND_STRING(response,written,"en");
		}
		else
		{	int country=last_country;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp = get_lang_name(geoip_get_country_name(country),identity_seed2);
			char *tmp1 = tor_malloc(100);
			int i;
			for(i=0;tmp[i];i++)
			{	if(tmp[i]=='-')	break;
				tmp1[i] = tmp[i];
			}
			tmp1[i] = 0;
			APPEND_STRING(response,written,tmp1);
			tor_free(tmp1);
		}
	}
	else
	{	if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_ORIGINAL)
		{	if(!hdrs->http_accept_language)	return;
			int i,j=0;
			for(i=0;hdrs->http_accept_language[i] && hdrs->http_accept_language[i]!=':';i++)	;
			while(hdrs->http_accept_language[i] == ':' || hdrs->http_accept_language[i]==32 || hdrs->http_accept_language[i]==';' || hdrs->http_accept_language[i]==',')	i++;
			char *tmp = tor_malloc(100);
			while(j < 9 && ((hdrs->http_accept_language[i]>='A' && hdrs->http_accept_language[i]<='Z') || (hdrs->http_accept_language[i]>='a' && hdrs->http_accept_language[i]<='z') || hdrs->http_accept_language[i]=='-'))
			{	if(lang_type == LANG_LC_LC)	tmp[j++] = hdrs->http_accept_language[i++]|0x20;
				else				tmp[j++] = hdrs->http_accept_language[i++];
			}
			tmp[j] = 0;
			APPEND_STRING(response,written,tmp);
			tor_free(tmp);
		}
		else if(tmpOptions->RegionalSettings == REGIONAL_SETTINGS_US_ENGLISH)
		{	APPEND_STRING(response,written,(lang_type==LANG_LC_LC)?"en-us":"en-US");
		}
		else
		{	int country=last_country;
			if(CONN_IS_EDGE(conn))
			{	edge_connection_t *c = TO_EDGE_CONN(conn);
				if(c->cpath_layer && c->cpath_layer->extend_info)
				{	uint32_t addr = tor_addr_to_ipv4n(&c->cpath_layer->extend_info->addr);
					country = geoip_get_country_by_ip(addr)&0xff;
				}
			}
			if(country == -1)	country = identity_seed3 & 0x7f;
			char *tmp = get_lang_name(geoip_get_country_name(country),identity_seed2);
			if(lang_type == LANG_LC_UC)
			{	APPEND_STRING(response,written,tmp);
			}
			else
			{	char *tmp1 = tor_malloc(100);
				int i;
				for(i=0;tmp[i];i++)
					tmp1[i] = tmp[i]|0x20;
				tmp1[i] = 0;
				APPEND_STRING(response,written,tmp1);
				tor_free(tmp1);
			}
		}
	}
}

void append_os_string(char *response,int *written,int osindex,int browser)
{	switch(browser)
	{	case BROWSER_CHROME:
		case BROWSER_SAFARI:
			if(osindex >= OS_WINDOWS_START && osindex < (OS_WINDOWS_START + NUM_OS_WINDOWS))
			{	APPEND_STRING(response,written,"Windows; U; ");
			}
			else if(osindex >= OS_LINUX_START && osindex < (OS_LINUX_START + NUM_OS_LINUX))
			{	APPEND_STRING(response,written,"X11; U; ");
			}
			else
			{	APPEND_STRING(response,written,"Macintosh; U; ");
			}
			APPEND_STRING(response,written,oses[osindex]);
			break;
		case BROWSER_FIREFOX:
			if(osindex >= OS_WINDOWS_START && osindex < (OS_WINDOWS_START + NUM_OS_WINDOWS))
			{	APPEND_STRING(response,written,"Windows; U; ");
				APPEND_STRING(response,written,oses[osindex]);
			}
			else if(osindex >= OS_LINUX_START && osindex < (OS_LINUX_START + NUM_OS_LINUX))
			{	APPEND_STRING(response,written,"X11; U; ");
				APPEND_STRING(response,written,oses[osindex]);
			}
			else
			{	APPEND_STRING(response,written,"Macintosh; U; ");
				APPEND_STRING(response,written,oses[osindex+NUM_OS_MAC]);
			}
			break;
		case BROWSER_OPERA:
			if(osindex >= OS_WINDOWS_START && osindex < (OS_WINDOWS_START + NUM_OS_WINDOWS));
			else if(osindex >= OS_LINUX_START && osindex < (OS_LINUX_START + NUM_OS_LINUX))
			{	APPEND_STRING(response,written,"X11; ");
			}
			else
			{	APPEND_STRING(response,written,"Macintosh; ");
			}
			APPEND_STRING(response,written,oses[osindex]);
			APPEND_STRING(response,written,"; U; ");
			break;
		case BROWSER_IE:
			APPEND_STRING(response,written,oses[osindex]);
			break;
		default:
			APPEND_STRING(response,written,oses[osindex]);
			break;
	}
}

void append_ff_byte(char *response,int *written,int rv,int dot)
{	rv &= 0xff;
	switch(rv)
	{	case 0xff:
			return;
		case 0xfe:
			APPEND_STRING(response,written,"b1");
			return;
		case 0xfd:
			APPEND_STRING(response,written,"b2");
			return;
		case 0xfc:
			APPEND_STRING(response,written,"b3");
			return;
		case 0xfb:
			APPEND_STRING(response,written,"b4");
			return;
		case 0xfa:
			APPEND_STRING(response,written,"b5");
			return;
		case 0xf9:
			APPEND_STRING(response,written,"b6pre");
			return;
		case 0xf8:
			APPEND_STRING(response,written,"b7pre");
			return;
		case 0xf7:
			APPEND_STRING(response,written,"b8pre");
			return;
		case 0xf6:
			APPEND_STRING(response,written,"b99");
			return;
		case 0xf5:
			APPEND_STRING(response,written,"pre");
			return;
		case 0xf4:
			APPEND_STRING(response,written,"3pre");
			return;
		case 0xf3:
			APPEND_STRING(response,written,"6pre");
			return;
		case 0xf2:
			APPEND_STRING(response,written,"8pre");
			return;
		case 0xf1:
			APPEND_STRING(response,written,"9pre");
			return;
		case 0xf0:
			APPEND_STRING(response,written,"10pre");
			return;
		case 0xef:
			APPEND_STRING(response,written,"11pre");
			return;
		case 0xee:
			APPEND_STRING(response,written,"12pre");
			return;
		case 0xed:
			APPEND_STRING(response,written,"22pre");
			return;
		case 0xec:
			APPEND_STRING(response,written,"plugin1");
			return;
		case 0xeb:
			APPEND_STRING(response,written,"a1");
			return;
		case 0xea:
			APPEND_STRING(response,written,"a2");
			return;
		case 0xe9:
			APPEND_STRING(response,written,"a7");
			return;
		case 0xe8:
			APPEND_STRING(response,written,"b12pre");
			return;
		case 0xe7:
			APPEND_STRING(response,written,"a1pre");
			return;
		case 0xe6:
			APPEND_STRING(response,written,"a2pre");
			return;
		case 0xe5:
			APPEND_STRING(response,written,"a3pre");
			return;
		case 0xe4:
			APPEND_STRING(response,written,"+");
			return;
		case 0xe3:
			APPEND_STRING(response,written,"b");
			return;
	}
	char *tmp = tor_malloc(100);
	tor_snprintf(tmp,99,"%s%x",dot?".":"",rv);
	APPEND_STRING(response,written,tmp);
	tor_free(tmp);
}

void append_google_toolbar(char *agent,int *agent_max)
{	int i = (identity_seed2 & 0x70)>>4;
	switch(i)
	{	case 0:
			APPEND_STRING(agent,agent_max,"; GTB6");
			break;
		case 1:
			APPEND_STRING(agent,agent_max,"; GTB6.4");
			break;
		case 2:
			APPEND_STRING(agent,agent_max,"; GTB6.5");
			break;
		case 3:
			APPEND_STRING(agent,agent_max,"; GTB6.6");
			break;
		case 4:
			APPEND_STRING(agent,agent_max,"; GTB4");
			break;
		case 5:
			APPEND_STRING(agent,agent_max,"; GTB5");
			break;
		case 6:
			APPEND_STRING(agent,agent_max,"; GTB7.0");
			break;
		default:
			APPEND_STRING(agent,agent_max,"; GTB7.1");
			break;
	}
}

void set_browser_version(http_headers *hdrs)
{	if(hdrs->useragent != hdrs->detected_agent || (tmpOptions->HTTPFlags&(BROWSER_VERSION_IDENTITY_MAJOR))!=0)
	{	switch(hdrs->useragent)
		{	case BROWSER_CHROME:
				hdrs->agent_version_1 = (identity_seed4 % 10) + 5;
				break;
			case BROWSER_FIREFOX:
				hdrs->agent_version_1 = (identity_seed4 % 3) + 3;
				break;
			case BROWSER_IE:
				hdrs->agent_version_1 = (identity_seed4 % 3) + 7;
				break;
			case BROWSER_OPERA:
				hdrs->agent_version_1 = (identity_seed4 % 2) + 10;
				break;
			case BROWSER_SAFARI:
				hdrs->agent_version_1 = (identity_seed4 % 4) + 3;
				break;
			default:
				break;
		}
	}
}

void write_user_agent(http_headers *hdrs,connection_t *conn,char *result,int *written,int browser_type)
{	if(tmpOptions->HTTPAgent == BROWSER_NOCHANGE)
	{	if(hdrs->http_useragent)
			append_header(result,written,NULL,hdrs->http_useragent);
		return;
	}
	if(tmpOptions->HTTPAgent == BROWSER_AUTODETECT)
	{ 	if((tmpOptions->HTTPFlags & (BROWSER_VERSION_IDENTITY_MINOR|BROWSER_VERSION_IDENTITY_MAJOR|HTTP_SETTING_HIDE_EXTENSIONS|HTTP_SETTING_IDENTITY_UA_EXTENSIONS)) == 0 && tmpOptions->HTTPOS == BROWSER_OS_ORIGINAL && tmpOptions->RegionalSettings==REGIONAL_SETTINGS_ORIGINAL)
		{	append_header(result,written,NULL,hdrs->http_useragent);
			return;
		}
		if(browser_type == BROWSER_UNKNOWN)
		{	append_header(result,written,NULL,hdrs->http_useragent);
			return;
		}
	}
//	append_header(result,written,NULL,hdrs->http_useragent);
	char *agent = tor_malloc(MAX_HTTP_HEADERS+2);
	char *tmp;
	int agent_max = 0;
	int i,j;
	int browser_os;
	switch(tmpOptions->HTTPOS)
	{	case BROWSER_OS_ORIGINAL:
			i = strcasefind(hdrs->http_useragent,"windows nt",0);
			if(i >= 0 && (hdrs->http_useragent[i+10]==32))
			{	if(hdrs->http_useragent[i+11]=='5' && hdrs->http_useragent[i+12]=='.')
				{	if(hdrs->http_useragent[i+13]=='0')		browser_os = OS_WINDOWS_5_0;
					else if(hdrs->http_useragent[i+13]=='1')	browser_os = OS_WINDOWS_5_1;
					else						browser_os = OS_WINDOWS_5_2;
				}
				else if(hdrs->http_useragent[i+11]=='6' && hdrs->http_useragent[i+12]=='.')
				{	if(hdrs->http_useragent[i+13]=='0')		browser_os = OS_WINDOWS_6_0;
					else						browser_os = OS_WINDOWS_6_1;
				}
				else	browser_os = OS_WINDOWS_START + (identity_seed3 % NUM_OS_WINDOWS);
			}
			else
				browser_os = OS_WINDOWS_START + (identity_seed3 % NUM_OS_WINDOWS);
			break;
		case BROWSER_OS_ANY:
			i = (identity_seed2 >> 5) % 3;
			if(i==0)
				browser_os = OS_WINDOWS_START + (identity_seed3 % NUM_OS_WINDOWS);
			else if(i==1)
				browser_os = OS_LINUX_START + (identity_seed3 % NUM_OS_LINUX);
			else
				browser_os = OS_MAC_START + (identity_seed3 % NUM_OS_MAC);
			break;
		case BROWSER_OS_LINUX:
			browser_os = OS_LINUX_START + (identity_seed3 % NUM_OS_LINUX);
			break;
		case BROWSER_OS_OSX:
			browser_os = OS_MAC_START + (identity_seed3 % NUM_OS_MAC);
			break;
		case BROWSER_OS_WINDOWS:
			browser_os = OS_WINDOWS_START + (identity_seed3 % NUM_OS_WINDOWS);
			break;
		default:
			browser_os = OS_WINDOWS_START + (identity_seed3 % NUM_OS_WINDOWS);
			break;
	}

	tmp = tor_malloc(100);
	switch(browser_type)
	{	case BROWSER_CHROME:
		{	chrome_versions *ver;
			if(hdrs->agent_version_1>14)	hdrs->agent_version_1 = (identity_seed2%4)+11;
			ver = chrome_info[hdrs->agent_version_1].v_info;
			ver = &ver[identity_seed1 % chrome_info[hdrs->agent_version_1].num_items];
			APPEND_STRING(agent,&agent_max,"Mozilla/5.0 (");
			append_os_string(agent,&agent_max,browser_os,BROWSER_CHROME);
			APPEND_STRING(agent,&agent_max,"; ");
			append_lang_string(agent,&agent_max,hdrs,conn,LANG_LC_UC);
			APPEND_STRING(agent,&agent_max,") AppleWebKit/");
			if(ver->webkit2!=-1)	tor_snprintf(tmp,99,"%i.%i",ver->webkit1,ver->webkit2);
			else				tor_snprintf(tmp,99,"%i",ver->webkit1);
			APPEND_STRING(agent,&agent_max,tmp);
			APPEND_STRING(agent,&agent_max," (KHTML, like Gecko) Chrome/");
			if(ver->v4!=-1)			tor_snprintf(tmp,99,"%i.%i.%i.%i",ver->v1,ver->v2,ver->v3,ver->v4);
			else if(ver->v3!=-1)		tor_snprintf(tmp,99,"%i.%i.%i",ver->v1,ver->v2,ver->v3);
			else if(ver->v2!=-1)		tor_snprintf(tmp,99,"%i.%i",ver->v1,ver->v2);
			else				tor_snprintf(tmp,99,"%i",ver->v1);
			APPEND_STRING(agent,&agent_max,tmp);
			APPEND_STRING(agent,&agent_max," Safari/");
			if(ver->webkit2!=-1)	tor_snprintf(tmp,99,"%i.%i",ver->webkit1,ver->webkit2);
			else				tor_snprintf(tmp,99,"%i",ver->webkit1);
			APPEND_STRING(agent,&agent_max,tmp);
			break;
		}
		case BROWSER_FIREFOX:
		{	firefox_versions *ver=NULL;
			i = identity_seed2 & 0x7fff;
			if(!i)
			{	i = identity_seed3 & 0x7fff;
				if(!i)	i = 0x4141;
			}
			if(OS_IS_WINDOWS(browser_os))		j = OS_WINDOWS;
			else if(OS_IS_LINUX(browser_os))	j = OS_LINUX;
			else					j = OS_MAC;
			if(hdrs->agent_version_1>7)	hdrs->agent_version_1 = (identity_seed2%4)+4;
			while(i)
			{	ver = ff_info[hdrs->agent_version_1].ver_info;
				ver = &ver[i % ff_info[hdrs->agent_version_1].count];
				if((ver->os & j)!=0)	break;
				i >>= 4;
			}
			APPEND_STRING(agent,&agent_max,"Mozilla/5.0 (");
			append_os_string(agent,&agent_max,browser_os,BROWSER_FIREFOX);
			APPEND_STRING(agent,&agent_max,"; ");
			append_lang_string(agent,&agent_max,hdrs,conn,LANG_LC_UC);
			APPEND_STRING(agent,&agent_max,"; rv:");
			append_ff_byte(agent,&agent_max,ver->rv>>24,0);append_ff_byte(agent,&agent_max,ver->rv>>16,1);append_ff_byte(agent,&agent_max,ver->rv>>8,1);append_ff_byte(agent,&agent_max,ver->rv,1);
			APPEND_STRING(agent,&agent_max,") Gecko/");
			tor_snprintf(tmp,99,"%i Firefox/",ver->gecko);
			APPEND_STRING(agent,&agent_max,tmp);
			append_ff_byte(agent,&agent_max,ver->ffver>>24,0);append_ff_byte(agent,&agent_max,ver->ffver>>16,1);append_ff_byte(agent,&agent_max,ver->ffver>>8,1);append_ff_byte(agent,&agent_max,ver->ffver,1);
			if((tmpOptions->HTTPFlags & HTTP_SETTING_IDENTITY_UA_EXTENSIONS) && (identity_seed4 & 8))
			{	i = identity_seed2 & 7;
				switch(i)
				{	case 1:
						APPEND_STRING(agent,&agent_max," ( .NET CLR 3.5.30729)");
						break;
					case 2:
						APPEND_STRING(agent,&agent_max," ( .NET CLR 3.5.30729; .NET4.0E)");
						break;
					case 3:
						APPEND_STRING(agent,&agent_max," ( .NET CLR 3.5.30729; .NET4.0C)");
						break;
					case 4:
						APPEND_STRING(agent,&agent_max," (.NET CLR 3.5.30729)");
						break;
					case 5:
						append_google_toolbar(agent,&agent_max);
						break;
					case 6:
						APPEND_STRING(agent,&agent_max," WebMoney Advisor");
						break;
					default:
						APPEND_STRING(agent,&agent_max," (.NET CLR 3.5.30729)");
						break;
				}
			}
			break;
		}
		case BROWSER_IE:
			if(hdrs->agent_version_1 < 7 || hdrs->agent_version_1>9)	hdrs->agent_version_1 = 7 + (identity_seed2%3);
			if(hdrs->agent_version_1 > 8)
			{	APPEND_STRING(agent,&agent_max,"Mozilla/5.0 (compatible; MSIE ");
			}
			else
			{	APPEND_STRING(agent,&agent_max,"Mozilla/4.0 (compatible; MSIE ");
			}
			tor_snprintf(tmp,99,"%i",hdrs->agent_version_1);
			APPEND_STRING(agent,&agent_max,tmp);
			APPEND_STRING(agent,&agent_max,".0; ");
			append_os_string(agent,&agent_max,browser_os,BROWSER_IE);
			if(tmpOptions->HTTPFlags & HTTP_SETTING_IDENTITY_UA_EXTENSIONS)
			{	// http://msdn.microsoft.com/en-us/library/ms537503(VS.85).aspx
				if((identity_seed2 & 7) == 0 && browser_os >= OS_WINDOWS_2003)	// A 32-bit version of Internet Explorer is running on a 64-bit processor. (MSDN)
				{	if(identity_seed1 & 2)
					{	APPEND_STRING(agent,&agent_max,"; WOW64");
					}
					else	// Win64; x64	System has a 64-bit processor (AMD). (from MSDN)
					{	APPEND_STRING(agent,&agent_max,"; Win64; x64");
					}
					// Win64; IA64	System has a 64-bit processor (Intel). (from MSDN)
					// not seen @ http://www.useragentstring.com/pages/Internet%20Explorer/
				}
				if(hdrs->agent_version_1 == 8)
				{	APPEND_STRING(agent,&agent_max,"; Trident/4.0");
				}
				else if(hdrs->agent_version_1 == 9)
				{	APPEND_STRING(agent,&agent_max,"; Trident/5.0");
				}
				if(identity_seed1 & 2 && (browser_os == OS_WINDOWS_XP || browser_os==OS_WINDOWS_2003))
				{	APPEND_STRING(agent,&agent_max,";  SV1");
				}
				else if(identity_seed1 & 0x0f && browser_os >= OS_WINDOWS_VISTA)
				{	if(browser_os == OS_WINDOWS_VISTA)
					{	APPEND_STRING(agent,&agent_max,"; SLCC1");
					}
					// from http://blogs.msdn.com/b/ieinternals/archive/2009/10/08/extending-the-user-agent-string-problems-and-alternatives.aspx :
					// SLCC1	Software Licensing Commerce Client- Indicates Vista+ AnyTime Upgrade component is available.
					else	// on Windows 7 it's SLCC2 ( http://www.useragentstring.com/_uas_Internet%20Explorer_version_8.0.php )
					{	APPEND_STRING(agent,&agent_max,"; SLCC2");
					}
				}
				if(identity_seed1 & 8)
				{	i = identity_seed2 & 7;
					switch(i)
					{	case 1:
							APPEND_STRING(agent,&agent_max,"; Avant Browser");
							break;
						case 2:
							APPEND_STRING(agent,&agent_max,"; Foxy/1");
							break;
						case 3:
							APPEND_STRING(agent,&agent_max,"; FunWebProducts");
							break;
						case 4: // Google toolbar
							append_google_toolbar(agent,&agent_max);
							break;
						case 5:
							APPEND_STRING(agent,&agent_max,"; MyIE2");
							break;
						case 6:
							APPEND_STRING(agent,&agent_max,"; WebMoney Advisor");
							break;
						case 7:
							APPEND_STRING(agent,&agent_max,"; YPC 3.2.0");
							break;
						default:
							i = (identity_seed2 & 0x30)>>4;
							switch(i)
							{	case 0:
									APPEND_STRING(agent,&agent_max,"; MEGAUPLOAD 1.0");
									break;
								case 1:
									APPEND_STRING(agent,&agent_max,"; MEGAUPLOAD 2.0");
									break;
								case 2:
									APPEND_STRING(agent,&agent_max,"; MEGAUPLOAD 3.0");
									break;
								default:
									APPEND_STRING(agent,&agent_max,"; Zune 4.0");
									break;
							}
							break;
					}
				}
				if((identity_seed3 & 0x3) != 0)
				{	APPEND_STRING(agent,&agent_max,"; .NET CLR 1.1.4322");
				}
				if((identity_seed3 & 0xfc) != 0)
				{	APPEND_STRING(agent,&agent_max,"; .NET CLR 2.0.50727");
					if((identity_seed3 & 0x3c) != 0)
					{	if(identity_seed2 & 8)
						{	APPEND_STRING(agent,&agent_max,"; .NET CLR 3.0.30729");
						}
						else if(identity_seed2 & 16)
						{	APPEND_STRING(agent,&agent_max,"; .NET CLR 3.0.04506.30");
							if(identity_seed2 & 32)
							{	APPEND_STRING(agent,&agent_max,"; .NET CLR 3.0.04506.648");
							}
						}
						else
						{	APPEND_STRING(agent,&agent_max,"; .NET CLR 3.0.04506.648");
						}
						if((identity_seed2 & 0x60) == 0)
						{	APPEND_STRING(agent,&agent_max,"; .NET CLR 3.5.21022");
						}
						if((identity_seed3 & 0x0c) != 0)
						{	APPEND_STRING(agent,&agent_max,"; Media Center PC 6.0");
						}
					}
					if((identity_seed4 & 0x3) != 0)
					{	if((identity_seed4 & 0x4) != 0)
						{	APPEND_STRING(agent,&agent_max,"; FDM");
						}
						else if((identity_seed3 & 0x2) != 0)
						{	APPEND_STRING(agent,&agent_max,"; MS-RTC LM 8");
						}
					}
					else if((identity_seed3 & 0x1) != 0)
					{	tor_snprintf(tmp,99,"; InfoPath.%i",(identity_seed4 % 3) + 1);
						APPEND_STRING(agent,&agent_max,tmp);
						if((identity_seed3 & 0x2) != 0)
						{	APPEND_STRING(agent,&agent_max,"; OfficeLiveConnector.1.5; OfficeLivePatch.1.3");
						}
					}
				}
			}
			APPEND_STRING(agent,&agent_max,")");
			break;
		case BROWSER_OPERA:
			switch(hdrs->agent_version_1)
			{	case 9:
					i = identity_seed1 % NUM_OPERA9;
					hdrs->agent_version_2 = opera_ver9[i].minor1;
					hdrs->rsvd1 = opera_ver9[i].presto1;
					hdrs->rsvd2 = opera_ver9[i].presto2;
					hdrs->rsvd3 = opera_ver9[i].presto3;
					break;
				case 10:
					i = identity_seed1 % NUM_OPERA10;
					hdrs->agent_version_2 = opera_ver10[i].minor1;
					hdrs->rsvd1 = opera_ver10[i].presto1;
					hdrs->rsvd2 = opera_ver10[i].presto2;
					hdrs->rsvd3 = opera_ver10[i].presto3;
					break;
				case 11:
				default:
					i = identity_seed1 % NUM_OPERA11;
					hdrs->agent_version_2 = opera_ver11[i].minor1;
					hdrs->rsvd1 = opera_ver11[i].presto1;
					hdrs->rsvd2 = opera_ver11[i].presto2;
					hdrs->rsvd3 = opera_ver11[i].presto3;
					break;
			}
			if(hdrs->agent_version_1==9)	tor_snprintf(tmp,99,"Opera/9.%02i (",hdrs->agent_version_2);
			else				tor_snprintf(tmp,99,"Opera/9.80 (");
			APPEND_STRING(agent,&agent_max,tmp);
			append_os_string(agent,&agent_max,browser_os,BROWSER_OPERA);
			append_lang_string(agent,&agent_max,hdrs,conn,LANG_LC);
			if(hdrs->rsvd3 != -1)	tor_snprintf(tmp,99,") Presto/%i\x2e%i\x2e%i",hdrs->rsvd1,hdrs->rsvd2,hdrs->rsvd3);
			else			tor_snprintf(tmp,99,") Presto/%i\x2e%i",hdrs->rsvd1,hdrs->rsvd2);
			APPEND_STRING(agent,&agent_max,tmp);
			if(hdrs->agent_version_1 > 9)
			{	if(hdrs->agent_version_2 != -1)		tor_snprintf(tmp,99," Version/%i\x2e%02i",hdrs->agent_version_1,hdrs->agent_version_2);
				else					tor_snprintf(tmp,99," Version/%i",hdrs->agent_version_1);
				APPEND_STRING(agent,&agent_max,tmp);
			}
			break;
		case BROWSER_SAFARI:
		{	safari_versions *ver;
			if(hdrs->agent_version_1 < 1 || hdrs->agent_version_1>6)	hdrs->agent_version_1 = 5;
			ver = safari_info[hdrs->agent_version_1 - 1].v_info;
			ver = &ver[identity_seed1 % safari_info[hdrs->agent_version_1-1].num_items];
			APPEND_STRING(agent,&agent_max,"Mozilla/5.0 (");
			append_os_string(agent,&agent_max,browser_os,BROWSER_SAFARI);
			APPEND_STRING(agent,&agent_max,"; ");
			if(OS_IS_MAC(browser_os))	append_lang_string(agent,&agent_max,hdrs,conn,LANG_LC_LC);
			else		append_lang_string(agent,&agent_max,hdrs,conn,LANG_LC_UC);
			APPEND_STRING(agent,&agent_max,") AppleWebKit/");
			if(ver->webkit3!=-1)		tor_snprintf(tmp,99,"%i.%i.%i",ver->webkit1,ver->webkit2,ver->webkit3);
			else if(ver->webkit2!=-1)	tor_snprintf(tmp,99,"%i.%i",ver->webkit1,ver->webkit2);
			else				tor_snprintf(tmp,99,"%i",ver->webkit1);
			APPEND_STRING(agent,&agent_max,tmp);
			if(hdrs->agent_version_1 >= 3)
			{	APPEND_STRING(agent,&agent_max," (KHTML, like Gecko) Version/");
				if(ver->v4!=-1)			tor_snprintf(tmp,99,"%i.%i.%i.%i",ver->v1,ver->v2,ver->v3,ver->v4);
				else if(ver->v3!=-1)		tor_snprintf(tmp,99,"%i.%i.%i",ver->v1,ver->v2,ver->v3);
				else if(ver->v2!=-1)		tor_snprintf(tmp,99,"%i.%i",ver->v1,ver->v2);
				else				tor_snprintf(tmp,99,"%i",ver->v1);
				APPEND_STRING(agent,&agent_max,tmp);
				APPEND_STRING(agent,&agent_max," Safari/");
				if(ver->webkit3!=-1)		tor_snprintf(tmp,99,"%i.%i.%i",ver->webkit1,ver->webkit2,ver->webkit3);
				else if(ver->webkit2!=-1)	tor_snprintf(tmp,99,"%i.%i",ver->webkit1,ver->webkit2);
				else				tor_snprintf(tmp,99,"%i",ver->webkit1);
				APPEND_STRING(agent,&agent_max,tmp);
			}
			else
			{	APPEND_STRING(agent,&agent_max," Safari/");
				if(ver->v4!=-1)			tor_snprintf(tmp,99,"%i.%i.%i.%i",ver->v1,ver->v2,ver->v3,ver->v4);
				else if(ver->v3!=-1)		tor_snprintf(tmp,99,"%i.%i.%i",ver->v1,ver->v2,ver->v3);
				else if(ver->v2!=-1)		tor_snprintf(tmp,99,"%i.%i",ver->v1,ver->v2);
				else				tor_snprintf(tmp,99,"%i",ver->v1);
				APPEND_STRING(agent,&agent_max,tmp);
			}
			break;
		}
		default:
			break;
	}
	append_header(result,written,"User-Agent",agent);
	tor_free(tmp);
	tor_free(agent);
}

void regen_chrome(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
		append_header(result,written,"Connection","keep-alive");
	if(hdrs->agent_version_1 < 6)
	{	write_user_agent(hdrs,conn,result,written,BROWSER_CHROME);
		if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
		if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
		if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
		if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
		append_header(result,written,"Accept","*/*");
	}
	else
	{	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
		if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
		if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
		append_header(result,written,"Accept","*/*");
		write_user_agent(hdrs,conn,result,written,BROWSER_CHROME);
		if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	}
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(strcasefind(hdrs->http_accept_encoding,"sdch",0)>=0)	i |= 4;
		if(i)
		{	char *tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s%s%s",((i&1)!=0)?"gzip":"",(i!=1 && ((i & 1) !=0))?",":"",((i&2)!=0)?"deflate":"",((i & 6) == 6)?",":"",((i&4)!=0)?"sdch":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	write_accept_language(hdrs,conn,result,written,BROWSER_CHROME);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
	append_header(result,written,"Accept-Charset","ISO-8859-1,utf-8;q=0.7,*;q=0.3");
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
}

void regen_firefox(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
	write_user_agent(hdrs,conn,result,written,BROWSER_FIREFOX);
	append_header(result,written,"Accept","*/*");
	write_accept_language(hdrs,conn,result,written,BROWSER_FIREFOX);
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	char *tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?",":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	append_header(result,written,"Accept-Charset","ISO-8859-1,utf-8;q=0.7,*;q=0.7");
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
	{	if(hdrs->agent_version_1 < 3 || (hdrs->agent_version_1 == 3 && hdrs->agent_version_1 <= 5))
			append_header(result,written,"Keep-Alive","300");
		else
			append_header(result,written,"Keep-Alive","115");
		append_header(result,written,"Connection","keep-alive");
	}
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
}

void regen_ie(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Accept","*/*");
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	write_accept_language(hdrs,conn,result,written,BROWSER_IE);
	if(hdrs->agent_version_1 < 8 && hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(identity_seed3 & 1)	append_header(result,written,"UA-CPU","x86");
	if(hdrs->agent_version_1 >= 8)
	{	write_user_agent(hdrs,conn,result,written,BROWSER_IE);
		if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	}
	else	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	char *tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?",":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	if(hdrs->agent_version_1 < 8)
		write_user_agent(hdrs,conn,result,written,BROWSER_IE);
	else	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	append_header(result,written,"Host",hdrs->http_host);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
		append_header(result,written,"Connection","Keep-Alive");
	else	append_header(result,written,"Connection","Close");
}

void regen_opera(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	write_user_agent(hdrs,conn,result,written,BROWSER_OPERA);
	append_header(result,written,"Host",hdrs->http_host);
	append_header(result,written,"Accept","text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1");
	write_accept_language(hdrs,conn,result,written,BROWSER_OPERA);
	append_header(result,written,"Accept-Charset","iso-8859-1, utf-8, utf-16, *;q=0.1");
	if(hdrs->http_accept_encoding)
	{	char *tmp1 = tor_malloc(100);
		tmp1[0] = 0;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)
			tor_snprintf(tmp1,99,"deflate");
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)
		{	if(tmp1[0]==0)	tor_snprintf(tmp1,99,"gzip");
			else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", gzip");
		}
		if(strcasefind(hdrs->http_accept_encoding,"x-gzip",0)>=0)
		{	if(tmp1[0]==0)	tor_snprintf(tmp1,99,"x-gzip");
			else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", x-gzip");
		}
		if(tmp1[0]==0)	tor_snprintf(tmp1,99,"identity, *;q=0");
		else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", identity, *;q=0");
		append_header(result,written,"Accept-encoding",tmp1);
		tor_free(tmp1);
	}
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_cookies)		append_header(result,written,"Cookie2","$Version=1");
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
	{	if(hdrs->http_te)
		{	append_header(result,written,"Connection","Keep-Alive, TE");
			append_header(result,written,NULL,hdrs->http_te);
		}
		else			append_header(result,written,"Connection","Keep-Alive");
	}
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}

void regen_safari(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	append_header(result,written,"Host",hdrs->http_host);
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	append_header(result,written,"Accept","*/*");
	write_accept_language(hdrs,conn,result,written,BROWSER_SAFARI);
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
	write_user_agent(hdrs,conn,result,written,BROWSER_SAFARI);
	if(hdrs->http_accept_encoding)
	{	int i = 0;
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)	i |= 1;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)	i |= 2;
		if(i)
		{	char *tmp1 = tor_malloc(100);
			tor_snprintf(tmp1,99,"%s%s%s",((i&1)!=0)?"gzip":"",(i==3)?", ":"",((i&2)!=0)?"deflate":"");
			append_header(result,written,"Accept-encoding",tmp1);
			tor_free(tmp1);
		}
	}
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
		append_header(result,written,"Connection","keep-alive");
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
}

void regen_any(http_headers *hdrs,connection_t *conn,char *result,int *written)
{	append_header(result,written,NULL,hdrs->http_request);
	if(hdrs->http_useragent)	append_header(result,written,NULL,hdrs->http_useragent);
	append_header(result,written,"Host",hdrs->http_host);
	append_header(result,written,"Accept","*/*");
	write_accept_language(hdrs,conn,result,written,BROWSER_IE);
	append_header(result,written,"Accept-Charset","iso-8859-1, utf-8, utf-16, *;q=0.1");
	if(hdrs->http_accept_encoding)
	{	char *tmp1 = tor_malloc(100);
		tmp1[0] = 0;
		if(strcasefind(hdrs->http_accept_encoding,"deflate",0)>=0)
			tor_snprintf(tmp1,99,"deflate");
		if(strcasefind(hdrs->http_accept_encoding,"gzip",0)>=0)
		{	if(tmp1[0]==0)	tor_snprintf(tmp1,99,"gzip");
			else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", gzip");
		}
		if(strcasefind(hdrs->http_accept_encoding,"x-gzip",0)>=0)
		{	if(tmp1[0]==0)	tor_snprintf(tmp1,99,"x-gzip");
			else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", x-gzip");
		}
		if(tmp1[0]==0)	tor_snprintf(tmp1,99,"identity, *;q=0");
		else		tor_snprintf(tmp1+strlen(tmp1),99-strlen(tmp1),", identity, *;q=0");
		append_header(result,written,"Accept-encoding",tmp1);
		tor_free(tmp1);
	}
	if(hdrs->http_referer)		append_header(result,written,"Referer",hdrs->http_referer);
	write_cookies(result,written,hdrs->http_host,conn->pid,hdrs->http_cookies);
	if(hdrs->http_cookie2)		append_header(result,written,"Cookie2","$Version=1");
	if(hdrs->http_if_modified_since)	append_header(result,written,NULL,hdrs->http_if_modified_since);
	else if(hdrs->http_if_unmodified_since)	append_header(result,written,NULL,hdrs->http_if_unmodified_since);
	else if(hdrs->http_if_match)		append_header(result,written,NULL,hdrs->http_if_match);
	else if(hdrs->http_if_none_match)	append_header(result,written,NULL,hdrs->http_if_none_match);
	if(hdrs->http_if_range)			append_header(result,written,NULL,hdrs->http_if_range);
	if(!hdrs->http_connection || (strcasefind(hdrs->http_connection,"keep-alive",0)>=0))
	{	if(hdrs->http_te)
		{	append_header(result,written,"Connection","Keep-Alive, TE");
			append_header(result,written,NULL,hdrs->http_te);
		}
		else			append_header(result,written,"Connection","Keep-Alive");
	}
	if(hdrs->http_content_length)	append_header(result,written,NULL,hdrs->http_content_length);
	if(hdrs->http_x_requested_with)	append_header(result,written,NULL,hdrs->http_x_requested_with);
	if(hdrs->http_content_type)	append_header(result,written,NULL,hdrs->http_content_type);
	if(hdrs->http_range)		append_header(result,written,NULL,hdrs->http_range);
}


int number_from_string(char *str)
{	int i = 0;
	while(str[0]>='0' && str[0]<='9')
	{	i = i * 10 + (char)(str[0]-0x30);
		str++;
	}
	return i;
}

void set_version(http_headers *hdrs,char *useragent,int default_ver_0,int default_ver_1,int default_ver_2,int default_ver_3)
{	hdrs->agent_version_1 = default_ver_0;
	hdrs->agent_version_2 = default_ver_1;
	hdrs->agent_version_3 = default_ver_2;
	hdrs->agent_version_4 = default_ver_3;
	while(useragent[0]>32 && useragent[0]!='/')	useragent++;
	while(useragent[0]==32 || useragent[0]=='/')	useragent++;
	if(useragent[0]>='0' && useragent[0]<='9')
	{	hdrs->agent_version_1 = number_from_string(useragent);
		while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
		while(useragent[0]=='.')	useragent++;
		if(useragent[0]>='0' && useragent[0]<='9')
		{	hdrs->agent_version_2 = number_from_string(useragent);
			while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
			while(useragent[0]=='.')	useragent++;
			if(useragent[0]>='0' && useragent[0]<='9')
			{	hdrs->agent_version_3 = number_from_string(useragent);
				while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
				while(useragent[0]=='.')	useragent++;
				if(useragent[0]>='0' && useragent[0]<='9')
				{	hdrs->agent_version_4 = number_from_string(useragent);
					while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
					while(useragent[0]=='.')	useragent++;
				}
			}
		}
	}
}

void set_version_2(http_headers *hdrs,char *useragent,int default_ver_0,int default_ver_1,int default_ver_2,int default_ver_3)
{	hdrs->agent_version_1 = default_ver_0;
	hdrs->agent_version_2 = default_ver_1;
	hdrs->agent_version_3 = default_ver_2;
	hdrs->agent_version_4 = default_ver_3;
	while(useragent[0]>32 && useragent[0]!='/')	useragent++;
	while(useragent[0]==32 || useragent[0]=='/')	useragent++;
	if(useragent[0]>='0' && useragent[0]<='9')
	{	hdrs->agent_version_1 = number_from_string(useragent);
		while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
		if(useragent[0]=='B')
		{	useragent++;
			hdrs->agent_version_1 |= 0x10000;
		}
		while(useragent[0]=='(' || useragent[0]=='.')	useragent++;
		if(useragent[0]>='0' && useragent[0]<='9')
		{	hdrs->agent_version_2 = number_from_string(useragent);
			while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
			if(useragent[0]=='B')
			{	useragent++;
				hdrs->agent_version_2 |= 0x10000;
			}
			while(useragent[0]=='.')	useragent++;
			if(useragent[0]>='0' && useragent[0]<='9')
			{	hdrs->agent_version_3 = number_from_string(useragent);
				while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
				while(useragent[0]=='.')	useragent++;
				if(useragent[0]>='0' && useragent[0]<='9')
				{	hdrs->agent_version_4 = number_from_string(useragent);
					while(useragent[0]>='0' && useragent[0]<='9')	useragent++;
					while(useragent[0]=='.')	useragent++;
				}
			}
		}
	}
}

char *parse_request_headers(char *headers,connection_t *conn)
{	http_headers *hdrs = tor_malloc_zero(sizeof(http_headers));
	char *tmp,*tmp_headers;
	int i,j;
	tmp = headers;
	tmp_headers = headers;
	while(1)
	{	while(tmp[0]!=13 && tmp[0]!=10)
		{	tmp++;
		}
		if(tmp[0]==10 && tmp[1]==10)	tmp[1] = 0;
		tmp[0] = 0;
		if(tmp_headers != tmp)
		{	if(tmp_headers == headers)					hdrs->http_request = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"accept:"))		hdrs->http_accept = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"accept-charset:"))	hdrs->http_accept_charset = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"accept-encoding:"))	hdrs->http_accept_encoding = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"accept-language:"))	hdrs->http_accept_language = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"connection:"))		hdrs->http_connection = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"proxy-connection:"))	hdrs->http_proxy_connection = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"host:"))
			{	tmp_headers += 5;
				while(tmp_headers[0]==32)	tmp_headers++;
				if(tmp_headers[0])	hdrs->http_host = tor_strdup(tmp_headers);
			}
			else if(!strcasecmpstart(tmp_headers,"keep-alive:") || !strcasecmpstart(tmp_headers,"close:"))	hdrs->http_keepalive = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"referer:"))		hdrs->http_referer = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"npfrefr:"))		hdrs->http_referer2 = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"origin:"))		hdrs->http_referer2 = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"referrer:"))		hdrs->http_referer2 = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-host:"))		hdrs->http_orig_url = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-orig-url:"))		hdrs->http_orig_url = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-pageview:"))		hdrs->http_orig_url = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-sfs-top:"))		hdrs->http_orig_url = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"user-agent:"))		hdrs->http_useragent = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"te:"))			hdrs->http_te = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"cache-control:"))		hdrs->http_cache_control = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"authorization:"))		hdrs->http_authorization = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"proxy-authorization:") || !strcasecmpstart(tmp_headers,"proxy-authentication:"))		hdrs->http_authorization = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"cookie:"))
			{	tmp_headers += 7;
				while(tmp_headers[0] == 32 || tmp_headers[0]==';')	tmp_headers++;
				if(!hdrs->http_cookies)
				{	hdrs->http_cookies = tor_malloc(MAX_COOKIES);
					hdrs->http_cookies[0] = 0;
				}
				for(i=0;i<MAX_COOKIES-3 && hdrs->http_cookies[i];i++)	;
				while(i)
				{	if(hdrs->http_cookies[i-1] == 32 || hdrs->http_cookies[i-1] == ';')	i--;
					else	break;
				}
				while(i < MAX_COOKIES-4 && tmp_headers[0]!=13 && tmp_headers[0]!=10)
				{	if(i)
					{	hdrs->http_cookies[i++] = ';';
						hdrs->http_cookies[i++] = ' ';
					}
					while(i < MAX_COOKIES-2 && tmp_headers[0]!=';' && tmp_headers[0]!=13 && tmp_headers[0]!=10)
					{	hdrs->http_cookies[i++] = tmp_headers[0];
						tmp_headers++;
					}
					while(i)
					{	if(hdrs->http_cookies[i-1] == 32 || hdrs->http_cookies[i-1] == ';')	i--;
						else	break;
					}
					while(tmp_headers[0] == 32 || tmp_headers[0]==';')	tmp_headers++;
				}
				hdrs->http_cookies[i] = 0;
			}
			else if(!strcasecmpstart(tmp_headers,"cookie2:"))		hdrs->http_cookie2 = tmp_headers;	// Cookie2: $Version="1"
			else if(!strcasecmpstart(tmp_headers,"if-modified-since:") && !(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS))
				hdrs->http_if_modified_since = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"if-unmodified-since:") && !(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS))
				hdrs->http_if_unmodified_since = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"if-match:") && !(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS))
				hdrs->http_if_match = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"if-none-match:") && !(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS))
				hdrs->http_if_none_match = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"if-range:") && !(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS))
				hdrs->http_if_range = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"date:"))			hdrs->http_date = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"range:"))			hdrs->http_range = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"content-type:"))		hdrs->http_content_type = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"content-length:"))
			{	char *tmp1;
				tmp1 = tmp_headers + 14;
				while(tmp1[0]==32 || tmp1[0]==':')	tmp1++;
				conn->need_data = 0;
				while(tmp1[0]>='0' && tmp1[0]<='9')
				{	conn->need_data = conn->need_data * 10 + (tmp1[0] - 0x30);
					tmp1++;
				}
				if(conn->need_data < 0)	conn->need_data = 0;
				hdrs->http_content_length = tmp_headers;
				
			}
			else if(!strcasecmpstart(tmp_headers,"content-md5:"))		hdrs->http_content_md5 = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"ua-cpu:"))		hdrs->http_ua_cpu = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-opera-id:"))		hdrs->http_x_opera_id = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-opera-info:"))		hdrs->http_x_opera_info = tor_strdup(tmp_headers);
			else if(!strcasecmpstart(tmp_headers,"x-opera-host:"))		hdrs->http_x_opera_host = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-oa:"))			hdrs->http_x_oa = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-ob:"))			hdrs->http_x_ob = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-oc:"))			hdrs->http_x_oc = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"x-requested-with:"))	hdrs->http_x_requested_with = tmp_headers;
			else if(!strcasecmpstart(tmp_headers,"request-range:")){	if(!hdrs->http_range)	hdrs->http_range = tmp_headers;}
			else if(!strcasecmpstart(tmp_headers,"pragma:"))		;
			else if(!strcasecmpstart(tmp_headers,"cache-control:"))		;
			else if (!is_header_dangerous(tmp_headers,conn))
			{	if(!hdrs->http_unknown_1)				hdrs->http_unknown_1 = tmp_headers;
				else if(!hdrs->http_unknown_2)				hdrs->http_unknown_2 = tmp_headers;
				else if(!hdrs->http_unknown_3)				hdrs->http_unknown_3 = tmp_headers;
				else if(!hdrs->http_unknown_4)				hdrs->http_unknown_4 = tmp_headers;
			}
		}
		if(tmp[1]==10 && tmp[2]==13 && tmp[3]==10)	break;
		if(!tmp[1])	break;
		tmp_headers = tmp+1;
		if(tmp_headers[0]==10)	tmp_headers++;
		tmp = tmp_headers;
	}
	if(!hdrs->http_request)
	{	tor_free(hdrs);
		return NULL;
	}
	if(hdrs->http_proxy_connection)	hdrs->http_connection = hdrs->http_proxy_connection;

	if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_CLIENT_IP)
	{	if(hdrs->http_x_opera_info)
		{	tmp=tor_malloc(strlen(hdrs->http_x_opera_info)+200);
			char *tmp1 = hdrs->http_x_opera_info;
			int fakeres = (identity_seed1 % NUM_SCREEN_RESOLUTIONS);
			i = 0;j = 0;
			while(tmp1[i])
			{	if((tmp1[i]|0x20)=='f' && (tmp1[i+1]=='=' || tmp1[i+1]<33))
				{	while(tmp1[i] && tmp1[i]!=',')	i++;
					tor_snprintf(tmp+j,10,"f=%i",((unsigned int)identity_seed1&3)+7);
					j = strlen(tmp);
				}
				else if((tmp1[i]|0x20)=='s' && ((tmp1[i+1]|0x20)=='w') && (tmp1[i+2]=='=' || tmp1[i+2]<33))
				{	while(tmp1[i] && tmp1[i]!=',')	i++;
					tor_snprintf(tmp+j,10,"sw=%i",screen_resolutions[fakeres][0]);
					j = strlen(tmp);
				}
				else if((tmp1[i]|0x20)=='s' && ((tmp1[i+1]|0x20)=='h') && (tmp1[i+2]=='=' || tmp1[i+2]<33))
				{	while(tmp1[i] && tmp1[i]!=',')	i++;
					tor_snprintf(tmp+j,10,"sh=%i",screen_resolutions[fakeres][1]-TASKBAR_HEIGHT);
					j = strlen(tmp);
				}
				else tmp[j++] = tmp1[i++];
			}
			tmp[j] = 0;
			tor_free(hdrs->http_x_opera_info);
			hdrs->http_x_opera_info = tmp;
		}
		if(hdrs->http_x_opera_id)
		{	tmp = hdrs->http_x_opera_id;
			uint32_t seed1 = identity_seed1;
			uint32_t seed2 = identity_seed2;
			while(tmp[0] && tmp[0]!=':')	tmp++;
			while(tmp[0])
			{	if((tmp[0]>='0' && tmp[0]<='9') || (tmp[0]>='A' && tmp[0]<='F') || (tmp[0]>='a' && tmp[0]<='f'))
				{	tmp[0] = (unsigned char)(seed1 & 0x0f) | 0x30;
					if(tmp[0]>'9')	tmp[0] += 7;
					seed1 = ((seed1 >> 1) + (seed1<<3)) ^ seed2;
				}
				tmp++;
			}
		}
	}

	if(!hdrs->http_host)
	{	if(strfind(hdrs->http_request,"://",0)>=0)
		{	char *normal_request;
			normal_request = hdrs->http_request;
			while(normal_request[0] && normal_request[0]!=':')	normal_request++;
			while(normal_request[0] && normal_request[0]=='/')	normal_request++;
			for(i=0;normal_request[i]!=':' && normal_request[i]!='/' && normal_request[i]>32;i++);
			hdrs->http_host = tor_malloc(i+1);
			for(i=0;normal_request[i]!=':' && normal_request[i]!='/' && normal_request[i]>32;i++)	hdrs->http_host[i] = normal_request[i];
			hdrs->http_host[i] = 0;
		}
		else if(TO_EDGE_CONN(conn)->socks_request && TO_EDGE_CONN(conn)->socks_request->original_address)
			hdrs->http_host = tor_strdup(TO_EDGE_CONN(conn)->socks_request->original_address);
		else
		{	char *normal_request = NULL;
			if(hdrs->http_orig_url)
				normal_request = hdrs->http_orig_url;
			else if(hdrs->http_referer)
				normal_request = hdrs->http_referer;
			else if(hdrs->http_referer2)
				normal_request = hdrs->http_referer2;
			if(normal_request)
			{	if(strfind(hdrs->http_orig_url,"://",0)>=0)
				{	while(normal_request[0] && normal_request[0]!=':')	normal_request++;
					while(normal_request[0] && normal_request[0]=='/')	normal_request++;
				}
				for(i=0;normal_request[i]!=':' && normal_request[i]!='/' && normal_request[i] > 32;i++)	;
				hdrs->http_host = tor_malloc(i+1);
				for(i=0;normal_request[i]!=':' && normal_request[i]!='/' && normal_request[i] > 32;i++)	hdrs->http_host[i] = normal_request[i];
				hdrs->http_host[i] = 0;
			}
			else
			{	hdrs->http_host = tor_malloc(10);
				hdrs->http_host[0] = 0;
			}
		}
	}
	if(is_banned(hdrs->http_host))
	{	if(CONN_IS_EDGE(conn))
			log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_BANNED_ADDRESS),hdrs->http_host,TO_EDGE_CONN(conn)->socks_request->port);
		tor_free(hdrs->http_host);
		tor_free(hdrs);
		connection_mark_unattached_ap(TO_EDGE_CONN(conn),END_STREAM_REASON_DONE);
		conn->state = AP_CONN_STATE_SOCKS_WAIT;
		return NULL;
	}

	if(conn->mode == CONNECTION_MODE_HTTP_SIMPLE && !(hdrs->http_x_oa || hdrs->http_x_opera_info || hdrs->http_x_opera_id))
	{	if(strcasefind(hdrs->http_host,".exit",0)>=0)
		{	tmp = hdrs->http_host;
			while(*tmp)	tmp++;
			while(tmp != hdrs->http_host)		// .exit
			{	tmp--;
				if(tmp[0] == '.')
				{	tmp[0] = 0;
					break;
				}
			}
			while(tmp != hdrs->http_host)		// .exitname
			{	tmp--;
				if(tmp[0] == '.')
				{	tmp[0] = 0;
					break;
				}
			}
		}
		if(strfind(hdrs->http_request,"://",0)>=0)
		{	char *normal_request;
			normal_request = hdrs->http_request;
			while(normal_request[0] && normal_request[0]>32)	normal_request++;
			while(normal_request[0]==32)	normal_request++;
			if(normal_request[0]!='/')
			{	while(normal_request[0] && normal_request[0]!=':')	normal_request++;
				while(normal_request[0] && (normal_request[0]=='/' || normal_request[0]==':'))	normal_request++;
				while(normal_request[0] && normal_request[0]!='/')	normal_request++;
				tmp = hdrs->http_request;
				while(*tmp && tmp[0]!=32)	tmp++;
				if(tmp[0]==32)	tmp++;
				while(normal_request[0])	*tmp++ = *normal_request++;
				*tmp = 0;
			}
		}
	}

	if(hdrs->http_referer)
	{	if(tmpOptions->HTTPFlags & HTTP_SETTING_NO_REFERER)
		{	if(tmpOptions->HTTPFlags & HTTP_SETTING_REFERER_SAME_DOMAIN)
			{	tmp = hdrs->http_referer;
				if(strfind(tmp,"://",0)>=0)
				{	while(*tmp)
					{	if(tmp[0]==':')	break;
						tmp++;
					}
					while(tmp[0]==':' || tmp[0]=='/')	tmp++;
				}
				while(tmp[0] && tmp[0]!='/')	tmp++;
				tmp[1] = 0;
			}
			else	hdrs->http_referer = NULL;
		}
		else if(tmpOptions->HTTPFlags & HTTP_SETTING_REFERER_SAME_DOMAIN)
		{	tmp = header_to_domain(hdrs->http_referer);
			char *tmp1 = url_to_domain(hdrs->http_host);
			for(i=0;tmp[i]>32 && tmp1[i]>32 && tmp[i]!=':' && tmp1[i]!=':' && tmp[i]!='/' && tmp1[i]!='/';i++)
			{	if((tmp[i]|0x20) != (tmp1[i]|0x20))
				{	hdrs->http_referer = NULL;
					break;
				}
			}
		}
	}
	if(hdrs->http_referer)
	{	while(hdrs->http_referer[0] && hdrs->http_referer[0]!=':')	hdrs->http_referer++;
		while(hdrs->http_referer[0]==32 || hdrs->http_referer[0]==':') hdrs->http_referer++;
		if(hdrs->http_referer[0]==0)
			hdrs->http_referer = NULL;
	}

	if(!hdrs->http_useragent)	hdrs->useragent = get_identity_user_agent();
	else
	{	i = MAX_HTTP_HEADERS;
		j = strfind(hdrs->http_useragent,"MSIE",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_IE;
			set_version(hdrs,hdrs->http_useragent+j,DEFAULT_IE_VER_0,DEFAULT_IE_VER_1,DEFAULT_IE_VER_2,DEFAULT_IE_VER_3);
		}
		j = strfind(hdrs->http_useragent,"Opera/",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_OPERA;
			j = strfind(hdrs->http_useragent,"Version/",0);
			if(j < 0)	set_version(hdrs,hdrs->http_useragent+i,DEFAULT_OPERA_VER_0,DEFAULT_OPERA_VER_1,DEFAULT_OPERA_VER_2,DEFAULT_OPERA_VER_3);
			else		set_version(hdrs,hdrs->http_useragent+j,DEFAULT_OPERA_VER_0,DEFAULT_OPERA_VER_1,DEFAULT_OPERA_VER_2,DEFAULT_OPERA_VER_3);
		}
		j = strfind(hdrs->http_useragent,"Firefox/",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_FIREFOX;
			set_version(hdrs,hdrs->http_useragent+j,DEFAULT_FIREFOX_VER_0,DEFAULT_FIREFOX_VER_1,DEFAULT_FIREFOX_VER_2,DEFAULT_FIREFOX_VER_3);
		}
		j = strfind(hdrs->http_useragent,"Chrome/",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_CHROME;
			set_version(hdrs,hdrs->http_useragent+j,DEFAULT_CHROME_VER_0,DEFAULT_CHROME_VER_1,DEFAULT_CHROME_VER_2,DEFAULT_CHROME_VER_3);
		}
		j = strfind(hdrs->http_useragent,"Safari/",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_SAFARI;
			set_version(hdrs,hdrs->http_useragent+j,DEFAULT_SAFARI_VER_0,DEFAULT_SAFARI_VER_1,DEFAULT_SAFARI_VER_2,DEFAULT_SAFARI_VER_3);
		}
		j = strfind(hdrs->http_useragent,"uTorrent/",0);
		if(j >= 0 && i > j)
		{	i = j;
			hdrs->detected_agent = BROWSER_UTORRENT;
			set_version_2(hdrs,hdrs->http_useragent+j,DEFAULT_UTORRENT_VER_0,DEFAULT_UTORRENT_VER_1,DEFAULT_UTORRENT_VER_2,DEFAULT_UTORRENT_VER_3);
		}
		if(i == MAX_HTTP_HEADERS)	hdrs->useragent = BROWSER_UNKNOWN;
	}
	if(tmpOptions->HTTPAgent == BROWSER_AUTODETECT || tmpOptions->HTTPAgent == BROWSER_NOCHANGE)			hdrs->useragent = hdrs->detected_agent;
	else if(tmpOptions->HTTPAgent == BROWSER_IDENTITY)		hdrs->useragent = get_identity_user_agent();
	else if(tmpOptions->HTTPAgent == BROWSER_IDENTITY_WIN_ONLY)	hdrs->useragent = get_identity_user_agent();
	else	hdrs->useragent = tmpOptions->HTTPAgent;

	tmp_headers = tor_malloc(MAX_HTTP_HEADERS+4);
	int written = 0;
	set_browser_version(hdrs);
	switch(hdrs->useragent)
	{	case BROWSER_IE:
			log(LOG_INFO,LD_APP,"Browser: Internet Explorer");
			regen_ie(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_CHROME:
			log(LOG_INFO,LD_APP,"Browser: Chrome");
			regen_chrome(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_OPERA:
			log(LOG_INFO,LD_APP,"Browser: Opera");
			regen_opera(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_SAFARI:
			log(LOG_INFO,LD_APP,"Browser: Safari");
			regen_safari(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_GOOGLEBOT:
			log(LOG_INFO,LD_APP,"Browser: GoogleBot");
			regen_googlebot(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_BING:
			log(LOG_INFO,LD_APP,"Browser: Bing Bot");
			regen_bingbot(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_YAHOO:
			log(LOG_INFO,LD_APP,"Browser: Yahoo! Bot");
			regen_yahoo(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_YANDEX:
			log(LOG_INFO,LD_APP,"Browser: Yandex Bot");
			regen_yandex(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_FIREFOX:
			log(LOG_INFO,LD_APP,"Browser: Firefox");
			regen_firefox(hdrs,conn,tmp_headers,&written);
			break;
		case BROWSER_UTORRENT:
			log(LOG_INFO,LD_APP,"Browser: uTorrent");
			regen_utorrent(hdrs,conn,tmp_headers,&written);
			break;
		default: //BROWSER_UNKNOWN
			log(LOG_INFO,LD_APP,"Browser: unknown");
			regen_any(hdrs,conn,tmp_headers,&written);
			break;
	}

	if(conn->mode != CONNECTION_MODE_HTTP_SIMPLE)
	{	if(hdrs->http_proxy_connection)
			append_header(tmp_headers,&written,"Proxy-Connection",(strcasefind(hdrs->http_proxy_connection,"keep-alive",0)>=0)?"Keep-Alive":"Close");
		if(hdrs->http_proxy_authorization)
			append_header(tmp_headers,&written,NULL,hdrs->http_proxy_authorization);
	}
	if(hdrs->http_authorization)
		append_header(tmp_headers,&written,NULL,hdrs->http_authorization);
	if(hdrs->http_x_opera_id || hdrs->http_x_opera_info || hdrs->http_x_opera_host || hdrs->http_x_oa || hdrs->http_x_ob || hdrs->http_x_oc)
	{	i = strlen(tmp_headers);
		if(hdrs->http_x_opera_info && i+strlen(hdrs->http_x_opera_info) < MAX_HTTP_HEADERS-30)
			append_header(tmp_headers,&written,NULL,hdrs->http_x_opera_info);
		if(hdrs->http_x_opera_id && i+strlen(hdrs->http_x_opera_id) < MAX_HTTP_HEADERS-30)
			append_header(tmp_headers,&written,NULL,hdrs->http_x_opera_id);
		if(hdrs->http_x_opera_host && i+strlen(hdrs->http_x_opera_host) < MAX_HTTP_HEADERS-30)
			append_header(tmp_headers,&written,NULL,hdrs->http_x_opera_host);
		if(hdrs->http_x_oa && i+strlen(hdrs->http_x_oa) < MAX_HTTP_HEADERS-30)
			append_header(tmp_headers,&written,NULL,hdrs->http_x_oa);
		if(hdrs->http_x_oc && i+strlen(hdrs->http_x_oc) < MAX_HTTP_HEADERS-30)
			append_header(tmp_headers,&written,NULL,hdrs->http_x_oc);
	}
	if(!(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_UNKNOWN))
	{	if(hdrs->http_unknown_1)	append_header(tmp_headers,&written,NULL,hdrs->http_unknown_1);
		if(hdrs->http_unknown_2)	append_header(tmp_headers,&written,NULL,hdrs->http_unknown_2);
		if(hdrs->http_unknown_3)	append_header(tmp_headers,&written,NULL,hdrs->http_unknown_3);
		if(hdrs->http_unknown_4)	append_header(tmp_headers,&written,NULL,hdrs->http_unknown_4);
	}
	i = strlen(tmp_headers);
	tmp_headers[i++] = 13;tmp_headers[i++] = 10;tmp_headers[i] = 0;

	if(hdrs->http_cookies)		tor_free(hdrs->http_cookies);
	if(hdrs->http_x_opera_info)	tor_free(hdrs->http_x_opera_info);
	if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUESTS)
	{	char *tmp1 = tor_malloc(1024);
		char *normal_request;
		normal_request = hdrs->http_request;
		i = strfind(hdrs->http_request,"://",0);
		if(i>=0 && i < 10)
		{	while(normal_request[0] >32)	normal_request++;
			while(normal_request[0]==32)	normal_request++;
			i = 0;
			while(i<1022 && normal_request[0]>32)	tmp1[i++] = *normal_request++;
		}
		else
		{	tor_snprintf(tmp1,1022,"http://%s",hdrs->http_host);
			i = strlen(tmp1);
			while(normal_request[0] >32)	normal_request++;
			while(normal_request[0]==32)	normal_request++;
			if(normal_request[0]!='/')	tmp1[i++]='/';
			while(i<1022 && normal_request[0]>32)	tmp1[i++] = *normal_request++;
		}
		tmp1[i] = 0;
		http_log(LOG_NOTICE,LANG_LOG_HTTP_REQUEST_RESOURCE,tmp1,strlen(tmp1),conn);
		tor_free(tmp1);
	}

	if(hdrs->http_te && (conn->need_data == 0) && hdrs->http_request[0]!='G' && hdrs->http_request[0]!='H')
	{	tmp = hdrs->http_te;
		while(tmp[0]!=':' && tmp[0])	tmp++;
		while(tmp[0]==32 || tmp[0]==':')	tmp++;
		if(strcasecmpstart(tmp,"identity"))
			conn->need_trailers |= EXPECTING_CHUNK;
	}
	else if(hdrs->http_connection && (conn->need_data == 0) && !hdrs->http_keepalive)
	{	tmp = hdrs->http_connection;
		while(tmp[0]!=':' && tmp[0])	tmp++;
		while(tmp[0]==32 || tmp[0]==':')	tmp++;
		if(strfind(tmp,"close",0)>=0)
			conn->need_trailers |= EXPECTING_CLOSE;
	}
	else if(hdrs->http_content_type && (conn->need_data==0))
	{	tmp = hdrs->http_content_type;
		if(strcasefind(tmp,"multipart/",0) >= 0)
		{	i = strcasefind(tmp,"boundary",0);
			if(i >= 0)
			{	tmp += i;
				while(tmp[0]==32)	tmp++;
				if(tmp[0]=='=')	tmp++;
				conn->need_boundary = 0;
				while(tmp[0]==32)	tmp++;
				while(tmp[0]!=13 && tmp[0]!=10)
				{	conn->need_boundary = conn->need_boundary * 3 + tmp[0];
					tmp++;
				}
				conn->need_trailers |= EXPECTING_BOUNDARY;
			}
		}
	}
	if(CONN_IS_EDGE(conn))
	{	if(conn->mode == CONNECTION_MODE_HTTP_SIMPLE && conn->last_host && strcasecmp(conn->last_host,hdrs->http_host))
		{	log(LOG_INFO,LD_APP,"Changing host from %s to %s",conn->last_host,hdrs->http_host);
			char *tmp1 = tor_malloc(1024);
			char *normal_request;
			normal_request = hdrs->http_request;
			if(strfind(hdrs->http_request,"://",0)>=0)
			{	while(normal_request[0] >32)	normal_request++;
				while(normal_request[0]==32)	normal_request++;
				i = 0;
				while(i<1022 && normal_request[0]>32)	tmp1[i++] = *normal_request++;
			}
			else
			{	tor_snprintf(tmp1,1022,"http://%s",hdrs->http_host);
				i = strlen(tmp1);
				while(normal_request[0] >32)	normal_request++;
				while(normal_request[0]==32)	normal_request++;
				if(normal_request[0]!='/')	tmp1[i++]='/';
				while(i<1022 && normal_request[0]>32)	tmp1[i++] = *normal_request++;
			}
			tmp1[i] = 0;
			tor_snprintf(tmp_headers,MAX_HTTP_HEADERS-1,"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: Close\r\n\r\n",tmp1);
			connection_write_to_buf(tmp_headers,strlen(tmp_headers),conn);
			tor_free(tmp1);
			if(hdrs->http_host)	tor_free(hdrs->http_host);
			tor_free(hdrs);
			tor_free(tmp_headers);
			connection_mark_unattached_ap(TO_EDGE_CONN(conn),END_STREAM_REASON_DONE);
			conn->state = AP_CONN_STATE_SOCKS_WAIT;
			return NULL;
		}
	}
	if(conn->last_host)	tor_free(conn->last_host);
	conn->last_host = hdrs->http_host;
	tor_free(hdrs);
	return tmp_headers;
}

char *parse_response_headers(connection_t *conn,char *headers,int hdrlen)
{	char *tmp,*tmp_headers;
	int i,j;
	int httpstatus = 0;
	tmp = headers;
	tmp_headers = headers;
	if(strcasecmpstart(headers,"http") || headers[4]!='/')
	{	tmp = tor_malloc(hdrlen+1);
		memcpy(tmp,headers,hdrlen);
		tmp[hdrlen] = 0;
		log(LOG_WARN,LD_APP,"Unrecognized response headers: %s",tmp);
		tor_free(tmp);
		return NULL;
	}
	while(tmp[0]>32)	tmp++;
	if(tmp[0]==32)
	{	while(tmp[0]==32)	tmp++;
		if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_STATUS)
		{	char *tmp1 = tor_malloc(1024);
			for(j=0;tmp[j] >= 32 && j < 1022;j++)	tmp1[j] = tmp[j];
			tmp1[j] = 0;
			http_log(LOG_NOTICE,LANG_LOG_HTTP_RESPONSE_STATUS,tmp1,j,conn);
			tor_free(tmp1);
		}
		while(tmp[0]>='0' && tmp[0]<='9')
		{	httpstatus = httpstatus * 10 + (tmp[0] - 0x30);
			tmp++;
		}
		if(!httpstatus)	return NULL;
	}
	char *response = tor_malloc(hdrlen*2);
	response[0] = 0;
	j = 0;
	while(hdrlen)
	{	if((tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_ETAGS) && ((!strcasecmpstart(tmp_headers,"etag")) || (!strcasecmpstart(tmp_headers,"last-modified"))))
		{	while(tmp_headers[0]!=13 && tmp_headers[0]!=10 && hdrlen)
			{	tmp_headers++;
				hdrlen--;
			}
			if(tmp_headers[0]==13 && hdrlen){	tmp_headers++;hdrlen--;}
			if(tmp_headers[0]==10 && hdrlen){	tmp_headers++;hdrlen--;}
			continue;
		}
		else if(!strcasecmpstart(tmp_headers,"content-length"))
		{	tmp = tmp_headers + 14;
			while(tmp[0]==32 || tmp[0]==':')	tmp++;
			conn->expecting_data = 0;
			while(tmp[0]>='0' && tmp[0]<='9')
			{	conn->expecting_data = conn->expecting_data * 10 + (tmp[0] - 0x30);
				tmp++;
			}
			if(conn->expecting_data < 0)	conn->expecting_data = 0;
		}
		else if(!strcasecmpstart(tmp_headers,"transfer-encoding") && (conn->expecting_data == 0))
		{	tmp = tmp_headers + 17;
			while(tmp[0]==32 || tmp[0]==':')	tmp++;
			if(strcasecmpstart(tmp,"identity"))
				conn->expecting_trailers |= EXPECTING_CHUNK;
		}
		else if(!strcasecmpstart(tmp_headers,"connection") && (conn->expecting_data == 0))
		{	tmp = tmp_headers + 10;
			while(tmp[0]==32 || tmp[0]==':')	tmp++;
			if(!strcasecmpstart(tmp,"close"))
				conn->expecting_trailers |= EXPECTING_CLOSE;
		}
		else if(!strcasecmpstart(tmp_headers,"proxy-connection") && (conn->expecting_data == 0))
		{	tmp = tmp_headers + 16;
			while(tmp[0]==32 || tmp[0]==':')	tmp++;
			if(!strcasecmpstart(tmp,"close"))
				conn->expecting_trailers |= EXPECTING_CLOSE;
		}
		else if(!strcasecmpstart(tmp_headers,"close") && (conn->expecting_data == 0))
		{	conn->expecting_trailers |= EXPECTING_KEEPALIVE;
		}
		else if(!strcasecmpstart(tmp_headers,"content-type") && (conn->expecting_data==0))
		{	tmp = tmp_headers + 12;
			i = 0;
			while(tmp[i]!=13 && tmp[i]!=10)	i++;
			if(strcasefind(tmp,"multipart/",i) >= 0)
			{	i = strcasefind(tmp,"boundary",i);
				if(i >= 0)
				{	tmp += i;
					while(tmp[0]==32)	tmp++;
					if(tmp[0]=='=')	tmp++;
					conn->last_boundary = 0;
					while(tmp[0]==32)	tmp++;
					while(tmp[0]!=13 && tmp[0]!=10)
					{	conn->last_boundary = conn->last_boundary * 3 + tmp[0];
						tmp++;
					}
					conn->expecting_trailers |= EXPECTING_BOUNDARY;
				}
			}
		}
		else if(!strcasecmpstart(tmp_headers,"set-cookie"))
		{	if(tmp_headers[10]=='2')
			{	while(tmp_headers[0]!=13 && tmp_headers[0]!=10 && hdrlen)
				{	tmp_headers++;
					hdrlen--;
				}
				if(tmp_headers[0]==13 && hdrlen){	tmp_headers++;hdrlen--;}
				if(tmp_headers[0]==10 && hdrlen){	tmp_headers++;hdrlen--;}
				continue;
			}
			register_new_cookie(tmp_headers,conn);
		}
		while(tmp_headers[0]!=13 && tmp_headers[0]!=10 && hdrlen)
		{	response[j++] = *tmp_headers++;
			hdrlen--;
		}
		while(hdrlen && ((tmp_headers[0]==13) || (tmp_headers[0]==10)))
		{	response[j++] = *tmp_headers++;
			hdrlen--;
		}
	}
	if((conn->expecting_trailers & EXPECTING_CLOSE) && ((conn->expecting_trailers != EXPECTING_CLOSE) || conn->expecting_data))
	{	conn->expecting_trailers ^= EXPECTING_CLOSE;
	}
	if(conn->expecting_trailers == 0 && !conn->expecting_data)
	{	if(httpstatus != 204 && httpstatus != 205 && httpstatus != 304 && httpstatus >=200)	// RFC 2616
		{	conn->expecting_trailers |= EXPECTING_CLOSE;
		}
	}
	response[j] = 0;
	return response;
}

void free_cookie(cookie_info *c)
{	if(c->cookie_name)	tor_free(c->cookie_name);
	if(c->cookie_val)	tor_free(c->cookie_val);
	if(c->cookie_domain)	tor_free(c->cookie_domain);
	if(c->cookie_path)	tor_free(c->cookie_path);
	tor_free(c);
}

void free_cookies(void)
{	while(cookies)
	{	cookie_info *c = cookies->next;
		free_cookie(cookies);
		cookies = c;
	}
}

int is_known_cookie(char *cookie,char *host,DWORD pid)
{	if(!(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_HTTP_COOKIES))	return 1;
	char *cdomain = url_to_domain(host);
	char *c = tor_strdup(cookie);
	char *cval = c;
	cookie_info *cookie_tmp = cookies;
	while(cval[0] && cval[0]!='=')	cval++;
	if(cval[0]=='=')
	{	cval[0] = 0;
		cval++;
	}
	while(cookie_tmp)
	{	if(cookie_tmp->pid == pid && !strcasecmp(cdomain,cookie_tmp->cookie_domain) && !strcasecmp(cookie_tmp->cookie_name,c) && !strcasecmp(cookie_tmp->cookie_val,cval))
		{	tor_free(c);
			return 1;
		}
		cookie_tmp = cookie_tmp->next;
	}
	tor_free(c);
	return 0;
}

void write_cookies(char *headers,int *written,char *host,DWORD pid,char *cookies2)
{	int max = MAX_HTTP_HEADERS - *written - 5;
	if(max <= 10 || is_header_banned("cookie"))	return;
	if(cookies2 && cookies2[0] && max > 10)
	{	char *tmp;
		int i = 0;
		int cwrote = 0;
		while(max > 10)
		{	tmp = cookies2;
			while(tmp[0]!=';' && tmp[0])	tmp++;
			if(tmp[0])	i = 1;
			else		i = 0;
			tmp[0] = 0;
			if(is_known_cookie(cookies2,host,pid))
			{	headers += strlen(headers);
				if(!cwrote)
				{	tor_snprintf(headers,max,"Cookie: ");
					cwrote = 1;
					max -= strlen(headers);
					headers += strlen(headers);
					tor_snprintf(headers,max,"%s",cookies2);
				}
				else	tor_snprintf(headers,max,"; %s",cookies2);
				max -= strlen(headers);
				headers += strlen(headers);
			}
			if(!i)	break;
			cookies2 = tmp+1;
			while(cookies2[0]==32 || cookies2[0]==';')	cookies2++;
			if(!cookies2[0])	break;
		}
		if(cwrote)
		{	headers += strlen(headers);
			*headers++ = 13;*headers++ = 10;*headers = 0;
			max -= 2;
		}
	}
	*written = MAX_HTTP_HEADERS - max - 5;
}

#define COOKIE_FLAG_HTTP 1
#define COOKIE_FLAG_HTTPS 2
void register_new_cookie(char *cookie,connection_t *conn)
{	cookie_info **pcookies,*tmp_cookies;
	int i,j;
	int cflags = 0;
	cookie_info *new_cookie = tor_malloc_zero(sizeof(cookie_info));
	while(cookie[0] > 32 && cookie[0] != ':')	cookie++;
	while(cookie[0] == ':' || cookie[0] == 32)	cookie++;
	for(i=0;cookie[i]>32 && cookie[i]!='=' && cookie[i]!=';';i++)	;
	new_cookie->cookie_name = tor_malloc(i+1);
	for(j=0;j<i;j++)
		new_cookie->cookie_name[j] = cookie[j];
	new_cookie->cookie_name[j] = 0;
	cookie += i;
	while(cookie[0]==32)	cookie++;
	if(cookie[0]=='=')
	{	cookie++;
		while(cookie[0]==32)	cookie++;
	}
	for(i=0;cookie[i]!=13 && cookie[i]!=10 && cookie[i]!=';';i++)	;
	new_cookie->cookie_val = tor_malloc(i+1);
	for(j=0;j<i;j++)
		new_cookie->cookie_val[j] = cookie[j];
	new_cookie->cookie_val[j] = 0;
	cookie += i;
	while(cookie[0]!=13 && cookie[0]!=10)
	{	while(cookie[0]==32 || cookie[0]==';')	cookie++;
		if(!strcasecmpstart(cookie,"expires"));
	//		expires = cookie;
		else if(!strcasecmpstart(cookie,"max-age"));
	//		expires = cookie;
		else if(!strcasecmpstart(cookie,"domain"))
		{	while(cookie[0] > 32 && cookie[0] != '=' && cookie[0] != ';')	cookie++;
			while(cookie[0]==32)	cookie++;
			if(cookie[0]=='=')	cookie++;
			while(cookie[0]==32)	cookie++;
			if(cookie[0]=='.')	cookie++;
			for(i=0;cookie[i]>32 && cookie[i]!=';';i++)	;
			if(new_cookie->cookie_domain)	tor_free(new_cookie->cookie_domain);
			new_cookie->cookie_domain = tor_malloc(i+1);
			for(j=0;j<i;j++)
				new_cookie->cookie_domain[j] = cookie[j];
			new_cookie->cookie_domain[j] = 0;
			cookie += i;
			continue;
		}
		else if(!strcasecmpstart(cookie,"path"))
		{	while(cookie[0] > 32 && cookie[0] != '=' && cookie[0] != ';')	cookie++;
			while(cookie[0]==32)	cookie++;
			if(cookie[0]=='=')	cookie++;
			while(cookie[0]==32)	cookie++;
			for(i=0;cookie[i]>32 && cookie[i]!=';';i++)	;
			if(new_cookie->cookie_path)	tor_free(new_cookie->cookie_path);
			new_cookie->cookie_path = tor_malloc(i+1);
			for(j=0;j<i;j++)
				new_cookie->cookie_path[j] = cookie[j];
			new_cookie->cookie_path[j] = 0;
			cookie += i;
			continue;
		}
		else if(!strcasecmpstart(cookie,"secure"))
			cflags |= COOKIE_FLAG_HTTPS;
		else if(!strcasecmpstart(cookie,"httponly"))
			cflags |= COOKIE_FLAG_HTTP;
		while(cookie[0]!=';' && cookie[0]!=13 && cookie[0]!=10)	cookie++;
		while(cookie[0]==';' || cookie[0]==32)	cookie++;
	}
	if(!new_cookie->cookie_domain)
	{	if(conn->last_host)
			new_cookie->cookie_domain = tor_strdup(url_to_domain(conn->last_host));
		else
		{	free_cookie(new_cookie);
			return;
		}
	}
	if(!new_cookie->cookie_path)	new_cookie->cookie_path = tor_strdup("/");
	new_cookie->pid = conn->pid;
	pcookies = &cookies;
	while(*pcookies)
	{	tmp_cookies = *pcookies;
		if(tmp_cookies->pid == conn->pid && !strcasecmp(tmp_cookies->cookie_name,new_cookie->cookie_name) && !strcasecmp(tmp_cookies->cookie_domain,new_cookie->cookie_domain) && !strcasecmp(tmp_cookies->cookie_path,new_cookie->cookie_path))
			break;
		pcookies = &tmp_cookies->next;
	}
	if(*pcookies)
	{	tmp_cookies = *pcookies;
		char *tmpval = tmp_cookies->cookie_val;
		tmp_cookies->cookie_val = new_cookie->cookie_val;
		if(tmpval)	tor_free(tmpval);
		new_cookie->cookie_val = NULL;
		free_cookie(new_cookie);
	}
	else	*pcookies = new_cookie;
}
