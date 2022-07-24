#define MAX_HTTP_REQUEST_LEN 65536

#define CONNECTION_MODE_UNKNOWN_INIT 0
#define CONNECTION_MODE_UNKNOWN 1
#define CONNECTION_MODE_SOCKS5_NEGOTIATE 2		// waiting for SOCKS_COMMAND_CONNECT
#define CONNECTION_MODE_HTTP_SIMPLE 3			// simple HTTP proxy
#define CONNECTION_MODE_HTTP_FROM_CHAIN 4		// HTTP chained with other proxies
#define CONNECTION_MODE_FTP 5
#define CONNECTION_MODE_IRC 6
#define CONNECTION_MODE_DCC 7
#define CONNECTION_MODE_NMDC 8
#define CONNECTION_MODE_NMDC_C2C 9
#define CONNECTION_MODE_ADC 10
#define CONNECTION_MODE_OTHER -1

#define MAX_COOKIES 4096
#define MAX_CACHED_WARNS 10
#define MAX_HTTP_HEADERS 8192

#define HTTP_SETTING_ALLOW_REFERER 0
#define HTTP_SETTING_NO_REFERER 1
#define HTTP_SETTING_REFERER_SAME_DOMAIN 2
#define HTTP_SETTING_REMOVE_REFERER_PARAMS 3

#define HTTP_SETTING_REMOVE_ETAGS 4

#define HTTP_SETTING_ORIG_LANGUAGE 0
#define HTTP_SETTING_EXIT_LANGUAGE 8
#define HTTP_SETTING_IDENTITY_LANGUAGE 16
#define HTTP_SETTING_EN_US_LANGUAGE 24

#define HTTP_SETTING_ORIG_UA_EXTENSIONS 0
#define HTTP_SETTING_HIDE_EXTENSIONS 32
#define HTTP_SETTING_IDENTITY_UA_EXTENSIONS 64

#define BROWSER_VERSION_ORIGINAL 0
#define BROWSER_VERSION_IDENTITY_MINOR 128
#define BROWSER_VERSION_IDENTITY_MAJOR 256

//#define HTTP_SETTING_REJECT_EXITNAME 512
//#define HTTP_SETTING_REJECT_ONION 1024
#define HTTP_SETTING_REMOVE_IFS 2048
#define HTTP_SETTING_REMOVE_CLIENT_IP 4096
#define HTTP_SETTING_REMOVE_UNKNOWN 8192
#define HTTP_SETTING_LOG_REQUESTS 16384
#define HTTP_SETTING_LOG_REQUEST_HEADERS 32768
#define HTTP_SETTING_LOG_RESPONSE_STATUS 65536
#define HTTP_SETTING_LOG_RESPONSE_TRAFFIC 65536*2

#define BROWSER_AUTODETECT 0
#define BROWSER_IDENTITY 0x80
#define BROWSER_IDENTITY_WIN_ONLY 0x101
#define BROWSER_NOCHANGE 0x81
#define BROWSER_ID_FIRST 1
#define BROWSER_UNKNOWN 1
#define BROWSER_CHROME 2
#define BROWSER_FIREFOX 3
#define BROWSER_IE 4
#define BROWSER_OPERA 5
#define BROWSER_SAFARI 6
#define BOT_ID_FIRST 7
#define BROWSER_BING 7
#define BROWSER_GOOGLEBOT 8
#define BROWSER_YAHOO 9
#define BROWSER_YANDEX 10
#define BROWSER_UTORRENT 11

#define BROWSER_OS_ORIGINAL 0
#define BROWSER_OS_ANY 1
#define BROWSER_OS_WINDOWS 2
#define BROWSER_OS_LINUX 3
#define BROWSER_OS_OSX 4

#define REGIONAL_SETTINGS_ORIGINAL 0
#define REGIONAL_SETTINGS_US_ENGLISH 1
#define REGIONAL_SETTINGS_EXIT 0x100

#define EXPECTING_CHUNK 1
#define EXPECTING_BOUNDARY 2
#define EXPECTING_NO_CONTENT 4
#define EXPECTING_CLOSE 8
#define EXPECTING_KEEPALIVE 16
#define EXPECTING_NO_DATA 32

typedef struct http_headers
{	int useragent;
	int detected_agent;
	int agent_version_1;
	int agent_version_2;
	int agent_version_3;
	int agent_version_4;
	int rsvd1,rsvd2,rsvd3,rsvd4;
	int agent_os;
	int agent_language;
	char *http_request;			// GET / HEAD / PUT / POST / OPTIONS
	char *http_host;			// Host:
	char *http_useragent;			// User-Agent:
	char *http_accept;			// Accept:
	char *http_accept_charset;		// Accept-Charset:
	char *http_accept_language;		// Accept-Language:
	char *http_accept_encoding;		// Accept-Encoding:
	char *http_referer;			// Referer:
	char *http_connection;			// Connection:
	char *http_proxy_connection;		// Proxy-Connection:
	char *http_keepalive;			// Keep-Alive:
	char *http_te;				// TE:
	char *http_cache_control;		// Cache-Control: / Pragma:
	char *http_authorization;		// Authorization:
	char *http_proxy_authorization;		// Proxy-Authorization: / Proxy-Authentication:
	char *http_cookies;			// Cookie:
	char *http_cookie2;			// Cookie2:
	char *http_if_modified_since;		// If-Modified-Since:
	char *http_if_unmodified_since;		// If-UnModified-Since:
	char *http_if_match;			// If-Match:
	char *http_if_none_match;		// If-None-Match:
	char *http_if_range;			// If-Range:
	char *http_date;			// Date:
	char *http_range;			// Range:
	char *http_content_type;		// Content-Type:
	char *http_content_length;		// Content-Length:
	char *http_content_md5;			// Content-MD5:
	char *http_ua_cpu;			// UA-CPU:
	char *http_x_opera_id;			// X-Opera-ID:
	char *http_x_opera_info;		// X-Opera-Info:
	char *http_x_opera_host;		// X-Opera-Host:
	char *http_x_oa;			// X-OA:
	char *http_x_ob;			// X-OB:
	char *http_x_oc;			// X-OC:
	char *http_x_requested_with;
	char *http_other;
	char *http_orig_url;			//  "X-Host:" / "X-Orig-Url:" / "X-PageView:" / "X-SFS-Top:"
	char *http_referer2;			// "NpfRefr:" / "Origin:" / "Referrer:"
	char *http_unknown_1;
	char *http_unknown_2;
	char *http_unknown_3;
	char *http_unknown_4;
} http_headers;

typedef struct cookie_info
{	struct cookie_info *next;
	char *cookie_name;
	char *cookie_val;
	char *cookie_path;
	char *cookie_domain;
	uint32_t identity;
	DWORD pid;
} cookie_info;

char *parse_request_headers(char *headers,connection_t *conn);
char *parse_response_headers(connection_t *conn,char *headers,int hdrlen);
int get_identity_user_agent(void);
void http_log(int severity,int lang_id,char *httpdata,int len,connection_t *conn);
void register_new_cookie(char *cookie,connection_t *conn);
void free_cookies(void);
int is_known_cookie(char *cookie,char *host,DWORD pid);
void write_cookies(char *headers,int *written,char *host,DWORD pid,char *cookies);
