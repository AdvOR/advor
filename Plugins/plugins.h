/*	
	void	__stdcall	log				(int severity,
								char *message);

	BOOL	__stdcall	tor_is_started			(void);

	int	__stdcall	get_connection_count		(void);

	int	__stdcall	get_connections			(connection_info_t *buffer,
								int connection_count);

	BOOL	__stdcall	close_connection		(DWORD connection_id);

	int	__stdcall	connection_read			(DWORD connection_id);

	int	__stdcall	connection_write		(DWORD connection_id);

	const char* __stdcall	get_socks_address		(DWORD connection_id,
								BOOL original_address);

	BOOL	__stdcall	set_socks_address		(DWORD connection_id,
								char *original_address,
								int command);

	DWORD	__stdcall	get_connecting_process		(DWORD connection_id)

	int	__stdcall	get_process_name		(DWORD pid,char *buffer)

	int	__stdcall	translate_address		(char *original_address,
								char *translated_address);

	void	__stdcall	map_address			(char *address,
								char *new_address);

	BOOL	__stdcall	tor_resolve_address		(char *address,
								BOOL reverse);

	DWORD	__stdcall	choose_exit			(DWORD flags,
								DWORD after,
								DWORD ip_range_low,
								DWORD ip_range_high,
								unsigned long bandwidth_rate_min,
								const char *country_id,
								DWORD connection_id,
								char *buffer);

	BOOL	__stdcall	get_router_info			(int index,
								DWORD router_ip,
								char *nickname,
								router_info_t *router_info);

	int	__stdcall	is_router_banned		(DWORD router_ip,
								char *nickname);

	int	__stdcall	ban_router			(DWORD router_ip,
								int ban_type,
								BOOL is_banned);

	const char * __stdcall	geoip_get_country_id		(DWORD ip);

	const char * __stdcall	geoip_get_country_name		(DWORD ip);

	long	__stdcall	get_time_delta			(void);

	int	__stdcall	crypto_rand_int			(unsigned int max);

	void	__stdcall	randomize_buffer		(char *buffer,
								int buffer_size);

	int	__stdcall	get_configuration_value		(char *option,
								char *buffer,
								int buffer_size);

	BOOL	__stdcall	set_configuration_value		(char *option,
								char *value);

	BOOL	__stdcall	intercept_process		(DWORD pid,
								DWORD flags,
								char *local_address);

	BOOL	__stdcall	create_intercepted_process	(char *exename,
								DWORD flags,
								char *local_address);

	BOOL	__stdcall	release_process			(DWORD pid);

	BOOL	__stdcall	is_process_intercepted		(DWORD pid);

	DWORD	__stdcall	create_connection		(char *remote_address,
								int remote_port,
								BOOL exclusive,
								LPARAM lParam);

	LPARAM*	__stdcall	get_connection_param		(DWORD connection_id);

	DWORD	__stdcall	accept_client			(SOCKET socket,
								char *remote_address,
								int remote_port,
								int exclusivity,
								LPARAM lParam);

	BOOL	__stdcall	hs_send_reply			(DWORD client_id,
								char *buffer,
								int buffer_size);

	int	__stdcall	as_from_ip			(DWORD ip);

	int	__stdcall	get_as_paths			(DWORD *iplist,
								DWORD *buffer,
								int buffer_size);

	BOOL	__stdcall	is_as_path_safe			(DWORD *aslist);

	void *	__stdcall	tor_malloc			(size_t size);

	void	__stdcall	tor_free			(void *mem);

	void *	__stdcall	safe_malloc			(size_t size);

	void	__stdcall	safe_free			(void *mem);

	int	__stdcall	write_protected_file		(char *filename,
								char *buffer,
								int bufsize);

	int	__stdcall	append_to_protected_file	(char *filename,
								char *buffer,
								int bufsize);

	int	__stdcall	read_protected_file		(char *filename,
								char **buffer);

	BOOL	__stdcall	protected_file_exists		(char *filename);

	int			tor_gzip_compress		(char **buffer_out,
								size_t *out_len,
								char *buffer_in,
								size_t in_len,
								int method);

	int			tor_gzip_uncompress		(char **buffer_out,
								size_t *out_len,
								const char *buffer_in,
								size_t in_len,
								int method,
								int complete_only,
								int log_level);

	tor_zlib_state_t *	tor_zlib_new			(int compress,
								int method);

	tor_zlib_output_t	tor_zlib_process		(tor_zlib_state_t *state,
								char **buffer_out,
								size_t *out_len,
								char **buffer_in,
								size_t *in_len,
								int finish);

	void			tor_zlib_free			(tor_zlib_state_t *state);

	int			detect_compression_method	(char *buffer_in,
								size_t in_len);

	char *	__stdcall	lang_get_string			(int,
								char *);

	void	__stdcall	lang_change_dialog_strings	(HWND hDlg,
								lang_dlg_info *dlgInfo);

*/


#ifndef _PLUGINS_H
#define _PLUGINS_H 1

#include <time.h>

#define int3 asm(".intel_syntax noprefix\nint 3\n.att_syntax prefix");

#define PLUGIN_FN_IDX_LOG 0
#define PLUGIN_FN_IDX_TOR_IS_STARTED 1
#define PLUGIN_FN_IDX_GET_CONNECTION_COUNT 2
#define PLUGIN_FN_IDX_GET_CONNECTIONS 3
#define PLUGIN_FN_IDX_CLOSE_CONNECTION 4
#define PLUGIN_FN_IDX_READ_CONNECTION 5
#define PLUGIN_FN_IDX_WRITE_CONNECTION 6
#define PLUGIN_FN_GET_SOCKS_ADDRESS 7
#define PLUGIN_FN_SET_SOCKS_ADDRESS 8
#define PLUGIN_FN_GET_CONNECTING_PROCESS 9
#define PLUGIN_FN_GET_PROCESS_NAME 10
#define PLUGIN_FN_TRANSLATE_ADDRESS 11
#define PLUGIN_FN_MAP_ADDRESS 12
#define PLUGIN_FN_TOR_RESOLVE_ADDRESS 13
#define PLUGIN_FN_CHOOSE_EXIT 14
#define PLUGIN_FN_GET_ROUTER_INFO 15
#define PLUGIN_FN_IS_ROUTER_BANNED 16
#define PLUGIN_FN_BAN_ROUTER 17
#define PLUGIN_FN_GET_COUNTRY_ID 18
#define PLUGIN_FN_GET_COUNTRY_NAME 19
#define PLUGIN_FN_GET_TIME_DELTA 20
#define PLUGIN_FN_CRYPTO_RAND_INT 21
#define PLUGIN_FN_RANDOMIZE_BUFFER 22
#define PLUGIN_FN_GET_CONFIGURATION_VALUE 23
#define PLUGIN_FN_SET_CONFIGURATION_VALUE 24
#define PLUGIN_FN_INTERCEPT_PROCESS 25
#define PLUGIN_FN_CREATE_INTERCEPTED_PROCESS 26
#define PLUGIN_FN_RELEASE_PROCESS 27
#define PLUGIN_FN_IS_PROCESS_INTERCEPTED 28
#define PLUGIN_FN_CREATE_CONNECTION 29
#define PLUGIN_FN_GET_CONNECTION_PARAM 30
#define PLUGIN_FN_ACCEPT_CLIENT 31
#define PLUGIN_FN_HS_SEND_REPLY 32
#define PLUGIN_FN_AS_FROM_IP 33
#define PLUGIN_FN_GET_AS_PATHS 34
#define PLUGIN_FN_IS_AS_PATH_SAFE 35
#define PLUGIN_FN_TOR_MALLOC 36
#define PLUGIN_FN_TOR_FREE 37
#define PLUGIN_FN_SAFE_MALLOC 38
#define PLUGIN_FN_SAFE_FREE 39
#define PLUGIN_FN_WRITE_PROTECTED_FILE 40
#define PLUGIN_FN_APPEND_TO_PROTECTED_FILE 41
#define PLUGIN_FN_READ_PROTECTED_FILE 42
#define PLUGIN_FN_PROTECTED_FILE_EXISTS 43
#define PLUGIN_FN_TOR_GZIP_COMPRESS 44
#define PLUGIN_FN_TOR_GZIP_UNCOMPRESS 45
#define PLUGIN_FN_TOR_ZLIB_NEW 46
#define PLUGIN_FN_TOR_ZLIB_PROCESS 47
#define PLUGIN_FN_TOR_ZLIB_FREE 48
#define PLUGIN_FN_DETECT_COMPRESSION_METHOD 49
#define PLUGIN_FN_GET_LANG_STR 50
#define PLUGIN_FN_LANG_CHANGE_DIALOG_STRINGS 51


#define PLUGIN_UNLOAD_ON_DEMAND 1
#define PLUGIN_UNLOAD_RELOAD 2
#define PLUGIN_UNLOAD_AT_EXIT 3
#define PLUGIN_UNLOAD_MUST_UNLOAD 4
#define PLUGIN_UNLOAD_CANCEL 0

HANDLE hPlugin=NULL;
void **functions=NULL;

#define LOG_DEBUG   8
/** Info-level severity: for messages that appear frequently during normal operation. */
#define LOG_INFO    7
/** Notice-level severity: for messages that appear infrequently during normal operation; that the user will probably care about; and that are not errors. */
#define LOG_ADDR 6
/** Proxy-level severity: for messages that appear when a new proxy request was received. */
#define LOG_NOTICE  5
/** Warn-level severity: for messages that only appear when something has gone wrong. */
#define LOG_WARN    4
/** Error-level severity: for messages that only appear when something has gone very wrong. */
#define LOG_ERR     3


// reference.left is used as a reference for width adjustments, if any
// the width remains unchanged
#define RESIZE_FLAG_NOCHANGE_WIDTH 0
// the width equals reference.left
#define RESIZE_FLAG_FIXED_WIDTH 1			// refWidthControl = width in pixels
// the width is adjusted to keep the same distance between newSize.right and the X coordinate of refWidthControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH 4
// the width is adjusted to keep the same distance between newSize.right and the right margin of refWidthControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH 8
// the width has same value as the width of refWidthControl
#define RESIZE_FLAG_SAME_AS_CONTROL_WIDTH_WIDTH RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH
// the width is increased proportionally relative to refWidthControl
#define RESIZE_FLAG_RELATIVE_TO_WIDTH_WIDTH 16
// the width is increased proportionally relative to the X coordinate of refWidthControl
#define RESIZE_FLAG_RELATIVE_TO_POS_LEFT_WIDTH 32
// the width is increased proportionally relative to the right margin of refWidthControl
#define RESIZE_FLAG_RELATIVE_TO_POS_RIGHT_WIDTH 64
// the width is adjusted to keep the same distance between newSize.right and the middle of refWidthControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH 128
#define RESIZE_MASK_WIDTH_NEED_REF (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH|RESIZE_FLAG_RELATIVE_TO_WIDTH_WIDTH|RESIZE_FLAG_RELATIVE_TO_POS_LEFT_WIDTH|RESIZE_FLAG_RELATIVE_TO_POS_RIGHT_WIDTH|RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH)

// reference.top is used as a reference for height adjustments, if any
// the height remains unchanged
#define RESIZE_FLAG_NOCHANGE_HEIGHT 0
// the height equals reference.top
#define RESIZE_FLAG_FIXED_HEIGHT 0x100
// the height is adjusted to keep the same distance between newSize.bottom and the Y coordinate of refHeightControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT 0x400
// the height is adjusted to keep the same distance between newSize.bottom and the bottom margin of refHeightControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT 0x800
// the height has same value as the height of refHeightControl
#define RESIZE_FLAG_SAME_AS_CONTROL_HEIGHT_HEIGHT RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT
// the height is increased proportionally relative to refHeightControl
#define RESIZE_FLAG_RELATIVE_TO_HEIGHT_HEIGHT 0x1000
// the height is increased proportionally relative to the Y coordinate of refHeightControl
#define RESIZE_FLAG_RELATIVE_TO_POS_TOP_HEIGHT 0x2000
// the height is increased proportionally relative to the bottom margin of refHeightControl
#define RESIZE_FLAG_RELATIVE_TO_POS_BOTTOM_HEIGHT 0x4000
// the height is adjusted to keep the same distance between newSize.bottom and the middle of refHeightControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_HEIGHT 0x8000
#define RESIZE_MASK_HEIGHT_NEED_REF (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT|RESIZE_FLAG_RELATIVE_TO_HEIGHT_HEIGHT|RESIZE_FLAG_RELATIVE_TO_POS_TOP_HEIGHT|RESIZE_FLAG_RELATIVE_TO_POS_BOTTOM_HEIGHT|RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_HEIGHT)

// reference.right is used as a reference for x-coordinate adjustments, if any
// the X coordinate remains unchanged
#define RESIZE_FLAG_NOCHANGE_POS_X 0
// X equals reference.right
#define RESIZE_FLAG_FIXED_POS_X 0x10000
// X is adjusted to keep the same to the X coordinate of refPosXControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X 0x20000
// X is adjusted to keep the same to the right margin of refPosXControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X 0x40000
// X is adjusted proportinally to X of refPosXControl
#define RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_LEFT_POS_X 0x80000
// X is adjusted proportinally to the right margin of refPosXControl
#define RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_RIGHT_POS_X 0x100000
// X is adjusted to keep the same distance to the middle of refPosXControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_X 0x200000
#define RESIZE_MASK_POSX_NEED_REF (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X|RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_LEFT_POS_X|RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_RIGHT_POS_X|RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_X)

// reference.bottom is used as a reference for y-coordinate adjustments, if any
// the Y coordinate remains unchanged
#define RESIZE_FLAG_NOCHANGE_POS_Y 0
// Y equals reference.bottom
#define RESIZE_FLAG_FIXED_POS_Y 0x1000000
// Y is adjusted to keep the same to the Y coordinate of refPosYControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y 0x2000000
// Y is adjusted to keep the same to the bottom margin of refPosYControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y 0x4000000
// Y is adjusted proportinally to Y of refPosYControl
#define RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_TOP_POS_Y 0x8000000
// Y is adjusted proportinally to the bottom margin of refPosYControl
#define RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_BOTTOM_POS_Y 0x10000000
// Y is adjusted to keep the same distance to the middle of refPosYControl
#define RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_Y 0x20000000
#define RESIZE_MASK_POSY_NEED_REF (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y|RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_TOP_POS_Y|RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_BOTTOM_POS_Y|RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_Y)

typedef struct resize_info_t
{	int ctrlId;
	int refWidthControl;
	int refHeightControl;
	int refPosXControl;
	int refPosYControl;
	RECT reference;
	DWORD flags;
} resize_info_t;


typedef struct connection_info_t
{
	DWORD connection_id;
	DWORD connection_type;
	DWORD connection_state;
	char *address;
	char *socks_original_address;
	char *socks_final_address;
	DWORD reserved;
	LPARAM *lParam;
} connection_info_t;

// Tor constants from or.h

#define _CONN_TYPE_MIN 3
/** Type for sockets listening for OR connections. */
#define CONN_TYPE_OR_LISTENER 3
/** A bidirectional TLS connection transmitting a sequence of cells.
 * May be from an OR to an OR, or from an OP to an OR. */
#define CONN_TYPE_OR 4
/** A TCP connection from an onion router to a stream's destination. */
#define CONN_TYPE_EXIT 5
/** Type for sockets listening for SOCKS connections. */
#define CONN_TYPE_AP_LISTENER 6
/** A SOCKS proxy connection from the user application to the onion
 * proxy. */
#define CONN_TYPE_AP 7
/** Type for sockets listening for HTTP connections to the directory server. */
#define CONN_TYPE_DIR_LISTENER 8
/** Type for HTTP connections to the directory server. */
#define CONN_TYPE_DIR 9
/** Connection from the main process to a CPU worker process. */
#define CONN_TYPE_CPUWORKER 10
/** Type for listening for connections from user interface process. */
#define CONN_TYPE_CONTROL_LISTENER 11
/** Type for connections from user interface process. */
#define CONN_TYPE_CONTROL 12
/** Type for sockets listening for transparent connections redirected by pf or
 * netfilter. */
#define CONN_TYPE_AP_TRANS_LISTENER 13
/** Type for sockets listening for transparent connections redirected by
 * natd. */
#define CONN_TYPE_AP_NATD_LISTENER 14
/** Type for sockets listening for DNS requests. */
#define CONN_TYPE_AP_DNS_LISTENER 15
#define _CONN_TYPE_MAX 15



/** State for any listener connection. */
#define LISTENER_STATE_READY 0

#define _CPUWORKER_STATE_MIN 1
/** State for a connection to a cpuworker process that's idle. */
#define CPUWORKER_STATE_IDLE 1
/** State for a connection to a cpuworker process that's processing a
 * handshake. */
#define CPUWORKER_STATE_BUSY_ONION 2
#define _CPUWORKER_STATE_MAX 2

#define CPUWORKER_TASK_ONION CPUWORKER_STATE_BUSY_ONION

#define _OR_CONN_STATE_MIN 1
/** State for a connection to an OR: waiting for connect() to finish. */
#define OR_CONN_STATE_CONNECTING 1
/** State for a connection to an OR: waiting for proxy command to flush. */
#define OR_CONN_STATE_PROXY_FLUSHING 2
/** State for a connection to an OR: waiting for proxy response. */
#define OR_CONN_STATE_PROXY_READING 3
/** State for a connection to an OR or client: SSL is handshaking, not done
 * yet. */
#define OR_CONN_STATE_TLS_HANDSHAKING 4
/** State for a connection to an OR: We're doing a second SSL handshake for
 * renegotiation purposes. */
#define OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING 5
/** State for a connection at an OR: We're waiting for the client to
 * renegotiate. */
#define OR_CONN_STATE_TLS_SERVER_RENEGOTIATING 6
/** State for a connection to an OR: We're done with our SSL handshake, but we
 * haven't yet negotiated link protocol versions and sent a netinfo cell.
 */
#define OR_CONN_STATE_OR_HANDSHAKING 7
/** State for a connection to an OR: Ready to send/receive cells. */
#define OR_CONN_STATE_OPEN 8
#define _OR_CONN_STATE_MAX 8

#define _EXIT_CONN_STATE_MIN 1
/** State for an exit connection: waiting for response from dns farm. */
#define EXIT_CONN_STATE_RESOLVING 1
/** State for an exit connection: waiting for connect() to finish. */
#define EXIT_CONN_STATE_CONNECTING 2
/** State for an exit connection: open and ready to transmit data. */
#define EXIT_CONN_STATE_OPEN 3
/** State for an exit connection: waiting to be removed. */
#define EXIT_CONN_STATE_RESOLVEFAILED 4
#define _EXIT_CONN_STATE_MAX 4

/* The AP state values must be disjoint from the EXIT state values. */
#define _AP_CONN_STATE_MIN 5
/** State for a SOCKS connection: waiting for SOCKS request. */
#define AP_CONN_STATE_SOCKS_WAIT 5
/** State for a SOCKS connection: got a y.onion URL; waiting to receive
 * rendezvous descriptor. */
#define AP_CONN_STATE_RENDDESC_WAIT 6
/** The controller will attach this connection to a circuit; it isn't our
 * job to do so. */
#define AP_CONN_STATE_CONTROLLER_WAIT 7
/** State for a SOCKS connection: waiting for a completed circuit. */
#define AP_CONN_STATE_CIRCUIT_WAIT 8
/** State for a SOCKS connection: sent BEGIN, waiting for CONNECTED. */
#define AP_CONN_STATE_CONNECT_WAIT 9
/** State for a SOCKS connection: sent RESOLVE, waiting for RESOLVED. */
#define AP_CONN_STATE_RESOLVE_WAIT 10
/** State for a SOCKS connection: ready to send and receive. */
#define AP_CONN_STATE_OPEN 11
/** State for a transparent natd connection: waiting for original
 * destination. */
#define AP_CONN_STATE_NATD_WAIT 12
#define _AP_CONN_STATE_MAX 12

/** True iff the AP_CONN_STATE_* value <b>s</b> means that the corresponding
 * edge connection is not attached to any circuit. */
#define AP_CONN_STATE_IS_UNATTACHED(s) \
  ((s) <= AP_CONN_STATE_CIRCUIT_WAIT || (s) == AP_CONN_STATE_NATD_WAIT)

#define _DIR_CONN_STATE_MIN 1
/** State for connection to directory server: waiting for connect(). */
#define DIR_CONN_STATE_CONNECTING 1
/** State for connection to directory server: sending HTTP request. */
#define DIR_CONN_STATE_CLIENT_SENDING 2
/** State for connection to directory server: reading HTTP response. */
#define DIR_CONN_STATE_CLIENT_READING 3
/** State for connection to directory server: happy and finished. */
#define DIR_CONN_STATE_CLIENT_FINISHED 4
/** State for connection at directory server: waiting for HTTP request. */
#define DIR_CONN_STATE_SERVER_COMMAND_WAIT 5
/** State for connection at directory server: sending HTTP response. */
#define DIR_CONN_STATE_SERVER_WRITING 6
#define _DIR_CONN_STATE_MAX 6

/** True iff the purpose of <b>conn</b> means that it's a server-side
 * directory connection. */
#define DIR_CONN_IS_SERVER(conn) ((conn)->purpose == DIR_PURPOSE_SERVER)

#define _CONTROL_CONN_STATE_MIN 1
/** State for a control connection: Authenticated and accepting v1 commands. */
#define CONTROL_CONN_STATE_OPEN 1
/** State for a control connection: Waiting for authentication; speaking
 * protocol v1. */
#define CONTROL_CONN_STATE_NEEDAUTH 2
#define _CONTROL_CONN_STATE_MAX 2

#define EXIT_SELECT_USE_IP_RANGE 1
#define EXIT_SELECT_USE_BANDWIDTH 2
#define EXIT_SELECT_USE_COUNTRY 4
#define EXIT_SELECT_SET_CONNECTION 8
#define EXIT_SELECT_GET_NICKNAME 16


typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed int int16_t;
typedef unsigned int uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;

#define DIGEST_LEN 20

typedef struct smartlist_t
{	void **list;
	int num_used;
	int capacity;
} smartlist_t; 

/** Information about another onion router in the network. */
typedef struct router_info_t
{	int cbSize;
	int index;
	char *address; /**< Location of OR: either a hostname or an IP address. */
	char *nickname; /**< Human-readable OR name. */

	char identity_digest[DIGEST_LEN];
	/** Declared publication time of the descriptor. */
	time_t published_on;

	uint32_t addr; /**< IPv4 address of OR, in host order. */
	uint16_t or_port; /**< Port for TLS connections. */
	uint16_t dir_port; /**< Port for HTTP directory connections. */

	char *platform; /**< What software/operating system is this OR using? */

	/* link info */
	uint32_t bandwidthrate; /**< How many bytes does this OR add to its token bucket per second? */
	uint32_t bandwidthburst; /**< How large is this OR's token bucket? */
	/** How many bytes/s is this router known to handle? */
	uint32_t bandwidthcapacity;
	smartlist_t *exit_policy; /**< What streams will this OR permit to exit?  NULL for 'reject *:*'. */
	long uptime; /**< How many seconds the router claims to have been up */
	smartlist_t *declared_family; /**< Nicknames of router which this router claims are its family. */
	char *contact_info; /**< Declared contact info for this router. */
	unsigned int is_hibernating:1; /**< Whether the router claims to be hibernating */
	unsigned int allow_single_hop_exits:1;  /**< Whether the router allows single hop exits. */

	/* local info */
	unsigned int is_running:1; /**< As far as we know, is this OR currently running? */
	unsigned int is_valid:1; /**< Has a trusted dirserver validated this OR?  (For Authdir: Have we validated this OR?)*/
	unsigned int is_fast:1; /** Do we think this is a fast OR? */
	unsigned int is_stable:1; /** Do we think this is a stable OR? */
	unsigned int is_possible_guard:1; /**< Do we think this is an OK guard? */
	unsigned int is_exit:1; /**< Do we think this is an OK exit? */
	unsigned int is_bad_exit:1; /**< Do we think this exit is censored, borked, or otherwise nasty? */
	unsigned int is_bad_directory:1; /**< Do we think this directory is junky, underpowered, or otherwise useless? */
	unsigned int wants_to_be_hs_dir:1; /**< True iff this router claims to be a hidden service directory. */
	unsigned int is_hs_dir:1; /**< True iff this router is a hidden service directory according to the authorities. */
	unsigned int policy_is_reject_star:1; /**< True iff the exit policy for this router rejects everything. */
} router_info_t;

typedef struct tor_zlib_state_t tor_zlib_state_t;

#define BAN_EXIT 'X'
#define BAN_GENERAL 0

#define INTERCEPT_FLAG_FAKE_LOCAL_TIME 2
#define INTERCEPT_FLAG_FAKE_IPS 8
#define INTERCEPT_FLAG_TCP_ONLY 16
#define INTERCEPT_FLAG_CHANGE_ICON 32
#define INTERCEPT_FLAG_EXCLUSIVE_EXIT 64
#define INTERCEPT_FLAG_NOTIFY_USER 512
#define INTERCEPT_FLAG_IGNORE_EXISTING_CONNECTIONS 2048

#define EXCLUSIVITY_UNDEFINED 0
#define EXCLUSIVITY_GENERAL 1
#define EXCLUSIVITY_PROCESS 2
#define EXCLUSIVITY_PLUGIN 3

#define HIDDENSERVICE_REGISTER_SERVICE 1
#define HIDDENSERVICE_UNREGISTER_SERVICE 0
#define HIDDENSERVICE_REGISTER_CLIENT 3
#define HIDDENSERVICE_UNREGISTER_CLIENT 2

#define AS_UNKNOWN 65536

#define NO_METHOD 0
#define GZIP_METHOD 1
#define ZLIB_METHOD 2
#define UNKNOWN_METHOD 3

typedef enum
{	TOR_ZLIB_OK, TOR_ZLIB_DONE, TOR_ZLIB_BUF_FULL, TOR_ZLIB_ERR
} tor_zlib_output_t;

typedef struct lang_dlg_info
{	int ctrlId;
	int langId;
} lang_dlg_info;

#define InitPlugin hPlugin=plugin_instance;functions=function_table;
#define log ((void __stdcall (*)(int,char *))(functions[PLUGIN_FN_IDX_LOG]))
#define tor_is_started ((BOOL __stdcall (*)(void))(functions[PLUGIN_FN_IDX_TOR_IS_STARTED]))
#define get_connection_count ((int __stdcall (*)(void))(functions[PLUGIN_FN_IDX_GET_CONNECTION_COUNT]))
#define get_connections(at_a,at_b) ((int __stdcall (*)(HANDLE,connection_info_t *,int))(functions[PLUGIN_FN_IDX_GET_CONNECTIONS]))(hPlugin,at_a,at_b)
#define close_connection ((BOOL __stdcall (*)(DWORD))(functions[PLUGIN_FN_IDX_CLOSE_CONNECTION]))
#define connection_read ((int __stdcall (*)(DWORD))(functions[PLUGIN_FN_IDX_READ_CONNECTION]))
#define connection_write ((int __stdcall (*)(DWORD))(functions[PLUGIN_FN_IDX_WRITE_CONNECTION]))
#define get_socks_address ((const char * __stdcall (*)(DWORD,BOOL))(functions[PLUGIN_FN_GET_SOCKS_ADDRESS]))
#define set_socks_address(at_a,at_b,at_c) ((BOOL __stdcall (*)(HANDLE,DWORD,char *,int))(functions[PLUGIN_FN_SET_SOCKS_ADDRESS]))(hPlugin,at_a,at_b,at_c)
#define get_connecting_process ((DWORD __stdcall (*)(DWORD))(functions[PLUGIN_FN_GET_CONNECTING_PROCESS]))
#define get_process_name ((int __stdcall (*)(DWORD,char *))(functions[PLUGIN_FN_GET_PROCESS_NAME]))
#define translate_address(at_a,at_b) ((int __stdcall (*)(HANDLE,char *,char *))(functions[PLUGIN_FN_TRANSLATE_ADDRESS]))(hPlugin,at_a,at_b)
#define map_address(at_a,at_b) ((void __stdcall (*)(HANDLE,char *,char *))(functions[PLUGIN_FN_MAP_ADDRESS]))(hPlugin,at_a,at_b)
#define tor_resolve_address(at_a,at_b) ((BOOL __stdcall (*)(HANDLE,char *,BOOL))(functions[PLUGIN_FN_TOR_RESOLVE_ADDRESS]))(hPlugin,at_a,at_b)
#define choose_exit ((DWORD __stdcall (*)(DWORD,DWORD,DWORD,DWORD,unsigned long,const char *,DWORD,char *))(functions[PLUGIN_FN_CHOOSE_EXIT]))
#define get_router_info ((BOOL __stdcall (*)(int,DWORD,char *,router_info_t *))(functions[PLUGIN_FN_GET_ROUTER_INFO]))
#define is_router_banned ((int __stdcall (*)(DWORD,char *))(functions[PLUGIN_FN_IS_ROUTER_BANNED]))
#define ban_router ((int __stdcall (*)(DWORD,int,BOOL))(functions[PLUGIN_FN_BAN_ROUTER]))
#define geoip_get_country_id ((const char * __stdcall (*)(DWORD))(functions[PLUGIN_FN_GET_COUNTRY_ID]))
#define geoip_get_country_name ((const char * __stdcall (*)(DWORD))(functions[PLUGIN_FN_GET_COUNTRY_NAME]))
#define get_time_delta ((long __stdcall (*)(void))(functions[PLUGIN_FN_GET_TIME_DELTA]))
#define crypto_rand_int ((int __stdcall (*)(unsigned int))(functions[PLUGIN_FN_CRYPTO_RAND_INT]))
#define randomize_buffer ((void __stdcall (*)(char *,int))(functions[PLUGIN_FN_RANDOMIZE_BUFFER]))
#define get_configuration_value(at_a,at_b,at_c) ((int __stdcall (*)(HANDLE,char *,char *,int))(functions[PLUGIN_FN_GET_CONFIGURATION_VALUE]))(hPlugin,at_a,at_b,at_c)
#define set_configuration_value(at_a,at_b) ((BOOL __stdcall (*)(HANDLE,char *,char *))(functions[PLUGIN_FN_SET_CONFIGURATION_VALUE]))(hPlugin,at_a,at_b)
#define intercept_process(at_a,at_b,at_c) ((BOOL __stdcall (*)(HANDLE,DWORD,DWORD,char *))(functions[PLUGIN_FN_INTERCEPT_PROCESS]))(hPlugin,at_a,at_b,at_c)
#define create_intercepted_process(at_a,at_b,at_c) ((BOOL __stdcall (*)(HANDLE,char *,DWORD,char *))(functions[PLUGIN_FN_CREATE_INTERCEPTED_PROCESS]))(hPlugin,at_a,at_b,at_c)
#define release_process(at_a) ((BOOL __stdcall (*)(HANDLE,DWORD))(functions[PLUGIN_FN_RELEASE_PROCESS]))(hPlugin,at_a)
#define is_process_intercepted(at_a) ((BOOL __stdcall (*)(HANDLE,DWORD))(functions[PLUGIN_FN_IS_PROCESS_INTERCEPTED]))(hPlugin,at_a)
#define create_connection(at_a,at_b,at_c,at_d) ((DWORD __stdcall (*)(HANDLE,char *,int,BOOL,LPARAM))(functions[PLUGIN_FN_CREATE_CONNECTION]))(hPlugin,at_a,at_b,at_c,at_d)
#define get_connection_param(at_a) ((LPARAM * __stdcall (*)(HANDLE,DWORD))(functions[PLUGIN_FN_GET_CONNECTION_PARAM]))(hPlugin,at_a)
#define accept_client(at_a,at_b,at_c,at_d,at_e) ((DWORD __stdcall (*)(HANDLE,SOCKET,char *,int,int,LPARAM))(functions[PLUGIN_FN_ACCEPT_CLIENT]))(hPlugin,at_a,at_b,at_c,at_d,at_e)
#define hs_send_reply(at_a,at_b,at_c) ((BOOL __stdcall (*)(HANDLE,DWORD,char *,int))(functions[PLUGIN_FN_HS_SEND_REPLY]))(hPlugin,at_a,at_b,at_c)
#define as_from_ip ((int __stdcall (*)(DWORD))(functions[PLUGIN_FN_AS_FROM_IP]))
#define get_as_paths(at_a,at_b,at_c) ((int __stdcall (*)(DWORD *,DWORD *,int))(functions[PLUGIN_FN_GET_AS_PATHS]))
#define is_as_path_safe ((int __stdcall (*)(DWORD *))(functions[PLUGIN_FN_IS_AS_PATH_SAFE]))
#define tor_malloc ((void * __stdcall (*)(size_t))(functions[PLUGIN_FN_TOR_MALLOC]))
#define tor_free ((void __stdcall (*)(void *))(functions[PLUGIN_FN_TOR_FREE]))
#define safe_malloc ((void * __stdcall (*)(size_t))(functions[PLUGIN_FN_SAFE_MALLOC]))
#define safe_free ((void __stdcall (*)(void *))(functions[PLUGIN_FN_SAFE_FREE]))
#define write_protected_file ((int __stdcall (*)(char *,char *,int))(functions[PLUGIN_FN_WRITE_PROTECTED_FILE]))
#define append_to_protected_file ((int __stdcall (*)(char *,char *,int))(functions[PLUGIN_FN_APPEND_TO_PROTECTED_FILE]))
#define read_protected_file ((int __stdcall (*)(char *,char **))(functions[PLUGIN_FN_READ_PROTECTED_FILE]))
#define protected_file_exists ((BOOL __stdcall (*)(char *))(functions[PLUGIN_FN_PROTECTED_FILE_EXISTS]))
#define tor_gzip_compress ((int (*)(char **,size_t *,char *,size_t,int))(functions[PLUGIN_FN_TOR_GZIP_COMPRESS]))
#define tor_gzip_uncompress ((int (*)(char **,size_t *,char *,size_t,int,int,int))(functions[PLUGIN_FN_TOR_GZIP_UNCOMPRESS]))
#define tor_zlib_new ((tor_zlib_state_t * (*)(int,int))(functions[PLUGIN_FN_TOR_ZLIB_NEW]))
#define tor_zlib_process ((tor_zlib_output_t (*)(tor_zlib_state_t *,char **,size_t *,char **,size_t *,int))(functions[PLUGIN_FN_TOR_ZLIB_PROCESS]))
#define tor_zlib_free ((void (*)(tor_zlib_state_t *))(functions[PLUGIN_FN_TOR_ZLIB_FREE]))
#define detect_compression_method ((int (*)(char *,size_t))(functions[PLUGIN_FN_DETECT_COMPRESSION_METHOD]))
#define lang_get_string(at_a,at_b) ((char * __stdcall (*)(HANDLE,int,char *))(functions[PLUGIN_FN_GET_LANG_STR]))(hPlugin,at_a,at_b)
#define lang_change_dialog_strings(at_a,at_b) ((void __stdcall (*)(HANDLE,HWND,lang_dlg_info *))(functions[PLUGIN_FN_LANG_CHANGE_DIALOG_STRINGS]))(hPlugin,at_a,at_b)

#endif
