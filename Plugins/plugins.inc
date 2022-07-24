;	AdvTor_Init			macro	at_description
;	AdvTor_Init_Lang		macro	at_lang_id,at_description
;	AdvTor_Log			macro	at_severity,at_message
;	AdvTor_TorIsStarted		macro
;	AdvTor_GetConnectionCount	macro
;	AdvTor_GetConnections		macro	at_buffer,at_count
;	AdvTor_CloseConnection		macro	at_conn
;	AdvTor_ConnectionRead		macro	at_conn
;	AdvTor_ConnectionWrite		macro	at_conn
;	AdvTor_GetSocksAddress		macro	at_conn,at_orig
;	AdvTor_SetSocksAddress		macro	at_conn,at_addr,at_cmd
;	AdvTor_GetConnectingProcess	macro	at_conn
;	AdvTor_GetProcessName		macro	at_conn,at_buffer
;	AdvTor_Translate_Address	macro	at_orig,at_new
;	AdvTor_MapAddress		macro	at_orig,at_new
;	AdvTor_TorResolveAddress	macro	at_addr,at_reverse
;	AdvTor_ChooseExit		macro	at_flags,at_after,at_range_low,at_range_high,at_bandwidth,at_country,at_conn,at_buffer
;	AdvTor_GetRouterInfo		macro	at_index,at_ip,at_nickname,at_routerinfo
;	AdvTor_IsRouterBanned		macro	at_ip,at_nickname
;	AdvTor_BanRouter		macro	at_ip,at_type,at_isbanned
;	AdvTor_GetCountryId		macro	at_ip
;	AdvTor_GetCountryName		macro	at_ip
;	AdvTor_GetTimeDelta		macro
;	AdvTor_CryptoRandInt		macro	at_max
;	AdvTor_RandomizeBuffer		macro	at_buffer,at_size
;	AdvTor_GetConfigurationValue	macro	at_option,at_buffer,at_size,at_toropt
;	AdvTor_SetConfigurationValue	macro	at_option,at_buffer
;	AdvTor_InterceptProcess		macro	at_pid,at_flags,at_localaddr
;	AdvTor_CreateInterceptedProcess	macro	at_exename,at_flags,at_localaddr
;	AdvTor_ReleaseProcess		macro	at_pid
;	AdvTor_IsProcessIntercepted	macro	at_pid
;	AdvTor_CreateConnection		macro	at_addr,at_port,at_excl,at_param
;	AdvTor_GetConnectionParam	macro	at_conn
;	AdvTor_AcceptClient		macro	at_socket,at_addr,at_port,at_excl,at_param
;	AdvTor_HS_SendReply		macro	at_client,at_buffer,at_size
;	AdvTor_ASFromIP			macro	at_ip
;	AdvTor_GetASPaths		macro	at_iplist,at_buffer,at_bufsize
;	AdvTor_IsASPathSafe		macro	at_aspaths
;	AdvTor_IsASPathSafe		macro	at_aspaths
;	AdvTor_malloc			macro	at_size
;	AdvTor_free			macro	at_buffer
;	AdvTor_safe_malloc		macro	at_size
;	AdvTor_safe_free		macro	at_buffer
;	AdvTor_write_protected_file	macro	at_fname,at_buffer,at_size
;	AdvTor_append_to_protected_file	macro	at_fname,at_buffer,at_size
;	AdvTor_read_protected_file	macro	at_fname,at_buffer
;	AdvTor_protected_file_exists	macro	at_fname
;	AdvTor_gzip_compress		macro	at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_method
;	AdvTor_gzip_uncompress		macro	at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_method,at_complete_only,at_log_level
;	AdvTor_zlib_new			macro	at_compress,at_method
;	AdvTor_zlib_process		macro	at_state,at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_finish
;	AdvTor_zlib_free		macro	at_state
;	AdvTor_detect_compression_method macro	at_buffer_in,at_in_len
;	AdvTor_lang_get_string		macro	at_str_id,at_default_str
;	AdvTor_lang_change_dialog_strings macro	at_dlg,at_lang_info_list



PLUGIN_FN_IDX_LOG = 0
PLUGIN_FN_IDX_TOR_IS_STARTED = 1
PLUGIN_FN_IDX_GET_CONNECTION_COUNT = 2
PLUGIN_FN_IDX_GET_CONNECTIONS = 3
PLUGIN_FN_IDX_CLOSE_CONNECTION = 4
PLUGIN_FN_IDX_READ_CONNECTION = 5
PLUGIN_FN_IDX_WRITE_CONNECTION = 6
PLUGIN_FN_GET_SOCKS_ADDRESS = 7
PLUGIN_FN_SET_SOCKS_ADDRESS = 8
PLUGIN_FN_GET_CONNECTING_PROCESS = 9
PLUGIN_FN_GET_PROCESS_NAME = 10
PLUGIN_FN_TRANSLATE_ADDRESS = 11
PLUGIN_FN_MAP_ADDRESS = 12
PLUGIN_FN_TOR_RESOLVE_ADDRESS = 13
PLUGIN_FN_CHOOSE_EXIT = 14
PLUGIN_FN_GET_ROUTER_INFO = 15
PLUGIN_FN_IS_ROUTER_BANNED = 16
PLUGIN_FN_BAN_ROUTER = 17
PLUGIN_FN_GET_COUNTRY_ID = 18
PLUGIN_FN_GET_COUNTRY_NAME = 19
PLUGIN_FN_GET_TIME_DELTA = 20
PLUGIN_FN_CRYPTO_RAND_INT = 21
PLUGIN_FN_RANDOMIZE_BUFFER = 22
PLUGIN_FN_GET_CONFIGURATION_VALUE = 23
PLUGIN_FN_SET_CONFIGURATION_VALUE = 24
PLUGIN_FN_INTERCEPT_PROCESS = 25
PLUGIN_FN_CREATE_INTERCEPTED_PROCESS = 26
PLUGIN_FN_RELEASE_PROCESS = 27
PLUGIN_FN_IS_PROCESS_INTERCEPTED = 28
PLUGIN_FN_CREATE_CONNECTION = 29
PLUGIN_FN_GET_CONNECTION_PARAM = 30
PLUGIN_FN_ACCEPT_CLIENT = 31
PLUGIN_FN_HS_SEND_REPLY = 32
PLUGIN_FN_AS_FROM_IP = 33
PLUGIN_FN_GET_AS_PATHS = 34
PLUGIN_FN_IS_AS_PATH_SAFE = 35
PLUGIN_FN_TOR_MALLOC = 36
PLUGIN_FN_TOR_FREE = 37
PLUGIN_FN_SAFE_MALLOC = 38
PLUGIN_FN_SAFE_FREE = 39
PLUGIN_FN_WRITE_PROTECTED_FILE = 40
PLUGIN_FN_APPEND_TO_PROTECTED_FILE = 41
PLUGIN_FN_READ_PROTECTED_FILE = 42
PLUGIN_FN_PROTECTED_FILE_EXISTS = 43
PLUGIN_FN_TOR_GZIP_COMPRESS = 44
PLUGIN_FN_TOR_GZIP_UNCOMPRESS = 45
PLUGIN_FN_TOR_ZLIB_NEW = 46
PLUGIN_FN_TOR_ZLIB_PROCESS = 47
PLUGIN_FN_TOR_ZLIB_FREE = 48
PLUGIN_FN_DETECT_COMPRESSION_METHOD = 49
PLUGIN_FN_GET_LANG_STR = 50
PLUGIN_FN_LANG_CHANGE_DIALOG_STRINGS = 51

PLUGIN_UNLOAD_ON_DEMAND = 1
PLUGIN_UNLOAD_RELOAD = 2
PLUGIN_UNLOAD_AT_EXIT = 3
PLUGIN_UNLOAD_MUST_UNLOAD = 4
PLUGIN_UNLOAD_CANCEL = 0

; to be added to ".data" or to ".data?"
AdvTor_vars	macro
	functions	dd	?
	hPlugin		dd	?
endm

; The following macros can be used instead of AdvTor_InitPlugin.
;	AdvTor_Init	offset plugin_description
;		...
;		plugin_initalization
;		...
;	AdvTor_Init_end
;
AdvTor_Init	macro	at_description
AdvTor_InitPlugin	PROC	uses esi edi ebx _hPlugin:DWORD,version:DWORD,lpDescription:DWORD,lpFunctions:DWORD
	push	lpFunctions
	pop	functions
	push	_hPlugin
	pop	hPlugin
	mov	edi,lpDescription
	lea	edx,at_description
	.while byte ptr[edx]
		mov	al,[edx]
		stosb
		inc	edx
	.endw
	mov	al,0
	stosb
endm

AdvTor_Init_Lang	macro	at_lang_id,at_description
AdvTor_InitPlugin	PROC	uses esi edi ebx _hPlugin:DWORD,version:DWORD,lpDescription:DWORD,lpFunctions:DWORD
	push	lpFunctions
	pop	functions
	push	_hPlugin
	pop	hPlugin
	.if version < 0002000d
		xor	eax,eax
		ret
	.endif
	AdvTor_lang_get_string	at_lang_id,at_description
	mov	edx,eax
	mov	edi,lpDescription
	.while byte ptr[edx]
		mov	al,[edx]
		stosb
		inc	edx
	.endw
	mov	al,0
	stosb
endm


AdvTor_Init_end	macro
AdvTor_InitPlugin	ENDP
endm

; these macros assume that lpFunctions is saved to a variable called "functions" and that the plugin handler is saved to a variable called "hPlugin"

AdvTor_Log	macro	at_severity,at_message
	push	at_message
	push	at_severity
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_LOG*4]
	call	eax
endm

AdvTor_TorIsStarted	macro
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_TOR_IS_STARTED*4]
	call	eax
endm

AdvTor_GetConnectionCount	macro
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_GET_CONNECTION_COUNT*4]
	call	eax
endm

AdvTor_GetConnections	macro	at_buffer,at_count
	push	at_count
	push	at_buffer
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_GET_CONNECTIONS*4]
	call	eax
endm

AdvTor_CloseConnection	macro	at_conn
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_CLOSE_CONNECTION*4]
	call	eax
endm

AdvTor_ConnectionRead	macro	at_conn
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_READ_CONNECTION*4]
	call	eax
endm

AdvTor_ConnectionWrite	macro	at_conn
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IDX_WRITE_CONNECTION*4]
	call	eax
endm

AdvTor_GetSocksAddress	macro	at_conn,at_orig
	push	at_orig
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_SOCKS_ADDRESS*4]
	call	eax
endm

AdvTor_SetSocksAddress	macro	at_conn,at_addr,at_cmd
	push	at_cmd
	push	at_addr
	push	at_conn
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_SET_SOCKS_ADDRESS*4]
	call	eax
endm

AdvTor_GetConnectingProcess	macro	at_conn
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_CONNECTING_PROCESS*4]
	call	eax
endm

AdvTor_GetProcessName	macro	at_conn,at_buffer
	push	at_buffer
	push	at_conn
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_PROCESS_NAME*4]
	call	eax
endm

AdvTor_Translate_Address	macro	at_orig,at_new
	push	at_new
	push	at_orig
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TRANSLATE_ADDRESS*4]
	call	eax
endm

AdvTor_MapAddress	macro	at_orig,at_new
	push	at_new
	push	at_orig
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_MAP_ADDRESS*4]
	call	eax
endm

AdvTor_TorResolveAddress	macro	at_addr,at_reverse
	push	at_reverse
	push	at_addr
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_RESOLVE_ADDRESS*4]
	call	eax
endm

AdvTor_ChooseExit	macro	at_flags,at_after,at_range_low,at_range_high,at_bandwidth,at_country,at_conn,at_buffer
	push	at_buffer
	push	at_conn
	push	at_country
	push	at_bandwidth
	push	at_range_high
	push	at_range_low
	push	at_after
	push	at_flags
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_CHOOSE_EXIT*4]
	call	eax
endm

AdvTor_GetRouterInfo	macro	at_index,at_ip,at_nickname,at_routerinfo
	push	at_routerinfo
	push	at_nickname
	push	at_ip
	push	at_index
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_ROUTER_INFO*4]
	call	eax
endm

AdvTor_IsRouterBanned	macro	at_ip,at_nickname
	push	at_nickname
	push	at_ip
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IS_ROUTER_BANNED*4]
	call	eax
endm

AdvTor_BanRouter	macro	at_ip,at_type,at_isbanned
	push	at_isbanned
	push	at_type
	push	at_ip
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_BAN_ROUTER*4]
	call	eax
endm

AdvTor_GetCountryId	macro	at_ip
	push	at_ip
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_COUNTRY_ID*4]
	call	eax
endm

AdvTor_GetCountryName	macro	at_ip
	push	at_ip
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_COUNTRY_NAME*4]
	call	eax
endm

AdvTor_GetTimeDelta	macro
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_TIME_DELTA*4]
	call	eax
endm

AdvTor_CryptoRandInt	macro	at_max
	push	at_max
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_CRYPTO_RAND_INT*4]
	call	eax
endm

AdvTor_RandomizeBuffer	macro	at_buffer,at_size
	push	at_size
	push	at_buffer
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_RANDOMIZE_BUFFER*4]
	call	eax
endm

AdvTor_GetConfigurationValue	macro	at_option,at_buffer,at_size,at_toropt
	push	at_toropt
	push	at_size
	push	at_buffer
	push	at_option
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_CONFIGURATION_VALUE*4]
	call	eax
endm

AdvTor_SetConfigurationValue	macro	at_option,at_buffer
	push	at_buffer
	push	at_option
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_SET_CONFIGURATION_VALUE*4]
	call	eax
endm

AdvTor_InterceptProcess	macro	at_pid,at_flags,at_localaddr
	push	at_localaddr
	push	at_flags
	push	at_pid
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_INTERCEPT_PROCESS*4]
	call	eax
endm

AdvTor_CreateInterceptedProcess	macro	at_exename,at_flags,at_localaddr
	push	at_localaddr
	push	at_flags
	push	at_exename
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_CREATE_INTERCEPTED_PROCESS*4]
	call	eax
endm

AdvTor_ReleaseProcess	macro	at_pid
	push	at_pid
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_RELEASE_PROCESS*4]
	call	eax
endm

AdvTor_IsProcessIntercepted	macro	at_pid
	push	at_pid
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IS_PROCESS_INTERCEPTED*4]
	call	eax
endm

AdvTor_CreateConnection	macro	at_addr,at_port,at_excl,at_param
	push	at_param
	push	at_excl
	push	at_port
	push	at_addr
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_CREATE_CONNECTION*4]
	call	eax
endm

AdvTor_GetConnectionParam	macro	at_conn
	push	at_conn
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_CONNECTION_PARAM*4]
	call	eax
endm

AdvTor_AcceptClient	macro	at_socket,at_addr,at_port,at_excl,at_param
	push	at_param
	push	at_excl
	push	at_port
	push	at_addr
	push	at_socket
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_ACCEPT_CLIENT*4]
	call	eax
endm

AdvTor_HS_SendReply	macro	at_client,at_buffer,at_size
	push	at_size
	push	at_buffer
	push	at_client
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_HS_SEND_REPLY*4]
	call	eax
endm

AdvTor_ASFromIP	macro	at_ip
	push	at_ip
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_AS_FROM_IP*4]
	call	eax
endm

AdvTor_GetASPaths	macro	at_iplist,at_buffer,at_bufsize
	push	at_bufsize
	push	at_buffer
	push	at_iplist
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_AS_PATHS*4]
	call	eax
endm

AdvTor_IsASPathSafe	macro	at_aspaths
	push	at_aspaths
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_IS_AS_PATH_SAFE*4]
	call	eax
endm

AdvTor_malloc	macro	at_size
	push	at_size
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_MALLOC*4]
	call	eax
endm

AdvTor_free	macro	at_buffer
	push	at_buffer
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_FREE*4]
	call	eax
endm

AdvTor_safe_malloc	macro	at_size
	push	at_size
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_SAFE_MALLOC*4]
	call	eax
endm

AdvTor_safe_free	macro	at_buffer
	push	at_buffer
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_SAFE_FREE*4]
	call	eax
endm

AdvTor_write_protected_file	macro	at_fname,at_buffer,at_size
	push	at_size
	push	at_buffer
	push	at_fname
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_WRITE_PROTECTED_FILE*4]
	call	eax
endm

AdvTor_append_to_protected_file	macro	at_fname,at_buffer,at_size
	push	at_size
	push	at_buffer
	push	at_fname
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_APPEND_TO_PROTECTED_FILE*4]
	call	eax
endm

AdvTor_read_protected_file	macro	at_fname,at_buffer
	push	at_buffer
	push	at_fname
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_READ_PROTECTED_FILE*4]
	call	eax
endm

AdvTor_protected_file_exists	macro	at_fname
	push	at_fname
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_PROTECTED_FILE_EXISTS*4]
	call	eax
endm

AdvTor_gzip_compress	macro	at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_method
	push	at_method
	push	at_in_len
	push	at_buffer_in
	push	at_out_len
	push	at_buffer_out
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_GZIP_COMPRESS*4]
	call	eax
	add	esp,4*5
endm

AdvTor_gzip_uncompress	macro	at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_method,at_complete_only,at_log_level
	push	at_log_level
	push	at_complete_only
	push	at_method
	push	at_in_len
	push	at_buffer_in
	push	at_out_len
	push	at_buffer_out
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_GZIP_UNCOMPRESS*4]
	call	eax
	add	esp,4*7
endm

AdvTor_zlib_new	macro	at_compress,at_method
	push	at_method
	push	at_compress
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_ZLIB_NEW*4]
	call	eax
	add	esp,4*2
endm

AdvTor_zlib_process	macro	at_state,at_buffer_out,at_out_len,at_buffer_in,at_in_len,at_finish
	push	at_finish
	push	at_in_len
	push	at_buffer_in
	push	at_out_len
	push	at_buffer_out
	push	at_state
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_ZLIB_PROCESS*4]
	call	eax
	add	esp,4*6
endm

AdvTor_zlib_free	macro	at_state
	push	at_state
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_TOR_ZLIB_FREE*4]
	call	eax
	add	esp,4
endm

AdvTor_detect_compression_method	macro	at_buffer_in,at_in_len
	push	at_in_len
	push	at_buffer_in
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_DETECT_COMPRESSION_METHOD*4]
	call	eax
	add	esp,8
endm

AdvTor_lang_get_string	macro	at_str_id,at_default_str
	push	at_default_str
	push	at_str_id
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_GET_LANG_STR*4]
	call	eax
endm

AdvTor_lang_change_dialog_strings	macro	at_dlg,at_lang_info_list
	push	at_lang_info_list
	push	at_dlg
	push	hPlugin
	mov	eax,functions
	mov	eax,[eax+PLUGIN_FN_LANG_CHANGE_DIALOG_STRINGS*4]
	call	eax
endm


LOG_DEBUG = 8
; Info-level severity: for messages that appear frequently during normal operation.
LOG_INFO = 7
; Notice-level severity: for messages that appear infrequently during normal operation; that the user will probably care about; and that are not errors.
LOG_ADDR = 6
; Proxy-level severity: for messages that appear when a new proxy request was received.
LOG_NOTICE = 5
; Warn-level severity: for messages that only appear when something has gone wrong.
LOG_WARN = 4
; Error-level severity: for messages that only appear when something has gone very wrong.
LOG_ERR = 3


; reference.left is used as a reference for width adjustments, if any
; the width remains unchanged
RESIZE_FLAG_NOCHANGE_WIDTH = 0
; the width equals reference.left
RESIZE_FLAG_FIXED_WIDTH = 1			; refWidthControl = width in pixels
; the width is adjusted to keep the same distance between newSize.right and the X coordinate of refWidthControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH = 4
; the width is adjusted to keep the same distance between newSize.right and the right margin of refWidthControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH = 8
; the width has same value as the width of refWidthControl
RESIZE_FLAG_SAME_AS_CONTROL_WIDTH_WIDTH = RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH
; the width is increased proportionally relative to refWidthControl
RESIZE_FLAG_RELATIVE_TO_WIDTH_WIDTH = 16
; the width is increased proportionally relative to the X coordinate of refWidthControl
RESIZE_FLAG_RELATIVE_TO_POS_LEFT_WIDTH = 32
; the width is increased proportionally relative to the right margin of refWidthControl
RESIZE_FLAG_RELATIVE_TO_POS_RIGHT_WIDTH = 64
; the width is adjusted to keep the same distance between newSize.right and the middle of refWidthControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH = 128
RESIZE_MASK_WIDTH_NEED_REF = (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_RELATIVE_TO_WIDTH_WIDTH or RESIZE_FLAG_RELATIVE_TO_POS_LEFT_WIDTH or RESIZE_FLAG_RELATIVE_TO_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH)

; reference.top is used as a reference for height adjustments, if any
; the height remains unchanged
RESIZE_FLAG_NOCHANGE_HEIGHT = 0
; the height equals reference.top
RESIZE_FLAG_FIXED_HEIGHT = 100h
; the height is adjusted to keep the same distance between newSize.bottom and the Y coordinate of refHeightControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT = 400h
; the height is adjusted to keep the same distance between newSize.bottom and the bottom margin of refHeightControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT = 800h
; the height has same value as the height of refHeightControl
RESIZE_FLAG_SAME_AS_CONTROL_HEIGHT_HEIGHT = RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT
; the height is increased proportionally relative to refHeightControl
RESIZE_FLAG_RELATIVE_TO_HEIGHT_HEIGHT = 1000h
; the height is increased proportionally relative to the Y coordinate of refHeightControl
RESIZE_FLAG_RELATIVE_TO_POS_TOP_HEIGHT = 2000h
; the height is increased proportionally relative to the bottom margin of refHeightControl
RESIZE_FLAG_RELATIVE_TO_POS_BOTTOM_HEIGHT = 4000h
; the height is adjusted to keep the same distance between newSize.bottom and the middle of refHeightControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_HEIGHT = 8000h
RESIZE_MASK_HEIGHT_NEED_REF = (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_HEIGHT or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT or RESIZE_FLAG_RELATIVE_TO_HEIGHT_HEIGHT or RESIZE_FLAG_RELATIVE_TO_POS_TOP_HEIGHT or RESIZE_FLAG_RELATIVE_TO_POS_BOTTOM_HEIGHT or RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_HEIGHT)

; reference.right is used as a reference for x-coordinate adjustments, if any
; the X coordinate remains unchanged
RESIZE_FLAG_NOCHANGE_POS_X = 0
; X equals reference.right
RESIZE_FLAG_FIXED_POS_X = 10000h
; X is adjusted to keep the same to the X coordinate of refPosXControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X = 20000h
; X is adjusted to keep the same to the right margin of refPosXControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X = 40000h
; X is adjusted proportinally to X of refPosXControl
RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_LEFT_POS_X = 80000h
; X is adjusted proportinally to the right margin of refPosXControl
RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_RIGHT_POS_X = 100000h
; X is adjusted to keep the same distance to the middle of refPosXControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_X = 200000h
RESIZE_MASK_POSX_NEED_REF = (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_X)

; reference.bottom is used as a reference for y-coordinate adjustments, if any
; the Y coordinate remains unchanged
RESIZE_FLAG_NOCHANGE_POS_Y = 0
; Y equals reference.bottom
RESIZE_FLAG_FIXED_POS_Y = 1000000h
; Y is adjusted to keep the same to the Y coordinate of refPosYControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y = 2000000h
; Y is adjusted to keep the same to the bottom margin of refPosYControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y = 4000000h
; Y is adjusted proportinally to Y of refPosYControl
RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_TOP_POS_Y = 8000000h
; Y is adjusted proportinally to the bottom margin of refPosYControl
RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_BOTTOM_POS_Y = 10000000h
; Y is adjusted to keep the same distance to the middle of refPosYControl
RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_Y = 20000000h
RESIZE_MASK_POSY_NEED_REF = (RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y or RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_TOP_POS_Y or RESIZE_FLAG_RELATIVE_TO_CONTROL_POS_BOTTOM_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_POS_Y)

resize_info_t	struct
	ctrlId			dd	?
	refWidthControl		dd	?
	refHeightControl	dd	?
	refPosXControl		dd	?
	refPosYControl		dd	?
	reference		RECT	<>
	_flags			dd	?
resize_info_t	ends

connection_info_t	struct
	connection_id		dd	?
	connection_type		dd	?
	connection_state	dd	?
	_address		dd	?
	socks_original_address	dd	?
	socks_final_address	dd	?
	reserved		dd	?
	lParam			dd	?
connection_info_t	ends


_CONN_TYPE_MIN = 3
; Type for sockets listening for OR connections.
CONN_TYPE_OR_LISTENER = 3
; A bidirectional TLS connection transmitting a sequence of cells. May be from an OR to an OR, or from an OP to an OR.
CONN_TYPE_OR = 4
; A TCP connection from an onion router to a stream's destination.
CONN_TYPE_EXIT = 5
; Type for sockets listening for SOCKS connections.
CONN_TYPE_AP_LISTENER = 6
; A SOCKS proxy connection from the user application to the onion proxy.
CONN_TYPE_AP = 7
; Type for sockets listening for HTTP connections to the directory server.
CONN_TYPE_DIR_LISTENER = 8
; Type for HTTP connections to the directory server.
CONN_TYPE_DIR = 9
; Connection from the main process to a CPU worker process.
CONN_TYPE_CPUWORKER = 10
; Type for listening for connections from user interface process.
CONN_TYPE_CONTROL_LISTENER = 11
; Type for connections from user interface process.
CONN_TYPE_CONTROL = 12
; Type for sockets listening for transparent connections redirected by pf or netfilter.
CONN_TYPE_AP_TRANS_LISTENER = 13
; Type for sockets listening for transparent connections redirected by natd.
CONN_TYPE_AP_NATD_LISTENER = 14
; Type for sockets listening for DNS requests.
CONN_TYPE_AP_DNS_LISTENER = 15
_CONN_TYPE_MAX = 15


; State for any listener connection.
LISTENER_STATE_READY = 0

_CPUWORKER_STATE_MIN = 1
; State for a connection to a cpuworker process that's idle.
CPUWORKER_STATE_IDLE = 1
; State for a connection to a cpuworker process that's processing a handshake.
CPUWORKER_STATE_BUSY_ONION = 2
_CPUWORKER_STATE_MAX = 2

CPUWORKER_TASK_ONION = CPUWORKER_STATE_BUSY_ONION

_OR_CONN_STATE_MIN = 1
; State for a connection to an OR: waiting for connect() to finish.
OR_CONN_STATE_CONNECTING = 1
; State for a connection to an OR: waiting for proxy command to flush.
OR_CONN_STATE_PROXY_FLUSHING = 2
; State for a connection to an OR: waiting for proxy response.
OR_CONN_STATE_PROXY_READING = 3
; State for a connection to an OR or client: SSL is handshaking, not done yet.
OR_CONN_STATE_TLS_HANDSHAKING = 4
; State for a connection to an OR: We're doing a second SSL handshake for renegotiation purposes.
OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING = 5
; State for a connection at an OR: We're waiting for the client to renegotiate.
OR_CONN_STATE_TLS_SERVER_RENEGOTIATING = 6
; State for a connection to an OR: We're done with our SSL handshake, but we haven't yet negotiated link protocol versions and sent a netinfo cell.
OR_CONN_STATE_OR_HANDSHAKING = 7
; State for a connection to an OR: Ready to send/receive cells.
OR_CONN_STATE_OPEN = 8
_OR_CONN_STATE_MAX = 8

_EXIT_CONN_STATE_MIN = 1
; State for an exit connection: waiting for response from dns farm.
EXIT_CONN_STATE_RESOLVING = 1
; State for an exit connection: waiting for connect() to finish.
EXIT_CONN_STATE_CONNECTING = 2
; State for an exit connection: open and ready to transmit data.
EXIT_CONN_STATE_OPEN = 3
; State for an exit connection: waiting to be removed.
EXIT_CONN_STATE_RESOLVEFAILED = 4
_EXIT_CONN_STATE_MAX = 4

; The AP state values must be disjoint from the EXIT state values.
_AP_CONN_STATE_MIN = 5
; State for a SOCKS connection: waiting for SOCKS request.
AP_CONN_STATE_SOCKS_WAIT = 5
; State for a SOCKS connection: got a y.onion URL; waiting to receive rendezvous descriptor.
AP_CONN_STATE_RENDDESC_WAIT = 6
; The controller will attach this connection to a circuit; it isn't our job to do so.
AP_CONN_STATE_CONTROLLER_WAIT = 7
; State for a SOCKS connection: waiting for a completed circuit.
AP_CONN_STATE_CIRCUIT_WAIT = 8
; State for a SOCKS connection: sent BEGIN, waiting for CONNECTED.
AP_CONN_STATE_CONNECT_WAIT = 9
; State for a SOCKS connection: sent RESOLVE, waiting for RESOLVED.
AP_CONN_STATE_RESOLVE_WAIT = 10
; State for a SOCKS connection: ready to send and receive.
AP_CONN_STATE_OPEN = 11
; State for a transparent natd connection: waiting for original destination.
AP_CONN_STATE_NATD_WAIT = 12
_AP_CONN_STATE_MAX = 12

_DIR_CONN_STATE_MIN = 1
; State for connection to directory server: waiting for connect().
DIR_CONN_STATE_CONNECTING = 1
; State for connection to directory server: sending HTTP request.
DIR_CONN_STATE_CLIENT_SENDING = 2
; State for connection to directory server: reading HTTP response.
DIR_CONN_STATE_CLIENT_READING = 3
; State for connection to directory server: happy and finished.
DIR_CONN_STATE_CLIENT_FINISHED = 4
; State for connection at directory server: waiting for HTTP request.
DIR_CONN_STATE_SERVER_COMMAND_WAIT = 5
; State for connection at directory server: sending HTTP response.
DIR_CONN_STATE_SERVER_WRITING = 6
_DIR_CONN_STATE_MAX = 6

_CONTROL_CONN_STATE_MIN = 1
; State for a control connection: Authenticated and accepting v1 commands.
CONTROL_CONN_STATE_OPEN = 1
; State for a control connection: Waiting for authentication; speaking protocol v1.
CONTROL_CONN_STATE_NEEDAUTH = 2
_CONTROL_CONN_STATE_MAX = 2

DIGEST_LEN = 20

router_info_t	struct
	cbSize			dd	?
	_index			dd	?
	_address		dd	?	; < Location of OR: either a hostname or an IP address.
	nickname		dd	?	; < Human-readable OR name.

	identity_digest		db	DIGEST_LEN dup(?)
	published_on		dd	?	; Declared publication time of the descriptor.

	_addr			dd	?	; < IPv4 address of OR, in host order.
	or_port			dw	?	; < Port for TLS connections.
	dir_port		dw	?	; < Port for HTTP directory connections.

	platform		dd	?	; < What software/operating system is this OR using?

	; link info
	bandwidthrate		dd	?	; < How many bytes does this OR add to its token bucket per second?
	bandwidthburst		dd	?	; < How large is this OR's token bucket?
	; How many bytes/s is this router known to handle?
	bandwidthcapacity	dd	?
	exit_policy		dd	?	; < What streams will this OR permit to exit?  NULL for 'reject *:*'.
	uptime			dd	?	; < How many seconds the router claims to have been up
	declared_family		dd	?	; < Nicknames of router which this router claims are its family.
	contact_info		dd	?	; < Declared contact info for this router.
	routerflags		dd	?
router_info_t	ends

lang_dlg_info	struct
	ctrlId	dd	?
	langId	dd	?
lang_dlg_info	ends

BAN_EXIT = 'X'
BAN_GENERAL = 0

INTERCEPT_FLAG_FAKE_LOCAL_TIME = 2
INTERCEPT_FLAG_FAKE_IPS = 8
INTERCEPT_FLAG_TCP_ONLY = 16
INTERCEPT_FLAG_CHANGE_ICON = 32
INTERCEPT_FLAG_EXCLUSIVE_EXIT = 64
INTERCEPT_FLAG_NOTIFY_USER = 512
INTERCEPT_FLAG_IGNORE_EXISTING_CONNECTIONS = 2048

EXCLUSIVITY_UNDEFINED = 0
EXCLUSIVITY_GENERAL = 1
EXCLUSIVITY_PROCESS = 2
EXCLUSIVITY_PLUGIN = 3

HIDDENSERVICE_REGISTER_SERVICE = 1
HIDDENSERVICE_UNREGISTER_SERVICE = 0
HIDDENSERVICE_REGISTER_CLIENT = 3
HIDDENSERVICE_UNREGISTER_CLIENT = 2

AS_UNKNOWN = 65536

NO_METHOD = 0
GZIP_METHOD = 1
ZLIB_METHOD = 2
UNKNOWN_METHOD = 3

TOR_ZLIB_OK = 0
TOR_ZLIB_DONE = 1
TOR_ZLIB_BUF_FULL = 2
TOR_ZLIB_ERR = 3

CP_UTF8 = 65001
