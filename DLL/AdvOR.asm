.586
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\wsock32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\wsock32.lib

ShowProcesses		PROTO	:DWORD
SetHook			PROTO	:DWORD,:DWORD,:DWORD,:DWORD
NewThread		PROTO	:DWORD,:DWORD,:DWORD
GetKernelBase		PROTO	:DWORD
_OpenProcess		PROTO	:DWORD
PipeThread		PROTO	:DWORD
TORHook			PROTO	:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetConnInfo		PROTO	:DWORD,:DWORD,:DWORD,:DWORD
include	lang.h
include	user32.h
include	resolve.h
include	socket.h
include	excl.h
include	tree.h


LOG_ERR = 3
LOG_WARN = 4
LOG_NOTICE = 5
LOG_ADDR = 6
LOG_INFO = 7
LOG_DEBUG = 8

MAX_PROC_PATH = 512

HOOK_CONNECT = 1
HOOK_WSACONNECT = 2
HOOK_GETHOSTNAME = 4
HOOK_GETHOSTBYNAME = 8
HOOK_WSAASYNCGETHOSTBYNAME = 16
HOOK_GETHOSTBYADDR = 32
HOOK_WSAASYNCGETHOSTBYADDR = 64
;HOOK_GETNAMEINFO = 128
;HOOK_GETADDRINFO = 128
HOOK_GETSYSTEMTIME = 100h
HOOK_SETSYSTEMTIME = 200h
HOOK_GETLOCALTIME = 400h
HOOK_SETLOCALTIME = 800h
HOOK_GETPROCESSTIMES = 1000h
HOOK_GETTHREADTIMES = 2000h
HOOK_GETSYSTEMTIMEASFILETIME = 4000h
HOOK_GETFILETIME = 8000h
HOOK_SETFILETIME = 10000h
HOOK_FINDFIRSTFILE = 20000h
HOOK_FINDNEXTFILE = 40000h
HOOK_CREATEPROCESSA = 1000000h
HOOK_CREATEPROCESSW = 2000000h
HOOK_CREATEPROCESSASUSERA = 4000000h
HOOK_CREATEPROCESSASUSERW = 8000000h
HOOK_SOCKET = 10000000h


connection_info	struct
	magic		dd	?		;'CONN'
	_key		dd	?
	source_ip	dd	?
	source_port	dw	?
	dest_ip		dd	?
	extra_info	db	512 dup(?)
connection_info	ends

LV_ITEMW	struct
	imask		dd	?
	iItem		dd	?
	iSubItem	dd	?
	state		dd	?
	stateMask	dd	?
	pszText		dd	?
	cchTextMax	dd	?
	iImage		dd	?
	lParam		dd	?
	iIndent		dd	?
	iGroupId	dd	?
	cColumns	dd	?
	puColumns	dd	?
LV_ITEMW	ends

PROCESSENTRY32W	struct
	dwSize			dd	?
	cntUsage		dd	?
	th32ProcessID		dd	?
	th32DefaultHeapID	dd	?
	th32ModuleID		dd	?
	cntThreads		dd	?
	th32ParentProcessID	dd	?
	pcPriClassBase		dd	?
	dwFlags			dd	?
	szExeFile		db	MAX_PATH*2 dup(?)
PROCESSENTRY32W	ends

MODULEENTRY32W	struct
	dwSize		dd	?
	th32ModuleID	dd	?
	th32ProcessID	dd	?
	GlblcntUsage	dd	?
	ProccntUsage	dd	?
	modBaseAddr	dd	?
	modBaseSize	dd	?
	hModule		dd	?
	szModule	db	MAX_MODULE_NAME32*2+2 dup(?)
	szExePath	db	MAX_PATH*2 dup(?)
MODULEENTRY32W	ends


.data?
	ctx		CONTEXT	<>
	hDialog		dd	?
	hThisInstance	dd	?
	Log		dd	?
	hKernel		dd	?
	hWsock		dd	?
	hAdvapi		dd	?
	hNtdll		dd	?
	hPipe		dd	?
	hEvent		dd	?
	user32data
	_VirtualAllocEx	dd	?
	_VirtualFreeEx	dd	?
	_CreateRemoteThread dd	?
	_LoadLibrary	dd	?
	_GetProcAddress	dd	?
	_ExitThread	dd	?
	_GetModuleHandle dd	?
	_GetModuleHandleA dd	?
	_GetLastError	dd	?
	_FreeLibrary	dd	?
	_NTCreateThreadEx dd	?
	_OpenProcessToken dd	?
	_LookupPrivilegeValueA dd ?
	_AdjustTokenPrivileges dd ?
	_GetTokenInformation dd	?
	thrid		dd	?
	_hDialog	dd	?
	_pid		dd	?
	saddr		sockaddr_in	<>
	lang_data
	filename	db	8192 dup(?)
	token_info_size	dd	?
	token_info	db	512 dup(?)
	lppew		PROCESSENTRY32W <>
	lvit		LV_ITEMW	<>
	lvcol		LV_COLUMN	<>
	connections_allowed	db	?
	hProcess	dd	?
	hSnapshot	dd	?
	kernelBase	dd	?
	unloaded	db	?
	pidname		db	257 dup(?)
	localhostname	db	256 dup(?)
	pipename	db	256 dup(?)
	pipe_key	dd	?
	conn_info_cache	dd	?
	conn_info_cnt	dd	?
	sysflags	dd	?			;1	hook_wsock
							;2	hook_gettime
							;4	kernel_delta
							;8	fake_ip
							;16	tcp_only
							;32	change_icon
							;256
							;512	show errors in a messagebox
							;1024	recursivity check
							;2048	new process created, don't check existing connections
	systemtimedelta	dd	?,?
	iphlpdata
	resolve_data
	socket_data
	excl_data
	saveconnect	dd	?,?			;size,hMem
			db	100 dup(?)		;old bytes
	savewsaconnect	dd	?,?
			db	100 dup(?)
	getsystemtime	dd	?,?
			db	100 dup(?)
	setsystemtime	dd	?,?
			db	100 dup(?)
	getlocaltime	dd	?,?
			db	100 dup(?)
	setlocaltime	dd	?,?
			db	100 dup(?)
	getprocesstimes	dd	?,?
			db	100 dup(?)
	getthreadtimes	dd	?,?
			db	100 dup(?)
	getsystemtimeasfiletime	dd	?,?
			db	100 dup(?)
	getfiletime	dd	?,?
			db	100 dup(?)
	setfiletime	dd	?,?
			db	100 dup(?)
	findfirstfile	dd	?,?
			db	100 dup(?)
	findnextfile	dd	?,?
			db	100 dup(?)
	createprocessa	dd	?,?
			db	100 dup(?)
	createprocessw	dd	?,?
			db	100 dup(?)
	winexec		dd	?,?
			db	100 dup(?)
	createprocessasusera dd	?,?
			db	100 dup(?)
	createprocessasuserw dd	?,?
			db	100 dup(?)
	pipeData	db	1024 dup(?)
	processes	dd	4096 dup(?)
	pipeNotifyMsg	db	1024 dup(?)
	hooklist	dd	1024 dup(?)
	newprocess	db	?
	buftmp		db	16384 dup(?)
	buftmp1		db	16384 dup(?)
	buftmp2		db	16384 dup(?)

.code
include	general.h
opc_table:
	db	-1	;00
	db	-1	;01
	db	-1	;02
	db	-1	;03
	db	-1	;04
	db	5	;05
	db	1	;06
	db	1	;07
	db	-1	;08
	db	-1	;09
	db	-1	;0a
	db	-1	;0b
	db	-1	;0c
	db	5	;0d
	db	1	;0e
	db	-2	;0f
	db	-1	;10
	db	-1	;11
	db	-1	;12
	db	-1	;13
	db	-1	;14
	db	5	;15
	db	1	;16
	db	1	;17
	db	-1	;18
	db	-1	;19
	db	-1	;1a
	db	-1	;1b
	db	-1	;1c
	db	5	;1d
	db	1	;1e
	db	1	;1f
	db	-1	;20
	db	-1	;21
	db	-1	;22
	db	-1	;23
	db	-1	;24
	db	5	;25
	db	1	;26
	db	1	;27
	db	-1	;28
	db	-1	;29
	db	-1	;2a
	db	-1	;2b
	db	-1	;2c
	db	5	;2d
	db	1	;2e
	db	1	;2f
	db	-1	;30
	db	-1	;31
	db	-1	;32
	db	-1	;33
	db	-1	;34
	db	5	;35
	db	1	;36
	db	1	;37
	db	-1	;38
	db	-1	;39
	db	-1	;3a
	db	-1	;3b
	db	-1	;3c
	db	5	;3d
	db	1	;3e
	db	1	;3f
	db	1	;40
	db	1	;41
	db	1	;42
	db	1	;43
	db	1	;44
	db	1	;45
	db	1	;46
	db	1	;47
	db	1	;48
	db	1	;49
	db	1	;4a
	db	1	;4b
	db	1	;4c
	db	1	;4d
	db	1	;4e
	db	1	;4f
	db	1	;50
	db	1	;51
	db	1	;52
	db	1	;53
	db	1	;54
	db	1	;55
	db	1	;56
	db	1	;57
	db	1	;58
	db	1	;59
	db	1	;5a
	db	1	;5b
	db	1	;5c
	db	1	;5d
	db	1	;5e
	db	1	;5f
	db	1	;60
	db	1	;61
	db	-1	;62
	db	-1	;63
	db	1	;64
	db	1	;65
	db	1	;66
	db	1	;67
	db	5	;68
	db	-3	;69 imm32+modrm
	db	2	;6a
	db	-4	;6b imm8+modrm
	db	1	;6c
	db	1	;6d
	db	1	;6e
	db	1	;6f
	db	2	;70
	db	2	;71
	db	2	;72
	db	2	;73
	db	2	;74
	db	2	;75
	db	2	;76
	db	2	;77
	db	2	;78
	db	2	;79
	db	2	;7a
	db	2	;7b
	db	2	;7c
	db	2	;7d
	db	2	;7e
	db	2	;7f
	db	-4	;80
	db	-3	;81
	db	-4	;82
	db	-4	;83
	db	-1	;84
	db	-1	;85
	db	-1	;86
	db	-1	;87
	db	-1	;88
	db	-1	;89
	db	-1	;8a
	db	-1	;8b
	db	-1	;8c
	db	-1	;8d
	db	-1	;8e
	db	-1	;8f
	db	1	;90
	db	1	;91
	db	1	;92
	db	1	;93
	db	1	;94
	db	1	;95
	db	1	;96
	db	1	;97
	db	1	;98
	db	1	;99
	db	7	;9a
	db	1	;9b
	db	1	;9c
	db	1	;9d
	db	1	;9e
	db	1	;9f
	db	5	;a0
	db	5	;a1
	db	5	;a2
	db	5	;a3
	db	1	;a4
	db	1	;a5
	db	1	;a6
	db	1	;a7
	db	2	;a8
	db	5	;a9
	db	1	;aa
	db	1	;ab
	db	1	;ac
	db	1	;ad
	db	1	;ae
	db	1	;af
	db	2	;b0
	db	2	;b1
	db	2	;b2
	db	2	;b3
	db	2	;b4
	db	2	;b5
	db	2	;b6
	db	2	;b7
	db	5	;b8
	db	5	;b9
	db	5	;ba
	db	5	;bb
	db	5	;bc
	db	5	;bd
	db	5	;be
	db	5	;bf
	db	-4	;c0
	db	-4	;c1
	db	3	;c2
	db	1	;c3
	db	-1	;c4
	db	-1	;c5
	db	-4	;c6
	db	-3	;c7
	db	4	;c8
	db	1	;c9
	db	3	;ca
	db	1	;cb
	db	1	;cc
	db	2	;cd
	db	1	;ce
	db	1	;cf
	db	2	;d0
	db	-1	;d1
	db	-1	;d2
	db	-1	;d3
	db	2	;d4
	db	2	;d5
	db	1	;d6
	db	1	;d7
	db	-1	;d8
	db	-1	;d9
	db	-1	;da
	db	-1	;db
	db	-1	;dc
	db	-1	;dd
	db	-1	;de
	db	-1	;df
	db	2	;e0
	db	2	;e1
	db	2	;e2
	db	2	;e3
	db	2	;e4
	db	2	;e5
	db	2	;e6
	db	2	;e7
	db	5	;e8
	db	5	;e9
	db	7	;ea
	db	2	;eb
	db	1	;ec
	db	1	;ed
	db	1	;ee
	db	1	;ef
	db	1	;f0
	db	1	;f1
	db	1	;f2
	db	1	;f3
	db	1	;f4
	db	1	;f5
	db	-4	;f6
	db	-1	;f7
	db	1	;f8
	db	1	;f9
	db	1	;fa
	db	1	;fb
	db	1	;fc
	db	1	;fd
	db	-1	;fe
	db	-1	;ff

opc_0f	db	-1	;00
	db	-1	;01
	db	-1	;02
	db	-1	;03
	db	2	;04 n/a
	db	2	;05
	db	2	;06
	db	2	;07
	db	2	;08
	db	2	;09
	db	2	;0a
	db	2	;0b
	db	2	;0c
	db	2	;0d
	db	2	;0e
	db	2	;0f
	db	2	;10 n/a
	db	2	;11 n/a
	db	2	;12 n/a
	db	2	;13 n/a
	db	2	;14 n/a
	db	2	;15 n/a
	db	2	;16 n/a
	db	2	;17 n/a
	db	2	;18 n/a
	db	2	;19 n/a
	db	2	;1a n/a
	db	2	;1b n/a
	db	2	;1c n/a
	db	2	;1d n/a
	db	2	;1e n/a
	db	2	;1f n/a
	db	3	;20
	db	3	;21
	db	3	;22
	db	3	;23
	db	3	;24
	db	2	;25 n/a
	db	3	;26
	db	2	;27 n/a
	db	2	;28 n/a
	db	2	;29 n/a
	db	2	;2a n/a
	db	2	;2b n/a
	db	2	;2c n/a
	db	2	;2d n/a
	db	2	;2e n/a
	db	2	;2f n/a
	db	2	;30
	db	2	;31
	db	2	;32
	db	2	;33
	db	2	;34 n/a
	db	2	;35 n/a
	db	2	;36 n/a
	db	2	;37 n/a
	db	2	;38 n/a
	db	2	;39 n/a
	db	2	;3a n/a
	db	2	;3b n/a
	db	2	;3c n/a
	db	2	;3d n/a
	db	2	;3e n/a
	db	2	;3f n/a
	db	-1	;40
	db	-1	;41
	db	-1	;42
	db	-1	;43
	db	-1	;44
	db	-1	;45
	db	-1	;46
	db	-1	;47
	db	-1	;48
	db	-1	;49
	db	-1	;4a
	db	-1	;4b
	db	-1	;4c
	db	-1	;4d
	db	-1	;4e
	db	-1	;4f
	db	2	;50 n/a
	db	2	;51 n/a
	db	2	;52 n/a
	db	2	;53 n/a
	db	2	;54 n/a
	db	2	;55 n/a
	db	2	;56 n/a
	db	2	;57 n/a
	db	2	;58 n/a
	db	2	;59 n/a
	db	2	;5a n/a
	db	2	;5b n/a
	db	2	;5c n/a
	db	2	;5d n/a
	db	2	;5e n/a
	db	2	;5f n/a
	db	-1	;60
	db	-1	;61
	db	-1	;62
	db	-1	;63
	db	-1	;64
	db	-1	;65
	db	-1	;66
	db	-1	;67
	db	-1	;68
	db	-1	;69
	db	-1	;6a
	db	-1	;6b
	db	-1	;6c n/a
	db	-1	;6d n/a
	db	-1	;6e
	db	-1	;6f
	db	-1	;70 n/a
	db	-1	;71 n/a
	db	-1	;72 n/a
	db	-1	;73 n/a
	db	-1	;74
	db	-1	;75
	db	-1	;76
	db	2	;77
	db	2	;78 n/a
	db	2	;79 n/a
	db	2	;7a n/a
	db	2	;7b n/a
	db	2	;7c n/a
	db	2	;7d n/a
	db	-1	;7e
	db	-1	;7f
	db	6	;80
	db	6	;81
	db	6	;82
	db	6	;83
	db	6	;84
	db	6	;85
	db	6	;86
	db	6	;87
	db	6	;88
	db	6	;89
	db	6	;8a
	db	6	;8b
	db	6	;8c
	db	6	;8d
	db	6	;8e
	db	6	;8f
	db	-1	;90
	db	-1	;91
	db	-1	;92
	db	-1	;93
	db	-1	;94
	db	-1	;95
	db	-1	;96
	db	-1	;97
	db	-1	;98
	db	-1	;99
	db	-1	;9a
	db	-1	;9b
	db	-1	;9c
	db	-1	;9d
	db	-1	;9e
	db	-1	;9f
	db	2	;a0
	db	2	;a1
	db	2	;a2
	db	-1	;a3
	db	-4	;a4
	db	-1	;a5
	db	2	;a6 n/a
	db	2	;a7 n/a
	db	2	;a8
	db	2	;a9
	db	2	;aa
	db	-1	;ab
	db	-4	;ac
	db	-1	;ad
	db	2	;ae n/a
	db	-1	;af
	db	-1	;b0
	db	-1	;b1
	db	-1	;b2
	db	-1	;b3
	db	-1	;b4
	db	-1	;b5
	db	-1	;b6
	db	-1	;b7
	db	-1	;b8 n/a
	db	-1	;b9 n/a
	db	-1	;ba n/a
	db	-1	;bb
	db	-1	;bc
	db	-1	;bd
	db	-1	;be
	db	-1	;bf
	db	-1	;c0
	db	-1	;c1
	db	2	;c2 n/a
	db	2	;c3 n/a
	db	2	;c4 n/a
	db	2	;c5 n/a
	db	2	;c6 n/a
	db	2	;c7 n/a
	db	2	;c8
	db	2	;c9
	db	2	;ca
	db	2	;cb
	db	2	;cc
	db	2	;cd
	db	2	;ce
	db	2	;cf
	db	-1	;d0 n/a
	db	-1	;d1
	db	-1	;d2
	db	-1	;d3
	db	-1	;d4 n/a
	db	-1	;d5
	db	-1	;d6 n/a
	db	-1	;d7 n/a
	db	-1	;d8
	db	-1	;d9
	db	-1	;da n/a
	db	-1	;db
	db	-1	;dc
	db	-1	;dd
	db	-1	;de n/a
	db	-1	;df
	db	2	;e0 n/a
	db	-1	;e1
	db	-1	;e2
	db	2	;e3 n/a
	db	2	;e4 n/a
	db	-1	;e5
	db	2	;e6 n/a
	db	2	;e7 n/a
	db	-1	;e8
	db	-1	;e9
	db	2	;ea n/a
	db	-1	;eb
	db	-1	;ec
	db	-1	;ed
	db	2	;ee n/a
	db	-1	;ef
	db	2	;f0 n/a
	db	-1	;f1
	db	-1	;f2
	db	-1	;f3
	db	2	;f4 n/a
	db	-1	;f5
	db	2	;f6 n/a
	db	2	;f7 n/a
	db	-1	;f8
	db	-1	;f9
	db	-1	;fa
	db	2	;fb n/a
	db	-1	;fc
	db	-1	;fd
	db	-1	;fe
	db	2	;ff n/a
_zero	dd	0

;bl=prefix, bh=delta
modrm:	mov	al,[esi]
	inc	bh
	mov	ah,al
	and	ax,0c00fh
	.if al==4
		inc	bh
	.elseif ax==5
		.if bl&2
			add	bh,2
		.else
			add	bh,4
		.endif
	.endif
	.if ah==40h
		inc	bh
	.elseif ah==80h
		.if bl&2
			add	bh,2
		.else
			add	bh,4
		.endif
	.endif
	ret


DllEntry PROC hInstance:DWORD,reason:DWORD,reserved1:DWORD
	.if reason==DLL_PROCESS_ATTACH
		push	hInstance
		pop	hThisInstance
		invoke	GetModuleFileNameW,hInstance,addr filename,4096
		mov	_VirtualAllocEx,0
		mov	hNtdll,0
		mov	hAdvapi,0
		mov	hKernel,0
		mov	_CreateRemoteThread,0
		mov	_OpenProcessToken,0
		resolve_init
		socket_init
		excl_init
		mov	connections_allowed,0
		mov	saveconnect,0
		mov	saveconnect[4],0
		mov	savewsaconnect,0
		mov	savewsaconnect[4],0
		mov	getsystemtime,0
		mov	getsystemtime[4],0
		mov	setsystemtime,0
		mov	setsystemtime[4],0
		mov	getlocaltime,0
		mov	getlocaltime[4],0
		mov	setlocaltime,0
		mov	setlocaltime[4],0
		mov	getprocesstimes,0
		mov	getprocesstimes[4],0
		mov	getthreadtimes,0
		mov	getthreadtimes[4],0
		mov	getsystemtimeasfiletime,0
		mov	getsystemtimeasfiletime[4],0
		mov	getfiletime,0
		mov	getfiletime[4],0
		mov	setfiletime,0
		mov	setfiletime[4],0
		mov	findfirstfile,0
		mov	findfirstfile[4],0
		mov	findnextfile,0
		mov	findnextfile[4],0
		mov	createprocessa,0
		mov	createprocessa[4],0
		mov	createprocessw,0
		mov	createprocessw[4],0
		mov	winexec,0
		mov	winexec[4],0
		mov	createprocessasusera,0
		mov	createprocessasusera[4],0
		mov	createprocessasuserw,0
		mov	createprocessasuserw[4],0
		user32init
		iphlpinit
		mov	kernelBase,0
		mov	systemtimedelta,0
		mov	sysflags,1
		mov	hDialog,0
		mov	unloaded,0
		mov	dword ptr pipeData,0
		mov	newprocess,0
		mov	dword ptr hooklist,0
		mov	hPipe,0
		lang_init
	.elseif reason==DLL_PROCESS_DETACH
	.elseif reason==DLL_THREAD_ATTACH
	.else
	.endif
	xor	eax,eax
	inc	eax
	ret
DllEntry Endp

user32init2
lang_procs
excl_procs
tree_procs

_advapi	db	'advapi32.dll',0
_opt	db	'OpenProcessToken',0
_lpv	db	'LookupPrivilegeValueA',0
_atp	db	'AdjustTokenPrivileges',0
_gti	db	'GetTokenInformation',0
_sdn	db	'SeDebugPrivilege',0
_stop	db	'SeTakeOwnershipPrivilege',0
selock	db	'SeLockMemoryPrivilege',0
SetProc	PROC	uses esi edi ebx lpLogFn:DWORD,hDlg:DWORD,_pipe:DWORD
	local	hToken:DWORD,luid:LUID
	local	tkp:TOKEN_PRIVILEGES
	call	u32_init
	lea	edi,pipename
	mov	edx,_pipe
	call	copyedx
	mov	al,0
	stosb
	invoke	LoadLibrary,addr _advapi
	mov	hAdvapi,eax
	.if eax
		invoke	GetProcAddress,hAdvapi,addr _opt
		mov	_OpenProcessToken,eax
		invoke	GetProcAddress,hAdvapi,addr _lpv
		.if eax==0
			mov	_OpenProcessToken,eax
		.endif
		mov	_LookupPrivilegeValueA,eax
		invoke	GetProcAddress,hAdvapi,addr _atp
		.if eax==0
			mov	_OpenProcessToken,eax
		.endif
		mov	_AdjustTokenPrivileges,eax
		invoke	GetProcAddress,hAdvapi,addr _gti
		.if eax==0
			mov	_OpenProcessToken,eax
		.endif
		mov	_GetTokenInformation,eax
		invoke	GetCurrentProcess
		mov	hProcess,eax
		.if eax && _OpenProcessToken
			lea	edx,hToken
			mov	hToken,0
			push	edx
			push	 TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY
			push	hProcess
			call	_OpenProcessToken
			.if eax
				push	hToken
				lea	edx,luid
				push	edx
				push	offset _sdn
				push	0
				call	_LookupPrivilegeValueA
				mov	tkp.PrivilegeCount,1
				mov	eax,luid.LowPart
				mov	tkp.Privileges.Luid.LowPart,eax
				mov	eax,luid.HighPart
				mov	tkp.Privileges.Luid.HighPart,eax
				mov	tkp.Privileges.Attributes,SE_PRIVILEGE_ENABLED
				push	0
				push	0
				push	0
				lea	edx,tkp
				push	edx
				push	0
				push	hToken
				call	_AdjustTokenPrivileges

				lea	edx,luid
				push	edx
				push	offset _stop
				push	0
				call	_LookupPrivilegeValueA
				mov	tkp.PrivilegeCount,1
				mov	eax,luid.LowPart
				mov	tkp.Privileges.Luid.LowPart,eax
				mov	eax,luid.HighPart
				mov	tkp.Privileges.Luid.HighPart,eax
				mov	tkp.Privileges.Attributes,SE_PRIVILEGE_ENABLED
				push	0
				push	0
				push	0
				lea	edx,tkp
				push	edx
				push	0
				push	hToken
				call	_AdjustTokenPrivileges

				lea	edx,luid
				push	edx
				push	offset selock
				push	0
				call	_LookupPrivilegeValueA
				mov	tkp.PrivilegeCount,1
				mov	eax,luid.LowPart
				mov	tkp.Privileges.Luid.LowPart,eax
				mov	eax,luid.HighPart
				mov	tkp.Privileges.Luid.HighPart,eax
				mov	tkp.Privileges.Attributes,SE_PRIVILEGE_ENABLED
				push	0
				push	0
				push	0
				lea	edx,tkp
				push	edx
				push	0
				push	hToken
				call	_AdjustTokenPrivileges

				mov	edx,[esp]
				mov	token_info_size,512
				push	offset token_info_size
				push	512
				push	offset token_info
				push	TokenUser
				push	edx
				call	_GetTokenInformation
				.if eax==0
					mov	token_info_size,0
				.endif
			.endif
			call	CloseHandle	;hProcess
		.endif
	.endif
	push	hDlg
	pop	hDialog
	push	lpLogFn
	pop	Log
	invoke	GetVersion
	.if eax>80000000h
		showLog	LANG_DLL_ERROR_1,msg1,LOG_WARN
		xor	eax,eax
		ret
	.endif
	user32SendDlgItemMessage	hDlg,12400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_ONECLICKACTIVATE or LVS_EX_CHECKBOXES or LVS_EX_FULLROWSELECT,LVS_EX_ONECLICKACTIVATE or LVS_EX_CHECKBOXES or LVS_EX_FULLROWSELECT
	mov	lvcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH
	mov	lvcol.fmt,LVCFMT_LEFT
	mov	lvcol.lx,300
	mov	lvcol.pszText,offset col1
	mov	lvcol.cchTextMax,sizeof col1
	mov	lvcol.iSubItem,0
	user32SendDlgItemMessage	hDlg,12400,LVM_INSERTCOLUMN,0,offset lvcol
	mov	lvcol.lx,100
	mov	lvcol.pszText,offset col2
	mov	lvcol.cchTextMax,sizeof col2
	user32SendDlgItemMessage	hDlg,12400,LVM_INSERTCOLUMN,1,offset lvcol
	invoke	ShowProcesses,hDlg
	invoke	CreateThread,0,0,addr PipeThread,0,0,addr thrid
	invoke	CloseHandle,0
	xor	eax,eax
	inc	eax
	ret
SetProc	ENDP

ShowProcesses	PROC	uses esi edi ebx hDlg:DWORD
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if eax==INVALID_HANDLE_VALUE
		ret
	.endif
	mov	hSnapshot,eax
	mov	lppew.dwSize,sizeof PROCESSENTRY32W
	invoke	Process32FirstW,hSnapshot,addr lppew
	.if eax==0
		user32SendDlgItemMessage	hDlg,12400,LVM_DELETEALLITEMS,0,0
		invoke	CloseHandle,hSnapshot
		ret
	.endif
	.if kernelBase==0
		invoke	GetKernelBase,0
		.if eax
			mov	kernelBase,eax
		.else
			mov	kernelBase,-1
		.endif
	.endif
	lea	edi,processes
	xor	ecx,ecx
	mov	lvit.iItem,ecx
	mov	lvit.iSubItem,0
	mov	lvit.state,0
	mov	lvit.stateMask,0
	mov	lvit.pszText,0
	mov	lvit.cchTextMax,0
	mov	lvit.iImage,0
	mov	lvit.iGroupId,0
	mov	lvit.cColumns,0
	mov	lvit.puColumns,0
	cld
	.while edi<offset processes[4096*4]
		mov	lvit.imask,LVIF_PARAM
		mov	lvit.lParam,0
		user32SendDlgItemMessage	hDlg,12400,LVM_GETITEM,0,offset lvit
		.break .if eax==0
		.if lvit.lParam
			mov	eax,lvit.lParam
			stosd
			lea	edx,hooklist
			.while dword ptr[edx]
				.break .if eax==[edx]
				lea	edx,[edx+4]
			.endw
			.if eax==[edx]
				mov	lvit.imask,LVIF_STATE
				mov	lvit.stateMask,LVIS_STATEIMAGEMASK
				mov	lvit.state,8192
				user32SendDlgItemMessage	hDlg,12400,LVM_SETITEMSTATE,lvit.iItem,offset lvit
			.endif
		.endif
		inc	lvit.iItem
	.endw
	xor	eax,eax
	stosd
	.while 1
		mov	eax,lppew.th32ProcessID
		xor	ecx,ecx
		.while processes[ecx]
			.if eax==processes[ecx]
				or	processes[ecx],80000000h
				.break
			.endif
			lea	ecx,[ecx+4]
		.endw
		.if (processes[ecx]==0)&&(lppew.th32ProcessID!=0)
			mov	lvit.imask,LVIF_PARAM or LVIF_TEXT
			lea	eax,lppew.szExeFile
			mov	lvit.pszText,eax
			mov	lvit.cchTextMax,MAX_PATH
			mov	eax,lppew.th32ProcessID
			mov	lvit.lParam,eax
			mov	lvit.iSubItem,0
			user32SendDlgItemMessageW	hDlg,12400,LVM_INSERTITEMW,0,offset lvit
			mov	lvit.iSubItem,1
			mov	lvit.imask,LVIF_TEXT
			mov	lvit.iItem,eax
			lea	edi,buftmp
			mov	eax,lvit.lParam
			call	itoa
			mov	al,0
			stosb
			mov	lvit.pszText,offset buftmp
			mov	ecx,edi
			sub	ecx,offset buftmp
			mov	lvit.cchTextMax,ecx
			user32SendDlgItemMessage	hDlg,12400,LVM_SETITEM,0,offset lvit
			mov	eax,lppew.th32ProcessID
			lea	edx,hooklist
			.while dword ptr[edx]
				.break .if eax==[edx]
				lea	edx,[edx+4]
			.endw
			.if eax==[edx]
				mov	lvit.imask,LVIF_STATE
				mov	lvit.iSubItem,0
				mov	lvit.stateMask,LVIS_STATEIMAGEMASK
				mov	lvit.state,8192
				user32SendDlgItemMessage	hDlg,12400,LVM_SETITEMSTATE,lvit.iItem,offset lvit
			.endif
			inc	lvit.iItem
		.endif
		invoke	Process32NextW,hSnapshot,addr lppew
		.break .if eax==0
	.endw
	mov	dword ptr hooklist,0
	lea	esi,processes
	.while dword ptr[esi]
		lodsd
		.if (!(eax&80000000h))
			xor	ecx,ecx
			mov	lvit.iItem,ecx
			mov	lvit.iSubItem,0
			mov	lvit.state,0
			mov	lvit.stateMask,0
			mov	lvit.imask,LVIF_PARAM
			mov	lvit.pszText,0
			mov	lvit.cchTextMax,0
			mov	lvit.iImage,0
			.while 1
				mov	lvit.lParam,0
				user32SendDlgItemMessage	hDlg,12400,LVM_GETITEM,0,offset lvit
				.break .if eax==0
				.if lvit.lParam
					mov	eax,[esi-4]
					.if eax==lvit.lParam
						invoke	UnregisterPidKey,lvit.iItem
						user32SendDlgItemMessage	hDlg,12400,LVM_DELETEITEM,lvit.iItem,0
						.break
					.endif
				.endif
				inc	lvit.iItem
			.endw
		.endif
	.endw
	invoke	CloseHandle,hSnapshot
	ret
ShowProcesses	ENDP

GetProcessName	PROC	pid:DWORD
	local	lppe1:DWORD,hSnap:DWORD
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if eax==INVALID_HANDLE_VALUE
		ret
	.endif
	mov	hSnap,eax
	invoke	GlobalAlloc,GPTR,sizeof PROCESSENTRY32W + 1024
	mov	lppe1,eax
	mov	edx,eax
	assume	edx:ptr PROCESSENTRY32W
	mov	[edx].dwSize,sizeof PROCESSENTRY32W
	invoke	Process32FirstW,hSnap,lppe1
	.if eax==0
		invoke	CloseHandle,hSnap
		invoke	GlobalFree,lppe1
		ret
	.endif
	.while 1
		mov	edx,lppe1
		mov	eax,[edx].th32ProcessID
		.if eax==pid
			lea	edx,[edx].szExeFile
			xor	ecx,ecx
			xor	eax,eax
			.while word ptr[edx+ecx*2]
				.if (word ptr[edx+ecx*2]=='\')||(word ptr[edx+ecx*2]=='/')
					lea	eax,[ecx+1]
				.endif
				inc	ecx
			.endw
			lea	edx,[edx+eax*2]
			mov	byte ptr[edi],0
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,MAX_PATH*2,0,0
			mov	byte ptr[edi+eax],0
			.while byte ptr[edi]
				inc	edi
			.endw
			invoke	GlobalFree,lppe1
			ret
		.endif
		invoke	Process32NextW,hSnap,lppe1
		.break .if eax==0
	.endw
	invoke	GlobalFree,lppe1
	assume	edx:nothing
	invoke	CloseHandle,hSnap
	ret
GetProcessName	ENDP


;undocumented structure
WtfIsThisShit	struct
	_size	ULONG	<>
	x1	ULONG	<>
	x2	ULONG	<>
	px3	PULONG	<>
	x4	ULONG	<>
	x5	ULONG	<>
	x6	ULONG	<>
	px7	PULONG	<>
	x8	ULONG	<>
WtfIsThisShit	ends

fntbl	dd	HOOK_CONNECT,offset _ws2_32,offset _connect
	dd	HOOK_WSACONNECT,offset _ws2_32,offset _wsaconnect
	dd	HOOK_GETHOSTNAME,offset _ws2_32,offset _gethostname
	dd	HOOK_GETHOSTBYNAME,offset _ws2_32,offset _gethostbyname
	dd	HOOK_WSAASYNCGETHOSTBYNAME,offset _ws2_32,offset _wsaasyncgethostbyname
	dd	HOOK_GETHOSTBYADDR,offset _ws2_32,offset _gethostbyaddr
	dd	HOOK_WSAASYNCGETHOSTBYADDR,offset _ws2_32,offset _wsaasyncgethostbyaddr
	dd	HOOK_GETSYSTEMTIME,offset kernel,offset _getsystemtime
	dd	HOOK_SETSYSTEMTIME,offset kernel,offset _setsystemtime
	dd	HOOK_GETLOCALTIME,offset kernel,offset _getlocaltime
	dd	HOOK_SETLOCALTIME,offset kernel,offset _setlocaltime
	dd	HOOK_GETPROCESSTIMES,offset kernel,offset _getprocesstimes
	dd	HOOK_GETTHREADTIMES,offset kernel,offset _getthreadtimes
	dd	HOOK_GETSYSTEMTIMEASFILETIME,offset kernel,offset _getstasft
	dd	HOOK_GETFILETIME,offset kernel,offset _getfiletime
	dd	HOOK_SETFILETIME,offset kernel,offset _setfiletime
	dd	HOOK_FINDFIRSTFILE,offset kernel,offset _findfirstfile
	dd	HOOK_FINDNEXTFILE,offset kernel,offset _findnextfile
	dd	HOOK_CREATEPROCESSA,offset kernel,offset _createprocessa
	dd	HOOK_CREATEPROCESSW,offset kernel,offset _createprocessw
	dd	HOOK_CREATEPROCESSASUSERA,offset _advapi,offset _createprocessasusera
	dd	HOOK_CREATEPROCESSASUSERW,offset _advapi,offset _createprocessasuserw
	dd	HOOK_SOCKET,offset _ws2_32,offset _socket
	dd	-1

_ntdll	db	'ntdll.dll',0
ntthr	db	'NtCreateThreadEx',0
CreateThreadEx	PROC	hProc:DWORD,lpStart:DWORD,lParam:DWORD
	local	wtf:WtfIsThisShit
	local	crap1:DWORD,crap2:DWORD
	local	thr_id:DWORD
	.if _CreateRemoteThread
		lea	eax,thr_id
		push	eax
		push	0
		push	lParam
		push	lpStart
		push	0
		push	0
		push	hProc
		call	_CreateRemoteThread
	.else
		xor	eax,eax
	.endif
	.if eax==0
		invoke	GetLastError
		push	eax
		.if hNtdll==0
			invoke	LoadLibrary,addr _ntdll
			mov	hNtdll,eax
		.endif
		.if hNtdll
			invoke	GetProcAddress,hNtdll,addr ntthr
			mov	_NTCreateThreadEx,eax
		.endif
		.if _NTCreateThreadEx
			; parameters from http://oxid.netsons.org/phpBB2/viewtopic.php?t=964
			mov	crap1,0
			mov	crap2,0
			mov	wtf._size,36
			mov	wtf.x1,10003h
			mov	wtf.x2,8
			lea	eax,crap1
			mov	wtf.px3,eax
			mov	wtf.x4,0
			mov	wtf.x5,10004h
			mov	wtf.x6,4
			lea	eax,crap2
			mov	wtf.px7,eax
			mov	wtf.x8,0
			mov	thr_id,0

			lea	eax,wtf
			push	eax
			push	0
			push	0
			push	0
			push	0
			push	lParam
			push	lpStart
			push	hProcess
			push	0
			push	1FFFFFh
			lea	eax,thr_id
			push	eax
			call	_NTCreateThreadEx
			mov	eax,thr_id
			.if eax
				pop	edx
				ret
			.endif
			pop	edx
			xor	eax,eax
		.else
			call	SetLastError
			xor	eax,eax
		.endif
	.endif
	ret
CreateThreadEx	ENDP

NewThread	PROC	lpStart:DWORD,hProc:DWORD,load:DWORD
	local	thr_id:DWORD
	local	hToken:DWORD,luid:LUID
	local	tkp:TOKEN_PRIVILEGES,tkp1:TOKEN_PRIVILEGES
	local	hMem:DWORD

	mov	hMem,0
	mov	hToken,0
	.if _OpenProcessToken
		invoke	GlobalAlloc,GPTR,8192
		mov	hMem,eax
		mov	dword ptr[eax],8000
		lea	edx,hToken
		push	edx
		push	 TOKEN_ADJUST_PRIVILEGES+TOKEN_QUERY
		push	hProcess
		call	_OpenProcessToken
		.if eax
			lea	edx,luid
			push	edx
			push	offset selock
			push	0
			call	_LookupPrivilegeValueA
			mov	tkp.PrivilegeCount,1
			mov	eax,luid.LowPart
			mov	tkp.Privileges.Luid.LowPart,eax
			mov	eax,luid.HighPart
			mov	tkp.Privileges.Luid.HighPart,eax
			mov	tkp.Privileges.Attributes,SE_PRIVILEGE_ENABLED
			mov	eax,hMem
			push	eax
			lea	eax,[eax+4]
			push	eax
			push	sizeof TOKEN_PRIVILEGES
			lea	edx,tkp
			push	edx
			push	0
			push	hToken
			call	_AdjustTokenPrivileges
			.if eax == 0
				invoke	GlobalFree,hMem
				mov	hMem,0
				invoke	CloseHandle,hToken
				mov	hToken,0
			.endif
		.else
			invoke	GlobalFree,hMem
			mov	hMem,0
			mov	hToken,0
		.endif
	.endif
	invoke	CreateThreadEx,hProc,lpStart,lpStart
	.if eax
		push	eax
		invoke	ResumeThread,eax
		invoke	Sleep,0
		pop	eax
		push	eax
		invoke	WaitForSingleObject,eax,INFINITE
		mov	eax,[esp]
		lea	edx,thr_id
		mov	dword ptr[edx],0
		push	eax
		invoke	GetExitCodeThread,eax,edx
		pop	edx
		push	eax
		invoke	CloseHandle,edx
		pop	eax
		.if eax==0
			invoke	GetLastError
			mov	thr_id,eax
			shr	byte ptr thr_id[3],1
			or	byte ptr thr_id[3],80h
			getLangStr	LANG_DLL_ERROR_4,msg4
			mov	lpStart,edx
		.else
			getLangStr	LANG_DLL_ERROR_5,msg5
			mov	lpStart,edx
		.endif
		call	CloseHandle
		mov	eax,thr_id
		.if load==0
			.if eax==0
				inc	eax
			.endif
		.elseif eax&80000000h
			lea	edi,buftmp
			mov	edx,lpStart
			call	copyedx
			shl	byte ptr thr_id[3],1
			mov	eax,thr_id
			call	itoa
			mov	al,0
			stosb
			log_error1	offset buftmp
			xor	eax,eax
			dec	eax
		.else
			mov	eax,HOOK_CONNECT or HOOK_WSACONNECT or HOOK_GETHOSTNAME or HOOK_GETHOSTBYNAME or HOOK_WSAASYNCGETHOSTBYNAME or HOOK_GETHOSTBYADDR or HOOK_WSAASYNCGETHOSTBYADDR
			.if sysflags&2
				or	eax,HOOK_GETSYSTEMTIME or HOOK_SETSYSTEMTIME or HOOK_GETLOCALTIME or HOOK_SETLOCALTIME or HOOK_GETPROCESSTIMES or HOOK_GETTHREADTIMES or HOOK_GETSYSTEMTIMEASFILETIME or HOOK_GETFILETIME or HOOK_SETFILETIME or HOOK_FINDFIRSTFILE or HOOK_FINDNEXTFILE
			.endif
			.if sysflags&16
				or	eax,HOOK_SOCKET
			.endif
			or	eax,HOOK_CREATEPROCESSA or HOOK_CREATEPROCESSW or HOOK_CREATEPROCESSASUSERA or HOOK_CREATEPROCESSASUSERW
			xchg	thr_id,eax
			and	eax,thr_id
			xor	eax,thr_id
			.if eax
				mov	thr_id,eax
				lea	edi,buftmp
				writeLangStr	LANG_DLL_ERROR_6,msg6
				lea	edx,fntbl
				.while dword ptr[edx]!=-1
					mov	eax,[edx]
					and	eax,thr_id
					.if eax
						push	edx
						mov	ax,0a0dh
						stosw
						mov	al,9
						stosb
						mov	edx,[edx+8]
						call	copyedx
						mov	eax,' [ '
						stosd
						dec	edi
						mov	edx,[esp]
						mov	edx,[edx+4]
						call	copyedx
						mov	ax,'] '
						stosw
						pop	edx
					.endif
					lea	edx,[edx+12]
				.endw
				mov	al,0
				stosb
				log_error1	offset buftmp
				xor	eax,eax
				dec	eax
				dec	eax
			.else
				xor	eax,eax
				inc	eax
			.endif
		.endif
	.endif
	push	eax
	.if hToken
		mov	eax,hMem
		mov	edx,[eax]
		lea	eax,[eax+4]
		push	0
		push	0
		push	edx
		push	eax
		push	0
		push	hToken
		call	_AdjustTokenPrivileges
		invoke	CloseHandle,hToken
	.endif
	.if hMem
		invoke	GlobalFree,hMem
	.endif
	pop	eax
	ret
NewThread	ENDP

EXPLICIT_ACCESS	struct
	grfAccessPermissions	dd	?
	grfAccessMode		dd	?
	grfInheritance		dd	?
	Trustee1		dd	?
	Trustee2		dd	?
	Trustee3		dd	?
	Trustee4		dd	?
	Trustee5		dd	?
EXPLICIT_ACCESS	ends

_ssi	db	'SetSecurityInfo',0
_seiaa	db	'SetEntriesInAclA',0
SE_KERNEL_OBJECT=6
_OpenProcess	PROC	uses esi edi ebx pid:DWORD
	local	duphandle:DWORD
	local	_SetSecurityInfo:DWORD
	local	mysid:SID
	local	expla:EXPLICIT_ACCESS
	local	pdacl:DWORD
	mov	_SetSecurityInfo,0
	invoke	OpenProcess,PROCESS_ALL_ACCESS,0,pid
	.if eax
		ret
	.endif
	invoke	OpenProcess,PROCESS_QUERY_INFORMATION or PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_VM_WRITE or PROCESS_VM_READ,0,pid
	.if eax
		ret
	.endif
	invoke	OpenProcess,PROCESS_QUERY_INFORMATION or PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_VM_WRITE,0,pid
	.if eax
		ret
	.endif
	invoke	OpenProcess,WRITE_DAC,0,pid
	.if eax==0
		invoke	OpenProcess,WRITE_OWNER,0,pid
		.if eax
			mov	esi,eax
			.if token_info_size
				invoke	GetProcAddress,hAdvapi,addr _ssi
				.if eax
					mov	_SetSecurityInfo,eax
					push	0
					push	0
					push	0
					lea	edx,token_info
					assume	edx:ptr TOKEN_USER
					lea	edx,[edx].User.Sid
					push	edx
					assume	edx:nothing
					push	OWNER_SECURITY_INFORMATION
					push	SE_KERNEL_OBJECT
					push	esi
					call	eax
					.if eax==ERROR_SUCCESS
						invoke	GetCurrentProcess
						mov	edx,eax
						invoke	DuplicateHandle,edx,esi,edx,addr duphandle,WRITE_DAC,0,0
						.if eax
							mov	eax,duphandle
						.endif
					.else
						xor	eax,eax
					.endif
				.endif
			.else
				xor	eax,eax
			.endif
			push	eax
			invoke	CloseHandle,esi
			pop	eax
		.endif
	.endif
	.if eax
		mov	esi,eax
		mov	mysid.Revision,SID_REVISION
		mov	mysid.SubAuthorityCount,1
		mov	dword ptr mysid.IdentifierAuthority.Value,0
		mov	word ptr mysid.IdentifierAuthority.Value[4],100h
		mov	mysid.SubAuthority,0
		mov	expla.grfAccessPermissions,PROCESS_QUERY_INFORMATION or PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_VM_WRITE
		mov	expla.grfAccessMode,2	;SET_ACCESS
		mov	expla.grfInheritance,0	;NO_INHERITANCE
		mov	expla.Trustee1,0
		mov	expla.Trustee2,0	;NO_MULTIPLE_TRUSTEE
		mov	expla.Trustee3,0	;TRUSTEE_IS_SID
		mov	expla.Trustee4,1	;TRUSTEE_IS_USER
		lea	eax,mysid
		mov	expla.Trustee5,eax
		mov	pdacl,0
		invoke	GetProcAddress,hAdvapi,addr _seiaa
		.if eax
			lea	edx,pdacl
			push	edx
			push	0
			lea	edx,expla
			push	edx
			push	1
			call	eax
			.if eax==ERROR_SUCCESS
				push	0
				push	pdacl
				push	0
				push	0
				push	DACL_SECURITY_INFORMATION
				push	SE_KERNEL_OBJECT
				push	esi
				call	_SetSecurityInfo
				invoke	LocalFree,pdacl
				.if eax!=ERROR_SUCCESS
					xor	eax,eax
				.else
					mov	al,1
				.endif
			.else
				xor	eax,eax
			.endif
		.endif
		invoke	GetCurrentProcess
		mov	edx,eax
		invoke	DuplicateHandle,edx,esi,edx,addr duphandle,PROCESS_QUERY_INFORMATION or PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_VM_WRITE,0,0
		.if eax==0
			mov	duphandle,eax
		.endif
		invoke	CloseHandle,esi
		mov	eax,duphandle
	.endif
	ret
_OpenProcess	ENDP

;e8 filenamesize

kernel	db	'kernel32.dll',0
vfunc1	db	'VirtualAllocEx',0
vfunc2	db	'VirtualFreeEx',0
vfunc3	db	'CreateRemoteThread',0
kfunc1	db	'LoadLibraryW',0
kfunc2	db	'GetProcAddress',0
kfunc3	db	'ExitThread',0
kfunc4	db	'GetModuleHandleW',0
kfunc4a	db	'GetModuleHandleA',0
kfunc5	db	'FreeLibrary',0
kfunc6	db	'GetLastError',0
torws	db	'TORWsHook',0
torwsun	db	'TORWsUnhook',0

get_proc_addresses:
	invoke	GetProcAddress,hKernel,addr vfunc1
	.if eax
		mov	_VirtualAllocEx,eax
		invoke	GetProcAddress,hKernel,addr vfunc2
		.if eax == 0
			mov	_VirtualAllocEx,eax
		.else
			mov	_VirtualFreeEx,eax
			invoke	GetProcAddress,hKernel,addr vfunc3
			.if eax==0
				mov	_VirtualAllocEx,eax
			.else
				mov	_CreateRemoteThread,eax
				invoke	GetProcAddress,hKernel,addr kfunc1
				mov	_LoadLibrary,eax
				invoke	GetProcAddress,hKernel,addr kfunc2
				mov	_GetProcAddress,eax
				invoke	GetProcAddress,hKernel,addr kfunc3
				mov	_ExitThread,eax
				invoke	GetProcAddress,hKernel,addr kfunc5
				mov	_FreeLibrary,eax
				invoke	GetProcAddress,hKernel,addr kfunc4
				mov	_GetModuleHandle,eax
				invoke	GetProcAddress,hKernel,addr kfunc4a
				mov	_GetModuleHandleA,eax
				invoke	GetProcAddress,hKernel,addr kfunc6
				mov	_GetLastError,eax
			.endif
		.endif
	.endif
	ret

include	storedproc.h

TORHook	PROC	uses esi edi ebx pid:DWORD,proxyport:DWORD,dwFlags:DWORD,best_delta_t:DWORD,localAddr:DWORD,pipekey:DWORD
	local	lpStart:DWORD,procKernelDelta:DWORD,procKernelBase:DWORD
	local	oldEntryAddr:DWORD
	.if hPipe==0
		getLangStr	LANG_DLL_PIPEINUSE,pipeinuse
		push	edx
		push	LOG_WARN
		call	Log
		xor	eax,eax
		ret
	.endif
	invoke	GetCurrentProcessId
	.if eax==pid
		xor	eax,eax
		ret
	.endif
	mov	eax,pid
	lea	edx,hooklist
	.while dword ptr[edx]
		.if eax==[edx]
			ret
		.endif
		lea	edx,[edx+4]
	.endw

	invoke	_OpenProcess,pid
	mov	hProcess,eax
	.if eax==0
		log_error	LANG_DLL_ERROR_2,msg2
		xor	eax,eax
		ret
	.endif
	.if localAddr
		mov	esi,localAddr
		lea	edi,localhostname
		mov	ecx,255
		.while (ecx!=0)&&(byte ptr[esi]!=0)
			movsb
			dec	ecx
		.endw
		mov	al,0
		stosb
	.endif
	.if hKernel==0
		invoke	LoadLibrary,addr kernel
		mov	hKernel,eax
	.endif
	.if hKernel
		.if _VirtualAllocEx==0
			call	get_proc_addresses
		.endif
		.if _VirtualAllocEx==0
			log_error	LANG_DLL_ERROR_3,msg3
			invoke	CloseHandle,hProcess
			xor	eax,eax
			ret
		.endif
		mov	eax,kernelBase
		mov	procKernelBase,eax
		.if (kernelBase!=0)&&(kernelBase!=-1)
			.if 1;(!(dwFlags&100h))
				invoke	GetKernelBase,pid
				mov	procKernelBase,eax
				sub	eax,kernelBase
				mov	procKernelDelta,eax
			.else
				mov	eax,kernelBase
				neg	eax
				mov	procKernelDelta,eax
			.endif
		.else
			mov	procKernelDelta,0
		.endif
		.if (dwFlags&4)
			or	sysflags,4
		.else
			and	sysflags,4 xor -1
			mov	procKernelDelta,0
		.endif
		.if dwFlags&2
			or	sysflags,2
		.else
			and	sysflags,2 xor -1
		.endif
		and	sysflags,2+4+1
		mov	eax,dwFlags
		and	eax,0fffffff8h
		or	sysflags,eax
		push	PAGE_EXECUTE_READWRITE
		push	MEM_COMMIT
		push	16384
		push	0
		push	hProcess
		call	_VirtualAllocEx
		.if eax < 10000h
			log_error	LANG_DLL_ERROR_3,msg3
			invoke	CloseHandle,hProcess
			xor	eax,eax
			ret
		.endif
		mov	lpStart,eax
		lea	edi,buftmp
	;	mov al,0cch			;int 3
	;	stosb
		mov	al,0e8h			;call delta_api
		stosb
		mov	eax,4+4+4+4 +4+4+4+4 +4+4+4
		stosd
		push	edi
		mov	eax,_LoadLibrary
		add	eax,procKernelDelta
		stosd
		mov	eax,_GetProcAddress
		add	eax,procKernelDelta
		stosd
		mov	eax,_ExitThread
		add	eax,procKernelDelta
		stosd
		mov	eax,_GetModuleHandle
		add	eax,procKernelDelta
		stosd
		mov	eax,_GetLastError
		add	eax,procKernelDelta
		stosd
		mov	eax,proxyport
		mov	saddr.sin_port,ax
		stosd
		mov	eax,pid
		stosd
		mov	eax,hDialog
		stosd
		mov	eax,lpStart
		stosd
		mov	eax,sysflags
		stosd
		mov	eax,best_delta_t
		mov	systemtimedelta,eax
		stosd
		mov	eax,procKernelBase
		stosd
		lea	edx,localhostname
		call	copyedx
		mov	al,0
		stosb
		mov	eax,pipekey
		.if sysflags&64
			invoke	RegisterNewKey,pid,pipekey
			mov	pipekey,eax
		.else
			and	al,0feh
			mov	pipekey,0
		.endif
		stosd
		lea	edx,pipename
		xor	ecx,ecx
		.while (byte ptr[edx]!=0)&&(ecx<255)
			mov	al,[edx]
			stosb
			inc	edx
			inc	ecx
		.endw
		mov	al,0
		stosb
		pop	edx
		mov	eax,edi
		sub	eax,edx
		mov	[edx-4],eax
		mov	al,5eh			;pop esi
		stosb

		mov	al,0e8h			;push offset dllname
		stosb
		xor	ecx,ecx
		.while word ptr filename[ecx]
			inc	ecx
			inc	ecx
		.endw
		inc	ecx
		inc	ecx
		lea	eax,[ecx]
		stosd
		lea	esi,filename
		cld
		rep	movsb
		mov	eax,057243c8bh		;mov	edi,[esp] , push edi
		stosd
		mov	eax,0c56ffh		;call dword ptr[esi+12] ;call GetModuleHandleW
		stosd
		dec	edi
		mov	ax,0c00bh		;or eax,eax
		stosw
		mov	ax,1775h		;jnz $+23 ;jnz _GetProcAddress
		stosw
		mov	ax,16ffh		;call dword ptr[esi] ;call LoadLibraryW
		stosw
		mov	ax,0c00bh		;or eax,eax
		stosw
		mov	ax,1175h		;jnz $+11h
		stosw


		mov	eax,501056ffh		;call dword ptr[esi+12] ;call GetLastError / push eax
		stosd
		mov	eax,03246cd0h		;shr	byte ptr[esp+3],1
		stosd
		mov	eax,03244c80h
		stosd
		mov	al,80h
		stosb				;or	byte ptr[esp+3],80h
		mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
		stosd
		mov	al,0e8h			;push	lpsz
		stosb
		mov	eax,10
		stosd
		mov	esi,offset torws	;"TORWsHook"
		mov	ecx,10
		rep	movsb
		mov	al,50h
		stosb				;push	eax	;hModule
		mov	al,0ffh
		stosb				;call	dword ptr[esi+4]	;call	GetProcAddress
		mov	ax,456h
		stosw

		mov	ax,0c00bh		;or eax,eax
		stosw
		mov	ax,0675h		;jnz $+8
		stosw
		mov	ax,6ah			;push 0
		stosw
		mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
		stosd
		mov	al,68h
		stosb
		mov	eax,lpStart
		stosd				;push hMem
		mov	ax,0d0ffh		;call eax
		stosw
		.if 0;dwFlags&100h
			mov	al,0bah		;mov	edx,oldEntryAddr
			stosb
			mov	eax,pipekey	;oldEntryAddr
			stosd
			mov	al,52h
			stosb			;push	edx
		;	mov	al,0b8h
		;	stosb
		;	mov	eax,oldBytes
		;	stosd
		;	mov	ax,0289h
		;	stosw			;mov	[edx],eax
		;	mov	ax,0c766h
		;	stosw
		;	mov	al,02
		;	stosb
		;	mov	eax,oldBytes4
		;	stosw			;mov	word ptr[edx],oldBytes4
			mov	al,0c3h
			stosb			;ret
		.else
			mov	al,50h
			stosb				;push	eax
			mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
			stosd
		.endif
		mov	ecx,edi
		sub	ecx,offset buftmp
		invoke	WriteProcessMemory,hProcess,lpStart,addr buftmp,ecx,addr lvcol
		.if eax==0
			push	MEM_RELEASE
			push	0
			push	lpStart
			push	hProcess
			call	_VirtualFreeEx
			log_error	LANG_DLL_ERROR_3,msg3
			invoke	CloseHandle,hProcess
			invoke	UnregisterPidKey,pid
			xor	eax,eax
			ret
		.endif
		invoke	GlobalAlloc,GPTR,1024
		push	eax
		mov	edi,eax
		writeLangStr	LANG_DLL_PROTECTING,protecting
		mov	eax,pid
		call	itoa
		mov	ax,'( '
		stosw
		push	edi
		invoke	GetProcessName,pid
		pop	edx
		.if edx!=edi
			mov	eax,[edx]
			push	eax
			mov	al,')'
			stosb
			pop	eax
		.else
			xor	eax,eax
			sub	edi,2
		.endif
		.if sysflags&64 && pipekey!=0
			invoke	GetSetChainKeyName,pid,pipekey,eax
			.if eax
				push	eax
				mov	ax,' ,'
				stosw
				mov	eax,'LCXE'
				stosd
				mov	al,'_'
				stosb
				pop	eax
				stosd
				mov	al,'_'
				stosb
				mov	eax,pipekey
				call	whex
			.endif
		.endif
		mov	al,0
		stosb
		pop	eax
		push	eax
		push	eax
		push	LOG_NOTICE
		call	Log
		call	GlobalFree
		.if dwFlags&100h
			mov	eax,lpStart
			mov	dword ptr pipeData[4],eax
		.endif
			invoke	NewThread,lpStart,hProcess,1
			.if eax==0
				lea	edi,buftmp
				writeLangStr	LANG_DLL_ERROR_4,msg4
				invoke	GetLastError
				call	itoa
				mov	al,0
				stosb
				log_error1	offset buftmp
				push	MEM_RELEASE
				push	0
				push	lpStart
				push	hProcess
				call	_VirtualFreeEx
				invoke	CloseHandle,hProcess
				invoke	UnregisterPidKey,pid
				xor	eax,eax
				ret
			.elseif eax==-1
				push	MEM_RELEASE
				push	0
				push	lpStart
				push	hProcess
				call	_VirtualFreeEx
				invoke	CloseHandle,hProcess
				invoke	UnregisterPidKey,pid
				xor	eax,eax
				ret
			.endif
		push	MEM_RELEASE
		push	0
		push	lpStart
		push	hProcess
		call	_VirtualFreeEx
		invoke	CloseHandle,hProcess
		xor	ecx,ecx
		mov	lvit.iItem,ecx
		mov	lvit.iSubItem,0
		mov	lvit.pszText,0
		mov	lvit.cchTextMax,0
		mov	lvit.iImage,0
		mov	lvit.iGroupId,0
		mov	lvit.cColumns,0
		mov	lvit.puColumns,0
		push	0
		.while 1
			mov	lvit.imask,LVIF_PARAM or LVIF_STATE
			mov	lvit.stateMask,LVIS_STATEIMAGEMASK
			mov	lvit.lParam,0
			user32SendDlgItemMessageW	hDialog,12400,LVM_GETITEMW,0,offset lvit
			.break .if eax==0
			mov	eax,lvit.lParam
			.if eax==pid
				mov	dword ptr[esp],1
				.break .if lvit.state&8192
				lea	edi,hooklist
				xor	ecx,ecx
				.while (dword ptr[edi]!=0)&&(ecx<1000)
					lea	edi,[edi+4]
					inc	ecx
				.endw
				.if ecx<1000
					mov	eax,pid
					mov	dword ptr[edi],eax
					mov	dword ptr[edi+4],0
				.endif
				.break
			.endif
			inc	lvit.iItem
		.endw
		pop	eax
		.if eax==0
			lea	edi,hooklist
			xor	ecx,ecx
			.while (dword ptr[edi]!=0)&&(ecx<1000)
				lea	edi,[edi+4]
				inc	ecx
			.endw
			.if ecx<1000
				mov	eax,pid
				mov	dword ptr[edi],eax
				mov	dword ptr[edi+4],0
			.endif
		.endif
		user32PostMessage	hDialog,WM_USER+11,pid,1
	;	.endif
	.endif
	xor	eax,eax
	inc	eax
	ret
TORHook	ENDP

TORUnhook	PROC	uses esi edi ebx pid:DWORD
	local	lpStart:DWORD,hProc:DWORD
	.if sysflags&1024
		xor	eax,eax
		inc	eax
		ret
	.endif
	invoke	GetCurrentProcessId
	.if eax==pid
		xor	eax,eax
		inc	eax
		ret
	.endif
		invoke	_OpenProcess,pid
		.if eax==0
			ret
		.endif
		mov	hProc,eax
		push	PAGE_EXECUTE_READWRITE	
		push	MEM_RESERVE or MEM_COMMIT
		push	16384
		push	0
		push	hProc
		call	_VirtualAllocEx
		.if eax==0
			log_error	LANG_DLL_ERROR_3,msg3
			invoke	CloseHandle,hProc
			xor	eax,eax
			ret
		.endif
		mov	lpStart,eax
		lea	edi,buftmp
		mov	al,0e8h			;call delta_api
		stosb
		mov	eax,4+4+4+4
		stosd
		mov	eax,_GetModuleHandle
		.if eax==0
			invoke	LoadLibrary,addr kernel
			mov	hKernel,eax
			invoke	GetProcAddress,hKernel,addr kfunc1
			mov	_LoadLibrary,eax
			invoke	GetProcAddress,hKernel,addr kfunc2
			mov	_GetProcAddress,eax
			invoke	GetProcAddress,hKernel,addr kfunc3
			mov	_ExitThread,eax
			invoke	GetProcAddress,hKernel,addr kfunc5
			mov	_FreeLibrary,eax
			invoke	GetProcAddress,hKernel,addr kfunc4
			mov	_GetModuleHandle,eax
		.endif
		stosd
		mov	eax,_GetProcAddress
		stosd
		mov	eax,_ExitThread
		stosd
		mov	eax,_FreeLibrary
		stosd
		mov	al,5eh			;pop esi
		stosb
		mov	al,0e8h			;push offset dllname
		stosb
		xor	ecx,ecx
		.while word ptr filename[ecx]
			inc	ecx
			inc	ecx
		.endw
		inc	ecx
		inc	ecx
		lea	eax,[ecx]
		stosd
		lea	esi,filename
		cld
		rep	movsb
		mov	ax,16ffh		;call dword ptr[esi] ;call LoadLibrary
		stosw
		mov	ax,0c00bh		;or eax,eax
		stosw
		mov	ax,0675h		;jnz $+8
		stosw
		mov	ax,0ff6ah		;push -1
		stosw
		mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
		stosd
		mov	al,50h
		stosb				;push	eax	;hModule
		mov	al,0e8h			;push	lpsz
		stosb
		mov	eax,12
		stosd
		mov	esi,offset torwsun	;"TORWsUnhook"
		mov	ecx,12
		rep	movsb
		mov	al,50h
		stosb				;push	eax	;hModule
		mov	al,0ffh
		stosb				;call	dword ptr[esi+4]	;call	GetProcAddress
		mov	ax,456h
		stosw

		mov	ax,0c00bh		;or eax,eax
		stosw
		mov	ax,0975h		;jnz $+8+3
		stosw
		mov	eax,0c30C56ffh		;call dword ptr[esi+12]		;call	FreeLibrary
		stosd
		dec	edi
		mov	ax,6ah			;push 0
		stosw
		mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
		stosd
		mov	al,68h
		stosb
		mov	eax,lpStart
		stosd				;push hMem
		mov	ax,0d0ffh
		stosw
		mov	eax,0c30C56ffh		;call dword ptr[esi+12]		;call	FreeLibrary
		stosd
		dec	edi
		mov	ax,6ah			;push 0
		stosw
		mov	eax,0c30856ffh		;call dword ptr[esi+8] ret	;call	ExitThread ret
		stosd
		mov	ecx,edi
		sub	ecx,offset buftmp
		invoke	WriteProcessMemory,hProc,lpStart,addr buftmp,ecx,addr lvcol
		.if eax==0
			push	MEM_RELEASE
			push	0
			push	lpStart
			push	hProc
			call	_VirtualFreeEx
			log_error	LANG_DLL_ERROR_3,msg3
			invoke	CloseHandle,hProc
			xor	eax,eax
			ret
		.endif

		invoke	NewThread,lpStart,hProc,0
		.if eax==0
			lea	edi,buftmp
			writeLangStr	LANG_DLL_ERROR_4,msg4
			invoke	GetLastError
			call	itoa
			mov	al,0
			stosb
			log_error1	offset buftmp
			push	MEM_RELEASE
			push	0
			push	lpStart
			push	hProc
			call	_VirtualFreeEx
			invoke	CloseHandle,hProc
			xor	eax,eax
			ret
		.elseif (eax==-1)||(eax==-2)
	;		push	MEM_RELEASE
	;		push	0
	;		push	lpStart
	;		push	hProc
	;		call	_VirtualFreeEx
	;		invoke	CloseHandle,hProc
	;		xor	eax,eax
	;		inc	eax
	;		ret
		.endif
		invoke	GlobalAlloc,GPTR,1024
		push	eax
		mov	edi,eax
		writeLangStr	LANG_DLL_UNPROTECTING,unprotecting
		mov	eax,pid
		call	itoa
		mov	ax,'( '
		stosw
		push	edi
		invoke	GetProcessName,pid
		pop	edx
		.if edx!=edi
			mov	al,')'
			stosb
		.else
			sub	edi,2
		.endif
		mov	al,0
		stosb
		pop	eax
		push	eax
		push	eax
		push	LOG_NOTICE
		call	Log
		call	GlobalFree

	push	MEM_RELEASE
	push	0
	push	lpStart
	push	hProc
	call	_VirtualFreeEx
	invoke	CloseHandle,hProc
	xor	ecx,ecx
	or	sysflags,1024
	mov	lvit.iItem,ecx
	mov	lvit.iSubItem,0
	mov	lvit.pszText,0
	mov	lvit.cchTextMax,0
	mov	lvit.iImage,0
	mov	lvit.iGroupId,0
	mov	lvit.cColumns,0
	mov	lvit.puColumns,0
	.while 1
		mov	lvit.imask,LVIF_PARAM or LVIF_STATE
		mov	lvit.stateMask,LVIS_STATEIMAGEMASK
		mov	lvit.lParam,0
		user32SendDlgItemMessageW	hDialog,12400,LVM_GETITEMW,0,offset lvit
		.break .if eax==0
		mov	eax,lvit.lParam
		.if eax==pid
			.break .if !(lvit.state&8192)
			mov	lvit.imask,LVIF_STATE
			mov	lvit.stateMask,LVIS_STATEIMAGEMASK
			mov	lvit.state,4096
			user32SendDlgItemMessageW	hDialog,12400,LVM_SETITEMSTATE,lvit.iItem,offset lvit
			.break
		.endif
		inc	lvit.iItem
	.endw
	user32PostMessage	hDialog,WM_USER+11,pid,1
	and	sysflags,1024 xor -1
	xor	eax,eax
	inc	eax
	ret
TORUnhook	ENDP

_connect	db	'connect',0
_wsaconnect	db	'WSAConnect',0
_gethostname	db	'gethostname',0
_gethostbyname	db	'gethostbyname',0
_wsaasyncgethostbyname db 'WSAAsyncGetHostByName',0
_gethostbyaddr	db	'gethostbyaddr',0
_wsaasyncgethostbyaddr db 'WSAAsyncGetHostByAddr',0
_getaddrinfo	db	'getaddrinfo',0
_getaddrinfow	db	'GetAddrInfoW',0
_getnameinfo	db	'getnameinfo',0
_getnameinfow	db	'GetNameInfoW',0
_socket		db	'socket',0
_wsasocketa	db	'WSASocketA',0
_wsasocket	db	'WSASocketW',0
_ws2_32		db	'ws2_32.dll',0

_getsystemtime	db	'GetSystemTime',0
_setsystemtime	db	'SetSystemTime',0
_getlocaltime	db	'GetLocalTime',0
_setlocaltime	db	'SetLocalTime',0
_getprocesstimes db	'GetProcessTimes',0
_getthreadtimes db	'GetThreadTimes',0
_getstasft	db	'GetSystemTimeAsFileTime',0
_getfiletime	db	'GetFileTime',0
_setfiletime	db	'GetFileTime',0
_findfirstfile	db	'FindFirstFileW',0
_findnextfile	db	'FindNextFileW',0
_createprocessa	db	'CreateProcessA',0
_createprocessw	db	'CreateProcessW',0
_winexec	db	'WinExec',0
_createprocessasusera db 'CreateProcessAsUserA',0
_createprocessasuserw db 'CreateProcessAsUserW',0

SetHook	PROC	uses esi edi ebx hLibrary:DWORD,function:DWORD,newproc:DWORD,procsave:DWORD
	local	_prefix:DWORD
	invoke	GetProcAddress,hLibrary,function
	mov	function,eax
	invoke	VirtualProtectEx,hProcess,function,100,PAGE_EXECUTE_READWRITE,addr buftmp
	.if eax
		mov	eax,function
		.if byte ptr[eax]==0e9h
			add	eax,[eax+1]
			add	eax,5
			.if dword ptr[eax+2]=='OvdA'
				mov	edi,function
				mov	esi,[eax+2+6]
				.if dword ptr[esi+4]
					push	esi
					mov	ecx,[esi]
					lea	esi,[esi+8]
					rep	movsb
					pop	esi
					invoke	VirtualFree,dword ptr[esi+4],100,MEM_RELEASE
					mov	dword ptr[esi],0
					mov	dword ptr[esi+4],0
				.endif
			.endif
		.endif
		mov	esi,function
		.if byte ptr[esi]==0e9h
			mov	eax,newproc
			sub	eax,esi
			add	eax,5
			.if eax==[esi+1]
				ret
			.endif
		.endif
		mov	edi,procsave
		invoke	VirtualAlloc,0,100,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		stosd
		stosd
		mov	edx,eax
		xor	ecx,ecx
		mov	_prefix,ecx
		.while 1	;ecx<5
			lodsb
			stosb
			mov	[edx],al
			inc	edx
			inc	ecx
			.continue .if (al==0f0h)||(al==0f2h)||(al==0f3h)
			.continue .if (al==064h)||(al==065h)||(al==036h)||(al==03eh)||(al==026h)||(al==02eh)
			.if (al==066h)
				or	_prefix,1
				.continue
			.elseif (al==067h)
				or	_prefix,2
				.continue
			.endif
			.if al==0e8h
				mov	eax,[esi]
				stosd
				mov	[edx],eax
				mov	eax,edx
				sub	eax,esi
				sub	[edx],eax
				lea	edx,[edx+4]
				lea	ecx,[ecx+4]
				.break
			.elseif al==0e9h
				mov	eax,[esi]
				stosd
				mov	[edx],eax
				mov	eax,edx
				sub	eax,esi
				sub	[edx],eax
				lea	edx,[edx+4]
				lea	ecx,[ecx+4]
				.break
			.elseif ((al>=70h)&&(al<80h))			;jcond short N, converted to long jmp
				mov	byte ptr[edx-1],0fh
				add	al,10h
				mov	byte ptr[edx],al
				inc	edx
				movsx	eax,byte ptr[esi]
				stosb
				.if eax&80000000h
					sub	eax,4
				.endif
				inc	ecx
				mov	[edx],eax
				mov	eax,edx
				sub	eax,esi
				sub	[edx],eax
				lea	edx,[edx+4]
				.break .if ecx>=5
				.continue
			.elseif (al==0ebh)				;jmp short, converted to long jmp
				.if ecx<4
					xor	eax,eax
					ret
				.endif
				mov	byte ptr[edx-1],0e9h
				movsx	eax,byte ptr[esi]
				stosb
				.if eax&80000000h
					sub	eax,3
				.endif
				inc	ecx
				mov	[edx],eax
				mov	eax,edx
				sub	eax,esi
				sub	[edx],eax
				lea	edx,[edx+4]
				.break
			.elseif (al==0fh)&&((byte ptr[esi]>=80h)&&(byte ptr[esi]<90h))	;jcond NN
				lodsb
				stosb
				inc	ecx
				mov	[edx],al
				inc	edx
				mov	eax,[esi]
				stosd
				mov	[edx],eax
				mov	eax,edx
				sub	eax,esi
				sub	[edx],eax
				lea	edx,[edx+4]
				lea	ecx,[ecx+4]
				.break
			.elseif (al>=0e0h)&&(al<0e4h)				;loopnz loopz loop jcxz
				xor	eax,eax					;there is no long form for these instructions so they are not handled in this version
				ret
			.elseif (al==0c3h)||(al==0cbh)||(al==0cfh)		;ret, retf, iret
				.if ecx<5					;possible end of function
					xor	eax,eax
					ret
				.endif
			.elseif (al==0c2h)||(al==0cah)				;ret N, retf N
				.if ecx<3					;possible end of function
					xor	eax,eax
					ret
				.endif
			.endif

			lea	ebx,opc_table
			xlat
			mov	ebx,_prefix
			.if al<80h
				movzx	eax,al
				dec	eax
				.if eax>=3
					.if _prefix&2
						dec	eax
						dec	eax
					.endif
				.endif
				mov	bh,al
			.elseif al==-1
				call	modrm
			.elseif al==-3
				.if _prefix&1
					add	bh,2
				.else
					add	bh,4
				.endif
				call	modrm
			.elseif al==-4
				inc	bh
				call	modrm
			.elseif al==-2
				inc	bh
				mov	al,[esi]
				push	ebx
				lea	ebx,opc_0f
				xlat
				pop	ebx
				.if al<80h
					movzx	eax,al
					dec	eax
					dec	eax
					.if eax>=3
						.if _prefix&2
							dec	eax
							dec	eax
						.endif
					.endif
					add	bh,al
				.elseif al==-1
					call	modrm
				.elseif al==-3
					.if _prefix&1
						add	bh,2
					.else
						add	bh,4
					.endif
					call	modrm
				.elseif al==-4
					inc	bh
					call	modrm
				.endif
			.endif
			movzx	eax,bh
			push	eax
			.while dword ptr[esp]
				lodsb
				stosb
				inc	ecx
				mov	[edx],al
				inc	edx
				dec	dword ptr[esp]
			.endw
			pop	eax
			.break .if ecx>=5
		.endw
		mov	eax,edi
		sub	eax,procsave
		sub	eax,8			;bytes saved
		mov	ebx,procsave
		mov	dword ptr[ebx],eax
		add	eax,function
		mov	ebx,eax
		sub	ebx,edx
		sub	ebx,5
		mov	byte ptr[edx],0e9h
		mov	dword ptr[edx+1],ebx
		mov	edx,function
		mov	byte ptr[edx],0e9h
		mov	eax,newproc
		sub	eax,edx
		sub	eax,5
		mov	[edx+1],eax
	.else
		xor	eax,eax
		ret
	.endif
	xor	eax,eax
	inc	eax
	ret
SetHook	ENDP

UnHook	PROC	uses esi edi ebx hLibrary,function:DWORD,newproc:DWORD,procsave:DWORD
	local	_prefix:DWORD
	invoke	GetProcAddress,hLibrary,function
	mov	function,eax
	invoke	VirtualProtectEx,hProcess,function,100,PAGE_EXECUTE_READWRITE,addr buftmp
	.if eax
		mov	eax,function
		.if byte ptr[eax]==0e9h
			add	eax,[eax+1]
			add	eax,5
			.if dword ptr[eax+2]=='OvdA'
				mov	edi,function
				mov	esi,[eax+2+6]
				.if dword ptr[esi+4]
					push	esi
					mov	ecx,[esi]
					lea	esi,[esi+8]
					rep	movsb
					pop	esi
					invoke	VirtualFree,dword ptr[esi+4],100,MEM_RELEASE
					mov	dword ptr[esi],0
					mov	dword ptr[esi+4],0
				.endif
			.endif
		.endif
	.else
		xor	eax,eax
		ret
	.endif
	xor	eax,eax
	inc	eax
	ret
UnHook	ENDP

;edx-8 = addr
;eax = ptr
;returns ecx
getdll	PROC	uses esi eax edx ebx
	local	_addr:DWORD,_size:DWORD,_prefix:DWORD
	local	_m:DWORD
	mov	edx,[edx-8]
	mov	_addr,edx
	invoke	GlobalAlloc,GPTR,sizeof MODULEENTRY32W + 8192
	mov	_m,eax
	mov	_size,0
	lea	edx,pidname+1
	xor	ecx,ecx
	push	edi
	mov	al,0
	stosb
	push	edi
	.while cl<byte ptr pidname && byte ptr[edx+ecx]!=0
		mov	al,[edx+ecx]
		stosb
		inc	ecx
	.endw
	assume	edx:ptr MODULEENTRY32W
	.if ecx<240
		invoke	CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,0
		.if eax!=INVALID_HANDLE_VALUE
			mov	_prefix,eax
			mov	edx,_m
			mov	[edx].modBaseAddr,0
			mov	[edx].modBaseSize,0
			mov	[edx].szExePath,0
			mov	[edx].dwSize,sizeof MODULEENTRY32W
			invoke	Module32FirstW,_prefix,_m
			.while eax
				mov	eax,_addr
				mov	edx,_m
				sub	eax,[edx].modBaseAddr
				.if eax<[edx].modBaseSize
					lea	ecx,[edx+sizeof MODULEENTRY32W]
					invoke	GetModuleFileNameW,[edx].hModule,ecx,4096
					mov	edx,_m
					lea	edx,[edx+sizeof MODULEENTRY32W]
				;	lea	edx,[edx].szExePath
					mov	ax,'[ '
					stosw
					xor	eax,eax
					.while word ptr[edx+eax*2]
						.if (word ptr[edx+eax*2]=='\')||(word ptr[edx+eax*2]=='/')
							lea	edx,[edx+eax*2+2]
							xor	eax,eax
							.continue
						.endif
						inc	eax
					.endw
					mov	byte ptr[edi],0
					invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,254,0,0
					mov	byte ptr[edi+eax],0
					.while byte ptr[edi]
						inc	edi
					.endw
					mov	al,']'
					stosb
					.break
				.endif
				mov	edx,_m
				mov	[edx].modBaseAddr,0
				mov	[edx].modBaseSize,0
				mov	[edx].szExePath,0
				mov	[edx].dwSize,sizeof MODULEENTRY32W
				invoke	Module32NextW,_prefix,_m
				.if eax==0
					.break
				.endif
			.endw
			invoke	CloseHandle,_prefix
		.endif
	.endif
	invoke	GlobalFree,_m
	assume	edx:nothing
	mov	eax,'IP( '
	stosd
	mov	eax,' :D'
	stosd
	dec	edi
	mov	eax,_pid
	call	itoa
	mov	al,')'
	stosb
	pop	eax
	mov	ecx,edi
	sub	ecx,eax
	pop	edx
	mov	[edx],cl
	ret
getdll	ENDP


newconnect:
	jmp	_skipsig1
	db	'AdvOR_'	;signature to check if the function is already hooked
	dd	offset saveconnect
_skipsig1:
	mov	eax,[esp+4+4]
	assume	eax:ptr sockaddr_in
	changeIcon2
	mov	ecx,dword ptr[eax].sin_addr
	.if ((cl==127)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
		jmp	_s_c1
	.endif

	assume	eax:nothing
	.while unloaded==0
		invoke	CreateFile,addr pipename,GENERIC_READ or GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
		.break .if eax!=INVALID_HANDLE_VALUE
		invoke	GetLastError
		.if eax==ERROR_PIPE_BUSY
			invoke	WaitNamedPipe,addr pipename,NMPWAIT_WAIT_FOREVER
		.else
			invoke	Sleep,100
		.endif
	.endw
	lea	edx,[esp+4+4]
	push	edi
		push	eax
			push	edx
				invoke	GlobalAlloc,GPTR,1024
			pop	edx
			mov	edi,eax
		pop	eax
		push	edi
			push	eax
				mov	eax,'NNOC'
				stosd
				mov	eax,pipe_key
				stosd
				push	edx
					push	edx
						mov	eax,[edx-4]
						mov	dword ptr[edi],sizeof sockaddr_in
						lea	edx,[edi+4]
						assume	edx:ptr sockaddr_in
						mov	dword ptr[edx].sin_addr,0
						mov	word ptr[edx].sin_port,0
						push	eax
							invoke	getsockname,eax,edx,edi
						pop	ecx
						lea	edx,[edi+4]
						push	edx
						.if ([edx].sin_port==0)||(eax==SOCKET_ERROR)
							mov	eax,ecx
							mov	dword ptr[edx].sin_addr,0100007fh
							mov	[edx].sin_family,AF_INET
							push	eax
								invoke	bind,eax,edx,sizeof sockaddr_in
							pop	eax
							lea	edx,[edi+4]
							mov	dword ptr[edx].sin_addr,0
							mov	word ptr[edx].sin_port,0
							mov	dword ptr[edi],sizeof sockaddr_in
							invoke	getsockname,eax,edx,edi
						.endif
						pop	edx
						mov	eax,dword ptr[edx].sin_addr
						stosd
						movzx	eax,word ptr[edx].sin_port
						stosw
						assume	edx:nothing
					pop	edx
					mov	edx,[edx]
					assume	edx:ptr sockaddr_in
					.if edx
						mov	eax,dword ptr [edx].sin_addr
					.else
						xor	eax,eax
					.endif
					stosd
					.if (al==0ffh)&&(ah>=16)
						push	edx
							mov	edx,onioncache
							.while edx
								lea	ecx,[edx+8]
								.while ecx<dword ptr[edx+4]
									.break .if eax==[ecx+4]
									lea	ecx,[ecx+264]
								.endw
								.if (ecx<dword ptr[edx+4])&&(eax==dword ptr[ecx+4])
									lea	edx,dword ptr[ecx+8]
									call	copyedx
									.break
								.endif
								mov	edx,dword ptr[edx]
							.endw
							mov	al,0
							stosb
						pop	edx
					.endif
					movzx	eax,word ptr[edx].sin_port
					stosw
					assume	edx:nothing
				pop	edx
				call	getdll
			pop	eax
			mov	ecx,edi
			mov	edi,[esp]
			sub	ecx,edi
			push	eax
				push	0
					mov	edx,esp
					push	eax
						invoke	WriteFile,eax,edi,ecx,edx,0
					pop	eax
					mov	edx,esp
					invoke	ReadFile,eax,edi,4,edx,0
					mov	edx,[edi]
				pop	eax
				pop	eax
				push	edx
				invoke	CloseHandle,eax
				pop	edx
			pop	eax
		push	edx
		invoke	GlobalFree,eax
		pop	eax
	pop	edi

	assume	eax:nothing
	.if eax
		mov	eax,[esp+4]	;hSocket
		push	sizeof saddr
		push	offset saddr
		push	eax
		call	_s_c1
	.else
		mov	eax,SOCKET_ERROR
	.endif
	changeIcon1
	ret	4+4+4

_s_c1:	jmp	dword ptr saveconnect[4]


newwsaconnect:
	jmp	_skipsig2
	db	'AdvOR_'
	dd	offset savewsaconnect
_skipsig2:
	mov	eax,[esp+4+4]
	assume	eax:ptr sockaddr_in
	changeIcon2
	mov	ecx,dword ptr[eax].sin_addr
	.if ((cl==127)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
		jmp	_s_c2
	.endif
	assume	eax:nothing
	.while unloaded==0
		invoke	CreateFile,addr pipename,GENERIC_READ or GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
		.break .if eax!=INVALID_HANDLE_VALUE
		invoke	GetLastError
		.if eax==ERROR_PIPE_BUSY
			invoke	WaitNamedPipe,addr pipename,NMPWAIT_WAIT_FOREVER
		.else
			invoke	Sleep,100
		.endif
	.endw
	lea	edx,[esp+4+4]
	push	edi
		push	edx
			push	eax
				invoke	GlobalAlloc,GPTR,1024
				mov	edi,eax
			pop	eax
		pop	edx
		push	edi
			push	eax
				mov	eax,'NNOC'
				stosd
				mov	eax,pipe_key
				stosd
				push	edx
					push	edx
						mov	eax,[edx-4]
						mov	dword ptr[edi],sizeof sockaddr_in
						lea	edx,[edi+4]
						assume	edx:ptr sockaddr_in
						mov	dword ptr[edx].sin_addr,0
						mov	word ptr[edx].sin_port,0
						push	eax
							invoke	getsockname,eax,edx,edi
						pop	ecx
						lea	edx,[edi+4]
						push	edx
							.if ([edx].sin_port==0)||(eax==SOCKET_ERROR)
								mov	eax,ecx
								mov	dword ptr[edx].sin_addr,0100007fh
								mov	[edx].sin_family,AF_INET
								push	eax
									invoke	bind,eax,edx,sizeof sockaddr_in
								pop	eax
								lea	edx,[edi+4]
								mov	dword ptr[edx].sin_addr,0
								mov	word ptr[edx].sin_port,0
								mov	dword ptr[edi],sizeof sockaddr_in
								invoke	getsockname,eax,edx,edi
							.endif
						pop	edx
						mov	eax,dword ptr[edx].sin_addr
						stosd
						movzx	eax,word ptr[edx].sin_port
						stosw
						assume	edx:nothing
					pop	edx
					mov	edx,[edx]
					assume	edx:ptr sockaddr_in
					mov	eax,dword ptr [edx].sin_addr
					stosd
					.if (al==0ffh)&&(ah>=16)
						push	edx
							mov	edx,onioncache
							.while edx
								lea	ecx,[edx+8]
								.while ecx<dword ptr[edx+4]
									.break .if eax==[ecx+4]
									lea	ecx,[ecx+264]
								.endw
								.if (ecx<dword ptr[edx+4])&&(eax==dword ptr[ecx+4])
									lea	edx,dword ptr[ecx+8]
									call	copyedx
									.break
								.endif
								mov	edx,dword ptr[edx]
							.endw
							mov	al,0
							stosb
						pop	edx
					.endif
					movzx	eax,word ptr[edx].sin_port
					stosw
					assume	edx:nothing
				pop	edx
				call	getdll
			pop	eax
			mov	ecx,edi
			mov	edi,[esp]
			sub	ecx,edi
			push	eax
				push	0
					mov	edx,esp
					push	eax
						invoke	WriteFile,eax,edi,ecx,edx,0
					pop	eax
					mov	edx,esp
					invoke	ReadFile,eax,edi,4,edx,0
					mov	edx,[edi]
				pop	eax
			pop	eax
			push	edx
			invoke	CloseHandle,eax
			pop	edx
		pop	eax
		push	edx
		invoke	GlobalFree,eax
		pop	eax
	pop	edi
	.if eax
		lea	edx,[esp+4]
		push	dword ptr[edx+24]
		push	dword ptr[edx+20]
		push	dword ptr[edx+16]
		push	dword ptr[edx+12]
		push	sizeof saddr
		push	offset saddr
		push	dword ptr[edx]
		call	_s_c2
	.else
		mov	eax,SOCKET_ERROR
	.endif
	changeIcon1
	ret	4+4+4 +4+4+4+4
_s_c2:	jmp	dword ptr savewsaconnect[4]

	resolve_procs
	socket_procs


_k_g1:	jmp	dword ptr getsystemtime[4]
newgetsystemtime:
	jmp	ngst1
	db	'AdvOR_'
	dd	offset getsystemtime
ngst1	PROC	lpSystemTime:DWORD
	push	lpSystemTime
	call	_k_g1
	push	eax
	push	0
	push	0
	mov	edx,esp
	invoke	SystemTimeToFileTime,lpSystemTime,edx
	mov	eax,systemtimedelta
	add	[esp],eax
	mov	eax,systemtimedelta[4]
	adc	dword ptr[esp+4],eax
	mov	edx,esp
	invoke	FileTimeToSystemTime,edx,lpSystemTime
	pop	eax
	pop	eax
	pop	eax
	ret
ngst1	ENDP

_k_gl1:	jmp	dword ptr getlocaltime[4]
newgetlocaltime:
	jmp	nglt1
	db	'AdvOR_'
	dd	offset getlocaltime
nglt1	PROC	lpSystemTime:DWORD
	push	lpSystemTime
	call	_k_gl1
	push	eax
	push	0
	push	0
	mov	edx,esp
	invoke	SystemTimeToFileTime,lpSystemTime,edx
	mov	eax,systemtimedelta
	add	[esp],eax
	mov	eax,systemtimedelta[4]
	adc	dword ptr[esp+4],eax
	mov	edx,esp
	invoke	FileTimeToSystemTime,edx,lpSystemTime
	pop	eax
	pop	eax
	pop	eax
	ret
nglt1	ENDP

_k_s1:	jmp	dword ptr setsystemtime[4]
newsetsystemtime:
	jmp	nsst1
	db	'AdvOR_'
	dd	offset setsystemtime
nsst1	PROC	lpSystemTime:DWORD
	sub	esp,sizeof SYSTEMTIME
	push	0
	push	0
	mov	edx,esp
	invoke	SystemTimeToFileTime,lpSystemTime,edx
	mov	eax,[esp]
	sub	eax,systemtimedelta
	mov	[esp],eax
	mov	eax,dword ptr[esp+4]
	sbb	eax,systemtimedelta[4]
	mov	dword ptr[esp+4],eax
	mov	edx,esp
	lea	ecx,[edx+8]
	invoke	FileTimeToSystemTime,edx,ecx
	mov	edx,esp
	lea	ecx,[edx+8]
	push	ecx
	call	_k_s1
	pop	edx
	mov	eax,systemtimedelta
	add	[edx],eax
	mov	eax,systemtimedelta[4]
	adc	eax,dword ptr[esp+4]
	pop	edx
	add	esp,sizeof SYSTEMTIME
	ret
nsst1	ENDP

_k_sl1:	jmp	dword ptr setlocaltime[4]
newsetlocaltime:
	jmp	nslt1
	db	'AdvOR_'
	dd	offset setlocaltime
nslt1	PROC	lpSystemTime:DWORD
	sub	esp,sizeof SYSTEMTIME
	push	0
	push	0
	mov	edx,esp
	invoke	SystemTimeToFileTime,lpSystemTime,edx
	mov	eax,[esp]
	sub	eax,systemtimedelta
	mov	[esp],eax
	mov	eax,dword ptr[esp+4]
	sbb	eax,systemtimedelta[4]
	mov	dword ptr[esp+4],eax
	mov	edx,esp
	lea	ecx,[edx+8]
	invoke	FileTimeToSystemTime,edx,ecx
	mov	edx,esp
	lea	ecx,[edx+8]
	push	ecx
	call	_k_sl1
	pop	edx
	pop	edx
	add	esp,sizeof SYSTEMTIME
	ret
nslt1	ENDP

_k_gpt1:	jmp	dword ptr getprocesstimes[4]
newgetprocesstimes:
	jmp	ngpt1
	db	'AdvOR_'
	dd	offset getprocesstimes
ngpt1	PROC	hFile:DWORD,lpCreationTime:DWORD,lpExitTime:DWORD,lpKernelTime:DWORD,lpUserTime:DWORD
	push	lpUserTime
	push	lpKernelTime
	push	lpExitTime
	push	lpCreationTime
	push	hFile
	call	_k_gpt1
	push	eax
	push	edx
	mov	edx,lpCreationTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	pop	edx
	pop	eax
	ret
ngpt1	ENDP

_k_gtt1:	jmp	dword ptr getthreadtimes[4]
newgetthreadtimes:
	jmp	ngtt2
	db	'AdvOR_'
	dd	offset getthreadtimes
ngtt2	PROC	hFile:DWORD,lpCreationTime:DWORD,lpExitTime:DWORD,lpKernelTime:DWORD,lpUserTime:DWORD
	push	lpUserTime
	push	lpKernelTime
	push	lpExitTime
	push	lpCreationTime
	push	hFile
	call	_k_gtt1
	push	eax
	push	edx
	mov	edx,lpCreationTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	pop	edx
	pop	eax
	ret
ngtt2	ENDP

_k_ngstft1:	jmp	dword ptr getsystemtimeasfiletime[4]
newgetstasft:
	jmp	ngstft1
	db	'AdvOR_'
	dd	offset getsystemtimeasfiletime
ngstft1	PROC	lpFileTime:DWORD
	push	lpFileTime
	call	_k_ngstft1
	push	eax
	push	edx
	mov	edx,lpFileTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	pop	edx
	pop	eax
	ret
ngstft1	ENDP

_k_gft:	jmp	dword ptr getfiletime[4]
newgetfiletime:
	jmp	ngft
	db	'AdvOR_'
	dd	offset getfiletime
ngft	PROC	hFile:DWORD,lpCreationTime:DWORD,lpLastAccessTime:DWORD,lpLastWriteTime:DWORD
	push	lpLastWriteTime
	push	lpLastAccessTime
	push	lpCreationTime
	push	hFile
	call	_k_gft
	push	eax
	push	edx
	mov	edx,lpCreationTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	mov	edx,lpLastAccessTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	mov	edx,lpLastWriteTime
	.if edx
		mov	eax,systemtimedelta
		add	[edx],eax
		mov	eax,systemtimedelta[4]
		adc	dword ptr[edx+4],eax
	.endif
	pop	edx
	pop	eax
	ret
ngft	ENDP

_k_sft:	jmp	dword ptr setfiletime[4]
newsetfiletime:
	jmp	nsft
	db	'AdvOR_'
	dd	offset setfiletime
nsft	PROC	hFile:DWORD,lpCreationTime:DWORD,lpLastAccessTime:DWORD,lpLastWriteTime:DWORD
	sub	esp,8*3
	mov	edx,lpCreationTime
	.if edx
		mov	eax,systemtimedelta
		add	eax,[edx]
		mov	[esp],eax
		mov	eax,systemtimedelta[4]
		adc	eax,dword ptr[edx+4]
		mov	[esp+4],eax
	.endif
	mov	edx,lpLastAccessTime
	.if edx
		mov	eax,systemtimedelta
		add	eax,[edx]
		mov	[esp +8],eax
		mov	eax,systemtimedelta[4]
		adc	eax,dword ptr[edx+4]
		mov	[esp+4 +8],eax
	.endif
	mov	edx,lpLastWriteTime
	.if edx
		mov	eax,systemtimedelta
		add	eax,[edx]
		mov	[esp +16],eax
		mov	eax,systemtimedelta[4]
		adc	eax,dword ptr[edx+4]
		mov	[esp+4 +16],eax
	.endif

	mov	edx,esp
	.if lpLastWriteTime
		push	edx
	.else
		push	0
	.endif
	lea	edx,[edx+8]
	.if lpLastAccessTime
		push	edx
	.else
		push	0
	.endif
	lea	edx,[edx+8]
	.if lpCreationTime
		push	edx
	.else
		push	0
	.endif
	push	hFile
	call	_k_sft
	add	esp,8*3
	ret
nsft	ENDP


_k_fff:	jmp	dword ptr findfirstfile[4]
newfindfirstfile:
	jmp	nfff
	db	'AdvOR_'
	dd	offset findfirstfile
nfff	PROC	fmask:DWORD,lpWdata:DWORD
	push	lpWdata
	push	fmask
	call	_k_fff
	push	eax
	push	edx
	mov	edx,lpWdata
	assume	edx:ptr WIN32_FIND_DATA
	.if eax!=INVALID_HANDLE_VALUE && edx!=0
		.if [edx].ftCreationTime.dwLowDateTime && [edx].ftCreationTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftCreationTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
		.if [edx].ftLastAccessTime.dwLowDateTime && [edx].ftLastAccessTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftLastAccessTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
		.if [edx].ftLastWriteTime.dwLowDateTime && [edx].ftLastWriteTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftLastWriteTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
	.endif
	pop	edx
	pop	eax
	ret
nfff	ENDP

_k_fnf:	jmp	dword ptr findnextfile[4]
newfindnextfile:
	jmp	nfnf
	db	'AdvOR_'
	dd	offset findnextfile
nfnf	PROC	fmask:DWORD,lpWdata:DWORD
	push	lpWdata
	push	fmask
	call	_k_fnf
	push	eax
	push	edx
	mov	edx,lpWdata
	assume	edx:ptr WIN32_FIND_DATA
	.if eax!=0 && edx!=0
		.if [edx].ftCreationTime.dwLowDateTime && [edx].ftCreationTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftCreationTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
		.if [edx].ftLastAccessTime.dwLowDateTime && [edx].ftLastAccessTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftLastAccessTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
		.if [edx].ftLastWriteTime.dwLowDateTime && [edx].ftLastWriteTime.dwHighDateTime
			push	edx
			lea	edx,[edx].ftLastWriteTime
			mov	eax,systemtimedelta
			add	dword ptr[edx],eax
			mov	eax,systemtimedelta[4]
			adc	dword ptr[edx+4],eax
			pop	edx
		.endif
	.endif
	pop	edx
	pop	eax
	ret
nfnf	ENDP


cprocess	macro
	mov	result,eax
	mov	edx,lppi
	assume	edx:ptr PROCESS_INFORMATION
	mov	ctx.ContextFlags,CONTEXT_FULL
	invoke	GetThreadContext,[edx].hThread,addr ctx
	mov	edx,lppi
	invoke	VirtualProtectEx,[edx].hProcess,ctx.regEax,2,PAGE_EXECUTE_READWRITE,addr oldProtect
	mov	edx,lppi
	lea	ecx,oldBytes
	invoke	ReadProcessMemory,[edx].hProcess,ctx.regEax,ecx,2,addr hFile
	mov	edx,lppi
	invoke	WriteProcessMemory,[edx].hProcess,ctx.regEax,addr ebfe,2,addr hFile
	mov	edx,lppi
	invoke	ResumeThread,[edx].hThread
	mov	eax,ctx.regEax
	mov	newEip,eax
	push	ctx.regEax
	.while 1
		mov	edx,lppi
		invoke	GetKernelBase,[edx].dwProcessId
		.break .if eax
		mov	edx,lppi
		invoke	GetThreadContext,[edx].hThread,addr ctx
		mov	eax,ctx.regEip
		mov	edx,[esp]
		.break .if eax==edx
		invoke	Sleep,10
	.endw
	pop	ctx.regEax
	assume	edx:nothing

	.while unloaded==0
		invoke	CreateFile,addr pipename,GENERIC_READ or GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
		.break .if eax!=INVALID_HANDLE_VALUE
		invoke	GetLastError
		.if eax==ERROR_PIPE_BUSY
			invoke	WaitNamedPipe,addr pipename,NMPWAIT_WAIT_FOREVER
		.else
			invoke	Sleep,100
		.endif
	.endw
	mov	hFile,eax
	push	edi
	invoke	GlobalAlloc,GPTR,MAX_PROC_PATH*2
	mov	hMem,eax
	mov	edi,eax
	mov	eax,'CORP'
	stosd
	mov	eax,pipe_key	;ctx.regEax
	stosd
	mov	edx,lppi
	assume	edx:ptr PROCESS_INFORMATION
	mov	eax,[edx].dwProcessId
	stosd
	assume	edx:nothing
endm

cprocess1	macro
	mov	edx,retAddr
	call	getdll
	mov	ecx,edi
	mov	edi,hMem
	sub	ecx,edi
	push	0
	mov	edx,esp
	invoke	WriteFile,hFile,edi,ecx,edx,0
	mov	edx,esp
	invoke	ReadFile,hFile,edi,4,edx,0
	pop	eax
	invoke	CloseHandle,hFile
	mov	edx,lppi
	assume	edx:ptr PROCESS_INFORMATION
	invoke	SuspendThread,[edx].hThread
	mov	edx,lppi
	lea	ecx,oldBytes
	invoke	WriteProcessMemory,[edx].hProcess,newEip,ecx,2,addr hFile
	assume	edx:nothing
	invoke	GlobalFree,hMem
	pop	edi
	pop	eax
	.if eax&CREATE_SUSPENDED
	.else
		mov	edx,lppi
		assume	edx:ptr PROCESS_INFORMATION
		invoke	ResumeThread,[edx].hThread
		assume	edx:nothing
	.endif
	mov	eax,result
	endm

ebfe	db	0ebh,0feh
_k_cpa:	jmp	dword ptr createprocessa[4]
newcreateprocessa:
	jmp	ncpa1
	db	'AdvOR_'
	dd	offset createprocessa
ncpa1:	lea	edx,[esp+4+4]
	jmp	ncpa
ncpa	PROC	uses esi edi ebx lpAppName:DWORD,lpCmdLine:DWORD,lpProcessAttrs:DWORD,lpThreadAttrs:DWORD,bInherit:DWORD,dwCreationFlags:DWORD,lpEnvironment:DWORD,lpCurrentDirectory:DWORD,lpsi:DWORD,lppi:DWORD
	local	result:DWORD,retAddr:DWORD,hMem:DWORD,hFile:DWORD,oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD
	mov	retAddr,edx
	.if newprocess
		push	lppi
		push	lpsi
		push	lpCurrentDirectory
		push	lpEnvironment
		push	dwCreationFlags
		push	bInherit
		push	lpThreadAttrs
		push	lpProcessAttrs
		push	lpCmdLine
		push	lpAppName
		call	_k_cpa
		ret
	.endif
	push	dwCreationFlags
	mov	newprocess,1

	push	lppi
	push	lpsi
	push	lpCurrentDirectory
	push	lpEnvironment
	mov	eax,dwCreationFlags
	or	eax,CREATE_SUSPENDED
	push	eax
	push	bInherit
	push	lpThreadAttrs
	push	lpProcessAttrs
	push	lpCmdLine
	push	lpAppName
	call	_k_cpa
	.if eax==0
		pop	edx
		ret
	.endif
	mov	newprocess,0
	cprocess
	mov	ecx,MAX_PROC_PATH
	.if lpAppName
		mov	edx,lpAppName
		.while (ecx!=0)&&(byte ptr[edx]!=0)
			mov	al,[edx]
			stosb
			inc	edx
			dec	ecx
		.endw
	.endif
	.if lpCmdLine
		mov	edx,lpCmdLine
		.if byte ptr[edx] && ecx>2
			mov	ax,0a0dh
			stosw
			dec	ecx
			dec	ecx
		.endif
		.while (ecx!=0)&&(byte ptr[edx]!=0)
			mov	al,[edx]
			stosb
			inc	edx
			dec	ecx
		.endw
	.endif
	mov	al,0
	stosb
	cprocess1
	ret
ncpa	ENDP

_k_cpw:	jmp	dword ptr createprocessw[4]
newcreateprocessw:
	jmp	ncpw
	db	'AdvOR_'
	dd	offset createprocessw
ncpw:	lea	edx,[esp+4+4]
	jmp	ncpw1
ncpw1	PROC	uses esi edi ebx lpAppName:DWORD,lpCmdLine:DWORD,lpProcessAttrs:DWORD,lpThreadAttrs:DWORD,bInherit:DWORD,dwCreationFlags:DWORD,lpEnvironment:DWORD,lpCurrentDirectory:DWORD,lpsi:DWORD,lppi:DWORD
	local	result:DWORD,retAddr:DWORD,hMem:DWORD,hFile:DWORD,oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD
	.if newprocess==0
		mov	retAddr,edx
		push	dwCreationFlags

		push	lppi
		push	lpsi
		push	lpCurrentDirectory
		push	lpEnvironment
		mov	eax,dwCreationFlags
		or	eax,CREATE_SUSPENDED
		push	eax
		push	bInherit
		push	lpThreadAttrs
		push	lpProcessAttrs
		push	lpCmdLine
		push	lpAppName
		call	_k_cpw
		.if eax==0
			pop	edx
			ret
		.endif
		cprocess
		mov	ecx,MAX_PROC_PATH
		.if lpAppName
			mov	edx,lpAppName
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,MAX_PROC_PATH-1,0,0
			mov	byte ptr[edi+eax],0
			mov	ecx,MAX_PROC_PATH
			.while byte ptr[edi] && ecx!=0
				inc	edi
				dec	ecx
			.endw
		.endif
		.if lpCmdLine
			mov	edx,lpCmdLine
			.if word ptr[edx] && ecx>3
				mov	ax,0a0dh
				stosw
				dec	ecx
				dec	ecx
				dec	ecx
				invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,ecx,0,0
				.if eax
					mov	byte ptr[edi+eax],0
				.endif
				.while byte ptr[edi]
					inc	edi
				.endw
			.endif
		.endif
		mov	al,0
		stosb
		cprocess1
		ret
	.else
		push	lppi
		push	lpsi
		push	lpCurrentDirectory
		push	lpEnvironment
		push	dwCreationFlags
		push	bInherit
		push	lpThreadAttrs
		push	lpProcessAttrs
		push	lpCmdLine
		push	lpAppName
		call	_k_cpw
	.endif
	ret
ncpw1	ENDP

newwinexec:
	jmp	nwe
	db	'AdvOR_'
	dd	offset winexec
nwe:	lea	edx,[esp+4+4]
	jmp	nwe1
nwe1	PROC	uses esi edi ebx lpCmdLine:DWORD,uShow:DWORD
	local	retAddr:DWORD
	local	hMem:DWORD,cDir:DWORD,_flags:DWORD
	local	oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD,hFile:DWORD
	local	lpSI:STARTUPINFO,lpPI:PROCESS_INFORMATION
	mov	retAddr,edx
	invoke	GlobalAlloc,GPTR,16384+MAX_PROC_PATH*2
	mov	hMem,eax
	mov	edi,eax
	lea	edx,[eax+8192]
	mov	dword ptr[edx],'\:c'
	mov	cDir,edx
	mov	esi,lpCmdLine
	.if byte ptr[esi]==34
		xor	ecx,ecx
		.while (byte ptr[esi+ecx+1]!=34)&&(byte ptr[esi+ecx+1]!=0)
			.break .if (byte ptr[esi+ecx+1]=='\')||(byte ptr[esi+ecx+1]=='/')
			inc	ecx
		.endw
		.if (byte ptr[esi+ecx+1]!='\')&&(byte ptr[esi+ecx+1]!='/')
			movsb
			.while (byte ptr[esi]!=34)&&(byte ptr[esi]!=0)
				movsb
			.endw
			.if byte ptr[esi]==34
				movsb
			.endif
		.else
			xor	ecx,ecx
			mov	edx,hMem
			lea	edx,[edx+8192]
			.while (byte ptr[esi+ecx+1]!=34)&&(byte ptr[esi+ecx+1]!=0)
				mov	al,[esi+ecx+1]
				mov	[edx+ecx],al
				inc	ecx
			.endw
			mov	byte ptr[edx+ecx],0
			.while ecx
				.if (byte ptr[edx+ecx]=='\')||(byte ptr[edx+ecx]=='/')
					mov	byte ptr[edx+ecx],0
					.break
				.endif
				dec	ecx
			.endw
		.endif
	.else
		xor	ecx,ecx
		.while (byte ptr[esi+ecx]!=32)&&(byte ptr[esi+ecx+1]!=0)
			.break .if (byte ptr[esi+ecx]=='\')||(byte ptr[esi+ecx+1]=='/')
			inc	ecx
		.endw
		.if (byte ptr[esi+ecx]!='\')&&(byte ptr[esi+ecx+1]!='/')
			.while (byte ptr[esi]!=32)&&(byte ptr[esi]!=0)
				movsb
			.endw
		.else
			xor	ecx,ecx
			mov	edx,hMem
			lea	edx,[edx+8192]
			.while (byte ptr[esi+ecx]!=32)&&(byte ptr[esi+ecx]!=0)
				mov	al,[esi+ecx]
				mov	[edx+ecx],al
				inc	ecx
			.endw
			mov	byte ptr[edx+ecx],0
			.while ecx
				.if (byte ptr[edx+ecx]=='\')||(byte ptr[edx+ecx]=='/')
					mov	byte ptr[edx+ecx],0
					.break
				.endif
				dec	ecx
			.endw
		.endif
	.endif
	.while byte ptr[esi]
		movsb
	.endw
	.while (edi!=hMem)&&((byte ptr[edi-1]==32)||(byte ptr[edi-1]==13)||(byte ptr[edi-1]==10)||(byte ptr[edi-1]==9))
		dec	edi
	.endw
	mov	al,0
	stosb
	mov	lpSI.cb,sizeof STARTUPINFO
	mov	lpSI.lpReserved,0
	mov	lpSI.lpDesktop,0
	mov	lpSI.lpTitle,0
	mov	lpSI.dwX,CW_USEDEFAULT
	mov	lpSI.dwY,CW_USEDEFAULT
	mov	lpSI.dwXSize,CW_USEDEFAULT
	mov	lpSI.dwYSize,CW_USEDEFAULT
	mov	lpSI.dwXCountChars,80
	mov	lpSI.dwYCountChars,25
	mov	lpSI.dwFillAttribute,FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE
	mov	lpSI.dwFlags,STARTF_USESHOWWINDOW
	mov	lpSI.wShowWindow,SW_SHOWDEFAULT
	mov	lpSI.cbReserved2,0
	mov	lpSI.lpReserved2,0
	mov	lpSI.hStdInput,0
	mov	lpSI.hStdOutput,0
	mov	lpSI.hStdError,0
	mov	lpPI.hProcess,0
	mov	lpPI.hThread,0
	mov	lpPI.dwProcessId,0
	mov	lpPI.dwThreadId,0
	mov	newprocess,1

	lea	eax,lpPI
	push	eax
	lea	eax,lpSI
	push	eax
	push	cDir
	push	0
	mov	eax,CREATE_SUSPENDED
	push	eax
	push	0
	push	0
	push	0
	push	hMem
	push	0
	call	_k_cpa
	mov	newprocess,0
	.if eax==0
		invoke	GlobalFree,hMem
		xor	eax,eax
		ret
	.endif
	mov	ctx.ContextFlags,CONTEXT_FULL
	invoke	GetThreadContext,lpPI.hThread,addr ctx
	invoke	VirtualProtectEx,lpPI.hProcess,ctx.regEax,2,PAGE_EXECUTE_READWRITE,addr oldProtect
	lea	ecx,oldBytes
	invoke	ReadProcessMemory,lpPI.hProcess,ctx.regEax,ecx,2,addr hFile
	invoke	WriteProcessMemory,lpPI.hProcess,ctx.regEax,addr ebfe,2,addr hFile
	invoke	ResumeThread,lpPI.hThread
	mov	eax,ctx.regEax
	mov	newEip,eax
	push	ctx.regEax
	.while 1
		invoke	GetKernelBase,lpPI.dwProcessId
		.break .if eax
		invoke	GetThreadContext,lpPI.hThread,addr ctx
		mov	eax,ctx.regEip
		mov	edx,[esp]
		.break .if eax==edx
		invoke	Sleep,10
	.endw
	pop	ctx.regEax
	assume	edx:nothing

	.while unloaded==0
		invoke	CreateFile,addr pipename,GENERIC_READ or GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
		.break .if eax!=INVALID_HANDLE_VALUE
		invoke	GetLastError
		.if eax==ERROR_PIPE_BUSY
			invoke	WaitNamedPipe,addr pipename,NMPWAIT_WAIT_FOREVER
		.else
			invoke	Sleep,100
		.endif
	.endw
	mov	hFile,eax
	push	edi
	mov	eax,hMem
	lea	edi,[eax+8192]
	mov	eax,'CORP'
	stosd
	mov	eax,pipe_key	;ctx.regEax
	stosd
	mov	eax,lpPI.dwProcessId
	stosd
	mov	ecx,MAX_PROC_PATH
	mov	edx,hMem
	.while (ecx!=0)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		dec	ecx
	.endw
	mov	al,0
	stosb
	mov	edx,retAddr
	call	getdll
	mov	ecx,edi
	mov	edi,hMem
	lea	edi,[edi+8192]
	sub	ecx,edi
	push	0
	mov	edx,esp
	invoke	WriteFile,hFile,edi,ecx,edx,0
	mov	edx,esp
	invoke	ReadFile,hFile,edi,4,edx,0
	pop	eax
	invoke	CloseHandle,hFile
	invoke	SuspendThread,lpPI.hThread
	lea	ecx,oldBytes
	invoke	WriteProcessMemory,lpPI.hProcess,newEip,ecx,2,addr hFile
	pop	edi
	invoke	ResumeThread,lpPI.hThread
	invoke	GlobalFree,hMem
	mov	eax,32
	ret
nwe1	ENDP


_k_cpaua:	jmp	dword ptr createprocessasusera[4]
newcreateprocessasusera:
	jmp	ncpaua1
	db	'AdvOR_'
	dd	offset createprocessasusera
ncpaua1:lea	edx,[esp+4+4]
	jmp	ncpaua
ncpaua	PROC	uses esi edi ebx hToken_:DWORD,lpAppName:DWORD,lpCmdLine:DWORD,lpProcessAttrs:DWORD,lpThreadAttrs:DWORD,bInherit:DWORD,dwCreationFlags:DWORD,lpEnvironment:DWORD,lpCurrentDirectory:DWORD,lpsi:DWORD,lppi:DWORD
	local	result:DWORD,retAddr:DWORD,hMem:DWORD,hFile:DWORD,oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD
	mov	retAddr,edx
	push	dwCreationFlags
	mov	newprocess,1

	push	lppi
	push	lpsi
	push	lpCurrentDirectory
	push	lpEnvironment
	mov	eax,dwCreationFlags
	or	eax,CREATE_SUSPENDED
	push	eax
	push	bInherit
	push	lpThreadAttrs
	push	lpProcessAttrs
	push	lpCmdLine
	push	lpAppName
	call	_k_cpa
	mov	newprocess,0
	.if eax==0
		pop	edx
		ret
	.endif
	cprocess
	mov	ecx,MAX_PROC_PATH
	.if lpAppName
		mov	edx,lpAppName
		.while (ecx!=0)&&(byte ptr[edx]!=0)
			mov	al,[edx]
			stosb
			inc	edx
			dec	ecx
		.endw
	.endif
	.if lpCmdLine
		mov	edx,lpCmdLine
		.if byte ptr[edx] && ecx>2
			mov	ax,0a0dh
			stosw
			dec	ecx
			dec	ecx
		.endif
		.while (ecx!=0)&&(byte ptr[edx]!=0)
			mov	al,[edx]
			stosb
			inc	edx
			dec	ecx
		.endw
	.endif
	mov	al,0
	stosb
	cprocess1
	ret
ncpaua	ENDP

_k_cpauw:	jmp	dword ptr createprocessasuserw[4]
newcreateprocessasuserw:
	jmp	ncpauw
	db	'AdvOR_'
	dd	offset createprocessasuserw
ncpauw:	lea	edx,[esp+4+4]
	jmp	ncpauw1
ncpauw1	PROC	uses esi edi ebx hToken_:DWORD,lpAppName:DWORD,lpCmdLine:DWORD,lpProcessAttrs:DWORD,lpThreadAttrs:DWORD,bInherit:DWORD,dwCreationFlags:DWORD,lpEnvironment:DWORD,lpCurrentDirectory:DWORD,lpsi:DWORD,lppi:DWORD
	local	result:DWORD,retAddr:DWORD,hMem:DWORD,hFile:DWORD,oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD
	.if newprocess==0
		mov	retAddr,edx
		push	dwCreationFlags
		mov	newprocess,1

		push	lppi
		push	lpsi
		push	lpCurrentDirectory
		push	lpEnvironment
		mov	eax,dwCreationFlags
		or	eax,CREATE_SUSPENDED
		push	eax
		push	bInherit
		push	lpThreadAttrs
		push	lpProcessAttrs
		push	lpCmdLine
		push	lpAppName
		call	_k_cpw
		mov	newprocess,0
		.if eax==0
			pop	edx
			ret
		.endif
		cprocess
		mov	ecx,MAX_PROC_PATH
		.if lpAppName
			mov	edx,lpAppName
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,MAX_PROC_PATH-1,0,0
			mov	byte ptr[edi+eax],0
			mov	ecx,MAX_PROC_PATH
			.while byte ptr[edi] && ecx != 0
				inc	edi
				dec	ecx
			.endw
		.endif
		.if lpCmdLine
			mov	edx,lpCmdLine
			.if word ptr[edx] && ecx>3
				mov	ax,0a0dh
				stosw
				dec	ecx
				dec	ecx
				dec	ecx
				invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,ecx,0,0
				.if eax
					mov	byte ptr[edi+eax],0
				.endif
				.while byte ptr[edi]
					inc	edi
				.endw
			.endif
		.endif
		mov	al,0
		stosb
		cprocess1
	.else
		push	lppi
		push	lpsi
		push	lpCurrentDirectory
		push	lpEnvironment
		push	dwCreationFlags
		push	bInherit
		push	lpThreadAttrs
		push	lpProcessAttrs
		push	lpCmdLine
		push	lpAppName
		call	_k_cpw
	.endif
	ret
ncpauw1	ENDP


getpidname	PROC
	lea	edi,pidname
	mov	al,0
	stosb
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if eax==INVALID_HANDLE_VALUE
		ret
	.endif
	mov	hSnapshot,eax
	mov	lppew.dwSize,sizeof PROCESSENTRY32W
	invoke	Process32FirstW,hSnapshot,addr lppew
	.if eax==0
		invoke	CloseHandle,hSnapshot
		ret
	.endif
	.while 1
		mov	eax,lppew.th32ProcessID
		.if eax==_pid
			lea	edx,lppew.szExeFile
			push	edi
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,255,0,0
			mov	byte ptr[edi+eax],0
			pop	edi
			mov	[edi-1],al
			invoke	CloseHandle,hSnapshot
			ret
		.endif
		invoke	Process32NextW,hSnapshot,addr lppew
		.break .if eax==0
	.endw
	invoke	CloseHandle,hSnapshot
	ret
getpidname	ENDP

getExeName	PROC	pid:DWORD
	local	lppe1:DWORD,hSnapshot1:DWORD
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if eax==INVALID_HANDLE_VALUE
		ret
	.endif
	mov	hSnapshot1,eax
	invoke	GlobalAlloc,GPTR,sizeof PROCESSENTRY32W+1024
	mov	lppe1,eax
	mov	edx,eax
	assume	edx:ptr PROCESSENTRY32W
	mov	[edx].dwSize,sizeof PROCESSENTRY32W
	invoke	Process32FirstW,hSnapshot1,lppe1
	.if eax==0
		invoke	CloseHandle,hSnapshot1
		invoke	GlobalFree,lppe1
		ret
	.endif
	.while 1
		mov	edx,lppe1
		mov	eax,[edx].th32ProcessID
		.if eax==pid
			lea	edx,[edx].szExeFile
			xor	ecx,ecx
			xor	eax,eax
			.while word ptr[edx+ecx*2]
				.if (word ptr[edx+ecx*2]=='\')||(word ptr[edx+ecx*2]=='/')
					lea	eax,[ecx+1]
				.endif
				inc	ecx
			.endw
			lea	edx,[edx+eax*2]
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,255,0,0
			mov	byte ptr[edi+eax],0
			lea	edi,[edi+eax]
			invoke	CloseHandle,hSnapshot1
			invoke	GlobalFree,lppe1
			ret
		.endif
		invoke	Process32NextW,hSnapshot1,lppe1
		.break .if eax==0
	.endw
	invoke	GlobalFree,lppe1
	invoke	CloseHandle,hSnapshot1
	ret
getExeName	ENDP

ProcessNameFromPid	PROC	uses edi lpBuf:DWORD,bufSize:DWORD,pid:DWORD
	local	_snapshot:DWORD
	local	_lppe:DWORD
	mov	edi,lpBuf
	mov	byte ptr[edi],0
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if eax==INVALID_HANDLE_VALUE
		xor	eax,eax
		ret
	.endif
	mov	_snapshot,eax
	invoke	GlobalAlloc,GPTR,sizeof PROCESSENTRY32W + 1024
	mov	_lppe,eax
	mov	edx,eax
	assume	edx:ptr PROCESSENTRY32W
	mov	[edx].dwSize,sizeof PROCESSENTRY32W
	invoke	Process32FirstW,_snapshot,_lppe
	.if eax==0
		invoke	CloseHandle,_snapshot
		invoke	GlobalFree,_lppe
		xor	eax,eax
		ret
	.endif
	.while 1
		mov	edx,_lppe
		mov	eax,[edx].th32ProcessID
		.if eax==pid
			lea	edx,[edx].szExeFile
			xor	ecx,ecx
			xor	eax,eax
			.while word ptr[edx+ecx*2]
				.if (word ptr[edx+ecx*2]=='\')||(word ptr[edx+ecx*2]=='/')
					lea	eax,[ecx+1]
				.endif
				inc	ecx
			.endw
			lea	edx,[edx+eax*2]
			invoke	WideCharToMultiByte,CP_UTF8,0,edx,-1,edi,255,0,0
			mov	byte ptr[edi+eax],0
			mov	bufSize,eax
			invoke	GlobalFree,_lppe
			invoke	CloseHandle,_snapshot
			mov	eax,bufSize
			ret
		.endif
		invoke	Process32NextW,_snapshot,_lppe
		.break .if eax==0
	.endw
	assume	edx:nothing
	invoke	GlobalFree,_lppe
	invoke	CloseHandle,_snapshot
	xor	eax,eax
	ret
ProcessNameFromPid	ENDP

setHookedFlag	macro	n
	.if eax
		or	hooked,n
	.endif
endm

TORWsHook	PROC	hMem:DWORD
	local	hooked:DWORD
	.if hDialog
		xor	eax,eax
		ret
	.endif
	lea	edi,saddr
	mov	ecx,sizeof saddr
	xor	eax,eax
	cld
	rep	stosd
	mov	saddr.sin_family,AF_INET
	push	esi
	lea	esi,[esi+16+4]
	mov	eax,[esi]
	xchg	al,ah
	mov	saddr.sin_port,ax
	mov	eax,100007fh
	mov	dword ptr saddr.sin_addr,eax
	mov	eax,[esi+4]
	mov	_pid,eax
	mov	eax,[esi+4+4]
	mov	_hDialog,eax
	mov	eax,[esi+4+4+4+4]
	mov	sysflags,eax
	mov	eax,[esi+4+4+4+4+4]
	mov	systemtimedelta,eax
	mov	eax,[esi+4+4+4+4+4+4]
	mov	kernelBase,eax
	push	edi
	lea	edx,[esi+4+4+4+4+4+4+4]
	lea	edi,localhostname
	call	copyedx
	mov	al,0
	stosb
	inc	edx
	mov	eax,[edx]
	mov	pipe_key,eax
	lea	edx,[edx+4]
	lea	edi,pipename
	call	copyedx
	mov	al,0
	stosb
	pop	edi
	call	getpidname
	mov	hooked,0
	invoke	GetCurrentProcess
	mov	hProcess,eax
	invoke	LoadLibrary,addr _ws2_32
	.if eax==0
		invoke	GetModuleHandle,addr _ws2_32
	.endif
	.if eax
		mov	hWsock,eax
		invoke	gethostname,addr buftmp,1024
		invoke	SetHook,hWsock,addr _connect,offset newconnect,addr saveconnect
		setHookedFlag	HOOK_CONNECT
		invoke	SetHook,hWsock,addr _wsaconnect,offset newwsaconnect,addr savewsaconnect
		setHookedFlag	HOOK_WSACONNECT
		invoke	SetHook,hWsock,addr _gethostname,offset newgethostname,addr savegethostname
		setHookedFlag	HOOK_GETHOSTNAME
		invoke	SetHook,hWsock,addr _gethostbyname,offset newgethostbyname,addr savegethostbyname
		setHookedFlag	HOOK_GETHOSTBYNAME
		invoke	SetHook,hWsock,addr _wsaasyncgethostbyname,offset newwsaasyncgethostbyname,addr savewsaasyncgethostbyname
		setHookedFlag	HOOK_WSAASYNCGETHOSTBYNAME
		invoke	SetHook,hWsock,addr _gethostbyaddr,offset newgethostbyaddr,addr savegethostbyaddr
		setHookedFlag	HOOK_GETHOSTBYADDR
		invoke	SetHook,hWsock,addr _wsaasyncgethostbyaddr,offset newwsaasyncgethostbyaddr,addr savewsaasyncgethostbyaddr
		setHookedFlag	HOOK_WSAASYNCGETHOSTBYADDR
		invoke	SetHook,hWsock,addr _getaddrinfo,offset newgetaddrinfo,addr savegetaddrinfo
		invoke	SetHook,hWsock,addr _getaddrinfow,offset newgetaddrinfow,addr savegetaddrinfow
		invoke	SetHook,hWsock,addr _getnameinfo,offset newgetnameinfo,addr savegetnameinfo
		invoke	SetHook,hWsock,addr _getnameinfow,offset newgetnameinfow,addr savegetnameinfow
		.if sysflags&16
			invoke	SetHook,hWsock,addr _socket,offset newsocket,addr savesocket
			setHookedFlag	HOOK_SOCKET
			invoke	SetHook,hWsock,addr _wsasocket,offset newwsasocket,addr savewsasocket
			setHookedFlag	HOOK_SOCKET
		.endif
	.endif
	invoke	GetModuleHandle,addr kernel
	.if eax==0
		invoke	LoadLibrary,addr kernel
	.endif
	.if eax
		mov	hKernel,eax
		invoke	GetModuleHandle,addr _advapi
		.if eax==0
			invoke	LoadLibrary,addr _advapi
		.endif
		mov	hAdvapi,eax
		.if sysflags&2
			.if systemtimedelta==0
				invoke	GetTickCount
				and	eax,0fffffh
				xor	edx,edx
			.else
				mov	eax,systemtimedelta
				cdq
			.endif
			mov	ecx,10000000
			imul	ecx
			mov	systemtimedelta,eax
			mov	dword ptr systemtimedelta[4],edx
			invoke	SetHook,hKernel,addr _getsystemtime,offset newgetsystemtime,addr getsystemtime
			setHookedFlag	HOOK_GETSYSTEMTIME
			invoke	SetHook,hKernel,addr _setsystemtime,offset newsetsystemtime,addr setsystemtime
			setHookedFlag	HOOK_SETSYSTEMTIME
			invoke	SetHook,hKernel,addr _getlocaltime,offset newgetlocaltime,addr getlocaltime
			setHookedFlag	HOOK_GETLOCALTIME
			invoke	SetHook,hKernel,addr _setlocaltime,offset newsetlocaltime,addr setlocaltime
			setHookedFlag	HOOK_SETLOCALTIME
			invoke	SetHook,hKernel,addr _getprocesstimes,offset newgetprocesstimes,addr getprocesstimes
			setHookedFlag	HOOK_GETPROCESSTIMES
			invoke	SetHook,hKernel,addr _getthreadtimes,offset newgetthreadtimes,addr getthreadtimes
			setHookedFlag	HOOK_GETTHREADTIMES
			invoke	SetHook,hKernel,addr _getstasft,offset newgetstasft,addr getsystemtimeasfiletime
			setHookedFlag	HOOK_GETSYSTEMTIMEASFILETIME
			invoke	SetHook,hKernel,addr _getfiletime,offset newgetfiletime,addr getfiletime
			setHookedFlag	HOOK_GETFILETIME
			invoke	SetHook,hKernel,addr _setfiletime,offset newsetfiletime,addr setfiletime
			setHookedFlag	HOOK_SETFILETIME
			invoke	SetHook,hKernel,addr _findfirstfile,offset newfindfirstfile,addr findfirstfile
			setHookedFlag	HOOK_FINDFIRSTFILE
			invoke	SetHook,hKernel,addr _findnextfile,offset newfindnextfile,addr findnextfile
			setHookedFlag	HOOK_FINDNEXTFILE
		.endif
		invoke	SetHook,hKernel,addr _createprocessa,offset newcreateprocessa,addr createprocessa
		setHookedFlag	HOOK_CREATEPROCESSA
		invoke	SetHook,hKernel,addr _createprocessw,offset newcreateprocessw,addr createprocessw
		setHookedFlag	HOOK_CREATEPROCESSW
		invoke	SetHook,hKernel,addr _winexec,offset newwinexec,addr winexec
		invoke	SetHook,hAdvapi,addr _createprocessasusera,offset newcreateprocessasusera,addr createprocessasusera
		setHookedFlag	HOOK_CREATEPROCESSASUSERA
		invoke	SetHook,hAdvapi,addr _createprocessasuserw,offset newcreateprocessasuserw,addr createprocessasuserw
		setHookedFlag	HOOK_CREATEPROCESSASUSERW
	.endif
	invoke	FlushInstructionCache,hProcess,0,0
	user32iconinit
	pop	esi
	mov	eax,hooked
	ret
TORWsHook	ENDP

TORWsUnhook	PROC	hMem:DWORD
	local	hooked:DWORD
	.if hDialog
		ret
	.endif
	mov	unloaded,1
	.if last_query
		invoke	GetTickCount
		sub	eax,last_query
		.if eax<1000
			invoke	Sleep,200
		.endif
	.endif
	invoke	GetCurrentProcess
	mov	hProcess,eax
	invoke	GetModuleHandle,addr _ws2_32
	.if eax==0
		invoke	LoadLibrary,addr _ws2_32
	.endif
	.if eax
		mov	hWsock,eax
		invoke	UnHook,hWsock,addr _connect,offset newconnect,addr saveconnect
		setHookedFlag	HOOK_CONNECT
		invoke	UnHook,hWsock,addr _wsaconnect,offset newwsaconnect,addr savewsaconnect
		setHookedFlag	HOOK_WSACONNECT
		invoke	UnHook,hWsock,addr _gethostname,offset newgethostname,addr savegethostname
		setHookedFlag	HOOK_GETHOSTNAME
		invoke	UnHook,hWsock,addr _gethostbyname,offset newgethostbyname,addr savegethostbyname
		setHookedFlag	HOOK_GETHOSTBYNAME
		invoke	UnHook,hWsock,addr _wsaasyncgethostbyname,offset newwsaasyncgethostbyname,addr savewsaasyncgethostbyname
		setHookedFlag	HOOK_WSAASYNCGETHOSTBYNAME
		invoke	UnHook,hWsock,addr _gethostbyaddr,offset newgethostbyaddr,addr savegethostbyaddr
		setHookedFlag	HOOK_GETHOSTBYADDR
		invoke	UnHook,hWsock,addr _wsaasyncgethostbyaddr,offset newwsaasyncgethostbyaddr,addr savewsaasyncgethostbyaddr
		setHookedFlag	HOOK_WSAASYNCGETHOSTBYADDR
		invoke	UnHook,hWsock,addr _getaddrinfo,offset newgetaddrinfo,addr savegetaddrinfo
		invoke	UnHook,hWsock,addr _getaddrinfow,offset newgetaddrinfow,addr savegetaddrinfow
		invoke	UnHook,hWsock,addr _getnameinfo,offset newgetnameinfo,addr savegetnameinfo
		invoke	UnHook,hWsock,addr _getnameinfow,offset newgetnameinfow,addr savegetnameinfow
		invoke	UnHook,hWsock,addr _socket,offset newsocket,addr savesocket
		setHookedFlag	HOOK_SOCKET
		invoke	UnHook,hWsock,addr _wsasocket,offset newwsasocket,addr savewsasocket
		setHookedFlag	HOOK_SOCKET
	.endif
	invoke	GetModuleHandle,addr kernel
	.if eax==0
		invoke	LoadLibrary,addr kernel
	.endif
	.if eax
		mov	hKernel,eax
		invoke	GetModuleHandle,addr _advapi
		.if eax==0
			invoke	LoadLibrary,addr _advapi
		.endif
		mov	hAdvapi,eax
		invoke	UnHook,hKernel,addr _getsystemtime,offset newgetsystemtime,addr getsystemtime
		setHookedFlag	HOOK_GETSYSTEMTIME
		invoke	UnHook,hKernel,addr _setsystemtime,offset newsetsystemtime,addr setsystemtime
		setHookedFlag	HOOK_SETSYSTEMTIME
		invoke	UnHook,hKernel,addr _getlocaltime,offset newgetlocaltime,addr getlocaltime
		setHookedFlag	HOOK_GETLOCALTIME
		invoke	UnHook,hKernel,addr _setlocaltime,offset newsetlocaltime,addr setlocaltime
		setHookedFlag	HOOK_SETLOCALTIME
		invoke	UnHook,hKernel,addr _getprocesstimes,offset newgetprocesstimes,addr getprocesstimes
		setHookedFlag	HOOK_GETPROCESSTIMES
		invoke	UnHook,hKernel,addr _getthreadtimes,offset newgetthreadtimes,addr getthreadtimes
		setHookedFlag	HOOK_GETTHREADTIMES
		invoke	UnHook,hKernel,addr _getstasft,offset newgetstasft,addr getsystemtimeasfiletime
		setHookedFlag	HOOK_GETSYSTEMTIMEASFILETIME
		invoke	UnHook,hKernel,addr _getfiletime,offset newgetfiletime,addr getfiletime
		setHookedFlag	HOOK_GETFILETIME
		invoke	UnHook,hKernel,addr _setfiletime,offset newsetfiletime,addr setfiletime
		setHookedFlag	HOOK_SETFILETIME
		invoke	UnHook,hKernel,addr _findfirstfile,offset newfindfirstfile,addr findfirstfile
		setHookedFlag	HOOK_FINDFIRSTFILE
		invoke	UnHook,hKernel,addr _findnextfile,offset newfindnextfile,addr findnextfile
		setHookedFlag	HOOK_FINDNEXTFILE
		invoke	UnHook,hKernel,addr _createprocessa,offset newcreateprocessa,addr createprocessa
		setHookedFlag	HOOK_CREATEPROCESSA
		invoke	UnHook,hKernel,addr _createprocessw,offset newcreateprocessw,addr createprocessw
		setHookedFlag	HOOK_CREATEPROCESSW
		invoke	UnHook,hKernel,addr _winexec,offset newwinexec,addr winexec
		invoke	UnHook,hAdvapi,addr _createprocessasusera,offset newcreateprocessasusera,addr createprocessasusera
		setHookedFlag	HOOK_CREATEPROCESSASUSERA
		invoke	UnHook,hAdvapi,addr _createprocessasuserw,offset newcreateprocessasuserw,addr createprocessasuserw
		setHookedFlag	HOOK_CREATEPROCESSASUSERW
		shell32_unhook
	.endif
	invoke	FlushInstructionCache,hProcess,0,0
	user32unload
	ret
TORWsUnhook	ENDP

GetKernelBase	PROC	__pid:DWORD
	local	_m:MODULEENTRY32
	local	_prefix:DWORD
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,__pid
	.if eax!=INVALID_HANDLE_VALUE
		mov	_prefix,eax
		mov	_m.modBaseAddr,0
		mov	_m.modBaseSize,0
		mov	_m.szExePath,0
		mov	_m.dwSize,sizeof MODULEENTRY32
		lea	eax,_m
		invoke	Module32First,_prefix,eax
		.while eax
			lea	edx,_m.szExePath
			xor	eax,eax
			.while byte ptr[edx+eax]
				.if (byte ptr[edx+eax]=='\')||(byte ptr[edx+eax]=='/')
					lea	edx,[edx+eax+1]
					xor	eax,eax
					.continue
				.endif
				inc	eax
			.endw
			mov	eax,[edx]
			or	eax,20202020h
			.if eax=='nrek'
				mov	eax,[edx+4]
				or	eax,20202020h
				.if (eax=='23le')
					mov	eax,[edx+8]
					or	eax,20202000h
					.if ((eax=='lld.')&&(byte ptr[edx+12]==0)) || byte ptr[edx+8]==0
						invoke	CloseHandle,_prefix
						mov	eax,_m.modBaseAddr
						ret
					.endif
				.endif
			.endif
			mov	_m.modBaseAddr,0
			mov	_m.modBaseSize,0
			mov	_m.szExePath,0
			mov	_m.dwSize,sizeof MODULEENTRY32
			lea	eax,_m
			invoke	Module32Next,_prefix,eax
		.endw
		invoke	CloseHandle,_prefix
	.endif
	xor	eax,eax
	ret
GetKernelBase	ENDP


CREATE_DEFAULT_ERROR_MODE=04000000h

CreateNewProcess	PROC	uses esi edi ebx lpMenuEntry:DWORD,proxyport:DWORD,dwFlags:DWORD,best_delta_t:DWORD,localAddr:DWORD,pipekey:DWORD
	local	hMem:DWORD,cDir:DWORD,_flags:DWORD
	local	oldProtect:DWORD,oldBytes:DWORD,newEip:DWORD,hFile:DWORD
	local	lpSI:STARTUPINFO,lpPI:PROCESS_INFORMATION
	local	lpDirW:DWORD,lpCmdW:DWORD,lpTitleW:DWORD
	local	hProcess1:DWORD
	invoke	GlobalAlloc,GPTR,16384+512
	mov	hMem,eax
	lea	edx,[eax+8192]
	mov	dword ptr[edx],'\:c'
	mov	cDir,edx
	mov	esi,lpMenuEntry
	.while byte ptr[esi]
		.break .if byte ptr[esi]=='='
		inc	esi
	.endw
	mov	hProcess1,0
	.if byte ptr[esi]=='='
		inc	esi
		mov	edi,hMem
		call	atoi
		mov	_flags,eax
		.while (byte ptr[esi]==',')||((byte ptr[esi]>='0')&&(byte ptr[esi]<='9'))
			inc	esi
		.endw
		.if byte ptr[esi]==34
			xor	ecx,ecx
			.while (byte ptr[esi+ecx+1]!=34)&&(byte ptr[esi+ecx+1]!=0)
				.break .if (byte ptr[esi+ecx+1]=='\')||(byte ptr[esi+ecx+1]=='/')
				inc	ecx
			.endw
			.if (byte ptr[esi+ecx+1]!='\')&&(byte ptr[esi+ecx+1]!='/')
				movsb
				.while (byte ptr[esi]!=34)&&(byte ptr[esi]!=0)
					movsb
				.endw
				.if byte ptr[esi]==34
					movsb
				.endif
			.else
				xor	ecx,ecx
				mov	edx,hMem
				lea	edx,[edx+8192]
				.while (byte ptr[esi+ecx+1]!=34)&&(byte ptr[esi+ecx+1]!=0)
					mov	al,[esi+ecx+1]
					mov	[edx+ecx],al
					inc	ecx
				.endw
				mov	byte ptr[edx+ecx],0
				.while ecx
					.if (byte ptr[edx+ecx]=='\')||(byte ptr[edx+ecx]=='/')
						mov	byte ptr[edx+ecx],0
						.break
					.endif
					dec	ecx
				.endw
			.endif
		.endif
		.while byte ptr[esi]
			movsb
		.endw
		.while (edi!=hMem)&&((byte ptr[edi-1]==32)||(byte ptr[edi-1]==13)||(byte ptr[edi-1]==10)||(byte ptr[edi-1]==9))
			dec	edi
		.endw
		mov	al,0
		stosb
		mov	lpSI.cb,sizeof STARTUPINFO
		mov	lpSI.lpReserved,0
		mov	lpSI.lpDesktop,0
		mov	edi,hMem
		lea	edi,[edi+16384]
		mov	lpSI.lpTitle,edi
		mov	edx,lpMenuEntry
		.while (byte ptr[edx]!=0)&&(byte ptr[edx]!='=')
			mov	al,[edx]
			stosb
			inc	edx
		.endw
		mov	al,0
		stosb
		mov	lpSI.dwX,CW_USEDEFAULT
		mov	lpSI.dwY,CW_USEDEFAULT
		mov	lpSI.dwXSize,CW_USEDEFAULT
		mov	lpSI.dwYSize,CW_USEDEFAULT
		mov	lpSI.dwXCountChars,80
		mov	lpSI.dwYCountChars,25
		mov	lpSI.dwFillAttribute,FOREGROUND_RED or FOREGROUND_GREEN or FOREGROUND_BLUE
		mov	lpSI.dwFlags,STARTF_USESHOWWINDOW
		mov	lpSI.wShowWindow,SW_SHOWDEFAULT
		mov	lpSI.cbReserved2,0
		mov	lpSI.lpReserved2,0
		mov	lpSI.hStdInput,0
		mov	lpSI.hStdOutput,0
		mov	lpSI.hStdError,0
		mov	lpPI.hProcess,0
		mov	lpPI.hThread,0
		mov	lpPI.dwProcessId,0
		mov	lpPI.dwThreadId,0
		invoke	get_unicode,hMem
		mov	lpCmdW,eax
		invoke	get_unicode,cDir
		mov	lpDirW,eax
		invoke	get_unicode,lpSI.lpTitle
		mov	lpTitleW,eax
		mov	lpSI.lpTitle,eax
		invoke	CreateProcessW,0,lpCmdW,0,0,0,CREATE_SUSPENDED,0,lpDirW,addr lpSI,addr lpPI
		push	eax
		invoke	GlobalFree,lpCmdW
		invoke	GlobalFree,lpDirW
		invoke	GlobalFree,lpTitleW
		pop	eax
		.if eax
			mov	edx,lpPI.hProcess
			mov	hProcess1,edx
			mov	ctx.ContextFlags,CONTEXT_FULL
			invoke	GetThreadContext,lpPI.hThread,addr ctx
			invoke	VirtualProtectEx,lpPI.hProcess,ctx.regEax,2,PAGE_EXECUTE_READWRITE,addr oldProtect
			lea	ecx,oldBytes
			invoke	ReadProcessMemory,lpPI.hProcess,ctx.regEax,ecx,2,addr hFile
			invoke	WriteProcessMemory,lpPI.hProcess,ctx.regEax,addr ebfe,2,addr hFile
			invoke	ResumeThread,lpPI.hThread
			mov	eax,ctx.regEax
			mov	newEip,eax
			push	ctx.regEax
			.while 1
				invoke	GetKernelBase,lpPI.dwProcessId
				.break .if eax
				invoke	GetThreadContext,lpPI.hThread,addr ctx
				mov	eax,ctx.regEip
				mov	edx,[esp]
				.break .if eax==edx
				invoke	Sleep,10
			.endw
			pop	ctx.regEax
			mov	ecx,_flags
			or	ecx,2048
			invoke	TORHook,lpPI.dwProcessId,proxyport,ecx,best_delta_t,localAddr,pipekey
			invoke	SuspendThread,lpPI.hThread
			lea	ecx,oldBytes
			invoke	WriteProcessMemory,lpPI.hProcess,newEip,ecx,2,addr hFile
			invoke	ResumeThread,lpPI.hThread
		.endif
	.endif
	invoke	GlobalFree,hMem
	mov	eax,hProcess1
	ret
CreateNewProcess	ENDP


UnloadDLL	PROC
	local	lParam:DWORD
	mov	unloaded,1
	.if hPipe
		invoke	CreateFile,addr pipename,GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
		push	eax
		xchg	edx,eax
		mov	dword ptr pipeData,'TIXE'
		invoke	WriteFile,edx,addr pipeData,512,addr lParam,0
		call	CloseHandle
		.while hPipe
			invoke	Sleep,10
		.endw
	.endif
	.if last_query
		invoke	GetTickCount
		sub	eax,last_query
		.if eax<1000
			invoke	Sleep,200
		.endif
	.endif
	invoke	SetEvent,hEvent
	invoke	CloseHandle,hEvent
	mov	edx,hostents
	.while edx
		push	dword ptr[edx]
		invoke	GlobalFree,edx
		pop	edx
	.endw
	mov	edx,onioncache
	.while edx
		push	dword ptr[edx]
		invoke	GlobalFree,edx
		pop	edx
	.endw
	mov	hostents,0
	mov	onioncache,0
	user32unload
	ret
UnloadDLL	ENDP

SetHibernationState	PROC	newState:DWORD
	mov	eax,newState
	mov	connections_allowed,al
	ret
SetHibernationState	ENDP

PipeThread	PROC	lParam:DWORD
	invoke	GlobalAlloc,GPTR,16384
	mov	conn_info_cache,eax
	mov	conn_info_cnt,0
	invoke	CreateEvent,0,1,0,0
	mov	hEvent,eax
	.while unloaded==0
		invoke	CreateNamedPipe,addr pipename,PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE or PIPE_READMODE_MESSAGE or PIPE_WAIT,1,1024,1024,INFINITE,0
		.break .if eax!=INVALID_HANDLE_VALUE
		invoke	Sleep,100
	.endw
	mov	hPipe,eax
	mov	pipeData,0
	.while 1
		.break .if unloaded
		invoke	ConnectNamedPipe,hPipe,0
		.break .if unloaded
		invoke	ReadFile,hPipe,addr pipeData,1024,addr lParam,0
		.if dword ptr pipeData=='CORP'
			lea	edi,pipeNotifyMsg
			push	edi
			writeLangStr	LANG_DLL_RESTRICTED_PROCESS,msgnp
			lea	edx,pipeData[12]
			.while byte ptr[edx]
				inc	edx
			.endw
			inc	edx
			movzx	ecx,byte ptr[edx]
			inc	edx
			.while (ecx!=0)&&(byte ptr[edx]!=0)
				mov	al,[edx]
				stosb
				inc	edx
				dec	ecx
			.endw
			writeLangStr	LANG_DLL_CREATED_A_NEW_PROCESS,msgnp1
			mov	eax,dword ptr pipeData[8]
			call	itoa
			mov	eax,' : '
			stosd
			dec	edi
			lea	edx,pipeData[12]
			mov	ecx,MAX_PROC_PATH
			mov	eax,edi
			sub	eax,offset pipeNotifyMsg
			.if eax>10000h
				int 3
			.endif
			.if eax > ecx
				xor	ecx,ecx
			.else
				sub	ecx,eax
			.endif
			.while (byte ptr[edx]!=0)&&(ecx!=0)
				mov	al,[edx]
				stosb
				inc	edx
				dec	ecx
			.endw
			mov	al,0
			stosb
			push	LOG_WARN
			call	Log
			mov	edx,dword ptr pipeData[8]
			movzx	ecx,saddr.sin_port
			mov	ebx,sysflags
			or	ebx,100h + 2048
			.if dword ptr pipeData[4] & 1
				or	ebx,64
			.else
				and	bl,64 xor -1
			.endif
			invoke	TORHook,edx,ecx,ebx,systemtimedelta,addr localhostname,dword ptr pipeData[4]
			invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		resolve_pipe
		socket_pipe
		tray_pipe
		.elseif dword ptr pipeData=='NNOC'
			mov	edi,conn_info_cache
			mov	eax,conn_info_cnt
			xor	ecx,ecx
			.while ecx<16
				.break .if !(al&1)
				shr	eax,1
				inc	ecx
			.endw
			.if ecx==16
				xor	ecx,ecx
			.endif
			shl	ecx,10
			push	ecx
			assume	edi:ptr connection_info
			lea	edi,[edi+ecx]
			push	edi
			xor	eax,eax
			stosd		;magic
			lea	esi,pipeData[4]
			movsd		;key
			movsd		;source IP
			movsw		;source port
			lodsd
			stosd		;dest IP
			.if (al==0ffh)&&(ah>=16)
				.while byte ptr[esi]
					movsb
				.endw
				movsb
			.endif
			movsw		;dest port
			lodsb
			stosb
			mov	edx,esi
			movzx	ecx,al
			.while (ecx!=0)&&(byte ptr[edx]!=0)
				mov	al,[edx]
				stosb
				inc	edx
				dec	ecx
			.endw
			mov	al,0
			stosb
			pop	edi
			pop	ecx
			mov	[edi].magic,'NNOC'
			shr	ecx,10
			mov	eax,1
			.if ecx
				shl	eax,cl
			.endif
			or	conn_info_cnt,eax
			.if connections_allowed == 0
				invoke	WriteFile,hPipe,addr _zero,4,addr lParam,0
				invoke	DisconnectNamedPipe,hPipe
				invoke	GlobalAlloc,GPTR,1024
				push	eax
				lea	edx,[eax+1020]
				push	edx
				push	eax
				movzx	edx,[edi].source_port
				xchg	dl,dh
				push	edx
				mov	ecx,[edi].source_ip
				xchg	cl,ch
				rol	ecx,16
				xchg	cl,ch
				push	ecx
				call	GetConnInfo
				call	GlobalFree
				.if [edi].magic==0
					invoke	ResetEvent,hEvent
				.endif
			.else
				.if dword ptr pipeData[4]==0
					inc	dword ptr pipeData[4]
				.endif
				invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
				invoke	DisconnectNamedPipe,hPipe
				mov	eax,conn_info_cnt
				.if ax==0ffffh
					invoke	WaitForSingleObject,hEvent,2000
					.if eax==WAIT_FAILED
						invoke	GetLastError
						.if eax==WAIT_TIMEOUT
							mov	conn_info_cnt,0
						.endif
					.endif
					invoke	ResetEvent,hEvent
				.endif
			.endif
			assume	edi:nothing
			mov	dword ptr pipeData,0
		.elseif dword ptr pipeData=='WOHS'
			user32PostMessage	hDialog,WM_USER+10,100,WM_LBUTTONUP
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		.elseif dword ptr pipeData=='CEXE' && byte ptr pipeData[4]==32
			user32SendMessage	hDialog,WM_USER+14,0,offset pipeData+5
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		.else
			invoke	GlobalAlloc,GPTR,2048
			mov	edi,eax
			push	edi
			push	edi
			writeLangStr	LANG_DLL_JUNKDATA,junkdata
			mov	ecx,lParam
			lea	esi,pipeData
			.while ecx
				lodsb
				.if al=='\'
					mov	ax,'\\'
					stosw
				.elseif al==13
					mov	ax,'r\'
					stosw
				.elseif al==10
					mov	ax,'n\'
					stosw
				.elseif al==9
					mov	ax,'t\'
					stosw
				.elseif (al>31)&&(al<128)
					stosb
				.else
					mov	word ptr[edi],'x\'
					inc	edi
					inc	edi
					mov	ah,al
					shr	al,4
					and	ax,0f0fh
					or	ax,3030h
					.if al>'9'
						add	al,7
					.endif
					.if ah>'9'
						add	ah,7
					.endif
					stosw
				.endif
			.endw
			mov	al,0
			stosb
			push	LOG_WARN
			call	Log
			call	GlobalFree
			invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		.endif
	.endw
	invoke	GlobalFree,conn_info_cache
	.if hPipe
		invoke	CloseHandle,hPipe
		mov	hPipe,0
	.endif
	invoke	ExitThread,0
	ret
PipeThread	ENDP

GetConnInfo	PROC	uses esi edi ebx _addr:DWORD,_port:DWORD,_result:DWORD,__port:DWORD
	mov	esi,conn_info_cache
	assume	esi:ptr connection_info
	mov	edx,conn_info_cnt
	xor	ecx,ecx
	mov	eax,1
	.while edx
		.if [esi+ecx].magic=='NNOC'
			push	eax
			mov	eax,[esi+ecx].source_ip
			xchg	al,ah
			rol	eax,16
			xchg	al,ah
			.if ((eax==0)||(eax==_addr))
				movzx	eax,word ptr[esi+ecx].source_port
				xchg	al,ah
				.if ax==word ptr _port
					lea	esi,[esi+ecx]
					push	esi
					lea	esi,[esi].dest_ip
					mov	edi,_result
					lodsd
					.if (al==0ffh)&&(ah>=16)
						.if byte ptr[esi]==0
							lodsb
							push	edi
							push	esi
							lodsw
							lea	edi,pipeNotifyMsg
							push	edi
							lodsb
							mov	edx,esi
							movzx	ecx,al
							.while (ecx!=0)&&(byte ptr[edx]!=0)
								mov	al,[edx]
								stosb
								inc	edx
								dec	ecx
							.endw
							writeLangStr	LANG_DLL_REINTERCEPT,reintercept
							mov	al,0
							stosb
							push	LOG_WARN
							call	Log
							pop	esi
							pop	edi
						.else
							xor	ecx,ecx
							.while byte ptr[esi] && ecx < 512
								movsb
								inc	ecx
							.endw
							.while byte ptr[esi]
								lodsb
							.endw
							lodsb
						.endif
					.else
						call	w_ip
					.endif
					mov	al,0
					stosb
					lodsw
					xchg	al,ah
					movzx	eax,ax
					mov	edx,__port
					mov	[edx],ax
					lea	edi,pipeNotifyMsg
					push	edi
					lodsb
					mov	edx,esi
					movzx	ecx,al
					.while (ecx!=0)&&(byte ptr[edx]!=0)
						mov	al,[edx]
						stosb
						inc	edx
						dec	ecx
					.endw
					writeLangStr	LANG_DLL_REDIRECTING,bypassmsg
					mov	edx,_result
					call	copyedx
					mov	al,':'
					stosb
					mov	eax,__port
					movzx	eax,word ptr[eax]
					call	itoa
					mov	eax,'. '
					stosd
					pop	edx
					pop	esi
					mov	[esi].magic,0
					pop	eax
					xor	eax,0ffffh
					and	conn_info_cnt,eax
					push	edx
					invoke	SetEvent,hEvent
					push	LOG_WARN
					call	Log
					xor	eax,eax
					inc	eax
					ret
				.endif
			.endif
			pop	eax
		.endif
		shr	edx,1
		shl	eax,1
		lea	ecx,[ecx+1024]
	.endw
	assume	esi:nothing
	xor	eax,eax
	ret
GetConnInfo	ENDP

GetAdvORVer	PROC
	mov	eax,00030000h		;0.3.0.0
	ret
GetAdvORVer	ENDP

iphlpprocs

End DllEntry
