socket_data	macro
	savesocket	dd	?,?
			db	100 dup(?)
	savewsasocket	dd	?,?
			db	100 dup(?)
endm

socket_init	macro
	mov	savesocket,0
	mov	savesocket[4],0
	mov	savewsasocket,0
	mov	savewsasocket[4],0
endm

socket_procs	macro
notify_wsock	PROC	uses esi edi ebx lpRet:DWORD,wsaerr:DWORD
	local	hMem:DWORD
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
	push	eax
	invoke	GlobalAlloc,GPTR,1024
	mov	hMem,eax
	mov	edi,hMem
	mov	eax,'KCOS'
	stosd
	mov	eax,pipe_key
	stosd
	mov	edx,lpRet
	mov	eax,[edx-4]
	stosd
	mov	eax,[edx]
	stosd
	mov	eax,[edx+4]
	stosd
	mov	eax,wsaerr
	stosd
	mov	edx,lpRet
	call	getdll
	mov	al,0
	stosb
	mov	ecx,edi
	mov	edi,hMem
	sub	ecx,edi
	pop	eax
	push	eax
	push	0
	mov	edx,esp
	push	eax
	invoke	WriteFile,eax,edi,ecx,edx,0
	pop	eax
	mov	edx,esp
	invoke	ReadFile,eax,edi,4,edx,0
	pop	eax
	pop	eax
	invoke	CloseHandle,eax
	invoke	GlobalFree,hMem
	ret
notify_wsock	ENDP

newsocket:
	jmp	_skipsig_s
	db	'AdvOR_'
	dd	offset savesocket
_skipsig_s:
	.if sysflags&16
		mov	eax,[esp+4]
		.if (eax!=AF_UNSPEC)&&(eax!=AF_UNIX)&&(eax!=AF_INET)
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAEAFNOSUPPORT
			invoke	WSASetLastError,WSAEAFNOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	12
		.elseif dword ptr[esp+8]!=SOCK_STREAM
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAESOCKTNOSUPPORT
			invoke	WSASetLastError,WSAESOCKTNOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	12
		.elseif (dword ptr[esp+12]!=IPPROTO_TCP)&&(dword ptr[esp+12]!=IPPROTO_IP)
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAEPROTONOSUPPORT
			invoke	WSASetLastError,WSAEPROTONOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	12
		.endif
	.endif
	jmp	dword ptr savesocket[4]

newwsasocket:
	jmp	_skipsig_ws
	db	'AdvOR_'
	dd	offset savewsasocket
_skipsig_ws:
	.if sysflags&16
		mov	eax,[esp+4]
		.if (eax!=AF_UNSPEC)&&(eax!=AF_UNIX)&&(eax!=AF_INET)
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAEAFNOSUPPORT
			invoke	WSASetLastError,WSAEAFNOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	24
		.elseif dword ptr[esp+8]!=SOCK_STREAM
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAESOCKTNOSUPPORT
			invoke	WSASetLastError,WSAESOCKTNOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	24
		.elseif (dword ptr[esp+12]!=IPPROTO_TCP)&&(dword ptr[esp+12]!=IPPROTO_IP)
			lea	eax,[esp+4+4]
			invoke	notify_wsock,eax,WSAEPROTONOSUPPORT
			invoke	WSASetLastError,WSAEPROTONOSUPPORT
			mov	eax,INVALID_SOCKET
			ret	24
		.endif
	.endif
	jmp	dword ptr savewsasocket[4]

wsaerr1	db	'WSAEPROTONOSUPPORT',0
wsaerr2	db	'WSAEAFNOSUPPORT',0
wsaerr3	db	'WSAESOCKTNOSUPPORT',0
wsaerr__ db	'WSAEINVAL',0

wsaerr_	dd	WSAEPROTONOSUPPORT,offset wsaerr1
	dd	WSAEAFNOSUPPORT,offset wsaerr2
	dd	WSAESOCKTNOSUPPORT,offset wsaerr3
	dd	-1

af_00		db	'AF_UNSPEC',0
af_01		db	'AF_UNIX',0
af_02		db	'AF_INET',0
af_03		db	'AF_IMPLINK',0
af_04		db	'AF_PUP',0
af_05		db	'AF_CHAOS',0
af_06		db	'AF_NS | AF_IPX',0
af_07		db	'AF_ISO',0
af_08		db	'AF_ECMA',0
af_09		db	'AF_DATAKIT',0
af_10		db	'AF_CCITT',0
af_11		db	'AF_SNA',0
af_12		db	'AF_DECnet',0
af_13		db	'AF_DLI',0
af_14		db	'AF_LAT',0
af_15		db	'AF_HYLINK',0
af_16		db	'AF_APPLETALK',0
af_17		db	'AF_NETBIOS',0
af_18		db	'AF_MAX',0

afs	dd	offset	af_00
	dd	offset	af_01
	dd	offset	af_02
	dd	offset	af_03
	dd	offset	af_04
	dd	offset	af_05
	dd	offset	af_06
	dd	offset	af_07
	dd	offset	af_08
	dd	offset	af_09
	dd	offset	af_10
	dd	offset	af_11
	dd	offset	af_12
	dd	offset	af_13
	dd	offset	af_14
	dd	offset	af_15
	dd	offset	af_16
	dd	offset	af_17
	dd	offset	af_18

strp1	db	'IPPROTO_IP',0
strp2	db	'IPPROTO_ICMP',0
strp3	db	'IPPROTO_GGP',0
strp4	db	'IPPROTO_TCP',0
strp5	db	'IPPROTO_PUP',0
strp6	db	'IPPROTO_UDP',0
strp7	db	'IPPROTO_IDP',0
strp8	db	'IPPROTO_ND',0
strp9	db	'IPPROTO_RAW',0
strpA	db	'IPPROTO_MAX',0

ipproto1	dd	0,offset strp1
		dd	1,offset strp2
		dd	2,offset strp3
		dd	6,offset strp4
		dd	12,offset strp5
		dd	17,offset strp6
		dd	22,offset strp7
		dd	77,offset strp8
		dd	255,offset strp9
		dd	256,offset strpA
		dd	-1

sockt1	db	'SOCK_STREAM',0
sockt2	db	'SOCK_DGRAM',0
sockt3	db	'SOCK_RAW',0
sockt4	db	'SOCK_RDM',0
sockt5	db	'SOCK_SEQPACKET',0

socktypes	dd	offset sockt1
		dd	offset sockt2
		dd	offset sockt3
		dd	offset sockt4
		dd	offset sockt5

endm

socket_pipe	macro
	.elseif dword ptr pipeData=='KCOS'
		lea	edi,pipeNotifyMsg
		push	edi
		writeLangStr	LANG_DLL_RESTRICTED_PROCESS,msgnp
		lea	edx,pipeData[8+16+1]
		call	copyedx
		writeLangStr	LANG_DLL_NON_TCP,msgns
		lea	edx,pipeData[8]
		mov	eax,[edx]
		.if eax>18
			mov	eax,' :FA'
			stosd
			mov	eax,[edx]
			call	itoa
		.else
			mov	edx,dword ptr afs[eax*4]
			call	copyedx
		.endif
		mov	eax,' , '
		stosd
		dec	edi
		mov	eax,dword ptr pipeData[12]
		.if (eax>=1)&&(eax<=5)
			dec	eax
			mov	edx,socktypes[eax*4]
			call	copyedx
		.else
			mov	eax,'epyT'
			stosd
			mov	ax,' :'
			stosw
			mov	eax,dword ptr pipeData[12]
			call	itoa
		.endif
		mov	eax,' , '
		stosd
		dec	edi
		mov	eax,dword ptr pipeData[16]
		lea	edx,ipproto1
		.while dword ptr[edx]!=-1
			.if eax==[edx]
				.break
			.endif
			lea	edx,[edx+8]
		.endw
		.if dword ptr[edx]!=-1
			mov	edx,[edx+4]
			call	copyedx
		.else
			mov	eax,'torP'
			stosd
			mov	eax,'loco'
			stosd
			mov	ax,' :'
			stosw
			mov	eax,dword ptr pipeData[16]
			call	itoa
		.endif
		writeLangStr	LANG_DLL_NON_TCP_2,msgns1
		mov	eax,dword ptr pipeData[20]
		lea	edx,wsaerr_
		.while dword ptr[edx]!=-1
			.if eax==[edx]
				mov	edx,[edx+4]
				.break
			.endif
			lea	edx,[edx+4]
		.endw
		.if dword ptr[edx]==-1
			lea	edx,wsaerr__
		.endif
		call	copyedx
		mov	eax,'. '
		stosd
		push	LOG_WARN
		call	Log
		invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
		invoke	DisconnectNamedPipe,hPipe
		mov	dword ptr pipeData,0
endm

iphlpdata	macro
	dlgHs			dd	?
	plugins_hs		dd	?
	hIphlp			dd	?
	_GetTcpTable		dd	?
	_GetExtendedTcpTable	dd	?
	_SetTcpEntry		dd	?
	tcpTbl			dd	?
	tcpTblSize		dd	?
endm

MIB_TCPROW	struct
	dwState		dd	?
	dwLocalAddr	dd	?
	dwLocalPort	dd	?
	dwRemoteAddr	dd	?
	dwRemotePort	dd	?
MIB_TCPROW	ends

MIB_TCPROW_OWNER_PID	struct
	dwState		dd	?
	dwLocalAddr	dd	?
	dwLocalPort	dd	?
	dwRemoteAddr	dd	?
	dwRemotePort	dd	?
	dwOwningPid	dd	?
MIB_TCPROW_OWNER_PID	ends

MIB_TCP_STATE_CLOSED = 1
MIB_TCP_STATE_LISTEN = 2
MIB_TCP_STATE_SYN_SENT = 3
MIB_TCP_STATE_SYN_RCVD = 4
MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_FIN_WAIT1 = 6
MIB_TCP_STATE_FIN_WAIT2 = 7
MIB_TCP_STATE_CLOSE_WAIT = 8
MIB_TCP_STATE_CLOSING = 9
MIB_TCP_STATE_LAST_ACK = 10
MIB_TCP_STATE_TIME_WAIT = 11
MIB_TCP_STATE_DELETE_TCB = 12

TCP_TABLE_OWNER_PID_LISTENER = 3
TCP_TABLE_OWNER_PID_CONNECTIONS = 4

iphlpinit	macro
	mov	hIphlp,0
	mov	_GetTcpTable,0
	mov	_GetExtendedTcpTable,0
	mov	_SetTcpEntry,0
	mov	tcpTbl,0
endm

iphlpprocs	macro
iphlplib	db	'iphlpapi.dll',0
ipfn1		db	'GetTcpTable',0
ipfn2		db	'GetExtendedTcpTable',0
ipfn3		db	'SetTcpEntry',0
lvPorts0	db	'Application [PID]',0
lvPorts1	db	'Local address',0
lvPorts2	db	'Local port',0
internalConn	db	'[Internal]',0

initiphlp:
	.if hIphlp==0
		invoke	LoadLibrary,addr iphlplib
		mov	hIphlp,eax
		.if eax
			invoke	GetProcAddress,eax,addr ipfn2
			.if eax
				mov	_GetExtendedTcpTable,eax
			.endif
			invoke	GetProcAddress,hIphlp,addr ipfn1
			.if eax
				mov	_GetTcpTable,eax
			.endif
			invoke	GetProcAddress,hIphlp,addr ipfn3
			.if eax
				mov	_SetTcpEntry,eax
			.endif
		.endif
	.endif
	ret

openPortsProc	PROC	uses esi edi ebx hDlg:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg==WM_INITDIALOG
		user32SendDlgItemMessage	hDlg,400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_ONECLICKACTIVATE or LVS_EX_FULLROWSELECT,LVS_EX_ONECLICKACTIVATE or LVS_EX_FULLROWSELECT
		langChangeDialogString	hDlg,LANG_DLG_HS_SELECT_A_SERVICE
		langChangeDialogString2	hDlg,1,LANG_DLG_HS_SELECT_PORT
		langChangeDialogString2	hDlg,2,LANG_DLG_HS_CANCEL
		.if _GetExtendedTcpTable
			langChangeDialogString2	hDlg,3,LANG_DLG_HS_SELECT_PROCESS
			mov	lvcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH
			mov	lvcol.fmt,LVCFMT_LEFT
			mov	lvcol.lx,120
			mov	lvcol.pszText,offset lvPorts0
			mov	lvcol.cchTextMax,sizeof lvPorts0
			mov	lvcol.iSubItem,0
			langInsertColumn	hDlg,400,LVM_INSERTCOLUMN,0,offset lvcol,LANG_DLG_HS_APPLICATION
			mov	lvcol.lx,90
			mov	lvcol.pszText,offset lvPorts1
			mov	lvcol.cchTextMax,sizeof lvPorts1
			langInsertColumn	hDlg,400,LVM_INSERTCOLUMN,1,offset lvcol,LANG_DLG_HS_LOCAL_ADDRESS
			mov	lvcol.lx,60
			mov	lvcol.pszText,offset lvPorts2
			mov	lvcol.cchTextMax,sizeof lvPorts2
			langInsertColumn	hDlg,400,LVM_INSERTCOLUMN,2,offset lvcol,LANG_DLG_HS_LOCAL_PORT
			.if tcpTbl==0
				mov	tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,1024
				mov	tcpTbl,eax
			.endif
			push	0
			push	TCP_TABLE_OWNER_PID_LISTENER
			push	AF_INET
			push	1
			lea	edx,tcpTblSize
			push	edx
			push	tcpTbl
			call	_GetExtendedTcpTable
			.if eax!=NO_ERROR
				invoke	GlobalFree,tcpTbl
				add	tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,tcpTblSize
				mov	tcpTbl,eax
				push	0
				push	TCP_TABLE_OWNER_PID_LISTENER
				push	AF_INET
				push	1
				lea	edx,tcpTblSize
				push	edx
				push	tcpTbl
				call	_GetExtendedTcpTable
			.endif
			xor	ecx,ecx
			mov	lvit.iItem,ecx
			mov	lvit.iSubItem,0
			mov	lvit.state,0
			mov	lvit.stateMask,0
			mov	lvit.pszText,0
			mov	lvit.cchTextMax,0
			mov	lvit.iImage,0
			invoke	GlobalAlloc,GPTR,1024
			push	eax
			mov	edi,eax
			invoke	GetCurrentProcessId
			mov	ebx,eax
			mov	esi,tcpTbl
			lodsd
			mov	ecx,eax
			.while ecx
				mov	edi,[esp]
				push	ecx
				assume	esi:ptr MIB_TCPROW_OWNER_PID
				.if [esi].dwOwningPid!=ebx
					push	ebx
					mov	lvit.pszText,edi
					invoke	getExeName,[esi].dwOwningPid
					mov	ax,'[ '
					stosw
					mov	eax,[esi].dwOwningPid
					call	itoa
					mov	ax,']'
					stosw
					mov	lvit.imask,LVIF_PARAM or LVIF_TEXT
					mov	lvit.cchTextMax,100
					mov	lvit.lParam,esi
					mov	lvit.iSubItem,0
					invoke	get_unicode,lvit.pszText
					push	eax
					mov	lvit.pszText,eax
					user32SendDlgItemMessageW	hDlg,400,LVM_INSERTITEMW,0,offset lvit
					mov	lvit.iItem,eax
					call	GlobalFree
					mov	edi,[esp+4+4]
					mov	lvit.pszText,edi
					mov	eax,[esi].dwLocalAddr
					call	w_ip
					mov	al,':'
					stosb
					mov	eax,[esi].dwLocalPort
					xchg	al,ah
					call	itoa
					mov	al,0
					stosb
					mov	lvit.iSubItem,1
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
					mov	edi,[esp+4+4]
					mov	eax,[esi].dwLocalPort
					xchg	al,ah
					call	itoa
					mov	al,0
					stosb
					mov	lvit.iSubItem,2
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.pszText,edi
					mov	eax,[esi].dwLocalPort
					xchg	al,ah
					call	itoa
					mov	al,0
					stosb
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
					pop	ebx
				.endif
				assume	esi:nothing
				lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
				pop	ecx
				dec	ecx
			.endw
			mov	esi,plugins_hs
			.if esi
				.while dword ptr[esi]
					mov	edi,[esp]
					mov	byte ptr[edi],0
					mov	eax,[esi]
					mov	lvit.pszText,eax
					mov	lvit.lParam,eax
					mov	lvit.imask,LVIF_PARAM or LVIF_TEXT
					mov	lvit.cchTextMax,100
					mov	lvit.iSubItem,0
					invoke	get_unicode,lvit.pszText
					push	eax
					mov	lvit.pszText,eax
					user32SendDlgItemMessageW	hDlg,400,LVM_INSERTITEMW,0,offset lvit
					mov	lvit.iItem,eax
					call	GlobalFree
					mov	lvit.pszText,edi
					mov	lvit.iSubItem,1
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
					mov	lvit.iSubItem,2
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.pszText,edi
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
					lodsd
				.endw
			.endif
			call	GlobalFree
		.elseif _GetTcpTable
			mov	lvcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH
			mov	lvcol.fmt,LVCFMT_LEFT
			mov	lvcol.lx,150
			mov	lvcol.pszText,offset lvPorts1
			mov	lvcol.cchTextMax,sizeof lvPorts1
			mov	lvcol.iSubItem,0
			langInsertColumn	hDlg,400,LVM_INSERTCOLUMN,0,offset lvcol,LANG_DLG_HS_LOCAL_ADDRESS
			mov	lvcol.lx,60
			mov	lvcol.pszText,offset lvPorts2
			mov	lvcol.cchTextMax,sizeof lvPorts2
			langInsertColumn	hDlg,400,LVM_INSERTCOLUMN,1,offset lvcol,LANG_DLG_HS_LOCAL_PORT
			.if tcpTbl==0
				mov	tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,1024
				mov	tcpTbl,eax
			.endif
			push	1
			lea	edx,tcpTblSize
			push	edx
			push	tcpTbl
			call	_GetTcpTable
			.if eax==ERROR_INSUFFICIENT_BUFFER
				invoke	GlobalFree,tcpTbl
				add	tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,tcpTblSize
				mov	tcpTbl,eax
				push	1
				lea	edx,tcpTblSize
				push	edx
				push	tcpTbl
				call	_GetTcpTable
			.endif
			xor	ecx,ecx
			mov	lvit.iItem,ecx
			mov	lvit.iSubItem,0
			mov	lvit.state,0
			mov	lvit.stateMask,0
			mov	lvit.pszText,0
			mov	lvit.cchTextMax,0
			mov	lvit.iImage,0
			invoke	GlobalAlloc,GPTR,1024
			push	eax
			mov	edi,eax
			mov	esi,tcpTbl
			lodsd
			mov	ecx,eax
			.while ecx
				mov	edi,[esp]
				push	ecx
				assume	esi:ptr MIB_TCPROW
				.if [esi].dwState==MIB_TCP_STATE_LISTEN
					mov	lvit.pszText,edi
					mov	eax,[esi].dwLocalAddr
					call	w_ip
					mov	al,':'
					stosb
					mov	eax,[esi].dwLocalPort
					xchg	al,ah
					call	itoa
					mov	al,0
					stosb
					mov	lvit.imask,LVIF_PARAM or LVIF_TEXT
					mov	lvit.cchTextMax,100
					mov	lvit.lParam,esi
					mov	lvit.iSubItem,0
					user32SendDlgItemMessage	hDlg,400,LVM_INSERTITEM,0,offset lvit
					mov	lvit.iSubItem,1
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.iItem,eax
					mov	lvit.pszText,edi
					mov	eax,[esi].dwLocalPort
					xchg	al,ah
					call	itoa
					mov	al,0
					stosb
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
				.endif
				assume	esi:nothing
				lea	esi,[esi+sizeof MIB_TCPROW]
				pop	ecx
				dec	ecx
			.endw
			mov	esi,plugins_hs
			.if esi
				.while dword ptr[esi]
					mov	edi,[esp]
					mov	byte ptr[edi],0
					mov	eax,[esi]
					mov	lvit.pszText,eax
					mov	lvit.lParam,eax
					mov	lvit.imask,LVIF_PARAM or LVIF_TEXT
					mov	lvit.cchTextMax,100
					mov	lvit.iSubItem,0
					user32SendDlgItemMessage	hDlg,400,LVM_INSERTITEM,0,offset lvit
					mov	lvit.iItem,eax
					mov	lvit.pszText,edi
					mov	lvit.iSubItem,1
					mov	lvit.imask,LVIF_TEXT
					mov	lvit.cchTextMax,100
					user32SendDlgItemMessage	hDlg,400,LVM_SETITEM,0,offset lvit
					lodsd
				.endw
			.endif
			call	GlobalFree
		.endif
	.elseif uMsg==WM_COMMAND
		mov	eax,wParam
		.if (ax==2)
			.if tcpTbl
				invoke	GlobalFree,tcpTbl
				mov	tcpTbl,0
			.endif
			user32EndDialog	hDlg,0
		.elseif ax==1
			user32SendDlgItemMessage	hDlg,400,LVM_GETNEXTITEM,-1,LVNI_SELECTED
			.if eax!=-1
				mov	lvit.iItem,eax
				mov	lvit.imask,LVIF_PARAM
				mov	lvit.lParam,0
				user32SendDlgItemMessage	hDlg,400,LVM_GETITEM,0,offset lvit
				mov	ecx,lvit.lParam
				mov	edx,plugins_hs
				.if plugins_hs
					.while dword ptr[edx]
						.break .if ecx==[edx]
						lea	edx,[edx+4]
					.endw
				.endif
				.if edx && (ecx==[edx]) && (ecx!=0)
					mov	edi,[edx]
					user32SendDlgItemMessage	dlgHs,19101,WM_SETTEXT,0,edi
					lea	edi,internalConn
					user32SendDlgItemMessage	dlgHs,19100,WM_SETTEXT,0,edi
					lea	edi,lParam
					mov	dword ptr[edi],'08'
					user32SendDlgItemMessage	dlgHs,19102,WM_SETTEXT,0,edi
				.elseif (eax!=0)&&(lvit.lParam!=0)
					.if _GetExtendedTcpTable
						mov	esi,lvit.lParam
						assume	esi:ptr MIB_TCPROW_OWNER_PID
						invoke	GlobalAlloc,GPTR,1024
						push	eax
						mov	edi,eax
						mov	eax,[esi].dwLocalAddr
						.if eax==0
							mov	eax,0100007fh
						.endif
						call	w_ip
						mov	al,0
						stosb
						mov	edi,[esp]
						user32SendDlgItemMessage	dlgHs,19101,WM_SETTEXT,0,edi
						mov	eax,[esi].dwLocalPort
						xchg	al,ah
						call	itoa
						mov	al,0
						stosb
						mov	edi,[esp]
						user32SendDlgItemMessage	dlgHs,19100,WM_SETTEXT,0,edi
						user32SendDlgItemMessage	dlgHs,19102,WM_SETTEXT,0,edi
						call	GlobalFree
						assume	esi:nothing
					.else
						mov	esi,lvit.lParam
						assume	esi:ptr MIB_TCPROW
						invoke	GlobalAlloc,GPTR,1024
						push	eax
						mov	edi,eax
						mov	eax,[esi].dwLocalAddr
						.if eax==0
							mov	eax,0100007fh
						.endif
						call	w_ip
						mov	al,0
						stosb
						mov	edi,[esp]
						user32SendDlgItemMessage	dlgHs,19101,WM_SETTEXT,0,edi
						mov	eax,[esi].dwLocalPort
						xchg	al,ah
						call	itoa
						mov	al,0
						stosb
						mov	edi,[esp]
						user32SendDlgItemMessage	dlgHs,19100,WM_SETTEXT,0,edi
						user32SendDlgItemMessage	dlgHs,19102,WM_SETTEXT,0,edi
						call	GlobalFree
						assume	esi:nothing
					.endif
				.endif
			.endif
			.if tcpTbl
				invoke	GlobalFree,tcpTbl
				mov	tcpTbl,0
			.endif
			user32EndDialog	hDlg,0
		.elseif ax==3
			user32SendDlgItemMessage	hDlg,400,LVM_GETNEXTITEM,-1,LVNI_SELECTED
			.if eax!=-1
				mov	lvit.iItem,eax
				mov	lvit.imask,LVIF_PARAM
				mov	lvit.lParam,0
				user32SendDlgItemMessage	hDlg,400,LVM_GETITEM,0,offset lvit
				mov	ecx,lvit.lParam
				mov	edx,plugins_hs
				.if plugins_hs
					.while dword ptr[edx]
						.break .if ecx==[edx]
						lea	edx,[edx+4]
					.endw
				.endif
				.if edx && (ecx==[edx]) && (ecx!=0)
					mov	edi,[edx]
					user32SendDlgItemMessage	dlgHs,19101,WM_SETTEXT,0,edi
					lea	edi,internalConn
					user32SendDlgItemMessage	dlgHs,19100,WM_SETTEXT,0,edi
					lea	edi,lParam
					mov	dword ptr[edi],'08'
					user32SendDlgItemMessage	dlgHs,19102,WM_SETTEXT,0,edi
				.elseif (eax!=0)&&(lvit.lParam!=0)
					mov	esi,lvit.lParam
					assume	esi:ptr MIB_TCPROW_OWNER_PID
					push	[esi].dwOwningPid
					invoke	GlobalAlloc,GPTR,1024
					push	eax
					mov	edi,eax
					mov	eax,[esi].dwLocalAddr
					.if eax==0
						mov	eax,0100007fh
					.endif
					call	w_ip
					mov	al,0
					stosb
					mov	edi,[esp]
					user32SendDlgItemMessage	dlgHs,19101,WM_SETTEXT,0,edi
					mov	esi,tcpTbl
					lodsd
					mov	ecx,eax
					.while ecx
						push	ecx
						mov	eax,[esp+4+4]
						.if eax==[esi].dwOwningPid
							mov	eax,[esi].dwLocalPort
							xchg	al,ah
							call	itoa
							mov	al,','
							stosb
							mov	edx,edi
							sub	edx,[esp+4]
							.break .if edx>1000
						.endif
						pop	ecx
						lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
						dec	ecx
					.endw
					.if edi!=[esp]
						dec	edi
					.endif
					mov	al,0
					stosb
					mov	edi,[esp]
					user32SendDlgItemMessage	dlgHs,19100,WM_SETTEXT,0,edi
					user32SendDlgItemMessage	dlgHs,19102,WM_SETTEXT,0,edi
					call	GlobalFree
					pop	eax
					assume	esi:nothing
				.endif
			.endif
			.if tcpTbl
				invoke	GlobalFree,tcpTbl
				mov	tcpTbl,0
			.endif
			user32EndDialog	hDlg,0
		.endif
	.endif
	xor	eax,eax
	ret
openPortsProc	ENDP

ShowOpenPorts	PROC	hParent:DWORD,hDlg:DWORD,pl_hs:DWORD
	call	initiphlp
	push	hDlg
	pop	dlgHs
	push	pl_hs
	pop	plugins_hs
	.if _GetExtendedTcpTable
		user32DialogBoxParam	2001,hParent,offset openPortsProc,0
	.elseif _GetTcpTable
		user32DialogBoxParam	2000,hParent,offset openPortsProc,0
	.else
		xor	eax,eax
		ret
	.endif
	xor	eax,eax
	inc	eax
	ret
ShowOpenPorts	ENDP

PidFromAddr	PROC	uses esi edi ebx address:DWORD,port:DWORD
	local	_tcpTbl:DWORD,_tcpTblSize:DWORD,__pid:DWORD
	mov	__pid,0
	call	initiphlp
	.if _GetExtendedTcpTable
		mov	_tcpTblSize,1024
		invoke	GlobalAlloc,GPTR,1024
		mov	_tcpTbl,eax
		push	0
		push	TCP_TABLE_OWNER_PID_CONNECTIONS
		push	AF_INET
		push	1
		lea	edx,_tcpTblSize
		push	edx
		push	_tcpTbl
		call	_GetExtendedTcpTable
		.if eax!=NO_ERROR
			invoke	GlobalFree,_tcpTbl
			add	_tcpTblSize,1024
			invoke	GlobalAlloc,GPTR,_tcpTblSize
			mov	_tcpTbl,eax
			push	0
			push	TCP_TABLE_OWNER_PID_CONNECTIONS
			push	AF_INET
			push	1
			lea	edx,_tcpTblSize
			push	edx
			push	_tcpTbl
			call	_GetExtendedTcpTable
		.endif
		mov	esi,_tcpTbl
		lodsd
		mov	ecx,eax
		.while ecx
			push	ecx
			assume	esi:ptr MIB_TCPROW_OWNER_PID
			mov	eax,address
			.if [esi].dwLocalAddr==eax
				mov	eax,port
				xchg	al,ah
				.if word ptr [esi].dwLocalPort==ax
					mov	eax,[esi].dwOwningPid
					mov	__pid,eax
					pop	ecx
					.break
				.endif
			.endif
			assume	esi:nothing
			lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
			pop	ecx
			dec	ecx
		.endw
		invoke	GlobalFree,_tcpTbl
	.endif
	mov	eax,__pid
	ret
PidFromAddr	ENDP

WarnOpenConnections	PROC	uses esi edi ebx __pid:DWORD,warn:DWORD
	local	_tcpTbl:DWORD,_tcpTblSize:DWORD
	mov	eax,__pid
	lea	edx,hooklist
	.while dword ptr[edx]
		.if eax==[edx]
			xor	eax,eax
			inc	eax
			ret
		.endif
		lea	edx,[edx+4]
	.endw
	call	initiphlp
	.if _GetExtendedTcpTable && _SetTcpEntry
		mov	_tcpTblSize,1024
		invoke	GlobalAlloc,GPTR,1024
		mov	_tcpTbl,eax
		invoke	GlobalAlloc,GPTR,4096
		push	eax
		.if warn!=0
			push	0
			push	TCP_TABLE_OWNER_PID_CONNECTIONS
			push	AF_INET
			push	1
			lea	edx,_tcpTblSize
			push	edx
			push	_tcpTbl
			call	_GetExtendedTcpTable
			.if eax!=NO_ERROR
				invoke	GlobalFree,_tcpTbl
				add	_tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,_tcpTblSize
				mov	_tcpTbl,eax
				push	0
				push	TCP_TABLE_OWNER_PID_CONNECTIONS
				push	AF_INET
				push	1
				lea	edx,_tcpTblSize
				push	edx
				push	_tcpTbl
				call	_GetExtendedTcpTable
			.endif
			mov	esi,_tcpTbl
			lodsd
			mov	ecx,eax
			.while ecx
				push	ecx
				assume	esi:ptr MIB_TCPROW_OWNER_PID
				mov	eax,[esi].dwOwningPid
				.if eax==__pid
					mov	eax,[esi].dwRemoteAddr
					.if al!=127
						pop	ecx
						.break
					.endif
				.endif
				assume	esi:nothing
				lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
				pop	ecx
				dec	ecx
			.endw
			.if ecx
				mov	edi,[esp]
				invoke	GetProcessName,__pid
				writeLangStr	LANG_DLL_CONNECTIONS_1,openconns
				mov	eax,0a0d0a0dh
				stosd

				mov	esi,_tcpTbl
				lodsd
				mov	ecx,eax
				.while ecx
					push	ecx
					assume	esi:ptr MIB_TCPROW_OWNER_PID
					mov	eax,[esi].dwOwningPid
					.if eax==__pid
						mov	eax,[esi].dwRemoteAddr
						.if al!=127
							mov	byte ptr[edi],9
							inc	edi
							call	w_ip
							mov	al,':'
							stosb
							movzx	eax,word ptr [esi].dwLocalPort
							xchg	al,ah
							call	itoa
							mov	ax,0a0dh
							stosw
						.endif
					.endif
					assume	esi:nothing
					lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
					pop	ecx
					dec	ecx
					mov	eax,edi
					sub	eax,[esp]
					.break .if eax>4000
				.endw
				.if eax>4000
					mov	eax,2e2e2e09h
					stosd
					mov	ax,0a0dh
					stosw
				.endif
				mov	ax,0a0dh
				stosw
				writeLangStr	LANG_DLL_CONNECTIONS_2,openconns1
				mov	edx,[esp]
				messagebox1	edx
				.if eax==IDCANCEL
					call	GlobalFree
					invoke	GlobalFree,_tcpTbl
					xor	eax,eax
					ret
				.endif
			.else
				mov	eax,IDNO
			.endif
		.else
			mov	eax,IDYES
		.endif
		.if eax==IDYES
			push	0
			push	TCP_TABLE_OWNER_PID_CONNECTIONS
			push	AF_INET
			push	1
			lea	edx,_tcpTblSize
			push	edx
			push	_tcpTbl
			call	_GetExtendedTcpTable
			.if eax!=NO_ERROR
				invoke	GlobalFree,_tcpTbl
				add	_tcpTblSize,1024
				invoke	GlobalAlloc,GPTR,_tcpTblSize
				mov	_tcpTbl,eax
				push	0
				push	TCP_TABLE_OWNER_PID_CONNECTIONS
				push	AF_INET
				push	1
				lea	edx,_tcpTblSize
				push	edx
				push	_tcpTbl
				call	_GetExtendedTcpTable
			.endif
			mov	esi,_tcpTbl
			lodsd
			mov	ecx,eax
			.while ecx
				push	ecx
				assume	esi:ptr MIB_TCPROW_OWNER_PID
				mov	eax,[esi].dwOwningPid
				.if eax==__pid
					mov	eax,[esi].dwRemoteAddr
					.if al!=127
						mov	edi,[esp+4]
						assume	edi:ptr MIB_TCPROW
						mov	[edi].dwState,MIB_TCP_STATE_DELETE_TCB
						mov	eax,[esi].dwLocalAddr
						mov	[edi].dwLocalAddr,eax
						mov	eax,[esi].dwLocalPort
						mov	[edi].dwLocalPort,eax
						mov	eax,[esi].dwRemoteAddr
						mov	[edi].dwRemoteAddr,eax
						mov	eax,[esi].dwRemotePort
						mov	[edi].dwRemotePort,eax
						assume	edi:nothing
						push	edi
						call	_SetTcpEntry
					.endif
				.endif
				assume	esi:nothing
				lea	esi,[esi+sizeof MIB_TCPROW_OWNER_PID]
				pop	ecx
				dec	ecx
			.endw
		.endif
		call	GlobalFree
		invoke	GlobalFree,_tcpTbl
	.endif
	xor	eax,eax
	inc	eax
	ret
WarnOpenConnections	ENDP

endm
