;h_listptr = ptr ip
;h_addrtype
;h_length

get_cached_ip	PROTO	:DWORD,:DWORD

MAX_HOST_TIME = 10*60*1000

host_data	struct
	_next		dd	?
	busy		db	?
	thread_id	dd	?
	expires		dd	?
	hostname	db	512 dup(?)
	ip		dd	?
	h_aliasptr	dd	?
	h_listptr	dd	2 dup(?)

	h_name		dd	?
	h_aliases	dd	?
	h_addrtype	dw	?
	h_length	dw	?
	h_addr_list	dd	?

	hostdata	db	1024 dup(?)
host_data	ends

addrinfo	struct
	ai_flags	dd	?
	ai_family	dd	?
	ai_socktype	dd	?
	ai_protocol	dd	?
	ai_addrlen	dd	?
	ai_canonname	dd	?
	ai_addr		dd	?
	ai_next		dd	?
addrinfo	ends


resolve_data	macro
	last_query	dd	?
	notify_wpad	db	?
	hostents	dd	?
	onioncache	dd	?
	next_fake_ip	dd	?
	ainfo		addrinfo	<>
	savegethostbyname dd	?,?
			db	100 dup(?)
	savegethostbyaddr dd	?,?
			db	100 dup(?)
	savewsaasyncgethostbyname dd	?,?
			db	100 dup(?)
	savewsaasyncgethostbyaddr dd	?,?
			db	100 dup(?)
	savegethostname	dd	?,?
			db	100 dup(?)
	savegetaddrinfo	dd	?,?
			db	100 dup(?)
	savegetaddrinfow dd	?,?
			db	100 dup(?)
	savegetnameinfo	dd	?,?
			db	100 dup(?)
	savegetnameinfow dd	?,?
			db	100 dup(?)
endm

resolve_init	macro
	lea	edx,localname
	lea	edi,localhostname
	cld
	call	copyedx
	mov	al,0
	stosb
	mov	savegethostname,0
	mov	savegethostname[4],0
	mov	savegethostbyname,0
	mov	savegethostbyname[4],0
	mov	savegethostbyaddr,0
	mov	savegethostbyaddr[4],0
	mov	savewsaasyncgethostbyname,0
	mov	savewsaasyncgethostbyname[4],0
	mov	savewsaasyncgethostbyaddr,0
	mov	savewsaasyncgethostbyaddr[4],0
	mov	savegetaddrinfo,0
	mov	savegetaddrinfo[4],0
	mov	savegetnameinfo,0
	mov	savegetnameinfo[4],0
	mov	savegetaddrinfow,0
	mov	savegetaddrinfow[4],0
	mov	savegetnameinfow,0
	mov	savegetnameinfow[4],0
	mov	hostents,0
	mov	onioncache,0
	mov	notify_wpad,0
	mov	last_query,0
	mov	next_fake_ip,10ffh
endm

get_hostent	macro
	invoke	GetCurrentThreadId
	mov	edx,hostents
	assume	edx:ptr host_data
	.if edx
		.while edx
			.break .if (eax==[edx].thread_id)
			mov	edx,[edx]._next
		.endw
	;	.if edx
	;		.while [edx].busy
	;			push	edx
	;			push	eax
	;			invoke	Sleep,10
	;			pop	eax
	;			pop	edx
	;		.endw
	;	.endif
	.endif
	.if edx==0
		push	eax
		invoke	GetTickCount
		mov	ecx,eax
		mov	edx,hostents
		.while edx
			mov	eax,ecx
			sub	eax,[edx].expires
			.if (eax>=MAX_HOST_TIME)	;&&([edx].busy==0)
				.break
			.endif
			mov	edx,[edx]._next
		.endw
		.if edx==0
			invoke	GlobalAlloc,GPTR,sizeof host_data
			lea	edx,hostents
			.while dword ptr[edx]
				mov	edx,dword ptr[edx]
			.endw
			mov	dword ptr[edx],eax
			mov	[edx]._next,0
			mov	edx,eax
		.endif
		pop	eax
		mov	[edx].thread_id,eax
	.endif
	mov	[edx].busy,1
	push	edx
	invoke	GetTickCount
	pop	edx
	mov	[edx].expires,eax
	mov	[edx].hostname,0
	lea	eax,[edx].hostname
	mov	[edx].h_name,eax
	lea	eax,[edx].h_aliasptr
	mov	dword ptr[eax],0
	mov	[edx].h_aliases,eax
	lea	eax,[edx].h_listptr
	lea	ecx,[edx].ip
	mov	[eax],ecx
	mov	dword ptr[eax+4],0
	mov	[edx].h_addr_list,eax
	mov	[edx].ip,0
	assume	edx:nothing
endm

select_read	macro
	push	last_query
	.while unloaded==0
		invoke	GetTickCount
		mov	last_query,eax
		sub	eax,[esp]
		.if eax>100000
			xor	eax,eax
			dec	eax
			.break
		.endif
		mov	fds.fd_count,1
		mov	eax,hSocket
		mov	fds.fd_array,eax
		mov	twait.tv_sec,0
		mov	twait.tv_usec,100000
		invoke	select,1,addr fds,0,0,addr twait
		.break .if eax
	.endw
	pop	edx
	.if eax==1
		push	0
		mov	edx,esp
		invoke	recv,hSocket,edx,4,MSG_PEEK
		pop	edx
		.if (eax==0)||(eax==SOCKET_ERROR)
			invoke	closesocket,hSocket
			mov	hSocket,0
			xor	eax,eax
			dec	eax
		.else
			xor	eax,eax
			inc	eax
		.endif
	.elseif unloaded
		invoke	closesocket,hSocket
		mov	hSocket,0
		xor	eax,eax
		dec	eax
	.endif
endm

select_write	macro
	.while unloaded==0
		invoke	GetTickCount
		mov	last_query,eax
		mov	fds.fd_count,1
		mov	eax,hSocket
		mov	fds.fd_array,eax
		mov	twait.tv_sec,0
		mov	twait.tv_usec,100000
		invoke	select,1,0,addr fds,0,addr twait
		.break .if eax
		mov	fds.fd_count,1
		mov	eax,hSocket
		mov	fds.fd_array,eax
		mov	twait.tv_sec,0
		mov	twait.tv_usec,0
		invoke	select,1,addr fds,0,0,addr twait
		.if eax
			invoke	closesocket,hSocket
			mov	hSocket,0
			xor	eax,eax
			dec	eax
		.endif
	.endw
	.if unloaded
		invoke	closesocket,hSocket
		mov	hSocket,0
		xor	eax,eax
		dec	eax
	.endif
endm

resolve_procs	macro
localname	db	'localhost',0
localnamew	dw	'l','o','c','a','l','h','o','s','t',0
;nohost		db	0
;nohostw		dw	0

get_ip	PROC	uses esi ebx ptrIp:DWORD
	xor	eax,eax
	xor	ecx,ecx
	mov	esi,ptrIp
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	mov	cl,al
	.if ((byte ptr[esi-1]!='.')&&(byte ptr[esi-1]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	mov	ch,al
	.if ((byte ptr[esi-1]!='.')&&(byte ptr[esi-1]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	shl	eax,16
	or	ecx,eax
	.if ((byte ptr[esi-1]!='.')&&(byte ptr[esi-1]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if ((byte ptr[esi-1]!='.')&&(byte ptr[esi-1]>32))
		xor	eax,eax
		ret
	.endif
	shl	eax,16+8
	or	ecx,eax
	xor	eax,eax
	inc	eax
	ret
get_ip	ENDP

get_ipW	PROC	uses esi ebx ptrIp:DWORD
	xor	eax,eax
	xor	ecx,ecx
	mov	esi,ptrIp
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoiW
	.if eax>255
		xor	eax,eax
		ret
	.endif
	mov	cl,al
	.if ((byte ptr[esi-2]!='.')&&(byte ptr[esi-2]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoiW
	.if eax>255
		xor	eax,eax
		ret
	.endif
	mov	ch,al
	.if ((byte ptr[esi-2]!='.')&&(byte ptr[esi-2]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoiW
	.if eax>255
		xor	eax,eax
		ret
	.endif
	shl	eax,16
	or	ecx,eax
	.if ((byte ptr[esi-2]!='.')&&(byte ptr[esi-2]!=' '))||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoiW
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if ((byte ptr[esi-2]!='.')&&(byte ptr[esi-2]>32))
		xor	eax,eax
		ret
	.endif
	shl	eax,16+8
	or	ecx,eax
	xor	eax,eax
	inc	eax
	ret
get_ipW	ENDP


get_cached_ip	PROC	uses ebx esi ptrName:DWORD,ip:DWORD
	invoke	get_ip,ptrName
	.if (eax==1)&&((cl==127)||(cl==255)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
		mov	eax,ecx
		ret
	.endif
	mov	edx,ptrName
	mov	ecx,edx
	.while byte ptr[edx]
		.if (byte ptr[edx]=='.')&&(byte ptr[edx+1]!=0)
			mov	ecx,edx
		.endif
		inc	edx
	.endw
	push	1
	.if byte ptr[ecx]=='.'
		lea	edx,[ecx+1]
		mov	eax,[edx]
		or	eax,20202020h
		.if (eax=='oino')&&((byte ptr[edx+4]=='n')||(byte ptr[edx+4]=='N'))&&((byte ptr[edx+5]==0)||(byte ptr[edx+5]=='.'))
			mov	byte ptr[esp],0
		.endif
	.endif
	pop	eax
	.if eax
		invoke	GetTickCount
	.endif
	push	eax
	mov	edi,onioncache
	mov	edx,ptrName
	.while edi
		mov	ebx,[edi+4]
		lea	esi,[edi+8]
		.while ebx>esi
			xor	ecx,ecx
			.while byte ptr[ebx+ecx+8-264]
				mov	al,[ebx+ecx+8-264]
				mov	ah,[edx+ecx]
				or	ax,2020h
				.break .if al!=ah
				inc	ecx
			.endw
			.if (byte ptr[ebx+ecx+8-264]==0)&&((byte ptr[edx+ecx]==0)||(byte ptr[edx+ecx]=='.'))
				pop	eax
				.if ip
					invoke	GetTickCount
					mov	[ebx-264],eax
					mov	eax,ip
					mov	[ebx+4-264],eax
				.elseif (!(sysflags&8))||(byte ptr[ebx+4-264]!=255)
					sub	eax,[ebx-264]
					.if eax>120000
						lea	edx,[ebx-264]
						jmp	_expired
					.endif
				.endif
				mov	eax,[ebx+4-264]
				pop	edx
				ret
			.endif
			sub	ebx,264
		.endw
		mov	edi,[edi]
	.endw
	pop	eax
	.if (eax!=0)&&(!(sysflags&8))&&(ip==0)
		pop	edx
		xor	eax,eax
		ret
	.endif
	mov	edi,onioncache
	.while edi
		lea	edx,[edi+26400+8]
		.if edx>[edi+4]
			mov	edx,[edi+4]
			add	dword ptr[edi+4],264
			.break
		.endif
		mov	edi,[edi]
	.endw
	.if edi==0
		lea	edi,onioncache
		.while dword ptr[edi]
			mov	edi,[edi]
		.endw
		invoke	GlobalAlloc,GPTR,26400+8
		mov	[edi],eax
		mov	dword ptr[eax],0
		lea	edx,[eax+8]
		mov	[eax+4],edx
		add	dword ptr[eax+4],264
	.endif
_expired:mov	edi,edx
	invoke	GetTickCount
	mov	dword ptr[edi],eax
	mov	eax,ip
	.if eax==0
		mov	eax,next_fake_ip
		mov	ecx,eax
		xchg	cl,ch
		rol	ecx,16
		xchg	cl,ch
		inc	ecx
		xchg	cl,ch
		rol	ecx,16
		xchg	cl,ch
		mov	dword ptr next_fake_ip,ecx
		mov	ip,eax
	.endif
	mov	dword ptr[edi+4],eax
	lea	edi,[edi+8]
	xor	ecx,ecx
	mov	edx,ptrName
	.while (byte ptr[edx]!=0)&&(word ptr[edx]!='.')&&(ecx<255)
		mov	al,[edx]
		stosb
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	mov	eax,ip
	pop	edx
	ret
get_cached_ip	ENDP

;eax,edi
get_cached_addr	PROC uses ecx edx
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
	ret
get_cached_addr	ENDP


socks5_1	db	5,1,0
get_host_name	PROC	uses edi ptrName:DWORD
	local	socks_saddr:sockaddr_in
	local	hSocket:DWORD,fds:fd_set,twait:timeval
	get_hostent
	push	edx
	assume	edx:ptr host_data
	mov	[edx].h_addrtype,2
	mov	[edx].h_length,4
	lea	ecx,[edx].ip
	mov	[edx].h_listptr,ecx
	lea	edi,[edx].hostname
	assume	edx:nothing
	mov	edx,ptrName
	xor	ecx,ecx
	.if edx
		.while ecx<255
			mov	al,[edx+ecx]
			stosb
			inc	ecx
			.break .if al==0
		.endw
	.endif
	mov	al,0
	stosb
	invoke	get_cached_ip,ptrName,0
	.if eax
		pop	edx
		assume	edx:ptr host_data
		mov	[edx].ip,eax
		lea	eax,[edx].h_name
		mov	[edx].busy,0
		assume	edx:nothing
		ret
	.endif
	assume	edx:ptr host_data
	mov	edx,[esp]
	lea	edi,[edx].hostdata
	mov	[edx].ip,0
	invoke	get_ip,ptrName
	.if eax
		pop	edx
		mov	[edx].ip,ecx
		lea	eax,[edx].h_name
		mov	[edx].busy,0
		ret
	.endif

	changeIcon2
	invoke	socket,PF_INET,SOCK_STREAM,IPPROTO_TCP
	.if eax!=INVALID_SOCKET
		mov	hSocket,eax
		.if dword ptr saveconnect[4]
			push	sizeof saddr
			push	offset saddr
			push	eax
			call	_s_c1
		.else
			invoke	connect,eax,addr saddr,sizeof saddr
		.endif
		.if eax==0
			select_write
			.if eax==1
				invoke	send,hSocket,addr socks5_1,3,0
				select_read
				.if eax==1
					invoke	recv,hSocket,edi,2,0
					.if (byte ptr[edi]==5)&&(byte ptr[edi+1]!=0ffh)
						mov	byte ptr[edi],5
						mov	byte ptr[edi+1],0f0h
						mov	byte ptr[edi+2],0
						mov	byte ptr[edi+3],3
						mov	edx,[esp]
						xor	ecx,ecx
						.while byte ptr[edx+ecx].hostname
							inc	ecx
						.endw
						mov	byte ptr[edi+4],cl
						xor	ecx,ecx
						.while byte ptr[edx+ecx].hostname
							mov	al,[edx+ecx].hostname
							mov	byte ptr[edi+5+ecx],al
							inc	ecx
						.endw
						mov	word ptr[edi+ecx+5],0
						lea	ecx,[edi+ecx+7]
						sub	ecx,edi
						push	ecx
						select_write
						pop	ecx
						.if eax==1
							invoke	send,hSocket,edi,ecx,0
							select_read
							.if eax==1
								mov	dword ptr[edi],0
								invoke	recv,hSocket,edi,10,0
								.if (word ptr[edi]==5)
									mov	eax,[edi+4]
									mov	edx,[esp]
									mov	[edx].ip,eax
									push	eax
									push	edx
									invoke	get_cached_ip,ptrName,[edx].ip
									pop	edx
									pop	eax
								.endif
							.endif
						.endif
					.endif
				.endif
			.endif
		.endif
		invoke	closesocket,hSocket
	.endif
	changeIcon1
	pop	edx
	lea	eax,[edx].h_name
	mov	[edx].busy,0
	assume	edx:nothing
	ret
get_host_name	ENDP

get_host_name1	PROC	uses edi ptrName:DWORD
	local	socks_saddr:sockaddr_in,hMem:DWORD,result:DWORD
	local	hSocket:DWORD,fds:fd_set,twait:timeval
	invoke	get_cached_ip,ptrName,0
	.if eax
		ret
	.endif
	invoke	GlobalAlloc,GPTR,512
	mov	hMem,eax
	mov	edi,eax
	mov	result,0

	changeIcon2
	invoke	socket,PF_INET,SOCK_STREAM,IPPROTO_TCP
	.if eax!=INVALID_SOCKET
		mov	hSocket,eax
		.if dword ptr saveconnect[4]
			push	sizeof saddr
			push	offset saddr
			push	eax
			call	_s_c1
		.else
			invoke	connect,eax,addr saddr,sizeof saddr
		.endif
		.if eax==0
			select_write
			.if eax==1
				invoke	send,hSocket,addr socks5_1,3,0
				select_read
				.if eax==1
					invoke	recv,hSocket,edi,2,0
					.if (byte ptr[edi]==5)&&(byte ptr[edi+1]!=0ffh)
						mov	byte ptr[edi],5
						mov	byte ptr[edi+1],0f0h
						mov	byte ptr[edi+2],0
						mov	byte ptr[edi+3],3
						mov	edx,[esp]
						xor	ecx,ecx
						mov	edx,ptrName
						.while byte ptr[edx+ecx]
							inc	ecx
						.endw
						mov	byte ptr[edi+4],cl
						xor	ecx,ecx
						.while byte ptr[edx+ecx]
							mov	al,[edx+ecx]
							mov	byte ptr[edi+5+ecx],al
							inc	ecx
						.endw
						mov	word ptr[edi+ecx+5],0
						lea	ecx,[edi+ecx+7]
						sub	ecx,edi
						push	ecx
						select_write
						pop	ecx
						.if eax==1
							invoke	send,hSocket,edi,ecx,0
							select_read
							.if eax==1
								mov	dword ptr[edi],0
								invoke	recv,hSocket,edi,10,0
								.if (word ptr[edi]==5)
									mov	eax,[edi+4]
									mov	result,eax
								.elseif word ptr[edi]==405h
								.endif
							.endif
						.endif
					.endif
				.endif
			.endif
		.endif
		invoke	closesocket,hSocket
	.endif
	invoke	GlobalFree,hMem
	changeIcon1
	mov	eax,result
	.if eax
		invoke	get_cached_ip,ptrName,result
	.endif
	ret
get_host_name1	ENDP

get_host_addr	PROC	uses edi ptrName:DWORD
	local	socks_saddr:sockaddr_in
	local	hSocket:DWORD,fds:fd_set,twait:timeval
	get_hostent
	push	edx
	assume	edx:ptr host_data
	mov	[edx].h_addrtype,2
	mov	[edx].h_length,4
	lea	ecx,[edx].ip
	mov	[edx].h_listptr,ecx
	lea	edi,[edx].ip
	assume	edx:nothing
	mov	edx,ptrName
	mov	eax,[edx]
	mov	[edi],eax
	.if (al==0ffh)&&(ah>=16)
		mov	edx,[esp]
		assume	edx:ptr host_data
		lea	edi,[edx].hostname
		assume	edx:nothing
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
		assume	edx:ptr host_data
		lea	eax,[edx].h_name
		mov	[edx].busy,0
		assume	edx:nothing
		ret
	.endif
	assume	edx:ptr host_data
	mov	edx,[esp]
	lea	edi,[edx].hostdata

	changeIcon2
	invoke	socket,PF_INET,SOCK_STREAM,IPPROTO_TCP
	.if eax!=INVALID_SOCKET
		mov	hSocket,eax
		.if dword ptr saveconnect[4]
			push	sizeof saddr
			push	offset saddr
			push	eax
			call	_s_c1
		.else
			invoke	connect,eax,addr saddr,sizeof saddr
		.endif
		.if eax==0
			select_write
			.if eax==1
				invoke	send,hSocket,addr socks5_1,3,0
				select_read
				.if eax==1
					invoke	recv,hSocket,edi,2,0
					.if (byte ptr[edi]==5)&&(byte ptr[edi+1]!=0ffh)
						mov	byte ptr[edi],5
						mov	byte ptr[edi+1],0f1h
						mov	byte ptr[edi+2],0
						mov	byte ptr[edi+3],1
						mov	edx,[esp]
						mov	eax,[edx].ip
						mov	[edi+4],eax
						mov	word ptr[edi+8],0
						select_write
						.if eax==1
							invoke	send,hSocket,edi,10,0
							select_read
							.if eax!=1
								mov	eax,ptrName
								mov	eax,[eax]
								mov	edx,[esp]
								lea	edi,[edx].hostname
								call	w_ip
								mov	al,0
								stosb
							.else
								mov	dword ptr[edi],0
								invoke	recv,hSocket,edi,512,0
								.if (word ptr[edi]==5)
									mov	edx,[esp]
									.if byte ptr[edi+3]==3
										xor	ecx,ecx
										.while cl<byte ptr[edi+4]
											mov	al,[edi+ecx+5]
											mov	[edx+ecx].hostname,al
											inc	ecx
										.endw
										mov	byte ptr[edx+ecx].hostname,0
									.elseif byte ptr[edi+3]==1
										mov	eax,[edi+4]
										lea	edi,[edx].hostname
										call	w_ip
										mov	al,0
										stosb
									.endif
								.else
									mov	eax,ptrName
									mov	eax,[eax]
									mov	edx,[esp]
									lea	edi,[edx].hostname
									call	w_ip
									mov	al,0
									stosb
								.endif
							.endif
						.endif
					.endif
				.endif
			.endif
		.endif
		invoke	closesocket,hSocket
	.endif
	changeIcon1
	pop	edx
	lea	eax,[edx].h_name
	mov	[edx].busy,0
	assume	edx:nothing
	ret
get_host_addr	ENDP

wpad_notify	PROC	uses esi edi ebx lpAddr:DWORD,lpRet:DWORD
	local	hMem:DWORD
	.if !(notify_wpad&1)
		or	notify_wpad,1
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
		mov	eax,'DAPW'
		stosd
		mov	eax,pipe_key
		stosd
		mov	edx,lpRet
		call	getdll
		mov	al,0
		stosb
		mov	edx,lpAddr
		xor	ecx,ecx
		.while (ecx<256)&&(byte ptr[edx]!=0)
			mov	al,[edx]
			stosb
			inc	edx
			inc	ecx
		.endw
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
	.endif
	invoke	WSASetLastError,WSAHOST_NOT_FOUND
	ret
wpad_notify	ENDP

newgethostbyname:
	jmp	_skipsig2a
	db	'AdvOR_'
	dd	offset savegethostbyname
_skipsig2a:
	mov	edx,[esp+4]
	.if edx==0
		lea	edx,zerostr
		mov	[esp+4],edx
		jmp	dword ptr savegethostbyname[4]
	.endif
	mov	eax,[edx]
	or	eax,20202020h
	.if (eax=='dapw')&&((byte ptr[edx+4]=='.')||(byte ptr[edx+4]==0))
		lea	eax,[esp+4+4]
		invoke	wpad_notify,edx,eax
		xor	eax,eax
		ret	4
	;	lea	edx,nohost
	;	mov	[esp+4],edx
	;	jmp	dword ptr savegethostbyname[4]
	.elseif (eax=='acol')
		mov	eax,[edx+4]
		or	eax,20202020h
		.if (eax=='sohl')
			mov	al,[edx+8]
			or	al,20h
			.if (al=='t')&&((byte ptr[edx+9]==0)||(byte ptr[edx+9]==':'))
				jmp	dword ptr savegethostbyname[4]
			.endif
		.endif
	.else
		invoke	get_ip,edx
		.if (eax==1)&&((cl==127)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
			jmp	dword ptr savegethostbyname[4]
		.endif
	.endif
	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'EMAN'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx-4]
	xor	ecx,ecx
	.while (ecx<256)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4 +4+4+4]
	invoke	get_host_name,edx
	pop	ebx
	pop	esi
	pop	edi
	ret	4

newwsaasyncgethostbyname:
	jmp	_skipsigwaghbn
	db	'AdvOR_'
	dd	offset savewsaasyncgethostbyname
_skipsigwaghbn:
	.if dword ptr[esp+4+16]<120h
		user32PostMessage	dword ptr[esp+4],dword ptr[esp+8],5,WSAENOBUFS*65536+120h
		mov	eax,5
		ret	20
	.endif
	mov	edx,[esp+4+8]
	.if edx==0
		lea	edx,zerostr
		mov	[esp+4+8],edx
		jmp	dword ptr savewsaasyncgethostbyname[4]
	.endif
	.if edx
		mov	eax,[edx]
		or	eax,20202020h
		.if (eax=='dapw')&&((byte ptr[edx+4]=='.')||(byte ptr[edx+4]==0))
			lea	eax,[esp+4+4]
			invoke	wpad_notify,edx,eax
			xor	eax,eax
			ret	20
	;		lea	edx,nohost
	;		mov	[esp+4+8],edx
	;		jmp	dword ptr savewsaasyncgethostbyname[4]
		.elseif (eax=='acol')
			mov	eax,[edx+4]
			or	eax,20202020h
			.if (eax=='sohl')
				mov	al,[edx+8]
				or	al,20h
				.if (al=='t')&&((byte ptr[edx+9]==0)||(byte ptr[edx+9]==':'))
					jmp	dword ptr savewsaasyncgethostbyname[4]
				.endif
			.endif
		.endif
		invoke	get_ip,edx
		.if (eax==1)&&(((cl==127)&&((ch<16)||(ch>20)))||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
			jmp	dword ptr savewsaasyncgethostbyname[4]
		.endif
	.endif
	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'EMAN'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx+4]
	xor	ecx,ecx
	.while (ecx<256)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4+4+4 +4+4+4]
	invoke	get_host_name,edx
	.if eax
		mov	eax,[eax+12]
		mov	eax,[eax]
		mov	eax,[eax]
	.endif
	pop	ebx
	pop	esi
	pop	edi
	sub	esp,20
	mov	ecx,esp
	push	edi
	mov	edi,ecx
	call	w_ip
	mov	al,0
	stosb
	pop	edi
	mov	edx,esp
	mov	[esp+20+4+4+4],edx
	lea	edx,[esp+24]
	push	dword ptr[edx+16]
	push	dword ptr[edx+12]
	push	dword ptr[edx+8]
	push	dword ptr[edx+4]
	push	dword ptr[edx]
	call	dword ptr savewsaasyncgethostbyname[4]
	add	esp,20
	ret	20

newgethostbyaddr:
	jmp	_skipsigghba
	db	'AdvOR_'
	dd	offset savegethostbyaddr
_skipsigghba:
	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'RDDA'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx-4]
	mov	eax,[edx]
	stosd
	.if (al==0ffh)&&(ah>=16)
		call	get_cached_addr
		mov	al,0
		stosb
	.endif
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4 +4+4+4]
	invoke	get_host_addr,edx
	pop	ebx
	pop	esi
	pop	edi
	ret	12

newwsaasyncgethostbyaddr:
	jmp	_skipsigwaghba
	db	'AdvOR_'
	dd	offset savewsaasyncgethostbyaddr
_skipsigwaghba:
	.if dword ptr[esp+4+16+8]<120h
		user32PostMessage	dword ptr[esp+4],dword ptr[esp+8],5,WSAENOBUFS*65536+120h
		mov	eax,5
		ret	28
	.endif
	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'RDDA'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx+4]
	mov	eax,[edx]
	stosd
	.if (al==0ffh)&&(ah>=16)
		call	get_cached_addr
		mov	al,0
		stosb
	.endif
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4+4+4 +4+4+4]
	invoke	get_host_addr,edx
	mov	edi,[esp+4+4+4+8 +4+4+4]
	mov	esi,eax
	lea	eax,[edi+16]
	mov	[edi],eax
	mov	edx,[esp+4+4+4+8 +4+4+4]
	push	edi
	mov	eax,[edx]
	stosd
	xor	ecx,ecx
	.while (ecx<256)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	mov	ecx,[esp]
	mov	dword ptr[ecx+4],edi
	xor	eax,eax
	stosd
	mov	word ptr[ecx+8],2
	mov	word ptr[ecx+10],4
	mov	dword ptr[ecx+12],edi
	lea	eax,[edi+8]
	stosd
	xor	eax,eax
	stosd
	mov	eax,[esi+12]
	mov	eax,[eax]
	mov	eax,[eax]
	stosd
	mov	ecx,edi
	pop	edi
	sub	ecx,edi
	pop	ebx
	pop	esi
	pop	edi
	user32PostMessage	dword ptr[esp+4],dword ptr[esp+8],5,ecx
	mov	eax,5
	ret	28

ngh1	PROC	uses esi edi ecx lpbuffer:DWORD,buffersize:DWORD
	xor	ecx,ecx
	.while localhostname[ecx]
		inc	ecx
	.endw
	inc	ecx
	.if ecx>buffersize
		xor	eax,eax
		inc	eax
		ret
	.endif
	mov	ecx,buffersize
	lea	esi,localhostname
	mov	edi,lpbuffer
	.while ecx
		movsb
		dec	ecx
	.endw
	.if ecx
		mov	al,0
		stosb
	.endif
	xor	eax,eax
	ret
ngh1	ENDP
newgethostname:
	jmp	ngh1
	db	'AdvOR_'
	dd	offset savegethostname

zerostr	dw	0
newgetaddrinfo:
	jmp	_skipsiggai
	db	'AdvOR_'
	dd	offset savegetaddrinfo
_skipsiggai:
	mov	edx,[esp+4]
	.if edx
		mov	eax,[edx]
		or	eax,20202020h
		.if (eax=='dapw')&&((byte ptr[edx+4]=='.')||(byte ptr[edx+4]==0))
			lea	eax,[esp+4+4]
			invoke	wpad_notify,edx,eax
		;	lea	edx,nohost
		;	mov	[esp+4],edx
		;	jmp	dword ptr savegetaddrinfo[4]
			mov	eax,WSAHOST_NOT_FOUND
			ret	16
		;	lea	edx,localname
		;	mov	[esp+4],edx
		;	jmp	dword ptr savegetaddrinfo[4]
		.elseif (eax=='acol')
			mov	eax,[edx+4]
			or	eax,20202020h
			.if (eax=='sohl')
				mov	al,[edx+8]
				or	al,20h
				.if (al=='t')&&((byte ptr[edx+9]==0)||(byte ptr[edx+9]==':'))
					jmp	dword ptr savegetaddrinfo[4]
				.endif
			.endif
		.endif
		invoke	get_ip,edx
		.if (eax==1)&&((cl==127)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
			jmp	dword ptr savegetaddrinfo[4]
		.endif
	.else
		jmp	dword ptr savegetaddrinfo[4]
	.endif

	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'EMAN'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx-4]
	xor	ecx,ecx
	.while (ecx<256)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4 +4+4+4]
	.if edx
		invoke	get_host_name1,edx
	.else
		xor	eax,eax
	.endif
	pop	ebx
	pop	esi
	pop	edi
	sub	esp,20
	push	edi
	lea	edi,[esp+4]
	push	edi
	.if eax==0
		pop	eax
		pop	edi
		invoke	WSASetLastError,WSAHOST_NOT_FOUND
		add	esp,20
		mov	eax,WSAHOST_NOT_FOUND
		ret	16
	.endif
	call	w_ip
	mov	al,0
	stosb
	pop	eax
	pop	edi
	lea	edx,[esp+4+20]
	push	dword ptr[edx+12]
	push	dword ptr[edx+8]
	push	dword ptr[edx+4]
	push	eax
	call	dword ptr savegetaddrinfo[4]
	add	esp,20
	ret	16

newgetaddrinfow:
	jmp	_skipsiggaiw
	db	'AdvOR_'
	dd	offset savegetaddrinfow
_skipsiggaiw:
	mov	edx,[esp+4]
	.if edx==0
		jmp	dword ptr savegetaddrinfow[4]
	.else
		mov	eax,[edx]
		or	eax,[edx+4-1]
		or	eax,20202020h
		.if (eax=='dpaw')&&((byte ptr[edx+8]=='.')||(byte ptr[edx+8]==0))
			lea	eax,[esp+4+4]
			invoke	wpad_notify,edx,eax
		;	lea	edx,nohostw
		;	mov	[esp+4],edx
		;	jmp	dword ptr savegetaddrinfow[4]
			mov	eax,WSAHOST_NOT_FOUND
			ret	16
		;	lea	edx,localnamew
		;	mov	[esp+4],edx
		;	jmp	dword ptr savegetaddrinfow[4]
		.elseif (eax=='aocl')
			mov	eax,[edx+8]
			or	eax,[edx+8+4-1]
			or	eax,20202020h
			.if (eax=='shol')
				mov	al,[edx+16]
				or	al,20h
				.if (al=='t')&&((byte ptr[edx+18]==0)||(byte ptr[edx+18]==':'))
					jmp	dword ptr savegetaddrinfow[4]
				.endif
			.endif
		.endif
		invoke	get_ipW,edx
		.if (eax==1)	;&&((cl==127)||(cl==10)||(cx==168*256+192)||((cl==172)&&(ch>=16)&&(ch<=31)))
			jmp	dword ptr savegetaddrinfow[4]
		.endif
	.endif
	mov	edx,[esp+4]
	lea	eax,[esp+4]
	sub	esp,256
	push	edi
	lea	edi,[esp+4]
	.if edx
		xor	ecx,ecx
		.while byte ptr[edx]
			mov	al,[edx]
			stosb
			inc	edx
			inc	edx
			inc	ecx
			.break .if cl>255
		.endw
	.endif
	mov	al,0
	stosb

	push	edi
	push	esi
	push	ebx
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
	lea	edx,[esp+4+4 +4+4+4+256+4]
	sub	esp,512+20
	push	edi
	lea	edi,[esp+4]
	push	eax
	mov	eax,'EMAN'
	stosd
	mov	eax,pipe_key
	stosd
	push	edx
	call	getdll
	mov	al,0
	stosb
	pop	edx
	mov	edx,[edx-4]
	xor	ecx,ecx
	.while (ecx<256)&&(byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
		inc	edx
		inc	ecx
	.endw
	mov	al,0
	stosb
	pop	eax
	mov	ecx,edi
	lea	edi,[esp+4]
	sub	ecx,edi
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
	pop	edi
	add	esp,512+20
	mov	edx,[esp+4 +4+4+4+256+4]
	.if edx
		lea	edx,[esp+16]
		invoke	get_host_name1,edx
	.else
		xor	eax,eax
	.endif
	pop	ebx
	pop	esi
	pop	edi
	mov	edi,esp
	.if eax==0
		pop	edi
		invoke	WSASetLastError,WSAHOST_NOT_FOUND
		add	esp,256
		mov	eax,WSAHOST_NOT_FOUND
		ret	16
	.endif
	call	w_ip
	mov	al,0
	stosb
	mov	edx,esp
	push	edi
	mov	ah,0
	.while byte ptr[edx]
		mov	al,[edx]
		stosw
		inc	edx
	.endw
	mov	al,0
	stosw
	pop	eax
	lea	edx,[esp+4+256+4]
	push	dword ptr[edx+12]
	push	dword ptr[edx+8]
	push	dword ptr[edx+4]
	push	eax
	call	dword ptr savegetaddrinfow[4]
	pop	edi
	add	esp,256
	ret	16

newgetnameinfo:
	jmp	_skipsiggni
	db	'AdvOR_'
	dd	offset savegetnameinfo
_skipsiggni:
	.if dword ptr[esp+4+12]<10h
		xor	eax,eax
		inc	eax
		ret	16+12
	.endif
	lea	edx,[esp+4]
	mov	ecx,[edx]
	sub	esp,32
	push	edi
	lea	edi,[esp+4]
	push	esi
	mov	esi,ecx
	mov	ecx,sizeof sockaddr_in
	cld
	rep	movsb
	pop	esi
	pop	edi
	mov	eax,esp
	assume	eax:ptr sockaddr_in
	mov	dword ptr[eax].sin_addr,100007fh
	assume	eax:nothing
	push	dword ptr[edx+24]
	push	dword ptr[edx+20]
	push	dword ptr[edx+16]
	push	dword ptr[edx+12]
	push	dword ptr[edx+8]
	push	dword ptr[edx+4]
	push	eax
	call	dword ptr savegetnameinfo[4]
	add	esp,32
	.if eax
		ret	16+12
	.endif
	mov	edx,[esp+4]
	.if edx!=0
		push	edi
		push	esi
		push	ebx
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
		lea	edx,[esp+4+4 +4+4+4]
		sub	esp,512+20
		push	edi
		lea	edi,[esp+4]
		push	eax
		mov	eax,'RDDA'
		stosd
		mov	eax,pipe_key
		stosd
		push	edx
		call	getdll
		mov	al,0
		stosb
		pop	edx
		mov	edx,[edx-4]
		assume	edx:ptr sockaddr_in
		mov	eax,dword ptr[edx].sin_addr
		stosd
		.if (al==0ffh)&&(ah>=16)
			call	get_cached_addr
			mov	al,0
			stosb
		.endif
		pop	eax
		mov	ecx,edi
		lea	edi,[esp+4]
		sub	ecx,edi
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
		pop	edi
		add	esp,512+20
		mov	edx,[esp+4 +4+4+4]
		assume	edx:ptr sockaddr_in
		lea	edx,[edx].sin_addr
		assume	edx:nothing
		invoke	get_host_addr,edx
		mov	edx,[eax]
		pop	ebx
		pop	esi
		mov	edi,[esp+4+4 +4+4]
		mov	ecx,[esp+4+4 +4+4+4]
		.if ecx
			dec	ecx
		.endif
		.while (byte ptr[edx]!=0)&&(ecx!=0)
			mov	al,[edx]
			stosb
			inc	edx
			dec	ecx
		.endw
		mov	al,0
		stosb
		pop	edi
		xor	eax,eax
	.endif
	xor	eax,eax
	ret	16+12

newgetnameinfow:
	jmp	_skipsiggniw
	db	'AdvOR_'
	dd	offset savegetnameinfow
_skipsiggniw:
	mov	eax,[esp+4]
	assume	eax:ptr sockaddr_in
	.if dword ptr[eax].sin_addr==100007fh
		jmp	dword ptr savegetnameinfow[4]
	.endif
	assume	eax:nothing
	.if dword ptr[esp+4+12]<20h
		xor	eax,eax
		inc	eax
		ret	16+12
	.endif

	lea	edx,[esp+4]
	mov	ecx,[edx]
	sub	esp,32
	push	edi
	lea	edi,[esp+4]
	push	esi
	mov	esi,ecx
	mov	ecx,sizeof sockaddr_in
	cld
	rep	movsb
	pop	esi
	pop	edi
	mov	eax,esp
	assume	eax:ptr sockaddr_in
	mov	dword ptr[eax].sin_addr,100007fh
	assume	eax:nothing
	push	dword ptr[edx+24]
	push	dword ptr[edx+20]
	push	dword ptr[edx+16]
	push	dword ptr[edx+12]
	push	dword ptr[edx+8]
	push	dword ptr[edx+4]
	push	eax
	call	dword ptr savegetnameinfow[4]
	add	esp,32
	.if eax
		ret	16+12
	.endif
	mov	edx,[esp+4]
	.if edx!=0
		push	edi
		push	esi
		push	ebx
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
		lea	edx,[esp+4+4 +4+4+4]
		sub	esp,512+20
		push	edi
		lea	edi,[esp+4]
		push	eax
		mov	eax,'RDDA'
		stosd
		mov	eax,pipe_key
		stosd
		push	edx
		call	getdll
		mov	al,0
		stosb
		pop	edx
		mov	edx,[edx-4]
		assume	edx:ptr sockaddr_in
		mov	eax,dword ptr[edx].sin_addr
		stosd
		.if (al==0ffh)&&(ah>=16)
			call	get_cached_addr
			mov	al,0
			stosb
		.endif
		pop	eax
		mov	ecx,edi
		lea	edi,[esp+4]
		sub	ecx,edi
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
		pop	edi
		add	esp,512+20
		mov	edx,[esp+4 +4+4+4]
		assume	edx:ptr sockaddr_in
		lea	edx,[edx].sin_addr
		assume	edx:nothing
		invoke	get_host_addr,edx
		mov	edx,[eax]
		pop	ebx
		pop	esi
		mov	edi,[esp+4+4 +4+4]
		mov	ecx,[esp+4+4 +4+4+4]
		mov	ah,0
		.while (byte ptr[edx]!=0)&&(ecx>=3)
			mov	al,[edx]
			stosw
			inc	edx
			dec	ecx
			dec	ecx
		.endw
		mov	al,0
		stosw
		pop	edi
		xor	eax,eax
	.endif
	xor	eax,eax
	ret	16+12

endm

resolve_pipe	macro
		.elseif dword ptr pipeData=='EMAN'
			lea	edi,pipeNotifyMsg
			push	edi
			writeLangStr	LANG_DLL_RESTRICTED_PROCESS,msgnp
			lea	edx,pipeData[9]
			call	copyedx
			inc	edx
			push	edx
			writeLangStr	LANG_DLL_RESOLVE,msgnr
			pop	edx
			call	copyedx
			mov	eax,'. '
			stosd
			push	LOG_WARN
			call	Log
			invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		.elseif dword ptr pipeData=='RDDA'
			lea	edi,pipeNotifyMsg
			push	edi
			writeLangStr	LANG_DLL_RESTRICTED_PROCESS,msgnp
			lea	edx,pipeData[9]
			call	copyedx
			inc	edx
			push	edx
			writeLangStr	LANG_DLL_REVDNS,msgna
			pop	edx
			mov	eax,[edx]
			push	edx
			call	w_ip
			pop	edx
			.if (byte ptr[edx]==0ffh)&&(byte ptr[edx+1]>=16)
				lea	edx,[edx+4]
				mov	ax,'( '
				stosw
				call	copyedx
				mov	al,')'
				stosb
			.endif
			mov	eax,'. '
			stosd
			push	LOG_WARN
			call	Log
			invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
		.elseif dword ptr pipeData=='DAPW'
			lea	edi,pipeNotifyMsg
			push	edi
			writeLangStr	LANG_DLL_RESTRICTED_PROCESS,msgnp
			lea	edx,pipeData[9]
			call	copyedx
			inc	edx
			push	edx
			writeLangStr	LANG_DLL_RESOLVE,msgnr
			pop	edx
			call	copyedx
			writeLangStr	LANG_DLL_WPAD,msgnw1
			mov	al,0
			stosb
			push	LOG_WARN
			call	Log
			invoke	WriteFile,hPipe,addr pipeData[4],4,addr lParam,0
			invoke	DisconnectNamedPipe,hPipe
			mov	dword ptr pipeData,0
endm
