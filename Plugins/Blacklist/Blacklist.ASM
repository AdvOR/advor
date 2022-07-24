.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
include \masm32\include\wininet.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\wininet.lib

dlgFunc				PROTO	:DWORD,:DWORD,:DWORD,:DWORD
format_str			PROTO	:DWORD,:DWORD,:DWORD
format_str_cb			PROTO	:DWORD,:DWORD,:DWORD
format_int			PROTO	:DWORD,:DWORD,:DWORD
get_unicode			PROTO	:DWORD

include	plugins.inc
include	plprocs.h

BLACKLIST_FLAG_VERIFY_ALL_ROUTERS = 1
BLACKLIST_FLAG_ROUTER_WARNINGS = 2
BLACKLIST_FLAG_BAN_ROUTERS = 4
BLACKLIST_FLAG_VERIFY_WEBSITES = 8
BLACKLIST_FLAG_WEBSITES_WARNINGS = 16
BLACKLIST_FLAG_BLOCK_WEBSITES = 32
BLACKLIST_FLAG_SHOW_404 = 64

.data
	resizeControls	resize_info_t	<-1,430,450,0,0,<-1,-1,-1,-1>,0>
			resize_info_t	<300,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH>
			resize_info_t	<1,0,0,300,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X>
			resize_info_t	<11,0,0,300,300,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y>
			resize_info_t	<400,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<401,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<402,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<403,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<404,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<405,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<500,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<501,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<50,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT>
			resize_info_t	<20,50,0,50,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<30,50,0,20,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<21,50,0,50,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<31,50,0,21,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<22,50,0,50,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<32,50,0,22,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<23,50,0,50,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<33,50,0,23,50,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_TOP_POS_Y>
			resize_info_t	<51,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_LEFT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT>
			resize_info_t	<100,51,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_MIDDLE_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT>
			resize_info_t	<3,0,0,100,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_POS_X or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_POS_Y or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT>
			resize_info_t	<24,0,0,0,0,<-1,-1,-1,-1>,RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH or RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT>
			resize_info_t	<0,0,0,0,0,<-1,-1,-1,-1>,0>
	bflags		dd	BLACKLIST_FLAG_VERIFY_ALL_ROUTERS or BLACKLIST_FLAG_ROUTER_WARNINGS or BLACKLIST_FLAG_BAN_ROUTERS or BLACKLIST_FLAG_WEBSITES_WARNINGS or BLACKLIST_FLAG_SHOW_404
	_InternetReadFile dd	0
	hInstance	dd	?
	hParent		dd	?
	hDialog		dd	?
	AdvTor_vars
	bread		dd	?
	totalips	dd	0
	totalwarns	dd	0
	totalbans	dd	0
	totalblocked	dd	0
	blocked		dd	0
	ips		dd	0
	ipuri		dd	0
	pointeri	dd	0
	lasturl		dd	0
	downloading	db	0
	routerinfo	router_info_t	<>
	routerhash	db	(DIGEST_LEN+1)*2 dup(?)
	buftmp		db	1024 dup(?)

.code
include	lang.h
notxt	db	0
_flags	db	'BlacklistFlags',0
_lurl	db	'LastUrl',0
_stats	db	'Stats',0
start	label	byte
pl_procs

DllEntry PROC dllInstance:DWORD,reason:DWORD,reserved1:DWORD
	.if reason==DLL_PROCESS_ATTACH
		push	dllInstance
		pop	hInstance
		mov	hParent,0
		mov	ipuri,0
		mov	pointeri,0
		mov	blocked,0
		mov	totalips,0
		mov	totalwarns,0
	.elseif reason==DLL_PROCESS_DETACH
	.elseif reason==DLL_THREAD_ATTACH
	.else
	.endif
	xor	eax,eax
	inc	eax
	ret
DllEntry Endp

showdigest:
	lea	edx,routerinfo.identity_digest
	mov	ecx,DIGEST_LEN
	.while ecx
		mov	al,[edx]
		mov	ah,al
		shr	al,4
		and	ax,0f0fh
		.if al>9
			add	al,7
		.endif
		.if ah>9
			add	ah,7
		.endif
		add	ax,3030h
		stosw
		inc	edx
		dec	ecx
	.endw
	ret

chklist:
	.if ips==0
		xor	eax,eax
		ret
	.endif
	push	edi
	mov	ecx,ips
	mov	edi,ipuri
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	mov	ebx,pointeri
	.while (ecx!=0)
		.if (eax>=[edi])&&(eax<=[edi+4])&&(dword ptr[edi]!=0)&&(dword ptr[edi]!=-1)
			push	eax
			push	edi
			push	ecx
			lea	edi,routerhash
			push	edx
			push	ebx
			call	showdigest
			mov	al,0
			stosb
			lea	edx,routerhash
			xor	eax,eax
			.if dword ptr routerinfo.identity_digest==0
				mov	eax,routerinfo._addr
				xor	edx,edx
			.endif
			AdvTor_IsRouterBanned	eax,edx
			pop	ebx
			pop	edx
			pop	ecx
			pop	edi
			.if eax!=1
				pop	eax
				pop	edi
				xor	eax,eax
				inc	eax
				ret
			.endif
			pop	eax
		.endif
		lea	edi,[edi+8]
		lea	ebx,[ebx+4]
		dec	ecx
	.endw
	xor	eax,eax
	pop	edi
	ret

verify_ip:
	.if ips==0
		xor	eax,eax
		ret
	.endif
	push	edi
	mov	ecx,ips
	mov	edi,ipuri
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	mov	ebx,pointeri
	.while (ecx!=0)
		.if (eax>=[edi])&&(eax<=[edi+4])&&(dword ptr[edi]!=0)&&(dword ptr[edi]!=-1)
			pop	edi
			xor	eax,eax
			inc	eax
			ret
		.endif
		lea	edi,[edi+8]
		lea	ebx,[ebx+4]
		dec	ecx
	.endw
	xor	eax,eax
	pop	edi
	ret

chkrange:
	.if ips==0
		xor	eax,eax
		ret
	.endif
	push	edi
	mov	ecx,ips
	mov	edi,ipuri
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	xchg	bl,bh
	rol	ebx,16
	xchg	bl,bh
	.if eax>ebx
		xchg	eax,ebx
	.endif
	.while (ecx!=0)
		.if (dword ptr[edi]!=0)&&(dword ptr[edi]!=-1) && (([edi] >= eax && [edi] <= ebx) || ([edi+4] >= eax && [edi+4] <= ebx) || ((eax>=[edi])&&(eax<=[edi+4])) || ((ebx>=[edi])&&(ebx<=[edi+4])))
			pop	edi
			xor	eax,eax
			inc	eax
			ret
		.endif
		lea	edi,[edi+8]
		dec	ecx
	.endw
	xor	eax,eax
	pop	edi
	ret

showrange:
	.if ips==0
		xor	eax,eax
		ret
	.endif
	push	edi
	push	edi
	mov	ecx,ips
	mov	edi,ipuri
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	xchg	bl,bh
	rol	ebx,16
	xchg	bl,bh
	.if eax>ebx
		xchg	eax,ebx
	.endif
	push	pointeri
	.while (ecx!=0)
		.if (dword ptr[edi]!=0)&&(dword ptr[edi]!=-1) && (([edi] >= eax && [edi] <= ebx) || ([edi+4] >= eax && [edi+4] <= ebx) || ((eax>=[edi])&&(eax<=[edi+4])) || ((ebx>=[edi])&&(ebx<=[edi+4])))
			push	eax
			mov	edx,[esp+8]
			push	edi
			mov	edi,edx
			mov	ax,0a0dh
			stosw
			mov	edx,[esp+8]
			mov	edx,[edx]
			push	edx
			.while byte ptr[edx]!=0 && byte ptr[edx]!=13 && byte ptr[edx]!=10 && byte ptr[edx]!=':'
				inc	edx
			.endw
			.if byte ptr[edx]==':'
				inc	edx
			.endif
			.while byte ptr[edx]!=0 && byte ptr[edx]!=13 && byte ptr[edx]!=10
				mov	al,[edx]
				stosb
				inc	edx
			.endw
			mov	al,9
			stosb
			pop	edx
			.while byte ptr[edx]!=0 && byte ptr[edx]!=13 && byte ptr[edx]!=10 && byte ptr[edx]!=':'
				mov	al,[edx]
				stosb
				inc	edx
			.endw
			mov	[esp+12],edi
			pop	edi
			pop	eax
			mov	edx,[esp+4]
			sub	edx,[esp+8]
			.if edx>1024
				mov	edi,[esp+4]
				mov	ax,0a0dh
				stosw
				mov	eax,'...'
				stosd
				dec	edi
				mov	[esp+4],edi
				.break
			.endif
		.endif
		lea	edi,[edi+8]
		add	dword ptr[esp],4
		dec	ecx
	.endw
	pop	eax
	pop	edi
	pop	eax
	ret

show_bl_router_info:
	.if routerinfo.nickname
		mov	edx,routerinfo.nickname
		call	copyedx
	.else
		lea	edx,routerinfo.identity_digest
		mov	ecx,20
		.while ecx
			mov	al,[edx]
			mov	ah,ah
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
			inc	edx
			dec	ecx
		.endw
	.endif
	mov	ax,'( '
	stosw
	mov	eax,routerinfo._addr
	call	w_ip
	mov	ax,' )'
	stosw
	.if routerinfo.routerflags&40h
		mov	eax,'tne['
		stosd
		mov	eax,' ]yr'
		stosd
	.endif
	.if routerinfo.routerflags&80h
		mov	eax,'ixe['
		stosd
		mov	eax,' ]t'
		stosd
		dec	edi
	.endif
	ret

show_blacklisted_router:
	push	ecx
	invoke	GlobalAlloc,GPTR,8192
	push	eax
	mov	edi,eax
	invoke	format_str_cb,LANG_ID_MSGB1,offset msgb1,offset show_bl_router_info
	dec	edi
	mov	eax,' - '
	stosd
	dec	edi
	mov	eax,routerinfo._addr
	mov	ecx,ips
	mov	esi,ipuri
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	mov	ebx,pointeri
	.if ebx
		push	edi
		.while (ecx!=0)
			.if (eax>=[esi])&&(eax<=[esi+4])&&(dword ptr[esi]!=0)&&(dword ptr[esi]!=-1)
				.if edi!=[esp]
					mov	eax,' / '
					stosd
					dec	edi
				.endif
				mov	edx,[ebx]
				.while byte ptr[edx]!=0 && byte ptr[edx]!=':'
					mov	al,[edx]
					stosb
					inc	edx
				.endw
			.endif
			lea	esi,[esi+8]
			lea	ebx,[ebx+4]
			dec	ecx
		.endw
		pop	edx
	.endif
	.if bflags&BLACKLIST_FLAG_BAN_ROUTERS && dword ptr routerinfo.identity_digest
		mov	ax,' .'
		stosw
		invoke	format_str_cb,LANG_ID_MSGB2,offset msgb2,offset showdigest
	.else
		mov	ax,'.'
		stosw
	.endif

	mov	edx,[esp]
	AdvTor_Log	LOG_WARN,edx
	inc	totalwarns
	.if hDialog
		invoke	SetDlgItemInt,hDialog,31,totalwarns,0
	.endif
	call	GlobalFree
	pop	ecx
	ret

check_all_routers:
	xor	ecx,ecx
	.while 1
		push	ecx
		mov	routerinfo.cbSize,sizeof routerinfo
		lea	edx,routerinfo
		push	edx
		push	0
		push	0
		push	ecx
		mov	eax,functions
		mov	eax,[eax+PLUGIN_FN_GET_ROUTER_INFO*4]
		call	eax
		pop	ecx
		inc	ecx
		.break .if eax==0
		mov	eax,routerinfo._addr
		.if eax
			push	ecx
			call	chklist
			.if (eax != 0)
				.if (bflags & BLACKLIST_FLAG_ROUTER_WARNINGS)
					call	show_blacklisted_router
				.endif
				.if bflags & BLACKLIST_FLAG_BAN_ROUTERS
					AdvTor_BanRouter	routerinfo._addr,BAN_GENERAL,1
					add	totalbans,eax
					.if hDialog
						invoke	SetDlgItemInt,hDialog,32,totalbans,0
					.endif
				.endif
			.endif
			pop	ecx
		.endif
	.endw
	ret

LoadBlacklist	PROC
	local	qfile:DWORD
	invoke	GlobalAlloc,GPTR,8192
	mov	qfile,eax
	invoke	GetModuleFileName,hInstance,qfile,8192
	mov	edx,qfile
	mov	ecx,edx
	.while byte ptr[edx]
		.if byte ptr[edx]=='\'
			lea	ecx,[edx+1]
		.endif
		inc	edx
	.endw
	mov	eax,'calb'
	mov	[ecx],eax
	mov	eax,'silk'
	mov	[ecx+4],eax
	mov	eax,'xt.t'
	mov	[ecx+8],eax
	mov	eax,'t'
	mov	[ecx+12],eax
	mov	totalips,0

	invoke	CreateFile,qfile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0
	.if eax!=INVALID_HANDLE_VALUE
		push	eax
		invoke	GetFileSize,eax,0
		lea	ecx,[eax+1024]
		push	eax
		invoke	GlobalAlloc,GPTR,ecx
		pop	ecx
		mov	esi,eax
		pop	eax
		push	eax
		invoke	ReadFile,eax,esi,ecx,addr bread,0
		mov	eax,esi
		add	eax,bread
		mov	byte ptr[eax],0
		call	CloseHandle
		mov	blocked,esi
		xor	ecx,ecx
		xor	eax,eax
		.while byte ptr[esi+ecx]
			.if byte ptr[esi+ecx]==13 || byte ptr[esi+ecx]==10
				inc	eax
				.if byte ptr[esi+ecx+1]==10
					inc	ecx
				.endif
			.endif
			inc	ecx
		.endw
		lea	eax,[eax+10]
		shl	eax,2
		push	eax
		invoke	GlobalAlloc,GPTR,eax
		mov	pointeri,eax
		pop	edx
		shl	edx,1
		invoke	GlobalAlloc,GPTR,edx
		mov	ipuri,eax
		mov	edi,eax
		xor	ecx,ecx
		.while byte ptr[esi]
			mov	eax,esi
			mov	edx,pointeri
			mov	dword ptr[edx+ecx*4],eax
			.while 1
				.while (byte ptr[esi]!=':')&&(byte ptr[esi]!=13)&&(byte ptr[esi]!=10)&&(byte ptr[esi]!=0)
					inc	esi
				.endw
				.if byte ptr[esi]==':'
					xor	eax,eax
					inc	eax
					.while (byte ptr[esi+eax]!=':')&&(byte ptr[esi+eax]!=13)&&(byte ptr[esi+eax]!=10)&&(byte ptr[esi+eax]!=0)
						inc	eax
					.endw
					.if byte ptr[esi+eax]==':'
						lea	esi,[esi+eax]
					.else
						.break
					.endif
				.else
					.break
				.endif
			.endw
			.if byte ptr[esi]==':'
				inc	esi
				push	ecx
				call	getrange
				.if eax==0
					dec	eax
				.endif
				pop	ecx
				xchg	al,ah
				rol	eax,16
				xchg	al,ah
				mov	edx,ipuri
				mov	dword ptr[edx+ecx*8],eax
				xchg	bl,bh
				rol	ebx,16
				xchg	bl,bh
				mov	dword ptr[edx+ecx*8+4],ebx
			.else
				xor	eax,eax
				dec	eax
				mov	edx,ipuri
				mov	dword ptr[edx+ecx*8],eax
				mov	dword ptr[edx+ecx*8+4],eax
			.endif
			.while (byte ptr[esi]!=13)&&(byte ptr[esi]!=10)&&(byte ptr[esi]!=0)
				inc	esi
			.endw
			.while (byte ptr[esi]==13)||(byte ptr[esi]==10)
				inc	esi
			.endw
			inc	ecx
		.endw
		mov	totalips,ecx
		mov	edx,ipuri
		mov	dword ptr[edx+ecx*8],0
		mov	dword ptr[edx+ecx*8+4],0
		mov	ips,ecx
		.if hDialog
			invoke	SetDlgItemInt,hDialog,30,totalips,0
		.endif
	.else
		invoke	GlobalAlloc,GPTR,16384
		push	eax
		mov	edi,eax
		invoke	format_str,LANG_ID_ERRF1,addr errf,qfile
		pop	edx
		push	edx
		AdvTor_Log	LOG_INFO,edx
		call	GlobalFree
		invoke	GlobalFree,qfile
		xor	eax,eax
		ret
	.endif
	invoke	GlobalFree,qfile
	.if bflags & BLACKLIST_FLAG_VERIFY_ALL_ROUTERS
		call	check_all_routers
	.endif
	ret
LoadBlacklist	ENDP


AdvTor_Init_Lang	LANG_ID_DESC1,offset desc1
	.if blocked==0
		call	LoadBlacklist
	.endif
	AdvTor_GetConfigurationValue	offset _flags,offset buftmp,100,0
	.if eax>1
		lea	esi,buftmp
		call	atoi
		mov	bflags,eax
	.endif
	AdvTor_GetConfigurationValue	offset _lurl,offset buftmp,256,0
	.if eax>1
		push	eax
		invoke	GlobalAlloc,GPTR,257
		mov	lasturl,eax
		mov	edi,eax
		pop	ecx
		lea	esi,buftmp
		.while byte ptr[esi]!=13 && byte ptr[esi]!=10 && byte ptr[esi]!=0
			movsb
		.endw
		mov	al,0
		stosb
	.endif
	AdvTor_GetConfigurationValue	offset _stats,offset buftmp,256,0
	.if eax>1
		lea	esi,buftmp
		call	atoi
		mov	totalwarns,eax
		call	atoi
		mov	totalbans,eax
		call	atoi
		mov	blocked,eax
	.endif
	xor	eax,eax
	inc	eax
	ret
AdvTor_Init_end

AdvTor_LanguageChange	PROC	uses esi edi ebx newLang:DWORD
	.if hDialog
		AdvTor_lang_change_dialog_strings	hDialog,offset dialog_strings
		.if ips
			AdvTor_lang_get_string	LANG_ID_DLG_SETTINGS,offset dtxt
			invoke	get_unicode,eax
			push	eax
			invoke	SetDlgItemTextW,hDialog,11,eax
			call	GlobalFree
		.endif
	.endif
	ret
AdvTor_LanguageChange	ENDP

AdvTor_UnloadPlugin	PROC	uses esi edi ebx reason:DWORD
	.if downloading!=0 && reason!=PLUGIN_UNLOAD_MUST_UNLOAD
		xor	eax,eax
		ret
	.endif
	lea	edi,buftmp
	mov	eax,bflags
	call	itoa
	mov	al,0
	stosb
	AdvTor_SetConfigurationValue	offset _flags,offset buftmp
	.if hDialog
		invoke	SendDlgItemMessage,hDialog,300,CB_GETCURSEL,0,0
		.if eax==CB_ERR
			invoke	GetDlgItemText,hDialog,300,addr buftmp,256
			.if eax>1
				invoke	SendDlgItemMessage,hDialog,300,CB_FINDSTRINGEXACT,-1,addr buftmp
				.if eax==CB_ERR
					AdvTor_SetConfigurationValue	offset _lurl,offset buftmp
				.endif
			.else
				AdvTor_SetConfigurationValue	offset _lurl,0
			.endif
		.endif
	.endif
	lea	edi,buftmp
	mov	eax,totalwarns
	call	itoa
	mov	al,32
	stosb
	mov	eax,totalbans
	call	itoa
	mov	al,32
	stosb
	mov	eax,totalblocked
	call	itoa
	mov	al,0
	stosb
	AdvTor_SetConfigurationValue	offset _stats,offset buftmp
	.if lasturl
		invoke	GlobalFree,lasturl
		mov	lasturl,0
	.endif
	.if hDialog
		invoke	DestroyWindow,hDialog
		mov	hDialog,0
	.endif
	.if ipuri
		invoke	GlobalFree,ipuri
		mov	ipuri,0
	.endif
	.if pointeri
		invoke	GlobalFree,pointeri
		mov	pointeri,0
	.endif
	.if blocked
		invoke	GlobalFree,blocked
		mov	blocked,0
	.endif
	xor	eax,eax
	inc	eax
	ret
AdvTor_UnloadPlugin	ENDP

AdvTor_RouterChanged	PROC	uses esi edi ebx ip:DWORD,digest:DWORD,changed:DWORD
	.if bflags & BLACKLIST_FLAG_VERIFY_ALL_ROUTERS && changed
		.if ip==0
			call	check_all_routers
		.else
			mov	dword ptr routerinfo.identity_digest,0
			mov	eax,ip
			mov	routerinfo._addr,eax
			call	chklist
			.if eax
				mov	routerinfo.cbSize,sizeof routerinfo
				lea	edx,routerinfo
				push	edx
				push	0
				push	ip
				push	0
				mov	eax,functions
				mov	eax,[eax+PLUGIN_FN_GET_ROUTER_INFO*4]
				call	eax
				.if (eax != 0) && dword ptr routerinfo._addr
					.if (bflags & BLACKLIST_FLAG_ROUTER_WARNINGS)
						call	show_blacklisted_router
					.endif
					.if bflags & BLACKLIST_FLAG_BAN_ROUTERS
						AdvTor_BanRouter	routerinfo._addr,BAN_GENERAL,1
						add	totalbans,eax
						.if hDialog
							invoke	SetDlgItemInt,hDialog,32,totalbans,0
						.endif
					.endif
				.endif
			.endif
		.endif
	.endif
	ret
AdvTor_RouterChanged	ENDP

AdvTor_GetConfigurationWindow	PROC	_hParent:DWORD
	push	_hParent
	pop	hParent
	invoke	CreateDialogParamW,hInstance,1000,hParent,addr dlgFunc,0
	mov	hDialog,eax
	ret
AdvTor_GetConfigurationWindow	ENDP

ResizeConfigurationWindow	PROC	newSize:DWORD
	lea	eax,resizeControls
	ret
ResizeConfigurationWindow	ENDP

http1	db	'HTTP/1.0 200 OK',13,10,'Content-Type: text/html; charset=UTF-8',13,10,'Connection: close',13,10,13,10,0
AdvTor_TranslateAddress	PROC	uses esi edi ebx connection_id:DWORD,original_address:DWORD,translated_address:DWORD,lParam:DWORD,is_error:DWORD
	local	hMem:DWORD,bptr:DWORD
	.if (is_error!=0) || (connection_id==0) || (!(bflags&BLACKLIST_FLAG_VERIFY_WEBSITES))

		xor	eax,eax
		inc	eax
		ret
	.endif
	xor	eax,eax
	.if translated_address
		invoke	is_ip,translated_address
	.endif
	.if eax==0 && original_address
		invoke	is_ip,original_address
	.endif
	.if eax
		mov	is_error,ecx
		mov	eax,ecx
		call	verify_ip
		.if eax
			.if bflags&BLACKLIST_FLAG_WEBSITES_WARNINGS
				mov	eax,[ebx]
				mov	bptr,eax
				invoke	GlobalAlloc,GPTR,1024
				mov	hMem,eax
				mov	edi,eax
				AdvTor_GetConnectingProcess	connection_id
				.if eax
					AdvTor_GetProcessName	eax,edi
					.while byte ptr[edi]
						inc	edi
					.endw
				.else
					AdvTor_lang_get_string	LANG_ID_UNKNOWN_PROCESS,offset unknown_process
					mov	edx,eax
					call	copyedx
				.endif
				mov	eax,' - '
				stosd
				dec	edi
				AdvTor_lang_get_string	LANG_ID_BANNED_ADDR,offset bannedaddr
				mov	edx,eax
				call	copyedx
				mov	eax,' - '
				stosd
				dec	edi
				.if original_address
					mov	edx,original_address
					call	copyedx
				.elseif translated_address
					mov	edx,translated_address
					call	copyedx
				.else
					mov	eax,is_error
					call	w_ip
				.endif
				mov	ax,'[ '
				stosw
				mov	eax,is_error
				call	w_ip
				mov	eax,' = '
				stosd
				dec	edi
				mov	edx,bptr
				mov	ecx,edi
				sub	ecx,hMem
				.while ecx<1000
					mov	al,[edx]
					.if al=='%'
						stosb
					.endif
					.break .if (al==':') || (al==13) || (al==10) || (al==0)
					stosb
					inc	edx
					inc	ecx
				.endw
				.if bflags&BLACKLIST_FLAG_BLOCK_WEBSITES
					mov	eax,' ,]'
					stosd
					dec	edi
					AdvTor_lang_get_string	LANG_ID_CLOSECONN,offset closeconn
					mov	edx,eax
					call	copyedx
					mov	al,0
					stosb
				.else
					mov	ax,']'
					stosw
				.endif
				AdvTor_Log	LOG_WARN,hMem
				invoke	GlobalFree,hMem
			.endif
			.if bflags&BLACKLIST_FLAG_SHOW_404
				invoke	GlobalAlloc,GPTR,8192
				mov	hMem,eax
				mov	edi,eax
				lea	edx,http1
				call	copyedx
				AdvTor_lang_get_string	LANG_ID_HTML1,offset html1
				mov	edx,eax
				xor	ecx,ecx
				.while byte ptr[edx]
					mov	al,[edx]
					inc	edx
					.if al=='%'
						.if byte ptr[edx]=='s'
							inc	edx
							push	edx
							.if ecx==0
								.if original_address
									mov	edx,original_address
									call	copyedx
								.elseif translated_address
									mov	edx,translated_address
									call	copyedx
								.else
									mov	eax,is_error
									call	w_ip
								.endif
								xor	ecx,ecx
								inc	ecx
							.else
								xor	ecx,ecx
								mov	edx,bptr
								.while ecx<1000
									mov	al,[edx]
									.if al=='"'
										mov	eax,'ouq&'
										stosd
										mov	ax,';t'
										stosw
										lea	ecx,[ecx+5]
									.elseif al=='<'
										mov	eax,';tl&'
										stosd
										lea	ecx,[ecx+3]
									.elseif al=='>'
										mov	eax,';tg&'
										stosd
										lea	ecx,[ecx+3]
									.else
										.break .if (al==':') || (al==13) || (al==10) || (al==0)
										stosb
									.endif
									inc	edx
									inc	ecx
								.endw
								xor	ecx,ecx
							.endif
							pop	edx
						.elseif byte ptr[edx]=='%'
							inc	edx
							stosb
						.endif
					.else
						stosb
					.endif
				.endw
				mov	ecx,edi
				sub	ecx,hMem
				AdvTor_HS_SendReply	connection_id,hMem,ecx
				invoke	GlobalFree,hMem
				inc	totalblocked
				.if hDialog
					invoke	SetDlgItemInt,hDialog,33,totalblocked,0
				.endif
				xor	eax,eax
				ret
			.endif
			.if bflags&BLACKLIST_FLAG_BLOCK_WEBSITES
				inc	totalblocked
				.if hDialog
					invoke	SetDlgItemInt,hDialog,33,totalblocked,0
				.endif
				xor	eax,eax
				ret
			.endif
		.endif
	.endif
	xor	eax,eax
	inc	eax
	ret
AdvTor_TranslateAddress	ENDP


defget	db	'/'
useragent	db	'Blacklist',0
blacklistdownload	PROC	uses esi edi	hUrl:DWORD
	local	hInternet:DWORD,hConn:DWORD,hReq:DWORD,lastPtr:DWORD
	local	hMem:DWORD,memSize:DWORD,hFile:DWORD
	local	qfile:DWORD,decBuf:DWORD,decSize:DWORD,method:DWORD
	invoke	InternetOpen,addr useragent,INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY,0,0,0
	mov	hInternet,eax
	mov	esi,hUrl
	lea	edi,[esi+1024]
	xor	ecx,ecx
	.while ecx<8
		.if word ptr[esi+ecx]=='/:' || word ptr[esi+ecx]=='\:'
			lea	esi,[esi+ecx+2]
			.if byte ptr[esi]=='/' || byte ptr[esi]=='\'
				inc	esi
			.endif
			.break
		.endif
		inc	ecx
	.endw
	.while byte ptr[esi]>32 && byte ptr[esi]!='/' && byte ptr[esi]!='\'
		movsb
	.endw
	mov	al,0
	stosb
	mov	lastPtr,esi
	mov	edx,hUrl
	lea	edx,[edx+1024]
	invoke	InternetConnect,hInternet,edx,INTERNET_DEFAULT_HTTP_PORT,0,0,INTERNET_SERVICE_HTTP,0,0
	.if eax==0
		invoke	GetLastError
		jmp	_showerr
	.endif
	mov	hConn,eax
	mov	edx,lastPtr
	.if byte ptr[edx]!='/'
		lea	edx,defget
	.endif
	invoke	HttpOpenRequest,hConn,0,edx,0,0,0,0,0
	.if eax==0
		invoke	GetLastError
		push	eax
		invoke	InternetCloseHandle,hConn
		pop	eax
_showerr:	push	eax
		mov	edi,hUrl
		lea	edi,[edi+1024]
		invoke	format_str,LANG_ID_ERRDL,offset errd1,hUrl
		pop	eax
		call	itoa
		mov	al,0
		stosb
		mov	edx,hUrl
		lea	edx,[edx+1024]
		AdvTor_Log	LOG_WARN,edx
		invoke	InternetCloseHandle,hInternet
		.if hDialog
			invoke	GetDlgItem,hDialog,1
			invoke	EnableWindow,eax,1
		.endif
		mov	downloading,0
		invoke	GlobalFree,hUrl
		invoke	ExitThread,0
		ret
	.endif
	mov	hReq,eax
	mov	bread,4
	invoke	HttpSendRequest,hReq,0,0,0,0
	invoke	GlobalAlloc,GPTR,1024*1024
	mov	hMem,eax
	mov	memSize,1024*1024
	mov	edi,eax
	.while 1
		.if _InternetReadFile==0
			call	__1
			db	'wininet.dll',0
		__1:	call	GetModuleHandle
			.if eax
				call	__2
				db	'InternetReadFile',0
			__2:	push	eax
				call	GetProcAddress
			.endif
			mov	_InternetReadFile,eax
		.endif
		.if _InternetReadFile
			push	offset bread
			push	64*1024
			push	edi
			push	hReq
			call	_InternetReadFile
		.else
			.break
		.endif
		.if bread
			add	edi,bread
			mov	edx,edi
			sub	edx,hMem
			lea	edx,[edx+131072]
			.if edx>memSize
				add	memSize,1024*1024
				invoke	GlobalAlloc,GPTR,memSize
				mov	ecx,edi
				mov	edi,eax
				mov	esi,hMem
				push	edi
				sub	ecx,esi
				cld
				rep	movsb
				invoke	GlobalFree,hMem
				pop	edx
				mov	hMem,edx
			.endif
			.if hDialog
				push	edi
				mov	eax,edi
				sub	eax,hMem
				mov	ecx,eax
				invoke	format_int,LANG_ID_DLG_BYTES_DOWNLOADED,addr bdown,ecx
				pop	edi
				invoke	get_unicode,edi
				push	eax
				invoke	SetDlgItemTextW,hDialog,11,eax
				call	GlobalFree
			.endif
		.else
			.break
		.endif
	.endw
	invoke	InternetCloseHandle,hReq
	invoke	InternetCloseHandle,hConn
	invoke	InternetCloseHandle,hInternet

	invoke	GlobalAlloc,GPTR,8192
	mov	qfile,eax
	invoke	GetModuleFileName,hInstance,qfile,8192
	mov	edx,qfile
	mov	ecx,edx
	.while byte ptr[edx]
		.if byte ptr[edx]=='\'
			lea	ecx,[edx+1]
		.endif
		inc	edx
	.endw
	mov	eax,'calb'
	mov	[ecx],eax
	mov	eax,'silk'
	mov	[ecx+4],eax
	mov	eax,'xt.t'
	mov	[ecx+8],eax
	mov	eax,'t'
	mov	[ecx+12],eax
	invoke	CreateFile,qfile,GENERIC_WRITE,FILE_SHARE_READ,0,CREATE_ALWAYS,0,0
	.if eax!=INVALID_HANDLE_VALUE
		push	eax
		mov	hFile,eax
		xor	ecx,ecx
		mov	edx,functions
		.while dword ptr[edx+ecx*4]
			inc	ecx
		.endw
		.if ecx < PLUGIN_FN_DETECT_COMPRESSION_METHOD
			xor	eax,eax
		.else
			AdvTor_detect_compression_method	hMem,10
		.endif
		mov	ecx,edi
		sub	ecx,hMem
		.if eax==GZIP_METHOD || eax==ZLIB_METHOD
			lea	edx,decBuf
			lea	ebx,decSize
			mov	decSize,0
			mov	decBuf,0
			mov	method,eax
			AdvTor_gzip_uncompress	edx,ebx,hMem,ecx,method,1,5
			.if eax==0
				invoke	WriteFile,hFile,decBuf,decSize,addr bread,0
				AdvTor_free	decBuf
				AdvTor_lang_get_string	LANG_ID_UNGZIPPED,offset ungzipped
				mov	ecx,edi
				sub	ecx,hMem
				mov	edi,hMem
				mov	edx,eax
				.while byte ptr[edx]
					mov	al,[edx]
					inc	edx
					.if al=='%'
						.if byte ptr[edx]=='s'
							inc	edx
							push	edx
							.if ecx
								mov	eax,ecx
								call	itoa
								xor	ecx,ecx
							.else
								mov	eax,decSize
								call	itoa
							.endif
							pop	edx
						.elseif byte ptr[edx]=='%'
							inc	edx
							stosb
						.endif
					.else
						stosb
					.endif
				.endw
				mov	al,0
				stosb
				AdvTor_Log	LOG_NOTICE,hMem
			.else
				mov	ecx,edi
				sub	ecx,hMem
				invoke	WriteFile,hFile,hMem,ecx,addr bread,0
			.endif
		.else
			invoke	WriteFile,hFile,hMem,ecx,addr bread,0
		.endif
		call	CloseHandle
	.endif
	invoke	GlobalFree,qfile
	invoke	GlobalFree,hMem
	.if hDialog
		invoke	GetDlgItem,hDialog,1
		invoke	EnableWindow,eax,1
		invoke	GetDlgItem,hDialog,24
		invoke	ShowWindow,eax,SW_HIDE
		lea	esi,controls
		.while word ptr[esi]
			lodsw
			movzx	eax,ax
			invoke	GetDlgItem,hDialog,eax
			invoke	ShowWindow,eax,SW_SHOW
		.endw
		AdvTor_lang_get_string	LANG_ID_DLG_SETTINGS,offset dtxt
		invoke	get_unicode,eax
		push	eax
		invoke	SetDlgItemTextW,hDialog,11,eax
		call	GlobalFree
	.endif
	push	pointeri
	push	ipuri
	push	blocked
	call	LoadBlacklist
	pop	eax
	.if eax!=blocked && eax!=0
		invoke	GlobalFree,eax
	.endif
	pop	eax
	.if eax!=ipuri && eax!=0
		invoke	GlobalFree,eax
	.endif
	pop	eax
	.if eax!=pointeri && eax!=0
		invoke	GlobalFree,eax
	.endif
	AdvTor_lang_get_string	LANG_ID_DLSUCCESS,offset dls
	mov	edx,eax
	AdvTor_Log	LOG_INFO,edx
	invoke	GlobalFree,hUrl
	mov	downloading,0
	invoke	ExitThread,0
	ret
blacklistdownload	ENDP


deflists	db	'http://list.iblocklist.com/?list=ijfqtofzixtwayqovmxn',0,0
controls	dw	400,401,402,403,404,405,500,501,50,20,30,21,31,22,32,23,33,51,100,3,0
dlgFunc	PROC	uses esi edi ebx hDlg:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg==WM_INITDIALOG
		lea	esi,deflists
		.while byte ptr[esi]
			invoke	SendDlgItemMessage,hDlg,300,CB_ADDSTRING,0,esi
			.while byte ptr[esi]
				lodsb
			.endw
			lodsb
		.endw
		AdvTor_lang_change_dialog_strings	hDlg,offset dialog_strings
		.if lasturl
			invoke	SendDlgItemMessage,hDlg,300,CB_ADDSTRING,0,esi
			invoke	SetDlgItemText,hDlg,300,lasturl
			invoke	GlobalFree,lasturl
			mov	lasturl,0
		.endif
		invoke	SetDlgItemInt,hDlg,30,totalips,0
		invoke	SetDlgItemInt,hDlg,31,totalwarns,0
		invoke	SetDlgItemInt,hDlg,32,totalbans,0
		invoke	SetDlgItemInt,hDlg,33,totalblocked,0
		.if bflags & BLACKLIST_FLAG_VERIFY_ALL_ROUTERS
			invoke	CheckDlgButton,hDlg,400,BST_CHECKED
		.else
			invoke	GetDlgItem,hDlg,401
			invoke	EnableWindow,eax,0
			invoke	GetDlgItem,hDlg,402
			invoke	EnableWindow,eax,0
		.endif
		.if bflags & BLACKLIST_FLAG_ROUTER_WARNINGS
			invoke	CheckDlgButton,hDlg,401,BST_CHECKED
		.endif
		.if bflags & BLACKLIST_FLAG_BAN_ROUTERS
			invoke	CheckDlgButton,hDlg,402,BST_CHECKED
		.endif
		.if bflags & BLACKLIST_FLAG_VERIFY_WEBSITES
			invoke	CheckDlgButton,hDlg,403,BST_CHECKED
		.else
			invoke	GetDlgItem,hDlg,404
			invoke	EnableWindow,eax,0
			invoke	GetDlgItem,hDlg,405
			invoke	EnableWindow,eax,0
			invoke	GetDlgItem,hDlg,500
			invoke	EnableWindow,eax,0
			invoke	GetDlgItem,hDlg,501
			invoke	EnableWindow,eax,0
		.endif
		.if bflags & BLACKLIST_FLAG_WEBSITES_WARNINGS
			invoke	CheckDlgButton,hDlg,404,BST_CHECKED
		.endif
		.if bflags & BLACKLIST_FLAG_BLOCK_WEBSITES
			invoke	CheckDlgButton,hDlg,405,BST_CHECKED
		.else
			invoke	GetDlgItem,hDlg,500
			invoke	EnableWindow,eax,0
			invoke	GetDlgItem,hDlg,501
			invoke	EnableWindow,eax,0
		.endif
		.if bflags & BLACKLIST_FLAG_SHOW_404
			invoke	CheckDlgButton,hDlg,501,BST_CHECKED
		.else
			invoke	CheckDlgButton,hDlg,500,BST_CHECKED
		.endif
		.if ips==0
			invoke	GetDlgItem,hDlg,24
			invoke	ShowWindow,eax,SW_SHOW
			lea	esi,controls
			.while word ptr[esi]
				lodsw
				movzx	eax,ax
				invoke	GetDlgItem,hDlg,eax
				invoke	ShowWindow,eax,SW_HIDE
			.endw
		.else
			invoke	GetDlgItem,hDlg,24
			invoke	ShowWindow,eax,SW_HIDE
		.endif
	.elseif uMsg==WM_COMMAND
		mov	eax,wParam
		.if ax==3
			invoke	GlobalAlloc,GPTR,8192
			push	eax
			invoke	GetDlgItemText,hDlg,100,eax,99
			mov	esi,[esp]
			call	getrange
			mov	wParam,eax
			mov	lParam,ebx
			mov	edi,[esp]
			mov	eax,wParam
			mov	ebx,lParam
			call	chkrange
			mov	ecx,eax
			push	ecx
			mov	eax,wParam
			mov	ebx,lParam
			.if ecx
				.if eax==ebx
					AdvTor_lang_get_string	LANG_ID_MB_IP_B,offset msg_ip_banned
				.else
					AdvTor_lang_get_string	LANG_ID_MB_RNG_B,offset msg_range_banned
				.endif
			.else
				.if eax==ebx
					AdvTor_lang_get_string	LANG_ID_MB_IP_NB,offset msg_ip_nb
				.else
					AdvTor_lang_get_string	LANG_ID_MB_RNG_NB,offset msg_range_nb
				.endif
			.endif
			mov	edx,eax
			.while byte ptr[edx]
				mov	al,[edx]
				inc	edx
				.if al=='%'
					.if byte ptr[edx]=='s'
						inc	edx
						push	edx
						mov	eax,wParam
						.if eax!=lParam
							mov	eax,wParam
							.if eax>lParam
								xchg	eax,lParam
								mov	wParam,eax
							.endif
							call	w_ip
							mov	al,'-'
							stosb
							mov	eax,lParam
						.endif
						call	w_ip
						pop	edx
					.elseif byte ptr[edx]=='%'
						inc	edx
						stosb
					.endif
				.else
					stosb
				.endif
			.endw
			pop	ecx
			.if ecx
				mov	ax,0a0dh
				stosw
				mov	eax,wParam
				mov	ebx,lParam
				call	showrange
			.endif
			mov	al,0
			stosb
			mov	edi,[esp]
			AdvTor_lang_get_string	LANG_ID_MB_RESULTS,offset msgbannedt
			invoke	get_unicode,eax
			push	eax
			invoke	get_unicode,edi
			mov	edx,[esp]
			push	eax
			mov	ecx,eax
			invoke	MessageBoxW,hParent,ecx,edx,0
			call	GlobalFree
			call	GlobalFree
			call	GlobalFree
		.elseif (ax==1) && (downloading==0)
			mov	downloading,1
			invoke	GetDlgItem,hDlg,1
			invoke	EnableWindow,eax,0
			invoke	GlobalAlloc,GPTR,2048
			push	eax
			invoke	GetDlgItemText,hDlg,300,eax,511
			pop	edx
			invoke	CreateThread,0,0,addr blacklistdownload,edx,0,addr bread
			.if eax
				invoke	CloseHandle,eax
			.endif
		.elseif ax==400
			invoke	IsDlgButtonChecked,hDlg,400
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_VERIFY_ALL_ROUTERS
				invoke	GetDlgItem,hDlg,401
				invoke	EnableWindow,eax,1
				invoke	GetDlgItem,hDlg,402
				invoke	EnableWindow,eax,1
			.else
				and	bflags,BLACKLIST_FLAG_VERIFY_ALL_ROUTERS xor -1
				invoke	GetDlgItem,hDlg,401
				invoke	EnableWindow,eax,0
				invoke	GetDlgItem,hDlg,402
				invoke	EnableWindow,eax,0
			.endif
		.elseif ax==401
			invoke	IsDlgButtonChecked,hDlg,401
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_ROUTER_WARNINGS
			.else
				and	bflags,BLACKLIST_FLAG_ROUTER_WARNINGS xor -1
			.endif
		.elseif ax==402
			invoke	IsDlgButtonChecked,hDlg,402
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_BAN_ROUTERS
			.else
				and	bflags,BLACKLIST_FLAG_BAN_ROUTERS xor -1
			.endif
		.elseif ax==403
			invoke	IsDlgButtonChecked,hDlg,403
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_VERIFY_WEBSITES
				invoke	GetDlgItem,hDlg,404
				invoke	EnableWindow,eax,1
				invoke	GetDlgItem,hDlg,405
				invoke	EnableWindow,eax,1
				.if bflags & BLACKLIST_FLAG_BLOCK_WEBSITES
					invoke	GetDlgItem,hDlg,500
					invoke	EnableWindow,eax,1
					invoke	GetDlgItem,hDlg,501
					invoke	EnableWindow,eax,1
				.endif
			.else
				and	bflags,BLACKLIST_FLAG_VERIFY_WEBSITES xor -1
				invoke	GetDlgItem,hDlg,404
				invoke	EnableWindow,eax,0
				invoke	GetDlgItem,hDlg,405
				invoke	EnableWindow,eax,0
				invoke	GetDlgItem,hDlg,500
				invoke	EnableWindow,eax,0
				invoke	GetDlgItem,hDlg,501
				invoke	EnableWindow,eax,0
			.endif
		.elseif ax==404
			invoke	IsDlgButtonChecked,hDlg,404
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_WEBSITES_WARNINGS
			.else
				and	bflags,BLACKLIST_FLAG_WEBSITES_WARNINGS xor -1
			.endif
		.elseif ax==405
			invoke	IsDlgButtonChecked,hDlg,405
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_BLOCK_WEBSITES
				.if bflags & BLACKLIST_FLAG_VERIFY_WEBSITES
					invoke	GetDlgItem,hDlg,500
					invoke	EnableWindow,eax,1
					invoke	GetDlgItem,hDlg,501
					invoke	EnableWindow,eax,1
				.endif
			.else
				and	bflags,BLACKLIST_FLAG_BLOCK_WEBSITES xor -1
				invoke	GetDlgItem,hDlg,500
				invoke	EnableWindow,eax,0
				invoke	GetDlgItem,hDlg,501
				invoke	EnableWindow,eax,0
			.endif
		.elseif ax==500
			invoke	IsDlgButtonChecked,hDlg,500
			.if eax==BST_CHECKED
				and	bflags,BLACKLIST_FLAG_SHOW_404 xor -1
			.endif
		.elseif ax==501
			invoke	IsDlgButtonChecked,hDlg,501
			.if eax==BST_CHECKED
				or	bflags,BLACKLIST_FLAG_SHOW_404
			.endif
		.endif
	.elseif uMsg==WM_VSCROLL
		invoke	PostMessage,hParent,WM_USER+13,wParam,hDlg
	.elseif uMsg==WM_HSCROLL
		invoke	PostMessage,hParent,WM_USER+12,wParam,hDlg
	.endif
	xor	eax,eax
	ret
dlgFunc	ENDP

End DllEntry
