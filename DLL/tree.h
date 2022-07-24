insertChildren	PROTO	:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

procAlloc	struct
	_next		dd	?
	pid		dd	?
	parentPid	dd	?
	exeName		db	MAX_PATH*4 dup(?)
procAlloc	ends

tree_procs	macro
strPid	db	' (PID: ',0

setExeName	PROC	uses edi ebx edx lpBuf:DWORD,dwPid:DWORD
	mov	edi,lpBuf
	xor	eax,eax
	.while word ptr[edi+eax]
		inc	eax
		inc	eax
	.endw
	.if eax>MAX_PATH*2
		sub	eax,40
	.endif
	lea	edi,[edi+eax]
	lea	edx,strPid
	call	copyedxW
	mov	eax,dwPid
	call	itoaW
	mov	eax,')'
	stosd
	ret
setExeName	ENDP

insertChildren	PROC	uses edi dwPid:DWORD,hMem:DWORD,hTree:DWORD,hItem:DWORD,tvins:DWORD
	mov	edx,tvins
	assume	edx:ptr TV_INSERTSTRUCTW
	push	[edx].hParent
	push	[edx].hInsertAfter
	mov	eax,hItem
	mov	[edx].hParent,eax
	mov	[edx].hInsertAfter,TVI_FIRST
	mov	edi,hMem
	.while edi
		assume	edi:ptr procAlloc
		mov	eax,dwPid
		.if (eax==[edi].parentPid)&&([edi].pid!=-1)&&(eax!=0)
			mov	edx,tvins
			mov	[edx].itemex.imask,TVIF_PARAM or TVIF_TEXT or TVIF_STATE
			mov	eax,[edi].pid
			mov	[edx].itemex.lParam,eax
			lea	ecx,[edi].exeName
			mov	[edx].itemex.pszText,ecx
			invoke	setExeName,ecx,[edx].itemex.lParam
			mov	[edx].itemex.cchTextMax,MAX_PATH
			mov	[edx].itemex.iImage,0
			mov	[edx].itemex.iSelectedImage,0
			mov	[edx].itemex.cChildren,0
			mov	[edx].itemex.stateMask,TVIS_STATEIMAGEMASK
			mov	[edx].itemex.state,8192
			mov	[edx].itemex.iIntegral,0
			user32SendMessageW	hTree,TVM_INSERTITEMW,0,edx
			mov	edx,tvins
			mov	[edx].hInsertAfter,eax
			invoke	insertChildren,[edi].pid,hMem,hTree,eax,edx
			mov	[edi].pid,-1
		.endif
		assume	edi:nothing
		mov	edi,[edi]
	.endw
	mov	edx,tvins
	pop	[edx].hInsertAfter
	pop	[edx].hParent
	assume	edx:nothing
	user32SendMessage	hTree,TVM_EXPAND,TVE_EXPAND,hItem
	ret
insertChildren	ENDP

ShowProcessTree	PROC	uses edi hWnd:DWORD,hTree:DWORD
	local	tmpPid:DWORD,hMem:DWORD,selectedProcess:DWORD
	local	lppe1:PROCESSENTRY32W,hSnap:DWORD
	local	tvinsw:TV_INSERTSTRUCTW
	user32SendMessage	hTree,TVM_DELETEITEM,0,TVI_ROOT
	mov	tmpPid,0
	mov	hMem,0
	lea	edx,tmpPid
	user32GetWindowThreadProcessId	hWnd,edx
	.if tmpPid
		invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
		.if eax==INVALID_HANDLE_VALUE
			ret
		.endif
		mov	hSnap,eax
		mov	lppe1.dwSize,sizeof PROCESSENTRY32W
		invoke	Process32FirstW,hSnap,addr lppe1
		.if eax==0
			invoke	CloseHandle,hSnap
			ret
		.endif
		lea	edi,hMem
		.while 1
			invoke	GlobalAlloc,GPTR,sizeof procAlloc
			mov	[edi],eax
			mov	edi,eax
			assume	edi:ptr procAlloc
			mov	[edi]._next,0
			mov	eax,lppe1.th32ProcessID
			mov	[edi].pid,eax
			mov	eax,lppe1.th32ParentProcessID
			mov	[edi].parentPid,eax
			lea	edx,lppe1.szExeFile
			xor	ecx,ecx
			xor	eax,eax
			.while word ptr[edx+ecx]
				.if (word ptr[edx+ecx]=='\')||(word ptr[edx+ecx]=='/')
					lea	eax,[ecx+2]
				.endif
				inc	ecx
				inc	ecx
			.endw
			lea	edx,[edx+eax]
			push	edi
			lea	edi,[edi].exeName
			xor	ecx,ecx
			.while word ptr[edx+ecx] && (ecx<(MAX_PATH*4 - 40))
				mov	ax,[edx+ecx]
				stosw
				inc	ecx
				inc	ecx
			.endw
			assume	edi:nothing
			mov	ax,0
			stosw
			pop	edi
			invoke	Process32NextW,hSnap,addr lppe1
			.break .if eax==0
		.endw
		invoke	CloseHandle,hSnap
		mov	tvinsw.hParent,TVI_ROOT
		mov	tvinsw.hInsertAfter,TVI_FIRST
		mov	selectedProcess,0
		mov	edi,hMem
		.while edi
			assume	edi:ptr procAlloc
			mov	eax,[edi].pid
			.if eax==tmpPid
				mov	selectedProcess,edi
				mov	tvinsw.itemex.imask,TVIF_PARAM or TVIF_TEXT or TVIF_STATE
				mov	eax,[edi].pid
				mov	tvinsw.itemex.lParam,eax
				lea	edx,[edi].exeName
				mov	tvinsw.itemex.pszText,edx
				invoke	setExeName,edx,tvinsw.itemex.lParam
				mov	tvinsw.itemex.cchTextMax,MAX_PATH
				mov	tvinsw.itemex.iImage,0
				mov	tvinsw.itemex.iSelectedImage,0
				mov	tvinsw.itemex.cChildren,0
				mov	tvinsw.itemex.stateMask,TVIS_STATEIMAGEMASK
				mov	tvinsw.itemex.state,8192
				mov	tvinsw.itemex.iIntegral,0
				lea	edx,tvinsw
				user32SendMessageW	hTree,TVM_INSERTITEMW,0,edx
				xchg	edx,eax
				invoke	insertChildren,[edi].pid,hMem,hTree,edx,addr tvinsw
				mov	[edi].pid,-1
				.break
			.endif
			assume	edi:nothing
			mov	edi,[edi]
		.endw

		mov	tvinsw.hParent,TVI_ROOT
		mov	tvinsw.hInsertAfter,TVI_LAST
		mov	selectedProcess,0
		mov	edi,hMem
		mov	edx,selectedProcess
		.if edx
			assume	edx:ptr procAlloc
			lea	edx,[edx].exeName
			assume	edx:nothing
			.while edi
				assume	edi:ptr procAlloc
				.if [edi].pid!=-1
					xor	ecx,ecx
					.while (word ptr[edx+ecx]!=0)&&(word ptr[edi+ecx].exeName!=0)
						mov	al,[edx+ecx]
						mov	ah,[edi+ecx].exeName
						or	ax,2020h
						.break .if al!=ah
						mov	al,[edx+ecx+1]
						mov	ah,[edi+ecx+1].exeName
						.break .if al!=ah
						inc	ecx
						inc	ecx
					.endw
					.if (word ptr[edx+ecx]==0)&&(word ptr[edi+ecx].exeName==0)
						push	edx
						mov	selectedProcess,edi
						mov	tvinsw.itemex.imask,TVIF_PARAM or TVIF_TEXT or TVIF_STATE
						mov	eax,[edi].pid
						mov	tvinsw.itemex.lParam,eax
						lea	edx,[edi].exeName
						mov	tvinsw.itemex.pszText,edx
						invoke	setExeName,edx,tvinsw.itemex.lParam
						mov	tvinsw.itemex.cchTextMax,MAX_PATH
						mov	tvinsw.itemex.iImage,0
						mov	tvinsw.itemex.iSelectedImage,0
						mov	tvinsw.itemex.cChildren,0
						mov	tvinsw.itemex.stateMask,TVIS_STATEIMAGEMASK
						mov	tvinsw.itemex.state,8192
						mov	tvinsw.itemex.iIntegral,0
						lea	edx,tvinsw
						user32SendMessageW	hTree,TVM_INSERTITEMW,0,edx
						xchg	edx,eax
						invoke	insertChildren,[edi].pid,hMem,hTree,edx,addr tvinsw
						mov	[edi].pid,-1
						pop	edx
					.endif
				.endif
				assume	edi:nothing
				mov	edi,[edi]
			.endw
		.endif

		mov	edi,hMem
		.while edi
			push	dword ptr[edi]
			invoke	GlobalFree,edi
			pop	edi
		.endw
	.endif
	ret
ShowProcessTree	ENDP

hookChildren	PROC	uses esi edi hTree:DWORD,hItem:DWORD,proxyPort:DWORD,best_delta_t:DWORD,pipekey:DWORD
	local	tvinsw:TV_INSERTSTRUCTW
	mov	tvinsw.itemex.imask,TVIF_STATE or TVIF_PARAM
	mov	tvinsw.itemex.lParam,0
	mov	tvinsw.itemex.stateMask,TVIS_STATEIMAGEMASK
	mov	eax,hItem
	mov	tvinsw.itemex.hItem,eax
	lea	edx,tvinsw.itemex
	user32SendMessageW	hTree,TVM_GETITEMW,0,edx
	.if eax
		.if (tvinsw.itemex.state&8192)&&(tvinsw.itemex.lParam!=0)
			invoke	GetCurrentProcessId
			.if eax!=tvinsw.itemex.lParam
				movzx	ecx,word ptr proxyPort
				mov	ebx,sysflags
				or	ebx,100h
				and	ebx,2048 xor -1
				invoke	TORHook,tvinsw.itemex.lParam,ecx,ebx,best_delta_t,addr localhostname,pipekey
				user32SendMessageW	hTree,TVM_GETNEXTITEM,TVGN_CHILD,tvinsw.itemex.hItem
				.if eax
					mov	hItem,eax
					.while 1
						invoke	hookChildren,hTree,hItem,proxyPort,best_delta_t,pipekey
						user32SendMessage	hTree,TVM_GETNEXTITEM,TVGN_NEXT,hItem
						.break .if eax==0
						mov	hItem,eax
					.endw
				.endif
			.endif
		.endif
	.endif
	ret
hookChildren	ENDP

HookProcessTree	PROC	uses esi edi ebx hTree:DWORD,proxyPort:DWORD,best_delta_t:DWORD,pipekey:DWORD,_sysflags:DWORD,_localname:DWORD
	local	hItem:DWORD
	.if _localname
		mov	esi,_localname
		lea	edi,localhostname
		mov	ecx,255
		.while (ecx!=0)&&(byte ptr[esi]!=0)
			movsb
			dec	ecx
		.endw
		mov	al,0
		stosb
	.endif
	mov	eax,_sysflags
	mov	sysflags,eax
	user32SendMessage	hTree,TVM_GETNEXTITEM,TVGN_ROOT,0
	.if eax
		or	sysflags,512
		mov	hItem,eax
		.while 1
			invoke	hookChildren,hTree,hItem,proxyPort,best_delta_t,pipekey
			user32SendMessage	hTree,TVM_GETNEXTITEM,TVGN_NEXT,hItem
			.break .if eax==0
			mov	hItem,eax
		.endw
		and	sysflags,512 xor -1
	.endif
	ret
HookProcessTree	ENDP

endm