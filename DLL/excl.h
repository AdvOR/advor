excl_info	struct
	process_id	dd	?
	chain_key	dd	?
	chain_name	dd	?
	sel_exit	dd	?		;0.0.0.0 = random country, random node
						;0.0.0.CC = country CC, random node
						;n.n.n.n = exit IP
excl_info	ends

excl_data	macro
	exclKeyList	dd	?
	exclKeyCount	dd	?
	exclKeyMaxCount	dd	?
endm

excl_init	macro
	mov	exclKeyList,0
	mov	exclKeyCount,0
endm

excl_procs	macro

GetProcessChainKey	PROC	__pid:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,__pid
		.while ecx
			.if eax==[edx].process_id
				mov	eax,[edx].chain_key
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	xor	eax,eax
	inc	eax
	ret
GetProcessChainKey	ENDP

GetProcessChains	PROC	uses esi edi lpBuffer:DWORD,maxCount:DWORD
	.if exclKeyCount!=0
		mov	ecx,maxCount
		.if ecx>exclKeyCount
			mov	ecx,exclKeyCount
		.endif
		push	ecx
		mov	eax,sizeof excl_info
		xor	edx,edx
		mul	ecx
		mov	ecx,eax
		cld
		rep	movsb
		pop	eax
	.else
		xor	eax,eax
	.endif
	ret
GetProcessChains	ENDP

RegisterNewKey	PROC	uses esi edi __pid:DWORD,_key:DWORD
	mov	eax,exclKeyCount
	inc	eax
	.if eax>exclKeyMaxCount
		mov	ecx,exclKeyMaxCount
		lea	ecx,[ecx+16]
		mov	exclKeyMaxCount,ecx
		mov	eax,sizeof excl_info
		xor	edx,edx
		mul	ecx
		invoke	GlobalAlloc,GPTR,eax
		mov	edi,eax
		mov	esi,exclKeyList
		mov	exclKeyList,edi
		push	esi
		.if esi
			mov	ecx,exclKeyCount
			mov	eax,sizeof excl_info
			xor	edx,edx
			mul	ecx
			mov	ecx,eax
			cld
			rep	movsb
		.endif
		pop	edx
		.if edx
			invoke	GlobalFree,edx
		.endif
	.endif
	mov	ecx,exclKeyCount
	mov	eax,sizeof excl_info
	xor	edx,edx
	mul	ecx
	add	eax,exclKeyList
	mov	edx,eax
	assume	edx:ptr excl_info
	mov	eax,__pid
	mov	[edx].process_id,eax
	mov	eax,_key
	or	eax,1
	mov	[edx].chain_key,eax
	mov	_key,eax
	mov	[edx].sel_exit,0
	mov	ecx,exclKeyList
	push	0
	.while ecx<edx
		assume	ecx:ptr excl_info
		.if [ecx].chain_key==eax
			pop	eax
			mov	eax,[ecx].chain_name
			push	eax
			.break
		.endif
		assume	ecx:nothing
		lea	ecx,[ecx+sizeof excl_info]
	.endw
	pop	eax
	mov	[edx].chain_name,eax
	assume	edx:nothing
	inc	exclKeyCount
	mov	eax,_key
	ret
RegisterNewKey	ENDP

UnregisterPidKey	PROC	uses esi edi __pid:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,__pid
		.while ecx
			.if eax==[edx].process_id
				push	edx
				dec	exclKeyCount
				mov	ecx,exclKeyCount
				mov	eax,sizeof excl_info
				xor	edx,edx
				mul	ecx
				mov	esi,eax
				add	esi,exclKeyList
				pop	edi
				mov	ecx,sizeof excl_info
				cld
				rep	movsb
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	ret
UnregisterPidKey	ENDP

GetSetChainKeyName	PROC	__pid:DWORD,dwKey:DWORD,newname:DWORD
	local	tmpkey:DWORD,tmpaddr:DWORD,tmpexit:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	tmpexit,0
		mov	eax,dwKey
		.while ecx
			.if eax==[edx].chain_key && [edx].chain_name!=0
				mov	eax,[edx].sel_exit
				mov	tmpexit,eax
				mov	eax,[edx].chain_name
				mov	newname,eax
				.break
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		mov	tmpkey,0
		mov	tmpaddr,0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,__pid
		.while ecx
			.if eax==[edx].process_id
				.if [edx].chain_name
					mov	eax,[edx].chain_name
				.elseif newname
					push	edx
					lea	edx,newname
					xor	ecx,ecx
					.while ecx<4
						mov	al,byte ptr [edx+ecx]
						.break .if al==0 || al=='.'
						.if al>='a' && al <='z'
							sub	al,20h
						.endif
						mov	byte ptr[edx+ecx],al
						inc	ecx
					.endw
					.while ecx<4
						mov	byte ptr[edx+ecx],'_'
						inc	ecx
					.endw
					pop	edx
					mov	eax,tmpexit
					mov	[edx].sel_exit,eax
					mov	eax,newname
					mov	[edx].chain_name,eax
				.else
					xor	eax,eax
				.endif
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	xor	eax,eax
	ret
GetSetChainKeyName	ENDP

GetChainKeyName	PROC	uses edi lpBuffer:DWORD,dwKey:DWORD
	mov	edi,lpBuffer
	.if dwKey==1
		mov	eax,'ENEG'
		stosd
		mov	eax,'LAR'
		stosd
		ret
	.elseif dwKey==0
		mov	eax,'EDNU'
		stosd
		mov	eax,'ENIF'
		stosd
		mov	ax,'D'
		stosw
		ret
	.elseif dwKey==4
		mov	eax,'CRID'
		stosd
		mov	eax,'NNO'
		stosd
		ret
	.elseif dwKey==5
		mov	eax,'ETNI'
		stosd
		mov	eax,'LANR'
		stosd
		mov	al,0
		stosb
		ret
	.elseif exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,dwKey
		.while ecx
			.if eax==[edx].chain_key
				mov	eax,'LCXE'
				stosd
				mov	al,'_'
				stosb
				mov	eax,[edx].chain_name
				.if eax
					stosd
					mov	al,'_'
					stosb
				.endif
				mov	eax,[edx].chain_key
				call	whex
				mov	al,0
				stosb
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	xor	eax,eax
	ret
GetChainKeyName	ENDP

GetChainExit	PROC	dwKey:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,dwKey
		.while ecx
			.if eax==[edx].chain_key
				mov	eax,[edx].sel_exit
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.else
		xor	eax,eax
	.endif
	ret
GetChainExit	ENDP

SetChainExit	PROC	dwKey:DWORD,exit:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,dwKey
		.while ecx
			.if eax==[edx].chain_key
				push	exit
				pop	[edx].sel_exit
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	ret
SetChainExit	ENDP

RegisterPluginKey	PROC	uses esi edi _key:DWORD
	mov	eax,exclKeyCount
	inc	eax
	.if eax>exclKeyMaxCount
		mov	ecx,exclKeyMaxCount
		lea	ecx,[ecx+16]
		mov	exclKeyMaxCount,ecx
		mov	eax,sizeof excl_info
		xor	edx,edx
		mul	ecx
		invoke	GlobalAlloc,GPTR,eax
		mov	edi,eax
		mov	esi,exclKeyList
		mov	exclKeyList,edi
		push	esi
		.if esi
			mov	ecx,exclKeyCount
			mov	eax,sizeof excl_info
			xor	edx,edx
			mul	ecx
			mov	ecx,eax
			cld
			rep	movsb
		.endif
		pop	edx
		.if edx
			invoke	GlobalFree,edx
		.endif
	.endif
	mov	ecx,exclKeyCount
	mov	eax,sizeof excl_info
	xor	edx,edx
	mul	ecx
	add	eax,exclKeyList
	mov	edx,eax
	assume	edx:ptr excl_info
	mov	[edx].process_id,0	;plugin
	mov	eax,_key
	or	eax,1
	mov	[edx].chain_key,eax
	mov	_key,eax
	mov	[edx].sel_exit,0
	mov	ecx,exclKeyList
	mov	eax,'GULP'
	mov	[edx].chain_name,eax
	assume	edx:nothing
	inc	exclKeyCount
	mov	eax,_key
	ret
RegisterPluginKey	ENDP

UnregisterPluginKey	PROC	uses esi edi __key:DWORD
	.if exclKeyCount!=0
		mov	edx,exclKeyList
		mov	ecx,exclKeyCount
		assume	edx:ptr excl_info
		mov	eax,__key
		.while ecx
			.if eax==[edx].chain_key
				push	edx
				dec	exclKeyCount
				mov	ecx,exclKeyCount
				mov	eax,sizeof excl_info
				xor	edx,edx
				mul	ecx
				mov	esi,eax
				add	esi,exclKeyList
				pop	edi
				mov	ecx,sizeof excl_info
				cld
				rep	movsb
				ret
			.endif
			dec	ecx
			lea	edx,[edx+sizeof excl_info]
		.endw
		assume	edx:nothing
	.endif
	ret
UnregisterPluginKey	ENDP

endm
