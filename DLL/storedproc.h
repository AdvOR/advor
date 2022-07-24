STORED_PROC_FIREFOX = 0
STORED_PROC_CHROME = 1
STORED_PROC_OPERA = 2
STORED_PROC_FIREFOX2 = 3

GetKernelDelta	PROC	pid:DWORD
	local	procKernelBase:DWORD,procKernelDelta:DWORD
	.if hKernel==0
		invoke	LoadLibrary,addr kernel
		mov	hKernel,eax
	.endif
	.if kernelBase==0
		invoke	GetKernelBase,0
		.if eax
			mov	kernelBase,eax
		.else
			mov	kernelBase,-1
		.endif
	.endif
	.if _VirtualAllocEx==0
		call	get_proc_addresses
	.endif
	.if _VirtualAllocEx
		mov	eax,kernelBase
		mov	procKernelBase,eax
		.if (kernelBase!=0)&&(kernelBase!=-1)
			invoke	GetKernelBase,pid
			mov	procKernelBase,eax
			sub	eax,kernelBase
			mov	procKernelDelta,eax
		.else
			mov	procKernelDelta,0
		.endif
		mov	eax,procKernelDelta
	.else
		xor	eax,eax
	.endif
	ret
GetKernelDelta	ENDP

GetFirefoxProc	PROC	kdelta:DWORD,buffer:DWORD,param1:DWORD,param2:DWORD
	mov	edi,buffer
	mov	al,0e8h
	stosb
	mov	eax,100
	mov	ecx,eax
	lea	eax,[eax+12]
	stosd
	mov	eax,param1			;constructor
	stosd
	mov	eax,param2			;RemoveAll()
	stosd
	mov	eax,_ExitThread
	add	eax,kdelta
	stosd					;	dd	ExitThread
	xor	eax,eax
	stosd
	mov	eax,0aaab6710h
	stosd
	mov	eax,11d50f2ch
	stosd
	mov	eax,10003ba5h
	stosd
	mov	eax,10eb01a4h
	stosd
	mov	eax,1097aff8h
	stosd
	xor	eax,eax
	sub	ecx,24
	rep	stosb
	mov	al,5fh
	stosb					;	pop	edi
	mov	eax,0c478dh
	stosd
	dec	edi				;	lea	eax,[edi+12]
	mov	al,50h
	stosb					;	push	eax
	mov	eax,5004408dh			;	lea	eax,[eax+4]
	stosd					;	push	eax
	mov	ax,6ah
	stosw
	mov	ax,17ffh
	stosw					;	call	dword ptr[edi]
	mov	eax,0474c00bh			;	.if eax
	stosd
	mov	eax,0857ff50h			;		invoke	ExitThread,eax
	stosd					;	.endif
	mov	eax,0c478bh
	stosd
	dec	edi				;	mov	eax,[edi+12]
	mov	al,50h				;	push	eax
	stosb
	mov	eax,0457ffh
	stosd
	dec	edi				;	call	dword ptr[edi+4]
	mov	al,50h
	stosb					;	push	eax
	mov	eax,0857ffh
	stosd					;	call	ExitThread

	mov	eax,edi
	sub	eax,buffer
	ret
GetFirefoxProc	ENDP

__ff0:	pop	edi
	call	__ff1
	db	'xpcom.dll',0
__ff1:	call	dword ptr[edi]		;GetModuleHandle
	.if eax
		push	eax
		call	__ff1a
		db	'NS_InitXPCOM2',0
__ff1a:		push	eax
		call	dword ptr[edi+4]
		mov	[edi+12],eax
		pop	eax
		call	__ff2
		db	'NS_GetComponentManager',0
__ff2:		push	eax
		call	dword ptr[edi+4]	;GetProcAddress
		.if eax
			mov	[edi+16],eax

			push	0
			mov	edx,esp
				push	edx
				call	dword ptr[edi+16]
				add	esp,4
			mov	esi,eax
			mov	eax,[esp]
			.if eax
				mov	ecx,[eax]
				call	__ff3
			;	db	1dh,8dh,62h,94h,31h,8bh,0aah,4bh,0b4h,74h,9ch,87h,2ch,44h,0fh,90h
			;	db	10h,67h,0abh,0aah,2ch,0fh,0d5h,11h,0a5h,3bh,0,10h,0a4h,1,0ebh,10h
				db	0fh,0e5h,0e9h,0d1h,8bh,0b7h,3bh,4eh,0a4h,74h,0f3h,0cbh,0cah,59h,0b0h,13h
__ff3:				pop	edx
				push	edx
				mov	edx,esp
					push	edx
					push	dword ptr[edx]
					mov	dword ptr[edx],0
					call	__ff4
					db	'@mozilla.org/cookiemanager;1',0
__ff4:					push	eax
int 3
					call	dword ptr[ecx+16]
				mov	esi,eax
				.if dword ptr[esp+4]
					mov	eax,[esp+4]
					mov	ecx,[eax]
					push	eax
					call	dword ptr[ecx+8]
				.endif
				pop	edx
			.endif
			pop	ecx
		.endif
	.endif
	push	eax
	call	dword ptr[edi+8]	;ExitThread
__ffx:

GetFirefoxProc2	PROC	kdelta:DWORD,buffer:DWORD,param1:DWORD,param2:DWORD
	local	proc_inc_esi:DWORD
	mov	edi,buffer
	mov	al,0e8h
	stosb
	xor	eax,eax
	stosd
	push	edi

	mov	eax,_GetModuleHandleA
	add	eax,kdelta
	stosd					;GetModuleHandleA
	mov	eax,_GetProcAddress
	add	eax,kdelta
	stosd					;GetProcAddress
	mov	eax,_ExitThread
	add	eax,kdelta
	stosd					;ExitThread
	xor	eax,eax
	stosd					;NS_InitXPCOM2
	stosd					;NS_GetComponentManager

	mov	ecx,edi
	pop	edx
	sub	ecx,edx
	mov	[edx-4],ecx
	lea	esi,__ff0
	mov	ecx,offset __ffx
	sub	ecx,esi
	rep	movsb
	mov	eax,edi
	sub	eax,buffer
	ret
GetFirefoxProc2	ENDP

GetChromeProc	PROC	kdelta:DWORD,buffer:DWORD,param1:DWORD,param2:DWORD
	mov	edi,buffer
	mov	al,0e8h
	stosb
	mov	eax,8
	stosd
	mov	eax,_ExitThread
	add	eax,kdelta
	stosd					;	dd	ExitThread
	mov	eax,param1			;constructor
	stosd
	mov	al,5fh
	stosb					;	pop	edi
	mov	al,68h
	stosb
	mov	eax,4+64
	stosd					;	push	REMOVE_COOKIES | REMOVE_LSO_DATA
	mov	ax,0c933h
	stosw
	mov	ax,6ah
	stosw					;	push	0
	mov	eax,0457ffh
	stosd
	dec	edi				;	call	dword ptr[edi+4]
	mov	ax,6ah
	stosw					;	push	0
	mov	eax,0057ffh
	stosd
	dec	edi				;	call	ExitThread
	mov	eax,edi
	sub	eax,buffer
	ret
GetChromeProc	ENDP

GetOperaProc	PROC	kdelta:DWORD,buffer:DWORD,param1:DWORD,param2:DWORD
	mov	edi,buffer
	mov	al,0e8h
	stosb
	mov	eax,100
	mov	ecx,eax
	lea	eax,[eax+12]
	stosd
	mov	eax,param1
	stosd
	mov	eax,param2
	stosd
	mov	eax,_ExitThread
	add	eax,kdelta
	stosd					;	dd	ExitThread
	xor	eax,eax
	rep	stosb
	mov	al,5fh
	stosb					;	pop	edi
	mov	ax,016ah
	stosw					;	push	1
	mov	al,68h
	stosb
	mov	eax,4005h
	stosd					;	push	4405h
	mov	ax,17ffh
	stosw					;	call	dword ptr[edi]
	mov	eax,0475c00bh			;	.if eax==0
	stosd
	mov	eax,0857ff50h			;		invoke	ExitThread,eax
	stosd					;	.endif
	mov	al,50h				;	push	eax
	stosb
	mov	eax,0457ffh
	stosd
	dec	edi				;	call	dword ptr[edi+4]
	mov	ax,016ah
	stosw					;	push	1
	mov	eax,0857ffh
	stosd					;	call	ExitThread

	mov	eax,edi
	sub	eax,buffer
	ret
GetOperaProc	ENDP

RelinkStoredProc	PROC	uses esi edi ebx pid:DWORD,procIndex:DWORD,buffer:DWORD,param1:DWORD,param2:DWORD
	local	kdelta:DWORD
	invoke	GetKernelDelta,pid
	mov	kdelta,eax
	mov	eax,procIndex
	.if eax==STORED_PROC_FIREFOX
		invoke	GetFirefoxProc,kdelta,buffer,param1,param2
	.elseif eax==STORED_PROC_CHROME
		invoke	GetChromeProc,kdelta,buffer,param1,param2
	.elseif eax==STORED_PROC_OPERA
		invoke	GetOperaProc,kdelta,buffer,param1,param2
	.elseif eax==STORED_PROC_FIREFOX2
		invoke	GetFirefoxProc2,kdelta,buffer,param1,param2
	.endif
	ret
RelinkStoredProc	ENDP
