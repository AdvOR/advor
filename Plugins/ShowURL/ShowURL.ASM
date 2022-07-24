.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

dlgFunc				PROTO	:DWORD,:DWORD,:DWORD,:DWORD
AdvTor_RegisterNewConnection	PROTO	:DWORD,:DWORD,:DWORD,:DWORD

include	plugins.inc

.data?
	AdvTor_vars

.code
desc1	db	'Shows the full URL used with HTTP proxy requests',0
notxt	db	0
start	label	byte


DllEntry PROC dllInstance:DWORD,reason:DWORD,reserved1:DWORD
	.if reason==DLL_PROCESS_ATTACH
	.elseif reason==DLL_PROCESS_DETACH
	.elseif reason==DLL_THREAD_ATTACH
	.else
	.endif
	xor	eax,eax
	inc	eax
	ret
DllEntry Endp

AdvTor_Init	offset desc1
	xor	eax,eax
	inc	eax
	ret
AdvTor_Init_end

AdvTor_UnloadPlugin	PROC	reason:DWORD
	xor	eax,eax
	inc	eax
	ret
AdvTor_UnloadPlugin	ENDP


AdvTor_RegisterNewConnection	PROC	uses edi connection_id:DWORD,connection_type:DWORD,connection_addr:DWORD,lParam:DWORD
	mov	edx,lParam
	mov	dword ptr[edx],0
	xor	eax,eax
	inc	eax
	ret
AdvTor_RegisterNewConnection	ENDP

newreq	db	'Downloading from ',0
AdvTor_HandleRead	PROC	connection_id:DWORD,connection_type:DWORD,connection_state:DWORD,conn_address:DWORD,buffer_in:DWORD,data_size:DWORD,max_size:DWORD,lParam:DWORD
	mov	edx,lParam
	.if edx!=0 && dword ptr[edx]!=1
		mov	ecx,data_size
		.if ecx>10
			mov	eax,buffer_in
			.if (dword ptr[eax]==' TEG') || (dword ptr[eax]=='TSOP') || (dword ptr[eax]==' TUP') || (dword ptr[eax]=='DAEH')
				xor	edx,edx
				.while edx<ecx
					.break .if byte ptr[eax+edx]==13 || byte ptr[eax+edx]==10
					inc	edx
				.endw
				.if edx<ecx
					mov	edx,3
					.while byte ptr[eax+edx]!=32 && byte ptr[eax+edx]!=13 && byte ptr[eax+edx]!=10
						inc	edx
					.endw
					.if byte ptr[eax+edx]==32
						.while byte ptr[eax+edx]!=13 && byte ptr[eax+edx]!=10
							.break .if word ptr[eax+edx]=='/:'
							inc	edx
						.endw
						.if word ptr[eax+edx]=='/:'
							invoke	GlobalAlloc,GPTR,512
							push	eax
							push	edi
							mov	edi,eax
							lea	edx,newreq
							.while byte ptr[edx]
								mov	al,[edx]
								stosb
								inc	edx
							.endw
							mov	edx,buffer_in
							.while byte ptr[edx]!=32
								inc	edx
							.endw
							.while byte ptr[edx]==32
								inc	edx
							.endw
							xor	ecx,ecx
							.while byte ptr[edx]>32 && ecx<400
								mov	al,[edx]
								.if al=='%'
									stosb
								.endif
								stosb
								inc	edx
								inc	ecx
							.endw
							mov	al,0
							stosb
							mov	edx,[esp+4]
							AdvTor_Log	LOG_NOTICE,edx
							pop	edi
							call	GlobalFree
						.endif
					.else
						mov	edx,lParam
						mov	dword ptr[edx],1
					.endif
				.endif
		;	.elseif dword ptr[eax]=='NNOC' && dword ptr[eax+4]==' TCE'
		;	.elseif word ptr[eax]==5 || word ptr[eax]==105h || word ptr[eax]==0f005h || word ptr[eax]==0f105h || word ptr[eax]==0e005h
		;	.elseif word ptr[eax]==104h || word ptr[eax]==0f004h || word ptr[eax]==0f104h || word ptr[eax]==0e004h
			.else
				mov	dword ptr[edx],1
			.endif
		.endif
	.endif
	xor	eax,eax
	inc	eax
	ret
AdvTor_HandleRead	ENDP

End DllEntry
