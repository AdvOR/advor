;License: Creative Commons NonCommercial

.386
.model	flat,stdcall
option	casemap:none

include	\masm32\include\windows.inc
include	\masm32\include\user32.inc
include	\masm32\include\kernel32.inc
include	\masm32\include\shell32.inc

includelib	\masm32\lib\user32.lib
includelib	\masm32\lib\kernel32.lib
includelib	\masm32\lib\shell32.lib

geoip_get_as_ptr	PROTO	:DWORD

.data?
				;2*8*10240
	tzara	dd	2024000 dup(?)
	h1	dd	?
	fsize	dd	?
	bread	dd	?
	tzaraidx dd	?
	lastidx	dd	?
	lastip	dd	?
	count	dd	?
	a1c	dd	?
	a1cr	dd	?
	tz_size	dd	?
	txt_size dd	?
	max_tzari dd	?
	max_coduri dd	?
				;16384000
	buffer1	db	176384000 dup(?)
	buffer2	db	176384000 dup(?)
	buffer3	db	176384000 dup(?)
	buffer4	db	176384000 dup(?)
	buffer5	db	176384000 dup(?)

.code
msg1	db	'IP ranges: ',0
msg2	db	13,10,'Resolved ranges from the fake "A1" country: ',0
msg3	db	' out of ',0
fname	db	'GeoIP.csv',0
fname0	db	'geoip_c.h',0
defc1	db	'??=Not Defined / Unallocated',0
defc2	db	'A1',0,'Anonymous Proxy',0
ranges	dd	-1
start:
	mov	tzaraidx,0
	mov	count,0
	mov	a1c,0
	mov	a1cr,0
	mov	lastidx,offset buffer3
	xor	eax,eax
	mov	edi,offset tzara
	mov	ecx,sizeof tzara
	cld
	rep	stosb

	mov	esi,offset tzara
	movzx	eax,word ptr defc1
	mov	dword ptr[esi],eax
	mov	eax,lastidx
	mov	[esi+4],eax
	mov	edi,eax
	lea	esi,defc1[3]
	.while (byte ptr[esi]!=0)
		movsb
	.endw
	mov	al,0
	stosb
	mov	lastidx,edi
	inc	tzaraidx
	mov	esi,offset tzara[8]
	movzx	eax,word ptr defc2
	mov	dword ptr[esi],eax
	mov	eax,lastidx
	mov	[esi+4],eax
	mov	edi,eax
	lea	esi,defc1[3]
	.while (byte ptr[esi]!=0)
		movsb
	.endw
	mov	al,0
	stosb
	mov	lastidx,edi
	inc	tzaraidx
	mov	lastip,0

	invoke	CreateFile,addr fname,GENERIC_READ,0,0,OPEN_EXISTING,0,0
	.if eax!=INVALID_HANDLE_VALUE
		push	eax
		invoke	GetFileSize,eax,0
		mov	fsize,eax
		pop	ebx
		push	ebx
		invoke	ReadFile,ebx,addr buffer1,eax,addr bread,0
		mov	ebx,offset buffer1
		add	ebx,fsize
		mov	byte ptr[ebx],0
		pop	eax
		invoke	CloseHandle,eax
		mov	esi,offset buffer1
		mov	edi,offset buffer2
		.while byte ptr[esi]!=0
			xor	ecx,ecx
			.while byte ptr[esi]>0
				.if byte ptr[esi]==','
					inc	ecx
					.break .if cl==2
				.endif
				inc	esi
			.endw
			.break .if byte ptr[esi]==0
			.while (byte ptr[esi]==32)||(byte ptr[esi]==9)||(byte ptr[esi]==34)||(byte ptr[esi]==',')
				inc	esi
			.endw
			call	atoi
			mov	edx,eax
			sub	eax,lastip
			.if eax>=2
				mov	eax,edx
				stosd
				mov	al,0
				stosb
				inc	count
			.endif
			mov	lastip,edx
			.while byte ptr[esi]>0
				.break .if byte ptr[esi]==','
				inc	esi
			.endw
			.break .if byte ptr[esi]==0
			.while (byte ptr[esi]==32)||(byte ptr[esi]==9)||(byte ptr[esi]==34)||(byte ptr[esi]==',')
				inc	esi
			.endw
			call	atoi
			mov	lastip,eax
			stosd
			.while (byte ptr[esi]==32)||(byte ptr[esi]==9)||(byte ptr[esi]==34)||(byte ptr[esi]==',')
				inc	esi
			.endw
			lodsw
			movzx	eax,ax
			push	edi
			push	esi
			mov	esi,offset tzara
			xor	ecx,ecx
			.while ecx<tzaraidx
				.break .if eax==[esi]
				inc	ecx
				lea	esi,[esi+8]
			.endw
			.if ecx==tzaraidx
				mov	dword ptr[esi],eax
				mov	eax,lastidx
				mov	[esi+4],eax
				mov	edi,eax
				pop	esi
				push	esi
				.while (byte ptr[esi]==32)||(byte ptr[esi]==9)||(byte ptr[esi]==34)||(byte ptr[esi]==',')
					inc	esi
				.endw
				.while (byte ptr[esi]!=34)&&(byte ptr[esi]!=0)
					movsb
				.endw
				mov	al,0
				stosb
				mov	lastidx,edi
				inc	tzaraidx
			.endif
			pop	esi
			pop	edi
			mov	al,cl
			stosb
			.while (byte ptr[esi]!=0ah)&&(byte ptr[esi]!=0)
				inc	esi
			.endw
			.while (byte ptr[esi]==13)||(byte ptr[esi]==10)||(byte ptr[esi]==32)||(byte ptr[esi]==9)
				inc	esi
			.endw
			inc	count
		.endw
		invoke	DeleteFile,addr fname0
		invoke	CreateFile,addr fname0,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0
		.if eax!=0
			mov	h1,eax
			mov	ecx,edi
			sub	ecx,offset buffer2
			mov	bread,ecx
			mov	eax,-1
			stosd

			mov	eax,bread
			xor	edx,edx
			mov	ecx,5
			div	ecx
			mov	max_tzari,eax

			lea	edi,buffer4
			push	edi
			mov	ecx,sizeof buffer4
			mov	al,0
			rep	stosb
			pop	edi
			lea	esi,buffer2
			mov	ecx,max_tzari
			inc	ecx
			.while ecx
				mov	eax,[esi]
				lea	ebx,buffer4
				rol	eax,8
				.while (al>[ebx])&&(dword ptr[ebx+1]!=0)
					mov	ebx,[ebx+1]
				.endw
				.if ebx==edi
					mov	[ebx],al
					lea	edi,[edi+1+4+4]
				.elseif (al!=[ebx])
					mov	[edi],al
					mov	edx,[ebx+1]
					mov	[edi+1],edx
					mov	[ebx+1],edi
					mov	ebx,edi
					mov	dword ptr[edi+5],0
					lea	edi,[edi+1+4+4]
				.endif
				.if dword ptr[ebx+5]==0
					mov	[ebx+5],edi
					mov	ebx,edi
				.else
					mov	ebx,[ebx+5]
				.endif
				rol	eax,8
				.while (al>[ebx])&&(dword ptr[ebx+1]!=0)
					mov	ebx,[ebx+1]
				.endw
				.if ebx==edi
					mov	[ebx],al
					lea	edi,[edi+1+4+4]
				.elseif (al!=[ebx])
					mov	[edi],al
					mov	edx,[ebx+1]
					mov	[edi+1],edx
					mov	[ebx+1],edi
					mov	ebx,edi
					mov	dword ptr[edi+5],0
					lea	edi,[edi+1+4+4]
				.endif
				.if dword ptr[ebx+5]==0
					mov	[ebx+5],edi
					mov	ebx,edi
				.else
					mov	ebx,[ebx+5]
				.endif
				rol	eax,8
				.while (al>[ebx])&&(dword ptr[ebx+1]!=0)
					mov	ebx,[ebx+1]
				.endw
				.if ebx==edi
					mov	[ebx],al
					lea	edi,[edi+1+4+4]
				.elseif (al!=[ebx])
					mov	[edi],al
					mov	edx,[ebx+1]
					mov	[edi+1],edx
					mov	[ebx+1],edi
					mov	ebx,edi
					mov	dword ptr[edi+5],0
					lea	edi,[edi+1+4+4]
				.endif
				.if dword ptr[ebx+5]==0
					mov	[ebx+5],edi
					mov	ebx,edi
				.else
					mov	ebx,[ebx+5]
				.endif
				rol	eax,8
				.while (al>[ebx])&&(dword ptr[ebx+1]!=0)
					mov	ebx,[ebx+1]
				.endw
				.if ebx==edi
					mov	[ebx],al
					lea	edi,[edi+1+4+4]
				.elseif (al!=[ebx])
					mov	[edi],al
					mov	edx,[ebx+1]
					mov	[edi+1],edx
					mov	[ebx+1],edi
					mov	ebx,edi
					lea	edi,[edi+1+4+1]
				.endif
				mov	al,[esi+4]
				mov	[ebx+5],al
				.if al==1
					inc	a1c
					mov	eax,[esi-5]
					invoke	geoip_get_as_ptr,eax
					push	eax
					mov	eax,[esi-5]
					inc	eax
					invoke	geoip_get_as_ptr,eax
					pop	edx
					.if eax==edx
						mov	dl,[esi-1]
						inc	a1cr
					.else
						mov	eax,[esi]
						invoke	geoip_get_as_ptr,eax
						push	eax
						mov	eax,[esi]
						inc	eax
						invoke	geoip_get_as_ptr,eax
						pop	edx
						.if edx==eax
							mov	dl,[esi+5+4]
							inc	a1cr
						.else
							lea	edx,ranges
							.while dword ptr[edx]!=-1
								mov	eax,[esi-5]
								inc	eax
								.if eax<=[edx+4]
									mov	eax,[esi]
									.break .if eax>=[edx]
								.endif
								lea	edx,[edx+10]
							.endw
							.if dword ptr[edx]!=-1
								movzx	eax,word ptr[edx+8]
								mov	edx,offset tzara
								push	ecx
								xor	ecx,ecx
								.while ecx<tzaraidx
									.break .if eax==[edx]
									inc	ecx
									lea	edx,[edx+8]
								.endw
								.if ecx>=tzaraidx
									int 3
								.endif
								mov	dl,cl
								pop	ecx
								inc	a1cr
							.else
								mov	al,[esi-1]
								.if al==[esi+5+4]
									mov	dl,al
									inc	a1cr
								.else
									mov	dl,0
								.endif
							.endif
						.endif
					.endif
					mov	[ebx+6],dl
				.endif
				lea	esi,[esi+5]
				dec	ecx
			.endw
			lea	edx,buffer4
			call	adjtree
			mov	ecx,edi
			sub	ecx,offset buffer4
			mov	tz_size,ecx
			mov	max_coduri,0

			mov	edi,offset buffer2
			mov	eax,'an_c'
			stosd
			mov	eax,'sem'
			stosd
			dec	edi
			mov	esi,offset tzara
			mov	ecx,tzaraidx
			.while ecx!=0
				mov	al,9
				stosb
				mov	ax,'bd'
				stosw
				mov	al,9
				stosb
				mov	al,39
				stosb
				lodsd
				stosw
				mov	al,39
				stosb
				mov	eax,',0,'
				stosd
				mov	byte ptr[edi-1],39
				lodsd
				push	esi
				mov	esi,eax
				.while byte ptr[esi]!=0
					lodsb
					.if al==39
						stosb
						mov	eax,',93,'
						stosd
						mov	al,39
						stosb
					.else
						stosb
					.endif
				.endw
				mov	al,39
				stosb
				mov	ax,'0,'
				stosw
				inc	max_coduri
				pop	esi
				mov	ax,0a0dh
				stosw
				dec	ecx
			.endw
			mov	al,9
			stosb
			mov	ax,'bd'
			stosw
			mov	al,9
			stosb
			mov	al,'0'
			stosb
			mov	ax,0a0dh
			stosw
			stosw
			mov	eax,'_mun'
			stosd
			mov	eax,' = c'
			stosd
			mov	eax,max_coduri
			call	itoa
			mov	ax,0a0dh
			stosw
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer2
			mov	txt_size,ecx
			invoke	WriteFile,h1,addr buffer2,txt_size,addr bread,0
			lea	edi,buffer2
			mov	eax,'ad_c'
			stosd
			mov	ax,'at'
			stosw
			lea	esi,buffer4
			mov	ecx,tz_size
			add	tz_size,8
			mov	dword ptr buffer4[ecx],0
			mov	dword ptr buffer4[ecx+4],0
			xor	ecx,ecx
			.while ecx<tz_size
				.if !(ecx&0fh)
					mov	al,9
					stosb
					mov	ax,'bd'
					stosw
					mov	al,9
					stosb
				.endif
				mov	al,'0'
				stosb
				lodsb
				mov	ah,al
				and	ax,0ff0h
				shr	al,4
				or	ax,3030h
				.if al>'9'
					add	al,7
				.endif
				.if ah>'9'
					add	ah,7
				.endif
				stosw
				mov	al,'h'
				stosb
				inc	ecx
				.if !(ecx&0fh)
					mov	ax,0a0dh
					stosw
				.else
					mov	al,','
					stosb
				.endif
			.endw
			.if byte ptr[edi-1]==','
				dec	edi
			.endif
			mov	ax,0a0dh
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer2

			invoke	WriteFile,h1,addr buffer2,ecx,addr bread,0
			invoke	CloseHandle,h1
		.endif

		mov	edi,offset buffer1
		lea	edx,msg1
		call	copyedx
		mov	eax,count
		call	itoa
		lea	edx,msg2
		call	copyedx
		mov	eax,a1cr
		call	itoa
		lea	edx,msg3
		call	copyedx
		mov	eax,a1c
		call	itoa
		mov	al,0
		stosb
		invoke	MessageBox,0,addr buffer1,addr fname,0
	.endif
	invoke	ExitProcess,0

atoi:	.while byte ptr[esi]==32
		inc	esi
	.endw
	xor	eax,eax
	.while (byte ptr[esi]>='0')&&(byte ptr[esi]<='9')
		mov	ebx,10
		xor	edx,edx
		mul	ebx
		mov	bl,[esi]
		inc	esi
		and	ebx,0fh
		add	eax,ebx
	.endw
	ret

itoa:	mov	ebx,10
	xor	edx,edx
	div	ebx
	or	eax,eax
	jz	_d1
	push	edx
	call	itoa
	pop	edx
_d1:	or	dl,30h
	mov	al,dl
	stosb
	ret

copyedx:.while byte ptr[edx]
		mov	al,[edx]
		stosb
		inc	edx
	.endw
	ret

adjtree:
	xor	ecx,ecx
adjtree1:
	.while	dword ptr[edx+1]!=0
		mov	eax,[edx+1]
		push	eax
		sub	eax,edx
		mov	[edx+1],eax
		mov	eax,[edx+1+4]
		.if (ecx<3)
			.if (eax==0)
				int 3
			.endif
			inc	ecx
			push	eax
			sub	eax,edx
			mov	[edx+1+4],eax
			pop	edx
			call	adjtree1
			dec	ecx
		.endif
		pop	edx
	.endw
	mov	eax,[edx+1+4]
	.if (ecx<3)
		.if (eax==0)
			int 3
		.endif
		inc	ecx
		push	eax
		sub	eax,edx
		mov	[edx+1+4],eax
		pop	edx
		call	adjtree1
		dec	ecx
	.endif
	ret

geoip_get_as_ptr	PROC	uses ebx ecx edx ip_1:DWORD
	mov	ecx,as_cnt
	mov	edx,ecx
	xor	ebx,ebx
	shr	edx,1
	mov	eax,ip_1
	.if eax<dword ptr as_ip_1[0] || eax>dword ptr as_ip_2[ecx*4-4]
		xor	eax,eax
		ret
	.endif
	.while 1
		.if eax<dword ptr as_ip_1[edx*4]
			mov	ecx,edx
			add	edx,ebx
			shr	edx,1
			.break .if ecx==edx
		.elseif eax>dword ptr as_ip_1[edx*4]
			mov	ebx,edx
			add	edx,ecx
			shr	edx,1
			.break .if ebx==edx
		.else
			.break
		.endif
	.endw
	.while eax>=as_ip_1[edx*4] && eax<=as_ip_2[edx*4]
		dec	edx
	.endw
	inc	edx
	.while eax>=as_ip_1[edx*4] && eax>as_ip_2[edx*4]
		inc	edx
	.endw
	mov	eax,edx
	ret
	include	..\AdvOR\or\geoip_as.h
geoip_get_as_ptr	ENDP

end	start