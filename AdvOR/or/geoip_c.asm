.586
.model flat,stdcall
option casemap:none

GlobalAlloc	PROTO	:DWORD,:DWORD
GlobalFree	PROTO	:DWORD
GPTR = 40h

.code

geoip_get_country_name	PROC	STDCALL	idx:DWORD
	lea	eax,c_names
	.if idx>=num_c
		ret
	.endif
	mov	ecx,idx
	.while ecx!=0
		.while (byte ptr[eax]!=0)
			inc	eax
		.endw
		inc	eax
		.while (byte ptr[eax]!=0)
			inc	eax
		.endw
		inc	eax
		.break .if byte ptr[eax]==0
		dec	ecx
	.endw
	ret
	include	geoip_c.h
	include	geoip_as.h
	include	geoip_lng.h
geoip_get_country_name	ENDP

GeoIP_getfullname	PROC	STDCALL	idx:DWORD
	mov	ecx,idx
	.if ecx<num_c
		lea	eax,c_names
		.while ecx!=0
			.while (byte ptr[eax]!=0)
				inc	eax
			.endw
			inc	eax
			.while (byte ptr[eax]!=0)
				inc	eax
			.endw
			inc	eax
			.break .if byte ptr[eax]==0
			dec	ecx
		.endw
	.endif
	.if byte ptr[eax]
		.while (byte ptr[eax]!=0)
			inc	eax
		.endw
		inc	eax
	.endif
	ret
GeoIP_getfullname	ENDP

geoip_get_country_by_ip	PROC	STDCALL	uses ebx ip:DWORD
	mov	eax,ip
	lea	ebx,c_data
	.while 1
		.break .if al<=[ebx]
		.break .if dword ptr[ebx+1]==0
		add	ebx,[ebx+1]
	.endw
	.if al<[ebx]
		add	ebx,[ebx+1+4]
		add	ebx,[ebx+1+4]
		add	ebx,[ebx+1+4]
		movzx	ax,byte ptr[ebx+1+4]
		.if al==1
			mov	ah,1
			mov	al,[ebx+1+4+1]
		.endif
	.elseif al==[ebx]
		ror	eax,8
		push	ebx
		add	ebx,[ebx+1+4]
		.while 1
			.break .if al<=[ebx]
			.break .if dword ptr[ebx+1]==0
			add	ebx,[ebx+1]
		.endw
		.if al<[ebx]
			add	ebx,[ebx+1+4]
			add	ebx,[ebx+1+4]
			movzx	ax,byte ptr[ebx+1+4]
			.if al==1
				mov	ah,1
				mov	al,[ebx+1+4+1]
			.endif
			pop	ebx
		.elseif al==[ebx]
			ror	eax,8
			push	ebx
			add	ebx,[ebx+1+4]
			.while 1
				.break .if al<=[ebx]
				.break .if dword ptr[ebx+1]==0
				add	ebx,[ebx+1]
			.endw
			.if al<[ebx]
				add	ebx,[ebx+1+4]
				movzx	ax,byte ptr[ebx+1+4]
				.if al==1
					mov	ah,1
					mov	al,[ebx+1+4+1]
				.endif
				pop	ebx
				pop	ebx
			.elseif al==[ebx]
				ror	eax,8
				push	ebx
				add	ebx,[ebx+1+4]
				.while 1
					.break .if al<[ebx]
					.break .if dword ptr[ebx+1]==0
					add	ebx,[ebx+1]
				.endw
				.if al<[ebx]
					movzx	ax,byte ptr[ebx+5]
					.if al==1
						mov	ah,1
						mov	al,[ebx+1+4+1]
					.endif
					pop	ebx
					pop	ebx
					pop	ebx
				.else
					pop	ebx
					.if dword ptr[ebx+1]
						add	ebx,[ebx+1]
						add	ebx,[ebx+1+4]
						movzx	ax,byte ptr[ebx+1+4]
						.if al==1
							mov	ah,1
							mov	al,[ebx+1+4+1]
						.endif
						pop	ebx
						pop	ebx
					.else
						pop	ebx
						.if dword ptr[ebx+1]
							add	ebx,[ebx+1]
							add	ebx,[ebx+1+4]
							add	ebx,[ebx+1+4]
							movzx	ax,byte ptr[ebx+1+4]
							.if al==1
								mov	ah,1
								mov	al,[ebx+1+4+1]
							.endif
							pop	ebx
						.else
							pop	ebx
							.if dword ptr[ebx+1]
								add	ebx,[ebx+1]
								add	ebx,[ebx+1+4]
								add	ebx,[ebx+1+4]
								add	ebx,[ebx+1+4]
								movzx	ax,byte ptr[ebx+1+4]
								.if al==1
									mov	ah,1
									mov	al,[ebx+1+4+1]
								.endif
							.endif
						.endif
					.endif
				.endif
			.else
				pop	ebx
				.if dword ptr[ebx+1]
					add	ebx,[ebx+1]
					add	ebx,[ebx+1+4]
					add	ebx,[ebx+1+4]
					movzx	ax,byte ptr[ebx+1+4]
					.if al==1
						mov	ah,1
						mov	al,[ebx+1+4+1]
					.endif
					pop	ebx
				.else
					pop	ebx
					.if dword ptr[ebx+1]
						add	ebx,[ebx+1]
						add	ebx,[ebx+1+4]
						add	ebx,[ebx+1+4]
						add	ebx,[ebx+1+4]
						movzx	ax,byte ptr[ebx+1+4]
						.if al==1
							mov	ah,1
							mov	al,[ebx+1+4+1]
						.endif
					.endif
				.endif
			.endif
		.else
			pop	ebx
			.if dword ptr[ebx+1]
				add	ebx,[ebx+1]
				add	ebx,[ebx+1+4]
				add	ebx,[ebx+1+4]
				add	ebx,[ebx+1+4]
				movzx	ax,byte ptr[ebx+1+4]
				.if al==1
					mov	ah,1
					mov	al,[ebx+1+4+1]
				.endif
			.endif
		.endif
	.endif
	movzx	eax,ax
	ret
geoip_get_country_by_ip	ENDP

geoip_get_n_countries	PROC
	mov	eax,num_c
	ret
geoip_get_n_countries	ENDP

geoip_get_country	PROC	uses ebx lpCountry:DWORD
	xor	ecx,ecx
	lea	ebx,c_names
	mov	edx,lpCountry
	mov	dx,[edx]
	or	dx,2020h
	.while ecx<num_c
		mov	ax,[ebx]
		or	ax,2020h
		.break .if dx==ax
		.while (byte ptr[ebx]!=0)
			inc	ebx
		.endw
		inc	ebx
		.while (byte ptr[ebx]!=0)
			inc	ebx
		.endw
		inc	ebx
		.break .if byte ptr[ebx]==0
		inc	ecx
	.endw
	.if ecx==num_c
		xor	ecx,ecx
		dec	ecx
	.endif
	mov	eax,ecx
	ret
geoip_get_country	ENDP

geoip_reverse	PROC	raddr:DWORD
	mov	eax,raddr
	xchg	al,ah
	rol	eax,16
	xchg	al,ah
	ret
geoip_reverse	ENDP


atoi	PROC
	xor	eax,eax
	xor	ebx,ebx
	push	edx
getdec0:mov	bl,[esi]
	sub	bl,'0'
	cmp	bl,10
	jnc	_getdec
	inc	esi
	push	ebx
	xor	edx,edx
	mov	bl,10
	mul	ebx
	pop	ebx
	add	eax,ebx
	jmp	getdec0
_getdec:pop	edx
	ret
atoi	ENDP

itoa:	mov	ecx,10
	xor	edx,edx
	div	ecx
	or	eax,eax
	jz	_d1
	push	edx
	call	itoa
	pop	edx
_d1:	or	dl,30h
	mov	al,dl
	stosb
	ret


is_ip	PROC	uses esi ebx str1:DWORD
	mov	esi,str1
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi]!='.')
		xor	eax,eax
		ret
	.endif
	inc	esi
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi]!='.')
		xor	eax,eax
		ret
	.endif
	inc	esi
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi]!='.')
		xor	eax,eax
		ret
	.endif
	inc	esi
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	.if eax>255
		xor	eax,eax
		ret
	.endif
	xor	eax,eax
	inc	eax
	ret
is_ip	ENDP

FormatMemInt	PROC	uses edi lpstr:DWORD,value:DWORD
	mov	edi,lpstr
	.if value & 0c0000000h
		mov	eax,value
		rol	eax,2
		and	eax,3
		call	itoa
		mov	al,'.'
		stosb
		mov	eax,value
		shr	eax,20
		and	eax,3ffh
		lea	eax,[eax*4+eax]
		lea	eax,[eax*4+eax]
		shr	eax,8
		.if al<10
			mov	byte ptr[edi],'0'
			inc	edi
		.endif
		call	itoa
		mov	eax,'BG '
		stosd
	.elseif value&03ff00000h
		mov	eax,value
		rol	eax,2+10
		and	eax,3ffh
		call	itoa
		mov	al,'.'
		stosb
		mov	eax,value
		shr	eax,10
		and	eax,3ffh
		lea	eax,[eax*4+eax]
		lea	eax,[eax*4+eax]
		shr	eax,8
		.if al<10
			mov	byte ptr[edi],'0'
			inc	edi
		.endif
		call	itoa
		mov	eax,'BM '
		stosd
	.elseif value&0000ffc00h
		mov	eax,value
		shr	eax,10
		and	eax,3ffh
		call	itoa
		mov	al,'.'
		stosb
		mov	eax,value
		and	eax,3ffh
		lea	eax,[eax*4+eax]
		lea	eax,[eax*4+eax]
		shr	eax,8
		.if al<10
			mov	byte ptr[edi],'0'
			inc	edi
		.endif
		call	itoa
		mov	eax,'BK '
		stosd
	.else
		mov	eax,value
		and	eax,3ffh
		call	itoa
		mov	eax,'B '
		stosd
	.endif
	ret
FormatMemInt	ENDP

FormatMemInt64	PROC	uses edi lpstr:DWORD,lpValue:DWORD
	mov	eax,lpValue
	.if dword ptr[eax+4]
		mov	edi,lpstr
		mov	eax,[eax+4]
		.if eax&0ffffff00h
			shr	eax,8
			call	itoa
			mov	al,'.'
			stosb
			mov	eax,lpValue
			mov	edx,[eax]
			mov	eax,[eax+4]
			shl	edx,1
			rcl	eax,1
			shl	edx,1
			rcl	eax,1
			and	eax,3ffh
			lea	eax,[eax*4+eax]
			lea	eax,[eax*4+eax]
			shr	eax,8
			.if al<10
				mov	byte ptr[edi],'0'
				inc	edi
			.endif
			call	itoa
			mov	eax,'BT '
			stosd
		.else
			mov	eax,lpValue
			mov	edx,[eax]
			mov	eax,[eax+4]
			shl	edx,1
			rcl	eax,1
			shl	edx,1
			rcl	eax,1
			and	eax,3ffh
			call	itoa
			mov	al,'.'
			stosb
			mov	eax,lpValue
			mov	eax,[eax]
			shr	eax,20
			and	eax,3ffh
			lea	eax,[eax*4+eax]
			lea	eax,[eax*4+eax]
			shr	eax,8
			.if al<10
				mov	byte ptr[edi],'0'
				inc	edi
			.endif
			call	itoa
			mov	eax,'BG '
			stosd
		.endif
	.else
		mov	eax,[eax]
		invoke	FormatMemInt,lpstr,eax
	.endif
	ret
FormatMemInt64	ENDP

SortIPList	PROC	uses edi esi ebx listPtr:DWORD,hMem:DWORD
	local	tmp_ip:DWORD
	mov	edi,listPtr
	mov	esi,edi
	mov	edi,hMem
	lea	edi,[edi+32768]
	.while byte ptr[esi]
		.while (byte ptr[esi]<33)&&(byte ptr[esi]!=0)
			inc	esi
		.endw
		.if byte ptr[esi]==';'
			.while (byte ptr[esi]!=0)&&(byte ptr[esi]!=13)&&(byte ptr[esi]!=10)
				inc	esi
			.endw
		.else
			.if (byte ptr[esi]>='0')&&(byte ptr[esi]<='9')
				call	atoi
				.if (eax<256)&&(byte ptr[esi]=='.')&&(byte ptr[esi+1]>='0')&&(byte ptr[esi+1]<='9')
					mov	byte ptr tmp_ip,al
					inc	esi
					call	atoi
					.if (eax<256)&&(byte ptr[esi]=='.')&&(byte ptr[esi+1]>='0')&&(byte ptr[esi+1]<='9')
						mov	byte ptr tmp_ip[1],al
						inc	esi
						call	atoi
						.if (eax<256)&&(byte ptr[esi]=='.')&&(byte ptr[esi+1]>='0')&&(byte ptr[esi+1]<='9')
							mov	byte ptr tmp_ip[2],al
							inc	esi
							call	atoi
							.if eax<256
								mov	byte ptr tmp_ip[3],al
								.if byte ptr[esi]==':'
									inc	esi
									call	atoi
								.else
									mov	eax,443
								.endif
								stosw
								mov	eax,tmp_ip
								xchg	al,ah
								rol	eax,16
								xchg	al,ah
								stosd
								mov	eax,tmp_ip
								invoke	geoip_get_country_by_ip,eax
								movzx	eax,al
								invoke	geoip_get_country_name,eax
								mov	ax,[eax]
								.if al==0
									mov	ax,'??'
								.endif
								xchg	al,ah
								stosw
								mov	eax,esi
								stosd
							.endif
						.endif
					.endif
				.endif
			.endif
			.while (byte ptr[esi]!=0)&&(byte ptr[esi]!=13)&&(byte ptr[esi]!=10)
				inc	esi
			.endw
		.endif
	.endw
	mov	esi,hMem
	lea	esi,[esi+32768]
	.while esi<edi
		lea	edx,[esi+12]
		mov	eax,[esi]
		mov	ecx,[esi+4]
		.while edx<edi
			.if (ecx>[edx+4])||((ecx==[edx+4])&&(eax>[edx]))
				xchg	eax,[edx]
				mov	[esi],eax
				xchg	ecx,[edx+4]
				mov	[esi+4],ecx
				push	dword ptr[edx+8]
				push	dword ptr[esi+8]
				pop	dword ptr[edx+8]
				pop	dword ptr[esi+8]
			.endif
			lea	edx,[edx+12]
		.endw
		lea	esi,[esi+12]
	.endw
	xor	eax,eax
	stosd
	mov	esi,hMem
	lea	esi,[esi+32768]
	mov	cx,-1
	mov	edi,hMem
	.while dword ptr[esi]
		mov	eax,[esi]
		.if eax==[esi+12]
			mov	eax,[esi+4]
			.if eax==[esi+12+4]
				lea	esi,[esi+12]
				.continue
			.endif
		.endif
		mov	ax,[esi+6]
		xchg	al,ah
		.if cx!=ax
			mov	cx,ax
			mov	ax,' ;'
			stosw
			mov	ax,cx
			stosw
			mov	ax,0a0dh
			stosw
		.endif
		lodsw
		push	ecx
		mov	eax,[esi]
		xchg	al,ah
		rol	eax,16
		xchg	al,ah
		mov	[esi],eax
		lodsb
		movzx	eax,al
		call	itoa
		mov	al,'.'
		stosb
		lodsb
		movzx	eax,al
		call	itoa
		mov	al,'.'
		stosb
		lodsb
		movzx	eax,al
		call	itoa
		mov	al,'.'
		stosb
		lodsb
		movzx	eax,al
		call	itoa
		mov	al,':'
		stosb
		lodsw
		mov	ax,[esi-8]
		call	itoa
		pop	ecx
		lodsd
		mov	edx,eax
		.while (byte ptr[edx]!=0)&&(byte ptr[edx]!=13)&&(byte ptr[edx]!=10)
			mov	al,[edx]
			stosb
			inc	edx
		.endw
		mov	ax,0a0dh
		stosw
	.endw
	mov	al,0
	stosb
	mov	eax,hMem
	ret
SortIPList	ENDP

RemoveComments	PROC	uses esi edi listPtr:DWORD
	mov	esi,listPtr
	mov	edi,listPtr
	.while (byte ptr[esi]!=0)&&(byte ptr[esi]<33)
		inc	esi
	.endw
	.while byte ptr[esi]
		.if byte ptr[esi]==';'
			.while (byte ptr[esi]!=0)&&(byte ptr[esi]!=13)&&(byte ptr[esi]!=10)
				inc	esi
			.endw
			.while (edi!=listPtr)&&((byte ptr[edi]==32)||(byte ptr[edi]==9))
				dec	edi
			.endw
		.else
			movsb
		.endif
	.endw
	mov	al,0
	stosb
	ret
RemoveComments	ENDP

geoip_get_as_ptr	PROC STDCALL	uses ebx ip_1:DWORD
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
geoip_get_as_ptr	ENDP

geoip_ptr_get_as_path	PROC STDCALL	uses edi esi ebx buffer:DWORD,idx:DWORD,ip_1:DWORD	;3*10*4
	local	my_as:DWORD,writeptr:DWORD
	.if idx>=as_cnt
		xor	eax,eax
		mov	edx,buffer
		mov	[edx],eax
		ret
	.endif
	mov	edi,buffer
	mov	eax,ip_1
	mov	edx,idx
	xor	ecx,ecx
	mov	writeptr,edi
	.while ecx<3
		.break .if eax<as_ip_1[edx*4]
		.if eax<=as_ip_2[edx*4]
			push	eax
			lea	esi,as_path
			lea	ebx,as_path
			add	ebx,as_idx[edx*4]
			.while esi<ebx
				.if word ptr[esi]==65535
					mov	eax,[esi+2+4]
					add	eax,esi
					.if eax<=ebx && eax!=esi
						mov	esi,eax
					.else
						mov	eax,[esi+2]
						stosd
						lea	esi,[esi+2+4+4]
					.endif
				.else
					mov	eax,[esi+2]
					add	eax,esi
					.if eax<=ebx && eax!=esi
						mov	esi,eax
					.else
						movzx	eax,word ptr[esi]
						stosd
						lea	esi,[esi+2+4]
					.endif
				.endif
			.endw
			.if esi!=ebx
				int 3
			.endif
			movzx	eax,word ptr[esi]
			.if eax==65535
				mov	eax,[esi+2]
			.endif
			stosd
			mov	my_as,eax
			xor	eax,eax
			dec	eax
			stosd
			pop	eax
			inc	ecx
		.endif
		inc	edx
	.endw
	.if edi==writeptr
		mov	eax,65536
		stosd
		xor	eax,eax
		dec	eax
		stosd
	.endif
	xor	eax,eax
	stosd
	mov	eax,my_as
	ret
geoip_ptr_get_as_path	ENDP

geoip_get_as_by_ip	PROC	uses edi esi ebx ip_1:DWORD
	local	my_as:DWORD
	mov	eax,ip_1
	invoke	geoip_get_as_ptr,eax
	mov	edx,eax
	.if edx>=as_cnt
		mov	eax,65536
		ret
	.endif
	mov	eax,ip_1
	.if eax>=as_ip_1[edx*4] && eax<=as_ip_2[edx*4]
		push	eax
		lea	esi,as_path
		lea	ebx,as_path
		add	ebx,as_idx[edx*4]
		.while esi<ebx
			.if word ptr[esi]==65535
				mov	eax,[esi+2+4]
				add	eax,esi
				.if eax<ebx && eax!=esi
					mov	esi,eax
				.else
					lea	esi,[esi+2+4+4]
				.endif
			.else
				mov	eax,[esi+2]
				add	eax,esi
				.if eax<ebx && eax!=esi
					mov	esi,eax
				.else
					lea	esi,[esi+2+4]
				.endif
			.endif
		.endw
		movzx	eax,word ptr[esi]
		.if eax==65535
			mov	eax,[esi+2]
		.endif
		mov	my_as,eax
		pop	eax
	.else
		mov	eax,65536
	.endif
	mov	eax,my_as
	ret
geoip_get_as_by_ip	ENDP

geoip_get_full_as_path	PROC STDCALL	uses edi esi ebx iplist:DWORD,buffer:DWORD,bufsize:DWORD
	local	my_as:DWORD,hMem:DWORD,ipcount:DWORD,paths:DWORD,writeptr:DWORD
	mov	ipcount,0
	invoke	GlobalAlloc,GPTR,3*12*4*10*2
	mov	hMem,eax
	mov	edi,eax
	mov	esi,iplist
	.while dword ptr[esi]
		mov	eax,[esi]
		.if eax!=7f000001h && eax!=-1
			invoke	geoip_get_as_ptr,eax
			invoke	geoip_ptr_get_as_path,edi,eax,dword ptr[esi]
			.while dword ptr[edi]
				lea	edi,[edi+4]
			.endw
			lea	edi,[edi+4]
			inc	ipcount
		.endif
		lodsd
	.endw
	.if ipcount<=1
		mov	ecx,bufsize
		mov	esi,hMem
		mov	edi,buffer
		mov	writeptr,edi
		.while ecx>3
			lodsd
			.if eax==-1 && edi!=writeptr
				or	dword ptr[edi-4],80000000h
			.endif
			stosd
			sub	ecx,4
			.break .if eax==0
		.endw
		invoke	GlobalFree,hMem
		mov	eax,65536
		ret
	.endif
	xor	eax,eax
	stosd

	mov	edi,buffer
	mov	paths,0
	and	bufsize,0fffffffch
	.if bufsize==0
		invoke	GlobalFree,hMem
		mov	eax,65536
		ret
	.endif
	.while bufsize
		mov	ecx,ipcount
		dec	ecx
		mov	esi,hMem
		.while ecx
			mov	writeptr,edi
			mov	ebx,esi
			.while dword ptr[ebx]!=0
				lea	ebx,[ebx+4]
			.endw
			lea	ebx,[ebx+4]
			.if paths&1
				xor	edx,edx
				.while dword ptr[esi+edx*4]!=0 && dword ptr[esi+edx*4]!=-1
					inc	edx
				.endw
				.if dword ptr[esi+edx*4]==-1 && dword ptr[esi+edx*4+4]!=0 && dword ptr[esi+edx*4+4]!=-1
					inc	edx
					lea	esi,[esi+edx*4]
				.endif
			.endif
			.if paths&2
				xor	edx,edx
				.while dword ptr[ebx+edx*4]!=0 && dword ptr[ebx+edx*4]!=-1
					inc	edx
				.endw
				.if dword ptr[ebx+edx*4]==-1 && dword ptr[ebx+edx*4+4]!=0 && dword ptr[ebx+edx*4+4]!=-1
					inc	edx
					lea	ebx,[ebx+edx*4]
				.endif
			.endif
			xor	edx,edx
			.while dword ptr[esi+edx*4]!=0 && dword ptr[esi+edx*4]!=-1
				inc	edx
			.endw
			.if edx
				dec	edx
			.endif
			.if dword ptr[esi+edx*4]!=0 && dword ptr[esi+edx*4]!=-1
				mov	eax,[esi+edx*4]
				stosd
				or	dword ptr[edi-4],80000000h
				sub	bufsize,4
				.while bufsize
					push	edx
					xor	edx,edx
					.while dword ptr[ebx+edx*4]!=0 && dword ptr[ebx+edx*4]!=-1 && dword ptr[ebx+edx*4]!=eax
						inc	edx
					.endw
					.if eax==[ebx+edx*4] && edx!=0
						inc	edx
						.while dword ptr[ebx+edx*4]!=0 && dword ptr[ebx+edx*4]!=-1
							mov	eax,[ebx+edx*4]
							stosd
							sub	bufsize,4
							.break .if bufsize==0
							inc	edx
						.endw
						.if edi!=writeptr && bufsize!=0
							or	dword ptr[edi-4],80000000h
						.endif
						xor	ebx,ebx
					.endif
					pop	edx
					.break .if ebx==0
					.break .if edx==0
					dec	edx
					mov	eax,[esi+edx*4]
					stosd
					sub	bufsize,4
				.endw
			.endif
			.if ebx && bufsize
				xor	edx,edx
				.while dword ptr[ebx+edx*4]!=0 && dword ptr[ebx+edx*4]!=-1
					mov	eax,[ebx+edx*4]
					stosd
					sub	bufsize,4
					.break .if bufsize==0
					inc	edx
				.endw
				.if edi!=writeptr && bufsize!=0
					or	dword ptr[edi-4],80000000h
				.endif
			.endif
			.break .if bufsize==0
			sub	bufsize,4
			.break .if bufsize==0
			dec	ecx
			.while dword ptr[esi]
				lodsd
			.endw
			lodsd
			.if ecx && edi != writeptr
				sub	edi,4
				add	bufsize,4
			.endif
		.endw
		xor	eax,eax
		dec	eax
		stosd
		inc	paths
		.break .if paths&4
	.endw
	.if bufsize
		xor	eax,eax
		stosd
	.else
		mov	dword ptr[edi-4],0
	.endif
	mov	esi,buffer
	mov	edi,esi
	.while dword ptr[esi]
		mov	ebx,esi
		.while dword ptr[ebx]
			.while dword ptr[ebx]!=-1 && dword ptr[ebx]!=0
				lea	ebx,[ebx+4]
			.endw
			.if dword ptr[ebx]==-1
				lea	ebx,[ebx+4]
			.else
				.break
			.endif
			xor	edx,edx
			.while dword ptr[esi+edx*4]!=0 && dword ptr[esi+edx*4]!=-1
				mov	eax,[esi+edx*4]
				.break .if eax!=[ebx+edx*4]
				inc	edx
			.endw
			.if (dword ptr[esi+edx*4]==0 || dword ptr[esi+edx*4]==-1) && (dword ptr[ebx+edx*4]==0 || dword ptr[ebx+edx*4]==-1)
				.while dword ptr[esi]!=-1 && dword ptr[esi]!=0
					lodsd
				.endw
				.if dword ptr[esi]==-1
					lodsd
					mov	ebx,esi
					.continue
				.else
					.break
				.endif
			.endif
		.endw
		.if dword ptr[esi]
			.while dword ptr[esi]!=-1 && dword ptr[esi]!=0
				movsd
			.endw
			.if dword ptr[esi]==-1
				movsd
			.endif
		.endif
	.endw
	xor	eax,eax
	stosd

	invoke	GlobalFree,hMem
	mov	eax,my_as
	ret
geoip_get_full_as_path	ENDP

geoip_is_as_path_safe	PROC STDCALL	uses esi lpPath:DWORD
	mov	esi,lpPath
	.while dword ptr[esi]
		.while dword ptr[esi]!=-1 && dword ptr[esi]!=0
			lodsd
			.if eax&40000000h
			.else
				xor	edx,edx
				.while dword ptr[esi+edx*4]!=0 && dword ptr[esi+edx*4]!=-1
					.if eax==[esi+edx*4] && edx!=0
						push	edx
						push	eax
						dec	edx
						xor	ecx,ecx
						.while ecx<edx
							mov	eax,[esi+ecx*4]
							.if eax!=[esi+edx*4]
								pop	eax
								pop	edx
								mov	lpPath,0
								or	dword ptr[esi+edx*4],40000000h
								or	dword ptr[esi-4],40000000h
								push	edx
								push	eax
							.endif
							inc	ecx
							dec	edx
						.endw
						pop	eax
						pop	edx
					.endif
					inc	edx
				.endw
			.endif
		.endw
		.if dword ptr[esi]==-1
			lodsd
		.endif
	.endw
	mov	eax,lpPath
	ret
geoip_is_as_path_safe	ENDP

geoip_as_path_to_str	PROC STDCALL	uses esi edi ebx lpPath:DWORD,buffer:DWORD,bufsize:DWORD
	invoke	geoip_is_as_path_safe,lpPath
	mov	esi,lpPath
	mov	edi,buffer
	xor	ecx,ecx
	inc	ecx
	mov	al,'#'
	stosb
	mov	eax,ecx
	push	ecx
	call	itoa
	pop	ecx
	mov	ax,' :'
	stosw
	.while bufsize>20
		.if dword ptr[esi]&80000000h
			mov	al,'['
			stosb
		.endif
		.if dword ptr[esi]&40000000h
			mov	eax,')X('
			stosd
			dec	edi
		.endif
		mov	ax,'SA'
		stosw
		mov	eax,[esi]
		and	eax,3fffffffh
		.if eax==65536
			mov	ax,'U_'
			stosw
			mov	eax,'ONKN'
			stosd
			mov	ax,'NW'
			stosw
		.else
			push	ecx
			call	itoa
			pop	ecx
		.endif
		.if dword ptr[esi]&80000000h
			mov	al,']'
			stosb
		.endif
		mov	eax,' >- '
		stosd
		lodsd
		.if dword ptr[esi]==-1
			sub	edi,4
			.if dword ptr[esi+4]
				inc	ecx
				mov	eax,0a0d0a0dh
				stosd
				mov	al,'#'
				stosb
				mov	eax,ecx
				push	ecx
				call	itoa
				pop	ecx
				mov	ax,' :'
				stosw
				lodsd
			.else
				.break
			.endif
		.elseif dword ptr[esi]==0
			sub	edi,4
			.break
		.endif
		mov	eax,edi
		sub	eax,buffer
		sub	bufsize,eax
		mov	buffer,edi
	.endw
	mov	eax,0a0dh
	stosd
	ret
geoip_as_path_to_str	ENDP

_enus	db	'en-US',0
get_lang_name	PROC STDCALL	uses ebx cname:DWORD,seed:DWORD
;	invoke	geoip_get_country_by_ip,ip
;	invoke	geoip_get_country_name,eax
	xor	edx,edx
	mov	eax,seed
	mov	seed,100
	div	seed
	mov	seed,edx
	mov	eax,cname
	movzx	eax,word ptr[eax]
	xor	ecx,ecx
	.while byte ptr ccodes[ecx*2]
		.break .if ax==word ptr ccodes[ecx*2]
		inc	ecx
	.endw
	.while ax==word ptr ccodes[ecx*2]
		mov	edx,lng_tbl[ecx*4]
		movzx	edx,byte ptr[edx]
		.if edx >= seed
			mov	edx,lng_tbl[ecx*4]
			lea	eax,[edx+1]
			ret
		.endif
		sub	seed,edx
		inc	ecx
	.endw
	mov	eax,lng_tbl[ecx*4]
	.if eax
		inc	eax
	.else
		lea	eax,_enus
	.endif
	ret
get_lang_name	ENDP

end
