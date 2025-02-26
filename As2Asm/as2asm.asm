;aggr.html can be updated from https://www.cidr-report.org/as2.0/aggr.html

.386
.model	flat,stdcall
option	casemap:none

include	\masm32\include\windows.inc
include	\masm32\include\kernel32.inc
include	\masm32\include\shell32.inc
include	\masm32\include\user32.inc

includelib	\masm32\lib\user32.lib
includelib	\masm32\lib\kernel32.lib
includelib	\masm32\lib\shell32.lib

tree_item	struct
	key	dd	?
	offs	dd	?
	next	dd	?
	prev	dd	?
	parent	dd	?
	child	dd	?
tree_item	ends

.data?
	tzara	dd	2024000 dup(?)
	lastas	dd	?
	numas	dd	?
	h1	dd	?
	treeoffs dd	?
	fsize	dd	?
	bread	dd	?
	tzaraidx dd	?
	lastidx	dd	?
	lastip	dd	?
	count	dd	?
	tz_size	dd	?
	txt_size dd	?
	max_tzari dd	?
	max_coduri dd	?
	buffer1	db	176384000 dup(?)
	buffer2	db	176384000 dup(?)
	buffer3	db	176384000 dup(?)
	buffer4	db	176384000 dup(?)
	buffer5	db	176384000 dup(?)

.code
fname	db	'aggr.html',0
fname0	db	'geoip_as.h',0
var1	db	13,10,13,10,'as_path',0
var2	db	13,10,13,10,'as_ip_1'
var3	db	'as_cnt = ',0
var4	db	13,10,'as_maxpath = ',0
var5	db	13,10,13,10,'as_ip_2'
var6	db	13,10,13,10,'as_idx'
start:
	mov	count,0
	mov	dword ptr tzara,0
	mov	lastas,0
	mov	numas,0
	lea	edx,buffer3[4]
	mov	dword ptr buffer3,0
	mov	treeoffs,edx
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
		.while byte ptr[esi]
			.if byte ptr[esi]>='0' && byte ptr[esi]<='9'
				xor	ecx,ecx
				.while byte ptr[esi+ecx]>='0' && byte ptr[esi+ecx]<='9'
					inc	ecx
				.endw
				.break .if byte ptr[esi+ecx]=='.'
			.endif
			inc	esi
		.endw
		mov	edi,offset buffer2
		.while byte ptr[esi]!=0
			push	edi
			call	get_as	;eax,edx,ecx
			pop	edi
			.if ecx
				inc	count
				stosd
				mov	eax,edx
				stosd
				mov	eax,ecx
				stosd
			.endif
		.endw

		push	edi
		lea	ecx,buffer2
		sub	edi,12
		.while ecx<edi
			mov	eax,[ecx]
			mov	ebx,[ecx+4]
			lea	edx,[ecx+12]
			.while edx<edi
				.if eax>[edx] || (eax==[edx] && ebx>[edx+4])
					xchg	eax,[edx]
					xchg	eax,[ecx]
					xchg	eax,[edx]
					xchg	eax,[edx+4]
					xchg	eax,[ecx+4]
					xchg	eax,[edx+4]
					xchg	eax,[edx+8]
					xchg	eax,[ecx+8]
					xchg	eax,[edx+8]
					mov	eax,[ecx]
					mov	ebx,[ecx+4]
				.endif
				lea	edx,[edx+12]
			.endw
			lea	ecx,[ecx+12]
		.endw
		pop	edi

		lea	esi,buffer2
		lea	edi,buffer2
		mov	ecx,count
		.while ecx
			movsd
			mov	eax,[esi+4]
			mov	edx,[esi]
			.while eax==[esi+4+12]
				.if edx<[esi]
					mov	edx,[esi]
				.endif
				lea	esi,[esi+12]
				.if ecx
					dec	ecx
				.else
					.break
				.endif
			.endw
			.if edx>[esi]
				mov	eax,edx
				stosd
				lodsd
			.else
				movsd
			.endif
			movsd
			.if ecx
				dec	ecx
			.endif
		.endw
		mov	eax,edi
		sub	eax,offset buffer2
		xor	edx,edx
		mov	ecx,12
		div	ecx
		mov	count,eax
		invoke	CreateFile,addr fname0,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0
		push	eax
		lea	edi,buffer4
		mov	esi,dword ptr buffer3
		xor	ecx,ecx
		inc	ecx
		call	write_tree
		push	edi
		lea	edi,buffer1
		lea	edx,var3
		call	copyedx
		mov	eax,count
		call	itoa
		lea	edx,var4
		call	copyedx
		mov	eax,numas
		call	itoa
		lea	edx,var1
		call	copyedx
		mov	ecx,edi
		sub	ecx,offset buffer1
		mov	eax,[esp+4]
		invoke	WriteFile,eax,addr buffer1,ecx,addr bread,0
		pop	edi
		mov	ebx,edi
		lea	esi,buffer4
		.while esi<ebx
			lea	edi,buffer1
			xor	ecx,ecx
			mov	al,9
			stosb
			mov	ax,'bd'
			stosw
			mov	al,9
			stosb
			.while esi<ebx && ecx<16
				lodsb
				call	whex3
				inc	ecx
				mov	al,','
				stosb
			.endw
			dec	edi
			mov	ax,0a0dh
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer1
			mov	eax,[esp]
			invoke	WriteFile,eax,addr buffer1,ecx,addr bread,0
		.endw

		xor	ecx,ecx
		lea	esi,buffer2
		.while ecx<count
			mov	eax,[esi+8]
			assume	eax:ptr tree_item
			mov	eax,[eax].offs
			assume	eax:nothing
			mov	[esi+8],eax
			inc	ecx
			lea	esi,[esi+12]
		.endw

		mov	eax,[esp]
		invoke	WriteFile,eax,addr var2,sizeof var2,addr bread,0
		lea	esi,buffer2
		lea	edi,buffer3
		mov	ecx,count
		.while ecx
			movsd
			lodsd
			lodsd
			dec	ecx
		.endw
		lea	esi,buffer3
		mov	ecx,count
		.while ecx!=0
			push	ecx
			lea	edi,buffer1
			mov	al,9
			stosb
			mov	ax,'dd'
			stosw
			mov	al,9
			stosb
			.if ecx >= 16
				mov	ecx,16
			.endif
			sub	[esp],ecx
			.while ecx!=0
				lodsd
				call	whex
				dec	ecx
				mov	al,','
				stosb
			.endw
			dec	edi
			mov	ax,0a0dh
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer1
			mov	eax,[esp+4]
			invoke	WriteFile,eax,addr buffer1,ecx,addr bread,0
			pop	ecx
		.endw

		mov	eax,[esp]
		invoke	WriteFile,eax,addr var5,sizeof var5,addr bread,0
		lea	esi,buffer2
		lea	edi,buffer3
		mov	ecx,count
		.while ecx
			lodsd
			movsd
			lodsd
			dec	ecx
		.endw
		lea	esi,buffer3
		mov	ecx,count
		.while ecx!=0
			push	ecx
			lea	edi,buffer1
			mov	al,9
			stosb
			mov	ax,'dd'
			stosw
			mov	al,9
			stosb
			.if ecx >= 16
				mov	ecx,16
			.endif
			sub	[esp],ecx
			.while ecx!=0
				lodsd
				call	whex
				dec	ecx
				mov	al,','
				stosb
			.endw
			dec	edi
			mov	ax,0a0dh
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer1
			mov	eax,[esp+4]
			invoke	WriteFile,eax,addr buffer1,ecx,addr bread,0
			pop	ecx
		.endw

		mov	eax,[esp]
		invoke	WriteFile,eax,addr var6,sizeof var6,addr bread,0
		lea	esi,buffer2
		lea	edi,buffer3
		mov	ecx,count
		.while ecx
			lodsd
			lodsd
			movsd
			dec	ecx
		.endw
		lea	esi,buffer3
		mov	ecx,count
		.while ecx!=0
			push	ecx
			lea	edi,buffer1
			mov	al,9
			stosb
			mov	ax,'dd'
			stosw
			mov	al,9
			stosb
			.if ecx >= 16
				mov	ecx,16
			.endif
			sub	[esp],ecx
			.while ecx!=0
				lodsd
				call	whex
				dec	ecx
				mov	al,','
				stosb
			.endw
			dec	edi
			mov	ax,0a0dh
			stosw
			mov	ecx,edi
			sub	ecx,offset buffer1
			mov	eax,[esp+4]
			invoke	WriteFile,eax,addr buffer1,ecx,addr bread,0
			pop	ecx
		.endw

		call	CloseHandle

		mov	edi,offset buffer1
		mov	eax,count
		call	itoa
		mov	al,0
		stosb
		invoke	MessageBox,0,addr buffer1,addr buffer1,0
	.endif
	invoke	ExitProcess,0

copyedx:.while byte ptr[edx]
		mov	al,[edx]
		stosb
		inc	edx
	.endw
	ret

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

whex:	mov	byte ptr[edi],'0'
	inc	edi
	push	ecx
	mov	ecx,8
	.while ecx
		rol	eax,4
		push	eax
		and	al,0fh
		or	al,30h
		.if al>'9'
			add	al,7
		.endif
		stosb
		pop	eax
		dec	ecx
	.endw
	pop	ecx
	mov	al,'h'
	stosb
	ret

whex2:	mov	byte ptr[edi],'0'
	inc	edi
	mov	ecx,4
	.while ecx
		rol	ax,4
		push	eax
		and	al,0fh
		or	al,30h
		.if al>'9'
			add	al,7
		.endif
		stosb
		pop	eax
		dec	ecx
	.endw
	mov	al,'h'
	stosb
	ret

whex3:	mov	byte ptr[edi],'0'
	inc	edi
	push	eax
	rol	al,4
		and	al,0fh
		or	al,30h
		.if al>'9'
			add	al,7
		.endif
		stosb
	pop	eax
		and	al,0fh
		or	al,30h
		.if al>'9'
			add	al,7
		.endif
		stosb
	mov	al,'h'
	stosb
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

get_as	PROC
	local	ip1,ip2:DWORD
	mov	ip1,0
	mov	ip2,0
	xor	ecx,ecx
	.if byte ptr[esi]=='<'
		.while byte ptr[esi]!=13 && byte ptr[esi]!=10 && byte ptr[esi]!=0 && byte ptr[esi]!='>'
			inc	esi
		.endw
		.if byte ptr[esi]=='>'
			inc	esi
		.else
			.while byte ptr[esi]==13 || byte ptr[esi]==10 || byte ptr[esi]==32 || byte ptr[esi]==9
				inc	esi
			.endw
			ret
		.endif
	.endif
	.while byte ptr[esi]==32 || byte ptr[esi]==13 || byte ptr[esi]==10
		inc	esi
	.endw
	.if byte ptr[esi]<'0' || byte ptr[esi]>'9'
		.while byte ptr[esi]!=13 && byte ptr[esi]!=10 && byte ptr[esi]!=0
			inc	esi
		.endw
		.while byte ptr[esi]==13 || byte ptr[esi]==10 || byte ptr[esi]==32
			inc	esi
		.endw
		ret
	.endif
	call	atoi
	.if eax>255
		ret
	.endif
	mov	byte ptr ip1+3,al
	.if byte ptr[esi]!='.'
		ret
	.endif
	inc	esi

	.if byte ptr[esi]<'0' || byte ptr[esi]>'9'
		inc	esi
		ret
	.endif
	call	atoi
	.if eax>255
		xor	ecx,ecx
		ret
	.endif
	mov	byte ptr ip1+2,al
	.if byte ptr[esi]!='.'
		xor	ecx,ecx
		ret
	.endif
	inc	esi

	.if byte ptr[esi]<'0' || byte ptr[esi]>'9'
		xor	ecx,ecx
		inc	esi
		ret
	.endif
	call	atoi
	.if eax>255
		xor	ecx,ecx
		ret
	.endif
	mov	byte ptr ip1+1,al
	.if byte ptr[esi]!='.'
		ret
	.endif
	inc	esi

	.if byte ptr[esi]<'0' || byte ptr[esi]>'9'
		xor	ecx,ecx
		inc	esi
		ret
	.endif
	call	atoi
	.if eax>255
		ret
	.endif
	mov	byte ptr ip1,al
	.if byte ptr[esi]!='/'
		ret
	.endif
	inc	esi
	call	atoi
	mov	ecx,32
	sub	ecx,eax
	xor	eax,eax
	.while ecx
		shl	eax,1
		or	al,1
		dec	ecx
	.endw
	mov	edx,ip1
	or	edx,eax
	mov	ip2,edx
	xor	eax,-1
	and	ip1,eax
	xor	ecx,ecx
	.while byte ptr[esi+ecx]==32 || byte ptr[esi+ecx]==')' || byte ptr[esi+ecx]=='-' || (byte ptr[esi+ecx]>='0' && byte ptr[esi+ecx]<='9')
		inc	ecx
	.endw
	.if dword ptr[esi+ecx]=='htiW' && dword ptr[esi+ecx+4]=='ward'
		xor	ecx,ecx
	.else
	xor	ecx,ecx
	.while byte ptr[esi]!=13 && byte ptr[esi]!=10 && byte ptr[esi]!=0
		.while byte ptr[esi]==32 || byte ptr[esi]=='('
			inc	esi
		.endw
		.if byte ptr[esi]<'0' || byte ptr[esi]>'9'
			.break
		.else
			call	atoi
			.if eax
				call	seek_tree
			.endif
		.endif
	.endw
	.endif
	.while byte ptr[esi]!=13 && byte ptr[esi]!=10 && byte ptr[esi]!=0
		inc	esi
	.endw
	.while byte ptr[esi]==13 || byte ptr[esi]==10 || byte ptr[esi]==32 || byte ptr[esi]==9
		inc	esi
	.endw
	mov	eax,ip1
	mov	edx,ip2
	ret
get_as	ENDP

add_as:
	movzx	ecx,cx
	.if ecx==0
		ret
	.endif
	inc	numas
	push	edi
	lea	edi,tzara
	.while dword ptr[edi]
		.if ecx==[edi]
			pop	edi
			ret
		.endif
		mov	edi,[edi+4]
	.endw
	mov	eax,ecx
	stosd
	push	edi
	stosd
	mov	edx,lastas
	.while byte ptr[edx]==32
		inc	edx
	.endw
	.while byte ptr[edx]!=0 && byte ptr[edx]!=13 && byte ptr[edx]!=10
		mov	al,[edx]
		inc	edx
		.if (al!='-' || byte ptr[edx]!='-') && (al!=' ' || byte ptr[edx]!=' ')
			stosb
		.endif
	.endw
	.while byte ptr[edi-1]==32 || byte ptr[edi-1]==','
		dec	edi
	.endw
	xor	eax,eax
	stosb
	stosd
	sub	edi,4
	mov	eax,edi
	pop	edi
	stosd
	pop	edi
	ret

seek_tree:
	.if dword ptr buffer3==0
		lea	edi,buffer3[4]
		assume	edi:ptr tree_item
		mov	[edi].key,eax
		mov	[edi].next,0
		mov	[edi].prev,0
		mov	[edi].parent,0
		mov	[edi].child,0
		assume	edi:nothing
		mov	dword ptr buffer3,edi
		mov	ecx,edi
		lea	edi,[edi+sizeof tree_item]
		mov	treeoffs,edi
		ret
	.endif
		.if ecx==0
			mov	edi,dword ptr buffer3
			assume	edi:ptr tree_item
			.if eax<[edi].key
				mov	edi,treeoffs
				mov	edx,dword ptr buffer3
				mov	dword ptr buffer3,edi
				mov	[edi].next,edx
				mov	[edi].key,eax
				mov	[edi].prev,0
				mov	[edi].parent,0
				mov	[edi].child,0
				mov	ecx,edi
				lea	edi,[edi+sizeof tree_item]
				mov	treeoffs,edi
				ret
			.endif
			.while 1
				.if eax==[edi].key
					mov	ecx,edi
					ret
				.endif
				.break .if eax<[edi].key
				.if [edi].next==0
					mov	ecx,treeoffs
					assume	ecx:ptr tree_item
					mov	[ecx].key,eax
					mov	[ecx].prev,edi
					mov	[edi].next,ecx
					mov	[ecx].next,0
					mov	[ecx].parent,0
					mov	[ecx].child,0
					assume	ecx:nothing
					lea	edi,[ecx+sizeof tree_item]
					mov	treeoffs,edi
					ret
				.endif
				mov	edi,[edi].next
			.endw
			mov	ecx,treeoffs
			assume	ecx:ptr tree_item
			mov	[ecx].key,eax
			mov	eax,[edi].prev
			mov	[ecx].prev,eax
			mov	[ecx].next,edi
			assume	eax:ptr tree_item
			.if eax
				mov	[eax].next,ecx
			.endif
			assume	eax:nothing
			mov	[edi].prev,ecx
			mov	[ecx].parent,0
			mov	[ecx].child,0
			assume	ecx:nothing
			assume	edi:nothing
			lea	edi,[ecx+sizeof tree_item]
			mov	treeoffs,edi
			ret
		.endif
		assume	edi:ptr tree_item
		mov	edi,ecx
		.if eax==[edi].key
			ret
		.endif
		.if [edi].child==0
			mov	ecx,treeoffs
			mov	[edi].child,ecx
			xchg	edi,ecx
			mov	[edi].key,eax
			mov	[edi].next,0
			mov	[edi].prev,0
			mov	[edi].parent,ecx
			mov	ecx,edi
			lea	edi,[edi+sizeof tree_item]
			mov	treeoffs,edi
			ret
		.endif
		mov	ecx,edi
		mov	edi,[edi].child
		.if eax<[edi].key
			mov	edx,ecx
			mov	edi,treeoffs
			mov	[edi].key,eax
			mov	[edi].parent,edx
			xchg	edi,edx
			mov	eax,[edi].child
			mov	[edi].child,edx
			xchg	edi,edx
			mov	[edi].next,eax
			mov	[edi].prev,0
			mov	[edi].child,0
			mov	ecx,edi
			lea	edi,[edi+sizeof tree_item]
			mov	treeoffs,edi
			ret
		.endif
		.while 1
			.if eax==[edi].key
				mov	ecx,edi
				ret
			.endif
			.break .if eax<[edi].key
			.if [edi].next==0
				mov	ecx,treeoffs
				assume	ecx:ptr tree_item
				mov	[ecx].key,eax
				mov	[ecx].prev,edi
				mov	[edi].next,ecx
				mov	eax,[edi].parent
				mov	[ecx].next,0
				mov	[ecx].parent,eax
				mov	[ecx].child,0
				assume	ecx:nothing
				lea	edi,[ecx+sizeof tree_item]
				mov	treeoffs,edi
				ret
			.endif
			mov	edi,[edi].next
		.endw
		mov	ecx,treeoffs
		assume	ecx:ptr tree_item
		mov	[ecx].key,eax
		mov	[ecx].next,edi
		mov	eax,[edi].prev
		mov	[ecx].prev,eax
		assume	eax:ptr tree_item
		.if eax
			mov	[eax].next,ecx
		.else
			mov	eax,[edi].parent
			mov	[eax].child,ecx
		.endif
		assume	eax:nothing
		mov	[edi].prev,ecx
		mov	eax,[edi].parent
		mov	[ecx].parent,eax
		mov	[ecx].child,0
		assume	ecx:nothing
		assume	edi:nothing
		lea	edi,[ecx+sizeof tree_item]
		mov	treeoffs,edi
		ret
		assume	edi:nothing
	ret

write_tree	PROC uses esi
	local	hFile:DWORD,level:DWORD
	mov	hFile,eax
	mov	level,ecx
	assume	esi:ptr tree_item
	mov	eax,edi
	sub	eax,offset buffer4
	mov	[esi].offs,eax
	mov	eax,[esi].key
	mov	edx,edi
	.if eax<65535
		stosw
	.else
		mov	word ptr[edi],65535
		inc	edi
		inc	edi
		stosd
	.endif
	xor	eax,eax
	push	ecx
	stosd
	.if [esi].child
		push	edx
		push	esi
		inc	ecx
		.if ecx>numas
			mov	numas,ecx
		.endif
		mov	esi,[esi].child
		mov	eax,hFile
		call	write_tree
		pop	esi
		pop	edx
	.endif
	pop	ecx
	push	ecx
	mov	eax,edi
	sub	eax,edx
	.if word ptr[edx]==0ffffh
		mov	[edx+2+4],eax
	.else
		mov	[edx+2],eax
	.endif
	.if [esi].next
		push	edx
		push	esi
		mov	esi,[esi].next
		mov	eax,hFile
		call	write_tree
		pop	esi
		pop	edx
	.endif
	pop	ecx
	assume	esi:nothing
	ret
write_tree	ENDP

end	start