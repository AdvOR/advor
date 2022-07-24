;	This program is free software; you can redistribute it and/or modify
;	it under the terms of the GNU General Public License as published by
;	the Free Software Foundation.
;
;	This program is distributed in the hope that it will be useful,
;	but WITHOUT ANY WARRANTY; without even the implied warranty of
;	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;	GNU General Public License for more details.
;
;	You should have received a copy of the GNU General Public License
;	along with this program; if not, write to the Free Software
;	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

;	To compile download masm32 from http://www.masm32.com and install it on the root directory of one of your hard drives
;	Copy source files to the partition where is masm32 installed and run \masm32\bin\blddll txtCmd
;	For more information send and e-mail to cristian.albu@gmail.com

pl_procs	macro

w_ip	PROC	public
	push	ebx
	push	ecx
	push	edx

	push	eax
	movzx	eax,al
	call	itoa
	mov	al,'.'
	stosb
	pop	eax
	push	eax
	shr	eax,8
	movzx	eax,al
	call	itoa
	mov	al,'.'
	stosb
	pop	eax
	push	eax
	shr	eax,16
	movzx	eax,al
	call	itoa
	mov	al,'.'
	stosb
	pop	eax
	push	eax
	shr	eax,24
	movzx	eax,al
	call	itoa
	pop	eax

	pop	edx
	pop	ecx
	pop	ebx
	ret
w_ip	ENDP

getrng:	xor	ecx,ecx
	.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
		inc	esi
	.endw
	xor	ebx,ebx
	dec	ebx
	xor	edx,edx
	.if (byte ptr[esi]<='9')&&(byte ptr[esi]>='0')
		push	ebx
		push	edx
		call	atoi
		dec	esi
		pop	edx
		pop	ebx
		.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
			inc	esi
		.endw
		mov	bl,al
		mov	dl,al
		.if byte ptr[esi]=='.'
			inc	esi
		.endif
		.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
			inc	esi
		.endw
		.if (byte ptr[esi]<='9')&&(byte ptr[esi]>='0')
			push	ebx
			push	edx
			call	atoi
			dec	esi
			pop	edx
			pop	ebx
			.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
				inc	esi
			.endw
			mov	bh,al
			mov	dh,al
			.if byte ptr[esi]=='.'
				inc	esi
			.endif
			.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
				inc	esi
			.endw
			.if (byte ptr[esi]<='9')&&(byte ptr[esi]>='0')
				push	ebx
				push	edx
				call	atoi
				dec	esi
				pop	edx
				pop	ebx
				.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
					inc	esi
				.endw
				rol	ebx,16
				rol	edx,16
				mov	bl,al
				mov	dl,al
				rol	ebx,16
				rol	edx,16
				.if byte ptr[esi]=='.'
					inc	esi
				.endif
				.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
					inc	esi
				.endw
				.if (byte ptr[esi]<='9')&&(byte ptr[esi]>='0')
					push	ebx
					push	edx
					call	atoi
					dec	esi
					pop	edx
					pop	ebx
					rol	ebx,16
					rol	edx,16
					mov	bh,al
					mov	dh,al
					rol	ebx,16
					rol	edx,16
				.endif
			.endif
		.endif
	.endif
	mov	eax,edx
	ret
;esi=src
;eax=start, ebx=end
getrange:
	.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
		inc	esi
	.endw
	call	getrng
;	dec	esi
	.while (byte ptr[esi]==32)||(byte ptr[esi]==9)||(byte ptr[esi]=='*')
		inc	esi
	.endw
	.while byte ptr[esi]=='-'
		inc	esi
		.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
			inc	esi
		.endw
		push	eax
		push	ebx
		call	getrng
		pop	ecx
		pop	edx
		.if eax>ebx
			xchg	eax,ebx
		.endif
		.if eax>ecx
			xchg	eax,ecx
		.endif
		.if eax>edx
			xchg	eax,edx
		.endif
		.if ebx<ecx
			xchg	ebx,ecx
		.endif
		.if ebx<edx
			xchg	ebx,edx
		.endif
		.while (byte ptr[esi]==32)||(byte ptr[esi]==9)
			inc	esi
		.endw
	.endw
	ret

copyedx:
	.while (byte ptr[edx]!=0)
		mov	al,[edx]
		stosb
		inc	edx
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

;edx=offset string,edi=hFile
copystr:
	xor	ecx,ecx
	inc	edi
	inc	edi
	push	edi
	.while byte ptr[edx+ecx]
		mov	al,[edx+ecx]
		stosb
		inc	ecx
	.endw
	pop	edi
	movzx	ecx,cx
	mov	[edi-2],cx
	lea	edi,[edi+ecx]
	ret

copystr1:
	movzx	ecx,word ptr[edx]
	push	esi
	lea	esi,[edx+2]
	rep	movsb
	mov	al,0
	stosb
	mov	edx,esi
	pop	esi
	ret

w2:	.if al>9
		mov	cl,10
		mov	ah,0
		div	cl
		or	ax,3030h
		stosw
	.else
		mov	byte ptr[edi],30h
		inc	edi
		or	al,30h
		stosb
	.endif
	ret
w4:	.if ax>=1000
		xor	dx,dx
		mov	cx,1000
		div	cx
		or	al,30h
		stosb
		mov	ax,dx
	.else
		mov	byte ptr[edi],30h
		inc	edi
	.endif
	.if al>=100
		mov	cl,100
		mov	ah,0
		div	cl
		or	al,30h
		stosb
		mov	al,ah
	.else
		mov	byte ptr[edi],30h
		inc	edi
	.endif
	jmp	w2


atoi:	xor	eax,eax
	xor	ebx,ebx
	push	edx
getdec0:mov	bl,[esi]
	inc	esi
	sub	bl,'0'
	cmp	bl,10
	jnc	_getdec
	push	ebx
	xor	edx,edx
	mov	bl,10
	mul	ebx
	pop	ebx
	add	eax,ebx
	jmp	getdec0
_getdec:pop	edx
	ret


is_ip	PROC	uses esi ebx str1:DWORD
	mov	esi,str1
	.if (byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	mov	str1,eax
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi-1]!='.')||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	mov	byte ptr str1[1],al
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi-1]!='.')||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	mov	byte ptr str1[2],al
	.if eax>255
		xor	eax,eax
		ret
	.endif
	.if (byte ptr[esi-1]!='.')||(byte ptr[esi]<'0')||(byte ptr[esi]>'9')
		xor	eax,eax
		ret
	.endif
	call	atoi
	mov	byte ptr str1[3],al
	.if eax>255
		xor	eax,eax
		ret
	.endif
	mov	ecx,str1
	xor	eax,eax
	inc	eax
	ret
is_ip	ENDP

endm
