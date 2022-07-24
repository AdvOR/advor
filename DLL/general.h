TV_ITEMEXW	struct
	imask		dd	?
	hItem		dd	?
	state		dd	?
	stateMask	dd	?
	pszText		dd	?
	cchTextMax	dd	?
	iImage		dd	?
	iSelectedImage	dd	?
	cChildren	dd	?
	lParam		dd	?
	iIntegral	dd	?
TV_ITEMEXW	ends

TV_INSERTSTRUCTW	struct
	hParent		dd	?
	hInsertAfter	dd	?
	itemex		TV_ITEMEXW <>
TV_INSERTSTRUCTW	ends

atoi	PROC	public
	xor	eax,eax
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
atoi	ENDP

atoiW	PROC	public
	xor	eax,eax
	xor	ebx,ebx
	push	edx
getdec0w:mov	bl,[esi]
	inc	esi
	inc	esi
	sub	bl,'0'
	cmp	bl,10
	jnc	_getdecw
	push	ebx
	xor	edx,edx
	mov	bl,10
	mul	ebx
	pop	ebx
	add	eax,ebx
	jmp	getdec0w
_getdecw:pop	edx
	ret
atoiW	ENDP

copyedx:.while byte ptr[edx]
		mov	al,[edx]
		stosb
		inc	edx
	.endw
	ret

copyedxW:
	mov	ah,0
	.while byte ptr[edx]
		mov	al,[edx]
		stosw
		inc	edx
	.endw
	ret

itoa:	push	ecx
	push	edx
	mov	ecx,10
	xor	edx,edx
	div	ecx
	.if eax
		call	itoa
	.endif
	or	dl,30h
	mov	al,dl
	stosb
	pop	edx
	pop	ecx
	ret

itoaW:	push	ecx
	push	edx
	mov	ecx,10
	xor	edx,edx
	div	ecx
	.if eax
		call	itoaW
	.endif
	or	dl,30h
	movzx	eax,dl
	stosw
	pop	edx
	pop	ecx
	ret

w_ip:	push	ebx
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

whex	PROC
	xor	ecx,ecx
	.while ecx<8
		rol	eax,4
		push	eax
		and	al,0fh
		or	al,30h
		.if al>39h
			add	al,7
		.endif
		stosb
		pop	eax
		inc	ecx
	.endw
	ret
whex	ENDP
