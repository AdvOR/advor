LANG_DLL_ERROR_1 = 2511				;msg1
LANG_DLL_ERROR_2 = 2512				;msg2
LANG_DLL_ERROR_3 = 2513				;msg3
LANG_DLL_ERROR_4 = 2514				;msg4
LANG_DLL_ERROR_5 = 2515				;msg5
LANG_DLL_ERROR_6 = 2516				;msg6
LANG_DLL_RESTRICTED_PROCESS = 2517		;msgnp
LANG_DLL_CREATED_A_NEW_PROCESS = 2518		;msgnp1
LANG_DLL_RESOLVE = 2519				;msgnr
LANG_DLL_REVDNS = 2520				;msgna
LANG_DLL_WPAD = 2521				;msgnw1
LANG_DLL_NON_TCP = 2522				;msgns
LANG_DLL_NON_TCP_2 = 2523			;msgns1
LANG_DLL_REDIRECTING = 2524			;bypassmsg
LANG_DLL_PROC_COL1 = 2525			;col1
LANG_DLL_PROC_COL2 = 2526			;col2
LANG_DLL_PROTECTING = 2527			;protecting
LANG_DLL_UNPROTECTING = 2528			;unprotecting
LANG_DLL_PIPEINUSE = 2529			;pipeinuse
LANG_DLL_REINTERCEPT = 2688
LANG_DLL_JUNKDATA = 2689
LANG_DLL_CONNECTIONS_1 = 2690
LANG_DLL_CONNECTIONS_2 = 2691

LANG_DLG_HS_SELECT_A_SERVICE = 2548
LANG_DLG_HS_SELECT_PROCESS = 2549
LANG_DLG_HS_SELECT_PORT = 2550
LANG_DLG_HS_CANCEL = 2551
LANG_DLG_HS_APPLICATION = 2552
LANG_DLG_HS_LOCAL_ADDRESS = 2553
LANG_DLG_HS_LOCAL_PORT = 2554

CP_UTF8 = 65001
LVM_INSERTCOLUMNW = LVM_INSERTCOLUMN+70

lang_data	macro
	get_lang_str	dd	?
endm


lang_init	macro
	mov	get_lang_str,0
endm

lang_procs	macro
msg1	db	'Current version of AdvOR cannot intercept processes on your system.',0
msg2	db	'Error opening process for writing',0
msg3	db	'Error allocating memory in target process',0
msg4	db	'Error creating remote thread, code: ',0
msg5	db	'Error loading AdvOR.dll in selected process, code: ',0
msg6	db	'The following functions could not be intercepted:',13,10,0
msgnp	db	'Restricted process ',0
msgnp1	db	' created a new process with PID ',0
msgnr	db	' tries to resolve the address ',0
msgna	db	' - reverse DNS lookup for address ',0
msgnw1	db	' - WPAD vulnerability detected, protecting ...',0
msgns	db	' - attempt to create a non-TCP socket ( ',0
msgns1	db	' ) - we return ',0
bypassmsg db	': Redirecting connection for address ',0
protecting db	'Setting proxy restrictions for process with PID ',0
unprotecting db	'Removing proxy restrictions from process with PID ',0
pipeinuse db	'There was an error creating AdvOR pipe. If there is another instance of same AdvOR, close it and try again.',0
reintercept db	' - connection request for an address that was not found in AdvOR.dll',39,'s onion cache. This can happen when a process is re-intercepted '
	db	'and it keeps its own DNS cache with fake IPs given by previous instances of AdvOR.dll. You can wait until programs',39,'s cache expires or you can restart the program.',0
junkdata db	'An application is sending junk through AdvOR pipe. The following data was received:',13,10,0
openconns db	' - the application has existing opened connections that do not go through the OR network. The following connections were found:',0
openconns1 db	'Do you want to close these connections ?',0
col1	db	'Process name',0
col2	db	'PID',0


SetGetLangStrCallback	PROC	f1:DWORD
	mov	eax,f1
	mov	get_lang_str,eax
	ret
SetGetLangStrCallback	ENDP

showLog	macro	a1,a2,a3
	.if get_lang_str
		push	a1
		call	get_lang_str
		add	esp,4
	.else
		lea	eax,a2
	.endif
	push	eax
	push	a3
	call	Log
endm

writeLangStr	macro	a1,a2
	.if get_lang_str
		push	a1
		call	get_lang_str
		add	esp,4
		xchg	edx,eax
	.else
		lea	edx,a2
	.endif
	call	copyedx
endm

getLangStr	macro	a1,a2
	.if get_lang_str
		push	a1
		call	get_lang_str
		add	esp,4
		xchg	edx,eax
	.else
		lea	edx,a2
	.endif
endm

langChangeDialogString	macro	a1,a2
	.if get_lang_str && _SendMessageW
		push	a1
		push	a2
		call	get_lang_str
		add	esp,4
		push	eax
		invoke	GlobalAlloc,GPTR,200
		mov	edx,[esp]
		push	eax
		xor	ecx,ecx
		.while byte ptr[edx+ecx]
			inc	ecx
		.endw
		invoke	MultiByteToWideChar,CP_UTF8,0,edx,ecx,eax,99
		mov	edx,[esp]
		mov	word ptr[eax*2+edx],0
		mov	eax,[esp+8]
		push	edx
		push	0
		push	WM_SETTEXT
		push	eax
		call	_SendMessageW
		call	GlobalFree
		pop	eax
		pop	eax
	.endif
endm

langChangeDialogString2	macro	a1,a2,a3
	.if get_lang_str && _SendDlgItemMessageW
		push	a1
		push	a2
		push	a3
		call	get_lang_str
		add	esp,4
		push	eax
		invoke	GlobalAlloc,GPTR,200
		mov	edx,[esp]
		push	eax
		xor	ecx,ecx
		.while byte ptr[edx+ecx]
			inc	ecx
		.endw
		invoke	MultiByteToWideChar,CP_UTF8,0,edx,ecx,eax,99
		mov	edx,[esp]
		mov	word ptr[eax*2+edx],0
		mov	ecx,[esp+8]
		mov	eax,[esp+12]
		push	edx
		push	0
		push	WM_SETTEXT
		push	ecx
		push	eax
		call	_SendDlgItemMessageW
		call	GlobalFree
		pop	eax
		pop	eax
		pop	eax
	.endif
endm

langInsertColumn	macro	a1,a2,a3,a4,a5,a6
	.if get_lang_str && _SendDlgItemMessageW
		invoke	GlobalAlloc,GPTR,200
		push	eax
		push	a6
		call	get_lang_str
		add	esp,4
		mov	edx,eax
		xor	ecx,ecx
		.if eax
			.while byte ptr[edx+ecx]
				inc	ecx
			.endw
		.endif
		mov	eax,[esp]
		invoke	MultiByteToWideChar,CP_UTF8,0,edx,ecx,eax,99
		mov	edx,[esp]
		mov	word ptr[eax*2+edx],0
		mov	lvcol.pszText,edx
		shr	eax,1
		mov	lvcol.cchTextMax,eax
		push	a5
		push	a4
		push	LVM_INSERTCOLUMNW
		push	a2
		push	a1
		call	_SendDlgItemMessageW
		call	GlobalFree
	.else
		user32SendDlgItemMessage	a1,a2,a3,a4,a5
	.endif
endm

get_unicode	PROC	str1:DWORD
	xor	ecx,ecx
	mov	edx,str1
	.while byte ptr[edx+ecx]
		inc	ecx
	.endw
	inc	ecx
	push	ecx
	lea	ecx,[ecx*2+4]
	push	ecx
	invoke	GlobalAlloc,GPTR,ecx
	pop	ecx
	sub	ecx,2
	pop	edx
	push	eax
	invoke	MultiByteToWideChar,CP_UTF8,0,str1,edx,eax,ecx
	pop	edx
	mov	word ptr[edx+eax*2],0
	xchg	eax,edx
	ret
get_unicode	ENDP


endm
