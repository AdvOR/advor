LANG_ID_DESC1 = 0
LANG_ID_ERRF1 = 1
LANG_ID_MSGB1 = 2
LANG_ID_MSGB2 = 3
LANG_ID_UNKNOWN_PROCESS = 4
LANG_ID_BANNED_ADDR = 5
LANG_ID_CLOSECONN = 6
LANG_ID_HTML1 = 7
LANG_ID_ERRDL = 8
LANG_ID_DLSUCCESS = 9
LANG_ID_UNGZIPPED = 10
LANG_ID_BLACKLIST_URL = 11
LANG_ID_DLG_SETTINGS = 30
LANG_ID_DLG_BYTES_DOWNLOADED = 31
LANG_ID_MB_RESULTS = 32
LANG_ID_MB_IP_B = 33
LANG_ID_MB_RNG_B = 34
LANG_ID_MB_IP_NB = 35
LANG_ID_MB_RNG_NB = 36

desc1	db	'IP blacklist',0
errf	db	'Error opening file %s',0
msgb1	db	'The router %s was found in blacklist',0
msgb2	db	'Banning router %s .',0
unknown_process	db	'[Unknown_process]',0
bannedaddr	db	'requested address was found in blacklist',0
closeconn	db	'closing connection.',0
html1	db	'<HTML><HEAD><TITLE>This website is blacklisted</TITLE></HEAD><BODY bgcolor="black"><CENTER><FONT color="white"><BR><BR><H1>Website blocked</H1><BR>The address you wanted to access &quot;<B>'
	db	'%s</B>&quot; was found in blacklist as &quot;<B>'
	db	'%s</B>&quot;</FONT></CENTER></BODY></HTML>',0
errd1	db	'Error downloading %s code: ',0
dls	db	'The blacklist was downloaded successfully.',0
ungzipped db	'The blacklist was uncompressed successfully. Compressed: %s, decompressed: %s',0
dtxt	db	'Blacklist downloads use your Internet Explorer proxy settings.',0
bdown	db	'%s bytes downloaded',0
msgbannedt	db	'Blacklist search results',0
msg_ip_banned	db	'The IP %s intersects the following banned ranges:',0
msg_range_banned db	'The IP range %s intersects the following banned ranges:',0
msg_ip_nb	db	'The IP %s is not blacklisted.',0
msg_range_nb	db	'The IP range %s is not blacklisted.',0

dialog_strings	lang_dlg_info	<10,11>
		lang_dlg_info	<1,12>
		lang_dlg_info	<11,13>
		lang_dlg_info	<400,14>
		lang_dlg_info	<401,15>
		lang_dlg_info	<402,16>
		lang_dlg_info	<403,17>
		lang_dlg_info	<404,18>
		lang_dlg_info	<405,19>
		lang_dlg_info	<500,20>
		lang_dlg_info	<501,21>
		lang_dlg_info	<50,22>
		lang_dlg_info	<20,23>
		lang_dlg_info	<21,24>
		lang_dlg_info	<22,25>
		lang_dlg_info	<23,26>
		lang_dlg_info	<51,27>
		lang_dlg_info	<3,28>
		lang_dlg_info	<24,29>
		lang_dlg_info	<0,0>


format_str	PROC	lang_id:DWORD,defstr1:DWORD,str2:DWORD
	AdvTor_lang_get_string	lang_id,defstr1
	mov	edx,eax
	.if edx
		.while byte ptr[edx]
			mov	al,[edx]
			inc	edx
			.if al=='%'
				.if byte ptr[edx]=='s'
					inc	edx
					push	edx
					mov	edx,str2
					call	copyedx
					pop	edx
				.elseif byte ptr[edx]=='%'
					inc	edx
					stosb
				.endif
			.else
				stosb
			.endif
		.endw
	.else
		mov	edx,str2
		call	copyedx
	.endif
	mov	al,0
	stosb
	ret
format_str	ENDP

format_str_cb	PROC	lang_id:DWORD,defstr1:DWORD,cb:DWORD
	AdvTor_lang_get_string	lang_id,defstr1
	mov	edx,eax
	.if edx
		.while byte ptr[edx]
			mov	al,[edx]
			inc	edx
			.if al=='%'
				.if byte ptr[edx]=='s'
					inc	edx
					push	edx
					call	cb
					pop	edx
				.elseif byte ptr[edx]=='%'
					inc	edx
					stosb
				.endif
			.else
				stosb
			.endif
		.endw
	.else
		call	cb
	.endif
	mov	al,0
	stosb
	ret
format_str_cb	ENDP

format_int	PROC	uses ebx lang_id:DWORD,defstr1:DWORD,_int:DWORD
	AdvTor_lang_get_string	lang_id,defstr1
	mov	edx,eax
	.if edx
		.while byte ptr[edx]
			mov	al,[edx]
			inc	edx
			.if al=='%'
				.if byte ptr[edx]=='s'
					inc	edx
					push	edx
					mov	eax,_int
					call	itoa
					pop	edx
				.elseif byte ptr[edx]=='%'
					inc	edx
					stosb
				.endif
			.else
				stosb
			.endif
		.endw
	.else
		mov	eax,_int
		call	itoa
	.endif
	mov	al,0
	stosb
	ret
format_int	ENDP

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
