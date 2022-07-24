MAX_PROC_WINDOWS=20

user32data	macro
	_SendDlgItemMessage	dd	?
	_SendDlgItemMessageW	dd	?
	_SendMessage		dd	?
	_SendMessageW		dd	?
	_PostMessage		dd	?
	_IsWindowVisible	dd	?
	_MessageBoxW		dd	?
	_GetWindowThreadProcessId dd	?
	_DialogBoxParam		dd	?
	_EndDialog		dd	?
	hUser32			dd	?
	user32icondata
endm

user32init	macro
	mov	_SendDlgItemMessage,0
	mov	_SendDlgItemMessageW,0
	mov	_SendMessage,0
	mov	_SendMessageW,0
	mov	_PostMessage,0
	mov	_IsWindowVisible,0
	mov	_MessageBoxW,0
	mov	_GetWindowThreadProcessId,0
	mov	_FindWindowExA,0
	mov	_DialogBoxParam,0
	mov	_EndDialog,0
endm

user32init2	macro
userlib	db	'user32.dll',0
strSendDlgItemMessage	db	'SendDlgItemMessageA',0
strSendDlgItemMessageW	db	'SendDlgItemMessageW',0
strSendMessage		db	'SendMessageA',0
strSendMessageW		db	'SendMessageW',0
strPostMessage		db	'PostMessageA',0
strIsWindowVisible	db	'IsWindowVisible',0
strMessageBoxW		db	'MessageBoxW',0
strGetWindowThreadProcessId db	'GetWindowThreadProcessId',0
strFindWindowEx		db	'FindWindowExA',0
strDialogBoxParam	db	'DialogBoxParamA',0
strEndDialog		db	'EndDialog',0
u32_init:
	invoke	GetModuleHandle,addr userlib
	.if eax==0
		invoke	LoadLibrary,addr userlib
	.endif
	mov	hUser32,eax
	.if eax
		invoke	GetProcAddress,hUser32,addr strSendDlgItemMessage
		mov	_SendDlgItemMessage,eax
		invoke	GetProcAddress,hUser32,addr strSendDlgItemMessageW
		mov	_SendDlgItemMessageW,eax
		invoke	GetProcAddress,hUser32,addr strSendMessage
		mov	_SendMessage,eax
		invoke	GetProcAddress,hUser32,addr strSendMessageW
		mov	_SendMessageW,eax
		invoke	GetProcAddress,hUser32,addr strPostMessage
		mov	_PostMessage,eax
		invoke	GetProcAddress,hUser32,addr strGetWindowThreadProcessId
		mov	_GetWindowThreadProcessId,eax
		invoke	GetProcAddress,hUser32,addr strIsWindowVisible
		mov	_IsWindowVisible,eax
		invoke	GetProcAddress,hUser32,addr strMessageBoxW
		mov	_MessageBoxW,eax
		invoke	GetProcAddress,hUser32,addr strFindWindowEx
		mov	_FindWindowExA,eax
		invoke	GetProcAddress,hUser32,addr strDialogBoxParam
		mov	_DialogBoxParam,eax
		invoke	GetProcAddress,hUser32,addr strEndDialog
		mov	_EndDialog,eax
	.endif
	ret
user32iconprocs
endm

user32SendDlgItemMessage	macro	a1,a2,a3,a4,a5
	.if _SendDlgItemMessage
		push	a5
		push	a4
		push	a3
		push	a2
		push	a1
		call	_SendDlgItemMessage
	.else
		xor	eax,eax
	.endif
endm

user32SendDlgItemMessageW	macro	a1,a2,a3,a4,a5
	.if _SendDlgItemMessageW
		push	a5
		push	a4
		push	a3
		push	a2
		push	a1
		call	_SendDlgItemMessageW
	.else
		xor	eax,eax
	.endif
endm

user32SendMessage	macro	a1,a2,a3,a4
	.if _SendMessage
		push	a4
		push	a3
		push	a2
		push	a1
		call	_SendMessage
	.else
		xor	eax,eax
	.endif
endm

user32SendMessageW	macro	a1,a2,a3,a4
	.if _SendMessageW
		push	a4
		push	a3
		push	a2
		push	a1
		call	_SendMessageW
	.else
		xor	eax,eax
	.endif
endm

user32DialogBoxParam	macro	a1,a2,a3,a4
	.if _DialogBoxParam
		push	a4
		push	a3
		push	a2
		push	a1
		push	hThisInstance
		call	_DialogBoxParam
	.else
		xor	eax,eax
	.endif
endm

user32EndDialog	macro	a1,a2
	.if _EndDialog
		push	a2
		push	a1
		call	_EndDialog
	.else
		xor	eax,eax
	.endif
endm

user32PostMessage	macro	a1,a2,a3,a4
	.if _PostMessage==0
		invoke	GetModuleHandle,addr userlib
		.if eax==0
			invoke	LoadLibrary,addr userlib
		.endif
		mov	hUser32,eax
		.if eax
			invoke	GetProcAddress,hUser32,addr strPostMessage
			mov	_PostMessage,eax
		.endif
	.endif
	.if _PostMessage
		push	a4
		push	a3
		push	a2
		push	a1
		call	_PostMessage
	.else
		xor	eax,eax
	.endif
endm

user32GetWindowThreadProcessId	macro	a1,a2
	.if _GetWindowThreadProcessId
		push	a2
		push	a1
		call	_GetWindowThreadProcessId
	.else
		xor	eax,eax
	.endif
endm

user32IsWindowVisible	macro	a1
	.if _IsWindowVisible
		push	a1
		call	_IsWindowVisible
	.else
		xor	eax,eax
	.endif
endm

log_error	macro	a1,a2
	showLog	LANG_DLL_ERROR_2,msg2,LOG_ERR
	.if (sysflags&512)&&(_MessageBoxW!=0)
		user32IsWindowVisible	hDialog
		.if eax==0
			push	edi
			push	0
			push	0
			invoke	GlobalAlloc,GPTR,4096
			mov	edi,eax
			.if get_lang_str
				push	a1
				call	get_lang_str
			.else
				lea	eax,a2
			.endif
			xor	ecx,ecx
			.while byte ptr[eax+ecx]
				inc	ecx
			.endw
			lea	edx,[ecx*2]
			invoke	MultiByteToWideChar,CP_UTF8,0,eax,ecx,edi,edx
			mov	word ptr[edi+eax*2],0
			push	edi
			push	0
			call	_MessageBoxW
			invoke	GlobalFree,edi
			pop	edi
		.endif
	.endif
endm

log_error1	macro	a1
	push	a1
	push	LOG_ERR
	call	Log
	.if (sysflags&512)&&(_MessageBoxW!=0)
		user32IsWindowVisible	hDialog
		.if eax==0
			push	edi
			push	a1
			invoke	GlobalAlloc,GPTR,4096
			mov	edi,eax
			pop	eax
			push	0
			push	0
			xor	ecx,ecx
			.while byte ptr[eax+ecx]
				inc	ecx
			.endw
			lea	edx,[ecx*2]
			invoke	MultiByteToWideChar,CP_UTF8,0,eax,ecx,edi,edx
			mov	word ptr[edi+eax*2],0
			push	edi
			push	0
			call	_MessageBoxW
			invoke	GlobalFree,edi
			pop	edi
		.endif
	.endif
endm

messagebox1	macro	a1
	.if (_MessageBoxW!=0)
		push	edi
		push	a1
		invoke	GlobalAlloc,GPTR,8192
		mov	edi,eax
		pop	eax
		push	MB_YESNOCANCEL
		call	@f
		dw	'W','A','R','N','I','N','G',0
	@@:	xor	ecx,ecx
		.while byte ptr[eax+ecx]
			inc	ecx
		.endw
		lea	edx,[ecx*2]
		invoke	MultiByteToWideChar,CP_UTF8,0,eax,ecx,edi,edx
		mov	word ptr[edi+eax*2],0
		push	edi
		push	hDialog
		call	_MessageBoxW
		push	eax
		invoke	GlobalFree,edi
		pop	eax
		pop	edi
	.endif
endm

procWindow	struct
	hWnd		dd	?
	trayID		dd	?
	hOldIcon	dd	?
	hOldIconSm	dd	?
	hIcon		dd	?
	hIconSm		dd	?
	hNewIcon1	dd	?
	hNewIcon1s	dd	?
	hIcon_1		dd	?
	hIcon_1s	dd	?
	hIcon_2		dd	?
	hIcon_2s	dd	?
	hIcon_3		dd	?
	hIcon_3s	dd	?
	hIcon_4		dd	?
	hIcon_4s	dd	?
procWindow	ends

user32icondata	macro
	_GetIconInfo			dd	?
	_FindWindowExA			dd	?
	_GetObjectA			dd	?
	_DeleteObject			dd	?
	_CreateBitmapIndirect		dd	?
	_CreateIconIndirect		dd	?
	_LoadIcon			dd	?
	_DestroyIcon			dd	?
	_GetBitmapBits			dd	?
	_GetClassLong			dd	?
	_DeleteDC			dd	?
	_CreateCompatibleDC		dd	?
	_LoadBitmap			dd	?
	_SelectObject			dd	?
	_StretchBlt			dd	?
	_SetClassLong			dd	?
	_Shell_NotifyIcon		dd	?
	_ExtractIcon			dd	?
	hMainBmp			dd	?
	hMainMaskA			dd	?
	hBmp_1				dd	?
	hBmp_1a				dd	?
	hBmp_2				dd	?
	hBmp_2a				dd	?
	hBmp_3				dd	?
	hBmp_3a				dd	?
	hBmp_4				dd	?
	hBmp_4a				dd	?
	hGdi				dd	?
	lastEnum			dd	?
	defaultIcon			dd	?
	nextIcon			dd	?
	savenotifyicon			dd	?,?
					db	100 dup(?)
	procWindows			procWindow	MAX_PROC_WINDOWS dup(<>)
	nid				NOTIFYICONDATA	<>
	iconThread			dd	?
endm

check_shell32	macro
	.if _Shell_NotifyIcon==0 && _pid
		call	initShell32
	.endif
endm


user32iconinit	macro
	.if (sysflags&32)&&(hDialog==0)
		mov	_GetIconInfo,0
		mov	_FindWindowExA,0
		mov	_GetWindowThreadProcessId,0
		mov	_SendMessage,0
		mov	_GetObjectA,0
		mov	_DeleteObject,0
		mov	_CreateBitmapIndirect,0
		mov	_CreateIconIndirect,0
		mov	_LoadIcon,0
		mov	_GetBitmapBits,0
		mov	_GetClassLong,0
		mov	_SetClassLong,0
		mov	_DeleteDC,0
		mov	_CreateCompatibleDC,0
		mov	_LoadBitmap,0
		mov	_SelectObject,0
		mov	_StretchBlt,0
		mov	_Shell_NotifyIcon,0
		mov	_ExtractIcon,0
		mov	savenotifyicon,0
		mov	savenotifyicon[4],0
		mov	hMainBmp,0
		lea	edi,procWindows
		xor	eax,eax
		mov	ecx,sizeof procWindows
		cld
		rep	stosb
		mov	defaultIcon,0
		mov	iconThread,0
		mov	hGdi,0
		mov	nextIcon,0
		invoke	CreateThread,0,0,addr initIconUpdate,0,0,addr iconThread
		mov	iconThread,eax
	.endif
endm

user32unload	macro
	.if (sysflags&32)&&(hDialog==0)
		.if hMainBmp
			push	hMainBmp
			call	_DeleteObject
			push	hMainMaskA
			call	_DeleteObject
			push	hBmp_1
			call	_DeleteObject
			push	hBmp_1a
			call	_DeleteObject
			push	hBmp_2
			call	_DeleteObject
			push	hBmp_2a
			call	_DeleteObject
			push	hBmp_3
			call	_DeleteObject
			push	hBmp_3a
			call	_DeleteObject
			push	hBmp_4
			call	_DeleteObject
			push	hBmp_4a
			call	_DeleteObject
		.endif
		.if _SendMessage
			push	esi
			lea	esi,procWindows
			xor	ecx,ecx
			.while ecx<MAX_PROC_WINDOWS
				push	ecx
				assume	esi:ptr procWindow
				.if [esi].trayID
					invoke	setWindowIcon,[esi].hWnd,[esi].hOldIcon,[esi].hIconSm,[esi].trayID
				.else
					invoke	setWindowIcon,[esi].hWnd,[esi].hIcon,[esi].hIconSm,0
					invoke	getWindowIcon,[esi].hWnd
					.if eax==[esi].hIcon
						push	[esi].hOldIcon
						call	_DestroyIcon
						push	[esi].hOldIconSm
						call	_DestroyIcon
					.else
						invoke	setWindowIcon,[esi].hWnd,[esi].hOldIcon,[esi].hOldIconSm,0
						push	[esi].hIcon
						call	_DestroyIcon
						push	[esi].hIconSm
						call	_DestroyIcon
					.endif
				.endif
				.if (_DestroyIcon!=0)
					.if ([esi].hNewIcon1)
						push	[esi].hNewIcon1
						call	_DestroyIcon
						mov	[esi].hNewIcon1,0
						push	[esi].hIcon_1
						call	_DestroyIcon
						push	[esi].hIcon_2
						call	_DestroyIcon
						push	[esi].hIcon_3
						call	_DestroyIcon
						push	[esi].hIcon_4
						call	_DestroyIcon
						.if [esi].trayID==0
							push	[esi].hNewIcon1s
							call	_DestroyIcon
							mov	[esi].hNewIcon1s,0
							push	[esi].hIcon_1s
							call	_DestroyIcon
							push	[esi].hIcon_2s
							call	_DestroyIcon
							push	[esi].hIcon_3s
							call	_DestroyIcon
							push	[esi].hIcon_4s
							call	_DestroyIcon
						.endif
					.endif
				.endif
				assume	esi:nothing
				pop	ecx
				inc	ecx
				lea	esi,[esi+sizeof procWindow]
			.endw
			pop	esi
		.endif
		.while iconThread
			invoke	Sleep,10
		.endw
	.endif
endm

shell32_unhook	macro
	invoke	GetModuleHandle,addr shell32
	.if eax
		invoke	UnHook,eax,addr shell32func1,offset newnotifyicon,addr savenotifyicon
	.endif
endm

tray_pipe	macro
	.elseif dword ptr pipeData=='YART'
		invoke	GlobalAlloc,GPTR,1024
		mov	edi,eax
		push	eax
		call	getTrayData
		mov	edx,[esp]
		invoke	WriteFile,hPipe,edx,1024,addr lParam,0
		invoke	DisconnectNamedPipe,hPipe
		mov	dword ptr pipeData,0
		call	GlobalFree
endm

user32iconprocs	macro
gdi32		db	'gdi32.dll',0
shell32		db	'shell32.dll',0
shell32func1	db	'Shell_NotifyIcon',0
usericonproc1	db	'GetIconInfo',0
usericonproc2	db	'FindWindowExA',0
usericonproc3	db	'GetWindowThreadProcessId',0
usericonproc4	db	'GetObjectA',0
usericonproc5	db	'DeleteObject',0
usericonproc6	db	'CreateBitmapIndirect',0
usericonproc7	db	'CreateIconIndirect',0
usericonproc8	db	'LoadIconA',0
usericonproc9	db	'DestroyIcon',0
usericonprocA	db	'GetBitmapBits',0
usericonprocB	db	'GetClassLongA',0
usericonprocC	db	'DeleteDC',0
usericonprocD	db	'CreateCompatibleDC',0
usericonprocE	db	'LoadBitmapA',0
usericonprocF	db	'SelectObject',0
usericonproc10	db	'StretchBlt',0
usericonproc11	db	'SetClassLongA',0
usericonproc12	db	'ExtractIconA',0
;shell_wnd1	db	'Shell_TrayWnd',0	- Avira doesn't like this
shell_wnd2	db	'TrayNotifyWnd',0
shell_wnd3	db	'SysPager',0
shell_wnd4	db	'ToolbarWindow32',0

setWindowIcon	PROC	hWnd:DWORD,hIconBig:DWORD,hIconSm:DWORD,iconID:DWORD
	.if iconID && (dword ptr savenotifyicon[4] || _Shell_NotifyIcon)
		mov	nid.cbSize,sizeof NOTIFYICONDATA
		mov	eax,hWnd
		mov	nid.hwnd,eax
		mov	eax,iconID
		mov	nid.uID,eax
		mov	nid.uFlags,NIF_ICON
		mov	eax,hIconBig
		mov	nid.hIcon,eax
		push	offset nid
		push	NIM_MODIFY
		.if dword ptr savenotifyicon[4]
			call	dword ptr savenotifyicon[4]
		.else
			call	_Shell_NotifyIcon
		.endif
		ret
	.endif
	push	hIconBig
	push	ICON_BIG
	push	WM_SETICON
	push	hWnd
	call	_SendMessage
	push	hIconSm
	push	ICON_SMALL
	push	WM_SETICON
	push	hWnd
	call	_SendMessage
	push	hIconBig
	push	GCL_HICON
	push	hWnd
	call	_SetClassLong
	push	hIconSm
	push	GCL_HICONSM
	push	hWnd
	call	_SetClassLong
	ret
setWindowIcon	ENDP

getWindowIcon	PROC	hWnd:DWORD
	push	0
	push	ICON_BIG
	push	WM_GETICON
	push	hWnd
	call	_SendMessage
	.if eax
		push	eax
		push	GCL_HICON
		push	hWnd
		call	_GetClassLong
		pop	edx
		.if eax!=edx
			mov	eax,defaultIcon
		.endif
		ret
	.endif
	push	GCL_HICON
	push	hWnd
	call	_GetClassLong
	.if eax
		ret
	.endif
	push	0
	push	ICON_SMALL
	push	WM_GETICON
	push	hWnd
	call	_SendMessage
	.if eax
		ret
	.endif
	push	GCL_HICONSM
	push	hWnd
	call	_GetClassLong
	.if eax
		ret
	.endif
	mov	eax,defaultIcon
	ret
getWindowIcon	ENDP

getWindowIcon1	PROC	hWnd:DWORD
	local	hIconBig:DWORD,hIconSm:DWORD
	push	0
	push	ICON_BIG
	push	WM_GETICON
	push	hWnd
	call	_SendMessage
	.if eax==0
		push	GCL_HICON
		push	hWnd
		call	_GetClassLong
	.endif
	mov	hIconBig,eax
	push	0
	push	ICON_SMALL
	push	WM_GETICON
	push	hWnd
	call	_SendMessage
	.if eax==0
		push	GCL_HICONSM
		push	hWnd
		call	_GetClassLong
	.endif
	mov	hIconSm,eax
	mov	eax,hIconBig
	.if eax==0
		mov	eax,hIconSm
	.endif
	mov	edx,hIconSm
	.if edx==0
		mov	edx,eax
	.endif
	.if eax==0
		.if _ExtractIcon
			invoke	GlobalAlloc,GPTR,8192
			push	eax
			invoke	GetModuleHandle,0
			mov	edx,[esp]
			push	eax
			invoke	GetModuleFileName,eax,edx,8192
			pop	eax
			mov	edx,[esp]
			push	0
			push	edx
			push	eax
			call	_ExtractIcon
			pop	edx
			push	eax
			push	edx
			call	GlobalFree
			pop	eax
			.if eax>1
				mov	edx,eax
				ret
			.endif
		.endif
		mov	eax,defaultIcon
		mov	edx,eax
	.endif
	ret
getWindowIcon1	ENDP

shell_addicon	PROC	uses esi edi hWnd:DWORD,iconID:DWORD,hIcon:DWORD
	lea	edi,procWindows
	xor	ecx,ecx
	assume	edi:ptr procWindow
	mov	eax,hWnd
	mov	edx,iconID
	.while ecx<MAX_PROC_WINDOWS
		.break .if (eax==[edi].hWnd)&&(edx==[edi].trayID)
		lea	edi,[edi+sizeof procWindow]
		inc	ecx
	.endw
	.if ecx>=MAX_PROC_WINDOWS
		lea	edi,procWindows
		xor	ecx,ecx
		.while ecx<MAX_PROC_WINDOWS
			.break .if [edi].hWnd==0
			lea	edi,[edi+sizeof procWindow]
			inc	ecx
		.endw
		.if ecx>=MAX_PROC_WINDOWS
			ret
		.endif
	.endif
	.if [edi].hWnd
		push	[edi].hNewIcon1
		call	_DestroyIcon
		mov	[edi].hNewIcon1,0
		push	[edi].hIcon_1
		call	_DestroyIcon
		mov	[edi].hIcon_1,0
		push	[edi].hIcon_2
		call	_DestroyIcon
		mov	[edi].hIcon_2,0
		push	[edi].hIcon_3
		call	_DestroyIcon
		mov	[edi].hIcon_3,0
		push	[edi].hIcon_4
		call	_DestroyIcon
		mov	[edi].hIcon_4,0
		mov	[edi].hWnd,0
		mov	[edi].trayID,0
	.endif
	mov	eax,hWnd
	mov	[edi].hWnd,eax
	mov	eax,hIcon
	mov	[edi].hIcon,eax
	mov	[edi].hOldIcon,eax
	mov	eax,iconID
	mov	[edi].trayID,eax
	mov	[edi].hNewIcon1,0
	call	createIcons
	invoke	setWindowIcon,[edi].hWnd,[edi].hNewIcon1,[edi].hNewIcon1s,iconID
	assume	edi:nothing
	ret
shell_addicon	ENDP


newnotifyicon:
	jmp	_skipsigshni
	db	'AdvOR_'
	dd	offset savenotifyicon
_skipsigshni:
	mov	eax,[esp+4]
	.if eax==NIM_DELETE
		mov	edx,[esp+8]
		assume	edx:ptr NOTIFYICONDATA
		mov	eax,[edx].hwnd
		mov	edx,[edx].uID
		assume	edx:nothing
		push	edi
		lea	edi,procWindows
		xor	ecx,ecx
		assume	edi:ptr procWindow
		.while ecx<MAX_PROC_WINDOWS
			.break .if (eax==[edi].hWnd)&&(edx==[edi].trayID)
			lea	edi,[edi+sizeof procWindow]
			inc	ecx
		.endw
		.if ecx<MAX_PROC_WINDOWS
			mov	[edi].hWnd,0
			mov	[edi].trayID,0
			push	[edi].hNewIcon1
			call	_DestroyIcon
			mov	[edi].hNewIcon1,0
			push	[edi].hIcon_1
			call	_DestroyIcon
			mov	[edi].hIcon_1,0
			push	[edi].hIcon_2
			call	_DestroyIcon
			mov	[edi].hIcon_2,0
			push	[edi].hIcon_3
			call	_DestroyIcon
			mov	[edi].hIcon_3,0
			push	[edi].hIcon_4
			call	_DestroyIcon
			mov	[edi].hIcon_4,0
		.endif
		pop	edi
		assume	edi:nothing
	.elseif (eax==NIM_ADD)||(eax==NIM_MODIFY)
		mov	edx,[esp+4]
		mov	eax,[esp+8]
		push	eax
		push	edx
		call	dword ptr savenotifyicon[4]
		.if eax
			mov	edx,[esp+8]
			assume	edx:ptr NOTIFYICONDATA
			.if [edx].uFlags&NIF_ICON
				push	eax
				invoke	shell_addicon,[edx].hwnd,[edx].uID,[edx].hIcon
				pop	eax
			.endif
			assume	edx:nothing
		.endif
		ret	8
	.endif
	jmp	dword ptr savenotifyicon[4]

getTrayData	PROC	uses esi
	local	hShellWnd:DWORD,hExplorer:DWORD,buttonCount:DWORD,hMem:DWORD,bytesRead:DWORD
	local	tbButton:TBBUTTON
	.if _FindWindowExA && _VirtualAllocEx
		sub	esp,20
		mov	edx,esp
		mov	dword ptr[edx],'lehS'			;Avira should fix their detection instead
		mov	dword ptr[edx+4],'rT_l'			;banning programs for the string "Shell_TrayWnd" is stupid
		mov	dword ptr[edx+8],'nWya'
		mov	dword ptr[edx+12],'d'
		push	0
		push	edx
		push	0
		push	0
		call	_FindWindowExA
		add	esp,20
		.if eax
			push	0
			push	offset shell_wnd2
			push	0
			push	eax
			call	_FindWindowExA
			push	0
			push	offset shell_wnd3
			push	0
			push	eax
			call	_FindWindowExA
			push	0
			push	offset shell_wnd4
			push	0
			push	eax
			call	_FindWindowExA
			.if eax
				mov	hShellWnd,eax
				user32SendMessage	hShellWnd,TB_BUTTONCOUNT,0,0
				mov	buttonCount,eax
				push	0
				mov	edx,esp
				push	edx
				push	hShellWnd
				call	_GetWindowThreadProcessId
				pop	eax
				.if eax
					invoke	OpenProcess,PROCESS_ALL_ACCESS,0,eax
					.if eax
						mov	hExplorer,eax
						push	PAGE_READWRITE
						push	MEM_COMMIT
						push	100
						push	0
						push	hExplorer
						call	_VirtualAllocEx
						.if eax
							mov	hMem,eax
							xor	ecx,ecx
							sub	esp,24
							mov	esi,esp
							.while (ecx<256)&&(ecx<buttonCount)
								push	ecx
								user32SendMessage	hShellWnd,TB_GETBUTTON,ecx,hMem
								invoke	ReadProcessMemory,hExplorer,hMem,addr tbButton,sizeof TBBUTTON,addr bytesRead
								invoke	ReadProcessMemory,hExplorer,tbButton.dwData,esi,24,addr bytesRead
								mov	eax,[esi]
								stosd				;hwnd
								mov	eax,[esi+4]
								stosd				;ID
								mov	eax,[esi+8]
								stosd				;callback
								mov	eax,[esi+12+8]
								stosd				;hIcon
								pop	ecx
								inc	ecx
							.endw
							add	esp,24
							push	MEM_RELEASE
							push	0
							push	hMem
							push	hExplorer
							call	_VirtualFreeEx
						.endif
						invoke	CloseHandle,hExplorer
					.endif
				.endif
			.endif
		.endif
	.endif
	ret
getTrayData	ENDP

initShell32	PROC
	local	hMem:DWORD,bytesRead:DWORD
	.if _Shell_NotifyIcon==0
		invoke	GetModuleHandle,addr shell32
		.if eax
			push	eax
			invoke	GetProcAddress,eax,addr shell32func1
			pop	edx
			.if eax
				push	edx
				mov	_Shell_NotifyIcon,eax
				mov	edx,[esp]
				invoke	GetProcAddress,edx,addr usericonproc12
				mov	_ExtractIcon,eax
				invoke	GlobalAlloc,GPTR,1024
				mov	hMem,eax
				.while unloaded==0
					invoke	CreateFile,addr pipename,GENERIC_READ or GENERIC_WRITE,0,0,OPEN_EXISTING,0,0
					.break .if eax!=INVALID_HANDLE_VALUE
					invoke	GetLastError
					.if eax==ERROR_PIPE_BUSY
						invoke	WaitNamedPipe,addr pipename,NMPWAIT_WAIT_FOREVER
					.else
						invoke	Sleep,100
					.endif
				.endw
				push	eax
				mov	edx,hMem
				mov	dword ptr[edx],'YART'
				mov	edx,[esp]
				invoke	WriteFile,edx,hMem,4,addr bytesRead,0
				mov	edx,[esp]
				invoke	ReadFile,edx,hMem,1024,addr bytesRead,0
				call	CloseHandle
				pop	eax
				invoke	SetHook,eax,addr shell32func1,offset newnotifyicon,addr savenotifyicon
				push	esi
				mov	esi,hMem
				xor	ecx,ecx
				.while (ecx<256)&&(dword ptr[esi])
					push	ecx
					push	0
					mov	edx,esp
					push	edx
					push	dword ptr[esi]
					call	_GetWindowThreadProcessId
					pop	eax
					.if (eax==_pid)&&(dword ptr[esi+4]!=0)
						invoke	shell_addicon,dword ptr[esi],dword ptr[esi+4],dword ptr[esi+8]
					.endif
					lea	esi,[esi+16]
					pop	ecx
					inc	ecx
				.endw
				pop	esi
				invoke	GlobalFree,hMem
			.endif
		.endif
	.endif
	ret
initShell32	ENDP



createBitmap1	PROC uses ebx edi ptrBmp:DWORD,ptrBmpMask:DWORD
	local	bmp1:BITMAP,hMem:DWORD
	local	hBmp:DWORD,oldBmp:DWORD,oldBmp2:DWORD
	local	hDC:DWORD,hDC2:DWORD
	mov	hBmp,eax
	.if hMainBmp==0
		push	21
		push	hThisInstance
		call	_LoadBitmap
		mov	hMainBmp,eax
		push	22
		push	hThisInstance
		call	_LoadBitmap
		mov	hMainMaskA,eax
		push	23
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_1,eax
		push	24
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_1a,eax
		push	25
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_2,eax
		push	26
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_2a,eax
		push	27
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_3,eax
		push	28
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_3a,eax
		push	29
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_4,eax
		push	30
		push	hThisInstance
		call	_LoadBitmap
		mov	hBmp_4a,eax
	.endif
	lea	eax,bmp1
	push	eax
	push	sizeof BITMAP
	push	hBmp
	call	_GetObjectA
	.if (eax!=0)&&(bmp1.bmHeight>8)
		push	0
		call	_CreateCompatibleDC
		mov	hDC,eax

		push	hBmp
		push	hDC
		call	_SelectObject

		mov	oldBmp,eax
		push	hDC
		call	_CreateCompatibleDC
		mov	hDC2,eax
		mov	eax,ptrBmpMask
		mov	eax,[eax]

		push	eax
		push	hDC2
		call	_SelectObject

		mov	oldBmp2,eax

		push	SRCAND
		push	48
		push	48
		push	0
		push	0
		push	hDC2
		push	bmp1.bmHeight
		push	bmp1.bmWidth
		push	0
		push	0
		push	hDC
		call	_StretchBlt

		mov	eax,ptrBmp
		mov	eax,[eax]

		push	eax
		push	hDC2
		call	_SelectObject

		push	SRCPAINT
		push	48
		push	48
		push	0
		push	0
		push	hDC2
		push	bmp1.bmHeight
		push	bmp1.bmWidth
		push	0
		push	0
		push	hDC
		call	_StretchBlt

		push	oldBmp
		push	hDC
		call	_SelectObject

		push	oldBmp2
		push	hDC2
		call	_SelectObject

		push	hDC2
		call	_DeleteDC
		push	hDC
		call	_DeleteDC

		mov	eax,bmp1.bmWidthBytes
		mov	ecx,bmp1.bmHeight
		xor	edx,edx
		mul	ecx
		push	eax
		invoke	GlobalAlloc,GPTR,eax
		mov	hMem,eax
		pop	edx
		push	eax
		push	edx
		push	hBmp
		call	_GetBitmapBits
		.if eax==0
			invoke	GlobalFree,hMem
			xor	eax,eax
			ret
		.endif
		mov	eax,hMem
		mov	bmp1.bmBits,eax
		lea	eax,bmp1
		push	eax
		call	_CreateBitmapIndirect
		.if hMem
			push	eax
			invoke	GlobalFree,hMem
			pop	eax
		.endif
	.endif
	ret
createBitmap1	ENDP

createIcons	PROC uses esi ebx
	local	iInfo:ICONINFO
	local	hBmp1:DWORD,hBmp2:DWORD
	assume	edi:ptr procWindow
	lea	edx,iInfo
	push	edx
	push	[edi].hIcon
	call	_GetIconInfo
	.if (eax==0)&&([edi].trayID!=0)
		invoke	getWindowIcon1,[edi].hWnd
		mov	[edi].hIcon,eax
		mov	[edi].hOldIcon,eax
		mov	[edi].hIconSm,eax
		mov	[edi].hOldIconSm,eax
		lea	edx,iInfo
		push	edx
		push	eax
		call	_GetIconInfo
	.endif
	.if eax
		mov	eax,iInfo.hbmMask
		mov	hBmp1,eax
		invoke	createBitmap1,addr hMainBmp,addr hMainMaskA
		mov	iInfo.hbmMask,eax
		mov	eax,iInfo.hbmColor
		mov	hBmp2,eax
		invoke	createBitmap1,addr hMainBmp,addr hMainMaskA
		mov	iInfo.hbmColor,eax
		lea	edx,iInfo
		push	edx
		call	_CreateIconIndirect
		mov	[edi].hNewIcon1,eax
		.if [edi].trayID==0
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hNewIcon1s,eax
		.else
			mov	[edi].hNewIcon1s,0
		.endif
		push	iInfo.hbmMask
		call	_DeleteObject
		push	iInfo.hbmColor
		call	_DeleteObject

		mov	eax,hBmp1
		invoke	createBitmap1,addr hBmp_1,addr hBmp_1a
		mov	iInfo.hbmMask,eax
		mov	eax,hBmp2
		invoke	createBitmap1,addr hBmp_1,addr hBmp_1a
		mov	iInfo.hbmColor,eax
		lea	edx,iInfo
		push	edx
		call	_CreateIconIndirect
		mov	[edi].hIcon_4,eax
		.if [edi].trayID
			mov	[edi].hIcon_4s,0
		.else
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIcon_4s,eax
		.endif
		push	iInfo.hbmMask
		call	_DeleteObject
		push	iInfo.hbmColor
		call	_DeleteObject
		push	hBmp1
		call	_DeleteObject
		push	hBmp2
		call	_DeleteObject

		lea	edx,iInfo
		push	edx
		push	[edi].hIcon
		call	_GetIconInfo
		mov	eax,iInfo.hbmMask
		mov	hBmp1,eax
		mov	eax,iInfo.hbmColor
		mov	hBmp2,eax
		mov	eax,hBmp1
		invoke	createBitmap1,addr hBmp_2,addr hBmp_2a
		mov	iInfo.hbmMask,eax
		mov	eax,hBmp2
		invoke	createBitmap1,addr hBmp_2,addr hBmp_2a
		mov	iInfo.hbmColor,eax
		lea	edx,iInfo
		push	edx
		call	_CreateIconIndirect
		mov	[edi].hIcon_3,eax
		.if [edi].trayID
			mov	[edi].hIcon_3s,0
		.else
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIcon_3s,eax
		.endif
		push	iInfo.hbmMask
		call	_DeleteObject
		push	iInfo.hbmColor
		call	_DeleteObject
		push	hBmp1
		call	_DeleteObject
		push	hBmp2
		call	_DeleteObject

		lea	edx,iInfo
		push	edx
		push	[edi].hIcon
		call	_GetIconInfo
		mov	eax,iInfo.hbmMask
		mov	hBmp1,eax
		mov	eax,iInfo.hbmColor
		mov	hBmp2,eax
		mov	eax,hBmp1
		invoke	createBitmap1,addr hBmp_3,addr hBmp_3a
		mov	iInfo.hbmMask,eax
		mov	eax,hBmp2
		invoke	createBitmap1,addr hBmp_3,addr hBmp_3a
		mov	iInfo.hbmColor,eax
		lea	edx,iInfo
		push	edx
		call	_CreateIconIndirect
		mov	[edi].hIcon_2,eax
		.if [edi].trayID
			mov	[edi].hIcon_2s,0
		.else
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIcon_2s,eax
		.endif
		push	iInfo.hbmMask
		call	_DeleteObject
		push	iInfo.hbmColor
		call	_DeleteObject
		push	hBmp1
		call	_DeleteObject
		push	hBmp2
		call	_DeleteObject

		lea	edx,iInfo
		push	edx
		push	[edi].hIcon
		call	_GetIconInfo
		mov	eax,iInfo.hbmMask
		mov	hBmp1,eax
		mov	eax,iInfo.hbmColor
		mov	hBmp2,eax
		mov	eax,hBmp1
		invoke	createBitmap1,addr hBmp_4,addr hBmp_4a
		mov	iInfo.hbmMask,eax
		mov	eax,hBmp2
		invoke	createBitmap1,addr hBmp_4,addr hBmp_4a
		mov	iInfo.hbmColor,eax
		lea	edx,iInfo
		push	edx
		call	_CreateIconIndirect
		mov	[edi].hIcon_1,eax
		.if [edi].trayID
			mov	[edi].hIcon_1s,0
		.else
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIcon_1s,eax
		.endif
		push	iInfo.hbmMask
		call	_DeleteObject
		push	iInfo.hbmColor
		call	_DeleteObject
		push	hBmp1
		call	_DeleteObject
		push	hBmp2
		call	_DeleteObject

		.if [edi].trayID
			mov	[edi].hIcon,0
			mov	[edi].hIconSm,0
		.else
			lea	edx,iInfo
			push	edx
			push	[edi].hIcon
			call	_GetIconInfo
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIcon,eax
			lea	edx,iInfo
			push	edx
			call	_CreateIconIndirect
			mov	[edi].hIconSm,eax
			push	iInfo.hbmMask
			call	_DeleteObject
			push	iInfo.hbmColor
			call	_DeleteObject
			push	hBmp1
			call	_DeleteObject
			push	hBmp2
			call	_DeleteObject
		.endif
	.endif
	assume	edi:nothing
	ret
createIcons	ENDP

initIconUpdate	PROC	uses esi edi	lParam:DWORD
	local	recheck:DWORD
	mov	recheck,0ffffh
	.if sysflags&32
		.if _GetIconInfo==-1
			invoke	ExitThread,0
		.elseif _GetIconInfo==0
			.while 1
				invoke	GetModuleHandle,addr userlib
				.break .if eax
				.if unloaded
					jmp	iconUpdExit
				.endif
				invoke	Sleep,100
			.endw
			mov	esi,eax
			invoke	GetModuleHandle,addr gdi32
			.if eax==0
				invoke	LoadLibrary,addr gdi32
			.endif
			mov	hGdi,eax
			.if hGdi==0
				jmp	iconUpdExit
			.endif
			invoke	GetProcAddress,esi,addr usericonproc1
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_GetIconInfo,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc2
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_FindWindowExA,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc3
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_GetWindowThreadProcessId,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonproc4
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_GetObjectA,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonproc5
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_DeleteObject,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonproc6
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_CreateBitmapIndirect,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc7
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_CreateIconIndirect,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc8
			.if eax
				mov	_LoadIcon,eax
				push	20
				push	hThisInstance
				call	_LoadIcon
				mov	defaultIcon,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc9
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_DestroyIcon,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonprocA
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_GetBitmapBits,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonprocB
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_GetClassLong,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonproc11
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_SetClassLong,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonprocC
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_DeleteDC,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonprocD
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_CreateCompatibleDC,eax
			.endif
			invoke	GetProcAddress,esi,addr usericonprocE
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_LoadBitmap,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonprocF
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_SelectObject,eax
			.endif
			invoke	GetProcAddress,hGdi,addr usericonproc10
			.if eax==0
				jmp	iconUpdExit
			.else
				mov	_StretchBlt,eax
			.endif
			invoke	GetProcAddress,esi,addr strSendMessage
			mov	_SendMessage,eax
		.endif
		check_shell32
		.while unloaded==0
			xor	ecx,ecx
			.while unloaded==0
				push	ecx
				.if nextIcon&&(cl&1)
					.if _SendMessage
						dec	nextIcon
						mov	eax,nextIcon
						push	eax
						lea	esi,procWindows
						xor	ecx,ecx
						.while ecx<MAX_PROC_WINDOWS
							assume	esi:ptr procWindow
							.if [esi].hWnd
								pop	eax
								push	eax
								push	ecx
								lea	edx,[esi+eax*8].hNewIcon1
								mov	ecx,[edx+4]
								mov	edx,[edx]
								invoke	setWindowIcon,[esi].hWnd,edx,ecx,[esi].trayID
								assume	esi:nothing
								pop	ecx
							.endif
							inc	ecx
							lea	esi,[esi+sizeof procWindow]
						.endw
						pop	eax
					.endif
				.endif
				invoke	Sleep,100
				pop	ecx
				inc	ecx
				.break .if ecx>=10
			.endw
			.continue .if nextIcon
			inc	recheck
			.if recheck>=1
				xor	esi,esi
				.while 1
					push	0
					push	0
					push	esi
					push	0
					call	_FindWindowExA
					.break	.if eax==0
					mov	esi,eax
					push	0
					mov	edx,esp
					push	edx
					push	esi
					call	_GetWindowThreadProcessId
					pop	eax
					.if eax==_pid
						mov	recheck,0
						lea	edi,procWindows
						xor	ecx,ecx
						assume	edi:ptr procWindow
						.while ecx<MAX_PROC_WINDOWS
							.break .if esi==[edi].hWnd
							lea	edi,[edi+sizeof procWindow]
							inc	ecx
						.endw
						.if ecx>=MAX_PROC_WINDOWS
							lea	edi,procWindows
							xor	ecx,ecx
							.while ecx<MAX_PROC_WINDOWS
								.break .if [edi].hWnd==0
								lea	edi,[edi+sizeof procWindow]
								inc	ecx
							.endw
							.break .if ecx>=MAX_PROC_WINDOWS
						.endif
						.if [edi].hWnd && ([edi].trayID==0)
							invoke	getWindowIcon,[edi].hWnd
							mov	edx,[edi].hNewIcon1
							.if (eax!=edx)
								lea	ecx,[edi].hNewIcon1
								.if ((eax==[edi].hIcon)||(eax==[edi].hOldIcon)||(eax==[ecx+8])||(eax==[ecx+16])||(eax==[ecx+24])||(eax==[ecx+32]))&&(edx!=0)
									invoke	setWindowIcon,[edi].hWnd,[edi].hNewIcon1,[edi].hNewIcon1s,0
									invoke	getWindowIcon,[edi].hWnd
									.if eax!=[edi].hNewIcon1
										jmp	seticonfailed
									.endif
								.else
					seticonfailed:			.if [edi].hNewIcon1
										.if (eax==defaultIcon)
											invoke	setWindowIcon,[edi].hWnd,[edi].hIcon,[edi].hIconSm,0
											invoke	getWindowIcon,[edi].hWnd
											.if eax!=[edi].hIcon
												invoke	setWindowIcon,[edi].hWnd,[edi].hOldIcon,[edi].hOldIconSm,0
											.else
												push	[edi].hOldIcon
												call	_DestroyIcon
												push	[edi].hOldIconSm
												call	_DestroyIcon
											.endif
										.else
											push	[edi].hOldIcon
											call	_DestroyIcon
											push	[edi].hOldIconSm
											call	_DestroyIcon
											push	[edi].hIcon
											call	_DestroyIcon
											push	[edi].hIconSm
											call	_DestroyIcon
										.endif
										push	[edi].hNewIcon1
										call	_DestroyIcon
										mov	[edi].hNewIcon1,0
										push	[edi].hIcon_1
										call	_DestroyIcon
										mov	[edi].hIcon_1,0
										push	[edi].hIcon_2
										call	_DestroyIcon
										mov	[edi].hIcon_2,0
										push	[edi].hIcon_3
										call	_DestroyIcon
										mov	[edi].hIcon_3,0
										push	[edi].hIcon_4
										call	_DestroyIcon
										mov	[edi].hIcon_4,0
										push	[edi].hNewIcon1s
										call	_DestroyIcon
										mov	[edi].hNewIcon1s,0
										push	[edi].hIcon_1s
										call	_DestroyIcon
										mov	[edi].hIcon_1s,0
										push	[edi].hIcon_2s
										call	_DestroyIcon
										mov	[edi].hIcon_2s,0
										push	[edi].hIcon_3s
										call	_DestroyIcon
										mov	[edi].hIcon_3s,0
										push	[edi].hIcon_4s
										call	_DestroyIcon
										mov	[edi].hIcon_4s,0
									.endif
									mov	[edi].hWnd,0
								.endif
							.endif
						.endif
						.if [edi].hWnd==0
							mov	[edi].hWnd,esi
							invoke	getWindowIcon1,esi
							mov	[edi].hIcon,eax
							mov	[edi].hOldIcon,eax
							mov	[edi].hIconSm,edx
							mov	[edi].hOldIconSm,edx
							mov	[edi].hNewIcon1,0
							mov	[edi].trayID,0
							call	createIcons
							invoke	setWindowIcon,[edi].hWnd,[edi].hNewIcon1,[edi].hNewIcon1s,0
						.endif
						assume	edi:nothing
					.endif
				.endw
				check_shell32
				.continue .if recheck!=0
				lea	esi,procWindows
				xor	ecx,ecx
				.while ecx<MAX_PROC_WINDOWS
					push	ecx
					assume	esi:ptr procWindow
					.if [esi].trayID==0
						push	0
						mov	edx,esp
						push	edx
						push	[esi].hWnd
						call	_GetWindowThreadProcessId
						pop	eax
						.if eax!=_pid
							mov	[esi].hWnd,0
							mov	[esi].trayID,0
							.if (_DestroyIcon!=0)
								.if ([esi].hNewIcon1)
									push	[esi].hNewIcon1
									call	_DestroyIcon
									mov	[esi].hNewIcon1,0
									push	[esi].hIcon_1
									call	_DestroyIcon
									mov	[esi].hIcon_1,0
									push	[esi].hIcon_2
									call	_DestroyIcon
									mov	[esi].hIcon_2,0
									push	[esi].hIcon_3
									call	_DestroyIcon
									mov	[esi].hIcon_3,0
									push	[esi].hIcon_4
									call	_DestroyIcon
									mov	[esi].hIcon_4,0
									push	[esi].hNewIcon1s
									call	_DestroyIcon
									mov	[esi].hNewIcon1s,0
									push	[esi].hIcon_1s
									call	_DestroyIcon
									mov	[esi].hIcon_1s,0
									push	[esi].hIcon_2s
									call	_DestroyIcon
									mov	[esi].hIcon_2s,0
									push	[esi].hIcon_3s
									call	_DestroyIcon
									mov	[esi].hIcon_3s,0
									push	[esi].hIcon_4s
									call	_DestroyIcon
									mov	[esi].hIcon_4s,0
									push	[esi].hOldIcon
									call	_DestroyIcon
									push	[esi].hOldIconSm
									call	_DestroyIcon
									push	[esi].hIcon
									call	_DestroyIcon
									push	[esi].hIconSm
									call	_DestroyIcon
								.endif
							.endif
						.endif
						assume	esi:nothing
					.endif
					pop	ecx
					inc	ecx
					lea	esi,[esi+sizeof procWindow]
				.endw
			.endif
		.endw
	.endif
iconUpdExit:
	mov	_GetIconInfo,-1
	push	iconThread
	mov	iconThread,0
	call	CloseHandle
	invoke	ExitThread,0
	ret
initIconUpdate	ENDP
endm

changeIcon2	macro
	mov	nextIcon,5
endm

changeIcon1	macro
	;mov	nextIcon,2
endm
