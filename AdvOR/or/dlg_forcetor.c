#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "config.h"

int close_all=0;
HANDLE started_processes[10];
HWND hDlgForceTor=NULL,hDlgQuickStart=NULL,hDlgSandboxing=NULL;
HWND hCapturedWindow;
HANDLE hWaitThread=NULL;
HANDLE hCursor=NULL,hOldCursor=NULL;
DWORD pidlist[MAX_PID_LIST];
LV_ITEM lvit;
LV_ITEMW lvitw;
NMLISTVIEW *pnmlv;
char *cmdLineTmp=NULL,*progNameTmp;
extern HANDLE hLibrary;
extern LPFN1 ShowProcesses,TORUnhook,SetGetLangStrCallback,GetProcessChainKey,RegisterPluginKey,UnregisterPluginKey,SetHibernationState;
extern LPFN2 SetProc;
extern LPFN3 TORHook;
extern LPFN12 CreateNewProcess;
extern LPFN4 UnloadDLL,GetAdvORVer;
//extern LPFN5 GetConnInfo;
extern LPFN6 ShowProcessTree;
extern LPFN7 HookProcessTree;
extern LPFN8 PidFromAddr,WarnOpenConnections;
extern LPFN9 ProcessNameFromPid;
extern LPFN11 ShowOpenPorts;
extern LPFN10 GetChainKeyName;
extern LPFN13 CreateThreadEx;
extern or_options_t *tmpOptions;
extern HANDLE hIcon1;
extern HWND hMainDialog;
extern HINSTANCE hInstance;
extern HTREEITEM pages[MAX_PAGE_INDEXES];
//int frame4[]={12400,12010,12011,12100,12401,12402,12403,12404,12405,12406,12407,-1};
lang_dlg_info lang_dlg_force_tor[]={
	{12010,LANG_DLG_PROCESSES},
	{0,0}
};

lang_dlg_info lang_dlg_quick_start[]={
	{12010,LANG_DLG_QUICKSTART_HINT},
	{12001,LANG_DLG_QUICKSTART_ADD},
	{12002,LANG_DLG_QUICKSTART_RUN},
	{12003,LANG_DLG_QUICKSTART_MODIFY},
	{12004,LANG_DLG_QUICKSTART_MOVE_UP},
	{12005,LANG_DLG_QUICKSTART_MOVE_DOWN},
	{12006,LANG_DLG_QUICKSTART_DELETE},
	{0,0}
};

lang_dlg_info lang_dlg_sandboxing[]={
	{12010,LANG_DLG_SANDBOXING_HINT},
	{12011,LANG_DLG_SANDBOXING_LOCAL_ADDRESS_HINT},
	{12012,LANG_DLG_FAKE_LOCAL_ADDRESS},
	{12401,LANG_DLG_FAKE_LOCAL_TIME},
	{12013,LANG_DLG_SANDBOXING_LOCAL_TIME_HINT},
	{12404,LANG_DLG_RESOLVE_TO_FAKE_IPS},
	{12014,LANG_DLG_SANDBOXING_FAKE_IPS_HINT},
	{12405,LANG_DLG_DISALLOW_NON_TCP},
	{12015,LANG_DLG_SANDBOXING_NON_TCP_HINT},
	{12407,LANG_DLG_FORCE_TOR_RESERVED1},
	{12016,LANG_DLG_SANDBOXING_EXCLUSIVE_EXIT_HINT},
	{12406,LANG_DLG_CHANGE_PROCESS_ICON},
	{12017,LANG_DLG_SANDBOXING_PROCESS_ICON_HINT},
	{0,0}
};


lang_dlg_info lang_dlg_pf[]={
	{10,LANG_PF_DLG_HELP},
	{1,LANG_PF_DLG_FORCE},
	{2,LANG_PF_DLG_CANCEL},
	{3,LANG_PF_DLG_CANCEL},
	{0,0}
};

lang_dlg_info lang_dlg_ofn[]={
	{10010,LANG_OFN_DLG_CMDLINE},
	{10400,LANG_OFN_DLG_REMEMBER},
	{10011,LANG_OFN_DLG_PROGNAME},
	{0,0}
};

lang_dlg_info lang_dlg_exit_confirm[]={
	{10,LANG_DLG_CONFIRM_EXIT_1},
	{400,LANG_DLG_CONFIRM_ALWAYS},
	{1,LANG_DLG_CONFIRM_YES},
	{2,LANG_DLG_CONFIRM_NO},
	{0,0}
};


UINT CALLBACK ofnHookProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
UINT CALLBACK ofnHookProcAdd(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void plugins_interceptprocess(DWORD,BOOL);
void dlgForceTor_menuRelease(int item);
void XorWindow(HWND hWnd);
int __stdcall dlgForceTor(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void dlgForceTor_interceptFocusedProcess(void);
void dlgForceTor_releaseFocusedProcess(void);
int addQuickStartItem(config_line_t *cfg);
void updateQuickStartItem(config_line_t *cfg);
void dlgForceTor_unhookAll(void);
void dlgForceTor_interceptNewProcess(void);
void dlgForceTor_addNewProcess(config_line_t *cfg1);
void dlgForceTor_menuAppendHookedProcesses(HMENU hMenu3);
HMENU getProcessesMenu(int tray);
int __stdcall dlgExit(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int canExit(int sysmenu);
void __stdcall wait_thread(LPARAM lParam) __attribute__((noreturn));
void dlgForceTor_scheduledExec(void);
void dlgForceTor_quickStart(void);
void dlgForceTor_quickStartFromMenu(int item);
void dlgForceTor_quickStartClearAll(void);
int __stdcall dlgInterceptProcesses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgSandboxing(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgQuickStart(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void dlgQuickStart_langUpdate(void);

void XorWindow(HWND hWnd)
{	RECT r1;HDC hDC;HPEN hPen,hOldPen;HBRUSH hOldBrush;
	GetWindowRect(hWnd,&r1);
	hDC=GetWindowDC(hWnd);
	SetROP2(hDC,R2_XORPEN);
	hPen=CreatePen(PS_INSIDEFRAME,4,0x870f0f);
	hOldPen=SelectObject(hDC,hPen);
	hOldBrush=SelectObject(hDC,GetStockObject(NULL_BRUSH));
	Rectangle(hDC,0,0,r1.right-r1.left,r1.bottom-r1.top);
	r1.right-=r1.left;r1.left=0;
	r1.bottom-=r1.top;r1.top=0;
	InvertRect(hDC,&r1);
	SelectObject(hDC,hOldPen);
	SelectObject(hDC,hOldBrush);
	ReleaseDC(hWnd,hDC);
	DeleteObject(hPen);
}

int __stdcall dlgForceTor(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{	case WM_INITDIALOG:
			if(LangGetLanguage())
			{	SetWindowTextL(hDlg,LANG_PF_DLG_TITLE);
				changeDialogStrings(hDlg,lang_dlg_pf);
			}
			ShowWindow(GetDlgItem(hDlg,500),SW_HIDE);
			ShowWindow(GetDlgItem(hDlg,12),SW_HIDE);
			ShowWindow(GetDlgItem(hDlg,1),SW_HIDE);
			ShowWindow(GetDlgItem(hDlg,2),SW_HIDE);
			SendDlgItemMessage(hDlg,11,STM_SETICON,(WPARAM)hIcon1,(LPARAM)0);
			SendDlgItemMessage(hDlg,500,TVM_DELETEITEM,0,(LPARAM)TVI_ROOT);
			hCapturedWindow=NULL;
			if(lParam)
			{	Sleep(10);SetTimer(hDlg,100,10,0);
			}
			break;
		case WM_COMMAND:
			if((LOWORD(wParam)==2)||(LOWORD(wParam)==3))
			{	if(GetCapture()==hDlg) ReleaseCapture();
				EndDialog(hDlg,0);
			}
			else if(LOWORD(wParam)==1)
			{	if(GetCapture()==hDlg) ReleaseCapture();
				ShowWindow(hDlg,SW_HIDE);
				if(hCapturedWindow && ((tmpOptions->Confirmations & CONFIRM_VERIFY_CONNECTIONS) != 0) && WarnOpenConnections)
				{	DWORD pid;
					GetWindowThreadProcessId(hCapturedWindow,&pid);
					if(pid)
					{	if(!WarnOpenConnections(pid,tmpOptions->Confirmations & CONFIRM_CLOSE_CONNECTIONS))
						{	EndDialog(hDlg,1);
							return 0;
						}
					}
				}
				if(HookProcessTree)
				{	int i=4|tmpOptions->ForceFlags;
					char *tmp2;
					if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2 = tor_strdup(tmpOptions->LocalHost);
					else							tmp2=tor_strdup("localhost");
					HookProcessTree(GetDlgItem(hDlg,500),(DWORD)tmpOptions->SocksPort,best_delta_t,(DWORD)crypto_rand_int(0x7fffffff),i,tmp2);
					tor_free(tmp2);
				}
				EndDialog(hDlg,1);
			}
			break;
		case WM_MOUSEMOVE:
			if(GetCapture())
			{	POINT p1;HWND testWnd;
				GetCursorPos(&p1);
				testWnd=WindowFromPoint(p1);
				while(GetWindowLong(testWnd,GWL_STYLE)&WS_CHILD) testWnd=GetParent(testWnd);
				if((testWnd!=hCapturedWindow)&&(testWnd!=hDlg)&&(testWnd!=hMainDialog))
				{	if(hCapturedWindow) XorWindow(hCapturedWindow);
					hCapturedWindow=testWnd;
					XorWindow(hCapturedWindow);
					LPWSTR tmp1=tor_malloc(400);
					GetWindowTextW(hCapturedWindow,tmp1,200);
					SetDlgItemTextW(hDlg,12,tmp1);
					tor_free(tmp1);
					if(ShowProcessTree) ShowProcessTree(hCapturedWindow,GetDlgItem(hDlg,500));
				}
			}
			break;
		case WM_LBUTTONUP:
			if(hCapturedWindow)
			{	XorWindow(hCapturedWindow);
				InvalidateRect(0,0,1);
				if(hOldCursor) SetCursor(hOldCursor);
				ReleaseCapture();
			}
			break;
		case WM_TIMER:
			KillTimer(hDlg,100);
		case WM_LBUTTONDOWN:
			ShowWindow(GetDlgItem(hDlg,500),SW_SHOW);
			ShowWindow(GetDlgItem(hDlg,12),SW_SHOW);
			ShowWindow(GetDlgItem(hDlg,1),SW_SHOW);
			ShowWindow(GetDlgItem(hDlg,2),SW_SHOW);
			ShowWindow(GetDlgItem(hDlg,3),SW_HIDE);
			ShowWindow(GetDlgItem(hDlg,10),SW_HIDE);
			ShowWindow(GetDlgItem(hDlg,11),SW_HIDE);
			SetCapture(hDlg);
			if(hCursor==NULL) hCursor=LoadCursor(hInstance,(LPCTSTR)10);
			if(hOldCursor==NULL) hOldCursor=LoadCursor(NULL,IDC_ARROW);
			SetCursor(hCursor);
			break;
	}
	return	0;
}

void dlgForceTor_interceptFocusedProcess(void)
{	HWND testWnd=GetForegroundWindow();
	DWORD pid=0;
	while(GetWindowLong(testWnd,GWL_STYLE)&WS_CHILD) testWnd=GetParent(testWnd);
	GetWindowThreadProcessId(testWnd,&pid);
	if(pid && pid != GetCurrentProcessId())
	{	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
		lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
		int i=0;
		char *tmp1 = tor_malloc(500);
		char *processname = tor_malloc(200);
		processname[0] = 0;
		getProcessName(processname,200,pid);
		while(i<MAX_PID_LIST)
		{	lvit.lParam=0;
			if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
			if((DWORD)lvit.lParam==pid)
			{	if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
				{	i = -1;	break;
				}
			}
			lvit.iItem++;
		}
		if(i==-1)	tor_snprintf(tmp1,500,get_lang_str(LANG_MB_ALREADY_INTERCEPTED),processname);
		else
		{	if(((tmpOptions->Confirmations & CONFIRM_VERIFY_CONNECTIONS) != 0) && WarnOpenConnections)
			{	if(!WarnOpenConnections(pid,tmpOptions->Confirmations & CONFIRM_CLOSE_CONNECTIONS))
				{	tor_free(tmp1);
					tor_free(processname);
					return;
				}
			}
			i=4|tmpOptions->ForceFlags;
			char *tmp2=tor_malloc(256);
			tor_snprintf(tmp2,255,"%s",tmpOptions->LocalHost);
			if(TORHook(pid,(HANDLE)tmpOptions->SocksPort,i,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff)))
			{	lvit.mask=LVIF_STATE;
				lvit.state=4096;
				lvit.stateMask=LVIS_STATEIMAGEMASK;
				SendDlgItemMessage(hDlgForceTor,12400,LVM_SETITEMSTATE,lvit.iItem,(LPARAM)&lvit);
				tor_snprintf(tmp1,500,get_lang_str(LANG_MB_INTERCEPT_SUCCESS),processname);
			}
			else	tor_snprintf(tmp1,500,get_lang_str(LANG_MB_INTERCEPT_FAIL),processname);
			tor_free(tmp2);
		}
		LangMessageBox(NULL,tmp1,LANG_DLG_SYSTEM_HOTKEY_INTERCEPT,MB_OK|MB_TASKMODAL|MB_SETFOREGROUND);
		tor_free(tmp1);
		tor_free(processname);
	}
}

void dlgForceTor_releaseFocusedProcess(void)
{	HWND testWnd=GetForegroundWindow();
	DWORD pid=0;
	while(GetWindowLong(testWnd,GWL_STYLE)&WS_CHILD) testWnd=GetParent(testWnd);
	GetWindowThreadProcessId(testWnd,&pid);
	if(pid && pid != GetCurrentProcessId())
	{	pidlist[0] = pid;
		dlgForceTor_menuRelease(0);
	}
}

UINT CALLBACK ofnHookProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())	changeDialogStrings(hDlg,lang_dlg_ofn);
		if(get_options()->ForceFlags&4) CheckDlgButton(hDlg,10400,BST_CHECKED);
		else
		{	EnableWindow(GetDlgItem(hDlg,10011),0);
			EnableWindow(GetDlgItem(hDlg,10101),0);
		}
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==10400)
		{	if(IsDlgButtonChecked(hDlg,10400)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10011),1);
				EnableWindow(GetDlgItem(hDlg,10101),1);
				get_options()->ForceFlags|=4;
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10011),0);
				EnableWindow(GetDlgItem(hDlg,10101),0);
				get_options()->ForceFlags&=4^0xffff;
			}
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	NMHDR *hdr=(NMHDR*)lParam;
		if(hdr->code==CDN_FILEOK)
		{	LPWSTR cmdLineW,progNameW;
			cmdLineW = tor_malloc(1024);progNameW = tor_malloc(1024);
			GetDlgItemTextW(hDlg,10100,cmdLineW,255);
			GetDlgItemTextW(hDlg,10101,progNameW,255);
			cmdLineTmp = get_utf(cmdLineW);
			progNameTmp = get_utf(progNameW);
			tor_free(cmdLineW);
			tor_free(progNameW);
		}
	}
	return 0;
}

UINT CALLBACK ofnHookProcAdd(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())	changeDialogStrings(hDlg,lang_dlg_ofn);
		CheckDlgButton(hDlg,10400,BST_CHECKED);
		if(cmdLineTmp)
		{	SetDlgItemTextL(hDlg,10100,cmdLineTmp);
			tor_free(cmdLineTmp);cmdLineTmp = NULL;
		}
		if(progNameTmp)
		{	SetDlgItemTextL(hDlg,10101,progNameTmp);
			tor_free(progNameTmp);progNameTmp = NULL;
		}
		else	EnableWindow(GetDlgItem(GetParent(hDlg),1),0);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==10400)
		{	if(IsDlgButtonChecked(hDlg,10400)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10011),1);
				EnableWindow(GetDlgItem(hDlg,10101),1);
				get_options()->ForceFlags|=4;
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10011),0);
				EnableWindow(GetDlgItem(hDlg,10101),0);
				get_options()->ForceFlags&=4^0xffff;
			}
		}
		else if(LOWORD(wParam)==10101 && HIWORD(wParam)==EN_CHANGE)
		{	if(SendDlgItemMessage(hDlg,10101,WM_GETTEXTLENGTH,0,0))	EnableWindow(GetDlgItem(GetParent(hDlg),1),1);
			else							EnableWindow(GetDlgItem(GetParent(hDlg),1),0);
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	NMHDR *hdr=(NMHDR*)lParam;
		if(hdr->code==CDN_FILEOK)
		{	if(SendDlgItemMessage(hDlg,10101,WM_GETTEXTLENGTH,0,0))
			{	LPWSTR cmdLineW,progNameW;
				cmdLineW = tor_malloc(1024);progNameW = tor_malloc(1024);
				GetDlgItemTextW(hDlg,10100,cmdLineW,255);
				GetDlgItemTextW(hDlg,10101,progNameW,255);
				cmdLineTmp = get_utf(cmdLineW);
				progNameTmp = get_utf(progNameW);
				tor_free(cmdLineW);
				tor_free(progNameW);
			}
			else
			{	SetWindowLong(hDlg,DWL_MSGRESULT,1);
				return 1;
			}
		}
	}
	return 0;
}

int addQuickStartItem(config_line_t *cfg)
{	char *tmp1,*tmp2;
	int i,j;
	if(!hDlgQuickStart)	return -1;
	tmp2=tor_malloc(256);
	tmp1=(char *)cfg->value;tmp2[0]=0;
	for(i=0;(*tmp1!='=')&&*tmp1&&i<255;tmp1++)	tmp2[i++]=*tmp1;
	tmp2[i]=0;
	lvitw.iSubItem=0;lvitw.mask=LVIF_TEXT|LVIF_PARAM;lvitw.state=0;lvitw.stateMask=0;lvitw.iImage=0;
	lvitw.lParam=(LPARAM)cfg;
	LPWSTR appname = get_unicode(tmp2);
	lvitw.pszText=appname;
	lvitw.cchTextMax=256;
	i=SendDlgItemMessageW(hDlgQuickStart,12400,LVM_INSERTITEMW,0,(LPARAM)&lvitw);
	if(i!=-1)
	{	lvitw.iItem=i;
		for(;*tmp1!='=' && *tmp1;tmp1++)	;
		if(*tmp1=='=')	tmp1++;
		while(tmp1[0]==32 || tmp1[0]==',' || (tmp1[0]>='0'&&tmp1[0]<='9'))	tmp1++;
		if(tmp1[0]==34)
		{	tmp1++;
			for(j=0;j<256 && tmp1[j] && tmp1[j]!=34;j++)	tmp2[j] = tmp1[j];
		}
		else
		{	for(j=0;j<256 && tmp1[j];j++)	tmp2[j] = tmp1[j];
		}
		tmp2[j] = 0;
		LangSetLVItem(hDlgQuickStart,12400,lvitw.iItem,1,tmp2);
		lvitw.iItem++;
	}
	tor_free(appname);
	tor_free(tmp2);
	return i;
}

void updateQuickStartItem(config_line_t *cfg)
{	char *tmp1,*tmp2;
	int i,j;
	if(!hDlgQuickStart)	return;
	lvitw.iItem = 0;
	while(1)
	{	lvitw.mask = LVIF_PARAM;
		lvitw.iSubItem = 0;
		lvitw.lParam = 0;
		if(!SendDlgItemMessageW(hDlgQuickStart,12400,LVM_GETITEMW,0,(LPARAM)&lvitw))	return;
		if(lvitw.lParam == (LPARAM)cfg)	break;
		lvitw.iItem++;
	}
	tmp2=tor_malloc(256);
	tmp1=(char *)cfg->value;tmp2[0]=0;
	for(i=0;(*tmp1!='=')&&*tmp1&&i<255;tmp1++)	tmp2[i++]=*tmp1;
	tmp2[i]=0;
	LangSetLVItem(hDlgQuickStart,12400,lvitw.iItem,0,tmp2);
	for(;*tmp1!='=' && *tmp1;tmp1++)	;
	if(*tmp1=='=')	tmp1++;
	while(tmp1[0]==32 || tmp1[0]==',' || (tmp1[0]>='0'&&tmp1[0]<='9'))	tmp1++;
	if(tmp1[0]==34)
	{	tmp1++;
		for(j=0;j<256 && tmp1[j] && tmp1[j]!=34;j++)	tmp2[j] = tmp1[j];
	}
	else
	{	for(j=0;j<256 && tmp1[j];j++)	tmp2[j] = tmp1[j];
	}
	tmp2[j] = 0;
	LangSetLVItem(hDlgQuickStart,12400,lvitw.iItem,1,tmp2);
	lvitw.iItem++;
	tor_free(tmp2);
}

void dlgForceTor_menuRelease(int item)
{	char *tmp1=tor_malloc(500);
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	lvit.lParam=pidlist[item];
	if((lvit.lParam)&&(TORUnhook))
	{	if(TORUnhook(lvit.lParam))
		{	tor_snprintf(tmp1,500,get_lang_str(LANG_MB_PID_RELEASED),(int)lvit.lParam);
			LangMessageBox(NULL,tmp1,LANG_MB_RELEASE,MB_OK|MB_TASKMODAL|MB_SETFOREGROUND);
		}
		else
		{	tor_snprintf(tmp1,500,get_lang_str(LANG_MB_RELEASE_ERROR),(int)lvit.lParam);
			LangMessageBox(NULL,tmp1,LANG_MB_RELEASE,MB_OK|MB_TASKMODAL|MB_SETFOREGROUND);
		}
	}
	tor_free(tmp1);
}

void dlgForceTor_unhookAll(void)
{	HANDLE hLib=hLibrary;hLibrary=NULL;
	GetConnInfo=NULL;ShowProcessTree=NULL;HookProcessTree=NULL;GetAdvORVer=NULL;ShowOpenPorts=NULL;PidFromAddr=NULL;ProcessNameFromPid=NULL;GetProcessChainKey=NULL;GetChainKeyName=NULL;RegisterPluginKey=NULL;UnregisterPluginKey=NULL;SetHibernationState=NULL;CreateThreadEx=NULL;
	if(hLib)
	{	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
		ShowProcesses=NULL;
		lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
		while(1)
		{	lvit.lParam=0;
			if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
			if((lvit.lParam)&&(TORUnhook))
			{	if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
				{	TORUnhook(lvit.lParam);
				}
			}
			lvit.iItem++;
		}
		if(UnloadDLL) UnloadDLL();
		UnloadDLL=NULL;
		TORUnhook=NULL;TORHook=NULL;
		CreateNewProcess=NULL;
		FreeLibrary(hLib);
	}
}

HMENU getProcessesMenu(int tray)
{	HMENU hMenu=CreatePopupMenu();int i,currentOption=0;
	char *tmp2=tor_malloc(256);
	config_line_t *cfg;
	for(cfg=tmpOptions->QuickStart;cfg;cfg=cfg->next)
	{	char *tmp1=(char *)cfg->value;tmp2[0]=0;
		if(tmp1)
		{	for(i=0;(*tmp1!='=')&&*tmp1;tmp1++)	tmp2[i++]=*tmp1;
			tmp2[i]=0;
		}
		LangAppendMenuStr(hMenu,MF_STRING,23000+currentOption,tmp2);
		currentOption++;
	}
	if(currentOption||tray)
	{	if(currentOption) AppendMenu(hMenu,MF_SEPARATOR,0,0);
		if(tray) LangAppendMenu(hMenu,MF_STRING,12402,LANG_MENU_INTERCEPT);
		LangAppendMenu(hMenu,MF_STRING,22999,LANG_MENU_CLEAR_LIST);
	}
	tor_free(tmp2);
	return hMenu;
}

WCHAR fnFilter[]=L"Executable files (*.exe,*.pif,*.cmd,*.lnk)\0*.exe;*.pif;*.cmd;*.lnk\0All files\0*.*\0\0";
void dlgForceTor_interceptNewProcess(void)
{	OPENFILENAMEW ofn;
	LPWSTR fileName;
	ZeroMemory(&ofn,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=hMainDialog;
	ofn.hInstance=hInstance;
	ofn.lpstrFilter=fnFilter;
	fileName=tor_malloc(8192);fileName[0]=0;
	ofn.lpstrFile=fileName;
	ofn.nMaxFile=4096;
	ofn.Flags=OFN_EXPLORER|OFN_ENABLETEMPLATE|OFN_ENABLEHOOK|OFN_HIDEREADONLY|OFN_NOCHANGEDIR|OFN_NODEREFERENCELINKS;
	ofn.lpTemplateName=MAKEINTRESOURCEW(1010);
	ofn.lpfnHook=ofnHookProc;tmpOptions->ForceFlags&=4^0xffff;
	cmdLineTmp=NULL;progNameTmp=NULL;
	if(GetOpenFileNameW(&ofn))
	{	char *exeName = get_utf(fileName);
		char *tmp1=tor_malloc(strlen(exeName)+1024),*tmp2,*tmp3;tmp2=exeName;
		int i;
		config_line_t *cfg;
		if(get_file_attributes(exeName)&FILE_ATTRIBUTE_DIRECTORY)
		{	{ for(;*tmp2;tmp2++)	; }
			{ for(;(tmp2>exeName)&&(*tmp2!='\\')&&(*tmp2!='/');tmp2--)	; }
			if((*tmp2=='\\')||(*tmp2=='/')) tmp2++;
		}
		for(tmp3=progNameTmp;*tmp3;tmp3++)
		{	if(*tmp3==34) *tmp3=39;
			else if(*tmp3=='=') *tmp3=':';
		}
		i=4|tmpOptions->ForceFlags;
		tor_snprintf(tmp1,strlen(exeName)+1024,"%s=%d,\"%s\" %s",progNameTmp,i,tmp2,cmdLineTmp);
		if(tmpOptions->ForceFlags&4)
		{	if(tmpOptions->QuickStart)
			{	{ for(cfg=tmpOptions->QuickStart;cfg->next;cfg=cfg->next); }
				cfg->next=tor_malloc_zero(sizeof(config_line_t));
				cfg=cfg->next;
			}
			else
			{	cfg=tor_malloc_zero(sizeof(config_line_t));
				tmpOptions->QuickStart=cfg;
			}
			cfg->key = (unsigned char *)tor_strdup("QuickStart");
			cfg->value=(unsigned char *)tor_strdup(tmp1);
			if(hDlgQuickStart)
				lvitw.iItem = SendDlgItemMessage(hDlgQuickStart,12400,LVM_GETITEMCOUNT,0,0);
			addQuickStartItem(cfg);
			cfg=NULL;
		}
		tor_free(exeName);
		tmp2=tor_malloc(256);
		tor_snprintf(tmp2,255,"%s",tmpOptions->LocalHost);
		if(CreateNewProcess) CreateNewProcess((DWORD)tmp1,(HANDLE)tmpOptions->SocksPort,i,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
		tor_free(tmp1);tor_free(tmp2);
	}
	tor_free(fileName);
	if(cmdLineTmp){ tor_free(cmdLineTmp);cmdLineTmp=NULL;}
	if(progNameTmp){ tor_free(progNameTmp);progNameTmp=NULL;}
}

void dlgForceTor_addNewProcess(config_line_t *cfg1)
{	OPENFILENAMEW ofn;
	LPWSTR fileName;
	int i,j;
	ZeroMemory(&ofn,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=hMainDialog;
	ofn.hInstance=hInstance;
	ofn.lpstrFilter=fnFilter;
	fileName=tor_malloc(8192);fileName[0]=0;
	if(cfg1)
	{	if(!cfg1->value)	return;
		char *tmp1;
		LPWSTR tmp2;
		cmdLineTmp = tor_malloc(1024);
		cmdLineTmp[0] = 0;
		progNameTmp = tor_malloc(1024);
		for(i=0;cfg1->value[i] && cfg1->value[i]!='=' && i<1023;i++)
		{	progNameTmp[i] = cfg1->value[i];
		}
		progNameTmp[i] = 0;
		for(;cfg1->value[i] && cfg1->value[i]!='=';i++);
		if(cfg1->value[i]=='=')	i++;
		while(cfg1->value[i]==32 || cfg1->value[i]==',' || (cfg1->value[i]>='0' && cfg1->value[i]<='9'))	i++;
		tmp1 = tor_malloc(1024);
		if(cfg1->value[i]==34)
		{	i++;j=0;
			while(cfg1->value[i]!=34 && cfg1->value[i] && j<1023)
			{	tmp1[j] = cfg1->value[i];
				i++;j++;
			}
			tmp1[j] = 0;
			tmp2 = get_unicode(tmp1);tor_free(tmp1);
			while(cfg1->value[i]!=34 && cfg1->value[i])	i++;
			if(cfg1->value[i] == 34)	i++;
		}
		else
		{	j=0;
			while(cfg1->value[i]>32 && j<1023)
			{	tmp1[j] = cfg1->value[i];
				i++;j++;
			}
			tmp1[j] = 0;
			tmp2 = get_unicode(tmp1);tor_free(tmp1);
			while(cfg1->value[i]>32)	i++;
		}
		while(cfg1->value[i] == 32)	i++;
		if(cfg1->value[i])	tor_snprintf(cmdLineTmp,1023,"%s",cfg1->value + i);
		for(i=0;tmp2[i] && i<4095;i++)	fileName[i] = tmp2[i];
		fileName[i] = 0;
	}
	else
	{	cmdLineTmp=NULL;progNameTmp=NULL;
	}
	ofn.lpstrFile=fileName;
	ofn.nMaxFile=4096;
	ofn.Flags=OFN_EXPLORER|OFN_ENABLETEMPLATE|OFN_ENABLEHOOK|OFN_HIDEREADONLY|OFN_NOCHANGEDIR|OFN_NODEREFERENCELINKS;
	ofn.lpTemplateName=MAKEINTRESOURCEW(1010);
	ofn.lpfnHook=ofnHookProcAdd;tmpOptions->ForceFlags&=4^0xffff;
	if(GetOpenFileNameW(&ofn) && progNameTmp && progNameTmp[0])
	{	char *exeName = get_utf(fileName);
		char *tmp1=tor_malloc(strlen(exeName)+1024),*tmp2,*tmp3;tmp2=exeName;
		config_line_t *cfg;
		if(get_file_attributes(exeName)&FILE_ATTRIBUTE_DIRECTORY)
		{	{ for(;*tmp2;tmp2++)	; }
			{ for(;(tmp2>exeName)&&(*tmp2!='\\')&&(*tmp2!='/');tmp2--)	; }
			if((*tmp2=='\\')||(*tmp2=='/')) tmp2++;
		}
		for(tmp3=progNameTmp;*tmp3;tmp3++)
		{	if(*tmp3==34) *tmp3=39;
			else if(*tmp3=='=') *tmp3=':';
		}
		i=4|tmpOptions->ForceFlags;
		tor_snprintf(tmp1,strlen(exeName)+1024,"%s=%d,\"%s\" %s",progNameTmp,i,tmp2,cmdLineTmp);
		if(cfg1)
		{	char *tmp4 = (char *)cfg1->value;
			cfg1->value = (unsigned char *)tor_strdup(tmp1);
			tor_free(tmp4);
			updateQuickStartItem(cfg1);
		}
		else
		{	if(tmpOptions->QuickStart)
			{	{ for(cfg=tmpOptions->QuickStart;cfg->next;cfg=cfg->next); }
				cfg->next=tor_malloc_zero(sizeof(config_line_t));
				cfg=cfg->next;
			}
			else
			{	cfg=tor_malloc_zero(sizeof(config_line_t));
				tmpOptions->QuickStart=cfg;
			}
			cfg->key = (unsigned char *)tor_strdup("QuickStart");
			cfg->value=(unsigned char *)tor_strdup(tmp1);
			lvitw.iItem = SendDlgItemMessage(hDlgQuickStart,12400,LVM_GETITEMCOUNT,0,0);
			addQuickStartItem(cfg);
		}
		cfg=NULL;
		tor_free(exeName);
		tor_free(tmp1);
	}
	tor_free(fileName);
	if(cmdLineTmp){ tor_free(cmdLineTmp);cmdLineTmp=NULL;}
	if(progNameTmp){ tor_free(progNameTmp);progNameTmp=NULL;}
}

void dlgForceTor_menuAppendHookedProcesses(HMENU hMenu3)
{	LV_ITEMW lvitw2;
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	LPWSTR tmpMenu=tor_malloc(200);
	char *tmpMenu1=tor_malloc(200);
	lvitw2.iItem=0;
	lvitw2.iSubItem=0;
	lvitw2.mask=LVIF_PARAM|LVIF_TEXT;
	lvitw2.cchTextMax=99;
	lvitw2.pszText=tmpMenu;
	int i=0;
	while(i<MAX_PID_LIST)
	{	lvitw2.lParam=0;
		if(SendDlgItemMessageW(hDlgForceTor,12400,LVM_GETITEMW,0,(LPARAM)&lvitw2)==0) break;
		if(lvitw2.lParam)
		{	if(SendDlgItemMessageW(hDlgForceTor,12400,LVM_GETITEMSTATE,lvitw2.iItem,LVIS_STATEIMAGEMASK)&8192)
			{	char *utfstr = get_utf(tmpMenu);
				tor_snprintf(tmpMenu1,200,"%s (PID: %d)",utfstr,(int)lvitw2.lParam);
				tor_free(utfstr);
				LangAppendMenuStr(hMenu3,MF_STRING,22000+i,tmpMenu1);pidlist[i]=lvitw2.lParam;i++;
			}
		}
		lvitw2.iItem++;
	}
	tor_free(tmpMenu);tor_free(tmpMenu1);
}

int confirmed = 0;
int __stdcall dlgExit(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_INITDIALOG)
	{	char *msgp = tor_malloc(4096);
		changeDialogStrings(hDlg,lang_dlg_exit_confirm);
		if(lParam)
		{	char *processes = (char *)lParam;
			confirmed = 2;
			tor_snprintf(msgp,4096,"%s\r\n%s\r\n%s\r\n%s",get_lang_str(LANG_DLG_CONFIRM_EXIT_2),processes,get_lang_str(LANG_DLG_CONFIRM_EXIT_3),get_lang_str(LANG_DLG_CONFIRM_EXIT_1));
		}
		else
		{	confirmed = 0;
			tor_snprintf(msgp,4096,"\r\n\r\n\r\n\t%s",get_lang_str(LANG_DLG_CONFIRM_EXIT_1));
		}
		LangSetWindowText(GetDlgItem(hDlg,10),msgp);
		tor_free(msgp);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==2)
		{	confirmed = 2;
			EndDialog(hDlg,0);
		}
		else if(LOWORD(wParam)==1)
		{	if(IsDlgButtonChecked(hDlg,400)==BST_CHECKED)
			{	if(confirmed==2)	tmpOptions->Confirmations &= CONFIRM_EXIT ^ 0xffff;
				else			tmpOptions->Confirmations |= CONFIRM_EXIT_ONLY_RELEASE;
			}
			confirmed = 1;
			EndDialog(hDlg,1);
		}
	}
	return 0;
}

int canExit(int sysmenu)
{	char *processes,*s;
	int i;
	if(confirmed)
	{	confirmed &= 1;
		return confirmed;
	}
	i = 0;
	if(close_all)
	{	if(hWaitThread)	TerminateThread(hWaitThread,0);
		if(hLibrary)
		{	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
			lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
			while(1)
			{	lvit.lParam=0;
				if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
				if(lvit.lParam)
				{	if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
					{	HANDLE hProcess=OpenProcess(PROCESS_TERMINATE,0,lvit.lParam);
						if(hProcess)
						{	TerminateProcess(hProcess,0);
							CloseHandle(hProcess);
						}
					}
				}
				lvit.iItem++;
			}
		}
		return 1;
	}
	if((tmpOptions->Confirmations & CONFIRM_EXIT) == 0)	return 1;
	processes = malloc(2048);
	s = processes;
	if(hLibrary)
	{	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
		lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
		while(i<5)
		{	lvit.lParam=0;
			if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
			if(lvit.lParam)
			{	if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
				{	*s++=9;
					getProcessName(s,200,lvit.lParam);s += strlen(s);
					tor_snprintf(s,20,"\tPID: %u\r\n",(unsigned int)lvit.lParam);
					s += strlen(s);
					i++;
				}
			}
			lvit.iItem++;
		}
		if(i>=5){	*s++=9;*s++='.';*s++='.';*s++='.';}
		*s=0;
	}
	if(!i){	free(processes);processes = NULL;}
	if(!processes && ((tmpOptions->Confirmations&CONFIRM_EXIT_ONLY_RELEASE)!=0))	return 1;
	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1013),hMainDialog,&dlgExit,(LPARAM)processes);
	if(processes)	free(processes);
	if(!sysmenu)	confirmed &= 1;
	return confirmed&1;
}

void __stdcall wait_thread(LPARAM lParam)
{	(void) lParam;
	int i;
	for(i=0;i<10;i++)
	{	if(started_processes[i]==0)	break;
	}
	WaitForMultipleObjects(i,&started_processes[0],0,INFINITE);
	if(hMainDialog)	PostMessage(hMainDialog,WM_SYSCOMMAND,SC_CLOSE,0);
	ExitThread(0);
}

smartlist_t *scheduled_progs = NULL;
void dlgForceTor_scheduleExec(char *prog)
{	if(!scheduled_progs)
		scheduled_progs = smartlist_create();
	smartlist_add(scheduled_progs,tor_strdup(prog));
}

void dlgForceTor_scheduledExec(void)
{
	char *tmp2=NULL;
	if(scheduled_progs)
	{	if(CreateNewProcess)
		{	SMARTLIST_FOREACH(scheduled_progs,char*,prog,
			{
				if(!tmp2)
				{	if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2=tor_strdup(tmpOptions->LocalHost);
					else							tmp2=tor_strdup("localhost");
				}
				char *tmp1 = tor_malloc(strlen(prog)+1024);
				tor_snprintf(tmp1,strlen(prog)+1023,"=%d,\"%s\"",4|tmpOptions->ForceFlags,prog);
				CreateNewProcess((DWORD)tmp1,(HANDLE)tmpOptions->SocksPort,4|tmpOptions->ForceFlags,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
				tor_free(tmp1);
			});
			if(tmp2)	tor_free(tmp2);
		}
		SMARTLIST_FOREACH(scheduled_progs,char *,prog,tor_free(prog));
		smartlist_free(scheduled_progs);
		scheduled_progs = NULL;
	}
}

void dlgForceTor_quickStart(void)
{	if(tmpOptions->QuickStart && CreateNewProcess)
	{	config_line_t *cfg,*cfg2;
		char *tmp2=NULL;
		for(cfg=tmpOptions->QuickStart;cfg;cfg=cfg->next)
		{	if(cfg->value)
			{	if(!strchr((char *)cfg->value, '='))
				{	if(!tmp2)
					{	if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2=tor_strdup(tmpOptions->LocalHost);
						else							tmp2=tor_strdup("localhost");
					}
					for(cfg2=tmpOptions->QuickStart;cfg2;cfg2=cfg2->next)
					{	if(!strcasecmpstart((char *)cfg2->value,(char *)cfg->value) && strchr((char *)cfg2->value, '='))
						{	CreateNewProcess((DWORD)cfg2->value,(HANDLE)tmpOptions->SocksPort,4|tmpOptions->ForceFlags,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
							break;
						}
					}
				}
			}
		}
		if(tmp2)
		{	tor_free(tmp2);
			if(IsWindowVisible(hMainDialog))
			{	SendDlgItemMessage(hMainDialog,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_DEBUG]);
			}
			cfg=tmpOptions->QuickStart;
			while(cfg)
			{	if(!strchr((char *)cfg->value, '='))
				{	tor_free(cfg->key);tor_free(cfg->value);
					tmpOptions->QuickStart=cfg->next;
					tor_free(cfg);cfg=tmpOptions->QuickStart;
				}
				else break;
			}
			for(cfg=tmpOptions->QuickStart;cfg&&cfg->next;)
			{	cfg2=cfg->next;
				if(!strchr((char *)cfg2->value, '='))
				{	tor_free(cfg2->key);tor_free(cfg2->value);
					cfg->next=cfg2->next;
					tor_free(cfg2);
				}
				else cfg=cfg->next;
			}
		}
	}
	if(tmpOptions->SynchronizeExit && CreateNewProcess)
	{	config_line_t *cfg,*cfg2;
		char *tmp2=NULL;
		int i=0;
		for(cfg=tmpOptions->SynchronizeExit;cfg && i<10;cfg=cfg->next)
		{	if(cfg->value)
			{	if(!tmp2)
				{	if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2=tor_strdup(tmpOptions->LocalHost);
					else							tmp2=tor_strdup("localhost");
				}
				for(cfg2=tmpOptions->QuickStart;cfg2;cfg2=cfg2->next)
				{	if(!strcasecmpstart((char *)cfg2->value,(char *)cfg->value) && strchr((char *)cfg2->value, '='))
					{	started_processes[i] = CreateNewProcess((DWORD)cfg2->value,(HANDLE)tmpOptions->SocksPort,4|tmpOptions->ForceFlags,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
						i++;
						break;
					}
				}
			}
		}
		while(i<10)
		{	started_processes[i] = NULL;
			i++;
		}
		if(tmp2)
		{	DWORD thr_id;
			close_all++;
			hWaitThread=CreateThread(0,0,(LPTHREAD_START_ROUTINE)wait_thread,0,0,(LPDWORD)&thr_id);
			tor_free(tmp2);
			if(IsWindowVisible(hMainDialog))
			{	SendDlgItemMessage(hMainDialog,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_DEBUG]);
			}
		}
	}
	dlgForceTor_scheduledExec();
}

void dlgForceTor_quickStartFromMenu(int item)
{	config_line_t *cfg;
	for(cfg=tmpOptions->QuickStart;item&&cfg;cfg=cfg->next)	item--;
	item=4|tmpOptions->ForceFlags;
	char *tmp2;
	if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2 = tor_strdup(tmpOptions->LocalHost);
	else							tmp2=tor_strdup("localhost");
	if(cfg&&cfg->value)
	{	if(CreateNewProcess) CreateNewProcess((DWORD)cfg->value,(HANDLE)tmpOptions->SocksPort,item,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
		if(IsWindowVisible(hMainDialog))
		{	SendDlgItemMessage(hMainDialog,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_DEBUG]);
		}
	}
	tor_free(tmp2);
}

void dlgForceTor_quickStartClearAll(void)
{	config_line_t *cfg;
	for(;;)
	{	cfg=tmpOptions->QuickStart;
		if(cfg==NULL) break;
		tor_free(cfg->key);tor_free(cfg->value);
		tmpOptions->QuickStart=cfg->next;
		tor_free(cfg);
	}
	if(hDlgQuickStart)
		SendDlgItemMessage(hDlgQuickStart,12400,LVM_DELETEALLITEMS,0,0);
}

int __stdcall dlgInterceptProcesses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlgForceTor=hDlg;
		if(LangGetLanguage())	changeDialogStrings(hDlg,lang_dlg_force_tor);
	}
	else if(uMsg==WM_TIMER)
	{	if((wParam==100)&&(ShowProcesses))	ShowProcesses((DWORD)hDlg);
	}
	else if(uMsg==WM_USER+10 || uMsg==WM_USER+14)
		PostMessage(hMainDialog,uMsg,wParam,lParam);
	else if(uMsg==WM_USER+11)
		plugins_interceptprocess(wParam,lParam);
	else if(uMsg==WM_NOTIFY)
	{	if(wParam==12400)
		{	pnmlv=(LPNMLISTVIEW)lParam;
			NMHDR *hdr=(LPNMHDR)lParam;
			if((hdr->code==LVN_ITEMCHANGED)&&(pnmlv->uChanged&LVIF_STATE)&&(pnmlv->iItem!=-1))
			{
				if((pnmlv->uOldState^pnmlv->uNewState)&8192)
				{	lvit.iItem=pnmlv->iItem;lvit.iSubItem=0;lvit.lParam=0;lvit.mask=LVIF_PARAM;
					SendDlgItemMessage(hDlg,12400,LVM_GETITEM,0,(LPARAM)&lvit);
					if(lvit.lParam)
					{	if((pnmlv->uNewState&8192)&&(TORHook!=0))
						{
							if(((tmpOptions->Confirmations & CONFIRM_VERIFY_CONNECTIONS) != 0) && WarnOpenConnections)
							{	if(!WarnOpenConnections(lvit.lParam,tmpOptions->Confirmations & CONFIRM_CLOSE_CONNECTIONS))
								{	return 0;
								}
							}
							int i=4|tmpOptions->ForceFlags;
							char *tmp2=tor_malloc(256);
							tor_snprintf(tmp2,255,"%s",tmpOptions->LocalHost);
							if(TORHook(lvit.lParam,(HANDLE)tmpOptions->SocksPort,i,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff))==0)
							{	lvit.mask=LVIF_STATE;
								lvit.state=4096;
								lvit.stateMask=LVIS_STATEIMAGEMASK;
								SendDlgItemMessage(hDlg,12400,LVM_SETITEMSTATE,lvit.iItem,(LPARAM)&lvit);
							}
							tor_free(tmp2);
						}
						else if(TORUnhook!=0)
						{	TORUnhook(lvit.lParam);
						}
					}
				}
			}
		}

	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

int __stdcall dlgSandboxing(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgSandboxing=hDlg;
		if(LangGetLanguage())	changeDialogStrings(hDlg,lang_dlg_sandboxing);
		if(tmpOptions->LocalHost==NULL)	tmpOptions->LocalHost=tor_strdup("localhost");
		SetDlgItemText(hDlg,12100,tmpOptions->LocalHost);
		if(tmpOptions->ForceFlags&2) CheckDlgButton(hDlg,12401,BST_CHECKED);
		if(tmpOptions->ForceFlags&8) CheckDlgButton(hDlg,12404,BST_CHECKED);
		if(tmpOptions->ForceFlags&16) CheckDlgButton(hDlg,12405,BST_CHECKED);
		if(tmpOptions->ForceFlags&32) CheckDlgButton(hDlg,12406,BST_CHECKED);
		if(tmpOptions->ForceFlags&64) CheckDlgButton(hDlg,12407,BST_CHECKED);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==12401)
		{	if(IsDlgButtonChecked(hDlg,12401)==BST_CHECKED)	tmpOptions->ForceFlags|=2;
			else	tmpOptions->ForceFlags&=0xffff^2;
		}
		else if(LOWORD(wParam)==12404)
		{	if(IsDlgButtonChecked(hDlg,12404)==BST_CHECKED)	tmpOptions->ForceFlags|=8;
			else	tmpOptions->ForceFlags&=0xffff^8;
		}
		else if(LOWORD(wParam)==12405)
		{	if(IsDlgButtonChecked(hDlg,12405)==BST_CHECKED)	tmpOptions->ForceFlags|=16;
			else	tmpOptions->ForceFlags&=0xffff^16;
		}
		else if(LOWORD(wParam)==12406)
		{	if(IsDlgButtonChecked(hDlg,12406)==BST_CHECKED)	tmpOptions->ForceFlags|=32;
			else	tmpOptions->ForceFlags&=0xffff^32;
		}
		else if(LOWORD(wParam)==12407)
		{	if(IsDlgButtonChecked(hDlg,12407)==BST_CHECKED)	tmpOptions->ForceFlags|=64;
			else	tmpOptions->ForceFlags&=0xffff^64;
		}
		else if((LOWORD(wParam)==12100)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,12100,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,12100,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->LocalHost;
			tmpOptions->LocalHost=tmp1;tor_free(tmp2);
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

void dlgQuickStart_langUpdate(void)
{	if(hDlgQuickStart)
	{	changeDialogStrings(hDlgQuickStart,lang_dlg_quick_start);
		LangSetColumn(hDlgQuickStart,12400,120,LANG_COLUMN_INTERCEPT_1,0);
		LangSetColumn(hDlgQuickStart,12400,192,LANG_COLUMN_INTERCEPT_2,1);
	}
}

int __stdcall dlgQuickStart(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlgQuickStart=hDlg;
		if(LangGetLanguage())	changeDialogStrings(hDlgQuickStart,lang_dlg_quick_start);
		LangInsertColumn(hDlgQuickStart,12400,120,LANG_COLUMN_INTERCEPT_1,0,LVCFMT_LEFT);
		LangInsertColumn(hDlgQuickStart,12400,192,LANG_COLUMN_INTERCEPT_2,1,LVCFMT_LEFT);
		config_line_t *cfg;
		SendDlgItemMessage(hDlg,12400,LVM_DELETEALLITEMS,0,0);
		lvitw.iItem=0;
		for(cfg=tmpOptions->QuickStart;cfg;cfg=cfg->next)
		{	if(cfg->value)	addQuickStartItem(cfg);
		}
		SendDlgItemMessage(hDlg,12400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==12001)
			dlgForceTor_addNewProcess(NULL);
		else if(LOWORD(wParam)==12002)
			dlgForceTor_interceptNewProcess();
		else if(LOWORD(wParam)==12003)
		{	lvitw.iItem = SendDlgItemMessage(hDlg,12400,LVM_GETNEXTITEM,-1,LVNI_ALL|LVNI_SELECTED);
			if(lvitw.iItem!=-1)
			{	config_line_t *cfg;
				lvitw.mask = LVIF_PARAM;
				lvitw.lParam = 0;
				lvitw.iSubItem = 0;
				SendDlgItemMessageW(hDlg,12400,LVM_GETITEMW,0,(LPARAM)&lvitw);
				cfg = (config_line_t *)lvitw.lParam;
				if(cfg)	dlgForceTor_addNewProcess(cfg);
				else	wParam = -1;
			}
			else	wParam = -1;
			if((int)wParam == -1)	LangMessageBox(hMainDialog,get_lang_str(LANG_MB_NO_SELECTION),LANG_MB_ERROR,MB_OK);
		}
		else if(LOWORD(wParam)==12004)
		{	lvitw.iItem=SendDlgItemMessageW(hDlg,12400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvitw.iItem!=-1 && lvitw.iItem)
			{	lvitw.lParam=0;lvitw.mask=LVIF_PARAM;lvitw.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,12400,LVM_GETITEMW,0,(LPARAM)&lvitw) && lvitw.lParam)
				{	config_line_t *cfg = (config_line_t *)lvitw.lParam,*cfg1;
					if(cfg)
					{	if(tmpOptions->QuickStart == cfg)	return 0;
						if(tmpOptions->QuickStart->next == cfg)
						{	tmpOptions->QuickStart->next = cfg->next;
							cfg->next = tmpOptions->QuickStart;
							tmpOptions->QuickStart = cfg;
						}
						else
						{	config_line_t *cfg2;
							cfg1 = tmpOptions->QuickStart;
							while(cfg1)
							{	cfg2 = cfg1->next;
								if(cfg2 && cfg2->next == cfg)
								{	cfg1->next = cfg;
									cfg1 = cfg->next;
									cfg->next = cfg2;
									cfg2->next = cfg1;
									break;
								}
								cfg1 = cfg1->next;
							}
						}
						SendDlgItemMessage(hDlg,12400,LVM_DELETEITEM,lvitw.iItem,0);
						lvitw.iItem--;
						int i = addQuickStartItem(cfg);
						if(i != -1)
						{	lvitw.iItem=i;
							lvitw.iSubItem = 0;
							lvitw.mask=LVIF_STATE;
							lvitw.state=LVIS_SELECTED;
							lvitw.stateMask=LVIS_SELECTED;
							SendDlgItemMessageW(hDlg,12400,LVM_SETITEMW,lvitw.iItem,(LPARAM)&lvitw);
						}
					}
				}
			}
		}
		else if(LOWORD(wParam)==12005)
		{	lvitw.iItem=SendDlgItemMessageW(hDlg,12400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvitw.iItem!=-1)
			{	lvitw.lParam=0;lvitw.mask=LVIF_PARAM;lvitw.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,12400,LVM_GETITEMW,0,(LPARAM)&lvitw) && lvitw.lParam)
				{	config_line_t *cfg = (config_line_t *)lvitw.lParam,*cfg1;
					if(cfg)
					{	if(!cfg->next)	return 0;
						if(cfg == tmpOptions->QuickStart)
						{	tmpOptions->QuickStart = cfg->next;
							cfg1 = tmpOptions->QuickStart->next;
							tmpOptions->QuickStart->next = cfg;
							cfg->next = cfg1;
						}
						else
						{	config_line_t *cfg2;
							cfg1 = tmpOptions->QuickStart;
							while(cfg1)
							{	if(cfg1->next == cfg)
								{	cfg1->next = cfg->next;
									cfg2 = cfg->next->next;
									cfg->next->next = cfg;
									cfg->next = cfg2;
									break;
								}
								cfg1 = cfg1->next;
							}
						}
						SendDlgItemMessage(hDlg,12400,LVM_DELETEITEM,lvitw.iItem,0);
						lvitw.iItem++;
						int i = addQuickStartItem(cfg);
						if(i != -1)
						{	lvitw.iItem=i;
							lvitw.iSubItem = 0;
							lvitw.mask=LVIF_STATE;
							lvitw.state=LVIS_SELECTED;
							lvitw.stateMask=LVIS_SELECTED;
							SendDlgItemMessageW(hDlg,12400,LVM_SETITEMW,lvitw.iItem,(LPARAM)&lvitw);
						}
					}
				}
			}
		}
		else if(LOWORD(wParam)==12006)
		{	lvitw.iItem=SendDlgItemMessageW(hDlg,12400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvitw.iItem!=-1)
			{	lvitw.lParam=0;lvitw.mask=LVIF_PARAM;lvitw.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,12400,LVM_GETITEMW,0,(LPARAM)&lvitw) && lvitw.lParam)
				{	config_line_t *cfg = (config_line_t *)lvitw.lParam,*cfg1;
					if(cfg)
					{	if(tmpOptions->QuickStart == cfg)	tmpOptions->QuickStart = cfg->next;
						else
						{	cfg1 = tmpOptions->QuickStart;
							while(cfg1)
							{	if(cfg1->next == cfg)
								{	cfg1->next = cfg->next;
									break;
								}
								cfg1 = cfg1->next;
							}
						}
						SendDlgItemMessage(hDlg,12400,LVM_DELETEITEM,lvitw.iItem,0);
						if(SendDlgItemMessage(hDlg,12400,LVM_GETITEMCOUNT,0,0) <= lvitw.iItem && lvitw.iItem)	lvitw.iItem--;
						lvitw.iSubItem = 0;
						lvitw.mask=LVIF_STATE;
						lvitw.state=LVIS_SELECTED;
						lvitw.stateMask=LVIS_SELECTED;
						SendDlgItemMessageW(hDlg,12400,LVM_SETITEMW,lvitw.iItem,(LPARAM)&lvitw);
						if(cfg->key)	tor_free(cfg->key);
						if(cfg->value)	tor_free(cfg->value);
						tor_free(cfg);
					}
				}
			}
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	if(wParam==12400)
		{	pnmlv=(LPNMLISTVIEW)lParam;
			NMHDR *hdr=(LPNMHDR)lParam;
			if(hdr->code==(unsigned int)NM_DBLCLK)
			{	lvitw.iItem=SendDlgItemMessageW(hDlg,12400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
				if(lvitw.iItem!=-1)
				{	lvitw.lParam=0;lvitw.mask=LVIF_PARAM;lvitw.iSubItem=0;
					if(SendDlgItemMessageW(hDlg,12400,LVM_GETITEMW,0,(LPARAM)&lvitw) && lvitw.lParam)
					{	config_line_t *cfg = (config_line_t *)lvitw.lParam;
						if(cfg)
						{	if(CreateNewProcess)
							{	int i=4|tmpOptions->ForceFlags;
								char *tmp2;
								if(tmpOptions->LocalHost && tmpOptions->LocalHost[0])	tmp2 = tor_strdup(tmpOptions->LocalHost);
								else							tmp2 = tor_strdup("localhost");
								CreateNewProcess((DWORD)cfg->value,(HANDLE)tmpOptions->SocksPort,i,best_delta_t,tmp2,(DWORD)crypto_rand_int(0x7fffffff));
								tor_free(tmp2);
							}
							if(IsWindowVisible(hMainDialog))
							{	SendDlgItemMessage(hMainDialog,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_DEBUG]);
							}
						}
					}
				}
			}
		}

	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
