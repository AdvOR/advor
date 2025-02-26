#include "or.h"
#include "dlg_util.h"
#include "language.h"
#include "geoip.h"
#include <shellapi.h>

extern HWND hMainDialog;
HANDLE currentDialog=NULL;
HANDLE hHideAllThread=NULL;
extern HINSTANCE hInstance;
extern or_options_t *tmpOptions;
extern LPFN1 ShowProcesses;
extern HWND hDlgForceTor;
extern LV_ITEM lvit;
extern NOTIFYICONDATA nid;

typedef struct window_show_info
{	struct window_show_info *next;
	HWND hWnd;
	UINT showCmd;
	DWORD pid,tid;
} window_show_info;

window_show_info *wshow = NULL;

BOOL CALLBACK enumWnd(HWND hWnd,LPARAM lParam);
void __stdcall hide_all_thread(LPARAM lParam) __attribute__((noreturn));
BOOL dlgUtil_canShow(void);

BOOL CALLBACK enumWnd(HWND hWnd,LPARAM lParam)
{	DWORD pid=0;
	DWORD *pidlist;
	WINDOWPLACEMENT wndpl;
	pidlist = (DWORD *)lParam;
	GetWindowThreadProcessId(hWnd,&pid);
	if(pid && pid != GetCurrentProcessId())
	{	while(pidlist[0])
		{	if(pidlist[0]==pid)	break;
			pidlist++;
		}
		if(pidlist[0]==pid)
		{	if(!IsWindowVisible(hWnd))	return 1;
			GetWindowPlacement(hWnd,&wndpl);
			if(wndpl.showCmd!=SW_HIDE)
			{	window_show_info *wsh=tor_malloc_zero(sizeof(window_show_info));
				if(!wshow)	wshow = wsh;
				else
				{	window_show_info *w;
					for(w=wshow;w->next;w=w->next);
					w->next=wsh;
				}
				wsh->hWnd=hWnd;
				wsh->showCmd=wndpl.showCmd;
				ShowWindow(hWnd,SW_HIDE);
			}
		}
	}
	return 1;
}

void __stdcall hide_all_thread(LPARAM lParam)
{	(void) lParam;
	DWORD *pidlist;
	int i,j,laststate;
	window_show_info *wsh;
	if(IsWindowVisible(hMainDialog))
	{	laststate = 1;
		ShowWindow(hMainDialog,SW_HIDE);
	}
	else
	{	laststate = 0;
		Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;
	}
	while(hHideAllThread)
	{	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
		i = SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMCOUNT,0,0);
		if(i <= 0)	i = 1;
		pidlist = tor_malloc((i+1)*4);
		lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
		j=0;
		while(i)
		{	lvit.lParam=0;
			if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
			pidlist[j] = lvit.lParam;
			if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
				j++;
			if(i==0)	break;
			lvit.iItem++;
			i--;
		}
		pidlist[j] = 0;
		EnumWindows(&enumWnd,(LPARAM)pidlist);
		if((tmpOptions->HotkeyHideAll & 0x2000) != 0)
		{
#if 0
			for(wsh=wshow;wsh;wsh=wsh->next)
			{
				if(wsh->pid==pidlist[i])	break;
			}
			if(!wsh)
			{	if(suspend_process(pidlist[i]))
				{	if(!wshow)
					{	wshow = tor_malloc_zero(sizeof(window_show_info));
						wsh = wshow;
					}
					else
					{	for(wsh=wshow;wsh->next;wsh=wsh->next);
						wsh->next = tor_malloc_zero(sizeof(window_show_info));
						wsh = wsh->next;
					}
					wsh->pid = pidlist[i];
				}
			}
			if(!wsh)
#endif
			{	for(i=0;pidlist[i];i++)
				{	HANDLE hSnapshot = thread_list_init(pidlist[i]);
					if(hSnapshot)
					{	int lastid;
						lastid = thread_list_get(0,pidlist[i],hSnapshot);
						while(lastid)
						{	for(wsh=wshow;wsh;wsh=wsh->next)
							{
								if(wsh->tid==(unsigned int)lastid)	break;
							}
							if(!wsh)
							{	if(!wshow)
								{	wshow = tor_malloc_zero(sizeof(window_show_info));
									wsh = wshow;
								}
								else
								{	{for(wsh=wshow;wsh->next;wsh=wsh->next);}
									wsh->next = tor_malloc_zero(sizeof(window_show_info));
									wsh = wsh->next;
								}
								wsh->tid = lastid;
								HANDLE hThread = open_thread(THREAD_SUSPEND_RESUME,0,lastid);
								SuspendThread(hThread);
								CloseHandle(hThread);
							}
							lastid = thread_list_get(lastid,pidlist[i],hSnapshot);
						}
						thread_list_close(hSnapshot);
					}
				}
			}
		}
		tor_free(pidlist);
		Sleep(100);
	}
	wsh = wshow;
	while(wsh)
	{	if(wsh->tid)
		{	HANDLE hThread = open_thread(THREAD_SUSPEND_RESUME,0,wsh->tid);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
		else if(wsh->pid)	resume_process(wsh->pid);
		wsh = wsh->next;
	}
	while(wshow)
	{	wsh = wshow;
		if(!wsh->tid && !wsh->pid)
			ShowWindow(wshow->hWnd,wshow->showCmd);
		wshow = wshow->next;
		tor_free(wsh);
	}
	wshow = NULL;
	if(laststate)
	{	ShowWindow(hMainDialog,SW_SHOWNORMAL);BringWindowToTop(hMainDialog);SetForegroundWindow(hMainDialog);
		SendDlgItemMessage(hMainDialog,100,EM_SCROLLCARET,0,0);
	}
	else
	{	HWND h = GetDlgItem(hMainDialog,4);
		PostMessage(hMainDialog,WM_COMMAND,4,(LPARAM)h);
	}
	CloseHandle(hHideAllThread);
	ExitThread(0);
}

void dlgUtil_hideAll(void)
{	DWORD thr_id;
	hHideAllThread=(HANDLE)-1;
	hHideAllThread=CreateThread(0,0,(LPTHREAD_START_ROUTINE)hide_all_thread,0,0,(LPDWORD)&thr_id);
	CloseHandle(hHideAllThread);
}

void dlgUtil_restoreAll(void)
{
	hHideAllThread=NULL;
}

BOOL dlgUtil_canShow(void)
{
	if(hHideAllThread)	return 0;
	return 1;
}

HWND createChildDialog(HANDLE hParent,int resourceId,DLGPROC dialogFunc)
{	HWND result;
	if(!hInstance) hInstance=GetModuleHandle(NULL);
	if(!hMainDialog) hMainDialog=hParent;
	result = CreateDialogParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(resourceId),hParent,dialogFunc,0);
	ShowWindow(result,SW_HIDE);
	return result;
}

void changeDialogStrings(HWND hDlg,lang_dlg_info *dlgInfo)
{	int cnt;
	for(cnt=0;dlgInfo[cnt].ctrlId!=0;cnt++)
		LangSetDlgItemText(hDlg,dlgInfo[cnt].ctrlId,dlgInfo[cnt].langId);
}

void getEditData(HWND hDlg,int editBox,config_line_t **option,const char *value)
{	int i,j;
	int tmpsize=SendDlgItemMessage(hDlg,editBox,WM_GETTEXTLENGTH,0,0)+1;
	config_line_t *cfg,**cfg1;
	char *tmp1=tor_malloc(tmpsize+2);
	SendDlgItemMessage(hDlg,editBox,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
	LangEnterCriticalSection();
	while(*option)
	{	cfg=*option;
		tor_free(cfg->key);tor_free(cfg->value);
		*option=cfg->next;
		tor_free(cfg);
	}
	j=0;cfg1=option;*cfg1=NULL;
	for(i=0;i<tmpsize;i++)
	{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==32)||(tmp1[i]==0))
		{	if(j!=i)
			{	tmp1[i]=0;
				*cfg1=tor_malloc_zero(sizeof(config_line_t));
				(*cfg1)->key = (unsigned char *)tor_strdup(value);
				(*cfg1)->value=(unsigned char *)tor_strdup(&tmp1[j]);
				cfg1=&((*cfg1)->next);
			}
			j=i+1;
		}
	}
	LangLeaveCriticalSection();
	tor_free(tmp1);
}

void getEditData1(HWND hDlg,int editBox,config_line_t **option,const char *value)
{	int i,j;
	int tmpsize=SendDlgItemMessage(hDlg,editBox,WM_GETTEXTLENGTH,0,0)+1;
	config_line_t *cfg,**cfg1;
	char *tmp1=tor_malloc(tmpsize+2);
	SendDlgItemMessage(hDlg,editBox,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
	LangEnterCriticalSection();
	RemoveComments(tmp1);tmpsize=strlen(tmp1);
	for(;;)
	{	cfg=*option;
		if(cfg==NULL) break;
		tor_free(cfg->key);tor_free(cfg->value);
		*option=cfg->next;
		tor_free(cfg);
	}
	j=0;cfg1=option;*cfg1=NULL;
	for(i=0;tmp1[i];i++)
	{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==0))
		{	if(j!=i)
			{	tmp1[i]=0;
				*cfg1=tor_malloc_zero(sizeof(config_line_t));
				(*cfg1)->key = (unsigned char *)tor_strdup(value);
				(*cfg1)->value=(unsigned char *)tor_strdup(&tmp1[j]);
				cfg1=&((*cfg1)->next);
			}
			j=i+1;
		}
	}
	LangLeaveCriticalSection();
	tor_free(tmp1);
}

void setEditData(HWND hDlg,int editBox,config_line_t *option)
{	int i,j;
	if(option!=NULL)
	{	config_line_t *cfg;
		i = 1024;
		for(cfg=option;cfg;cfg=cfg->next)
			i += strlen((char *)cfg->value) + 2;
		char *tmp1=tor_malloc(i),*tmp2;
		if(i > 29999)	SendDlgItemMessage(hDlg,editBox,EM_LIMITTEXT,i+32768,0);
		tmp2=tmp1;
		for(cfg=option;cfg;cfg=cfg->next)
		{	for(j=0;i;i--,j++)
			{	if(!cfg->value[j]) break;
				*tmp1++=cfg->value[j];
			}
			if(i < 2)	break;
			*tmp1++=13;*tmp1++=10;i-=2;
		}
		*tmp1=0;
		SetDlgItemText(hDlg,editBox,tmp2);
		tor_free(tmp2);
	}
}

void selectComboId(HWND hDlg,int combo,LPARAM id)
{	HWND hCombo = GetDlgItem(hDlg,combo);
	int i;
	for(i=0;;i++)
	{	if(SendMessage(hCombo,CB_GETITEMDATA,i,0)==id)
		{	SendMessage(hCombo,CB_SETCURSEL,i,0);
			return;
		}
	}
}

void initmemunits(HWND hDlg,int combo)
{
	SendDlgItemMessage(hDlg,combo,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,SendDlgItemMessage(hDlg,combo,CB_ADDSTRING,0,(LPARAM)"Bytes"),(LPARAM)0);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,SendDlgItemMessage(hDlg,combo,CB_ADDSTRING,0,(LPARAM)"KB"),(LPARAM)10);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,SendDlgItemMessage(hDlg,combo,CB_ADDSTRING,0,(LPARAM)"MB"),(LPARAM)20);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,SendDlgItemMessage(hDlg,combo,CB_ADDSTRING,0,(LPARAM)"GB"),(LPARAM)30);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,SendDlgItemMessage(hDlg,combo,CB_ADDSTRING,0,(LPARAM)"TB"),(LPARAM)40);
}

#define TIME_MINUTES 60
#define TIME_HOURS (TIME_MINUTES*60)
#define TIME_DAYS (TIME_HOURS*24)
#define TIME_WEEKS (TIME_DAYS*7)
#define TIME_MONTHS (TIME_DAYS*30)
#define TIME_YEARS (TIME_DAYS*365)

void inittimeunits(HWND hDlg,int combo,int edit,uint32_t value)
{
	SendDlgItemMessage(hDlg,combo,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_SECONDS),DLG_TIME_UNIT_SECONDS);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_MINUTES),DLG_TIME_UNIT_MINUTES);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_HOURS),DLG_TIME_UNIT_HOURS);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_DAYS),DLG_TIME_UNIT_DAYS);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_WEEKS),DLG_TIME_UNIT_WEEKS);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_MONTHS),DLG_TIME_UNIT_MONTHS);
	SendDlgItemMessage(hDlg,combo,CB_SETITEMDATA,LangCbAddString(hDlg,combo,LANG_DLG_TIME_UNIT_YEARS),DLG_TIME_UNIT_YEARS);
	if(value)
	{	if((value%TIME_YEARS) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_YEARS,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_YEARS);
		}
		else if((value%TIME_MONTHS) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_MONTHS,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_MONTHS);
		}
		else if((value%TIME_WEEKS) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_WEEKS,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_WEEKS);
		}
		else if((value%TIME_DAYS) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_DAYS,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_DAYS);
		}
		else if((value%TIME_HOURS) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_HOURS,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_HOURS);
		}
		else if((value%TIME_MINUTES) == 0)
		{	SetDlgItemInt(hDlg,edit,value/TIME_MINUTES,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_MINUTES);
		}
		else
		{	SetDlgItemInt(hDlg,edit,value,0);
			selectComboId(hDlg,combo,DLG_TIME_UNIT_SECONDS);
		}
	}
	else
	{	SetDlgItemInt(hDlg,edit,value,0);
		selectComboId(hDlg,combo,DLG_TIME_UNIT_SECONDS);
	}
}

uint32_t gettimeunit(HWND hDlg,int combo,int edit)
{	uint32_t i;
	i = SendDlgItemMessage(hDlg,combo,CB_GETCURSEL,0,0);
	if(i != (uint32_t)CB_ERR)
	{	i = SendDlgItemMessage(hDlg,combo,CB_GETITEMDATA,i,0);
		switch(i)
		{	case DLG_TIME_UNIT_YEARS:
				i = TIME_YEARS;
				break;
			case DLG_TIME_UNIT_MONTHS:
				i = TIME_MONTHS;
				break;
			case DLG_TIME_UNIT_WEEKS:
				i = TIME_WEEKS;
				break;
			case DLG_TIME_UNIT_DAYS:
				i = TIME_DAYS;
				break;
			case DLG_TIME_UNIT_HOURS:
				i = TIME_HOURS;
				break;
			case DLG_TIME_UNIT_MINUTES:
				i = TIME_MINUTES;
				break;
			default:
				i = 1;
				break;
		}
	}
	else	i = 1;
	return i * GetDlgItemInt(hDlg,edit,NULL,0);
}
