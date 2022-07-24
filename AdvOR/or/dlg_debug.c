#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "language.h"

HWND hDlgDebug=NULL;
WNDPROC oldEditProc;
extern HWND hMainDialog;
extern or_options_t *tmpOptions;
char strban[256+3];
extern char exename[MAX_PATH+1];
extern HINSTANCE hInstance;

//int frame2[]={400,401,10,300,100,-1};
lang_dlg_info lang_dlg_debug[]={
	{400,LANG_DLG_SAVE_TO_LOG},
	{401,LANG_DLG_AUTO_REFRESH},
	{11,LANG_DLG_RESERVED_05},
	{10,LANG_DLG_CLEAR_WINDOW},
	{0,0}
};

BOOL is_dns_letter(char c);
int is_NaN(char *str);
void dlgDebug_logFilterAdd(char *strban);
int __stdcall dlgFilters(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall newEditProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgDebug(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void dlgDebug_langUpdate(void);

lang_dlg_info lang_dlg_filters[]={
	{11050,LANG_DLG_DEBUG_FILTER},
	{0,0}
};

BOOL is_dns_letter(char c)
{	if((c<='Z')&&(c>='A'))	return 1;
	if((c<='z')&&(c>='a'))	return 1;
	if((c<='9')&&(c>='0'))	return 1;
	if(c=='-')	return 1;
	return 0;
}

int is_NaN(char *str)
{	while(str[0] && str[0]!='.')
	{	if(str[0] < '0' || str[0] > '9')
			return 1;
		str++;
	}
	return 0;
}

int dlgDebug_find_address(char *str)
{	int i;
	int pos = -1;
	int points=0;
	for(i=0;str[i];i++)
	{	if(is_dns_letter(str[i]) && (pos!=-1 || str[i]!='-'))
		{	if(pos == -1)	pos = i;}
		else if(pos != -1 && str[i]=='.' && is_dns_letter(str[i+1]) && str[i+1]!='-')
			points++;
		else if(points && (str[pos]<'0' || str[pos]>'9' || is_NaN(&str[pos]) || is_ip(&str[pos])))	break;
		else
		{	pos = -1;
			points = 0;
		}
	}
	if(pos >= 0 && str[pos]>='0' && str[pos]<='9')
		if(points < 3)	return -1;
	return points?pos:-1;
}

void dlgDebug_copy_address(char *str,char *dest,int max)
{	int i;
	for(i=0;str[i] && i < max-1;i++)
	{	if(is_dns_letter(str[i]))
			*dest = str[i];
		else if(str[i]=='.' && is_dns_letter(str[i+1]) && str[i+1]!='-')
			*dest = '.';
		else	break;
		dest++;
	}
	*dest = 0;
}

int dlgDebug_find_domain(char *str)
{	int i;
	int points=0;
	if(is_ip(str))	return 0;
	if(str[0]>='0' && str[0]<='9')	return 0;
	for(i=0;str[i];i++)
	{	if(!is_dns_letter(str[i]))
		{	if(str[i]=='.' && is_dns_letter(str[i+1]))
				points++;
			else if(points)	break;
			else	return 0;
		}
	}
	if(points < 2)	return 0;
	for(i=0;str[i];i++)
	{	if(!is_dns_letter(str[i]))
		{	if(str[i]=='.')
			{	if(points > 2)	points--;
				else return i;
			}
		}
	}
	return 0;
}

void dlgDebug_logFilterAdd(char *strban2)
{	if(strban2[0])
	{	int i,j,k=0;
		char *tmp1=getLogFilter();for(j=0;tmp1&&*(tmp1+j);j++);
		char *tmp2=tor_malloc(j+256+5),*tmp3;tmp3=tmp2;
		if(tmp1)
		{	for(i=0;*tmp1;i++){	k=*tmp1;*tmp2++=*tmp1++;}
			if((k!=13)&&(k!=10)){	*tmp2++=13;*tmp2++=10;}
		}
		for(i=0;strban2[i];i++)	*tmp2++=strban2[i];
		*tmp2++=13;*tmp2++=10;*tmp2++=0;
		setLogFilter(tmp3);set_log_filter();strban[0]=0;
	}
}

void dlgDebug_setLogFilter(or_options_t *options)
{	if(options->NotifyFilter!=NULL)
	{	char *tmp1=tor_malloc(65536),*tmp2;
		int i=0,j;tmp2=tmp1;
		config_line_t *cfg;
		for(cfg=options->NotifyFilter;cfg;cfg=cfg->next)
		{	for(j=0;i<65530;i++,j++)
			{	if(!cfg->value[j]) break;
				*tmp1++=cfg->value[j];
			}
			*tmp1++=13;*tmp1++=10;i+=2;
			if(i>65530) break;
		}
		*tmp1=0;
		setLogFilter(tmp2);
		config_line_t **cfg1,**cfg2;
		cfg1=&options->DebugFilter;
		cfg2=&options->NotifyFilter;
		while(*cfg2)
		{	*cfg1 = tor_malloc_zero(sizeof(config_line_t));
			(*cfg1)->key = (unsigned char *)tor_strdup("DebugFilter");
			(*cfg1)->value = (unsigned char *)tor_strdup((const char *)(*cfg2)->value);
			cfg2=&((*cfg2)->next);
			cfg1=&((*cfg1)->next);
		}
	}
}

void set_log_filter(void)
{	int i,j,k;
	if(!(tmpOptions)) return;
	char *tmp1=getLogFilter();
	if(!tmp1) return;
	config_line_t *cfg,**cfg1,**cfg2;
	while(tmpOptions->NotifyFilter)
	{	cfg=tmpOptions->NotifyFilter;
		tor_free(cfg->key);tor_free(cfg->value);
		tmpOptions->NotifyFilter=cfg->next;
		tor_free(cfg);
	}
	j=0;cfg1=&tmpOptions->NotifyFilter;
	int tmpsize=strlen(tmp1)+1;
	for(i=0;i<=tmpsize;i++)
	{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==0))
		{	if(j!=i)
			{	k=tmp1[i];tmp1[i]=0;
				*cfg1=tor_malloc_zero(sizeof(config_line_t));
				(*cfg1)->key = (unsigned char *)tor_strdup("NotifyFilter");
				(*cfg1)->value=(unsigned char *)tor_strdup(&tmp1[j]);
				cfg1=&((*cfg1)->next);
				tmp1[i]=k;
			}
			while((tmp1[i]==13)||(tmp1[i]==10)) i++;
			j=i;
		}
	}
	tmp1=NULL;
	while(tmpOptions->DebugFilter)
	{	cfg=tmpOptions->DebugFilter;
		tor_free(cfg->key);tor_free(cfg->value);
		tmpOptions->DebugFilter=cfg->next;
		tor_free(cfg);
	}
	cfg1=&tmpOptions->DebugFilter;
	cfg2=&tmpOptions->NotifyFilter;
	while(*cfg2)
	{	*cfg1 = tor_malloc_zero(sizeof(config_line_t));
		(*cfg1)->key = (unsigned char *)tor_strdup("DebugFilter");
		(*cfg1)->value = (unsigned char *)tor_strdup((const char *)(*cfg2)->value);
		cfg2=&((*cfg2)->next);
		cfg1=&((*cfg1)->next);
	}
}

int __stdcall dlgFilters(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())
		{	SetWindowTextL(hDlg,LANG_FILTERS_TITLE);
			changeDialogStrings(hDlg,lang_dlg_filters);
		}
		SendDlgItemMessage(hDlg,11104,EM_LIMITTEXT,65536,0);
		SetDlgItemTextL(hDlg,11104,getLogFilter()?getLogFilter():"");
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==2)	EndDialog(hDlg,0);
		else if(LOWORD(wParam)==1)
		{	int tmpsize=SendDlgItemMessage(hDlg,11104,WM_GETTEXTLENGTH,0,0)*2;
			char *tmp1=tor_malloc(tmpsize+2);
			LangGetDlgItemText(hDlg,11104,tmp1,tmpsize+1);
			setLogFilter(tmp1);tmp1=NULL;set_log_filter();
			EndDialog(hDlg,0);
		}
	}
	return 0;
}

int __stdcall newEditProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	int lpStart=0,lpEnd,i,j;
	char *tmpsel,*tmpsel1,*tmpsel2,*tmpsel3;
	HMENU hMenu;POINT cPoint;
	if(uMsg==WM_RBUTTONUP)
	{	tmpsel=tor_malloc_zero(2048);
		lpEnd=LangGetSelText(hDlg,tmpsel+1024);
		if(lpEnd)
		{	tmpsel1=tmpsel;tmpsel2=tmpsel+1024;tmpsel3=&strban[0];i=0;
			tor_snprintf(tmpsel1,1024,get_lang_str(LANG_MNU_FILTER));
			while(*tmpsel1) tmpsel1++;
			while((*tmpsel2==13)||(*tmpsel2==10)||(*tmpsel2==32)||(*tmpsel2==9))	tmpsel2++;
			while((*tmpsel2)&&(*tmpsel2!=13)&&(*tmpsel2!=10)&&(i<(lpEnd-lpStart)))
			{	if(*tmpsel2=='&')	*tmpsel1++='&';
				*tmpsel3++=*tmpsel2;*tmpsel1++=*tmpsel2++;i++;
			}
			*tmpsel1++=34;*tmpsel1=0;*tmpsel3=0;
		}
		hMenu=CreatePopupMenu();
		LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,20100,LANG_MENU_COPY);
		if(*tmpsel)
		{	AppendMenu(hMenu,MF_SEPARATOR,0,0);
			LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,20101,tmpsel);
			lpStart = dlgDebug_find_address(strban);
			if(lpStart >= 0)
			{	InsertMenu(hMenu,0,MF_SEPARATOR,0,0);
				char *tmp1=tmpsel;
				if(is_ip(&strban[lpStart]))	j = 0;
				else
				{	j = dlgDebug_find_domain(&strban[lpStart]);
					tor_snprintf(tmp1,1022,get_lang_str(LANG_MNU_TRACK_EXIT));
					for(i=0;tmp1[i] && i < 1021;i++);
					tmp1[i++] = '*';
					if(!j)	tmp1[i++] = '.';
					dlgDebug_copy_address(&strban[j + lpStart],&tmp1[i],1023-i);
					LangInsertMenuStr(hMenu,2,MF_STRING|MF_UNCHECKED|MF_ENABLED|MF_BYPOSITION,20104,tmpsel);
					j = 1;
				}
				tmp1=tmpsel;
				tor_snprintf(tmpsel,1024,get_lang_str(LANG_MNU_TRACK_EXIT_1));
				for(i=0;tmp1[i] && i < 1023;i++)	;
				dlgDebug_copy_address(&strban[lpStart],&tmp1[i],1023-i);
				LangInsertMenuStr(hMenu,2+j,MF_STRING|MF_UNCHECKED|MF_ENABLED|MF_BYPOSITION,20103,tmpsel);
				tmp1=tmpsel;
				tor_snprintf(tmp1,1024,get_lang_str(LANG_MNU_REMEMBER_EXIT));
				for(i=0;tmp1[i] && i < 1023;i++)	;
				dlgDebug_copy_address(&strban[lpStart],&tmp1[i],1023-i);
				LangInsertMenuStr(hMenu,3+j,MF_STRING|MF_UNCHECKED|MF_ENABLED|MF_BYPOSITION,20105,tmpsel);
				tmp1=tmpsel;
				tor_snprintf(tmp1,1024,get_lang_str(LANG_MNU_FORGET_EXIT));
				for(i=0;tmp1[i] && i < 1023;i++)	;
				dlgDebug_copy_address(&strban[lpStart],&tmp1[i],1023-i);
				LangInsertMenuStr(hMenu,4+j,MF_STRING|MF_UNCHECKED|MF_ENABLED|MF_BYPOSITION,20106,tmpsel);
				tmp1=tmpsel;
				tor_snprintf(tmp1,1024,get_lang_str(LANG_MNU_BAN_HOST));
				for(i=0;tmp1[i] && i < 1023;i++)	;
				dlgDebug_copy_address(&strban[lpStart],&tmp1[i],1023-i);
				LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,20102,tmpsel);
			}
		}
		LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,20107,LANG_MNU_DUMP_STATS);
		GetCursorPos(&cPoint);
		TrackPopupMenu(hMenu,TPM_LEFTALIGN,cPoint.x,cPoint.y,0,hMainDialog,0);
		DestroyMenu(hMenu);
		tor_free(tmpsel);
		return 0;
	}
	return CallWindowProc(oldEditProc,hDlg,uMsg,wParam,lParam);
}

void dlgDebug_langUpdate(void)
{	if(!hDlgDebug || !LangGetLanguage()) return;
	int i,j=0;
	char *langTmp,*langTmp1;
	SendDlgItemMessage(hDlgDebug,300,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_DEBUG),(LPARAM)LOG_DEBUG);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_INFO),(LPARAM)LOG_INFO);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_PROXY),(LPARAM)LOG_ADDR);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_NOTICE),(LPARAM)LOG_NOTICE);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_WARNING),(LPARAM)LOG_WARN);
	SendDlgItemMessage(hDlgDebug,300,CB_SETITEMDATA,LangCbAddString(hDlgDebug,300,LANG_CB_ERROR),(LPARAM)LOG_ERR);
	for(i=0;i<10;i++)
	{	j=SendDlgItemMessage(hDlgDebug,300,CB_GETITEMDATA,i,0);
		if(j==CB_ERR) break;
		if((tmpOptions->logging&0xff)==j)
		{	SendDlgItemMessage(hDlgDebug,300,CB_SETCURSEL,i,0);
			break;
		}
	}
	langTmp=tor_malloc(MAX_PATH+1);tor_snprintf(langTmp,MAX_PATH,"%s.&log",exename);
	i=strlen(langTmp)+50;
	langTmp1=tor_malloc(i);
	tor_snprintf(langTmp1,i,get_lang_str(LANG_DLG_SAVE_TO_OTHER_LOG),langTmp);
	SetDlgItemTextL(hDlgDebug,400,langTmp1);
	tor_free(langTmp);tor_free(langTmp1);
	changeDialogStrings(hDlgDebug,lang_dlg_debug);
}

int __stdcall dlgDebug(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgDebug=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_debug);
		}
		SendDlgItemMessage(hDlg,100,EM_LIMITTEXT,65536,0);
		char *fname,*fname1;
		if(is_read_only())
			EnableWindow(GetDlgItem(hDlg,400),0);
		else if(tmpOptions->logging&0x8000)
		{	CheckDlgButton(hDlg,400,BST_CHECKED);
			fname=get_datadir_fname_suffix(NULL,".log");
			setLog(tmpOptions->logging&0xff,fname);
			tor_free(fname);
		}
		fname=tor_malloc(MAX_PATH+1);tor_snprintf(fname,MAX_PATH,"%s.&log",exename);
		int i=strlen(fname)+50;
		fname1=tor_malloc(i);
		tor_snprintf(fname1,i,get_lang_str(LANG_DLG_SAVE_TO_OTHER_LOG),fname);
		LangSetWindowText(GetDlgItem(hDlg,400),fname1);
		tor_free(fname);tor_free(fname1);
		strban[0]=0;
		SendDlgItemMessage(hDlg,100,EM_LIMITTEXT,65535,0);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_DEBUG),(LPARAM)LOG_DEBUG);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_INFO),(LPARAM)LOG_INFO);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_PROXY),(LPARAM)LOG_ADDR);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_NOTICE),(LPARAM)LOG_NOTICE);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_WARNING),(LPARAM)LOG_WARN);
		SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,LangCbAddString(hDlg,300,LANG_CB_ERROR),(LPARAM)LOG_ERR);
		if(tmpOptions->logging&0x4000){	CheckDlgButton(hDlg,401,BST_CHECKED);setDialog(hDlg);}
		else	setDialog(NULL);
		int j=0;
		for(i=0;i<10;i++)
		{	j=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,i,0);
			if(j==CB_ERR) break;
			if((tmpOptions->logging&0xff)==j)
			{	SendDlgItemMessage(hDlg,300,CB_SETCURSEL,i,0);
				break;
			}
		}
		LONG s = GetWindowLong(GetDlgItem(hDlg,100),GWL_WNDPROC);
		oldEditProc=(WNDPROC)s;
		SetWindowLong(GetDlgItem(hDlg,100),GWL_WNDPROC,(LONG)&newEditProc);
		LangShowCache(hDlg);
	}
	else if(uMsg==WM_COMMAND)
	{
		if((LOWORD(wParam)==300)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	int i=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
			if(i!=CB_ERR)
			{	tmpOptions->logging&=0xff00;tmpOptions->logging|=i&0xff;
				setLogging(i);
				if((tmpOptions->logging&0xff)<LOG_ADDR)	tmpOptions->SafeLogging=1;
				else	tmpOptions->SafeLogging=0;
			}
		}
		else if(LOWORD(wParam)==400)
		{	if(IsDlgButtonChecked(hDlg,400)==BST_CHECKED)
			{	tmpOptions->logging|=0x8000;
				char *fname=fname=get_datadir_fname_suffix(NULL,".log");
				setLog(tmpOptions->logging&0xff,fname);
				tor_free(fname);
			}
			else
			{	tmpOptions->logging&=0x7fff;
				setLog(tmpOptions->logging&0xff,NULL);
			}
		}
		else if(LOWORD(wParam)==401)
		{	if(IsDlgButtonChecked(hDlg,401)==BST_CHECKED)	setDialog(hDlg);
			else	setDialog(NULL);
		}
		else if(LOWORD(wParam)==10)	LangClearText(hDlg);
		else if(LOWORD(wParam)==11)	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1012),hDlg,&dlgFilters,0);
	}
	else if(uMsg==WM_TIMER)
	{	if(wParam==101)	LangDebugScroll(hDlg);
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
