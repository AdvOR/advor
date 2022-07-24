#include "or.h"
#include "dlg_util.h"
#include "connection.h"
#include "policies.h"

HWND hDlgProxy=NULL,hDlgBannedAddresses=NULL,hDlgAdvancedProxy=NULL;
extern HWND hMainDialog;
extern HINSTANCE hInstance;
extern or_options_t *tmpOptions;

void dlgForceTor_interceptNewProcess(void);

//int frame5[]={13400,13100,13010,13101,13401,13102,13402,13103,13403,13404,13405,13104,13406,13105,13050,-1};
lang_dlg_info lang_dlg_proxy[]={
	{13010,LANG_DLG_PROXY_SETTINGS},
	{13400,LANG_DLG_LOCAL_PROXY_PORT},
	{13011,LANG_DLG_LOCAL_PROXY_ADDR},
	{13012,LANG_DLG_PROXY_PROTOCOLS},
	{13013,LANG_DLG_PROXY_PROTOCOLS_LIST},
	{13401,LANG_DLG_PROXY_USER_PASS},
	{13014,LANG_DLG_PROXY_WARN},
	{13015,LANG_DLG_PROXY_RUN},
	{13001,LANG_DLG_PROXY_RUN_BTN},
	{13016,LANG_DLG_PROXY_SELECT_WINDOW},
	{13017,LANG_DLG_PROXY_START},
	{0,0}
};

lang_dlg_info lang_dlg_banned_addresses[]={
	{13405,LANG_DLG_BANNED_PORTS},
	{13406,LANG_DLG_BANNED_HOSTS},
	{13401,LANG_DLG_HTTP_REJECT_EXITNAME},
	{13402,LANG_DLG_HTTP_REJECT_ONION},
	{0,0}
};

lang_dlg_info lang_dlg_advanced_proxy[]={
	{13401,LANG_DLG_IP_RESTRICTIONS},
	{13402,LANG_DLG_HANDSHAKE_TIMEOUT},
	{13403,LANG_DLG_DISALLOW_DNS_RESOLVE},
	{13404,LANG_DLG_ALLOW_NON_RFC953},
	{0,0}
};

BOOL is_banned(const char *_addr);
void dlgProxy_banSocksAddress(char *socksAddress);
void dlgProxy_banDebugAddress(char *strban);
int __stdcall dlgProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgBannedAddresses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgAdvancedProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

BOOL is_banned(const char *_addr)
{	if(tmpOptions->BannedHosts)
	{	config_line_t *cfg;
		for(cfg=tmpOptions->BannedHosts;cfg;cfg=cfg->next)
		{	if(!stricmp((char *)cfg->value,_addr)) return 1;
		}
	}
	return 0;
}


void dlgProxy_banSocksAddress(char *socksAddress)
{	if(!socksAddress[0]) return;
	int i=0,j=0;
	while(socksAddress[i] && socksAddress[i]!=':')	i++;
	if(socksAddress[i]==':'){	j = i;socksAddress[i]=0;}
	if(is_banned(socksAddress))
	{	if(j)	socksAddress[j] = ':';
		return;
	}
	if(!hDlgBannedAddresses)
	{	config_line_t *cfg;
		char *tmp = tor_malloc(256);
		if(tmpOptions->BannedHosts)
		{	for(cfg=tmpOptions->BannedHosts;cfg->next;cfg=cfg->next)	;
			cfg->next = tor_malloc_zero(sizeof(config_line_t));
			cfg = cfg->next;
			cfg->key = (unsigned char *)tor_strdup("BannedHosts");
			cfg->value = (unsigned char *)tor_strdup(socksAddress);
		}
		else
		{	tmpOptions->BannedHosts = tor_malloc_zero(sizeof(config_line_t));
			cfg = tmpOptions->BannedHosts;
			cfg->key = (unsigned char *)tor_strdup("BannedHosts");
			cfg->value = (unsigned char *)tor_strdup(socksAddress);
		}
		tor_snprintf(tmp,255,get_lang_str(LANG_MB_BAN_ADDED),&socksAddress[0]);
		LangMessageBox(hMainDialog,tmp,LANG_LB_CONNECTIONS,MB_OK);
		tor_free(tmp);
	}
	else
	{	int tmpsize=SendDlgItemMessage(hDlgBannedAddresses,13105,WM_GETTEXTLENGTH,0,0);
		char *tmp2=tor_malloc(tmpsize+256+5),*tmp3;
		tmp3=tmp2;
		GetDlgItemText(hDlgBannedAddresses,13105,tmp2,tmpsize+1);tmp2+=tmpsize;
		if(tmpsize && (tmp3[tmpsize-1]!=13) && (tmp3[tmpsize-1]!=10)){	*tmp2++=13;*tmp2++=10;}
		for(i=0;(socksAddress[i]!=0);i++)	*tmp2++=socksAddress[i];
		*tmp2++=13;*tmp2++=10;*tmp2++=0;
		SetDlgItemText(hDlgBannedAddresses,13105,tmp3);
		getEditData(hDlgBannedAddresses,13105,&tmpOptions->BannedHosts,"BannedHosts");
		tor_snprintf(tmp3,256,get_lang_str(LANG_MB_BAN_ADDED),&socksAddress[0]);
		LangMessageBox(hMainDialog,tmp3,LANG_LB_CONNECTIONS,MB_OK);
		tor_free(tmp3);
	}
	if(j)	socksAddress[j] = ':';
}

void dlgProxy_banDebugAddress(char *strban)
{	if(strban[0])
	{	int i=dlgDebug_find_address(strban);
		dlgDebug_copy_address(&strban[i],&strban[i],strlen(&strban[i])+1);
		if(is_banned(&strban[i]))	return;
		if(!hDlgBannedAddresses)
		{	config_line_t *cfg;
			if(tmpOptions->BannedHosts)
			{	for(cfg=tmpOptions->BannedHosts;cfg->next;cfg=cfg->next)	;
				cfg->next = tor_malloc_zero(sizeof(config_line_t));
				cfg = cfg->next;
				cfg->key = (unsigned char *)tor_strdup("BannedHosts");
				cfg->value = (unsigned char *)tor_strdup(&strban[i]);
			}
			else
			{	tmpOptions->BannedHosts = tor_malloc_zero(sizeof(config_line_t));
				cfg = tmpOptions->BannedHosts;
				cfg->key = (unsigned char *)tor_strdup("BannedHosts");
				cfg->value = (unsigned char *)tor_strdup(&strban[i]);
			}
		}
		else
		{	int tmpsize=SendDlgItemMessage(hDlgBannedAddresses,13105,WM_GETTEXTLENGTH,0,0);
			char *tmp2,*tmp3;
			tmp2=tor_malloc(tmpsize+256+5);tmp3=tmp2;
			GetDlgItemText(hDlgBannedAddresses,13105,tmp2,tmpsize+1);tmp2+=tmpsize;
			if(tmpsize > 2 && (tmp3[tmpsize-1]!= 10 || tmp3[tmpsize-2]!=13))
			{	*tmp2++ = 13;*tmp2++ = 10;}
			for(;strban[i];i++)	*tmp2++=strban[i];
			*tmp2++=13;*tmp2++=10;*tmp2++=0;
			SetDlgItemText(hDlgBannedAddresses,13105,tmp3);
			getEditData(hDlgBannedAddresses,13105,&tmpOptions->BannedHosts,"BannedHosts");
			tor_free(tmp3);
		}
	}
}

int __stdcall dlgProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgProxy=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_proxy);
		}
		if(tmpOptions->SocksPort)
		{	CheckDlgButton(hDlg,13400,BST_CHECKED);SetDlgItemInt(hDlg,13100,tmpOptions->SocksPort,0);
			if(tmpOptions->DirFlags&DIR_FLAG_SOCKS_AUTH && tmpOptions->SocksAuthenticator && tmpOptions->SocksAuthenticator[0])
			{	EnableWindow(GetDlgItem(hDlg,13102),1);
				CheckDlgButton(hDlg,13401,BST_CHECKED);
			}
			else	EnableWindow(GetDlgItem(hDlg,13102),0);
		}
		else{	EnableWindow(GetDlgItem(hDlg,13100),0);EnableWindow(GetDlgItem(hDlg,13011),0);EnableWindow(GetDlgItem(hDlg,13101),0);
			EnableWindow(GetDlgItem(hDlg,13012),0);EnableWindow(GetDlgItem(hDlg,13013),0);
			EnableWindow(GetDlgItem(hDlg,13401),0);EnableWindow(GetDlgItem(hDlg,13102),0);
			EnableWindow(GetDlgItem(hDlg,13014),0);EnableWindow(GetDlgItem(hDlg,13015),0);EnableWindow(GetDlgItem(hDlg,13001),0);EnableWindow(GetDlgItem(hDlg,13016),0);EnableWindow(GetDlgItem(hDlg,13002),0);
			EnableWindow(GetDlgItem(hMainDialog,9),0);EnableWindow(GetDlgItem(hMainDialog,10),0);
		}
		if(tmpOptions->SocksListenAddress)	SetDlgItemText(hDlg,13101,(LPCSTR)tmpOptions->SocksListenAddress->value);
		else SetDlgItemText(hDlg,13101,"127.0.0.1");
		if(tmpOptions->SocksAuthenticator!=NULL)	SetDlgItemText(hDlg,13102,tmpOptions->SocksAuthenticator);
		HANDLE hIcon1=LoadIcon(hInstance,MAKEINTRESOURCE(9));
		SendDlgItemMessage(hDlg,13002,BM_SETIMAGE,IMAGE_ICON,(LPARAM)hIcon1);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==13400)
		{	if(IsDlgButtonChecked(hDlg,13400)==BST_CHECKED)
			{	tmpOptions->SocksPort=GetDlgItemInt(hDlg,13100,0,0);
				EnableWindow(GetDlgItem(hDlg,13100),1);EnableWindow(GetDlgItem(hDlg,13011),1);EnableWindow(GetDlgItem(hDlg,13101),1);
				EnableWindow(GetDlgItem(hDlg,13012),1);EnableWindow(GetDlgItem(hDlg,13013),1);
				EnableWindow(GetDlgItem(hDlg,13401),1);if(IsDlgButtonChecked(hDlg,13401))	EnableWindow(GetDlgItem(hDlg,13102),1);
				EnableWindow(GetDlgItem(hDlg,13014),1);EnableWindow(GetDlgItem(hDlg,13015),1);EnableWindow(GetDlgItem(hDlg,13001),1);EnableWindow(GetDlgItem(hDlg,13016),1);EnableWindow(GetDlgItem(hDlg,13002),1);
				EnableWindow(GetDlgItem(hMainDialog,9),1);EnableWindow(GetDlgItem(hMainDialog,10),1);
				retry_all_listeners(0,0);
			}
			else
			{	tmpOptions->SocksPort=0;
				EnableWindow(GetDlgItem(hDlg,13100),0);EnableWindow(GetDlgItem(hDlg,13011),0);EnableWindow(GetDlgItem(hDlg,13101),0);
				EnableWindow(GetDlgItem(hDlg,13012),0);EnableWindow(GetDlgItem(hDlg,13013),0);
				EnableWindow(GetDlgItem(hDlg,13401),1);if(IsDlgButtonChecked(hDlg,13401))	EnableWindow(GetDlgItem(hDlg,13102),1);
				EnableWindow(GetDlgItem(hDlg,13014),0);EnableWindow(GetDlgItem(hDlg,13015),0);EnableWindow(GetDlgItem(hDlg,13001),0);EnableWindow(GetDlgItem(hDlg,13016),0);EnableWindow(GetDlgItem(hDlg,13002),0);
				EnableWindow(GetDlgItem(hMainDialog,9),0);EnableWindow(GetDlgItem(hMainDialog,10),0);
				retry_all_listeners(0,0);
			}
		}
		else if(LOWORD(wParam)==13401)
		{	if(IsDlgButtonChecked(hDlg,13401)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,13102,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,13102,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->SocksAuthenticator;
				tmpOptions->SocksAuthenticator=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,13102),1);
				tmpOptions->DirFlags |= DIR_FLAG_SOCKS_AUTH;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_SOCKS_AUTH ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,13102),0);
			}
		}
		else if((LOWORD(wParam)==13100)&&(HIWORD(wParam)==EN_CHANGE))
		{	tmpOptions->SocksPort=GetDlgItemInt(hDlg,13100,0,0);
			retry_all_listeners(0,0);
		}
		else if((LOWORD(wParam)==13101)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData(hDlg,13101,&tmpOptions->SocksListenAddress,"SocksListenAddress");
			retry_all_listeners(0,0);
		}
		else if((LOWORD(wParam)==13102)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,13102,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,13102,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->SocksAuthenticator;
			tmpOptions->SocksAuthenticator=tmp1;tor_free(tmp2);
		}
		else if(LOWORD(wParam)==13001)
			dlgForceTor_interceptNewProcess();
		else if(LOWORD(wParam)==13002)
		{	HWND h = GetDlgItem(hMainDialog,9);
			PostMessage(hMainDialog,WM_COMMAND,9,(LPARAM)h);
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return	0;
}

int __stdcall dlgBannedAddresses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	char *tmp1,*tmp2;
		int i,j;
		config_line_t *cfg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_banned_addresses);
		}
		SendDlgItemMessage(hDlg,13102,EM_LIMITTEXT,65536,0);
		if(tmpOptions->RejectPlaintextPorts)
		{	tmp1=smartlist_join_strings(tmpOptions->RejectPlaintextPorts, ",", 0, NULL);
			SetDlgItemText(hDlg,13104,tmp1);
			tor_free(tmp1);}
		SendDlgItemMessage(hDlg,13105,EM_LIMITTEXT,65536,0);
		if(tmpOptions->BannedHosts!=NULL)
		{	int k = 0;
			for(cfg=tmpOptions->BannedHosts;cfg;cfg=cfg->next)
				k += strlen((char *)cfg->value) + 2;
			tmp1=tor_malloc(k+1024);i=0;tmp2=tmp1;
			for(cfg=tmpOptions->BannedHosts;cfg;cfg=cfg->next)
			{	for(j=0;;i++,j++)
				{	if(!cfg->value[j]) break;
					*tmp1++=cfg->value[j];
				}
				*tmp1++=13;*tmp1++=10;i+=2;
			}
			*tmp1=0;
			if(k > 16384)
				SendDlgItemMessage(hDlg,13105,EM_LIMITTEXT,k+16384,0);
			SetDlgItemText(hDlg,13105,tmp2);
			tor_free(tmp2);
		}
		hDlgBannedAddresses=hDlg;
		if(!(tmpOptions->AllowTorHosts & ALLOW_DOT_EXIT))		CheckDlgButton(hDlg,13401,BST_CHECKED);
		if(!(tmpOptions->AllowTorHosts & ALLOW_DOT_ONION))		CheckDlgButton(hDlg,13402,BST_CHECKED);
	}
	else if(uMsg==WM_COMMAND && hDlgBannedAddresses)
	{	if((LOWORD(wParam)==13104)&&(HIWORD(wParam)==EN_CHANGE))
		{	char *tmp1=tor_malloc(32768);
			GetDlgItemText(hDlg,13104,tmp1,32767);
			if(tmpOptions->RejectPlaintextPorts)
			{	SMARTLIST_FOREACH(tmpOptions->RejectPlaintextPorts, char *, cp, tor_free(cp));
				smartlist_clear(tmpOptions->RejectPlaintextPorts);
			}
			else	tmpOptions->RejectPlaintextPorts=smartlist_create();
			smartlist_split_string(tmpOptions->RejectPlaintextPorts, tmp1, ",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
			tor_free(tmp1);
		}
		else if((LOWORD(wParam)==13105)&&(HIWORD(wParam)==EN_CHANGE))
			getEditData(hDlg,13105,&tmpOptions->BannedHosts,"BannedHosts");
		else if(LOWORD(wParam)==13401)
		{	if(IsDlgButtonChecked(hDlg,13401)==BST_UNCHECKED)	tmpOptions->AllowTorHosts |= ALLOW_DOT_EXIT;
			else						tmpOptions->AllowTorHosts &= ALLOW_DOT_EXIT ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==13402)
		{	if(IsDlgButtonChecked(hDlg,13402)==BST_UNCHECKED)	tmpOptions->AllowTorHosts |= ALLOW_DOT_ONION;
			else						tmpOptions->AllowTorHosts &= ALLOW_DOT_ONION ^ 0xffffffff;
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return	0;
}

int __stdcall dlgAdvancedProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgAdvancedProxy=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_advanced_proxy);
		}
		if(tmpOptions->SocksPolicy){	setEditData(hDlg,13102,tmpOptions->SocksPolicy);CheckDlgButton(hDlg,13401,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,13102),0);
		SendDlgItemMessage(hDlg,13102,EM_LIMITTEXT,65536,0);
		if(tmpOptions->SocksTimeout>=32767) EnableWindow(GetDlgItem(hDlg,13103),0);
		else{	CheckDlgButton(hDlg,13402,BST_CHECKED);SetDlgItemInt(hDlg,13103,tmpOptions->SocksTimeout,0);}
		if(tmpOptions->SafeSocks)		CheckDlgButton(hDlg,13403,BST_CHECKED);
		if(tmpOptions->AllowNonRFC953Hostnames) CheckDlgButton(hDlg,13404,BST_CHECKED);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==13401)
		{	if(IsDlgButtonChecked(hDlg,13401)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,13102),1);getEditData1(hDlg,13102,&tmpOptions->SocksPolicy,"SocksPolicy");
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,13102),0);
				config_line_t *cfg;
				for(;;)
				{	cfg=tmpOptions->SocksPolicy;
					if(cfg==NULL) break;
					tor_free(cfg->key);tor_free(cfg->value);
					tmpOptions->SocksPolicy=cfg->next;
					tor_free(cfg);
				}
			}
			policies_parse_from_options(tmpOptions);
		}
		else if((LOWORD(wParam)==13102)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData1(hDlg,13102,&tmpOptions->SocksPolicy,"SocksPolicy");
			policies_parse_from_options(tmpOptions);
		}
		else if(LOWORD(wParam)==13402)
		{	if(IsDlgButtonChecked(hDlg,13402)==BST_CHECKED)
			{	tmpOptions->SocksTimeout=GetDlgItemInt(hDlg,13103,0,0);EnableWindow(GetDlgItem(hDlg,13103),1);
			}
			else
			{	tmpOptions->SocksTimeout=32767;EnableWindow(GetDlgItem(hDlg,13103),0);
			}
		}
		else if((LOWORD(wParam)==13103)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->SocksTimeout=GetDlgItemInt(hDlg,13103,0,0);
		else if(LOWORD(wParam)==13403)
		{	if(IsDlgButtonChecked(hDlg,13403)==BST_CHECKED)	tmpOptions->SafeSocks=1;
			else	tmpOptions->SafeSocks=0;
		}
		else if(LOWORD(wParam)==13404)
		{	if(IsDlgButtonChecked(hDlg,13404)==BST_CHECKED)	tmpOptions->AllowNonRFC953Hostnames=1;
			else	tmpOptions->AllowNonRFC953Hostnames=0;
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return	0;
}
