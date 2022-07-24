#include "or.h"
#include "dlg_util.h"
#include "proxy.h"

HWND hDlgProxyHTTP=NULL;
extern HWND hMainDialog;
extern or_options_t *tmpOptions;
extern int lngFlag;

lang_dlg_info lang_dlg_proxy_http[]={
	{16010,LANG_DLG_HTTP_BROWSER_TYPE},
	{16011,LANG_DLG_HTTP_BROWSER_VERSION},
	{16012,LANG_DLG_HTTP_BROWSER_OS},
	{16013,LANG_DLG_HTTP_BROWSER_EXTENSIONS},
	{16014,LANG_DLG_HTTP_REGIONAL_SETTINGS},
	{16400,LANG_DLG_HTTP_REFERERS_SAME_DOMAIN},
	{16403,LANG_DLG_HTTP_REMOVE_ETAGS},
	{16404,LANG_DLG_HTTP_REMOVE_IFS},
	{16405,LANG_DLG_HTTP_REMOVE_DANGEROUS_HEADERS},
	{16406,LANG_DLG_HTTP_REMOVE_UNKNOWN_HEADERS},
	{16050,LANG_DLG_HTTP_REMOVE_HEADERS},
	{16051,LANG_DLG_HTTP_DEBUG_MESSAGES},
	{16407,LANG_DLG_HTTP_LOG_REQUESTS},
	{16408,LANG_DLG_HTTP_LOG_REQUEST_HEADERS},
	{16409,LANG_DLG_HTTP_LOG_RESPONSE_STATUS},
	{16410,LANG_DLG_HTTP_LOG_RESPONSE_TRAFFIC},
	{0,0}
};

void selectComboItem(HWND hDlg,int combo,int data);
void dlgProxyHttp_langUpdate(void);
int __stdcall dlgProxyHTTP(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void selectComboItem(HWND hDlg,int combo,int data)
{	int i=0,j;
	while(1)
	{	j = SendDlgItemMessage(hDlg,combo,CB_GETITEMDATA,i,0);
		if(j == CB_ERR)	return;
		if(j == data)	break;
		i++;
	}
	SendDlgItemMessage(hDlg,combo,CB_SETCURSEL,i,0);
}

void dlgProxyHttp_langUpdate(void)
{	if(!hDlgProxyHTTP)	return;
	if(LangGetLanguage())
	{	changeDialogStrings(hDlgProxyHTTP,lang_dlg_proxy_http);
	}
	lngFlag |= LANGUAGE_FLAG_UPDATING_COMBOBOXES;
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_ORIGINAL),BROWSER_AUTODETECT);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_NOCHANGE),BROWSER_NOCHANGE);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_IDENTITY),BROWSER_IDENTITY);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_CHROME),BROWSER_CHROME);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_FIREFOX),BROWSER_FIREFOX);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_IE),BROWSER_IE);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_OPERA),BROWSER_OPERA);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_SAFARI),BROWSER_SAFARI);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_UTORRENT),BROWSER_UTORRENT);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_BING),BROWSER_BING);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_GOOGLE),BROWSER_GOOGLEBOT);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_YAHOO),BROWSER_YAHOO);
	SendDlgItemMessage(hDlgProxyHTTP,16300,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16300,LANG_DLG_HTTP_BROWSER_TYPE_YANDEX),BROWSER_YANDEX);
	selectComboItem(hDlgProxyHTTP,16300,tmpOptions->HTTPAgent);
	SendDlgItemMessage(hDlgProxyHTTP,16301,CB_RESETCONTENT,0,0);
//	SendDlgItemMessage(hDlgProxyHTTP,16301,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16301,LANG_DLG_HTTP_BROWSER_VERSION_ORIGINAL),BROWSER_VERSION_ORIGINAL);
	SendDlgItemMessage(hDlgProxyHTTP,16301,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16301,LANG_DLG_HTTP_BROWSER_VERSION_IDENTITY_MINOR),BROWSER_VERSION_IDENTITY_MINOR);
	SendDlgItemMessage(hDlgProxyHTTP,16301,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16301,LANG_DLG_HTTP_BROWSER_VERSION_IDENTITY_MAJOR),BROWSER_VERSION_IDENTITY_MAJOR);
	selectComboItem(hDlgProxyHTTP,16301,tmpOptions->HTTPFlags&(BROWSER_VERSION_IDENTITY_MINOR|BROWSER_VERSION_IDENTITY_MAJOR));
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16302,LANG_DLG_HTTP_BROWSER_OS_ORIGINAL),BROWSER_OS_ORIGINAL);
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16302,LANG_DLG_HTTP_BROWSER_OS_ANY),BROWSER_OS_ANY);
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16302,LANG_DLG_HTTP_BROWSER_OS_WINDOWS),BROWSER_OS_WINDOWS);
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16302,LANG_DLG_HTTP_BROWSER_OS_LINUX),BROWSER_OS_LINUX);
	SendDlgItemMessage(hDlgProxyHTTP,16302,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16302,LANG_DLG_HTTP_BROWSER_OS_OSX),BROWSER_OS_OSX);
	selectComboItem(hDlgProxyHTTP,16302,tmpOptions->HTTPOS);
	SendDlgItemMessage(hDlgProxyHTTP,16303,CB_RESETCONTENT,0,0);
//	SendDlgItemMessage(hDlgProxyHTTP,16303,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16303,LANG_DLG_HTTP_BROWSER_EXTENSIONS_EXISTING),HTTP_SETTING_ORIG_UA_EXTENSIONS);
	SendDlgItemMessage(hDlgProxyHTTP,16303,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16303,LANG_DLG_HTTP_BROWSER_EXTENSIONS_HIDE_ALL),HTTP_SETTING_HIDE_EXTENSIONS);
	SendDlgItemMessage(hDlgProxyHTTP,16303,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16303,LANG_DLG_HTTP_BROWSER_EXTENSIONS_IDENTITY),HTTP_SETTING_IDENTITY_UA_EXTENSIONS);
	selectComboItem(hDlgProxyHTTP,16303,tmpOptions->HTTPFlags&(HTTP_SETTING_HIDE_EXTENSIONS|HTTP_SETTING_IDENTITY_UA_EXTENSIONS));
	SendDlgItemMessage(hDlgProxyHTTP,16304,CB_RESETCONTENT,0,0);
	SendDlgItemMessage(hDlgProxyHTTP,16304,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16304,LANG_DLG_HTTP_REGIONAL_SETTINGS_ORIGINAL),REGIONAL_SETTINGS_ORIGINAL);
	SendDlgItemMessage(hDlgProxyHTTP,16304,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16304,LANG_DLG_HTTP_REGIONAL_SETTINGS_US_ENGLISH),REGIONAL_SETTINGS_US_ENGLISH);
	SendDlgItemMessage(hDlgProxyHTTP,16304,CB_SETITEMDATA,LangCbAddString(hDlgProxyHTTP,16304,LANG_DLG_HTTP_REGIONAL_SETTINGS_IDENTITY),REGIONAL_SETTINGS_EXIT);
	selectComboItem(hDlgProxyHTTP,16304,tmpOptions->RegionalSettings);
	lngFlag &= LANGUAGE_FLAG_UPDATING_COMBOBOXES ^ 0xffff;
}

int __stdcall dlgProxyHTTP(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgProxyHTTP=hDlg;
		dlgProxyHttp_langUpdate();
		if(tmpOptions->HTTPFlags & HTTP_SETTING_REFERER_SAME_DOMAIN)	CheckDlgButton(hDlg,16400,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_ETAGS)		CheckDlgButton(hDlg,16403,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_IFS)		CheckDlgButton(hDlg,16404,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_CLIENT_IP)	CheckDlgButton(hDlg,16405,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_REMOVE_UNKNOWN)		CheckDlgButton(hDlg,16406,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUESTS)		CheckDlgButton(hDlg,16407,BST_CHECKED);
		else								EnableWindow(GetDlgItem(hDlg,16408),0);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_REQUEST_HEADERS)	CheckDlgButton(hDlg,16408,BST_CHECKED);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_STATUS)	CheckDlgButton(hDlg,16409,BST_CHECKED);
		else								EnableWindow(GetDlgItem(hDlg,16410),0);
		if(tmpOptions->HTTPFlags & HTTP_SETTING_LOG_RESPONSE_TRAFFIC)	CheckDlgButton(hDlg,16410,BST_CHECKED);
		if(tmpOptions->BannedHeaders!=NULL)
		{	char *tmp1=tor_malloc(65536),*tmp2;
			int i=0,j;
			tmp2=tmp1;
			config_line_t *cfg;
			for(cfg=tmpOptions->BannedHeaders;cfg;cfg=cfg->next)
			{	for(j=0;i<65530;i++,j++)
				{	if(!cfg->value[j]) break;
					*tmp1++=cfg->value[j];
				}
				*tmp1++=13;*tmp1++=10;i+=2;
				if(i>65530) break;
			}
			*tmp1=0;
			SetDlgItemText(hDlg,16100,tmp2);
			tor_free(tmp2);
		}
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==16400)
		{	if(IsDlgButtonChecked(hDlg,16400)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_REFERER_SAME_DOMAIN;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_REFERER_SAME_DOMAIN ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16403)
		{	if(IsDlgButtonChecked(hDlg,16403)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_REMOVE_ETAGS;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_REMOVE_ETAGS ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16404)
		{	if(IsDlgButtonChecked(hDlg,16404)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_REMOVE_IFS;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_REMOVE_IFS ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16405)
		{	if(IsDlgButtonChecked(hDlg,16405)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_REMOVE_CLIENT_IP;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_REMOVE_CLIENT_IP ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16406)
		{	if(IsDlgButtonChecked(hDlg,16406)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_REMOVE_UNKNOWN;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_REMOVE_UNKNOWN ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16407)
		{	if(IsDlgButtonChecked(hDlg,16407)==BST_CHECKED)
			{	tmpOptions->HTTPFlags |= HTTP_SETTING_LOG_REQUESTS;
				EnableWindow(GetDlgItem(hDlg,16408),1);
			}
			else
			{	tmpOptions->HTTPFlags &= HTTP_SETTING_LOG_REQUESTS ^ 0xffffffff;
				EnableWindow(GetDlgItem(hDlg,16408),0);
			}
		}
		else if(LOWORD(wParam)==16408)
		{	if(IsDlgButtonChecked(hDlg,16408)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_LOG_REQUEST_HEADERS;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_LOG_REQUEST_HEADERS ^ 0xffffffff;
		}
		else if(LOWORD(wParam)==16409)
		{	if(IsDlgButtonChecked(hDlg,16409)==BST_CHECKED)
			{	tmpOptions->HTTPFlags |= HTTP_SETTING_LOG_RESPONSE_STATUS;
				EnableWindow(GetDlgItem(hDlg,16410),1);
			}
			else
			{	tmpOptions->HTTPFlags &= HTTP_SETTING_LOG_RESPONSE_STATUS ^ 0xffffffff;
				EnableWindow(GetDlgItem(hDlg,16410),0);
			}
		}
		else if(LOWORD(wParam)==16410)
		{	if(IsDlgButtonChecked(hDlg,16410)==BST_CHECKED)	tmpOptions->HTTPFlags |= HTTP_SETTING_LOG_RESPONSE_TRAFFIC;
			else						tmpOptions->HTTPFlags &= HTTP_SETTING_LOG_RESPONSE_TRAFFIC ^ 0xffffffff;
		}
		else if((LOWORD(wParam)==16100)&&(HIWORD(wParam)==EN_CHANGE))
			getEditData(hDlg,16100,&tmpOptions->BannedHeaders,"BannedHeaders");
		else if(!(lngFlag & LANGUAGE_FLAG_UPDATING_COMBOBOXES))
		{	if(LOWORD(wParam)==16300 && HIWORD(wParam)==CBN_SELCHANGE)
			{	int i = SendDlgItemMessage(hDlg,16300,CB_GETCURSEL,0,0);
				if(i != CB_ERR)
				{	i = SendDlgItemMessage(hDlg,16300,CB_GETITEMDATA,i,0);
					if(i != CB_ERR)
					{	tmpOptions->HTTPAgent = i;
					}
				}
			}
			else if(LOWORD(wParam)==16301 && HIWORD(wParam)==CBN_SELCHANGE)
			{	int i = SendDlgItemMessage(hDlg,16301,CB_GETCURSEL,0,0);
				if(i != CB_ERR)
				{	i = SendDlgItemMessage(hDlg,16301,CB_GETITEMDATA,i,0);
					if(i != CB_ERR)
					{	tmpOptions->HTTPFlags &= 0xffffffff ^ (BROWSER_VERSION_IDENTITY_MINOR|BROWSER_VERSION_IDENTITY_MAJOR);
						tmpOptions->HTTPFlags |= i&(BROWSER_VERSION_IDENTITY_MINOR|BROWSER_VERSION_IDENTITY_MAJOR);
					}
				}
			}
			else if(LOWORD(wParam)==16302 && HIWORD(wParam)==CBN_SELCHANGE)
			{	int i = SendDlgItemMessage(hDlg,16302,CB_GETCURSEL,0,0);
				if(i != CB_ERR)
				{	i = SendDlgItemMessage(hDlg,16302,CB_GETITEMDATA,i,0);
					if(i != CB_ERR)
					{	tmpOptions->HTTPOS = i;
					}
				}
			}
			else if(LOWORD(wParam)==16303 && HIWORD(wParam)==CBN_SELCHANGE)
			{	int i = SendDlgItemMessage(hDlg,16303,CB_GETCURSEL,0,0);
				if(i != CB_ERR)
				{	i = SendDlgItemMessage(hDlg,16303,CB_GETITEMDATA,i,0);
					if(i != CB_ERR)
					{	tmpOptions->HTTPFlags &= (HTTP_SETTING_HIDE_EXTENSIONS|HTTP_SETTING_IDENTITY_UA_EXTENSIONS) ^ 0xffffffff;
						tmpOptions->HTTPFlags |= i&(HTTP_SETTING_HIDE_EXTENSIONS|HTTP_SETTING_IDENTITY_UA_EXTENSIONS);
					}
				}
			}
			else if(LOWORD(wParam)==16304 && HIWORD(wParam)==CBN_SELCHANGE)
			{	int i = SendDlgItemMessage(hDlg,16304,CB_GETCURSEL,0,0);
				if(i != CB_ERR)
				{	i = SendDlgItemMessage(hDlg,16304,CB_GETITEMDATA,i,0);
					if(i != CB_ERR)
					{	tmpOptions->RegionalSettings = i;
					}
				}
			}
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return	0;
}
