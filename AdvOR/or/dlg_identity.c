#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "proxy.h"

HWND hDlgIdentity=NULL;
extern HWND hMainDialog;
extern or_options_t *tmpOptions;
extern time_t time_to_change_identity;
char dlg_identity_flag = 0;

lang_dlg_info lang_dlg_identity[]={
	{12010,LANG_DLG_IDENTITY_EVENTS},
	{12400,LANG_DLG_IDENTITY_SEEDS},
	{12011,LANG_DLG_IDENTITY_SEEDS_HINT},
	{12409,LANG_DLG_IDENTITY_REINIT_KEYS},
	{12020,LANG_DLG_IDENTITY_REINIT_KEYS_HINT},
	{12401,LANG_DLG_IDENTITY_CLOSE_CONNECTIONS},
	{12012,LANG_DLG_IDENTITY_CLOSE_CONNECTIONS_HINT},
	{12402,LANG_DLG_IDENTITY_EXPIRE_CIRCUITS},
	{12013,LANG_DLG_IDENTITY_EXPIRE_CIRCUITS_HINT},
	{12403,LANG_DLG_IDENTITY_EXPIRE_ADDRESSMAPS},
	{12014,LANG_DLG_IDENTITY_EXPIRE_ADDRESSMAPS_HINT},
	{12404,LANG_DLG_IDENTITY_EXPIRE_HTTP_COOKIES},
	{12015,LANG_DLG_IDENTITY_EXPIRE_HTTP_COOKIES_HINT},
	{12405,LANG_DLG_IDENTITY_DELETE_FLASH_COOKIES},
	{12016,LANG_DLG_IDENTITY_DELETE_FLASH_COOKIES_HINT},
	{12406,LANG_DLG_IDENTITY_CLEAR_SILVERLIGHT_COOKIES},
	{12017,LANG_DLG_IDENTITY_CLEAR_SILVERLIGHT_COOKIES_HINT},
	{12407,LANG_DLG_IDENTITY_RANDOMIZE_WMPLAYER_ID},
	{12018,LANG_DLG_IDENTITY_RANDOMIZE_WMPLAYER_ID_HINT},
	{12408,LANG_DLG_IDENTITY_EXPIRE_COOKIES},
	{12019,LANG_DLG_IDENTITY_EXPIRE_COOKIES_HINT},
	{12410,LANG_DLG_IDENTITY_MESSAGEBOX},
	{12021,LANG_DLG_IDENTITY_MESSAGEBOX_HINT},
	{12411,LANG_DLG_IDENTITY_EVERY_TIME},
	{12500,LANG_DLG_IDENTITY_AUTOMATIC_IP_CHANGE},
	{12501,LANG_DLG_IDENTITY_AUTOMATIC_IDENTITY_CHANGE},
	{12412,LANG_DLG_IDENTITY_AUTOMATIC_CHANGE_HINT},
	{0,0}
};

int __stdcall dlgIdentity(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void dlgIdentity_updateFlags(void);
void dlgIdentity_langUpdate(void);

void dlgIdentity_updateFlags(void)
{	if(hDlgIdentity)
	{	if(tmpOptions->IdentityFlags & IDENTITY_FLAG_DESTROY_CIRCUITS)	CheckDlgButton(hDlgIdentity,12401,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_CIRCUITS)	CheckDlgButton(hDlgIdentity,12402,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS)	CheckDlgButton(hDlgIdentity,12403,BST_CHECKED);
	}
}

void dlgIdentity_langUpdate(void)
{
	if(LangGetLanguage())
	{	changeDialogStrings(hDlgIdentity,lang_dlg_identity);
	}
	dlg_identity_flag = 0;
	inittimeunits(hDlgIdentity,12300,12100,tmpOptions->IdentityAutoChange);
	dlg_identity_flag = 1;
}

int __stdcall dlgIdentity(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgIdentity=hDlg;
		dlgIdentity_langUpdate();
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_GENERATE_SEEDS)	CheckDlgButton(hDlg,12400,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_DESTROY_CIRCUITS)	CheckDlgButton(hDlg,12401,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_CIRCUITS)	CheckDlgButton(hDlg,12402,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS)	CheckDlgButton(hDlg,12403,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_DELETE_HTTP_COOKIES)	CheckDlgButton(hDlg,12404,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_DELETE_FLASH_COOKIES)	CheckDlgButton(hDlg,12405,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_DELETE_SILVERLIGHT_COOKIES)CheckDlgButton(hDlg,12406,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_RANDOMIZE_WMPLAYER_ID)	CheckDlgButton(hDlg,12407,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_EXPIRE_HTTP_COOKIES)	CheckDlgButton(hDlg,12408,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_REINIT_KEYS)	CheckDlgButton(hDlg,12409,BST_CHECKED);
		if(!(tmpOptions->IdentityFlags & IDENTITY_FLAG_NO_MESSAGEBOX))	CheckDlgButton(hDlg,12410,BST_CHECKED);
		if(tmpOptions->IdentityFlags & IDENTITY_FLAG_AUTO_CHANGE_IP)	CheckDlgButton(hDlg,12500,BST_CHECKED);
		else								CheckDlgButton(hDlg,12501,BST_CHECKED);
		if(!tmpOptions->IdentityAutoChange)
		{	EnableWindow(GetDlgItem(hDlg,12100),0);
			EnableWindow(GetDlgItem(hDlg,12300),0);
			EnableWindow(GetDlgItem(hDlg,12500),0);
			EnableWindow(GetDlgItem(hDlg,12501),0);
			EnableWindow(GetDlgItem(hDlg,12412),0);
		}
		else	CheckDlgButton(hDlg,12411,BST_CHECKED);
		dlg_identity_flag = 1;
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==12400)
		{	if(IsDlgButtonChecked(hDlg,12400)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_GENERATE_SEEDS;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_GENERATE_SEEDS ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12401)
		{	if(IsDlgButtonChecked(hDlg,12401)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_DESTROY_CIRCUITS;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_DESTROY_CIRCUITS ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12402)
		{	if(IsDlgButtonChecked(hDlg,12402)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_EXPIRE_CIRCUITS;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_EXPIRE_CIRCUITS ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12403)
		{	if(IsDlgButtonChecked(hDlg,12403)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12404)
		{	if(IsDlgButtonChecked(hDlg,12404)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_DELETE_HTTP_COOKIES;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_DELETE_HTTP_COOKIES ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12405)
		{	if(IsDlgButtonChecked(hDlg,12405)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_DELETE_FLASH_COOKIES;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_DELETE_FLASH_COOKIES ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12406)
		{	if(IsDlgButtonChecked(hDlg,12406)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_DELETE_SILVERLIGHT_COOKIES;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_DELETE_SILVERLIGHT_COOKIES ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12407)
		{	if(IsDlgButtonChecked(hDlg,12407)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_RANDOMIZE_WMPLAYER_ID;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_RANDOMIZE_WMPLAYER_ID ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12408)
		{	if(IsDlgButtonChecked(hDlg,12408)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_EXPIRE_HTTP_COOKIES;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_EXPIRE_HTTP_COOKIES ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12409)
		{	if(IsDlgButtonChecked(hDlg,12409)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_REINIT_KEYS;
			else						tmpOptions->IdentityFlags &= IDENTITY_FLAG_REINIT_KEYS ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12410)
		{	if(IsDlgButtonChecked(hDlg,12410)==BST_CHECKED)	tmpOptions->IdentityFlags &= IDENTITY_FLAG_NO_MESSAGEBOX ^ IDENTITY_FLAGS_ALL;
			else						tmpOptions->IdentityFlags |= IDENTITY_FLAG_NO_MESSAGEBOX;
		}
		else if((((LOWORD(wParam)==12100)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==12300)&&(HIWORD(wParam)==CBN_SELCHANGE))) && dlg_identity_flag)
		{	tmpOptions->IdentityAutoChange = gettimeunit(hDlg,12300,12100);
			if(tmpOptions->IdentityAutoChange)	time_to_change_identity = get_time(NULL)+tmpOptions->IdentityAutoChange;
		}
		else if(LOWORD(wParam)==12411 && dlg_identity_flag)
		{	if(IsDlgButtonChecked(hDlg,12411)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,12100),1);
				EnableWindow(GetDlgItem(hDlg,12300),1);
				EnableWindow(GetDlgItem(hDlg,12500),1);
				EnableWindow(GetDlgItem(hDlg,12501),1);
				EnableWindow(GetDlgItem(hDlg,12412),1);
				tmpOptions->IdentityAutoChange = gettimeunit(hDlg,12300,12100);
				if(tmpOptions->IdentityAutoChange)	time_to_change_identity = get_time(NULL)+tmpOptions->IdentityAutoChange;
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,12100),0);
				EnableWindow(GetDlgItem(hDlg,12300),0);
				EnableWindow(GetDlgItem(hDlg,12500),0);
				EnableWindow(GetDlgItem(hDlg,12501),0);
				EnableWindow(GetDlgItem(hDlg,12412),0);
				tmpOptions->IdentityAutoChange = 0;
			}
		}
		else if(LOWORD(wParam)==12500)
		{	if(IsWindowEnabled(GetDlgItem(hDlg,12500)) && IsDlgButtonChecked(hDlg,12500))
				tmpOptions->IdentityFlags |= IDENTITY_FLAG_AUTO_CHANGE_IP;
			else	tmpOptions->IdentityFlags &= IDENTITY_FLAG_AUTO_CHANGE_IP ^ IDENTITY_FLAGS_ALL;
		}
		else if(LOWORD(wParam)==12501)
		{	if(IsWindowEnabled(GetDlgItem(hDlg,12501)) && IsDlgButtonChecked(hDlg,12501))
				tmpOptions->IdentityFlags &= IDENTITY_FLAG_AUTO_CHANGE_IP ^ IDENTITY_FLAGS_ALL;
			else	tmpOptions->IdentityFlags |= IDENTITY_FLAG_AUTO_CHANGE_IP;
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return	0;
}

