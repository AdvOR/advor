#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "connection.h"

HWND hDlgSystem=NULL;
HANDLE hEdit1;
extern or_options_t *tmpOptions;
extern HWND hMainDialog;
extern HINSTANCE hInstance;
extern char *password;
extern DWORD password_size;
extern int encryption;
int hkreg=0;
//int frame3[]={11400,11401,11402,11010,11011,11300,11100,11301,11403,11404,11405,11101,11012,11013,11102,11406,11103,11050,11104,-1};
lang_dlg_info lang_dlg_system[]={
	{11010,LANG_DLG_ADVERTISED_OS},
	{11011,LANG_DLG_ADVERTISED_TORVER},
	{11013,LANG_DLG_LANGUAGE},
	{11400,LANG_DLG_START_AUTOMATICALLY},
	{11401,LANG_DLG_MINIMIZE_AT_STARTUP},
	{11402,LANG_DLG_START_WITH_WINDOWS},
	{11403,LANG_DLG_USE_HW_ACCEL},
	{11404,LANG_DLG_FLASH_MEM},
	{11405,LANG_DLG_CONTROL_PORT},
	{11012,LANG_DLG_CONTROL_ADDRESS},
	{11406,LANG_DLG_CONTROL_PASSWORD},
	{11050,LANG_DLG_SYSTEM_HOTKEYS},
	{11110,LANG_DLG_SYSTEM_HOTKEY_RESTORE},
	{11104,LANG_DLG_SYSTEM_HOTKEY_NEW_IDENTITY},
	{11105,LANG_DLG_SYSTEM_HOTKEY_INTERCEPT},
	{11106,LANG_DLG_SYSTEM_HOTKEY_RELEASE},
	{11116,LANG_DLG_SYSTEM_HOTKEY_HIDEALL},
	{11117,LANG_DLG_SYSTEM_HOTKEY_PAUSEALL},
	{11118,LANG_DLG_SYSTEM_HOTKEY_RESUMEALL},
	{11112,LANG_DLG_CONFIRM_CONNECTIONS},
	{11113,LANG_DLG_CONFIRM_EXIT},
	{11114,LANG_DLG_CONFIRM_EXIT_RELEASE},
	{11115,LANG_SYSTEM_ENCRYPT},
	{11001,LANG_SYSTEM_NEW_PASS},
	{0,0}
};

lang_dlg_info lang_dlg_password[]={
	{10,LANG_SYSTEM_ENTER_PASSWORD},
	{500,LANG_SYSTEM_USE_PASSWORD},
	{11,LANG_SYSTEM_REENTER},
	{501,LANG_SYSTEM_KEYFILE},
	{12,LANG_SYSTEM_FILE_OFFSET},
	{1,LANG_SYSTEM_PASSWORD_OK},
	{2,LANG_SYSTEM_PASSWORD_CANCEL},
	{0,0}
};

const char runkey[]="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
const char valuename[]="AdvOR";
const char voidmsg[]="\0";

int __stdcall dlgPassword(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void addTorVer(const char *newVer);
void dlgSystem_UnregisterHotKeys(void);
void dlgSystem_RegisterHotKeys(void);
void dlgSystem_RegisterRestoreHotKey(void);
int __stdcall dlgSystem(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgGetPassword(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void addTorVer(const char *newVer)
{	if(!hDlgSystem)	return;
	if(newVer)	SendDlgItemMessage(hDlgSystem,11100,CB_ADDSTRING,0,(LPARAM)newVer);
	else
	{	while(1)
		{	if(SendDlgItemMessage(hDlgSystem,11100,CB_DELETESTRING,0,0)==CB_ERR) break;
		}
	}
}

void dlgSystem_UnregisterHotKeys(void)
{	if((hkreg & 1) != 0)
	{	if(UnregisterHotKey(hMainDialog,11700))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_NEW_IDENTITY_UNREGISTER));
			hkreg &= 1 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_NEW_IDENTITY_UNREGISTER_FAIL));
	}
	if((hkreg & 2) != 0)
	{	if(UnregisterHotKey(hMainDialog,11701))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_INTERCEPT_UNREGISTER));
			hkreg &= 2 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_INTERCEPT_UNREGISTER_FAIL));
	}
	if((hkreg & 4) != 0)
	{	if(UnregisterHotKey(hMainDialog,11702))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RELEASE_UNREGISTER));
			hkreg &= 4 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RELEASE_UNREGISTER_FAIL));
	}
	if((hkreg & 8) != 0)
	{	if(UnregisterHotKey(hMainDialog,11703))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTORE_UNREGISTER));
			hkreg &= 8 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTORE_UNREGISTER_FAIL));
	}
	if((hkreg & 16) != 0)
	{	if(UnregisterHotKey(hMainDialog,11704))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_HIDEALL_UNREGISTER));
			hkreg &= 16 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_HIDEALL_UNREGISTER_FAIL));
	}
	if((hkreg & 32) != 0)
	{	if(UnregisterHotKey(hMainDialog,11705))
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTOREALL_UNREGISTER));
			hkreg &= 32 ^ 0xff;
		}
		else	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTOREALL_UNREGISTER_FAIL));
	}
}

void dlgSystem_RegisterHotKeys(void)
{	dlgSystem_UnregisterHotKeys();
	if((tmpOptions->HotkeyNewIdentity & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11700,((tmpOptions->HotkeyNewIdentity >> 8) & 0x0f),(tmpOptions->HotkeyNewIdentity & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_NEW_IDENTITY_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_NEW_IDENTITY_SUCCESS));
			hkreg |= 1;
		}
	}
	if((tmpOptions->HotkeyIntercept & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11701,((tmpOptions->HotkeyIntercept >> 8) & 0x0f),(tmpOptions->HotkeyIntercept & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_INTERCEPT_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_INTERCEPT_SUCCESS));
			hkreg |= 2;
		}
	}
	if((tmpOptions->HotkeyRelease & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11702,((tmpOptions->HotkeyRelease >> 8) & 0x0f),(tmpOptions->HotkeyRelease & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RELEASE_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RELEASE_SUCCESS));
			hkreg |= 4;
		}
	}
	if((tmpOptions->HotkeyRestore & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11703,((tmpOptions->HotkeyRestore >> 8) & 0x0f),(tmpOptions->HotkeyRestore & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTORE_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTORE_SUCCESS));
			hkreg |= 8;
		}
	}
	if((tmpOptions->HotkeyHideAll & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11704,((tmpOptions->HotkeyHideAll >> 8) & 0x0f),(tmpOptions->HotkeyHideAll & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_HIDEALL_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_HIDEALL_SUCCESS));
			hkreg |= 16;
		}
	}
}

void dlgSystem_RegisterRestoreHotKey(void)
{
	if((tmpOptions->HotkeyRestoreAll & 0x1000) != 0)
	{	if(!RegisterHotKey(hMainDialog,11705,((tmpOptions->HotkeyRestoreAll >> 8) & 0x0f),(tmpOptions->HotkeyRestoreAll & 0xff)))
			log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTOREALL_FAIL));
		else
		{	log(LOG_INFO,LD_APP,get_lang_str(LANG_LOG_DLG_HOTKEY_RESTOREALL_SUCCESS));
			hkreg |= 32;
		}
	}
}

int __stdcall dlgSystem(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgSystem=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_system);
		}
		enumLanguages(GetDlgItem(hDlg,11301),tmpOptions->Language);
		if(tmpOptions->AutoStart&1)	CheckDlgButton(hDlg,11400,BST_CHECKED);
		if(tmpOptions->AutoStart&2)	CheckDlgButton(hDlg,11401,BST_CHECKED);
		if(tmpOptions->AutoStart&4)	CheckDlgButton(hDlg,11402,BST_CHECKED);
		if(tmpOptions->HardwareAccel)	CheckDlgButton(hDlg,11403,BST_CHECKED);
		if(tmpOptions->AvoidDiskWrites)	CheckDlgButton(hDlg,11404,BST_CHECKED);
		hEdit1=FindWindowEx(GetDlgItem(hDlg,11300),NULL,NULL,NULL);
		int i;
		SendDlgItemMessage(hDlg,11300,CB_ADDSTRING,0,(LPARAM)"<< Random >>");
		for(i=0;i<41;i++) SendDlgItemMessage(hDlg,11300,CB_ADDSTRING,0,(LPARAM)versions[i]);
		SetDlgItemText(hDlg,11300,tmpOptions->winver);
		SendDlgItemMessage(hDlg,11100,CB_ADDSTRING,0,(LPARAM)"<< Auto >>");
		SetDlgItemText(hDlg,11100,tmpOptions->SelectedTorVer);
		if(tmpOptions->ControlPort){ CheckDlgButton(hDlg,11405,BST_CHECKED);SetDlgItemInt(hDlg,11101,tmpOptions->ControlPort,0);}
		else{	EnableWindow(GetDlgItem(hDlg,11101),0);EnableWindow(GetDlgItem(hDlg,11012),0);EnableWindow(GetDlgItem(hDlg,11102),0);EnableWindow(GetDlgItem(hDlg,11406),0);EnableWindow(GetDlgItem(hDlg,11103),0);}
		if(tmpOptions->ControlListenAddress)	SetDlgItemText(hDlg,11102,(LPCSTR)tmpOptions->ControlListenAddress->value);
		else SetDlgItemText(hDlg,11102,"127.0.0.1");
		if(tmpOptions->CookieAuthentication){ CheckDlgButton(hDlg,11406,BST_CHECKED); if(tmpOptions->HashedControlPassword)  SetDlgItemText(hDlg,11103,(LPCSTR)tmpOptions->HashedControlPassword->value);}
		else	EnableWindow(GetDlgItem(hDlg,11103),0);
		if((tmpOptions->HotkeyNewIdentity & 0x800)!=0)	CheckDlgButton(hDlg,11107,BST_CHECKED);
		if((tmpOptions->HotkeyIntercept & 0x800)!=0)	CheckDlgButton(hDlg,11108,BST_CHECKED);
		if((tmpOptions->HotkeyRelease & 0x800)!=0)	CheckDlgButton(hDlg,11109,BST_CHECKED);
		if((tmpOptions->HotkeyRestore & 0x800)!=0)	CheckDlgButton(hDlg,11111,BST_CHECKED);
		if((tmpOptions->HotkeyHideAll & 0x800)!=0)	CheckDlgButton(hDlg,11119,BST_CHECKED);
		if((tmpOptions->HotkeyRestoreAll & 0x800)!=0)	CheckDlgButton(hDlg,11121,BST_CHECKED);
		if((tmpOptions->HotkeyHideAll & 0x2000)!=0)	CheckDlgButton(hDlg,11117,BST_CHECKED);
		SendDlgItemMessage(hDlg,11200,HKM_SETHOTKEY,(tmpOptions->HotkeyNewIdentity & 0xfff),0);
		SendDlgItemMessage(hDlg,11201,HKM_SETHOTKEY,(tmpOptions->HotkeyIntercept & 0xfff),0);
		SendDlgItemMessage(hDlg,11202,HKM_SETHOTKEY,(tmpOptions->HotkeyRelease & 0xfff),0);
		SendDlgItemMessage(hDlg,11203,HKM_SETHOTKEY,(tmpOptions->HotkeyRestore & 0xfff),0);
		SendDlgItemMessage(hDlg,11120,HKM_SETHOTKEY,(tmpOptions->HotkeyHideAll & 0xfff),0);
		SendDlgItemMessage(hDlg,11122,HKM_SETHOTKEY,(tmpOptions->HotkeyRestoreAll & 0xfff),0);
		if((tmpOptions->HotkeyNewIdentity & 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11107),0);
			EnableWindow(GetDlgItem(hDlg,11200),0);
		}
		else	CheckDlgButton(hDlg,11104,BST_CHECKED);
		if((tmpOptions->HotkeyIntercept & 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11108),0);
			EnableWindow(GetDlgItem(hDlg,11201),0);
		}
		else	CheckDlgButton(hDlg,11105,BST_CHECKED);
		if((tmpOptions->HotkeyRelease& 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11109),0);
			EnableWindow(GetDlgItem(hDlg,11202),0);
		}
		else	CheckDlgButton(hDlg,11106,BST_CHECKED);
		if((tmpOptions->HotkeyRestore& 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11111),0);
			EnableWindow(GetDlgItem(hDlg,11203),0);
		}
		else	CheckDlgButton(hDlg,11110,BST_CHECKED);
		if((tmpOptions->HotkeyHideAll& 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11119),0);
			EnableWindow(GetDlgItem(hDlg,11120),0);
			EnableWindow(GetDlgItem(hDlg,11117),0);
			EnableWindow(GetDlgItem(hDlg,11118),0);
			EnableWindow(GetDlgItem(hDlg,11121),0);
			EnableWindow(GetDlgItem(hDlg,11122),0);
		}
		else	CheckDlgButton(hDlg,11116,BST_CHECKED);
		if((tmpOptions->HotkeyRestoreAll& 0x1000)==0)
		{	EnableWindow(GetDlgItem(hDlg,11121),0);
			EnableWindow(GetDlgItem(hDlg,11122),0);
		}
		else	CheckDlgButton(hDlg,11118,BST_CHECKED);
		if((tmpOptions->Confirmations & CONFIRM_VERIFY_CONNECTIONS)!=0)
		{	if((tmpOptions->Confirmations & CONFIRM_CLOSE_CONNECTIONS) != 0)
				CheckDlgButton(hDlg,11112,BST_INDETERMINATE);
			else	CheckDlgButton(hDlg,11112,BST_CHECKED);
		}
		if((tmpOptions->Confirmations & CONFIRM_EXIT) != 0)
			CheckDlgButton(hDlg,11113,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,11114),0);
		if((tmpOptions->Confirmations & CONFIRM_EXIT_ONLY_RELEASE) != 0)
			CheckDlgButton(hDlg,11114,BST_CHECKED);
		if(encryption & 2)	CheckDlgButton(hDlg,11115,BST_CHECKED);
		else			EnableWindow(GetDlgItem(hDlg,11001),0);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==11300)
		{	if((HIWORD(wParam)==CBN_EDITCHANGE)||(HIWORD(wParam)==CBN_EDITUPDATE))
			{	int tmpsize=SendMessage(hEdit1,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendMessage(hEdit1,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->winver;
				tmpOptions->winver=tmp1;tor_free(tmp2);
			}
			else if(HIWORD(wParam)==CBN_SELCHANGE)
			{	char *tmp1=tor_malloc(SendDlgItemMessage(hDlg,11300,CB_GETLBTEXTLEN,SendDlgItemMessage(hDlg,11300,CB_GETCURSEL,0,0),(LPARAM)0)+16);
				SendDlgItemMessage(hDlg,11300,CB_GETLBTEXT,SendDlgItemMessage(hDlg,11300,CB_GETCURSEL,0,0),(LPARAM)tmp1);
				char *tmp2=tmpOptions->winver;
				tmpOptions->winver=tmp1;tor_free(tmp2);
			}
		}
		else if((LOWORD(wParam)==11301)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	if(tmpOptions->Language) tor_free(tmpOptions->Language);
			tmpOptions->Language=tor_malloc(100);
			tmpOptions->Language[0]=0;
			LPWSTR lstr = tor_malloc(MAX_PATH * 2);
			SendDlgItemMessageW(hDlg,11301,CB_GETLBTEXT,SendDlgItemMessage(hDlg,11301,CB_GETCURSEL,0,0),(LPARAM)lstr);
			char *ustr = get_utf(lstr);
			tor_free(lstr);
			tor_free(tmpOptions->Language);
			tmpOptions->Language = ustr;
			ustr=getLanguageFileName(tmpOptions->Language);
			if(tmpOptions->Language[0]=='<' || load_lng(ustr))
			{	setNewLanguage();
				if(get_lang_str(LANG_STR_ABOUT_LNG))	log(LOG_WARN,LD_APP,get_lang_str(LANG_STR_ABOUT_LNG));
			}
			tor_free(ustr);
		}
		else if(LOWORD(wParam)==11400)
		{	if(IsDlgButtonChecked(hDlg,11400)==BST_CHECKED)	tmpOptions->AutoStart|=1;
			else	tmpOptions->AutoStart&=0xfe;
		}
		else if(LOWORD(wParam)==11401)
		{	if(IsDlgButtonChecked(hDlg,11401)==BST_CHECKED)	tmpOptions->AutoStart|=2;
			else	tmpOptions->AutoStart&=0xff^2;
		}
		else if(LOWORD(wParam)==11402)
		{	HKEY hKey;
			char *tmp1,*tmp2=tor_malloc(4);
			if(IsDlgButtonChecked(hDlg,11402)==BST_CHECKED)
			{	tmpOptions->AutoStart|=4;
				CheckDlgButton(hDlg,11402,BST_CHECKED);
				tmp1=tor_malloc(MAX_PATH+1);GetModuleFileName(0,tmp1,MAX_PATH);
				int tmpsize=strlen(tmp1)+1;
				if(RegCreateKeyEx(HKEY_CURRENT_USER,runkey,0,(LPTSTR)&voidmsg,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,(PHKEY)&hKey,(LPDWORD)tmp2)==ERROR_SUCCESS)
				{	RegSetValueEx(hKey,valuename,0,REG_SZ,(BYTE *)tmp1,tmpsize);
					RegCloseKey(hKey);
				}
				tor_free(tmp1);
			}
			else
			{	tmpOptions->AutoStart&=0xff^4;
				if(RegCreateKeyEx(HKEY_CURRENT_USER,runkey,0,(LPTSTR)&voidmsg,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,(PHKEY)&hKey,(LPDWORD)tmp2)==ERROR_SUCCESS)
				{	RegDeleteValue(hKey,valuename);
					RegCloseKey(hKey);
				}
			}
			tor_free(tmp2);
		}
		else if(LOWORD(wParam)==11403)
		{	if(IsDlgButtonChecked(hDlg,11403)==BST_CHECKED)	tmpOptions->HardwareAccel=1;
			else	tmpOptions->HardwareAccel=0;
		}
		else if(LOWORD(wParam)==11404)
		{	if(IsDlgButtonChecked(hDlg,11404)==BST_CHECKED)	tmpOptions->AvoidDiskWrites=1;
			else	tmpOptions->AvoidDiskWrites=0;
		}
		else if(LOWORD(wParam)==11405)
		{	if(IsDlgButtonChecked(hDlg,11405)==BST_CHECKED)
			{	tmpOptions->ControlPort=GetDlgItemInt(hDlg,11101,0,0);
				EnableWindow(GetDlgItem(hDlg,11101),1);EnableWindow(GetDlgItem(hDlg,11012),1);EnableWindow(GetDlgItem(hDlg,11102),1);EnableWindow(GetDlgItem(hDlg,11406),1);
				if(tmpOptions->CookieAuthentication)	EnableWindow(GetDlgItem(hDlg,11103),1);
				retry_all_listeners(0,0);
			}
			else
			{	tmpOptions->ControlPort=0; EnableWindow(GetDlgItem(hDlg,11101),0);EnableWindow(GetDlgItem(hDlg,11012),0);EnableWindow(GetDlgItem(hDlg,11102),0);EnableWindow(GetDlgItem(hDlg,11406),0);EnableWindow(GetDlgItem(hDlg,11103),0);
				retry_all_listeners(0,0);
			}
		}
		else if(LOWORD(wParam)==11406)
		{	if(IsDlgButtonChecked(hDlg,11406)==BST_CHECKED)
			{	tmpOptions->CookieAuthentication=1;EnableWindow(GetDlgItem(hDlg,11103),1);}
			else
			{	tmpOptions->CookieAuthentication=0;EnableWindow(GetDlgItem(hDlg,11103),0);}
		}
		else if((LOWORD(wParam)==11101)&&(HIWORD(wParam)==EN_CHANGE))
		{	tmpOptions->ControlPort=GetDlgItemInt(hDlg,11101,0,0);
			retry_all_listeners(0,0);
		}
		else if((LOWORD(wParam)==11102)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData(hDlg,11102,&tmpOptions->ControlListenAddress,"ControlListenAddress");
			retry_all_listeners(0,0);
		}
		else if((LOWORD(wParam)==11103)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData(hDlg,11103,&tmpOptions->HashedControlPassword,"HashedControlPassword");
		}
		else if((LOWORD(wParam)==11100)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,11100,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,11100,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->SelectedTorVer;
			tmpOptions->SelectedTorVer=tmp1;
			if(tmpOptions->SelectedTorVer[0]!='<')
			{	tmp1=tmpOptions->torver;
				tmpOptions->torver=tor_strdup(tmpOptions->SelectedTorVer);
				if(tmp1)	tor_free(tmp1);
			}
			tor_free(tmp2);
		}
		else if(LOWORD(wParam)==11104)
		{	if(IsDlgButtonChecked(hDlg,11104)==BST_CHECKED)
			{	tmpOptions->HotkeyNewIdentity|=0x1000;
				EnableWindow(GetDlgItem(hDlg,11107),1);EnableWindow(GetDlgItem(hDlg,11200),1);
			}
			else
			{	tmpOptions->HotkeyNewIdentity&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11107),0);EnableWindow(GetDlgItem(hDlg,11200),0);
			}
			tmpOptions->HotkeyNewIdentity &= 0xf800;
			tmpOptions->HotkeyNewIdentity |= SendDlgItemMessage(hDlg,11200,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11105)
		{	if(IsDlgButtonChecked(hDlg,11105)==BST_CHECKED)
			{	tmpOptions->HotkeyIntercept|=0x1000;
				EnableWindow(GetDlgItem(hDlg,11108),1);EnableWindow(GetDlgItem(hDlg,11201),1);
			}
			else
			{	tmpOptions->HotkeyIntercept&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11108),0);EnableWindow(GetDlgItem(hDlg,11201),0);
			}
			tmpOptions->HotkeyIntercept &= 0xf800;
			tmpOptions->HotkeyIntercept |= SendDlgItemMessage(hDlg,11201,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11106)
		{	if(IsDlgButtonChecked(hDlg,11106)==BST_CHECKED)
			{	tmpOptions->HotkeyRelease|=0x1000;
				EnableWindow(GetDlgItem(hDlg,11109),1);EnableWindow(GetDlgItem(hDlg,11202),1);
			}
			else
			{	tmpOptions->HotkeyRelease&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11109),0);EnableWindow(GetDlgItem(hDlg,11202),0);
			}
			tmpOptions->HotkeyRelease &= 0xf800;
			tmpOptions->HotkeyRelease |= SendDlgItemMessage(hDlg,11202,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11110)
		{	if(IsDlgButtonChecked(hDlg,11110)==BST_CHECKED)
			{	tmpOptions->HotkeyRestore|=0x1000;
				EnableWindow(GetDlgItem(hDlg,11111),1);EnableWindow(GetDlgItem(hDlg,11203),1);
			}
			else
			{	tmpOptions->HotkeyRestore&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11111),0);EnableWindow(GetDlgItem(hDlg,11203),0);
			}
			tmpOptions->HotkeyRestore &= 0xf800;
			tmpOptions->HotkeyRestore |= SendDlgItemMessage(hDlg,11203,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11116)
		{	if(IsDlgButtonChecked(hDlg,11116)==BST_CHECKED)
			{	tmpOptions->HotkeyHideAll|=0x1000;
				EnableWindow(GetDlgItem(hDlg,11119),1);EnableWindow(GetDlgItem(hDlg,11120),1);
				EnableWindow(GetDlgItem(hDlg,11117),1);EnableWindow(GetDlgItem(hDlg,11118),1);
				if((tmpOptions->HotkeyRestoreAll& 0x1000)!=0)
				{	EnableWindow(GetDlgItem(hDlg,11121),1);EnableWindow(GetDlgItem(hDlg,11122),1);
				}
			}
			else
			{	tmpOptions->HotkeyHideAll&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11119),0);EnableWindow(GetDlgItem(hDlg,11120),0);
				EnableWindow(GetDlgItem(hDlg,11117),0);EnableWindow(GetDlgItem(hDlg,11118),0);
				EnableWindow(GetDlgItem(hDlg,11121),0);EnableWindow(GetDlgItem(hDlg,11122),0);
			}
			tmpOptions->HotkeyHideAll &= 0xf800;
			tmpOptions->HotkeyHideAll |= SendDlgItemMessage(hDlg,11120,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11118)
		{	if(IsDlgButtonChecked(hDlg,11118)==BST_CHECKED)
			{	tmpOptions->HotkeyRestoreAll|=0x1000;
				if((tmpOptions->HotkeyHideAll& 0x1000)!=0)
				{	EnableWindow(GetDlgItem(hDlg,11121),1);EnableWindow(GetDlgItem(hDlg,11122),1);}
			}
			else
			{	tmpOptions->HotkeyRestoreAll&=0xffff^0x1000;
				EnableWindow(GetDlgItem(hDlg,11121),0);EnableWindow(GetDlgItem(hDlg,11122),0);
			}
			tmpOptions->HotkeyRestoreAll &= 0xf800;
			tmpOptions->HotkeyRestoreAll |= SendDlgItemMessage(hDlg,11122,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11117)
		{	if(IsDlgButtonChecked(hDlg,11117)==BST_CHECKED)
				tmpOptions->HotkeyHideAll|=0x2000;
			else	tmpOptions->HotkeyHideAll&=0xffff^0x2000;
		}
		else if(LOWORD(wParam)==11107)
		{	if(IsDlgButtonChecked(hDlg,11107)==BST_CHECKED)	tmpOptions->HotkeyNewIdentity |= 0x800;
			else	tmpOptions->HotkeyNewIdentity &= 0xffff ^ 0x800;
			tmpOptions->HotkeyNewIdentity &= 0xf800;
			tmpOptions->HotkeyNewIdentity |= SendDlgItemMessage(hDlg,11200,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11108)
		{	if(IsDlgButtonChecked(hDlg,11108)==BST_CHECKED)	tmpOptions->HotkeyIntercept |= 0x800;
			else	tmpOptions->HotkeyIntercept &= 0xffff ^ 0x800;
			tmpOptions->HotkeyIntercept &= 0xf800;
			tmpOptions->HotkeyIntercept |= SendDlgItemMessage(hDlg,11201,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11109)
		{	if(IsDlgButtonChecked(hDlg,11109)==BST_CHECKED)	tmpOptions->HotkeyRelease |= 0x800;
			else	tmpOptions->HotkeyRelease &= 0xffff ^ 0x800;
			tmpOptions->HotkeyRelease &= 0xf800;
			tmpOptions->HotkeyRelease |= SendDlgItemMessage(hDlg,11202,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11111)
		{	if(IsDlgButtonChecked(hDlg,11111)==BST_CHECKED)	tmpOptions->HotkeyRestore |= 0x800;
			else	tmpOptions->HotkeyRestore &= 0xffff ^ 0x800;
			tmpOptions->HotkeyRestore &= 0xf800;
			tmpOptions->HotkeyRestore |= SendDlgItemMessage(hDlg,11203,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11119)
		{	if(IsDlgButtonChecked(hDlg,11119)==BST_CHECKED)	tmpOptions->HotkeyHideAll |= 0x800;
			else	tmpOptions->HotkeyHideAll &= 0xffff ^ 0x800;
			tmpOptions->HotkeyHideAll &= 0xf800;
			tmpOptions->HotkeyHideAll |= SendDlgItemMessage(hDlg,11120,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11121)
		{	if(IsDlgButtonChecked(hDlg,11121)==BST_CHECKED)	tmpOptions->HotkeyRestoreAll |= 0x800;
			else	tmpOptions->HotkeyRestoreAll &= 0xffff ^ 0x800;
			tmpOptions->HotkeyRestoreAll &= 0xf800;
			tmpOptions->HotkeyRestoreAll |= SendDlgItemMessage(hDlg,11122,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11200)
		{	tmpOptions->HotkeyNewIdentity &= 0xf800;
			tmpOptions->HotkeyNewIdentity |= SendDlgItemMessage(hDlg,11200,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11201)
		{	tmpOptions->HotkeyIntercept &= 0xf800;
			tmpOptions->HotkeyIntercept |= SendDlgItemMessage(hDlg,11201,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11202)
		{	tmpOptions->HotkeyRelease &= 0xf800;
			tmpOptions->HotkeyRelease |= SendDlgItemMessage(hDlg,11202,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11203)
		{	tmpOptions->HotkeyRestore &= 0xf800;
			tmpOptions->HotkeyRestore |= SendDlgItemMessage(hDlg,11203,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11120)
		{	tmpOptions->HotkeyHideAll &= 0xf800;
			tmpOptions->HotkeyHideAll |= SendDlgItemMessage(hDlg,11120,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11122)
		{	tmpOptions->HotkeyRestoreAll &= 0xf800;
			tmpOptions->HotkeyRestoreAll |= SendDlgItemMessage(hDlg,11122,HKM_GETHOTKEY,0,0) & 0x7ff;
			dlgSystem_RegisterHotKeys();
		}
		else if(LOWORD(wParam)==11112)
		{	int i = IsDlgButtonChecked(hDlg,11112);
			tmpOptions->Confirmations &= (CONFIRM_VERIFY_CONNECTIONS | CONFIRM_CLOSE_CONNECTIONS) ^ 0xffff;
			if(i==BST_CHECKED)	tmpOptions->Confirmations |= CONFIRM_VERIFY_CONNECTIONS;
			else if(i==BST_INDETERMINATE)	tmpOptions->Confirmations |= CONFIRM_VERIFY_CONNECTIONS | CONFIRM_CLOSE_CONNECTIONS;
		}
		else if(LOWORD(wParam)==11113)
		{	if(IsDlgButtonChecked(hDlg,11113)==BST_CHECKED)
			{	tmpOptions->Confirmations |= CONFIRM_EXIT;
				EnableWindow(GetDlgItem(hDlg,11114),1);
			}
			else
			{	tmpOptions->Confirmations &= CONFIRM_EXIT ^ 0xffff;
				EnableWindow(GetDlgItem(hDlg,11114),0);
			}
		}
		else if(LOWORD(wParam)==11114)
		{	if(IsDlgButtonChecked(hDlg,11114)==BST_CHECKED)
				tmpOptions->Confirmations |= CONFIRM_EXIT_ONLY_RELEASE;
			else	tmpOptions->Confirmations &= CONFIRM_EXIT_ONLY_RELEASE ^ 0xffff;
		}
		else if(LOWORD(wParam)==11115)
		{	if(IsDlgButtonChecked(hDlg,11115)==BST_CHECKED && !password)
			{	if(DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1014),hMainDialog,&dlgPassword,0))
				{	if(password)
					{	load_all_files();
						delete_all_files();
						encryption |= 2;
						save_settings();
					}
					else
					{	free_password();
						delete_dat_file();
						save_settings();
					}
				}
				if(!password)
				{	CheckDlgButton(hDlg,11115,BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg,11001),0);
				}
				else	EnableWindow(GetDlgItem(hDlg,11001),1);
			}
			else if(password)
			{	if(LangMessageBox(0,get_lang_str(LANG_SYSTEM_PASS_PROMPT),LANG_MB_SAVE_SETTINGS,MB_YESNO)==IDYES)
				{	free_password();
					delete_dat_file();
					save_settings();
					EnableWindow(GetDlgItem(hDlg,11001),0);
				}
				else
				{	CheckDlgButton(hDlg,11115,BST_CHECKED);
					EnableWindow(GetDlgItem(hDlg,11001),1);
				}
			}
		}
		else if(LOWORD(wParam)==11001 && password)
		{	if(DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1014),hMainDialog,&dlgPassword,0))
			{	if(password)
				{	load_all_files();
					delete_all_files();
					encryption |= 2;
					save_settings();
				}
				else
				{	delete_dat_file();
					save_settings();
					CheckDlgButton(hDlg,11115,BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg,11001),0);
				}
			}
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

WCHAR allFilter[]=L"All files\0*.*\0\0";
int __stdcall dlgPassword(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())
		{	SetWindowTextL(hDlg,LANG_SYSTEM_PASSWORD);
			changeDialogStrings(hDlg,lang_dlg_password);
		}
		SetDlgItemInt(hDlg,103,0,0);
		CheckDlgButton(hDlg,500,BST_CHECKED);
		EnableWindow(GetDlgItem(hDlg,102),0);
		EnableWindow(GetDlgItem(hDlg,3),0);
		EnableWindow(GetDlgItem(hDlg,12),0);
		EnableWindow(GetDlgItem(hDlg,103),0);
		SetFocus(GetDlgItem(hDlg,100));
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==3)
		{	OPENFILENAMEW ofn;
			LPWSTR fileName;
			ZeroMemory(&ofn,sizeof(ofn));
			ofn.lStructSize=sizeof(ofn);
			ofn.hwndOwner=hMainDialog;
			ofn.hInstance=hInstance;
			ofn.lpstrFilter=allFilter;
			fileName=tor_malloc(8192);fileName[0]=0;
			ofn.lpstrFile=fileName;
			ofn.nMaxFile=4096;
			ofn.Flags=OFN_EXPLORER|OFN_HIDEREADONLY|OFN_NOCHANGEDIR|OFN_NODEREFERENCELINKS;
			if(GetOpenFileNameW(&ofn))	SetDlgItemTextW(hDlg,102,fileName);
			tor_free(fileName);
		}
		else if(LOWORD(wParam)==500)
		{	if(IsDlgButtonChecked(hDlg,500)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,100),1);
				EnableWindow(GetDlgItem(hDlg,11),1);
				EnableWindow(GetDlgItem(hDlg,101),1);
				EnableWindow(GetDlgItem(hDlg,102),0);
				EnableWindow(GetDlgItem(hDlg,3),0);
				EnableWindow(GetDlgItem(hDlg,12),0);
				EnableWindow(GetDlgItem(hDlg,103),0);
			}
		}
		else if(LOWORD(wParam)==501)
		{	if(IsDlgButtonChecked(hDlg,501)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,100),0);
				EnableWindow(GetDlgItem(hDlg,11),0);
				EnableWindow(GetDlgItem(hDlg,101),0);
				EnableWindow(GetDlgItem(hDlg,102),1);
				EnableWindow(GetDlgItem(hDlg,3),1);
				EnableWindow(GetDlgItem(hDlg,12),1);
				EnableWindow(GetDlgItem(hDlg,103),1);
			}
		}
		else if(LOWORD(wParam)==2)
		{	EndDialog(hDlg,0);
		}
		else if(LOWORD(wParam)==1)
		{	if(IsDlgButtonChecked(hDlg,500)==BST_CHECKED)
			{	char *tmp1 = tor_malloc_zero(MAX_PASSWORD_SIZE);
				char *tmp2 = tor_malloc_zero(MAX_PASSWORD_SIZE);
				GetDlgItemText(hDlg,100,tmp1,MAX_PASSWORD_SIZE-1);
				GetDlgItemText(hDlg,101,tmp2,MAX_PASSWORD_SIZE-2);
				if(strcmp(tmp1,tmp2))
				{	LangMessageBox(hDlg,get_lang_str(LANG_SYSTEM_REENTER_ERROR),LANG_MB_ERROR,MB_OK);
					memset(tmp1,0,MAX_PASSWORD_SIZE);tor_free(tmp1);
					memset(tmp2,0,MAX_PASSWORD_SIZE);tor_free(tmp2);
				}
				else if(strlen(tmp1)==0 && password)
				{	if(LangMessageBox(0,get_lang_str(LANG_SYSTEM_PASS_PROMPT),LANG_MB_SAVE_SETTINGS,MB_YESNO)==IDYES)
					{	free_password();
						EndDialog(hDlg,1);
					}
				}
				else
				{	alloc_password();
					memcpy(password,tmp1,MAX_PASSWORD_SIZE);
					password_size = strlen(tmp1);
					memset(tmp1,0,MAX_PASSWORD_SIZE);tor_free(tmp1);
					memset(tmp2,0,MAX_PASSWORD_SIZE);tor_free(tmp2);
					EndDialog(hDlg,1);
				}
			}
			else
			{	LPWSTR fname=tor_malloc(8192);
				GetDlgItemTextW(hDlg,102,fname,4096);
				HANDLE hFile=CreateFileW(fname,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,NULL);
				tor_free(fname);
				if(hFile!=INVALID_HANDLE_VALUE)
				{	alloc_password();
					int i = GetDlgItemInt(hDlg,103,NULL,0);
					if(i)	SetFilePointer(hFile,i,NULL,FILE_BEGIN);
					ReadFile(hFile,password,MAX_PASSWORD_SIZE,&password_size,NULL);
					CloseHandle(hFile);
					EndDialog(hDlg,1);
				}
			}
		}
	}
	return 0;
}

int __stdcall dlgGetPassword(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	SetDlgItemInt(hDlg,103,0,0);
		CheckDlgButton(hDlg,500,BST_CHECKED);
		EnableWindow(GetDlgItem(hDlg,102),0);
		EnableWindow(GetDlgItem(hDlg,3),0);
		EnableWindow(GetDlgItem(hDlg,12),0);
		EnableWindow(GetDlgItem(hDlg,103),0);
		SetFocus(GetDlgItem(hDlg,100));
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==3)
		{	OPENFILENAMEW ofn;
			LPWSTR fileName;
			ZeroMemory(&ofn,sizeof(ofn));
			ofn.lStructSize=sizeof(ofn);
			ofn.hwndOwner=hMainDialog;
			ofn.hInstance=hInstance;
			ofn.lpstrFilter=allFilter;
			fileName=tor_malloc(8192);fileName[0]=0;
			ofn.lpstrFile=fileName;
			ofn.nMaxFile=4096;
			ofn.Flags=OFN_EXPLORER|OFN_HIDEREADONLY|OFN_NOCHANGEDIR|OFN_NODEREFERENCELINKS;
			if(GetOpenFileNameW(&ofn))	SetDlgItemTextW(hDlg,102,fileName);
			tor_free(fileName);
		}
		else if(LOWORD(wParam)==500)
		{	if(IsDlgButtonChecked(hDlg,500)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,100),1);
				EnableWindow(GetDlgItem(hDlg,11),1);
				EnableWindow(GetDlgItem(hDlg,101),1);
				EnableWindow(GetDlgItem(hDlg,102),0);
				EnableWindow(GetDlgItem(hDlg,3),0);
				EnableWindow(GetDlgItem(hDlg,12),0);
				EnableWindow(GetDlgItem(hDlg,103),0);
			}
		}
		else if(LOWORD(wParam)==501)
		{	if(IsDlgButtonChecked(hDlg,501)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,100),0);
				EnableWindow(GetDlgItem(hDlg,11),0);
				EnableWindow(GetDlgItem(hDlg,101),0);
				EnableWindow(GetDlgItem(hDlg,102),1);
				EnableWindow(GetDlgItem(hDlg,3),1);
				EnableWindow(GetDlgItem(hDlg,12),1);
				EnableWindow(GetDlgItem(hDlg,103),1);
			}
		}
		else if(LOWORD(wParam)==2)
		{	EndDialog(hDlg,0);
		}
		else if(LOWORD(wParam)==1)
		{	if(IsDlgButtonChecked(hDlg,500)==BST_CHECKED)
			{	char *tmp1 = tor_malloc_zero(MAX_PASSWORD_SIZE);
				GetDlgItemText(hDlg,100,tmp1,MAX_PASSWORD_SIZE-1);
				if(strlen(tmp1)==0)
				{	EndDialog(hDlg,0);
				}
				else
				{	alloc_password();
					memcpy(password,tmp1,MAX_PASSWORD_SIZE);
					password_size = strlen(tmp1);
					memset(tmp1,0,MAX_PASSWORD_SIZE);tor_free(tmp1);
					EndDialog(hDlg,1);
				}
			}
			else
			{	LPWSTR fname=tor_malloc(8192);
				GetDlgItemTextW(hDlg,102,fname,4096);
				HANDLE hFile=CreateFileW(fname,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,NULL);
				tor_free(fname);
				if(hFile!=INVALID_HANDLE_VALUE)
				{	alloc_password();
					int i = GetDlgItemInt(hDlg,103,NULL,0);
					if(i)	SetFilePointer(hFile,i,NULL,FILE_BEGIN);
					ReadFile(hFile,password,MAX_PASSWORD_SIZE,&password_size,NULL);
					CloseHandle(hFile);
					EndDialog(hDlg,1);
				}
			}
		}
	}
	return 0;
}
