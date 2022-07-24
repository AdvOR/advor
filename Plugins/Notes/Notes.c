#include <windows.h>
#include "plugins.h"

#define NOTES_FILE "notes.txt"

HWND hDialog = NULL;
HINSTANCE hInstance = NULL;
int timer = 0;
resize_info_t dlgResize[2] = {
			{100,0,0,0,0,{-1,-1,-1,-1},RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_RIGHT_WIDTH|RESIZE_FLAG_SAME_DISTANCE_CONTROL_POS_BOTTOM_HEIGHT},
			{0,0,0,0,0,{-1,-1,-1,-1},0}};

int __stdcall dlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

BOOL __stdcall DllMain(HANDLE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{	hInstance = hModule;
	return 1;
}

int __stdcall AdvTor_InitPlugin(HANDLE plugin_instance,DWORD version,char *plugin_description,void *function_table)
{	InitPlugin
	strcpy(plugin_description,"Hidden Service example plugin");
	return 1;
}

int __stdcall AdvTor_UnloadPlugin(int reason)
{	if(hDialog)	DestroyWindow(hDialog);
	hDialog = NULL;
	timer = 0;
	return 1;
}

HWND __stdcall AdvTor_GetConfigurationWindow(HWND hParent)
{	if(!hDialog)
	{	hDialog = CreateDialogParamW(hInstance,(LPWSTR)1000,hParent,&dlgProc,0);
		ShowWindow(hDialog,SW_SHOW);
	}
	return hDialog;
}

resize_info_t* __stdcall ResizeConfigurationWindow(RECT newSize)
{	return &dlgResize[0];
}

int __stdcall dlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	switch(uMsg)
	{	case WM_INITDIALOG:
			SendDlgItemMessage(hDlg,100,EM_LIMITTEXT,1024*128,0);
			if(protected_file_exists(NOTES_FILE))
			{	LPWSTR txt = NULL;
				read_protected_file(NOTES_FILE,(char **)&txt);
				if(txt)	SetDlgItemTextW(hDlg,100,txt);
				tor_free(txt);
			}
			break;
		case WM_COMMAND:
			if(LOWORD(wParam)==100 && HIWORD(wParam)==EN_CHANGE)
			{	if(!timer)
				{	SetTimer(hDlg,100,1000,NULL);
					timer++;
				}
			}
			break;
		case WM_DESTROY:
		case WM_TIMER:
			if(timer)	KillTimer(hDlg,100);
			timer = 0;
			wParam = SendDlgItemMessageW(hDlg,100,WM_GETTEXTLENGTH,0,0) + 1;
			LPWSTR txt = tor_malloc(wParam*2 + 4);
			GetDlgItemTextW(hDlg,100,txt,wParam);
			write_protected_file(NOTES_FILE,(char *)txt,wParam*2);
			tor_free(txt);
			break;
		default:
			break;
	}
	return 0;
}
