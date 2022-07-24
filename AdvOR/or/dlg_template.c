#include "or.h"
#include "dlg_util.h"

HWND hDlg_=NULL;

lang_dlg_info lang_dlg_[]={
	{0,0}
};

int __stdcall dlg_(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlg_=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_);
		}
	}
	return 0;
}

