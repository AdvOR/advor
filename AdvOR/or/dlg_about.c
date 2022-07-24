#include "or.h"
#include "dlg_util.h"

HWND hDlgAbout=NULL,hDlgHostedServices=NULL,hDlgInterceptHelp=NULL;

int __stdcall dlgAbout(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgHostedServices(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgInterceptHelp(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

lang_dlg_info lang_dlg_hosted_services[]={
	{16010,LANG_DLG_HOSTED_SERVICES},
	{0,0}
};

lang_dlg_info lang_dlg_intercept_help[]={
	{16010,LANG_DLG_INTERCEPT},
	{0,0}
};


// "Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer"
// This string is not for language files.
char frame8txt[]="\r\n\t\tAdvanced Onion Router v"
	advtor_ver
	"\r\n\r\nAdvanced Onion Router consists of Tor, Graphical Interface and extensions.\r\n\r\n"
	"[1] Tor is distributed under this license:\r\n\r\n"
	"Copyright © 2001-2004, Roger Dingledine\r\n"
	"Copyright © 2004-2006, Roger Dingledine, Nick Mathewson\r\n"
	"Copyright © 2007-2017, The Tor Project, Inc.\r\n\r\n"
	"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\r\n"
	"\t* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\r\n"
	"\t* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\r\n"
	"\t* Neither the names of the copyright owners nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\r\n"
	"\tThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/), zlib (http://www.zlib.net/) and libevent (http://www.monkey.org/~provos/libevent/).\r\n\r\n"
	"[2] Graphical Interface, extensions added to Tor client and AdvOR.dll are distributed under Creative Commons Attribution - NonCommercial - ShareAlike license ( http://creativecommons.org/licenses/by-nc-sa/3.0/ ).\r\n\r\n"
	"Copyright © by Albu Cristian, 2009-2017\r\n";

int __stdcall dlgAbout(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) wParam;
	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{
		SetDlgItemText(hDlg,16010,frame8txt);
	}
	return 0;
}

int __stdcall dlgHostedServices(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) wParam;
	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	changeDialogStrings(hDlg,lang_dlg_hosted_services);
	}
	return 0;
}

int __stdcall dlgInterceptHelp(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) wParam;
	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	changeDialogStrings(hDlg,lang_dlg_intercept_help);
	}
	return 0;
}
