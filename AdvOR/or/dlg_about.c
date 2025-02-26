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
	"Copyright © 2007-2025, The Tor Project, Inc.\r\n\r\n"
	"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\r\n\r\n"
	"* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\r\n"
	"* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\r\n"
	"* Neither the names of the copyright owners nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\r\n\r\n"
	"This product includes following software:\r\n\r\n"
	"* OpenSSL - https://www.openssl.org/\r\n"
	"* zLib - https://www.zlib.net/\r\n"
	"* LibEvent - https://libevent.org/\r\n"
	"* LibNTLM - https://savannah.nongnu.org/projects/libntlm/\r\n\r\n"
	"[2] Graphical Interface, extensions added to Tor client and AdvOR.dll are distributed under Creative Commons Attribution - NonCommercial - ShareAlike license - https://creativecommons.org/licenses/by-nc-sa/3.0/\r\n\r\n"
	"Copyright © by Albu Cristian, 2009-2025\r\n\r\n"
	"[3] Disclaimer\r\n\r\n"
	"This software is provided by the copyright holders and contributors \"as is\" and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the copyright owner or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.\r\n";

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
