#include "or.h"
#include "dlg_util.h"
#include "geoip.h"
#include "main.h"
#include "circuitbuild.h"
#include "config.h"

#define INTERNET_FLAG_RELOAD 0x80000000
#define INTERNET_FLAG_RAW_DATA 0x40000000
#define INTERNET_FLAG_EXISTING_CONNECT 0x20000000
#define INTERNET_FLAG_ASYNC 0x10000000
#define INTERNET_FLAG_PASSIVE 0x08000000
#define INTERNET_FLAG_NO_CACHE_WRITE 0x04000000
#define INTERNET_FLAG_DONT_CACHE INTERNET_FLAG_NO_CACHE_WRITE
#define INTERNET_FLAG_MAKE_PERSISTENT 0x02000000
#define INTERNET_FLAG_OFFLINE 0x1000000
#define INTERNET_FLAG_SECURE 0x800000
#define INTERNET_FLAG_KEEP_CONNECTION 0x400000
#define INTERNET_FLAG_NO_AUTO_REDIRECT 0x200000
#define INTERNET_FLAG_READ_PREFETCH 0x100000
#define INTERNET_FLAG_NO_COOKIES 0x80000
#define INTERNET_FLAG_NO_AUTH 0x40000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP 0x8000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS 0x4000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x2000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID 0x1000
#define INTERNET_FLAG_MUST_CACHE_REQUEST 16
#define INTERNET_FLAG_RESYNCHRONIZE 0x800
#define INTERNET_FLAG_HYPERLINK 0x400
#define INTERNET_FLAG_NO_UI 0x200
#define INTERNET_FLAG_PRAGMA_NOCACHE 0x100
#define INTERNET_FLAG_TRANSFER_ASCII FTP_TRANSFER_TYPE_ASCII
#define INTERNET_FLAG_TRANSFER_BINARY FTP_TRANSFER_TYPE_BINARY
#define INTERNET_OPTION_SECURITY_FLAGS 31
#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define SECURITY_FLAG_SECURE 1
#define SECURITY_FLAG_SSL 2
#define SECURITY_FLAG_SSL3 4
#define SECURITY_FLAG_PCT 8
#define SECURITY_FLAG_PCT4 16
#define SECURITY_FLAG_IETFSSL4 0x20
#define SECURITY_FLAG_IGNORE_REVOCATION 0x00000080
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#define SECURITY_FLAG_IGNORE_WRONG_USAGE 0x00000200
#define SECURITY_FLAG_40BIT 0x10000000
#define SECURITY_FLAG_128BIT 0x20000000
#define SECURITY_FLAG_56BIT 0x40000000
#define SECURITY_FLAG_UNKNOWNBIT 0x80000000
#define SECURITY_FLAG_NORMALBITNESS SECURITY_FLAG_40BIT
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID INTERNET_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTPS INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS
#define SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTP INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP
#define INTERNET_DEFAULT_HTTPS_PORT 443
#define INTERNET_SERVICE_HTTP 3

HWND hDlgBridges=NULL;
extern HWND hMainDialog;
//int frame12[]={24010,24400,24401,24002,24050,24100,24402,24404,24405,24101,24406,24102,24407,24103,24408,24104,-1};
extern or_options_t *tmpOptions;
lang_dlg_info lang_dlg_bridges[]={
	{24010,LANG_BRIDGES_MSG_ENABLE},
	{24400,LANG_DLG_USE_BRIDGES},
	{24401,LANG_DLG_UPDATE_BRIDGES},
	{24002,LANG_BRIDGES_GET_NEW},
	{24050,LANG_BRIDGES_USE_BRIDGES},
	{24409,LANG_DLG_BRIDGES_NTLM_PROXY},
	{24003,LANG_DLG_BRIDGES_NTLM_DOMAIN},
	{24004,LANG_DLG_BRIDGES_NTLM_ACCOUNT},
	{24402,LANG_BRIDGES_TUNNEL_DIR_CONNS},
	{24404,LANG_DLG_DIR_PRIVATE},
	{24405,LANG_BRIDGES_HTTP_PROXY},
	{24406,LANG_BRIDGES_PROXY_ACCOUNT},
	{24407,LANG_BRIDGES_HTTPS_PROXY},
	{24408,LANG_BRIDGES_PROXY_ACCOUNT},
	{0,0}
};


#define INTERNET_FLAG_NO_CACHE_WRITE 0x04000000
#define INTERNET_FLAG_NO_COOKIES 0x80000
typedef PVOID HINTERNET;
typedef HINTERNET (WINAPI *LPInternetOpenA)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef HINTERNET (WINAPI *LPInternetOpenUrlA)(HINTERNET,LPCSTR,LPCSTR,DWORD,DWORD,DWORD);
typedef BOOL (WINAPI *LPInternetReadFile)(HINTERNET,PVOID,DWORD,PDWORD);
typedef BOOL (WINAPI *LPInternetCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *LPInternetSetOption)(HINTERNET hInternet,DWORD dwOption,LPVOID lpBuffer,DWORD dwBufferLength);
typedef BOOL (WINAPI *LPInternetQueryOption)(HINTERNET hInternet,DWORD dwOption,LPVOID lpBuffer,LPDWORD lpdwBufferLength);
typedef HINTERNET (WINAPI *LPInternetConnect)(HINTERNET hInternet,LPCTSTR lpszServerName,int nServerPort,LPCTSTR lpszUsername,LPCTSTR lpszPassword,DWORD dwService,DWORD dwFlags,DWORD_PTR dwContext);
typedef HINTERNET (WINAPI *LPHttpOpenRequest)(HINTERNET hConnect,LPCTSTR lpszVerb,LPCTSTR lpszObjectName,LPCTSTR lpszVersion,LPCTSTR lpszReferer,LPCTSTR *lplpszAcceptTypes,DWORD dwFlags,DWORD_PTR dwContext);
typedef BOOL (WINAPI *LPHttpSendRequest)(HINTERNET hRequest,LPCTSTR lpszHeaders,DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength);
int getNewBridges(HWND hDlg,int allowInvalid);
void setEditBridges(config_line_t **option);
int __stdcall dlgBridges(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

LPInternetOpenA _InternetOpen=NULL;
LPInternetOpenUrlA _InternetOpenUrl=NULL;
LPInternetReadFile _InternetReadFile=NULL;
LPInternetCloseHandle _InternetCloseHandle=NULL;
LPInternetSetOption _InternetSetOption=NULL;
LPInternetQueryOption _InternetQueryOption=NULL;
LPInternetConnect _InternetConnect=NULL;
LPHttpOpenRequest _HttpOpenRequest=NULL;
LPHttpSendRequest _HttpSendRequest=NULL;
HINSTANCE hWininet=NULL;


int getNewBridges(HWND hDlg,int allowInvalid)
{	char *bridges_tmp=tor_malloc(16384);
	char *tmp1,*tmp2,*tmp3;
	HINTERNET hInternet,hConn,hReq=NULL;
	DWORD bytesRead=0;
	if(_InternetOpen==NULL)
	{	GetSystemDirectory(bridges_tmp,8192);
		tor_snprintf(bridges_tmp+8192,8192,"%s\\wininet.dll",bridges_tmp);
		hWininet=LoadLibrary(bridges_tmp+8192);
		if(hWininet==NULL)
		{	LangMessageBox(hDlg,get_lang_str(LANG_BRIDGES_WININET),LANG_MB_ERROR,MB_OK);
			tor_free(bridges_tmp);return 0;
		}
		_InternetOpen=(LPInternetOpenA)GetProcAddress(hWininet,"InternetOpenA");
		_InternetOpenUrl=(LPInternetOpenUrlA)GetProcAddress(hWininet,"InternetOpenUrlA");
		_InternetReadFile=(LPInternetReadFile)GetProcAddress(hWininet,"InternetReadFile");
		_InternetCloseHandle=(LPInternetCloseHandle)GetProcAddress(hWininet,"InternetCloseHandle");
		_InternetSetOption=(LPInternetSetOption)GetProcAddress(hWininet,"InternetSetOptionA");
		_InternetQueryOption=(LPInternetQueryOption)GetProcAddress(hWininet,"InternetQueryOptionA");
		_InternetConnect=(LPInternetConnect)GetProcAddress(hWininet,"InternetConnectA");
		_HttpOpenRequest=(LPHttpOpenRequest)GetProcAddress(hWininet,"HttpOpenRequestA");
		_HttpSendRequest=(LPHttpSendRequest)GetProcAddress(hWininet,"HttpSendRequestA");
		if(!(_InternetOpen && _InternetOpenUrl && _InternetReadFile && _InternetCloseHandle && _InternetSetOption && _InternetConnect && _InternetQueryOption && _HttpOpenRequest && _HttpSendRequest))
		{	LangMessageBox(hDlg,get_lang_str(LANG_BRIDGES_WININET),LANG_MB_ERROR,MB_OK);
			tor_free(bridges_tmp);return 0;
		}
	}
	hInternet=_InternetOpen("",INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0);
	bytesRead = 0;
	if(allowInvalid)
	{	hConn = _InternetConnect(hInternet,"bridges.torproject.org",INTERNET_DEFAULT_HTTPS_PORT,NULL,NULL,INTERNET_SERVICE_HTTP,0,0);
		if(hConn)
		{	hReq = _HttpOpenRequest(hConn,"GET","/",NULL,NULL,NULL,INTERNET_FLAG_SECURE|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_NO_COOKIES|INTERNET_FLAG_IGNORE_CERT_DATE_INVALID|INTERNET_FLAG_NO_AUTH|INTERNET_FLAG_NO_UI|INTERNET_FLAG_PRAGMA_NOCACHE|INTERNET_FLAG_RELOAD,0);
			if(hReq)
			{	DWORD dwFlags;
				DWORD dwBuffLen = sizeof(dwFlags);
				_InternetQueryOption(hReq,INTERNET_OPTION_SECURITY_FLAGS,(LPVOID)&dwFlags,&dwBuffLen);
				dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_REVOCATION;
				_InternetSetOption(hReq,INTERNET_OPTION_SECURITY_FLAGS,&dwFlags,sizeof(dwFlags));
				_HttpSendRequest(hReq,NULL,0,NULL,0);
			}
		}
		if(hReq)
		{	_InternetReadFile(hReq,bridges_tmp,16384,&bytesRead);
			_InternetCloseHandle(hReq);
			_InternetCloseHandle(hConn);
			_InternetCloseHandle(hInternet);
		}
	}
	else
	{	hReq=_InternetOpenUrl(hInternet,"https://bridges.torproject.org",NULL,0,INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_NO_COOKIES,0);
		_InternetReadFile(hReq,bridges_tmp,16384,&bytesRead);
		_InternetCloseHandle(hReq);
		_InternetCloseHandle(hInternet);
	}
	if(bytesRead)
	{	bridges_tmp[bytesRead]=0;
		tmp1=tmp2=bridges_tmp;
		while(*tmp2)
		{
			if(*tmp2=='<')
			{	while((*tmp2!='>')&&(*tmp2!=0))	tmp2++;
				if(*tmp2=='>')	tmp2++;
			}
			else if(*tmp2=='&')
			{	if(!strcmpstart(tmp2,"amp;")){	*tmp1++='&';tmp2+=5;}
				else if(!strcmpstart(tmp2,"lt;")){	*tmp1++='<';tmp2+=4;}
				else if(!strcmpstart(tmp2,"gt;")){	*tmp1++='>';tmp2+=4;}
				else if(!strcmpstart(tmp2,"quot;")){	*tmp1++=34;tmp2+=6;}
				else if(!strcmpstart(tmp2,"apos;")){	*tmp1++=39;tmp2+=6;}
				else	*tmp1++=*tmp2++;
			}
			else	*tmp1++=*tmp2++;
		}
		*tmp1=0;
		tmp1=tmp2=bridges_tmp;
		while(*tmp1)
		{	if((*tmp1>='0')&&(*tmp1<='9'))
			{	if(is_ip(tmp1))
				{	while(((*tmp1>='0')&&(*tmp1<='9'))||(*tmp1=='.')||(*tmp1==':'))	*tmp2++=*tmp1++;
					*tmp2++=13;*tmp2++=10;
				}
				else	while((*tmp1>='0')&&(*tmp1<='9')) tmp1++;
			}
			else	tmp1++;
		}
		if(bridges_tmp==tmp2){	tor_free(bridges_tmp);return 0;}
		*tmp2=0;
		if(tmp2-bridges_tmp<8192)
		{	tor_snprintf(bridges_tmp+8192,8192,get_lang_str(LANG_BRIDGES_DOWNLOAD_OK),bridges_tmp);
			LangMessageBox(hDlg,bridges_tmp+8192,LANG_BRIDGES_DOWNLOAD,MB_OK);
		}
		bytesRead=SendDlgItemMessage(hDlg,24100,WM_GETTEXTLENGTH,0,0);
		tmp2=tor_malloc(bytesRead+strlen(bridges_tmp)+5);tmp3=tmp2;
		if(bytesRead>32000) bytesRead=32000;
		GetDlgItemText(hDlg,24100,tmp2,bytesRead+1);tmp2+=bytesRead;
		if(bytesRead && *(tmp2-1)>31){	*tmp2++=13;*tmp2++=10;}
		tmp1=bridges_tmp;
		for(;*tmp1!=0;)	*tmp2++=*tmp1++;
		*tmp2=0;
		tmp2=tor_malloc(65535);
		tmp2=SortIPList(tmp3,tmp2);
		SetDlgItemText(hDlg,24100,tmp2);
		tor_free(tmp2);
		tor_free(tmp3);
		tor_free(bridges_tmp);
		HWND item = GetDlgItem(hDlg,24100);
		PostMessage(hDlg,WM_COMMAND,(EN_CHANGE<<16)|24100,(LPARAM)item);
		return 1;
	}
	else
	{	if(!allowInvalid)
		{	if(LangMessageBox(hDlg,get_lang_str(LANG_BRIDGES_INVALID_CA),LANG_BRIDGES_DOWNLOAD,MB_YESNO)==IDYES)
				getNewBridges(hDlg,1);
		}
		else	LangMessageBox(hDlg,get_lang_str(LANG_BRIDGES_NO_BRIDGES),LANG_BRIDGES_DOWNLOAD,MB_OK);
	}
	tor_free(bridges_tmp);
	return 0;
}

void setEditBridges(config_line_t **option)
{	int i,j;
	if(*option!=NULL)
	{	char *tmp1=tor_malloc(65536),*tmp2;i=0;tmp2=tmp1;
		config_line_t *cfg;
		for(cfg=*option;cfg;cfg=cfg->next)
		{	for(j=0;i<32000;i++,j++)
			{	if(!cfg->value[j]) break;
				*tmp1++=cfg->value[j];
			}
			*tmp1++=13;*tmp1++=10;i+=2;
			if(i>32000) break;
		}
		*tmp1=0;
		tmp1=tor_malloc(65535);
		tmp1=SortIPList(tmp2,tmp1);
		SetDlgItemText(hDlgBridges,24100,tmp1);
		tor_free(tmp1);
		tor_free(tmp2);
	}
}

int __stdcall dlgBridges(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgBridges=hDlg;
		HWND hCombo = GetDlgItem(hDlg,24300);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"HTTP"),PROXY_HTTP);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"HTTPS"),PROXY_CONNECT);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"Socks4"),PROXY_SOCKS4);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"Socks5"),PROXY_SOCKS5);
		hCombo = GetDlgItem(hDlg,24301);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"HTTPS"),PROXY_CONNECT);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"Socks4"),PROXY_SOCKS4);
		SendMessage(hCombo,CB_SETITEMDATA,SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)"Socks5"),PROXY_SOCKS5);
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_bridges);
		}
		if(tmpOptions->UseBridges){ CheckDlgButton(hDlg,24400,BST_CHECKED);}
		else
		{	EnableWindow(GetDlgItem(hDlg,24401),0);
			EnableWindow(GetDlgItem(hDlg,24002),0);
			EnableWindow(GetDlgItem(hDlg,24050),0);
			EnableWindow(GetDlgItem(hDlg,24100),0);
		}
		if(tmpOptions->UpdateBridgesFromAuthority){ CheckDlgButton(hDlg,24401,BST_CHECKED);}
		if((tmpOptions->TunnelDirConns2 & 1) != 0)
		{	if((tmpOptions->TunnelDirConns2 & 2) != 0)	CheckDlgButton(hDlg,24402,BST_CHECKED);
			else						CheckDlgButton(hDlg,24402,BST_INDETERMINATE);
		}
		if(tmpOptions->AllDirActionsPrivate) CheckDlgButton(hDlg,24404,BST_CHECKED);
		SendDlgItemMessage(hDlg,24102,EM_LIMITTEXT,48,0);
		SendDlgItemMessage(hDlg,24104,EM_LIMITTEXT,48,0);


		if(tmpOptions->CorporateProxy!=NULL)
		{	SetDlgItemText(hDlg,24105,tmpOptions->CorporateProxy);
		}
		else	tmpOptions->DirFlags &= DIR_FLAG_NTLM_PROXY ^ DIR_FLAGS_ALL;
		if(tmpOptions->DirFlags&DIR_FLAG_NTLM_PROXY)	CheckDlgButton(hDlg,24409,BST_CHECKED);
		else
		{	EnableWindow(GetDlgItem(hDlg,24105),0);
			EnableWindow(GetDlgItem(hDlg,24003),0);
			EnableWindow(GetDlgItem(hDlg,24106),0);
			EnableWindow(GetDlgItem(hDlg,24004),0);
			EnableWindow(GetDlgItem(hDlg,24107),0);
		}
		if(tmpOptions->CorporateProxyDomain!=NULL)	SetDlgItemText(hDlg,24106,tmpOptions->CorporateProxyDomain);
		if(tmpOptions->CorporateProxyAuthenticator!=NULL)	SetDlgItemText(hDlg,24107,tmpOptions->CorporateProxyAuthenticator);
		if(tmpOptions->DirProxy!=NULL)
		{	SetDlgItemText(hDlg,24101,tmpOptions->DirProxy);
		}
		else	tmpOptions->DirFlags &= DIR_FLAG_HTTP_PROXY ^ DIR_FLAGS_ALL;
		if(tmpOptions->DirFlags&DIR_FLAG_HTTP_PROXY)	CheckDlgButton(hDlg,24405,BST_CHECKED);
		else
		{	EnableWindow(GetDlgItem(hDlg,24101),0);
			EnableWindow(GetDlgItem(hDlg,24300),0);
			EnableWindow(GetDlgItem(hDlg,24406),0);
			EnableWindow(GetDlgItem(hDlg,24102),0);
		}
		if(tmpOptions->DirProxyAuthenticator!=NULL)	SetDlgItemText(hDlg,24102,tmpOptions->DirProxyAuthenticator);
		else	tmpOptions->DirFlags &= DIR_FLAG_HTTP_AUTH ^ DIR_FLAGS_ALL;
		if(tmpOptions->DirFlags & DIR_FLAG_HTTP_AUTH)	CheckDlgButton(hDlg,24406,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,24102),0);
		if(tmpOptions->ORProxy!=NULL)
			SetDlgItemText(hDlg,24103,tmpOptions->ORProxy);
		else	tmpOptions->DirFlags &= DIR_FLAG_HTTPS_PROXY ^ DIR_FLAGS_ALL;
		if(tmpOptions->DirFlags & DIR_FLAG_HTTPS_PROXY)	CheckDlgButton(hDlg,24407,BST_CHECKED);
		else
		{	EnableWindow(GetDlgItem(hDlg,24103),0);
			EnableWindow(GetDlgItem(hDlg,24301),0);
			EnableWindow(GetDlgItem(hDlg,24408),0);
			EnableWindow(GetDlgItem(hDlg,24104),0);
		}
		if(tmpOptions->ORProxyAuthenticator!=NULL)	SetDlgItemText(hDlg,24104,tmpOptions->ORProxyAuthenticator);
		else	tmpOptions->DirFlags &= DIR_FLAG_HTTPS_AUTH ^ DIR_FLAGS_ALL;
		if(tmpOptions->DirFlags & DIR_FLAG_HTTPS_AUTH)	CheckDlgButton(hDlg,24408,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,24104),0);
		selectComboId(hDlg,24300,tmpOptions->DirProxyProtocol);
		selectComboId(hDlg,24301,tmpOptions->ORProxyProtocol);
		setEditBridges(&tmpOptions->Bridges);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==24400)
		{	if(IsDlgButtonChecked(hDlg,24400)==BST_CHECKED)
			{	tmpOptions->UseBridges=1;
				EnableWindow(GetDlgItem(hDlg,24401),1);
				EnableWindow(GetDlgItem(hDlg,24002),1);
				EnableWindow(GetDlgItem(hDlg,24050),1);
				EnableWindow(GetDlgItem(hDlg,24100),1);
			}
			else
			{	tmpOptions->UseBridges=0;
				EnableWindow(GetDlgItem(hDlg,24401),0);
				EnableWindow(GetDlgItem(hDlg,24002),0);
				EnableWindow(GetDlgItem(hDlg,24050),0);
				EnableWindow(GetDlgItem(hDlg,24100),0);
			}
		}
		else if(LOWORD(wParam)==24401)
		{	if(IsDlgButtonChecked(hDlg,24401)==BST_CHECKED)	tmpOptions->UpdateBridgesFromAuthority=1;
			else	tmpOptions->UpdateBridgesFromAuthority=0;
		}
		else if(LOWORD(wParam)==24002)
		{	if(getNewBridges(hDlg,0))
			{	getEditData1(hDlg,24100,&tmpOptions->Bridges,"Bridges");
				clear_bridge_list();
				config_line_t *cfg;
				for(cfg=tmpOptions->Bridges;cfg;cfg=cfg->next)	parse_bridge_line((char *)cfg->value,0);
			}
		}
		else if((LOWORD(wParam)==24100)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData1(hDlg,24100,&tmpOptions->Bridges,"Bridges");
			clear_bridge_list();
			config_line_t *cfg;
			for(cfg=tmpOptions->Bridges;cfg;cfg=cfg->next)	parse_bridge_line((char *)cfg->value,0);
		}
		else if(LOWORD(wParam)==24402)
		{	int i = IsDlgButtonChecked(hDlg,24402);
			if(i==BST_CHECKED)		tmpOptions->TunnelDirConns2 = 3;
			else if(i == BST_INDETERMINATE)	tmpOptions->TunnelDirConns2 = 1;
			else				tmpOptions->TunnelDirConns2 = 0;
		}
		else if((LOWORD(wParam)==24101)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24101,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24101,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->DirProxy;
			tmpOptions->DirProxy=tmp1;tor_free(tmp2);
			tor_addr_port_parse(tmpOptions->DirProxy,&tmpOptions->DirProxyAddr, &tmpOptions->DirProxyPort);
			if(tmpOptions->DirProxyPort==0)	tmpOptions->DirProxyPort=80;
		}
		else if((LOWORD(wParam)==24102)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24102,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24102,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->DirProxyAuthenticator;
			tmpOptions->DirProxyAuthenticator=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==24103)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24103,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24103,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->ORProxy;
			tmpOptions->ORProxy=tmp1;tor_free(tmp2);
			tor_addr_port_parse(tmpOptions->ORProxy,&tmpOptions->ORProxyAddr, &tmpOptions->ORProxyPort);
			if(tmpOptions->ORProxyPort==0)	tmpOptions->ORProxyPort=443;
		}
		else if((LOWORD(wParam)==24104)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24104,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24104,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->ORProxyAuthenticator;
			tmpOptions->ORProxyAuthenticator=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==24105)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24105,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24105,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->CorporateProxy;
			tmpOptions->CorporateProxy=tmp1;tor_free(tmp2);
			tor_addr_port_parse(tmpOptions->CorporateProxy,&tmpOptions->CorporateProxyAddr,&tmpOptions->CorporateProxyPort);
			if(tmpOptions->CorporateProxyPort==0)	tmpOptions->CorporateProxyPort=8080;
		}
		else if((LOWORD(wParam)==24106)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24106,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24106,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->CorporateProxyDomain;
			tmpOptions->CorporateProxyDomain=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==24107)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,24107,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,24107,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->CorporateProxyAuthenticator;
			tmpOptions->CorporateProxyAuthenticator=tmp1;tor_free(tmp2);
		}
		else if(LOWORD(wParam)==24404)
		{	if(IsDlgButtonChecked(hDlg,24404)==BST_CHECKED){	tmpOptions->AllDirActionsPrivate|=1;}
			else{	tmpOptions->AllDirActionsPrivate=0;}
		}
		else if(LOWORD(wParam)==24405)
		{	if(IsDlgButtonChecked(hDlg,24405)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,24101,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,24101,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->DirProxy;
				tmpOptions->DirProxy=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,24101),1);
				EnableWindow(GetDlgItem(hDlg,24300),1);
				EnableWindow(GetDlgItem(hDlg,24406),1);
				if(tmpOptions->DirProxyAuthenticator)	EnableWindow(GetDlgItem(hDlg,24102),1);
				tor_addr_port_parse(tmpOptions->DirProxy,&tmpOptions->DirProxyAddr, &tmpOptions->DirProxyPort);
				if(tmpOptions->DirProxyPort==0)	tmpOptions->DirProxyPort=80;
				tmpOptions->DirFlags |= DIR_FLAG_HTTP_PROXY;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_HTTP_PROXY ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,24101),0);
				EnableWindow(GetDlgItem(hDlg,24300),0);
				EnableWindow(GetDlgItem(hDlg,24406),0);
				EnableWindow(GetDlgItem(hDlg,24102),0);
			}
		}
		else if(LOWORD(wParam)==24406)
		{	if(IsDlgButtonChecked(hDlg,24406)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,24102,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,24102,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->DirProxyAuthenticator;
				tmpOptions->DirProxyAuthenticator=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,24102),1);
				tmpOptions->DirFlags |= DIR_FLAG_HTTP_AUTH;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_HTTP_AUTH ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,24102),0);
			}
		}
		else if(LOWORD(wParam)==24407)
		{	if(IsDlgButtonChecked(hDlg,24407)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,24103,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,24103,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->ORProxy;
				tmpOptions->ORProxy=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,24103),1);
				EnableWindow(GetDlgItem(hDlg,24301),1);
				EnableWindow(GetDlgItem(hDlg,24408),1);
				if(tmpOptions->ORProxyAuthenticator)	EnableWindow(GetDlgItem(hDlg,24104),1);
				tor_addr_port_parse(tmpOptions->ORProxy,&tmpOptions->ORProxyAddr, &tmpOptions->ORProxyPort);
				if(tmpOptions->ORProxyPort==0)	tmpOptions->ORProxyPort=443;
				tmpOptions->DirFlags |= DIR_FLAG_HTTPS_PROXY;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_HTTPS_PROXY ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,24103),0);
				EnableWindow(GetDlgItem(hDlg,24301),0);
				EnableWindow(GetDlgItem(hDlg,24408),0);
				EnableWindow(GetDlgItem(hDlg,24104),0);
			}
		}
		else if(LOWORD(wParam)==24408)
		{	if(IsDlgButtonChecked(hDlg,24408)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,24104,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,24104,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->ORProxyAuthenticator;
				tmpOptions->ORProxyAuthenticator=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,24104),1);
				tmpOptions->DirFlags |= DIR_FLAG_HTTPS_AUTH;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_HTTPS_AUTH ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,24104),0);
			}
		}
		else if(LOWORD(wParam)==24409)
		{	if(IsDlgButtonChecked(hDlg,24409)==BST_CHECKED)
			{	int tmpsize=SendDlgItemMessage(hDlg,24105,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,24105,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->CorporateProxy;
				tmpOptions->CorporateProxy=tmp1;tor_free(tmp2);
				EnableWindow(GetDlgItem(hDlg,24105),1);
				EnableWindow(GetDlgItem(hDlg,24003),1);
				EnableWindow(GetDlgItem(hDlg,24106),1);
				EnableWindow(GetDlgItem(hDlg,24004),1);
				EnableWindow(GetDlgItem(hDlg,24107),1);
				tor_addr_port_parse(tmpOptions->CorporateProxy,&tmpOptions->CorporateProxyAddr,&tmpOptions->CorporateProxyPort);
				if(tmpOptions->CorporateProxyPort==0)	tmpOptions->CorporateProxyPort=8080;
				tmpOptions->DirFlags |= DIR_FLAG_NTLM_PROXY;
			}
			else
			{	tmpOptions->DirFlags &= DIR_FLAG_NTLM_PROXY ^ DIR_FLAGS_ALL;
				EnableWindow(GetDlgItem(hDlg,24105),0);
				EnableWindow(GetDlgItem(hDlg,24003),0);
				EnableWindow(GetDlgItem(hDlg,24106),0);
				EnableWindow(GetDlgItem(hDlg,24004),0);
				EnableWindow(GetDlgItem(hDlg,24107),0);
			}
		}
		else if((LOWORD(wParam)==24300)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	int i = SendDlgItemMessage(hDlg,24300,CB_GETCURSEL,0,0);
			if(i != CB_ERR)
				tmpOptions->DirProxyProtocol = SendDlgItemMessage(hDlg,24300,CB_GETITEMDATA,i,(LPARAM)0);
		}
		else if((LOWORD(wParam)==24301)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	int i = SendDlgItemMessage(hDlg,24301,CB_GETCURSEL,0,0);
			if(i != CB_ERR)
				tmpOptions->ORProxyProtocol = SendDlgItemMessage(hDlg,24301,CB_GETITEMDATA,i,(LPARAM)0);
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
