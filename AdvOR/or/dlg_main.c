#include "or.h"
#include "dlg_util.h"
#include "plugins.h"
#include "dlg_resize.h"
#include "geoip.h"
#include "main.h"
#include "routerlist.h"
#include "config.h"
#include "circuitlist.h"
#include "hibernate.h"
#include "control.h"
#include <shellapi.h>

#define STARTUP_OPTION_START_TOR 1
#define STARTUP_OPTION_MINIMIZE_AT_STARTUP 2
#define STARTUP_OPTION_RESIZE_SETTINGS_APPLIED 4
#define SPLITTER_WIDTH 5
#define MIN_SPLIT_DELTA 10

typedef void (*SplitterAdjust)(void);

HWND hMainDialog=NULL;
int isTopMost = 0;
HTREEITEM pages[MAX_PAGE_INDEXES] = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
HANDLE hIconConnected,hIcon1,hIconDisconnected,hIconConnecting,hMenu;
NOTIFYICONDATA nid;
extern HWND hDlgProxy,hDlgBannedAddresses,hDlgAdvancedProxy,hDlgProxyHTTP;
extern HWND hDlgAuthorities;
extern HWND hDlgRouterRestrictions,hDlgRouterBans,hDlgRouterFavorites;
extern HWND hDlgCircuitBuild,hDlgTrackedHosts;
extern HWND hDlgConnections;
extern HWND hDlgBridges;
extern HWND hDlgHiddenServices;
extern HWND hDlgPlugins;
extern HWND hDlgSystem;
extern HWND hDlgIdentity;
extern HWND hDlgForceTor,hDlgQuickStart,hDlgSandboxing;
extern HWND hDlgServer;
extern HWND hDlgNetInfo;
extern HWND hDlgDebug;
extern HWND hDlgAbout,hDlgHostedServices,hDlgInterceptHelp;
extern HWND hDlgBypassBlacklists;
extern HINSTANCE hInstance;
extern HANDLE hThread;
extern DWORD thread_id;
extern int selectedVer;
extern int lastSort;
extern char strban[256+3];
extern or_options_t *tmpOptions;
extern char exename[MAX_PATH+1];
extern BOOL started;
extern resize_info_t resize_main[];
extern resize_info_t resize_proxy[];
extern resize_info_t resize_banned_addresses[];
extern resize_info_t resize_advanced_proxy[];
extern resize_info_t resize_proxy_http[];
extern resize_info_t resize_authorities[];
extern resize_info_t resize_router_restrictions[];
extern resize_info_t resize_router_bans[];
extern resize_info_t resize_router_favorites[];
extern resize_info_t resize_circuit_build[];
extern resize_info_t resize_tracked_hosts[];
extern resize_info_t resize_connections[];
extern resize_info_t resize_bridges[];
extern resize_info_t resize_bypass_blacklists[];
extern resize_info_t resize_hs[];
extern resize_info_t resize_plugins[];
extern resize_info_t resize_system[];
extern resize_info_t resize_force_tor[];
extern resize_info_t resize_quick_start[];
extern resize_info_t resize_sandboxing[];
extern resize_info_t resize_server[];
extern resize_info_t resize_network_information[];
extern resize_info_t resize_debug[];
extern resize_info_t resize_about[];
extern resize_info_t resize_plugin[];
extern resize_info_t resize_identity[];
char newname[200];
int frame=DLG_FRAME_PROXY;
int stateIcon = -1;
HWND selWnd=NULL;
resize_info_t *resize_sel=NULL;
int startupOption=0;
POINT point;
int splitX = -1;
int spltX0=0;
HWND hSplitterParent = NULL;
HWND hSplitter = NULL;
char spltClassRegged=0;
const char *spltclass = "Splitter";
SplitterAdjust spltProc;

HANDLE hLibrary;
LPFN1 ShowProcesses=NULL,TORUnhook=NULL,SetGetLangStrCallback=NULL,GetProcessChainKey=NULL,RegisterPluginKey=NULL,UnregisterPluginKey=NULL,SetHibernationState=NULL;
LPFN2 SetProc=NULL;
LPFN3 TORHook=NULL;
LPFN12 CreateNewProcess=NULL;
LPFN13 CreateThreadEx=NULL;
LPFN4 UnloadDLL=NULL,GetAdvORVer=NULL;
LPFN5 GetConnInfo=NULL;
LPFN6 ShowProcessTree=NULL;
LPFN7 HookProcessTree=NULL;
LPFN8 PidFromAddr=NULL,WarnOpenConnections=NULL;
LPFN9 ProcessNameFromPid=NULL;
LPFN11 ShowOpenPorts=NULL;
LPFN10 GetChainKeyName=NULL;
LPFN14 RelinkStoredProc=NULL;
int __stdcall tor_thread(LPARAM lParam);

lang_dlg_info lang_dlg_main[]={
	{1,LANG_DLG_START_TOR},
	{6,LANG_DLG_NEW_IDENTITY},
	{3,LANG_DLG_SAVE_SETTINGS},
	{5,LANG_DLG_ALWAYS_ON_TOP},
	{4,LANG_DLG_MINIMIZE_TO_TRAY},
	{2,LANG_DLG_EXIT},
	{0,0}
};

int __stdcall dlgProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgProxyHTTP(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgBannedAddresses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgAdvancedProxy(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgInterceptProcesses(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgDebug(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgForceTor(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgQuickStart(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgSandboxing(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgCircuitBuild(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgTrackedHosts(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgConnections(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgBridges(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgBypassBlacklists(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgHiddenServices(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgPlugins(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgAuthorities(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterRestrictions(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterBans(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterFavorites(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgExitSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgSystem(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgServer(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgNetInfo(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgAbout(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgHostedServices(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgInterceptHelp(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgExit(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgIdentity(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgfunc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall spltproc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void initSplitter(HWND hParent,int ctrl,SplitterAdjust moveW);
void splt_resize3(void);
void dlgProxy_banDebugAddress(char *strban);
void dlgDebug_logFilterAdd(char *strban);
void dlgTrackedHosts_trackedHostExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_trackedDomainExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapRemove(HWND hDlg,char *newAddr);
void dlgForceTor_quickStart(void);
void dlgForceTor_unhookAll(void);
void dlgForceTor_menuAppendHookedProcesses(HMENU hMenu3);
void dlgForceTor_menuRelease(int item);
void dlgForceTor_quickStartClearAll(void);
void dlgForceTor_quickStartFromMenu(int item);
void dlgForceTor_interceptNewProcess(void);
void dlgForceTor_interceptFocusedProcess(void);
void dlgForceTor_releaseFocusedProcess(void);
void dlgQuickStart_langUpdate(void);
void dlgSystem_RegisterHotKeys(void);
void dlgSystem_UnregisterHotKeys(void);
void dlgSystem_RegisterRestoreHotKey(void);
void dlgForceTor_scheduledExec(void);
BOOL dlgUtil_canShow(void);
void dlgProxyHttp_langUpdate(void);
void dlgIdentity_langUpdate(void);
int canExit(int);
void schedule_stop_tor(void);
void releaseGraph(void);
void recalcGraph(void);
void signewnym_impl(time_t now,int msgshow);
void set_identity_exit(uint32_t);
HMENU getProcessesMenu(int tray);
void __stdcall _proxy_log(int log_level,const char *msg);
void getExclKeyName(char *s1,DWORD exclKey);
void saveWindowPos(void);
HANDLE getStateIcon(void);
void setLastSort(int newSort);

void __stdcall _proxy_log(int log_level,const char *msg)
{	log(log_level,LD_APP,"%s",msg);
}

void setStartupOption(int commandId)
{	if(commandId==CMD_START)	startupOption |= STARTUP_OPTION_START_TOR;
	else if(commandId==CMD_MINIMIZE)	startupOption |= STARTUP_OPTION_MINIMIZE_AT_STARTUP;
}

void progressLog(int percent,const char *message)
{	SendDlgItemMessage(hMainDialog,1002,PBM_SETPOS,percent,0);
	SetDlgItemTextL(hMainDialog,1003,message);
}

void showLastExit(char *rname,uint32_t addr)
{	uint32_t raddr=geoip_reverse(addr);
	unsigned int country;
	set_identity_exit(raddr);
	if(started==2)
	{	tor_snprintf(newname,200,"%s - %s",exename,get_lang_str(LANG_DLG_NOT_CONNECTED));
		LangSetWindowText(hMainDialog,newname);
	}
	else if(rname)
	{	country = geoip_get_country_by_ip(raddr);
		tor_snprintf(newname,200,"%s [exit(%s%s): %d.%d.%d.%d (%s)]",exename,geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,rname);
		LangSetWindowText(hMainDialog,newname);
	}
	else
	{	raddr=get_router_sel();
		if(raddr && raddr!=0x0100007f)
		{	raddr=geoip_reverse(raddr);
			country = geoip_get_country_by_ip(raddr);
			tor_snprintf(newname,200,"%s [exit(%s%s): %d.%d.%d.%d]%s",exename,geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,(addr==0xffffffff)?"":" - no exit");
		}
		else if(get_country_sel()<0x1ff)	tor_snprintf(newname,200,"%s [exit(%s)]%s",exename,geoip_get_country_name(get_country_sel()),(addr==0xffffffff)?"":" - no exit");
		else	tor_snprintf(newname,200,"%s - %s exit",exename,(addr==0xffffffff)?"new":"no");
		LangSetWindowText(hMainDialog,newname);
	}
	if(nid.cbSize)
	{	tor_snprintf(nid.szTip,63,newname);
		nid.uFlags=NIF_TIP;
		Shell_NotifyIcon(NIM_MODIFY,&nid);
	}
}

char *getLanguageFileName(const char *source)
{	char *lngname=tor_malloc(MAX_PATH*2+2);
	tor_snprintf(lngname,MAX_PATH*2,"%s-%s.lng",exename,source);
	return lngname;
}

int getProcessName(char *buffer,int bufsize,DWORD pid)
{	if(ProcessNameFromPid) return ProcessNameFromPid(buffer,bufsize,pid);
	*buffer=0;
	return 0;
}

DWORD getPID(uint32_t addr,int port)
{	if(PidFromAddr)	return PidFromAddr(addr,port);
	return 0;
}

DWORD getChainKey(DWORD pid)
{	if(pid && GetProcessChainKey) return GetProcessChainKey(pid);
	return 0;
}

void getExclKeyName(char *s1,DWORD exclKey)
{	if(!GetChainKeyName)	tor_snprintf(s1,10,"GENERAL");
	else	GetChainKeyName(s1,exclKey);
}

RECT lastWindowRect,desktopRect;
unsigned int isZoomed=0;
void saveWindowPos(void)
{	isZoomed=IsZoomed(hMainDialog);
	if(!isZoomed)
	{	GetWindowRect(GetDesktopWindow(),&desktopRect);
		GetWindowRect(hMainDialog,&lastWindowRect);
	}
	char *oldvar=tmpOptions->WindowPos;
	tmpOptions->WindowPos=tor_malloc(100);
	tor_snprintf(tmpOptions->WindowPos,100,"%u,%u,%u,%u,%u,%u,%u,%u",isZoomed,(unsigned int)desktopRect.right,(unsigned int)desktopRect.bottom,(unsigned int)lastWindowRect.left,(unsigned int)lastWindowRect.top,(unsigned int)lastWindowRect.right,(unsigned int)lastWindowRect.bottom,(lastSort<0)?((-lastSort) | 0x80):lastSort);
	if(oldvar)	tor_free(oldvar);
	oldvar = tmpOptions->GuiPlacement3;
	tor_asprintf((unsigned char **)&tmpOptions->GuiPlacement3,"%s,%d",tmpOptions->WindowPos,splitX);
	if(oldvar)	tor_free(oldvar);
}

HANDLE getStateIcon(void)
{	switch(stateIcon)
	{	case STATE_CONNECTED:
			return hIconConnected;
		case STATE_CONNECTING:
			return hIconConnecting;
		default:
			break;
	}
	return hIconDisconnected;
}

void setState(int state)
{
	if(stateIcon != state)
	{	stateIcon = state;
		HANDLE icon = getStateIcon();
		SendMessage(hMainDialog,WM_SETICON,(WPARAM)ICON_BIG,(LPARAM)icon);
		if(nid.cbSize)
		{	nid.uFlags=NIF_ICON;
			nid.hIcon = icon;
			Shell_NotifyIcon(NIM_MODIFY,&nid);
		}
		if(SetHibernationState)	SetHibernationState(state);
	}
}

void setLastSort(int newSort)
{	lastSort = newSort;
	saveWindowPos();
}

void save_settings(void)
{	if(options_save_current()<0) LangMessageBox(hMainDialog,get_lang_str(LANG_MB_WRITE_ERROR),LANG_MB_ERROR,MB_OK);
	else
	{	flush_configuration_data();
		LangMessageBox(hMainDialog,get_lang_str(LANG_MB_OPTIONS_SAVED),LANG_MB_SAVE_SETTINGS,MB_OK);
	}
}

TV_INSERTSTRUCTW tvins;

HTREEITEM addTreeItem(HTREEITEM hParent,const char *name,DWORD lParam,int tree_idx)
{	if(!name)
	{	if(tree_idx!=-1)	pages[tree_idx] = NULL;
		return NULL;
	}
	tvins.hParent = hParent;
	tvins.hInsertAfter = TVI_LAST;
	tvins.item.mask = TVIF_PARAM | TVIF_TEXT;
	tvins.item.lParam = lParam;
	tvins.item.hItem = NULL;
	tvins.item.stateMask = 0;
	tvins.item.pszText = get_unicode(name);
	LONG r=SendDlgItemMessageW(hMainDialog,200,TVM_INSERTITEMW,0,(LPARAM)&tvins);
	hParent = (HTREEITEM)r;
	if(tree_idx!=-1)	pages[tree_idx] = hParent;
	tor_free(tvins.item.pszText);
	return hParent;
}

void setTreeItem(HTREEITEM hItem,const char *name)
{	if(name)
	{	tvins.item.mask = TVIF_TEXT;
		tvins.item.hItem = hItem;
		tvins.item.stateMask = 0;
		tvins.item.pszText = get_unicode(name);
		SendDlgItemMessageW(hMainDialog,200,TVM_SETITEMW,0,(LPARAM)&tvins.item);
		tor_free(tvins.item.pszText);
	}
}

void dlgRouterRestrictions_langUpdate(void);
void dlgHiddenServices_langUpdate(void);
void dlgPlugins_langUpdate(void);
void tree_lang_update(void);
void dlgDebug_langUpdate(void);

extern lang_dlg_info lang_dlg_proxy[];
extern lang_dlg_info lang_dlg_banned_addresses[];
extern lang_dlg_info lang_dlg_advanced_proxy[];
extern lang_dlg_info lang_dlg_authorities[];
extern lang_dlg_info lang_dlg_circuitbuild[];
extern lang_dlg_info lang_dlg_tracked_hosts[];
extern lang_dlg_info lang_dlg_connections[];
extern lang_dlg_info lang_dlg_bridges[];
extern lang_dlg_info lang_dlg_bypass_blacklists[];
extern lang_dlg_info lang_dlg_system[];
extern lang_dlg_info lang_dlg_force_tor[];
extern lang_dlg_info lang_dlg_sandboxing[];
extern lang_dlg_info lang_dlg_server[];
extern lang_dlg_info lang_dlg_router_bans[];
extern lang_dlg_info lang_dlg_router_favorites[];
extern lang_dlg_info lang_dlg_hosted_services[];
extern lang_dlg_info lang_dlg_intercept_help[];

void setNewLanguage(void)
{	if(hMainDialog==NULL) return;
	changeDialogStrings(hMainDialog,lang_dlg_main);
	if(hDlgProxy)	changeDialogStrings(hDlgProxy,lang_dlg_proxy);
	if(hDlgBannedAddresses)	changeDialogStrings(hDlgBannedAddresses,lang_dlg_banned_addresses);
	if(hDlgAdvancedProxy)	changeDialogStrings(hDlgAdvancedProxy,lang_dlg_advanced_proxy);
	dlgProxyHttp_langUpdate();
	if(hDlgAuthorities) changeDialogStrings(hDlgAuthorities,lang_dlg_authorities);
	dlgRouterRestrictions_langUpdate();
	if(hDlgRouterBans)	changeDialogStrings(hDlgRouterBans,lang_dlg_router_bans);
	if(hDlgRouterFavorites)	changeDialogStrings(hDlgRouterFavorites,lang_dlg_router_favorites);
	if(hDlgCircuitBuild)	changeDialogStrings(hDlgCircuitBuild,lang_dlg_circuitbuild);
	if(hDlgTrackedHosts)	changeDialogStrings(hDlgTrackedHosts,lang_dlg_tracked_hosts);
	if(hDlgConnections)	changeDialogStrings(hDlgConnections,lang_dlg_connections);
	if(hDlgBridges)	changeDialogStrings(hDlgBridges,lang_dlg_bridges);
	if(hDlgBypassBlacklists) changeDialogStrings(hDlgBypassBlacklists,lang_dlg_bypass_blacklists);
	if(hDlgHostedServices)	changeDialogStrings(hDlgHostedServices,lang_dlg_hosted_services);
	dlgHiddenServices_langUpdate();
	dlgPlugins_langUpdate();
	if(hDlgSystem)	changeDialogStrings(hDlgSystem,lang_dlg_system);
	if(hDlgIdentity)	dlgIdentity_langUpdate();
	if(hDlgInterceptHelp)	changeDialogStrings(hDlgInterceptHelp,lang_dlg_intercept_help);
	if(hDlgForceTor)	changeDialogStrings(hDlgForceTor,lang_dlg_force_tor);
	dlgQuickStart_langUpdate();
	if(hDlgSandboxing)	changeDialogStrings(hDlgSandboxing,lang_dlg_sandboxing);
	if(hDlgServer)	changeDialogStrings(hDlgServer,lang_dlg_server);
	tree_lang_update();
	dlgDebug_langUpdate();
	setTreeItem(pages[INDEX_PAGE_PROXY],get_lang_str(LANG_LB_PROXY));
	setTreeItem(pages[INDEX_PAGE_BANLIST],get_lang_str(LANG_LB_BANNED_ADDRESSES));
	setTreeItem(pages[INDEX_PAGE_HTTP_HEADERS],get_lang_str(LANG_LB_HTTP_HEADERS));
	setTreeItem(pages[INDEX_PAGE_CONNECTIONS],get_lang_str(LANG_LB_CONNECTIONS));
	setTreeItem(pages[INDEX_PAGE_ADVANCED_PROXY_SETTINGS],get_lang_str(LANG_LB_ADVANCED_PROXY_SETTINGS));
	setTreeItem(pages[INDEX_PAGE_NETWORK],get_lang_str(LANG_LB_NETSTAT));
	setTreeItem(pages[INDEX_PAGE_BRIDGES],get_lang_str(LANG_LB_BRIDGES));
	setTreeItem(pages[INDEX_PAGE_BYPASSBL],get_lang_str(LANG_LB_BYPASSBL));
	setTreeItem(pages[INDEX_PAGE_AUTHORITIES],get_lang_str(LANG_LB_AUTHORITIES));
	setTreeItem(pages[INDEX_PAGE_ROUTER_RESTRICTIONS],get_lang_str(LANG_LB_ROUTER_RESTRICTIONS));
	setTreeItem(pages[INDEX_PAGE_BANNED_ROUTERS],get_lang_str(LANG_LB_BANNED_ROUTERS));
	setTreeItem(pages[INDEX_PAGE_FAVORITE_ROUTERS],get_lang_str(LANG_LB_FAVORITE_ROUTERS));
	setTreeItem(pages[INDEX_PAGE_CIRCUIT_BUILD],get_lang_str(LANG_LB_CIRCUIT_BUILD));
	setTreeItem(pages[INDEX_PAGE_TRACKED_HOSTS],get_lang_str(LANG_LB_TRACKED_HOSTS));
	setTreeItem(pages[INDEX_PAGE_HOSTED_SERVICES],get_lang_str(LANG_LB_HOSTED_SERVICES));
	setTreeItem(pages[INDEX_PAGE_HIDDEN_SERVICES],get_lang_str(LANG_LB_HIDDEN_SERVICES));
	setTreeItem(pages[INDEX_PAGE_OR_SERVER],get_lang_str(LANG_LB_SERVER));
	setTreeItem(pages[INDEX_PAGE_PRIVATE_IDENTITY],get_lang_str(LANG_LB_PRIVATE_IDENTITY));
	if(hLibrary)
	{	setTreeItem(pages[INDEX_PAGE_INTERCEPT],get_lang_str(LANG_LB_INTERCEPT));
		setTreeItem(pages[INDEX_PAGE_QUICK_START],get_lang_str(LANG_LB_QUICK_START));
		setTreeItem(pages[INDEX_PAGE_PROCESSES],get_lang_str(LANG_LB_PROCESSES));
		setTreeItem(pages[INDEX_PAGE_SANDBOXING],get_lang_str(LANG_LB_SANDBOXING));
	}
	setTreeItem(pages[INDEX_PAGE_PLUGINS],get_lang_str(LANG_LB_PLUGINS));
	setTreeItem(pages[INDEX_PAGE_SYSTEM],get_lang_str(LANG_LB_SYSTEM));
	setTreeItem(pages[INDEX_PAGE_DEBUG],get_lang_str(LANG_LB_DEBUG));
	//	setTreeItem(pages[INDEX_PAGE_FILTERS],get_lang_str(LANG_LB_FILTERS));
	setTreeItem(pages[INDEX_PAGE_ABOUT],get_lang_str(LANG_LB_ABOUT));
	dlg_set_all_plugins();
	plugins_language_change();
}

void initSplitter(HWND hParent,int ctrl,SplitterAdjust moveW)
{	HWND hWnd = GetDlgItem(hParent,ctrl);
	RECT r;
	POINT pt;
	spltProc = moveW;
	GetWindowRect(hWnd,&r);
	r.right -= r.left;
	r.bottom -= r.top;
	pt.x = r.left;
	pt.y = r.top;
	ScreenToClient(hParent,&pt);
	hSplitter = hWnd;
	hSplitterParent = hParent;
	DestroyWindow(hWnd);
	if(!spltClassRegged)
	{	WNDCLASSEX wndcl;
		wndcl.cbSize = sizeof(wndcl);
		wndcl.style = CS_BYTEALIGNWINDOW;
		wndcl.lpfnWndProc = (WNDPROC)&spltproc;
		wndcl.cbClsExtra = 0;
		wndcl.cbWndExtra = 0;
		wndcl.hInstance = hInstance;
		wndcl.hIcon = wndcl.hIconSm = NULL;
		wndcl.hCursor = LoadCursor(NULL,IDC_SIZEWE);
		wndcl.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
		wndcl.lpszMenuName = NULL;
		wndcl.lpszClassName = spltclass;
		RegisterClassEx(&wndcl);
		spltClassRegged = 1;
	}
	hWnd = CreateWindowEx(WS_EX_TOPMOST,spltclass,0,WS_CHILD | WS_VISIBLE,splitX!=-1?splitX:pt.x,0,SPLITTER_WIDTH,r.bottom,hParent,(HMENU)ctrl,hInstance,0);
	if(splitX!=-1)
		spltProc();
}

int __stdcall spltproc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_LBUTTONDOWN)
	{	spltX0 = LOWORD(lParam);
		if(spltX0 & 0x8000) spltX0 -= 0x10000;
		SetCapture(hDlg);
		return 0;
	}
	else if(uMsg==WM_LBUTTONUP)
	{	ReleaseCapture();
		return 0;
	}
	else if(uMsg==WM_MOUSEMOVE && (wParam & MK_LBUTTON) != 0)
	{	DWORD i;
		DWORD delta;
		i = LOWORD(lParam);
		if(i & 0x8000)	i -= 0x10000;
		delta = i - spltX0;
		if(delta)
		{	RECT r,r1;
			GetWindowRect(hDlg,&r);
			r.bottom -= r.top;
			POINT pt;
			pt.x = r.left + delta;
			pt.y = 0;
			ScreenToClient(hSplitterParent,&pt);
			GetWindowRect(hSplitterParent,&r1);
			if(pt.x > 10 && pt.x+20 < r1.right-r1.left)
			{
				splitX = pt.x;
				MoveWindow(hDlg,pt.x,0,SPLITTER_WIDTH,r.bottom,1);
				spltProc();
				BringWindowToTop(hDlg);
				return 0;
			}
		}
	}
	return DefWindowProc(hDlg,uMsg,wParam,lParam);
}

void splt_resize3(void)
{
	resizeDialogControls(hMainDialog,resize_main,0,0);
	resizeChildDialog(hMainDialog,selWnd,resize_sel);
	if(resize_sel==resize_network_information) recalcGraph();
	else if(resize_sel==resize_debug)	LangDebugScroll(hDlgDebug);
	RedrawWindow(hMainDialog,NULL,NULL,RDW_INVALIDATE|RDW_INTERNALPAINT|RDW_UPDATENOW|RDW_ALLCHILDREN|RDW_NOERASE);
	if(startupOption&STARTUP_OPTION_RESIZE_SETTINGS_APPLIED)
		saveWindowPos();
}



int __stdcall dlgfunc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	int i;
	if(uMsg==WM_INITDIALOG)
	{	hMainDialog=hDlg;
		SetClassLong(hDlg,GCL_STYLE,GetClassLong(hDlg,GCL_STYLE)|CS_HREDRAW|CS_VREDRAW|CS_PARENTDC);
		if(LangGetLanguage()) changeDialogStrings(hDlg,lang_dlg_main);
		get_winver();
		tor_snprintf(newname,200,"%s  %s by Albu Cristian, 2009-2025",exename,advtor_ver);
		LangSetWindowText(hDlg,newname);
		hIcon1=LoadIcon(hInstance,MAKEINTRESOURCE(9));
		SendDlgItemMessage(hDlg,9,BM_SETIMAGE,IMAGE_ICON,(LPARAM)hIcon1);
		hIconConnected=LoadIcon(hInstance,MAKEINTRESOURCE(1));
		hIconDisconnected=LoadIcon(hInstance,MAKEINTRESOURCE(2));
		hIconConnecting=LoadIcon(hInstance,MAKEINTRESOURCE(3));
		nid.cbSize=0;
		setState(STATE_DISCONNECTED);
		SendDlgItemMessage(hDlg,1002,0,PBM_SETRANGE,MAKELPARAM(0,100));
		selWnd=hDlgProxy=createChildDialog(hDlg,DLG_FRAME_PROXY,&dlgProxy);
		resize_sel = resize_proxy;
		ShowWindow(hDlgProxy,SW_SHOW);
		hDlgForceTor=createChildDialog(hDlg,DLG_FRAME_INTERCEPT_PROCESSES,&dlgInterceptProcesses);
		hDlgDebug=createChildDialog(hDlg,DLG_FRAME_DEBUG,&dlgDebug);
		EnableWindow(GetDlgItem(hDlg,6),0);EnableWindow(GetDlgItem(hDlg,8),0);
		HTREEITEM hParent;
		hParent = addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_PROXY),DLG_FRAME_PROXY,INDEX_PAGE_PROXY);
		addTreeItem(hParent,get_lang_str(LANG_LB_BANNED_ADDRESSES),DLG_FRAME_BANNED_ADDRESSES,INDEX_PAGE_BANLIST);
		addTreeItem(hParent,get_lang_str(LANG_LB_HTTP_HEADERS),DLG_FRAME_HTTP_HEADERS,INDEX_PAGE_HTTP_HEADERS);
		addTreeItem(hParent,get_lang_str(LANG_LB_CONNECTIONS),DLG_FRAME_CONNECTIONS,INDEX_PAGE_CONNECTIONS);
		addTreeItem(hParent,get_lang_str(LANG_LB_ADVANCED_PROXY_SETTINGS),DLG_FRAME_ADVANCED_PROXY_SETTINGS,INDEX_PAGE_ADVANCED_PROXY_SETTINGS);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		hParent = addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_NETSTAT),DLG_FRAME_OR_NETWORK,INDEX_PAGE_NETWORK);
		addTreeItem(hParent,get_lang_str(LANG_LB_BRIDGES),DLG_FRAME_BRIDGES,INDEX_PAGE_BRIDGES);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		addTreeItem(hParent,get_lang_str(LANG_LB_BYPASSBL),DLG_FRAME_BYPASSBL,INDEX_PAGE_BYPASSBL);
		addTreeItem(hParent,get_lang_str(LANG_LB_AUTHORITIES),DLG_FRAME_AUTHORITIES,INDEX_PAGE_AUTHORITIES);
		hParent = addTreeItem(hParent,get_lang_str(LANG_LB_ROUTER_RESTRICTIONS),DLG_FRAME_ROUTER_RESTRICTIONS,INDEX_PAGE_ROUTER_RESTRICTIONS);
		addTreeItem(hParent,get_lang_str(LANG_LB_BANNED_ROUTERS),DLG_FRAME_BANNED_ROUTERS,INDEX_PAGE_BANNED_ROUTERS);
		addTreeItem(hParent,get_lang_str(LANG_LB_FAVORITE_ROUTERS),DLG_FRAME_FAVORITE_ROUTERS,INDEX_PAGE_FAVORITE_ROUTERS);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		hParent = pages[INDEX_PAGE_NETWORK];
		addTreeItem(hParent,get_lang_str(LANG_LB_CIRCUIT_BUILD),DLG_FRAME_CIRCUIT_BUILD,INDEX_PAGE_CIRCUIT_BUILD);
		addTreeItem(hParent,get_lang_str(LANG_LB_TRACKED_HOSTS),DLG_FRAME_TRACKED_HOSTS,INDEX_PAGE_TRACKED_HOSTS);
		hParent = addTreeItem(hParent,get_lang_str(LANG_LB_HOSTED_SERVICES),DLG_FRAME_HOSTED_SERVICES,INDEX_PAGE_HOSTED_SERVICES);
		addTreeItem(hParent,get_lang_str(LANG_LB_HIDDEN_SERVICES),DLG_FRAME_HIDDEN_SERVICES,INDEX_PAGE_HIDDEN_SERVICES);
		addTreeItem(hParent,get_lang_str(LANG_LB_SERVER),DLG_FRAME_HOST_ROUTER,INDEX_PAGE_OR_SERVER);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_PRIVATE_IDENTITY),DLG_FRAME_PRIVATE_IDENTITY,INDEX_PAGE_PRIVATE_IDENTITY);
		char *tmp1=get_datadir_fname_suffix(NULL,".dll");
		hLibrary=load_library(tmp1);
		if(hLibrary)
		{	GetAdvORVer=(LPFN4)GetProcAddress(hLibrary,"GetAdvORVer");
			if(GetAdvORVer && GetAdvORVer()>=0x00020006)
			{	SetProc=(LPFN2)GetProcAddress(hLibrary,"SetProc");ShowProcesses=(LPFN1)GetProcAddress(hLibrary,"ShowProcesses");
				TORHook=(LPFN3)GetProcAddress(hLibrary,"TORHook");TORUnhook=(LPFN1)GetProcAddress(hLibrary,"TORUnhook");
				SetGetLangStrCallback=(LPFN1)GetProcAddress(hLibrary,"SetGetLangStrCallback");
				if(SetGetLangStrCallback) SetGetLangStrCallback((DWORD)&get_lang_str);
				if(SetProc((DWORD)&_proxy_log,hDlgForceTor,pipeName)==0)
				{	FreeLibrary(hLibrary);SetProc=NULL;ShowProcesses=NULL;TORHook=NULL;TORUnhook=NULL;
				}
				else
				{	hParent = addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_INTERCEPT),DLG_FRAME_INTERCEPT,INDEX_PAGE_INTERCEPT);
					addTreeItem(hParent,get_lang_str(LANG_LB_QUICK_START),DLG_FRAME_QUICK_START,INDEX_PAGE_QUICK_START);
					addTreeItem(hParent,get_lang_str(LANG_LB_PROCESSES),DLG_FRAME_INTERCEPT_PROCESSES,INDEX_PAGE_PROCESSES);
					addTreeItem(hParent,get_lang_str(LANG_LB_SANDBOXING),DLG_FRAME_SANDBOXING,INDEX_PAGE_SANDBOXING);
					SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
				}
				UnloadDLL=(LPFN4)GetProcAddress(hLibrary,"UnloadDLL");
				GetConnInfo=(LPFN5)GetProcAddress(hLibrary,"GetConnInfo");
				ShowProcessTree=(LPFN6)GetProcAddress(hLibrary,"ShowProcessTree");
				HookProcessTree=(LPFN7)GetProcAddress(hLibrary,"HookProcessTree");
				PidFromAddr=(LPFN8)GetProcAddress(hLibrary,"PidFromAddr");
				WarnOpenConnections=(LPFN8)GetProcAddress(hLibrary,"WarnOpenConnections");
				GetProcessChainKey=(LPFN1)GetProcAddress(hLibrary,"GetProcessChainKey");
				GetChainKeyName=(LPFN10)GetProcAddress(hLibrary,"GetChainKeyName");
				ProcessNameFromPid=(LPFN9)GetProcAddress(hLibrary,"ProcessNameFromPid");
				ShowOpenPorts=(LPFN11)GetProcAddress(hLibrary,"ShowOpenPorts");
				RegisterPluginKey=(LPFN1)GetProcAddress(hLibrary,"RegisterPluginKey");
				UnregisterPluginKey=(LPFN1)GetProcAddress(hLibrary,"UnregisterPluginKey");
				CreateNewProcess=(LPFN12)GetProcAddress(hLibrary,"CreateNewProcess");
				SetHibernationState=(LPFN1)GetProcAddress(hLibrary,"SetHibernationState");
				CreateThreadEx=(LPFN13)GetProcAddress(hLibrary,"CreateThreadEx");
				RelinkStoredProc=(LPFN14)GetProcAddress(hLibrary,"RelinkStoredProc");
			}
			else
			{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_VERSION_TOO_OLD));
				FreeLibrary(hLibrary);hLibrary=NULL;
			}
		}
		else log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_ERROR_LOADING_DLL),tmp1);
		tor_free(tmp1);
		hParent = addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_PLUGINS),DLG_FRAME_PLUGINS,INDEX_PAGE_PLUGINS);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		hParent = addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_SYSTEM),DLG_FRAME_SYSTEM,INDEX_PAGE_SYSTEM);
		hParent = addTreeItem(hParent,get_lang_str(LANG_LB_DEBUG),DLG_FRAME_DEBUG,INDEX_PAGE_DEBUG);
	//	addTreeItem(hParent,get_lang_str(LANG_LB_FILTERS),DLG_FRAME_DEBUG_FILTERS,INDEX_PAGE_FILTERS);
		SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)pages[INDEX_PAGE_SYSTEM]);
	//	SendDlgItemMessage(hDlg,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent);
		addTreeItem(TVI_ROOT,get_lang_str(LANG_LB_ABOUT),DLG_FRAME_ABOUT,INDEX_PAGE_ABOUT);
		SendDlgItemMessage(hDlg,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_PROXY]);
		if(is_read_only())	EnableWindow(GetDlgItem(hDlg,3),0);
		HWND h=GetDlgItem(hDlg,1);
		if((tmpOptions->AutoStart&1) || (startupOption&STARTUP_OPTION_START_TOR)){	CheckDlgButton(hDlg,1,BST_CHECKED);PostMessage(hDlg,WM_COMMAND,1,(LPARAM)h);}
		if((tmpOptions->AutoStart&2) || (startupOption&STARTUP_OPTION_MINIMIZE_AT_STARTUP)){	ShowWindow(hDlg,SW_MINIMIZE);PostMessage(hDlg,WM_SYSCOMMAND,SC_MINIMIZE,0);}
		if(get_lang_str(LANG_LOG_DLG_WELCOME))	log(LOG_NOTICE,LD_GENERAL,get_lang_str(LANG_LOG_DLG_WELCOME),advtor_ver,tmpOptions->SocksPort,tmpOptions->SocksPort);
		dlgForceTor_quickStart();
		dlgStatsRWInit();
		load_plugins();
		initSplitter(hDlg,201,&splt_resize3);
		dlgSystem_RegisterHotKeys();
		PostMessage(hDlg,WM_SIZE,0,0);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==2)
		{	if(canExit(0))
			{	if(!unload_plugins(hDlg)) return 0;
				remove_plugins();
				if(nid.cbSize) Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;
				dlgForceTor_unhookAll();
				dlgSystem_UnregisterHotKeys();
				releaseGraph();
				EndDialog(hDlg,0);
			}
		}
		else if(LOWORD(wParam)==3)
		{	save_settings();
		}
		else if(LOWORD(wParam)==1)
		{	if(started == 1 && !IsDlgButtonChecked(hDlg,1))
			{	EnableWindow(GetDlgItem(hDlg,6),0);EnableWindow(GetDlgItem(hDlg,8),0);
				schedule_stop_tor();
				LangSetDlgItemText(hDlg,1,LANG_DLG_START_TOR);
				setState(STATE_DISCONNECTED);
			}
			else if(started==2 && IsDlgButtonChecked(hDlg,1))
			{	started=1;plugins_start(1);
				EnableWindow(GetDlgItem(hDlg,6),1);EnableWindow(GetDlgItem(hDlg,8),1);
				hibernate_end_time_elapsed(get_time(NULL));
				LangSetDlgItemText(hDlg,1,LANG_MNU_STOP_TOR);
				setState(STATE_CONNECTING);
			}
			else if(started==0)
			{	started=1;plugins_start(1);	//SetDlgItemText(hDlg,1,"&Stop");
				LangSetDlgItemText(hDlg,1,LANG_MNU_STOP_TOR);
				setState(STATE_CONNECTING);
				if(!tmpOptions->MaxUnusedOpenCircuits)	control_event_bootstrap(BOOTSTRAP_STATUS_STARTED,0);
				identity_init();
				hThread=CreateThread(0,0,(LPTHREAD_START_ROUTINE)tor_thread,0,0,(LPDWORD)&thread_id);
				EnableWindow(GetDlgItem(hDlg,6),1);EnableWindow(GetDlgItem(hDlg,8),1);
				if(frame!=DLG_FRAME_OR_NETWORK)
					SendDlgItemMessage(hDlg,200,TVM_SELECTITEM,TVGN_CARET,(LPARAM)pages[INDEX_PAGE_DEBUG]);
			}
		}
		else if(LOWORD(wParam)==6 && started==1)
		{	set_router_sel(0,1);signewnym_impl(get_time(NULL),1);
		}
		else if(LOWORD(wParam)==5)
		{	if(IsDlgButtonChecked(hDlg,5)==BST_CHECKED)
			{	SetWindowPos(hDlg,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
				isTopMost = 1;
			}
			else
			{	SetWindowPos(hDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
				isTopMost = 0;
			}
		}
		else if(LOWORD(wParam)==4)
		{	nid.cbSize=sizeof(nid);nid.hWnd=hDlg;nid.uID=100;nid.uFlags=NIF_ICON|NIF_MESSAGE|NIF_TIP;nid.uCallbackMessage=WM_USER+10;nid.hIcon=getStateIcon();
			tor_snprintf(nid.szTip,63,newname);
			Shell_NotifyIcon(NIM_ADD,&nid);
			ShowWindow(hDlg,SW_HIDE);
		}
		else if(LOWORD(wParam)==7)
		{	Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;
			ShowWindow(hDlg,SW_SHOWNORMAL);BringWindowToTop(hDlg);SetForegroundWindow(hDlg);
			SendDlgItemMessage(hDlg,100,EM_SCROLLCARET,0,0);
		}
		else if(LOWORD(wParam)==8)
		{	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1001),hDlg,&dlgExitSelect,SELECT_SET_EXIT);
		}
		else if(LOWORD(wParam)==10)
		{	HMENU hMenu1 = getProcessesMenu(1);
			HMENU hMenu3=CreatePopupMenu();
			LangAppendMenu(hMenu1,MF_POPUP,(UINT)hMenu3,LANG_MENU_RELEASE);
			dlgForceTor_menuAppendHookedProcesses(hMenu3);
			RECT r;
			GetWindowRect(GetDlgItem(hDlg,10),&r);
			SetForegroundWindow(hDlg);
			TrackPopupMenu(hMenu1,TPM_LEFTALIGN,r.left,r.bottom,0,hDlg,NULL);
			DestroyMenu(hMenu1);
			DestroyMenu(hMenu3);
		}
		else if(LOWORD(wParam)==9)
		{	if(IsWindowVisible(hDlg)) wParam=1;
			else wParam=0;
			if(wParam) ShowWindow(hDlg,SW_HIDE);
			DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1002),hDlg,&dlgForceTor,0);
			if(wParam) ShowWindow(hDlg,SW_SHOW);
		}
		else if(LOWORD(wParam)==11)
		{	HWND h=GetDlgItem(hDlg,1);
			CheckDlgButton(hDlg,1,BST_CHECKED);PostMessage(hDlg,WM_COMMAND,1,(LPARAM)h);
		}
		else if(LOWORD(wParam)==12)
		{	HWND h=GetDlgItem(hDlg,1);
			CheckDlgButton(hDlg,1,BST_UNCHECKED);PostMessage(hDlg,WM_COMMAND,1,(LPARAM)h);
		}
		else if(LOWORD(wParam)==12402)
			dlgForceTor_interceptNewProcess();
		else if(LOWORD(wParam)==20100 && hDlgDebug)
			SendDlgItemMessage(hDlgDebug,100,WM_COPY,0,0);
		else if(LOWORD(wParam)==20101)
			dlgDebug_logFilterAdd(strban);
		else if(LOWORD(wParam)==20102)
			dlgProxy_banDebugAddress(strban);
		else if(LOWORD(wParam)==20103)
		{	if(strban[0])
			{	i = dlgDebug_find_address(strban);
				if(i != -1)
					dlgTrackedHosts_trackedHostExitAdd(hDlg,&strban[i]);
			}
		}
		else if(LOWORD(wParam)==20104)
		{	if(strban[0])
			{	i = dlgDebug_find_address(strban);
				if(i != -1)
					dlgTrackedHosts_trackedDomainExitAdd(hDlg,&strban[i]);
			}
		}
		else if(LOWORD(wParam)==20105)
		{	if(strban[0])
			{	i = dlgDebug_find_address(strban);
				if(i != -1)
					dlgTrackedHosts_addressMapAdd(hDlg,&strban[i]);
			}
		}
		else if(LOWORD(wParam)==20106)
		{	if(strban[0])
			{	i = dlgDebug_find_address(strban);
				if(i != -1)
					dlgTrackedHosts_addressMapRemove(hDlg,&strban[i]);
			}
		}
		else if(LOWORD(wParam)==20107)	dumpstats(LOG_NOTICE);
		else if(LOWORD(wParam)==20199)
		{	set_router_sel((uint32_t)0x0100007f,1);
			signewnym_impl(get_time(NULL),1);
		}
		else if((LOWORD(wParam)>=20200)&&(LOWORD(wParam)<21000))
		{	uint32_t newSel=get_menu_selection(LOWORD(wParam)-20200);
			if(newSel)
			{	set_router_sel(newSel,1);
				signewnym_impl(get_time(NULL),1);
			}
		}
		else if((LOWORD(wParam)>=22000)&&(LOWORD(wParam)<(22000+MAX_PID_LIST)))
			dlgForceTor_menuRelease(LOWORD(wParam)-22000);
		else if(LOWORD(wParam)==22999)
			dlgForceTor_quickStartClearAll();
		else if((LOWORD(wParam)>=23000)&&(LOWORD(wParam)<24000))
			dlgForceTor_quickStartFromMenu(LOWORD(wParam)-23000);
	}
	else if((uMsg==(WM_USER+10))&&(LOWORD(wParam)==100))
	{	if(dlgUtil_canShow())
		{	if((lParam==WM_LBUTTONUP)||(lParam==WM_LBUTTONDBLCLK))
			{	if(nid.cbSize){	Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;}
				ShowWindow(hDlg,SW_SHOWNORMAL);BringWindowToTop(hDlg);SetForegroundWindow(hDlg);
				if(resize_sel==resize_debug)	LangDebugScroll(hDlgDebug);
			}
			else if(lParam==WM_RBUTTONUP)
			{	HMENU hMenu2=NULL,hMenu3=NULL,hMenu4=getProcessesMenu(1);
				hMenu=CreatePopupMenu();
				LangAppendMenu(hMenu,MF_STRING,7,LANG_MENU_SHOW_WINDOW);
				LangAppendMenu(hMenu,MF_STRING,9,LANG_MENU_FORCE_TOR);
				LangAppendMenu(hMenu,MF_POPUP,(UINT)hMenu4,LANG_MENU_QUICK_START);
				hMenu3=CreatePopupMenu();
				LangAppendMenu(hMenu,MF_POPUP,(UINT)hMenu3,LANG_MENU_RELEASE);
				dlgForceTor_menuAppendHookedProcesses(hMenu3);
				if(started&1)
				{	AppendMenu(hMenu,MF_SEPARATOR,0,0);
					LangAppendMenu(hMenu,MF_STRING,6,LANG_MENU_NEW_IDENTITY);
					hMenu2=CreatePopupMenu();
					add_routers_to_menu(hMenu2);
					AppendMenu(hMenu2,MF_STRING,20199,"-- &No exit");
					AppendMenu(hMenu2,MF_SEPARATOR,0,0);
					AppendMenu(hMenu2,MF_STRING,8,"&Advanced ...");
					LangAppendMenu(hMenu,MF_POPUP,(UINT)hMenu2,LANG_MENU_SELECT_IP);
					AppendMenu(hMenu,MF_SEPARATOR,0,0);
				}
				else LangAppendMenu(hMenu,MF_STRING,11,LANG_MENU_START_TOR);
				if(!is_read_only())	LangAppendMenu(hMenu,MF_STRING,3,LANG_MENU_SAVE_SETTINGS);
				if(started&1)	LangAppendMenu(hMenu,MF_STRING,12,LANG_MNU_STOP_TOR);
				LangAppendMenu(hMenu,MF_STRING,2,LANG_MENU_EXIT);
				GetCursorPos(&point);
				SetForegroundWindow(hDlg);
				TrackPopupMenu(hMenu,TPM_RIGHTALIGN,point.x,point.y,0,hDlg,NULL);
				DestroyMenu(hMenu);
				if(hMenu2) DestroyMenu(hMenu2);
				DestroyMenu(hMenu3);DestroyMenu(hMenu4);
			}
		}
	}
	else if(uMsg==WM_USER+11)
	{	if(IsWindowVisible(hDlg)) wParam=1;
		else wParam=0;
		if(wParam) ShowWindow(hDlg,SW_HIDE);
		DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1002),hDlg,&dlgForceTor,1);
		if(wParam) ShowWindow(hDlg,SW_SHOW);
	}
	else if(uMsg==WM_USER+12)
	{	scrollChildren((HWND)lParam,translateScroll((HWND)lParam,wParam,SB_HORZ),0);
	}
	else if(uMsg==WM_USER+13)
	{	scrollChildren((HWND)lParam,0,translateScroll((HWND)lParam,wParam,SB_VERT));
	}
	else if(uMsg==WM_USER+14)
	{	dlgForceTor_scheduleExec((char*)lParam);
		dlgForceTor_scheduledExec();
	}
	else if(uMsg==WM_SIZE)
	{	if(!IsIconic(hDlg))
		{	if(!(startupOption&STARTUP_OPTION_RESIZE_SETTINGS_APPLIED))
			{	if(tmpOptions->WindowPos || tmpOptions->GuiPlacement3)
				{	int j;
					if(tmpOptions->GuiPlacement3)
						tor_sscanf(tmpOptions->GuiPlacement3,"%u,%u,%u,%u,%u,%u,%u,%u,%u",&isZoomed,(unsigned int *)&desktopRect.right,(unsigned int *)&desktopRect.bottom,(unsigned int *)&lastWindowRect.left,(unsigned int *)&lastWindowRect.top,(unsigned int *)&lastWindowRect.right,(unsigned int *)&lastWindowRect.bottom,&lastSort,&splitX);
					else
					{
						tor_sscanf(tmpOptions->WindowPos,"%u,%u,%u,%u,%u,%u,%u,%u",&isZoomed,(unsigned int *)&desktopRect.right,(unsigned int *)&desktopRect.bottom,(unsigned int *)&lastWindowRect.left,(unsigned int *)&lastWindowRect.top,(unsigned int *)&lastWindowRect.right,(unsigned int *)&lastWindowRect.bottom,&lastSort);
					}
					if(((lastSort&0x80)!=0) && lastSort>0)	lastSort = -(lastSort & 0x7f);
					if(isZoomed)	ShowWindow(hDlg,SW_MAXIMIZE);
					else
					{	i=desktopRect.right;j=desktopRect.bottom;
						GetWindowRect(GetDesktopWindow(),&desktopRect);
						if(i==desktopRect.right && j==desktopRect.bottom)
						{	if(lastWindowRect.left>desktopRect.left && lastWindowRect.right>lastWindowRect.left && lastWindowRect.right<desktopRect.right && lastWindowRect.top>desktopRect.top && lastWindowRect.bottom>lastWindowRect.top && lastWindowRect.bottom<desktopRect.bottom)
								MoveWindow(hDlg,lastWindowRect.left,lastWindowRect.top,lastWindowRect.right-lastWindowRect.left,lastWindowRect.bottom-lastWindowRect.top,1);
						}
					}
					if(splitX != -1)
					{	RECT r;
						GetWindowRect(GetDlgItem(hDlg,201),&r);
						MoveWindow(GetDlgItem(hDlg,201),splitX,0,SPLITTER_WIDTH,r.bottom-r.top,1);
					}
				}
				startupOption |= STARTUP_OPTION_RESIZE_SETTINGS_APPLIED;
			}
			resizeDialogControls(hDlg,resize_main,0,0);
			if(selWnd)	resizeChildDialog(hDlg,selWnd,resize_sel);
			if(resize_sel==resize_network_information) recalcGraph();
			else if(resize_sel==resize_debug)	LangDebugScroll(hDlgDebug);
			RedrawWindow(hDlg,NULL,NULL,RDW_INVALIDATE|RDW_INTERNALPAINT|RDW_UPDATENOW|RDW_ALLCHILDREN|RDW_NOERASE);
			if(startupOption&STARTUP_OPTION_RESIZE_SETTINGS_APPLIED)	saveWindowPos();
		}
	}
	else if(uMsg==WM_MOVE)
	{	if(!IsIconic(hDlg) && (startupOption&STARTUP_OPTION_RESIZE_SETTINGS_APPLIED))	saveWindowPos();
	}
	else if(uMsg==WM_HOTKEY)
	{	HWND h;
		switch(LOWORD(wParam))
		{	case 11700:
				h = GetDlgItem(hDlg,6);
				PostMessage(hDlg,WM_COMMAND,6,(LPARAM)h);
				break;
			case 11701:
				dlgForceTor_interceptFocusedProcess();
				break;
			case 11702:
				dlgForceTor_releaseFocusedProcess();
				break;
			case 11703:
				if(IsWindowVisible(hDlg))
				{	h = GetDlgItem(hDlg,4);
					PostMessage(hDlg,WM_COMMAND,4,(LPARAM)h);
				}
				else
				{	h = GetDlgItem(hDlg,7);
					PostMessage(hDlg,WM_COMMAND,7,(LPARAM)h);
				}
				break;
			case 11704:
				dlgSystem_UnregisterHotKeys();
				dlgSystem_RegisterRestoreHotKey();
				dlgUtil_hideAll();
				break;
			case 11705:
				dlgUtil_restoreAll();
				dlgSystem_UnregisterHotKeys();
				dlgSystem_RegisterHotKeys();
				break;
			default:
				break;
		}
	}
	else if(uMsg==WM_SYSCOMMAND)
	{	if((wParam&0xfff0)==SC_MINIMIZE)
		{	HWND h = GetDlgItem(hDlg,4);
			PostMessage(hDlg,WM_COMMAND,4,(LPARAM)h);
		}
		else if(((wParam&0xfff0)==SC_MINIMIZE)&&(nid.cbSize))
		{	Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;
		}
		else if(((wParam&0xfff0)==SC_CLOSE))
		{	if(canExit(1))
			{	if(!unload_plugins(hDlg)) return 1;
				remove_plugins();
				if(nid.cbSize){ Shell_NotifyIcon(NIM_DELETE,&nid);nid.cbSize=0;}
				dlgForceTor_unhookAll();
				dlgSystem_UnregisterHotKeys();
				releaseGraph();
			}
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	if(wParam==200)
		{	NM_TREEVIEWW *pnmtvw=(NM_TREEVIEWW*)lParam;
			if(pnmtvw->hdr.code==TVN_SELCHANGEDW && pnmtvw->itemNew.hItem)
			{	tvins.item.hItem = pnmtvw->itemNew.hItem;
				tvins.item.lParam = 0;
				tvins.item.mask = TVIF_PARAM;
				SendDlgItemMessage(hDlg,200,TVM_GETITEM,0,(LPARAM)&tvins.item);
				int tmpframe = tvins.item.lParam;
				if(frame==tmpframe) return 0;
				switch(frame)
				{	case DLG_FRAME_PROXY:
						ShowWindow(hDlgProxy,SW_HIDE);
						scrollBack(hDlgProxy);
						break;
					case DLG_FRAME_BANNED_ADDRESSES:
						ShowWindow(hDlgBannedAddresses,SW_HIDE);
						scrollBack(hDlgBannedAddresses);
						break;
					case DLG_FRAME_HTTP_HEADERS:
						ShowWindow(hDlgProxyHTTP,SW_HIDE);
						scrollBack(hDlgProxyHTTP);
						break;
					case DLG_FRAME_ADVANCED_PROXY_SETTINGS:
						ShowWindow(hDlgAdvancedProxy,SW_HIDE);
						scrollBack(hDlgAdvancedProxy);
						break;
					case DLG_FRAME_AUTHORITIES:
						ShowWindow(hDlgAuthorities,SW_HIDE);
						scrollBack(hDlgAuthorities);
						break;
					case DLG_FRAME_ROUTER_RESTRICTIONS:
						ShowWindow(hDlgRouterRestrictions,SW_HIDE);
						scrollBack(hDlgRouterRestrictions);
						break;
					case DLG_FRAME_BANNED_ROUTERS:
						ShowWindow(hDlgRouterBans,SW_HIDE);
						scrollBack(hDlgRouterBans);
						break;
					case DLG_FRAME_FAVORITE_ROUTERS:
						ShowWindow(hDlgRouterFavorites,SW_HIDE);
						scrollBack(hDlgRouterFavorites);
						break;
					case DLG_FRAME_CIRCUIT_BUILD:
						ShowWindow(hDlgCircuitBuild,SW_HIDE);
						scrollBack(hDlgCircuitBuild);
						break;
					case DLG_FRAME_TRACKED_HOSTS:
						ShowWindow(hDlgTrackedHosts,SW_HIDE);
						scrollBack(hDlgTrackedHosts);
						break;
					case DLG_FRAME_CONNECTIONS:
						ShowWindow(hDlgConnections,SW_HIDE);
						scrollBack(hDlgConnections);
						break;
					case DLG_FRAME_BRIDGES:
						ShowWindow(hDlgBridges,SW_HIDE);
						scrollBack(hDlgBridges);
						break;
					case DLG_FRAME_BYPASSBL:
						ShowWindow(hDlgBypassBlacklists,SW_HIDE);
						scrollBack(hDlgBypassBlacklists);
						break;
					case DLG_FRAME_HOSTED_SERVICES:
						ShowWindow(hDlgHostedServices,SW_HIDE);
						scrollBack(hDlgHostedServices);
						break;
					case DLG_FRAME_HIDDEN_SERVICES:
						ShowWindow(hDlgHiddenServices,SW_HIDE);
						scrollBack(hDlgHiddenServices);
						break;
					case DLG_FRAME_PLUGINS:
						ShowWindow(hDlgPlugins,SW_HIDE);
						scrollBack(hDlgPlugins);
						break;
					case DLG_FRAME_PRIVATE_IDENTITY:
						ShowWindow(hDlgIdentity,SW_HIDE);
						scrollBack(hDlgIdentity);
						break;
					case DLG_FRAME_SYSTEM:
						ShowWindow(hDlgSystem,SW_HIDE);
						scrollBack(hDlgSystem);
						break;
					case DLG_FRAME_INTERCEPT:
						ShowWindow(hDlgInterceptHelp,SW_HIDE);
						scrollBack(hDlgInterceptHelp);
						break;
					case DLG_FRAME_QUICK_START:
						ShowWindow(hDlgQuickStart,SW_HIDE);
						scrollBack(hDlgQuickStart);
						break;
					case DLG_FRAME_INTERCEPT_PROCESSES:
						KillTimer(hDlgForceTor,100);
						ShowWindow(hDlgForceTor,SW_HIDE);
						scrollBack(hDlgForceTor);
						break;
					case DLG_FRAME_SANDBOXING:
						ShowWindow(hDlgSandboxing,SW_HIDE);
						scrollBack(hDlgSandboxing);
						break;
					case DLG_FRAME_HOST_ROUTER:
						ShowWindow(hDlgServer,SW_HIDE);
						scrollBack(hDlgServer);
						break;
					case DLG_FRAME_OR_NETWORK:
						KillTimer(hDlgNetInfo,102);
						ShowWindow(hDlgNetInfo,SW_HIDE);
						scrollBack(hDlgNetInfo);
						break;
					case DLG_FRAME_DEBUG:
						ShowWindow(hDlgDebug,SW_HIDE);
						scrollBack(hDlgDebug);
						break;
					case DLG_FRAME_ABOUT:
						ShowWindow(hDlgAbout,SW_HIDE);
						scrollBack(hDlgAbout);
						break;
					default:
						if(frame>=4096)
						{	selWnd=get_plugin_window(frame);
							if(selWnd)
							{	ShowWindow(selWnd,SW_HIDE);
								scrollBack(selWnd);
							}
						}
						break;
				}
				frame=tmpframe;
				switch(frame)
				{	case DLG_FRAME_PROXY:
						if(!hDlgProxy)	hDlgProxy=createChildDialog(hDlg,1100,&dlgProxy);
						selWnd = hDlgProxy;
						resize_sel = resize_proxy;
						break;
					case DLG_FRAME_BANNED_ADDRESSES:
						if(!hDlgBannedAddresses)	hDlgBannedAddresses=createChildDialog(hDlg,1114,&dlgBannedAddresses);
						selWnd = hDlgBannedAddresses;
						resize_sel = resize_banned_addresses;
						break;
					case DLG_FRAME_HTTP_HEADERS:
						if(!hDlgProxyHTTP)	hDlgProxyHTTP=createChildDialog(hDlg,1116,&dlgProxyHTTP);
						selWnd = hDlgProxyHTTP;
						resize_sel = resize_proxy_http;
						break;
					case DLG_FRAME_ADVANCED_PROXY_SETTINGS:
						if(!hDlgAdvancedProxy)	hDlgAdvancedProxy=createChildDialog(hDlg,1115,&dlgAdvancedProxy);
						selWnd = hDlgAdvancedProxy;
						resize_sel = resize_advanced_proxy;
						break;
					case DLG_FRAME_AUTHORITIES:
						if(!hDlgAuthorities)	hDlgAuthorities=createChildDialog(hDlg,1101,&dlgAuthorities);
						selWnd = hDlgAuthorities;
						resize_sel = resize_authorities;
						break;
					case DLG_FRAME_ROUTER_RESTRICTIONS:
						if(!hDlgRouterRestrictions)	hDlgRouterRestrictions=createChildDialog(hDlg,1102,&dlgRouterRestrictions);
						selWnd = hDlgRouterRestrictions;
						resize_sel = resize_router_restrictions;
						break;
					case DLG_FRAME_BANNED_ROUTERS:
						if(!hDlgRouterBans)	hDlgRouterBans=createChildDialog(hDlg,1117,&dlgRouterBans);
						selWnd = hDlgRouterBans;
						resize_sel = resize_router_bans;
						break;
					case DLG_FRAME_FAVORITE_ROUTERS:
						if(!hDlgRouterFavorites)	hDlgRouterFavorites=createChildDialog(hDlg,1118,&dlgRouterFavorites);
						selWnd = hDlgRouterFavorites;
						resize_sel = resize_router_favorites;
						break;
					case DLG_FRAME_CIRCUIT_BUILD:
						if(!hDlgCircuitBuild)	hDlgCircuitBuild=createChildDialog(hDlg,1103,&dlgCircuitBuild);
						selWnd = hDlgCircuitBuild;
						resize_sel = resize_circuit_build;
						break;
					case DLG_FRAME_TRACKED_HOSTS:
						if(!hDlgTrackedHosts)	hDlgTrackedHosts=createChildDialog(hDlg,1119,&dlgTrackedHosts);
						selWnd = hDlgTrackedHosts;
						resize_sel = resize_tracked_hosts;
						break;
					case DLG_FRAME_CONNECTIONS:
						if(!hDlgConnections)	hDlgConnections=createChildDialog(hDlg,1104,&dlgConnections);
						selWnd = hDlgConnections;
						resize_sel = resize_connections;
						break;
					case DLG_FRAME_BRIDGES:
						if(!hDlgBridges)	hDlgBridges=createChildDialog(hDlg,1105,&dlgBridges);
						selWnd = hDlgBridges;
						resize_sel = resize_bridges;
						break;
					case DLG_FRAME_BYPASSBL:
						if(!hDlgBypassBlacklists) hDlgBypassBlacklists = createChildDialog(hDlg,1123,&dlgBypassBlacklists);
						selWnd = hDlgBypassBlacklists;
						resize_sel = resize_bypass_blacklists;
						break;
					case DLG_FRAME_HOSTED_SERVICES:
						if(!hDlgHostedServices)	hDlgHostedServices=createChildDialog(hDlg,1113,&dlgHostedServices);
						selWnd = hDlgHostedServices;
						resize_sel = resize_about;
						break;
					case DLG_FRAME_HIDDEN_SERVICES:
						if(!hDlgHiddenServices)	hDlgHiddenServices=createChildDialog(hDlg,1106,&dlgHiddenServices);
						selWnd = hDlgHiddenServices;
						resize_sel = resize_hs;
						break;
					case DLG_FRAME_PLUGINS:
						if(!hDlgPlugins)	hDlgPlugins=createChildDialog(hDlg,1107,&dlgPlugins);
						selWnd = hDlgPlugins;
						resize_sel = resize_plugins;
						break;
					case DLG_FRAME_SYSTEM:
						if(!hDlgSystem)	hDlgSystem=createChildDialog(hDlg,1108,&dlgSystem);
						selWnd = hDlgSystem;
						resize_sel = resize_system;
						break;
					case DLG_FRAME_PRIVATE_IDENTITY:
						if(!hDlgIdentity)	hDlgIdentity=createChildDialog(hDlg,1120,&dlgIdentity);
						selWnd = hDlgIdentity;
						resize_sel = resize_identity;
						break;
					case DLG_FRAME_INTERCEPT:
						if(!hDlgInterceptHelp)	hDlgInterceptHelp=createChildDialog(hDlg,1113,&dlgInterceptHelp);
						selWnd = hDlgInterceptHelp;
						resize_sel = resize_about;
						break;
					case DLG_FRAME_QUICK_START:
						if(!hDlgQuickStart)	hDlgQuickStart=createChildDialog(hDlg,1121,&dlgQuickStart);
						selWnd = hDlgQuickStart;
						resize_sel = resize_quick_start;
						break;
					case DLG_FRAME_INTERCEPT_PROCESSES:
						if(!hDlgForceTor)	hDlgForceTor=createChildDialog(hDlg,1109,&dlgInterceptProcesses);
						selWnd = hDlgForceTor;
						resize_sel = resize_force_tor;
						SetTimer(hDlgForceTor,100,1000,0);
						break;
					case DLG_FRAME_SANDBOXING:
						if(!hDlgSandboxing)	hDlgSandboxing=createChildDialog(hDlg,1122,&dlgSandboxing);
						selWnd = hDlgSandboxing;
						resize_sel = resize_sandboxing;
						break;
					case DLG_FRAME_HOST_ROUTER:
						if(!hDlgServer)	hDlgServer=createChildDialog(hDlg,1110,&dlgServer);
						selWnd = hDlgServer;
						resize_sel = resize_server;
						break;
					case DLG_FRAME_OR_NETWORK:
						if(!hDlgNetInfo)	hDlgNetInfo=createChildDialog(hDlg,1111,&dlgNetInfo);
						selWnd = hDlgNetInfo;
						resize_sel = resize_network_information;
						SetTimer(hDlgNetInfo,102,1000,0);
						break;
					case DLG_FRAME_DEBUG:
						if(!hDlgDebug)	hDlgDebug=createChildDialog(hDlg,1112,&dlgDebug);
						selWnd = hDlgDebug;
						resize_sel = resize_debug;
						break;
					case DLG_FRAME_ABOUT:
						if(!hDlgAbout)	hDlgAbout=createChildDialog(hDlg,1113,&dlgAbout);
						selWnd = hDlgAbout;
						resize_sel = resize_about;
						break;
					default:
						if(frame>=4096)
						{	selWnd = get_plugin_window(frame);
							resize_plugin[0].refWidthControl=frame;
							resize_sel = resize_plugin;
						}
						else
						{	selWnd = 0;
							resize_sel = 0;
						}
						break;
				}
				if(selWnd)
				{	resizeChildDialog(hDlg,selWnd,resize_sel);
					if(resize_sel==resize_network_information) recalcGraph();
					ShowWindow(selWnd,SW_SHOW);
					if(resize_sel==resize_debug)	LangDebugScroll(hDlgDebug);
					RedrawWindow(hDlg,NULL,NULL,RDW_INVALIDATE|RDW_INTERNALPAINT|RDW_UPDATENOW|RDW_ALLCHILDREN|RDW_NOERASE);
				}
			}
		}
	}
	return 0;
}
