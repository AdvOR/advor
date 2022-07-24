#include "or.h"
#include "dlg_util.h"
#include "geoip.h"
#include "main.h"
#include "routerlist.h"

HWND hDlgBypassBlacklists=NULL;
extern or_options_t *tmpOptions;

lang_dlg_info lang_dlg_bypass_blacklists[]={
	{50,LANG_DLG_BYPASSBL_RECENT_EXITS},
	{10,LANG_DLG_BYPASSBL_RECENT_EXITS_HINT},
	{11,LANG_DLG_BYPASSBL_MAX_UPTIME},
	{12,LANG_DLG_BYPASSBL_MAX_BLACKLISTED_TIME},
	{13,LANG_DLG_BYPASSBL_MAX_BLACKLISTED_TIME_UNIT},
	{400,LANG_DLG_BYPASSBL_SAVE_NODE_STATS},
	{401,LANG_DLG_BYPASSBL_EXCLUDE_GEOIP_BANS},
	{51,LANG_DLG_BYPASSBL_RESERVED},
	{14,LANG_DLG_BYPASSBL_RESERVED_HINT},
	{0,0}
};

#define IP_FLAG_IPV6 1
#define IP_FLAG_EXIT_NODE 2
#define IP_FLAG_PROXY_SOCKS4 4
#define IP_FLAG_PROXY_SOCKS5 8
#define IP_FLAG_PROXY_HTTP 16

#pragma pack(push,1)
typedef struct ip_info_t
{	struct ip_info_t *next;
	int flags;
	uint32_t addr[4];
	time_t added;
	time_t last_seen;
} ip_info_t;
#define IPLIST_SIZE sizeof(ip_info_t) - sizeof(int)
#pragma pack(pop)

int __stdcall dlgBypassBlacklists(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int dlgBypassBlacklists_isRecent(uint32_t addr,routerinfo_t *router,time_t now);

ip_info_t *exitlist = NULL;

#define DAY_IN_SECONDS 24*60*60

void iplist_free(void)
{	ip_info_t *tmp;
	while(exitlist)
	{	tmp = exitlist->next;
		tor_free(exitlist);
		exitlist = tmp;
	}
}

void iplist_write(void)
{	char *fname = get_datadir_fname(DATADIR_IPLIST);
	if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_SAVE_STATS)
	{	HANDLE hFile = open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
		if(hFile!=INVALID_HANDLE_VALUE)
		{	ip_info_t *list;
			time_t old = get_time(NULL) - (tmpOptions->ExitMaxSeen * DAY_IN_SECONDS);
			DWORD written;
			list = exitlist;
			while(list)
			{	if(old < list->last_seen)
					WriteFile(hFile,&list->flags,IPLIST_SIZE,&written,NULL);
				list = list->next;
			}
			CloseHandle(hFile);
		}
	}
	else	delete_file(fname);
	tor_free(fname);
}

void iplist_init(void)
{	if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_SAVE_STATS)
	{	char *fname = get_datadir_fname(DATADIR_IPLIST);
		HANDLE hFile = open_file(fname,GENERIC_READ,OPEN_EXISTING);
		if(hFile!=INVALID_HANDLE_VALUE)
		{	ip_info_t *list = NULL;
			time_t old = get_time(NULL) - (tmpOptions->ExitMaxSeen * DAY_IN_SECONDS);
			DWORD read=1;
			while(read)
			{	if(!list)
					list = tor_malloc_zero(sizeof(ip_info_t));
				read = 0;
				ReadFile(hFile,&list->flags,IPLIST_SIZE,&read,NULL);
				if(read && old < list->last_seen)
				{	list->next = exitlist;
					exitlist = list;
					list = NULL;
				}
			}
			if(list)
				tor_free(list);
			CloseHandle(hFile);
		}
		tor_free(fname);
	}
}


int __stdcall dlgBypassBlacklists(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgBypassBlacklists=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_bypass_blacklists);
		}
		SetDlgItemInt(hDlg,100,tmpOptions->ExitMaxUptime,0);
		SetDlgItemInt(hDlg,101,tmpOptions->ExitMaxSeen,0);
		if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_SAVE_STATS)	CheckDlgButton(hDlg,400,BST_CHECKED);
		if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_EXCLUDE_GEOIP_BANS)	CheckDlgButton(hDlg,401,BST_CHECKED);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==400)
		{	if(IsDlgButtonChecked(hDlg,400)==BST_CHECKED)
			{	tmpOptions->ExitSeenFlags |= EXIT_SEEN_FLAG_SAVE_STATS;
				routerlist_refresh_iplist();
			}
			else
			{	tmpOptions->ExitSeenFlags &= EXIT_SEEN_FLAG_SAVE_STATS ^ 0xffff;
				iplist_free();
			}
		}
		else if(LOWORD(wParam)==401)
		{	if(IsDlgButtonChecked(hDlg,401)==BST_CHECKED)
				tmpOptions->ExitSeenFlags |= EXIT_SEEN_FLAG_EXCLUDE_GEOIP_BANS;
			else	tmpOptions->ExitSeenFlags &= EXIT_SEEN_FLAG_EXCLUDE_GEOIP_BANS ^ 0xffff;
		}
		else if((LOWORD(wParam)==100)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->ExitMaxUptime=GetDlgItemInt(hDlg,100,0,0);
		else if((LOWORD(wParam)==101)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->ExitMaxSeen=GetDlgItemInt(hDlg,101,0,0);
	}
	return 0;
}

time_t dlgBypassBlacklists_getLongevity(routerinfo_t *router)
{	time_t rstart,now;
	now = get_time(NULL);
	if(!router) return now;
	rstart = now - router->uptime;
	if((tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_SAVE_STATS))// && (router->is_exit))
	{	ip_info_t *list;
		uint32_t raddr=geoip_reverse(router->addr);
		list = exitlist;
		while(list)
		{	if((raddr == list->addr[0]) && (list->flags&IP_FLAG_EXIT_NODE) != 0)
			{	if(rstart < list->added)
					list->added = rstart;
				else	rstart = list->added;
				list->last_seen = now;
				break;
			}
			list = list->next;
		}
		if(!list)
		{	list = tor_malloc_zero(sizeof(ip_info_t));
			list->next = exitlist;
			list->addr[0] = raddr;
			list->added = rstart;
			list->last_seen = now;
			list->flags = IP_FLAG_EXIT_NODE;
			exitlist = list;
		}
	}
	return rstart;
}

int dlgBypassBlacklists_isRecent(uint32_t addr,routerinfo_t *router,time_t now)
{	time_t delta = now - router->estimated_start;
	if(delta > tmpOptions->ExitMaxUptime)	return 0;
	if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_EXCLUDE_GEOIP_BANS)
	{	if(geoip_get_country_by_ip(addr) > 0xff)
			return 0;
	}
	return 1;
}
