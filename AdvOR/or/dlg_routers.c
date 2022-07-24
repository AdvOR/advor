#include "or.h"
#include "dlg_util.h"
#include "geoip.h"
#include "routerlist.h"
#include "main.h"

#define MAX_ROUTERSELECT_RETRIES 5000

NMLISTVIEW *nmLV;
LV_ITEM lvit;
HWND hListView=NULL;

extern or_options_t *tmpOptions;
extern int selectedVer;
const char *bannedBW="--------";
const char *nostr="\0";
const char *maxstr="\xff\xff\xff\xff\xff\xff\xff\xff";

int lastSort=0,lastSel=0;
uint32_t lastRouter=0;

lang_dlg_info lang_dlg_exit[]={
	{10,LANG_EXIT_DLG_COUNTRY},
	{401,LANG_EXIT_DLG_CLOSE_CONN},
	{402,LANG_EXIT_DLG_EXPIRE_HOSTS},
	{403,LANG_EXIT_DLG_CONSECUTIVE_EXITS},
	{404,LANG_EXIT_DLG_RECENT_EXITS},
	{1,LANG_EXIT_DLG_SELECT},
	{3,LANG_EXIT_DLG_ADD_FAV},
	{4,LANG_EXIT_DLG_SET_BAN},
	{2,LANG_EXIT_DLG_CANCEL},
	{0,0}
};

lang_dlg_info lang_dlg_routers[]={
	{10,LANG_EXIT_DLG_COUNTRY},
	{1,LANG_EXIT_DLG_SELECT},
	{3,LANG_EXIT_DLG_ADD_FAV},
	{4,LANG_EXIT_DLG_SET_BAN},
	{2,LANG_EXIT_DLG_CANCEL},
	{0,0}
};

void signewnym_impl(time_t now,int msgshow);
void add_router_to_favorites(HWND hDlg,char *router,char favtype);
void add_router_to_banlist(HWND hDlg,char *router,char bantype);
void setLastSort(int newSort);
void sort_all_items(void);
void dlgIdentity_updateFlags(void);
int dlgBypassBlacklists_isRecent(uint32_t addr,routerinfo_t *router,time_t now);
int CALLBACK CompareFunc1(LPARAM lParam1,LPARAM lParam2,LPARAM lParamSort);
int __stdcall dlgExitSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void next_router_from_sorted_exits(void);


int CALLBACK CompareFunc1(LPARAM lParam1,LPARAM lParam2,LPARAM lParamSort)
{	(void) lParamSort;
	if(lParam1==0)	return -1;
	else if(lParam2==0) return 1;
	else if(lParam1<0)
	{	if(lParam2>=0) return 1;
		lParam1 = 0-lParam1;lParam2 = 0-lParam2;
	}
	else if(lParam2<0)	return -1;
	routerinfo_t *r1,*r2;
	int result=0;
	r1=get_router(lParam1);
	r2=get_router(lParam2);
	if(!r1) r1=r2;
	if(!r2) r2=r1;
	if(!r1) return 0;
	if((lastSort==2)||(lastSort==-2)||(lastSort==4)||(lastSort==-4))
	{	if(lastSort==2)
		{	if((r1->addr>>16) == (r2->addr>>16)) result = (r1->addr&0xffff) - (r2->addr&0xffff);
			else result = (r1->addr>>16&0xffff) - (r2->addr>>16&0xffff);
		}
		else if(lastSort==-2)
		{	if((r1->addr>>16) == (r2->addr>>16)) result = (r2->addr&0xffff) - (r1->addr&0xffff);
			else result = (r2->addr>>16&0xffff) - (r1->addr>>16&0xffff);
		}
		else if(lastSort==4) result = r1->bandwidthcapacity - r2->bandwidthcapacity;
		else result = r2->bandwidthcapacity - r1->bandwidthcapacity;
	}
	else if((lastSort==1) || (lastSort==-1))
	{	if(lastSort==1) result = strcmp(geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(r1->addr))&0xff),geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(r2->addr))&0xff));
		else result = strcmp(geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(r2->addr))&0xff),geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(r1->addr))&0xff));
	}
	else if((lastSort==3) || (lastSort==-3))
	{	if(lastSort==3) result = stricmp(r1->nickname,r2->nickname);
		else result = stricmp(r2->nickname,r1->nickname);
	}
	else if((lastSort==5) || (lastSort==-5))
	{	if(lastSort==5) result = (r1->is_exit?2:0)+(r1->is_possible_guard?1:0)-(r2->is_exit?2:0)-(r2->is_possible_guard?1:0);
		else result = (r2->is_exit?2:0)+(r2->is_possible_guard?1:0)-(r1->is_exit?2:0)-(r1->is_possible_guard?1:0);
	}
	if(!result)
	{	if(lastSort>0)	result = r1->router_id - r2->router_id;
		else result = r2->router_id - r1->router_id;
	}
	return result;
}

void sort_all_items(void)
{	if(lastSort)	SendMessage(hListView,LVM_SORTITEMS,lastSort,(LPARAM)(PFNLVCOMPARE)CompareFunc1);
	lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if(lvit.iItem!=-1)
	{	RECT rcItem;
		rcItem.left=0;
		SendMessage(hListView,LVM_GETITEMRECT,lvit.iItem,(LPARAM)&rcItem);
		lvit.lParam=SendMessage(hListView,LVM_GETCOUNTPERPAGE,0,0)/2;
		if(lvit.iItem<lvit.lParam) lvit.lParam=lvit.iItem;
		SendMessage(hListView,LVM_SCROLL,0,(lvit.iItem-lvit.lParam-SendMessage(hListView,LVM_GETTOPINDEX,0,0))*(rcItem.bottom-rcItem.top));
		SendMessage(hListView,LVM_ENSUREVISIBLE,lvit.iItem,0);
	}
}

int last_country_sel;
int __stdcall dlgExitSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_INITDIALOG)
	{	int	cIndex,cbErr;
		const char *fullname;
		last_country_sel=get_country_sel();
		if(LangGetLanguage())
		{	SetWindowTextL(hDlg,LANG_EXIT_DLG_TITLE);
			changeDialogStrings(hDlg,lang_dlg_exit);
		}
		cbErr=LangCbAddString(hDlg,300,LANG_CB_RANDOM_COUNTRY);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,0x200);
		cbErr=LangCbAddString(hDlg,300,LANG_CB_NO_EXIT);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,0x1ff);
		if(last_country_sel==0x200) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,0,0);
		else if(last_country_sel==0x1ff) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,1,0);
		fullname = GeoIP_getfullname(0);
		cbErr=SendDlgItemMessage(hDlg,300,CB_ADDSTRING,0,(LPARAM)fullname);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,(LPARAM)0);
		if(last_country_sel==0) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,cbErr,0);
		for(cIndex=2;cIndex<geoip_get_n_countries();cIndex++)
		{	fullname = GeoIP_getfullname(cIndex);
			cbErr=SendDlgItemMessage(hDlg,300,CB_ADDSTRING,0,(LPARAM)fullname);
			if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,(LPARAM)cIndex);
			if(cIndex==last_country_sel) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,cbErr,0);
		}
		SendDlgItemMessage(hDlg,400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT);
		LangInsertColumn(hDlg,400,50,LANG_COLUMN_EXIT_1,0,LVCFMT_LEFT);
		LangInsertColumn(hDlg,400,150,LANG_COLUMN_EXIT_2,1,LVCFMT_LEFT);
		LangInsertColumn(hDlg,400,165,LANG_COLUMN_EXIT_3,2,LVCFMT_LEFT);
		LangInsertColumn(hDlg,400,70,LANG_COLUMN_EXIT_4,3,LVCFMT_RIGHT);
		hListView=GetDlgItem(hDlg,400);
		routerlist_reindex();
		add_all_routers_to_list(hDlg,SELECT_EXIT,last_country_sel);
		if(tmpOptions->IdentityFlags&IDENTITY_FLAG_DESTROY_CIRCUITS)	CheckDlgButton(hDlg,401,BST_CHECKED);
		if(tmpOptions->IdentityFlags&IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS)	CheckDlgButton(hDlg,402,BST_CHECKED);
		if(tmpOptions->IdentityFlags&IDENTITY_FLAG_LIST_SELECTION)	CheckDlgButton(hDlg,403,BST_CHECKED);
		if(tmpOptions->ExitSeenFlags&EXIT_SEEN_FLAG_ENABLED)	CheckDlgButton(hDlg,404,BST_CHECKED);
		sort_all_items();
		SetFocus(hListView);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==2)
		{	EndDialog(hDlg,0);
		}
		else if(LOWORD(wParam)==1)
		{	lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=0;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam==0 && last_country_sel!=0x1ff)
			{	set_country_sel(last_country_sel,1);
				if(tmpOptions->IdentityFlags&IDENTITY_FLAG_LIST_SELECTION)
				{	routerinfo_t *router = get_router_by_index(get_random_router_index(SELECT_EXIT,last_country_sel));
					if(router)
					{	set_router_id_sel(router->router_id,1);
						lastRouter=router->router_id;
					}
				}
			}
			else if(lvit.lParam<0)
			{	set_country_sel(last_country_sel,0);
				return -1;
			}
			else if(lvit.lParam==1 || last_country_sel==0x1ff)
			{	set_router_sel(0x0100007f,1);
				set_country_sel(0x1ff,0);
				set_router_id_sel(0,0);
				last_country_sel = 0x1ff;
			}
			else if(lvit.lParam>0)
			{	set_country_sel(last_country_sel,0);
				routerinfo_t *router=get_router_by_index(lvit.lParam);
				if(router)
				{	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_LIST_SELECTION)	set_router_id_sel(router->router_id,1);
					else	set_router_sel(router->addr,1);
					lastRouter=router->router_id;
				}
				else return 0;
			}
			showLastExit(NULL,0);
			signewnym_impl(get_time(NULL),0);
		//	if(last_country_sel!=0x1ff)	showLastExit(NULL,-1);
			EndDialog(hDlg,1);
		}
		else if(LOWORD(wParam)==3)
		{	char *favtmp1=NULL;
			lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam>=0) favtmp1=find_router_by_index(lvit.lParam);
			if(lvit.lParam>=0 && favtmp1==NULL)
			{	lvit.lParam=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
				if(lvit.lParam!=0x200)
				{
					favtmp1=tor_malloc(10);
					tor_snprintf(favtmp1,10,"{%s}",geoip_get_country_name(lvit.lParam));
				}
			}
			if(favtmp1)
			{	add_router_to_favorites(hDlg,favtmp1,'X');
				tor_free(favtmp1);
			}
		}
		else if(LOWORD(wParam)==4)
		{	char *bantmp1=NULL,cBan=0;
			lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam>=0) bantmp1=find_router_by_index(lvit.lParam);
			if(lvit.lParam>=0 && bantmp1==NULL)
			{	lvit.lParam=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
				if(lvit.lParam!=0x200)
				{	cBan++;
					bantmp1=tor_malloc(10);
					tor_snprintf(bantmp1,10,"{%s}",geoip_get_country_name(lvit.lParam));
				}
			}
			if(bantmp1)
			{	add_router_to_banlist(hDlg,bantmp1,'X');
				if(cBan)
				{	SendMessage(hListView,LVM_DELETEALLITEMS,0,0);
					add_all_routers_to_list(hDlg,SELECT_EXIT,last_country_sel);
				}
				else
				{	lvit.pszText=(char *)bannedBW;
					lvit.cchTextMax=10;
					lvit.mask=LVIF_TEXT;
					lvit.iSubItem=3;
					SendMessage(hListView,LVM_SETITEM,0,(LPARAM)&lvit);
					lvit.mask=LVIF_PARAM;
					lvit.lParam=0-lvit.lParam;
					lvit.iSubItem=0;
					SendMessage(hListView,LVM_SETITEM,0,(LPARAM)&lvit);
				}
				sort_all_items();
				tor_free(bantmp1);
				EnableWindow(GetDlgItem(hDlg,1),0);EnableWindow(GetDlgItem(hDlg,3),0);EnableWindow(GetDlgItem(hDlg,4),0);
			}
		}
		else if((LOWORD(wParam)==300)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	int cbErr;
			cbErr=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
			if(cbErr!=CB_ERR)
			{	last_country_sel=cbErr;
				SendMessage(hListView,LVM_DELETEALLITEMS,0,0);
				add_all_routers_to_list(hDlg,SELECT_EXIT,last_country_sel);
				sort_all_items();
			}
		}
		else if(LOWORD(wParam)==401)
		{	if(IsDlgButtonChecked(hDlg,401)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_DESTROY_CIRCUITS;
			else	tmpOptions->IdentityFlags &= IDENTITY_FLAGS_ALL^IDENTITY_FLAG_DESTROY_CIRCUITS;
			dlgIdentity_updateFlags();
		}
		else if(LOWORD(wParam)==402)
		{	if(IsDlgButtonChecked(hDlg,402)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS;
			else	tmpOptions->IdentityFlags &= IDENTITY_FLAGS_ALL^IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS;
			dlgIdentity_updateFlags();
		}
		else if(LOWORD(wParam)==403)
		{	if(IsDlgButtonChecked(hDlg,403)==BST_CHECKED)	tmpOptions->IdentityFlags |= IDENTITY_FLAG_LIST_SELECTION;
			else	tmpOptions->IdentityFlags &= IDENTITY_FLAGS_ALL^IDENTITY_FLAG_LIST_SELECTION;
		}
		else if(LOWORD(wParam)==404)
		{	if(IsDlgButtonChecked(hDlg,404)==BST_CHECKED)	tmpOptions->ExitSeenFlags |= EXIT_SEEN_FLAG_ENABLED;
			else	tmpOptions->ExitSeenFlags &= 0xffff^EXIT_SEEN_FLAG_ENABLED;
			SendMessage(hListView,LVM_DELETEALLITEMS,0,0);
			add_all_routers_to_list(hDlg,SELECT_EXIT,last_country_sel);
			sort_all_items();
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	nmLV=(LPNMLISTVIEW)lParam;
		if(nmLV->hdr.code==LVN_COLUMNCLICK)
		{	if(((nmLV->iSubItem+1)==lastSort)||((nmLV->iSubItem+1)==-lastSort))	setLastSort(-lastSort);
			else	setLastSort(nmLV->iSubItem+1);
			sort_all_items();SetFocus(hListView);
		}
		else if((nmLV->hdr.code==LVN_ITEMCHANGED) && ((nmLV->uChanged&LVIF_STATE)!=0) && (nmLV->iItem!=-1) && (((nmLV->uNewState ^ nmLV->uOldState)&LVIS_SELECTED)!=0) && ((nmLV->uNewState & LVIS_SELECTED) != 0))
		{	lvit.iItem=nmLV->iItem;
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam<0)
			{	EnableWindow(GetDlgItem(hDlg,1),0);
				EnableWindow(GetDlgItem(hDlg,3),0);
				EnableWindow(GetDlgItem(hDlg,4),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,1),1);
				EnableWindow(GetDlgItem(hDlg,3),1);
				EnableWindow(GetDlgItem(hDlg,4),1);
			}
		}
	}
	return	0;
}

int __stdcall dlgRouterSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	if(uMsg==WM_INITDIALOG)
	{	int	cIndex,cbErr,cbSel=get_country_sel();
		const char *fullname;
		if(LangGetLanguage())
		{	SetWindowTextL(hDlg,LANG_EXIT_DLG_TITLE);
			changeDialogStrings(hDlg,lang_dlg_routers);
		}
		lastSel=lParam;
		last_country_sel=(lastSel==SELECT_EXIT)?cbSel:0x200;
		cbErr=LangCbAddString(hDlg,300,LANG_CB_RANDOM_COUNTRY);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,0x200);
		if(cbSel==0x200 || lastSel!=SELECT_EXIT)	SendDlgItemMessage(hDlg,300,CB_SETCURSEL,0,0);
		cbErr=LangCbAddString(hDlg,300,LANG_CB_NO_EXIT);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,0x1ff);
		fullname = GeoIP_getfullname(0);
		cbErr=SendDlgItemMessage(hDlg,300,CB_ADDSTRING,0,(LPARAM)fullname);
		if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,(LPARAM)0);
		if(cbSel==0) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,cbErr,0);
		for(cIndex=2;cIndex<geoip_get_n_countries();cIndex++)
		{	fullname = GeoIP_getfullname(cIndex);
			cbErr=SendDlgItemMessage(hDlg,300,CB_ADDSTRING,0,(LPARAM)fullname);
			if(cbErr!=CB_ERR) SendDlgItemMessage(hDlg,300,CB_SETITEMDATA,cbErr,(LPARAM)cIndex);
			if(cIndex==cbSel) SendDlgItemMessage(hDlg,300,CB_SETCURSEL,cbErr,0);
		}
		SendDlgItemMessage(hDlg,400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT);
		if(lParam==SELECT_ANY)
		{	LangInsertColumn(hDlg,400,50,LANG_COLUMN_EXIT_1,0,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,130,LANG_COLUMN_EXIT_2,1,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,155,LANG_COLUMN_EXIT_3,2,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,70,LANG_COLUMN_EXIT_4,3,LVCFMT_RIGHT);
			LangInsertColumn(hDlg,400,30,LANG_COLUMN_EXIT_5,4,LVCFMT_LEFT);
		}
		else
		{	LangInsertColumn(hDlg,400,50,LANG_COLUMN_EXIT_1,0,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,150,LANG_COLUMN_EXIT_2,1,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,165,LANG_COLUMN_EXIT_3,2,LVCFMT_LEFT);
			LangInsertColumn(hDlg,400,70,LANG_COLUMN_EXIT_4,3,LVCFMT_RIGHT);
		}
		hListView=GetDlgItem(hDlg,400);
		routerlist_reindex();
		add_all_routers_to_list(hDlg,lastSel,last_country_sel);
		sort_all_items();SetFocus(hListView);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==2)
			EndDialog(hDlg,-1);
		else if(LOWORD(wParam)==1)
		{	lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam==0)
			{	lvit.lParam=get_random_router_index(lastSel,last_country_sel);
			}
			if(lvit.lParam>=0)	EndDialog(hDlg,lvit.lParam);
		}
		else if(LOWORD(wParam)==3)
		{	char *favtmp1=NULL;
			lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam>=0) favtmp1=find_router_by_index(lvit.lParam);
			if(lvit.lParam>=0 && favtmp1==NULL)
			{	lvit.lParam=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
				if(lvit.lParam!=0x200)
				{
					favtmp1=tor_malloc(10);
					tor_snprintf(favtmp1,10,"{%s}",geoip_get_country_name(lvit.lParam));
				}
			}
			if(favtmp1)
			{	add_router_to_favorites(hDlg,favtmp1,(lastSel==SELECT_EXIT)?'X':((lastSel==SELECT_ENTRY)?'E':'X'));
				tor_free(favtmp1);
			}
		}
		else if(LOWORD(wParam)==4)
		{	char *bantmp1=NULL,cBan=0;
			lvit.iItem=SendMessage(hListView,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam>=0) bantmp1=find_router_by_index(lvit.lParam);
			if(lvit.lParam>=0 && bantmp1==NULL)
			{	lvit.lParam=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
				if(lvit.lParam!=0x200)
				{	cBan++;
					bantmp1=tor_malloc(10);
					tor_snprintf(bantmp1,10,"{%s}",geoip_get_country_name(lvit.lParam));
				}
			}
			if(bantmp1)
			{	add_router_to_banlist(hDlg,bantmp1,(lastSel==SELECT_EXIT)?'X':0);
				if(cBan)
				{	SendMessage(hListView,LVM_DELETEALLITEMS,0,0);
					add_all_routers_to_list(hDlg,lastSel,last_country_sel);
				}
				else
				{	lvit.pszText=(char *)bannedBW;
					lvit.cchTextMax=10;
					lvit.mask=LVIF_TEXT;
					lvit.iSubItem=3;
					SendMessage(hListView,LVM_SETITEM,0,(LPARAM)&lvit);
					lvit.mask=LVIF_PARAM;
					lvit.lParam=0-lvit.lParam;
					lvit.iSubItem=0;
					SendMessage(hListView,LVM_SETITEM,0,(LPARAM)&lvit);
				}
				sort_all_items();
				tor_free(bantmp1);
				EnableWindow(GetDlgItem(hDlg,1),0);EnableWindow(GetDlgItem(hDlg,3),0);EnableWindow(GetDlgItem(hDlg,4),0);
			}
		}
		else if((LOWORD(wParam)==300)&&(HIWORD(wParam)==CBN_SELCHANGE))
		{	int cbErr;
			cbErr=SendDlgItemMessage(hDlg,300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,300,CB_GETCURSEL,0,0),0);
			if(cbErr!=CB_ERR) last_country_sel=cbErr;
			SendMessage(hListView,LVM_DELETEALLITEMS,0,0);
			add_all_routers_to_list(hDlg,lastSel,last_country_sel);
			sort_all_items();
		}
	}
	else if(uMsg==WM_NOTIFY)
	{	nmLV=(LPNMLISTVIEW)lParam;
		if(nmLV->hdr.code==LVN_COLUMNCLICK)
		{	if(((nmLV->iSubItem+1)==lastSort)||((nmLV->iSubItem+1)==-lastSort))	setLastSort(-lastSort);
			else	setLastSort(nmLV->iSubItem+1);
			sort_all_items();SetFocus(hListView);
		}
		else if((nmLV->hdr.code==LVN_ITEMCHANGED) && ((nmLV->uChanged&LVIF_STATE)!=0) && (nmLV->iItem!=-1) && (((nmLV->uNewState ^ nmLV->uOldState)&LVIS_SELECTED)!=0) && ((nmLV->uNewState & LVIS_SELECTED) != 0))
		{	lvit.iItem=nmLV->iItem;
			lvit.mask=LVIF_PARAM;
			lvit.iSubItem=0;
			lvit.lParam=-1;
			SendMessage(hListView,LVM_GETITEM,0,(LPARAM)&lvit);
			if(lvit.lParam<0)
			{	EnableWindow(GetDlgItem(hDlg,1),0);
				EnableWindow(GetDlgItem(hDlg,3),0);
				EnableWindow(GetDlgItem(hDlg,4),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,1),1);
				EnableWindow(GetDlgItem(hDlg,3),1);
				EnableWindow(GetDlgItem(hDlg,4),1);
			}
		}
	}
	return	0;
}

void next_router_from_sorted_exits(void)
{	routerlist_t *rl;
	int retries = 0;
	routerinfo_t *prev,*prev2;
	smartlist_t *sl;
	time_t now = get_time(NULL);;
	unsigned int i,min,min2;
	int r;
	unsigned long l,minl;
	char *rstr,*minstr;
	lastRouter = get_router_id_sel();
	prev = get_router_by_index(lastRouter);
	if(!prev)
	{	if(get_router_sel())	prev = get_router_by_ip(get_router_sel());
		else	prev = get_router_by_index(get_random_router_index(SELECT_EXIT,get_country_sel()));
	}
	if(prev) lastRouter = prev->router_id;
	while(1)
	{	rl = router_get_routerlist();
		if(!rl) return;
		sl = rl->routers;
		int csel=get_country_sel();
		prev2 = prev = get_router_by_index(lastRouter);
		i=0;min=0;min2=0;
		if(prev) i = prev->router_id;
		min = i;
		switch(lastSort)
		{	case 0:
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	if(((router->router_id <=min) || (i==min)) && router->router_id > i)
						{	prev = router;
							min = router->router_id;
						}
					}
				});
				break;
			case 1:		//country,asc
				if(prev) rstr = (char*)geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(prev->addr))&0xff);
				else rstr = (char*)geoip_get_country_name(0);
				minstr = rstr;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	r = strcmp(rstr,geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff));
						if(r==0)
						{	if(((router->router_id <=min) || (i==min)) && router->router_id > i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(r<0)
						{	if((strcmp(geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff),minstr) <= 0) || !strcmp(minstr,rstr))
							{	prev2 = router;
								minstr=(char*)geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff);
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case -1:	//country,desc
				if(prev) rstr = (char*)geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(prev->addr))&0xff);
				else rstr = (char *)maxstr;
				minstr = rstr;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	r = strcmp(rstr,geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff));
						if(r==0)
						{	if(((router->router_id >=min) || (i==min)) && router->router_id < i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(r>0)
						{	if((strcmp(geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff),minstr) >= 0) || !strcmp(minstr,rstr))
							{	prev2 = router;
								minstr=(char*)geoip_get_country_name(geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff);
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case 2:		//IP,asc
				if(prev) l = prev->addr;
				else l = 0;
				minl = l;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	if(l==router->addr)
						{	if(((router->router_id <=min) || (i==min)) && router->router_id > i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(l < (unsigned long)router->addr)
						{	if(((unsigned long)router->addr <= minl) || (l==minl))
							{	prev2 = router;
								minl = router->addr;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case -2:	//IP,desc
				if(prev) l = prev->addr;
				else l = 0xffffffff;
				minl = l;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	if(l==router->addr)
						{	if(((router->router_id >=min) || (i==min)) && router->router_id < i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(l > (unsigned long)router->addr)
						{	if(((unsigned long)router->addr >= minl) || (l==minl))
							{	prev2 = router;
								minl = router->addr;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case 3:		//nickname,asc
				if(prev) rstr = prev->nickname;
				else rstr = (char *)nostr;
				minstr = rstr;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	r = strcasecmp(rstr,router->nickname);
						if(r==0)
						{	if(((router->router_id <=min) || (i==min)) && router->router_id > i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(r<0)
						{	if((strcasecmp(router->nickname,minstr) <= 0) || !strcasecmp(rstr,minstr))
							{	prev2 = router;
								minstr=router->nickname;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case -3:	//nickname,desc
				if(prev) rstr = prev->nickname;
				else rstr = (char *)maxstr;
				minstr = rstr;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	r = strcasecmp(rstr,router->nickname);
						if(r==0)
						{	if(((router->router_id >=min) || (i==min)) && router->router_id < i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(r>0)
						{	if((strcasecmp(router->nickname,minstr) >= 0) || !strcasecmp(rstr,minstr))
							{	prev2 = router;
								minstr=router->nickname;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case 4:		//bandwidth,asc
				if(prev) l = prev->bandwidthcapacity;
				else l = 0;
				minl = l;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	if(l==router->bandwidthcapacity)
						{	if(((router->router_id <=min) || (i==min)) && router->router_id > i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(l<router->bandwidthcapacity)
						{	if((router->bandwidthcapacity <= minl) || (l==minl))
							{	prev2 = router;
								minl = router->bandwidthcapacity;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			case -4:	//bandwidth,desc
				if(prev) l = prev->bandwidthcapacity;
				else l = 0xffffffff;
				minl = l;
				SMARTLIST_FOREACH(sl,routerinfo_t *, router,
				{	if(router->is_exit &&(csel==0x200 || (geoip_get_country_by_ip(geoip_reverse(router->addr))&0xff)==csel))
					{	if(l==router->bandwidthcapacity)
						{	if(((router->router_id >=min) || (i==min)) && router->router_id < i)
							{	prev = router;
								min = router->router_id;
							}
						}
						else if(l>router->bandwidthcapacity)
						{	if((router->bandwidthcapacity >= minl)||(l==minl))
							{	prev2 = router;
								minl = router->bandwidthcapacity;
								min2 = router->router_id;
							}
						}
					}
				});
				break;
			default:
				break;
		}
		if(min==i)
		{	min=min2;
			prev=prev2;
		}
		lastRouter = min;
		if(prev && ((tmpOptions->_ExcludeExitNodesUnion && (routerset_contains_router(tmpOptions->_ExcludeExitNodesUnion,prev))) || (!prev->is_running) || (prev->is_bad_exit) || (!(prev->is_valid)) || (tmpOptions->CircuitBandwidthRate && (prev->bandwidthcapacity < tmpOptions->CircuitBandwidthRate))))
		{	if(++retries >= MAX_ROUTERSELECT_RETRIES)
			{	lastRouter = min = 0;
				break;
			}
		}
		if(tmpOptions->ExitSeenFlags & EXIT_SEEN_FLAG_ENABLED && !dlgBypassBlacklists_isRecent(geoip_reverse(prev->addr),prev,now))
		{	if(++retries >= MAX_ROUTERSELECT_RETRIES)
			{	lastRouter = min = 0;
				break;
			}
		}
		else break;
	}
	set_router_id_sel(min,0);
}
