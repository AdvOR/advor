#include "or.h"
#include "dlg_util.h"
#include "config.h"
#include "circuitlist.h"
#include "connection_edge.h"

HWND hMainDialog,hDlgTrackedHosts=NULL;
extern int frame;

lang_dlg_info lang_dlg_tracked_hosts[]={
	{14050,LANG_DLG_FORCED_EXIT_HOSTS},
	{14010,LANG_DLG_ADDRMAP_FORMAT},
	{14408,LANG_DLG_TRACKED_HOSTS},
	{14011,LANG_DLG_TRACKED_HOSTS_HINT},
	{14409,LANG_DLG_TRACKED_HOSTS_EXPIRE},
	{0,0}
};

extern or_options_t *tmpOptions;

int __stdcall dlgTrackedHosts(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void schedule_expire_tracked_hosts(void);
void schedule_register_addressmaps(void);
void schedule_addrmap_change(void);
void schedule_trackhost_change(void);
void dlgTrackedHosts_trackedHostExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_trackedDomainExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapRemove(HWND hDlg,char *newAddr);
void scheduled_addrmap_change(void);
void scheduled_trackhost_change(void);

void dlgTrackedHosts_trackedHostExitAdd(HWND hDlg,char *newAddr)
{	if(!newAddr[0])	return;
	if(!hDlgTrackedHosts)
	{	hDlgTrackedHosts=createChildDialog(hMainDialog,1119,&dlgTrackedHosts);
		if(frame!=1119) ShowWindow(hDlgTrackedHosts,SW_HIDE);
	}
	int tmpsize=SendDlgItemMessage(hDlgTrackedHosts,14108,WM_GETTEXTLENGTH,0,0);
	char *tmp2=tor_malloc(tmpsize+256+5),*tmp3;tmp3=tmp2;
	GetDlgItemText(hDlgTrackedHosts,14108,tmp2,tmpsize+1);tmp2+=tmpsize;
	if((tmpsize>=1)&&(tmp3[tmpsize-1]>32)){ *tmp2++=13;*tmp2++=10;}
	dlgDebug_copy_address(newAddr,newAddr,strlen(newAddr)+1);
	tor_snprintf(tmp2,strlen(newAddr)+1,"%s",newAddr);
	tmp2 += strlen(tmp2);
	*tmp2++=13;*tmp2++=10;*tmp2++=0;
	SetDlgItemText(hDlgTrackedHosts,14108,tmp3);
	if(tmpOptions->TrackHostExits)
	{	SMARTLIST_FOREACH(tmpOptions->TrackHostExits, char *, cp, tor_free(cp));
		smartlist_clear(tmpOptions->TrackHostExits);
	}
	else	tmpOptions->TrackHostExits=smartlist_create();
	smartlist_split_string(tmpOptions->TrackHostExits, tmp3, "\r\n",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_CIRCUITUSE_REGISTERING_NEW_TRACKED_EXIT),newAddr);
	log(LOG_NOTICE,LD_APP,tmp3);
	LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	tor_free(tmp3);
	schedule_expire_tracked_hosts();
}

void dlgTrackedHosts_trackedDomainExitAdd(HWND hDlg,char *newAddr)
{	if(!newAddr[0])	return;
	if(!hDlgTrackedHosts)
	{	hDlgTrackedHosts=createChildDialog(hMainDialog,1119,&dlgTrackedHosts);
		if(frame!=1119) ShowWindow(hDlgTrackedHosts,SW_HIDE);
	}
	int tmpsize=SendDlgItemMessage(hDlgTrackedHosts,14108,WM_GETTEXTLENGTH,0,0);
	char *tmp2=tor_malloc(tmpsize+256+5),*tmp3;tmp3=tmp2;
	GetDlgItemText(hDlgTrackedHosts,14108,tmp2,tmpsize+1);tmp2+=tmpsize;
	if((tmpsize>=1)&&(tmp3[tmpsize-1]>32)){ *tmp2++=13;*tmp2++=10;}
	int i = dlgDebug_find_domain(newAddr);
	dlgDebug_copy_address(newAddr+i,newAddr+i,strlen(newAddr)+1);
	tor_snprintf(tmp2,strlen(newAddr+i)+2,"%s%s",newAddr[i]=='.'?"":".",newAddr+i);
	tmp2 += strlen(tmp2);
	*tmp2++=13;*tmp2++=10;*tmp2++=0;
	SetDlgItemText(hDlgTrackedHosts,14108,tmp3);
	if(tmpOptions->TrackHostExits)
	{	SMARTLIST_FOREACH(tmpOptions->TrackHostExits, char *, cp, tor_free(cp));
		smartlist_clear(tmpOptions->TrackHostExits);
	}
	else	tmpOptions->TrackHostExits=smartlist_create();
	smartlist_split_string(tmpOptions->TrackHostExits, tmp3, "\r\n",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_CIRCUITUSE_REGISTERING_NEW_TRACKED_EXIT),newAddr + dlgDebug_find_domain(newAddr));
	log(LOG_NOTICE,LD_APP,tmp3);
	LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	tor_free(tmp3);
	schedule_expire_tracked_hosts();
}

void dlgTrackedHosts_addressMapAdd(HWND hDlg,char *newAddr)
{	char *tmp1a,*tmp1b;
	if(!hDlgTrackedHosts)
	{	hDlgTrackedHosts=createChildDialog(hMainDialog,1119,&dlgTrackedHosts);
		if(frame!=1119) ShowWindow(hDlgTrackedHosts,SW_HIDE);
	}
	int tmpsize=SendDlgItemMessage(hDlgTrackedHosts,14106,WM_GETTEXTLENGTH,0,0);
	char *tmp2=tor_malloc(tmpsize+256+5),*tmp1,*tmp3;tmp3=tmp2;
	int i;
	tmpsize = GetDlgItemText(hDlgTrackedHosts,14106,tmp2,tmpsize+1);tmp2+=tmpsize;
	if(tmpsize > 2 && (tmp3[tmpsize-1]!=10 || tmp3[tmpsize-2]!=13))
	{	tmp2[0]=13;tmp2[1]=10;tmp2 += 2;
	}
	tmp1=tmp2;
	dlgDebug_copy_address(newAddr,newAddr,strlen(newAddr)+1);
	tor_snprintf(tmp2,strlen(newAddr)+1,"%s",newAddr);
	tmp2 += strlen(tmp2);
	*tmp2++=0;tmp1a=tmp2;
	for(;*tmp1!=0;tmp1++,tmp2++) *tmp2=*tmp1;
	*tmp2=0;*tmp1++=0x20;
	tmp1b=circuit_find_most_recent_exit(tmp1);
	if(tmp1b)
	{	*tmp2++='.';
		for(i=0;tmp1b[i];i++)	*tmp2++=tmp1b[i];
		tor_free(tmp1b);
		*tmp2++='.';*tmp2++='e';*tmp2++='x';*tmp2++='i';*tmp2++='t';*tmp2=0;
		log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_ADDED),tmp1a);
		*tmp2++=13;*tmp2++=10;*tmp2++=0;
		SetDlgItemText(hDlgTrackedHosts,14106,tmp3);
		getEditData1(hDlgTrackedHosts,14106,&tmpOptions->AddressMap,"AddressMap");
		schedule_register_addressmaps();
		tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_ADDED),newAddr);
		LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	}
	else
	{	log(LOG_WARN,LD_APP,get_lang_str(LANG_LOG_DLG_NO_EXIT_FOUND),tmp1,tmp1);
		tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_DLG_NO_EXIT_FOUND),tmp1,tmp1);
		LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	}
	tor_free(tmp3);
	schedule_expire_tracked_hosts();
	schedule_register_addressmaps();
}

void dlgTrackedHosts_addressMapRemove(HWND hDlg,char *newAddr)
{	char *tmp1a;
	if(!hDlgTrackedHosts)
	{	hDlgTrackedHosts=createChildDialog(hMainDialog,1119,&dlgTrackedHosts);
		if(frame!=1119) ShowWindow(hDlgTrackedHosts,SW_HIDE);
	}
	int tmpsize=SendDlgItemMessage(hDlgTrackedHosts,14106,WM_GETTEXTLENGTH,0,0);
	char *tmp2=tor_malloc(tmpsize+256+5),*tmp1,*tmp3;tmp3=tmp2;
	int i;
	GetDlgItemText(hDlgTrackedHosts,14106,tmp2,tmpsize+1);tmp2+=tmpsize+1;
	tmp1=tmp2;
	dlgDebug_copy_address(newAddr,newAddr,strlen(newAddr)+1);
	tor_snprintf(tmp2,strlen(newAddr)+1,"%s",newAddr);
	tmp2 += strlen(tmp2);
	*tmp2++=0;tmp1a=tmp3;tmp2=tmp1;
	while(*tmp1a)
	{	for(i=0;tmp2[i];i++)
		{	if((tmp2[i]|0x20) != (tmp1a[i]|0x20)) break;
		}
		if((tmp2[i]==0)&&(tmp1a[i]<33))	break;
		while(*tmp1a>32) tmp1a++;
		while(*tmp1a<33 && *tmp1a) tmp1a++;
	}
	if(*tmp1a)
	{	{ for(i=0;tmp1a[i]&&tmp1a[i]!=0x0d&&tmp1a[i]!=0x0a;i++)	; }
		if(tmp1a[i]==0x0d) i++;
		if(tmp1a[i]==0x0a) i++;
		while(tmp1a[i]){	*tmp1a=tmp1a[i];tmp1a++;}
		*tmp1a=0;
		log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_REMOVED),tmp1);
		SetDlgItemText(hDlgTrackedHosts,14106,tmp3);
		getEditData1(hDlgTrackedHosts,14106,&tmpOptions->AddressMap,"AddressMap");
		schedule_register_addressmaps();
		tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_REMOVED),newAddr);
		LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	}
	else
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_ENTRY_NOT_FOUND),tmp1);
		tor_snprintf(tmp3,256,get_lang_str(LANG_LOG_DLG_ADDRESSMAP_ENTRY_NOT_FOUND),newAddr);
		LangMessageBox(hDlg,tmp3,LANG_LB_CONNECTIONS,MB_OK);
	}
	tor_free(tmp3);
	schedule_expire_tracked_hosts();
	schedule_register_addressmaps();
}

void scheduled_addrmap_change(void)
{
	getEditData1(hDlgTrackedHosts,14106,&tmpOptions->AddressMap,"AddressMap");
	addressmap_clear_transient();
	config_register_addressmaps(tmpOptions);
	parse_virtual_addr_network(tmpOptions->VirtualAddrNetwork,0,0);
}

void scheduled_trackhost_change(void)
{
	char *tmp1=tor_malloc(32768);
	GetDlgItemText(hDlgTrackedHosts,14108,tmp1,32767);
	if(tmpOptions->TrackHostExits)
	{	SMARTLIST_FOREACH(tmpOptions->TrackHostExits, char *, cp, tor_free(cp));
		smartlist_clear(tmpOptions->TrackHostExits);
	}
	else	tmpOptions->TrackHostExits=smartlist_create();
	smartlist_split_string(tmpOptions->TrackHostExits, tmp1, "\r\n",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
	tor_free(tmp1);
	addressmap_clear_transient();
}

int __stdcall dlgTrackedHosts(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgTrackedHosts=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_tracked_hosts);
		}
		SetDlgItemInt(hDlg,14109,tmpOptions->TrackHostExitsExpire,0);
		setEditData(hDlg,14106,tmpOptions->AddressMap);
		if(tmpOptions->TrackHostExits)
		{	char *tmp1=smartlist_join_strings(tmpOptions->TrackHostExits, "\r\n", 0, NULL);
			SetDlgItemText(hDlg,14108,tmp1);
			tor_free(tmp1);
		}
	}
	else if(uMsg==WM_COMMAND)
	{
		if((LOWORD(wParam)==14109)&&(HIWORD(wParam)==EN_CHANGE))
		{	tmpOptions->TrackHostExitsExpire=GetDlgItemInt(hDlg,14109,0,0);
		}
		else if((LOWORD(wParam)==14106)&&(HIWORD(wParam)==EN_CHANGE))
		{	schedule_addrmap_change();
		}
		else if((LOWORD(wParam)==14108)&&(HIWORD(wParam)==EN_CHANGE))
		{	schedule_trackhost_change();
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
