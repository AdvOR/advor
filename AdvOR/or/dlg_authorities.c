#include "or.h"
#include "dlg_util.h"
#include "config.h"
#include "routerlist.h"
#include "main.h"

void expire_consensus(void);
void update_v2_networkstatus_cache_downloads(time_t);
void update_consensus_networkstatus_downloads(time_t);
void update_certificate_downloads(time_t);
void dlgAuthorities_initDirServers(config_line_t **option);
void setEditDataDir(config_line_t **option);
int __stdcall dlgAuthorities(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
extern HWND hMainDialog;

//int frame10[]={18000,18100,18012,18020,18401,18402,18001,18403,18101,18404,18405,18010,18102,18011,18406,18407,18103,18408,18104,18014,-1};
lang_dlg_info lang_dlg_authorities[]={
	{18000,LANG_DLG_DIR_LIST},
	{18012,LANG_DLG_DIR_STATUS},
	{18401,LANG_DLG_DIR_RANDOM},
	{18402,LANG_DLG_DIR_CONSENSUS_EXP},
	{18001,LANG_DLG_DIR_REFRESH_NOW},
	{18403,LANG_DLG_DIR_RESOLUTION_TIMEOUT},
	{18404,LANG_DLG_DIR_WAIT_DESCRIPTORS},
	{18405,LANG_DLG_DIR_FAKE_TIME},
	{18010,LANG_DLG_DIR_RANDOMIZE_DELTA},
	{18011,LANG_DLG_DIR_RANDOMIZE_DELTA_UNITS},
	{18406,LANG_DLG_DIR_ROUTER_TIME},
	{18407,LANG_DLG_DIR_MAX_DL_FAILURES},
	{18408,LANG_DLG_DIR_REMOVE_CONSENSUS},
	{18014,LANG_DLG_DIR_REMOVE_CONSENSUS_UNITS},
	{0,0}
};
HWND hDlgAuthorities=NULL;
extern or_options_t *tmpOptions;
const char *dirservers[] = {
	"moria1 orport=9201 v3ident=F533C81CEF0BC0267857C99B2F471ADF249FA232 128.31.0.39:9231 1A25 C635 8DB9 1342 AA51 720A 5038 B727 4273 2498",
	"tor26 orport=443 v3ident=2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C 217.196.147.77:80 FAA4 BCA4 A6AC 0FB4 CA2F 8AD5 A11D 9E12 2BA8 94F6",
	"dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 45.66.35.11:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
	"gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
	"dannenberg orport=443 v3ident=0232AF901C31A04EE9848595AF9BB7620D4C5B2E 193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
	"maatuska orport=80 v3ident=49015F787433103580E3B66A1707A00E60F2D15B 171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
	"longclaw orport=443 v3ident=23D15D965BC35114467363C165C4F724B64B4F66 199.58.81.140:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145",
	"bastet orport=443 v3ident=27102BC123E7AF1D4741AE047E160C91ADC76B21 204.13.164.118:80 24E2 F139 121D 4394 C54B 5BCC 368B 3B41 1857 C413",
	"Serge orport=9001 66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533",
	"faravahar orport=443 v3ident=70849B868D606BAECFB6128C5E3D782029AA394F 216.218.219.41:80 E3E4 2D35 F801 C9D5 AB23 584E 0025 D56F E2B3 3396",
	NULL };

void dlgAuthorities_initDirServers(config_line_t **option)
{	int i;
	config_line_t *cfg,**cfg1;
	if(*option==NULL)
	{	cfg1=option;
		for(i=0;dirservers[i];i++)
		{	*cfg1=tor_malloc_zero(sizeof(config_line_t));
			(*cfg1)->key = (unsigned char *)tor_strdup("DirServers");
			(*cfg1)->value = (unsigned char *)tor_strdup(dirservers[i]);
			cfg1=&((*cfg1)->next);
		}
		for(cfg=*option;cfg;cfg=cfg->next) parse_dir_server_line((char *)cfg->value,NO_AUTHORITY,0);
	}
	last_dir_status[0]=0;
}

void setEditDataDir(config_line_t **option)
{	if(*option!=NULL)
	{
		config_line_t *cfg;
		int j = 0;
		for(cfg=*option;cfg;cfg=cfg->next)
			j += strlen((char *)cfg->value) + 2;
		char *tmp1=tor_malloc(j+1024),*tmp2;
		tmp2=tmp1;
		for(cfg=*option;cfg;cfg=cfg->next)
		{	for(j=0;;j++)
			{	if(!cfg->value[j]) break;
				*tmp1++=cfg->value[j];
			}
			*tmp1++=13;*tmp1++=10;
		}
		*tmp1=0;
		SetDlgItemText(hDlgAuthorities,18100,tmp2);
		tor_free(tmp2);
	}
}

void updateDirStatus(void)
{	if(hDlgAuthorities)	SetDlgItemTextL(hDlgAuthorities,18020,last_dir_status);
}


int __stdcall dlgAuthorities(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgAuthorities=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_authorities);
		}
		updateDirStatus();
		setEditDataDir(&tmpOptions->DirServers);
		if(tmpOptions->DirFlags&DIR_FLAG_RANDOM_AUTHORITY) CheckDlgButton(hDlg,18401,BST_CHECKED);
		if(tmpOptions->DirFlags&DIR_FLAG_NO_AUTO_UPDATE) CheckDlgButton(hDlg,18402,BST_CHECKED);
		if(tmpOptions->ResolveTimeout) CheckDlgButton(hDlg,18403,BST_CHECKED);
		SetDlgItemInt(hDlg,18101,tmpOptions->ResolveTimeout,0);
		if(tmpOptions->DirFlags&DIR_FLAG_WAIT_MORE_DESCRIPTORS) CheckDlgButton(hDlg,18404,BST_CHECKED);
		if(tmpOptions->MaxDlFailures) CheckDlgButton(hDlg,18407,BST_CHECKED);
		SetDlgItemInt(hDlg,18103,tmpOptions->MaxDlFailures,0);
		if(tmpOptions->MaxFileAge) CheckDlgButton(hDlg,18408,BST_CHECKED);
		SetDlgItemInt(hDlg,18104,tmpOptions->MaxFileAge,0);
		if(tmpOptions->DirFlags&DIR_FLAG_FAKE_LOCAL_TIME)
			CheckDlgButton(hDlg,18405,BST_CHECKED);
		else
		{	EnableWindow(GetDlgItem(hDlg,18010),0);
			EnableWindow(GetDlgItem(hDlg,18102),0);
			EnableWindow(GetDlgItem(hDlg,18011),0);
			EnableWindow(GetDlgItem(hDlg,18406),0);
		}
		SetDlgItemInt(hDlg,18102,tmpOptions->MaxTimeDelta,0);
		if(tmpOptions->DirFlags&DIR_FLAG_USE_ROUTER_TIME) CheckDlgButton(hDlg,18406,BST_CHECKED);
	}
	else if(uMsg==WM_COMMAND)
	{
		if((LOWORD(wParam)==18100)&&(HIWORD(wParam)==EN_CHANGE))
		{	config_line_t *cfg;
			clear_trusted_dir_servers();
			getEditData1(hDlg,18100,&tmpOptions->DirServers,"DirServers");
			for(cfg=tmpOptions->DirServers;cfg;cfg=cfg->next) parse_dir_server_line((char *)cfg->value,NO_AUTHORITY,0);
		}
		else if(LOWORD(wParam)==18401)
		{	if(IsDlgButtonChecked(hDlg,18401)==BST_CHECKED){	tmpOptions->DirFlags|=DIR_FLAG_RANDOM_AUTHORITY;}
			else{	tmpOptions->DirFlags&=DIR_FLAG_RANDOM_AUTHORITY ^ DIR_FLAGS_ALL;}
		}
		else if(LOWORD(wParam)==18402)
		{	if(IsDlgButtonChecked(hDlg,18402)==BST_CHECKED){	tmpOptions->DirFlags|=DIR_FLAG_NO_AUTO_UPDATE;}
			else{	tmpOptions->DirFlags&=DIR_FLAGS_ALL ^ DIR_FLAG_NO_AUTO_UPDATE;}
		}
		else if((LOWORD(wParam)==18403)||(((LOWORD(wParam)==18101)&&(HIWORD(wParam)==EN_CHANGE))))
		{	if(IsDlgButtonChecked(hDlg,18403)==BST_CHECKED){	tmpOptions->ResolveTimeout=GetDlgItemInt(hDlg,18101,NULL,0);}
			else{	tmpOptions->ResolveTimeout=0;}
		}
		else if(LOWORD(wParam)==18404)
		{	if(IsDlgButtonChecked(hDlg,18404)==BST_CHECKED){	tmpOptions->DirFlags|=DIR_FLAG_WAIT_MORE_DESCRIPTORS;}
			else{	tmpOptions->DirFlags&=DIR_FLAGS_ALL ^ DIR_FLAG_WAIT_MORE_DESCRIPTORS;}
		}
		else if((LOWORD(wParam)==18407)||(((LOWORD(wParam)==18103)&&(HIWORD(wParam)==EN_CHANGE))))
		{	if(IsDlgButtonChecked(hDlg,18407)==BST_CHECKED){	tmpOptions->MaxDlFailures=GetDlgItemInt(hDlg,18103,NULL,0);}
			else{	tmpOptions->MaxDlFailures=0;}
		}
		else if((LOWORD(wParam)==18408)||(((LOWORD(wParam)==18104)&&(HIWORD(wParam)==EN_CHANGE))))
		{	if(IsDlgButtonChecked(hDlg,18408)==BST_CHECKED){	tmpOptions->MaxFileAge=GetDlgItemInt(hDlg,18104,NULL,0);}
			else{	tmpOptions->MaxFileAge=0;}
		}
		else if(LOWORD(wParam)==18405)
		{	if(IsDlgButtonChecked(hDlg,18405)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,18010),1);
				EnableWindow(GetDlgItem(hDlg,18102),1);
				EnableWindow(GetDlgItem(hDlg,18011),1);
				EnableWindow(GetDlgItem(hDlg,18406),1);
				tmpOptions->DirFlags|=DIR_FLAG_FAKE_LOCAL_TIME;
				if((tmpOptions->BestTimeDelta)&&(tmpOptions->DirFlags&DIR_FLAG_USE_ROUTER_TIME)) delta_t=tmpOptions->BestTimeDelta;
				else delta_t=crypto_rand_int(tmpOptions->MaxTimeDelta*2)-tmpOptions->MaxTimeDelta;
				update_best_delta_t(delta_t);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,18010),0);
				EnableWindow(GetDlgItem(hDlg,18102),0);
				EnableWindow(GetDlgItem(hDlg,18011),0);
				EnableWindow(GetDlgItem(hDlg,18406),0);
				tmpOptions->DirFlags&=DIR_FLAGS_ALL ^ DIR_FLAG_FAKE_LOCAL_TIME;
				delta_t=0;
				update_best_delta_t(0);
			}
		}
		else if(((LOWORD(wParam)==18102)&&(HIWORD(wParam)==EN_CHANGE)))
		{	tmpOptions->MaxTimeDelta=GetDlgItemInt(hDlg,18102,NULL,0);
			if((tmpOptions->BestTimeDelta)&&(tmpOptions->DirFlags&DIR_FLAG_USE_ROUTER_TIME)) delta_t=tmpOptions->BestTimeDelta;
			else delta_t=crypto_rand_int(tmpOptions->MaxTimeDelta*2)-tmpOptions->MaxTimeDelta;
			update_best_delta_t(delta_t);
		}
		else if(LOWORD(wParam)==18406)
		{	if(IsDlgButtonChecked(hDlg,18406)==BST_CHECKED){	tmpOptions->DirFlags|=DIR_FLAG_USE_ROUTER_TIME;}
			else{	tmpOptions->DirFlags&=DIR_FLAGS_ALL ^ DIR_FLAG_USE_ROUTER_TIME;}
		}
		else if(LOWORD(wParam)==18001)
		{	expire_consensus();
			update_v2_networkstatus_cache_downloads(get_time(NULL));
			update_consensus_networkstatus_downloads(get_time(NULL));
			update_certificate_downloads(get_time(NULL));
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
