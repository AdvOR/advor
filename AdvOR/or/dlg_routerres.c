#include "or.h"
#include "dlg_util.h"
#include "routerlist.h"


HWND hDlgRouterRestrictions = NULL;
HWND hDlgRouterBans = NULL;
HWND hDlgRouterFavorites = NULL;
extern HWND hMainDialog;
extern or_options_t *tmpOptions;
routerset_t *r1,*r2;

//int frame7[]={15050,15400,15401,15402,15403,15404,15405,15406,15407,15408,15409,15051,15100,15052,15101,15410,15102,15010,15503,15004,15500,15501,15502,-1};
lang_dlg_info lang_dlg_router_restrictions[]={
	{15050,LANG_DLG_ALLOWED_INVALID},
	{15400,LANG_DLG_ALLOWED_INVALID_ENTRY},
	{15401,LANG_DLG_ALLOWED_INVALID_EXIT},
	{15402,LANG_DLG_ALLOWED_INVALID_MIDDLE},
	{15403,LANG_DLG_ALLOWED_INVALID_RENDEZVOUS},
	{15404,LANG_DLG_ALLOWED_INVALID_INTRODUCTION},
	{15405,LANG_DLG_AVOID_SAME_SUBNETS},
	{15406,LANG_DLG_FAST_CIRCUITS},
	{15410,LANG_DLG_ESTIMATE_AS_PATHS},
	{15407,LANG_DLG_DOWNLOAD_EXTRA_INFO},
	{15501,LANG_DLG_RESERVED_01},
	{15502,LANG_DLG_RESERVED_02},
	{0,0}
};

lang_dlg_info lang_dlg_router_bans[]={
	{15400,LANG_DLG_GEOIP_BLACKLIST},
	{15051,LANG_DLG_BANNED_NODES},
	{0,0}
};

lang_dlg_info lang_dlg_router_favorites[]={
	{15408,LANG_DLG_USE_ONLY_ENTRIES_FROM_FAVORITES},
	{15409,LANG_DLG_USE_ONLY_EXITS_FROM_FAVORITES},
	{15010,LANG_DLG_PRIORITY},
	{15052,LANG_DLG_FAVORITE_NODES},
	{0,0}
};

void dlgRouterRestrictions_langUpdate(void);
void refreshFavoriteNodes(void);
void refreshBannedNodes(void);
void add_router_to_banlist(HWND hDlg,char *router,char bantype);
void add_router_to_favorites(HWND hDlg,char *router,char favtype);
void show_bans(void);
void show_favorites(void);
int __stdcall dlgRouterRestrictions(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterFavorites(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgRouterBans(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void refreshFavoriteNodes(void)
{	r1=tmpOptions->EntryNodes;
	r2=routerset_new();
	int len = SendDlgItemMessage(hDlgRouterFavorites,15101,WM_GETTEXTLENGTH,0,0)+1024;
	char *tmp1=tor_malloc(len),*tmp2,*tmp3;tmp2=tmp1;tmp3=tmp1;GetDlgItemText(hDlgRouterFavorites,15101,tmp1,len);
	while(*tmp1)
	{	while((*tmp1==32)||(*tmp1==9))	tmp1++;
		if((*tmp1==13)||(*tmp1==10))
		{	while((*tmp1==13)||(*tmp1==10)){	tmp1++;}
			*tmp2++=',';
		}
		else if((*tmp1=='[')&&(*(tmp1+2)==']'))
		{	if((*(tmp1+1)=='e')||(*(tmp1+1)=='E'))
			{	tmp1+=3;
				while((*tmp1==32)||(*tmp1==9))	tmp1++;
				while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
			}
			else
				while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
		}
		else
			while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
	}
	*tmp2=0;routerset_parse(r2,tmp3,"EntryNodes");
	tmpOptions->EntryNodes=r2;
	if(r1)	routerset_free(r1);
	r1=tmpOptions->ExitNodes;
	r2=routerset_new();
	tmp1=tmp3;tmp2=tmp3;GetDlgItemText(hDlgRouterFavorites,15101,tmp1,len);
	while(*tmp1)
	{	while((*tmp1==32)||(*tmp1==9))	tmp1++;
		if((*tmp1==13)||(*tmp1==10))
		{	while((*tmp1==13)||(*tmp1==10)){	tmp1++;}
			*tmp2++=',';
		}
		else if((*tmp1=='[')&&(*(tmp1+2)==']'))
		{	if((*(tmp1+1)=='e')||(*(tmp1+1)=='E'))
			{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
			}
			else if((*(tmp1+1)=='x')||(*(tmp1+1)=='X'))
			{	tmp1+=3;
				while((*tmp1==32)||(*tmp1==9))	tmp1++;
				while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
			}
			else
			{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
			}
		}
		else
		{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
		}
	}
	*tmp2=0;routerset_parse(r2,tmp3,"ExitNodes");
	tmpOptions->ExitNodes=r2;
	if(r1)	routerset_free(r1);
	tor_free(tmp3);
}

void refreshBannedNodes(void)
{	r1=tmpOptions->ExcludeExitNodes;
	r2=routerset_new();
	int len = SendDlgItemMessage(hDlgRouterBans,15100,WM_GETTEXTLENGTH,0,0) + 1024;
	char *tmp1=tor_malloc(len),*tmp2,*tmp3;tmp2=tmp1;tmp3=tmp1;GetDlgItemText(hDlgRouterBans,15100,tmp1,len);
	while(*tmp1)
	{	while((*tmp1==32)||(*tmp1==9))	tmp1++;
		if((*tmp1==13)||(*tmp1==10))
		{	while((*tmp1==13)||(*tmp1==10)){	tmp1++;}
			*tmp2++=',';
		}
		else if((*tmp1=='[')&&(*(tmp1+2)==']'))
		{	if((*(tmp1+1)=='x')||(*(tmp1+1)=='X'))
			{	tmp1+=3;
				while((*tmp1==32)||(*tmp1==9))	tmp1++;
				while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
			}
			else
				while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
		}
		else
			while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
	}
	*tmp2=0;routerset_parse(r2,tmp3,"ExcludeExitNodes");
	tmpOptions->ExcludeExitNodes=r2;
	if(r1)	routerset_free(r1);
	r1=tmpOptions->ExcludeNodes;
	r2=routerset_new();
	tmp1=tmp3;tmp2=tmp3;GetDlgItemText(hDlgRouterBans,15100,tmp1,len);
	while(*tmp1)
	{	while((*tmp1==32)||(*tmp1==9))	tmp1++;
		if((*tmp1==13)||(*tmp1==10))
		{	while((*tmp1==13)||(*tmp1==10)){	tmp1++;}
			*tmp2++=',';
		}
		else if((*tmp1=='[')&&(*(tmp1+2)==']'))
		{	if((*(tmp1+1)=='x')||(*(tmp1+1)=='X'))
			{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	tmp1++;
			}
			else
			{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
			}
		}
		else
		{	while((*tmp1!=0)&&(*tmp1!=13)&&(*tmp1!=10))	*tmp2++=*tmp1++;
		}
	}
	*tmp2=0;routerset_parse(r2,tmp3,"ExcludeNodes");
	tmpOptions->ExcludeNodes=r2;
	if(r1)	routerset_free(r1);
	if(tmpOptions->ExcludeExitNodes || tmpOptions->ExcludeNodes)
	{	r2 = tmpOptions->_ExcludeExitNodesUnion;
		r1 = routerset_new();
		routerset_union(r1,tmpOptions->ExcludeExitNodes);
		routerset_union(r1,tmpOptions->ExcludeNodes);
		tmpOptions->_ExcludeExitNodesUnion = r1;
		if(r2)	routerset_free(r2);
	}
	tor_free(tmp3);
}

void add_router_to_banlist(HWND hDlg,char *router,char bantype)
{	if(hDlgRouterBans)
	{	char *bantmp2,*bantmp3;
		int bantmpsize,i;
		bantmpsize=SendDlgItemMessage(hDlgRouterBans,15100,WM_GETTEXTLENGTH,0,0);
		bantmp2=tor_malloc(bantmpsize+256+5);bantmp3=bantmp2;
		GetDlgItemText(hDlgRouterBans,15100,bantmp2,bantmpsize+1);bantmp2+=bantmpsize;
		if((bantmpsize>2)&&((*(bantmp2-1)!=0x0d)&&(*(bantmp2-1)!=0x0a)))
		{	*bantmp2++=0x0d;*bantmp2++=0x0a;}
		if(bantype){	*bantmp2++='[';*bantmp2++=bantype;*bantmp2++=']';*bantmp2++=32;}
		for(i=0;router[i];i++)	*bantmp2++=router[i];
		*bantmp2++=13;*bantmp2++=10;*bantmp2++=0;
		tor_snprintf(bantmp2,100,get_lang_str(LANG_MB_BAN_ADDED),bantmp3+bantmpsize);
		if(hDlg) LangMessageBox(hDlg,bantmp2,LANG_MB_BANS,MB_OK);
		log(LOG_NOTICE,LD_APP,bantmp2);
		bantmpsize = strlen(bantmp3);
		if(bantmpsize > 29999)	SendDlgItemMessage(hDlgRouterBans,15100,EM_LIMITTEXT,bantmpsize+32768,0);
		SetDlgItemText(hDlgRouterBans,15100,bantmp3);
		refreshBannedNodes();
		tor_free(bantmp3);
	}
	else if(bantype)
	{	char *tmp1=routerset_to_string(tmpOptions->ExcludeExitNodes);
		int i=strlen(tmp1)+256+5;
		char *tmp2=tor_malloc(i),*tmp3=tor_malloc(256);;
		tor_snprintf(tmp2,i,"%s,%s",tmp1,router);
		r1=tmpOptions->ExcludeExitNodes;
		r2=routerset_new();
		routerset_parse(r2,tmp2,"ExcludeExitNodes");
		tmpOptions->ExcludeExitNodes=r2;
		if(r1)	routerset_free(r1);
		tor_snprintf(tmp3,256,"[X] %s",router);
		tor_snprintf(tmp2,100,get_lang_str(LANG_MB_BAN_ADDED),tmp3);
		if(hDlg) LangMessageBox(hDlg,tmp2,LANG_MB_BANS,MB_OK);
		log(LOG_NOTICE,LD_APP,tmp2);
		tor_free(tmp1);tor_free(tmp2);tor_free(tmp3);
		if(tmpOptions->ExcludeExitNodes || tmpOptions->ExcludeNodes)
		{	r2 = tmpOptions->_ExcludeExitNodesUnion;
			r1 = routerset_new();
			routerset_union(r1,tmpOptions->ExcludeExitNodes);
			routerset_union(r1,tmpOptions->ExcludeNodes);
			tmpOptions->_ExcludeExitNodesUnion = r1;
			if(r2)	routerset_free(r2);
		}
	}
	else
	{	char *tmp1=routerset_to_string(tmpOptions->ExcludeNodes);
		int i=strlen(tmp1)+256+5;
		char *tmp2=tor_malloc(i);
		tor_snprintf(tmp2,i,"%s,%s",tmp1,router);
		r1=tmpOptions->ExcludeNodes;
		r2=routerset_new();
		routerset_parse(r2,tmp2,"ExcludeNodes");
		tmpOptions->ExcludeNodes=r2;
		if(r1)	routerset_free(r1);
		tor_snprintf(tmp2,100,get_lang_str(LANG_MB_BAN_ADDED),router);
		if(hDlg) LangMessageBox(hDlg,tmp2,LANG_MB_BANS,MB_OK);
		log(LOG_NOTICE,LD_APP,tmp2);
		tor_free(tmp1);tor_free(tmp2);
		if(tmpOptions->ExcludeExitNodes || tmpOptions->ExcludeNodes)
		{	r2 = tmpOptions->_ExcludeExitNodesUnion;
			r1 = routerset_new();
			routerset_union(r1,tmpOptions->ExcludeExitNodes);
			routerset_union(r1,tmpOptions->ExcludeNodes);
			tmpOptions->_ExcludeExitNodesUnion = r1;
			if(r2)	routerset_free(r2);
		}
	}
}

void add_router_to_favorites(HWND hDlg,char *router,char favtype)
{	if(hDlgRouterFavorites)
	{	char *favtmp2,*favtmp3;
		int favtmpsize;
		int i;
		favtmpsize=SendDlgItemMessage(hDlgRouterFavorites,15101,WM_GETTEXTLENGTH,0,0);
		favtmp2=tor_malloc(favtmpsize+256+5);favtmp3=favtmp2;
		GetDlgItemText(hDlgRouterFavorites,15101,favtmp2,favtmpsize+1);favtmp2+=favtmpsize;
		if((favtmpsize>2)&&((*(favtmp2-1)!=0x0d)&&(*(favtmp2-1)!=0x0a)))
		{	*favtmp2++=0x0d;*favtmp2++=0x0a;}
		*favtmp2++='[';*favtmp2++=favtype;*favtmp2++=']';*favtmp2++=32;
		for(i=0;router[i];i++)	*favtmp2++=router[i];
		*favtmp2++=13;*favtmp2++=10;*favtmp2++=0;
		tor_snprintf(favtmp2,100,get_lang_str(LANG_MB_FAV_ADDED),favtmp3+favtmpsize);
		LangMessageBox(hDlg,favtmp2,LANG_MB_FAVORITES,MB_OK);
		log(LOG_NOTICE,LD_APP,favtmp2);
		favtmpsize = strlen(favtmp3);
		if(favtmpsize > 29999)	SendDlgItemMessage(hDlgRouterFavorites,15101,EM_LIMITTEXT,favtmpsize+32768,0);
		SetDlgItemText(hDlgRouterFavorites,15101,favtmp3);
		refreshFavoriteNodes();
		tor_free(favtmp3);
	}
	else if(favtype=='X')
	{	char *tmp1=routerset_to_string(tmpOptions->ExitNodes);
		int i=strlen(tmp1)+256+5;
		char *tmp2=tor_malloc(i),*tmp3=tor_malloc(256);
		tor_snprintf(tmp2,i,"%s,%s",tmp1,router);
		r1=tmpOptions->ExitNodes;
		r2=routerset_new();
		routerset_parse(r2,tmp2,"ExitNodes");
		tmpOptions->ExitNodes=r2;
		if(r1)	routerset_free(r1);
		tor_snprintf(tmp3,256,"[X] %s",router);
		tor_snprintf(tmp2,100,get_lang_str(LANG_MB_FAV_ADDED),tmp3);
		LangMessageBox(hDlg,tmp2,LANG_MB_FAVORITES,MB_OK);
		log(LOG_NOTICE,LD_APP,tmp2);
		tor_free(tmp1);tor_free(tmp2);tor_free(tmp3);
	}
	else if(favtype=='E')
	{	char *tmp1=routerset_to_string(tmpOptions->EntryNodes);
		int i=strlen(tmp1)+256+5;
		char *tmp2=tor_malloc(i),*tmp3=tor_malloc(256);
		tor_snprintf(tmp2,i,"%s,%s",tmp1,router);
		r1=tmpOptions->EntryNodes;
		r2=routerset_new();
		routerset_parse(r2,tmp2,"EntryNodes");
		tmpOptions->EntryNodes=r2;
		if(r1)	routerset_free(r1);
		tor_snprintf(tmp3,256,"[E] %s",router);
		tor_snprintf(tmp2,100,get_lang_str(LANG_MB_FAV_ADDED),tmp3);
		LangMessageBox(hDlg,tmp2,LANG_MB_FAVORITES,MB_OK);
		log(LOG_NOTICE,LD_APP,tmp2);
		tor_free(tmp1);tor_free(tmp2);tor_free(tmp3);
	}
}

void show_bans(void)
{	char *tmp1,*tmp2,*tmp3,*tmp4;
	if(hDlgRouterBans)
	{	if((tmpOptions->ExcludeNodes)||(tmpOptions->ExcludeExitNodes))
		{	char *tmp_e1=NULL,*tmp_e2=NULL;
			int len= 0;
			if(tmpOptions->ExcludeNodes)
			{	tmp_e1 = routerset_to_string(tmpOptions->ExcludeNodes);
				if(tmp_e1)
				{	tmp1 = tmp_e1;
					while(*tmp1)
					{	len++;
						if(*tmp1==',')	len++;
						tmp1++;
					}
				}
			}
			if(tmpOptions->ExcludeExitNodes)
			{	tmp_e2 = routerset_to_string(tmpOptions->ExcludeExitNodes);
				if(tmp_e2)
				{	tmp1 = tmp_e2;
					while(*tmp1)
					{	len++;
						if(*tmp1==',')	len+=3;
						tmp1++;
					}
				}
			}
			len += 1024;
			tmp3=tor_malloc(len);tmp4=tmp3;
			if(tmp_e1)
			{	tmp2=tmp_e1;
				while(*tmp2)
				{	if(*tmp2==','){	*tmp3++=13;*tmp3++=10;tmp2++;}
					else	*tmp3++=*tmp2++;
				}
				tor_free(tmp_e1);
				if(tmp3!=tmp4){*tmp3++=13;*tmp3++=10;}
			}
			if(tmp_e2)
			{	tmp2=tmp_e2;
				while(*tmp2)
				{	if((*tmp2!=0)&&(*tmp2!=','))
					{	*tmp3++='[';*tmp3++='X';*tmp3++=']';*tmp3++=32;
						while((*tmp2!=0)&&(*tmp2!=','))	*tmp3++=*tmp2++;
					}
					else if(*tmp2==',')
					{	*tmp3++=13;*tmp3++=10;tmp2++;}
				}
				tor_free(tmp_e2);
			}
			*tmp3=0;
			if(len > 29999)	SendDlgItemMessage(hDlgRouterBans,15100,EM_LIMITTEXT,len+32768,0);
			SetDlgItemText(hDlgRouterBans,15100,tmp4);tor_free(tmp4);
		}
		else	SetDlgItemText(hDlgRouterBans,15100,"");
	}
}

void show_favorites(void)
{	char *tmp1,*tmp2,*tmp3,*tmp4;
	if((tmpOptions->EntryNodes)||(tmpOptions->ExitNodes))
	{	char *tmp_e1=NULL,*tmp_e2=NULL;
		int len = 0;
		if(tmpOptions->EntryNodes)
		{	tmp_e1 = routerset_to_string(tmpOptions->EntryNodes);
			if(tmp_e1)
			{	tmp1 = tmp_e1;
				while(*tmp1)
				{	len++;
					if(*tmp1==',')	len+=3;
					tmp1++;
				}
			}
		}
		if(tmpOptions->ExitNodes)
		{	tmp_e2 = routerset_to_string(tmpOptions->ExitNodes);
			if(tmp_e2)
			{	tmp1 = tmp_e2;
				while(*tmp1)
				{	len++;
					if(*tmp1==',')	len+=3;
					tmp1++;
				}
			}
		}
		len += 1024;
		tmp3=tor_malloc(len);tmp4=tmp3;
		if(tmp_e1)
		{	tmp2=tmp_e1;
			while(*tmp2)
			{	if((*tmp2!=0)&&(*tmp2!=','))
				{	*tmp3++='[';*tmp3++='E';*tmp3++=']';*tmp3++=32;
					while((*tmp2!=0)&&(*tmp2!=','))	*tmp3++=*tmp2++;
				}
				else if(*tmp2==',')
				{	*tmp3++=13;*tmp3++=10;tmp2++;}
			}
			tor_free(tmp_e1);
			if(tmp3!=tmp4){*tmp3++=13;*tmp3++=10;}
		}
		if(tmp_e2)
		{	tmp2=tmp_e2;
			while(*tmp2)
			{	if((*tmp2!=0)&&(*tmp2!=','))
				{	*tmp3++='[';*tmp3++='X';*tmp3++=']';*tmp3++=32;
					while((*tmp2!=0)&&(*tmp2!=','))	*tmp3++=*tmp2++;
				}
				else if(*tmp2==',')
				{	*tmp3++=13;*tmp3++=10;tmp2++;}
			}
			tor_free(tmp_e2);
		}
		*tmp3=0;
		if(len > 29999)	SendDlgItemMessage(hDlgRouterFavorites,15101,EM_LIMITTEXT,len+32768,0);
		SetDlgItemText(hDlgRouterFavorites,15101,tmp4);tor_free(tmp4);
	}
}


int __stdcall dlgRouterRestrictions(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlgRouterRestrictions=hDlg;
		dlgRouterRestrictions_langUpdate();
		if(tmpOptions->_AllowInvalid&ALLOW_INVALID_ENTRY)	CheckDlgButton(hDlg,15400,BST_CHECKED);
		if(tmpOptions->_AllowInvalid&ALLOW_INVALID_EXIT)	CheckDlgButton(hDlg,15401,BST_CHECKED);
		if(tmpOptions->_AllowInvalid&ALLOW_INVALID_MIDDLE)	CheckDlgButton(hDlg,15402,BST_CHECKED);
		if(tmpOptions->_AllowInvalid&ALLOW_INVALID_INTRODUCTION)	CheckDlgButton(hDlg,15404,BST_CHECKED);
		if(tmpOptions->_AllowInvalid&ALLOW_INVALID_RENDEZVOUS)	CheckDlgButton(hDlg,15403,BST_CHECKED);
		if((tmpOptions->EnforceDistinctSubnets&3)==0)
		{	EnableWindow(GetDlgItem(hDlg,15501),0);EnableWindow(GetDlgItem(hDlg,15502),0);
		}
		else	CheckDlgButton(hDlg,15405,BST_CHECKED);
		if((tmpOptions->EnforceDistinctSubnets&1)!=0)
		{	CheckDlgButton(hDlg,15501,BST_CHECKED);
		}
		else
		{	CheckDlgButton(hDlg,15502,BST_CHECKED);
			tmpOptions->EnforceDistinctSubnets |= 2;
		}
		if((tmpOptions->EnforceDistinctSubnets&4)!=0)
		{	CheckDlgButton(hDlg,15410,BST_CHECKED);
		}
		if(tmpOptions->FastFirstHopPK)	CheckDlgButton(hDlg,15406,BST_CHECKED);
		if(tmpOptions->FetchUselessDescriptors)	CheckDlgButton(hDlg,15407,BST_CHECKED);
		SendDlgItemMessage(hDlg,15500,TBM_SETRANGE,1,MAKELONG(1,10));
		SendDlgItemMessage(hDlg,15500,TBM_SETPOS,1,tmpOptions->CircuitPathLength);
		if(tmpOptions->CircuitPathLength < 2)	EnableWindow(GetDlgItem(hDlg,15406),0);
		show_favorites();
	}
	else if(uMsg==WM_COMMAND)
	{
		if((LOWORD(wParam)>=15400)&&(LOWORD(wParam)<=15404))
		{	tmpOptions->_AllowInvalid=0;
			char *tmp1=tor_malloc(32768),*tmp2;
			if(tmpOptions->AllowInvalidNodes)
			{	SMARTLIST_FOREACH(tmpOptions->AllowInvalidNodes, char *, cp, tor_free(cp));
				smartlist_clear(tmpOptions->AllowInvalidNodes);
			}
			else	tmpOptions->AllowInvalidNodes=smartlist_create();
			tmp2=tmp1;
			if(IsDlgButtonChecked(hDlg,15400)==BST_CHECKED){	*tmp2++='e';*tmp2++='n';*tmp2++='t';*tmp2++='r';*tmp2++='y';}
			if(IsDlgButtonChecked(hDlg,15401)==BST_CHECKED){	if(tmp1!=tmp2) *tmp2++=',';*tmp2++='e';*tmp2++='x';*tmp2++='i';*tmp2++='t';}
			if(IsDlgButtonChecked(hDlg,15402)==BST_CHECKED){	if(tmp1!=tmp2) *tmp2++=',';*tmp2++='m';*tmp2++='i';*tmp2++='d';*tmp2++='d';*tmp2++='l';*tmp2++='e';}
			if(IsDlgButtonChecked(hDlg,15404)==BST_CHECKED){	if(tmp1!=tmp2) *tmp2++=',';*tmp2++='i';*tmp2++='n';*tmp2++='t';*tmp2++='r';*tmp2++='o';*tmp2++='d';*tmp2++='u';*tmp2++='c';*tmp2++='t';*tmp2++='i';*tmp2++='o';*tmp2++='n';}
			if(IsDlgButtonChecked(hDlg,15403)==BST_CHECKED){	if(tmp1!=tmp2) *tmp2++=',';*tmp2++='r';*tmp2++='e';*tmp2++='n';*tmp2++='d';*tmp2++='e';*tmp2++='z';*tmp2++='v';*tmp2++='o';*tmp2++='u';*tmp2++='s';}
			smartlist_split_string(tmpOptions->AllowInvalidNodes, tmp1, ",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
			tor_free(tmp1);
		}
		else if(LOWORD(wParam)==15405)
		{	if(IsDlgButtonChecked(hDlg,15405)==BST_CHECKED)
			{	tmpOptions->EnforceDistinctSubnets&=0xfffc;
				if(IsDlgButtonChecked(hDlg,15501)==BST_CHECKED)	tmpOptions->EnforceDistinctSubnets|=1;
				else if(IsDlgButtonChecked(hDlg,15502)==BST_CHECKED)	tmpOptions->EnforceDistinctSubnets|=2;
				else
				{	tmpOptions->EnforceDistinctSubnets|=1;
					CheckDlgButton(hDlg,15501,BST_CHECKED);
				}
				EnableWindow(GetDlgItem(hDlg,15501),1);EnableWindow(GetDlgItem(hDlg,15502),1);
			}
			else
			{	tmpOptions->EnforceDistinctSubnets&=0xfffc;
				EnableWindow(GetDlgItem(hDlg,15501),0);EnableWindow(GetDlgItem(hDlg,15502),0);
			}
		}
		else if(LOWORD(wParam)==15501)
		{	if(IsWindowEnabled(GetDlgItem(hDlg,15501)) && IsDlgButtonChecked(hDlg,15501))
			{	tmpOptions->EnforceDistinctSubnets|=1;
				tmpOptions->EnforceDistinctSubnets&=0xfffd;
			}
			else
			{	tmpOptions->EnforceDistinctSubnets&=0xfffe;
				tmpOptions->EnforceDistinctSubnets|=2;
			}
		}
		else if(LOWORD(wParam)==15502)
		{	if(IsWindowEnabled(GetDlgItem(hDlg,15502)) && IsDlgButtonChecked(hDlg,15502))
			{	tmpOptions->EnforceDistinctSubnets|=2;
				tmpOptions->EnforceDistinctSubnets&=0xfffe;
			}
			else
			{	tmpOptions->EnforceDistinctSubnets&=0xfffd;
				tmpOptions->EnforceDistinctSubnets|=1;
			}
		}
		else if(LOWORD(wParam)==15410)
		{	if(IsDlgButtonChecked(hDlg,15410)==BST_CHECKED)	tmpOptions->EnforceDistinctSubnets|=4;
			else tmpOptions->EnforceDistinctSubnets&=0xfffb;
		}
		else if(LOWORD(wParam)==15406)
		{	if(IsDlgButtonChecked(hDlg,15406)==BST_CHECKED)	tmpOptions->FastFirstHopPK=1;
			else	tmpOptions->FastFirstHopPK=0;
		}
		else if(LOWORD(wParam)==15407)
		{	if(IsDlgButtonChecked(hDlg,15407)==BST_CHECKED)	tmpOptions->FetchUselessDescriptors=1;
			else	tmpOptions->FetchUselessDescriptors=0;
		}
	}
	else if(uMsg==WM_HSCROLL)
	{	HWND h = GetDlgItem(hDlg,15500);
		if(lParam==(LPARAM)h)
		{	int i = tmpOptions->CircuitPathLength;
			tmpOptions->CircuitPathLength=SendDlgItemMessage(hDlg,15500,TBM_GETPOS,0,0);
			char *tmp1=tor_malloc(50);tor_snprintf(tmp1,50,get_lang_str(LANG_DLG_CIRCUIT_LENGTH_ROUTERS),tmpOptions->CircuitPathLength);
			SetDlgItemTextL(hDlg,15004,tmp1);tor_free(tmp1);
			if(i!=tmpOptions->CircuitPathLength)
			{	if(i == 1)				EnableWindow(GetDlgItem(hDlg,15406),1);
				if(tmpOptions->CircuitPathLength < 2)	EnableWindow(GetDlgItem(hDlg,15406),0);
			}
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

void dlgRouterRestrictions_langUpdate(void)
{	if(hDlgRouterRestrictions)
	{	changeDialogStrings(hDlgRouterRestrictions,lang_dlg_router_restrictions);
		char *langTmp=tor_malloc(150);tor_snprintf(langTmp,150,get_lang_str(LANG_DLG_CIRCUIT_LENGTH_ROUTERS),tmpOptions->CircuitPathLength);
		SetDlgItemTextL(hDlgRouterRestrictions,15004,langTmp);tor_free(langTmp);
	}
}

int __stdcall dlgRouterBans(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgRouterBans=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_router_bans);
		}
		if(tmpOptions->IdentityFlags&IDENTITY_FLAG_AVOID_GEOIP_BANS)
			CheckDlgButton(hDlg,15400,BST_CHECKED);
		SendDlgItemMessage(hDlg,15100,EM_LIMITTEXT,65535,0);
		show_bans();
	}
	else if(uMsg==WM_COMMAND)
	{	if((LOWORD(wParam)==15100)&&(HIWORD(wParam)==EN_CHANGE))
			refreshBannedNodes();
		else if(LOWORD(wParam)==15400)
		{	if(IsDlgButtonChecked(hDlg,15400)==BST_CHECKED)	tmpOptions->IdentityFlags|=IDENTITY_FLAG_AVOID_GEOIP_BANS;
			else	tmpOptions->IdentityFlags&=0xffff^IDENTITY_FLAG_AVOID_GEOIP_BANS;
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

int __stdcall dlgRouterFavorites(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlgRouterFavorites=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_router_favorites);
		}
		if(tmpOptions->StrictEntryNodes)	CheckDlgButton(hDlg,15408,BST_CHECKED);
		if(tmpOptions->StrictExitNodes){	CheckDlgButton(hDlg,15409,BST_CHECKED);EnableWindow(GetDlgItem(hDlg,15010),0);EnableWindow(GetDlgItem(hDlg,15503),0);}
		SendDlgItemMessage(hDlg,15101,EM_LIMITTEXT,65535,0);
		show_favorites();
		SendDlgItemMessage(hDlg,15503,TBM_SETRANGE,1,MAKELONG(0,100));
		SendDlgItemMessage(hDlg,15503,TBM_SETPOS,1,tmpOptions->FavoriteExitNodesPriority);
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==15408)
		{	if(IsDlgButtonChecked(hDlg,15408)==BST_CHECKED)	tmpOptions->StrictEntryNodes=1;
			else	tmpOptions->StrictEntryNodes=0;
		}
		else if(LOWORD(wParam)==15409)
		{	if(IsDlgButtonChecked(hDlg,15409)==BST_CHECKED)
			{	tmpOptions->StrictExitNodes=1;EnableWindow(GetDlgItem(hDlg,15010),0);EnableWindow(GetDlgItem(hDlg,15503),0);}
			else
			{	tmpOptions->StrictExitNodes=0;EnableWindow(GetDlgItem(hDlg,15010),1);EnableWindow(GetDlgItem(hDlg,15503),1);}
		}
		else if((LOWORD(wParam)==15101)&&(HIWORD(wParam)==EN_CHANGE))
			refreshFavoriteNodes();
	}
	else if(uMsg==WM_HSCROLL)
	{	HWND h = GetDlgItem(hDlg,15503);
		 if(lParam==(LPARAM)h)
			tmpOptions->FavoriteExitNodesPriority=SendDlgItemMessage(hDlg,15503,TBM_GETPOS,0,0);
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
