#include "or.h"
#include "dlg_util.h"
#include "connection.h"
#include "router.h"
#include "policies.h"

HWND hDlgServer=NULL;
extern HWND hMainDialog;
int orportpending = -1;
//int frame9[]={17400,17100,17010,17101,17011,17102,17012,17103,17013,17104,17401,17402,17403,17404,17105,17406,17106,17015,17107,17016,17050,17108,17051,17109,17017,17407,17408,17409,17410,17411,17001,-1};
lang_dlg_info lang_dlg_server[]={
	{17400,LANG_DLG_SERVER_PORT},
	{17010,LANG_DLG_SERVER_ADDR},
	{17011,LANG_DLG_SERVER_NICK},
	{17012,LANG_DLG_SERVER_MAIL},
	{17013,LANG_DLG_SERVER_ADV_ADDR},
	{17401,LANG_DLG_SERVER_SELF_TEST},
	{17402,LANG_DLG_SERVER_ACT_AS_BRIDGE},
	{17403,LANG_DLG_SERVER_GEOIP_STATS},
	{17413,LANG_DLG_REFUSE_UNKNOWN_EXITS},
	{17412,LANG_DLG_CIRCUIT_TIMEOUT_EXIT},
	{17406,LANG_DLG_SERVER_MAX_ONIONSKINS},
	{17410,LANG_DLG_RESERVED_03},
	{17411,LANG_DLG_RESERVED_04},
	{17015,LANG_DLG_SERVER_CPUS},
	{17016,LANG_DLG_SERVER_MSG_EXIT},
	{17050,LANG_DLG_SERVER_ACCEPT_POLICY},
	{17051,LANG_DLG_SERVER_REJECT_POLICY},
	{17017,LANG_DLG_SERVER_PUBLISH},
	{17001,LANG_DLG_SERVER_PUBLISH_NOW},
	{0,0}
};

extern int compute_publishserverdescriptor(or_options_t *options);
extern or_options_t *tmpOptions;

const char *acceptstr = "accept ";
const char *rejectstr = "reject ";

void getEditData2(config_line_t **option);
void setEditData1(int editBox,config_line_t **option,BOOL isBanned);
void addpublishoptions(void);
void dlgServerUpdate(void);
int __stdcall dlgServer(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void getEditData2(config_line_t **option)
{	int i,j,k,l,s;
	k=0;
	int tmpsize=SendDlgItemMessage(hDlgServer,17108,WM_GETTEXTLENGTH,0,0) + SendDlgItemMessage(hDlgServer,17109,WM_GETTEXTLENGTH,0,0)+1+1+2;
	char *tmp1=tor_malloc(tmpsize+2);
	config_line_t *cfg,**cfg1;
	for(;;)
	{	cfg=*option;
		if(cfg==NULL) break;
		tor_free(cfg->key);tor_free(cfg->value);
		*option=cfg->next;
		tor_free(cfg);
	}
	j=0;cfg1=option;*cfg1=NULL;
	SendDlgItemMessage(hDlgServer,17108,WM_GETTEXT,tmpsize,(LPARAM)tmp1);
	s=strlen(tmp1);
	for(i=0;i<s+1;i++)
	{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==0))
		{	if(j!=i)
			{	if((tmp1[j]=='*')&&(tmp1[j+1]==':')&&(tmp1[j+2]=='*'))
					k=1;
				else
				{
					tmp1[i]=0;
					*cfg1=tor_malloc_zero(sizeof(config_line_t));
					(*cfg1)->key = (unsigned char *)tor_strdup("ExitPolicy");
					l = strlen(&tmp1[j]);
					(*cfg1)->value=tor_malloc(l+7+2);
					memmove(&(*cfg1)->value[0],acceptstr,7);
					memmove(&(*cfg1)->value[7],&tmp1[j],l+1);
					cfg1=&((*cfg1)->next);
				}
			}
			j=i+1;
		}
	}
	SendDlgItemMessage(hDlgServer,17109,WM_GETTEXT,tmpsize,(LPARAM)tmp1);
	s=strlen(tmp1);
	for(i=0,j=0;i<s+1;i++)
	{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==0))
		{	if(j!=i)
			{	tmp1[i]=0;
				*cfg1=tor_malloc_zero(sizeof(config_line_t));
				(*cfg1)->key = (unsigned char *)tor_strdup("ExitPolicy");
				l = strlen(&tmp1[j]);
				(*cfg1)->value=tor_malloc(l+7+2);
				memmove(&(*cfg1)->value[0],rejectstr,7);
				memmove(&(*cfg1)->value[7],&tmp1[j],l+1);
				cfg1=&((*cfg1)->next);
			}
			j=i+1;
		}
	}
	if(k)
	{
		*cfg1=tor_malloc_zero(sizeof(config_line_t));
		(*cfg1)->key = (unsigned char *)tor_strdup("ExitPolicy");
		(*cfg1)->value=(unsigned char *)tor_strdup("accept *:*");
	}
	tor_free(tmp1);
}


void setEditData1(int editBox,config_line_t **option,BOOL isBanned)
{	int j;
	if(*option==NULL)
	{	LangEnterCriticalSection();
		*option=tor_malloc_zero(sizeof(config_line_t));
		(*option)->key = (unsigned char *)tor_strdup("ExitPolicy");
		(*option)->value=(unsigned char *)tor_strdup("accept *:*");
		LangLeaveCriticalSection();
	}
	if(*option!=NULL)
	{	char *tmp1=tor_malloc(65536),*tmp2;
		int i=0;tmp2=tmp1;
		config_line_t *cfg;
		for(cfg=*option;cfg;cfg=cfg->next)
		{	if(isBanned)
			{	j=0;
				while(1)
				{
					if(!strcasecmpstart((char *)&cfg->value[j],"reject"))
					{	j+=6;
						for(;cfg->value[j]==32;j++)	;
						for(;i<65530;i++,j++)
						{	if((!cfg->value[j])||(cfg->value[j]<32)||(cfg->value[j]==',')||(cfg->value[j]==';')) break;
							*tmp1++=cfg->value[j];
						}
						*tmp1++=13;*tmp1++=10;i+=2;
						if(i>65530) break;
					}
					else
					{
						for(;;j++)
						{	if((!cfg->value[j])||(cfg->value[j]<32)||(cfg->value[j]==',')||(cfg->value[j]==';')) break;
						}
					}
					while((cfg->value[j]==',')||(cfg->value[j]==';')||(cfg->value[j]<33))
					{
						if(!cfg->value[j]) break;
						j++;
					}
					if(!cfg->value[j]) break;
				}
			}
			else
			{
				j=0;
				while(1)
				{
					if(!strcasecmpstart((char *)&cfg->value[j],"reject"))
					{
						for(;;j++)
						{	if((!cfg->value[j])||(cfg->value[j]<32)||(cfg->value[j]==',')||(cfg->value[j]==';')) break;
						}
					}
					else
					{
						if(!strcasecmpstart((char *)&cfg->value[j],"accept"))
						{
							j+=6;
							for(;cfg->value[j]==32;j++)	;
						}
						for(;i<65530;i++,j++)
						{	if((!cfg->value[j])||(cfg->value[j]<32)||(cfg->value[j]==',')||(cfg->value[j]==';')) break;
							*tmp1++=cfg->value[j];
						}
						*tmp1++=13;*tmp1++=10;i+=2;
						if(i>65530) break;
					}
					while((cfg->value[j]==',')||(cfg->value[j]==';')||(cfg->value[j]<33))
					{
						if(!cfg->value[j]) break;
						j++;
					}
					if(!cfg->value[j]) break;
				}
			}
		}
		*tmp1=0;
		SetDlgItemText(hDlgServer,editBox,tmp2);
		tor_free(tmp2);
		cfg=NULL;
	}
}

void addpublishoptions(void)
{	int notbridge = 0;
	if(tmpOptions->PublishServerDescriptor)
	{
		SMARTLIST_FOREACH(tmpOptions->PublishServerDescriptor, char *, s,{tor_free(s);});
		smartlist_clear(tmpOptions->PublishServerDescriptor);
		smartlist_free(tmpOptions->PublishServerDescriptor);
		tmpOptions->PublishServerDescriptor = NULL;
	}
	if(!tmpOptions->PublishServerDescriptor)	tmpOptions->PublishServerDescriptor=smartlist_create();
	if(IsDlgButtonChecked(hDlgServer,17407)){	smartlist_add(tmpOptions->PublishServerDescriptor,tor_strdup("v1"));notbridge = 1;}
	if(IsDlgButtonChecked(hDlgServer,17408)){	smartlist_add(tmpOptions->PublishServerDescriptor,tor_strdup("v2"));notbridge = 1;}
	if(IsDlgButtonChecked(hDlgServer,17409)){	smartlist_add(tmpOptions->PublishServerDescriptor,tor_strdup("v3"));notbridge = 1;}
	if(IsDlgButtonChecked(hDlgServer,17410))
	{	if(notbridge)	CheckDlgButton(hDlgServer,17410,BST_UNCHECKED);
		else		smartlist_add(tmpOptions->PublishServerDescriptor,tor_strdup("bridge"));
	}
	if(IsDlgButtonChecked(hDlgServer,17411))	smartlist_add(tmpOptions->PublishServerDescriptor,tor_strdup("hidserv"));
	compute_publishserverdescriptor(tmpOptions);
}

BOOL dlgServerInit=0;
int dlgServerChanged=0;

void dlgServerUpdate(void)
{	if(!dlgServerChanged) return;
	int i;
	switch(dlgServerChanged)
	{	case 1:
			if(orportpending != -1)
			{	tmpOptions->ORPort = orportpending;
				orportpending = -1;
			}
			init_keys();retry_all_listeners(0,0);
			break;
		case 2:
			policies_parse_from_options(tmpOptions);
			break;
		case 3:
			i=tmpOptions->ORPort;if(!tmpOptions->ORPort)	tmpOptions->ORPort=9501;
			init_keys();router_rebuild_descriptor(0);router_upload_dir_desc_to_dirservers(1);
			tmpOptions->ORPort=i;
			break;
		default:
			break;
	}
	dlgServerChanged = 0;
}

int __stdcall dlgServer(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgServer=hDlg;
		dlgServerInit=1;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_server);
		}
		if(tmpOptions->Nickname) SetDlgItemText(hDlg,17102,tmpOptions->Nickname);
		if(tmpOptions->ContactInfo) SetDlgItemText(hDlg,17103,tmpOptions->ContactInfo);
		if(tmpOptions->Address) SetDlgItemText(hDlg,17104,tmpOptions->Address);
		if(tmpOptions->ORPort){ CheckDlgButton(hDlg,17400,BST_CHECKED);SetDlgItemInt(hDlg,17100,tmpOptions->ORPort,0);}
		else{	EnableWindow(GetDlgItem(hDlg,17100),0);EnableWindow(GetDlgItem(hDlg,17010),0);EnableWindow(GetDlgItem(hDlg,17101),0);}
		if(tmpOptions->ORListenAddress)	SetDlgItemText(hDlg,17101,(LPCSTR)tmpOptions->ORListenAddress->value);
		else SetDlgItemText(hDlg,17101,"127.0.0.1");
		if(tmpOptions->ShutdownWaitLength){ CheckDlgButton(hDlg,17412,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,17110),0);
		if(tmpOptions->MaxOnionsPending){	SetDlgItemInt(hDlg,17106,tmpOptions->MaxOnionsPending,0);CheckDlgButton(hDlg,17406,BST_CHECKED);}
		else{	EnableWindow(GetDlgItem(hDlg,17106),0);EnableWindow(GetDlgItem(hDlg,17015),0);EnableWindow(GetDlgItem(hDlg,17107),0);}
		SetDlgItemInt(hDlg,17107,tmpOptions->NumCpus,0);
		SendDlgItemMessage(hDlg,17108,EM_LIMITTEXT,65536,0);
		setEditData1(17108,&tmpOptions->ExitPolicy,0);
		SendDlgItemMessage(hDlg,17109,EM_LIMITTEXT,65536,0);
		setEditData1(17109,&tmpOptions->ExitPolicy,1);
		SetDlgItemInt(hDlg,17110,tmpOptions->ShutdownWaitLength,0);
		if(tmpOptions->AssumeReachable)	CheckDlgButton(hDlg,17401,BST_CHECKED);
		if(tmpOptions->RefuseUnknownExits_ == 1) CheckDlgButton(hDlg,17413,BST_CHECKED);
		else if(tmpOptions->RefuseUnknownExits_ == -1) CheckDlgButton(hDlg,17413,BST_INDETERMINATE);
		if(tmpOptions->BridgeRelay)	CheckDlgButton(hDlg,17402,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,17403),0);
		if(tmpOptions->BridgeRecordUsageByCountry)	CheckDlgButton(hDlg,17403,BST_CHECKED);
		if(tmpOptions->PublishServerDescriptor)
		{	SMARTLIST_FOREACH(tmpOptions->PublishServerDescriptor,const char *,string,{
				if(!strcasecmp(string, "v1"))	CheckDlgButton(hDlg,17407,BST_CHECKED);
				else if(!strcmp(string, "1"))
				{	if(tmpOptions->BridgeRelay) CheckDlgButton(hDlg,17410,BST_CHECKED);
					else{	CheckDlgButton(hDlg,17408,BST_CHECKED);CheckDlgButton(hDlg,17409,BST_CHECKED);}
				}
				else if(!strcasecmp(string, "v2"))	CheckDlgButton(hDlg,17408,BST_CHECKED);
				else if(!strcasecmp(string, "v3"))	CheckDlgButton(hDlg,17409,BST_CHECKED);
				else if(!strcasecmp(string, "bridge"))	CheckDlgButton(hDlg,17410,BST_CHECKED);
				else if(!strcasecmp(string, "hidserv"))	CheckDlgButton(hDlg,17411,BST_CHECKED);
			});
		}
		dlgServerInit=0;
	}
	else if(uMsg==WM_COMMAND && !dlgServerInit)
	{
		if(LOWORD(wParam)==17406)
		{	if(IsDlgButtonChecked(hDlg,17406)==BST_CHECKED)
			{	tmpOptions->MaxOnionsPending=GetDlgItemInt(hDlg,17106,0,0);EnableWindow(GetDlgItem(hDlg,17106),1);EnableWindow(GetDlgItem(hDlg,17015),1);EnableWindow(GetDlgItem(hDlg,17107),1);
			}
			else
			{	tmpOptions->MaxOnionsPending=0;EnableWindow(GetDlgItem(hDlg,17106),0);EnableWindow(GetDlgItem(hDlg,17015),0);EnableWindow(GetDlgItem(hDlg,17107),0);
			}
		}
		else if((LOWORD(wParam)==17106)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->MaxOnionsPending=GetDlgItemInt(hDlg,17106,0,0);
		else if((LOWORD(wParam)==17107)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->NumCpus=GetDlgItemInt(hDlg,17107,0,0);
		else if((LOWORD(wParam)==17102)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,17102,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,17102,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->Nickname;
			tmpOptions->Nickname=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==17103)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,17103,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,17103,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->ContactInfo;
			tmpOptions->ContactInfo=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==17104)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,17104,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,17104,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->Address;
			if(*tmp1) tmpOptions->Address=tmp1;
			else tmpOptions->Address=NULL;
			tor_free(tmp2);
		}
		else if(LOWORD(wParam)==17400)
		{	if(IsDlgButtonChecked(hDlg,17400)==BST_CHECKED)
			{	orportpending=GetDlgItemInt(hDlg,17100,0,0);
				EnableWindow(GetDlgItem(hDlg,17100),1);EnableWindow(GetDlgItem(hDlg,17010),1);EnableWindow(GetDlgItem(hDlg,17101),1);
			}
			else
			{	orportpending=0; EnableWindow(GetDlgItem(hDlg,17100),0);EnableWindow(GetDlgItem(hDlg,17010),0);EnableWindow(GetDlgItem(hDlg,17101),0);
			}
			dlgServerChanged = 1;
		}
		else if(LOWORD(wParam)==17412)
		{	if(IsDlgButtonChecked(hDlg,17412)==BST_CHECKED)
			{	tmpOptions->ShutdownWaitLength=GetDlgItemInt(hDlg,17110,0,0);EnableWindow(GetDlgItem(hDlg,17110),1);
			}
			else
			{	tmpOptions->ShutdownWaitLength=0;EnableWindow(GetDlgItem(hDlg,17110),0);
			}
		}
		else if(LOWORD(wParam)==17413)
		{	char *tmp1 = tmpOptions->RefuseUnknownExits;
			if(IsDlgButtonChecked(hDlg,17413)==BST_CHECKED)
			{	tmpOptions->RefuseUnknownExits_ = 1;
				tmpOptions->RefuseUnknownExits = tor_strdup("1");
			}
			else if(IsDlgButtonChecked(hDlg,17413)==BST_UNCHECKED)
			{	tmpOptions->RefuseUnknownExits_ = 0;
				tmpOptions->RefuseUnknownExits = tor_strdup("0");
			}
			else
			{	tmpOptions->RefuseUnknownExits_ = -1;
				tmpOptions->RefuseUnknownExits = tor_strdup("auto");
			}
			tor_free(tmp1);
		}
		else if((LOWORD(wParam)==17100)&&(HIWORD(wParam)==EN_CHANGE))
		{	orportpending=GetDlgItemInt(hDlg,17100,0,0);
			dlgServerChanged = 1;
		}
		else if((LOWORD(wParam)==17101)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData(hDlg,17101,&tmpOptions->ORListenAddress,"ORListenAddress");
			dlgServerChanged = 1;
		}
		else if((LOWORD(wParam)==17110)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->ShutdownWaitLength=GetDlgItemInt(hDlg,17110,0,0);
		else if(((LOWORD(wParam)==17108)||(LOWORD(wParam)==17109))&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData2(&tmpOptions->ExitPolicy);
			dlgServerChanged = 2;
		}
		else if(LOWORD(wParam)==17401)
		{	if(IsDlgButtonChecked(hDlg,17401)==BST_CHECKED)	tmpOptions->AssumeReachable=1;
			else	tmpOptions->AssumeReachable=0;
		}
		else if(LOWORD(wParam)==17402)
		{	if(IsDlgButtonChecked(hDlg,17402)==BST_CHECKED){	tmpOptions->BridgeRelay=1;EnableWindow(GetDlgItem(hDlg,17403),1);}
			else{	tmpOptions->BridgeRelay=0;EnableWindow(GetDlgItem(hDlg,17403),0);}
		}
		else if(LOWORD(wParam)==17403)
		{	if(IsDlgButtonChecked(hDlg,17403)==BST_CHECKED)	tmpOptions->BridgeRecordUsageByCountry=1;
			else	tmpOptions->BridgeRecordUsageByCountry=0;
		}
		else if(LOWORD(wParam)==17001)
		{	dlgServerChanged = 3;
		}
		else if((LOWORD(wParam)>=17407)&&(LOWORD(wParam)<=17411))
		{	if(LOWORD(wParam) == 17407 || LOWORD(wParam) == 17408 || LOWORD(wParam) == 17409)
			{	if(IsDlgButtonChecked(hDlg,17410) == BST_CHECKED)	CheckDlgButton(hDlg,17410,0);}
			else if(LOWORD(wParam) == 17410)
			{	if(IsDlgButtonChecked(hDlg,17407) == BST_CHECKED)	CheckDlgButton(hDlg,17407,0);
				if(IsDlgButtonChecked(hDlg,17408) == BST_CHECKED)	CheckDlgButton(hDlg,17408,0);
				if(IsDlgButtonChecked(hDlg,17409) == BST_CHECKED)	CheckDlgButton(hDlg,17409,0);
			}
			addpublishoptions();}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}

