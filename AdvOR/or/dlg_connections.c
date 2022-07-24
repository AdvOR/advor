#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "hibernate.h"
#include "policies.h"

HWND hDlgConnections=NULL;
extern or_options_t *tmpOptions;

//int frame1[]={10400,10100,10300,10401,10101,10301,10402,10102,10302,10403,10103,10303,10404,10104,10304,10407,10107,10408,10108,10409,10109,10410,10110,10412,10112,10405,10105,10305,10406,10106,10411,10111,-1};
lang_dlg_info lang_dlg_connections[]={
	{10400,LANG_DLG_BANDWIDTH_RATE},
	{10401,LANG_DLG_BANDWIDTH_BURST},
	{10402,LANG_DLG_ADVERTISED_BANDWIDTH},
	{10403,LANG_DLG_RELAY_BW_RATE},
	{10404,LANG_DLG_RELAY_BW_BURST},
	{10413,LANG_DLG_PER_CONN_BW_RATE},
	{10414,LANG_DLG_PER_CONN_BW_BURST},
	{10405,LANG_DLG_ISP_LIMIT},
	{10406,LANG_DLG_ISP_LIMIT_AVAIL},
	{10411,LANG_DLG_MAX_CONNECTIONS},
	{10412,LANG_DLG_LONG_RUNNING_CONNECTIONS},
	{10407,LANG_DLG_BUFFER_SIZE},
	{10408,LANG_DLG_KEEPALIVE},
	{10409,LANG_DLG_CONN_IP},
	{10410,LANG_DLG_FIREWALL_RESTRICTIONS},
	{0,0}
};

void setbandwidthval(HWND hDlg,uint64_t bwrate,int checkbox,int editbox,int combo);
int __stdcall dlgConnections(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void setbandwidthval(HWND hDlg,uint64_t bwrate,int checkbox,int editbox,int combo)
{	int i=0,j=0;
	if(!bwrate)
	{	CheckDlgButton(hDlg,checkbox,BST_UNCHECKED);
		EnableWindow(GetDlgItem(hDlg,editbox),0);
		EnableWindow(GetDlgItem(hDlg,combo),0);
	}
	else	CheckDlgButton(hDlg,checkbox,BST_CHECKED);
	for(j=0;j<5 && bwrate;j++)
	{	if((bwrate&0x3ff)==0){i++;bwrate/=1024;}
		else	break;}
	SendDlgItemMessage(hDlg,combo,CB_SETCURSEL,i,0);
	i=bwrate&0xffffffff;
	SetDlgItemInt(hDlg,editbox,i,0);
}


int __stdcall dlgConnections(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_connections);
		}
		initmemunits(hDlg,10300);initmemunits(hDlg,10301);initmemunits(hDlg,10302);initmemunits(hDlg,10303);initmemunits(hDlg,10304);initmemunits(hDlg,10305);initmemunits(hDlg,10306);initmemunits(hDlg,10307);
		setbandwidthval(hDlg,tmpOptions->BandwidthRate,10400,10100,10300);
		setbandwidthval(hDlg,tmpOptions->BandwidthBurst,10401,10101,10301);
		setbandwidthval(hDlg,tmpOptions->MaxAdvertisedBandwidth,10402,10102,10302);
		setbandwidthval(hDlg,tmpOptions->RelayBandwidthRate,10403,10103,10303);
		setbandwidthval(hDlg,tmpOptions->RelayBandwidthBurst,10404,10104,10304);
		setbandwidthval(hDlg,tmpOptions->PerConnBWRate,10413,10113,10306);
		setbandwidthval(hDlg,tmpOptions->PerConnBWBurst,10414,10114,10307);
		setbandwidthval(hDlg,tmpOptions->AccountingMax,10405,10105,10305);
		if(tmpOptions->AccountingStart!=NULL){ CheckDlgButton(hDlg,10406,BST_CHECKED);SetDlgItemText(hDlg,10106,tmpOptions->AccountingStart);}
		else	EnableWindow(GetDlgItem(hDlg,10106),0);
		if(tmpOptions->ConstrainedSockets) CheckDlgButton(hDlg,10407,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,10107),0);
		if(tmpOptions->KeepalivePeriod) CheckDlgButton(hDlg,10408,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,10108),0);
		if(tmpOptions->OutboundBindAddress!=NULL){ CheckDlgButton(hDlg,10409,BST_CHECKED);SetDlgItemText(hDlg,10109,tmpOptions->OutboundBindAddress);}
		else	EnableWindow(GetDlgItem(hDlg,10109),0);
		if(tmpOptions->FascistFirewall){ CheckDlgButton(hDlg,10410,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,10110),0);
		if(tmpOptions->ConnLimit){ CheckDlgButton(hDlg,10411,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,10111),0);
		SetDlgItemInt(hDlg,10111,tmpOptions->ConnLimit,0);
		SetDlgItemInt(hDlg,10107,tmpOptions->ConstrainedSockSize,0);
		SetDlgItemInt(hDlg,10108,tmpOptions->KeepalivePeriod,0);
		SendDlgItemMessage(hDlg,10110,EM_LIMITTEXT,65536,0);
		setEditData(hDlg,10110,tmpOptions->ReachableAddresses);
		if(tmpOptions->LongLivedPorts)
		{	char *tmp1=smartlist_join_strings(tmpOptions->LongLivedPorts, ",", 0, NULL);
			SetDlgItemText(hDlg,10112,tmp1);
			tor_free(tmp1);
			CheckDlgButton(hDlg,10412,BST_CHECKED);
		}
		else	EnableWindow(GetDlgItem(hDlg,10112),0);
		if(tmpOptions->AccountingMax==0){EnableWindow(GetDlgItem(hDlg,10406),0);EnableWindow(GetDlgItem(hDlg,10106),0);}
		hDlgConnections=hDlg;
	}
	else if(uMsg==WM_COMMAND && hDlgConnections)
	{
		if((LOWORD(wParam)==10400)||((LOWORD(wParam)==10100)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10300)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10400)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10100),1);EnableWindow(GetDlgItem(hDlg,10300),1);
				tmpOptions->BandwidthRate=(uint64_t)GetDlgItemInt(hDlg,10100,0,0)<<SendDlgItemMessage(hDlg,10300,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10300,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10100),0);EnableWindow(GetDlgItem(hDlg,10300),0);
				tmpOptions->BandwidthRate=0;
			}
		}
		else if((LOWORD(wParam)==10401)||((LOWORD(wParam)==10101)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10301)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10401)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10101),1);EnableWindow(GetDlgItem(hDlg,10301),1);
				tmpOptions->BandwidthBurst=(uint64_t)GetDlgItemInt(hDlg,10101,0,0)<<SendDlgItemMessage(hDlg,10301,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10301,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10101),0);EnableWindow(GetDlgItem(hDlg,10301),0);
				tmpOptions->BandwidthBurst=0;
			}
		}
		else if((LOWORD(wParam)==10402)||((LOWORD(wParam)==10102)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10302)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10402)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10102),1);EnableWindow(GetDlgItem(hDlg,10302),1);
				tmpOptions->MaxAdvertisedBandwidth=(uint64_t)GetDlgItemInt(hDlg,10102,0,0)<<SendDlgItemMessage(hDlg,10302,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10302,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10102),0);EnableWindow(GetDlgItem(hDlg,10302),0);
				tmpOptions->MaxAdvertisedBandwidth=0x10000000000ull;
			}
		}
		else if((LOWORD(wParam)==10403)||((LOWORD(wParam)==10103)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10303)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10403)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10103),1);EnableWindow(GetDlgItem(hDlg,10303),1);
				tmpOptions->RelayBandwidthRate=(uint64_t)GetDlgItemInt(hDlg,10103,0,0)<<SendDlgItemMessage(hDlg,10303,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10303,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10103),0);EnableWindow(GetDlgItem(hDlg,10303),0);
				tmpOptions->RelayBandwidthRate=0;
			}
		}
		else if((LOWORD(wParam)==10404)||((LOWORD(wParam)==10104)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10304)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10404)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10104),1);EnableWindow(GetDlgItem(hDlg,10304),1);
				tmpOptions->RelayBandwidthBurst=(uint64_t)GetDlgItemInt(hDlg,10104,0,0)<<SendDlgItemMessage(hDlg,10304,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10304,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10104),0);EnableWindow(GetDlgItem(hDlg,10304),0);
				tmpOptions->RelayBandwidthBurst=0;
			}
		}
		else if((LOWORD(wParam)==10413)||((LOWORD(wParam)==10113)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10306)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10413)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10113),1);EnableWindow(GetDlgItem(hDlg,10306),1);
				tmpOptions->PerConnBWRate=(uint64_t)GetDlgItemInt(hDlg,10113,0,0)<<SendDlgItemMessage(hDlg,10306,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10306,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10113),0);EnableWindow(GetDlgItem(hDlg,10306),0);
				tmpOptions->PerConnBWRate=0;
			}
		}
		else if((LOWORD(wParam)==10414)||((LOWORD(wParam)==10114)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10307)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,10414)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10114),1);EnableWindow(GetDlgItem(hDlg,10307),1);
				tmpOptions->PerConnBWBurst=(uint64_t)GetDlgItemInt(hDlg,10114,0,0)<<SendDlgItemMessage(hDlg,10307,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10307,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10114),0);EnableWindow(GetDlgItem(hDlg,10307),0);
				tmpOptions->PerConnBWBurst=0;
			}
		}
		else if(LOWORD(wParam)==10405)
		{	if(IsDlgButtonChecked(hDlg,10405)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10105),1);EnableWindow(GetDlgItem(hDlg,10305),1);
				EnableWindow(GetDlgItem(hDlg,10406),1);
				if(IsDlgButtonChecked(hDlg,10406)==BST_CHECKED)	EnableWindow(GetDlgItem(hDlg,10106),1);
				tmpOptions->AccountingMax=(uint64_t)GetDlgItemInt(hDlg,10105,0,0)<<SendDlgItemMessage(hDlg,10305,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10305,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10105),0);EnableWindow(GetDlgItem(hDlg,10305),0);
				EnableWindow(GetDlgItem(hDlg,10406),0);EnableWindow(GetDlgItem(hDlg,10106),0);
				tmpOptions->AccountingMax=0;
			}
		}
		else if(((LOWORD(wParam)==10105)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==10305)&&(HIWORD(wParam)==CBN_SELCHANGE)))
			tmpOptions->AccountingMax=(uint64_t)GetDlgItemInt(hDlg,10105,0,0)<<SendDlgItemMessage(hDlg,10305,CB_GETITEMDATA,SendDlgItemMessage(hDlg,10305,CB_GETCURSEL,0,0),0);
		else if(LOWORD(wParam)==10407)
		{	if(IsDlgButtonChecked(hDlg,10407)==BST_CHECKED)
			{	tmpOptions->ConstrainedSockets=1;EnableWindow(GetDlgItem(hDlg,10107),1);
			}
			else
			{	tmpOptions->ConstrainedSockets=0;EnableWindow(GetDlgItem(hDlg,10107),0);
			}
		}
		else if((LOWORD(wParam)==10107)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->ConstrainedSockSize=GetDlgItemInt(hDlg,10107,0,0);
		else if(LOWORD(wParam)==10411)
		{	if(IsDlgButtonChecked(hDlg,10411)==BST_CHECKED)
			{	tmpOptions->ConnLimit=GetDlgItemInt(hDlg,10111,0,0);EnableWindow(GetDlgItem(hDlg,10111),1);
			}
			else
			{	tmpOptions->ConnLimit=0;EnableWindow(GetDlgItem(hDlg,10111),0);
			}
		}
		else if((LOWORD(wParam)==10111)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->ConnLimit=GetDlgItemInt(hDlg,10111,0,0);
		else if(LOWORD(wParam)==10408)
		{	if(IsDlgButtonChecked(hDlg,10408)==BST_CHECKED)
			{	tmpOptions->KeepalivePeriod=GetDlgItemInt(hDlg,10108,0,0);EnableWindow(GetDlgItem(hDlg,10108),1);
			}
			else
			{	tmpOptions->KeepalivePeriod=0;EnableWindow(GetDlgItem(hDlg,10108),0);
			}
		}
		else if((LOWORD(wParam)==10108)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->KeepalivePeriod=GetDlgItemInt(hDlg,10108,0,0);
		else if((LOWORD(wParam)==10106)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,10106,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,10106,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->AccountingStart;
			tmpOptions->AccountingStart=tmp1;tor_free(tmp2);
			accounting_parse_options(tmpOptions, 0);
			if(accounting_is_enabled(tmpOptions)) configure_accounting(get_time(NULL));
		}
		else if(LOWORD(wParam)==10406)
		{	if(IsDlgButtonChecked(hDlg,10406)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10106),1);
				int tmpsize=SendDlgItemMessage(hDlg,10106,WM_GETTEXTLENGTH,0,0);
				char *tmp1=tor_malloc(tmpsize+2);
				SendDlgItemMessage(hDlg,10106,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
				char *tmp2=tmpOptions->AccountingStart;
				tmpOptions->AccountingStart=tmp1;tor_free(tmp2);
				accounting_parse_options(tmpOptions, 0);
				if(accounting_is_enabled(tmpOptions)) configure_accounting(get_time(NULL));
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10106),0);
				char *tmp1=tmpOptions->AccountingStart;
				tmpOptions->AccountingStart=NULL;tor_free(tmp1);
				accounting_parse_options(tmpOptions, 0);
				if(accounting_is_enabled(tmpOptions)) configure_accounting(get_time(NULL));
			}
		}
		else if((LOWORD(wParam)==10109)&&(HIWORD(wParam)==EN_CHANGE))
		{	
			int tmpsize=SendDlgItemMessage(hDlg,10109,WM_GETTEXTLENGTH,0,0);
			char *tmp1=tor_malloc(tmpsize+2);
			SendDlgItemMessage(hDlg,10109,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			char *tmp2=tmpOptions->OutboundBindAddress;
			tmpOptions->OutboundBindAddress=tmp1;tor_free(tmp2);
		}
		else if((LOWORD(wParam)==10110)&&(HIWORD(wParam)==EN_CHANGE))
		{	int tmpsize=SendDlgItemMessage(hDlg,10110,WM_GETTEXTLENGTH,0,0)+1;
			char *tmp1=tor_malloc(tmpsize+2);
			config_line_t *cfg,**cfg1;
			SendDlgItemMessage(hDlg,10110,WM_GETTEXT,tmpsize+1,(LPARAM)tmp1);
			for(;;)
			{	cfg=tmpOptions->ReachableAddresses;
				if(cfg==NULL) break;
				tor_free(cfg->key);tor_free(cfg->value);
				tor_free(cfg);
				tmpOptions->ReachableAddresses=tmpOptions->ReachableAddresses->next;
			}
			int i,j=0;cfg1=&tmpOptions->ReachableAddresses;
			for(i=0;i<tmpsize;i++)
			{	if((tmp1[i]==13)||(tmp1[i]==10)||(tmp1[i]==0))
				{	if(j!=i)
					{	tmp1[i]=0;
						*cfg1=tor_malloc_zero(sizeof(config_line_t));
						(*cfg1)->key = (unsigned char *)tor_strdup("ReachableAddresses");
						(*cfg1)->value=(unsigned char *)tor_strdup(&tmp1[j]);
						cfg1=&((*cfg1)->next);
					}
					j=i+1;
				}
			}
			tor_free(tmp1);
			policies_parse_from_options(tmpOptions);
		}
		else if(LOWORD(wParam)==10409)
		{	if(IsDlgButtonChecked(hDlg,10409)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10109),1);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10109),0);
				char *tmp1=tmpOptions->OutboundBindAddress;
				tmpOptions->OutboundBindAddress=NULL;tor_free(tmp1);
			}
		}
		else if(LOWORD(wParam)==10410)
		{	if(IsDlgButtonChecked(hDlg,10410)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10110),1);
				tmpOptions->FascistFirewall=1;
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10110),0);
				tmpOptions->FascistFirewall=0;
			}
		}
		else if(LOWORD(wParam)==10407)
		{	if(IsDlgButtonChecked(hDlg,10407)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10107),1);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10107),0);
			}
		}
		else if(LOWORD(wParam)==10408)
		{	if(IsDlgButtonChecked(hDlg,10408)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10108),1);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10108),0);
			}
		}
		else if(LOWORD(wParam)==10409)
		{	if(IsDlgButtonChecked(hDlg,10409)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10109),1);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10109),0);
			}
		}
		else if(LOWORD(wParam)==10410)
		{	if(IsDlgButtonChecked(hDlg,10410)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,10110),1);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,10110),0);
			}
		}
		else if((LOWORD(wParam)==10112)&&(HIWORD(wParam)==EN_CHANGE))
		{	char *tmp1=tor_malloc(32768);
			GetDlgItemText(hDlg,10112,tmp1,32767);
			if(tmpOptions->LongLivedPorts)
			{	SMARTLIST_FOREACH(tmpOptions->LongLivedPorts, char *, cp, tor_free(cp));
				smartlist_clear(tmpOptions->LongLivedPorts);
			}
			else	tmpOptions->LongLivedPorts=smartlist_create();
			smartlist_split_string(tmpOptions->LongLivedPorts, tmp1, ",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
			tor_free(tmp1);
		}
		else if(LOWORD(wParam)==10412)
		{	if(IsDlgButtonChecked(hDlg,10412)==BST_CHECKED)
			{	char *tmp1=tor_malloc(32768);
				GetDlgItemText(hDlg,10112,tmp1,32767);
				if(tmpOptions->LongLivedPorts)
				{	SMARTLIST_FOREACH(tmpOptions->LongLivedPorts, char *, cp, tor_free(cp));
					smartlist_clear(tmpOptions->LongLivedPorts);
				}
				else	tmpOptions->LongLivedPorts=smartlist_create();
				smartlist_split_string(tmpOptions->LongLivedPorts, tmp1, ",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
				tor_free(tmp1);EnableWindow(GetDlgItem(hDlg,10112),1);
			}
			else
			{	if(tmpOptions->LongLivedPorts)
				{	SMARTLIST_FOREACH(tmpOptions->LongLivedPorts, char *, cp, tor_free(cp));
					smartlist_clear(tmpOptions->LongLivedPorts);
				}
				tmpOptions->LongLivedPorts=NULL;
				EnableWindow(GetDlgItem(hDlg,10112),0);
			}
		}
	}
	return 0;
}
