#include "or.h"
#include "dlg_util.h"
#include "connection_edge.h"
#include "config.h"
#include "circuitbuild.h"
#include "relay.h"

HWND hDlgCircuitBuild=NULL;
extern HWND hMainDialog;

//int frame6[]={14400,14100,14401,14101,14402,14102,14403,14103,14404,14104,14050,14051,14106,14107,14408,14108,14409,14109,14410,14110,14300,14001,-1};
lang_dlg_info lang_dlg_circuitbuild[]={
	{14412,LANG_DLG_LEARN_CIRC_BUILD_TIMEOUT},
	{14400,LANG_DLG_CIRCUIT_BUILD_TIMEOUT},
	{14401,LANG_DLG_CIRCUIT_IDLE_TIMEOUT},
	{14413,LANG_DLG_CIRC_STREAM_TIMEOUT},
	{14414,LANG_DLG_CELL_SCALE_FACTOR},
	{14402,LANG_DLG_MAXIMUM_PREDICTED_CIRCS},
	{14403,LANG_DLG_CIRCUIT_BUILD_PERIOD},
	{14404,LANG_DLG_CIRCUIT_EXPIRATION},
	{14411,LANG_DLG_CIRCUIT_BUILD_BANDWIDTH},
	{14410,LANG_DLG_ENTRY_GUARDS_USE},
	{14001,LANG_DLG_ENTRY_GUARDS_REINIT},
	{14051,LANG_DLG_NODE_FAMILIES},
	{0,0}
};

extern or_options_t *tmpOptions;
extern smartlist_t *entry_guards;

int __stdcall dlgCircuitBuild(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void setbandwidthval(HWND hDlg,uint64_t bwrate,int checkbox,int editbox,int combo);

void addentryguards(void)
{	if(!hDlgCircuitBuild) return;
	SendDlgItemMessage(hDlgCircuitBuild,14300,CB_RESETCONTENT,0,0);
	if(entry_guards)
		SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
		{	SendDlgItemMessage(hDlgCircuitBuild,14300,CB_ADDSTRING,0,(LPARAM)(entry->nickname));
		});
}

int __stdcall dlgCircuitBuild(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgCircuitBuild=hDlg;
		if(LangGetLanguage())
		{	changeDialogStrings(hDlg,lang_dlg_circuitbuild);
		}
		if(tmpOptions->LearnCircuitBuildTimeout)	CheckDlgButton(hDlg,14412,BST_CHECKED);
		SetDlgItemInt(hDlg,14100,tmpOptions->CircuitBuildTimeout,0);
		SetDlgItemInt(hDlg,14101,tmpOptions->CircuitIdleTimeout,0);
		SetDlgItemInt(hDlg,14108,tmpOptions->CircuitStreamTimeout,0);
		SetDlgItemInt(hDlg,14102,tmpOptions->MaxUnusedOpenCircuits,0);
		SetDlgItemInt(hDlg,14103,tmpOptions->NewCircuitPeriod,0);
		SetDlgItemInt(hDlg,14104,tmpOptions->MaxCircuitDirtiness,0);
		SetDlgItemInt(hDlg,14110,tmpOptions->NumEntryGuards,0);
		unsigned char *str;tor_asprintf(&str,"%.04f",tmpOptions->CircuitPriorityHalflife);SetDlgItemText(hDlg,14109,(char *)str);tor_free(str);
		if(tmpOptions->CircuitBuildTimeout){ CheckDlgButton(hDlg,14400,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14100),0);
		if(tmpOptions->CircuitIdleTimeout){ CheckDlgButton(hDlg,14401,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14101),0);
		if(tmpOptions->CircuitStreamTimeout){ CheckDlgButton(hDlg,14413,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14108),0);
		if(tmpOptions->MaxUnusedOpenCircuits){ CheckDlgButton(hDlg,14402,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14102),0);
		if(tmpOptions->NewCircuitPeriod){ CheckDlgButton(hDlg,14403,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14103),0);
		if(tmpOptions->MaxCircuitDirtiness){ CheckDlgButton(hDlg,14404,BST_CHECKED);}
		else	EnableWindow(GetDlgItem(hDlg,14104),0);
		if(tor_lround(tmpOptions->CircuitPriorityHalflife)!=0)	CheckDlgButton(hDlg,14414,BST_CHECKED);
		else	EnableWindow(GetDlgItem(hDlg,14109),0);
		initmemunits(hDlg,14301);
		setbandwidthval(hDlg,tmpOptions->CircuitBandwidthRate,14411,14105,14301);
		if(tmpOptions->UseEntryGuards){ CheckDlgButton(hDlg,14410,BST_CHECKED);}
		else{	EnableWindow(GetDlgItem(hDlg,14110),0);EnableWindow(GetDlgItem(hDlg,14300),0);EnableWindow(GetDlgItem(hDlg,14001),0);}
		setEditData(hDlg,14107,tmpOptions->NodeFamilies);
		addentryguards();
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==14400)
		{	if(IsDlgButtonChecked(hDlg,14400)==BST_CHECKED)
			{	tmpOptions->CircuitBuildTimeout=GetDlgItemInt(hDlg,14100,0,0);EnableWindow(GetDlgItem(hDlg,14100),1);
			}
			else
			{	tmpOptions->CircuitBuildTimeout=0;EnableWindow(GetDlgItem(hDlg,14100),0);
			}
		}
		else if(LOWORD(wParam)==14401)
		{	if(IsDlgButtonChecked(hDlg,14401)==BST_CHECKED)
			{	tmpOptions->CircuitIdleTimeout=GetDlgItemInt(hDlg,14101,0,0);EnableWindow(GetDlgItem(hDlg,14101),1);
			}
			else
			{	tmpOptions->CircuitIdleTimeout=0;EnableWindow(GetDlgItem(hDlg,14101),0);
			}
		}
		else if(LOWORD(wParam)==14402)
		{	if(IsDlgButtonChecked(hDlg,14402)==BST_CHECKED)
			{	tmpOptions->MaxUnusedOpenCircuits=GetDlgItemInt(hDlg,14102,0,0);EnableWindow(GetDlgItem(hDlg,14102),1);
			}
			else
			{	tmpOptions->MaxUnusedOpenCircuits=0;EnableWindow(GetDlgItem(hDlg,14102),0);
			}
		}
		else if(LOWORD(wParam)==14403)
		{	if(IsDlgButtonChecked(hDlg,14403)==BST_CHECKED)
			{	tmpOptions->NewCircuitPeriod=GetDlgItemInt(hDlg,14103,0,0);EnableWindow(GetDlgItem(hDlg,14103),1);
			}
			else
			{	tmpOptions->NewCircuitPeriod=0;EnableWindow(GetDlgItem(hDlg,14103),0);
			}
		}
		else if(LOWORD(wParam)==14404)
		{	if(IsDlgButtonChecked(hDlg,14404)==BST_CHECKED)
			{	tmpOptions->MaxCircuitDirtiness=GetDlgItemInt(hDlg,14104,0,0);EnableWindow(GetDlgItem(hDlg,14104),1);
			}
			else
			{	tmpOptions->MaxCircuitDirtiness=0;EnableWindow(GetDlgItem(hDlg,14104),0);
			}
		}
		else if(LOWORD(wParam)==14410)
		{	if(IsDlgButtonChecked(hDlg,14410)==BST_CHECKED)
			{	tmpOptions->UseEntryGuards=GetDlgItemInt(hDlg,14110,0,0);EnableWindow(GetDlgItem(hDlg,14110),1);EnableWindow(GetDlgItem(hDlg,14300),1);EnableWindow(GetDlgItem(hDlg,14001),1);
			}
			else
			{	tmpOptions->UseEntryGuards=0;EnableWindow(GetDlgItem(hDlg,14110),0);EnableWindow(GetDlgItem(hDlg,14300),0);EnableWindow(GetDlgItem(hDlg,14001),0);
			}
		}
		else if(LOWORD(wParam)==14412)
		{	if(IsDlgButtonChecked(hDlg,14412)==BST_CHECKED)	tmpOptions->LearnCircuitBuildTimeout = 1;
			else						tmpOptions->LearnCircuitBuildTimeout = 0;
		}
		else if(LOWORD(wParam)==14413)
		{	if(IsDlgButtonChecked(hDlg,14413)==BST_CHECKED)
			{	tmpOptions->CircuitStreamTimeout=GetDlgItemInt(hDlg,14108,0,0);EnableWindow(GetDlgItem(hDlg,14108),1);
			}
			else
			{	tmpOptions->CircuitStreamTimeout=0;EnableWindow(GetDlgItem(hDlg,14108),0);
			}
		}
		else if(LOWORD(wParam)==14414)
		{	if(IsDlgButtonChecked(hDlg,14414)==BST_CHECKED)
			{	char *str = tor_malloc(20);
				GetDlgItemTextA(hDlg,14109,str,19);
				tmpOptions->CircuitPriorityHalflife=atof(str);
				tor_free(str);
				EnableWindow(GetDlgItem(hDlg,14109),1);
				cell_ewma_set_scale_factor(tmpOptions,NULL);
			}
			else
			{	tmpOptions->CircuitPriorityHalflife=0;EnableWindow(GetDlgItem(hDlg,14109),0);
			}
		}
		else if((LOWORD(wParam)==14100)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->CircuitBuildTimeout=GetDlgItemInt(hDlg,14100,0,0);
		else if((LOWORD(wParam)==14110)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->NumEntryGuards=GetDlgItemInt(hDlg,14110,0,0);
		else if((LOWORD(wParam)==14101)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->CircuitIdleTimeout=GetDlgItemInt(hDlg,14101,0,0);
		else if((LOWORD(wParam)==14102)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->MaxUnusedOpenCircuits=GetDlgItemInt(hDlg,14102,0,0);
		else if((LOWORD(wParam)==14103)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->NewCircuitPeriod=GetDlgItemInt(hDlg,14103,0,0);
		else if((LOWORD(wParam)==14104)&&(HIWORD(wParam)==EN_CHANGE))
		{	tmpOptions->MaxCircuitDirtiness=GetDlgItemInt(hDlg,14104,0,0);
			if(!tmpOptions->MaxCircuitDirtiness) tmpOptions->MaxCircuitDirtiness++;
		}
		else if((LOWORD(wParam)==14107)&&(HIWORD(wParam)==EN_CHANGE))
		{	getEditData1(hDlg,14107,&tmpOptions->NodeFamilies,"NodeFamilies");
		}
		else if((LOWORD(wParam)==14411)||((LOWORD(wParam)==14105)&&(HIWORD(wParam)==EN_CHANGE))||((LOWORD(wParam)==14301)&&(HIWORD(wParam)==CBN_SELCHANGE)))
		{	if(IsDlgButtonChecked(hDlg,14411)==BST_CHECKED)
			{	EnableWindow(GetDlgItem(hDlg,14105),1);EnableWindow(GetDlgItem(hDlg,14301),1);
				tmpOptions->CircuitBandwidthRate=(uint64_t)GetDlgItemInt(hDlg,14105,0,0)<<SendDlgItemMessage(hDlg,14301,CB_GETITEMDATA,SendDlgItemMessage(hDlg,14301,CB_GETCURSEL,0,0),0);
			}
			else
			{	EnableWindow(GetDlgItem(hDlg,14105),0);EnableWindow(GetDlgItem(hDlg,14301),0);
				tmpOptions->CircuitBandwidthRate=0;
			}
		}
		else if((LOWORD(wParam)==14108)&&(HIWORD(wParam)==EN_CHANGE))
			tmpOptions->CircuitStreamTimeout=GetDlgItemInt(hDlg,14108,0,0);
		else if((LOWORD(wParam)==14109)&&(HIWORD(wParam)==EN_CHANGE))
		{	char *str = tor_malloc(20);
			GetDlgItemTextA(hDlg,14109,str,19);
			tmpOptions->CircuitPriorityHalflife=atof(str);
			tor_free(str);
			EnableWindow(GetDlgItem(hDlg,14109),1);
			cell_ewma_set_scale_factor(tmpOptions,NULL);
		}
		else if(LOWORD(wParam)==14001)
		{	entry_guards_free_all();addentryguards();}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
