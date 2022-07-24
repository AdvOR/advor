#include "or.h"
#include "dlg_util.h"
#include "plugins.h"

HWND hDlgPlugins=NULL;
LV_ITEMW lvit;
plugin_info_t *tmp_plugin;
extern HWND hMainDialog;
extern or_options_t *tmpOptions;
extern HINSTANCE hInstance;
//int frame14[]={26400,26001,26002,26003,26004,26005,26006,26007,-1};
lang_dlg_info lang_dlg_plugins[]={
	{26001,LANG_PLUGINS_RESCAN},
	{26002,LANG_PLUGINS_REMOVE},
	{26003,LANG_PLUGINS_RELOAD},
	{26004,LANG_PLUGINS_UNLOAD},
	{26005,LANG_PLUGINS_RIGHTS},
	{0,0}
};

lang_dlg_info lang_dlg_pr[]={
	{400,LANG_PLUGINS_RIGHTS_CONFIG},
	{401,LANG_PLUGINS_RIGHTS_SETTINGS},
	{402,LANG_PLUGINS_RIGHTS_TRAFFIC},
	{403,LANG_PLUGINS_RIGHTS_ADDRMAP},
	{404,LANG_PLUGINS_RIGHTS_CONNECTIONS},
	{405,LANG_PLUGINS_RIGHTS_ACCEPT},
	{406,LANG_PLUGINS_RIGHTS_HS},
	{407,LANG_PLUGINS_RIGHTS_INTERCEPT},
	{1,LANG_PLUGINS_RIGHTS_OK},
	{2,LANG_PLUGINS_RIGHTS_CANCEL},
	{0,0}
};

void refreshPluginList(void);
void updatePluginStatus(int plugin_id,int load_status);
void updatePluginDescription(int plugin_id,char *description);
void selectPlugin(int lastsel);
void dlgPlugins_langUpdate(void);
int __stdcall dlgPlugins(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgPluginRights(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);

void refreshPluginList(void)
{	if(!hDlgPlugins) return;
	plugin_info_t *plugin_list=get_plugin_list();
	int i;
	SendDlgItemMessage(hDlgPlugins,26400,LVM_DELETEALLITEMS,0,0);
	lvit.iItem=0;
	while(plugin_list)
	{	if(plugin_list->rights&PLUGIN_RIGHT__CAN_BE_SHOWN_IN_PLUGIN_LIST)
		{	lvit.iSubItem=0;lvit.mask=LVIF_TEXT|LVIF_PARAM;lvit.state=0;lvit.stateMask=0;lvit.iImage=0;
			lvit.lParam=plugin_list->plugin_id;
			LPWSTR plname = get_unicode(plugin_list->dll_name);
			lvit.pszText=plname;
			lvit.cchTextMax=256;
			i=SendDlgItemMessageW(hDlgPlugins,26400,LVM_INSERTITEMW,0,(LPARAM)&lvit);
			if(i!=-1)
			{	lvit.iItem=i;
				LangSetLVItem(hDlgPlugins,26400,lvit.iItem,1,plugin_list->load_status&PLUGIN_LOADSTATUS_LOADED?get_lang_str(LANG_PLUGINS_STATUS_LOADED):plugin_list->load_status&(PLUGIN_LOADSTATUS_LOAD_ERROR|PLUGIN_LOADSTATUS_INIT_FAILED)?get_lang_str(LANG_PLUGINS_STATUS_ERROR):plugin_list->load_status&PLUGIN_LOADSTATUS_DISABLED?get_lang_str(LANG_PLUGINS_STATUS_DISABLED):get_lang_str(LANG_PLUGINS_STATUS_UNKNOWN));
				LangSetLVItem(hDlgPlugins,26400,lvit.iItem,2,plugin_list->description);
				lvit.iItem++;
			}
			tor_free(plname);
		}
		plugin_list=plugin_list->next_plugin;
	}
}


void updatePluginStatus(int plugin_id,int load_status)
{	if(!hDlgPlugins) return;
	int i=0;
	while(1)
	{	lvit.iItem=i;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
		lvit.lParam=0;
		if(!SendDlgItemMessageW(hDlgPlugins,26400,LVM_GETITEMW,0,(LPARAM)&lvit)) break;
		if(plugin_id==lvit.lParam)
		{	LangSetLVItem(hDlgPlugins,26400,lvit.iItem,1,load_status&PLUGIN_LOADSTATUS_LOADED?get_lang_str(LANG_PLUGINS_STATUS_LOADED):load_status&(PLUGIN_LOADSTATUS_LOAD_ERROR|PLUGIN_LOADSTATUS_INIT_FAILED)?get_lang_str(LANG_PLUGINS_STATUS_ERROR):load_status&PLUGIN_LOADSTATUS_DISABLED?get_lang_str(LANG_PLUGINS_STATUS_DISABLED):get_lang_str(LANG_PLUGINS_STATUS_UNKNOWN));
			return;
		}
		i++;
	}
}

void updatePluginDescription(int plugin_id,char *description)
{	if(!hDlgPlugins) return;
	int i=0;
	while(1)
	{	lvit.iItem=i;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
		lvit.lParam=0;
		if(!SendDlgItemMessageW(hDlgPlugins,26400,LVM_GETITEMW,0,(LPARAM)&lvit)) break;
		if(plugin_id==lvit.lParam)
		{	LangSetLVItem(hDlgPlugins,26400,lvit.iItem,2,description);
			return;
		}
		i++;
	}
}

void selectPlugin(int lastsel)
{	int i=0;
	while(1)
	{	lvit.iItem=i;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
		lvit.lParam=0;
		if(!SendDlgItemMessageW(hDlgPlugins,26400,LVM_GETITEMW,0,(LPARAM)&lvit)) break;
		if(lastsel==lvit.lParam)
		{	lvit.stateMask=LVIS_SELECTED;
			lvit.mask=LVIF_STATE;
			lvit.state=LVIS_SELECTED;
			SendDlgItemMessageW(hDlgPlugins,26400,LVM_SETITEMW,lvit.iItem,(LPARAM)&lvit);
			return;
		}
		i++;
	}
}


void dlgPlugins_langUpdate(void)
{	if(hDlgPlugins && LangGetLanguage())
	{	changeDialogStrings(hDlgPlugins,lang_dlg_plugins);
		LangSetColumn(hDlgPlugins,26400,90,LANG_PLUGINS_LIST_DLL,0);
		LangSetColumn(hDlgPlugins,26400,60,LANG_PLUGINS_LIST_STATUS,1);
		LangSetColumn(hDlgPlugins,26400,250,LANG_PLUGINS_LIST_DESCRIPTION,2);
	}
}

int __stdcall dlgPluginRights(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	if(LangGetLanguage())
		{	SetWindowTextL(hDlg,LANG_PLUGINS_RIGHTS_TITLE);
			changeDialogStrings(hDlg,lang_dlg_pr);
		}
		if(tmp_plugin)
		{	if(tmp_plugin->rights&PLUGIN_RIGHT__ADVTOR_PAGE)	CheckDlgButton(hDlg,400,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_CHANGE_OPTIONS)	CheckDlgButton(hDlg,401,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC)	CheckDlgButton(hDlg,402,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES)	CheckDlgButton(hDlg,403,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS)	CheckDlgButton(hDlg,404,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_ACCEPT_CLIENTS)	CheckDlgButton(hDlg,405,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER)	CheckDlgButton(hDlg,406,BST_CHECKED);
			if(tmp_plugin->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)	CheckDlgButton(hDlg,407,BST_CHECKED);
		}
	}
	else if(uMsg==WM_COMMAND)
	{	if(LOWORD(wParam)==1)
		{	if(tmp_plugin)
			{	if(IsDlgButtonChecked(hDlg,400)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__ADVTOR_PAGE;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__ADVTOR_PAGE;
				if(IsDlgButtonChecked(hDlg,401)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_CHANGE_OPTIONS;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_CHANGE_OPTIONS;
				if(IsDlgButtonChecked(hDlg,402)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC;
				if(IsDlgButtonChecked(hDlg,403)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES;
				if(IsDlgButtonChecked(hDlg,404)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS;
				if(IsDlgButtonChecked(hDlg,405)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_ACCEPT_CLIENTS;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_ACCEPT_CLIENTS;
				if(IsDlgButtonChecked(hDlg,406)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER;
				if(IsDlgButtonChecked(hDlg,407)==BST_CHECKED)	tmp_plugin->rights|=PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES;
				else tmp_plugin->rights &= PLUGIN_RIGHT__ALL_RIGHTS ^ PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES;
			}
			EndDialog(hDlg,0);
		}
		else if(LOWORD(wParam)==2)
		{	EndDialog(hDlg,0);
		}
	}
	return 0;
}


int __stdcall dlgPlugins(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	(void) lParam;
	if(uMsg==WM_INITDIALOG)
	{	hDlgPlugins=hDlg;
		LangInsertColumn(hDlg,26400,90,LANG_PLUGINS_LIST_DLL,0,LVCFMT_LEFT);
		LangInsertColumn(hDlg,26400,60,LANG_PLUGINS_LIST_STATUS,1,LVCFMT_RIGHT);
		LangInsertColumn(hDlg,26400,250,LANG_PLUGINS_LIST_DESCRIPTION,2,LVCFMT_LEFT);
		dlgPlugins_langUpdate();
		SendDlgItemMessage(hDlg,26400,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT,LVS_EX_ONECLICKACTIVATE|LVS_EX_FULLROWSELECT);
		refreshPluginList();
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==26001)
		{	refresh_plugins(tmpOptions);
			load_all_plugins();
			refreshPluginList();
		}
		else if(LOWORD(wParam)==26002)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	if(remove_plugin(hDlg,lvit.lParam))
					{	SendDlgItemMessageW(hDlg,26400,LVM_DELETEITEM,lvit.iItem,0);
						lvit.stateMask=LVIS_SELECTED;
						lvit.mask=LVIF_STATE;
						lvit.state=LVIS_SELECTED;
						if(!SendDlgItemMessageW(hDlg,26400,LVM_SETITEMW,lvit.iItem,(LPARAM)&lvit) && lvit.iItem)
						{	lvit.iItem--;
							SendDlgItemMessageW(hDlg,26400,LVM_SETITEMW,lvit.iItem,(LPARAM)&lvit);
						}
					}
				}
			}
		}
		else if(LOWORD(wParam)==26003)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	reload_plugin(hDlg,lvit.lParam);
				}
			}
		}
		else if(LOWORD(wParam)==26004)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	disable_plugin(hDlg,lvit.lParam);
				}
			}
		}
		else if(LOWORD(wParam)==26005)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	tmp_plugin=find_plugin(lvit.lParam);
					if(tmp_plugin)	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1011),hDlg,&dlgPluginRights,0);
				}
			}
		}
		else if(LOWORD(wParam)==26006)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	if(plugin_move_up(lvit.lParam))
					{	int lastsel=lvit.lParam;
						refreshPluginList();
						selectPlugin(lastsel);
					}
				}
			}
		}
		else if(LOWORD(wParam)==26007)
		{	lvit.iItem=SendDlgItemMessageW(hDlg,26400,LVM_GETNEXTITEM,-1,MAKELPARAM(LVNI_SELECTED,0));
			if(lvit.iItem!=-1)
			{	lvit.lParam=0;lvit.mask=LVIF_PARAM;lvit.iSubItem=0;
				if(SendDlgItemMessageW(hDlg,26400,LVM_GETITEMW,0,(LPARAM)&lvit) && lvit.lParam)
				{	if(plugin_move_down(lvit.lParam))
					{	int lastsel=lvit.lParam;
						refreshPluginList();
						selectPlugin(lastsel);
					}
				}
			}
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
