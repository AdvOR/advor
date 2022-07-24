#include "dlg_resize.h"

typedef BOOL (WINAPI *LP_InitPlugin)(HANDLE,DWORD,char *,void *) __attribute__((stdcall));
typedef BOOL (WINAPI *LP_UnloadPlugin)(int exit) __attribute__((stdcall));			// unload from GUI = 1 / exitting program, prompt user = 2 / exitting, must terminate = 3 / exit/unload canceled by user = 0
typedef HWND (WINAPI *LP_GetConfigurationWindow)(HWND hParent) __attribute__((stdcall));
typedef resize_info_t* (WINAPI *LP_ResizeConfigurationWindow)(RECT *newSize) __attribute__((stdcall));
typedef int (WINAPI *LP_RegisterConnection)(DWORD,int,char *,LPARAM *) __attribute__((stdcall));
typedef int (WINAPI *LP_UnregisterConnection)(DWORD,int,char *,LPARAM *) __attribute__((stdcall));
typedef int (WINAPI *LP_ConnectionRead)(DWORD,int,int,char *,char *,int*,int,LPARAM *) __attribute__((stdcall));
typedef int (WINAPI *LP_ConnectionWrite)(DWORD,int,int,char *,char *,int*,int,LPARAM *) __attribute__((stdcall));
typedef int (WINAPI *LP_TranslateAddress)(DWORD,char *,char *,LPARAM *,BOOL) __attribute__((stdcall));
typedef int (WINAPI *LP_ChangeIdentity)(DWORD,char *,long) __attribute__((stdcall));
typedef void (WINAPI *LP_Start)(BOOL) __attribute__((stdcall));
typedef void (WINAPI *LP_RouterChanged)(uint32_t,char *,int) __attribute__((stdcall));
typedef BOOL (WINAPI *LP_HiddenService_NotifyService)(int,char *,int,DWORD,LPARAM *) __attribute__((stdcall));
typedef BOOL (WINAPI *LP_HiddenService_HandleRead)(char *,DWORD,char *,int,LPARAM *) __attribute__((stdcall));
typedef BOOL (WINAPI *LP_InterceptProcess)(DWORD,BOOL) __attribute__((stdcall));
typedef void (WINAPI *LP_LanguageChange)(char *) __attribute__((stdcall));


typedef struct plugin_info_t plugin_info_t;

#define PLUGIN_LOADSTATUS_FOUND 1
#define PLUGIN_LOADSTATUS_REMOVED 2
#define PLUGIN_LOADSTATUS_DISABLED 4
#define PLUGIN_LOADSTATUS_LOAD_ERROR 8
#define PLUGIN_LOADSTATUS_INIT_FAILED 16
#define PLUGIN_LOADSTATUS_LOADED 32

#define PLUGIN_LOADSTATUS_MASK 0xffff

#define PLUGIN_RIGHT__CAN_BE_SHOWN_IN_PLUGIN_LIST 1
#define PLUGIN_RIGHT__CAN_BE_LOADED 2
#define PLUGIN_RIGHT__ADVTOR_PAGE 4
#define PLUGIN_RIGHT__CAN_CHANGE_OPTIONS 8
#define PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC 16
#define PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES 32	//can change destination address of a connection
#define PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS 64
#define PLUGIN_RIGHT__CAN_ACCEPT_CLIENTS 128
#define PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER 256
#define PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES 512

#define PLUGIN_UNLOAD_ON_DEMAND 1
#define PLUGIN_UNLOAD_RELOAD 2			// 1 = FreeLibrary, -1 = call init without FreeLibrary, 0 = cannot reload
#define PLUGIN_UNLOAD_AT_EXIT 3
#define PLUGIN_UNLOAD_MUST_UNLOAD 4
#define PLUGIN_UNLOAD_CANCEL 0

#define PLUGIN_RIGHT__ALL_RIGHTS 0xffff

#define PLUGIN_FN_INIT "AdvTor_InitPlugin"
#define PLUGIN_FN_UNLOAD "AdvTor_UnloadPlugin"
#define PLUGIN_FN_GETCONFIG "AdvTor_GetConfigurationWindow"
#define PLUGIN_FN_HANDLE_READ "AdvTor_HandleRead"
#define PLUGIN_FN_HANDLE_WRITE "AdvTor_HandleWrite"
#define PLUGIN_FN_RESIZE "ResizeConfigurationWindow"
#define PLUGIN_FN_NEWCONN "AdvTor_RegisterNewConnection"
#define PLUGIN_FN_CLOSECONN "AdvTor_UnregisterConnection"
#define PLUGIN_FN_CONN_READ "AdvTor_HandleRead"
#define PLUGIN_FN_CONN_WRITE "AdvTor_HandleWrite"
#define PLUGIN_FN_REWRITE_ADDR "AdvTor_TranslateAddress"
#define PLUGIN_FN_NEW_IDENTITY "AdvTor_ChangeIdentity"
#define PLUGIN_FN_START "AdvTor_Start"
#define PLUGIN_FN_ROUTERCHANGED "AdvTor_RouterChanged"
#define PLUGIN_FN_HS_NOTIFYSERVICE "HiddenService_NotifyService"
#define PLUGIN_FN_HS_HANDLEREAD "HiddenService_HandleRead"
#define PLUGIN_FN_INTERCEPT_PROCESS "AdvTor_InterceptProcess"
#define PLUGIN_FN_LANGUAGE_CHANGE "AdvTor_LanguageChange"

struct plugin_info_t
{	int plugin_id;
	char dll_name[MAX_PATH+1];
	char description[256];
	int load_status;
	int rights;
	HINSTANCE hDll;
	HWND hDlg;
	HTREEITEM hItem;
	int listItem;
	int connection_param;
	int lng_error;
	int maxdefs;
	struct lang_str_info *loaded_lng;
	char *lngfile;
	LP_InitPlugin InitPlugin __attribute__((stdcall));
	LP_UnloadPlugin UnloadPlugin __attribute__((stdcall));
	LP_GetConfigurationWindow GetConfigurationWindow __attribute__((stdcall));
	LP_ResizeConfigurationWindow ResizeConfigurationWindow __attribute__((stdcall));
	LP_RegisterConnection RegisterConnection __attribute__((stdcall));
	LP_UnregisterConnection UnregisterConnection __attribute__((stdcall));
	LP_ConnectionRead ConnectionRead __attribute__((stdcall));
	LP_ConnectionWrite ConnectionWrite __attribute__((stdcall));
	LP_TranslateAddress TranslateAddress __attribute__((stdcall));
	LP_ChangeIdentity ChangeIdentity __attribute__((stdcall));
	LP_Start AdvTorStart __attribute__((stdcall));
	LP_RouterChanged RouterChanged __attribute__((stdcall));
	LP_HiddenService_NotifyService HiddenService_NotifyService __attribute__((stdcall));
	LP_HiddenService_HandleRead HiddenService_HandleRead __attribute__((stdcall));
	LP_InterceptProcess InterceptProcess __attribute__((stdcall));
	LP_LanguageChange LanguageChange __attribute__((stdcall));
	DWORD exclKey;
	struct plugin_info_t* next_plugin;
};

typedef struct connection_info_t
{
	DWORD connection_id;
	DWORD connection_type;
	DWORD connection_state;
	char *address;
	char *socks_original_address;
	char *socks_final_address;
	DWORD reserved;
	LPARAM *lParam;
} connection_info_t;


void load_plugins(void);
void load_all_plugins(void);
void refresh_plugins(or_options_t *options);
int unload_plugins(HWND hDlg);
plugin_info_t *get_plugin_list(void);
void remove_plugins(void);
int remove_plugin(HWND hDlg,int plugin_id);
void disable_plugin(HWND hDlg,int plugin_id);
void reload_plugin(HWND hDlg,int plugin_id);
int plugin_move_up(int plugin_id);
int plugin_move_down(int plugin_id);
void dlg_add_all_plugins(void);
void dlg_set_all_plugins(void);
HWND get_plugin_window(int list_item);
int plugins_connection_add(connection_t *conn);
int plugins_connection_remove(connection_t *conn);
void plugins_read_event(connection_t *conn,size_t before);
void plugins_write_event(connection_t *conn,size_t before);
void plugins_new_identity(void);
int plugins_remap(edge_connection_t *conn,char **address,char *original_address,BOOL is_error);
edge_connection_t *find_connection_by_id(DWORD connection_id);
void plugins_start(int started_);
plugin_info_t *find_plugin(int plugin_id);
void plugins_language_change(void);
