#include "or.h"
#include "dlg_util.h"
#include "main.h"
#include "circuitlist.h"
#include "connection.h"
#include "directory.h"
#include "router.h"
#include "routerlist.h"
#include "geoip.h"
#include "policies.h"
#include "config.h"
#include "circuitbuild.h"
#include "control.h"

#define NODE_TYPE_CIRCUIT 1
#define NODE_TYPE_ROUTER 2

#define SELECTION_TYPE_CIRCUIT 1
#define SELECTION_TYPE_HOP 2
#define SELECTION_TYPE_STREAM 3

HWND hDlgNetInfo=NULL;
NM_TREEVIEW *pnmtv;
NM_TREEVIEWW *pnmtvw;
extern HWND hMainDialog;
extern HINSTANCE hInstance;
extern BOOL started;
extern smartlist_t *entry_guards;
extern uint32_t last_guessed_ip;
//int frame13[]={25010,25500,25011,25100,25001,25002,25050,25012,25013,25014,25015,25052,25016,25017,25018,25019,25051,-1};
lang_dlg_info lang_dlg_netinfo[]={
	{25010,LANG_NETINFO_CIRCUIT_LIST},
	{25011,LANG_NETINFO_SELECTION_DETAILS},
	{25001,LANG_NETINFO_DESTROY_CIRCUIT},
	{25002,LANG_NETINFO_NEW_CIRCUIT},
	{25050,LANG_NETINFO_TRAFFIC},
	{25012,LANG_NETINFO_TRAFFIC_DOWNLOAD},
	{25014,LANG_NETINFO_TRAFFIC_UPLOAD},
	{25052,LANG_NETINFO_TOTALS},
	{25016,LANG_NETINFO_TOTALS_DOWNLOAD},
	{25018,LANG_NETINFO_TOTALS_UPLOAD},
	{0,0}
};

lang_dlg_info lang_dlg_circ[]={
	{10,LANG_NETINFO_ESTIMATED_LIST},
	{11,LANG_NETINFO_CIRCUIT_LENGTH},
	{3,LANG_NETINFO_ESTIMATE_NEW},
	{1,LANG_NETINFO_BUILD_OK},
	{2,LANG_NETINFO_BUILD_CANCEL},
	{4,LANG_NETINFO_NEW_ENTRY},
	{6,LANG_NETINFO_INSERT_NODE},
	{7,LANG_NETINFO_NEW_EXIT},
	{0,0}
};

void dlgTrackedHosts_trackedHostExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_trackedDomainExitAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapAdd(HWND hDlg,char *newAddr);
void dlgTrackedHosts_addressMapRemove(HWND hDlg,char *newAddr);
void dlgProxy_banSocksAddress(char *socksAddress);
int __stdcall dlgRouterSelect(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void getExclKeyName(char *,DWORD);
void get_dll_name(char *s1,HANDLE hPlugin);

routerinfo_t *choose_good_exit_server(uint8_t purpose, routerlist_t *dir,int need_uptime, int need_capacity, int is_internal,DWORD exclKey);
routerinfo_t *choose_good_entry_server(uint8_t purpose, cpath_build_state_t *state);
routerinfo_t *choose_good_middle_server(uint8_t purpose,cpath_build_state_t *state,crypt_path_t *head,int cur_len);
void circuit_free_cpath(crypt_path_t *cpath);
void circuit_reset_failure_count(int timeout);
int is_router_excluded(const extend_info_t *exit);
int onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice);
int __stdcall dlgNewCircuit(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
int __stdcall dlgNetInfo(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void add_router_to_favorites(HWND hDlg,char *router,char favtype);
void add_router_to_banlist(HWND hDlg,char *router,char bantype);
void drawGraph(HWND hWnd);
void recalcGraph(void);
void releaseGraph(void);
void dlgShowCircuits(void);
void show_connection_info(connection_t *conn,char *s1);
void tree_destroy_circuit_menu(void);
HTREEITEM insert_new_node(TV_INSERTSTRUCT *nodeinfo);
void tree_ban_entry_menu(void);
void tree_ban_exit_menu(void);
void tree_fav_entry_menu(void);
void tree_fav_exit_menu(void);
void tree_invalidate_router(void);
void tree_close_connection(void);
void tree_kill_process(void);
void build_show_router_info(char *s1,routerinfo_t *r);
void tree_build_circuit(HWND hDlg);
void replace_entry(HWND hDlg,routerinfo_t *r);
void replace_exit(HWND hDlg,routerinfo_t *r);
void replace_middle(HWND hDlg,routerinfo_t *r);
void tree_create_circuit_menu(void);
void tree_set_priority(int new_priority);
void tree_lang_update(void);
circuit_t *tree_get_selected_circuit(void);
void tree_show_menu(HTREEITEM hItem);

uint32_t stats_bw_read[128];
uint32_t stats_bw_written[128];
unsigned int draw_bw_read[128],draw_bw_written[128];
uint64_t totals_read=0,totals_written=0;
uint32_t last_max=1,last_max_128=1;
int stats_idx=0;
int flag_busy=0;
BITMAPINFO bmdata;
HBITMAP hBitmap=NULL,hOldBitmap=NULL;
RECT wndr;
TV_ITEM tvit;
TV_INSERTSTRUCT tvins;
unsigned char *bmpbits=NULL;
int adding_circuits=0;
char lastMid[20];
LPARAM selected_item=0;
HTREEITEM selected_node=0;
int selection_type=0;
HTREEITEM lastContextSel=0;
uint32_t lastRouterSel=0;
int lastPortSel=0;
int lastPid=0;
char lastSocksAddress[MAX_SOCKS_ADDR_LEN];
char lastSocksOriginalAddress[MAX_SOCKS_ADDR_LEN];

void dlgStatsRWInit(void)
{	int i;
	for(i=0;i<128;i++)	stats_bw_read[i]=stats_bw_written[i]=0;
}

void dlgUpdateRWStats(int seconds,uint32_t bw_read,uint32_t bw_written)
{	totals_read += bw_read;
	totals_written += bw_written;
	if(stats_idx==0)
	{	last_max=last_max_128;
		last_max_128=1;
	}
	if(bw_read>last_max || bw_written>last_max) last_max=bw_read>bw_written?bw_read:bw_written;
	if(bw_read>last_max_128 || bw_written>last_max_128) last_max_128=bw_read>bw_written?bw_read:bw_written;
	if(seconds>1)
	{	bw_read /= seconds;
		bw_written /= seconds;
	}
	stats_bw_read[stats_idx]=bw_read;
	stats_bw_written[stats_idx]=bw_written;
	stats_idx++;
	stats_idx &= 0x7f;
}

void drawGraph(HWND hWnd)
{	int i,j,k,l;
	unsigned char *memPtr;
	HDC hTmpDC=NULL;
	HDC hMemDC;
	if(bmpbits==NULL || hBitmap==NULL)
	{	hMemDC=CreateCompatibleDC(NULL);
		GetWindowRect(hWnd,&wndr);
		wndr.bottom-=wndr.top;
		wndr.right-=wndr.left;
		wndr.left=wndr.right;
		while(wndr.left>128) wndr.left >>= 1;
		bmdata.bmiHeader.biSize=40;
		bmdata.bmiHeader.biPlanes=1;
		bmdata.bmiHeader.biBitCount=32;
		bmdata.bmiHeader.biWidth=128;
		bmdata.bmiHeader.biHeight=-64;
		bmdata.bmiHeader.biCompression=BI_RGB;
		bmdata.bmiHeader.biSizeImage=0;
		bmdata.bmiHeader.biXPelsPerMeter=0;
		bmdata.bmiHeader.biYPelsPerMeter=0;
		bmdata.bmiHeader.biClrImportant=0;
		bmdata.bmiHeader.biClrUsed=0;
		hBitmap=CreateDIBSection(hMemDC,&bmdata,DIB_RGB_COLORS,(void *)&bmpbits,0,0);
		DeleteDC(hMemDC);
	}
	if(bmpbits)
	{	for(l=0;last_max>>l!=0;l++)	;
		memPtr=bmpbits;k=stats_idx;
		for(i=0;i<128;i++)
		{	draw_bw_read[i]=(stats_bw_read[(i+k)&0x7f]<<6)>>l;
			draw_bw_written[i]=(stats_bw_written[(i+k)&0x7f]<<6)>>l;
		}
		for(j=63;j>32;j--)
		{
			for(i=0;i<128;i++)
			{	*memPtr++=10;
				*memPtr++=draw_bw_read[i]>(uint32_t)j?255:0;
				*memPtr++=draw_bw_written[i]>(uint32_t)j?255:0;
				*memPtr++=0;
			}
		}
		for(i=0;i<128;i++)
		{	*memPtr++=0xff;
			*memPtr++=0xff;
			*memPtr++=0xff;
			*memPtr++=0;
		}
		for(j=31;j>=0;j--)
		{
			for(i=0;i<128;i++)
			{	*memPtr++=10;
				*memPtr++=draw_bw_read[i]>(uint32_t)j?255:0;
				*memPtr++=draw_bw_written[i]>(uint32_t)j?255:0;
				*memPtr++=0;
			}
		}
		hTmpDC=GetDC(hWnd);
		StretchDIBits(hTmpDC,0,0,wndr.right,wndr.bottom,128-wndr.left,0,wndr.left,64,bmpbits,&bmdata,DIB_RGB_COLORS,SRCCOPY);
		FormatMemInt(lastMid,l?1<<l:1);
		SetBkMode(hTmpDC,TRANSPARENT);
		SetTextColor(hTmpDC,0);
		TextOut(hTmpDC,1,(wndr.bottom>>1)-15,lastMid,strlen(lastMid));
		SetTextColor(hTmpDC,0xffffff);
		TextOut(hTmpDC,0,(wndr.bottom>>1)-16,lastMid,strlen(lastMid));
		ReleaseDC(hWnd,hTmpDC);
	}
}

void recalcGraph(void)
{	GetWindowRect(GetDlgItem(hDlgNetInfo,25051),&wndr);
	wndr.bottom-=wndr.top;
	wndr.right-=wndr.left;
	wndr.left=wndr.right;
	while(wndr.left>128) wndr.left >>= 1;
}

void releaseGraph(void)
{	if(hBitmap) DeleteObject(hBitmap);
	hBitmap=NULL;
	bmpbits=NULL;
}

#define MAX_TV_INSERT_RETRIES 16

HTREEITEM insert_new_node(TV_INSERTSTRUCT *nodeinfo)
{
	HTREEITEM result=NULL;
	int i = 0;
	while(i < MAX_TV_INSERT_RETRIES)
	{	LONG h = SendDlgItemMessage(hDlgNetInfo,25500,TVM_INSERTITEM,0,(LPARAM)nodeinfo);
		result = (HTREEITEM)h;
		if(result)	break;
		if(i & 4)
			log(LOG_WARN,LD_APP,get_lang_str(LANG_MB_ERROR_UPDATING_TREE));
		Sleep(100);
		i++;
	}
	if(!result)
		LangMessageBox(hMainDialog,get_lang_str(LANG_MB_ERROR_UPDATING_TREE),LANG_MB_ERROR,MB_OK);
	return result;
}

void dlgShowCircuits(void)
{	if(adding_circuits) return;
	selected_node=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)TVI_ROOT);
	tvins.hParent=TVI_ROOT;
	tvins.hInsertAfter=TVI_FIRST;
	circuit_tree_add_circs();
	adding_circuits++;
//control_event_circuit_status
}

void dlgShowRWStats(HWND hDlg)
{	if(flag_busy) return;
	flag_busy++;
	char memInt[20];int i;
	FormatMemInt(memInt,stats_bw_read[(stats_idx-1)&0xff]);
	for(i=0;memInt[i];i++)	;
	memInt[i++]='/';memInt[i++]='s';memInt[i]=0;
	SetDlgItemText(hDlg,25013,memInt);
	FormatMemInt(memInt,stats_bw_written[(stats_idx-1)&0xff]);
	for(i=0;memInt[i];i++)	;
	memInt[i++]='/';memInt[i++]='s';memInt[i]=0;
	SetDlgItemText(hDlg,25015,memInt);
	FormatMemInt64(memInt,&totals_read);
	SetDlgItemText(hDlg,25017,memInt);
	FormatMemInt64(memInt,&totals_written);
	SetDlgItemText(hDlg,25019,memInt);
	drawGraph(GetDlgItem(hDlg,25051));
	dlgShowCircuits();
	flag_busy=0;
}


void show_connection_info(connection_t *conn,char *s1)
{
	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE),conn_type_to_string(conn->type));s1 += strlen(s1);
	switch(conn->magic)
	{	case BASE_CONNECTION_MAGIC:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_BASE));
			break;
		case OR_CONNECTION_MAGIC:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_OR));
			break;
		case EDGE_CONNECTION_MAGIC:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_EDGE));
			break;
		case DIR_CONNECTION_MAGIC:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_DIR));
			break;
		case CONTROL_CONNECTION_MAGIC:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_CONTROL));
			break;
		default:
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TYPE_UNKNOWN));
			break;
	}
	s1 += strlen(s1);
	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_STATE),conn_state_to_string(conn->type,conn->state));s1 += strlen(s1);
	if(conn->purpose>=_DIR_PURPOSE_MIN && conn->purpose <= _DIR_PURPOSE_MAX)
	{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_PURPOSE),dir_conn_purpose_to_string(conn->purpose));s1 += strlen(s1);}
	else if(conn->purpose>=_EXIT_PURPOSE_MIN && conn->purpose <= _EXIT_PURPOSE_MAX)
	{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_PURPOSE),conn->purpose==EXIT_PURPOSE_CONNECT?get_lang_str(LANG_NETINFO_CONNECTION_PURPOSE_CONNECT):get_lang_str(LANG_NETINFO_CONNECTION_PURPOSE_RESOLVE));s1 += strlen(s1);}
	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TIME_CREATED));s1 += strlen(s1);format_iso_time(s1,conn->timestamp_created);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_LAST_READ_TIME));s1 += strlen(s1);format_iso_time(s1,conn->timestamp_lastread);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_LAST_WRITE_TIME));s1 += strlen(s1);format_iso_time(s1,conn->timestamp_lastwritten);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
	if(conn->address){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_ADDRESS),conn->address);s1 += strlen(s1);}
	if(conn->type==CONN_TYPE_OR || conn->magic==OR_CONNECTION_MAGIC)
	{	or_connection_t *conn1=TO_OR_CONN(conn);
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TIME_CLIENT));s1 += strlen(s1);format_iso_time(s1,conn1->client_used);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
		uint32_t raddr1=tor_addr_to_ipv4n(&conn1->real_addr);
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_ACTUAL_ADDRESS),raddr1&0xff,(raddr1>>8)&0xff,(raddr1>>16)&0xff,(raddr1>>24)&0xff);s1 += strlen(s1);
		if(conn1->is_bad_for_new_circs){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TOO_OLD));s1 += strlen(s1);}
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_BW_RATE));s1 += strlen(s1);
		FormatMemInt(s1,conn1->bandwidthrate);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_BW_BURST));s1 += strlen(s1);
		FormatMemInt(s1,conn1->bandwidthburst);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
	}
	else if(conn->type==CONN_TYPE_AP || conn->type==CONN_TYPE_EXIT || conn->magic==EDGE_CONNECTION_MAGIC)
	{	edge_connection_t *conn2=TO_EDGE_CONN(conn);
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_EXCL_KEY));s1 += strlen(s1);getExclKeyName(s1,conn->exclKey);s1 += strlen(s1);*s1++=13;*s1++=10;*s1=0;
		if(conn2->chosen_exit_name){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_CHOSEN_EXIT),conn2->chosen_exit_name);s1 += strlen(s1);}
		if(conn2->_base.pid)
		{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_PID),(unsigned int)conn2->_base.pid);s1 += strlen(s1);
			getProcessName(s1,200,conn2->_base.pid);s1 += strlen(s1);*s1++=13;*s1++=10;*s1=0;
		}
		else if(conn2->_base.hPlugin)
		{	tor_snprintf(s1,100,get_lang_str(LANG_PLUGINS_PLUGIN));s1 += strlen(s1);
			get_dll_name(s1,conn2->_base.hPlugin);s1 += strlen(s1);*s1++=13;*s1++=10;*s1=0;
		}
		if(conn2->socks_request)
		{	if(conn2->socks_request->original_address){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_SOCKS_ADDRESS),conn2->socks_request->original_address,conn2->socks_request->port);s1 += strlen(s1);}
			if(conn2->socks_request->address){		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_SOCKS_FINAL_ADDRESS),conn2->socks_request->address,conn2->socks_request->port);s1 += strlen(s1);}
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_SOCKS_LAST_REQUEST),conn2->socks_request->command==SOCKS_COMMAND_CONNECT?get_lang_str(LANG_NETINFO_SOCKS_REQUEST_CONNECT):conn2->socks_request->command==SOCKS_COMMAND_RESOLVE?get_lang_str(LANG_NETINFO_SOCKS_REQUEST_RESOLVE):conn2->socks_request->command==SOCKS_COMMAND_RESOLVE_PTR?get_lang_str(LANG_NETINFO_SOCKS_REQUEST_NAME):conn2->socks_request->command==SOCKS_COMMAND_SELECT_ROUTER?get_lang_str(LANG_NETINFO_SOCKS_REQUEST_SELECT):get_lang_str(LANG_NETINFO_SOCKS_REQUEST_UNKNOWN));s1 += strlen(s1);
		}
		if(conn2->chosen_exit_name){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_CHOSEN_EXIT),conn2->chosen_exit_name);s1 += strlen(s1);}
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_BYTES_READ));s1 += strlen(s1);
		FormatMemInt(s1,conn2->n_read);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_BYTES_WRITTEN));s1 += strlen(s1);
		FormatMemInt(s1,conn2->n_written);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
		if(conn2->want_onehop){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_ONE_HOP));s1 += strlen(s1);}
		if(conn2->chosen_exit_optional){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_OPTIONAL_EXIT));s1 += strlen(s1);}
		if(conn2->chosen_exit_retries){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_CONNECTION_TRACKED_EXIT));s1 += strlen(s1);}
	}
	else if(conn->type==CONN_TYPE_DIR || conn->magic==DIR_CONNECTION_MAGIC)
	{	dir_connection_t *conn3=TO_DIR_CONN(conn);
		if(conn3->requested_resource){	tor_snprintf(s1,500,get_lang_str(LANG_NETINFO_DIR_REQUEST),conn3->requested_resource);s1 += strlen(s1);}
		if(!conn3->dirconn_direct){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_DIR_CONNECTED_VIA_TOR));s1 += strlen(s1);}
		tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_PURPOSE_2),router_purpose_to_string(conn3->router_purpose));s1 += strlen(s1);
	}
}

void tree_show_sel(HTREEITEM hItem,LPARAM lParam)
{	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	if(lParam==NODE_TYPE_CIRCUIT)
	{	circuit_t *circ=get_circuit_by_hitem(hItem);
		if(circ)
		{	char *s=circuit_dump(circ),*s1;
			s1 = tor_malloc(32768);
			if(s)
			{	tor_snprintf(s1,1024,"%s\r\n",s);
				tor_free(s);s = s1;
				s1=s+strlen(s);*s1++=13;*s1++=10;
			}
			else s = s1;
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_EXCL_KEY));
			s1 += strlen(s1);getExclKeyName(s1,circ->exclKey);s1 += strlen(s1);*s1++=13;*s1++=10;
			uint32_t *iplist,*aslist;
			iplist=tor_malloc(100);aslist=tor_malloc(8192);
			int i=0;
			if(last_guessed_ip)
			{	iplist[0]=last_guessed_ip;i++;}
			if(CIRCUIT_IS_ORIGIN(circ))
			{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
				crypt_path_t *hop=c->cpath;
				while(hop && hop->extend_info)
				{	routerinfo_t *ri = router_get_by_digest(hop->extend_info->identity_digest);
					if(ri)	iplist[i++] = ri->addr;
					hop=hop->next;
					if(hop==c->cpath) break;
				}
			}
			iplist[i] = 0;
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_AS_PATH));s1 += strlen(s1);*s1=0;
			geoip_get_full_as_path(iplist,aslist,8188);
			geoip_as_path_to_str(aslist,s1,16384);
			tor_free(iplist);tor_free(aslist);
			SetDlgItemTextL(hDlgNetInfo,25100,s);
			tor_free(s);
		}
		selected_item=lParam;
		selection_type=SELECTION_TYPE_CIRCUIT;
		selected_node=hItem;
		SetDlgItemTextL(hDlgNetInfo,25001,get_lang_str(LANG_NETINFO_DESTROY_CIRCUIT));
		SetDlgItemTextL(hDlgNetInfo,25002,get_lang_str(LANG_NETINFO_NEW_CIRCUIT));
	}
	else
	{	crypt_path_t *hop=(crypt_path_t*)lParam;
		connection_t *conn=NULL;
		if(hop->magic == CRYPT_PATH_MAGIC)
		{	char *s=tor_malloc(32767),*s1;
			routerinfo_t *ri=NULL;
			uint32_t raddr=0;
			int port=0;
			tor_snprintf(s,100,get_lang_str(LANG_NETINFO_HOP_STATE),hop->state==CPATH_STATE_CLOSED?get_lang_str(LANG_NETINFO_HOP_STATE_CLOSED):hop->state==CPATH_STATE_AWAITING_KEYS?get_lang_str(LANG_NETINFO_HOP_STATE_AWAITING_KEYS):hop->state==CPATH_STATE_OPEN?get_lang_str(LANG_NETINFO_HOP_STATE_OPEN):get_lang_str(LANG_NETINFO_HOP_STATE_UNKNOWN));
			s1=s+strlen(s);
			if(hop->extend_info)
			{	ri = router_get_by_digest(hop->extend_info->identity_digest);
				if(ri)
				{	raddr=geoip_reverse(ri->addr);
					port=ri->or_port;
				}
				else
				{	raddr=tor_addr_to_ipv4n(&hop->extend_info->addr);
				}
				if(hop->extend_info->port) port=hop->extend_info->port;
			}
			int country = geoip_get_country_by_ip(raddr);
			unsigned char *country_name;
			tor_asprintf(&country_name,"%s%s",geoip_get_country_name(country&0xff),country>0xff?get_lang_str(LANG_NETINFO_BLACKLISTED):"");
			tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_HOP_ADDRESS),country_name,raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,port);
			tor_free(country_name);
			s1+=strlen(s1);
			if(geoip_get_as_by_ip(geoip_reverse(raddr))!=65536)
			{	uint32_t *iplist=tor_malloc(12);
				uint32_t *aslist=tor_malloc(8192);
				iplist[0] = geoip_reverse(raddr);iplist[1] = 0;
				tor_snprintf(s1,20," (AS%i)\r\n",geoip_get_as_by_ip(iplist[0]));
				s1 += strlen(s1);tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_AS_PATH));s1 += strlen(s1);*s1=0;
				geoip_get_full_as_path(iplist,aslist,8192);
				geoip_as_path_to_str(aslist,s1,8192);
				tor_free(iplist);tor_free(aslist);
			}
			else	tor_snprintf(s1,20," (AS_UNKNOWN)\r\n");
			s1 += strlen(s1);
			while(1)
			{	conn=get_connection_by_addr(raddr,port,conn);
				if(!conn) break;
				show_connection_info(conn,s1);
				s1 += strlen(s1);
			}
			if(ri)
			{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_NAME),hop->extend_info->nickname);s1 += strlen(s1);
				if(ri->declared_family && smartlist_len(ri->declared_family))
				{	size_t n;
					char *family = smartlist_join_strings(ri->declared_family," ",0,&n);
					tor_snprintf(s1,1024,get_lang_str(LANG_NETINFO_ROUTER_FAMILY),family);
					tor_free(family);
					s1 += strlen(s1);
				}
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_PURPOSE),router_purpose_to_string(ri->purpose));s1 += strlen(s1);
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_PUBLISHED));s1 += strlen(s1);format_iso_time(s1,ri->cache_info.published_on);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
				if(ri->platform){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_PLATFORM),ri->platform);s1 += strlen(s1);}
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_BW_RATE));s1 += strlen(s1);
				FormatMemInt(s1,ri->bandwidthrate);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_BW_BURST));s1 += strlen(s1);
				FormatMemInt(s1,ri->bandwidthburst);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_BW_CAPACITY));s1 += strlen(s1);
				FormatMemInt(s1,ri->bandwidthcapacity);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
				if(ri->uptime>60)
				{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_UPTIME));s1 += strlen(s1);
					long uptime=ri->uptime;
					if(uptime>(3600*24)){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_UPTIME_DAYS),uptime/3600/24);uptime%=3600*24;s1 += strlen(s1);}
					if(uptime>3600){	tor_snprintf(s1,200,get_lang_str(LANG_NETINFO_ROUTER_UPTIME_HOURS),uptime/3600);uptime%=3600;s1 += strlen(s1);}
					if(uptime>60){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_UPTIME_MINUTES),uptime/60);uptime%=60;s1 += strlen(s1);}
					tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_UPTIME_SECONDS),uptime);s1 += strlen(s1);
				}
				else tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_LOW_UPTIME),ri->uptime);s1 += strlen(s1);
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_LAST_TIME_REACHED));s1 += strlen(s1);format_iso_time(s1,ri->last_reachable);s1+=strlen(s1);
				tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_REACHABILITY_TEST_SINCE));s1 += strlen(s1);format_iso_time(s1,ri->testing_since);s1+=strlen(s1);*s1++=13;*s1++=10;*s1=0;
				if(ri->contact_info){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_CONTACT_INFO),ri->contact_info);s1 += strlen(s1);}
				if(ri->is_hibernating){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_HIBERNATING));s1 += strlen(s1);}
				if(ri->caches_extra_info){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_SERVES_EXTRAINFO));s1 += strlen(s1);}
				if(ri->allow_single_hop_exits){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_ALLOWS_SINGLE_HOP_EXIT));s1 += strlen(s1);}
				if(ri->is_running){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_RUNNING));s1 += strlen(s1);}
				if(ri->is_valid){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_VALIDATED));s1 += strlen(s1);}
				else{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_NOT_VALIDATED));s1 += strlen(s1);}
				if(!ri->is_named){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_INVALID_NICKNAME));s1 += strlen(s1);}
				if(ri->is_fast){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_FAST));s1 += strlen(s1);}
				if(ri->is_stable){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_STABLE));s1 += strlen(s1);}
				if(ri->is_possible_guard){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_CAN_BE_ENTRY_GUARD));s1 += strlen(s1);}
				if(ri->is_exit && !ri->is_bad_exit){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_CAN_BE_EXIT));s1 += strlen(s1);}
				else if(ri->is_bad_exit){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_BAD_EXIT));s1 += strlen(s1);}
				if(ri->is_bad_directory){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_IS_BAD_DIR));s1 += strlen(s1);}
				if(ri->wants_to_be_hs_dir){	tor_snprintf(s1,200,get_lang_str(LANG_NETINFO_ROUTER_HS_DIR),ri->is_hs_dir?get_lang_str(LANG_NETINFO_ROUTER_HS_DIR_OK):get_lang_str(LANG_NETINFO_ROUTER_NOT_HS_DIR));s1 += strlen(s1);}
				else if(ri->is_hs_dir){	tor_snprintf(s1,200,get_lang_str(LANG_NETINFO_ROUTER_IS_HS_DIR));s1 += strlen(s1);}
				if(ri->policy_is_reject_star){	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_ROUTER_POLICY_REJECTS_EVERYTHING));s1 += strlen(s1);}
				if(ri->exit_policy)
				{	tor_snprintf(s1,100,"\r\n%s\r\n",get_lang_str(LANG_NETINFO_ROUTER_EXIT_POLICY));s1 += strlen(s1);
					int i;
					addr_policy_t *tmpe;
					for (i=0;i<smartlist_len(ri->exit_policy) && i<10;++i)
					{	tmpe = smartlist_get(ri->exit_policy, i);
						policy_write_item(s1,1024,tmpe,1);
						s1 += strlen(s1);
						*s1++=13;*s1++=10;*s1=0;
					}
				}
				else
				{	tor_snprintf(s1,100,"\r\n%s reject *:*\r\n",get_lang_str(LANG_NETINFO_ROUTER_EXIT_POLICY));s1 += strlen(s1);
				}
			}
			else
			{	if(hop->extend_info)
				{	tor_snprintf(s1,100,get_lang_str(LANG_NETINFO_HOP_DIGEST));
					s1 += strlen(s1);
					base16_encode(s1,HEX_DIGEST_LEN+1,hop->extend_info->identity_digest,DIGEST_LEN);s1[HEX_DIGEST_LEN]=0;
					s1 += strlen(s1);
				}
			}
			SetDlgItemTextL(hDlgNetInfo,25100,s);
			selected_item=lParam;
			selection_type=SELECTION_TYPE_HOP;
			selected_node=hItem;
			tor_free(s);
			SetDlgItemTextL(hDlgNetInfo,25001,get_lang_str(LANG_NETINFO_DESTROY_CIRCUIT));
			SetDlgItemTextL(hDlgNetInfo,25002,get_lang_str(LANG_NETINFO_NEW_CIRCUIT));
		}
		else
		{	conn=(connection_t*)lParam;
			if(conn->magic==EDGE_CONNECTION_MAGIC)
			{	char *s=tor_malloc(32767);
				show_connection_info(conn,s);
				SetDlgItemTextL(hDlgNetInfo,25100,s);
				tor_free(s);
				selected_item=lParam;
				selection_type=SELECTION_TYPE_STREAM;
				selected_node=hItem;
				SetDlgItemTextL(hDlgNetInfo,25001,get_lang_str(LANG_NETINFO_CLOSE_CONNECTION));
				SetDlgItemTextL(hDlgNetInfo,25002,get_lang_str(LANG_NETINFO_KILL_PROCESS));
			}
		}
	}
}

void add_all_conns(circuit_t *circ)
{	if(!circ->hItem || circ->marked_for_close) return;
	if(CIRCUIT_IS_ORIGIN(circ))
	{	LangEnterCriticalSection();
		origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
		crypt_path_t *hop=c->cpath;
		uint32_t raddr;
		char *nodename=tor_malloc(1024);
		routerinfo_t *ri;
		int expandtree;
		TV_INSERTSTRUCT tvins1;
		HTREEITEM hParent;
		tvins1.hParent=circ->hItem;
		tvins1.hInsertAfter=TVI_LAST;
		tvins1.item.hItem=0;
		tvins1.item.state=0;
		tvins1.item.stateMask=0;
		tvins1.item.iImage=0;
		tvins1.item.iSelectedImage=0;
		tvins1.item.cChildren=0;
		while(hop && hop->extend_info)
		{	if(hop->hItem) tvins1.hParent=hop->hItem;
			else
			{	ri = router_get_by_digest(hop->extend_info->identity_digest);
				if(ri)	raddr=geoip_reverse(ri->addr);
				else	raddr=tor_addr_to_ipv4n(&hop->extend_info->addr);
				int country = geoip_get_country_by_ip(raddr);
				if(hop->extend_info->nickname)
					tor_snprintf(nodename,1024,"[%s%s] %d.%d.%d.%d (%s)",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,hop->extend_info->nickname);
				else if(ri && ri->nickname)
					tor_snprintf(nodename,1024,"[%s%s] %d.%d.%d.%d (%s)",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,ri->nickname);
				else
				{	tor_snprintf(nodename,1024,"[%s%s] %d.%d.%d.%d - $",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
					nodename[strlen(nodename)+HEX_DIGEST_LEN]=0;
					base16_encode(nodename+strlen(nodename),HEX_DIGEST_LEN+1,hop->extend_info->identity_digest,DIGEST_LEN);
				}
				if(SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_CHILD,(LPARAM)tvins1.hParent))	expandtree=0;
				else	expandtree=1;
				hParent=tvins1.hParent;
				tvins1.item.mask=TVIF_PARAM|TVIF_TEXT;
				tvins1.item.lParam=(LPARAM)hop;
				tvins1.item.pszText=nodename;
				tvins1.item.cchTextMax=1024;
				hop->circ=circ;
				hop->hItem=tvins1.hParent=insert_new_node(&tvins1);
				if(expandtree)
					if(!SendDlgItemMessage(hDlgNetInfo,25500,TVM_EXPAND,TVE_EXPAND,(LPARAM)hParent))
						log(LOG_WARN,LD_APP,get_lang_str(LANG_MB_ERROR_UPDATING_TREE));
			}
			hop=hop->next;
			if(hop==c->cpath) break;
		}
		tor_free(nodename);
		LangLeaveCriticalSection();
	}
}

TV_INSERTSTRUCTW tvinsw;
void add_all_streams(HTREEITEM hItem,edge_connection_t *streams)
{	if(!hItem) return;
	char *nodename=tor_malloc(2048),*s1;
	LangEnterCriticalSection();
	while(streams)
	{	if(!streams->_base.marked_for_close)
		{	uint32_t raddr=tor_addr_to_ipv4n(&streams->_base.addr);
			nodename[0]=0;
			if(streams->_base.hPlugin)	get_dll_name(nodename,streams->_base.hPlugin);
			else if(!streams->_base.pid || !getProcessName(nodename,1023,streams->_base.pid))
			{	if(!raddr) tor_snprintf(nodename,256,"[Internal]");
				else tor_snprintf(nodename,256,"%d.%d.%d.%d:%d",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff,streams->_base.port);
			}
			if(strlen(nodename) > 1024)	nodename[1024]=0;
			s1=nodename+strlen(nodename);
			if(streams->socks_request)
			{	if(streams->socks_request->original_address && streams->socks_request->original_address[0]){	tor_snprintf(s1,512," -> %s",streams->socks_request->original_address);s1 += strlen(s1);}
				else if(streams->socks_request->address){	tor_snprintf(s1,512," -> %s",streams->socks_request->address);s1 += strlen(s1);}
				switch(streams->socks_request->command)
				{	case SOCKS_COMMAND_CONNECT:
						tor_snprintf(s1,100," (connect)");s1 += strlen(s1);
						break;
					case SOCKS_COMMAND_RESOLVE:
						tor_snprintf(s1,100," (resolve)");s1 += strlen(s1);
						break;
					case SOCKS_COMMAND_RESOLVE_PTR:
						tor_snprintf(s1,100," (reverse DNS)");s1 += strlen(s1);
						break;
					case SOCKS_COMMAND_SELECT_ROUTER:
						tor_snprintf(s1,100," (select router)");s1 += strlen(s1);
						break;
					default:
						tor_snprintf(s1,100," (unknown request)");s1 += strlen(s1);
						break;
				}
			}
			tvinsw.item.mask=TVIF_PARAM|TVIF_TEXT;
			tvinsw.hParent=hItem;
			tvinsw.hInsertAfter=TVI_LAST;
			tvinsw.item.hItem=0;
			tvinsw.item.state=0;
			tvinsw.item.stateMask=0;
			tvinsw.item.pszText=get_unicode(nodename);
			tvinsw.item.cchTextMax=1024;
			tvinsw.item.iImage=0;
			tvinsw.item.iSelectedImage=0;
			tvinsw.item.cChildren=0;
			tvinsw.item.lParam=(LPARAM)streams;
			if(streams->_base.hItem)
			{	if(streams->_base.hItem==selected_node) selected_node=0;
				SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)streams->_base.hItem);
			}
			int retries = 0;
			while(retries < MAX_TV_INSERT_RETRIES)
			{	LONG h = SendDlgItemMessageW(hDlgNetInfo,25500,TVM_INSERTITEMW,0,(LPARAM)&tvinsw);
				tvinsw.hInsertAfter=(HTREEITEM)h;
				if(tvinsw.hInsertAfter)	break;
				if(retries & 4)
					log(LOG_WARN,LD_APP,get_lang_str(LANG_MB_ERROR_UPDATING_TREE));
				Sleep(100);
				retries++;
			}
			streams->_base.hItem=tvinsw.hInsertAfter;
			tor_free(tvinsw.item.pszText);
		}
		else break;
		streams=streams->next_stream;
	}
	tor_free(nodename);
	LangLeaveCriticalSection();
}

void tree_add_streams(circuit_t *circ)
{	if(!adding_circuits || circ->hItem==NULL) return;
	if(CIRCUIT_IS_ORIGIN(circ))
	{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
		if(c->p_streams)	add_all_streams(circ->hItem,c->p_streams);
	}
	else
	{	or_circuit_t *c1=TO_OR_CIRCUIT(circ);
		if(c1->n_streams)	add_all_streams(circ->hItem,c1->n_streams);
		if(c1->resolving_streams) add_all_streams(circ->hItem,c1->resolving_streams);
	}
}

void tree_add_circ(circuit_t *circ,char *nodename)
{	LangEnterCriticalSection();
	tvins.item.mask=TVIF_PARAM|TVIF_TEXT;
	tvins.hParent=TVI_ROOT;
	tvins.hInsertAfter=TVI_LAST;
	tvins.item.hItem=0;
	tvins.item.state=0;
	tvins.item.stateMask=0;
	tvins.item.pszText=nodename;
	tvins.item.cchTextMax=1024;
	tvins.item.iImage=0;
	tvins.item.iSelectedImage=0;
	tvins.item.cChildren=0;
	tvins.item.lParam=NODE_TYPE_CIRCUIT;
	circ->hItem=tvins.hInsertAfter=insert_new_node(&tvins);
	LangLeaveCriticalSection();
	add_all_conns(circ);
	if(CIRCUIT_IS_ORIGIN(circ))
	{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
		if(c->p_streams)	add_all_streams(circ->hItem,c->p_streams);
		if(!c->build_state->is_internal && circ->state == CIRCUIT_STATE_OPEN)	setState(STATE_CONNECTED);
	}
	else
	{	or_circuit_t *c1=TO_OR_CIRCUIT(circ);
		if(c1->n_streams)	add_all_streams(circ->hItem,c1->n_streams);
		if(c1->resolving_streams) add_all_streams(circ->hItem,c1->resolving_streams);
	}
}

void tree_add_new_circ(circuit_t *circ)
{	if(!adding_circuits)
	{	if(CIRCUIT_IS_ORIGIN(circ) && !TO_ORIGIN_CIRCUIT(circ)->build_state->is_internal && circ->state == CIRCUIT_STATE_OPEN)
			setState(STATE_CONNECTED);
		return;
	}
	if(circ->hItem)	tree_remove_circ(circ);
	LangEnterCriticalSection();
	char *nodeName=tor_malloc(1024);
	tor_snprintf(nodeName,1023,"[%s] Circuit_%d - %s",circuit_purpose_to_string(circ->purpose),(unsigned int)circ->n_circ_id,circuit_state_to_string(circ->state));
	tvins.item.mask=TVIF_PARAM|TVIF_TEXT;
	tvins.item.hItem=0;
	tvins.item.state=0;
	tvins.item.stateMask=0;
	tvins.item.pszText=nodeName;
	tvins.item.cchTextMax=1024;
	tvins.item.iImage=0;
	tvins.item.iSelectedImage=0;
	tvins.item.cChildren=0;
	tvins.item.lParam=NODE_TYPE_CIRCUIT;
	tvins.hParent=TVI_ROOT;
	tvins.hInsertAfter=TVI_LAST;
	circ->hItem=tvins.hInsertAfter=insert_new_node(&tvins);
	tor_free(nodeName);
	LangLeaveCriticalSection();
	add_all_conns(circ);
	if(CIRCUIT_IS_ORIGIN(circ))
	{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
		if(c->p_streams)	add_all_streams(circ->hItem,c->p_streams);
		if(!c->build_state->is_internal && circ->state == CIRCUIT_STATE_OPEN)	setState(STATE_CONNECTED);
	}
	else if(circ->magic==OR_CIRCUIT_MAGIC)
	{	or_circuit_t *c=TO_OR_CIRCUIT(circ);
		if(c->n_streams)	add_all_streams(circ->hItem,c->n_streams);
		if(c->resolving_streams) add_all_streams(circ->hItem,c->resolving_streams);
	}
}

void tree_set_circ(circuit_t *circ)
{	if(!adding_circuits || circ->hItem==NULL)
	{	if(CIRCUIT_IS_ORIGIN(circ) && !TO_ORIGIN_CIRCUIT(circ)->build_state->is_internal && circ->state == CIRCUIT_STATE_OPEN)
			setState(STATE_CONNECTED);
		return;
	}
	LangEnterCriticalSection();
	char *nodeName=tor_malloc(1024);
	if(CIRCUIT_IS_ORIGIN(circ))
	{	if(TO_ORIGIN_CIRCUIT(circ)->build_state->is_internal)
			tor_snprintf(nodeName,1023,"[Internal][%s] %s_%d - %s",(circ->magic==ORIGIN_CIRCUIT_MAGIC)?"Origin":(circ->magic==OR_CIRCUIT_MAGIC)?"OR":"Unknown",circuit_purpose_to_string(circ->purpose),(unsigned int)circ->n_circ_id,circuit_state_to_string(circ->state));
		else
		{	tor_snprintf(nodeName,1023,"[Exit][%s] %s_%d - %s",(circ->magic==ORIGIN_CIRCUIT_MAGIC)?"Origin":(circ->magic==OR_CIRCUIT_MAGIC)?"OR":"Unknown",circuit_purpose_to_string(circ->purpose),(unsigned int)circ->n_circ_id,circuit_state_to_string(circ->state));
			if(circ->state == CIRCUIT_STATE_OPEN)	setState(STATE_CONNECTED);
		}
	}
	else	tor_snprintf(nodeName,1023,"[%s] %s_%d - %s",(circ->magic==ORIGIN_CIRCUIT_MAGIC)?"Origin":(circ->magic==OR_CIRCUIT_MAGIC)?"OR":"Unknown",circuit_purpose_to_string(circ->purpose),(unsigned int)circ->n_circ_id,circuit_state_to_string(circ->state));
	tvit.mask=TVIF_TEXT;
	tvit.hItem=circ->hItem;
	tvit.state=0;
	tvit.stateMask=0;
	tvit.pszText=nodeName;
	tvit.cchTextMax=1024;
	tvit.iImage=0;
	tvit.iSelectedImage=0;
	tvit.cChildren=0;
	tvit.lParam=NODE_TYPE_CIRCUIT;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_SETITEM,0,(LPARAM)&tvit);
	tor_free(nodeName);
	LangLeaveCriticalSection();
}

void tree_remove_stream(edge_connection_t *stream)
{	LangEnterCriticalSection();
	if(stream->_base.hItem==selected_node) selected_node=0;
	if(stream->_base.hItem)	SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)stream->_base.hItem);
	stream->_base.hItem=0;
	LangLeaveCriticalSection();
}

void remove_all_streams(edge_connection_t *streams)
{	LangEnterCriticalSection();
	while(streams)
	{	if(streams->_base.hItem)
		{	if(streams->_base.hItem==selected_node) selected_node=0;
			SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)streams->_base.hItem);
		}
		streams->_base.hItem=NULL;
		streams=streams->next_stream;
	}
	LangLeaveCriticalSection();
}

void tree_remove_streams(circuit_t *circ)
{	if(CIRCUIT_IS_ORIGIN(circ))
	{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(circ);
		if(c->p_streams)	remove_all_streams(c->p_streams);
	}
	else
	{	or_circuit_t *c1=TO_OR_CIRCUIT(circ);
		if(c1->n_streams)	remove_all_streams(c1->n_streams);
		if(c1->resolving_streams) remove_all_streams(c1->resolving_streams);
	}
}

void tree_remove_circ(circuit_t *circ)
{	if(adding_circuits && circ->hItem)
	{	tree_remove_streams(circ);
		LangEnterCriticalSection();
		if(circ->hItem==selected_node) selected_node=0;
		SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)circ->hItem);
		if(SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_ROOT,(LPARAM)0)==0)
			setState(STATE_CONNECTING);
		circ->hItem=NULL;
		LangLeaveCriticalSection();
	}
}

void tree_remove_hop(crypt_path_t *cpath)
{	if(cpath->hItem)
	{	LangEnterCriticalSection();
		if(cpath->circ)
		{	origin_circuit_t *c=TO_ORIGIN_CIRCUIT(cpath->circ);
			crypt_path_t *hop=c->cpath;
			int i=0;
			while(hop && hop->extend_info)
			{	if(hop==cpath) i++;
				else if(i)
				{	tree_remove_hop(hop);
					break;
				}
				hop=hop->next;
				if(hop==c->cpath) break;
			}
		}
		if(cpath->hItem==selected_node) selected_node=0;
		SendDlgItemMessage(hDlgNetInfo,25500,TVM_DELETEITEM,0,(LPARAM)cpath->hItem);
		cpath->hItem=NULL;
		LangLeaveCriticalSection();
	}
}

void tree_destroy_circuit_menu(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem) return;
	circuit_t *circ;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	if(lParam!=NODE_TYPE_CIRCUIT)
	{	HTREEITEM hParent=hItem;
		LONG h;
		while(hItem)
		{	h = SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_PARENT,(LPARAM)hItem);
			hItem=(HTREEITEM)h;
			if(hItem) hParent=hItem;
		}
		circ=get_circuit_by_hitem(hParent);
		if(!circ) return;
	}
	else circ=get_circuit_by_hitem(hItem);
	if(circ && !circ->marked_for_close)
	{	circ->timestamp_dirty = -get_options()->MaxCircuitDirtiness;
      		circuit_mark_for_close(circ,END_CIRC_REASON_REQUESTED);
	}
}

void tree_ban_entry_menu(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem || !lastRouterSel) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	char *routername=find_router_by_ip_port(lastRouterSel,lastPortSel);
	if(!routername) return;
	routerinfo_t *router=find_routerinfo_by_ip_port(lastRouterSel,lastPortSel);
	if(router)
	{	entry_guard_t *entry = is_an_entry_guard(router->cache_info.identity_digest);
		if (entry)
		{	entry->made_contact=0;
			entry_guard_register_connect_status(router->cache_info.identity_digest,0,0,get_time(NULL));
		}
	}
	add_router_to_banlist(hMainDialog,routername,0);
	tor_free(routername);
	tree_destroy_circuit_menu();
}

void tree_ban_exit_menu(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem || !lastRouterSel) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	char *routername=find_router_by_ip_port(lastRouterSel,lastPortSel);
	if(!routername) return;
	add_router_to_banlist(hMainDialog,routername,'X');
	tor_free(routername);
	tree_destroy_circuit_menu();
}

void tree_fav_entry_menu(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem || !lastRouterSel) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	char *routername=find_router_by_ip_port(lastRouterSel,lastPortSel);
	if(!routername) return;
	add_router_to_favorites(hMainDialog,routername,'E');
	tor_free(routername);
}

void tree_fav_exit_menu(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem || !lastRouterSel) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	char *routername=find_router_by_ip_port(lastRouterSel,lastPortSel);
	if(!routername) return;
	add_router_to_favorites(hMainDialog,routername,'X');
	tor_free(routername);
}

void tree_invalidate_router(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem || !lastRouterSel) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	routerinfo_t *router=find_routerinfo_by_ip_port(lastRouterSel,lastPortSel);
	if(!router) return;
	if(router->is_valid)
	{	char *msg=tor_malloc(256);
		router->is_valid=0;
		tor_snprintf(msg,256,get_lang_str(LANG_MB_SET_INVALID),router->nickname?router->nickname:"Unnamed");
		log(LOG_INFO,LD_APP,msg);
		LangMessageBox(hMainDialog,msg,LANG_MB_INVD_TITLE,MB_OK);
		tor_free(msg);
	}
	else
	{	char *msg=tor_malloc(256);
		tor_snprintf(msg,256,get_lang_str(LANG_MB_ALREADY_INVALID),router->nickname?router->nickname:"Unnamed");
		LangMessageBox(hMainDialog,msg,LANG_MB_INVD_TITLE,MB_OK);
		tor_free(msg);
	}
}

void tree_close_connection(void)
{	HTREEITEM hItem=lastContextSel;
	if(!hItem) return;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	connection_t *conn=(connection_t*)tvit.lParam;
	if(!conn) return;
	if(conn && conn->magic==EDGE_CONNECTION_MAGIC)
	{	TO_EDGE_CONN(conn)->edge_has_sent_end = 1;
		TO_EDGE_CONN(conn)->end_reason = END_STREAM_REASON_DESTROY | END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
		connection_mark_for_close(conn);
	}
}

void tree_kill_process(void)
{	if(!lastPid) return;
	HANDLE hProcess=OpenProcess(PROCESS_TERMINATE,0,lastPid);
	if(hProcess)
	{	TerminateProcess(hProcess,0);
		CloseHandle(hProcess);
	}
	else
	{	char *msg=tor_malloc(1024),*errormsg;
		int lasterror=GetLastError();
		errormsg=format_win32_error(lasterror);
		tor_snprintf(msg,1023,get_lang_str(LANG_NETINFO_ERROR_OPENING_PROCESS),lasterror,errormsg);
		LangMessageBox(hMainDialog,msg,LANG_MB_ERROR,MB_OK);
		tor_free(errormsg);
		tor_free(msg);
	}
}

void tree_destroy_circuit(void)
{	circuit_t *circ;
	if(!selected_node) return;
	if(selection_type==SELECTION_TYPE_STREAM)
	{	tvit.hItem=selected_node;tvit.mask=TVIF_PARAM;tvit.lParam=0;
		SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
		selected_item=tvit.lParam;
		if(!selected_item) return;
		connection_t *conn=(connection_t*)selected_item;
		if(conn && conn->magic==EDGE_CONNECTION_MAGIC)
		{	TO_EDGE_CONN(conn)->edge_has_sent_end = 1;
			TO_EDGE_CONN(conn)->end_reason = END_STREAM_REASON_DESTROY | END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
			connection_mark_for_close(conn);
		}
		return;
	}
	if(selection_type != SELECTION_TYPE_CIRCUIT)
	{	HTREEITEM hItem=selected_node,hParent=selected_node;
		LONG h;
		while(hItem)
		{	h = SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_PARENT,(LPARAM)hItem);
			hItem=(HTREEITEM)h;
			if(hItem) hParent=hItem;
		}
		circ=get_circuit_by_hitem(hParent);
		if(!circ) return;
	}
	else circ=get_circuit_by_hitem(selected_node);
	if(circ && !circ->marked_for_close)
	{	circ->timestamp_dirty = -get_options()->MaxCircuitDirtiness;
      		circuit_mark_for_close(circ,END_CIRC_REASON_REQUESTED);
	}
}

void build_show_router_info(char *s1,routerinfo_t *r)
{	if(r)
	{	uint32_t raddr=geoip_reverse(r->addr);
		int country = geoip_get_country_by_ip(raddr);
		tor_snprintf(s1,100,"; [%s%s] %d.%d.%d.%d (",geoip_get_country_name(country&0xff),country>0xff?"*":"",raddr&0xff,(raddr>>8)&0xff,(raddr>>16)&0xff,(raddr>>24)&0xff);
		s1 += strlen(s1);
		FormatMemInt(s1,r->bandwidthrate);s1+=strlen(s1);*s1++=')';*s1++=13;*s1++=10;*s1=0;
		s1 += strlen(s1);
		if(r->nickname && router_get_by_nickname(r->nickname,0))	tor_snprintf(s1,100,"%s\r\n",r->nickname);
		else
		{	s1[0]='$';base16_encode(s1+1,HEX_DIGEST_LEN+1,r->cache_info.identity_digest,DIGEST_LEN);s1[HEX_DIGEST_LEN+1]=0;s1 += strlen(s1);*s1++=13;*s1++=10;*s1=0;
		}
		s1 += strlen(s1);*s1++=13;*s1++=10;*s1=0;
	}
}

void tree_estimate_circuit(HWND hDlg,int hops)
{	routerlist_t *rl = router_get_routerlist();
	if(!rl) return;
	char *nodelist=tor_malloc(32768),*s1;
	int cur_len=0,str_len=0,failures=0;
	cpath_build_state_t *state = tor_malloc_zero(sizeof(cpath_build_state_t));
	crypt_path_t *cpath=NULL;
	extend_info_t *info=NULL;
	routerinfo_t *r;
	s1=nodelist;s1[0]=0;
	if(hops>1)
	{	r =  choose_good_entry_server(CIRCUIT_PURPOSE_C_GENERAL,state);
		build_show_router_info(s1,r);s1 += strlen(s1);
		if(r)
		{	info = extend_info_from_router(r);
			if(info)
			{	onion_append_hop(&cpath,info);
				extend_info_free(info);
			}
		}
		else failures++;
		hops--;cur_len++;
	}
	while(hops>1)
	{	r =  choose_good_middle_server(CIRCUIT_PURPOSE_C_GENERAL,state,cpath,cur_len);
		build_show_router_info(s1,r);s1 += strlen(s1);
		if(r)
		{	info = extend_info_from_router(r);
			if(info)
			{	onion_append_hop(&cpath,info);
				extend_info_free(info);
			}
		}
		else failures++;
		hops--;cur_len++;
		str_len=s1-nodelist;
		if(str_len>32000) break;
	}
	r = choose_good_exit_server(CIRCUIT_PURPOSE_C_GENERAL,rl,0,1,0,0);
	build_show_router_info(s1,r);s1 += strlen(s1);
	if(!r)	failures++;
	if(failures)
	{	char *msg=tor_malloc(1024);
		tor_snprintf(msg,1023,get_lang_str(LANG_NETINFO_BUILD_ESTIMATE_FAILED),failures);
		LangMessageBox(hDlg,msg,LANG_NETINFO_BUILD_ESTIMATE_PATH,MB_OK);
		tor_free(msg);
	}
	if(cpath)	circuit_free_cpath(cpath);
	SetDlgItemText(hDlg,100,nodelist);
	SendDlgItemMessage(hDlg,100,EM_SETSEL,-1,-1);
	tor_free(state);
	tor_free(nodelist);
}

void tree_build_circuit(HWND hDlg)
{	char *nodelist=tor_malloc(32768),*s1,*s2,c;
	int hops=0;
	GetDlgItemText(hDlg,100,nodelist,32767);
	s1=nodelist;
	origin_circuit_t *circ;
	circuit_reset_failure_count(0);
	circ = origin_circuit_init(CIRCUIT_PURPOSE_C_GENERAL,0);
	extend_info_t *info=NULL;
	routerinfo_t *r=NULL;
	while(*s1)
	{	while(*s1)
		{	while((*s1<=32)&&(*s1!=0))	s1++;
			if(*s1==';')
			{	while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
			}
			else break;
		}
		if(*s1)
		{	s2=s1;
			while(*s2>32 && *s1!=';')	s2++;
			c = *s2;*s2=0;
			r=router_get_by_nickname(s1,0);
			if(r && ((info = extend_info_from_router(r))!=NULL))
			{	onion_append_hop(&circ->cpath,info);
				hops++;
				extend_info_free(info);
			}
			else
			{	char *msg=tor_malloc(1024);
				tor_snprintf(msg,1023,get_lang_str(LANG_NETINFO_ROUTER_NOT_FOUND),s1);
				LangMessageBox(hDlg,msg,LANG_NETINFO_ROUTER_NOT_FOUND_TITLE,MB_OK);
				tor_free(msg);
				circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_NOPATH);
				tor_free(nodelist);
				return;
			}
			*s2=c;
			s1=s2;
		}
	}
	if(r)
	{	circ->build_state->chosen_exit=extend_info_from_router(r);
		if(is_router_excluded(circ->build_state->chosen_exit))
		{	char *msg=tor_malloc(1024);
			tor_snprintf(msg,1023,get_lang_str(LANG_NETINFO_ROUTER_IN_BANLIST),s1);
			if(LangMessageBox(hDlg,msg,LANG_NETINFO_BANNED_ROUTER,MB_YESNO)==IDNO)
			{	tor_free(msg);
				circuit_mark_for_close(TO_CIRCUIT(circ),END_CIRC_REASON_NOPATH);
				tor_free(nodelist);
				return;
			}
			tor_free(msg);
		}
	}
	circ->build_state->desired_path_len=hops;
	add_all_conns(TO_CIRCUIT(circ));
	control_event_circuit_status(circ,CIRC_EVENT_LAUNCHED,0);
	tor_free(nodelist);
	if(circ->cpath)
		circuit_handle_first_hop(circ);
}

void replace_entry(HWND hDlg,routerinfo_t *r)
{	char *nodelist=tor_malloc(32768),*s1,*s2;
	s1=nodelist;
	build_show_router_info(s1,r);s1 += strlen(s1);
	GetDlgItemText(hDlg,100,s1,32600);
	s2=s1;
	while(*s1)
	{	while((*s1<=32)&&(*s1!=0))	s1++;
		if(*s1==';')
		{	while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
		}
		else break;
	}
	if(*s1)
	{	while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
		while(*s1==13 || *s1==10) s1++;
		while(*s1)	*s2++=*s1++;
	}
	*s2=0;
	SetDlgItemText(hDlg,100,nodelist);
	tor_free(nodelist);
}

void replace_exit(HWND hDlg,routerinfo_t *r)
{	char *nodelist=tor_malloc(32768),*s1,*s2;
	char *lastnode=NULL,*prevcomm=NULL;;
	s1=nodelist;
	GetDlgItemText(hDlg,100,s1,32600);
	int max_length=GetDlgItemInt(hDlg,101,NULL,0);
	s2=s1;
	int numnodes=0;
	while(*s1)
	{	while(*s1)
		{	while((*s1<=32)&&(*s1!=0))	s1++;
			if(*s1==';')
			{	prevcomm=s1;
				while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
			}
			else break;
		}
		if(*s1)
		{	lastnode=s1;
			while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
			while(*s1==13 || *s1==10) s1++;
			numnodes++;
		}
	}
	if(numnodes>=max_length)
	{	if(prevcomm)	lastnode=prevcomm;
		if(lastnode)	*lastnode=0;
	}
	else
	{	while(s1>s2)
		{	s1--;
			if(*s1==13)	*s1=0;
			else if(*s1==10)	*s1=0;
			else break;
		}
		s1 += strlen(s1);
		*s1++=13;*s1++=10;*s1++=13;*s1++=10;*s1=0;
	}
	s1 = s2;
	s1 += strlen(s1);
	build_show_router_info(s1,r);s1 += strlen(s1);
	*s1=0;
	SetDlgItemText(hDlg,100,nodelist);
	tor_free(nodelist);
}

void replace_middle(HWND hDlg,routerinfo_t *r)
{	char *nodelist=tor_malloc(32768),*s1,*s2;
	char *lastnode=NULL,*prevcomm=NULL;;
	s1=nodelist;
	GetDlgItemText(hDlg,100,s1,32600);
	int max_length=GetDlgItemInt(hDlg,101,NULL,0);
	s2=s1;
	int numnodes=0;
	while(*s1)
	{	while(*s1)
		{	while((*s1<=32)&&(*s1!=0))	s1++;
			if(*s1==';')
			{	prevcomm=s1;
				while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
			}
			else break;
		}
		if(*s1)
		{	lastnode=s1;
			while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
			while(*s1==13 || *s1==10) s1++;
			numnodes++;
		}
	}
	if(prevcomm)	lastnode=prevcomm;
	if(numnodes<max_length)
	{	char *s3=tor_malloc(32768),*s4;
		s4=s3;s1=s2;
		if(lastnode)
			while(s1<lastnode)	*s4++=*s1++;
		*s4=0;
		build_show_router_info(s4,r);s4 += strlen(s4);
		while(*s1)	*s4++=*s1++;
		*s4=0;
		strcpy(s2,s3);
		tor_free(s3);
	}
	else
	{	s1=s2;
		char *s3;
		if(!lastnode)	lastnode=s1;
		s3=lastnode;lastnode=NULL;
		while(*s1 && s1<s3)
		{	while(*s1 && s1<s3)
			{	while((*s1<=32)&&(*s1!=0))	s1++;
				if(*s1==';')
				{	prevcomm=s1;
					while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
				}
				else break;
			}
			if(*s1 && s1<s3)
			{	lastnode=s1;
				while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
				while(*s1==13 || *s1==10) s1++;
			}
		}
		s3=tor_malloc(32768);
		char *s4;
		s4=s3;s1=s2;
		if(prevcomm)	lastnode=prevcomm;
		if(lastnode)
			while(s1<lastnode)	*s4++=*s1++;
		*s4=0;
		build_show_router_info(s4,r);s4 += strlen(s4);
		if(*s1==';')
		{	while(*s1>=32)	s1++;
			while(*s1==13 || *s1==10)	s1++;
		}
		while(*s1!=0 && *s1!=13 && *s1!=10)	s1++;
		while(*s1==13 || *s1==10)	s1++;
		while(*s1)	*s4++=*s1++;
		*s4=0;
		strcpy(s2,s3);
		tor_free(s3);
	}
	SetDlgItemText(hDlg,100,nodelist);
	tor_free(nodelist);
}

void tree_create_circuit_menu(void)
{	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1003),hMainDialog,&dlgNewCircuit,0);
}

void tree_set_priority(int new_priority)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem) return;
	circuit_t *circ;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	if(lParam!=NODE_TYPE_CIRCUIT)
	{	HTREEITEM hParent=hItem;
		LONG h;
		while(hItem)
		{	h = SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_PARENT,(LPARAM)hItem);
			hItem=(HTREEITEM)h;
			if(hItem) hParent=hItem;
		}
		circ=get_circuit_by_hitem(hParent);
		if(!circ) return;
	}
	else circ=get_circuit_by_hitem(hItem);
	if(circ)	circ->priority = new_priority;
}


void tree_create_circuit(void)
{	if(selection_type==SELECTION_TYPE_STREAM)
	{	if(!selected_node) return;
		tvit.hItem=selected_node;tvit.mask=TVIF_PARAM;tvit.lParam=0;
		SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
		selected_item=tvit.lParam;
		if(!selected_item) return;
		connection_t *conn=(connection_t*)selected_item;
		if(conn && conn->magic==EDGE_CONNECTION_MAGIC)
		{	if(conn->pid)
			{	HANDLE hProcess=OpenProcess(PROCESS_TERMINATE,0,conn->pid);
				if(hProcess)
				{	TerminateProcess(hProcess,0);
					CloseHandle(hProcess);
				}
				else
				{	char *msg=tor_malloc(1024),*errormsg;
					int lasterror=GetLastError();
					errormsg=format_win32_error(lasterror);
					tor_snprintf(msg,1023,get_lang_str(LANG_NETINFO_ERROR_OPENING_PROCESS),lasterror,errormsg);
					LangMessageBox(hMainDialog,msg,LANG_MB_ERROR,MB_OK);
					tor_free(errormsg);
					tor_free(msg);
				}
			}
			else	LangMessageBox(hMainDialog,get_lang_str(LANG_NETINFO_PID_NOT_FOUND),LANG_MB_ERROR,MB_OK);
		}
		return;
	}
	DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1003),hMainDialog,&dlgNewCircuit,0);
}

void tree_lang_update(void)
{
	if(hDlgNetInfo && LangGetLanguage())
	{	changeDialogStrings(hDlgNetInfo,lang_dlg_netinfo);
		if(selection_type==SELECTION_TYPE_STREAM)
		{	SetDlgItemTextL(hDlgNetInfo,25001,get_lang_str(LANG_NETINFO_CLOSE_CONNECTION));
			SetDlgItemTextL(hDlgNetInfo,25002,get_lang_str(LANG_NETINFO_KILL_PROCESS));
		}
		else
		{	SetDlgItemTextL(hDlgNetInfo,25001,get_lang_str(LANG_NETINFO_DESTROY_CIRCUIT));
			SetDlgItemTextL(hDlgNetInfo,25002,get_lang_str(LANG_NETINFO_NEW_CIRCUIT));
		}
	}
}

circuit_t *tree_get_selected_circuit(void)
{	LPARAM lParam;
	HTREEITEM hItem=lastContextSel;
	if(!hItem) return NULL;
	circuit_t *circ;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return NULL;
	if(lParam!=NODE_TYPE_CIRCUIT)
	{	HTREEITEM hParent=hItem;
		LONG h;
		while(hItem)
		{	h = SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETNEXTITEM,TVGN_PARENT,(LPARAM)hItem);
			hItem=(HTREEITEM)h;
			if(hItem) hParent=hItem;
		}
		circ=get_circuit_by_hitem(hParent);
		if(!circ) return NULL;
	}
	else circ=get_circuit_by_hitem(hItem);
	return circ;
}

void tree_show_menu(HTREEITEM hItem)
{	LPARAM lParam;
	HMENU hMenu;POINT cPoint;
	tvit.hItem=hItem;tvit.mask=TVIF_PARAM;tvit.lParam=0;
	SendDlgItemMessage(hDlgNetInfo,25500,TVM_GETITEM,0,(LPARAM)&tvit);
	lParam=tvit.lParam;
	if(lParam==0) return;
	lastContextSel=hItem;
	hMenu=CreatePopupMenu();
	if(lParam==NODE_TYPE_CIRCUIT)
	{	LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25003,LANG_NETINFO_DESTROY_CIRCUIT);
		LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25004,LANG_NETINFO_NEW_CIRCUIT);
		AppendMenu(hMenu,MF_SEPARATOR,0,0);
		circuit_t *circ = tree_get_selected_circuit();
		if(circ && !circ->marked_for_close)
		{	HMENU hMenu2 = CreatePopupMenu();
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25020,LANG_NETINFO_CIRC_PRIORITY_HIGH);
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25021,LANG_NETINFO_CIRC_PRIORITY_NORMAL);
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25022,LANG_NETINFO_CIRC_PRIORITY_LOW);
			if(circ->priority < 0)	CheckMenuItem(hMenu2,25020,MF_BYCOMMAND|MF_CHECKED);
			else if(circ->priority == 0)	CheckMenuItem(hMenu2,25021,MF_BYCOMMAND|MF_CHECKED);
			else if(circ->priority > 0)	CheckMenuItem(hMenu2,25022,MF_BYCOMMAND|MF_CHECKED);
			LangAppendMenu(hMenu,MF_POPUP,(UINT)hMenu2,LANG_NETINFO_CIRC_PRIORITY);
			hMenu2 = CreatePopupMenu();
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25025,LANG_NETINFO_CIRC_AVAILABILITY_ALWAYS);
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25026,LANG_NETINFO_CIRC_AVAILABILITY_NORMAL);
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25027,LANG_NETINFO_CIRC_AVAILABILITY_EXPIRED);
			LangAppendMenu(hMenu2,MF_STRING|MF_UNCHECKED|MF_ENABLED,25028,LANG_NETINFO_CIRC_AVAILABILITY_NOT_SET);
			int max_dirtiness = get_options()->MaxCircuitDirtiness;
			if(!circ->timestamp_dirty)	CheckMenuItem(hMenu2,25028,MF_BYCOMMAND|MF_CHECKED);
			else
			{	if(max_dirtiness)
				{	if((uint64_t)circ->timestamp_dirty > (get_time(NULL) + 0x10000000ULL))	CheckMenuItem(hMenu2,25025,MF_BYCOMMAND|MF_CHECKED);
					else if((uint64_t)circ->timestamp_dirty < (uint64_t)(get_time(NULL)-max_dirtiness))	CheckMenuItem(hMenu2,25027,MF_BYCOMMAND|MF_CHECKED);
					else										CheckMenuItem(hMenu2,25026,MF_BYCOMMAND|MF_CHECKED);
				}
				else	CheckMenuItem(hMenu2,25025,MF_BYCOMMAND|MF_CHECKED);
			}
			LangAppendMenu(hMenu,MF_POPUP,(UINT)hMenu2,LANG_NETINFO_CIRC_AVAILABILITY);
		}
	}
	else
	{	crypt_path_t *hop=(crypt_path_t*)lParam;
		routerinfo_t *ri=NULL;
		if(hop->magic == CRYPT_PATH_MAGIC)
		{	LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25003,LANG_NETINFO_DESTROY_CIRCUIT);
			LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25004,LANG_NETINFO_NEW_CIRCUIT);
			if(hop->extend_info)
			{	ri = router_get_by_digest(hop->extend_info->identity_digest);
				if(ri)
				{	lastRouterSel=ri->addr;
					lastPortSel=ri->or_port;
				}
				else
				{	lastRouterSel=tor_addr_to_ipv4h(&hop->extend_info->addr);
				}
				if(hop->extend_info->port) lastPortSel=hop->extend_info->port;
				if(ri && lastRouterSel)
				{	AppendMenu(hMenu,MF_SEPARATOR,0,0);
					char *menustr=tor_malloc(256);
					tor_snprintf(menustr,255,get_lang_str(LANG_MNU_BAN_ENTRY),hop->extend_info->nickname);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25005,menustr);
					if(ri->is_exit)
					{	tor_snprintf(menustr,255,get_lang_str(LANG_MNU_BAN_EXIT),hop->extend_info->nickname);
						LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25006,menustr);
					}
					tor_snprintf(menustr,255,get_lang_str(LANG_MNU_MARK_INVALID),hop->extend_info->nickname);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25007,menustr);
					if((ri->is_possible_guard)||(ri->is_exit))	AppendMenu(hMenu,MF_SEPARATOR,0,0);
					if(ri->is_possible_guard)
					{	tor_snprintf(menustr,255,get_lang_str(LANG_MNU_FAV_ENTRY),hop->extend_info->nickname);
						LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25008,menustr);
					}
					if(ri->is_exit)
					{	tor_snprintf(menustr,255,get_lang_str(LANG_MNU_FAV_EXIT),hop->extend_info->nickname);
						LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25009,menustr);
					}
					tor_free(menustr);
				}
			}
		}
		else
		{	connection_t *conn=(connection_t*)lParam;
			if(conn->magic==EDGE_CONNECTION_MAGIC)
			{	LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25003,LANG_NETINFO_DESTROY_CIRCUIT);
				LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25004,LANG_NETINFO_NEW_CIRCUIT);
				AppendMenu(hMenu,MF_SEPARATOR,0,0);
				LangAppendMenu(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25010,LANG_NETINFO_CLOSE_CONNECTION);
				edge_connection_t *conn2=TO_EDGE_CONN(conn);
				char *menustr=tor_malloc(512);
				if(conn2->_base.pid)
				{	lastPid=conn2->_base.pid;
					char *s1=tor_malloc(200);
					getProcessName(s1,200,conn2->_base.pid);
					tor_snprintf(menustr,255,get_lang_str(LANG_MNU_KILL_PROCESS),s1,(unsigned int)conn2->_base.pid);
					tor_free(s1);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25011,menustr);
				}
				if(conn2->socks_request && conn2->socks_request->original_address)
				{	tor_snprintf(lastSocksOriginalAddress,MAX_SOCKS_ADDR_LEN,conn2->socks_request->original_address);
					tor_snprintf(lastSocksAddress,MAX_SOCKS_ADDR_LEN,conn2->socks_request->address);
					AppendMenu(hMenu,MF_SEPARATOR,0,0);
					tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_TRACK_EXIT),conn2->socks_request->original_address);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25012,menustr);
					char *s1=conn2->socks_request->original_address,*s2;
					s2=s1;
					while(*s2)	s2++;
					while(s2>s1)
					{	s2--;
						if(*s2=='.') break;
					}
					while(s2>s1)
					{	s2--;
						if(*s2=='.') break;
					}
					if(s2>s1)
					{	tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_TRACK_EXIT_1),s2);
						LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25013,menustr);
					}
					tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_REMEMBER_EXIT),conn2->socks_request->original_address);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25014,menustr);
					tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_FORGET_EXIT),conn2->socks_request->original_address);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25015,menustr);
					AppendMenu(hMenu,MF_SEPARATOR,0,0);
					tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_BAN_HOST),conn2->socks_request->original_address);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25016,menustr);
					tor_snprintf(menustr,512,"%s%s",get_lang_str(LANG_MNU_BAN_HOST),conn2->socks_request->address);
					LangAppendMenuStr(hMenu,MF_STRING|MF_UNCHECKED|MF_ENABLED,25017,menustr);
				}
				tor_free(menustr);
			}
		}
	}
	GetCursorPos(&cPoint);
	TrackPopupMenu(hMenu,TPM_LEFTALIGN,cPoint.x,cPoint.y,0,hDlgNetInfo,0);
	DestroyMenu(hMenu);
}


int __stdcall dlgNewCircuit(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	int circuit_length;
	(void) lParam;
	switch(uMsg)
	{	case WM_INITDIALOG:
			if(LangGetLanguage())
			{	SetWindowTextL(hDlg,LANG_NETINFO_BUILD_CIRCUIT);
				changeDialogStrings(hDlg,lang_dlg_circ);
			}
			circuit_length=get_options()->CircuitPathLength;
			SetDlgItemInt(hDlg,101,circuit_length,0);
			tree_estimate_circuit(hDlg,circuit_length);
			break;
		case WM_COMMAND:
			if(LOWORD(wParam)==2)
			{	EndDialog(hDlg,0);
			}
			else if(LOWORD(wParam)==1)
			{	tree_build_circuit(hDlg);
				EndDialog(hDlg,1);
			}
			else if(LOWORD(wParam)==3)
			{	circuit_length=GetDlgItemInt(hDlg,101,NULL,0);
				tree_estimate_circuit(hDlg,circuit_length);
			}
			else if(LOWORD(wParam)==4)
			{	int i=DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1005),hDlg,&dlgRouterSelect,SELECT_ENTRY);
				if(i!=-1)
				{	routerinfo_t *r=get_router_by_index(i);
					if(r)	replace_entry(hDlg,r);
				}
			}
			else if(LOWORD(wParam)==6)
			{	int i=DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1005),hDlg,&dlgRouterSelect,SELECT_ANY);
				if(i!=-1)
				{	routerinfo_t *r=get_router_by_index(i);
					if(r)	replace_middle(hDlg,r);
				}
			}
			else if(LOWORD(wParam)==7)
			{	int i=DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1005),hDlg,&dlgRouterSelect,SELECT_EXIT);
				if(i!=-1)
				{	routerinfo_t *r=get_router_by_index(i);
					if(r)	replace_exit(hDlg,r);
				}
			}
			else if(LOWORD(wParam)==5)
			{	HMENU hMenu=CreatePopupMenu();
				add_favorite_entries_to_menu(hMenu);
				if(entry_guards)
				{	int i=20000;
					SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
					{	if(router_get_by_digest(entry->identity))
						{	AppendMenu(hMenu,MF_STRING,i++,entry->nickname);
							if(i>=20100) break;
						}
					});
				}
				RECT wRect;GetWindowRect(GetDlgItem(hDlg,4),&wRect);
				TrackPopupMenu(hMenu,TPM_LEFTALIGN,wRect.left,wRect.bottom,0,hDlg,0);
				DestroyMenu(hMenu);
			}
			else if(LOWORD(wParam)==8)
			{	HMENU hMenu=CreatePopupMenu();
				add_routers_to_menu(hMenu);
				RECT wRect;GetWindowRect(GetDlgItem(hDlg,7),&wRect);
				TrackPopupMenu(hMenu,TPM_LEFTALIGN,wRect.left,wRect.bottom,0,hDlg,0);
				DestroyMenu(hMenu);
			}
			else if((LOWORD(wParam)>=20000) && (LOWORD(wParam)<20100))
			{	if(entry_guards)
				{	WPARAM i=20000;
					SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
					{	if(router_get_by_digest(entry->identity))
						{	if(i==wParam)
							{	routerinfo_t *r=router_get_by_digest(entry->identity);
								if(r)	replace_entry(hDlg,r);
								break;
							}
							i++;
						}
					});
				}
			}
			else if((LOWORD(wParam)>=20100) && (LOWORD(wParam)<20200))
			{	uint32_t newSel=get_menu_selection(LOWORD(wParam)-20100);
				if(newSel)
				{	routerinfo_t *r=get_router_by_index(newSel-1024);
					if(r)	replace_entry(hDlg,r);
				}
			}
			else if((LOWORD(wParam)>=20200) && (LOWORD(wParam)<21000))
			{	uint32_t newSel=get_menu_selection(LOWORD(wParam)-20200);
				if(newSel)
				{	routerinfo_t *r=get_router_by_ip(newSel);
					if(r)	replace_exit(hDlg,r);
				}
			}
			break;
		default:
			break;
	}
	return	0;
}


int __stdcall dlgNetInfo(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{	if(uMsg==WM_INITDIALOG)
	{	hDlgNetInfo=hDlg;
		tree_lang_update();
		dlgShowRWStats(hDlg);
	}
	else if(uMsg==WM_COMMAND)
	{
		if(LOWORD(wParam)==25001)
			tree_destroy_circuit();
		else if(LOWORD(wParam)==25002 && started&1)
			tree_create_circuit();
		else if(LOWORD(wParam)==25003)
			tree_destroy_circuit_menu();
		else if(LOWORD(wParam)==25004 && started&1)
			tree_create_circuit_menu();
		else if(LOWORD(wParam)==25005)
			tree_ban_entry_menu();
		else if(LOWORD(wParam)==25006)
			tree_ban_exit_menu();
		else if(LOWORD(wParam)==25007)
			tree_invalidate_router();
		else if(LOWORD(wParam)==25008)
			tree_fav_entry_menu();
		else if(LOWORD(wParam)==25009)
			tree_fav_exit_menu();
		else if(LOWORD(wParam)==25010)
			tree_close_connection();
		else if(LOWORD(wParam)==25011)
			tree_kill_process();
		else if(LOWORD(wParam)==25012)
			dlgTrackedHosts_trackedHostExitAdd(hDlg,lastSocksOriginalAddress);
		else if(LOWORD(wParam)==25013)
			dlgTrackedHosts_trackedDomainExitAdd(hDlg,lastSocksOriginalAddress);
		else if(LOWORD(wParam)==25014)
			dlgTrackedHosts_addressMapAdd(hDlg,lastSocksOriginalAddress);
		else if(LOWORD(wParam)==25015)
			dlgTrackedHosts_addressMapRemove(hDlg,lastSocksOriginalAddress);
		else if(LOWORD(wParam)==25016)
			dlgProxy_banSocksAddress(lastSocksOriginalAddress);
		else if(LOWORD(wParam)==25017)
			dlgProxy_banSocksAddress(lastSocksAddress);
		else if(LOWORD(wParam)==25020)
			tree_set_priority(-1);
		else if(LOWORD(wParam)==25021)
			tree_set_priority(0);
		else if(LOWORD(wParam)==25022)
			tree_set_priority(1);
		else if(LOWORD(wParam)==25025)
		{	circuit_t *circ = tree_get_selected_circuit();
			if(circ)	circ->timestamp_dirty = get_time(NULL) + 0x20000000LL;
		}
		else if(LOWORD(wParam)==25026)
		{	circuit_t *circ = tree_get_selected_circuit();
			if(circ)	circ->timestamp_dirty = get_time(NULL);
		}
		else if(LOWORD(wParam)==25027)
		{	circuit_t *circ = tree_get_selected_circuit();
			if(circ)	circ->timestamp_dirty = get_time(NULL) - (get_options()->MaxCircuitDirtiness + 1);
		}
		else if(LOWORD(wParam)==25028)
		{	circuit_t *circ = tree_get_selected_circuit();
			if(circ)	circ->timestamp_dirty = 0;
		}
	}
	else if(uMsg==WM_TIMER)
	{	if(wParam==102)	dlgShowRWStats(hDlg);
	}
	else if((uMsg==WM_DRAWITEM) && (wParam==25051))
	{	drawGraph(GetDlgItem(hDlg,25051));
	}
	else if(uMsg==WM_NOTIFY)
	{	if(wParam==25500)
		{	pnmtvw=(NM_TREEVIEWW*)lParam;
			if(pnmtvw->hdr.code==TVN_SELCHANGEDW && pnmtvw->itemNew.hItem)	tree_show_sel(pnmtvw->itemNew.hItem,pnmtvw->itemNew.lParam);
			else if(pnmtvw->hdr.code==TVN_SELCHANGEDA)
			{	pnmtv=(NM_TREEVIEW*)lParam;
				if(pnmtv->itemNew.hItem)	tree_show_sel(pnmtv->itemNew.hItem,pnmtv->itemNew.lParam);
			}
			else if(pnmtvw->hdr.code==(unsigned int)NM_RCLICK)
			{	LONG h = SendDlgItemMessage(hDlg,25500,TVM_GETNEXTITEM,TVGN_DROPHILITE,0);
				HTREEITEM hItem=(HTREEITEM)h;
				if(!hItem)
				{	h = SendDlgItemMessage(hDlg,25500,TVM_GETNEXTITEM,TVGN_CARET,0);
					hItem=(HTREEITEM)h;
				}
				if(hItem)
				{	tree_show_menu(hItem);
				}
			}
		}
	}
	else if(uMsg==WM_VSCROLL)	PostMessage(hMainDialog,WM_USER+13,wParam,(LPARAM)hDlg);
	else if(uMsg==WM_HSCROLL)	PostMessage(hMainDialog,WM_USER+12,wParam,(LPARAM)hDlg);
	return 0;
}
