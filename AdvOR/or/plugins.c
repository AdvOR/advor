#include "or.h"
#include "plugins.h"
#include "dlg_util.h"
#include "main.h"
#include "geoip.h"
#include "routerlist.h"
#include "connection_edge.h"
#include "connection.h"
#include "rendservice.h"
#include "circuitlist.h"
#include "control.h"
#include "dnsserv.h"
#include "buffers.h"
#include "config.h"
#include <windows.h>

int next_plugin_id=0;
plugin_info_t *plugins=NULL;
int next_list_item=4096;
extern HWND hMainDialog;
extern LPFN1 RegisterPluginKey,UnregisterPluginKey;

int connection_params[MAX_PLUGIN_CONNECTION_PARAMS];
DWORD get_plugin_key(plugin_info_t *plugin_tmp);
void set_constrained_socket_buffers(int sock, int size);
void rend_init_plugin(plugin_info_t *plugin_tmp);
rend_service_t* find_service(char *onionaddress);
void __stdcall plugin_log(int severity,char *message);
BOOL __stdcall plugin_tor_is_started(void);
int __stdcall plugin_get_connection_count(void);
int __stdcall plugin_get_connections(HANDLE hPlugin,connection_info_t *buffer,int nCount);
int __stdcall plugin_close_connection(DWORD connection_id);
int __stdcall plugin_connection_read(DWORD connection_id);
int __stdcall plugin_connection_write(DWORD connection_id);
char * __stdcall plugin_get_socks_address(DWORD connection_id,BOOL original_address);
BOOL __stdcall plugin_set_socks_address(HANDLE plugin_instance,DWORD connection_id,char *original_address,int command);
DWORD __stdcall plugin_get_connecting_process(DWORD connection_id);
int __stdcall plugin_get_process_name(DWORD pid,char *buffer);
int __stdcall plugin_translate_address(HANDLE plugin_instance,char *original_address,char *translated_address);
void __stdcall plugin_map_address(HANDLE plugin_instance,char *address, char *new_address);
int __stdcall plugin_tor_resolve_address(HANDLE plugin_instance,char *address,BOOL reverse);
const char * __stdcall plugin_geoip_get_country_id(DWORD ip);
const char * __stdcall plugin_geoip_get_country_name(DWORD ip);
long __stdcall plugin_get_time_delta(void);
int __stdcall plugin_crypto_rand_int(unsigned int max);
void __stdcall plugin_randomize_buffer(char *buffer,int buffer_size);
int __stdcall plugin_get_configuration_value(HANDLE hPlugin,char *option,char *buffer,int buffer_size,BOOL tor_option);
BOOL __stdcall plugin_set_configuration_value(HANDLE hPlugin,char *option,char *value);
BOOL __stdcall plugin_intercept_process(HANDLE plugin_instance,DWORD pid,DWORD flags,char *local_address);
BOOL __stdcall plugin_is_process_intercepted(HANDLE plugin_instance,DWORD pid);
DWORD __stdcall plugin_create_connection(HANDLE plugin_instance,char *remote_address,unsigned int remote_port,BOOL exclusive,LPARAM lParam);
LPARAM* __stdcall plugin_get_connection_param(HANDLE plugin_instance,DWORD connection_id);
DWORD __stdcall plugin_accept_client(HANDLE plugin_instance,SOCKET socket,char *remote_address,int remote_port,int exclusive,LPARAM lParam);
BOOL __stdcall plugin_create_intercepted_process(HANDLE plugin_instance,char *exename,DWORD flags,char *local_address);
BOOL __stdcall plugin_release_process(HANDLE plugin_instance,DWORD pid);
int plugin_notify_service(rend_service_t *service,int added,connection_t *conn,int port);
void * __stdcall plugin_tor_malloc(size_t len);
void __stdcall plugin_tor_free(void *buffer);
int __stdcall plugin_file_exists(char *fname);
int __stdcall plugin_read_file(char *fname,char **buffer);
int __stdcall plugin_write_file(char *fname,char *buf,int bufsize);
int __stdcall plugin_append_to_file(char *fname,char *buf,int bufsize);
const char * __stdcall plugin_get_lang_str(HANDLE hPlugin,int langId,char *defaultStr);
void __stdcall plugin_changeDialogStrings(HANDLE hPlugin,HWND hDlg,lang_dlg_info *dlgInfo);
int __stdcall plugin_force_delete_file(char *fname);
int __stdcall plugin_force_delete_subdir(char *fname);
void *get_plugins_hs(void);
resize_info_t *get_resize_info(RECT newSize,int list_item);
void dlg_add_plugin(plugin_info_t *plugin_tmp);
void dlg_set_plugin(plugin_info_t *plugin_tmp);
void dlg_remove_plugin(plugin_info_t *plugin_tmp);
void remove_all_functions(plugin_info_t *plugin_tmp);
void load_plugin(plugin_info_t *plugin_tmp);
void set_plugins_config(void);
void add_plugins(or_options_t *options);
int unload_plugin(HWND hDlg,plugin_info_t *plugin_info,int reason);
HANDLE find_plugin_by_name(char *dll_name);
void get_dll_name(char *s1,HANDLE hPlugin);
void close_connection(connection_t *conn);
void plugins_routerchanged(uint32_t addr,char *digest,int changed);
void plugins_interceptprocess(DWORD pid,BOOL intercepted);

void __stdcall plugin_log(int severity,char *message)
{	log(severity,LD_APP,message);
}

BOOL __stdcall plugin_tor_is_started(void)
{	return tor_is_started();
}

int __stdcall plugin_get_connection_count(void)
{	smartlist_t *conns=get_connection_array();
	return smartlist_len(conns);
}

int __stdcall plugin_get_connections(HANDLE hPlugin,connection_info_t *buffer,int nCount)
{	plugin_info_t *plugin_tmp;
	int conn_param=-1,i=0;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->hDll==hPlugin)
		{	conn_param = plugin_tmp->connection_param;
			break;
		}
	}
	smartlist_t *conns=get_connection_array();
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		buffer[i].connection_id = conn->global_identifier&0xffffffff;
		buffer[i].connection_type = conn->type;
		buffer[i].connection_state = conn->state;
		buffer[i].address = conn->address;
		if(conn->type==CONN_TYPE_AP || conn->type==CONN_TYPE_EXIT || conn->magic==EDGE_CONNECTION_MAGIC)
		{	edge_connection_t *conn2=TO_EDGE_CONN(conn);
			if(conn2->socks_request)
			{	buffer[i].socks_original_address = conn2->socks_request->original_address;
				buffer[i].socks_final_address = conn2->socks_request->address;
			}
			else
			{	buffer[i].socks_original_address = NULL;
				buffer[i].socks_final_address = NULL;
			}
		}
		else
		{	buffer[i].socks_original_address = NULL;
			buffer[i].socks_final_address = NULL;
		}
		buffer[i].reserved = 0;
		buffer[i].lParam = ((conn_param==-1)?NULL:(LPARAM *)&conn->lParam[conn_param]);
		i++;
		if(i >= nCount) return i;
	});
	return i;
}

int __stdcall plugin_close_connection(DWORD connection_id)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	if(CONN_IS_EDGE(conn))
			{	edge_connection_t *conn1=TO_EDGE_CONN(conn);
				connection_edge_end(conn1,END_STREAM_REASON_DONE);
				if (conn1->socks_request)	conn1->socks_request->has_finished = 1;
			}
			if(!conn->marked_for_close)	connection_mark_for_close(conn);
			return 1;
		}
	});
	return 0;
}

void connection_read_event(connection_t *conn);
void connection_write_event(connection_t *conn);
int __stdcall plugin_connection_read(DWORD connection_id)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	connection_read_event(conn);
			return 1;
		}
	});
	return 0;
}

int __stdcall plugin_connection_write(DWORD connection_id)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	connection_write_event(conn);
			return 1;
		}
	});
	return 0;
}

char * __stdcall plugin_get_socks_address(DWORD connection_id,BOOL original_address)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	if(CONN_IS_EDGE(conn))
			{	edge_connection_t *conn1=TO_EDGE_CONN(conn);
				if(conn1->socks_request)
				{	if(original_address) return conn1->socks_request->original_address;
					else return conn1->socks_request->address;
				}
				else return NULL;
			}
			else	return NULL;
		}
	});
	return NULL;
}

BOOL __stdcall plugin_set_socks_address(HANDLE plugin_instance,DWORD connection_id,char *original_address,int command)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES)) return 0;
	smartlist_t *conns=get_connection_array();
	if(is_banned(original_address))	return 0;
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	if(CONN_IS_EDGE(conn))
			{	edge_connection_t *conn1=TO_EDGE_CONN(conn);
				if(conn1->socks_request)
				{	conn1->socks_request->command=command;
					if(conn1->socks_request->address)
						tor_free(conn1->socks_request->address);
					if(conn1->socks_request->original_address)
						tor_free(conn1->socks_request->original_address);
					conn1->socks_request->address = tor_strdup(original_address);
					conn1->socks_request->original_address = tor_strdup(original_address);
					circuit_t *circ=circuit_get_by_edge_conn(conn1);
					if(!circ)	conn->state=AP_CONN_STATE_CIRCUIT_WAIT;
					else	connection_ap_detach_retriable(conn1,TO_ORIGIN_CIRCUIT(circ),END_STREAM_REASON_MISC);
					control_event_stream_status(conn1,STREAM_EVENT_NEW,0);
					return connection_ap_handshake_rewrite_and_attach(conn1,NULL,NULL) + 1;
				}
				else return 0;
			}
			else	return 0;
		}
	});
	return 0;
}

edge_connection_t *find_connection_by_id(DWORD connection_id)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
		{	if(CONN_IS_EDGE(conn))	return TO_EDGE_CONN(conn);
			return NULL;
		}
	});
	return NULL;
}


DWORD __stdcall plugin_get_connecting_process(DWORD connection_id)
{	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)
			return conn->pid;
	});
	return 0;
}

int __stdcall plugin_get_process_name(DWORD pid,char *buffer)
{	buffer[0]=0;
	getProcessName(buffer,200,pid);
	return strlen(buffer)+1;
}

int __stdcall plugin_translate_address(HANDLE plugin_instance,char *original_address,char *translated_address)
{	plugin_info_t *plugin_tmp;
	char *t;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES)) return 0;
	t = tor_strdup(original_address);
	addressmap_rewrite(&t,NULL);
	plugins_remap(NULL,&t,t,0);
	strcpy(translated_address,t);
	tor_free(t);
	return strlen(translated_address)+1;
}

void __stdcall plugin_map_address(HANDLE plugin_instance,char *address, char *new_address)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(plugin_tmp && (plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES))
		addressmap_register(address,new_address,2,ADDRMAPSRC_CONTROLLER);
}

int __stdcall plugin_tor_resolve_address(HANDLE plugin_instance,char *address,BOOL reverse)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES) || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS)) return 0;
	return dnsserv_launch_request(address,reverse)+1;
}

DWORD __stdcall plugin_choose_exit(DWORD flags,DWORD after,DWORD ip_range_low,DWORD ip_range_high,unsigned long bandwidth_rate_min,const char *country_id,DWORD connection_id,char *buffer);
BOOL __stdcall plugin_get_router_info(int index,DWORD router_ip,char *nickname,router_info_t *router_info);
int __stdcall plugin_is_router_banned(DWORD router_ip,char *nickname);
int __stdcall plugin_ban_router(DWORD router_ip,int ban_type,BOOL is_banned);

const char * __stdcall plugin_geoip_get_country_id(DWORD ip)
{	return geoip_get_country_name(geoip_get_country_by_ip(ip));
}

const char * __stdcall plugin_geoip_get_country_name(DWORD ip)
{	return GeoIP_getfullname(geoip_get_country_by_ip(ip)&0xff);
}

long __stdcall plugin_get_time_delta(void)
{	return best_delta_t;
}

int __stdcall plugin_crypto_rand_int(unsigned int max)
{	return crypto_rand_int(max);
}

void __stdcall plugin_randomize_buffer(char *buffer,int buffer_size)
{	crypto_rand(buffer,buffer_size);
}

int __stdcall plugin_get_configuration_value(HANDLE hPlugin,char *option,char *buffer,int buffer_size,BOOL tor_option)
{	(void) tor_option;
	if(!buffer_size) return 0;
	int i=0;
	buffer_size--;
	if(hPlugin)
	{	config_line_t *answer=get_options()->PluginOptions;
		if(!answer) return 0;
		plugin_info_t *plugin_tmp;
		for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
		{	if(plugin_tmp->hDll==hPlugin)
			{	break;
			}
		}
		if(!plugin_tmp) return 0;
		char *tmp2;
		while(answer && i<buffer_size)
		{	tmp2=(char *)answer->value;
			if(!strcasecmpstart(tmp2,plugin_tmp->dll_name))
			{	tmp2 += strlen(plugin_tmp->dll_name);
				if(*tmp2==':')
				{	tmp2++;
					if(!strcasecmpstart(tmp2,option))
					{	tmp2 += strlen(option);
						if(*tmp2=='=')
						{	tmp2++;
							while(*tmp2 && (i<buffer_size))	buffer[i++]=*tmp2++;
							if(i<buffer_size)	buffer[i++]=13;
							if(i<buffer_size)	buffer[i++]=10;
						}
					}
				}
			}
			answer = answer->next;
		}
		buffer[i]=0;
	}
	else
	{	if(!option_is_recognized(option))	return 0;
		config_line_t *answer = option_get_assignment(get_options(),option);
		if (!answer)	return 0;
		char *tmp2;
		while(answer && i<buffer_size)
		{	config_line_t *next;
			tmp2=(char *)answer->value;
			while(*tmp2 && (i<buffer_size))	buffer[i++]=*tmp2++;
			if(i<buffer_size)	buffer[i++]=13;
			if(i<buffer_size)	buffer[i++]=10;
			next = answer->next;
			tor_free(answer->key);
			tor_free(answer->value);
			tor_free(answer);
			answer = next;
		}
		buffer[i]=0;
	}
	return ++i;
}

BOOL __stdcall plugin_set_configuration_value(HANDLE hPlugin,char *option,char *value)
{	int i=0,j;
	config_line_t *next;
	if(hPlugin)
	{	config_line_t *answer=get_options()->PluginOptions;
		config_line_t **answer_ptr=&get_options()->PluginOptions;
	//	if(!answer) return 0;
		plugin_info_t *plugin_tmp;
		for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
		{	if(plugin_tmp->hDll==hPlugin)
			{	break;
			}
		}
		if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_CHANGE_OPTIONS)) return 0;
		char *tmp2;
		while(answer)
		{	next=answer->next;
			tmp2=(char *)answer->value;
			if(!strcasecmpstart(tmp2,plugin_tmp->dll_name))
			{	tmp2 += strlen(plugin_tmp->dll_name);
				if(*tmp2==':')
				{	tmp2++;
					if(!strcasecmpstart(tmp2,option))
					{	tmp2 += strlen(option);
						if(*tmp2=='=')
						{	tor_free(answer->key);
							tor_free(answer->value);
							tor_free(answer);
							*answer_ptr = next;
							answer = next;
						}
						else
						{	answer_ptr = &answer->next;
							answer = answer->next;
						}
					}
					else
					{	answer_ptr = &answer->next;
						answer = answer->next;
					}
				}
				else
				{	answer_ptr = &answer->next;
					answer = answer->next;
				}
			}
			else
			{	answer_ptr = &answer->next;
				answer = answer->next;
			}
		}
		if(!value) return 1;
		answer=get_options()->PluginOptions;
		if(answer)	while(answer->next) answer=answer->next;
		while(*value)
		{	if(answer)
			{	answer->next = tor_malloc_zero(sizeof(config_line_t));
				answer=answer->next;
			}
			else
			{	answer = tor_malloc_zero(sizeof(config_line_t));
				get_options()->PluginOptions = answer;
			}
			answer->key = (unsigned char *)tor_strdup("PluginOptions");
			for(i=0;value[i] && value[i]!=13 && value[i]!=10;i++)	;
			i += strlen(plugin_tmp->dll_name) + strlen(option) + 4;
			answer->value = tor_malloc(i);
			tor_snprintf((char *)answer->value,i,"%s:%s=",plugin_tmp->dll_name,option);
			j=strlen((char *)answer->value);
			tmp2=(char *)&answer->value[j];
			i -= j;
			if(i) i--;
			for(;i && *value && *value!=13 && *value!=10;i--)
			{	*tmp2++=*value++;
			}
			*tmp2=0;
			while((*value==13) || (*value==10))	value++;
		}
		return 1;
	}
	return 0;
}

extern LPFN3 TORHook,CreateNewProcess;
extern LPFN1 ShowProcesses,TORUnhook;
extern HWND hDlgForceTor;

BOOL __stdcall plugin_intercept_process(HANDLE plugin_instance,DWORD pid,DWORD flags,char *local_address)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)) return 0;
	if(!TORHook) return 0;
	int i=4|flags;
	char *tmp2=NULL;
	if(!local_address)
	{	tmp2=tor_malloc(256);GetDlgItemText(hDlgForceTor,12100,tmp2,255);
		local_address=tmp2;
	}
	if(!TORHook(pid,(HANDLE)get_options()->SocksPort,i,best_delta_t,local_address,(DWORD)crypto_rand_int(0x7fffffff))==0)
	{	if(tmp2)	tor_free(tmp2);
		return 0;
	}
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	if(tmp2)	tor_free(tmp2);
	return 1;
}

BOOL __stdcall plugin_create_intercepted_process(HANDLE plugin_instance,char *exename,DWORD flags,char *local_address)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)) return 0;
	if(!CreateNewProcess) return 0;
	int i=4|flags;
	char *tmp2=NULL;
	if(!local_address)
	{	tmp2=tor_malloc(256);GetDlgItemText(hDlgForceTor,12100,tmp2,255);
		local_address=tmp2;
	}
	if(!CreateNewProcess((DWORD)exename,(HANDLE)get_options()->SocksPort,i,best_delta_t,local_address,(DWORD)crypto_rand_int(0x7fffffff))==0)
	{	if(tmp2)	tor_free(tmp2);
		return 0;
	}
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	if(tmp2)	tor_free(tmp2);
	return 1;
}

BOOL __stdcall plugin_release_process(HANDLE plugin_instance,DWORD pid)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)) return 0;
	if(!TORUnhook)	return 0;
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	return TORUnhook(pid);
}

BOOL __stdcall plugin_is_process_intercepted(HANDLE plugin_instance,DWORD pid)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)) return 0;
	if(ShowProcesses)	ShowProcesses((DWORD)hDlgForceTor);
	LV_ITEM lvit;
	lvit.iItem=0;lvit.iSubItem=0;lvit.mask=LVIF_PARAM;
	while(1)
	{	lvit.lParam=0;
		if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEM,0,(LPARAM)&lvit)==0) break;
		if(lvit.lParam==(LPARAM)pid)
		{	if(SendDlgItemMessage(hDlgForceTor,12400,LVM_GETITEMSTATE,lvit.iItem,LVIS_STATEIMAGEMASK)&8192)
				return 1;
			else return 0;
		}
		lvit.iItem++;
	}
	return 0;
}

DWORD __stdcall plugin_create_connection(HANDLE plugin_instance,char *remote_address,unsigned int remote_port,BOOL exclusive,LPARAM lParam)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS)) return 0;
	if(is_banned(remote_address))
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_PLUGINS_BANNED),plugin_tmp->dll_name,safe_str(remote_address));
		return 0;
	}
	edge_connection_t *conn=edge_connection_new(CONN_TYPE_AP,AF_INET);
	conn->_base.address=tor_strdup("0.0.0.0");
	conn->_base.port=0;
	conn->_base.hPlugin=plugin_instance;
	if(exclusive)	conn->_base.exclKey=get_plugin_key(plugin_tmp);
	conn->socks_request->port=remote_port;
	conn->socks_request->socks_version='P';
	if(conn->socks_request->address)
		tor_free(conn->socks_request->address);
	if(conn->socks_request->original_address)
		tor_free(conn->socks_request->original_address);
	conn->socks_request->address = tor_strdup(remote_address);
	conn->socks_request->original_address = tor_strdup(remote_address);
	conn->socks_request->command=SOCKS_COMMAND_CONNECT;
	if(plugin_tmp->connection_param!=-1)	conn->_base.lParam[plugin_tmp->connection_param]=lParam;
	log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_CONNECTION_REQUEST),safe_str(conn->socks_request->address),conn->socks_request->port);
	control_event_stream_status(conn, STREAM_EVENT_NEW, 0);
	if(connection_ap_handshake_rewrite_and_attach(conn,NULL,NULL)+1)	return conn->_base.global_identifier&0xffffffff;
	return 0;
}

LPARAM* __stdcall plugin_get_connection_param(HANDLE plugin_instance,DWORD connection_id)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || (plugin_tmp->connection_param==-1)) return NULL;
	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(connection_id==tmpid)	return (LPARAM *)&conn->lParam[plugin_tmp->connection_param];
	});
	return NULL;
}

DWORD __stdcall plugin_accept_client(HANDLE plugin_instance,SOCKET socket,char *remote_address,int remote_port,int exclusive,LPARAM lParam)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__CAN_ACCEPT_CLIENTS)) return 0;
	if(remote_address && is_banned(remote_address))
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_PLUGINS_BANNED),plugin_tmp->dll_name,safe_str(remote_address));
		closesocket(socket);
		return 0;
	}
	if(exclusive==EXCLUSIVITY_DIRCONN || exclusive==EXCLUSIVITY_INTERNAL)
	{	log(LOG_ADDR,LD_APP,get_lang_str(LANG_PLUGINS_EXCLUSIVITY_RESERVED),plugin_tmp->dll_name,safe_str(remote_address));
		closesocket(socket);
		return 0;
	}
	connection_t *newconn;
	char addrbuf[256];
	tor_addr_t addr;
	uint16_t port;
	struct sockaddr *remote = (struct sockaddr*)addrbuf;
	socklen_t remotelen = (socklen_t)sizeof(addrbuf);
	or_options_t *options = get_options();
	memset(addrbuf, 0, sizeof(addrbuf));

	set_socket_nonblocking(socket);
	if(options->ConstrainedSockets)	set_constrained_socket_buffers(socket,(int)options->ConstrainedSockSize);
	getsockname(socket,remote,&remotelen);
	tor_addr_from_sockaddr(&addr,remote,&port);
	newconn=connection_new(CONN_TYPE_AP,AF_INET);
	newconn->s = socket;
	tor_addr_copy(&newconn->addr, &addr);
	newconn->port = port;
	newconn->address = tor_dup_addr(&addr);
	newconn->pid=getPID(tor_addr_to_ipv4n(&newconn->addr),port);
	if(exclusive==EXCLUSIVITY_UNDEFINED)	newconn->exclKey=0;
	else if(exclusive==EXCLUSIVITY_GENERAL)	newconn->exclKey=1;
	else if(exclusive==EXCLUSIVITY_PROCESS)	newconn->exclKey=getChainKey(newconn->pid);
	else if(exclusive==EXCLUSIVITY_PLUGIN)	newconn->exclKey=get_plugin_key(plugin_tmp);
	LangEnterCriticalSection();
	LangLeaveCriticalSection();
	if(connection_add(newconn) < 0)
	{	connection_free(newconn);
		closesocket(socket);
		return 0;
	}
	connection_start_reading(newconn);
	newconn->state=AP_CONN_STATE_SOCKS_WAIT;
	edge_connection_t *e_conn=TO_EDGE_CONN(newconn);
	if(plugin_tmp->connection_param!=-1)	newconn->lParam[plugin_tmp->connection_param]=lParam;
	if(remote_address)
	{	if(e_conn->socks_request->address)
			tor_free(e_conn->socks_request->address);
		if(e_conn->socks_request->original_address)
			tor_free(e_conn->socks_request->original_address);
		e_conn->socks_request->command=SOCKS_COMMAND_CONNECT;
		e_conn->socks_request->address = tor_strdup(remote_address);
		e_conn->socks_request->original_address = tor_strdup(remote_address);
		e_conn->socks_request->port=remote_port;
		log(LOG_ADDR,LD_APP,get_lang_str(LANG_LOG_CONNECTION_CONNECTION_REQUEST),safe_str(e_conn->socks_request->address),e_conn->socks_request->port);
		control_event_stream_status(e_conn,STREAM_EVENT_NEW,0);
		connection_ap_handshake_rewrite_and_attach(e_conn,NULL,NULL);
	}
	int tmpid=newconn->global_identifier&0xffffffff;
	return tmpid;
}

BOOL __stdcall plugin_hs_send_reply(HANDLE plugin_instance,DWORD client_id,char *buffer,int buffer_size);

void * __stdcall plugin_tor_malloc(size_t len)
{	return tor_malloc(len);
}

void __stdcall plugin_tor_free(void *buffer)
{	return tor_free(buffer);
}

int __stdcall plugin_file_exists(char *fname)
{	int r;
	char *fpath = tor_malloc(MAX_PATH*2+1);
	tor_snprintf(fpath,MAX_PATH*2,"%s--%s",fullpath,fname);
	r = (file_status(fpath)==FN_FILE)?1:0;
	tor_free(fpath);
	return r;
}

int __stdcall plugin_read_file(char *fname,char **buffer)
{	struct stat st;
	char *fpath = tor_malloc(MAX_PATH*2+1);
	tor_snprintf(fpath,MAX_PATH*2,"%s--%s",fullpath,fname);
	st.st_size = -1;
	*buffer = read_file_to_str(fpath,RFTS_BIN,&st);
	tor_free(fpath);
	return st.st_size;
}

int __stdcall plugin_write_file(char *fname,char *buf,int bufsize)
{	int r;
	char *fpath = tor_malloc(MAX_PATH*2+1);
	tor_snprintf(fpath,MAX_PATH*2,"%s--%s",fullpath,fname);
	r = write_buf_to_file(fpath,buf,bufsize);
	tor_free(fpath);
	return r;
}

int __stdcall plugin_append_to_file(char *fname,char *buf,int bufsize)
{	int r;
	char *fpath = tor_malloc(MAX_PATH*2+1);
	tor_snprintf(fpath,MAX_PATH*2,"%s--%s",fullpath,fname);
	r = append_bytes_to_file(fpath,buf,bufsize,1);
	tor_free(fpath);
	return r;
}

const char * __stdcall plugin_get_lang_str(HANDLE hPlugin,int langId,char *defaultStr)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->hDll==hPlugin)
		{	if(!plugin_tmp->loaded_lng)
			{	if(plugin_tmp->lng_error)	return defaultStr;
				plugin_tmp->loaded_lng = plugin_load_lng(plugin_tmp->dll_name,&plugin_tmp->maxdefs,get_options()->Language,&plugin_tmp->lngfile);
				if(!plugin_tmp->loaded_lng)
				{	plugin_tmp->lng_error++;
					return defaultStr;
				}
			}
			if(plugin_tmp->maxdefs < langId)	return defaultStr;
			if(plugin_tmp->loaded_lng[langId].langStr)	return plugin_tmp->loaded_lng[langId].langStr;
			return defaultStr;
		}
	}
	return defaultStr;
}

void __stdcall plugin_changeDialogStrings(HANDLE hPlugin,HWND hDlg,lang_dlg_info *dlgInfo)
{	int cnt;
	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->hDll==hPlugin)
		{	if(!plugin_tmp->loaded_lng)
			{	if(plugin_tmp->lng_error)	return;
				plugin_tmp->loaded_lng = plugin_load_lng(plugin_tmp->dll_name,&plugin_tmp->maxdefs,get_options()->Language,&plugin_tmp->lngfile);
				if(!plugin_tmp->loaded_lng)
				{	plugin_tmp->lng_error++;
					return;
				}
			}
			for(cnt=0;dlgInfo[cnt].langId!=0;cnt++)
			{	if(plugin_tmp->maxdefs > dlgInfo[cnt].langId && plugin_tmp->loaded_lng[dlgInfo[cnt].langId].langStr)
				{	if(dlgInfo[cnt].ctrlId==0)
						LangSetWindowText(hDlg,plugin_tmp->loaded_lng[dlgInfo[cnt].langId].langStr);
					else	LangSetWindowText(GetDlgItem(hDlg,dlgInfo[cnt].ctrlId),plugin_tmp->loaded_lng[dlgInfo[cnt].langId].langStr);
				}
			}
			return;
		}
	}
}

int __stdcall plugin_force_delete_file(char *fname)
{	return ForceDelete(fname);
}

int __stdcall plugin_force_delete_subdir(char *fname)
{	return ForceDeleteSubdir(fname);
}

void *function_tbl[]={
	&plugin_log,
	&plugin_tor_is_started,
	&plugin_get_connection_count,
	&plugin_get_connections,
	&plugin_close_connection,
	&plugin_connection_read,
	&plugin_connection_write,
	&plugin_get_socks_address,
	&plugin_set_socks_address,
	&plugin_get_connecting_process,
	&plugin_get_process_name,
	&plugin_translate_address,
	&plugin_map_address,
	&plugin_tor_resolve_address,
	&plugin_choose_exit,
	&plugin_get_router_info,
	&plugin_is_router_banned,
	&plugin_ban_router,
	&plugin_geoip_get_country_id,
	&plugin_geoip_get_country_name,
	&plugin_get_time_delta,
	&plugin_crypto_rand_int,
	&plugin_randomize_buffer,
	&plugin_get_configuration_value,
	&plugin_set_configuration_value,
	&plugin_intercept_process,
	&plugin_create_intercepted_process,
	&plugin_release_process,
	&plugin_is_process_intercepted,
	&plugin_create_connection,
	&plugin_get_connection_param,
	&plugin_accept_client,
	&plugin_hs_send_reply,
	&geoip_get_as_by_ip,
	&geoip_get_full_as_path,
	&geoip_is_as_path_safe,
	&plugin_tor_malloc,
	&plugin_tor_free,
	&safe_malloc,
	&safe_free,
	&plugin_write_file,
	&plugin_append_to_file,
	&plugin_read_file,
	&plugin_file_exists,
	&tor_gzip_compress,
	&tor_gzip_uncompress,
	&tor_zlib_new,
	&tor_zlib_process,
	&tor_zlib_free,
	&detect_compression_method,
	&plugin_get_lang_str,
	&plugin_changeDialogStrings,
	&plugin_force_delete_file,
	&plugin_force_delete_subdir,
	NULL
};

HWND get_plugin_window(int list_item)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->listItem==list_item)
		{	if(plugin_tmp->GetConfigurationWindow && plugin_tmp->rights&PLUGIN_RIGHT__ADVTOR_PAGE)
			{	if(plugin_tmp->hDlg==NULL)	plugin_tmp->hDlg=(plugin_tmp->GetConfigurationWindow)(hMainDialog);
				if(plugin_tmp->hDlg)	ShowWindow(plugin_tmp->hDlg,SW_HIDE);
				return plugin_tmp->hDlg;
			}
			return NULL;
		}
	}
	return NULL;
}

DWORD get_plugin_key(plugin_info_t *plugin_tmp)
{	if(!plugin_tmp->exclKey)
	{	if(RegisterPluginKey)	plugin_tmp->exclKey=RegisterPluginKey(crypto_rand_int(0x7fff)^(DWORD)plugin_tmp->hDll);
		else plugin_tmp->exclKey=crypto_rand_int(0x7fff)^(DWORD)plugin_tmp->hDll;
	}
	return plugin_tmp->exclKey;
}

resize_info_t *get_resize_info(RECT newSize,int list_item)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->listItem==list_item)
		{	if(plugin_tmp->ResizeConfigurationWindow)
				return (plugin_tmp->ResizeConfigurationWindow)(&newSize);
			return NULL;
		}
	}
	return NULL;
}

void *get_plugins_hs(void)
{	plugin_info_t *plugin_tmp;
	int i=0,j=0;
	char **plugins_hs;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->HiddenService_HandleRead)	i++;
	}
	if(i)
	{	plugins_hs=tor_malloc_zero((i+1)*sizeof(char *));
		plugin_tmp=plugins;
		while(j<i && plugin_tmp)
		{	while(plugin_tmp)
			{	if(plugin_tmp->HiddenService_HandleRead) break;
				plugin_tmp=plugin_tmp->next_plugin;
			}
			if(plugin_tmp)
			{	plugins_hs[j++]=&plugin_tmp->dll_name[0];
				plugin_tmp=plugin_tmp->next_plugin;
			}
			else break;
		}
		return plugins_hs;
	}
	return NULL;
}

extern HTREEITEM pages[MAX_PAGE_INDEXES];
void dlg_add_plugin(plugin_info_t *plugin_tmp)
{	if(plugin_tmp->GetConfigurationWindow && plugin_tmp->rights&PLUGIN_RIGHT__ADVTOR_PAGE)
	{	plugin_tmp->listItem = next_list_item;
		char *plstr = tor_malloc(100);
		tor_snprintf(plstr,99,"%s (%s)",plugin_tmp->description,plugin_tmp->dll_name);
		plugin_tmp->hItem = addTreeItem(pages[INDEX_PAGE_PLUGINS],plstr,plugin_tmp->listItem,-1);
		SendDlgItemMessage(hMainDialog,200,TVM_EXPAND,TVE_EXPAND,(LPARAM)pages[INDEX_PAGE_PLUGINS]);
		tor_free(plstr);
	}
	int i;
	for(i=0;i<MAX_PLUGIN_CONNECTION_PARAMS;i++)
	{	if(connection_params[i]==0)
		{	connection_params[i]=next_list_item;
			plugin_tmp->connection_param=i;
			break;
		}
	}
	next_list_item = ((next_list_item+1) & 32767) | 4096;			// just in case someone is crazy enough to reload plugins 28671+ times in same AdvTor session
}

void dlg_set_plugin(plugin_info_t *plugin_tmp)
{	if(plugin_tmp->hItem)
	{	char *plstr = tor_malloc(100);
		tor_snprintf(plstr,99,"%s (%s)",plugin_tmp->description,plugin_tmp->dll_name);
		setTreeItem(plugin_tmp->hItem,plstr);
		tor_free(plstr);
	}
}

void dlg_remove_plugin(plugin_info_t *plugin_tmp)
{	if(plugin_tmp->GetConfigurationWindow && plugin_tmp->listItem)
	{	SendDlgItemMessage(hMainDialog,200,TVM_DELETEITEM,0,(LPARAM)plugin_tmp->hItem);
		plugin_tmp->hItem = NULL;
		plugin_tmp->listItem=0;
		plugin_tmp->hDlg=NULL;
	}
	else if(plugin_tmp->connection_param!=-1 && plugin_tmp->connection_param<MAX_PLUGIN_CONNECTION_PARAMS)
	{	connection_params[plugin_tmp->connection_param]=0;
		plugin_tmp->connection_param=-1;
	}
}

void dlg_add_all_plugins(void)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if((plugin_tmp->load_status & PLUGIN_LOADSTATUS_LOADED) != 0)	dlg_add_plugin(plugin_tmp);
	}
}

void dlg_set_all_plugins(void)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if((plugin_tmp->load_status & PLUGIN_LOADSTATUS_LOADED) != 0)	dlg_set_plugin(plugin_tmp);
	}
}

void remove_all_functions(plugin_info_t *plugin_tmp)
{	plugin_tmp->InitPlugin=NULL;
	plugin_tmp->UnloadPlugin=NULL;
	plugin_tmp->GetConfigurationWindow=NULL;
	plugin_tmp->ResizeConfigurationWindow=NULL;
	plugin_tmp->RegisterConnection=NULL;
	plugin_tmp->UnregisterConnection=NULL;
	plugin_tmp->ConnectionRead=NULL;
	plugin_tmp->ConnectionWrite=NULL;
	plugin_tmp->TranslateAddress=NULL;
	plugin_tmp->ChangeIdentity=NULL;
	plugin_tmp->AdvTorStart=NULL;
	plugin_tmp->RouterChanged=NULL;
	plugin_tmp->HiddenService_NotifyService=NULL;
	plugin_tmp->HiddenService_HandleRead=NULL;
	plugin_tmp->InterceptProcess=NULL;
	plugin_tmp->LanguageChange=NULL;
	if(plugin_tmp->loaded_lng)	tor_free(plugin_tmp->loaded_lng);
	if(plugin_tmp->lngfile)		tor_free(plugin_tmp->lngfile);
	plugin_tmp->loaded_lng = NULL;
	plugin_tmp->maxdefs = 0;
	plugin_tmp->lng_error = 0;
	if(UnregisterPluginKey && plugin_tmp->exclKey)
	{	UnregisterPluginKey(plugin_tmp->exclKey);
		plugin_tmp->exclKey=0;
	}
}

void load_plugin(plugin_info_t *plugin_tmp)
{	if(!(plugin_tmp->load_status&PLUGIN_LOADSTATUS_LOADED) && (plugin_tmp->rights & PLUGIN_RIGHT__CAN_BE_LOADED))
	{	plugin_tmp->description[0]=0;
		if(!plugin_tmp->hDll)
		{	HINSTANCE hDll;
			hDll=get_module_handle(plugin_tmp->dll_name);
			if(!hDll)
			{	char *fname=get_datadir_fname(DATADIR_PLUGINS);
				char *plname=tor_malloc(1024);
				tor_snprintf(plname,1024,"%s\\%s",fname,plugin_tmp->dll_name);
				hDll=load_library(plname);
				tor_free(plname);tor_free(fname);
			}
			if(!hDll)
			{	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_LOAD_ERROR;
				log(LOG_WARN,LD_APP,get_lang_str(LANG_PLUGINS_LOAD_ERROR),plugin_tmp->dll_name);
			}
			else
			{	plugin_tmp->hDll=hDll;
			}
		}
		if(plugin_tmp->hDll)
		{
			plugin_tmp->load_status &= PLUGIN_LOADSTATUS_LOAD_ERROR^PLUGIN_LOADSTATUS_MASK;
			plugin_tmp->InitPlugin=(LP_InitPlugin)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_INIT);
			plugin_tmp->UnloadPlugin=(LP_UnloadPlugin)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_UNLOAD);
			plugin_tmp->GetConfigurationWindow=(LP_GetConfigurationWindow)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_GETCONFIG);
			plugin_tmp->ResizeConfigurationWindow=(LP_ResizeConfigurationWindow)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_RESIZE);
			plugin_tmp->RegisterConnection=(LP_RegisterConnection)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_NEWCONN);
			plugin_tmp->UnregisterConnection=(LP_UnregisterConnection)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_CLOSECONN);
			plugin_tmp->ConnectionRead=(LP_ConnectionRead)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_CONN_READ);
			plugin_tmp->ConnectionWrite=(LP_ConnectionWrite)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_CONN_WRITE);
			plugin_tmp->TranslateAddress=(LP_TranslateAddress)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_REWRITE_ADDR);
			plugin_tmp->ChangeIdentity=(LP_ChangeIdentity)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_NEW_IDENTITY);
			plugin_tmp->AdvTorStart=(LP_Start)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_START);
			plugin_tmp->RouterChanged=(LP_RouterChanged)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_ROUTERCHANGED);
			plugin_tmp->HiddenService_NotifyService=(LP_HiddenService_NotifyService)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_HS_NOTIFYSERVICE);
			plugin_tmp->HiddenService_HandleRead=(LP_HiddenService_HandleRead)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_HS_HANDLEREAD);
			plugin_tmp->InterceptProcess=(LP_InterceptProcess)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_INTERCEPT_PROCESS);
			plugin_tmp->LanguageChange=(LP_LanguageChange)GetProcAddress(plugin_tmp->hDll,PLUGIN_FN_LANGUAGE_CHANGE);
			if(plugin_tmp->InitPlugin)
			{	plugin_tmp->load_status &= PLUGIN_LOADSTATUS_INIT_FAILED^PLUGIN_LOADSTATUS_MASK;
				if((plugin_tmp->InitPlugin)(plugin_tmp->hDll,ADVTOR_DW_VER,plugin_tmp->description,function_tbl))
				{	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_LOADED;
					plugin_tmp->hDlg=NULL;
					plugin_tmp->connection_param=-1;
					dlg_add_plugin(plugin_tmp);
					if(plugin_tmp->HiddenService_NotifyService)	rend_init_plugin(plugin_tmp);
				}
				else
				{	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_INIT_FAILED;
					log(LOG_WARN,LD_APP,get_lang_str(LANG_PLUGINS_INIT_ERROR_2),plugin_tmp->dll_name);
					FreeLibrary(plugin_tmp->hDll);plugin_tmp->hDll=NULL;
				}
			}
			else
			{	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_INIT_FAILED;
				log(LOG_WARN,LD_APP,get_lang_str(LANG_PLUGINS_INIT_ERROR_1),plugin_tmp->dll_name);
				FreeLibrary(plugin_tmp->hDll);plugin_tmp->hDll=NULL;
			}
		}
	}
	else if(!(plugin_tmp->rights & PLUGIN_RIGHT__CAN_BE_LOADED))
	{	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_DISABLED;
		plugin_tmp->description[0]=0;
	}
}

void load_all_plugins(void)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
		load_plugin(plugin_tmp);
}

void set_plugins_config(void)
{	or_options_t *options=get_options();
	config_line_t *cfg,**cfg1;
	plugin_info_t *plugin_tmp;
	char *plname=tor_malloc(1024);
	while(options->Plugins)
	{	tor_free(options->Plugins->key);tor_free(options->Plugins->value);
		cfg=options->Plugins;
		options->Plugins=options->Plugins->next;
		tor_free(cfg);
	}
	cfg1=&options->Plugins;*cfg1=NULL;
	plugin_tmp=plugins;
	while(plugin_tmp)
	{	tor_snprintf(plname,1024,"%s %u",plugin_tmp->dll_name,plugin_tmp->rights);
		*cfg1=tor_malloc_zero(sizeof(config_line_t));
		(*cfg1)->key = (unsigned char *)tor_strdup("Plugins");
		(*cfg1)->value=(unsigned char *)tor_strdup(plname);
		cfg1=&((*cfg1)->next);
		plugin_tmp=plugin_tmp->next_plugin;
	}
	tor_free(plname);
}

void refresh_plugins(or_options_t *options)
{	(void) options;
	char *fname=get_datadir_fname(DATADIR_PLUGINS);
	char *plname=tor_malloc(1024);
	plugin_info_t *plugin_tmp;
	int isLoaded;
	WIN32_FIND_DATAW wfdata;
	HANDLE hFind;
	DWORD attrs;
	if(plugins)
	{	plugin_tmp=plugins;
		while(plugin_tmp)
		{	plugin_tmp->load_status &= PLUGIN_LOADSTATUS_FOUND ^ PLUGIN_LOADSTATUS_MASK;
			plugin_tmp->rights |= PLUGIN_RIGHT__CAN_BE_SHOWN_IN_PLUGIN_LIST;
			plugin_tmp=plugin_tmp->next_plugin;
		}
	}
	tor_snprintf(plname,1024,"%s\\*.dll",fname);
	if((hFind=find_first_file(plname,&wfdata))!=INVALID_HANDLE_VALUE)
	{	while(1)
		{	char *found_plugin = get_utf(wfdata.cFileName);
			plugin_tmp=plugins;
			while(plugin_tmp)
			{	if(!strcasecmp(plugin_tmp->dll_name,found_plugin)) break;
				plugin_tmp=plugin_tmp->next_plugin;
			}
			if(plugin_tmp)	plugin_tmp->load_status |= PLUGIN_LOADSTATUS_FOUND;
			else
			{	tor_snprintf(plname,1024,"%s\\%s",fname,found_plugin);
				isLoaded=0;
				HINSTANCE hDll;
				hDll=get_module_handle(plname);
				if(hDll) isLoaded++;
				else hDll=load_library_ex(plname);
				if(hDll)
				{	if(GetProcAddress(hDll,PLUGIN_FN_INIT))
					{	plugin_info_t *newPlugin=tor_malloc_zero(sizeof(plugin_info_t));
						newPlugin->hDll=NULL;
						newPlugin->plugin_id = next_plugin_id++;
						newPlugin->next_plugin=NULL;
						remove_all_functions(newPlugin);
						newPlugin->rights=PLUGIN_RIGHT__ALL_RIGHTS;
						newPlugin->load_status=PLUGIN_LOADSTATUS_FOUND;
						tor_snprintf(newPlugin->dll_name,MAX_PATH,"%s",found_plugin);
						if(plugins)
						{	plugin_tmp=plugins;
							while(plugin_tmp->next_plugin)	plugin_tmp=plugin_tmp->next_plugin;
							plugin_tmp->next_plugin=newPlugin;
						}
						else	plugins=newPlugin;
					}
					if(!isLoaded) FreeLibrary(hDll);
				}
			}
			tor_free(found_plugin);
			if(!FindNextFileW(hFind,&wfdata)) break;
		}
		FindClose(hFind);
	}
	else
	{	attrs=get_file_attributes(fname);
		if(attrs==0xffffffff)	log(LOG_WARN,LD_APP,get_lang_str(LANG_PLUGINS_NO_DIR),fname);
		else if(!(attrs&FILE_ATTRIBUTE_DIRECTORY))	log(LOG_WARN,LD_APP,get_lang_str(LANG_PLUGINS_NO_DIR_2),fname);
	}
	set_plugins_config();

	tor_free(fname);
	tor_free(plname);
}

void add_plugins(or_options_t *options)
{	plugin_info_t *plugin_tmp;
	config_line_t *option=options->Plugins;
	int i;
	if(plugins)
	{	plugin_tmp=plugins;
		while(plugin_tmp)
		{	plugin_tmp->load_status &= PLUGIN_LOADSTATUS_FOUND ^ PLUGIN_LOADSTATUS_MASK;
			plugin_tmp=plugin_tmp->next_plugin;
		}
	}
	while(option)
	{	plugin_info_t *newPlugin=tor_malloc_zero(sizeof(plugin_info_t));
		newPlugin->hDll=NULL;
		newPlugin->plugin_id = next_plugin_id++;
		newPlugin->next_plugin=NULL;
		remove_all_functions(newPlugin);
		newPlugin->rights=PLUGIN_RIGHT__ALL_RIGHTS;
		newPlugin->load_status=PLUGIN_LOADSTATUS_FOUND;
		for(i=0;i<MAX_PATH && (unsigned char)option->value[i]>32;i++)	newPlugin->dll_name[i]=option->value[i];
		newPlugin->dll_name[i]=0;
		while(option->value[i]==32) i++;
		newPlugin->rights=atoi((char *)&option->value[i]);
		if(plugins)
		{	plugin_tmp=plugins;
			while(plugin_tmp->next_plugin)	plugin_tmp=plugin_tmp->next_plugin;
			plugin_tmp->next_plugin=newPlugin;
		}
		else	plugins=newPlugin;
		option=option->next;
	}
}

void remove_plugins(void)
{	plugin_info_t *plugin_tmp;
	while(plugins)
	{	plugin_tmp=plugins->next_plugin;
		tor_free(plugins);
		plugins=plugin_tmp;
	}

}

plugin_info_t *get_plugin_list(void)
{	return plugins;
}

void load_plugins(void)
{	or_options_t *options=get_options();
	int i;
	for(i=0;i<MAX_PLUGIN_CONNECTION_PARAMS;i++)	connection_params[i]=0;
	next_plugin_id = crypto_rand_int(0x3fff) | 0x1500;
	if(!options->Plugins)	refresh_plugins(options);
	else add_plugins(options);
	if(plugins)	load_all_plugins();
}

int unload_plugin(HWND hDlg,plugin_info_t *plugin_info,int reason)
{	int r;
	if(plugin_info->load_status&PLUGIN_LOADSTATUS_LOADED)
	{	if(plugin_info->UnloadPlugin)
		{	r=(plugin_info->UnloadPlugin)(reason);
			if(r==0 && reason!=PLUGIN_UNLOAD_RELOAD)
			{	char *msg=tor_malloc(512);
				tor_snprintf(msg,512,get_lang_str(LANG_PLUGINS_UNLOADING),plugin_info->dll_name);
				if(LangMessageBox(hDlg,msg,LANG_LB_PLUGINS,MB_YESNO)==IDNO)
				{	tor_free(msg);
					(plugin_info->UnloadPlugin)(PLUGIN_UNLOAD_CANCEL);
					return r;
				}
				tor_free(msg);
				(plugin_info->UnloadPlugin)(PLUGIN_UNLOAD_MUST_UNLOAD);
			}
			if(reason==PLUGIN_UNLOAD_RELOAD)
			{	if(r==1)
				{	dlg_remove_plugin(plugin_info);
					remove_all_functions(plugin_info);
					FreeLibrary(plugin_info->hDll);
					plugin_info->hDll=NULL;
					plugin_info->load_status &= PLUGIN_LOADSTATUS_MASK^PLUGIN_LOADSTATUS_LOADED;
				}
				return r;
			}
		}
		else if(plugin_info->hDlg)
		{	DestroyWindow(plugin_info->hDlg);
			plugin_info->hDlg=NULL;
		}
		dlg_remove_plugin(plugin_info);
		remove_all_functions(plugin_info);
		FreeLibrary(plugin_info->hDll);
		plugin_info->hDll=NULL;
		plugin_info->load_status &= PLUGIN_LOADSTATUS_MASK^PLUGIN_LOADSTATUS_LOADED;
	}
	return 1;
}

int unload_plugins(HWND hDlg)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(!unload_plugin(hDlg,plugin_tmp,PLUGIN_UNLOAD_AT_EXIT)) return 0;	}
	return 1;
}

plugin_info_t *find_plugin(int plugin_id)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->plugin_id==plugin_id) return plugin_tmp;	}
	return NULL;
}

HANDLE find_plugin_by_name(char *dll_name)
{	plugin_info_t *plugin_tmp;
	plugin_tmp=plugins;
	while(plugin_tmp)
	{	if(!strcasecmp(plugin_tmp->dll_name,dll_name)) return plugin_tmp->hDll;
		plugin_tmp=plugin_tmp->next_plugin;
	}
	return 0;
}

int remove_plugin(HWND hDlg,int plugin_id)
{	plugin_info_t *plugin_tmp=find_plugin(plugin_id);
	if(plugin_tmp)
	{	if(!unload_plugin(hDlg,plugin_tmp,PLUGIN_UNLOAD_ON_DEMAND)) return 0;
		plugin_tmp->load_status &= PLUGIN_LOADSTATUS_FOUND ^ PLUGIN_LOADSTATUS_MASK;
		plugin_tmp->rights &= PLUGIN_RIGHT__ALL_RIGHTS^PLUGIN_RIGHT__CAN_BE_SHOWN_IN_PLUGIN_LIST;
		updatePluginStatus(plugin_tmp->plugin_id,plugin_tmp->load_status);
		set_plugins_config();
	}
	return 1;
}

void disable_plugin(HWND hDlg,int plugin_id)
{	plugin_info_t *plugin_tmp=find_plugin(plugin_id);
	if(plugin_tmp)
	{	unload_plugin(hDlg,plugin_tmp,PLUGIN_UNLOAD_ON_DEMAND);
		plugin_tmp->rights &= PLUGIN_RIGHT__ALL_RIGHTS^PLUGIN_RIGHT__CAN_BE_LOADED;
		plugin_tmp->load_status |= PLUGIN_LOADSTATUS_DISABLED;
		updatePluginStatus(plugin_tmp->plugin_id,plugin_tmp->load_status);
		set_plugins_config();
	}
}

void reload_plugin(HWND hDlg,int plugin_id)
{	plugin_info_t *plugin_tmp=find_plugin(plugin_id);
	int r;
	if(plugin_tmp)
	{	r=unload_plugin(hDlg,plugin_tmp,PLUGIN_UNLOAD_RELOAD);
		plugin_tmp->rights |= PLUGIN_RIGHT__CAN_BE_LOADED;
		plugin_tmp->load_status &= PLUGIN_LOADSTATUS_DISABLED^PLUGIN_LOADSTATUS_MASK;
		if(r)	load_plugin(plugin_tmp);
		updatePluginStatus(plugin_tmp->plugin_id,plugin_tmp->load_status);
		updatePluginDescription(plugin_tmp->plugin_id,plugin_tmp->description);
		set_plugins_config();
	}
}

int plugin_move_up(int plugin_id)
{	plugin_info_t *plugin_tmp=find_plugin(plugin_id),*plugin_tmp1,*plugin_tmp2;
	if(plugin_tmp)
	{	if(plugin_tmp==plugins)	return 0;
		else if(plugins->next_plugin==plugin_tmp)
		{	plugins->next_plugin=plugin_tmp->next_plugin;
			plugin_tmp->next_plugin=plugins;
			plugins=plugin_tmp;
			set_plugins_config();
			return 1;
		}
		plugin_tmp1=plugins;
		while(plugin_tmp1)
		{	plugin_tmp2=plugin_tmp1->next_plugin;
			if(plugin_tmp2 && plugin_tmp2->next_plugin==plugin_tmp)
			{	plugin_tmp1->next_plugin=plugin_tmp;
				plugin_tmp1=plugin_tmp->next_plugin;
				plugin_tmp->next_plugin=plugin_tmp2;
				plugin_tmp2->next_plugin=plugin_tmp1;
				set_plugins_config();
				return 1;
			}
			plugin_tmp1=plugin_tmp1->next_plugin;
		}
	}
	return 0;
}

int plugin_move_down(int plugin_id)
{	plugin_info_t *plugin_tmp=find_plugin(plugin_id),*plugin_tmp1,*plugin_tmp2;
	if(plugin_tmp)
	{	if(plugin_tmp->next_plugin==NULL) return 0;
		if(plugin_tmp==plugins)
		{	plugins=plugins->next_plugin;
			plugin_tmp1=plugins->next_plugin;
			plugins->next_plugin=plugin_tmp;
			plugin_tmp->next_plugin=plugin_tmp1;
			set_plugins_config();
			return 1;
		}
		plugin_tmp1=plugins;
		while(plugin_tmp1)
		{	if(plugin_tmp1->next_plugin==plugin_tmp)
			{	plugin_tmp1->next_plugin=plugin_tmp->next_plugin;
				plugin_tmp2=plugin_tmp->next_plugin->next_plugin;
				plugin_tmp->next_plugin->next_plugin=plugin_tmp;
				plugin_tmp->next_plugin=plugin_tmp2;
				set_plugins_config();
				return 1;
			}
			plugin_tmp1=plugin_tmp1->next_plugin;
		}
	}
	return 0;
}

void get_dll_name(char *s1,HANDLE hPlugin)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->hDll==hPlugin)
		{	tor_snprintf(s1,100,plugin_tmp->dll_name);
			return;
		}
	}
}



int plugins_connection_add(connection_t *conn)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->RegisterConnection && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC && plugin_tmp->rights&PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS)
		{	if((plugin_tmp->RegisterConnection)(conn->global_identifier&0xffffffff,conn->type,conn->address,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param])==0)	return -1;
		}
	}
	return 0;
}

int plugins_connection_remove(connection_t *conn)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->UnregisterConnection && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC && plugin_tmp->rights&PLUGIN_RIGHT__CAN_CREATE_OR_CONNECTIONS)
		{	if((plugin_tmp->UnregisterConnection)(conn->global_identifier&0xffffffff,conn->type,conn->address,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param])==0)	return -1;
		}
	}
	return 0;
}

chunk_t *chunk_new_with_alloc_size(size_t alloc);
chunk_t *buf_add_chunk_with_capacity(buf_t *buf, size_t capacity, int capped);

void close_connection(connection_t *conn)
{	if(CONN_IS_EDGE(conn))
	{	edge_connection_t *conn1=TO_EDGE_CONN(conn);
		connection_edge_end(conn1,END_STREAM_REASON_DONE);
		if (conn1->socks_request)	conn1->socks_request->has_finished = 1;
	}
	if(!conn->marked_for_close)	connection_mark_for_close(conn);
}

void plugins_read_event(connection_t *conn,size_t before)
{	plugin_info_t *plugin_tmp;
	buf_t *buf=conn->inbuf;
	chunk_t *dest=NULL,*next_dest;
	size_t tmppos=before;
	int r,data_size,capacity;
	if(before==buf->datalen)
	{	if(!buf->tail || buf->tail->datalen)
			buf_add_chunk_with_capacity(buf,4096,0);
	}
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->ConnectionRead && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC)
		{	if(!dest)
			{	if(buf->datalen < before) before = buf->datalen;
				dest=buf->head;
				while(tmppos)
				{	if(dest->datalen > tmppos) break;
					else if(dest->datalen == tmppos)
					{	tmppos = 0;
						dest = dest->next;
						break;
					}
					tmppos -= dest->datalen;
					dest = dest->next;
				}
			}
			if(tmppos)
			{	chunk_repack(dest);
				data_size = dest->datalen-tmppos;
				capacity = (dest->mem + dest->memlen) - (dest->data + dest->datalen) + data_size;
				if(conn->hs_plugin&&plugin_tmp->HiddenService_HandleRead && plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER && (plugin_tmp->hDll==conn->hPlugin))
				{	r = (plugin_tmp->HiddenService_HandleRead)(conn->address,conn->global_identifier&0xffffffff,dest->data+tmppos,data_size,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
					if(r==0)
					{	close_connection(conn);
						return;
					}
				}
				r = (plugin_tmp->ConnectionRead)(conn->global_identifier&0xffffffff,conn->type,conn->state,conn->address,dest->data+tmppos,&data_size,capacity,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
				data_size -= dest->datalen-tmppos;
				buf->datalen += data_size;
				dest->datalen += data_size;
				if(r==-1)
				{	close_connection(conn);
					return;
				}
				else if(r==0)
				{	chunk_t *new_chunk=chunk_new_with_alloc_size(4096);
					new_chunk->next=dest->next;
					if(buf->tail==dest) buf->tail=new_chunk;
					dest->next=new_chunk;
					next_dest=dest->next;
				}
				else next_dest=dest->next;
			}
			else next_dest=dest;
			for(;next_dest;next_dest=next_dest->next)
			{	chunk_repack(dest);
				capacity = (dest->mem + dest->memlen) - (dest->data + dest->datalen) + dest->datalen;
				if(conn->hs_plugin&&plugin_tmp->HiddenService_HandleRead && plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER && (plugin_tmp->hDll==conn->hPlugin))
				{	r = (plugin_tmp->HiddenService_HandleRead)(conn->address,conn->global_identifier&0xffffffff,next_dest->data,next_dest->datalen,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
					if(r==0)
					{	close_connection(conn);
						return;
					}
				}
				r = (plugin_tmp->ConnectionRead)(conn->global_identifier&0xffffffff,conn->type,conn->state,conn->address,next_dest->data,(int *)&next_dest->datalen,capacity,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
				if(r==-1)
				{	close_connection(conn);
					return;
				}
				else if(r==0)
				{	chunk_t *new_chunk=chunk_new_with_alloc_size(4096);
					new_chunk->next=next_dest->next;
					if(buf->tail==next_dest) buf->tail=new_chunk;
					next_dest->next=new_chunk;
				}
			}
		}
	}
}

void plugins_write_event(connection_t *conn,size_t before)
{	plugin_info_t *plugin_tmp;
	buf_t *buf=conn->outbuf;
	chunk_t *dest=NULL,*next_dest;
	size_t tmppos=before;
	int r,data_size,capacity;
	if(before==buf->datalen)
	{	if(!buf->tail || buf->tail->datalen)
			buf_add_chunk_with_capacity(buf,4096,0);
	}
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if((plugin_tmp->ConnectionWrite && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC) || ((conn->hs_plugin)&&(plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER)&&(plugin_tmp->HiddenService_HandleRead)))
		{	if(!dest)
			{	if(buf->datalen < before) before = buf->datalen;
				dest=buf->head;
				while(tmppos)
				{	if(dest->datalen > tmppos) break;
					else if(dest->datalen == tmppos)
					{	tmppos = 0;
						dest = dest->next;
						break;
					}
					tmppos -= dest->datalen;
					dest = dest->next;
				}
			}
			if(tmppos)
			{	chunk_repack(dest);
				data_size = dest->datalen-tmppos;
				capacity = (dest->mem + dest->memlen) - (dest->data + dest->datalen) + data_size;
				if(conn->hs_plugin&&plugin_tmp->HiddenService_HandleRead && (plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER) && (plugin_tmp->hDll==conn->hPlugin))
				{	r = (plugin_tmp->HiddenService_HandleRead)(conn->address,conn->global_identifier&0xffffffff,dest->data+tmppos,data_size,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
					if(r==0)
					{	close_connection(conn);
						return;
					}
				}
				else if(plugin_tmp->ConnectionWrite && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC) r = (plugin_tmp->ConnectionWrite)(conn->global_identifier&0xffffffff,conn->type,conn->state,conn->address,dest->data+tmppos,&data_size,capacity,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
				else continue;
				data_size -= dest->datalen-tmppos;
				buf->datalen += data_size;
				dest->datalen += data_size;
				if(r==-1)
				{	close_connection(conn);
					return;
				}
				else if(r==0)
				{	chunk_t *new_chunk=chunk_new_with_alloc_size(4096);
					new_chunk->next=dest->next;
					if(buf->tail==dest) buf->tail=new_chunk;
					dest->next=new_chunk;
					next_dest=dest->next;
				}
				else next_dest=dest->next;
			}
			else next_dest=dest;
			for(;next_dest;next_dest=next_dest->next)
			{	chunk_repack(dest);
				capacity = (dest->mem + dest->memlen) - (dest->data + dest->datalen) + dest->datalen;
				if(conn->hs_plugin&&plugin_tmp->HiddenService_HandleRead && (plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER) && (plugin_tmp->hDll==conn->hPlugin))
				{	r = (plugin_tmp->HiddenService_HandleRead)(conn->address,conn->global_identifier&0xffffffff,next_dest->data,next_dest->datalen,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
					if(r==0)
					{	close_connection(conn);
						return;
					}
				}
				else if(plugin_tmp->ConnectionWrite && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_CLIENT_TRAFFIC) r = (plugin_tmp->ConnectionWrite)(conn->global_identifier&0xffffffff,conn->type,conn->state,conn->address,next_dest->data,(int *)&next_dest->datalen,capacity,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
				else continue;
				if(r==-1)
				{	close_connection(conn);
					return;
				}
				else if(r==0)
				{	chunk_t *new_chunk=chunk_new_with_alloc_size(4096);
					new_chunk->next=next_dest->next;
					if(buf->tail==next_dest) buf->tail=new_chunk;
					next_dest->next=new_chunk;
				}
			}
		}
	}
}

BOOL __stdcall plugin_hs_send_reply(HANDLE plugin_instance,DWORD client_id,char *buffer,int buffer_size)
{	plugin_info_t *plugin_tmp;
	buf_t *buf;chunk_t *dest;
	for(plugin_tmp=plugins;plugin_tmp && (plugin_tmp->hDll!=plugin_instance);plugin_tmp=plugin_tmp->next_plugin)	;
	if(!plugin_tmp || !(plugin_tmp->rights&PLUGIN_RIGHT__HIDDEN_SERVICE_PROVIDER)) return 0;
	smartlist_t *conns=get_connection_array();
	DWORD tmpid;
	SMARTLIST_FOREACH(conns, connection_t *, conn,{
		tmpid=conn->global_identifier&0xffffffff;
		if(client_id==tmpid)
		{	if(conn->hs_plugin)
			{	buf=conn->inbuf;dest=NULL;
				dest=buf->head;
				if(dest)
				{	while(dest->next)	dest=dest->next;
				}
				chunk_t *new_chunk=buf_add_chunk_with_capacity(buf,buffer_size,0);
				memmove(new_chunk->data,buffer,buffer_size);
				new_chunk->datalen = buffer_size;
				buf->datalen += buffer_size;
				connection_read_event(conn);
			}
			else
			{	buf=conn->outbuf;dest=NULL;
				dest=buf->head;
				if(dest)
				{	while(dest->next)	dest=dest->next;
				}
				chunk_t *new_chunk=buf_add_chunk_with_capacity(buf,buffer_size,0);
				memmove(new_chunk->data,buffer,buffer_size);
				new_chunk->datalen = buffer_size;
				buf->datalen += buffer_size;
				conn->outbuf_flushlen += buffer_size;
				connection_start_writing(conn);
			}
			return 1;
		}
	});
	return 0;
}


int plugins_remap(edge_connection_t *conn,char **address,char *original_address,BOOL is_error)
{	plugin_info_t *plugin_tmp;
	int r;
	char *addrtmp = NULL;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->TranslateAddress && plugin_tmp->rights&PLUGIN_RIGHT__CAN_TRANSLATE_ADDRESSES)
		{	if(!addrtmp)
			{	addrtmp = tor_malloc(1024);
				tor_snprintf(addrtmp,1023,"%s",*address);
			}
			if(conn)	r=(plugin_tmp->TranslateAddress)(TO_CONN(conn)->global_identifier&0xffffffff,original_address,addrtmp,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&TO_CONN(conn)->lParam[plugin_tmp->connection_param],is_error);
			else		r=(plugin_tmp->TranslateAddress)(0,original_address,addrtmp,NULL,is_error);
			if(!r)
			{	if(addrtmp)	tor_free(addrtmp);
				log(LOG_ADDR,LD_APP,get_lang_str(LANG_PLUGINS_BANNED),plugin_tmp->dll_name,safe_str(*address));
				return 0;
			}
		}
	}
	if(addrtmp)
	{	if(*address)	tor_free(*address);
		*address = tor_strdup(addrtmp);
		tor_free(addrtmp);
	}
	return 1;
}

void plugins_new_identity(void)
{	uint32_t raddr=geoip_reverse(get_router_sel());
	char *country=NULL;
	if(get_country_sel()!=0x200)	country=(char *)geoip_get_country_name(get_country_sel());
	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->ChangeIdentity)
			(plugin_tmp->ChangeIdentity)(raddr,country,best_delta_t);
	}
}

void plugins_start(int started)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->AdvTorStart)
			(plugin_tmp->AdvTorStart)(started);
	}
}

void plugins_routerchanged(uint32_t addr,char *digest,int changed)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->RouterChanged)
			(plugin_tmp->RouterChanged)(geoip_reverse(addr),digest,changed);
	}
}

int plugin_notify_service(rend_service_t *service,int added,connection_t *conn,int port)
{	if(!service || !service->plugin[0])	return 0;
	char buf[100];
	int i,result=1;
	if(conn && !service)	service=find_service(conn->address);
	if(!service)	return 0;
	rend_service_port_config_t *p;
	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(!strcasecmp(plugin_tmp->dll_name,service->plugin))
		{	if(plugin_tmp->HiddenService_NotifyService)
			{	tor_snprintf(buf,sizeof(buf),"%s.onion",service->service_id);
				if(conn)
				{	result=(plugin_tmp->HiddenService_NotifyService)(added,buf,port,conn->global_identifier&0xffffffff,(plugin_tmp->connection_param==-1)?NULL:(LPARAM *)&conn->lParam[plugin_tmp->connection_param]);
					conn->hs_plugin=1;
					conn->port=port;
					if(conn->address)	tor_free(conn->address);
					conn->address=tor_strdup(buf);
				}
				else
				{	for(i=0;i<smartlist_len(service->ports);++i)
					{	p=smartlist_get(service->ports,i);
						result=(plugin_tmp->HiddenService_NotifyService)(added,buf,p->virtual_port,0,NULL);
						if(!result)	return 0;
					}
				}
				return result;
			}
			else return 1;
		}
	}
	return 1;
}

void plugins_interceptprocess(DWORD pid,BOOL intercepted)
{	plugin_info_t *plugin_tmp;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->InterceptProcess && plugin_tmp->rights&PLUGIN_RIGHT__CAN_INTERCEPT_PROCESSES)
			(plugin_tmp->InterceptProcess)(pid,intercepted);
	}
}

void plugins_language_change(void)
{	plugin_info_t *plugin_tmp;
	char *lng = get_options()->Language;
	for(plugin_tmp=plugins;plugin_tmp;plugin_tmp=plugin_tmp->next_plugin)
	{	if(plugin_tmp->loaded_lng)	tor_free(plugin_tmp->loaded_lng);
		if(plugin_tmp->lngfile)		tor_free(plugin_tmp->lngfile);
		plugin_tmp->loaded_lng = NULL;
		plugin_tmp->lngfile = NULL;
		plugin_tmp->maxdefs = 0;
		plugin_tmp->lng_error = 0;
		if(plugin_tmp->LanguageChange)
			(plugin_tmp->LanguageChange)(lng);
	}
}
