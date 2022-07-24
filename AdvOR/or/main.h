/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file main.h
 * \brief Header file for main.c.
 **/

#ifndef _TOR_MAIN_H
#define _TOR_MAIN_H

extern int can_complete_circuit;

time_t set_new_time(time_t);
time_t get_time(time_t*);
time_t update_time(time_t);
void adjust_time(int);
void update_best_delta_t(long t);

void updateDirStatus(void);
int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_unregister_events(connection_t *conn);
int connection_in_array(connection_t *conn);
void add_connection_to_closeable_list(connection_t *conn);
int connection_is_on_closeable_list(connection_t *conn);

smartlist_t *get_connection_array(void);

/** Bitmask for events that we can turn on and off with
 * connection_watch_events. */
typedef enum watchable_events {
  READ_EVENT=0x02, /**< We want to know when a connection is readable */
  WRITE_EVENT=0x04 /**< We want to know when a connection is writable */
} watchable_events_t;
void connection_watch_events(connection_t *conn, watchable_events_t events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void connection_stop_reading_from_linked_conn(connection_t *conn);

void directory_all_unreachable(time_t now);
void directory_info_has_arrived(time_t now, int from_cache);

void ip_address_changed(int at_interface);
void dns_servers_relaunch_checks(void);

void handle_signals(int is_parent);
void process_signal(uintptr_t sig);

int try_locking(or_options_t *options, int err_if_locked);
int have_lockfile(void);
void release_lockfile(void);

void tor_cleanup(void);
void tor_free_all(int postfork);

int tor_main(int argc, char *argv[]) __attribute__((noreturn));

void set_log_filter(void);

char *get_default_conf_file(void);
void showLastExit(char *rname,uint32_t addr);
void clearServiceList(void);
void setStartupOption(int commandId);
char *getLanguageFileName(const char *source);
void setNewLanguage(void);
int __stdcall is_ip(char *txt1);
void __stdcall FormatMemInt(char *memInt,uint32_t);
void __stdcall FormatMemInt64(char *,uint64_t*);
void dlgStatsRWInit(void);
void dlgUpdateRWStats(int seconds,uint32_t bw_read,uint32_t bw_written);
void dlgShowRWStats(HWND hDlg);
void tree_show_sel(HTREEITEM hItem,LPARAM lParam);
void tree_add_circ(circuit_t *circ,char *nodename);
void tree_add_new_circ(circuit_t *circ);
void tree_remove_circ(circuit_t *circ);
void tree_set_circ(circuit_t *circ);
void tree_remove_hop(crypt_path_t *cpath);
void add_all_conns(circuit_t *circ);
connection_t *get_connection_by_addr(uint32_t ip,int port,connection_t *after);
void add_all_streams(HTREEITEM hItem,edge_connection_t *streams);
void tree_remove_stream(edge_connection_t *stream);
void remove_all_streams(edge_connection_t *streams);
void tree_remove_streams(circuit_t *circ);
void tree_add_streams(circuit_t *circ);
DWORD getPID(uint32_t addr,int port);
DWORD getChainKey(DWORD pid);
int getProcessName(char *buffer,int bufsize,DWORD pid);
void tree_destroy_circuit(void);
void tree_create_circuit(void);
void tree_estimate_circuit(HWND hDlg,int hops);
int tor_is_started(void);
void updatePluginStatus(int plugin_id,int load_status);
void updatePluginDescription(int plugin_id,char *description);
void dlgDebug_setLogFilter(or_options_t *options);
void dlgServerUpdate(void);
void dlgForceTor_scheduleExec(char *prog);
void save_settings(void);
void setState(int);
HTREEITEM addTreeItem(HTREEITEM hParent,const char *name,DWORD lParam,int tree_idx);
void setTreeItem(HTREEITEM hItem,const char *name);
void identity_add_process(DWORD);
void identity_init(void);
void dumpstats(int severity); /* log stats */
void iplist_free(void);
void iplist_write(void);
void iplist_init(void);
time_t dlgBypassBlacklists_getLongevity(routerinfo_t *router);

#ifdef MAIN_PRIVATE
int do_main_loop(void);
int do_list_fingerprint(void);
void do_hash_password(void);
int tor_init(int argc, char **argv);
#endif

#define MAX_PAGE_INDEXES 27

#define INDEX_PAGE_PROXY 0
#define INDEX_PAGE_BANLIST 1
#define INDEX_PAGE_HTTP_HEADERS 2
#define INDEX_PAGE_CONNECTIONS 3
#define INDEX_PAGE_ADVANCED_PROXY_SETTINGS 4
#define INDEX_PAGE_NETWORK 5
#define INDEX_PAGE_BRIDGES 6
#define INDEX_PAGE_AUTHORITIES 7
#define INDEX_PAGE_ROUTER_RESTRICTIONS 8
#define INDEX_PAGE_BANNED_ROUTERS 9
#define INDEX_PAGE_FAVORITE_ROUTERS 10
#define INDEX_PAGE_CIRCUIT_BUILD 11
#define INDEX_PAGE_TRACKED_HOSTS 12
#define INDEX_PAGE_HOSTED_SERVICES 13
#define INDEX_PAGE_HIDDEN_SERVICES 14
#define INDEX_PAGE_OR_SERVER 15
#define INDEX_PAGE_PRIVATE_IDENTITY 16
#define INDEX_PAGE_INTERCEPT 17
#define INDEX_PAGE_QUICK_START 18
#define INDEX_PAGE_PROCESSES 19
#define INDEX_PAGE_SANDBOXING 20
#define INDEX_PAGE_PLUGINS 21
#define INDEX_PAGE_SYSTEM 22
#define INDEX_PAGE_DEBUG 23
#define INDEX_PAGE_FILTERS 24
#define INDEX_PAGE_ABOUT 25
#define INDEX_PAGE_BYPASSBL 26


#define DLG_FRAME_PROXY 1100
#define DLG_FRAME_AUTHORITIES 1101
#define DLG_FRAME_ROUTER_RESTRICTIONS 1102
#define DLG_FRAME_CIRCUIT_BUILD 1103
#define DLG_FRAME_CONNECTIONS 1104
#define DLG_FRAME_BRIDGES 1105
#define DLG_FRAME_HIDDEN_SERVICES 1106
#define DLG_FRAME_PLUGINS 1107
#define DLG_FRAME_SYSTEM 1108
#define DLG_FRAME_INTERCEPT_PROCESSES 1109
#define DLG_FRAME_HOST_ROUTER 1110
#define DLG_FRAME_OR_NETWORK 1111
#define DLG_FRAME_DEBUG 1112
#define DLG_FRAME_ABOUT 1113
#define DLG_FRAME_BANNED_ADDRESSES 1114
#define DLG_FRAME_HTTP_HEADERS 1115
#define DLG_FRAME_ADVANCED_PROXY_SETTINGS 1116
#define DLG_FRAME_BANNED_ROUTERS 1117
#define DLG_FRAME_FAVORITE_ROUTERS 1118
#define DLG_FRAME_TRACKED_HOSTS 1119
#define DLG_FRAME_HOSTED_SERVICES 1120
#define DLG_FRAME_PRIVATE_IDENTITY 1121
#define DLG_FRAME_INTERCEPT 1122
#define DLG_FRAME_QUICK_START 1123
#define DLG_FRAME_SANDBOXING 1124
#define DLG_FRAME_DEBUG_FILTERS 1125	// moved to a separate dialog
#define DLG_FRAME_BYPASSBL 1126

#endif

