#include "or.h"
#include "proxy.h"
#include "plugins.h"
#include "geoip.h"
#include "config.h"
#include "circuitlist.h"
#include "hibernate.h"
#include "main.h"
#include "rendclient.h"
#include "connection_edge.h"
#include "router.h"
#include "routerlist.h"
#include <shlobj.h>

#define MAX_CACHED_WARNS 10
#define MAX_CACHED_PIDS 100
#define IDENTITY_EXPIRE_CIRCUITS 1
#define IDENTITY_EXPIRE_TRACKED_HOSTS 2
#define IDENTITY_DESTROY_CIRCUITS 4
#define IDENTITY_EXPIRE_COOKIES 8
#define IDENTITY_REINIT_KEYS 16
#define IDENTITY_REGISTER_ADDRESSMAPS 32
#define IDENTITY_ENTER_HIBERNATION 64
#define IDENTITY_EXIT_CHANGED 128
#define IDENTITY_ADDRMAP_CHANGED 256
#define IDENTITY_TRACKHOST_CHANGED 512

#define STORED_PROC_FIREFOX 0
#define STORED_PROC_CHROME 1
#define STORED_PROC_OPERA 2
#define STORED_PROC_FIREFOX2 3

DWORD pid_list[MAX_CACHED_PIDS];
extern HWND hMainDialog;
extern HINSTANCE hInstance;
extern BOOL started;
int pid_index = 0;
int last_country = -1;

uint32_t identity_seed1,identity_seed2,identity_seed3,identity_seed4;
//extern DWORD http_warnings[MAX_CACHED_WARNS*2];
extern or_options_t *tmpOptions;
extern int selectedVer;
extern LPFN13 CreateThreadEx;
extern LPFN14 RelinkStoredProc;
int signewnym_pending = 0;
char *appdata = NULL;
char *localappdata = NULL;
char *userprofile = NULL;

int randomize_wmplayer(void);
int delete_flash_cookies(char **msg,int *msgsize);
int delete_silverlight_cookies(char **msg,int *msgsize);
void delete_cookies(char **msg,int *msgsize);
void dlgForceTor_scheduledExec(void);
void scheduled_addrmap_change(void);
void scheduled_trackhost_change(void);
void set_identity_exit(uint32_t addr);
unsigned long get_seed(int bitpos);
void schedule_expire_tracked_hosts(void);
void schedule_register_addressmaps(void);
void schedule_stop_tor(void);
void schedule_addrmap_change(void);
void schedule_trackhost_change(void);
void signewnym_scheduled_tasks(void);
void signewnym_impl(time_t now,int msgshow);
void identity_auto_change(time_t now);
void identity_exit(void);
void get_appdata(void);
void free_smartlist(smartlist_t *entries);
void delete_ie_cookies(DWORD pid,const char *module,char **msg,int *msgsize);
void delete_opera_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path);
void delete_firefox_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path);
void delete_chrome_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path);
void delete_safari_cookies(DWORD pid,const char *module,char **msg,int *msgsize,char *path);
int count_opera_cookies(const char *fname);

void set_identity_exit(uint32_t addr)
{	if(last_country == -1)
		last_country = geoip_get_country_by_ip(addr)&0xff;
//	log(LOG_WARN,LD_APP,"Selected country: %s (%i.%i.%i.%i)",geoip_get_country_name(last_country),addr&0xff,(addr>>8)&0xff,(addr>>16)&0xff,(addr>>24)&0xff);
}

unsigned long get_seed(int bitpos)	//128*2
{	uint32_t s1,s2;
	int bpos = (bitpos>>5)&3;
	switch(bpos)
	{	case 0:
			s1 = identity_seed1;
			s2 = identity_seed2;
			break;
		case 1:
			s1 = identity_seed2;
			s2 = identity_seed1;
			break;
		case 2:
			s1 = identity_seed3;
			s2 = identity_seed4;
			break;
		case 3:
			s1 = identity_seed4;
			s2 = identity_seed3;
			break;
		case 4:
			s1 = identity_seed1 ^ identity_seed3;
			s2 = identity_seed2 + identity_seed3;
			break;
		case 5:
			s1 = identity_seed2 ^ identity_seed4;
			s2 = identity_seed1 + identity_seed4;
			break;
		case 6:
			s1 = identity_seed3 ^ identity_seed2;
			s2 = identity_seed4 - identity_seed2;
			break;
		case 7:
			s1 = identity_seed4 ^ identity_seed1;
			s2 = identity_seed3 - identity_seed1;
			break;
		default:
			s1 = identity_seed1;
			s2 = identity_seed2;
			break;
	}
	if((bitpos%32) == 0)	return s1;
	bitpos %= 32;
	while(bitpos)
	{	s1 >>= 1;
		if(s2&1)	s1 |= 0x80000000;
		else		s1 &= 0x7fffffff;
		s2 >>= 1;
		bitpos--;
	}
	return s1;
}


void identity_add_process(DWORD pid)
{	int i;
	for(i = 0;i<pid_index;i++)
	{	if(pid_list[i]==pid)	return;
	}
	if(pid_index < MAX_CACHED_PIDS)
	{	pid_list[pid_index] = pid;
		pid_index++;
	}
}

void identity_init(void)
{	crypto_rand((char *)&identity_seed1,4);
	crypto_rand((char *)&identity_seed2,4);
	crypto_rand((char *)&identity_seed3,4);
	crypto_rand((char *)&identity_seed4,4);
	identity_seed1 &= 0x7fffffff;
	identity_seed2 &= 0x7fffffff;
	identity_seed3 &= 0x7fffffff;
	identity_seed4 &= 0x7fffffff;
}

void schedule_expire_tracked_hosts(void)
{
	signewnym_pending |= IDENTITY_EXPIRE_TRACKED_HOSTS;
}

void schedule_register_addressmaps(void)
{
	signewnym_pending |= IDENTITY_REGISTER_ADDRESSMAPS;
}

void schedule_stop_tor(void)
{
	signewnym_pending |= IDENTITY_ENTER_HIBERNATION;
}

void schedule_addrmap_change(void)
{
	signewnym_pending |= IDENTITY_ADDRMAP_CHANGED;
}

void schedule_trackhost_change(void)
{
	signewnym_pending |= IDENTITY_TRACKHOST_CHANGED;
}

void signewnym_scheduled_tasks(void)
{	if(signewnym_pending & IDENTITY_EXPIRE_COOKIES) free_cookies();
	if(signewnym_pending & IDENTITY_REINIT_KEYS)		init_keys();
	if(signewnym_pending & IDENTITY_DESTROY_CIRCUITS)	circuit_expire_all_circs(0);
	else if(signewnym_pending & IDENTITY_EXPIRE_CIRCUITS)
	{	circuit_expire_all_circuits();
		rend_client_purge_state();
	}
	if(signewnym_pending & IDENTITY_EXPIRE_TRACKED_HOSTS)	addressmap_clear_transient();
	if(signewnym_pending & IDENTITY_REGISTER_ADDRESSMAPS)
	{	config_register_addressmaps(tmpOptions);
		parse_virtual_addr_network(tmpOptions->VirtualAddrNetwork, 0, 0);
	}
	if(signewnym_pending & IDENTITY_ENTER_HIBERNATION)
	{	started=2;
		plugins_start(0);
		circuit_expire_all_circs(0);
		hibernate_go_dormant(get_time(NULL));
		showLastExit(NULL,0);
	}
	if(signewnym_pending & IDENTITY_ADDRMAP_CHANGED)
		scheduled_addrmap_change();
	if(signewnym_pending & IDENTITY_TRACKHOST_CHANGED)
		scheduled_trackhost_change();
	if(signewnym_pending & IDENTITY_EXIT_CHANGED)
		showLastExit(NULL,-1);
	signewnym_pending = 0;
}

void signewnym_impl(time_t now,int msgshow)
{	char *msg = NULL,*msgp = NULL;
	int msgsize = 0;
	(void) now;
	if(msgshow)
	{	msg = tor_malloc(2048);
		char *str=print_router_sel();
		tor_snprintf(msg,2047,"%s\r\n\r\n",str);
		msgsize = 2048 - strlen(msg);
		tor_free(str);
		msgp = msg + strlen(msg);
	}
	showLastExit(NULL,0);
	plugins_new_identity();
	if((tmpOptions->BestTimeDelta)&&(tmpOptions->DirFlags&DIR_FLAG_USE_ROUTER_TIME)) delta_t=tmpOptions->BestTimeDelta;
	else delta_t=crypto_rand_int(tmpOptions->MaxTimeDelta*2)-tmpOptions->MaxTimeDelta;
	update_best_delta_t(delta_t);
	if(selectedVer==-1) selectedVer=crypto_rand_int(41);
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_REINIT_KEYS)			signewnym_pending |= IDENTITY_REINIT_KEYS;
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_EXPIRE_CIRCUITS)		signewnym_pending |= IDENTITY_EXPIRE_CIRCUITS;
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS)	signewnym_pending |= IDENTITY_EXPIRE_TRACKED_HOSTS;
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_GENERATE_SEEDS)
	{	crypto_rand((char *)&identity_seed1,4);
		crypto_rand((char *)&identity_seed2,4);
		crypto_rand((char *)&identity_seed3,4);
		crypto_rand((char *)&identity_seed4,4);
	}
	showLastExit(NULL,-1);
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_EXPIRE_HTTP_COOKIES)		signewnym_pending |= IDENTITY_EXPIRE_COOKIES;
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_DELETE_HTTP_COOKIES)
	{	delete_cookies(&msgp,&msgsize);
	}
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_DELETE_FLASH_COOKIES)
	{	delete_flash_cookies(&msgp,&msgsize);
	}
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_DELETE_SILVERLIGHT_COOKIES)
	{	delete_silverlight_cookies(&msgp,&msgsize);
	}
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_RANDOMIZE_WMPLAYER_ID)
	{	randomize_wmplayer();
	}
	if(tmpOptions->IdentityFlags&IDENTITY_FLAG_DESTROY_CIRCUITS)		signewnym_pending |= IDENTITY_DESTROY_CIRCUITS;
//	http_warnings[0] = 0;
//	http_warn_idx = 0;
	if(msgshow && !(tmpOptions->IdentityFlags&IDENTITY_FLAG_NO_MESSAGEBOX))
	{	LangMessageBox(NULL,msg,LANG_MB_NEW_IDENTITY,MB_OK|MB_TASKMODAL|MB_SETFOREGROUND);
		tor_free(msg);
	}
	signewnym_pending |= IDENTITY_EXIT_CHANGED;
	last_country = -1;
	pid_index = 0;
}

void identity_auto_change(time_t now)
{
	if(started != 1)
		return;
	showLastExit(NULL,0);
	set_router_sel(0,1);
	if(tmpOptions->IdentityFlags & IDENTITY_FLAG_AUTO_CHANGE_IP)
	{	showLastExit(NULL,-1);
		signewnym_pending |= IDENTITY_EXPIRE_CIRCUITS;
		signewnym_pending |= IDENTITY_EXPIRE_TRACKED_HOSTS;
		last_country = -1;
		pid_index = 0;
	}
	else	signewnym_impl(now,0);
	signewnym_scheduled_tasks();
}

void identity_exit(void)
{	if(appdata)		tor_free(appdata);
	if(localappdata)	tor_free(localappdata);
	if(userprofile)		tor_free(userprofile);
	free_cookies();
}

int get_identity_user_agent(void)
{	return BROWSER_ID_FIRST+1 + ((identity_seed2 & 0xff) % (BOT_ID_FIRST - BROWSER_ID_FIRST-1));
}



const char *wmkey="Software\\Microsoft\\MediaPlayer\\Player\\Settings";
const char *wmvaluename="Client ID";
const char *regfilename = "undo.reg";
const char *regstr = "REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\Microsoft\\MediaPlayer\\Player\\Settings]\r\n\"Client ID\"=\"";

int randomize_wmplayer(void)
{	HKEY hKey=NULL;
	DWORD keytype;
	char *regdata = tor_malloc(100);
	DWORD datasize = 100;
	int i;
	if(RegOpenKeyEx(HKEY_CURRENT_USER,wmkey,0,KEY_ALL_ACCESS,&hKey) != ERROR_SUCCESS)
	{	log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_REGISTRY_ERROR),wmkey);
		return 0;
	}
	keytype = REG_SZ;
	i = RegQueryValueEx(hKey,wmvaluename,NULL,&keytype,(LPBYTE)regdata,&datasize);
	if(i == ERROR_MORE_DATA)
	{	tor_free(regdata);regdata = tor_malloc(datasize+1);
		i = RegQueryValueEx(hKey,wmvaluename,NULL,&keytype,(LPBYTE)regdata,&datasize);
	}
	if(i==ERROR_SUCCESS)
	{	log(LOG_DEBUG,LD_APP,get_lang_str(LANG_IDENTITY_WMPLAYER_ID),regdata);
		char *regfile = get_datadir_fname(regfilename);
		if(get_file_attributes(regfile)==0xffffffff)
		{	HANDLE hFile = open_file(regfile,GENERIC_WRITE,CREATE_ALWAYS);
			if(hFile!=INVALID_HANDLE_VALUE)
			{	char *tmpstr = tor_malloc(1024);
				DWORD written;
				tor_snprintf(tmpstr,1023,"%s%s\"\r\n",regstr,regdata);
				WriteFile(hFile,tmpstr,strlen(tmpstr),&written,NULL);
				CloseHandle(hFile);
				tor_free(tmpstr);
				log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_WMPLAYER_ID_SAVED),regfile);
			}
		}
		tor_free(regfile);
	}
	sprintf(regdata,"{%04X%04X-%04X-%04X-%04X-%04X%04X%04X}",(unsigned int)get_seed(120)&0xffff,(unsigned int)get_seed(177)&0xffff,(unsigned int)get_seed(75)&0xffff,(unsigned int)get_seed(22)&0xffff,(unsigned int)get_seed(201)&0xffff,(unsigned int)get_seed(190)&0xffff,(unsigned int)get_seed(155)&0xffff,(unsigned int)get_seed(45)&0xffff);
	log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_WMPLAYER_ID_CHANGED),regdata);
	RegSetValueEx(hKey,wmvaluename,0,REG_SZ,(LPBYTE)regdata,strlen(regdata));
	RegCloseKey(hKey);
	tor_free(regdata);
	return 1;
}

const char *folderskey="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
const char *folder1 = "AppData";
const char *folder2 = "Local AppData";
const char *folder3 = "Local Settings";

void get_appdata(void)
{	LPITEMIDLIST idl;
	IMalloc *m;
	HKEY hKey;
	DWORD keytype;
	DWORD datasize;
	int i;
	if(!appdata)
	{	if(SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&idl)==NOERROR)
		{	appdata = tor_malloc(MAX_PATH);
			if(!SHGetPathFromIDList(idl,appdata))
			{	tor_free(appdata);
				appdata = NULL;
			}
			SHGetMalloc(&m);
			if(m)
			{	m->lpVtbl->Free(m, idl);
				m->lpVtbl->Release(m);
			}
		}
		if(!appdata)
		{	appdata = tor_malloc(MAX_PATH);
			if(RegOpenKeyEx(HKEY_CURRENT_USER,folderskey,0,KEY_ALL_ACCESS,&hKey) == ERROR_SUCCESS)
			{	datasize = MAX_PATH - 1;
				keytype = REG_SZ;
				i = RegQueryValueEx(hKey,folder1,NULL,&keytype,(LPBYTE)appdata,&datasize);
				if(i == ERROR_MORE_DATA)
				{	tor_free(appdata);appdata = tor_malloc(datasize+1);
					i = RegQueryValueEx(hKey,folder1,NULL,&keytype,(LPBYTE)appdata,&datasize);
				}
				if(i != ERROR_SUCCESS)
				{	char *tmp = tor_malloc(MAX_PATH);
					datasize = MAX_PATH - 1;
					keytype = REG_SZ;
					i = RegQueryValueEx(hKey,folder3,NULL,&keytype,(LPBYTE)tmp,&datasize);
					if(i == ERROR_MORE_DATA)
					{	tor_free(tmp);tmp = tor_malloc(datasize+1);
						i = RegQueryValueEx(hKey,folder3,NULL,&keytype,(LPBYTE)tmp,&datasize);
					}
					if(i==ERROR_SUCCESS)
					{	tor_free(appdata);
						i = 0;
						while(tmp[i])	i++;
						if(i && tmp[i-1] == '\\')	i--;
						while(i && tmp[i-1]!='\\')	i--;
						if(i && tmp[i-1] == '\\')	i--;
						tmp[i] = 0;
						i = strlen(tmp)+100;
						appdata = tor_malloc(i);
						tor_snprintf(appdata,i-1,"%s\\Application Data",tmp);
					}
					else
					{	tor_free(appdata);
						appdata = NULL;
					}
					tor_free(tmp);
				}
				RegCloseKey(hKey);
			}
			else
			{	tor_free(appdata);
				appdata = NULL;
			}
		}
	}
	if(!localappdata)
	{	if(SHGetSpecialFolderLocation(NULL,CSIDL_LOCAL_APPDATA,&idl)==NOERROR)
		{	localappdata = tor_malloc(MAX_PATH);
			if(!SHGetPathFromIDList(idl,localappdata))
			{	tor_free(localappdata);
				localappdata = NULL;
			}
			SHGetMalloc(&m);
			if(m)
			{	m->lpVtbl->Free(m, idl);
				m->lpVtbl->Release(m);
			}
		}
		if(!localappdata)
		{	localappdata = tor_malloc(MAX_PATH);
			if(RegOpenKeyEx(HKEY_CURRENT_USER,folderskey,0,KEY_ALL_ACCESS,&hKey) == ERROR_SUCCESS)
			{	datasize = MAX_PATH - 1;
				keytype = REG_SZ;
				i = RegQueryValueEx(hKey,folder2,NULL,&keytype,(LPBYTE)localappdata,&datasize);
				if(i == ERROR_MORE_DATA)
				{	tor_free(localappdata);localappdata = tor_malloc(datasize+1);
					i = RegQueryValueEx(hKey,folder2,NULL,&keytype,(LPBYTE)localappdata,&datasize);
				}
				if(i != ERROR_SUCCESS)
				{	char *tmp = tor_malloc(MAX_PATH);
					datasize = MAX_PATH - 1;
					keytype = REG_SZ;
					i = RegQueryValueEx(hKey,folder3,NULL,&keytype,(LPBYTE)tmp,&datasize);
					if(i == ERROR_MORE_DATA)
					{	tor_free(tmp);tmp = tor_malloc(datasize+1);
						i = RegQueryValueEx(hKey,folder3,NULL,&keytype,(LPBYTE)tmp,&datasize);
					}
					if(i==ERROR_SUCCESS)
					{	tor_free(localappdata);
						i = 0;
						while(tmp[i])	i++;
						if(i && tmp[i-1] == '\\')	i--;
						tmp[i] = 0;
						i = strlen(tmp)+100;
						localappdata = tor_malloc(i);
						tor_snprintf(localappdata,i,"%s\\Application Data",tmp);
					}
					else
					{	tor_free(localappdata);
						localappdata = NULL;
					}
					tor_free(tmp);
				}
				RegCloseKey(hKey);
			}
			else
			{	tor_free(localappdata);
				localappdata = NULL;
			}
		}
	}
	if(appdata)
	{	i = 0;
		while(appdata[i])	i++;
		if(i && appdata[i-1]=='\\')	i--;
		appdata[i] = 0;
	}
	if(!userprofile && appdata)
	{	userprofile = tor_malloc(MAX_PATH);
		tor_snprintf(userprofile,MAX_PATH-1,"%s",appdata);
		i = 0;
		while(userprofile[i])	i++;
		if(i && userprofile[i-1] == '\\')	i--;
		while(i && userprofile[i-1]!='\\')	i--;
		if(i)	userprofile[i-1] = 0;
	}
	if(localappdata)
	{	i = 0;
		while(localappdata[i])	i++;
		if(i && localappdata[i-1]=='\\')	i--;
		localappdata[i] = 0;
	}
}

void free_smartlist(smartlist_t *entries)
{	if(entries)
	{	SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
		smartlist_free(entries);
	}
}

const char *fpath1 = "\\Macromedia\\Flash Player\\#SharedObjects";
const char *fpath1a = "\\Macromedia\\Flash Player";	// some versions of flash players save cookies here
const char *fpath2 = "\\Macromedia\\Flash Player\\macromedia.com\\support\\flashplayer\\sys";
const char *fpath3 = "\\Adobe\\Flash Player\\AssetCache";
int delete_flash_cookies(char **msg,int *msgsize)
{	get_appdata();
	if(appdata)
	{	char *newpath = tor_malloc(1024),*tmppath,*tmpsol;
		int numcookies = 0,numshown = 0,solitems=0;
		DWORD i,j = 0,k,l;
		HANDLE hFile;
		char *dstr = tor_malloc(512);
		tor_snprintf(newpath,1023,"%s%s\\*.*",appdata,fpath1);
		smartlist_t *objdir,*domains;
		objdir = listdir(newpath);
		if(objdir)
		{	tmppath = tor_malloc(1024);
			SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s%s\\%s\\*.*",appdata,fpath1,fn);
				log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_DELETING_FILE),newpath);
				domains = listdir(newpath);
				if(domains)
				{	SMARTLIST_FOREACH(domains,char *,fn1,
					{	if(*msgsize)
						{	if(numshown<4)
							{	tor_snprintf(dstr+j,511-j,"\r\n\t%s",fn1);
								j = strlen(dstr);
								numshown++;
							}
							else if(numshown==4)
							{	tor_snprintf(dstr+j,511-j,"\r\n\t...");
							}
						}
						tor_snprintf(tmppath,1023,"%s%s\\%s\\%s",appdata,fpath1,fn,fn1);
						numcookies += ForceDeleteSubdir(tmppath);
					});
				}
				tor_snprintf(newpath,1023,"%s%s\\%s",appdata,fpath1,fn);
				numcookies += ForceDeleteSubdir(newpath);
			});
			free_smartlist(objdir);
			tor_free(tmppath);
		}
		tor_snprintf(newpath,1023,"%s%s\\*.*",appdata,fpath1a);
		objdir = listdir(newpath);
		if(objdir)
		{	tmppath = tor_malloc(1024);
			SMARTLIST_FOREACH(objdir,char *,fn,
			{	if(strcasecmp(fn,"#SharedObjects") && strcasecmp(fn,"macromedia.com"))
				{	tor_snprintf(newpath,1023,"%s%s\\%s\\*.*",appdata,fpath1a,fn);
					log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_DELETING_FILE),newpath);
					domains = listdir(newpath);
					if(domains)
					{	SMARTLIST_FOREACH(domains,char *,fn1,
						{	if(*msgsize)
							{	if(numshown<4)
								{	tor_snprintf(dstr+j,511-j,"\r\n\t%s",fn1);
									j = strlen(dstr);
									numshown++;
								}
								else if(numshown==4)
								{	tor_snprintf(dstr+j,511-j,"\r\n\t...");
								}
							}
							tor_snprintf(tmppath,1023,"%s%s\\%s\\%s",appdata,fpath1,fn,fn1);
							numcookies += ForceDeleteSubdir(tmppath);
						});
					}
					tor_snprintf(newpath,1023,"%s%s\\%s",appdata,fpath1,fn);
					numcookies += ForceDeleteSubdir(newpath);
				}
			});
			free_smartlist(objdir);
			tor_free(tmppath);
		}
		if(numcookies && *msgsize)
		{	tor_snprintf(*msg,*msgsize,"%s%i%s\r\n",get_lang_str(LANG_IDENTITY_FLASH_COOKIES_DELETED),numcookies,dstr);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		numcookies = 0;
		tor_snprintf(newpath,1023,"%s%s\\*.*",appdata,fpath2);
		objdir = listdir(newpath);
		if(objdir)
		{	tmppath = tor_malloc(1024);
			SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s%s\\%s",appdata,fpath2,fn);
				if(!strcasecmp(fn,"settings.sol"))
				{	hFile = open_file(newpath,GENERIC_READ,OPEN_EXISTING);
					if(hFile)
					{	j = GetFileSize(hFile,NULL);k = 0;
						tmpsol = NULL;
						if(j != 0xffffffff)
						{	tmpsol = tor_malloc(j+5);
							ReadFile(hFile,tmpsol,j,&j,NULL);
							tmpsol[j]=0;
							for(i=0;i<j;i++)
							{	if(!strcasecmpstart(tmpsol+i,"\x07\x64\x6fmains"))
								{	l = i + 10;
									while(l < j)
									{	l += 4+(unsigned char)tmpsol[l];
										k--;
										solitems++;
										if(l < j && tmpsol[l] == 0) break;
									}
									while(l < j)
									{	tmpsol[i++] = tmpsol[l++];
									}
									j = i;k = 1;
									break;
								}
							}
						}
						CloseHandle(hFile);
						if(k && tmpsol)
						{	ForceDelete(newpath);
							hFile = open_file(newpath,GENERIC_WRITE,CREATE_ALWAYS);
							if(hFile)
							{	WriteFile(hFile,tmpsol,j,&j,NULL);
								CloseHandle(hFile);
							}
						}
						if(tmpsol)	tor_free(tmpsol);
					}
				}
				else
				{	numcookies += ForceDeleteSubdir(newpath);
				}
			});
			free_smartlist(objdir);
			tor_free(tmppath);
		}
		if(numcookies && *msgsize)
		{	tor_snprintf(*msg,*msgsize,"%s%i\r\n",get_lang_str(LANG_IDENTITY_FLASH_WEBSITES_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(solitems && *msgsize)
		{	tor_snprintf(*msg,*msgsize,"%s%i\r\n",get_lang_str(LANG_IDENTITY_FLASH_HISTORY_DELETED),solitems);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		numcookies = 0;
		tor_snprintf(newpath,1023,"%s%s\\*.*",appdata,fpath3);
		objdir = listdir(newpath);
		if(objdir)
		{	tmppath = tor_malloc(1024);
			SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s%s\\%s",appdata,fpath3,fn);
				numcookies += ForceDeleteSubdir(newpath);
			});
			free_smartlist(objdir);
			tor_free(tmppath);
		}
		if(numcookies && *msgsize)
		{	tor_snprintf(*msg,*msgsize,"%s%i\r\n",get_lang_str(LANG_IDENTITY_FLASH_CACHED_ITEMS_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		tor_free(dstr);
		tor_free(newpath);
		return 1;
	}
	return 0;
}

int delete_silverlight_cookies(char **msg,int *msgsize)
{	get_appdata();
	smartlist_t *objdir;
	int numcookies = 0;
	char *newpath = tor_malloc(1024);
	if(localappdata)
	{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Silverlight\\is\\*.*",localappdata);		// 2k/XP
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Silverlight\\is\\%s",localappdata,fn);
				log(LOG_INFO,LD_APP,"Deleting %s",newpath);
				numcookies += ForceDeleteSubdir(newpath);
			});
			free_smartlist(objdir);
		}
	}
	if(userprofile)
	{	tor_snprintf(newpath,1023,"%s\\AppData\\LocalLow\\Microsoft\\Silverlight\\is\\*.*",userprofile);	// 7ista
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\AppData\\LocalLow\\Microsoft\\Silverlight\\is\\%s",userprofile,fn);
				log(LOG_INFO,LD_APP,get_lang_str(LANG_IDENTITY_DELETING_FILE),newpath);
				numcookies += ForceDeleteSubdir(newpath);
			});
			free_smartlist(objdir);
		}
	}
	if(numcookies && *msgsize)
	{	tor_snprintf(*msg,*msgsize,"%s%i\r\n",get_lang_str(LANG_IDENTITY_SILVERLIGHT_COOKIES_DELETED),numcookies);
		*msgsize -= strlen(*msg);
		*msg += strlen(*msg);
	}
	tor_free(newpath);
	return 1;
}

typedef struct _INTERNET_CACHE_ENTRY_INFOA
{	DWORD dwStructSize;
	LPSTR lpszSourceUrlName;
	LPSTR lpszLocalFileName;
	DWORD CacheEntryType;
	DWORD dwUseCount;
	DWORD dwHitRate;
	DWORD dwSizeLow;
	DWORD dwSizeHigh;
	FILETIME LastModifiedTime;
	FILETIME ExpireTime;
	FILETIME LastAccessTime;
	FILETIME LastSyncTime;
	PBYTE lpHeaderInfo;
	DWORD dwHeaderInfoSize;
	LPSTR lpszFileExtension;
	DWORD dwReserved;
} INTERNET_CACHE_ENTRY_INFOA,*LPINTERNET_CACHE_ENTRY_INFOA;
#define COOKIE_CACHE_ENTRY 0x100000
typedef void (WINAPI *_CplProcW)(HWND hWnd,HINSTANCE hInstance,LPWSTR cmdLine,int cmdShow);
typedef HANDLE (WINAPI *_FindFirstUrlCacheEntry)(LPCSTR,LPINTERNET_CACHE_ENTRY_INFOA,PDWORD);
typedef BOOL (WINAPI *_FindNextUrlCacheEntry)(HANDLE,LPINTERNET_CACHE_ENTRY_INFOA,PDWORD);
typedef BOOL (WINAPI *_FindCloseUrlCache)(HANDLE);
typedef BOOL (WINAPI *_DeleteUrlCacheEntry)(LPCSTR);
WCHAR clearTracksParam[]={'2',0};

void delete_ie_cookies(DWORD pid,const char *module,char **msg,int *msgsize)
{	HINSTANCE hModule = LoadLibrary("inetcpl.cpl");
	int numcookies = 0,numdomcookies = 0;
	if(hModule)
	{	_CplProcW CplProc = (_CplProcW)GetProcAddress(hModule,"ClearMyTracksByProcessW");
		if(CplProc)
		{	CplProc(hMainDialog,hInstance,&clearTracksParam[0],SW_HIDE);
			FreeLibrary(hModule);
			if(*msgsize)
			{	char *procname = tor_malloc(200);
				getProcessName(procname,199,pid);
				tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
				tor_free(procname);
				*msgsize -= strlen(*msg);
				*msg += strlen(*msg);
			}
			if(*msgsize)
			{	tor_snprintf(*msg,*msgsize,"\t%sInternet Explorer [inetcpl.cpl]\r\n\t%s\r\n",get_lang_str(LANG_IDENTITY_INTERFACE),get_lang_str(LANG_IDENTITY_IE_COOKIES_DELETED_1));
				*msgsize -= strlen(*msg);
				*msg += strlen(*msg);
			}
			return;
		}
		FreeLibrary(hModule);
		int freelib = 0;
		hModule = GetModuleHandle("wininet.dll");
		if(!hModule)
		{	hModule = LoadLibrary("wininet.dll");
			freelib++;
		}
		if(hModule)
		{	_FindFirstUrlCacheEntry FindFirstUrlCacheEntry = (_FindFirstUrlCacheEntry)GetProcAddress(hModule,"FindFirstUrlCacheEntryA");
			_FindNextUrlCacheEntry FindNextUrlCacheEntry = (_FindNextUrlCacheEntry)GetProcAddress(hModule,"FindNextUrlCacheEntryA");
			_FindCloseUrlCache FindCloseUrlCache = (_FindCloseUrlCache)GetProcAddress(hModule,"FindCloseUrlCache");
			_DeleteUrlCacheEntry DeleteUrlCacheEntry = (_DeleteUrlCacheEntry)GetProcAddress(hModule,"DeleteUrlCacheEntry");
			if(FindFirstUrlCacheEntry && DeleteUrlCacheEntry)
			{	LPINTERNET_CACHE_ENTRY_INFOA cacheInfo = tor_malloc(8192);
				DWORD infoSize = 8192;
				cacheInfo->dwStructSize = infoSize;
				HANDLE hFind = FindFirstUrlCacheEntry(NULL,cacheInfo,&infoSize);
				if(!hFind)
				{	cacheInfo = tor_realloc(cacheInfo,infoSize);
					cacheInfo->dwStructSize = infoSize;
					hFind = FindFirstUrlCacheEntry(NULL,cacheInfo,&infoSize);
				}
				if(hFind)
				{	while(1)
					{	if(cacheInfo->CacheEntryType & COOKIE_CACHE_ENTRY)
						{	DeleteUrlCacheEntry(cacheInfo->lpszSourceUrlName);
							numcookies++;
						}
						cacheInfo->dwStructSize = infoSize;
						if(!FindNextUrlCacheEntry(hFind,cacheInfo,&infoSize))
						{	if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
							{	cacheInfo = tor_realloc(cacheInfo,infoSize);
							}
							else break;
						}
					}
					FindCloseUrlCache(hFind);
				}
				tor_free(cacheInfo);
				if(numcookies)
				{	if(*msgsize)
					{	char *procname = tor_malloc(200);
						getProcessName(procname,199,pid);
						tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
						tor_free(procname);
						*msgsize -= strlen(*msg);
						*msg += strlen(*msg);
					}
					if(*msgsize)
					{	tor_snprintf(*msg,*msgsize,"\t%sInternet Explorer [wininet.dll]\r\n",get_lang_str(LANG_IDENTITY_INTERFACE));
						*msgsize -= strlen(*msg);
						*msg += strlen(*msg);
					}
					if(*msgsize && numcookies)
					{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_COOKIES_DELETED),numcookies);
						*msgsize -= strlen(*msg);
						*msg += strlen(*msg);
					}
				}
				if(freelib)	FreeLibrary(hModule);
				return;
			}
			if(freelib)	FreeLibrary(hModule);
		}
	}
	get_appdata();
	char *newpath = tor_malloc(1024),*tmp;
	smartlist_t *objdir;
	if(userprofile)
	{	tor_snprintf(newpath,1023,"%s\\Cookies\\*.*",userprofile);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Cookies\\%s",userprofile,fn);
				if(strcasecmp(fn,"index.dat"))
					numcookies += ForceDelete(newpath);
				else{	;}	//ForceDelete(newpath);     - crashes IE 6
			});
			free_smartlist(objdir);
		}
		tor_snprintf(newpath,1023,"%s\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\DOMStore\\*.*",userprofile);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\DOMStore\\%s",userprofile,fn);
				numdomcookies += ForceDelete(newpath);
			});
			free_smartlist(objdir);
		}
	}
	if(appdata)
	{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Windows\\Cookies\\*.*",appdata);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Windows\\Cookies\\%s",appdata,fn);
				if(strcasecmp(fn,"index.dat"))
					numcookies += ForceDelete(newpath);
				else{	;}	//ForceDelete(newpath);	- crashes IE 6
			});
			free_smartlist(objdir);
		}
	}
	if(localappdata)
	{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Internet Explorer\\DOMStore\\*.*",localappdata);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Microsoft\\Internet Explorer\\DOMStore\\%s",localappdata,fn);
				numdomcookies += ForceDelete(newpath);
			});
			free_smartlist(objdir);
		}
	}
	LPITEMIDLIST idl;
	IMalloc *m;
	int i;
	tmp = tor_malloc(1024);tmp[0] = 0;
	if(SHGetSpecialFolderLocation(NULL,CSIDL_COOKIES,&idl)==NOERROR)
	{	SHGetPathFromIDList(idl,tmp);
		SHGetMalloc(&m);
		if(m)
		{	m->lpVtbl->Free(m, idl);
			m->lpVtbl->Release(m);
		}
	}
	else if(GetTempPath(1023,tmp))
	{	i = 0;
		while(tmp[i])	i++;
		if(i && tmp[i-1]=='\\')	i--;
		tor_snprintf(tmp+i,1024,"\\Cookies");
	}
	if(tmp[0])
	{	i = 0;
		while(tmp[i])	i++;
		if(i && tmp[i-1]=='\\')	i--;
		tmp[i] = 0;
		tor_snprintf(newpath,1023,"%s\\*.*",tmp);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\%s",tmp,fn);
				if(strcasecmp(fn,"index.dat"))
					numcookies += ForceDelete(newpath);
				else{	;}//ForceDelete(newpath);
			});
			free_smartlist(objdir);
		}
	}
	tor_free(tmp);

	if(numcookies || numdomcookies)
	{	if(*msgsize)
		{	char *procname = tor_malloc(200);
			getProcessName(procname,199,pid);
			tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
			tor_free(procname);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize)
		{	tor_snprintf(*msg,*msgsize,"\t%sInternet Explorer\r\n",get_lang_str(LANG_IDENTITY_INTERFACE));
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_COOKIES_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numdomcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_DOM_COOKIES_DELETED),numdomcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
	}
	tor_free(newpath);
}

int count_opera_cookies(const char *fname)
{	HANDLE hFile = open_file(fname,GENERIC_READ,OPEN_EXISTING);
	int i,k=0,l;
	DWORD j;
	char *tmpfile;
	if(hFile)
	{	j = GetFileSize(hFile,NULL);
		tmpfile = NULL;
		if(j != 0xffffffff)
		{	tmpfile = tor_malloc(j+1);
			ReadFile(hFile,tmpfile,j,&j,NULL);
			for(i=0;i<(int)j-4;i++)
			{	if(tmpfile[i]==0x10 && tmpfile[i+1]==0)
				{	l = tmpfile[i+2] & 0xff;
					if(i+l+4 < (int)j && tmpfile[i+3+l]==0x11 && tmpfile[i+4+l]==0)	k++;
				}
			}
			tor_free(tmpfile);
		}
		CloseHandle(hFile);
	}
	return k;
}

void delete_opera_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path)
{	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	DWORD i = 0,portable=0,j;
	if(hProcess)
	{	BYTE *modbase;
		DWORD modsize = 0,bytesread;
		unsigned char *dlldata;
		GetModuleBaseEx(pid,"opera.dll",&modbase,&modsize);
		if(modsize)
		{	dlldata =  tor_malloc(102410);
			while(modsize)
			{	bytesread = 0;
				ReadProcessMemory(hProcess,modbase,dlldata,(modsize>=102400)?102400:modsize,&bytesread);
				if(bytesread > 16)
				{	for(i=0;i<bytesread-16;i++)
					{	if(dlldata[i]==0xc2 && dlldata[i+1]==0x04 && dlldata[i+2]==0x00 && ((dlldata[i+3]==0x51 && dlldata[i+4]==0xe8 && dlldata[i+9]==0x6a && dlldata[i+10]==0x0f && dlldata[i+11]==0xe8 && dlldata[i+16]==0x59 && dlldata[i+17]==0xc3) || (dlldata[i+3]==0xe8 && dlldata[i+8]==0x6a && dlldata[i+9]==0x0f && dlldata[i+10]==0xe8)))
						{	if(dlldata[i+10]==0xe8)
							{	bytesread = *(DWORD *)(&dlldata[i+11]);
								modbase += i + 11 + 4 + bytesread;
							}
							else
							{	bytesread = *(DWORD *)(&dlldata[i+12]);
								modbase += i + 12 + 4 + bytesread;
							}
							HANDLE hThread=NULL;
							if(CreateThreadEx)	hThread = CreateThreadEx(hProcess,(LPTHREAD_START_ROUTINE)modbase,(LPARAM)0x4005);	//65f7
							if(!hThread)		hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)modbase,(LPVOID)0x4005,0,&modsize);
							if(hThread)
							{	WaitForSingleObject(hThread,1000);
								CloseHandle(hThread);
								if(*msgsize)
								{	char *procname = tor_malloc(200);
									getProcessName(procname,199,pid);
									tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
									tor_free(procname);
									*msgsize -= strlen(*msg);
									*msg += strlen(*msg);
								}
								if(*msgsize)
								{	tor_snprintf(*msg,*msgsize,"\t%sOpera [opera.dll]\r\n\t%s\r\n",get_lang_str(LANG_IDENTITY_INTERFACE),get_lang_str(LANG_IDENTITY_OPERA_COOKIES_DELETED_1));
									*msgsize -= strlen(*msg);
									*msg += strlen(*msg);
								}
								tor_free(dlldata);
								CloseHandle(hProcess);
								return;
							}
							GetLastError();
							modsize = 0;
							break;
						}
						else if((*(uint32_t *)(&dlldata[i])==0x36ff016a) && dlldata[i+4]==0xe8 && dlldata[i+9]==0x50 && dlldata[i+10]==0xe8 && (dlldata[i+20]==0xc9||dlldata[i+18]==0xc9) && RelinkStoredProc)
						{	BYTE *param1 = modbase + i + 5 + 4 + *(DWORD *)(&dlldata[i+5]);
							BYTE *param2 = modbase + i + 11 + 4 + *(DWORD *)(&dlldata[i+11]);
							DWORD result = 0;
							HANDLE hThread=NULL;
							RelinkStoredProc(pid,STORED_PROC_OPERA,(char *)dlldata,(uint32_t)param1,(uint32_t)param2);
							LPVOID lpBuffer = VirtualAllocEx(hProcess,NULL,2048,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
							if(lpBuffer)
							{	WriteProcessMemory(hProcess,lpBuffer,dlldata,2048,&result);
								if(CreateThreadEx)	hThread = CreateThreadEx(hProcess,(LPTHREAD_START_ROUTINE)lpBuffer,(LPARAM)0);
								if(!hThread)		hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)lpBuffer,(LPVOID)0,0,&result);
								if(hThread)
								{	WaitForSingleObject(hThread,10000);
									GetExitCodeThread(hThread,&result);
									CloseHandle(hThread);
									if(result)
									{	if(*msgsize)
										{	char *procname = tor_malloc(200);
											getProcessName(procname,199,pid);
											tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
											tor_free(procname);
											*msgsize -= strlen(*msg);
											*msg += strlen(*msg);
										}
										if(*msgsize)
										{	tor_snprintf(*msg,*msgsize,"\t%sOpera [opera.dll]\r\n\t%s\r\n",get_lang_str(LANG_IDENTITY_INTERFACE),get_lang_str(LANG_IDENTITY_OPERA_COOKIES_DELETED_1));
											*msgsize -= strlen(*msg);
											*msg += strlen(*msg);
										}
										tor_free(dlldata);
										VirtualFreeEx(hProcess,lpBuffer,2048,MEM_RELEASE);
										CloseHandle(hProcess);
										return;
									}
								}
								VirtualFreeEx(hProcess,lpBuffer,2048,MEM_RELEASE);
							}
							break;
						}
					}
				}
				if(bytesread && modsize >= bytesread)
				{	if(bytesread<=30)
					{	modbase++;
						modsize--;
					}
					else
					{	modbase += bytesread;//-30;
						modsize -= bytesread;//-30;
					}
				}
				else break;
			}
			tor_free(dlldata);
		}
		CloseHandle(hProcess);
	}

	get_appdata();
	i = 0;
	char *newpath = tor_malloc(1024),*tmp;
	smartlist_t *objdir;
	int numcookies = 0,numdomcookies = 0;
	tor_snprintf(newpath,1023,"%s",path);
	while(newpath[i])	i++;
	while(i && newpath[i-1]!='\\')	i--;
	tor_snprintf(newpath+i,1023-i,"operaprefs_default.ini");
	tmp = read_file_to_str(newpath,RFTS_BIN,NULL);
	j = 0;
	while(tmp[j])
	{	if(tmp[j]==13 || tmp[j]==10)
		{	if(!strcasecmpstart(tmp+j+1,"multi user"))
			{	while(tmp[j] && tmp[j]!='=')	j++;
				while(tmp[j]=='=' || tmp[j]==32) j++;
				if(tmp[j]=='0')	portable = 1;
				break;
			}
		}
		j++;
	}
	tor_free(tmp);

	tor_snprintf(newpath+i,1023-i,"profile\\cookies4.dat");
	if(file_exists(newpath))
	{	j = count_opera_cookies(newpath);
		if(ForceDelete(newpath))	numcookies += j;
	}

	tor_snprintf(newpath+i,1023-i,"profile\\icons\\cache\\cookies4.dat");
	if(file_exists(newpath))
	{	j = count_opera_cookies(newpath);
		if(ForceDelete(newpath))	numcookies += j;
	}

	tor_snprintf(newpath+i,1023-i,"pstorage");
	if(file_exists(newpath))
	{	j = ForceDeleteSubdir(newpath);
		if(j)	numdomcookies += j-1;
	}

	tor_snprintf(newpath+i,1023-i,"profile\\pstorage");
	if(file_exists(newpath))
	{	j = ForceDeleteSubdir(newpath);
		if(j)	numdomcookies += j-1;
	}

	if(!portable)
	{	if(appdata)
		{	tor_snprintf(newpath,1023,"%s\\Opera\\*.*",appdata);
			objdir = listdir(newpath);
			if(objdir)
			{	SMARTLIST_FOREACH(objdir,char *,fn,
				{	tor_snprintf(newpath,1023,"%s\\Opera\\%s\\cookies4.dat",appdata,fn);
					if(file_exists(newpath))
					{	j = count_opera_cookies(newpath);
						if(ForceDelete(newpath))	numcookies += j;
					}
					tor_snprintf(newpath,1023,"%s\\Opera\\%s\\profile\\cookies4.dat",appdata,fn);
					if(file_exists(newpath))
					{	j = count_opera_cookies(newpath);
						if(ForceDelete(newpath))	numcookies += j;
					}
					tor_snprintf(newpath,1023,"%s\\Opera\\%s\\pstorage",appdata,fn);
					if(file_exists(newpath))
					{	j = ForceDeleteSubdir(newpath);
						if(j)	numdomcookies += j-1;
					}
				});
				free_smartlist(objdir);
			}
		}
		if(localappdata)
		{	tor_snprintf(newpath,1023,"%s\\Opera\\*.*",localappdata);
			objdir = listdir(newpath);
			if(objdir)
			{	SMARTLIST_FOREACH(objdir,char *,fn,
				{	tor_snprintf(newpath,1023,"%s\\Opera\\%s\\icons\\cache\\cookies4.dat",localappdata,fn);
					if(file_exists(newpath))
					{	j = count_opera_cookies(newpath);
						if(ForceDelete(newpath))	numcookies += j;
					}
				});
				free_smartlist(objdir);
			}
		}
	}

	if(numcookies || numdomcookies)
	{	if(*msgsize)
		{	char *procname = tor_malloc(200);
			getProcessName(procname,199,pid);
			tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
			tor_free(procname);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize)
		{	if(portable)	tor_snprintf(*msg,*msgsize,"\t%sOpera [Portable]\r\n",get_lang_str(LANG_IDENTITY_INTERFACE));
			else		tor_snprintf(*msg,*msgsize,"\t%sOpera [Multi User]\r\n",get_lang_str(LANG_IDENTITY_INTERFACE));
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_COOKIES_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numdomcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_DOM_COOKIES_DELETED),numdomcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
	}
	tor_free(newpath);
}

void delete_firefox_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path)
{	(void) path;
	get_appdata();
	char *newpath = tor_malloc(1024);
	smartlist_t *objdir;
	int numcookies = 0;
	if(appdata)
	{	tor_snprintf(newpath,1023,"%s\\Mozilla\\Firefox\\Profiles\\*.*",appdata);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Mozilla\\Firefox\\Profiles\\%s\\cookies.sqlite",appdata,fn);
				if(file_exists(newpath))
				{	if(ForceDelete(newpath))	numcookies ++;
				}
				tor_snprintf(newpath,1023,"%s\\Mozilla\\Firefox\\Profiles\\%s\\sessionstore.js",appdata,fn);
				if(file_exists(newpath))	ForceDelete(newpath);
			});
			free_smartlist(objdir);
		}
	}
	if(numcookies)
	{	if(*msgsize)
		{	char *procname = tor_malloc(200);
			getProcessName(procname,199,pid);
			tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n\t%sFirefox\r\n",procname,module,(unsigned int)pid,get_lang_str(LANG_IDENTITY_INTERFACE));
			tor_free(procname);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i.\r\n",get_lang_str(LANG_IDENTITY_COOKIE_DBS_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
	}
	tor_free(newpath);
}


void delete_chrome_cookies(DWORD pid,const char *module,char **msg,int *msgsize,const char *path)
{	(void) path;
	int i = 0;
/*	if(RelinkStoredProc)
	{	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
		if(hProcess)
		{	BYTE *modbase,*modbasetmp;
			DWORD modsize = 0,bytesread;
			DWORD modsizetmp;
			unsigned char *dlldata;
			GetModuleBaseEx(pid,"chrome.dll",&modbase,&modsize);
			if(modsize)
			{	dlldata =  tor_malloc(102410);
				uint32_t strbase = 0;
				modsizetmp = modsize;
				modbasetmp = modbase;
				while(modsizetmp)
				{	bytesread = 0;
					ReadProcessMemory(hProcess,modbasetmp,dlldata,(modsizetmp>=102400)?102400:modsizetmp,&bytesread);
					if(bytesread > 25)
					{	for(i=0;i<bytesread-25;i++)
						{	if(!strcmp(dlldata+i,"ClearBrowsingData_Cookies"))
							{	strbase = (uint32_t)(modbasetmp+i);
								break;
							}
						}
						if(strbase)	break;
					}
					if(bytesread && modsizetmp >= bytesread)
					{	if(bytesread<=30)
						{	modbasetmp++;
							modsizetmp--;
						}
						else
						{	modbasetmp += bytesread;//-30;
							modsizetmp -= bytesread;//-30;
						}
					}
					else break;
				}
				if(strbase)
				{	modsizetmp = modsize;
					modbasetmp = modbase;
					BYTE *lastproc = NULL,*bestproc=NULL;
					while(modsizetmp)
					{	bytesread = 0;
						ReadProcessMemory(hProcess,modbasetmp,dlldata,(modsizetmp>=102400)?102400:modsizetmp,&bytesread);
						if(bytesread > 16)
						{	for(i=0;i<bytesread-16;i++)
							{	if(*(uint32_t *)(&dlldata[i])==strbase)
								{	bestproc = lastproc;
									break;
								}
								else if((dlldata[i]==0x55 && dlldata[i+1]==0x8b && dlldata[i+2]==0xec) || (dlldata[i]==0x81 && dlldata[i+1]==0xec && i>2 && dlldata[i-1]==0xcc))
									lastproc = modbasetmp+i;
							}
							if(bestproc)	break;
						}
						if(bytesread && modsizetmp >= bytesread)
						{	if(bytesread<=30)
							{	modbasetmp++;
								modsizetmp--;
							}
							else
							{	modbasetmp += bytesread;//-30;
								modsizetmp -= bytesread;//-30;
							}
						}
						else break;
					}
					if(bestproc)
					{	DWORD result = 0;
						HANDLE hThread=NULL;
						RelinkStoredProc(pid,STORED_PROC_CHROME,dlldata,(uint32_t)bestproc,0);
						LPVOID lpBuffer = VirtualAllocEx(hProcess,NULL,2048,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
						if(lpBuffer)
						{	WriteProcessMemory(hProcess,lpBuffer,dlldata,2048,&result);
							if(CreateThreadEx)	hThread = CreateThreadEx(hProcess,(LPTHREAD_START_ROUTINE)lpBuffer,(LPARAM)0);
							if(!hThread)		hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)lpBuffer,(LPVOID)0,0,&result);
							if(hThread)
							{	WaitForSingleObject(hThread,10000);
								GetExitCodeThread(hThread,&result);
								CloseHandle(hThread);
								if(!result)
								{	if(*msgsize)
									{	char *procname = tor_malloc(200);
										getProcessName(procname,199,pid);
										tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
										tor_free(procname);
										*msgsize -= strlen(*msg);
										*msg += strlen(*msg);
									}
									if(*msgsize)
									{	tor_snprintf(*msg,*msgsize,"\tInterface: Chrome [chrome.dll]\r\n\tBrowsingDataRemover->Remove(REMOVE_COOKIES | REMOVE_LSO_DATA): cookies deleted.\r\n");
										*msgsize -= strlen(*msg);
										*msg += strlen(*msg);
									}
									tor_free(dlldata);
									VirtualFreeEx(hProcess,lpBuffer,2048,MEM_RELEASE);
									CloseHandle(hProcess);
									return;
								}
							}
							VirtualFreeEx(hProcess,lpBuffer,2048,MEM_RELEASE);
						}
					}
				}
				tor_free(dlldata);
			}
			CloseHandle(hProcess);
		}
	}*/
	get_appdata();
	char *newpath = tor_malloc(1024);
	smartlist_t *objdir;
	int numcookies = 0,numdomcookies = 0;
	if(localappdata)
	{	tor_snprintf(newpath,1023,"%s\\Google\\Chrome\\User Data\\Default\\Cookies",localappdata);
		if(file_exists(newpath) && ForceDelete(newpath))	numcookies ++;
		tor_snprintf(newpath,1023,"%s\\Google\\Chrome\\User Data\\Default\\Extension Cookies",localappdata);
		if(file_exists(newpath) && ForceDelete(newpath))	numcookies ++;
		tor_snprintf(newpath,1023,"%s\\Google\\Chrome\\User Data\\Default\\Local Storage\\*.*",localappdata);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	if(!strcasecmpstart(fn,"http"))
				{	i = strlen(fn);
					if(i > 12 && !strcasecmp(fn+i-12,"localstorage"))
					{	tor_snprintf(newpath,1023,"%s\\Google\\Chrome\\User Data\\Default\\Local Storage\\%s",localappdata,fn);
						numdomcookies += ForceDeleteSubdir(newpath);
					}
				}
			});
			free_smartlist(objdir);
		}
	}
	if(numcookies || numdomcookies)
	{	if(*msgsize)
		{	char *procname = tor_malloc(200);
			getProcessName(procname,199,pid);
			tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n\t%sChrome\r\n",procname,module,(unsigned int)pid,get_lang_str(LANG_IDENTITY_INTERFACE));
			tor_free(procname);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i.\r\n",get_lang_str(LANG_IDENTITY_COOKIE_DBS_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numdomcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_DOM_COOKIES_DELETED),numdomcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
	}
	tor_free(newpath);
}

void delete_safari_cookies(DWORD pid,const char *module,char **msg,int *msgsize,char *path)
{	HINSTANCE hLibrary = load_library_ex(path);
	if(hLibrary)
	{	LPFN1 CFHTTPCookieStorageDeleteAllCookies=NULL;
		LPFN1 _CFHTTPCookieStorageGetDefault=NULL;
		if((CFHTTPCookieStorageDeleteAllCookies=(LPFN1)GetProcAddress(hLibrary,"CFHTTPCookieStorageDeleteAllCookies"))!=0 && (_CFHTTPCookieStorageGetDefault=(LPFN1)GetProcAddress(hLibrary,"_CFHTTPCookieStorageGetDefault"))!=0)
		{	BYTE *libptr;
			DWORD modsize = 0;
			GetModuleBaseEx(GetCurrentProcessId(),module,&libptr,&modsize);
			FreeLibrary(hLibrary);
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
			if(hProcess)
			{	BYTE *modbase;
				GetModuleBaseEx(pid,module,&modbase,&modsize);
				if(modsize)
				{	CFHTTPCookieStorageDeleteAllCookies = (LPFN1)(modbase - (uint32_t)libptr + (uint32_t)CFHTTPCookieStorageDeleteAllCookies);
					_CFHTTPCookieStorageGetDefault = (LPFN1)(modbase - (uint32_t)libptr + (uint32_t)_CFHTTPCookieStorageGetDefault);
					HANDLE hThread=NULL;
					if(CreateThreadEx)	hThread = CreateThreadEx(hProcess,(LPTHREAD_START_ROUTINE)_CFHTTPCookieStorageGetDefault,(LPARAM)0);
					if(!hThread)		hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)_CFHTTPCookieStorageGetDefault,(LPVOID)0,0,&modsize);
					if(hThread)
					{	WaitForSingleObject(hThread,1000);
						GetExitCodeThread(hThread,&modsize);
						CloseHandle(hThread);
						if(CreateThreadEx)	hThread = CreateThreadEx(hProcess,(LPTHREAD_START_ROUTINE)CFHTTPCookieStorageDeleteAllCookies,(LPARAM)modsize);
						if(!hThread)		hThread = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)CFHTTPCookieStorageDeleteAllCookies,(LPVOID)modsize,0,&modsize);
						if(hThread)
						{	WaitForSingleObject(hThread,1000);
							CloseHandle(hThread);
						}
						if(*msgsize)
						{	char *procname = tor_malloc(200);
							getProcessName(procname,199,pid);
							tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
							tor_free(procname);
							*msgsize -= strlen(*msg);
							*msg += strlen(*msg);
						}
						if(*msgsize)
						{	tor_snprintf(*msg,*msgsize,"\t%sSafari [CFNetwork.dll]\r\n\t%s\r\n",get_lang_str(LANG_IDENTITY_INTERFACE),get_lang_str(LANG_IDENTITY_SAFARI_COOKIES_DELETED_1));
							*msgsize -= strlen(*msg);
							*msg += strlen(*msg);
						}
						CloseHandle(hProcess);
						return;
					}
					CloseHandle(hProcess);
				}
			}
			hLibrary = load_library(path);
			if(hLibrary)
			{	if((CFHTTPCookieStorageDeleteAllCookies=(LPFN1)GetProcAddress(hLibrary,"CFHTTPCookieStorageDeleteAllCookies"))!=0 && (_CFHTTPCookieStorageGetDefault=(LPFN1)GetProcAddress(hLibrary,"_CFHTTPCookieStorageGetDefault"))!=0)
				{	CFHTTPCookieStorageDeleteAllCookies(_CFHTTPCookieStorageGetDefault(0));
					if(*msgsize)
					{	char *procname = tor_malloc(200);
						getProcessName(procname,199,pid);
						tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n",procname,module,(unsigned int)pid);
						tor_free(procname);
						*msgsize -= strlen(*msg);
						*msg += strlen(*msg);
					}
					if(*msgsize)
					{	tor_snprintf(*msg,*msgsize,"\t%sSafari [CFNetwork.dll]\r\n\t%s\r\n",get_lang_str(LANG_IDENTITY_INTERFACE),get_lang_str(LANG_IDENTITY_SAFARI_COOKIES_DELETED_1));
						*msgsize -= strlen(*msg);
						*msg += strlen(*msg);
					}
					FreeLibrary(hLibrary);
					return;
				}
				FreeLibrary(hLibrary);
			}
		}
	}

	get_appdata();
	char *newpath = tor_malloc(1024);
	smartlist_t *objdir;
	int numcookies = 0,numdomcookies = 0;
	if(appdata)
	{	tor_snprintf(newpath,1023,"%s\\Apple Computer\\Safari\\Cookies\\Cookies.plist",appdata);
		if(file_exists(newpath) && ForceDelete(newpath))	numcookies ++;
	}
	if(localappdata)
	{	tor_snprintf(newpath,1023,"%s\\Apple Computer\\Safari\\LocalStorage\\*.*",localappdata);
		objdir = listdir(newpath);
		if(objdir)
		{	SMARTLIST_FOREACH(objdir,char *,fn,
			{	tor_snprintf(newpath,1023,"%s\\Apple Computer\\Safari\\LocalStorage\\%s",localappdata,fn);
				numdomcookies += ForceDeleteSubdir(newpath);
			});
			free_smartlist(objdir);
		}
	}
	if(numcookies || numdomcookies)
	{	if(*msgsize)
		{	char *procname = tor_malloc(200);
			getProcessName(procname,199,pid);
			tor_snprintf(*msg,*msgsize,"%s : %s [PID: %u]\r\n\t%sSafari\r\n",procname,module,(unsigned int)pid,get_lang_str(LANG_IDENTITY_INTERFACE));
			tor_free(procname);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i.\r\n",get_lang_str(LANG_IDENTITY_COOKIE_DBS_DELETED),numcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
		if(*msgsize && numdomcookies)
		{	tor_snprintf(*msg,*msgsize,"\t%s%i\r\n",get_lang_str(LANG_IDENTITY_DOM_COOKIES_DELETED),numdomcookies);
			*msgsize -= strlen(*msg);
			*msg += strlen(*msg);
		}
	}
	tor_free(newpath);
}

#define COOKIES_IE 1
#define COOKIES_OPERA 2
#define COOKIES_FIREFOX 3
#define COOKIES_CHROME 4
#define COOKIES_SAFARI 5
void delete_cookies(char **msg,int *msgsize)
{	int i,j,k;
	smartlist_t *modules;
	int cdeleted = 0;
	for(i=0;i<pid_index;i++)
	{	modules = list_modules(pid_list[i]);
		if(modules)
		{	SMARTLIST_FOREACH(modules,char *,fn,
			{	k = 0;
				for(j=0;fn[j];j++)
				{	if(fn[j]=='\\')	k = j + 1;
				}
				if(!strcasecmpstart(fn+k,"wininet.dll") && ((cdeleted & COOKIES_IE) == 0))
				{	delete_ie_cookies(pid_list[i],"wininet.dll",msg,msgsize);
					cdeleted |= COOKIES_IE;
				}
				else if(!strcasecmpstart(fn+k,"opera.dll"))
				{	delete_opera_cookies(pid_list[i],"opera.dll",msg,msgsize,fn);
					cdeleted |= COOKIES_OPERA;
				}
				else if(!strcasecmpstart(fn+k,"chrome.dll"))
				{	delete_chrome_cookies(pid_list[i],"chrome.dll",msg,msgsize,fn);
					cdeleted |= COOKIES_CHROME;
				}
				else if(!strcasecmpstart(fn+k,"xul.dll"))
				{	delete_firefox_cookies(pid_list[i],"xul.dll",msg,msgsize,fn);
					cdeleted |= COOKIES_FIREFOX;
				}
				else if(!strcasecmpstart(fn+k,"cfnetwork.dll"))
				{	delete_safari_cookies(pid_list[i],"CFNetwork.dll",msg,msgsize,fn);
					cdeleted |= COOKIES_SAFARI;
				}
			});
			free_smartlist(modules);
		}
	}
}
