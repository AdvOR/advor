#include "or.h"
#include "main.h"
#include "config.h"

int encryption = 0;	// bit 0 = cache all configuration files in RAM (read-only mode)
			// bit 1 = encrypt configuration files using AES (not implemented yet)
file_info_t *first_file = NULL;
char *password = NULL;
DWORD password_size = 0;
extern HINSTANCE hInstance;
extern HWND hMainDialog;

int __stdcall dlgGetPassword(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
void unload_file(file_info_t *file);
time_t convert_file_time(FILETIME *ft);
file_info_t *load_file(char *fname);
file_info_t *add_new_file(file_info_t *filelist,const char *getname);
file_info_t *add_new_filename(file_info_t *filelist,char *fname);
void delete_config_file(const char *fname);
void delete_config_filename(char *path);
file_info_t *find_file(const char *fname);
file_info_t *get_file(const char *fname);
char *get_file_name(char *fname);
int ftime_definitely_after(time_t now, time_t when);
int ftime_definitely_before(time_t now, time_t when);
void show_last_error(int err_id,const char *fname);
void init_nt_functions(void);
void init_kernel_functions(void);
DWORD WINAPI closeHandles(LPVOID lParam) __attribute__((noreturn));
int close_all_handles(char *fname);
int CaNtDeleteFile(char *fname);


void alloc_password(void)
{	if(password)	return;
	password = VirtualAlloc(NULL,MAX_PASSWORD_SIZE,MEM_COMMIT,PAGE_READWRITE|PAGE_NOCACHE);
	if(!password)	password = VirtualAlloc(NULL,MAX_PASSWORD_SIZE,MEM_COMMIT,PAGE_READWRITE);
	password_size = 0;
}

void free_password(void)
{	if(password)
	{	memset(password,0,MAX_PASSWORD_SIZE);
		VirtualFree(password,0,MEM_RELEASE);
	}
	password = NULL;
}

void set_read_only(void)
{	encryption |= 1;
}

int is_read_only(void)
{	return encryption&1;
}

HANDLE open_file(const char *fname,DWORD access,DWORD creationDistribution)
{	int i=strlen(fname)+1;
	HANDLE hFile;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	hFile = CreateFileW(tmp,access,FILE_SHARE_READ,0,creationDistribution,0,NULL);
	tor_free(tmp);
	return hFile;
}

HINSTANCE get_module_handle(char *fname)
{	int i=strlen(fname)+1;
	HINSTANCE hFile;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	hFile = GetModuleHandleW(tmp);
	tor_free(tmp);
	return hFile;
}

HINSTANCE load_library(const char *fname)
{	int i=strlen(fname)+1;
	HINSTANCE hFile;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	hFile = LoadLibraryW(tmp);
	tor_free(tmp);
	return hFile;
}

HINSTANCE load_library_ex(const char *fname)
{	int i=strlen(fname)+1;
	HINSTANCE hFile;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	hFile = LoadLibraryExW(tmp,0,DONT_RESOLVE_DLL_REFERENCES);
	tor_free(tmp);
	return hFile;
}

DWORD get_file_attributes(char *fname)
{	int i=strlen(fname);
	DWORD attrs;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	attrs = GetFileAttributesW(tmp);
	tor_free(tmp);
	return attrs;
}

int file_exists(char *fname)
{	if(get_file_attributes(fname) == 0xffffffff)	return 0;
	return 1;
}


HANDLE find_first_file(char *pattern,LPWIN32_FIND_DATAW findData)
{	int i=strlen(pattern)+1;
	HANDLE hFind;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)pattern,-1,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	hFind = FindFirstFileW(tmp,findData);
	tor_free(tmp);
	return hFind;
}

void unload_file(file_info_t *file)
{	if(file->filename)	tor_free(file->filename);
	if(file->filedata)	tor_free(file->filedata);
	tor_free(file);
}

void unload_all_files(void)
{	file_info_t *next_file;
	flush_configuration_data();
	while(first_file)
	{	next_file = first_file->next;
		unload_file(first_file);
		first_file = next_file;
	}
	free_password();
}

#ifndef EPOCH_BIAS
#define EPOCH_BIAS 11644473600ULL
#endif
#ifndef EPOCH_RATE
#define EPOCH_RATE 10000000ULL
#endif

time_t convert_file_time(FILETIME *ft)
{	ULARGE_INTEGER ull;
	ull.LowPart = ft->dwLowDateTime;
	ull.HighPart = ft->dwHighDateTime;
	return (ull.QuadPart - EPOCH_BIAS)/EPOCH_RATE;
}

file_info_t *load_file(char *fname)
{	char *fdata;
	HANDLE hFile;
	uint32_t fsize;
	FILETIME ft;
	hFile = open_file(fname,GENERIC_READ,OPEN_EXISTING);
	if(hFile==INVALID_HANDLE_VALUE)	return NULL;
	fsize = GetFileSize(hFile,NULL);
	if(fsize+1 >= SIZE_T_CEILING)
	{	CloseHandle(hFile);
		return NULL;
	}
	fdata = tor_malloc(fsize+1);
	DWORD numread = 0;
	ReadFile(hFile,fdata,fsize,&numread,NULL);
	file_info_t *finfo = tor_malloc_zero(sizeof(file_info_t));
	GetFileTime(hFile,NULL,NULL,&ft);
	CloseHandle(hFile);
	finfo->filetime = convert_file_time(&ft);
	finfo->filedata = fdata;
	finfo->filesize = finfo->allocsize = fsize;
	fdata = fname;
	while(*fdata)
	{	if(fdata[0]=='\\' && fdata[1]!=0)	fname=fdata+1;
		fdata++;
	}
	finfo->filename = tor_strdup(fname);
	return finfo;
}

file_info_t *add_new_file(file_info_t *filelist,const char *getname)
{	file_info_t *loadedfile;
	char *fname = get_datadir_fname(getname);
	loadedfile = load_file(fname);
	if(filelist)	filelist->next = loadedfile;
	else	first_file = loadedfile;
	if(!loadedfile)	loadedfile = filelist;
	tor_free(fname);
	return loadedfile;
}

file_info_t *add_new_filename(file_info_t *filelist,char *fname)
{	file_info_t *loadedfile;
	loadedfile = load_file(fname);
	if(filelist)	filelist->next = loadedfile;
	else	first_file = filelist = loadedfile;
	if(!loadedfile)	loadedfile = filelist;
	return loadedfile;
}

void load_all_files(void)
{	file_info_t *new_file = NULL;
	if(first_file)	return;
	char *fname,*fname1;
	int i,j,k;
	char wcards[10];
	new_file = add_new_file(NULL,DATADIR_UNVERIFIED_CONSENSUS);
	new_file = add_new_file(new_file,DATADIR_CACHED_CONSENSUS);
	new_file = add_new_file(new_file,DATADIR_CACHED_CERTS);
	new_file = add_new_file(new_file,DATADIR_CACHED_DESCRIPTORS);
	new_file = add_new_file(new_file,DATADIR_CACHED_DESCRIPTORS_NEW);
	new_file = add_new_file(new_file,DATADIR_CACHED_ROUTERS);
	new_file = add_new_file(new_file,DATADIR_CACHED_EXTRAINFO);
	new_file = add_new_file(new_file,DATADIR_CONTROL_AUTH_COOKIE);
	new_file = add_new_file(new_file,DATADIR_APPROVED_ROUTERS);
	new_file = add_new_file(new_file,DATADIR_CACHED_CERTS);
	new_file = add_new_file(new_file,DATADIR_V3_STATUS_VOTES);
	new_file = add_new_file(new_file,DATADIR_NETWORKSTATUS_BRIDGES);
	new_file = add_new_file(new_file,DATADIR_KEYS_SECRET_ONION_KEY);
	new_file = add_new_file(new_file,DATADIR_KEYS_SECRET_ONION_KEY_OLD);
	new_file = add_new_file(new_file,DATADIR_KEYS_LEGACY_SIGNING_KEY);
	new_file = add_new_file(new_file,DATADIR_KEYS_AUTHORITY_SIGNING_KEY);
	new_file = add_new_file(new_file,DATADIR_KEYS_LEGACY_CERTIFICATE);
	new_file = add_new_file(new_file,DATADIR_KEYS_AUTHORITY_CERTIFICATE);
	new_file = add_new_file(new_file,DATADIR_KEYS_SECRET_ID_KEY);
	new_file = add_new_file(new_file,DATADIR_FINGERPRINT);
	new_file = add_new_file(new_file,DATADIR_GEOIP_STATS);
	new_file = add_new_file(new_file,DATADIR_ROUTER_STABILITY);
	new_file = add_new_file(new_file,DATADIR_HSUSAGE);
	new_file = add_new_filename(new_file,get_default_conf_file());

	fname = get_datadir_fname(DATADIR_CACHED_STATUS);
	smartlist_t *entries;
	entries = tor_listdir(fname);
	tor_free(fname);
	if(entries)
	{	SMARTLIST_FOREACH(entries,char *,fn,
		{	new_file = add_new_filename(new_file,fn);
		});
		SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
		smartlist_free(entries);
	}

	fname=tor_malloc(1024);
	tor_snprintf(fname,1023,"%s--*.*",fullpath);
	entries = tor_listdir(fname);
	if(entries)
	{	SMARTLIST_FOREACH(entries,char *,fn,
		{	new_file = add_new_filename(new_file,fn);
		});
		SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
		smartlist_free(entries);
	}

	fname1 = tor_malloc(1024);
	for(i=0;i<5;i++)
	{	wcards[i]='?';wcards[i+1]=0;
		tor_snprintf(fname,1023,"%s-%s-private_key",fullpath,wcards);
		entries = tor_listdir(fname);
		if(entries)
		{	SMARTLIST_FOREACH(entries, const char *, fn,
			{	if(fn)
				{	for(j=strlen(fn)-1;j>0;j--)
					{	if(fn[j]<='9' && fn[j]>='0')	break;
					}
					while(j>0 && (fn[j]<='9' && fn[j]>='0'))	j--;
					if(!(fn[j]<='9' && fn[j]>='0'))	j++;
					k=0;
					while(fn[j]<='9' && fn[j]>='0')	fname[k++]=fn[j++];
					fname[k] = 0;
					tor_snprintf(fname1,1023,"%s-%s-private_key",fullpath,fname);
					new_file = add_new_filename(new_file,fname1);
					tor_snprintf(fname1,1023,"%s-%s-hostname",fullpath,fname);
					new_file = add_new_filename(new_file,fname1);
					tor_snprintf(fname1,1023,"%s-%s-client_keys",fullpath,fname);
					new_file = add_new_filename(new_file,fname1);
				}
			});
			SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
			smartlist_free(entries);
		}
	}
	tor_free(fname);
	tor_free(fname1);
}

void delete_config_file(const char *fname)
{	char *path = get_datadir_fname(fname);
	int i=strlen(path)+1;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)path,i,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	DeleteFileW(tmp);
	tor_free(path);
	tor_free(tmp);
}

void delete_config_filename(char *path)
{	int i=strlen(path)+1;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)path,i,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	DeleteFileW(tmp);
	tor_free(tmp);
}

void delete_dat_file(void)
{	char *fname = get_datadir_fname_suffix(NULL,".dat");
	delete_config_filename(fname);
	tor_free(fname);
}

void delete_all_files(void)
{	if((encryption&1) != 0)	return;
	char *fname,*fname1;
	int i,j,k;
	char wcards[10];
	delete_config_file(DATADIR_UNVERIFIED_CONSENSUS);
	delete_config_file(DATADIR_CACHED_CONSENSUS);
	delete_config_file(DATADIR_CACHED_CERTS);
	delete_config_file(DATADIR_CACHED_DESCRIPTORS);
	delete_config_file(DATADIR_CACHED_DESCRIPTORS_NEW);
	delete_config_file(DATADIR_CACHED_ROUTERS);
	delete_config_file(DATADIR_CACHED_EXTRAINFO);
	delete_config_file(DATADIR_CONTROL_AUTH_COOKIE);
	delete_config_file(DATADIR_APPROVED_ROUTERS);
	delete_config_file(DATADIR_CACHED_CERTS);
	delete_config_file(DATADIR_V3_STATUS_VOTES);
	delete_config_file(DATADIR_NETWORKSTATUS_BRIDGES);
	delete_config_file(DATADIR_KEYS_SECRET_ONION_KEY);
	delete_config_file(DATADIR_KEYS_SECRET_ONION_KEY_OLD);
	delete_config_file(DATADIR_KEYS_LEGACY_SIGNING_KEY);
	delete_config_file(DATADIR_KEYS_AUTHORITY_SIGNING_KEY);
	delete_config_file(DATADIR_KEYS_LEGACY_CERTIFICATE);
	delete_config_file(DATADIR_KEYS_AUTHORITY_CERTIFICATE);
	delete_config_file(DATADIR_KEYS_SECRET_ID_KEY);
	delete_config_file(DATADIR_FINGERPRINT);
	delete_config_file(DATADIR_GEOIP_STATS);
	delete_config_file(DATADIR_ROUTER_STABILITY);
	delete_config_file(DATADIR_HSUSAGE);
	delete_config_filename(get_default_conf_file());

	fname = get_datadir_fname(DATADIR_CACHED_STATUS);
	smartlist_t *entries;
	entries = tor_listdir(fname);
	tor_free(fname);
	if(entries)
	{	SMARTLIST_FOREACH(entries,char *,fn,
		{	delete_config_filename(fn);
		});
		SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
		smartlist_free(entries);
	}

	fname=tor_malloc(1024);
	tor_snprintf(fname,1023,"%s--*.*",fullpath);
	entries = tor_listdir(fname);
	if(entries)
	{	SMARTLIST_FOREACH(entries,char *,fn,
		{	delete_config_filename(fn);
		});
		SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
		smartlist_free(entries);
	}

	fname1 = tor_malloc(1024);
	for(i=0;i<5;i++)
	{	wcards[i]='?';wcards[i+1]=0;
		tor_snprintf(fname,1023,"%s-%s-private_key",fullpath,wcards);
		entries = tor_listdir(fname);
		if(entries)
		{	SMARTLIST_FOREACH(entries, const char *, fn,
			{	if(fn)
				{	for(j=strlen(fn)-1;j>0;j--)
					{	if(fn[j]<='9' && fn[j]>='0')	break;
					}
					while(j>0 && (fn[j]<='9' && fn[j]>='0'))	j--;
					if(!(fn[j]<='9' && fn[j]>='0'))	j++;
					k=0;
					while(fn[j]<='9' && fn[j]>='0')	fname[k++]=fn[j++];
					fname[k] = 0;
					tor_snprintf(fname1,1023,"%s-%s-private_key",fullpath,fname);
					delete_config_filename(fname1);
					tor_snprintf(fname1,1023,"%s-%s-hostname",fullpath,fname);
					delete_config_filename(fname1);
					tor_snprintf(fname1,1023,"%s-%s-client_keys",fullpath,fname);
					delete_config_filename(fname1);
				}
			});
			SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
			smartlist_free(entries);
		}
	}
	tor_free(fname);
	tor_free(fname1);
}

file_info_t *find_file(const char *fname)
{	file_info_t *result;
	const char *tmp;
	tmp = fname;
	while(*tmp)
	{	if(tmp[0]=='\\' && tmp[1]!=0)	fname=tmp+1;
		tmp++;
	}
	result = first_file;
	while(result)
	{	if(!strcasecmp(result->filename,fname))	break;
		result = result->next;
	}
	return result;
}

file_info_t *get_file(const char *fname)
{	file_info_t *file = find_file(fname);
	if(file)	return file;
	file = tor_malloc_zero(sizeof(file_info_t));
	file->filedata = tor_malloc(1024);
	file->allocsize = 1024;
	file->filesize = 0;
	file->filepos = 0;
	file->filetime = get_time(NULL);
	const char *fdata;
	fdata = fname;
	while(*fdata)
	{	if(fdata[0]=='\\' && fdata[1]!=0)	fname=fdata+1;
		fdata++;
	}
	file->filename = tor_strdup(fname);
	if(!first_file)	first_file = file;
	else
	{	file_info_t *file1;
		file1 = first_file;
		while(file1->next)
		{	file1 = file1->next;
		}
		file1->next = file;
	}
	return file;
}

extern char exename[MAX_PATH+1];
char *get_file_name(char *fname)
{	int i=0;
	while(fname[i])
	{	if(fname[i]=='\\')
		{	fname += i + 1;
			i = 0;
		}
		else	i++;
	}
	return fname + strlen(exename);
}

char bufzero[4] = "\0\0\0\0";
void flush_configuration_data(void)
{	HANDLE hFile;
	file_info_t *finfo;
	if((encryption & 2) == 0 || (encryption&1) != 0)	return;
	if(password)
	{	char *fname = get_datadir_fname_suffix(NULL,".new");
		#ifdef RANDOMIZE_ENCRYPTION
			char *random_garbage;
		#endif
		char *wbuf,*cbuf;
		crypto_cipher_env_t *env1;
		int i,j,k;
		uint32_t fsize;
		#ifdef RANDOMIZE_ENCRYPTION
			uint32_t ssize = crypto_rand_int(512)+256;
		#endif
		hFile=open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
		if(hFile != INVALID_HANDLE_VALUE)
		{	DWORD bytesWritten;
			#ifdef RANDOMIZE_ENCRYPTION
				random_garbage = tor_malloc(ssize);
				crypto_rand(random_garbage,ssize);
				WriteFile(hFile,&ssize,2,&bytesWritten,NULL);
				WriteFile(hFile,random_garbage,ssize,&bytesWritten,NULL);
			#endif
			finfo = first_file;
			env1 = crypto_new_cipher_env();
			crypto_cipher_set_key(env1,password);
			crypto_cipher_encrypt_init_cipher(env1);
			while(finfo)
			{	if(finfo->filesize)
				{	char *filename = get_file_name(finfo->filename);
					k = strlen(filename)+1;
					i = finfo->filesize+k+8+4;
					fsize = finfo->filesize + k;
					char *compressed = NULL;
					size_t cbytes = 0;
					if(!tor_gzip_compress(&compressed,&cbytes,finfo->filedata,finfo->filesize,GZIP_METHOD))
					{	i = i + cbytes - finfo->filesize;
						fsize = fsize + cbytes - finfo->filesize;
						wbuf = tor_malloc(i);
						cbuf = tor_malloc(i+1024);
						memcpy(wbuf,&fsize,4);
						memcpy(wbuf+4,&finfo->filetime,8);
						memcpy(wbuf+12,filename,k);
						memcpy(wbuf+12+k,compressed,cbytes);
						tor_free(compressed);
					}
					else
					{	wbuf = tor_malloc(i);
						cbuf = tor_malloc(i+1024);
						memcpy(wbuf,&fsize,4);
						memcpy(wbuf+4,&finfo->filetime,8);
						memcpy(wbuf+12,filename,k);
						memcpy(wbuf+12+k,finfo->filedata,finfo->filesize);
					}
					#ifdef RANDOMIZE_ENCRYPTION
						k=0;
						for(j=12;j<i;j++)
						{	wbuf[j] ^= random_garbage[k];
							k++;
							if(k >= ssize)	k = 0;
						}
					#endif
					memcpy(cbuf,wbuf,12);
					crypto_cipher_encrypt(env1,cbuf+4,wbuf+4,i-4);
					WriteFile(hFile,cbuf,i,&bytesWritten,NULL);
					tor_free(wbuf);
					tor_free(cbuf);
				}
				finfo = finfo->next;
			}
			WriteFile(hFile,&bufzero,4,&bytesWritten,NULL);
			CloseHandle(hFile);
			crypto_free_cipher_env(env1);
			#ifdef RANDOMIZE_ENCRYPTION
				tor_free(random_garbage);
			#endif
		}
		delete_dat_file();
		char *fnametmp = get_datadir_fname_suffix(NULL,".dat");
		i=strlen(fname)+1;
		LPWSTR tmp=tor_malloc(i*2+4);
		j=strlen(fnametmp)+1;
		LPWSTR tmp1=tor_malloc(j*2+4);
		i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,-1,tmp,i*2);
		j=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fnametmp,-1,tmp1,j*2);
		if(i >= 0)	tmp[i]=0;
		if(j >= 0)	tmp1[j]=0;
		i = MoveFileW(tmp,tmp1);
		tor_free(fnametmp);
		tor_free(tmp);
		tor_free(tmp1);
		tor_free(fname);
	}
	else
	{	finfo = first_file;
		DWORD bytesWritten;
		char *fpath = tor_malloc(MAX_PATH+1);
		while(finfo)
		{	tor_snprintf(fpath,MAX_PATH,"%s%s",fullpath,get_file_name(finfo->filename));
			hFile = open_file(fpath,GENERIC_WRITE,CREATE_ALWAYS);
			if(hFile)
			{	WriteFile(hFile,finfo->filedata,finfo->filesize,&bytesWritten,NULL);
				CloseHandle(hFile);
			}
			finfo = finfo->next;
		}
		tor_free(fpath);
	}
}

void read_configuration_data(void)
{	char *fname = get_datadir_fname_suffix(NULL,".dat");
	HANDLE hFile = open_file(fname,GENERIC_READ,OPEN_EXISTING);
	if(hFile!=INVALID_HANDLE_VALUE)
	{	uint32_t fsize=0;
		#ifdef RANDOMIZE_ENCRYPTION
			uint32_t ssize=0;
			char *random_garbage;
		#endif
		DWORD bytesRead;
		if(!password)
		{	alloc_password();
			if(!DialogBoxParamW(hInstance,(LPWSTR)MAKEINTRESOURCE(1015),hMainDialog,&dlgGetPassword,0) || !password)
				ExitProcess(0);
		}
		if(password)
		{
			#ifdef RANDOMIZE_ENCRYPTION
				ReadFile(hFile,&ssize,2,&bytesRead,NULL);
				if(bytesRead)
				{
			#endif
				crypto_cipher_env_t *env1;
				char *fdata,*ddata;
				file_info_t *finfo,*filelist;
				filelist = first_file;
				if(filelist)
				{	while(filelist->next)	filelist = filelist->next;
				}
				int k;
				env1 = crypto_new_cipher_env();
				crypto_cipher_set_key(env1,password);
				crypto_cipher_decrypt_init_cipher(env1);
				#ifdef RANDOMIZE_ENCRYPTION
					int j;
					random_garbage = tor_malloc(ssize);
					ReadFile(hFile,random_garbage,ssize,&bytesRead,NULL);
				#endif
				while(1)
				{	ReadFile(hFile,&fsize,4,&bytesRead,NULL);
					if(fsize < 4)	break;
					fsize += 8;
					fdata = tor_malloc(fsize+1024);
					if(fdata)
					{	ReadFile(hFile,fdata,fsize,&bytesRead,NULL);
						ddata = tor_malloc(fsize+1024);
						crypto_cipher_decrypt(env1,ddata,fdata,fsize);
						#ifdef RANDOMIZE_ENCRYPTION
							k=0;
							for(j=8;j<fsize;j++)
							{	ddata[j] ^= random_garbage[k];
								k++;
								if(k >= ssize)	k = 0;
							}
						#endif
						finfo = tor_malloc_zero(sizeof(file_info_t));
						memcpy(&finfo->filetime,ddata,8);
						k = strlen(ddata+8) + strlen(exename) + 2;
						finfo->filename = tor_malloc(k);
						tor_snprintf(finfo->filename,k,"%s%s",exename,ddata+8);
						k = strlen(ddata+8);
						fsize -= 9+k;
						int method = detect_compression_method(ddata+9+k,fsize);
						if(method == GZIP_METHOD || method == ZLIB_METHOD)
						{	tor_gzip_uncompress(&finfo->filedata,&finfo->filesize,ddata+9+k,fsize,method,1,LOG_INFO);
							finfo->allocsize = finfo->filesize;
						}
						else
						{	finfo->filesize = fsize;
							finfo->allocsize = fsize+1024;
							finfo->filedata = tor_malloc(fsize+1024);
							memcpy(finfo->filedata,ddata+9+k,fsize);
						}
						if(filelist)	filelist->next = finfo;
						else	first_file = finfo;
						filelist = finfo;
						tor_free(ddata);
						tor_free(fdata);
					}
				}
				#ifdef RANDOMIZE_ENCRYPTION
					tor_free(random_garbage);
				#endif
				crypto_free_cipher_env(env1);
			#ifdef RANDOMIZE_ENCRYPTION
				}
			#endif
		}
		if(!find_file(get_default_conf_file()))
		{	MessageBox(0,"Invalid password.","Error",MB_OK);
			ExitProcess(0);
		}
		CloseHandle(hFile);
		encryption |= 2;
	}
	tor_free(fname);
	return;
}

static int ftime_skew = 0;	/** Our current estimate of our skew, such that we think the current time is closest to time(NULL)+ftime_skew. */
static int ftime_slop = 60;	/** Tolerance during time comparisons, in seconds. */

/** Return true if we think that <b>now</b> is definitely after <b>when</b>. */
int ftime_definitely_after(time_t now, time_t when)	/* It is definitely after when if the earliest time it could be is still after when. */
{	return (now + ftime_skew - ftime_slop) >= when;
}
/** Return true if we think that <b>now</b> is definitely before <b>when</b>. */
int ftime_definitely_before(time_t now, time_t when)	/* It is definitely before when if the latest time it could be is still before when. */
{	return (now + ftime_skew + ftime_slop) < when;
}


int delete_file(char *fname)
{	if(encryption)
	{	file_info_t *file1,*file2;
		file1 = find_file(fname);
		if(file1)
		{	if(first_file == file1)	first_file = file1->next;
			else
			{	file2 = first_file;
				while(file2 && file2->next != file1)	file2 = file2->next;
				if(file2)
				{	file2->next = file1->next;
				}
			}
			unload_file(file1);
		}
		return 0;
	}
	int i=strlen(fname)+1;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,i,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	i = DeleteFileW(tmp);
	tor_free(tmp);
	if(!i)	return -1;
	return 0;
}

/** Rename the file <b>from</b> to the file <b>to</b>.  On unix, this is the same as rename(2). On windows, this removes <b>to</b> first if it already exists. Returns 0 on success. Returns -1 and sets errno on failure. */
int replace_file(char *from,char *to)
{	if(encryption)
	{	file_info_t *file1 = find_file(to);
		if(file1)	delete_file(file1->filename);
		file1 = find_file(from);
		if(!file1)	return -1;
		char *tmp;
		tmp=to;
		while(*tmp)
		{	if(tmp[0]=='\\' && tmp[1]!=0)	to = tmp+1;
			tmp++;
		}
		tor_free(file1->filename);
		file1->filename = tor_strdup(to);
		return 0;
	}
	switch(file_status(to))
	{	case FN_NOENT:
			break;
		case FN_FILE:
			if(delete_file(to))	return -1;
			break;
		case FN_ERROR:
			return -1;
		case FN_DIR:
			errno = EISDIR;
			return -1;
	}
	int i=strlen(from)+1;
	LPWSTR tmp=tor_malloc(i*2+4);
	int j=strlen(to)+1;
	LPWSTR tmp1=tor_malloc(j*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)from,-1,tmp,i*2);
	j=MultiByteToWideChar(CP_UTF8,0,(LPSTR)to,-1,tmp1,j*2);
	if(i >= 0)	tmp[i]=0;
	if(j >= 0)	tmp1[j]=0;
	i = MoveFileW(tmp,tmp1);
	tor_free(tmp);
	tor_free(tmp1);
	if(!i)	return -1;
	return 0;
}


/** Return FN_ERROR if filename can't be read, FN_NOENT if it doesn't exist, FN_FILE if it is a regular file, or FN_DIR if it's a directory.  On FN_ERROR, sets errno. */
file_status_t file_status(char *fname)
{	if(encryption)
	{	if(find_file(fname))	return FN_FILE;
		return FN_NOENT;
	}
	int i=strlen(fname)+1;
	LPWSTR tmp=tor_malloc(i*2+4);
	i=MultiByteToWideChar(CP_UTF8,0,(LPSTR)fname,i,tmp,i*2);
	if(i >= 0)	tmp[i]=0;
	DWORD attrs = GetFileAttributesW(tmp);
	tor_free(tmp);
	if(attrs == 0xffffffff)	return FN_NOENT;
	else if(attrs & FILE_ATTRIBUTE_DIRECTORY)	return FN_DIR;
	return FN_FILE;
}

void show_last_error(int err_id,const char *fname)
{	int err=GetLastError();
	char *errstr=format_win32_error(err);
	log(LOG_WARN,LD_FS,get_lang_str(err_id),fname,errstr);
	tor_free(errstr);
}


int start_writing_to_file(char *fname,open_file_t **data_out)
{	size_t tempname_len = strlen(fname)+16;
	open_file_t *new_file = tor_malloc_zero(sizeof(open_file_t));
	tor_assert(fname);
	tor_assert(data_out);
	tor_assert(tempname_len > strlen(fname)); /*check for overflow*/
	new_file->filename = tor_strdup(fname);
	new_file->tempname = tor_malloc(tempname_len);

	tor_snprintf(new_file->tempname, tempname_len, "%s.tmp", fname);
	*data_out = new_file;
	if(encryption)
	{	new_file->mem_file = get_file(fname);
		return 1;
	}
	new_file->hFile = open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
	if(new_file->hFile==INVALID_HANDLE_VALUE)
	{	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,fname);
		*data_out = NULL;
		tor_free(new_file->filename);
		tor_free(new_file->tempname);
		tor_free(new_file);
		return 0;
	}
	return 1;
}

int start_appending_to_file(char *fname,open_file_t **data_out)
{	size_t tempname_len = strlen(fname)+16;
	open_file_t *new_file = tor_malloc_zero(sizeof(open_file_t));
	tor_assert(fname);
	tor_assert(data_out);
	tor_assert(tempname_len > strlen(fname)); /*check for overflow*/
	new_file->filename = tor_strdup(fname);
	new_file->tempname = tor_malloc(tempname_len);

	tor_snprintf(new_file->tempname, tempname_len, "%s.tmp", fname);
	*data_out = new_file;
	if(encryption)
	{	new_file->mem_file = get_file(fname);
		return 1;
	}
	new_file->hFile = open_file(fname,GENERIC_READ|GENERIC_WRITE,OPEN_ALWAYS);
	if(new_file->hFile==INVALID_HANDLE_VALUE)
		new_file->hFile = open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
	else	SetFilePointer(new_file->hFile,0,0,FILE_END);
	if(new_file->hFile==INVALID_HANDLE_VALUE)
	{	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,fname);
		*data_out = NULL;
		tor_free(new_file->filename);
		tor_free(new_file->tempname);
		tor_free(new_file);
		return 0;
	}
	return 1;
}

/** Helper function: close and free the underlying file and memory in <b>file_data</b>.  If we were writing into a temporary file, then delete that file (if abort_write is true) or replaces the target file with the temporary file (if abort_write is false). */
int finish_writing_to_file(open_file_t *file_data, int abort_write)
{	int r = 0;
	tor_assert(file_data && file_data->filename);
	if(encryption && file_data->mem_file)
	{	file_data->mem_file->filetime = get_time(NULL);
	}
	else
	{	if(file_data->hFile && !CloseHandle(file_data->hFile))
		{	show_last_error(LANG_LOG_UTIL_ERROR_CLOSING_FILE,file_data->filename);
			abort_write = r = -1;
		}
	}
	if(abort_write)
		delete_file(file_data->tempname);
	else if(replace_file(file_data->tempname, file_data->filename))
	{	log_warn(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_REPLACING_FILE),file_data->filename,strerror(errno));
		r = -1;
	}
	tor_free(file_data->filename);
	tor_free(file_data->tempname);
	tor_free(file_data);
	return r;
}


int write_string_to_file(open_file_t *file,const char *str)
{	int len = strlen(str);
	if(encryption)
	{	file_info_t *wfile = file->mem_file;
		if(wfile)
		{	if(wfile->allocsize < (wfile->filesize + len))
			{	wfile->allocsize += len + 4096;
				char *newbuffer = tor_malloc(wfile->allocsize);
				memcpy(newbuffer,wfile->filedata,wfile->filesize);
				char *s;
				s = wfile->filedata;
				wfile->filedata = newbuffer;
				tor_free(s);
			}
			memcpy(wfile->filedata + wfile->filesize,str,len);
			wfile->filesize += len;
			return 0;
		}
	}
	DWORD bytesWritten;
	WriteFile(file->hFile,str,len,&bytesWritten,NULL);
	if(bytesWritten != (DWORD)len)	return -1;
	return 0;
}

int write_buffer_to_file(open_file_t *file,char *str,int len)
{	if(encryption)
	{	file_info_t *wfile = file->mem_file;
		if(wfile)
		{	if(wfile->allocsize < (wfile->filesize + len))
			{	wfile->allocsize += len + 4096;
				char *newbuffer = tor_malloc(wfile->allocsize);
				memcpy(newbuffer,wfile->filedata,wfile->filesize);
				char *s;
				s = wfile->filedata;
				wfile->filedata = newbuffer;
				tor_free(s);
			}
			memcpy(wfile->filedata + wfile->filesize,str,len);
			wfile->filesize += len;
			return 0;
		}
	}
	DWORD bytesWritten;
	WriteFile(file->hFile,str,len,&bytesWritten,NULL);
	if(bytesWritten != (DWORD)len)	return -1;
	return 0;
}

int get_file_size(open_file_t *open_file)
{	if(encryption)
	{	file_info_t *wfile = open_file->mem_file;
		if(wfile)	return wfile->filesize;
	}
	return GetFileSize(open_file->hFile,NULL);
}

/** Given a smartlist of sized_chunk_t, write them atomically to a file <b>fname</b>, overwriting or creating the file as necessary. */
int write_chunks_to_file(char *fname,smartlist_t *chunks, int bin)
{	(void) bin;
	if(encryption)
	{	int bufsize=0;
		int pos;
		SMARTLIST_FOREACH(chunks, sized_chunk_t *, chunk,
		{	bufsize += chunk->len;
		});
		file_info_t *file = get_file(fname);
		char *tmp = file->filedata;
		file->filedata = tor_malloc(bufsize);
		file->filesize = bufsize;
		file->filetime = get_time(NULL);
		file->allocsize = bufsize;
		pos = 0;
		SMARTLIST_FOREACH(chunks, sized_chunk_t *, chunk,
		{	if((unsigned int)bufsize>=chunk->len)
			{	memcpy(file->filedata+pos,chunk->bytes,chunk->len);
				bufsize -= chunk->len;
				pos += chunk->len;
			}
		});
		if(tmp)	tor_free(tmp);
		return 0;
	}
	HANDLE hFile = open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
	if(hFile==INVALID_HANDLE_VALUE)
	{	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,fname);
		return -1;
	}
	DWORD bytesWritten;
	SMARTLIST_FOREACH(chunks, sized_chunk_t *, chunk,
	{	WriteFile(hFile,chunk->bytes,chunk->len,&bytesWritten,NULL);
		if(chunk->len!=bytesWritten)
		{	show_last_error(LANG_LOG_UTIL_ERROR_WRITING_FILE,fname);
			CloseHandle(hFile);
			return -1;
		}
	});
	CloseHandle(hFile);
	return 0;
}


/** As write_str_to_file, but does not assume a NUL-terminated string. Instead, we write <b>bufsize</b> bytes, starting at <b>str</b>. */
int write_buf_to_file(const char *filename,const char *buf,int bufsize)
{	if(encryption)
	{	file_info_t *file = get_file(filename);
		char *tmp;
		tmp = file->filedata;
		file->filedata = tor_malloc(bufsize+1024);
		file->filesize = bufsize;
		file->filetime = get_time(NULL);
		file->allocsize = bufsize+1024;
		memcpy(file->filedata,buf,bufsize);
		if(tmp)	tor_free(tmp);
		return 0;
	}

	HANDLE hFile=open_file(filename,GENERIC_WRITE,CREATE_ALWAYS);
	if(hFile==INVALID_HANDLE_VALUE)
	{	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,filename);
		return -1;
	}
	DWORD bytesWritten;
	WriteFile(hFile,buf,bufsize,&bytesWritten,NULL);
	if((DWORD)bufsize!=bytesWritten)
	{	show_last_error(LANG_LOG_UTIL_ERROR_WRITING_FILE,filename);
		CloseHandle(hFile);
		return -1;
	}
	CloseHandle(hFile);
	return 0;
}


/** As write_bytes_to_file, but if the file already exists, append the bytes to the end of the file instead of overwriting it. */
int append_bytes_to_file(char *fname,char *str, size_t len,int bin)
{	(void) bin;
	if(encryption)
	{	file_info_t *file=get_file(fname);
		if(!file)	return -1;
		if(file->allocsize < (file->filesize + len))
		{	file->allocsize += len;
			char *newbuffer = tor_malloc(file->allocsize);
			memcpy(newbuffer,file->filedata,file->filesize);
			char *s;
			s = file->filedata;
			file->filedata = newbuffer;
			tor_free(s);
		}
		memcpy(file->filedata + file->filesize,str,len);
		file->filesize += len;
		file->filetime = get_time(NULL);
		return 0;
	}
	HANDLE hFile=open_file(fname,GENERIC_READ|GENERIC_WRITE,OPEN_EXISTING);
	if(hFile==INVALID_HANDLE_VALUE)	hFile=open_file(fname,GENERIC_WRITE,CREATE_ALWAYS);
	else	SetFilePointer(hFile,0,NULL,FILE_END);
	if(hFile==INVALID_HANDLE_VALUE)
	{	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,fname);
		return -1;
	}
	DWORD bytesWritten;
	WriteFile(hFile,str,len,&bytesWritten,NULL);
	if(len!=bytesWritten)
	{	show_last_error(LANG_LOG_UTIL_ERROR_WRITING_FILE,fname);
		CloseHandle(hFile);
		return -1;
	}
	CloseHandle(hFile);
	return 0;
}

/** Read the contents of <b>filename</b> into a newly allocated string; return the string on success or NULL on failure.
 * If <b>stat_out</b> is provided, store the result of stat()ing the file into <b>stat_out</b>.
 * If <b>flags</b> &amp; RFTS_BIN, open the file in binary mode.
 * If <b>flags</b> &amp; RFTS_IGNORE_MISSING, don't warn if the file doesn't exist. */
/* This function <em>may</em> return an erroneous result if the file is modified while it is running, but must not crash or overflow. Right now, the error case occurs when the file length grows between the call to stat and the call to read_all: the resulting string will be truncated. */
char *read_file_to_str(char *filename, int flags, struct stat *stat_out)
{	char *string;
	int bin = flags & RFTS_BIN;
	if(encryption)
	{	file_info_t *file=find_file(filename);
		if(!file)	return NULL;
		string = tor_malloc(file->filesize+2);
		memcpy(string,file->filedata,file->filesize);
		string[file->filesize] = 0;
		string[file->filesize+1] = 0;
		if(!bin && strchr(string, '\r'))
			tor_strstrip(string, "\r");
		if(stat_out)
		{	stat_out->st_mtime = file->filetime;
			stat_out->st_size = file->filesize;
		}
		return string;
	}
	HANDLE hFile = open_file(filename,GENERIC_READ,OPEN_EXISTING);
	if(hFile==INVALID_HANDLE_VALUE)
	{	if(!(flags & RFTS_IGNORE_MISSING))	show_last_error(LANG_LOG_UTIL_ERROR_OPENING_FILE_3,filename);
		return NULL;
	}
	uint32_t fsize = GetFileSize(hFile,NULL);
	if(fsize+1 >= SIZE_T_CEILING)
	{	CloseHandle(hFile);
		return NULL;
	}
	string = tor_malloc(fsize+2);

	DWORD numread = 0;
	ReadFile(hFile,string,fsize,&numread,NULL);
	string[numread] = '\0'; /* NUL-terminate the result. */
	string[numread+1] = '\0'; /* for UNICODE files. */

	if(!bin && strchr(string, '\r'))
	{	// log_debug(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_CONVERTING_CRLF),filename);
		tor_strstrip(string, "\r");
		numread = strlen(string);
	}
	if(bin && numread != fsize)	/* Unless we're using text mode on win32, we'd better have an exact match for size. */
	{	log_warn(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_READING_FILE_2),numread,fsize,filename);
		tor_free(string);
		CloseHandle(hFile);
		return NULL;
	}
	if(stat_out)
	{	FILETIME ft;
		GetFileTime(hFile,NULL,NULL,&ft);
		stat_out->st_mtime = convert_file_time(&ft);
		stat_out->st_size = numread;
	}
	CloseHandle(hFile);
	return string;
}


/** Return a new list containing the filenames in the directory <b>dirname</b>. Return NULL on error or if <b>dirname</b> is not a directory. */
WIN32_FIND_DATAW findData;
smartlist_t *tor_listdir(char *dirname)
{	smartlist_t *result;
	char *pattern;
	if(encryption)
	{	file_info_t *file;
		file = first_file;
		pattern = dirname;
		while(*pattern)
		{	if(pattern[0]=='\\' && pattern[1]!=0)	dirname = pattern+1;
			pattern++;
		}
		result = smartlist_create();
		while(file)
		{	if(!strcasecmpstart(file->filename,dirname))	smartlist_add(result,tor_strdup(file->filename));
			file = file->next;
		}
	}
	else
	{	HANDLE handle;
		size_t pattern_len = strlen(dirname)+16;
		pattern = tor_malloc(pattern_len);
		tor_snprintf(pattern, pattern_len, "%s*.*", dirname);
		if(INVALID_HANDLE_VALUE == (handle = find_first_file(pattern, &findData)))
		{	tor_free(pattern);
			return NULL;
		}
		result = smartlist_create();
		char *tmpname = tor_malloc(MAX_PATH*2 + 4);
		int i;
		BOOL* usedDefault=NULL;
		while(1)
		{	i = WideCharToMultiByte(CP_UTF8,0,findData.cFileName,-1,tmpname,MAX_PATH+1,NULL,usedDefault);
			if(i >= 0)	tmpname[i] = 0;
			if(strcmp(tmpname, ".") && strcmp(tmpname, ".."))
				smartlist_add(result,tor_strdup(tmpname));
			if(!FindNextFileW(handle,&findData))
			{	DWORD err;
				if((err = GetLastError()) != ERROR_NO_MORE_FILES)
				{	char *errstr = format_win32_error(err);
					log_warn(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_READING_DIR),dirname,errstr);
					tor_free(errstr);
				}
				break;
			}
		}
		tor_free(tmpname);
		FindClose(handle);
		tor_free(pattern);
	}
	return result;
}

WIN32_FIND_DATAW wfData;
smartlist_t *listdir(char *pattern)
{	smartlist_t *result;
	HANDLE handle;
	if((handle = find_first_file(pattern, &wfData)) == INVALID_HANDLE_VALUE)
		return NULL;
	result = smartlist_create();
	char *tmpname = tor_malloc(MAX_PATH*2 + 4);
	int i;
	BOOL* usedDefault=NULL;
	while(1)
	{	i = WideCharToMultiByte(CP_UTF8,0,wfData.cFileName,-1,tmpname,MAX_PATH+1,NULL,usedDefault);
		if(i >= 0)	tmpname[i] = 0;
		if(strcmp(tmpname, ".") && strcmp(tmpname, ".."))
			smartlist_add(result,tor_strdup(tmpname));
		if(!FindNextFileW(handle,&wfData))
		{	DWORD err;
			if((err = GetLastError()) != ERROR_NO_MORE_FILES)
			{	char *errstr = format_win32_error(err);
				log_warn(LD_FS,get_lang_str(LANG_LOG_UTIL_ERROR_READING_DIR),pattern,errstr);
				tor_free(errstr);
			}
			break;
		}
	}
	tor_free(tmpname);
	FindClose(handle);
	return result;
}


/** Return a newly allocated string holding a filename relative to the data directory.  If <b>sub1</b> is present, it is the first path component after the data directory.  If <b>sub2</b> is also present, it is the second path component after the data directory.  If <b>suffix</b> is present, it is appended to the filename.
 * Examples:
 *    get_datadir_fname2_suffix("a", NULL, NULL) -> $DATADIR/a
 *    get_datadir_fname2_suffix("a", NULL, ".tmp") -> $DATADIR/a.tmp
 *    get_datadir_fname2_suffix("a", "b", ".tmp") -> $DATADIR/a/b/.tmp
 *    get_datadir_fname2_suffix("a", "b", NULL) -> $DATADIR/a/b
 * Note: Consider using the get_datadir_fname* macros in or.h. */
char *get_datadir_fname2_suffix(const char *sub1,const char *sub2,const char *suffix)
{	char *fname = NULL;
	size_t len;
	len = 2+strlen(fullpath);
	if(sub1)
	{	len++;
		len += strlen(sub1)+1;
		if(sub2)	len += strlen(sub2)+1;
	}
	if(suffix)	len += strlen(suffix)+1;
	len++;
	fname = tor_malloc(len);
	if(sub1)
	{	if(sub2)	tor_snprintf(fname, len, "%s-%s-%s",fullpath,sub1, sub2);
		else		tor_snprintf(fname, len, "%s-%s",fullpath,sub1);
	}
	else		tor_snprintf(fname,len,"%s",fullpath);
	if(suffix)	strlcat(fname, suffix, len);
	return fname;
}


tor_mmap_t *tor_mmap_file(char *filename)
{	if(encryption)
	{	file_info_t *file = get_file(filename);
		if(!file)	return NULL;
		tor_mmap_t *handle;
		handle = tor_malloc_zero(sizeof(tor_mmap_t));
		handle->file = file;
		handle->data = file->filedata;
		handle->size = file->filesize;
		return handle;
	}
	tor_mmap_t *res = tor_malloc_zero(sizeof(tor_mmap_t));
	res->file_handle = INVALID_HANDLE_VALUE;
	res->mmap_handle = NULL;
	res->file_handle = open_file(filename,GENERIC_READ,OPEN_EXISTING);
	if(res->file_handle != INVALID_HANDLE_VALUE)
	{	res->size = GetFileSize(res->file_handle, NULL);
		if(res->size == 0)
		{	log_info(LD_FS,get_lang_str(LANG_LOG_COMPAT_FILE_IS_EMPTY),filename);
			errno = ERANGE;
			tor_munmap_file(res);
			return NULL;
		}
		res->mmap_handle = CreateFileMappingW(res->file_handle,NULL,PAGE_READONLY,
#if SIZEOF_SIZE_T > 4
					(res->base.size >> 32),
#else
					0,
#endif
					(res->size & 0xfffffffful),NULL);
		if(res->mmap_handle)
		{	res->data = (char*) MapViewOfFile(res->mmap_handle,FILE_MAP_READ,0,0,0);
			if(res->data)	return res;
		}
	}
	DWORD e = GetLastError();
	int severity = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? LOG_INFO : LOG_WARN;
	char *msg = format_win32_error(e);
	log_fn(severity,LD_FS,get_lang_str(LANG_LOG_COMPAT_COULD_NOT_MMAP_FILE),filename,msg);
	tor_free(msg);
	if(e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
		errno = ENOENT;
	else	errno = EINVAL;
	tor_munmap_file(res);
	return NULL;
}
void tor_munmap_file(tor_mmap_t *handle)
{	if(encryption)
	{	memset(handle, 0, sizeof(tor_mmap_t));
	}
	else
	{	if(handle->data)	/* This is an ugly cast, but without it, "data" in struct tor_mmap_t would have to be redefined as non-const. */
			UnmapViewOfFile( (LPVOID) handle->data);
		if(handle->mmap_handle != NULL)
			CloseHandle(handle->mmap_handle);
		if(handle->file_handle != INVALID_HANDLE_VALUE)
			CloseHandle(handle->file_handle);
	}
	tor_free(handle);
}


char *get_mmap_data(tor_mmap_t *map)
{	if(encryption)
	{	map->data = map->file->filedata;
		map->size = map->file->filesize;
	}
	return map->data;
}


/** Given a file name check to see whether the file exists but has not been modified for a very long time. If so, remove it. */
//#define VERY_OLD_FILE_AGE (28*24*60*60)
void remove_file_if_very_old(char *fname, time_t now)
{	or_options_t *options = get_options();
	time_t filetime;
	if(!options)	return;
	else if(!options->MaxFileAge)	return;
	filetime = get_file_time(fname);
	if(filetime < now-(options->MaxFileAge*24*60*60))
	{	char buf[ISO_TIME_LEN+1];
		format_local_iso_time(buf,filetime);
		log_notice(LD_GENERAL,get_lang_str(LANG_LOG_CONFIG_OBSOLETE_FILE_REMOVE),fname,buf);
		delete_file(fname);
	}
}

int write_private_key_to_filename(crypto_pk_env_t *env,char *fname)
{	char *s = crypto_pk_get_private_key_str(env);
	int r;
	if(s)
	{	r = write_buf_to_file(fname,s,strlen(s));
		memset(s,0,strlen(s));
		tor_free(s);
	}
	else r = -1;
	return r;
}

void delete_serv_files(char *key)
{	char fname[512];
	if (strlcpy(fname,fullpath,sizeof(fname))>=sizeof(fname) || strlcat(fname,"-",sizeof(fname)) >= sizeof(fname) || strlcat(fname,key,sizeof(fname)) >= sizeof(fname) || strlcat(fname,"-private_key",sizeof(fname)) >= sizeof(fname))
	{	log_warn(LD_CONFIG, get_lang_str(LANG_LOG_RENDSERVICE_DIR_NAME_TOO_LONG),key);}
	else delete_file(fname);
	if(strlcpy(fname,fullpath,sizeof(fname))>=sizeof(fname) || strlcat(fname,"-",sizeof(fname)) >= sizeof(fname) || strlcat(fname,key,sizeof(fname)) >= sizeof(fname) || strlcat(fname,"-hostname",sizeof(fname)) >= sizeof(fname))
	{	log_warn(LD_CONFIG, get_lang_str(LANG_LOG_RENDSERVICE_DIR_NAME_TOO_LONG),key);}
	else delete_file(fname);
}

int make_backup(char *fname)
{	size_t fn_tmp_len = strlen(fname)+32;
	char *fn_tmp;
	int r = 0;
	tor_assert(fn_tmp_len > strlen(fname)); /*check for overflow*/
	fn_tmp = tor_malloc(fn_tmp_len);
	if(tor_snprintf(fn_tmp, fn_tmp_len, "%s.bak", fname)<0)
	{	log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_TOR_SNPRINTF_FAILED));
		tor_free(fn_tmp);
		r = -1;
	}
	log_notice(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONFIG_FILE_RENAME),fn_tmp);
	if(replace_file(fname,fn_tmp) < 0)
	{	log_warn(LD_FS,get_lang_str(LANG_LOG_CONFIG_CONFIG_FILE_RENAME_ERROR),fname, fn_tmp, strerror(errno));
		delete_file(fname);
		r = -1;
	}
	tor_free(fn_tmp);
	return r;
}

void remove_datadir_file(char *str)
{	char *fname = get_datadir_fname(str);
	delete_file(fname);
	tor_free(fname);
}

time_t get_file_time(char *fname)
{	if(encryption)
	{	file_info_t *file = find_file(fname);
		if(file)	return update_time(file->filetime);
		return get_time(NULL);
	}
	WIN32_FIND_DATAW findData2;
	HANDLE hFind=find_first_file(fname,&findData2);
	if(hFind==INVALID_HANDLE_VALUE)	return get_time(NULL);
	FindClose(hFind);
	return update_time(convert_file_time(&findData2.ftLastWriteTime));
}

void get_exe_name(char *dest)
{	LPWSTR tmp=tor_malloc(MAX_PATH*2+4);
	BOOL* usedDefault=NULL;
	int i;
	i = GetModuleFileNameW(NULL,tmp,MAX_PATH);
	i = WideCharToMultiByte(CP_UTF8,0,tmp,i,dest,MAX_PATH+1,NULL,usedDefault);
	if(i >= 0)	dest[i] = 0;
}


#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define OBJ_CASE_INSENSITIVE 64L
#define MAX_MODULE_NAME32 255
#define TH32CS_SNAPTHREAD 4
#define TH32CS_SNAPMODULE 0x8

typedef struct _UNICODE_STRING
{	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{	ULONG		Length;
	HANDLE		RootDirectory;
	PUNICODE_STRING	ObjectName;
	ULONG		Attributes;
	PVOID		SecurityDescriptor;
	PVOID		SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_HANDLE
{	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct tagMODULEENTRY32W
{	DWORD dwSize;
	DWORD th32ModuleID;
	DWORD th32ProcessID;
	DWORD GlblcntUsage;
	DWORD ProccntUsage;
	BYTE *modBaseAddr;
	DWORD modBaseSize;
	HMODULE hModule; 
	WCHAR szModule[MAX_MODULE_NAME32 + 1];
	WCHAR szExePath[MAX_PATH];
} MODULEENTRY32W,*PMODULEENTRY32W,*LPMODULEENTRY32W; 

typedef struct tagMODULEENTRY32 {
	DWORD dwSize;
	DWORD th32ModuleID;
	DWORD th32ProcessID;
	DWORD GlblcntUsage;
	DWORD ProccntUsage;
	BYTE *modBaseAddr;
	DWORD modBaseSize;
	HMODULE hModule;
	char szModule[MAX_MODULE_NAME32 + 1];
	char szExePath[MAX_PATH];
} MODULEENTRY32,*PMODULEENTRY32,*LPMODULEENTRY32; 

typedef struct tagTHREADENTRY32 {
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ThreadID;
	DWORD th32OwnerProcessID;
	LONG tpBasePri;
	LONG tpDeltaPri;
	DWORD dwFlags;
} THREADENTRY32,*PTHREADENTRY32,*LPTHREADENTRY32; 

typedef DWORD (NTAPI *_NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
typedef DWORD (NTAPI *_NtDuplicateObject)(HANDLE SourceProcessHandle,USHORT SourceHandle,HANDLE TargetProcessHandle,PHANDLE TargetHandle,ACCESS_MASK DesiredAccess,ULONG Attributes,ULONG Options);
typedef DWORD (NTAPI *_NtQueryObject)(HANDLE ObjectHandle,ULONG ObjectInformationClass,PVOID ObjectInformation,ULONG ObjectInformationLength,PULONG ReturnLength);
typedef DWORD (NTAPI *_NtDeleteFile)(OBJECT_ATTRIBUTES *ObjectAttributes);
typedef BOOL (NTAPI *_NtSuspendProcess)(HANDLE);
typedef BOOL (NTAPI *_NtResumeProcess)(HANDLE);
typedef BOOL (NTAPI *_RtlCreateUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR SourceString);
typedef void (NTAPI *_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef HANDLE (WINAPI *_CreateToolhelp32Snapshot)(DWORD dwFlags,DWORD th32ProcessID);
typedef BOOL (WINAPI *_Module32First)(HANDLE hSnapshot,LPMODULEENTRY32W lpme);
typedef BOOL (WINAPI *_Module32Next)(HANDLE hSnapshot,LPMODULEENTRY32W lpme);
typedef BOOL (WINAPI *_Module32FirstA)(HANDLE hSnapshot,LPMODULEENTRY32 lpme);
typedef BOOL (WINAPI *_Module32NextA)(HANDLE hSnapshot,LPMODULEENTRY32 lpme);
typedef BOOL (WINAPI *_Thread32First)(HANDLE hSnapshot,LPTHREADENTRY32 lpte);
typedef BOOL (WINAPI *_Thread32Next)(HANDLE hSnapshot,LPTHREADENTRY32 lpme);
typedef HANDLE (WINAPI *_OpenThread)(DWORD,BOOL,DWORD);

HMODULE hNtdll=NULL,hKernel=NULL;
_NtQuerySystemInformation NtQuerySystemInformation = NULL;
_NtDuplicateObject NtDuplicateObject = NULL;
_NtQueryObject NtQueryObject = NULL;
_NtDeleteFile NtDeleteFile = NULL;
_RtlCreateUnicodeString RtlCreateUnicodeString = NULL;
_RtlFreeUnicodeString RtlFreeUnicodeString = NULL;
_NtSuspendProcess NtSuspendProcess = NULL;
_NtResumeProcess NtResumeProcess = NULL;
_CreateToolhelp32Snapshot CreateToolhelp32Snapshot = NULL;
_Module32First Module32FirstW = NULL;
_Module32Next Module32NextW = NULL;
_Module32FirstA Module32FirstA = NULL;
_Module32NextA Module32NextA = NULL;
_Thread32First Thread32First = NULL;
_Thread32Next Thread32Next = NULL;
_OpenThread OpenThread = NULL;
UNICODE_STRING PathNameString;
OBJECT_ATTRIBUTES ObjectAttributes;

void init_nt_functions(void)
{	if(!RtlCreateUnicodeString)
	{	hNtdll = GetModuleHandleA("ntdll.dll");
		NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll,"NtQuerySystemInformation");
		NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hNtdll,"NtDuplicateObject");
		NtQueryObject = (_NtQueryObject)GetProcAddress(hNtdll,"NtQueryObject");
		NtDeleteFile = (_NtDeleteFile)GetProcAddress(hNtdll,"NtDeleteFile");
		RtlCreateUnicodeString = (_RtlCreateUnicodeString)GetProcAddress(hNtdll,"RtlCreateUnicodeString");
		RtlFreeUnicodeString = (_RtlFreeUnicodeString)GetProcAddress(hNtdll,"RtlFreeUnicodeString");
		NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(hNtdll,"NtSuspendProcess");
		NtResumeProcess = (_NtResumeProcess)GetProcAddress(hNtdll,"NtResumeProcess");
	}
}

void init_kernel_functions(void)
{	if(!CreateToolhelp32Snapshot)
	{	hKernel = GetModuleHandleA("kernel32.dll");
		CreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(hKernel,"CreateToolhelp32Snapshot");
		Module32FirstW = (_Module32First)GetProcAddress(hKernel,"Module32FirstW");
		Module32NextW = (_Module32Next)GetProcAddress(hKernel,"Module32NextW");
		Module32FirstA = (_Module32FirstA)GetProcAddress(hKernel,"Module32First");
		Module32NextA = (_Module32NextA)GetProcAddress(hKernel,"Module32Next");
		Thread32First = (_Thread32First)GetProcAddress(hKernel,"Thread32First");
		Thread32Next = (_Thread32Next)GetProcAddress(hKernel,"Thread32Next");
		OpenThread = (_OpenThread)GetProcAddress(hKernel,"OpenThread");
	}
}


	PSYSTEM_HANDLE_INFORMATION handleInfo;
	uint32_t tmp_pid;
	HANDLE processHandle;
	ULONG returnLength = 0x1000,cLength=0x1000;
	HANDLE hDupFile;
	SYSTEM_HANDLE handle;
	char *rfname;
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	PVOID objectNameInfo;
	UNICODE_STRING objectName;
	int processed;
	unsigned int handleCnt;

DWORD WINAPI closeHandles(LPVOID lParam)
{	unsigned int i;
	int j,k,l;
	char *fname = (char *)lParam;
	while(1)
	{	for(i = 0;i < handleInfo->HandleCount;i++)
		{	if(handleInfo->Handles[i].ProcessId != 0xffffffff)	break;
		}
		if(i >= handleInfo->HandleCount)	break;
		tmp_pid = handleInfo->Handles[i].ProcessId;
		processHandle = OpenProcess(PROCESS_DUP_HANDLE,0,tmp_pid);
		if(!processHandle)
		{	for(i = 0;i < handleInfo->HandleCount;i++)
			{	if(handleInfo->Handles[i].ProcessId == tmp_pid)	handleInfo->Handles[i].ProcessId = -1;
			}
			processed++;
		}
		else
		{	for(handleCnt = 0;handleCnt < handleInfo->HandleCount;handleCnt++)
			{	hDupFile = NULL;
				if(handleInfo->Handles[handleCnt].ProcessId == tmp_pid)
				{	handle = handleInfo->Handles[handleCnt];
					if(NtDuplicateObject(processHandle,handle.Handle,GetCurrentProcess(),&hDupFile,0,0,0) < 0x80000000)
					{	if(NtQueryObject(hDupFile,ObjectTypeInformation,objectTypeInfo,0x1000,NULL) < 0x80000000)
						{	processed++;
							if(1)//(((objectTypeInfo->Name.Buffer[0]|0x20)=='f' && (objectTypeInfo->Name.Buffer[1]|0x20)=='i' && (objectTypeInfo->Name.Buffer[2]|0x20)=='l' && (objectTypeInfo->Name.Buffer[3]|0x20)=='e'))
							{	if(GetFileType(hDupFile)!=FILE_TYPE_PIPE)
								{
									returnLength = cLength;
									if((NtQueryObject(hDupFile,ObjectNameInformation,objectNameInfo,0x1000,&returnLength) > 0x7fffffff))
									{	if(returnLength>cLength)
										{	cLength = returnLength;
											objectNameInfo = tor_realloc(objectNameInfo,cLength);
											if(NtQueryObject(hDupFile,ObjectNameInformation,objectNameInfo,returnLength,NULL) >0x7fffffff)
												returnLength = 0;
										}
										else	returnLength = 0;
									}
									if(returnLength)
									{	objectName = *(PUNICODE_STRING)objectNameInfo;
										if(objectName.Length)
										{	rfname = get_utf_n(objectName.Buffer,objectName.Length);
											l = processed;
											processed = -2;
											j = 0;k = 0;
											while(rfname[j])	j++;
											while(fname[k])	k++;
											while(k && j)
											{	k--;j--;
												if((rfname[j]|0x20) != (fname[k] | 0x20))
												{	if(fname[k]==':')
													{	k = 0;j = 0;
													}
													break;
												}
											}
											if(k == 0)
											{	CloseHandle(hDupFile);
												NtDuplicateObject(processHandle,handle.Handle,GetCurrentProcess(),&hDupFile,0,0,DUPLICATE_CLOSE_SOURCE);
												CloseHandle(hDupFile);
												hDupFile = NULL;
											}
											else
											{	j = 0;k = 0;
												while(rfname[j])	j++;
												while(fname[k])	k++;
												while(j && rfname[j-1]>='0' && rfname[j-1]<='9')	j--;
												if(j && rfname[j-1]=='_')
												{	j--;
													while(k && j)
													{	k--;j--;
														if((rfname[j]|0x20) != (fname[k] | 0x20) && (rfname[j]!='_' || fname[k]!='\\'))
														{	if(fname[k]==':')
															{	k = 0;j = 0;
															}
															break;
														}
														else if(fname[k]==':')
														{	k = 0;j = 0;
															break;
														}
													}
													if(k == 0)
													{	CloseHandle(hDupFile);
														NtDuplicateObject(processHandle,handle.Handle,GetCurrentProcess(),&hDupFile,0,0,DUPLICATE_CLOSE_SOURCE);
														CloseHandle(hDupFile);
														hDupFile = NULL;
													}
												}
											}
											processed = l;
											tor_free(rfname);
										}
									}
								}
							}
						}
						if(hDupFile)	CloseHandle(hDupFile);
					}
					handleInfo->Handles[handleCnt].ProcessId = -1;
				}
			}
			CloseHandle(processHandle);
		}
	}
	processed = -1;
	ExitThread(0);
}

int close_all_handles(char *fname)
{	if(!NtQuerySystemInformation)
		return 0;
	HANDLE hThread;
	DWORD threadId;
	uint32_t i,j=0x10000;

	handleInfo = tor_malloc(j);
	while ((i = NtQuerySystemInformation(SystemHandleInformation,handleInfo,j,NULL)) == (uint32_t)STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = tor_realloc(handleInfo, j *= 2);
	if(i <0x80000000)
	{	objectTypeInfo = tor_malloc(0x1000);
		objectNameInfo = tor_malloc(cLength);
		processed = 0;
		hThread = CreateThread(NULL,0,&closeHandles,fname,0,&threadId);
		while(processed!=-1)
		{	threadId = processed;
			WaitForSingleObject(hThread,100);
			if(threadId==(uint32_t)processed && (uint32_t)processed != 0xfffffffe)
			{	TerminateThread(hThread,0);
				CloseHandle(hThread);
				handleInfo->Handles[handleCnt].ProcessId = -1;
				CloseHandle(hDupFile);
				CloseHandle(processHandle);
				hThread = CreateThread(NULL,0,&closeHandles,fname,0,&threadId);
			}
		}
		tor_free(objectNameInfo);
		tor_free(objectTypeInfo);
		i = 1;
	}
	else i = 0;
	tor_free(handleInfo);
	return i;
}

int CaNtDeleteFile(char *fname)
{	if(!NtDeleteFile)	return 1;
	char *tmp = tor_malloc(1024);
	tor_snprintf(tmp,1023,"\\??\\%s",fname);
	LPWSTR wfname = get_unicode(tmp);
	tor_free(tmp);
	RtlCreateUnicodeString(&PathNameString,wfname);
	tor_free(wfname);
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.ObjectName = &PathNameString;
	ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = NULL;
	int i = NtDeleteFile(&ObjectAttributes);
	RtlFreeUnicodeString(&PathNameString);
	if(i < 0)	return 1;
	log(LOG_INFO,LD_APP,"NtDeleteFile(): the file %s was deleted successfully",fname);
	return 0;
}

int ForceDelete(char *fname)
{	if(!fname)	return 0;
	LPWSTR tmp=get_unicode(fname);
	int i;
	if(DeleteFileW(tmp))
		i = 1;
	else
	{	init_nt_functions();
		if(CaNtDeleteFile(fname))
		{	close_all_handles(fname);
			if(CaNtDeleteFile(fname))
				i = DeleteFileW(tmp);
			else	i = 1;
		}
		else	i = 1;
	}
	tor_free(tmp);
	if(i)	log(LOG_INFO,LD_APP,"ForceDelete(): the file %s was deleted successfully",fname);
	else	log(LOG_WARN,LD_APP,"ForceDelete(): could not delete the file %s",fname);
	if(i)	i = 1;
	return i;
}

int ForceDeleteSubdir(char *dirname)
{	char *dirpattern = tor_malloc(1024);
	DWORD attrs;
	int i;
	int delfiles = 0;
	tor_snprintf(dirpattern,1023,"%s\\*.*",dirname);
	smartlist_t *objdir;
	objdir = listdir(dirpattern);
	if(objdir)
	{	SMARTLIST_FOREACH(objdir,char *,fn,
		{	tor_snprintf(dirpattern,1023,"%s\\%s",dirname,fn);
			log(LOG_INFO,LD_APP,"Deleting %s",dirpattern);
			attrs = get_file_attributes(dirpattern);
			if(attrs!=0xffffffff)
			{	if(attrs & FILE_ATTRIBUTE_DIRECTORY)	delfiles += ForceDeleteSubdir(dirpattern);
				else					delfiles += ForceDelete(dirpattern);
			}
		});
		SMARTLIST_FOREACH(objdir, char *, fn, tor_free(fn));
		smartlist_free(objdir);
	}
	LPWSTR tmp = get_unicode(dirname);
	i = RemoveDirectoryW(tmp);
	if(!i)
	{	init_nt_functions();
		if(CaNtDeleteFile(dirname))
		{	close_all_handles(dirname);
			if(CaNtDeleteFile(dirname))
				i = RemoveDirectoryW(tmp);
			else	i = 1;
		}
		else i = 1;
	}
	tor_free(tmp);
	tor_free(dirpattern);
	if(i)	log(LOG_INFO,LD_APP,"ForceDelete(): the directory %s was deleted successfully",dirname);
	else	log(LOG_INFO,LD_APP,"ForceDelete(): could not delete the directory %s",dirname);
	return delfiles;
}

smartlist_t *list_modules(DWORD pid)
{	init_kernel_functions();
	if(!CreateToolhelp32Snapshot)	return NULL;
	MODULEENTRY32W *modEntry = tor_malloc(sizeof(MODULEENTRY32W));
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
	smartlist_t *modules = NULL;
	if((DWORD)hSnapshot != (DWORD)-1)
	{	modEntry->dwSize = sizeof(MODULEENTRY32W);
		if(Module32FirstW(hSnapshot,modEntry))
		{	modules = smartlist_create();
			smartlist_add(modules,get_utf(modEntry->szExePath));
			modEntry->dwSize = sizeof(MODULEENTRY32W);
			while(Module32NextW(hSnapshot,modEntry))
			{	modEntry->dwSize = sizeof(MODULEENTRY32W);
				smartlist_add(modules,get_utf(modEntry->szExePath));
			}
		}
		CloseHandle(hSnapshot);
	}
	tor_free(modEntry);
	return modules;
}

void GetModuleBaseEx(DWORD pid,const char *module,BYTE **result,DWORD *rsize)
{	init_kernel_functions();
	if(!CreateToolhelp32Snapshot)	return;
	char *modname;
	MODULEENTRY32W *modEntry = tor_malloc(sizeof(MODULEENTRY32W));
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
	if((DWORD)hSnapshot != (DWORD)-1)
	{	modEntry->dwSize = sizeof(MODULEENTRY32W);
		if(Module32FirstW(hSnapshot,modEntry))
		{	modname = get_utf(modEntry->szModule);
			if(!strcasecmpstart(modname,module))
			{	tor_free(modname);
				*result = modEntry->modBaseAddr;
				*rsize = modEntry->modBaseSize;
				tor_free(modEntry);
				CloseHandle(hSnapshot);
				return;
			}
			tor_free(modname);
			modEntry->dwSize = sizeof(MODULEENTRY32W);
			while(Module32NextW(hSnapshot,modEntry))
			{	modname = get_utf(modEntry->szModule);
				modEntry->dwSize = sizeof(MODULEENTRY32W);
				if(!strcasecmpstart(modname,module))
				{	tor_free(modname);
					*result = modEntry->modBaseAddr;
					*rsize = modEntry->modBaseSize;
					tor_free(modEntry);
					CloseHandle(hSnapshot);
					return;
				}
				tor_free(modname);
			}
		}
		CloseHandle(hSnapshot);
	}
	tor_free(modEntry);
}

void GetModuleNameA(uint32_t addr,char *str)
{	MODULEENTRY32 modEntry;
	init_kernel_functions();
	if(!CreateToolhelp32Snapshot)	return;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetCurrentProcessId());
	if((DWORD)hSnapshot != (DWORD)-1)
	{	modEntry.dwSize = sizeof(MODULEENTRY32);
		if(Module32FirstA(hSnapshot,&modEntry))
		{	if((uint32_t)modEntry.modBaseAddr <= addr && ((uint32_t)modEntry.modBaseAddr + modEntry.modBaseSize) > addr)
				strcpy(str,modEntry.szModule);
			else
			{	modEntry.dwSize = sizeof(MODULEENTRY32);
				while(Module32NextA(hSnapshot,&modEntry))
				{	if((uint32_t)modEntry.modBaseAddr <= addr && ((uint32_t)modEntry.modBaseAddr + modEntry.modBaseSize) > addr)
					{	strcpy(str,modEntry.szModule);
						break;
					}
					modEntry.dwSize = sizeof(MODULEENTRY32);
				}
			}
		}
		CloseHandle(hSnapshot);
	}
}

HANDLE thread_list_init(DWORD pid)
{	HANDLE h;
	init_kernel_functions();
	if(!CreateToolhelp32Snapshot)	return NULL;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,pid);
	if(h == NULL || h == (HANDLE)-1)	return NULL;
	return h;
}

void thread_list_close(HANDLE h)
{
	CloseHandle(h);
}

DWORD thread_list_get(DWORD lastid,DWORD pid,HANDLE hList)
{	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	while(1)
	{	if(lastid==0)
		{	if(!Thread32First(hList,&te32))	return 0;}
		else	if(!Thread32Next(hList,&te32))	return 0;
		if(te32.th32OwnerProcessID == pid)
			return te32.th32ThreadID;
		lastid = 1;
	}
	return 0;
}

HANDLE open_thread(DWORD a,BOOL b,DWORD c)
{
	if(!OpenThread)
		init_kernel_functions();
	if(OpenThread)
		return OpenThread(a,b,c);
	return NULL;
}

BOOL suspend_process(DWORD pid)
{	init_nt_functions();
	if(NtSuspendProcess)
	{
		HANDLE h = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
		if(!h)	return 0;
		if(NtSuspendProcess(h))
		{	CloseHandle(h);
			return 1;
		}
		CloseHandle(h);
	}
	return 0;
}

void resume_process(DWORD pid)
{
	if(!NtResumeProcess)
		init_nt_functions();
	if(NtResumeProcess)
	{
		HANDLE h = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
		if(h)
		{	NtResumeProcess(h);
			CloseHandle(h);
		}
	}
}
