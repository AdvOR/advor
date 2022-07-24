#ifndef __FILE_IO_H
#define __FILE_IO_H 1

#define MAX_PASSWORD_SIZE 4096

// undefine this to xor compressed data with a random sized buffer filled with strong random data before encrypting with AES
//#define RANDOMIZE_ENCRYPTION 1

void alloc_password(void);
void free_password(void);

//#define DATADIR_BW_ACCOUNTING "bw_accounting"
#define DATADIR_UNVERIFIED_CONSENSUS "unverified-consensus"
#define DATADIR_CACHED_CONSENSUS "cached-consensus"
#define DATADIR_CACHED_STATUS "cached-status"
#define DATADIR_CACHED_CERTS "cached-certs"
#define DATADIR_CACHED_DESCRIPTORS "cached-descriptors"
#define DATADIR_CACHED_DESCRIPTORS_NEW "cached-descriptors.new"
#define DATADIR_CACHED_ROUTERS "cached-routers"
#define DATADIR_CACHED_EXTRAINFO "cached-extrainfo"
#define DATADIR_CONTROL_AUTH_COOKIE "control_auth_cookie"
#define DATADIR_APPROVED_ROUTERS "approved-routers"
#define DATADIR_V3_STATUS_VOTES "v3-status-votes"
#define DATADIR_NETWORKSTATUS_BRIDGES "networkstatus-bridges"
#define DATADIR_KEYS_SECRET_ONION_KEY "keys-secret_onion_key"
#define DATADIR_KEYS_SECRET_ONION_KEY_OLD "keys-secret_onion_key.old"
#define DATADIR_KEYS_LEGACY_SIGNING_KEY "keys-legacy_signing_key"
#define DATADIR_KEYS_AUTHORITY_SIGNING_KEY "keys-authority_signing_key"
#define DATADIR_KEYS_LEGACY_CERTIFICATE "keys-legacy_certificate"
#define DATADIR_KEYS_AUTHORITY_CERTIFICATE "keys-authority_certificate"
#define DATADIR_KEYS_SECRET_ID_KEY "keys-secret_id_key"
#define DATADIR_FINGERPRINT "fingerprint"
#define DATADIR_GEOIP_STATS "geoip-stats"
#define DATADIR_GEOIP_DIRREQ_STATS "dirreq-stats"
#define DATADIR_GEOIP_BRIDGE_STATS "bridge-stats"
#define DATADIR_GEOIP_ENTRY_STATS "entry-stats"
#define DATADIR_GEOIP_EXIT_STATS "exit-stats"
#define DATADIR_BUFFER_STATS "buffer-stats"
#define DATADIR_ROUTER_STABILITY "router-stability"
#define DATADIR_UNPARSEABLE_DESC "unparseable-desc"
#define DATADIR_IPLIST "iplist.dat"
#define DATADIR_HSUSAGE "hsusage"
#define DATADIR_PLUGINS "plugins"

void unload_all_files(void);
void load_all_files(void);
void delete_all_files(void);
void delete_dat_file(void);

/** Return values from file_status(); see that function's documentation for details. */
typedef enum { FN_ERROR, FN_NOENT, FN_FILE, FN_DIR } file_status_t;
file_status_t file_status(char *filename);

/** Possible behaviors for check_private_dir() on encountering a nonexistent directory; see that function's documentation for details. */
#define OPEN_FLAGS_REPLACE (O_WRONLY|O_CREAT|O_TRUNC)

typedef struct file_info_t
{	struct file_info_t *next;
	char *filename;
	char *filedata;
	time_t filetime;
	uint32_t filesize;
	uint32_t allocsize;
	uint32_t filepos;
} file_info_t;

/** Represents a file that we're writing to, with support for atomic commit: we can write into a a temporary file, and either remove the file on failure, or replace the original file on success. */
typedef struct open_file_t
{	char *tempname; /**< Name of the temporary file. */
	char *filename; /**< Name of the original file. */
	HANDLE hFile;
	file_info_t *mem_file;
} open_file_t;


int start_writing_to_file(char *fname,open_file_t **data_out);
int start_appending_to_file(char *fname,open_file_t **data_out);
int finish_writing_to_file(open_file_t *,int);
int write_str_to_file(const char *fname, const char *str, int bin);

/** An ad-hoc type to hold a string of characters and a count; used by write_chunks_to_file. */
typedef struct sized_chunk_t
{	const char *bytes;
	size_t len;
} sized_chunk_t;

int write_chunks_to_file(char *fname, struct smartlist_t *chunks,int bin);
int append_bytes_to_file(char *fname, char *str, size_t len,int bin);

struct stat;
#define RFTS_IGNORE_MISSING 1
#define RFTS_BIN 2
char *read_file_to_str(char *filename, int flags, struct stat *stat_out)
  ATTR_MALLOC;
char *expand_filename(const char *filename);
struct smartlist_t *tor_listdir(char *dirname);
struct smartlist_t *listdir(char *pattern);
int path_is_relative(const char *filename) ATTR_PURE;

/* ===== File compatibility */
int replace_file(char *from,char *to);

off_t tor_fd_getpos(int fd);
int tor_fd_seekend(int fd);

#define FILE_ACTION_CLOSE 1
#define FILE_ACTION_OVERWRITE 2

#ifdef MS_WINDOWS
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/** Represents an mmaped file. Allocated via tor_mmap_file; freed with tor_munmap_file. */
typedef struct tor_mmap_t
{	char *data; /**< Mapping of the file's contents. */
	size_t size; /**< Size of the file. */
	/* None of the fields below should be accessed from outside compat.c */
	file_info_t *file;
#ifdef HAVE_SYS_MMAN_H
	size_t mapping_size; /**< Size of the actual mapping. (This is this file size, rounded up to the nearest page.) */
#elif defined MS_WINDOWS
	HANDLE file_handle;
	HANDLE mmap_handle;
#endif
} tor_mmap_t;

tor_mmap_t *tor_mmap_file(char *filename) ATTR_NONNULL((1));
void tor_munmap_file(tor_mmap_t *handle) ATTR_NONNULL((1));
char *get_mmap_data(tor_mmap_t *map);
int write_buf_to_file(const char *filename,const char *buf,int bufsize);
int write_string_to_file(open_file_t *out,const char *str);
int write_buffer_to_file(open_file_t *file,char *str,int len);
int get_file_size(open_file_t *open_file);
int write_private_key_to_filename(crypto_pk_env_t *env,char *fname);
void delete_serv_files(char *key);
void remove_file_if_very_old(char *fname, time_t now);
int make_backup(char *fname);
int delete_file(char *fname);
void remove_datadir_file(char *str);
time_t get_file_time(char *fname);

char *get_datadir_fname2_suffix(const char *sub1,const char *sub2,const char *suffix);
#define get_datadir_fname(sub1) get_datadir_fname2_suffix((sub1),NULL,NULL)
#define get_datadir_fname_suffix(sub1,sub2) get_datadir_fname2_suffix((sub1),NULL,(sub2))

void read_configuration_data(void);
void flush_configuration_data(void);
void set_read_only(void);
int is_read_only(void);
void get_exe_name(char *dest);
HINSTANCE load_library(const char *fname);
HINSTANCE load_library_ex(const char *fname);
HINSTANCE get_module_handle(char *fname);
HANDLE find_first_file(char *pattern,LPWIN32_FIND_DATAW findData);
DWORD get_file_attributes(char *fname);
int file_exists(char *fname);
int ForceDelete(char *fname);
int ForceDeleteSubdir(char *dirname);
smartlist_t *list_modules(DWORD pid);
int overwrite_file(char *fname);
void GetModuleBaseEx(DWORD pid,const char *module,BYTE **result,DWORD *rsize);
void GetModuleNameA(uint32_t addr,char *str);
HANDLE thread_list_init(DWORD pid);
void thread_list_close(HANDLE h);
DWORD thread_list_get(DWORD lastid,DWORD pid,HANDLE hList);
HANDLE open_thread(DWORD a,BOOL b,DWORD c);
HANDLE open_file(const char *fname,DWORD access,DWORD creationDistribution);
BOOL suspend_process(DWORD pid);
void resume_process(DWORD pid);

#endif
