#include "or.h"

typedef enum
{	AddrMode1616,
	AddrMode1632,
	AddrModeReal,
	AddrModeFlat
} ADDRESS_MODE; 

typedef struct err_str_info
{	uint32_t errcode;
	const char *errStr;
} err_str_info;

typedef struct _tagADDRESS
{	DWORD Offset;
	WORD Segment;
	ADDRESS_MODE Mode;
} ADDRESS,*LPADDRESS;

typedef struct _KDHELP
{	DWORD Thread;
	DWORD ThCallbackStack;
	DWORD NextCallback;
	DWORD FramePointer;
	DWORD KiCallUserMode;
	DWORD KeUserCallbackDispatcher;
	DWORD SystemRangeStart;
} KDHELP,*PKDHELP;

typedef struct _tagSTACKFRAME
{	ADDRESS AddrPC; 
	ADDRESS AddrReturn; 
	ADDRESS AddrFrame; 
	ADDRESS AddrStack; 
	LPVOID FuncTableEntry; 
	DWORD Params[4]; 
	BOOL Far; 
	BOOL Virtual; 
	DWORD Reserved[3];
	KDHELP KdHelp;
} STACKFRAME,*LPSTACKFRAME; 

typedef struct _ADDRESS64
{	uint64_t Offset;
	WORD Segment;
	ADDRESS_MODE Mode;
} ADDRESS64,*LPADDRESS64;

typedef struct _KDHELP64
{	uint64_t Thread;
	DWORD ThCallbackStack;
	DWORD ThCallbackBStore;
	DWORD NextCallback;
	DWORD FramePointer;
	uint64_t KiCallUserMode;
	uint64_t KeUserCallbackDispatcher;
	uint64_t SystemRangeStart;
	uint64_t Reserved[8];
} KDHELP64,*PKDHELP64;

typedef struct _STACKFRAME64
{	ADDRESS64 AddrPC;
	ADDRESS64 AddrReturn;
	ADDRESS64 AddrFrame;
	ADDRESS64 AddrStack;
	ADDRESS64 AddrBStore;
	PVOID FuncTableEntry;
	uint64_t Params[4];
	BOOL Far;
	BOOL Virtual;
	uint64_t Reserved[3];
	KDHELP64 KdHelp;
} STACKFRAME64,*LPSTACKFRAME64;

typedef BOOL (WINAPI *_StackWalk)(DWORD,HANDLE,HANDLE,LPSTACKFRAME,LPVOID,LPVOID,LPVOID,LPVOID,LPVOID);
typedef BOOL (WINAPI *_StackWalk64)(DWORD,HANDLE,HANDLE,LPSTACKFRAME64,LPVOID,LPVOID,LPVOID,LPVOID,LPVOID);

void init_seh(void);
void restore_seh(void);
