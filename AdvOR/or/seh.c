#include "seh.h"

LPTOP_LEVEL_EXCEPTION_FILTER lpOldFilter=NULL;
extern int encryption;
extern uint32_t *alloc_root;
extern HWND hMainDialog;
extern HINSTANCE hInstance;

err_str_info err_tbl[]={
{EXCEPTION_ACCESS_VIOLATION,"EXCEPTION_ACCESS_VIOLATION"},
{EXCEPTION_ARRAY_BOUNDS_EXCEEDED,"EXCEPTION_ARRAY_BOUNDS_EXCEEDED"},
{EXCEPTION_BREAKPOINT,"EXCEPTION_BREAKPOINT"},
{EXCEPTION_DATATYPE_MISALIGNMENT,"EXCEPTION_DATATYPE_MISALIGNMENT"},
{EXCEPTION_FLT_DENORMAL_OPERAND,"EXCEPTION_FLT_DENORMAL_OPERAND"},
{EXCEPTION_FLT_DIVIDE_BY_ZERO,"EXCEPTION_FLT_DIVIDE_BY_ZERO"},
{EXCEPTION_FLT_INEXACT_RESULT,"EXCEPTION_FLT_INEXACT_RESULT"},
{EXCEPTION_FLT_INVALID_OPERATION,"EXCEPTION_FLT_INVALID_OPERATION"},
{EXCEPTION_FLT_OVERFLOW,"EXCEPTION_FLT_OVERFLOW"},
{EXCEPTION_FLT_STACK_CHECK,"EXCEPTION_FLT_STACK_CHECK"},
{EXCEPTION_FLT_UNDERFLOW,"EXCEPTION_FLT_UNDERFLOW"},
{EXCEPTION_ILLEGAL_INSTRUCTION,"EXCEPTION_ILLEGAL_INSTRUCTION"},
{EXCEPTION_IN_PAGE_ERROR,"EXCEPTION_IN_PAGE_ERROR"},
{EXCEPTION_INT_DIVIDE_BY_ZERO,"EXCEPTION_INT_DIVIDE_BY_ZERO"},
{EXCEPTION_INT_OVERFLOW,"EXCEPTION_INT_OVERFLOW"},
{0xc0000026,"EXCEPTION_INVALID_DISPOSITION"},
{EXCEPTION_NONCONTINUABLE,"EXCEPTION_NONCONTINUABLE"},
{EXCEPTION_PRIV_INSTRUCTION,"EXCEPTION_PRIV_INSTRUCTION"},
{EXCEPTION_SINGLE_STEP,"EXCEPTION_SINGLE_STEP"},
{0xc00000fd,"EXCEPTION_STACK_OVERFLOW"},
{0,0}
};

const WCHAR txtFilter[]=L"Text files\0*.txt\0All files\0*.*\0\0";

void show_reg_info(uint32_t value,const char *regname,char *str,int len);
#ifdef DEBUG_MALLOC
void tor_memdump(HANDLE hFile,char *buffer);
#endif
LONG __stdcall exception_filter(struct _EXCEPTION_POINTERS *ExceptionInfo)  __attribute__((noreturn));

#define PAGE_READ (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY)
#define PAGE_WRITE (PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)
#define PAGE_EXEC (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)

void show_reg_info(uint32_t value,const char *regname,char *str,int len)
{	MEMORY_BASIC_INFORMATION m;
	unsigned int i;
	unsigned char *mem;
	tor_snprintf(str,len,"\r\n\t[%s]: ",regname);
	len -= strlen(str);
	str += strlen(str);
	VirtualQuery((LPCVOID)value,&m,32);
	if(m.State == MEM_FREE)
		tor_snprintf(str,len,"FREE: %08X, len: %08X",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
	else if(m.State == MEM_RESERVE)
		tor_snprintf(str,len,"RESERVED: %08X, len: %08X",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
	else if(m.State == MEM_COMMIT)
	{	tor_snprintf(str,len,"[%s%s%s%s]: %08X, len: %08X",(m.AllocationProtect&(PAGE_READ))!=0?"R":"",(m.AllocationProtect&(PAGE_WRITE))!=0?"W":"",(m.AllocationProtect&(PAGE_EXEC))!=0?"X":"",(m.AllocationProtect&(PAGE_EXEC|PAGE_READ|PAGE_WRITE))!=0?"":"No access",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
		if((m.AllocationProtect&(PAGE_READ))!=0)
		{	len -= strlen(str);
			str += strlen(str);
			if(m.RegionSize >= 32)	m.RegionSize = 32;
			mem = (unsigned char *)value;
			tor_snprintf(str,len," [");
			len -= strlen(str);
			str += strlen(str);
			for(i=0;i<m.RegionSize;i++)
			{	tor_snprintf(str,len," %02X",mem[i]);
				len -= strlen(str);
				str += strlen(str);
			}
			tor_snprintf(str,len," ]");
		}
	}
	else	tor_snprintf(str,len,"Unknown state: %08X, len: %08X",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
	len -= strlen(str);
	str += strlen(str);
}

#ifdef DEBUG_MALLOC
void tor_memdump(HANDLE hFile,char *buffer)
{	uint32_t *md,*mdprev;
	MEMORY_BASIC_INFORMATION m;
	DWORD d;
	md = mdprev = alloc_root;
	while(md)
	{	VirtualQuery((LPCVOID)md,&m,32);
		if(m.State == MEM_FREE)
		{	tor_snprintf(buffer,2048,"FREE: %08X, len: %08X\r\n",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
			WriteFile(hFile,buffer,strlen(buffer),&d,NULL);
			break;
		}
		else if(m.State == MEM_RESERVE)
		{	tor_snprintf(buffer,2048,"RESERVED: %08X, len: %08X\r\n",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
			WriteFile(hFile,buffer,strlen(buffer),&d,NULL);
			break;
		}
		else if(m.State == MEM_COMMIT)
		{	if((m.AllocationProtect&(PAGE_READ))!=0)
			{
#ifdef MALLOC_SENTINELS
				unsigned char *c;
				c = (unsigned char *)md;
				c += md[4] + 20;
				if(*(uint32_t *)c != 0x55aa1234)
				{	tor_snprintf(buffer,2048,"[%08X:%i] %08X[%08X] ([%s%s%s%s]: %08X, len: %08X)\r\n",md[2],md[3],(uint32_t)md,md[4],(m.AllocationProtect&(PAGE_READ))!=0?"R":"",(m.AllocationProtect&(PAGE_WRITE))!=0?"W":"",(m.AllocationProtect&(PAGE_EXEC))!=0?"X":"",(m.AllocationProtect&(PAGE_EXEC|PAGE_READ|PAGE_WRITE))!=0?"":"No access",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
					tor_snprintf(buffer,2048,"\tPrevious: [%08X:%i] %08X[%08X]\r\n",mdprev[2],mdprev[3],(uint32_t)mdprev,mdprev[4]);
					WriteFile(hFile,buffer,strlen(buffer),&d,NULL);
					tor_snprintf(buffer,2048,"\tSentinel overwritten with %08X\r\n",*(uint32_t *)c);
					WriteFile(hFile,buffer,strlen(buffer),&d,NULL);
				}
#endif
			}
			else
			{	tor_snprintf(buffer,2048,"No read access: %08X, len: %08X\r\n",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
				WriteFile(hFile,buffer,strlen(buffer),&d,NULL);
				break;
			}
		}
		else	tor_snprintf(buffer,2048,"Unknown state: %08X, len: %08X",(uint32_t)m.BaseAddress,(uint32_t)m.RegionSize);
		mdprev = md;
		md = (uint32_t*)md[1];
	}
}
#endif

LONG __stdcall exception_filter(struct _EXCEPTION_POINTERS *ExceptionInfo)
{	char errstr[8192];
	int errstrlen = 0;
	uint32_t tmp;
	unsigned int i;
	tmp = ExceptionInfo->ExceptionRecord->ExceptionCode;
	tor_snprintf(&errstr[0],200,"\r\nBIG FUCKING ERROR %08X\r\nAdvOR version: %s",tmp,advtor_ver);
	errstrlen += strlen(errstr);
	for(i=0;err_tbl[i].errcode;i++)
	{	if(err_tbl[i].errcode == tmp)
		{	tor_snprintf(&errstr[errstrlen],200,"\r\n\tException code: %s",err_tbl[i].errStr);
			break;
		}
	}
	if(!err_tbl[i].errcode)
		tor_snprintf(&errstr[errstrlen],200,"\r\n\tException code: %08X",tmp);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\tAddress: %08X",(uint32_t)ExceptionInfo->ExceptionRecord->ExceptionAddress);
	errstrlen += strlen(errstr+errstrlen);
	if(tmp == EXCEPTION_ACCESS_VIOLATION)
	{	tor_snprintf(&errstr[errstrlen],200,"\r\n\tCause: %s address: %08X",ExceptionInfo->ExceptionRecord->ExceptionInformation[0]?"Write to":"Read from",(uint32_t)ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
		errstrlen += strlen(errstr+errstrlen);
	}
	else
	{	tor_snprintf(&errstr[errstrlen],200,"\r\n\tParameters: ");
		errstrlen += strlen(errstr+errstrlen);
		i = 0;
		while(i < ExceptionInfo->ExceptionRecord->NumberParameters)
		{	tor_snprintf(&errstr[errstrlen],200,"%s%08X",i?" , ":"",(uint32_t)ExceptionInfo->ExceptionRecord->ExceptionInformation[i]);
			errstrlen += strlen(errstr+errstrlen);
			i++;
		}
	}
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tEAX=%08X\tEBX=%08X\tECX=%08X\tEDX=%08X",(uint32_t)ExceptionInfo->ContextRecord->Eax,(uint32_t)ExceptionInfo->ContextRecord->Ebx,(uint32_t)ExceptionInfo->ContextRecord->Ecx,(uint32_t)ExceptionInfo->ContextRecord->Edx);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tESI=%08X\tEDI=%08X\tEBP=%08X\tESP=%08X",(uint32_t)ExceptionInfo->ContextRecord->Esi,(uint32_t)ExceptionInfo->ContextRecord->Edi,(uint32_t)ExceptionInfo->ContextRecord->Ebp,(uint32_t)ExceptionInfo->ContextRecord->Esp);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tDR0=%08X\tDR1=%08X\tDR2=%08X\tDR3=%08X",(uint32_t)ExceptionInfo->ContextRecord->Dr0,(uint32_t)ExceptionInfo->ContextRecord->Dr1,(uint32_t)ExceptionInfo->ContextRecord->Dr2,(uint32_t)ExceptionInfo->ContextRecord->Dr3);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tDR6=%08X\tDR7=%08X\tFS =%08X\tGS =%08X",(uint32_t)ExceptionInfo->ContextRecord->Dr6,(uint32_t)ExceptionInfo->ContextRecord->Dr7,(uint32_t)ExceptionInfo->ContextRecord->SegFs,(uint32_t)ExceptionInfo->ContextRecord->SegGs);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tCS =%08X\tDS =%08X\tES =%08X\tSS =%08X",(uint32_t)ExceptionInfo->ContextRecord->SegCs,(uint32_t)ExceptionInfo->ContextRecord->SegDs,(uint32_t)ExceptionInfo->ContextRecord->SegEs,(uint32_t)ExceptionInfo->ContextRecord->SegSs);
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\t\tEIP=%08X\tEFlags=%08X\r\n",(uint32_t)ExceptionInfo->ContextRecord->Eip,(uint32_t)ExceptionInfo->ContextRecord->EFlags);
	errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Eax,"EAX",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Ebx,"EBX",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Ecx,"ECX",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Edx,"EDX",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Esi,"ESI",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Edi,"EDI",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Ebp,"EBP",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Esp,"ESP",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	show_reg_info(ExceptionInfo->ContextRecord->Eip,"EIP",&errstr[errstrlen],8192-errstrlen);errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],200,"\r\n\r\n\tModule: ");
	errstrlen += strlen(errstr+errstrlen);
	GetModuleNameA((uint32_t)ExceptionInfo->ExceptionRecord->ExceptionAddress,&errstr[errstrlen]);
	if(errstr[errstrlen]==0)	tor_snprintf(&errstr[errstrlen],200,"unknown");
	errstrlen += strlen(errstr+errstrlen);
	tor_snprintf(&errstr[errstrlen],5,"\r\n\r\n");
	errstrlen += 4;
	tor_snprintf(&errstr[errstrlen],200,"\r\n\r\nDo you want to save a crash report ?");
	if(MessageBox(0,errstr,"Advanced Onion Router " advtor_ver " - Error",MB_YESNO)==IDYES)
	{	errstr[errstrlen] = 0;
		HANDLE hFile;
		if(encryption || (hFile = CreateFile("AdvOR-crash.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,0,NULL))==INVALID_HANDLE_VALUE)
		{	OPENFILENAMEW ofn;
			LPWSTR fileName;
			ZeroMemory(&ofn,sizeof(ofn));
			ofn.lStructSize=sizeof(ofn);
			ofn.hwndOwner=hMainDialog;
			ofn.hInstance=hInstance;
			ofn.lpstrFilter=txtFilter;
			fileName=tor_malloc(8192);fileName[0]=0;
			ofn.lpstrFile=fileName;
			ofn.nMaxFile=4095;
			ofn.Flags=OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST;
			if(GetSaveFileNameW(&ofn) == 0)	hFile = INVALID_HANDLE_VALUE;
			else	hFile = CreateFileW(fileName,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);
			tor_free(fileName);
		}
		if(hFile != INVALID_HANDLE_VALUE)
		{	DWORD written;
			SetFilePointer(hFile,0,NULL,FILE_END);
			WriteFile(hFile,errstr,errstrlen,&written,NULL);
			HANDLE hDbgHelp = GetModuleHandle("dbghelp.dll");
			if(!hDbgHelp)	hDbgHelp = LoadLibrary("dbghelp.dll");
			_StackWalk64 StackWalk64 = NULL;
			if(hDbgHelp)	StackWalk64 = GetProcAddress(hDbgHelp,"StackWalk64");
			HANDLE hImagehlp = GetModuleHandle("imagehlp.dll");
			if(!hImagehlp)	hImagehlp = LoadLibrary("imagehlp.dll");
			_StackWalk StackWalk = NULL;
			LPVOID SymFunctionTableAccess=NULL,SymGetModuleBase=NULL;
			if(hImagehlp)
			{	StackWalk = GetProcAddress(hImagehlp,"StackWalk");
				SymFunctionTableAccess = GetProcAddress(hImagehlp,"SymFunctionTableAccess");
				SymGetModuleBase = GetProcAddress(hImagehlp,"SymGetModuleBase");
				i = 0;
				if(StackWalk64)
				{	STACKFRAME64 callStack;
					HANDLE hProcess = GetCurrentProcess();
					HANDLE hThread = GetCurrentThread();
					ZeroMemory(&callStack,sizeof(callStack));
					callStack.AddrPC.Offset = ExceptionInfo->ContextRecord->Eip;
					callStack.AddrPC.Mode = AddrModeFlat;
					callStack.AddrStack.Offset = ExceptionInfo->ContextRecord->Esp;
					callStack.AddrStack.Mode = AddrModeFlat;
					callStack.AddrFrame.Offset = ExceptionInfo->ContextRecord->Ebp;
					callStack.AddrFrame.Mode = AddrModeFlat;
					while(1)
					{	if(!StackWalk64(IMAGE_FILE_MACHINE_I386,hProcess,hThread,&callStack,NULL,NULL,NULL,NULL,NULL) || callStack.AddrFrame.Offset==0)
							break;
						errstr[7000]=0;
						GetModuleNameA((uint32_t)(uint32_t)callStack.AddrPC.Offset,&errstr[7000]);
						if(errstr[7000]==0)	tor_snprintf(&errstr[7000],200,"unknown");
						tor_snprintf(errstr,8191,"[%s] %s%sPC=%08X, Return = %08X, SP=%08X, Params: %08X, %08X, %08X, %08X\r\n",&errstr[7000],callStack.Far?"[Far] ":"",callStack.Virtual?"[Virtual] ":"",(uint32_t)callStack.AddrPC.Offset,(uint32_t)callStack.AddrReturn.Offset,(uint32_t)callStack.AddrStack.Offset,(uint32_t)callStack.Params[0],(uint32_t)callStack.Params[1],(uint32_t)callStack.Params[2],(uint32_t)callStack.Params[3]);
						WriteFile(hFile,errstr,strlen(errstr),&written,NULL);
						i++;
					}
				}
				if(i < 2 && StackWalk && SymFunctionTableAccess && SymGetModuleBase)
				{	STACKFRAME callStack;
					HANDLE hProcess = GetCurrentProcess();
					HANDLE hThread = GetCurrentThread();
					ZeroMemory(&callStack,sizeof(callStack));
					callStack.AddrPC.Offset = ExceptionInfo->ContextRecord->Eip;
					callStack.AddrPC.Mode = AddrModeFlat;
					callStack.AddrStack.Offset = ExceptionInfo->ContextRecord->Esp;
					callStack.AddrStack.Mode = AddrModeFlat;
					callStack.AddrFrame.Offset = ExceptionInfo->ContextRecord->Ebp;
					callStack.AddrFrame.Mode = AddrModeFlat;
					while(1)
					{	if(!StackWalk(IMAGE_FILE_MACHINE_I386,hProcess,hThread,&callStack,NULL,NULL,SymFunctionTableAccess,SymGetModuleBase,NULL) || callStack.AddrFrame.Offset==0)
							break;
						errstr[7000]=0;
						GetModuleNameA((uint32_t)(uint32_t)callStack.AddrPC.Offset,&errstr[7000]);
						if(errstr[7000]==0)	tor_snprintf(&errstr[7000],200,"unknown");
						tor_snprintf(&errstr[0],8191,"[%s] %s%sPC=%08X, Return = %08X, SP=%08X, Params: %08X, %08X, %08X, %08X\r\n",&errstr[7000],callStack.Far?"[Far] ":"",callStack.Virtual?"[Virtual] ":"",(uint32_t)callStack.AddrPC.Offset,(uint32_t)callStack.AddrReturn.Offset,(uint32_t)callStack.AddrStack.Offset,(uint32_t)callStack.Params[0],(uint32_t)callStack.Params[1],(uint32_t)callStack.Params[2],(uint32_t)callStack.Params[3]);
						WriteFile(hFile,errstr,strlen(errstr),&written,NULL);
					}
				}
			}
#ifdef DEBUG_MALLOC
			tor_snprintf(errstr,100,"\r\n\r\n");
			WriteFile(hFile,errstr,strlen(errstr),&written,NULL);
			tor_memdump(hFile,errstr);
#endif
			tor_snprintf(errstr,100,"\r\n------------------------\r\n\r\n");
			WriteFile(hFile,errstr,strlen(errstr),&written,NULL);
			CloseHandle(hFile);
		}
	}
	// ExitProcess no longer works with some OpenSSL setups
	TerminateProcess(GetCurrentProcess(),0);
	ExitProcess(0);
//	return EXCEPTION_CONTINUE_SEARCH;
}

void init_seh(void)
{	lpOldFilter = SetUnhandledExceptionFilter(&exception_filter);
}

void restore_seh(void)
{	SetUnhandledExceptionFilter(lpOldFilter);
}
