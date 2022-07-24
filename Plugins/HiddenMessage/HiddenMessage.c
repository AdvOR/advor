#include <windows.h>
#include "plugins.h"

char *message="HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 71\r\n\r\n<HTML><HEAD><TITLE>Test</TITLE></HEAD><BODY><H1>Test</H1></BODY></HTML>";

BOOL __stdcall DllMain(HANDLE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{	return 1;
}

int __stdcall AdvTor_InitPlugin(HANDLE plugin_instance,DWORD version,char *plugin_description,void *function_table)
{	InitPlugin
	strcpy(plugin_description,"Hidden Service example plugin");
	return 1;
}

int __stdcall AdvTor_UnloadPlugin(int reason)
{	return 1;
}

BOOL __stdcall HiddenService_HandleRead(char *onion_address,DWORD client_id,char *buffer,int buffer_size,LPARAM *lParam)
{	if((buffer_size > 3) && !strnicmp(buffer,"GET",3))
		hs_send_reply(client_id,message,strlen(message));
	return 1;
}
