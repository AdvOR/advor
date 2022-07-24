@echo off
gcc -c -enable-stdcall-fixup HiddenMessage.c -o HiddenMessage.o
gcc -shared -enable-stdcall-fixup HiddenMessage.o HiddenMessage.def -o HiddenMessage.dll
if exist HiddenMessage.dll strip HiddenMessage.dll
if exist HiddenMessage.dll copy /y HiddenMessage.dll ..