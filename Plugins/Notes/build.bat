@echo off
windres rsrc.rc -o rsrc.o
gcc -c -enable-stdcall-fixup Notes.c -o Notes.o
gcc -shared -enable-stdcall-fixup Notes.o rsrc.o Notes.def -o Notes.dll
if exist Notes.dll strip Notes.dll
if exist rsrc.o del rsrc.o
if exist Notes.dll copy /y Notes.dll ..