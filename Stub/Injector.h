#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <iostream>  
#include <fstream>
#include <winnt.h>
#include "PE.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOCFLAG RELOC_FLAG64
#elif _WIN32
#define RELOCFLAG RELOC_FLAG32
#endif

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(void* FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

struct ManualMappingData
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	f_RtlAddFunctionTable pRtlAddFunctionTable;
	HINSTANCE hMod;
	int Status;
};

void __stdcall ShellCode(ManualMappingData* pData);
int GetProcessId(const char* name);
void Injector(PE Dll, const char* target);