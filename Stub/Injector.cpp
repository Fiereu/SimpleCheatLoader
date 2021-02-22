#include "Injector.h"


void __stdcall ShellCode(ManualMappingData* pData)
{
	if (!pData)
		return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOptHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	f_LoadLibraryA _LoadLibraryA = pData->pLoadLibraryA;
	f_GetProcAddress _GetProcAddress = pData->pGetProcAddress;
	f_DLL_ENTRY_POINT _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptHeader->AddressOfEntryPoint);
	f_RtlAddFunctionTable _RtlAddFunctionTable = pData->pRtlAddFunctionTable;

	BYTE* LocationDelta = pBase - pOptHeader->ImageBase;

	if (LocationDelta) {

		if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return;
		}

		auto* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT Entries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativInfo = (WORD*)(pRelocData + 1);

			for (UINT i = 0; i != Entries; ++i, ++pRelativInfo)
			{
				if (RELOCFLAG(*pRelativInfo)) {
					UINT_PTR* pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativInfo) & 0xFFF));
					*pPatch += (UINT_PTR)(LocationDelta);
				}
			}
			pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData)+pRelocData->SizeOfBlock);
		}
	}

	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

		auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* Mod = (char*)(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(Mod);

			ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);
			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}
			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}

	}

	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
	{
		auto pTLS = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		if (pTLS) {
			DWORD Count = (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1;
			if (Count) {
				_RtlAddFunctionTable(pTLS, Count, (DWORD64)pBase);
			}
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = (HINSTANCE)pBase;
	pData->Status = 1;
}

int GetProcessId(const char* name)
{
	DWORD pid = -1;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			_bstr_t b(entry.szExeFile);
			
			if (_stricmp(b, name) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				BOOL Is32Bit;
				IsWow64Process(hProcess, &Is32Bit);
#ifdef _WIN64
				if (Is32Bit)
					return -2;
#elif _WIN32
				if (!Is32Bit)
					return -2;
#endif
				pid = GetProcessId(hProcess);
				CloseHandle(hProcess);
				return pid;
			}
		}
	}
	CloseHandle(snapshot);
	return pid;
}

void Injector(PE Dll, const char* target)
{
	int pid = -1;
	while (pid == -1)
	{
		pid = GetProcessId(target);
		if (pid == -2)
		{
			return;
		}
	}
	printf("Process: \t\t%d\n", pid);

	if (!Dll.isValid())
	{
		printf("Invalid Dll found!!!\n");
		ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
		printf("Invalid Dll found!!!\n");
		return;
	}

#ifdef _WIN64
	if (Dll.getFileHeader()->Machine != IMAGE_FILE_MACHINE_AMD64) {
		ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
		return;
	}
#elif _WIN32
	if (Dll.getFileHeader()->Machine != IMAGE_FILE_MACHINE_I386) {
		ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
		printf("Invalid Arch-Type!!!\n");
		return;
	}
#endif

	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	printf("Opened Process\n");
	ULONG NewImageBase = (ULONG)VirtualAllocEx(hTarget, (void*)Dll.getOptHeader()->ImageBase, Dll.getOptHeader()->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NewImageBase)
	{
		NewImageBase = (ULONG)VirtualAllocEx(hTarget, NULL, Dll.getOptHeader()->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!NewImageBase)
		{
			CloseHandle(hTarget);
			ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
			return;
		}
	}
	ManualMappingData data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = (f_GetProcAddress)GetProcAddress;
	data.Status = 0;
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(Dll.getNTHeader());
	for (UINT i = 0; i != Dll.getFileHeader()->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hTarget, (LPVOID)(NewImageBase + pSectionHeader->VirtualAddress), (LPVOID)(Dll.getLocation() + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, nullptr))
			{
				CloseHandle(hTarget);
				ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
				VirtualFreeEx(hTarget, (LPVOID)(NewImageBase), 0, MEM_RELEASE);
				return;
			}
		}
	}

	memcpy_s((void*)Dll.getLocation(), Dll.getOptHeader()->SizeOfImage, &data, sizeof(data));
	WriteProcessMemory(hTarget, (LPVOID)NewImageBase, (void*)Dll.getLocation(), 0x1000, nullptr);
	printf("New Dll Image Base: \t0x%X\n", NewImageBase);

	void* pShellcode = VirtualAllocEx(hTarget, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		CloseHandle(hTarget);
		ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
		VirtualFreeEx(hTarget, (LPVOID)NewImageBase, 0, MEM_RELEASE);
		return;
	}

	WriteProcessMemory(hTarget, pShellcode, ShellCode, 0x1000, nullptr);
	printf("Shellcode at: \t\t0x%X\n", pShellcode);
	
	HANDLE hThread = CreateRemoteThread(hTarget, nullptr, 0, (LPTHREAD_START_ROUTINE)(pShellcode), (LPVOID)NewImageBase, 0, nullptr);
	if (!hThread) {
		CloseHandle(hTarget);
		ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
		VirtualFreeEx(hTarget, (LPVOID)NewImageBase, 0, MEM_RELEASE);
		VirtualFreeEx(hTarget, pShellcode, 0, MEM_RELEASE);
		return;
	}
	
	CloseHandle(hThread);
	int status = 0;
	while (status == 0)
	{
		ManualMappingData data_checked{ 0 };
		ReadProcessMemory(hTarget, (LPVOID)NewImageBase, &data_checked, sizeof(data_checked), nullptr);
		status = data_checked.Status;
	};
	
	VirtualFreeEx(hTarget, pShellcode, 0, MEM_RELEASE);
	CloseHandle(hTarget);
	ZeroMemory((void*)Dll.getLocation(), Dll.getSize());
	return;
}