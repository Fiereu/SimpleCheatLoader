#include <Windows.h>
#include <iostream>

#include "Packer.h"

int main(int argc, char** argv)
{
	if (argc != 5) {
		printf("[-] Invalid Arguments\nUse: Builder.exe <Process> <Stub-Path> <DLL-Path> <Out>");
		return 1;
	}
	
	printf("[~] Target: %s\n", argv[1]);
	printf("[~] Stub: %s\n", argv[2]);
	printf("[~] DLL: %s\n", argv[3]);
	printf("[~] OUT: %s\n", argv[4]);
	PackDll(argv[1], argv[2], argv[3], argv[4]);
}