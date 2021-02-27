#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include "Crypt.h"

/*
MIT License

Copyright(c) 2020 Fiereu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this softwareand associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright noticeand this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

class PE
{
public:
	PE(const char* path);
	PE(DWORD Address, DWORD Size);
	~PE();
	bool isLoaded();
	bool isValid();
	bool is64Bit();
	DWORD getLocation();
	DWORD getSize();
	void setSize(DWORD size);
	IMAGE_DOS_HEADER* getDOSHeader();
	IMAGE_NT_HEADERS* getNTHeader();
	IMAGE_OPTIONAL_HEADER* getOptHeader();
	IMAGE_FILE_HEADER* getFileHeader();
	IMAGE_SECTION_HEADER* getSectionHeaderAt(int index);
	IMAGE_SECTION_HEADER* getSectionHeader();
	DWORD getDOSHeaderAddress();
	DWORD getNTHeaderAddress();
	DWORD getOptHeaderAddress();
	DWORD getAddressOfEntryPoint();
	DWORD getSectionHeaderAddress();
	DWORD getSectionHeaderSize();
	DWORD getSectionCount();
	DWORD insertBytes(DWORD offset, BYTE* data, DWORD size);
	DWORD patchBytes(DWORD offset, BYTE* data, DWORD size);
	DWORD addSection(IMAGE_SECTION_HEADER sectionHeader, BYTE* sectionData, DWORD size);
	BYTE* getBytes();
	DWORD addData(BYTE* data, DWORD size);
	const char* getPath();
	void PrintInfo();
private:
	const char* Path;
	bool Failed;
	bool LoadedFromMemory;
	DWORD Location;
	DWORD Size;
};

