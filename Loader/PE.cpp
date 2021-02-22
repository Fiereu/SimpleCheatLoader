#include "PE.h"
bool PE::isLoaded()
{
	return !Failed;
}

bool PE::isValid()
{
	BYTE MZ[2] = { 'M', 'Z' };
	BYTE PE[2] = { 'P', 'E' };
	DWORD NTHeaderLocation = getNTHeaderAddress();
	return (memcmp(&MZ, &Location, 2) && memcmp(&PE, &NTHeaderLocation, 2));
}

bool PE::is64Bit()
{
	if(getOptHeader()->Magic == 0x10b)
		return false;
	if(getOptHeader()->Magic == 0x20b)
		return true;
	return false;
}

DWORD PE::getLocation()
{
	if (!Failed)
	{
		return Location;
	}
	else
		return 0;
}

DWORD PE::getSize()
{
	if (!Failed)
	{
		return Size;
	}
	else
		return 0;
}

void PE::setSize(DWORD size)
{
	this->Size = size;
}

IMAGE_DOS_HEADER* PE::getDOSHeader()
{
	if (!Failed)
	{
		return (IMAGE_DOS_HEADER*)Location;
	}
	else
		return 0;
}

IMAGE_NT_HEADERS* PE::getNTHeader()
{
	if (!Failed)
	{
		return (IMAGE_NT_HEADERS*)(Location + getDOSHeader()->e_lfanew);
	}
	else
		return 0;
}

IMAGE_OPTIONAL_HEADER* PE::getOptHeader()
{
	return (IMAGE_OPTIONAL_HEADER*)&getNTHeader()->OptionalHeader;
}

IMAGE_FILE_HEADER* PE::getFileHeader()
{
	return (IMAGE_FILE_HEADER*)&getNTHeader()->FileHeader;
}

IMAGE_SECTION_HEADER* PE::getSectionHeaderAt(int index)
{
	if (!Failed)
	{
		IMAGE_SECTION_HEADER* Sections = nullptr;
		if (index > getSectionCount())
			return Sections;
		DWORD SectionAddress = getSectionHeaderAddress() + (index * sizeof(IMAGE_SECTION_HEADER));
		Sections = (IMAGE_SECTION_HEADER*)SectionAddress;
		return Sections;
	}
	else
		return 0;
}

IMAGE_SECTION_HEADER* PE::getSectionHeader()
{
	if (!Failed)
	{
		IMAGE_SECTION_HEADER* Sections = new IMAGE_SECTION_HEADER[getSectionCount()];
		DWORD SectionAddress = getSectionHeaderAddress();
		Sections = (IMAGE_SECTION_HEADER*)SectionAddress;
		return Sections;
	}
	else
		return 0;
}

DWORD PE::getDOSHeaderAddress()
{
	if (!Failed)
	{
		return Location;
	}
	else
		return 0;
}

DWORD PE::getNTHeaderAddress()
{
	if (!Failed)
	{
		return (Location + getDOSHeader()->e_lfanew);
	}
	else
		return 0;
}

DWORD PE::getOptHeaderAddress()
{
	if (!Failed)
	{
		IMAGE_OPTIONAL_HEADER* OptHeader = getOptHeader();
		return (DWORD)OptHeader;
	}
	else
		return 0;
}

DWORD PE::getAddressOfEntryPoint()
{
	if (!Failed)
	{
		IMAGE_OPTIONAL_HEADER* optHeader = getOptHeader();
		return optHeader->AddressOfEntryPoint;
	}
	else
		return 0;
}

DWORD PE::getSectionHeaderAddress()
{
	if (!Failed)
	{
		return getNTHeaderAddress() + sizeof(getNTHeader()->Signature) + sizeof(getNTHeader()->FileHeader) + getFileHeader()->SizeOfOptionalHeader;
	}
	else
		return 0;
}

DWORD PE::getSectionHeaderSize()
{
	if (!Failed)
	{
		return (getFileHeader()->NumberOfSections - 1) * 40;
	}
	else
		return 0;
}

DWORD PE::getSectionCount()
{
	if (!Failed)
	{
		return getFileHeader()->NumberOfSections;
	}
	else
		return 0;
}

DWORD PE::insertBytes(DWORD offset, BYTE* data, DWORD size)
{
	if (!Failed)
	{
		DWORD newAddress = (DWORD)VirtualAlloc(0, this->Size + size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy_s((void*)newAddress, this->Size + size, (void*)this->Location, offset);
		memcpy_s((void*)(newAddress + offset), this->Size + size - offset, (void*)data, size);
		memcpy_s((void*)(newAddress + offset + size), this->Size - offset, (void*)(this->Location + offset), this->Size - offset);


		ZeroMemory((void*)Location, Size);
		VirtualFree((void*)Location, 0, MEM_RELEASE);

		this->Location = newAddress;
		this->Size += size;
		return this->Location;
	}
	else
		return 0;
}

DWORD PE::patchBytes(DWORD offset, BYTE* data, DWORD size)
{
	if (!Failed)
	{
		DWORD Address = getLocation() + offset;
		memcpy_s((void*)Address, this->Size, (void*)data, size);
		return Address;
	}
	else
		return 0;
}

DWORD PE::addSection(IMAGE_SECTION_HEADER sectionHeader, BYTE* sectionData, DWORD size)
{
	DWORD sectionDataSize = size;
	IMAGE_SECTION_HEADER* lastSectionHeader = (IMAGE_SECTION_HEADER*)getSectionHeaderAt(getSectionCount() - 1);
	BYTE* sectionHeaderData = new BYTE[40];
	sectionHeaderData = (BYTE*)&sectionHeader;
	DWORD sectionHeaderDataSize = 40;

	getFileHeader()->NumberOfSections++;
	sectionHeader.SizeOfRawData = sectionDataSize;
	sectionHeader.PointerToRawData = lastSectionHeader->SizeOfRawData + lastSectionHeader->PointerToRawData;
	sectionHeader.VirtualAddress = lastSectionHeader->VirtualAddress + 0x1000;

	getOptHeader()->SizeOfHeaders += sectionHeaderDataSize;

	getOptHeader()->SizeOfImage += sectionHeaderDataSize + sectionDataSize + IMAGE_SIZEOF_SHORT_NAME;
	getOptHeader()->SizeOfImage += getOptHeader()->SizeOfImage % getOptHeader()->SectionAlignment;

	patchBytes(getSectionHeaderAddress() - Location + getSectionHeaderSize(), sectionHeaderData, sectionHeaderDataSize);
	insertBytes(sectionHeader.PointerToRawData, sectionData, sectionDataSize);

	return getLocation();
}

DWORD PE::addData(BYTE* data, DWORD size)
{
	if (!Failed)
	{
		DWORD newAddress = (DWORD)VirtualAlloc(0, this->Size + size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy_s((void*)newAddress, this->Size + size, (void*)this->Location, this->Size);
		memcpy_s((void*)(newAddress + this->Size), size, (void*)data, size);


		ZeroMemory((void*)Location, Size);
		VirtualFree((void*)Location, 0, MEM_RELEASE);

		this->Location = newAddress;
		this->Size += size;
		return this->Location;
	}
	else
		return 0;
}

BYTE* PE::getBytes()
{
	BYTE* Data = new BYTE[this->Size];
	Data = (BYTE*)this->Location;
	return Data;
}

bool PE::runPE()
{
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	CONTEXT* CTX;
	DWORD* ImageBase;
	void* pImageBase;


	if (isValid())
	{
		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));

		if (!CreateProcessA(getPath(), (LPSTR)getPath(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
		{
			TerminateProcess(PI.hProcess, 0);
			return false;
		}
		printf("Suspended process created\n");

		CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		CTX->ContextFlags = CONTEXT_FULL;

		if (!GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
		{
			TerminateProcess(PI.hProcess, 0);
			return false;
		}
		printf("ThreadContext created\n");

#if _WIN64

		ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Rbx + 16), LPVOID(&ImageBase), 8, 0);

		pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(getOptHeader()->ImageBase), getOptHeader()->SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(PI.hProcess, pImageBase, (void*)getLocation(), getOptHeader()->SizeOfHeaders, NULL);

		IMAGE_SECTION_HEADER* SectionHeader;

		for (int count = 0; count < getSectionCount(); count++)
		{
			SectionHeader = getSectionHeaderAt(count);
			WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress), LPVOID(getLocation() + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
		}

		WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rdx + 16), LPVOID(&getOptHeader()->ImageBase), 8, 0);

		CTX->Rcx = DWORD(pImageBase) + getOptHeader()->AddressOfEntryPoint;
		SetThreadContext(PI.hThread, LPCONTEXT(CTX));
		ResumeThread(PI.hThread);

#elif _WIN32

		ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

		pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(getOptHeader()->ImageBase), getOptHeader()->SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(PI.hProcess, pImageBase, (void*)getLocation(), getOptHeader()->SizeOfHeaders, NULL);

		IMAGE_SECTION_HEADER* SectionHeader;

		for (int count = 0; count < getSectionCount(); count++)
		{
			SectionHeader = getSectionHeaderAt(count);
			WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress), LPVOID(getLocation() + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
		}
		WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&getOptHeader()->ImageBase), 4, 0);

		CTX->Eax = DWORD(pImageBase) + getOptHeader()->AddressOfEntryPoint;
		SetThreadContext(PI.hThread, LPCONTEXT(CTX));
		ResumeThread(PI.hThread);

#endif
		return true;
	}
	printf("File is no Valid PE File\n");
	return false;
}

const char* PE::getPath()
{
	return Path;
}

void PE::PrintInfo()
{
	printf("Loaded PE-File at: \t0x%X\n", getLocation());
	printf("Size: \t\t\t0x%X\n", getSize());
	printf("Valid PE-File: \t\t%s\n", isValid() ? "True" : "False");
	printf("Sectiontable Size: \t0x%X\n", getSectionHeaderSize());
	IMAGE_SECTION_HEADER* Sections = new IMAGE_SECTION_HEADER[getSectionCount()];
	Sections = getSectionHeader();
	for (int i = 0; i < getSectionCount(); i++)
	{
		printf("Section %d: \t\t%s\n", i, (const char*)Sections[i].Name);
	}
	printf("\n");
}

PE::~PE()
{
	if (!Failed && !LoadedFromMemory)
	{
		ZeroMemory((void*)Location, Size);
		VirtualFree((void*)Location, 0, MEM_RELEASE);
	}
}

PE::PE(const char* path)
{
	this->Path = path;
	Failed = false;

	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
	{
		printf("[-] Cant access File\n");
		Failed = true;
		return;
	}

	std::ifstream f(path, std::ios::binary);

	if (f.fail())
	{
		printf("[-] Opening the file failed: %X\n", (DWORD)f.rdstate());
		f.close();
		Failed = true;
		return;
	}
	f.seekg(0, f.end);
	this->Size = f.tellg();
	f.seekg(0, f.beg);

	if (this->Size < 0x1000)
	{
		printf("[-] Filesize is invalid.\n");
		f.close();
		Failed = true;
		return;
	}

	BYTE* Address = new BYTE[(UINT_PTR)this->Size];
	ZeroMemory(Address, this->Size);
	if (!Address)
	{
		printf("[-] Memory allocating failed\n");
		f.close();
		Failed = true;
		return;
	}

	f.seekg(0, std::ios::beg);
	f.read((char*)Address, this->Size);
	f.close();

	this->LoadedFromMemory = false;
	this->Location = (DWORD)Address;
}

PE::PE(DWORD Address, DWORD Size)
{
	this->LoadedFromMemory = true;
	this->Path = "";
	this->Size = Size;
	this->Location = Address;
}
