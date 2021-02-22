#include "Packer.h"

struct Data
{
	DWORD PayloadLocation, PayloadSize, MessageSize, MessageLocation;
};

void PackDll(const char* Message, const char* stub, const char* in, const char* out)
{
	PE EXE = PE(in);
	if (!EXE.isLoaded())
		return;
	EXE.PrintInfo();

	PE Stub = PE(stub);
	if (!Stub.isLoaded())
		return;
	Stub.PrintInfo();

	IMAGE_SECTION_HEADER PayloadSection = IMAGE_SECTION_HEADER();
	const char* SectionName = ".cheat";
	strcpy_s((char*)PayloadSection.Name, IMAGE_SIZEOF_SHORT_NAME, SectionName);
	PayloadSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
	PayloadSection.PointerToRelocations = 0;
	PayloadSection.PointerToLinenumbers = 0;
	PayloadSection.NumberOfLinenumbers = 0;
	PayloadSection.NumberOfRelocations = 0;

	Data PayloadData;
	PayloadData.MessageSize = 0xFF;
	PayloadData.MessageLocation = sizeof(Data);
	PayloadData.PayloadSize = EXE.getSize();
	PayloadData.PayloadLocation = PayloadData.MessageLocation + PayloadData.MessageSize;

	BYTE* ByteMessage = new BYTE[PayloadData.MessageSize];
	ZeroMemory(ByteMessage, PayloadData.MessageSize);
	if (Message != "")
		strcpy_s((char*)ByteMessage, PayloadData.MessageSize, Message);


	EXE.insertBytes(0, ByteMessage, PayloadData.MessageSize);
	EXE.insertBytes(0, (BYTE*)&PayloadData, sizeof(Data));
	
	XOR(EXE.getBytes(), EXE.getSize());

	printf("Added Section at: \t0x%X\n", Stub.addSection(PayloadSection, EXE.getBytes(), EXE.getSize()));
	
	std::ofstream f(out, std::ios::binary);
	f.write((const char*)Stub.getLocation(), Stub.getSize());
	f.close();
	Sleep(200);
}