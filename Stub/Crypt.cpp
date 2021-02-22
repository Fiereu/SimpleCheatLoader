#include "Crypt.h"

void XOR(BYTE* data, DWORD size)
{
	for (int i = 0; i < size; i++)
	{
		data[i] = data[i] ^ 0x83FE + i;
	}
}