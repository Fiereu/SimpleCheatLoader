#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>

#include "PE.h"

void PackDll(const char* Message, const char* stub, const char* in, const char* out);