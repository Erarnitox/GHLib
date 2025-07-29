#include "ToolingLib.hpp"
#include "Windows.h"
#include "tlhelp32.h"
#include "winternl.h"
#include "WtsApi32.h"
#include "fstream"

// Global function pointers
BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HINSTANCE(WINAPI* pLoadLibraryA)(char* lpLibFilename);

// Type definitions
using VirtualProtect_t = BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
using LoadLibraryA_t = HINSTANCE(WINAPI*)(char* lpLibFilename);
using GetProcAddress_t = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using DLL_ENTRY_POINT_t = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA {
	LoadLibraryA_t pLoadLibraryA;
	GetProcAddress_t pGetProcAddress;
	HINSTANCE hMod;
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline HMODULE WINAPI get_module_handle(LPCWSTR module_name) {
#ifdef _M_IX86
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else 
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

	if (not module_name)
		return (HMODULE)(((BYTE*)ProcEnvBlk)[0x10]);

	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
		if (lstrcmpiW((LPCWSTR)(pEntry->FullDllName.Buffer), module_name) == 0)
			return (HMODULE)pEntry->DllBase;
	}

	// if nothing is found:
	return (HMODULE) NULL;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void disable_etw() {
	DWORD old_protect = 0;
	unsigned char sEtwEventWrite[] = "EtwEventWrite";
	void* pEventWrite = GetProcAddress(get_module_handle((LPWSTR)"ntdll.dll"), (LPCSTR)sEtwEventWrite);
	pVirtualProtect(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &old_protect);

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif

	pVirtualProtect(pEventWrite, 4096, old_protect, &old_protect);
	FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline FARPROC WINAPI get_proc_address(HMODULE hMod, const char* proc_name) {
	char* pBaseAddr = (char*)hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're loking for
	void* pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)proc_name >> 16) == 0) {
		WORD ordinal = (WORD)proc_name & 0xffff; // convert to WORD
		DWORD Base = pExportDirAddr->Base; // first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions) {
			return NULL;
		}

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
	}

	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; ++i) {
			char* tmp_func_name = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

			if (strcmp(proc_name, tmp_func_name) == 0) {
				// found! get the fucntion virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
				break;
			}
		}

	}

	// check if found RVA is forwarded to external library function
	if ((char*)pProcAddr >= (char*)pExportDirAddr && (char*)pProcAddr < (char*)(pExportDirAddr + pExportDataDir->Size)) {
		char* sFwdDLL = _strdup((char*)pProcAddr);
		if (not sFwdDLL) return NULL;

		// get external function name
		char* sFwdFunction = strchr(sFwdDLL, '.');
		*sFwdFunction = 0;
		++sFwdFunction;

		// resolve LoadLibrary function pointer, keep it as global variable
		if (pLoadLibraryA == NULL) {
			pLoadLibraryA = (LoadLibraryA_t) get_proc_address(get_module_handle(L"KERNEL32.DLL"), "LoadLibraryA");
			if (not pLoadLibraryA) return NULL;
		}

		// load the external library
		HMODULE hFwd = (HMODULE)pLoadLibraryA(sFwdDLL);
		free(sFwdDLL);
		if (!hFwd) return NULL;

		// get the address of function the original call is forwarded to
		pProcAddr = get_proc_address(hFwd, sFwdFunction);
	}

	return (FARPROC)pProcAddr;
}

// initialize the function pointers:
//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline void init_function_pointers() {
	//static bool initialized{ false };
	//if (initialized) return;
	//initialized = true;

	if (not pVirtualProtect) {
		pVirtualProtect = (VirtualProtect_t) GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
	}
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void write_memory() {
	WriteProcessMemory(hProcess, ammoAddresses[0], &ammoValue[0], sizeof(int), 0);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
int read_memory() {
	ReadProcessMemory(hProcess, ammoAddresses[0], &ammoValue, sizeof(int), 0);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
uintptr_t Process::get_module_address(const wchar_t* modName) {
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->pid); //create a snapshot of all modules loaded by our game process
	if (hSnap != INVALID_HANDLE_VALUE) { //check if creating a snapshot was successful
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) { //place the first module in our snapshot in modEntry
			do {
				if (!_wcsicmp((wchar_t*)modEntry.szModule, modName)) { //cheack if the module has the name of the module we are looking for
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr; //if we have found our module, save its address in modBaseAddr
					break; //break out of the loop
				}
			} while (Module32Next(hSnap, &modEntry)); //place the next module in the snapshot into modentry (looping over each module in the snapshot)
		}
	}
	CloseHandle(hSnap); // "delete" our snapshot
	return modBaseAddr; //return the address of the found module or 0 if we did not find it
}

bool Process::is_running() {
	DWORD dwExit{};
	return GetExitCodeProcess(this->hProc, &dwExit) && dwExit == STILL_ACTIVE;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode& Shellcode::execute() {
	auto exec_mem = VirtualAlloc(0, this->length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlMoveMemory(exec_mem, this->opcodes, this->length);
	if (exec_mem == 0) return *this;

	DWORD oldprotect;
	auto rv = pVirtualProtect(exec_mem, this->length, PAGE_EXECUTE_READ, &oldprotect);
	if (rv == 0) return *this;
	
	HANDLE thread_handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
	if (thread_handle == 0) return *this;

	WaitForSingleObject(thread_handle, -1);

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode& Shellcode::load_from_res(uint64_t id = 100) {
	HRSRC resource = FindResource(NULL, MAKEINTRESOURCE((LPSTR)id), RT_RCDATA);
	if (resource == 0) return *this;

	HANDLE res_handle = LoadResource(NULL, resource);
	if (res_handle == 0) return *this;

	this->opcodes = (unsigned char*) LockResource(res_handle);
	this->length = SizeofResource(NULL, resource);

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode& Shellcode::encrypt() {
	if (this->encrypted) return *this;
	this->encrypted = true;

	this->key = new unsigned char[this->length];
	if (this->key == nullptr) return *this;

	for (size_t i{ 0 }; i < this->length; ++i) {
		this->key[i] = (unsigned char) std::rand();
		this->opcodes[i] = this->opcodes[i] xor this->key[i];
	}

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode& Shellcode::decrypt() {
	if (not this->encrypted) return *this;
	this->encrypted = false;

	for (size_t i{ 0 }; i < this->length; ++i) {
		this->opcodes[i] = this->opcodes[i] xor this->key[i];
	}

	delete[] this->key;
	this->key = nullptr;

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode& Shellcode::clear() {
	if(this->key)
		delete[] this->key;

	this->opcodes = nullptr;
	this->encrypted = false;
	this->length = 0;
	this->key = nullptr;

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
size_t Shellcode::get_length() const {
	return this->length;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
unsigned char* Shellcode::get_data() const {
	return this->opcodes;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode::~Shellcode() {
	if (this->key)
		delete[] this->key;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode::Shellcode() : opcodes{ nullptr }, length{ 0 }, encrypted{ 0 }, key{ nullptr }
{
	
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Shellcode::Shellcode(std::vector<unsigned char>& opcodes) : opcodes{ nullptr }, length{ 0 }, encrypted{ 0 }, key{ nullptr }
{
	this->opcodes = opcodes.data();
	this->length = opcodes.size();
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline int find_target(const char* procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpi(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);
	return pid;
}


//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Process::Process(const char* base_name) {
	this->pid = find_target(base_name);
	if (!pid) return;

	this->hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void WINAPI shellcode(MANUAL_MAPPING_DATA* pData);
Process& Process::manual_map(const char* dll_path) {
	//open our dll. ios::ate seeks to the end of the file:
	std::ifstream dllFile(dll_path, std::ios::binary | std::ios::ate);

	//check if the file could be opened:
	if (dllFile.fail()) {
		dllFile.close();
		return *this;
	}

	std::streampos dllSize{ dllFile.tellg() };
	BYTE* pSrcData{ new BYTE[static_cast<UINT_PTR>(dllSize)] };

	//read our dll files content and store it inside pSrcData:
	dllFile.seekg(0, std::ios::beg);
	dllFile.read(reinterpret_cast<char*>(pSrcData), dllSize);
	dllFile.close();

	IMAGE_NT_HEADERS* pOldNtHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew) };
	IMAGE_OPTIONAL_HEADER* pOldOptHeader{ &pOldNtHeader->OptionalHeader };
	IMAGE_FILE_HEADER* pOldFileHeader{ &pOldNtHeader->FileHeader };

	//test for valid dll:
	if (~(pOldFileHeader->Characteristics) & IMAGE_FILE_DLL) {
		delete[] pSrcData;
		return *this;
	}

	BYTE* pTargetBase{
		reinterpret_cast<BYTE*>(
			VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase),
				pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
	};

	if (!pTargetBase) {
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase) {
			delete[] pSrcData;
			return *this;
		}
	}

	//write the sections of our dll to the games process
	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return *this;
			}
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = (LoadLibraryA_t) LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<GetProcAddress_t>(GetProcAddress);

	/*write the data/header to the beginning of our module:*/
	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	//allocate memory for our shellcode:
	void* pShellcode{ VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
	if (!pShellcode) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return *this;
	}

	//write the shellcode to our game:
	WriteProcessMemory(hProc, pShellcode, shellcode, 0x1000, nullptr);

	//create a new Thread and call the shellcode:
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return *this;
	}

	CloseHandle(hThread);

	//check if our shellcode is still in use:
	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return *this;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

//our shellcode function to resolve dependencies and call the dll entry:
void WINAPI shellcode(MANUAL_MAPPING_DATA* pData) {
	/*pData is custom struct that coains the pointer to the entry point
	* of our DLL and the data we need for Relocation.
	*/
	if (!pData) return;

	//module base
	BYTE* pBase{ reinterpret_cast<BYTE*>(pData) };

	//optional header
	auto* pOpt{ &reinterpret_cast<IMAGE_NT_HEADERS*>
		(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader
	};

	/*
	* Functions that we need to call we pass through
	* our pData as pointer so we are able to find
	* and call them:
	*/
	LoadLibraryA_t _LoadLibraryA{ pData->pLoadLibraryA };
	GetProcAddress_t _GetProcAddress{ pData->pGetProcAddress };

	//the entry point of our dll (relative to base):
	DLL_ENTRY_POINT_t _DllMain{ (DLL_ENTRY_POINT_t)(pBase + pOpt->AddressOfEntryPoint) };

	//offset from the prefered image base:
	BYTE* LocationDelta{ pBase - pOpt->ImageBase };

	/*if Location == 0, then it got loaded into its prefered
	* image base.
	*/
	if (LocationDelta) {
		//if the image can't be relocated:
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

		auto* pRelocData{
			reinterpret_cast<IMAGE_BASE_RELOCATION*>
			(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		};

		//relocate the image:
		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries{ (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) };
			WORD* pRelativeInfo{ reinterpret_cast<WORD*>(pRelocData + 1) };

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				//check if relocation is neccessary:
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR* pPatch{ reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF)) };
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	//fix imports:
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr{
			reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>
			(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		};

		//loop over the import table:
		while (pImportDescr->Name) {
			char* szMod{ reinterpret_cast<char*>(pBase + pImportDescr->Name) };
			HINSTANCE hDll{ _LoadLibraryA(szMod) }; //load the import
			/*
			* using LoadLibrary to load our imports might get detected by some
			* anti cheats. Anther option here would be to call ManualMap recusively.
			*/

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef) pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				//load by oridinal number:
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {//load by name:
					auto* pImport{ reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef)) };
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	//tls callbacks:
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS{ reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };
		auto* pCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks) };
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	//call our dll entry point:
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Process& Process::inject(const Shellcode& payload) {
	if (not this->hProc) return *this;

	LPVOID pRemoteCode = VirtualAllocEx(this->hProc, NULL, payload.get_length(), MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload.get_data(), (SIZE_T)payload.get_length(), (SIZE_T*)NULL);
	
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
	if (not hThread) return *this;

	WaitForSingleObject(hThread, 500);
	CloseHandle(hThread);

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Process& Process::inject(const char* dll_path) {
	if (not this->hProc) return *this;
	PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	PVOID remBuf = VirtualAllocEx(this->hProc, NULL, strnlen(dll_path, 512), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(this->hProc, remBuf, (LPVOID)dll_path, strnlen(dll_path, 512), NULL);

	CreateRemoteThread(this->hProc, NULL, 0, pLoadLibrary, remBuf, 0, NULL);

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline HANDLE FindThread(int pid) {
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnapshot, &te32)) {
		CloseHandle(hThreadSnapshot);
		return NULL;
	}

	HANDLE hThread = nullptr;
	do {
		if (te32.th32OwnerProcessID == pid) {
			hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
			if (hThread != nullptr) {
				break;
			}
		}
	} while (Thread32Next(hThreadSnapshot, &te32));

	CloseHandle(hThreadSnapshot);
	if (not hThread)
		return NULL;

	return hThread;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Process& Process::inject_apc(const Shellcode& payload) {
	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = FindThread(this->pid);
	if (not hThread) {
		return *this;
	}

	// Decrypt and inject the payload
	pRemoteCode = VirtualAllocEx(this->hProc, NULL, payload.get_length(), MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(this->hProc, pRemoteCode, (PVOID)payload.get_data(), (SIZE_T)payload.get_length(), (SIZE_T*)NULL);

	// execute the payload by adding async procedure call (APC) object to thread's APC queue
	QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, NULL);

	return *this;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
static inline char* ScanBasic(const char* pattern, const char* mask, char* begin, size_t size) {
	size_t patternLen = strlen(mask);

	for (size_t i = 0; i < size; i++) {
		bool found = true;
		for (size_t j = 0; j < patternLen; j++) {
			if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j)) {
				found = false;
				break;
			}
		}
		if (found) {
			return (begin + i);
		}
	}
	return nullptr;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
char* Internal::scan(const char* pattern, const char* mask, char* begin, size_t size) {
	//Example pattern:
	// const char* internalSendPattern{ "\x55\x8B\xEC\x53\x8B\xD9\x83\x7B\x0C\x00\x74\x54\x8B\x8B\x1C\x00\x02\x00\x85\xC9\x74\x2E\x8B\x01\x8B\x01\x8B\x40\x18\xFF\xD0" };
	// const char* internalSendMask{ "xxxxxxxxxx??xx????xxxxxxx" };

	char* match{ nullptr };
	MEMORY_BASIC_INFORMATION mbi{};

	for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize) {
		if (!VirtualQuery(curr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;
		match = ScanBasic(pattern, mask, curr, mbi.RegionSize);

		if (match != nullptr && match != pattern) {
			break;
		}
	}
	return match;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Process::~Process() {
	CloseHandle(this->hProc);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
bool is_running(const std::string& mutex_name) {
	const std::string mut{ std::string("Global\\").append(mutex_name) }; 
	HANDLE hSync = CreateMutex(NULL, FALSE, mut.data());
	
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(hSync);
		return true;
	} else {
		return false;
	}
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
InlineHook::InlineHook(void* toHook, void* ourFunct, int len) : tToHook(toHook), oldOpcodes(nullptr), tLen(len) {
	if (len < 5) {
		return;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	oldOpcodes = std::make_unique<char[]>(len);
	if (oldOpcodes != nullptr) {
		for (int i = 0; i < len; ++i) {
			oldOpcodes[i] = ((char*)toHook)[i];
		}
	}

	memset(toHook, 0x90, len);

	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	VirtualProtect(toHook, len, curProtection, &curProtection);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
InlineHook::~InlineHook() {
	if (oldOpcodes != nullptr) {
		DWORD curProtection;
		VirtualProtect(tToHook, tLen, PAGE_EXECUTE_READWRITE, &curProtection);
		for (int i = 0; i < tLen; ++i) {
			((char*)tToHook)[i] = oldOpcodes[i];
		}
		VirtualProtect(tToHook, tLen, curProtection, &curProtection);
	}
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
int Process::find_target_wts(const char* proc_name) {
	int pid = 0;
	WTS_PROCESS_INFOA* proc_info;
	DWORD pi_count = 0;

	if (not WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count)) {
		return 0;
	}

	for (int i{ 0 }; i < pi_count; ++i) {
		if (lstrcmp(proc_name, proc_info[i].pProcessName) == 0) {
			pid = proc_info[i].ProcessId;
			break;
		}
	}

	return pid;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
int Process::find_target_ths(const char* proc_name) {
	return find_target(proc_name);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
int Process::find_target_nsi(const char* proc_name) {
	int pid = 0;
	PVOID buffer = NULL;
	DWORD bufSize = 0;

	// resolve function address
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, 0, 0, &bufSize);

	if (bufSize == 0)
		return -1;

	// allocate appropriate buffer for proces information
	if (buffer = VirtualAlloc(0, bufSize, MEM_COMMIT, PAGE_READWRITE)) {
		SYSTEM_PROCESS_INFORMATION* sysproc_info = (SYSTEM_PROCESS_INFORMATION*)buffer;
		if (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, buffer, bufSize, &bufSize)) {
			while (true) {
				if (lstrcmp(proc_name, (LPSTR)sysproc_info->ImageName.Buffer) == 0) {
					pid = (int)sysproc_info->UniqueProcessId;
					break;
				}

				// done?
				if (not sysproc_info->NextEntryOffset)
					break;

				// check next entry
				sysproc_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sysproc_info + sysproc_info->NextEntryOffset);
			}
		}
		else return 0;
	}
	else return 0;

	VirtualFree(buffer, bufSize, MEM_RELEASE);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
uintptr_t Internal::get_module_base(const wchar_t* modName) {
	return (uintptr_t)GetModuleHandleW(modName);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
uintptr_t Internal::resolve_ptr(uintptr_t ptr, std::vector<unsigned int> offsets) {
	for (unsigned int i = 0; i < offsets.size(); ++i) { //loop over the offsets
		ptr = *(char*)ptr; //dereference pointer
		ptr += offsets[i]; //add the current offset to addr
	}
	return ptr; //return the address the multi level pointer is pointing at currently
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::patch(char* dst, char* src, size_t size) {
	DWORD oldprotect; //variable to hold a backup of our old protection
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect); //make memory writeable and save the old protection in oldprotect
	memcpy(dst, src, size); //write the new opcodes to the target location
	VirtualProtect(dst, size, oldprotect, &oldprotect); //restore our old protection
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::Nop::Nop(char* dst, size_t size)
	: dst{ dst }, size{ size }, originalCode{ new char[size] }, nopCode{ new char[size] } {
	memset(nopCode, 0x90, size); //initialize our nopCode
	memcpy(originalCode, dst, size); //backup our original Code
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::Nop::enable() { //enable our patch
	//write the code that does nothing to memory:
	patch(dst, nopCode, size);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::Nop::disable() { //disable our patch
	//write the original code back to memory:
	patch(dst, originalCode, size);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::Nop::~Nop() { //clean up our patch object
	delete[] this->originalCode;
	delete[] this->nopCode;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::ManagedPatch::ManagedPatch(char* dst, char* src, size_t size)
	: dst{ dst }, size{ size }, originalCode{ new char[size] }, newCode{ new char[size] } {
	memcpy(newCode, src, size); //initialize our newCode
	memcpy(originalCode, dst, size); //backup our original Code
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::ManagedPatch::enable() { //enable our patch
	//write the code that does nothing to memory:
	patch(dst, newCode, size);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::ManagedPatch::disable() { //disable our patch
	//write the original code back to memory:
	patch(dst, originalCode, size);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::ManagedPatch::~ManagedPatch() { //clean up our patch object
	delete[] this->originalCode;
	delete[] this->newCode;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::Hook::Hook(void* toHook, void* ourFunct, int len) : tToHook{ toHook }, oldOpcodes{ nullptr }, tLen{ len }, enabled{ false } {
	/*a jmp instruction is 5 bytes in size.
	The place we overwrite needs to be at least of that size*/
	if (len < 5) {
		return;
	}

	DWORD curProtection; //stores the old memory prtection
	//make the memory with the code we want to overwrite writeable 
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	//save the current opcodes byte by byte into a char array
	oldOpcodes = std::make_unique<char[]>(len);
	if (oldOpcodes != nullptr) {
		for (int i = 0; i < len; ++i) {
			oldOpcodes[i] = ((char*)toHook)[i];
		}
	}

	//Overwrite the place we want to hook with nop instructions
	memset(toHook, 0x90, len);

	//claculate the relative address of where to jump to
	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

	*(BYTE*)toHook = 0xE9; //place the opcode for the jmp instruction
	//place the address of where to jump to
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	//restore the old code protection
	VirtualProtect(toHook, len, curProtection, &curProtection);
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
Internal::Hook::~Hook() {
	if (oldOpcodes != nullptr) {
		DWORD curProtection;
		//make memory writeable
		VirtualProtect(tToHook, tLen, PAGE_EXECUTE_READWRITE, &curProtection);
		for (int i = 0; i < tLen; ++i) { //write the old opcodes back to the hooked location
			((char*)tToHook)[i] = Hook::oldOpcodes[i];
		}
		//restore old memory protection
		VirtualProtect(tToHook, tLen, curProtection, &curProtection);
	}
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::Hook::enable() {
	this->enabled = true;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
void Internal::Hook::disable() {
	this->enabled = false;
}

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
bool Internal::Hook::isEnabled() {
	return enabled;
}
