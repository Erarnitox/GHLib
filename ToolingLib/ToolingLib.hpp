#pragma once

#include <vector>
#include <string>
#include <memory>

#define COMP_CALL consteval 
#define SEMI_CALL constexpr
#define RUNT_CALL inline

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
class Shellcode {
private:
	unsigned char* opcodes;
	size_t length;
	bool encrypted = false;
	unsigned char* key = nullptr;

public:
	SEMI_CALL Shellcode(std::vector<unsigned char>& opcodes);
	SEMI_CALL Shellcode();
	RUNT_CALL ~Shellcode();
	RUNT_CALL Shellcode& execute();
	SEMI_CALL Shellcode& load_from_res(size_t d);
	SEMI_CALL Shellcode& encrypt();
	RUNT_CALL Shellcode& decrypt();
	RUNT_CALL Shellcode& clear();
	SEMI_CALL size_t get_length() const;
	SEMI_CALL unsigned char* get_data() const;
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
class String {
private:
	char key[512];
	char data[521];
	size_t length;
public:
	// stores the provided string in an encrypted way
	COMP_CALL String(const char* string);

	// decrypts into a copy and returns that copy
	RUNT_CALL std::string get() const;
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
struct Patch {
	char* destination; //address of the code to patch
	size_t size; //size of the patch
	char* original_code; //backup of the original code
	char* new_code; //new functionality
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
class Process {
private:
	int pid;
	size_t hProc;
	// std::vector<Patch> patches;

public:
	static int find_target_ths(const char* proc_name);
	static int find_target_wts(const char* proc_name);
	static int find_target_nsi(const char* proc_name);

	Process(const char* base_name);
	Process(int pid);
	~Process();
	Process& inject(const Shellcode& payload);
	Process& inject(const char* dll_path);
	Process& manual_map(const char* dll_path);
	Process& inject_apc(const Shellcode& payload);

	// Process& apply(Patch& patch);
	//T read_memory(byte* from, size_t length);
	//void write_memory(byte* to, T value);

	size_t get_module_address(const wchar_t* modName);
	
	[[nodiscard]]
	bool is_running();
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
RUNT_CALL bool is_running(const std::string& mutex_name = "SexyWin");

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
RUNT_CALL void disable_etw();

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
class InlineHook {
    void* tToHook;
    std::unique_ptr<char[]> oldOpcodes;
    int tLen;
public:
	InlineHook(void* toHook, void* ourFunct, int len);
	~InlineHook();
};

//--------------------------------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------------------------------
namespace Internal {
	RUNT_CALL char* scan(const char* pattern, const char* mask, char* begin, size_t size);

	//gets the address where a module of our game got loaded to:
	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	RUNT_CALL uintptr_t get_module_base(const wchar_t* modName);

	//find dynamic address a multi level pointer is pointing to:
	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	RUNT_CALL uintptr_t resolve_ptr(uintptr_t ptr, std::vector<unsigned int> offsets);

	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	RUNT_CALL void patch(char* dst, char* src, size_t size); //write new code to memory

	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	class Nop { //class for replacing code with code that does nothing
	private:
		char* dst; //address of the code to patch
		size_t size; //size of the patch
		char* originalCode; //backup of the original code
		char* nopCode; //code that does nothing
	public:
		Nop(char* dst, size_t size); //constructor
		~Nop(); //destructor
		void enable(); //enable the patch
		void disable(); //disable the patch
	};

	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	class ManagedPatch {
		char* dst; //address of the code to patch
		size_t size; //size of the patch
		char* originalCode; //backup of the original code
		char* newCode; //new functionality
	public:
		ManagedPatch(char* dst, char* src, size_t size); //constructor
		~ManagedPatch(); //destructor
		void enable(); //enable the patch
		void disable(); //disable the patch
	};

	//--------------------------------------------------------------------------------------------------------
	//
	//--------------------------------------------------------------------------------------------------------
	class Hook { //class for our Hook
		void* tToHook; //pointer to where to place the hook
		std::unique_ptr<char[]> oldOpcodes; //save old opodes here
		int tLen; //length of the overwritten instructions(s)
		bool enabled; //is the Hook enabled
	public:
		Hook(void* toHook, void* ourFunct, int len); //constructor creates the hook
		~Hook(); //Destructor restores the original code
		void enable(); //enable the hook
		void disable(); //disable the hook
		bool isEnabled(); //returns if the hook is enabled
	};
}

