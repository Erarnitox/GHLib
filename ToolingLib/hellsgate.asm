.data
	wSystemCall DWORD 000h

.code
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellsDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellsDescent ENDP
end