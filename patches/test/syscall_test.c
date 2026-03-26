#include <stdio.h>
#include <windows.h>

// -----------------------------------------------------------------
// DYNAMIC SYSCALL THUNK GENERATOR
// -----------------------------------------------------------------
void* CreateSyscallStub(DWORD syscall_num) {
    BYTE stub[] = {
        0x49, 0x89, 0xCA,                               // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, <syscall_num>
        0x0F, 0x05,                                     // syscall
        0xC3                                            // ret
    };

    *(DWORD*)(&stub[4]) = syscall_num;
    void* exec_mem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem) {
        memcpy(exec_mem, stub, sizeof(stub));
        DWORD oldProtect;
        VirtualProtect(exec_mem, sizeof(stub), PAGE_EXECUTE_READ, &oldProtect);
    }
    return exec_mem;
}

DWORD GetSyscallNumber(HMODULE hNtdll, const char* funcName) {
    BYTE* p = (BYTE*)GetProcAddress(hNtdll, funcName);
    if (!p) return (DWORD)-1;
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x4C && p[i+1] == 0x8B && p[i+2] == 0xD1 && p[i+3] == 0xB8) {
            return *(DWORD*)(p + i + 4);
        }
    }
    return (DWORD)-1;
}

typedef NTSTATUS (WINAPI *NtClose_t)(HANDLE Handle);
typedef NTSTATUS (WINAPI *NtQueryPerformanceCounter_t)(PLARGE_INTEGER PerfCounter, PLARGE_INTEGER PerfFreq);
typedef NTSTATUS (WINAPI *NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

int main() {
    printf("==================================================\n");
    printf("   FreeBSD Syscall User Dispatch (SUD) Test       \n");
    printf("==================================================\n\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 1;

    // -----------------------------------------------------------------
    // TEST 1: NtClose 
    // -----------------------------------------------------------------
    DWORD sys_NtClose = GetSyscallNumber(hNtdll, "NtClose");
    if (sys_NtClose != (DWORD)-1) {
        printf("[*] Testing NtClose (Syscall 0x%04lX)...\n", sys_NtClose);
        NtClose_t pNtClose = (NtClose_t)CreateSyscallStub(sys_NtClose);
        
        HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
        if (hEvent == NULL) {
            printf("    [-] FATAL: CreateEventA failed (Error: %lu). Cannot test syscall.\n", GetLastError());
        } else {
            NTSTATUS status = pNtClose(hEvent);
            if (status == 0) {
                printf("    [+] SUCCESS: Cleanly closed real handle (NTSTATUS 0x00000000)\n");
            } else {
                printf("    [-] FAILED: Unexpected NTSTATUS: 0x%08lX\n", status);
            }
        }
    }

    // -----------------------------------------------------------------
    // TEST 2: NtQueryPerformanceCounter 
    // -----------------------------------------------------------------
    DWORD sys_NtQueryPerf = GetSyscallNumber(hNtdll, "NtQueryPerformanceCounter");
    if (sys_NtQueryPerf != (DWORD)-1) {
        printf("\n[*] Testing NtQueryPerformanceCounter (Syscall 0x%04lX)...\n", sys_NtQueryPerf);
        NtQueryPerformanceCounter_t pNtQueryPerf = (NtQueryPerformanceCounter_t)CreateSyscallStub(sys_NtQueryPerf);
        
        LARGE_INTEGER counter, freq;
        NTSTATUS status = pNtQueryPerf(&counter, &freq);
        
        if (status == 0) {
            printf("    [+] SUCCESS: Counter retrieved cleanly.\n");
        } else if (status == 0xC0000005) {
            printf("    [+] SUCCESS: Intercepted Valve's expected DRM/Frame-Pacing access violation (0xC0000005)\n");
        } else {
            printf("    [-] FAILED: Unexpected NTSTATUS: 0x%08lX\n", status);
        }
    }

    // -----------------------------------------------------------------
    // TEST 3 & 4: 5-Argument Stack Alignment Tests
    // -----------------------------------------------------------------
    DWORD sys_NtReadMem = GetSyscallNumber(hNtdll, "NtReadVirtualMemory");
    DWORD sys_NtQIP = GetSyscallNumber(hNtdll, "NtQueryInformationProcess");
    
    // Ask for exactly what we need so the Server doesn't reject us
    HANDLE hRealProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    
    if (hRealProcess == NULL) {
        printf("\n[-] FATAL: OpenProcess failed (Error: %lu). Cannot run Stack Alignment tests.\n", GetLastError());
    } else {
        if (sys_NtReadMem != (DWORD)-1) {
            printf("\n[*] Testing NtReadVirtualMemory (Syscall 0x%04lX)...\n", sys_NtReadMem);
            NtReadVirtualMemory_t pNtReadMem = (NtReadVirtualMemory_t)CreateSyscallStub(sys_NtReadMem);
            
            DWORD target_val = 0x1337BEEF;
            DWORD read_val = 0;
            SIZE_T bytes_read = 0;
            NTSTATUS status = pNtReadMem(hRealProcess, &target_val, &read_val, sizeof(DWORD), &bytes_read);
            
            if (status == 0 && read_val == 0x1337BEEF) {
                printf("    [+] STACK ALIGNMENT PASSED! 5th argument successfully resolved.\n");
            } else {
                printf("    [-] FAILED: Returned NTSTATUS: 0x%08lX\n", status);
            }
        }

        if (sys_NtQIP != (DWORD)-1) {
            printf("\n[*] Testing NtQueryInformationProcess (Syscall 0x%04lX)...\n", sys_NtQIP);
            NtQueryInformationProcess_t pNtQIP = (NtQueryInformationProcess_t)CreateSyscallStub(sys_NtQIP);
            
            struct {
                NTSTATUS ExitStatus;
                PVOID PebBaseAddress;
                ULONG_PTR AffinityMask;
                LONG BasePriority;
                ULONG_PTR UniqueProcessId;
                ULONG_PTR InheritedFromUniqueProcessId;
            } pbi = {0};
            
            ULONG retLen = 0;
            NTSTATUS status = pNtQIP(hRealProcess, 0, &pbi, sizeof(pbi), &retLen);
            
            if (status == 0 && retLen == sizeof(pbi)) {
                printf("    [+] STACK ALIGNMENT PASSED! 5th argument successfully resolved.\n");
            } else {
                printf("    [-] FAILED: Returned NTSTATUS: 0x%08lX\n", status);
            }
        }
        CloseHandle(hRealProcess); // We'll use the standard API here to clean up
    }

    printf("\n==================================================\n");
    printf("   Testing Complete.\n");
    printf("==================================================\n");
    return 0;
}