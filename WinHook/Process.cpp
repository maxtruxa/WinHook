/* Copyright (c) 2013 Max Truxa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "WinHook.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

#ifdef _UNICODE
// TlHelp32.h does not use the common ASCII / unicode pattern with prefixing
// the functions with 'A' or 'W' but redefines the names of the ASCII versions
// to the unicode versions, so they are not usable without undefining them.
#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next
#endif
pid_t WinHookApi GetProcessIdByImageNameA(
    __in char const* imageName
    )
{
    // Acquire snapshot.
    handle_t snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if(snapshot == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    // Iterate over all snapshot entries.
    if(Process32First(snapshot, &entry) == FALSE)
    {
        PRESERVE_LAST_ERROR(
            CloseHandle(snapshot);
        )
        return 0;
    }
    pid_t processId = 0;
    bool relative = (strchr(imageName, ':') == NULL);
    do
    {
        // Return module handle if name matches.
        if(relative)
        {
            if(_stricmp(entry.szExeFile, imageName) == 0)
                processId = entry.th32ProcessID;
        }
        else
        {
#pragma WARN("TODO: Implement searching for absolute image name.")
            break;
        }
    }
    while(Process32Next(snapshot, &entry) == TRUE && processId == 0);
    PRESERVE_LAST_ERROR(
        CloseHandle(snapshot);
    )
    return processId;
}
#ifdef _UNICODE
#define PROCESSENTRY32 PROCESSENTRY32W
#define Process32First Process32FirstW
#define Process32Next Process32NextW
#endif

pid_t WinHookApi GetProcessIdByImageNameW(
    __in wchar_t const* imageName
    )
{
    // Acquire snapshot.
    handle_t snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if(snapshot == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    // Iterate over all snapshot entries.
    if(Process32FirstW(snapshot, &entry) == FALSE)
    {
        PRESERVE_LAST_ERROR(
            CloseHandle(snapshot);
        )
        return 0;
    }
    pid_t processId = 0;
    bool relative = (wcschr(imageName, L':') == NULL);
    do
    {
        // Return module handle if name matches.
        if(relative)
        {
            if(_wcsicmp(entry.szExeFile, imageName) == 0)
                processId = entry.th32ProcessID;
        }
        else
        {
#pragma WARN("TODO: Implement searching for absolute image name.")
            break;
        }
    }
    while(Process32NextW(snapshot, &entry) == TRUE && processId == 0);
    PRESERVE_LAST_ERROR(
        CloseHandle(snapshot);
    )
    return processId;
}

__forceinline pid_t WinHookApi _GetProcessIdByWindow(
    __in HWND window
    )
{
    pid_t processId;
    tid_t threadId = GetWindowThreadProcessId(window, (DWORD*)&processId);
    if(threadId == 0)
        return 0;
    return processId;
}

pid_t WinHookApi GetProcessIdByWindowTitleA(
    __in char const* windowTitle
    )
{
    HWND window = FindWindowA(NULL, windowTitle);
    if(window == NULL)
        return 0;
    return _GetProcessIdByWindow(window);
}

pid_t WinHookApi GetProcessIdByWindowTitleW(
    __in wchar_t const* windowTitle
    )
{
    HWND window = FindWindowW(NULL, windowTitle);
    if(window == NULL)
        return 0;
    return _GetProcessIdByWindow(window);
}

pid_t WinHookApi GetProcessIdByThreadId(
    __in tid_t threadId
    )
{
    handle_t thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
    if(thread == NULL)
        return 0;
    pid_t processId = GetProcessIdOfThread(thread);
    PRESERVE_LAST_ERROR(
        CloseHandle(thread);
    )
    return processId;
}

#ifndef _WIN64
tid_t WinHookApi GetMainThreadIdFromTIB(
    __in handle_t process
    )
{
    ptr32_t tib = NULL;
    // Perform black magic ;)
    _asm
    {
        // FS register points to the Win32 TIB.
        // 0x18 is the offset into the TIB at which the linear TIB base address is stored.
        mov eax, fs:[0x18]
        // Save base address of TIB.
        mov [tib], eax
    }
    // Read thread id from target process.
    tid_t threadId;
    size_t bytesRead = ReadMemoryEx(process, tib + 0x24, &threadId, sizeof(threadId));
    if(bytesRead != sizeof(threadId))
        return 0;
    return threadId;
}
#endif

tid_t WinHookApi GetMainThreadIdByCreationTime(
    __in pid_t processId
    )
{
    // Acquire snapshot.
    handle_t snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if(snapshot == INVALID_HANDLE_VALUE)
        return 0;
    THREADENTRY32 entry;
    entry.dwSize = sizeof(entry);
    tid_t threadId = 0;
    // Iterate over all snapshot entries.
    if(Thread32First(snapshot, &entry) == FALSE)
    {
        PRESERVE_LAST_ERROR(
            CloseHandle(snapshot);
        )
        return 0;
    };
    FILETIME oldest = { MAXDWORD, MAXDWORD };
    do
    {
        // Check if thread belongs to target process.
        if(entry.th32OwnerProcessID == processId)
        {
            handle_t thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if(thread == NULL)
                break;
            FILETIME times[4];
            if(GetThreadTimes(thread, &times[0], &times[1], &times[2], &times[3]) == FALSE)
            {
                PRESERVE_LAST_ERROR(
                    CloseHandle(thread);
                )
                break;
            }
            // True when creation time of current thread is earlier than former one.
            if(CompareFileTime(&times[0], &oldest) < 0)
            {
                threadId = entry.th32ThreadID;
                oldest = times[0];
            }
            CloseHandle(thread);
        }
    }
    while(Thread32Next(snapshot, &entry) == TRUE);
    PRESERVE_LAST_ERROR(
        CloseHandle(snapshot);
    )
    return threadId;
}

#ifdef _UNICODE
// TlHelp32.h does not use the common ASCII / unicode pattern with prefixing
// the functions with 'A' or 'W' but redefines the names of the ASCII versions
// to the unicode versions, so they are not usable without undefining them.
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif
HMODULE WinHookApi GetModuleHandleExA(
    __in pid_t processId,
    __in char const* moduleName
    )
{
    // Acquire snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if(snapshot == INVALID_HANDLE_VALUE)
        return NULL;
    MODULEENTRY32 entry;
    entry.dwSize = sizeof(entry);
    // Iterate over all snapshot entries.
    if(Module32First(snapshot, &entry) == FALSE)
    {
        PRESERVE_LAST_ERROR(
            CloseHandle(snapshot);
        )
        return NULL;
    }
    HMODULE module = NULL;
    bool relative = (strchr(moduleName, ':') == NULL);
    do
    {
        // Return module handle if name matches.
        if(relative)
        {
            if(_stricmp(entry.szModule, moduleName) == 0)
                module = entry.hModule;
        }
        else
        {
            if(_stricmp(entry.szExePath, moduleName) == 0)
                module = entry.hModule;
        }
    }
    while(Module32Next(snapshot, &entry) == TRUE && module == NULL);
    PRESERVE_LAST_ERROR(
        CloseHandle(snapshot);
    )
    return module;
}
#ifdef _UNICODE
#define MODULEENTRY32 MODULEENTRY32W
#define Module32First Module32FirstW
#define Module32Next Module32NextW
#endif

HMODULE WinHookApi GetModuleHandleExW(
    __in pid_t processId,
    __in wchar_t const* moduleName
    )
{
    // Acquire snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if(snapshot == INVALID_HANDLE_VALUE)
        return NULL;
    MODULEENTRY32W entry;
    entry.dwSize = sizeof(entry);
    // Iterate over all snapshot entries.
    if(Module32FirstW(snapshot, &entry) == FALSE)
    {
        PRESERVE_LAST_ERROR(
            CloseHandle(snapshot);
        )
        return NULL;
    }
    HMODULE module = NULL;
    bool relative = (wcschr(moduleName, L':') == NULL);
    do
    {
        // Return module handle if name matches.
        if(relative)
        {
            if(_wcsicmp(entry.szModule, moduleName) == 0)
                module = entry.hModule;
        }
        else
        {
            if(_wcsicmp(entry.szExePath, moduleName) == 0)
                module = entry.hModule;
        }
    }
    while(Module32NextW(snapshot, &entry) == TRUE && module == NULL);
    PRESERVE_LAST_ERROR(
        CloseHandle(snapshot);
    )
    return module;
}

ptr_t WinHookApi GetProcAddressEx(
    __in handle_t process,
    __in HMODULE module,
    __in char const* functionName
    )
{
#pragma WARN( \
    "TODO: Get proc address by reading the export table from the target process.\n" \
    "ATM the determined addresses are only valid, when the library exporting the \n" \
    "function is loaded in the current process at the same base address." \
    )
    return (ptr_t)GetProcAddress(module, functionName);
}

bool WinHookApi _ExecuteFunctionAsNewThreadEx(
    __in handle_t process,
    __in HMODULE remoteModule,
    __in char const* functionName,
    __in ptr_t parameter,
    __in bool wait,
    __out_opt dword_t* returnValue
    )
{
    ptr_t remoteFunction = GetProcAddressEx(process, remoteModule, functionName);
    if(remoteFunction == NULL)
        return false;
    // Run function in target process as new thread
    handle_t thread = CreateRemoteThread(
        process,
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)remoteFunction,
        (void*)parameter,
        NULL,
        NULL
        );
    if(thread == NULL)
        return false;
    // Wait for thread to exit
    bool result = (WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0);
    // Retrieve exit code
    if(result && returnValue != NULL)
        result = (GetExitCodeThread(thread, (DWORD*)returnValue) != FALSE);
    PRESERVE_LAST_ERROR(
        CloseHandle(thread);
    )
    return result;
}

bool WinHookApi ExecuteFunctionAsNewThreadExA(
    __in handle_t process,
    __in char const* moduleName,
    __in char const* functionName,
    __in ptr_t parameter,
    __in bool wait,
    __out_opt dword_t* returnValue
    )
{
    // Get address of exported function to execute in address space of target process
    HMODULE remoteModule = GetModuleHandleExA(GetProcessId(process), moduleName);
    if(remoteModule == NULL)
        return false;
    return _ExecuteFunctionAsNewThreadEx(
        process,
        remoteModule,
        functionName,
        parameter,
        wait,
        returnValue
        );
}

bool WinHookApi ExecuteFunctionAsNewThreadExW(
    __in handle_t process,
    __in wchar_t const* moduleName,
    __in char const* functionName,
    __in ptr_t parameter,
    __in bool wait,
    __out_opt dword_t* returnValue
    )
{
    // Get address of exported function to execute in address space of target process
    HMODULE remoteModule = GetModuleHandleExW(GetProcessId(process), moduleName);
    if(remoteModule == NULL)
        return false;
    return _ExecuteFunctionAsNewThreadEx(
        process,
        remoteModule,
        functionName,
        parameter,
        wait,
        returnValue
        );
}

ptr_t WinHookApi GetEipEx(
    __in handle_t thread
    )
{
    // Suspend target thread before performing any operation.
    if(SuspendThread(thread) == (DWORD)-1)
        return NULL;
    // Get current SS:ESP, CS:EIP, FLAGS, EBP of target thread.
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if(GetThreadContext(thread, &ctx) == FALSE)
    {
        // Resume thread on error and preserve error code for caller.
        PRESERVE_LAST_ERROR(
            ResumeThread(thread);
        )
        return NULL;
    }
    // Resume target thread.
    if(ResumeThread(thread) == (DWORD)-1)
        return NULL;
    return ctx.Eip;
}

bool WinHookApi SetEipEx(
    __in handle_t thread,
    __in ptr_t eip
    )
{
    // Suspend target thread before performing any operation.
    if(SuspendThread(thread) == (DWORD)-1)
        return false;
    // Get current SS:ESP, CS:EIP, FLAGS, EBP of target thread.
    ptr_t oldEip = NULL;
    bool eipSet = false;
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if(GetThreadContext(thread, &ctx) == FALSE)
        goto OnError;
    // Set EIP to target address and write SS:ESP, CS:EIP, FLAGS, EBP back.
    oldEip = ctx.Eip;
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.Eip = eip;
    if(SetThreadContext(thread, &ctx) == FALSE)
        goto OnError;
    eipSet = true;
    // Resume target thread.
    if(ResumeThread(thread) == (DWORD)-1)
        goto OnError;
    return true;
OnError:
    // Resume thread on error and preserve error code for caller.
    PRESERVE_LAST_ERROR(
        // If EIP was already set, try to reset it.
        if(eipSet)
        {
            ctx.ContextFlags = CONTEXT_CONTROL;
            ctx.Eip = oldEip;
            SetThreadContext(thread, &ctx);
        }
        ResumeThread(thread);
    )
    return false;
}

// Precompiled stub guard for injecting into target process.
// Using a __declspec(naked) function with inline assembly is not an option,
// since there is no reliable way of calculating the size of the stub or
// determining the offsets of the addresses to patch.
byte_t _StubGuardInit[] = {
    '\x68', '\xde', '\xc0', '\xad', '\xde', // push 0xdeadc0de          ; Push return address so we can return to it later
    '\x9c',                                 // pushfd                   ; Push eFLAGS register
    '\x60'                                  // pushad                   ; Push general-purpose registers
};
// When patching, add push instruction for parameters here.
byte_t _StubGuardCallAndExit[] = {
    '\xb8', '\xde', '\xc0', '\xad', '\xde', // mov eax, 0xdeadc0de      ; Push stub address
    '\xff', '\xd0',                         // call eax                 ; Call stub
    //'\xa3', '\xde', '\xc0', '\xad', '\xde', // mov [0xdeadc0de], eax    ; Store return value for checking
    '\x61',                                 // popad                    ; Pop previously pushed general-purpose registers
    '\x9d',                                 // popfd                    ; Pop previously pushed eFLAGS register
    '\xc3'                                  // ret                      ; Return control to the hijacked thread
};

#define STUBGUARD_INIT_OFFSET_EIP 1
#define STUBGUARD_EXIT_OFFSET_STUB 1
#define STUBGUARD_EXIT_OFFSET_RESULT 8

bool WinHookApi ExecuteStubEx(
    __in handle_t process,
    __in handle_t thread,
    __in void const* stub,
    __in size_t stubSize,
    __in ptr_t* parameters,
    __in size_t parameterCount
    )
{
    ptr_t oldEip = NULL;
    ptr_t remoteStub = NULL;
    ptr_t remoteGuard = NULL;
    bool threadSuspended = false;
    bool eipSet = false;
    // Suspend target thread before performing any operation.
    if(SuspendThread(thread) == (DWORD)-1)
        goto OnError;
    threadSuspended = true;
    // Get current value of EIP in target thread.
    oldEip = GetEipEx(thread);
    if(oldEip == NULL)
        goto OnError;
    // Write stub to address space of target process
    remoteStub = StoreMemoryEx(process, Execute, 0, stub, stubSize);
    if(remoteStub == NULL)
        goto OnError;
    // Patch stub guard with EIP to return to, given parameters for stub, and address of stub.
    size_t patchedGuardSize =
        sizeof(_StubGuardInit) + ((1 + sizeof(parameters[0])) * parameterCount) + sizeof(_StubGuardCallAndExit);
    byte_t* patchedGuard = new byte_t[patchedGuardSize];
    memcpy_s(patchedGuard, patchedGuardSize, _StubGuardInit, sizeof(_StubGuardInit));
    *(ptr_t*)(patchedGuard + STUBGUARD_INIT_OFFSET_EIP) = oldEip;
    byte_t* patchedGuardPos = patchedGuard + sizeof(_StubGuardInit);
    for(size_t i = parameterCount; i > 0; i--)
    {
        *patchedGuardPos = '\x68'; // push
        *(ptr_t*)(patchedGuardPos + 1) = parameters[i - 1];
        patchedGuardPos += 1 + sizeof(parameters[0]);
    }
    size_t patchedGuardSizeLeft = patchedGuardSize - (patchedGuardPos - patchedGuard);
    memcpy_s(patchedGuardPos, patchedGuardSizeLeft, _StubGuardCallAndExit, sizeof(_StubGuardCallAndExit));
    *(ptr_t*)(patchedGuardPos + STUBGUARD_EXIT_OFFSET_STUB) = remoteStub;
    // Write patched stub guard to address space of target process.
    remoteGuard = StoreMemoryEx(process, Execute, 0, patchedGuard, patchedGuardSize);
    delete[] patchedGuard;
    if(remoteGuard == NULL)
        goto OnError;
    // Set EIP of target thread to stub guard.
    if(!SetEipEx(thread, remoteGuard))
        goto OnError;
    eipSet = true;
    // Resume target thread.
    if(ResumeThread(thread) == (DWORD)-1)
        goto OnError;
    return true;
OnError:
    PRESERVE_LAST_ERROR(
        // Free allocated resources.
        if(remoteGuard != NULL)
            FreeMemoryEx(process, remoteGuard);
        if(remoteStub != NULL)
            FreeMemoryEx(process, remoteStub);
        // Try to restore a valid state in the target process.
        // Reset EIP to old value.
        if(eipSet)
            SetEipEx(thread, oldEip);
        // Resume remote thread with an (again) valid EIP.
        if(threadSuspended)
            ResumeThread(thread);
    )
    return false;
}

bool WinHookApi ExecuteStubEx(
    __in handle_t thread,
    __in void const* stub,
    __in size_t stubSize,
    __in ptr_t* parameters,
    __in size_t parameterCount
    )
{
    // Open the process associated with the target thread.
    pid_t processId = GetProcessIdOfThread(thread);
    if(processId == 0)
        return false;
    handle_t process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
    if(process == NULL)
        return false;
    bool result = ExecuteStubEx(process, thread, stub, stubSize, parameters, parameterCount);
    PRESERVE_LAST_ERROR(
        CloseHandle(process);
    )
    return result;
}
