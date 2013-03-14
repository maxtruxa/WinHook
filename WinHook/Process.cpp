/* Copyright (c) 2013 Max Truxa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "WinHookInternal.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

DWORD WINAPI GetProcessID(
    __in LPCSTR szProcessName
    )
{
    /* Acquire snapshot */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if(hSnapshot == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    DWORD dwProcessID = 0;
    /* Iterate over all snapshot entries */
    if(Process32First(hSnapshot, &entry) == TRUE)
    {
        do
        {
            /* Return process id if name matches */
            if(_stricmp(entry.szExeFile, szProcessName) == 0)
                dwProcessID = entry.th32ProcessID;
        }
        while(Process32Next(hSnapshot, &entry) == TRUE && dwProcessID == 0);
    }
    CloseHandlePreservingLastError(hSnapshot);
    return dwProcessID;
}

DWORD WINAPI GetMainThreadID(
    __in HANDLE hProcess
    )
{
    LPVOID pTIB = NULL;
    /* Perform black magic ;) */
    _asm
    {
        /* fs points to the Win32 TIB
         * 0x18 is the offset into the TIB at which the linear TIB base address is stored */
        mov eax, fs:[0x18]
        /* Save base address of TIB */
        mov [pTIB], eax
    }
    /* Read thread id from target process */
    DWORD dwThreadID;
    if(ReadProcessMemory(hProcess, static_cast<BYTE*>(pTIB) + 0x24, &dwThreadID, sizeof(dwThreadID), NULL) == FALSE)
        return 0;
    return dwThreadID;
}

DWORD WINAPI GetMainThreadID(
    __in DWORD dwProcessID
    )
{
    /* ReadProcessMemory: PROCESS_VM_READ
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwProcessID);
    if(hProcess == NULL)
        return 0;
    DWORD dwThreadID = GetMainThreadID(hProcess);
    CloseHandlePreservingLastError(hProcess);
    return dwThreadID;
}

HMODULE WINAPI RemoteGetModuleHandle(
    __in HANDLE hProcess,
    __in LPCSTR szModuleName
    )
{
#pragma message WARN("TODO: Use CreateToolhelp32Snapshot instead of EnumProcessModules.")
    HMODULE* hAllModules = NULL;
    try
    {
        /* Determine buffer size required to hold snapshot of all modules loaded by target process */
        hAllModules = new HMODULE;
        DWORD dwNeeded = 0;
        EnumProcessModules(hProcess, hAllModules, sizeof(HMODULE), &dwNeeded);
        if(dwNeeded == 0)
            return NULL;
        delete hAllModules;
        hAllModules = NULL;
        /* Get snapshot of all modules */
        hAllModules = new HMODULE[dwNeeded / sizeof(HMODULE)];
        if(EnumProcessModules(hProcess, hAllModules, sizeof(HMODULE) * dwNeeded, &dwNeeded) != FALSE)
        {
            /* Iterate over all entries */
            CHAR szNameOfModuleToTest[MAX_PATH];
            for(size_t i = 0; i < (dwNeeded / sizeof(HMODULE)); i++)
            {
                /* Return module handle if name matches */
                if(GetModuleBaseName(hProcess, hAllModules[i], szNameOfModuleToTest, sizeof(szNameOfModuleToTest)) == 0)
                    continue;
                if(_stricmp(szNameOfModuleToTest, szModuleName) == 0)
                {
                    HMODULE hModule = hAllModules[i];
                    delete [] hAllModules;
                    return hModule;
                }
            }
        }
    }
    catch(...) { }
    if(hAllModules != NULL)
        delete [] hAllModules;
    return NULL;
}

HMODULE WINAPI RemoteGetModuleHandle(
    __in DWORD dwProcessID,
    __in LPCSTR szModuleName
    )
{
    /* EnumProcessModules: PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
     * GetModuleBaseName: PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
     */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    HMODULE hModule = RemoteGetModuleHandle(hProcess, szModuleName);
    CloseHandlePreservingLastError(hProcess);
    return hModule;
}

FARPROC WINAPI RemoteGetProcAddress(
    __in HANDLE hProcess,
    __in HMODULE hModule,
    __in LPCSTR szFunctionName
    )
{
#pragma message WARN("TODO: Implement it the correct way.")
    return GetProcAddress(hModule, szFunctionName);
}

FARPROC WINAPI RemoteGetProcAddress(
    __in HANDLE hProcess,
    __in LPCSTR szModulename,
    __in LPCSTR szFunctionName
    )
{
    //HMODULE hModule = RemoteGetModuleHandle(hProcess, szModulename);
    HMODULE hModule = GetModuleHandle(szModulename);
    if(hModule == NULL)
        return FALSE;
    return RemoteGetProcAddress(hProcess, hModule, szFunctionName);
}

FARPROC WINAPI RemoteGetProcAddress(
    __in DWORD dwProcessID,
    __in LPCSTR szModulename,
    __in LPCSTR szFunctionName
    )
{
    /*
     */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    FARPROC pRemoteProc = RemoteGetProcAddress(hProcess, szModulename, szFunctionName);
    CloseHandlePreservingLastError(hProcess);
    return pRemoteProc;
}

LPVOID WINAPI RemoteStoreData(
    __in HANDLE hProcess,
    __in LPCVOID pData,
    __in DWORD dwDataSize,
    __in DWORD dwProtection
    )
{
    /* Allocate memory in address space of target process */
    LPVOID pRemoteData = VirtualAllocEx(hProcess, NULL, dwDataSize, MEM_RESERVE | MEM_COMMIT, dwProtection);
    if(pRemoteData == NULL)
        return NULL;
    /* Write data to allocated memory */
    if(WriteProcessMemory(hProcess, pRemoteData, pData, dwDataSize, NULL) == FALSE)
    {
        DWORD dwLastError = GetLastError();
        RemoteFreeData(hProcess, pRemoteData, dwDataSize);
        SetLastError(dwLastError);
        return NULL;
    }
    return pRemoteData;
}

LPVOID WINAPI RemoteStoreData(
    __in DWORD dwProcessID,
    __in LPCVOID pData,
    __in DWORD dwDataSize,
    __in DWORD dwProtection
    )
{
    /* VirtualAllocEx: PROCESS_VM_OPERATION
     * WriteProcessMemory: PROCESS_VM_WRITE, PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    LPVOID pRemoteData = RemoteStoreData(hProcess, pData, dwDataSize, dwProtection);
    CloseHandlePreservingLastError(hProcess);
    return pRemoteData;
}

BOOL WINAPI RemoteFreeData(
    __in HANDLE hProcess,
    __in LPVOID pData,
    __in DWORD dwDataSize
    )
{
    /* Release memory */
    return VirtualFreeEx(hProcess, pData, dwDataSize, MEM_DECOMMIT);
}

BOOL WINAPI RemoteFreeData(
    __in DWORD dwProcessID,
    __in LPVOID pData,
    __in DWORD dwDataSize
    )
{
    /* VirtualFreeEx: PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    BOOL bResult = RemoteFreeData(hProcess, pData, dwDataSize);
    CloseHandlePreservingLastError(hProcess);
    return bResult;
}

BOOL WINAPI RemoteExecuteFunctionInNewThread(
    __in HANDLE hProcess,
    __in LPCSTR szModuleName,
    __in LPCSTR szFunctionName,
    __in LPVOID pParameter,
    __in BOOL bWait,
    __out_opt DWORD* pReturnValue
    )
{
    /* Get address of exported function to execute in address space of target process */
    LPVOID pFuncAddr = static_cast<LPVOID>(RemoteGetProcAddress(hProcess, szModuleName, szFunctionName));
    if(pFuncAddr == NULL)
        return FALSE;
    /* Run function in target process as new thread */
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pFuncAddr, pParameter, NULL, NULL);
    if(hThread == NULL)
        return FALSE;
    /* Wait for thread to exit */
    BOOL bResult = (WaitForSingleObject(hThread, INFINITE) == WAIT_OBJECT_0 ? TRUE : FALSE);
    /* Retrieve exit code */
    if(bResult == TRUE && pReturnValue != NULL)
    {
        bResult = GetExitCodeThread(hThread, pReturnValue);
    }
    CloseHandlePreservingLastError(hThread);
    return bResult;
}

BOOL WINAPI RemoteExecuteFunctionInNewThread(
    __in DWORD dwProcessID,
    __in LPCSTR szModuleName,
    __in LPCSTR szFunctionName,
    __in LPVOID pParameter,
    __in BOOL bWait,
    __out_opt DWORD* pReturnValue
    )
{
    /* RemoteGetModuleHandle: PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
    * CreateRemoteThread: PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ
    */
    DWORD dwAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    HANDLE hProcess = OpenProcess(dwAccess, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    BOOL bResult = RemoteExecuteFunctionInNewThread(hProcess, szModuleName, szFunctionName, pParameter, bWait, pReturnValue);
    CloseHandlePreservingLastError(hProcess);
    return bResult;
}

BYTE _StubGuardInit[] = {
    '\x68', '\xde', '\xc0', '\xad', '\xde', /* push 0xdeadc0de          ; Push return address so we can return to it later  */
    '\x9c',                                 /* pushfd                   ; Push eFLAGS register                              */
    '\x60'                                  /* pushad                   ; Push general-purpose registers                    */
};
/* When patching, add push instruction for parameters here */
BYTE _StubGuardCallAndExit[] = {
    '\xb8', '\xde', '\xc0', '\xad', '\xde', /* mov eax, 0xdeadc0de      ; Call stub                                         */
    '\xff', '\xd0',                         /* call eax                 ;                                                   */
    //'\xa3', '\xde', '\xc0', '\xad', '\xde', /* mov [0xdeadc0de], eax    ; Store return value for checking                   */
    '\x61',                                 /* popad                    ; Pop previously pushed general-purpose registers   */
    '\x9d',                                 /* popfd                    ; Pop previously pushed eFLAGS register             */
    '\xc3'                                  /* ret                      ; Return control to the hijacked thread             */
};

#define STUBGUARD_INIT_OFFSET_EIP 1
#define STUBGUARD_EXIT_OFFSET_STUB 1
#define STUBGUARD_EXIT_OFFSET_RESULT 8

BOOL WINAPI RemoteExecuteStub(
    __in HANDLE hProcess,
    __in HANDLE hThread,
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    )
{
    BOOL bResult = FALSE;
    UINT_PTR pOldEip = NULL;
    LPVOID pRemoteStub = NULL;
    LPVOID pRemoteGuard = NULL;
    BOOL bThreadSuspended = FALSE;
    BOOL bEipSet = FALSE;
    /* Suspend target thread before performing any operation */
    if(SuspendThread(hThread) == static_cast<DWORD>(-1))
        goto Exit;
    bThreadSuspended = TRUE;
    /* Get current value of EIP in target thread */
    pOldEip = RemoteGetEIP(hThread);
    if(pOldEip == NULL)
        goto Exit;
    /* Write stub to address space of target process */
    pRemoteStub = RemoteStoreData(hProcess, pStub, dwStubSize, PAGE_EXECUTE_READWRITE);
    if(pRemoteStub == NULL)
        goto Exit;
    /* Patch stub guard with EIP to return to, given parameters for stub, and address of stub */
    DWORD dwPatchedGuardSize = sizeof(_StubGuardInit) + (sizeof(*ppParameters) * dwParameterCount) + sizeof(_StubGuardCallAndExit);
    BYTE* pPatchedGuard = new BYTE[dwPatchedGuardSize];
    memcpy_s(pPatchedGuard, dwPatchedGuardSize, _StubGuardInit, sizeof(_StubGuardInit));
    *reinterpret_cast<UINT_PTR*>(pPatchedGuard + STUBGUARD_INIT_OFFSET_EIP) = static_cast<UINT_PTR>(pOldEip);
    BYTE* pPatchedGuardPos = pPatchedGuard + sizeof(_StubGuardInit);
    for(DWORD i = dwParameterCount; i > 0; i--)
    {
        *pPatchedGuardPos = '\x68'; /* push */
        *reinterpret_cast<UINT_PTR*>(pPatchedGuardPos + 1) = ppParameters[i - 1];
        pPatchedGuardPos += 1 + sizeof(*ppParameters);
    }
    memcpy_s(pPatchedGuardPos, dwPatchedGuardSize - (pPatchedGuardPos - pPatchedGuard), _StubGuardInit, sizeof(_StubGuardInit));
    *reinterpret_cast<UINT_PTR*>(pPatchedGuardPos + STUBGUARD_EXIT_OFFSET_STUB) = reinterpret_cast<UINT_PTR>(pRemoteStub);
    /* Write patched stub guard to address space of target process */
    pRemoteGuard = RemoteStoreData(hProcess, pPatchedGuard, dwPatchedGuardSize, PAGE_EXECUTE_READWRITE);
    delete[] pPatchedGuard;
    if(pRemoteGuard == NULL)
        goto Exit;
    /* Set EIP of target thread to stub guard */
    if(RemoteSetEIP(hThread, reinterpret_cast<UINT_PTR>(pRemoteGuard)) == FALSE)
        goto Exit;
    bEipSet = TRUE;
    /* Resume target thread */
    if(ResumeThread(hThread) == static_cast<DWORD>(-1))
        goto Exit;
    bResult = TRUE;
    Exit:
    if(bResult == FALSE)
    {
        /* Free allocated resources */
        if(pRemoteGuard != NULL)
            RemoteFreeData(hProcess, pRemoteGuard, dwPatchedGuardSize);
        if(pRemoteStub != NULL)
            RemoteFreeData(hProcess, pRemoteStub, dwStubSize);
        if(bEipSet == TRUE)
        {
            /* Try to reset EIP to old value */
            RemoteSetEIP(hThread, pOldEip);
        }
        /* Try to resume remote thread with a (again) valid EIP */
        if(bThreadSuspended == TRUE)
            ResumeThread(hThread);
    }
    return bResult;
}

BOOL WINAPI RemoteExecuteStub(
    __in HANDLE hThread,
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    )
{
    /* Open the process associated with the target thread */
    DWORD dwProcessID = GetProcessIdOfThread(hThread);
    if(dwProcessID == 0)
        return FALSE;
    /* RemoteStoreData: PROCESS_VM_WRITE, PROCESS_VM_OPERATION
     * RemoteFreeData: PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessID);
    if(hProcess == NULL)
        return FALSE;
    BOOL bResult = RemoteExecuteStub(hProcess, hThread, pStub, dwStubSize, ppParameters, dwParameterCount);
    CloseHandlePreservingLastError(hProcess);
    return bResult;
}

BOOL WINAPI RemoteExecuteStub(
    __in DWORD dwThreadID,
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    )
{
    /* GetProcessIdOfThread: THREAD_QUERY_INFORMATION
     * SuspendThread: THREAD_SUSPEND_RESUME
     * RemoteGetEIP: THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION
     * RemoteSetEIP: THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT
     * ResumeThread: THREAD_SUSPEND_RESUME
     */
    DWORD dwAccess = THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
    HANDLE hThread = OpenThread(dwAccess, FALSE, dwThreadID);
    if(hThread == NULL)
        return FALSE;
    BOOL bResult = RemoteExecuteStub(hThread, pStub, dwStubSize, ppParameters, dwParameterCount);
    CloseHandlePreservingLastError(hThread);
    return bResult;
}

UINT_PTR WINAPI RemoteGetEIP(
    __in HANDLE hThread
    )
{
    /* Suspend target thread before performing any operation. */
    if(SuspendThread(hThread) == static_cast<DWORD>(-1))
        return NULL;
    /* Get current SS:ESP, CS:EIP, FLAGS, EBP of target thread */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if(GetThreadContext(hThread, &ctx) == FALSE)
    {
        /* Resume thread on error and preserve error code for caller */
        DWORD dwLastError = GetLastError();
        ResumeThread(hThread);
        SetLastError(dwLastError);
        return NULL;
    }
    /* Resume target thread */
    if(ResumeThread(hThread) == static_cast<DWORD>(-1))
        return NULL;
    return ctx.Eip;
}

UINT_PTR WINAPI RemoteGetEIP(
    __in DWORD dwThreadID
    )
{
    /* SuspendThread: THREAD_SUSPEND_RESUME
     * GetThreadContext: THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION (x86_64)
     * ResumeThread: THREAD_SUSPEND_RESUME
     */
    DWORD dwAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION;
    HANDLE hThread = OpenThread(dwAccess, FALSE, dwThreadID);
    if(hThread == NULL)
        return NULL;
    UINT_PTR pEIP = RemoteGetEIP(hThread);
    CloseHandlePreservingLastError(hThread);
    return pEIP;
}

BOOL WINAPI RemoteSetEIP(
    __in HANDLE hThread,
    __in UINT_PTR pEIP
    )
{
    /* Suspend target thread before performing any operation. */
    if(SuspendThread(hThread) == static_cast<DWORD>(-1))
        return FALSE;
    /* Get current SS:ESP, CS:EIP, FLAGS, EBP of target thread */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if(GetThreadContext(hThread, &ctx) == FALSE)
        return FALSE;
    /* Set EIP to target address and write SS:ESP, CS:EIP, FLAGS, EBP back */
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.Eip = pEIP;
    if(SetThreadContext(hThread, &ctx) == FALSE)
        return FALSE;
    /* Resume target thread */
    if(ResumeThread(hThread) == static_cast<DWORD>(-1))
        return FALSE;
    return TRUE;
}

BOOL WINAPI RemoteSetEIP(
    __in DWORD dwThreadID,
    __in UINT_PTR pEIP
    )
{
    /* SuspendThread: THREAD_SUSPEND_RESUME
     * GetThreadContext: THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION (x86_64)
     * SetThreadContext: THREAD_SET_CONTEXT
     * ResumeThread: THREAD_SUSPEND_RESUME
     */
    DWORD dwAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;
    HANDLE hThread = OpenThread(dwAccess, FALSE, dwThreadID);
    if(hThread == NULL)
        return FALSE;
    BOOL bResult = RemoteSetEIP(hThread, pEIP);
    CloseHandlePreservingLastError(hThread);
    return bResult;
}
