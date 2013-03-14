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

#ifndef __WinHook_WinHook_hpp__
#define __WinHook_WinHook_hpp__

#include <Windows.h>

/****************************************************************
 * Preprocessor
 */

#ifdef _M_X64
#pragma message ERR("x86_64 is not supported yet!")
#endif

#ifdef BUILDING_WINHOOK
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif

#define __STRINGISE__(n) #n
#define __EXPAND_AND_STRINGISE__(n) __STRINGISE__(n)
#define PREMSG(lvl, exp) (__FILE__ "(" __EXPAND_AND_STRINGISE__(__LINE__) ") : " lvl ": [" __FUNCTION__ "] " exp)
#define WARN(exp) PREMSG("warning", exp)
#define ERR (exp) PREMSG("error", exp)

/****************************************************************
 * Privileges
 */

/* Enables or removes a privilege for the current process.
 */
EXPORTED BOOL WINAPI AdjustPrivilege(
    __in LPCSTR szName,
    __in BOOL bEnable
    );

/* Enables the debug privilege for the current process.
 */
EXPORTED BOOL WINAPI EnableDebugPrivilege();

/****************************************************************
 * Process manipulation
 */

/* Retrieves the process id of the first process whose image name matches the
 * specified string.
 */
EXPORTED DWORD WINAPI GetProcessID(
    __in LPCSTR szProcessName
    );

/* Retrieves the thread id of the main thread of the specified process.
 */
EXPORTED DWORD WINAPI GetMainThreadID(
    __in HANDLE hProcess            /* PROCESS_VM_READ */
    );
EXPORTED DWORD WINAPI GetMainThreadID(
    __in DWORD dwProcessID
    );

/* Acquires the handle to the first module loaded by a remote process whose
 * name matches the specified string.
 */
EXPORTED HMODULE WINAPI RemoteGetModuleHandle(
    __in HANDLE hProcess,           /* PROCESS_QUERY_INFORMATION, PROCESS_VM_READ */
    __in LPCSTR szModuleName
    );
EXPORTED HMODULE WINAPI RemoteGetModuleHandle(
    __in DWORD dwProcessID,
    __in LPCSTR szModuleName
    );

/* Returns the address of a function in another process. This function must be
 * exported by a DLL that was already loaded by the target process.
 */
EXPORTED FARPROC WINAPI RemoteGetProcAddress(
    __in HANDLE hProcess,
    __in HMODULE hModule,
    __in LPCSTR szFunctionName
    );
EXPORTED FARPROC WINAPI RemoteGetProcAddress(
    __in HANDLE hProcess,
    __in LPCSTR szModulename,
    __in LPCSTR szFunctionName
    );
EXPORTED FARPROC WINAPI RemoteGetProcAddress(
    __in DWORD dwProcessID,
    __in LPCSTR szModulename,
    __in LPCSTR szFunctionName
    );

/* Allocates a region of memory with the specified access rights within the
 * virtual address space of another process and writes data to it.
 */
EXPORTED LPVOID WINAPI RemoteStoreData(
    __in HANDLE hProcess,           /* PROCESS_VM_OPERATION, PROCESS_VM_WRITE */
    __in LPCVOID pData,
    __in DWORD dwDataSize,
    __in DWORD dwProtection
    );
EXPORTED LPVOID WINAPI RemoteStoreData(
    __in DWORD dwProcessID,
    __in LPCVOID pData,
    __in DWORD dwDataSize,
    __in DWORD dwProtection
    );

/* Frees a region of memory within the virtual address space of another
 * process, previously allocated by a call to `RemoteStoreData()`.
 */
EXPORTED BOOL WINAPI RemoteFreeData(
    __in HANDLE hProcess,           /* PROCESS_VM_OPERATION */
    __in LPVOID pData,
    __in DWORD dwDataSize
    );
EXPORTED BOOL WINAPI RemoteFreeData(
    __in DWORD dwProcessID,
    __in LPVOID pData,
    __in DWORD dwDataSize
    );

/* Lets another process execute a function in a new thread and optionally waits
 * for it to exit. This function must be exported by a DLL that was already
 * loaded by the target process.
 */
EXPORTED BOOL WINAPI RemoteExecuteFunctionInNewThread(
    __in HANDLE hProcess,           /* PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE */
    __in LPCSTR szModuleName,
    __in LPCSTR szFunctionName,
    __in LPVOID pParameter,
    __in BOOL bWait,
    __out_opt DWORD* pReturnValue = NULL
    );
EXPORTED BOOL WINAPI RemoteExecuteFunctionInNewThread(
    __in DWORD dwProcessID,
    __in LPCSTR szModuleName,
    __in LPCSTR szFunctionName,
    __in LPVOID pParameter,
    __in BOOL bWait,
    __out_opt DWORD* pReturnValue = NULL
    );

/* Lets another process execute a stub in the specified thread.
 */
EXPORTED BOOL WINAPI RemoteExecuteStub(
    __in HANDLE hProcess,           /* PROCESS_VM_WRITE, PROCESS_VM_OPERATION */
    __in HANDLE hThread,            /* THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT */
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    );
EXPORTED BOOL WINAPI RemoteExecuteStub(
    __in HANDLE hThread,            /* THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT */
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    );
EXPORTED BOOL WINAPI RemoteExecuteStub(
    __in DWORD dwThreadID,
    __in LPCVOID pStub,
    __in DWORD dwStubSize,
    __in UINT_PTR* ppParameters,
    __in DWORD dwParameterCount
    );

/* Gets the current EIP of the specified thread.
 */
EXPORTED UINT_PTR WINAPI RemoteGetEIP(
    __in HANDLE hThread             /* THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION */
    );
EXPORTED UINT_PTR WINAPI RemoteGetEIP(
    __in DWORD dwThreadID
    );

/* Sets the current EIP of the specified thread.
 */
EXPORTED BOOL WINAPI RemoteSetEIP(
    __in HANDLE hThread,            /* THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT */
    __in UINT_PTR pEIP
    );
EXPORTED BOOL WINAPI RemoteSetEIP(
    __in DWORD dwThreadID,
    __in UINT_PTR pEIP
    );

#endif // #ifndef __WinHook_WinHook_hpp__
