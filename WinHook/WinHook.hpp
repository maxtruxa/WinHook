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

#ifndef __WinHook_WinHook_hpp__
#define __WinHook_WinHook_hpp__

#include <Windows.h>

/****************************************************************
 * Preprocessor
 */

#ifdef _WIN64
#pragma message ERR("x86_64 is not supported yet!")
#endif // #ifdef _WIN64

#ifdef BUILDING_WINHOOK
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif // #ifdef BUILDING_WINHOOK

#define WinHookApi __stdcall

#define __STRINGISE__(n) #n
#define __EXPAND_AND_STRINGISE__(n) __STRINGISE__(n)
#define PREMSG(lvl, exp) \
    message (__FILE__ "(" __EXPAND_AND_STRINGISE__(__LINE__) ") : " lvl ": [" __FUNCTION__ "] " exp)
#define WARN(exp) PREMSG("warning", exp)
#define ERR (exp) PREMSG("error", exp)

#define PRESERVE_LAST_ERROR(exp) { DWORD lastError = GetLastError(); exp; SetLastError(lastError); }

#define BITMASK_IS_SET(value, mask) (((value) & (mask)) == (mask))

#define COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))

/****************************************************************
 * Types
 */

/* Size specific types
 */
typedef __int8  int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8  uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

/* Basic types
 */
typedef int32_t  int_t;
typedef uint32_t uint_t;
#ifdef _UNICODE
typedef wchar_t char_t;
#else
typedef char char_t;
#endif // #ifdef _UNICODE

/* Machine types
 */
typedef uint8_t  byte_t;
typedef uint16_t word_t;
typedef uint32_t dword_t;
typedef uint64_t qword_t;

/* Additional types
 */
typedef uint32_t size32_t;
typedef uint64_t size64_t;
// size_t is most likely already defined through sourceannotations.h
#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
#ifdef _WIN64
typedef size64_t  size_t;
#else
typedef size32_t  size_t;
#endif // #ifdef _WIN64
#endif // #ifndef _SIZE_T_DEFINED
typedef uint32_t ptr32_t;
typedef uint64_t ptr64_t;
#ifdef _WIN64
typedef ptr64_t  ptr_t;
#else
typedef ptr32_t  ptr_t;
#endif // #ifdef _WIN64
typedef int32_t  offset32_t;
typedef int64_t  offset64_t;
#ifdef _WIN64
typedef offset64_t  offset_t;
#else
typedef offset32_t  offset_t;
#endif // #ifdef _WIN64
typedef dword_t pid_t;
typedef dword_t tid_t;

/* Windows specific types
 */
typedef HANDLE handle_t;

/****************************************************************
 * Memory.cpp
 */

enum PageProtection
{
    Invalid = 0,
    Execute = PAGE_EXECUTE,
    ExecuteRead = PAGE_EXECUTE_READ,
    ExecuteReadWrite = PAGE_EXECUTE_READWRITE,
    ExecuteWriteCopy = PAGE_EXECUTE_WRITECOPY,
    NoAccess = PAGE_NOACCESS,
    ReadOnly = PAGE_READONLY,
    ReadWrite = PAGE_READWRITE,
    WriteCopy = PAGE_WRITECOPY,
    Guard = PAGE_GUARD,
    NoCache = PAGE_NOCACHE,
    WriteCombine = PAGE_WRITECOMBINE
};

/* StoreMemoryEx
 *
 * Purpose:
 *   Allocates a region of memory within the virtual address space of a specified process and writes data to it.
 *
 * Parameters:
 *   process            in          The handle to a process. The function uses the address space of this process.
 *                                  The handle must have PROCESS_VM_OPERATION and PROCESS_VM_WRITE access rights.
 *   protection         in          The access protection for the region of pages to be allocated.
 *   allocSize          in          The size of the region of memory to allocate, in bytes.
 *                                  If this parameter is set to 0, the buffer size specified is used for allocation. If
 *                                  no buffer size is given, this parameter must be set to a value different than 0.
 *                                  This value is rounded up to the next page boundary.
 *   buffer             in          A pointer to the buffer that contains data to be copied to the address space of the
 *                                  specified process.
 *                                  If this parameter is set to NULL, memory is allocated without writing to it.
 *   bufferSize         in          The number of bytes to be copied from the buffer.
 *                                  If this parameter is set to 0, memory is allocated without writing to it.
 *
 * Return Value:
 *   If the function succeeds, the return value is the base address of the allocated region of pages.
 *   If the function fails, the return value is NULL. To get extended error information, call GetLastError.
 *
 * Comments:
 *   If the specified access protection would not allow writing, the function sets the protection to ReadWrite,
 *   copies the contents from buffer, and reverts the protection to the specified one.
 */
EXPORTED ptr_t WinHookApi StoreMemoryEx(
    __in handle_t process,
    __in PageProtection protection,
    __in size_t allocSize,
    __in_opt void const* buffer,
    __in_opt size_t bufferSize
    );

/* FreeMemoryEx
 *
 * Purpose:
 *   Frees a region of pages within the virtual address space of a specified process, typically previously allocated by
 *   a call to StoreMemoryEx.
 *
 * Parameters:
 *   process            in          The handle to a process. The function frees memory within the virtual address space
 *                                  of the process.
 *                                  The handle must have the PROCESS_VM_OPERATION access right.
 *   address            in          A pointer to the base address of the region of pages to be freed.
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi FreeMemoryEx(
    __in handle_t process,
    __in ptr_t address
    );

/* ProtectMemoryEx
 *
 * Purpose:
 *   Changes the access protection of a region of pages in the virtual address space of a specified process.
 *
 * Parameters:
 *   process            in          A handle to the process whose access protection is to be changed.
 *                                  The handle must have the PROCESS_VM_OPERATION access right.
 *   address            in          A pointer to the base address of the region of pages whose access protection
 *                                  is to be changed.
 *   size               in          The size of the region whose access protection attributes are changed, in bytes. The
 *                                  region of affected memory pages includes all pages containing one or more bytes of
 *                                  the region.
 *   newProtection      in          The access protection to be applied to the region of pages.
 *
 * Return Value:
 *   If the function succeeds, the return value is the old access protection.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED PageProtection WinHookApi ProtectMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __in size_t size,
    __in PageProtection newProtection
    );

/* ReadMemoryEx
 *
 * Purpose:
 *   Reads data from an area of memory in a specified process.
 *
 * Parameters:
 *   process            in          A handle to the process with memory that is being read.
 *                                  The handle must have the PROCESS_VM_READ access right.
 *   address            in          The base address in the specified process from which to read.
 *   buffer             out         A pointer to a buffer that receives the contents from the address space of the
 *                                  specified process.
 *   bufferSize         in          The number of bytes to be read from the specified process.
 *
 * Return Value:
 *   If the function succeeds, the return value is the number of bytes read.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED size_t WinHookApi ReadMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __out void* buffer,
    __in size_t bufferSize
    );

/* WriteMemoryEx
 *
 * Purpose:
 *   Writes data to an area of memory in a specified process.
 *
 * Parameters:
 *   process            in          A handle to the process with memory to be modified.
 *                                  The handle must have PROCESS_VM_OPERATION and PROCESS_VM_WRITE access rights.
 *   address            in          The base address in the specified process to which data is written.
 *   buffer             in          A pointer to the buffer that contains data to be written in the address space of the
 *                                  specified process.
 *   bufferSize         in          The number of bytes to be written to the specified process.
 *
 * Return Value:
 *   If the function succeeds, the return value is the number bytes written.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED size_t WinHookApi WriteMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __in void const* buffer,
    __in size_t bufferSize
    );

/****************************************************************
 * Privileges.cpp
 */

/* AdjustPrivilege
 *
 * Purpose:
 *   Enables or disables a privilege for the current process.
 *
 * Parameters:
 *   name               in          A pointer to a null-terminated string that specifies the name of the privilege to
 *                                  enable or disable.
 *   enable             in          Specifies whether the privilege is enabled or disabled.
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi AdjustPrivilegeA(
    __in char const* name,
    __in bool enable
    );
EXPORTED bool WinHookApi AdjustPrivilegeW(
    __in wchar_t const* name,
    __in bool enable
    );
#ifdef _UNICODE
#define AdjustPrivilege AdjustPrivilegeW
#else
#define AdjustPrivilege AdjustPrivilegeA
#endif

/* EnableDebugPrivilege
 *
 * Purpose:
 *   Enables the debug privilege for the current process.
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi EnableDebugPrivilege();

/****************************************************************
 * Process.cpp
 */

/* GetProcessIdByImageName
 *
 * Purpose:
 *   Retrieves the process id of the first process whose image name matches the specified string.
 *
 * Parameters:
 *   imageName          in          A pointer to a null-terminated string that specifies the image name to search for.
 *
 * Return Value:
 *   If the function succeeds, the return value is the process id.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED pid_t WinHookApi GetProcessIdByImageNameA(
    __in char const* imageName
    );
EXPORTED pid_t WinHookApi GetProcessIdByImageNameW(
    __in wchar_t const* imageName
    );
#ifdef _UNICODE
#define GetProcessIdByImageName GetProcessIdByImageNameW
#else
#define GetProcessIdByImageName GetProcessIdByImageNameA
#endif

/* GetProcessIdByWindowTitle
 *
 * Purpose:
 *   Retrieves the process id of the first process whose window title matches the specified string.
 *
 * Parameters:
 *   windowTitle        in          A pointer to a null-terminated string that specifies the window title to search for.
 *
 * Return Value:
 *   If the function succeeds, the return value is the process id.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED pid_t WinHookApi GetProcessIdByWindowTitleA(
    __in char const* windowTitle
    );
EXPORTED pid_t WinHookApi GetProcessIdByWindowTitleW(
    __in wchar_t const* windowTitle
    );
#ifdef _UNICODE
#define GetProcessIdByWindowTitle GetProcessIdByWindowTitleW
#else
#define GetProcessIdByWindowTitle GetProcessIdByWindowTitleA
#endif

/* GetProcessIdByThreadId
 *
 * Purpose:
 *   Retrieves the process id of the process associated with the specified thread.
 *
 * Parameters:
 *   threadId           in          The id of the thread whose associated process id to retrieve.
 *
 * Return Value:
 *   If the function succeeds, the return value is the process id.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED pid_t WinHookApi GetProcessIdByThreadId(
    __in tid_t threadId
    );

/* GetMainThreadIdFromTIB
 *
 * Purpose:
 *   Retrieves the thread id of the main thread of the specified process by looking it up in the thread information
 *   block.
 *
 * Parameters:
 *   process            in          A handle to the process whose main thread id to retrieve.
 *                                  The handle must have the PROCESS_VM_READ access right.
 *
 * Return Value:
 *   If the function succeeds, the return value is the main thread id.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 *
 * Remarks:
 *   This method is only available under x86.
 */
#ifndef _WIN64
EXPORTED tid_t WinHookApi GetMainThreadIdFromTIB(
    __in handle_t process
    );
#endif

/* GetMainThreadIdByCreationTime
 *
 * Purpose:
 *   Retrieves the thread id of the thread with the earliest creation time of the specified process.
 *
 * Parameters:
 *   processId          in          The process id of the process whose main thread id to retrieve.
 *
 * Return Value:
 *   If the function succeeds, the return value is the main thread id.
 *   If the function fails, the return value is 0. To get extended error information, call GetLastError.
 */
EXPORTED tid_t WinHookApi GetMainThreadIdByCreationTime(
    __in pid_t processId
    );

/* GetModuleHandleEx
 *
 * Purpose:
 *   Retrieves the handle to the first module loaded by a remote process whose name matches the specified string.
 *
 * Parameters:
 *   processId          in          The process id of the process whose modules to search.
 *   moduleName         in          A pointer to a null-terminated string that specifies the module name to search for.
 *
 * Return Value:
 *   If the function succeeds, the return value is the main thread id.
 *   If the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
EXPORTED HMODULE WinHookApi GetModuleHandleExA(
    __in pid_t processId,
    __in char const* moduleName
    );
EXPORTED HMODULE WinHookApi GetModuleHandleExW(
    __in pid_t processId,
    __in wchar_t const* moduleName
    );
#ifdef _UNICODE
#define GetModuleHandleEx GetModuleHandleExW
#else
#define GetModuleHandleEx GetModuleHandleExA
#endif

/* GetProcAddressEx
 *
 * Purpose:
 *   Returns the address of a function in another process. This function must be exported by a DLL that was already
 *   loaded by the target process.
 *
 * Parameters:
 *   process            in
 *   module             in
 *   functionName       in
 *
 * Return Value:
 *   If the function succeeds, the return value is XXX.
 *   If the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
EXPORTED ptr_t WinHookApi GetProcAddressEx(
    __in handle_t process,
    __in HMODULE module,
    __in char const* functionName
    );

/* ExecuteFunctionAsNewThreadEx
 *
 * Purpose:
 *   Lets another process execute a function in a new thread and optionally waits for it to exit. This function must be
 *   exported by a DLL that was already loaded by the target process.
 *
 * Parameters:
 *   process            in
 *   moduleName         in
 *   functionName       in
 *   parameter          in
 *   wait               in
 *   returnValue        out opt
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi ExecuteFunctionAsNewThreadExA(
    __in handle_t process,          // PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
    __in char const* moduleName,
    __in char const* functionName,
    __in ptr_t parameter,
    __in bool wait,
    __out_opt dword_t* returnValue = NULL
    );
EXPORTED bool WinHookApi ExecuteFunctionAsNewThreadExW(
    __in handle_t process,          // PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
    __in wchar_t const* moduleName,
    __in char const* functionName,
    __in ptr_t parameter,
    __in bool wait,
    __out_opt dword_t* returnValue = NULL
    );
#ifdef _UNICODE
#define ExecuteFunctionAsNewThreadEx ExecuteFunctionAsNewThreadExW
#else
#define ExecuteFunctionAsNewThreadEx ExecuteFunctionAsNewThreadExA
#endif

/* GetEipEx
 *
 * Purpose:
 *   Gets the current EIP of the specified thread.
 *
 * Parameters:
 *   thread             in
 *
 * Return Value:
 *   If the function succeeds, the return value is the current EIP of the specified thread.
 *   If the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
EXPORTED ptr_t WinHookApi GetEipEx(
    __in handle_t thread            // THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION
    );

/* SetEipEx
 *
 * Purpose:
 *   Sets the current EIP of the specified thread.
 *
 * Parameters:
 *   thread             in
 *   eip                in
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi SetEipEx(
    __in handle_t thread,           // THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT
    __in ptr_t eip
    );

/* ExecuteStubEx
 *
 * Purpose:
 *   Lets another process execute a stub in the specified thread.
 *
 * Parameters:
 *   process            in
 *   thread             in
 *   stub               in
 *   stubSize           in
 *   parameters         in
 *   parameterCount     in
 *
 * Return Value:
 *   If the function succeeds, the return value is true.
 *   If the function fails, the return value is false. To get extended error information, call GetLastError.
 */
EXPORTED bool WinHookApi ExecuteStubEx(
    __in handle_t process,          // PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    __in handle_t thread,           // THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
    __in void const* stub,
    __in size_t stubSize,
    __in ptr_t* parameters,
    __in size_t parameterCount
    );
EXPORTED bool WinHookApi ExecuteStubEx(
    __in handle_t thread,           // THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
    __in void const* stub,
    __in size_t stubSize,
    __in ptr_t* parameters,
    __in size_t parameterCount
    );

#endif // #ifndef __WinHook_WinHook_hpp__
