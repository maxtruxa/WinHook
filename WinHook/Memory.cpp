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

LPVOID WINAPI RemoteStoreMemory(
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
        RemoteFreeMemory(hProcess, pRemoteData, dwDataSize);
        SetLastError(dwLastError);
        return NULL;
    }
    return pRemoteData;
}

LPVOID WINAPI RemoteStoreMemory(
    __in DWORD dwProcessId,
    __in LPCVOID pData,
    __in DWORD dwDataSize,
    __in DWORD dwProtection
    )
{
    /* VirtualAllocEx: PROCESS_VM_OPERATION
     * WriteProcessMemory: PROCESS_VM_WRITE, PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);
    if(hProcess == NULL)
        return FALSE;
    LPVOID pRemoteData = RemoteStoreMemory(hProcess, pData, dwDataSize, dwProtection);
    CloseHandlePreservingLastError(hProcess);
    return pRemoteData;
}

BOOL WINAPI RemoteFreeMemory(
    __in HANDLE hProcess,
    __in LPVOID pData,
    __in DWORD dwDataSize
    )
{
    /* Release memory */
    return VirtualFreeEx(hProcess, pData, dwDataSize, MEM_DECOMMIT);
}

BOOL WINAPI RemoteFreeMemory(
    __in DWORD dwProcessId,
    __in LPVOID pData,
    __in DWORD dwDataSize
    )
{
    /* VirtualFreeEx: PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwProcessId);
    if(hProcess == NULL)
        return FALSE;
    BOOL bResult = RemoteFreeMemory(hProcess, pData, dwDataSize);
    CloseHandlePreservingLastError(hProcess);
    return bResult;
}

DWORD RemoteProtectMemory(
    __in HANDLE hProcess,
    __in LPCVOID lpAddress,
    __in DWORD dwNewProtection
    )
{
    MEMORY_BASIC_INFORMATION memoryInfo;
    if(VirtualQueryEx(hProcess, lpAddress, &memoryInfo, sizeof(memoryInfo)) == 0)
        return FALSE;
    if(memoryInfo.Protect == dwNewProtection)
        return memoryInfo.Protect;
    DWORD dwOldProtection;
    if(VirtualProtectEx(hProcess, memoryInfo.BaseAddress, memoryInfo.RegionSize, dwNewProtection, &dwOldProtection) == FALSE)
        return 0;
    return dwOldProtection;
}

DWORD RemoteProtectMemory(
    __in DWORD dwProcessId,
    __in LPCVOID lpAddress,
    __in DWORD dwNewProtection
    )
{
    /* VirtualQueryEx: PROCESS_QUERY_INFORMATION
     * VirtualProtectEx: PROCESS_VM_OPERATION
     */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, dwProcessId);
    if(hProcess == NULL)
        return FALSE;
    DWORD dwOldProtection = RemoteProtectMemory(hProcess, lpAddress, dwNewProtection);
    CloseHandlePreservingLastError(hProcess);
    return dwOldProtection;
}
