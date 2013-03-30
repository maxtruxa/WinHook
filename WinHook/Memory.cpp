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

ptr_t WinHookApi StoreMemoryEx(
    __in handle_t process,
    __in PageProtection protection,
    __in size_t allocSize,
    __in void const* buffer,
    __in size_t bufferSize
    )
{
    if(allocSize == 0)
        allocSize = bufferSize;
    // Allocate memory in address space of target process
    ptr_t remoteAddress = (ptr_t)VirtualAllocEx(process, NULL, allocSize, MEM_RESERVE | MEM_COMMIT, protection);
    if(remoteAddress == NULL)
        goto OnError;
    if(buffer == NULL || bufferSize == 0)
        return remoteAddress;
    // If memory protection is not writable, make it writable
    PageProtection oldProtection = Invalid;
    if(!BITMASK_IS_SET(protection, ExecuteReadWrite)
    && !BITMASK_IS_SET(protection, ReadWrite))
    {
        oldProtection = ProtectMemoryEx(process, remoteAddress, bufferSize, ReadWrite);
        if(oldProtection == Invalid)
            goto OnError;
    }
    // Write data to allocated memory
    size_t bytesWritten = WriteMemoryEx(process, remoteAddress, buffer, bufferSize);
    if(bytesWritten != bufferSize)
        goto OnError;
    // Revert to original memory protection
    if(oldProtection != Invalid)
    {
        if(ProtectMemoryEx(process, remoteAddress, bufferSize, oldProtection) == Invalid)
            goto OnError;
    }
    return remoteAddress;
OnError:
    PRESERVE_LAST_ERROR(
        // On error free allocated memory so it does not leak
        if(remoteAddress != NULL)
        {
                FreeMemoryEx(process, remoteAddress);
        }
    )
    return NULL;
}

bool WinHookApi FreeMemoryEx(
    __in handle_t process,
    __in ptr_t address
    )
{
    // Release memory
    return (VirtualFreeEx(process, (void*)address, 0, MEM_RELEASE) != FALSE);
}

PageProtection WinHookApi ProtectMemory(
    __in ptr_t address,
    __in size_t size,
    __in PageProtection newProtection
    )
{
    PageProtection oldProtection;
    if(VirtualProtect((void*)address, size, newProtection, (DWORD*)&oldProtection) == FALSE)
        return Invalid;
    return oldProtection;
}

PageProtection WinHookApi ProtectMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __in size_t size,
    __in PageProtection newProtection
    )
{
    PageProtection oldProtection;
    if(VirtualProtectEx(process, (void*)address, size, newProtection, (DWORD*)&oldProtection) == FALSE)
        return Invalid;
    return oldProtection;
}

size_t WinHookApi ReadMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __out void* buffer,
    __in size_t bufferSize
    )
{
    size_t bytesRead = 0;
    if(ReadProcessMemory(process, (void const*)address, buffer, bufferSize, (SIZE_T*)&bytesRead) == FALSE)
        return 0;
    return bytesRead;
}

size_t WinHookApi WriteMemoryEx(
    __in handle_t process,
    __in ptr_t address,
    __in void const* buffer,
    __in size_t bufferSize
    )
{
    size_t bytesWritten = 0;
    if(WriteProcessMemory(process, (void*)address, buffer, bufferSize, (SIZE_T*)&bytesWritten) == FALSE)
        return 0;
    return bytesWritten;
}
