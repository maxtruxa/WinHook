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

__forceinline bool WINAPI _AdjustPrivilege(
    __in LUID* luid,
    __in bool enable
    )
{
    HANDLE hToken;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE)
        return false;
    TOKEN_PRIVILEGES privToken;
    privToken.PrivilegeCount = 1;
    privToken.Privileges[0].Luid = *luid;
    privToken.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED);
    bool result = (AdjustTokenPrivileges(hToken, FALSE, &privToken, sizeof(privToken), NULL, NULL) != FALSE);
    PRESERVE_LAST_ERROR(
        CloseHandle(hToken);
    )
    return result;
}

bool WinHookApi AdjustPrivilegeA(
    __in char const* name,
    __in bool enable
    )
{
    LUID luid;
    if(LookupPrivilegeValueA(NULL, name, &luid) == FALSE)
        return false;
    return _AdjustPrivilege(&luid, enable);
}

bool WinHookApi AdjustPrivilegeW(
    __in wchar_t const* name,
    __in bool enable
    )
{
    LUID luid;
    if(LookupPrivilegeValueW(NULL, name, &luid) == FALSE)
        return false;
    return _AdjustPrivilege(&luid, enable);
}

bool WinHookApi EnableDebugPrivilege()
{
    return AdjustPrivilege(SE_DEBUG_NAME, true);
}
