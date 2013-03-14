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

BOOL WINAPI AdjustPrivilege(
    __in LPCSTR szName,
    __in BOOL bEnable
    )
{
    HANDLE hToken;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE)
        return FALSE;
    LUID luid;
    if(LookupPrivilegeValue(NULL, szName, &luid) == FALSE)
    {
        CloseHandlePreservingLastError(hToken);
        return FALSE;
    }
    TOKEN_PRIVILEGES privToken;
    privToken.PrivilegeCount = 1;
    privToken.Privileges[0].Luid = luid;
    privToken.Privileges[0].Attributes =
        (bEnable == TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED);
    BOOL bResult = AdjustTokenPrivileges(hToken, FALSE, &privToken, sizeof(privToken), NULL, NULL);
    CloseHandlePreservingLastError(hToken);
    return bResult;
}

BOOL WINAPI EnableDebugPrivilege()
{
    return AdjustPrivilege(SE_DEBUG_NAME, TRUE);
}
