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

#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#include <stdio.h>

DWORD SetMemoryProtection(
    __in LPCVOID lpAddress,
    __in DWORD dwNewProtection
    )
{
    MEMORY_BASIC_INFORMATION memoryInfo;
    if(VirtualQuery(lpAddress, &memoryInfo, sizeof(memoryInfo)) == 0)
        return FALSE;
    if(memoryInfo.Protect == dwNewProtection)
        return memoryInfo.Protect;
    DWORD dwOldProtection;
    if(VirtualProtect(memoryInfo.BaseAddress, memoryInfo.RegionSize, dwNewProtection, &dwOldProtection) == FALSE)
        return 0;
    return dwOldProtection;
}


/* Global variables to hold addresses of true functions */
static int (WINAPI* TrueSend)(SOCKET s, char const* buf, int len, int flags) = send;
static int (WINAPI* TrueRecv)(SOCKET s, char* buf, int len, int flags) = recv;

/* Replacement function for `send` */
int WINAPI NewSend(SOCKET s, char const* buf, int len, int flags)
{
    return TrueSend(s, buf, len, flags);
}

/* Replacement function for `recv` */
int WINAPI NewRecv(SOCKET s, char* buf, int len, int flags)
{
    return TrueRecv(s, buf, len, flags);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID)
{
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
            CHAR szInfo[2048];
            sprintf_s(szInfo, sizeof(szInfo), "send => %08x\nrecv => %08x", TrueSend, TrueRecv);
            MessageBox(NULL, szInfo, "ATTACH", MB_OK);
            DWORD dwOldProtection = SetMemoryProtection(TrueSend, PAGE_EXECUTE_READWRITE);
            if(dwOldProtection == 0)
                MessageBox(NULL, "VirtualProtect => PAGE_EXECUTE_READWRITE", "FAILED", MB_OK);
            /* TODO: Add trampoline etc. */
            if(SetMemoryProtection(TrueSend, dwOldProtection) == 0)
                MessageBox(NULL, "VirtualProtect => Revert", "FAILED", MB_OK);
        } break;
    case DLL_PROCESS_DETACH:
        {
            MessageBox(NULL, "Unloaded", "DETACH", MB_OK);
        } break;
    }
    return TRUE;
}
