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

#include <stdio.h>
#include "..\WinHook\WinHook.hpp"
#ifdef _DEBUG
#pragma comment(lib, "..\\Debug\\WinHook.lib")
#else
#pragma comment(lib, "..\\Release\\WinHook.lib")
#endif

/* Use themed controls */
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' \
    version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_BUTTON_INJECT_CLASSIC    10001
#define ID_BUTTON_UNJECT_CLASSIC    10002
#define ID_BUTTON_INJECT_FANCY      10003
#define ID_BUTTON_UNJECT_FANCY      10004
#define ID_EDIT_PROCESS             10101
#define ID_EDIT_DLL                 10102

namespace Global
{
    HWND hWnd;
    HWND hWndEditProcess;
    HWND hWndEditDll;
    HWND hWndButtonInjectClassic;
    HWND hWndButtonUnjectClassic;
    HWND hWndButtonInjectFancy;
    HWND hWndButtonUnjectFancy;
};

/* Displays a message box with the specified error message.
 */
void ErrorMessage(
    __in LPCSTR szErrorMessage,
    __in_opt DWORD dwErrorCode = GetLastError()
    )
{
    CHAR szTitle[2048];
    sprintf_s(szTitle, sizeof(szTitle), "WinHook Injector - Error %u", dwErrorCode);
    MessageBox(NULL, szErrorMessage, szTitle, MB_OK | MB_ICONERROR);
}

/* Displays a message box with the specified warning message.
 */
void WarningMessage(
    __in LPCSTR szWarningMessage,
    __in_opt DWORD dwErrorCode = GetLastError()
    )
{
    CHAR szTitle[2048];
    sprintf_s(szTitle, sizeof(szTitle), "WinHook Injector - Warning %u", dwErrorCode);
    MessageBox(NULL, szWarningMessage, szTitle, MB_OK | MB_ICONWARNING);
}

/* Displays a message box with the specified success message.
 */
void SuccessMessage(
    __in LPCSTR szSuccessMessage
    )
{
    MessageBox(NULL, szSuccessMessage, "WinHook Injector - Success", MB_OK | MB_ICONINFORMATION);
}

void InjectDLLClassic(
    __in DWORD dwProcessID,
    __in CHAR const* szDllName
    )
{
    /* Write dll name to address space of target process */
    DWORD dwParameterSize = strlen(szDllName) + 1;
    LPVOID pParameter = RemoteStoreData(dwProcessID, szDllName, dwParameterSize, PAGE_READWRITE);
    if(pParameter == NULL)
    {
        ErrorMessage("Failed to write dll name to remote process memory.");
        return;
    }
    /* Start a new thread in the target process with `LoadLibraryA` as entry point */
    HMODULE hRemoteModule = NULL;
    BOOL bResult = RemoteExecuteFunctionInNewThread(dwProcessID, "kernel32.dll", "LoadLibraryA", pParameter,
        TRUE, reinterpret_cast<DWORD*>(&hRemoteModule));
    if(bResult == FALSE)
        ErrorMessage("Failed to call `LoadLibraryA` in remote process.");
    /* Free dll name from address space of target process */
    if(RemoteFreeData(dwProcessID, pParameter, dwParameterSize) == FALSE)
    {
        WarningMessage("Failed to free dll name in remote process memory.");
    }
    if(bResult == TRUE)
    {
        /* `LoadLibraryA` returns NULL on failure and a valid HMODULE on success */
        if(hRemoteModule != NULL)
        {
            CHAR szSuccessMessage[2048];
            sprintf_s(szSuccessMessage, sizeof(szSuccessMessage), "Remote executed `LoadLibraryA` returned %08x.", hRemoteModule);
            SuccessMessage(szSuccessMessage);
        }
        else
        {
            SuccessMessage("Remote executed `LoadLibraryA` returned NULL.");
        }
    }
}

void UnjectDLLClassic(
    __in DWORD dwProcessID,
    __in CHAR const* szDllName
    )
{
    /* Locate filename portion of dll since module names exist only of that part */
    CHAR const* szDllNamePure = strrchr(szDllName, '\\');
    if(szDllNamePure == NULL)
        szDllNamePure = szDllName;
    else
        szDllNamePure++;
    /* Retrieve handle to module in target process to free */
    HMODULE hModule = RemoteGetModuleHandle(dwProcessID, szDllNamePure);
    if(hModule == NULL)
    {
        ErrorMessage("Could not find dll in target process.");
        return;
    }
    /* Start a new thread in the target process with `FreeLibrary` as entry point */
    BOOL bRemoteResult = FALSE;
    if(RemoteExecuteFunctionInNewThread(dwProcessID, "kernel32.dll", "FreeLibrary", (LPVOID)hModule,
        TRUE, reinterpret_cast<DWORD*>(&bRemoteResult)) == FALSE)
    {
        ErrorMessage("Failed to free dll in remote process.");
        return;
    }
    if(bRemoteResult == TRUE)
        SuccessMessage("Remote executed `FreeLibrary` returned TRUE.");
    else
        SuccessMessage("Remote executed `FreeLibrary` returned FALSE.");
}

typedef HMODULE (__stdcall* LoadLibraryAFCTPTR)(LPCSTR);

HMODULE __stdcall InjectionStub(
    __in LoadLibraryAFCTPTR pLoadLibrary,
    __in LPCSTR szDllName
    )
{
    return pLoadLibrary(szDllName);
}

void InjectDLLFancy(
    __in DWORD dwProcessID,
    __in CHAR const* szDllName
    )
{
    /* Find address of `LoadLibraryA` in target process to pass it into the stub */
    FARPROC pLoadLibrary = RemoteGetProcAddress(dwProcessID, "kernel32.dll", "LoadLibraryA");
    if(pLoadLibrary == NULL)
    {
        ErrorMessage("Could not find `LoadLibraryA` in target process.");
        return;
    }
    /* Write dll name to address space of target process */
    DWORD dwParameterSize = strlen(szDllName) + 1;
    LPVOID pParameter = RemoteStoreData(dwProcessID, szDllName, dwParameterSize, PAGE_READWRITE);
    if(pParameter == NULL)
    {
        ErrorMessage("Failed to write dll name to remote process memory.");
        return;
    }
    /* Build parameter list for stub */
    UINT_PTR pParameters[] = { (UINT_PTR)pLoadLibrary, (UINT_PTR)pParameter };
    /* Let main process of target process execute stub and return to normal behaviour afterwards */
    if(RemoteExecuteStub(GetMainThreadID(dwProcessID), InjectionStub, 100, pParameters, 2) == FALSE)
    {
        ErrorMessage("Failed to manipulate target process.");
        if(RemoteFreeData(dwProcessID, pParameter, dwParameterSize) == FALSE)
            WarningMessage("Failed to free dll name in remote process memory.");
        return;
    }
    /* Free dll name from address space of target process */
    /*if(RemoteFreeData(dwProcessID, pParameter, dwParameterSize) == FALSE)
    {
        WarningMessage("Failed to free dll name in remote process memory.");
    }*/
    SuccessMessage("Injection successfull.");
}

typedef BOOL (__stdcall* FreeLibraryFCTPTR)(HMODULE);

BOOL __stdcall UnjectionStub(
    __in FreeLibraryFCTPTR pFreeLibrary,
    __in HMODULE hModule
    )
{
    return pFreeLibrary(hModule);
}

void UnjectDLLFancy(
    __in DWORD dwProcessID,
    __in CHAR const* szDllName
    )
{
}

BOOL CreateGui(
    __in HWND parenthWnd
    );

LRESULT CALLBACK WindowProc(
    __in HWND hWnd,
    __in UINT message,
    __in WPARAM wParam,
    __in LPARAM lParam
    )
{
    switch(message)
    {
    case WM_CREATE:
        {
            if(CreateGui(hWnd) == FALSE)
            {
                ErrorMessage("CreateGui failed.");
                DestroyWindow(hWnd);
                break;
            }
        } break;
    case WM_COMMAND:
        {
            switch(LOWORD(wParam))
            {
            case ID_BUTTON_INJECT_CLASSIC:
            case ID_BUTTON_UNJECT_CLASSIC:
            case ID_BUTTON_INJECT_FANCY:
            case ID_BUTTON_UNJECT_FANCY:
                {
                    /* Read values from edit boxes */
                    CHAR szProcessName[MAX_PATH];
                    GetWindowText(Global::hWndEditProcess, szProcessName, sizeof(szProcessName));
                    CHAR szDllNameRelative[MAX_PATH];
                    GetWindowTextA(Global::hWndEditDll, szDllNameRelative, sizeof(szDllNameRelative));
                    CHAR szDllName[MAX_PATH];
                    GetCurrentDirectory(sizeof(szDllName), szDllName);
                    strcat_s(szDllName, sizeof(szDllName), "\\");
                    strcat_s(szDllName, sizeof(szDllName), szDllNameRelative);
                    /* If target process is already specified by pid just convert it */
                    DWORD dwProcessID = strtoul(szProcessName, NULL, 0);
                    /* If not search for target process */
                    if(dwProcessID == 0)
                        dwProcessID = GetProcessID(szProcessName);
                    if(dwProcessID == 0 && GetLastError() != ERROR_SUCCESS)
                    {
                        ErrorMessage("Could not find target process.");
                        break;
                    }
                    switch(LOWORD(wParam))
                    {
                    case ID_BUTTON_INJECT_CLASSIC:
                        InjectDLLClassic(dwProcessID, szDllName);
                        break;
                    case ID_BUTTON_UNJECT_CLASSIC:
                        UnjectDLLClassic(dwProcessID, szDllName);
                        break;
                    case ID_BUTTON_INJECT_FANCY:
                        InjectDLLFancy(dwProcessID, szDllName);
                        break;
                    case ID_BUTTON_UNJECT_FANCY:
                        UnjectDLLFancy(dwProcessID, szDllName);
                        break;
                    }
                } break;
            }
        } break;
    case WM_CLOSE:
        {
            DestroyWindow(hWnd);
        } break;
    case WM_DESTROY:
        {
            PostQuitMessage(0);
        } break;
    default:
        {
        } return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

BOOL InitGui(
    __in HINSTANCE hInstance,
    __in int nCmdShow
    )
{
    InitCommonControls();
    WNDCLASSEX wc;
    ZeroMemory(&wc, sizeof(WNDCLASSEX));
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "WinHookWindowClassFooBar1337";
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    ATOM classAtom = RegisterClassEx(&wc);
    if(classAtom == 0)
        return FALSE;
    Global::hWnd = CreateWindowEx(
        NULL,
        MAKEINTATOM(classAtom),
        "WinHook Injector",
        WS_OVERLAPPEDWINDOW | WS_MAXIMIZEBOX | WS_THICKFRAME,
        ((GetSystemMetrics(SM_CXSCREEN) - 300) / 2),
        ((GetSystemMetrics(SM_CYSCREEN) - 170) / 2),
        250,
        172,
        NULL,
        NULL,
        hInstance,
        NULL
        );
    if(Global::hWnd == NULL)
        return FALSE;
    if(ShowWindow(Global::hWnd, nCmdShow) != 0)
        return FALSE;
    return UpdateWindow(Global::hWnd);
}

BOOL CreateGui(
    __in HWND parenthWnd
    )
{
    Global::hWndEditProcess = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "Edit",
        "notepad++.exe",
        WS_TABSTOP | WS_VISIBLE /*| ES_READONLY*/ | WS_CHILD | ES_AUTOHSCROLL,
        10, 10,
        215, 20,
        parenthWnd,
        (HMENU)ID_EDIT_PROCESS,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    Global::hWndEditDll = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "Edit",
        "TestHook.dll",
        WS_TABSTOP | WS_VISIBLE /*| ES_READONLY*/ | WS_CHILD | ES_AUTOHSCROLL,
        10, 40,
        215, 20,
        parenthWnd,
        (HMENU)ID_EDIT_DLL,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    Global::hWndButtonInjectClassic = CreateWindowEx(
        0,
        "Button",
        "Inject Classic",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 67,
        104, 25,
        parenthWnd,
        (HMENU)ID_BUTTON_INJECT_CLASSIC,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    Global::hWndButtonUnjectClassic = CreateWindowEx(
        0,
        "Button",
        "Unject Classic",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        122, 67,
        104, 25,
        parenthWnd,
        (HMENU)ID_BUTTON_UNJECT_CLASSIC,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    Global::hWndButtonInjectFancy = CreateWindowEx(
        0,
        "Button",
        "Inject Like A Boss",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 100,
        104, 25,
        parenthWnd,
        (HMENU)ID_BUTTON_INJECT_FANCY,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    Global::hWndButtonUnjectFancy = CreateWindowEx(
        0,
        "Button",
        "Unject Like A Boss",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        122, 100,
        104, 25,
        parenthWnd,
        (HMENU)ID_BUTTON_UNJECT_FANCY,
        (HINSTANCE)GetWindowLong(parenthWnd, GWL_HINSTANCE),
        NULL
        );
    int nTextLength = GetWindowTextLength(Global::hWndEditProcess);
    SetFocus(Global::hWndEditProcess);
    PostMessage(Global::hWndEditProcess, EM_SETSEL, (WPARAM)0, (LPARAM)nTextLength);
    LOGFONT lf;
    GetObject (GetStockObject(DEFAULT_GUI_FONT), sizeof(LOGFONT), &lf);
    HFONT hFont = CreateFont (lf.lfHeight, lf.lfWidth,
    lf.lfEscapement, lf.lfOrientation, lf.lfWeight,
    lf.lfItalic, lf.lfUnderline, lf.lfStrikeOut, lf.lfCharSet,
    lf.lfOutPrecision, lf.lfClipPrecision, lf.lfQuality,
    lf.lfPitchAndFamily, lf.lfFaceName);
    PostMessage(parenthWnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndEditDll, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndEditProcess, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndButtonInjectClassic, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndButtonUnjectClassic, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndButtonInjectFancy, WM_SETFONT, (WPARAM)hFont, TRUE);
    PostMessage(Global::hWndButtonUnjectFancy, WM_SETFONT, (WPARAM)hFont, TRUE);
    return TRUE;
}

int CALLBACK WinMain(
    __in HINSTANCE hInstance,
    __in HINSTANCE hPrevInstance,
    __in LPSTR lpCmdLine,
    __in int nCmdShow
    )
{
    /* Debug privilege is needed to mess with other processes */
    if(EnableDebugPrivilege() == FALSE)
    {
        ErrorMessage("Failed to enable debug privilege.");
        return ERROR_SUCCESS;
    }
    if(InitGui(hInstance, nCmdShow) == FALSE)
    {
        ErrorMessage("InitGui failed.");
        return ERROR_SUCCESS;
    }
    MSG msg;
    while(GetMessage(&msg, Global::hWnd, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}
