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
#include <tchar.h>
#include "..\WinHook\WinHook.hpp"
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "..\\x64\\Release\\WinHook.lib")
#else
#pragma comment(lib, "..\\Win32\\Debug\\WinHook.lib")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "..\\x64\\Release\\WinHook.lib")
#else
#pragma comment(lib, "..\\Win32\\Release\\WinHook.lib")
#endif
#endif

#define PrintError(msg, ...) _tprintf(_T("ERROR %x: ") msg _T("\n"), GetLastError(), __VA_ARGS__)
#define PrintWarning(msg, ...) _tprintf(_T("WARNING %x: ") msg _T("\n"), GetLastError(), __VA_ARGS__)
#define PrintSuccess(msg, ...) _tprintf(_T("SUCCESS %x: ") msg _T("\n"), GetLastError(), __VA_ARGS__)

bool InjectDllClassic(
    __in pid_t processId,
    __in char_t const* dllName
    )
{
    handle_t process = NULL;
    ptr_t remoteParameter = NULL;
    // Open process.
    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to open target process."));
        return false;
    }
    // Write dll name to address space of target process.
    size_t parameterSize = (_tcslen(dllName) + 1) * sizeof(char_t);
    remoteParameter = StoreMemoryEx(process, ReadWrite, parameterSize, dllName, parameterSize);
    if(remoteParameter == NULL)
    {
        PrintError(_T("Failed to write dll name to remote process memory."));
        goto OnError;
    }
    // Start a new thread in the target process with `LoadLibrary` as entry point.
    HMODULE remoteModule = NULL;
    if(!ExecuteFunctionAsNewThreadEx(
        process,
        _T("kernel32.dll"),
#ifdef _UNICODE
        "LoadLibraryW",
#else
        "LoadLibraryA",
#endif
        remoteParameter,
        true,
        (dword_t*)&remoteModule
        )
    )
    {
        PrintError(_T("Failed to call `LoadLibraryA` in remote process."));
        goto OnError;
    }
    // Free dll name from address space of target process.
    if(!FreeMemoryEx(process, remoteParameter))
    {
        PrintWarning(_T("Failed to free dll name in remote process memory."));
    }
    // `LoadLibrary` returns NULL on failure and a valid HMODULE on success.
    PrintSuccess(_T("Remote executed `LoadLibrary` returned %08x."), remoteModule);
    CloseHandle(process);
    return true;
OnError:
    PRESERVE_LAST_ERROR(
        if(remoteParameter != NULL)
            FreeMemoryEx(process, remoteParameter);
        if(process != NULL)
            CloseHandle(process);
    );
    return false;
}

bool EjectDllClassic(
    __in pid_t processId,
    __in char_t const* dllName
    )
{
    handle_t process = NULL;
    // Open process.
    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to open target process."));
        return false;
    }
    // Locate filename portion of dll since module names exist only of that part.
    char_t const* dllNamePure = _tcsrchr(dllName, _T('\\'));
    if(dllNamePure == NULL)
        dllNamePure = dllName;
    else
        dllNamePure++;
    // Retrieve handle to module in target process that should be freed.
    HMODULE module = GetModuleHandleEx(processId, dllNamePure);
    if(module == NULL)
    {
        PrintError(_T("Could not find dll in target process."));
        goto OnError;
    }
    // Start a new thread in the target process with `FreeLibrary` as entry point.
    BOOL remoteResult = FALSE;
    if(!ExecuteFunctionAsNewThreadEx(
        process,
        _T("kernel32.dll"),
        "FreeLibrary",
        (ptr_t)module,
        true,
        (dword_t*)&remoteResult
        )
    )
    {
        PrintError(_T("Failed to free dll in remote process."));
        goto OnError;
    }
    // `FreeLibrary` returns FALSE on failure and TRUE on success.
    PrintSuccess(_T("Remote executed `FreeLibrary` returned %d."), remoteResult);
    CloseHandle(process);
    return true;
OnError:
    PRESERVE_LAST_ERROR(
        if(process != NULL)
            CloseHandle(process);
    );
    return false;
}

#ifdef EXPERIMENTAL_BUILD

HMODULE WinHookApi InjectionStub(
    __in HMODULE (WINAPI* loadLibrary)(LPCSTR),
    __in char const* dllName
    )
{
    return loadLibrary(dllName);
}

bool InjectDllStealthy(
    __in pid_t processId,
    __in char_t const* dllName
    )
{
    handle_t process = NULL;
    handle_t thread = NULL;
    ptr_t remoteParameter = NULL;
    // Open process.
    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to open target process."));
        goto OnError;
    }
    // Open thread.
    tid_t threadId = GetMainThreadIdByCreationTime(processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to retrieve id of main thread."));
        goto OnError;
    }
    thread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if(thread == NULL)
    {
        PrintError(_T("Failed to open main thread."));
        goto OnError;
    }
    // Retrieve handle to kernel32.dll in target process.
    HMODULE module = GetModuleHandleEx(processId, _T("kernel32.dll"));
    if(module == NULL)
    {
        PrintError(_T("Could not find kernel32.dll in target process."));
        goto OnError;
    }
    // Find address of `LoadLibrary` in target process to pass it into the stub.
    ptr_t remoteLoadLibrary = GetProcAddressEx(
        process,
        module,
#ifdef _UNICODE
        "LoadLibraryW"
#else
        "LoadLibraryA"
#endif
    );
    if(remoteLoadLibrary == NULL)
    {
        PrintError(_T("Could not find `LoadLibrary` in target process."));
        goto OnError;
    }
    // Write dll name to address space of target process.
    size_t parameterSize = (_tcslen(dllName) + 1) * sizeof(char_t);
    remoteParameter = StoreMemoryEx(process, ReadWrite, parameterSize, dllName, parameterSize);
    if(remoteParameter == NULL)
    {
        PrintError(_T("Failed to write dll name to remote process memory."));
        goto OnError;
    }
    // Build parameter list for stub.
    ptr_t parameters[] = { remoteLoadLibrary, remoteParameter };
    // Let main process of target process execute stub and return to normal execution flow afterwards.
    if(!ExecuteStubEx(process, thread, InjectionStub, 100, parameters, 2))
    {
        PrintError(_T("Failed to manipulate target process."));
        goto OnError;
    }
    // Free dll name from address space of target process.
    // Currently commented out since there is no way to determine whether the stub has run already.
    /*if(!FreeMemoryEx(process, remoteParameter))
    {
        PrintWarning(_T("Failed to free dll name in remote process memory."));
    }*/
    PrintSuccess(_T("Injection successfull."));
    CloseHandle(thread);
    CloseHandle(process);
    return true;
OnError:
    PRESERVE_LAST_ERROR(
        if(remoteParameter != NULL)
            FreeMemoryEx(process, remoteParameter);
        if(thread != NULL)
            CloseHandle(thread);
        if(process != NULL)
            CloseHandle(process);
    );
    return false;
}

BOOL WinHookApi EjectionStub(
    __in BOOL (WINAPI* freeLibrary)(HMODULE),
    __in HMODULE module
    )
{
    return freeLibrary(module);
}

bool EjectDllStealthy(
    __in pid_t processId,
    __in char_t const* dllName
    )
{
    handle_t process = NULL;
    handle_t thread = NULL;
    // Open process.
    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to open target process."));
        goto OnError;
    }
    // Open thread.
    tid_t threadId = GetMainThreadIdByCreationTime(processId);
    if(process == NULL)
    {
        PrintError(_T("Failed to retrieve id of main thread."));
        goto OnError;
    }
    thread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if(thread == NULL)
    {
        PrintError(_T("Failed to open main thread."));
        goto OnError;
    }
    // Retrieve handle to kernel32.dll in target process.
    HMODULE module = GetModuleHandleEx(processId, _T("kernel32.dll"));
    if(module == NULL)
    {
        PrintError(_T("Could not find kernel32.dll in target process."));
        goto OnError;
    }
    // Find address of `FreeLibrary` in target process to pass it into the stub.
    ptr_t remoteLoadLibrary = GetProcAddressEx(process, module, "FreeLibrary");
    if(remoteLoadLibrary == NULL)
    {
        PrintError(_T("Could not find `FreeLibrary` in target process."));
        goto OnError;
    }
    // Locate filename portion of dll since module names exist only of that part.
    char_t const* dllNamePure = _tcsrchr(dllName, _T('\\'));
    if(dllNamePure == NULL)
        dllNamePure = dllName;
    else
        dllNamePure++;
    // Retrieve handle to module in target process that should be freed.
    HMODULE moduleToFree = GetModuleHandleEx(processId, dllNamePure);
    if(moduleToFree == NULL)
    {
        PrintError(_T("Could not find dll in target process."));
        goto OnError;
    }
    // Build parameter list for stub.
    ptr_t parameters[] = { remoteLoadLibrary, (ptr_t)moduleToFree };
    // Let main process of target process execute stub and return to normal execution flow afterwards.
    if(!ExecuteStubEx(process, thread, EjectionStub, 100, parameters, 2))
    {
        PrintError(_T("Failed to manipulate target process."));
        goto OnError;
    }
    PrintSuccess(_T("Injection successfull."));
    CloseHandle(thread);
    CloseHandle(process);
    return true;
OnError:
    PRESERVE_LAST_ERROR(
        if(thread != NULL)
            CloseHandle(thread);
        if(process != NULL)
            CloseHandle(process);
    );
    return false;
}

#endif // #ifdef EXPERIMENTAL_BUILD

#define INJECTION_TYPE_CLASSIC  1
#ifdef EXPERIMENTAL_BUILD
#define INJECTION_TYPE_STEALTHY 2
#endif // #ifdef EXPERIMENTAL_BUILD

int _tmain(int argc, char_t** argv)
{
    // Check commandline.
    if(argc < 3)
    {
        _tprintf(
            _T("Usage:\n")
            _T("  %s <process> <dll> [<attach>] [<type>]\n")
            _T("    <process>  Process to inject into; either image name or process id\n")
            _T("    <dll>      DLL to inject; relative or absolute file name\n")
            _T("    <attach>   Attach or detach DLL; one of the following values:\n")
            _T("               attach (default)\n")
            _T("               detach\n")
            _T("    <type>     Type of injection; one of the following values:\n")
            _T("               classic (default)\n")
#ifdef EXPERIMENTAL_BUILD
            _T("               stealthy\n")
#endif // #ifdef EXPERIMENTAL_BUILD
            ,
            _tcsrchr(argv[0], _T('\\')) + 1
        );
        return ERROR_SUCCESS;
    }
    // Target process?
    char_t* processName = argv[1];
    // If target process is already specified by pid just convert it.
    pid_t processId = _tcstoul(processName, NULL, 0);
    // If not search for target process.
    if(processId == 0)
        processId = GetProcessIdByImageName(processName);
    if(processId == 0 && GetLastError() != ERROR_SUCCESS)
    {
        PrintError(_T("Could not find target process."));
        return ERROR_SUCCESS;
    }
    // DLL to inject?
    char_t* dllNameRelative = argv[2];
    char_t dllName[MAX_PATH];
    if(_tcschr(dllName, _T(':')) == NULL) // Path is relative.
    {
        GetCurrentDirectory(COUNT_OF(dllName), dllName);
        _tcscat_s(dllName, COUNT_OF(dllName), _T("\\"));
        _tcscat_s(dllName, COUNT_OF(dllName), dllNameRelative);
    }
    else
    {
        _tcscpy_s(dllName, COUNT_OF(dllName), dllNameRelative);
    }
    // Attach or detach?
    bool attach;
    if(argc < 3)
    {
        attach = true;
    }
    else
    {
        char_t* attachParam = argv[3];
        if(_tcsicmp(attachParam, _T("attach")) == 0)
        {
            attach = true;
        }
        else if(_tcsicmp(attachParam, _T("detach")) == 0)
        {
            attach = false;
        }
        else
        {
            PrintError(_T("Invalid value for parameter <attach>."));
            return ERROR_SUCCESS;
        }
    }
    // What type of injection should be used?
    dword_t injectionType;
    if(argc < 4)
    {
        injectionType = INJECTION_TYPE_CLASSIC;
    }
    else
    {
        char_t* injectionTypeParam = argv[4];
        if(_tcsicmp(injectionTypeParam, _T("classic")) == 0)
        {
            injectionType = INJECTION_TYPE_CLASSIC;
        }
#ifdef EXPERIMENTAL_BUILD
        else if(_tcsicmp(injectionTypeParam, _T("stealthy")) == 0)
        {
            injectionType = INJECTION_TYPE_STEALTHY;
        }
#endif // #ifdef EXPERIMENTAL_BUILD
        else
        {
            PrintError(_T("Invalid value for parameter <type>."));
            return ERROR_SUCCESS;
        }
    }
    // Debug privilege is required to mess with other processes.
    if(!EnableDebugPrivilege())
    {
        PrintError(_T("Failed to enable debug privilege."));
        return ERROR_SUCCESS;
    }
    if(attach)
    {
        switch(injectionType)
        {
        case INJECTION_TYPE_CLASSIC:
            InjectDllClassic(processId, dllName);
            break;
#ifdef EXPERIMENTAL_BUILD
        case INJECTION_TYPE_STEALTHY:
            InjectDllStealthy(processId, dllName);
            break;
#endif // #ifdef EXPERIMENTAL_BUILD
        }
    }
    else
    {
        switch(injectionType)
        {
        case INJECTION_TYPE_CLASSIC:
            EjectDllClassic(processId, dllName);
            break;
#ifdef EXPERIMENTAL_BUILD
        case INJECTION_TYPE_STEALTHY:
            EjectDllStealthy(processId, dllName);
            break;
#endif // #ifdef EXPERIMENTAL_BUILD
        }
    }
    return ERROR_SUCCESS;
}
