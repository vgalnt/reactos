/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS GUI/console setup
 * FILE:            base/setup/setup/setup.c
 * PURPOSE:         Second stage setup
 * PROGRAMMER:      Eric Kohl
 */

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>

//#define NDEBUG
#include <debug.h>

typedef INT (WINAPI *PINSTALL_REACTOS)(INT argc, WCHAR** argv);

/* FUNCTIONS ****************************************************************/

static
VOID
RunInstallReactOS(INT argc, WCHAR* argv[])
{
    HMODULE hDll;
    PINSTALL_REACTOS InstallReactOS;

    hDll = LoadLibraryW(L"syssetup.dll");
    if (hDll == NULL)
    {
        DPRINT1("RunInstallReactOS: Failed to load 'syssetup.dll'!\n");
        return;
    }

    DPRINT("RunInstallReactOS: Loaded 'syssetup.dll'!\n");

    /* Call the standard Windows-compatible export */
    InstallReactOS = (PINSTALL_REACTOS)GetProcAddress(hDll, "InstallWindowsNt");

    if (InstallReactOS == NULL)
    {
        DPRINT1("RunInstallReactOS: Failed to get address for 'InstallWindowsNt()'!\n");
    }
    else
    {
        InstallReactOS(argc, argv);
    }
}


/* Called from wmainCRTStartup */
INT wmain(INT argc, WCHAR* argv[])
{
    LPWSTR CmdLine, p;

    // NOTE: Temporary, until we correctly use argc/argv.
    CmdLine = GetCommandLineW();
    DPRINT("wmain: CmdLine: <%S>\n", CmdLine);

    p = wcschr(CmdLine, L'-');
    if (p == NULL)
        return ERROR_INVALID_PARAMETER;
    p++;

    // NOTE: On Windows, "mini" means "minimal UI", and can be used
    // in addition to "newsetup"; these options are not exclusive.
    if (_wcsicmp(p, L"newsetup") == 0 || _wcsicmp(p, L"mini") == 0)
    {
        RunInstallReactOS(argc, argv);
    }

#if 0
    /* Add new setup types here */
    else if (...)
    {

    }
#endif

    return 0;
}

/* EOF */
