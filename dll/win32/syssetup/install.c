/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           System setup
 * FILE:              dll/win32/syssetup/install.c
 * PROGRAMER:         Eric Kohl
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

#define COBJMACROS

#include <io.h>
#include <wincon.h>
#include <winnls.h>
#include <winsvc.h>
#include <userenv.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shobjidl.h>
#include <rpcproxy.h>
#include <ndk/cmfuncs.h>

//#define NDEBUG
#include <debug.h>

DWORD WINAPI
SetupStartService(LPCWSTR lpServiceName, BOOL bWait);

/* GLOBALS ******************************************************************/

HINF hSysSetupInf = INVALID_HANDLE_VALUE; // 'SyssetupInf' for NT
ADMIN_INFO AdminInfo;
BOOL MiniSetup = FALSE;
BOOL Upgrade = FALSE;
BOOL SkipMissingFiles = FALSE;
HWND MainWindowHandle = NULL; // HACK

/* FUNCTIONS ****************************************************************/

static VOID
FatalError(char *pszFmt,...)
{
    char szBuffer[512];
    va_list ap;

    va_start(ap, pszFmt);
    vsprintf(szBuffer, pszFmt, ap);
    va_end(ap);

    LogItem(NULL, L"Failed");

    strcat(szBuffer, "\nRebooting now!");
    MessageBoxA(NULL,
                szBuffer,
                "ReactOS Setup",
                MB_OK);
}

static HRESULT
CreateShellLink(
    LPCWSTR pszLinkPath,
    LPCWSTR pszCmd,
    LPCWSTR pszArg,
    LPCWSTR pszDir,
    LPCWSTR pszIconPath,
    INT iIconNr,
    LPCWSTR pszComment)
{
    IShellLinkW *psl;
    IPersistFile *ppf;

    HRESULT hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (LPVOID*)&psl);

    if (SUCCEEDED(hr))
    {
        hr = IShellLinkW_SetPath(psl, pszCmd);

        if (pszArg)
            hr = IShellLinkW_SetArguments(psl, pszArg);

        if (pszDir)
            hr = IShellLinkW_SetWorkingDirectory(psl, pszDir);

        if (pszIconPath)
            hr = IShellLinkW_SetIconLocation(psl, pszIconPath, iIconNr);

        if (pszComment)
            hr = IShellLinkW_SetDescription(psl, pszComment);

        hr = IShellLinkW_QueryInterface(psl, &IID_IPersistFile, (LPVOID*)&ppf);

        if (SUCCEEDED(hr))
        {
            hr = IPersistFile_Save(ppf, pszLinkPath, TRUE);
            IPersistFile_Release(ppf);
        }

        IShellLinkW_Release(psl);
    }

    return hr;
}

static BOOL
CreateShortcut(
    LPCWSTR pszFolder,
    LPCWSTR pszName,
    LPCWSTR pszCommand,
    LPCWSTR pszDescription,
    INT iIconNr,
    LPCWSTR pszWorkingDir)
{
    DWORD dwLen;
    LPWSTR Ptr;
    LPWSTR lpFilePart;
    WCHAR szPath[MAX_PATH];
    WCHAR szWorkingDirBuf[MAX_PATH];

    /* If no working directory is provided, try to compute a default one */
    if (pszWorkingDir == NULL || pszWorkingDir[0] == L'\0')
    {
        if (ExpandEnvironmentStringsW(pszCommand, szPath, ARRAYSIZE(szPath)) == 0)
            wcscpy(szPath, pszCommand);

        dwLen = GetFullPathNameW(szPath,
                                 ARRAYSIZE(szWorkingDirBuf),
                                 szWorkingDirBuf,
                                 &lpFilePart);
        if (dwLen != 0 && dwLen <= ARRAYSIZE(szWorkingDirBuf))
        {
            /* Since those should only be called with (.exe) files,
               lpFilePart has not to be NULL */
            ASSERT(lpFilePart != NULL);

            /* We're only interested in the path. Cut the file name off.
               Also remove the trailing backslash unless the working directory
               is only going to be a drive, i.e. C:\ */
            *(lpFilePart--) = L'\0';
            if (!(lpFilePart - szWorkingDirBuf == 2 &&
                  szWorkingDirBuf[1] == L':' && szWorkingDirBuf[2] == L'\\'))
            {
                *lpFilePart = L'\0';
            }
            pszWorkingDir = szWorkingDirBuf;
        }
    }

    /* If we failed to compute a working directory, just do not use one */
    if (pszWorkingDir && pszWorkingDir[0] == L'\0')
        pszWorkingDir = NULL;

    /* Build the shortcut file name */
    wcscpy(szPath, pszFolder);
    Ptr = PathAddBackslash(szPath);
    wcscpy(Ptr, pszName);

    /* Create the shortcut */
    return SUCCEEDED(CreateShellLink(szPath,
                                     pszCommand,
                                     L"",
                                     pszWorkingDir,
                                     /* Special value to indicate no icon */
                                     (iIconNr != -1 ? pszCommand : NULL),
                                     iIconNr,
                                     pszDescription));
}

static BOOL CreateShortcutsFromSection(HINF hinf, LPWSTR pszSection, LPCWSTR pszFolder)
{
    INFCONTEXT Context;
    DWORD dwFieldCount;
    INT iIconNr;
    WCHAR szCommand[MAX_PATH];
    WCHAR szName[MAX_PATH];
    WCHAR szDescription[MAX_PATH];
    WCHAR szDirectory[MAX_PATH];

    if (!SetupFindFirstLine(hinf, pszSection, NULL, &Context))
        return FALSE;

    do
    {
        dwFieldCount = SetupGetFieldCount(&Context);
        if (dwFieldCount < 3)
            continue;

        if (!SetupGetStringFieldW(&Context, 1, szCommand, ARRAYSIZE(szCommand), NULL))
            continue;

        if (!SetupGetStringFieldW(&Context, 2, szName, ARRAYSIZE(szName), NULL))
            continue;

        if (!SetupGetStringFieldW(&Context, 3, szDescription, ARRAYSIZE(szDescription), NULL))
            continue;

        if (dwFieldCount < 4 || !SetupGetIntField(&Context, 4, &iIconNr))
            iIconNr = -1; /* Special value to indicate no icon */

        if (dwFieldCount < 5 || !SetupGetStringFieldW(&Context, 5, szDirectory, ARRAYSIZE(szDirectory), NULL))
            szDirectory[0] = L'\0';

        wcscat(szName, L".lnk");

        CreateShortcut(pszFolder, szName, szCommand, szDescription, iIconNr, szDirectory);

    } while (SetupFindNextLine(&Context, &Context));

    return TRUE;
}

static BOOL CreateShortcuts(HINF hinf, LPCWSTR szSection)
{
    INFCONTEXT Context;
    WCHAR szPath[MAX_PATH];
    WCHAR szFolder[MAX_PATH];
    WCHAR szFolderSection[MAX_PATH];
    INT csidl;

    CoInitialize(NULL);

    if (!SetupFindFirstLine(hinf, szSection, NULL, &Context))
        return FALSE;

    do
    {
        if (SetupGetFieldCount(&Context) < 2)
            continue;

        if (!SetupGetStringFieldW(&Context, 0, szFolderSection, ARRAYSIZE(szFolderSection), NULL))
            continue;

        if (!SetupGetIntField(&Context, 1, &csidl))
            continue;

        if (!SetupGetStringFieldW(&Context, 2, szFolder, ARRAYSIZE(szFolder), NULL))
            continue;

        if (FAILED(SHGetFolderPathAndSubDirW(NULL, csidl|CSIDL_FLAG_CREATE, (HANDLE)-1, SHGFP_TYPE_DEFAULT, szFolder, szPath)))
            continue;

        CreateShortcutsFromSection(hinf, szFolderSection, szPath);

    } while (SetupFindNextLine(&Context, &Context));

    CoUninitialize();

    return TRUE;
}

static VOID
CreateTempDir(
    IN LPCWSTR VarName)
{
    WCHAR szTempDir[MAX_PATH];
    WCHAR szBuffer[MAX_PATH];
    DWORD dwLength;
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                      0,
                      KEY_QUERY_VALUE,
                      &hKey) != ERROR_SUCCESS)
    {
        FatalError("Error: %lu\n", GetLastError());
        return;
    }

    /* Get temp dir */
    dwLength = sizeof(szBuffer);
    if (RegQueryValueExW(hKey,
                         VarName,
                         NULL,
                         NULL,
                         (LPBYTE)szBuffer,
                         &dwLength) != ERROR_SUCCESS)
    {
        FatalError("Error: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Expand it */
    if (!ExpandEnvironmentStringsW(szBuffer, szTempDir, ARRAYSIZE(szTempDir)))
    {
        FatalError("Error: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Create profiles directory */
    if (!CreateDirectoryW(szTempDir, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            FatalError("Error: %lu\n", GetLastError());
            goto cleanup;
        }
    }

cleanup:
    RegCloseKey(hKey);
}

#if 0
static BOOL
InstallSysSetupInfDevices(VOID)
{
    INFCONTEXT InfContext;
    WCHAR szLineBuffer[256];
    DWORD dwLineLength;

    if (!SetupFindFirstLineW(hSysSetupInf,
                            L"DeviceInfsToInstall",
                            NULL,
                            &InfContext))
    {
        return FALSE;
    }

    do
    {
        if (!SetupGetStringFieldW(&InfContext,
                                  0,
                                  szLineBuffer,
                                  ARRAYSIZE(szLineBuffer),
                                  &dwLineLength))
        {
            return FALSE;
        }

        if (!SetupDiInstallClassW(NULL, szLineBuffer, DI_QUIETINSTALL, NULL))
        {
            return FALSE;
        }
    }
    while (SetupFindNextLine(&InfContext, &InfContext));

    return TRUE;
}
#endif

#if 0
static BOOL
InstallSysSetupInfComponents(VOID)
{
    INFCONTEXT InfContext;
    WCHAR szNameBuffer[256];
    WCHAR szSectionBuffer[256];
    HINF hComponentInf = INVALID_HANDLE_VALUE;

    if (!SetupFindFirstLineW(hSysSetupInf,
                             L"Infs.Always",
                             NULL,
                             &InfContext))
    {
        DPRINT("No Inf.Always section found\n");
    }
    else
    {
        do
        {
            if (!SetupGetStringFieldW(&InfContext,
                                      1, // Get the component name
                                      szNameBuffer,
                                      ARRAYSIZE(szNameBuffer),
                                      NULL))
            {
                FatalError("Error while trying to get component name \n");
                return FALSE;
            }

            if (!SetupGetStringFieldW(&InfContext,
                                      2, // Get the component install section
                                      szSectionBuffer,
                                      ARRAYSIZE(szSectionBuffer),
                                      NULL))
            {
                FatalError("Error while trying to get component install section \n");
                return FALSE;
            }

            DPRINT("Trying to execute install section '%S' from '%S' \n", szSectionBuffer, szNameBuffer);

            hComponentInf = SetupOpenInfFileW(szNameBuffer,
                                              NULL,
                                              INF_STYLE_WIN4,
                                              NULL);

            if (hComponentInf == INVALID_HANDLE_VALUE)
            {
                FatalError("SetupOpenInfFileW() failed to open '%S' (Error: %lu)\n", szNameBuffer, GetLastError());
                return FALSE;
            }

            if (!SetupInstallFromInfSectionW(NULL,
                                             hComponentInf,
                                             szSectionBuffer,
                                             SPINST_ALL,
                                             NULL,
                                             NULL,
                                             SP_COPY_NEWER,
                                             SetupDefaultQueueCallbackW,
                                             NULL,
                                             NULL,
                                             NULL))
           {
                FatalError("Error while trying to install : %S (Error: %lu)\n", szNameBuffer, GetLastError());
                SetupCloseInfFile(hComponentInf);
                return FALSE;
           }

           SetupCloseInfFile(hComponentInf);
        }
        while (SetupFindNextLine(&InfContext, &InfContext));
    }

    return TRUE;
}
#endif

BOOL
RegisterTypeLibraries(HINF hinf, LPCWSTR szSection)
{
    INFCONTEXT InfContext;
    BOOL res;
    WCHAR szName[MAX_PATH];
    WCHAR szPath[MAX_PATH];
    INT csidl;
    LPWSTR p;
    HMODULE hmod;
    HRESULT hret;

    DPRINT("RegisterTypeLibraries()\n");

    /* Begin iterating the entries in the inf section */
    res = SetupFindFirstLine(hinf, szSection, NULL, &InfContext);
    if (!res) return FALSE;

    do
    {
        /* Get the name of the current type library */
        if (!SetupGetStringFieldW(&InfContext, 1, szName, ARRAYSIZE(szName), NULL))
        {
            FatalError("SetupGetStringFieldW failed\n");
            continue;
        }

        if (!SetupGetIntField(&InfContext, 2, &csidl))
            csidl = CSIDL_SYSTEM;

        hret = SHGetFolderPathW(NULL, csidl, NULL, 0, szPath);
        if (FAILED(hret))
        {
            FatalError("SHGetFolderPathW failed hret=0x%lx\n", hret);
            continue;
        }

        p = PathAddBackslash(szPath);
        wcscpy(p, szName);

        hmod = LoadLibraryW(szName);
        if (hmod == NULL)
        {
            FatalError("LoadLibraryW failed\n");
            continue;
        }

        __wine_register_resources(hmod);

    } while (SetupFindNextLine(&InfContext, &InfContext));

    return TRUE;
}

#if 0
static BOOL
EnableUserModePnpManager(VOID)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL bRet = FALSE;

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        DPRINT1("Unable to open the service control manager.\n");
        DPRINT1("Last Error %d\n", GetLastError());
        goto cleanup;
    }

    hService = OpenServiceW(hSCManager,
                            L"PlugPlay",
                            SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (hService == NULL)
    {
        DPRINT1("Unable to open PlugPlay service\n");
        goto cleanup;
    }

    bRet = ChangeServiceConfigW(hService,
                                SERVICE_NO_CHANGE,
                                SERVICE_AUTO_START,
                                SERVICE_NO_CHANGE,
                                NULL, NULL, NULL,
                                NULL, NULL, NULL, NULL);
    if (!bRet)
    {
        DPRINT1("Unable to change the service configuration\n");
        goto cleanup;
    }

    bRet = StartServiceW(hService, 0, NULL);
    if (!bRet && (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING))
    {
        DPRINT1("Unable to start service\n");
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hService != NULL)
        CloseServiceHandle(hService);
    if (hSCManager != NULL)
        CloseServiceHandle(hSCManager);
    return bRet;
}
#endif

#if 0
static INT_PTR CALLBACK
StatusMessageWindowProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            WCHAR szMsg[256];

            if (!LoadStringW(hDllInstance, IDS_STATUS_INSTALL_DEV, szMsg, ARRAYSIZE(szMsg)))
                return FALSE;
            SetDlgItemTextW(hwndDlg, IDC_STATUSLABEL, szMsg);
            return TRUE;
        }
    }
    return FALSE;
}
#endif

#if 0
static DWORD WINAPI
ShowStatusMessageThread(
    IN LPVOID lpParameter)
{
    HWND hWnd, hItem;
    MSG Msg;
    UNREFERENCED_PARAMETER(lpParameter);

    hWnd = CreateDialogParam(hDllInstance,
                             MAKEINTRESOURCE(IDD_STATUSWINDOW_DLG),
                             GetDesktopWindow(),
                             StatusMessageWindowProc,
                             (LPARAM)NULL);
    if (!hWnd)
        return 0;

    ShowWindow(hWnd, SW_SHOW);

    hItem = GetDlgItem(hWnd, IDC_STATUSPROGRESS);
    if (hItem)
    {
        PostMessage(hItem, PBM_SETMARQUEE, TRUE, 40);
    }

    /* Message loop for the Status window */
    while (GetMessage(&Msg, NULL, 0, 0))
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }

    EndDialog(hWnd, 0);

    return 0;
}
#endif

#if 0
static LONG
ReadRegSzKey(
    IN HKEY hKey,
    IN LPCWSTR pszKey,
    OUT LPWSTR* pValue)
{
    LONG rc;
    DWORD dwType;
    DWORD cbData = 0;
    LPWSTR pwszValue;

    if (!pValue)
        return ERROR_INVALID_PARAMETER;

    *pValue = NULL;
    rc = RegQueryValueExW(hKey, pszKey, NULL, &dwType, NULL, &cbData);
    if (rc != ERROR_SUCCESS)
        return rc;
    if (dwType != REG_SZ)
        return ERROR_FILE_NOT_FOUND;
    pwszValue = HeapAlloc(GetProcessHeap(), 0, cbData + sizeof(WCHAR));
    if (!pwszValue)
        return ERROR_NOT_ENOUGH_MEMORY;
    rc = RegQueryValueExW(hKey, pszKey, NULL, NULL, (LPBYTE)pwszValue, &cbData);
    if (rc != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pwszValue);
        return rc;
    }
    /* NULL-terminate the string */
    pwszValue[cbData / sizeof(WCHAR)] = '\0';

    *pValue = pwszValue;
    return ERROR_SUCCESS;
}
#endif

#if 0
static BOOL
IsConsoleBoot(VOID)
{
    HKEY hControlKey = NULL;
    LPWSTR pwszSystemStartOptions = NULL;
    LPWSTR pwszCurrentOption, pwszNextOption; /* Pointers into SystemStartOptions */
    BOOL bConsoleBoot = FALSE;
    LONG rc;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control",
                       0,
                       KEY_QUERY_VALUE,
                       &hControlKey);
    if (rc != ERROR_SUCCESS)
        goto cleanup;

    rc = ReadRegSzKey(hControlKey, L"SystemStartOptions", &pwszSystemStartOptions);
    if (rc != ERROR_SUCCESS)
        goto cleanup;

    /* Check for CONSOLE switch in SystemStartOptions */
    pwszCurrentOption = pwszSystemStartOptions;
    while (pwszCurrentOption)
    {
        pwszNextOption = wcschr(pwszCurrentOption, L' ');
        if (pwszNextOption)
            *pwszNextOption = L'\0';
        if (wcsicmp(pwszCurrentOption, L"CONSOLE") == 0)
        {
            DPRINT("Found %S. Switching to console boot\n", pwszCurrentOption);
            bConsoleBoot = TRUE;
            goto cleanup;
        }
        pwszCurrentOption = pwszNextOption ? pwszNextOption + 1 : NULL;
    }

cleanup:
    if (hControlKey != NULL)
        RegCloseKey(hControlKey);
    if (pwszSystemStartOptions)
        HeapFree(GetProcessHeap(), 0, pwszSystemStartOptions);
    return bConsoleBoot;
}
#endif

static BOOL
GetClassGuidForInf(
    PWSTR InfName,
    LPGUID ClassGuid)
{
    DWORD RequiredSize;
    WCHAR ClassName[0x20];

    DPRINT("GetClassGuidForInf: '%ws'\n", InfName);

    if (!SetupDiGetINFClassW(InfName, ClassGuid, ClassName, 0x20, NULL))
    {
        DPRINT1("GetClassGuidForInf: ret FALSE\n");
        return FALSE;
    }

    if (!pSetupIsGuidNull(ClassGuid))
    {
        DPRINT1("GetClassGuidForInf: ret TRUE\n");
        return TRUE;
    }

    DPRINT("GetClassGuidForInf: '%ws'\n", ClassName);

    if (!SetupDiClassGuidsFromName(ClassName, ClassGuid, 1, &RequiredSize))
    {
        DPRINT1("GetClassGuidForInf: ret FALSE\n");
        return FALSE;
    }

    if (!RequiredSize)
    {
        DPRINT1("GetClassGuidForInf: ret FALSE\n");
        return FALSE;
    }

    DPRINT("GetClassGuidForInf: ret TRUE\n");
    return TRUE;
}

static BOOL
InstallPnpClassInstallers(
    HWND WndHandle,
    HINF InfHandle,
    HSPFILEQ FileQueue)
{
    SERVICE_STATUS ServiceStatus;
    SC_HANDLE hService;
    INFCONTEXT Context;
    SC_HANDLE hScm;
    GUID ClassGuid;
    PWSTR InfName;
    HKEY phkClass;
    LONG Count;
    DWORD ix;
    BOOL ret = FALSE;
    BOOL Result = TRUE;

    DPRINT("InstallPnpClassInstallers()\n");

    hScm = OpenSCManagerW(NULL, NULL, GENERIC_READ);
    if (hScm)
    {
        hService = OpenServiceW(hScm, L"PlugPlay", SERVICE_QUERY_STATUS);
        if (hService)
        {
            while (TRUE)
            {
                if (!QueryServiceStatus(hService, &ServiceStatus))
                {
                    LogItem(NULL, L"SETUP: QueryServiceStatus() failed. Error = %d", GetLastError());
                    DPRINT("InstallPnpClassInstallers: QueryServiceStatus() failed. Error = %d\n", GetLastError());

                    LogItem(NULL, L"SETUP: Couldn't find out the status of the Plug&Play service");
                    DPRINT("InstallPnpClassInstallers: Couldn't find out the status of the Plug&Play service\n");

                    break;
                }

                if (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    DPRINT("InstallPnpClassInstallers: PlugPlay service is running\n");
                    break;
                }

                LogItem(NULL, L"SETUP: PlugPlay service isn't running yet--sleeping 1 second...");
                DPRINT("InstallPnpClassInstallers: PlugPlay service isn't running yet--sleeping 1 second...\n");

                Sleep(1000);
            }

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hScm);
    }

    Count = SetupGetLineCountW(InfHandle, L"DeviceInfsToInstall");
    if (Count > 0)
    {
        for (ix = 0; ix < Count; ix++)
        {
            if (!SetupGetLineByIndexW(InfHandle, L"DeviceInfsToInstall", ix, &Context))
                continue;

            InfName = pSetupGetField(&Context, 1);
            if (!InfName)
                continue;

            DPRINT("InstallPnpClassInstallers: [%d] call SetupDiInstallClass('%ls')\n", ix, InfName);
            ret = SetupDiInstallClassW(WndHandle, InfName, (DI_FORCECOPY | DI_NOVCP), FileQueue);
            DPRINT("InstallPnpClassInstallers: ('%ls') ret %X\n", InfName, ret);

            if (!ret)
            {
                LogItem(NULL, L"SETUP: SetupDiInstallClass() failed. Filename = %ls Error = %lx.", InfName, GetLastError());
                DPRINT("InstallPnpClassInstallers: SetupDiInstallClass() failed. Filename = %ls Error = %lx.\n", InfName, GetLastError());

                Result = FALSE;
            }
        }
    }

    Count = SetupGetLineCountW(InfHandle, L"DeviceInfsToInstallIfExists");
    if (Count <= 0)
    {
        DPRINT("InstallPnpClassInstallers: ret Result %X\n", Result);
        return Result;
    }

    for (ix = 0; ix < Count; ix++)
    {
        if (!SetupGetLineByIndexW(InfHandle, L"DeviceInfsToInstallIfExists", ix, &Context))
            continue;

        InfName = pSetupGetField(&Context, 1);
        if (!InfName)
            continue;

        if (!GetClassGuidForInf(InfName, &ClassGuid))
            continue;

        if (CM_Open_Class_KeyW(&ClassGuid, NULL, KEY_READ, RegDisposition_OpenExisting, &phkClass, CM_OPEN_CLASS_KEY_INSTALLER))
            continue;

        RegCloseKey(phkClass);

        if (!SetupDiInstallClassW(WndHandle, InfName, (DI_FORCECOPY | DI_NOVCP), FileQueue))
        {
            LogItem(NULL, L"SETUP: SetupDiInstallClass() failed. Filename = %ls Error = %lx.", InfName, GetLastError());
            DPRINT("InstallPnpClassInstallers: SetupDiInstallClass() failed. Filename = %ls Error = %lx.\n", InfName, GetLastError());

            Result = FALSE;
        }
    }

    DPRINT("InstallPnpClassInstallers: ret Result %X\n", Result);
    return Result;
}

static PQUEUE_CALLBACK_CONTEXT
InitSysSetupQueueCallbackEx(
    HWND OwnerWindow,
    HWND AlternateProgressWindow,
    UINT ProgressMessage,
    DWORD Reserved1,
    PVOID Reserved2)
{
    PQUEUE_CALLBACK_CONTEXT CallbackCtx;

    DPRINT("InitSysSetupQueueCallbackEx: %X\n", ProgressMessage);

    CallbackCtx = pSetupMalloc(sizeof(*CallbackCtx));
    if (!CallbackCtx)
    {
        DPRINT1("InitSysSetupQueueCallbackEx: ret NULL\n");
        return NULL;
    }

    CallbackCtx->Skip = 0;
    CallbackCtx->DefaultContext = SetupInitDefaultQueueCallbackEx(OwnerWindow,
                                                                  AlternateProgressWindow,
                                                                  ProgressMessage,
                                                                  Reserved1,
                                                                  Reserved2);
    DPRINT("InitSysSetupQueueCallbackEx: ret %X\n", CallbackCtx);
    return CallbackCtx;
}

static
VOID
WINAPI
AssertFail_s(
    LPSTR FileName,
    UINT Line,
    LPSTR Assertion)
{
    LPCSTR lpCaption;
    CHAR lpText[4096];
    CHAR DllFilename[260];

    GetModuleFileNameA(hDllInstance, DllFilename, 260);

    lpCaption = strrchr(DllFilename, '\\');

    if (lpCaption)
        lpCaption++;
    else
        lpCaption = DllFilename;

    wsprintfA(lpText, "Assertion failure at line %u in file %s: %s\n\nCall DebugBreak()?", Line, FileName, Assertion);

    if (MessageBoxA(NULL, lpText, lpCaption, 0x12014) == 6)
        DebugBreak();
}

static
BOOL
WINAPI
FileExists_s(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFileFindData)
{
    DPRINT("FileExists_s()\n");
    ASSERT(FALSE);
    return FALSE;
}

static UINT
WINAPI
SysSetupQueueCallback(
    PVOID InContext,
    UINT Notification,
    UINT_PTR Param1,
    UINT_PTR Param2)
{
    PQUEUE_CALLBACK_CONTEXT Context = InContext;
    PFILEPATHS_W FilePathsW = (PFILEPATHS_W)Param1;
    DWORD dwFileAttributes;
    WCHAR lpFileName[260];
    PWCHAR Ptr;
    UINT Result;

    DPRINT("SysSetupQueueCallback: %X, %X\n", Notification, Param1);

    if ((Notification == SPFILENOTIFY_COPYERROR || Notification == SPFILENOTIFY_NEEDMEDIA) &&
        SkipMissingFiles &&
        (FilePathsW->Win32Error == ERROR_FILE_NOT_FOUND || FilePathsW->Win32Error == ERROR_PATH_NOT_FOUND))
    {
        if (Notification == SPFILENOTIFY_COPYERROR)
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }
        else
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }

        return FILEOP_SKIP;
    }

    if (Notification == SPFILENOTIFY_COPYERROR ||
        Notification == SPFILENOTIFY_RENAMEERROR ||
        Notification == SPFILENOTIFY_DELETEERROR)
    {
        if (FilePathsW->Win32Error == ERROR_DIRECTORY)
        {
            wcscpy(lpFileName, FilePathsW->Target);

            Ptr = wcsrchr(lpFileName, '\\');
            if (Ptr)
                *Ptr = 0;

            if (FileExists_s(lpFileName, NULL))
            {
                DeleteFileW(lpFileName);
                LogItem(NULL, L"autochk turned directory %s into file, delete file and retry\n", lpFileName);
                return FILEOP_RETRY;
            }
        }
    }

    if (Notification & (SPFILENOTIFY_TARGETNEWER | SPFILENOTIFY_TARGETEXISTS | SPFILENOTIFY_LANGMISMATCH))
    {
        AssertFail_s(__FILE__, __LINE__, "FALSE");
        //ReportError(..);
        return FILEOP_RETRY;
    }

    Result = SetupDefaultQueueCallbackW(Context->DefaultContext, Notification, (UINT_PTR)FilePathsW, Param2);

    if (Notification == SPFILENOTIFY_ENDQUEUE)
    {
        if (!FilePathsW)
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }

        return Result;
    }

    if (Notification == SPFILENOTIFY_STARTDELETE ||
        Notification == SPFILENOTIFY_STARTRENAME)
    {
        if (Result == FILEOP_SKIP)
            Context->Skip = TRUE;
        else
            Context->Skip = FALSE;

        return Result;
    }

    if (Notification == SPFILENOTIFY_ENDDELETE)
    {
        if (FilePathsW->Win32Error != ERROR_SUCCESS || Context->Skip)
        {
            if (FilePathsW->Win32Error == ERROR_FILE_NOT_FOUND || FilePathsW->Win32Error == ERROR_PATH_NOT_FOUND)
            {
                DPRINT1("SysSetupQueueCallback: FIXME\n");
                //AssertFail_s(__FILE__, __LINE__, "FALSE");
                //ReportError(..);
            }
            else if (FilePathsW->Win32Error != ERROR_SUCCESS)
            {
                DPRINT1("SysSetupQueueCallback: FIXME\n");
                //AssertFail_s(__FILE__, __LINE__, "FALSE");
                //ReportError(..);
            }
            else
            {
                DPRINT1("SysSetupQueueCallback: FIXME\n");
                //AssertFail_s(__FILE__, __LINE__, "FALSE");
                //ReportError(..);
            }
        }
        else
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }

        return Result;
    }

    if (Notification == SPFILENOTIFY_DELETEERROR)
    {
        if (Result == FILEOP_SKIP)
            Context->Skip = 1;

        return Result;
    }

    if (Notification == SPFILENOTIFY_ENDRENAME)
    {
        if (FilePathsW->Win32Error != ERROR_SUCCESS)
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }
        else if (Context->Skip)
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }
        else
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
        }

        return Result;
    }

    if (Notification == SPFILENOTIFY_RENAMEERROR)
    {
        if (Result == FILEOP_SKIP)
            Context->Skip = 1;

        return Result;
    }

    if (Notification == SPFILENOTIFY_STARTCOPY)
    {
        if (Result == FILEOP_SKIP)
            Context->Skip = TRUE;
        else
            Context->Skip = FALSE;

        return Result;
    }

    if (Notification == SPFILENOTIFY_ENDCOPY)
    {
        if (FilePathsW->Win32Error == ERROR_SUCCESS && !Context->Skip)
        {
            //LogRepairInfo(FilePathsW->Source, FilePathsW->Target);
            DPRINT("SysSetupQueueCallback: FIXME LogRepairInfo()\n");

            //AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);

            dwFileAttributes = GetFileAttributesW((LPCWSTR)FilePathsW->Target);
            SetFileAttributesW((LPCWSTR)FilePathsW->Target, (dwFileAttributes & ~1));
        }

        DPRINT1("SysSetupQueueCallback: Win32Error %d, Skip %X, '%S'\n", FilePathsW->Win32Error, Context->Skip, FilePathsW->Target);
        //AssertFail_s(__FILE__, __LINE__, "FALSE");
        //ReportError(..);

        return Result;
    }

    if (Notification == SPFILENOTIFY_COPYERROR)
    {
        if (Result == FILEOP_SKIP)
            Context->Skip = 1;

        return Result;
    }

    if (Notification == SPFILENOTIFY_NEEDMEDIA)
    {
        if (Result == FILEOP_SKIP)
        {
            AssertFail_s(__FILE__, __LINE__, "FALSE");
            //ReportError(..);
            Context->Skip = 1;
        }

        return Result;
    }

    if (Notification == SPFILENOTIFY_STARTREGISTRATION ||
        Notification == SPFILENOTIFY_ENDREGISTRATION)
    {
        AssertFail_s(__FILE__, __LINE__, "FALSE");
        //RegistrationQueueCallback(..);
    }

    return Result;
}

static VOID
WINAPI
TermSysSetupQueueCallback(
    PQUEUE_CALLBACK_CONTEXT CallbackCtx)
{
    DPRINT("TermSysSetupQueueCallback()\n");
    ASSERT(FALSE);
}

static BOOL
CopySystemFiles(VOID)
{
    PQUEUE_CALLBACK_CONTEXT CallbackCtx;
    HSPFILEQ FileQueue;
    DWORD QueueResult;
    BOOL Result;
  #ifndef __REACTOS__
    PWCHAR SectionName;
  #endif

    DPRINT("CopySystemFiles()\n");

    if (hSysSetupInf == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CopySystemFiles: hSysSetupInf == INVALID_HANDLE_VALUE\n");
        return FALSE;
    }

    FileQueue = SetupOpenFileQueue();
    if (FileQueue == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CopySystemFiles: FileQueue == INVALID_HANDLE_VALUE\n");
        return FALSE;
    }

  #ifndef __REACTOS__
    if (!Win31Upgrade)
        SectionName = L"Files.Install.CleanInstall";
    else
        SectionName = L"Files.Install.CleanInstall.Win31";

    Result = SetupInstallFilesFromInfSectionW(hSysSetupInf, NULL, FileQueue, SectionName, NULL, BaseCopyStyle);
  #endif

    InstallPnpClassInstallers(MainWindowHandle, hSysSetupInf, FileQueue);

  #ifndef __REACTOS__
    if (!Result)
    {
        goto Exit;
    }
  #endif

    Result = FALSE;

    CallbackCtx = InitSysSetupQueueCallbackEx(MainWindowHandle, INVALID_HANDLE_VALUE, 0, 0, NULL);
    if (!CallbackCtx)
    {
        DPRINT("CopySystemFiles: CallbackCtx is NULL\n");
        goto Exit;
    }

    if (!SetupScanFileQueueW(FileQueue, (SPQ_SCAN_PRUNE_COPY_QUEUE | SPQ_SCAN_FILE_VALIDITY), MainWindowHandle, NULL, NULL, &QueueResult))
        QueueResult = 0;

    if (QueueResult != 1)
    {
        DPRINT("CopySystemFiles: call SetupCommitFileQueueW()\n");
        Result = SetupCommitFileQueueW(MainWindowHandle, FileQueue, SysSetupQueueCallback, CallbackCtx);
    }

    TermSysSetupQueueCallback(CallbackCtx);

Exit:

    SetupCloseFileQueue(FileQueue);

    DPRINT("CopySystemFiles: ret %X\n", Result);
    return Result;
}

static BOOL
CommonInstall(VOID)
{
  #if 0
    HANDLE hThread = NULL;
  #endif
    BOOL bResult = FALSE;

    DPRINT("CommonInstall()\n");
    LogItem(L"BEGIN_SECTION", L"Common Initialiazation");

    hSysSetupInf = SetupOpenInfFileW(L"syssetup.inf", NULL, INF_STYLE_WIN4, NULL);
    if (hSysSetupInf == INVALID_HANDLE_VALUE)
    {
        FatalError("SetupOpenInfFileW() failed to open 'syssetup.inf' (Error %d)\n", GetLastError());
        return FALSE;
    }

  #if 0
    if (!InstallSysSetupInfDevices())
    {
        FatalError("InstallSysSetupInfDevices() failed! (Error %d)\n", GetLastError());
        goto Exit;
    }
  #endif

  #if 0
    if(!InstallSysSetupInfComponents())
    {
        FatalError("InstallSysSetupInfComponents() failed! (Error %d)\n", GetLastError());
        goto Exit;
    }
  #endif

    if (Upgrade)
    {
      #ifndef __REACTOS__
        LogItemL"BEGIN_SECTION", L"Upgrading System Files");
        UpgradeSystemFiles();
        LogItem(L"END_SECTION", L"Upgrading System Files");
      #endif
    }
    else
    {
        LogItem(L"BEGIN_SECTION", L"Copying System Files");
        CopySystemFiles();
        LogItem(L"END_SECTION", L"Copying System Files");
    }

  #if 0
    if (!IsConsoleBoot())
    {
        hThread = CreateThread(NULL, 0, ShowStatusMessageThread, NULL, 0, NULL);
    }
  #endif

  #if 0
    if (!EnableUserModePnpManager())
    {
        FatalError("EnableUserModePnpManager() failed!\n");
        goto Exit;
    }
  #endif

    if (MiniSetup)
    {
        DPRINT("CommonInstall(CMP_WaitNoPendingInstallEvents)\n");
        CMP_WaitNoPendingInstallEvents(INFINITE);
    }

    bResult = TRUE;
    DPRINT("CommonInstall: bResult is TRUE\n");

  #if 0
Exit:
  #endif

    if (bResult == FALSE)
    {
        SetupCloseInfFile(hSysSetupInf);
    }

  #if 0
    if (hThread != NULL)
    {
        PostThreadMessage(GetThreadId(hThread), WM_QUIT, 0, 0);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
  #endif

    LogItem(L"END_SECTION", L"Common Initialiazation");

    DPRINT("CommonInstall: bResult %X\n", bResult);
    return bResult;
}

static
DWORD
InstallLiveCD(VOID)
{
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    BOOL bRes;

    if (!CommonInstall())
        goto error;

    /* Install the TCP/IP protocol driver */
    bRes = InstallNetworkComponent(L"MS_TCPIP");
    if (!bRes && GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        DPRINT("InstallNetworkComponent() failed with error 0x%lx\n", GetLastError());
    }
    else
    {
        /* Start the TCP/IP protocol driver */
        SetupStartService(L"Tcpip", FALSE);
        SetupStartService(L"Dhcp", FALSE);
        SetupStartService(L"Dnscache", FALSE);
    }

    /* Register components */
    _SEH2_TRY
    {
        if (!SetupInstallFromInfSectionW(NULL,
                                         hSysSetupInf, L"RegistrationPhase2",
                                         SPINST_ALL,
                                         0, NULL, 0, NULL, NULL, NULL, NULL))
        {
            DPRINT1("SetupInstallFromInfSectionW failed!\n");
        }

        RegisterTypeLibraries(hSysSetupInf, L"TypeLibraries");
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Catching exception\n");
    }
    _SEH2_END;

    SetupCloseInfFile(hSysSetupInf);

    /* Run the shell */
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    bRes = CreateProcessW(L"userinit.exe",
                          NULL,
                          NULL,
                          NULL,
                          FALSE,
                          0,
                          NULL,
                          NULL,
                          &StartupInfo,
                          &ProcessInformation);
    if (!bRes)
        goto error;

    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);

    return 0;

error:
    MessageBoxW(
        NULL,
        L"Failed to load LiveCD! You can shutdown your computer, or press ENTER to reboot.",
        L"ReactOS LiveCD",
        MB_OK);
    return 0;
}

static BOOL
SetSetupType(DWORD dwSetupType)
{
    DWORD dwError;
    HKEY hKey;

    dwError = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\Setup",
        0,
        KEY_SET_VALUE,
        &hKey);
    if (dwError != ERROR_SUCCESS)
        return FALSE;

    dwError = RegSetValueExW(
        hKey,
        L"SetupType",
        0,
        REG_DWORD,
        (LPBYTE)&dwSetupType,
        sizeof(DWORD));
    RegCloseKey(hKey);
    if (dwError != ERROR_SUCCESS)
        return FALSE;

    return TRUE;
}

static DWORD CALLBACK
HotkeyThread(LPVOID Parameter)
{
    ATOM hotkey;
    MSG msg;

    DPRINT("HotkeyThread start\n");

    hotkey = GlobalAddAtomW(L"Setup Shift+F10 Hotkey");

    if (!RegisterHotKey(NULL, hotkey, MOD_SHIFT, VK_F10))
        DPRINT1("RegisterHotKey failed with %lu\n", GetLastError());

    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.hwnd == NULL && msg.message == WM_HOTKEY && msg.wParam == hotkey)
        {
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;

            if (CreateProcessW(L"cmd.exe",
                               NULL,
                               NULL,
                               NULL,
                               FALSE,
                               CREATE_NEW_CONSOLE,
                               NULL,
                               NULL,
                               &si,
                               &pi))
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else
            {
                DPRINT1("Failed to launch command prompt: %lu\n", GetLastError());
            }
        }
    }

    UnregisterHotKey(NULL, hotkey);
    GlobalDeleteAtom(hotkey);

    DPRINT("HotkeyThread terminate\n");
    return 0;
}

static
BOOL
InitializeProgramFilesDir(VOID)
{
    LONG Error;
    HKEY hKey;
    DWORD dwLength;
    WCHAR szProgramFilesDirPath[MAX_PATH];
    WCHAR szCommonFilesDirPath[MAX_PATH];
    WCHAR szBuffer[MAX_PATH];

    /* Load 'Program Files' location */
    if (!LoadStringW(hDllInstance,
                     IDS_PROGRAMFILES,
                     szBuffer,
                     ARRAYSIZE(szBuffer)))
    {
        DPRINT1("Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LoadStringW(hDllInstance,
                     IDS_COMMONFILES,
                     szCommonFilesDirPath,
                     ARRAYSIZE(szCommonFilesDirPath)))
    {
        DPRINT1("Warning: %lu\n", GetLastError());
    }

    /* Expand it */
    if (!ExpandEnvironmentStringsW(szBuffer,
                                   szProgramFilesDirPath,
                                   ARRAYSIZE(szProgramFilesDirPath)))
    {
        DPRINT1("Error: %lu\n", GetLastError());
        return FALSE;
    }

    wcscpy(szBuffer, szProgramFilesDirPath);
    wcscat(szBuffer, L"\\");
    wcscat(szBuffer, szCommonFilesDirPath);

    if (!ExpandEnvironmentStringsW(szBuffer,
                                   szCommonFilesDirPath,
                                   ARRAYSIZE(szCommonFilesDirPath)))
    {
        DPRINT1("Warning: %lu\n", GetLastError());
    }

    /* Store it */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                          0,
                          KEY_SET_VALUE,
                          &hKey);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Error: %lu\n", Error);
        return FALSE;
    }

    dwLength = (wcslen(szProgramFilesDirPath) + 1) * sizeof(WCHAR);
    Error = RegSetValueExW(hKey,
                           L"ProgramFilesDir",
                           0,
                           REG_SZ,
                           (LPBYTE)szProgramFilesDirPath,
                           dwLength);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Error: %lu\n", Error);
        RegCloseKey(hKey);
        return FALSE;
    }

    dwLength = (wcslen(szCommonFilesDirPath) + 1) * sizeof(WCHAR);
    Error = RegSetValueExW(hKey,
                           L"CommonFilesDir",
                           0,
                           REG_SZ,
                           (LPBYTE)szCommonFilesDirPath,
                           dwLength);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Warning: %lu\n", Error);
    }

    RegCloseKey(hKey);

    /* Create directory */
    // FIXME: Security!
    if (!CreateDirectoryW(szProgramFilesDirPath, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DPRINT1("Error: %lu\n", GetLastError());
            return FALSE;
        }
    }

    /* Create directory */
    // FIXME: Security!
    if (!CreateDirectoryW(szCommonFilesDirPath, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DPRINT1("Warning: %lu\n", GetLastError());
            // return FALSE;
        }
    }

    return TRUE;
}

static
VOID
InitializeDefaultUserLocale(VOID)
{
    WCHAR szBuffer[80];
    PWSTR ptr;
    HKEY hLocaleKey;
    DWORD ret;
    DWORD dwSize;
    LCID lcid;
    INT i;

    struct {LCTYPE LCType; PWSTR pValue;} LocaleData[] = {
        /* Number */
        {LOCALE_SDECIMAL, L"sDecimal"},
        {LOCALE_STHOUSAND, L"sThousand"},
        {LOCALE_SNEGATIVESIGN, L"sNegativeSign"},
        {LOCALE_SPOSITIVESIGN, L"sPositiveSign"},
        {LOCALE_SGROUPING, L"sGrouping"},
        {LOCALE_SLIST, L"sList"},
        {LOCALE_SNATIVEDIGITS, L"sNativeDigits"},
        {LOCALE_INEGNUMBER, L"iNegNumber"},
        {LOCALE_IDIGITS, L"iDigits"},
        {LOCALE_ILZERO, L"iLZero"},
        {LOCALE_IMEASURE, L"iMeasure"},
        {LOCALE_IDIGITSUBSTITUTION, L"NumShape"},

        /* Currency */
        {LOCALE_SCURRENCY, L"sCurrency"},
        {LOCALE_SMONDECIMALSEP, L"sMonDecimalSep"},
        {LOCALE_SMONTHOUSANDSEP, L"sMonThousandSep"},
        {LOCALE_SMONGROUPING, L"sMonGrouping"},
        {LOCALE_ICURRENCY, L"iCurrency"},
        {LOCALE_INEGCURR, L"iNegCurr"},
        {LOCALE_ICURRDIGITS, L"iCurrDigits"},

        /* Time */
        {LOCALE_STIMEFORMAT, L"sTimeFormat"},
        {LOCALE_STIME, L"sTime"},
        {LOCALE_S1159, L"s1159"},
        {LOCALE_S2359, L"s2359"},
        {LOCALE_ITIME, L"iTime"},
        {LOCALE_ITIMEMARKPOSN, L"iTimePrefix"},
        {LOCALE_ITLZERO, L"iTLZero"},

        /* Date */
        {LOCALE_SLONGDATE, L"sLongDate"},
        {LOCALE_SSHORTDATE, L"sShortDate"},
        {LOCALE_SDATE, L"sDate"},
        {LOCALE_IFIRSTDAYOFWEEK, L"iFirstDayOfWeek"},
        {LOCALE_IFIRSTWEEKOFYEAR, L"iFirstWeekOfYear"},
        {LOCALE_IDATE, L"iDate"},
        {LOCALE_ICALENDARTYPE, L"iCalendarType"},

        /* Misc */
        {LOCALE_SCOUNTRY, L"sCountry"},
        {LOCALE_SABBREVLANGNAME, L"sLanguage"},
        {LOCALE_ICOUNTRY, L"iCountry"},
        {0, NULL}};

    ret = RegOpenKeyExW(HKEY_USERS,
                        L".DEFAULT\\Control Panel\\International",
                        0,
                        KEY_READ | KEY_WRITE,
                        &hLocaleKey);
    if (ret != ERROR_SUCCESS)
    {
        return;
    }

    dwSize = 9 * sizeof(WCHAR);
    ret = RegQueryValueExW(hLocaleKey,
                           L"Locale",
                           NULL,
                           NULL,
                           (PBYTE)szBuffer,
                           &dwSize);
    if (ret != ERROR_SUCCESS)
        goto done;

    lcid = (LCID)wcstoul(szBuffer, &ptr, 16);
    if (lcid == 0)
        goto done;

    i = 0;
    while (LocaleData[i].pValue != NULL)
    {
        if (GetLocaleInfoW(lcid,
                           LocaleData[i].LCType | LOCALE_NOUSEROVERRIDE,
                           szBuffer,
                           ARRAYSIZE(szBuffer)))
        {
            RegSetValueExW(hLocaleKey,
                           LocaleData[i].pValue,
                           0,
                           REG_SZ,
                           (PBYTE)szBuffer,
                           (wcslen(szBuffer) + 1) * sizeof(WCHAR));
        }

        i++;
    }

done:
    RegCloseKey(hLocaleKey);
}

static
DWORD
SaveDefaultUserHive(VOID)
{
    WCHAR szDefaultUserHive[MAX_PATH];
    HKEY hUserKey = NULL;
    DWORD cchSize;
    DWORD dwError;

    DPRINT("SaveDefaultUserHive()\n");

    cchSize = ARRAYSIZE(szDefaultUserHive);
    GetDefaultUserProfileDirectoryW(szDefaultUserHive, &cchSize);

    wcscat(szDefaultUserHive, L"\\ntuser.dat");

    dwError = RegOpenKeyExW(HKEY_USERS,
                            L".DEFAULT",
                            0,
                            KEY_READ,
                            &hUserKey);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("RegOpenKeyExW() failed (Error %lu)\n", dwError);
        return dwError;
    }

    pSetupEnablePrivilege(L"SeBackupPrivilege", TRUE);

    /* Save the Default hive */
    dwError = RegSaveKeyExW(hUserKey,
                            szDefaultUserHive,
                            NULL,
                            REG_STANDARD_FORMAT);
    if (dwError == ERROR_ALREADY_EXISTS)
    {
        WCHAR szBackupHive[MAX_PATH];

        /* Build the backup hive file name by replacing the extension */
        wcscpy(szBackupHive, szDefaultUserHive);
        wcscpy(&szBackupHive[wcslen(szBackupHive) - 4], L".bak");

        /* Back up the existing default user hive by renaming it, replacing any possible existing old backup */
        if (!MoveFileExW(szDefaultUserHive,
                         szBackupHive,
                         MOVEFILE_REPLACE_EXISTING))
        {
            dwError = GetLastError();
            DPRINT1("Failed to create a default-user hive backup '%S', MoveFileExW failed (Error %lu)\n",
                    szBackupHive, dwError);
        }
        else
        {
            /* The backup has been done, retry saving the Default hive */
            dwError = RegSaveKeyExW(hUserKey,
                                    szDefaultUserHive,
                                    NULL,
                                    REG_STANDARD_FORMAT);
        }
    }
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("RegSaveKeyExW() failed (Error %lu)\n", dwError);
    }

    pSetupEnablePrivilege(L"SeBackupPrivilege", FALSE);

    RegCloseKey(hUserKey);

    return dwError;
}

static
DWORD
InstallReactOS(VOID)
{
    WCHAR szBuffer[MAX_PATH];
    HANDLE token;
    TOKEN_PRIVILEGES privs;
    HKEY hKey;
    HINF hShortcutsInf;
    HANDLE hHotkeyThread;
    BOOL ret;

    DPRINT("InstallReactOS()\n");

    InitializeSetupLog(FALSE);
    LogItem(NULL, L"Installing ReactOS");

    CreateTempDir(L"TEMP");
    CreateTempDir(L"TMP");

    if (!InitializeProgramFilesDir())
    {
        FatalError("InitializeProgramFilesDir() failed");
        return 0;
    }

    if (!InitializeProfiles())
    {
        FatalError("InitializeProfiles() failed");
        return 0;
    }

    InitializeDefaultUserLocale();

    if (GetWindowsDirectoryW(szBuffer, ARRAYSIZE(szBuffer)))
    {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                          0,
                          KEY_WRITE,
                          &hKey) == ERROR_SUCCESS)
        {
            RegSetValueExW(hKey,
                           L"PathName",
                           0,
                           REG_SZ,
                           (LPBYTE)szBuffer,
                           (wcslen(szBuffer) + 1) * sizeof(WCHAR));

            RegSetValueExW(hKey,
                           L"SystemRoot",
                           0,
                           REG_SZ,
                           (LPBYTE)szBuffer,
                           (wcslen(szBuffer) + 1) * sizeof(WCHAR));

            RegCloseKey(hKey);
        }

        PathAddBackslash(szBuffer);
        wcscat(szBuffer, L"system");
        CreateDirectory(szBuffer, NULL);
    }

    if (SaveDefaultUserHive() != ERROR_SUCCESS)
    {
        FatalError("SaveDefaultUserHive() failed");
        return 0;
    }

    if (!CopySystemProfile(0))
    {
        FatalError("CopySystemProfile() failed");
        return 0;
    }

    hHotkeyThread = CreateThread(NULL, 0, HotkeyThread, NULL, 0, NULL);

    if (!CommonInstall())
        return 0;

    /* Install the TCP/IP protocol driver */
    ret = InstallNetworkComponent(L"MS_TCPIP");
    if (!ret && GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        DPRINT("InstallNetworkComponent() failed with error 0x%lx\n", GetLastError());
    }
    else
    {
        /* Start the TCP/IP protocol driver */
        SetupStartService(L"Tcpip", FALSE);
        SetupStartService(L"Dhcp", FALSE);
        SetupStartService(L"Dnscache", FALSE);
    }

    InstallWizard();

    InstallSecurity();

    SetAutoAdminLogon();

    hShortcutsInf = SetupOpenInfFileW(L"shortcuts.inf",
                                      NULL,
                                      INF_STYLE_WIN4,
                                      NULL);
    if (hShortcutsInf == INVALID_HANDLE_VALUE)
    {
        FatalError("Failed to open shortcuts.inf");
        return 0;
    }

    if (!CreateShortcuts(hShortcutsInf, L"ShortcutFolders"))
    {
        FatalError("CreateShortcuts() failed");
        return 0;
    }

    SetupCloseInfFile(hShortcutsInf);

    hShortcutsInf = SetupOpenInfFileW(L"rosapps_shortcuts.inf",
                                       NULL,
                                       INF_STYLE_WIN4,
                                       NULL);
    if (hShortcutsInf != INVALID_HANDLE_VALUE)
    {
        if (!CreateShortcuts(hShortcutsInf, L"ShortcutFolders"))
        {
            FatalError("CreateShortcuts(rosapps) failed");
            return 0;
        }
        SetupCloseInfFile(hShortcutsInf);
    }

    SetupCloseInfFile(hSysSetupInf);
    SetSetupType(0);

    if (hHotkeyThread)
    {
        PostThreadMessage(GetThreadId(hHotkeyThread), WM_QUIT, 0, 0);
        CloseHandle(hHotkeyThread);
    }

    LogItem(NULL, L"Installing ReactOS done");
    TerminateSetupActionLog();

    if (AdminInfo.Name != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, AdminInfo.Name);

    if (AdminInfo.Domain != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, AdminInfo.Domain);

    if (AdminInfo.Password != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, AdminInfo.Password);

    /* Get shutdown privilege */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
        FatalError("OpenProcessToken() failed!");
        return 0;
    }
    if (!LookupPrivilegeValue(NULL,
                              SE_SHUTDOWN_NAME,
                              &privs.Privileges[0].Luid))
    {
        FatalError("LookupPrivilegeValue() failed!");
        return 0;
    }
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(token,
                              FALSE,
                              &privs,
                              0,
                              (PTOKEN_PRIVILEGES)NULL,
                              NULL) == 0)
    {
        FatalError("AdjustTokenPrivileges() failed!");
        return 0;
    }

    ExitWindowsEx(EWX_REBOOT, 0);
    return 0;
}

/*
 * Standard Windows-compatible export, which dispatches
 * to either 'InstallReactOS' or 'InstallLiveCD'.
 */
VOID
WINAPI
InstallWindowsNt(INT argc, WCHAR** argv)
{
    INT i;
    PWSTR p;

    LogItem(L"BEGIN_SECTION", L"Installing ReactOS");
    DPRINT1("InstallWindowsNt()\n");

    for (i = 0; i < argc; ++i)
    {
        p = argv[i];
        if (*p == L'-')
        {
            p++;

            /*
               NOTE: On Windows, "mini" means "minimal UI", and can be used in addition to "newsetup";
               these options are not exclusive.
            */
            if (_wcsicmp(p, L"mini") == 0)
            {
                MiniSetup = 1;
                InstallLiveCD();
                break;
            }

            if (_wcsicmp(p, L"newsetup") == 0)
            {
                InstallReactOS();
                break;
            }

            /* Add support for other switches */
        }
    }

    LogItem(L"END_SECTION", L"Installing ReactOS");
    DPRINT1("InstallWindowsNt: exit\n");
}

/*
 * @unimplemented
 */
DWORD WINAPI
SetupChangeFontSize(
    IN HANDLE hWnd,
    IN LPCWSTR lpszFontSize)
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
DWORD WINAPI
SetupChangeLocaleEx(HWND hWnd,
                    LCID Lcid,
                    LPCWSTR lpSrcRootPath,
                    char Unknown,
                    DWORD dwUnused1,
                    DWORD dwUnused2)
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @implemented
 */
DWORD WINAPI
SetupChangeLocale(HWND hWnd, LCID Lcid)
{
    return SetupChangeLocaleEx(hWnd, Lcid, NULL, 0, 0, 0);
}

DWORD
WINAPI
SetupStartService(
    LPCWSTR lpServiceName,
    BOOL bWait)
{
    SC_HANDLE hManager = NULL;
    SC_HANDLE hService = NULL;
    DWORD dwError = ERROR_SUCCESS;

    hManager = OpenSCManagerW(NULL,
                              NULL,
                              SC_MANAGER_ALL_ACCESS);
    if (hManager == NULL)
    {
        dwError = GetLastError();
        goto done;
    }

    hService = OpenServiceW(hManager,
                            lpServiceName,
                            SERVICE_START);
    if (hService == NULL)
    {
        dwError = GetLastError();
        goto done;
    }

    if (!StartService(hService, 0, NULL))
    {
        dwError = GetLastError();
        goto done;
    }

done:
    if (hService != NULL)
        CloseServiceHandle(hService);

    if (hManager != NULL)
        CloseServiceHandle(hManager);

    return dwError;
}
