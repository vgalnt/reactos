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
BOOL PrivilegeAlreadySet = FALSE;
HWND MainWindowHandle = NULL; // HACK
PWCHAR szPnpLogFile = L"pnplog.txt";
PWCHAR szEnumDevSection = L"EnumeratedDevices";

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
    HANDLE hFind;
    DWORD Error;
    UINT uMode;
    WIN32_FIND_DATAW FindFileData;

    uMode = SetErrorMode(1);

    hFind = FindFirstFileW(lpFileName, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
    }
    else
    {
        FindClose(hFind);

        if (lpFileFindData)
            memcpy(lpFileFindData, &FindFileData, sizeof(*lpFileFindData));

        Error = ERROR_SUCCESS;
    }

    SetErrorMode(uMode);
    SetLastError(Error);

    return (Error == ERROR_SUCCESS);
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

    if (CallbackCtx->DefaultContext)
        SetupTermDefaultQueueCallback(CallbackCtx->DefaultContext);

    pSetupFree(CallbackCtx);
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

#if 0
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
#endif

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

BOOL
WINAPI
PrecompileInfFiles(
    HWND hWndProgress,
    ULONG StartProgress,
    ULONG EndProgress)
{
    WCHAR OsDirBuffer[MAX_PATH + 1];
    WCHAR DirBuffer[MAX_PATH + 1];
    WIN32_FIND_DATAW FindFileData;
    PPRECOMPILE_INF LastEntry = NULL;
    PPRECOMPILE_INF Entry;
    HANDLE hFindFile;
    HINF InfHandle;
  #ifndef __REACTOS__
    ULONG ProgressPerPercent;
  #endif
    ULONG FileCount;
    ULONG ix;
    DWORD Error;
    BOOL Result;

    DPRINT("PrecompileInfFiles: %d-%d\n", StartProgress, EndProgress);
    LogItem(NULL, L"SETUP: Entering PrecompileInfFiles()");

    GetCurrentDirectoryW((MAX_PATH + 1), DirBuffer);

    if (!GetWindowsDirectoryW(OsDirBuffer, (MAX_PATH + 1)))
    {
        DPRINT("PrecompileInfFiles: GetWindowsDirectoryW() failed\n");
        ASSERT(FALSE);
        return FALSE;
    }

    wcscat(OsDirBuffer, L"\\inf");
    SetCurrentDirectoryW(OsDirBuffer);

    FileCount = 0;

    hFindFile = FindFirstFileW(L"*.inf", &FindFileData);

    if (hFindFile == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        DPRINT("PrecompileInfFiles: FindFirstFile(*.inf) failed. Error = %d\n", Error);
        LogItem(NULL, L"SETUP: FindFirstFile(*.inf) failed. Error = %d", Error);
    }
    else
    {
        do
        {
            if (!(FindFileData.dwFileAttributes & 0x10))
            {
                Entry = pSetupMalloc(sizeof(*Entry));
                if (Entry)
                {
                    Entry->FileName = pSetupDuplicateString(FindFileData.cFileName);
                    Entry->Next = LastEntry;
                    LastEntry = Entry;
                    FileCount++;
                }
            }
        }
        while (FindNextFileW(hFindFile, &FindFileData));

        FindClose(hFindFile);
    }

  #ifndef __REACTOS__
    ProgressPerPercent = ((FileCount + 1) * 100 / (EndProgress - StartProgress));
    SendMessageW(hWndProgress, 0x800C, (FileCount + 1), 0);
    SendMessageW(hWndProgress, 0x401, 0, ((WORD)ProgressPerPercent << 16));
    SendMessageW(hWndProgress, 0x402, ((ULONG)ProgressPerPercent * StartProgress / 100), 0);
    SendMessageW(hWndProgress, 0x404, 1, 0);
  #endif

    for (ix = 0; ; ix++)
    {
      #ifndef __REACTOS__
        if (ix != 0)
            SendMessageW(hWndProgress, 0x405, 0, 0);
      #endif

        if (ix >= FileCount)
            break;

        DPRINT("PrecompileInfFiles: Pre-compiling file: %ls\n", LastEntry->FileName);
        LogItem(NULL, L"SETUP: Pre-compiling file: %ls", LastEntry->FileName);

        InfHandle = SetupOpenInfFileW(LastEntry->FileName, NULL, INF_STYLE_WIN4, NULL);

        if (InfHandle == INVALID_HANDLE_VALUE)
        {
            Error = GetLastError();

            if ((LONG)Error >= 0)
            {
                DPRINT("PrecompileInfFiles: SetupOpenInfFile() failed. FileName = %ls, Error = %d\n", LastEntry->FileName, Error);
                LogItem(NULL, L"SETUP: SetupOpenInfFile() failed. FileName = %ls, Error = %d", LastEntry->FileName, Error);
            }
            else
            {
                DPRINT("PrecompileInfFiles: SetupOpenInfFile() failed. FileName = %ls, Error = %lx\n", LastEntry->FileName, Error);
                LogItem(NULL, L"SETUP: SetupOpenInfFile() failed. FileName = %ls, Error = %lx", LastEntry->FileName, Error);
            }
        }
        else
        {
            SetupCloseInfFile(InfHandle);
        }

        Entry = LastEntry;
        LastEntry = LastEntry->Next;

        if (Entry->FileName)
            pSetupFree(Entry->FileName);

        pSetupFree(Entry);
    }

    DPRINT("PrecompileInfFiles: Total inf files = %d, total precompiled: %d\n", FileCount, ix);
    LogItem(NULL, L"SETUP: Total inf files = %d, total precompiled: %d", FileCount, ix);

    LogItem(NULL, L"SETUP: Calling pSetupInfCacheBuild()");
    pSetupInfCacheBuild(1);

  #ifndef __REACTOS__
    SendMessageW(hWndProgress, 0x402, (EndProgress * ProgressPerPercent / 100), 0);
  #endif

    SetCurrentDirectoryW(DirBuffer);

    LogItem(NULL, L"SETUP: Leaving PrecompileInfFiles()");

    Result = (ix != 0);
    DPRINT("PrecompileInfFiles: ret Result %X\n", Result);
    return Result;
}

BOOL
WINAPI
GetDeviceConfigFlags(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    PDWORD PropertyBuffer)
{
    DWORD Error;

    DPRINT("GetDeviceConfigFlags: %X\n", DeviceInfoData);

    *PropertyBuffer = 0;

    if (SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                          DeviceInfoData,
                                          SPDRP_CONFIGFLAGS,
                                          NULL,
                                          (PBYTE)PropertyBuffer,
                                          sizeof(*PropertyBuffer),
                                          NULL))
    {
        return TRUE;
    }

    Error = GetLastError();

    if (Error == ERROR_INVALID_DATA)
        return TRUE;

    if ((INT)Error >= 0)
        LogItem(NULL, L"SETUP:   GetDeviceConfigFlags failed. Error = %d", Error);
    else
        LogItem(NULL, L"SETUP:   GetDeviceConfigFlags failed. Error = %lx", Error);

    return FALSE;
}

BOOL
WINAPI
SetDeviceConfigFlags(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    PDWORD PropertyBuffer)
{
    DWORD Error;

    DPRINT("SetDeviceConfigFlags: %X\n", DeviceInfoData);

    if (SetupDiSetDeviceRegistryPropertyW(DeviceInfoSet,
                                          DeviceInfoData,
                                          SPDRP_CONFIGFLAGS,
                                          (PBYTE)PropertyBuffer,
                                          sizeof(*PropertyBuffer)))
    {
        return TRUE;
    }

    Error = GetLastError();

    if ((INT)Error >= 0)
        LogItem(NULL, L"SETUP:   SetDeviceConfigFlags failed. Error = %d", Error);
    else
        LogItem(NULL, L"SETUP:   SetDeviceConfigFlags failed. Error = %lx", Error);

    return FALSE;
}

VOID
WINAPI
MarkPnpDevicesAsNeedReinstall(VOID)
{
    SP_DEVINFO_DATA DeviceInfoData;
    HDEVINFO DeviceInfoSet;
    DWORD ConfigFlags;
    DWORD Error;
    DWORD ix;
    ULONG ulProblemNumber;
    ULONG ulStatus;
    BOOL Result;

    DPRINT("MarkPnpDevicesAsNeedReinstall()\n");
    LogItem(NULL, L"SETUP: Entering MarkPnpDevicesAsNeedReinstall().");

    DeviceInfoSet = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
    if (DeviceInfoSet == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();

        if ((INT)Error >= 0)
            LogItem(NULL, L"SETUP: SetupDiGetClassDevs(DIGCF_ALLCLASSES) failed. Error = %d", Error);
        else
            LogItem(NULL, L"SETUP: SetupDiGetClassDevs(DIGCF_ALLCLASSES) failed. Error = %lx", Error);

        LogItem(NULL, L"SETUP: Leaving MarkPnpDevicesAsNeedReinstall(). No devices marked.");

        return;
    }

    DeviceInfoData.cbSize = sizeof(DeviceInfoData);

    for (ix = 0; SetupDiEnumDeviceInfo(DeviceInfoSet, ix, &DeviceInfoData); ix++)
    {
        if (CM_Get_DevNode_Status(&ulStatus, &ulProblemNumber, DeviceInfoData.DevInst, 0) == CR_SUCCESS)
            continue;

        Result = GetDeviceConfigFlags(DeviceInfoSet, &DeviceInfoData, &ConfigFlags);
        if (!Result)
        {
            LogItem(NULL, L"SETUP:   GetDeviceConfigFlags failed. Index = %d", ix);
            continue;
        }

        ConfigFlags |= 0x20;

        Result = SetDeviceConfigFlags(DeviceInfoSet, &DeviceInfoData, &ConfigFlags);
        if (!Result)
        {
            LogItem(NULL, L"SETUP:   SetDeviceConfigFlags failed. Index = %d", ix);
        }
    }

    Error = GetLastError();
    if (Error != ERROR_NO_MORE_ITEMS)
    {
        LogItem(NULL, L"SETUP: Device = %d, SetupDiEnumDeviceInfo() failed. Error = %d", ix, Error);
    }

    LogItem(NULL, L"SETUP: Leaving MarkPnpDevicesAsNeedReinstall(). Devices marked = %d", ix);

    SetupDiDestroyDeviceInfoList(DeviceInfoSet);
}

BOOL
WINAPI
SelectBestDriver(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    BOOL* OutIsOemDriver)
{
    SP_DRVINSTALL_PARAMS DriverInstallParams;
    SP_DRVINFO_DATA_W DriverInfoData;
    DWORD ix;

    DPRINT("SelectBestDriver: %p\n", DeviceInfoData);

    *OutIsOemDriver = FALSE;

    DriverInfoData.cbSize = sizeof(DriverInfoData);

    for (ix = 0; ; ix++)
    {
        if (!SetupDiEnumDriverInfoW(DeviceInfoSet, DeviceInfoData, 2, ix, &DriverInfoData))
            break;

        DriverInstallParams.cbSize = sizeof(DriverInstallParams);

        if (!SetupDiGetDriverInstallParamsW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInstallParams))
            continue;

        if (!(DriverInstallParams.Flags & 0x4000))
            continue;

        LogItem(NULL, L"SETUP: Using Oem F6 driver for this device.");

        *OutIsOemDriver = TRUE;

        DriverInfoData.cbSize = sizeof(DriverInfoData);

        for (ix = 0; ; ix++)
        {
            if (!SetupDiEnumDriverInfoW(DeviceInfoSet, DeviceInfoData, 2, ix, &DriverInfoData))
                break;

            DriverInstallParams.cbSize = sizeof(DriverInstallParams);

            if (SetupDiGetDriverInstallParamsW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInstallParams) &&
                !((DriverInstallParams.Flags & 0x4000)))
            {
                DPRINT1("SelectBestDriver: FIXME (Flags %X)\n", DriverInstallParams.Flags);
                ASSERT(FALSE);
                DriverInstallParams.Flags |= 0x800;
                //SetupDiSetDriverInstallParamsW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInstallParams);
            }
        }

        return SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV, DeviceInfoSet, DeviceInfoData);
    }

    return SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV, DeviceInfoSet, DeviceInfoData);
}

BOOL
WINAPI
SyssetupInstallNullDriver(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData)
{
    PWCHAR UnknownClassGuid = L"{4D36E97E-E325-11CE-BFC1-08002BE10318}";
    SP_DEVINSTALL_PARAMS_W DeviceInstallParams;
    WCHAR Guid[64];
    INT Error;

    DPRINT("SyssetupInstallNullDriver: %p, %p\n", DeviceInfoSet, DeviceInfoData);

    if (IsEqualGUID(&DeviceInfoData->ClassGuid, &GUID_NULL))
    {
        LogItem(NULL, L"SETUP:            Setting GUID_DEVCLASS_UNKNOWN for this device");

        if (!SetupDiSetDeviceRegistryPropertyW(DeviceInfoSet,
                                               DeviceInfoData,
                                               SPDRP_CLASSGUID,
                                               (PBYTE)UnknownClassGuid,
                                               ((wcslen(UnknownClassGuid) + 1) * sizeof(WCHAR))))
        {
            Error = GetLastError();

            if (Error >= 0)
            {
                LogItem(NULL, L"SETUP:            SetupDiSetDeviceRegistryProperty(SPDRP_CLASSGUID) failed. Error = %d", Error);
                DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceRegistryProperty(SPDRP_CLASSGUID) failed. Error = %d\n", Error);
            }
            else
            {
                LogItem(NULL, L"SETUP:            SetupDiSetDeviceRegistryProperty(SPDRP_CLASSGUID) failed. Error = %lx", Error);
                DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceRegistryProperty(SPDRP_CLASSGUID) failed. Error = %lx\n", Error);
            }
        }
    }
    else
    {
        pSetupStringFromGuid(&DeviceInfoData->ClassGuid, Guid, 64);
        LogItem(NULL, L"SETUP:            GUID = %ls", Guid);
        DPRINT("SyssetupInstallNullDriver: GUID = %ls\n", Guid);
    }

    if (!SetupDiSetSelectedDriverW(DeviceInfoSet, DeviceInfoData, NULL))
    {
        Error = GetLastError();

        if (Error >= 0)
        {
            LogItem(NULL, L"SETUP:            SetupDiSetSelectedDriver() failed. Error = %d", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiSetSelectedDriver() failed. Error = %d\n", Error);
        }
        else
        {
            LogItem(NULL, L"SETUP:            SetupDiSetSelectedDriver() failed. Error = %lx", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiSetSelectedDriver() failed. Error = %lx\n", Error);
        }

        return FALSE;
    }

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);

    if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        DeviceInstallParams.Flags |= 0x00800000;
        DeviceInstallParams.FlagsEx |= 0x20000000;

        if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
        {
            Error = GetLastError();

            if (Error >= 0)
            {
                LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %d", Error);
                DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceInstallParams() failed. Error = %d\n", Error);
            }
            else
            {
                LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %lx", Error);
                DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceInstallParams() failed. Error = %lx\n", Error);
            }
        }
    }
    else
    {
        Error = GetLastError();

        if (Error >= 0)
        {
            LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %d", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiGetDeviceInstallParams() failed. Error = %d\n", Error);
        }
        else
        {
            LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %lx", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiGetDeviceInstallParams() failed. Error = %lx\n", Error);
        }
    }

    if (SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DeviceInfoSet, DeviceInfoData))
        return TRUE;

    Error = GetLastError();

    if (Error >= 0)
    {
        LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed on first attempt. Error = %d", Error);
        DPRINT("SyssetupInstallNullDriver: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %d\n", Error);
    }
    else
    {
        LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed on first attempt. Error = %lx", Error);
        DPRINT("SyssetupInstallNullDriver: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %lx\n", Error);
    }

    LogItem(NULL, L"SETUP:            Trying a second time with DI_FLAGSEX_SETFAILEDINSTALL set.");
    DPRINT("SyssetupInstallNullDriver: Trying a second time with DI_FLAGSEX_SETFAILEDINSTALL set.\n");

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);

    if (!SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();

        if (Error >= 0)
        {
            LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %d", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiGetDeviceInstallParams() failed. Error = %d\n", Error);
        }
        else
        {
            LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %lx", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiGetDeviceInstallParams() failed. Error = %lx\n", Error);
        }

        return FALSE;
    }

    DeviceInstallParams.FlagsEx |= 0x00000080;

    if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();

        if (Error >= 0)
        {
            LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %d", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceInstallParams() failed. Error = %d\n", Error);
        }
        else
        {
            LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %lx", Error);
            DPRINT("SyssetupInstallNullDriver: SetupDiSetDeviceInstallParams() failed. Error = %lx\n", Error);
        }

        return FALSE;
    }

    if (SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DeviceInfoSet, DeviceInfoData))
        return TRUE;

    Error = GetLastError();

    if (Error >= 0)
    {
        LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %d", Error);
        DPRINT("SyssetupInstallNullDriver: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %d\n", Error);
    }
    else
    {
        LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %lx", Error);
        DPRINT("SyssetupInstallNullDriver: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %lx\n", Error);
    }

    return FALSE;
}

BOOL
WINAPI
RebuildListWithoutOldInternetDrivers(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData)
{
    SP_DEVINSTALL_PARAMS_W DeviceInstallParams;
    SP_DRVINSTALL_PARAMS DriverInstallParams;
    SP_DRVINFO_DATA_W DriverInfoData;
    HSPFILEQ FileQueue;
    DWORD Result;
    BOOL Ret;

    DPRINT("RebuildListWithoutOldInternetDrivers: %p\n", DeviceInfoSet);

    DriverInfoData.cbSize = sizeof(DriverInfoData);

    if (!SetupDiGetSelectedDriverW(DeviceInfoSet, DeviceInfoData, &DriverInfoData))
    {
        DPRINT("RebuildListWithoutOldInternetDrivers: SetupDiGetSelectedDriverW() failed\n");
        return FALSE;
    }

    DriverInstallParams.cbSize = sizeof(DriverInstallParams);
    if (!SetupDiGetDriverInstallParamsW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInstallParams))
    {
        DPRINT("RebuildListWithoutOldInternetDrivers: SetupDiGetDriverInstallParamsW() failed\n");
        return FALSE;
    }

    if (!(DriverInstallParams.Flags & 0x400))
    {
        DPRINT("RebuildListWithoutOldInternetDrivers: Flags %X\n", DriverInstallParams.Flags);
        return FALSE;
    }

    Ret = TRUE;

    FileQueue = SetupOpenFileQueue();
    if (FileQueue == INVALID_HANDLE_VALUE)
    {
        return Ret;
    }

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);

    if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        DeviceInstallParams.Flags |= 8;
        DeviceInstallParams.FileQueue = FileQueue;

        if (SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
        {
            Result = 0;

            if (SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES, DeviceInfoSet, DeviceInfoData) &&
                SetupScanFileQueueW(FileQueue, SPQ_SCAN_FILE_VALIDITY, NULL, NULL, NULL, &Result) &&
                (Result == 1 || Result == 2))
            {
                DPRINT("RebuildListWithoutOldInternetDrivers: Ret is FALSE\n");
                Ret = FALSE;
            }
        }
    }

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);

    if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        DeviceInstallParams.Flags &= ~8;
        DeviceInstallParams.FileQueue = INVALID_HANDLE_VALUE;

        SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams);
    }

    SetupCloseFileQueue(FileQueue);

    return Ret;
}

INT
WINAPI
SyssetupGetPnPFlags(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    PSP_DRVINFO_DATA_W DriverInfoData)
{
    SP_DRVINFO_DETAIL_DATA_W DriverInfoDetailData;
    WCHAR InfSectionWithExt[255];
    INFCONTEXT Context;
    HINF hInfFile;
    INT PnPFlags = 0;

    DPRINT("SyssetupGetPnPFlags: %p\n", DeviceInfoSet);

    DriverInfoDetailData.cbSize = sizeof(DriverInfoDetailData);

    if (!SetupDiGetDriverInfoDetailW(DeviceInfoSet, DeviceInfoData, DriverInfoData, &DriverInfoDetailData, sizeof(DriverInfoDetailData), NULL))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            AssertFail_s(__FILE__, __LINE__, "Err == ERROR_INSUFFICIENT_BUFFER");
            return PnPFlags;
        }
    }

    hInfFile = SetupOpenInfFileW(DriverInfoDetailData.InfFileName, NULL, INF_STYLE_WIN4, NULL);
    if (hInfFile == INVALID_HANDLE_VALUE)
    {
        return PnPFlags;
    }

    if (SetupDiGetActualSectionToInstallW(hInfFile, DriverInfoDetailData.SectionName, InfSectionWithExt, 255, NULL, NULL))
    {
        if (SetupFindFirstLineW(hInfFile, InfSectionWithExt, L"SyssetupPnPFlags", &Context))
        {
            if (!SetupGetIntField(&Context, 1, &PnPFlags))
            {
                PnPFlags = 0;
            }
        }
    }
    else
    {
        AssertFail_s(__FILE__, __LINE__, "0");
    }

    SetupCloseInfFile(hInfFile);

    return PnPFlags;
}

BOOL
WINAPI
SkipDeviceInstallation(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    HINF InfHandle,
    PWCHAR Key)
{
    HKEY hKey;
    WCHAR ReturnBuffer[261];

    DPRINT("SkipDeviceInstallation: %X\n", Key);

    hKey = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, 0x2000000);
    if (hKey == INVALID_HANDLE_VALUE)
    {
        LogItem(NULL, L"SETUP:            Device not yet installed.");
        return FALSE;
    }

    RegCloseKey(hKey);

    LogItem(NULL, L"SETUP:            Device already installed.");

    if (MiniSetup)
        return TRUE;

    return (SetupGetLineTextW(NULL, InfHandle, L"InstalledDevicesToSkip", Key, ReturnBuffer, 261, NULL) == TRUE);
}

VOID
WINAPI
FlushFilesToDisk(
    LPWSTR lpFileName)
{
    HANDLE hFile;
    DWORD Error;

    DPRINT("FlushFilesToDisk: '%S'\n", lpFileName);

    if (!PrivilegeAlreadySet)
    {
        if (!pSetupEnablePrivilege(L"SeBackupPrivilege", TRUE))
        {
            PrivilegeAlreadySet = FALSE;
        }
        else if (!pSetupEnablePrivilege(L"SeRestorePrivilege", TRUE))
        {
            PrivilegeAlreadySet = FALSE;
        }
        else
        {
            PrivilegeAlreadySet = TRUE;
        }
    }

    hFile = CreateFileW(lpFileName,
                        (GENERIC_READ | GENERIC_WRITE),
                        (FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: Failed to open %ls. Error = %d", lpFileName, Error);
        DPRINT1("FlushFilesToDisk: Failed to open %ls. Error = %d\n", lpFileName, Error);
        return;
    }

    if (FlushFileBuffers(hFile))
        Error = ERROR_SUCCESS;
    else
        Error = GetLastError();

    CloseHandle(hFile);

    if (Error != ERROR_SUCCESS)
    {
        LogItem(NULL, L"SETUP: FlushFileBuffers() failed. Root = %ls, Error = %d", lpFileName, Error);
        DPRINT1("FlushFilesToDisk: FlushFileBuffers() failed. Root = %ls, Error = %d\n", lpFileName, Error);
    }
}

BOOL
WINAPI
MarkDeviceAsNeedsReinstallIfNeeded(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData)
{
    DPRINT("FlushFilesToDisk()\n");
    ASSERT(FALSE);
    return FALSE;
}

DWORD
WINAPI
pInstallPnpEnumeratedDeviceThread(
    LPVOID lpThreadParameter)
{
    PPNP_ENUM_DEVICE_CONTEXT EnumDevContext = lpThreadParameter;
    SP_DRVINFO_DETAIL_DATA_W DriverInfoDetailData;
    SP_DEVINSTALL_PARAMS_W DeviceInstallParams;
    SP_DRVINFO_DATA_W DriverInfoData;
    PQUEUE_CALLBACK_CONTEXT CallbackCtx;
    PSP_DEVINFO_DATA DeviceInfoData;
    HDEVINFO DeviceInfoSet;
    HSPFILEQ OldFileQueue;
    HSPFILEQ FileQueue2;
    HSPFILEQ FileQueue;
    HKEY phkClass;
    PWSTR Device;
    DWORD FileQueueFlags;
    DWORD ConfigFlags;
    DWORD OldFlags;
    DWORD Result;
    DWORD Error;
    //ULONG pulProblemNumber;
    //ULONG pulStatus;
    WCHAR Buffer[262];
    BOOL IsFqFlags4;
    BOOL IsCommitFileQueue;

    DPRINT("pInstallPnpEnumeratedDeviceThread: %X\n", EnumDevContext);

    DeviceInfoSet = EnumDevContext->Info;
    Device = EnumDevContext->Description;
    DeviceInfoData = &EnumDevContext->InfoData;

    Error = ERROR_SUCCESS;
    IsCommitFileQueue = TRUE;
    IsFqFlags4 = FALSE;

    FileQueue = SetupOpenFileQueue();
    if (FileQueue == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupOpenFileQueue() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupOpenFileQueue() failed. Error = %d, Device = %ls", Error, Device);
        goto Exit;
    }

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);
    if (!SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiGetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiGetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    DeviceInstallParams.Flags |= 0x00800000;
    if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    if (!CM_Open_Class_KeyW(&DeviceInfoData->ClassGuid, NULL, KEY_READ, RegDisposition_OpenExisting, &phkClass, CM_OPEN_CLASS_KEY_INSTALLER))
    {
        RegCloseKey(phkClass);
    }
    else
    {
        FileQueue2 = SetupOpenFileQueue();
        if (FileQueue2 == INVALID_HANDLE_VALUE)
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: SetupOpenFileQueue() failed. Error = %d, Device = %ls", Error, Device);
            DPRINT1("SETUP: SetupOpenFileQueue() failed. Error = %d, Device = %ls", Error, Device);
            goto Finish;
        }

        DriverInfoData.cbSize = sizeof(DriverInfoData);
        if (!SetupDiGetSelectedDriverW(DeviceInfoSet, DeviceInfoData, &DriverInfoData))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: SetupDiGetSelectedDriver() failed. Error = %d, Device = %ls", Error, Device);
            DPRINT1("SETUP: SetupDiGetSelectedDriver() failed. Error = %d, Device = %ls", Error, Device);
            goto Finish;
        }

        DriverInfoDetailData.cbSize = sizeof(DriverInfoDetailData);
        if (!SetupDiGetDriverInfoDetailW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInfoDetailData, sizeof(DriverInfoDetailData), NULL))
        {
            if (GetLastError() != CM_OPEN_CLASS_KEY_INSTALLER)
            {
                Error = GetLastError();
                LogItem(NULL, L"SETUP: SetupDiGetDriverInfoDetail() failed. Error = %d, Device = %ls", Error, Device);
                DPRINT1("SETUP: SetupDiGetDriverInfoDetail() failed. Error = %d, Device = %ls", Error, Device);
                goto Finish;
            }
        }

        if (!SetupDiInstallClassW(NULL, DriverInfoDetailData.InfFileName, 0x02000008, FileQueue2))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: SetupDiInstallClass(%s) failed. Error = %d, Device = %ls", DriverInfoDetailData.InfFileName, Error, Device);
            DPRINT1("SETUP: SetupDiInstallClass(%s) failed. Error = %d, Device = %ls", DriverInfoDetailData.InfFileName, Error, Device);
            goto Finish;
        }

        CallbackCtx = InitSysSetupQueueCallbackEx(NULL, INVALID_HANDLE_VALUE, 0, 0, NULL);
        if (!CallbackCtx)
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: InitSysSetupQueueCallbackEx() failed. Error = %d", Error);
            DPRINT1("SETUP: InitSysSetupQueueCallbackEx() failed. Error = %d", Error);
            goto Finish;
        }

        if (!SetupCommitFileQueueW(NULL, FileQueue2, SysSetupQueueCallback, CallbackCtx))
            Error = GetLastError();

        TermSysSetupQueueCallback(CallbackCtx);
        SetupCloseFileQueue(FileQueue2);

        if (Error != ERROR_SUCCESS)
        {
            LogItem(NULL, L"SETUP: SetupCommitFileQueue(%s) failed while installing Class. Error = %d, Device = %ls", DriverInfoDetailData.InfFileName, Error, Device);
            DPRINT1("SETUP: SetupCommitFileQueue(%s) failed while installing Class. Error = %d, Device = %ls", DriverInfoDetailData.InfFileName, Error, Device);
            goto Finish;
        }

        LogItem(NULL, L"SETUP:            SetupDiInstallClass() succeeded. Device = %ls", Device);
        DPRINT1("SETUP:            SetupDiInstallClass() succeeded. Device = %ls", Device);
    }

    if (!SetupDiCallClassInstaller(DIF_ALLOW_INSTALL, DeviceInfoSet, DeviceInfoData))
    {
        Error = GetLastError();
        if (Error != ERROR_DI_DO_DEFAULT)
        {
            LogItem(NULL, L"SETUP: SetupDiCallClassInstaller(DIF_ALLOW_INSTALL) failed. Error = %d, Device = %ls", Error, Device);
            DPRINT1("SETUP: SetupDiCallClassInstaller(DIF_ALLOW_INSTALL) failed. Error = %d, Device = %ls", Error, Device);
            goto Finish;
        }
    }

    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_ALLOW_INSTALL) succeeded. Device = %ls", Device);
    DPRINT1("SETUP:            SetupDiCallClassInstaller(DIF_ALLOW_INSTALL) succeeded. Device = %ls", Device);

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);
    if (!SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiGetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiGetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    DeviceInstallParams.Flags |= 0x02000000;

    OldFileQueue = DeviceInstallParams.FileQueue;
    DeviceInstallParams.FileQueue = FileQueue;

    OldFlags = DeviceInstallParams.Flags;
    DeviceInstallParams.Flags |= 8;

  #ifndef __REACTOS__
    WCHAR String[260];
    String[0] = 0;
    if (pDoesExistingDriverNeedBackup(DeviceInfoSet, DeviceInfoData, (LPBYTE)String, 260))
    {
        LogItem(NULL, L"SETUP:            Backing up 3rd party drivers for Device = %ls", Device);
        DPRINT1("SETUP:            Backing up 3rd party drivers for Device = %ls", Device);
        DeviceInstallParams.FlagsEx |= 0x00080000;
    }
  #endif

    if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES, DeviceInfoSet, DeviceInfoData))
    {
        Error = GetLastError();
        if (Error != ERROR_DI_DO_DEFAULT)
        {
            LogItem(NULL, L"SETUP: SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES) failed. Error = %lx, Device = %ls ", Error, Device);
            DPRINT1("SETUP: SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES) failed. Error = %lx, Device = %ls ", Error, Device);
            goto Finish;
        }
    }

    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES) succeeded. Device = %ls", Device);
    DPRINT1("SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES) succeeded. Device = %ls", Device);

    CallbackCtx = InitSysSetupQueueCallbackEx(0, INVALID_HANDLE_VALUE, 0, 0, 0);

  #ifndef __REACTOS__
    if (pSetupVerifyQueuedCatalogs(FileQueue))
    {
        DriverInfoData.cbSize = sizeof(DriverInfoData);
        if (!SetupDiGetSelectedDriverW(DeviceInfoSet, DeviceInfoData, &DriverInfoData))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: SetupDiGetSelectedDriver() failed. Error = %d, Device = %ls", Error, Device);
            DPRINT1("SETUP: SetupDiGetSelectedDriver() failed. Error = %d, Device = %ls", Error, Device);
            goto Finish;
        }

        DriverInfoDetailData.cbSize = sizeof(DriverInfoDetailData);
        if (!SetupDiGetDriverInfoDetailW(DeviceInfoSet, DeviceInfoData, &DriverInfoData, &DriverInfoDetailData, 0x622, 0))
        {
            Error = GetLastError();
            if (Error != ERROR_INSUFFICIENT_BUFFER)
            {
                LogItem(NULL, L"SETUP: SetupDiGetDriverInfoDetail() failed. Error = %d, Device = %ls", Error, Device);
                DPRINT1("SETUP: SetupDiGetDriverInfoDetail() failed. Error = %d, Device = %ls", Error, Device);
                goto Finish;
            }
        }

        if (Upgrade)
        {
            if (!pSetupInfIsFromOemLocation(DriverInfoDetailData.InfFileName, 1) &&
                !IsInfInLayoutInf(DriverInfoDetailData.InfFileName))
            {
                PWCHAR FileTitle;

                if (String[0])
                    FileTitle = pSetupGetFileTitle(DriverInfoDetailData.InfFileName);

                if (!String[0] || !lstrcmpiW(String, FileTitle)))
                {
                    if (SetupScanFileQueueW(FileQueue, 0x81, hwndParent, 0, 0, &Result) && Result == 1)
                        IsCommitFileQueue = FALSE;
                }
            }
        }
    }
    else
  #endif
    {
        SetupScanFileQueueW(FileQueue, 0xA2, 0, 0, 0, &Result);
    }

    if (IsEqualGUID(&DeviceInfoData->ClassGuid, &GUID_DEVCLASS_COMPUTER))
        IsCommitFileQueue = FALSE;

    Error = ERROR_SUCCESS;

    if (IsCommitFileQueue)
    {
        if (!SetupCommitFileQueueW(0, FileQueue, (PSP_FILE_CALLBACK_W)SysSetupQueueCallback, CallbackCtx))
            Error = GetLastError();
    }

    if (SetupGetFileQueueFlags(FileQueue, &FileQueueFlags))
    {
        if (FileQueueFlags & 0x004) // ?
            IsFqFlags4 = 1;
    }

    TermSysSetupQueueCallback(CallbackCtx);

    if (Error != ERROR_SUCCESS)
    {
        LogItem(NULL, L"SETUP: SetupCommitFileQueue() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupCommitFileQueue() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    if (!IsFqFlags4)
        DeviceInstallParams.FlagsEx |= 0x20000000;

    DeviceInstallParams.FileQueue = OldFileQueue;
    DeviceInstallParams.Flags = OldFlags | 0x1000000;

    if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiSetDeviceInstallParams() failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    GetWindowsDirectoryW(Buffer, 261);
    Buffer[3] = 0;

    FlushFilesToDisk(Buffer);

    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DeviceInfoSet, DeviceInfoData))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) succeeded. Device = %ls", Device);
    DPRINT1("SETUP:            SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) succeeded. Device = %ls", Device);
    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DeviceInfoSet, DeviceInfoData))
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: SetupDiCallClassInstaller(DIF_REGISTER_INSTALLINTERFACES) failed. Error = %d, Device = %ls", Error, Device);
        DPRINT1("SETUP: SetupDiCallClassInstaller(DIF_REGISTER_INSTALLINTERFACES) failed. Error = %d, Device = %ls", Error, Device);
        goto Finish;
    }

    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLINTERFACES) succeeded. Device = %ls", Device);
    DPRINT1("SETUP:            SetupDiCallClassInstaller(DIF_INSTALLINTERFACES) succeeded. Device = %ls", Device);

    // ?? CM_Get_DevNode_Status(&pulStatus, &pulProblemNumber, DeviceInfoData->DevInst, 0);

    Error = ERROR_SUCCESS;
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DeviceInfoSet, DeviceInfoData))
    {
        Error = GetLastError();
        if (Error != ERROR_DI_DO_DEFAULT)
        {
            LogItem(NULL, L"SETUP: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %lx, Device = %ls ", Error, Device);
            DPRINT1("SETUP: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed. Error = %lx, Device = %ls ", Error, Device);
            goto Finish;
        }
    }

    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) suceeded. Device = %ls ", Device);
    DPRINT1("SETUP:            SetupDiCallClassInstaller(DIF_INSTALLDEVICE) suceeded. Device = %ls ", Device);

    if (!MarkDeviceAsNeedsReinstallIfNeeded(DeviceInfoSet, DeviceInfoData))
        Error = GetLastError();

Finish:

    if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
    {
        DeviceInstallParams.FileQueue = INVALID_HANDLE_VALUE;
        DeviceInstallParams.Flags &= ~8;
        SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams);
    }

    SetupCloseFileQueue(FileQueue);

Exit:

    if (Error == ERROR_SUCCESS)
        return Error;

    if (IsEqualGUID(&DeviceInfoData->ClassGuid, &GUID_DEVCLASS_SCSIADAPTER))
    {
        LogItem(NULL, L"SETUP:            Not installing the null driver on this SCSI Adapter device");
        DPRINT1("SETUP:            Not installing the null driver on this SCSI Adapter device");

        ConfigFlags = 0;
        GetDeviceConfigFlags(DeviceInfoSet, DeviceInfoData, &ConfigFlags);

        ConfigFlags &= (ConfigFlags & ~0x420);
        SetDeviceConfigFlags(DeviceInfoSet, DeviceInfoData, &ConfigFlags);

        return Error;
    }

    LogItem(NULL, L"SETUP:            Installing the null driver for this device");
    DPRINT1("SETUP:            Installing the null driver for this device");

    if (!SyssetupInstallNullDriver(DeviceInfoSet, DeviceInfoData))
    {
        LogItem(NULL, L"SETUP:            Unable to install null driver");
        DPRINT1("SETUP:            Unable to install null driver");
    }

    return Error;
}

BOOL
WINAPI
InstallEnumeratedDevices(
    HWND hWndParent,
    HINF hSetupInf,
    HWND hWndProgress,
    ULONG StartProgress,
    ULONG EndProgress)
{
    SP_DEVINSTALL_PARAMS_W DeviceInstallParams;
    PPNP_ENUM_DEVICE_CONTEXT EnumDevContext;
    SP_DRVINFO_DATA_W DriverInfoData;
    PSP_DEVINFO_DATA DeviceInfoData = NULL;
    HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
    HANDLE hPnpProcessedEvent = NULL;
    HANDLE hPnpPipeEvent;
    HANDLE hEvent;
    HANDLE hNewHwPipe = INVALID_HANDLE_VALUE;
    HANDLE hHandle;
  #ifndef __REACTOS__
    PVOID AnswerFileDriver;
    PVOID AfDriverTable;
  #endif
    WCHAR ReturnedString[256 + 1];
    WCHAR DeviceClass[256 + 1];
    WCHAR DeviceId[MAX_PATH];
    WCHAR PnpLogFileName[MAX_PATH + 1];
    WCHAR Guid[64];
    DWORD BytesRead = 0;
    DWORD Milliseconds;
    DWORD WaitResult;
    DWORD ThreadId;
    DWORD ExitCode;
    DWORD Error;
  #ifndef __REACTOS__
    ULONG ProgressPerPercent = 100;
  #endif
    INT PnPFlags;
    ULONG ix;
    BOOLEAN IsInstallSuccess;
    BOOLEAN IsCycleRun;
    BOOLEAN Result = TRUE;
    BOOL IsOemDriver;

    DPRINT("InstallEnumeratedDevices: hWndParent %X\n", hWndParent);
    LogItem(NULL, L"SETUP: Entering InstallEnumeratedDevices()");

    if (!GetWindowsDirectoryW(PnpLogFileName, (MAX_PATH + 1)))
    {
        AssertFail_s(__FILE__, __LINE__, "FALSE");
        return FALSE;
    }

    if (!pSetupConcatenatePaths(PnpLogFileName, szPnpLogFile, (MAX_PATH + 1), 0))
    {
        DPRINT1("InstallEnumeratedDevices: pSetupConcatenatePaths() is failed\n");
        AssertFail_s(__FILE__, __LINE__, "FALSE");
        return FALSE;
    }

  #ifndef __REACTOS__
    AfDriverTable = CreateAfDriverTable();  // L"$winnt$.inf"
  #endif

    hPnpPipeEvent = CreateEventW(NULL, TRUE, FALSE, L"PNP_Create_Pipe_Event");
    if (!hPnpPipeEvent)
    {
        Error = GetLastError();
        if (Error != ERROR_ALREADY_EXISTS)
        {
            LogItem(NULL, L"SETUP: CreateEvent() failed. Error = %d", Error);
            Result = FALSE;
            goto Exit;
        }

        hPnpPipeEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"PNP_Create_Pipe_Event");
        if (!hPnpPipeEvent)
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: OpenEvent() failed. Error = %d", Error);
            Result = FALSE;
            goto Exit;
        }
    }

    hPnpProcessedEvent = CreateEventW(NULL, TRUE, FALSE, L"PNP_Batch_Processed_Event");
    if (!hPnpProcessedEvent)
    {
        Error = GetLastError();
        if (Error != 183)
        {
            LogItem(NULL, L"SETUP: CreateEvent() failed. Error = %d", Error);
            Result = FALSE;
            goto Exit;
        }

        hPnpProcessedEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"PNP_Batch_Processed_Event");
        if (!hPnpProcessedEvent)
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: OpenEvent() failed. Error = %d", Error);
            Result = FALSE;
            goto Exit;
        }
    }

    hNewHwPipe = CreateNamedPipeW(L"\\\\.\\pipe\\PNP_New_HW_Found",
                                  PIPE_ACCESS_INBOUND,
                                  (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE),
                                  1,
                                  sizeof(DeviceId),
                                  sizeof(DeviceId),
                                  180000,
                                  NULL);
    SetEvent(hPnpPipeEvent);

    if (hNewHwPipe == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: CreateNamedPipe() failed. Error = %d", Error);
        Result = FALSE;
        goto Exit;
    }

    if (!ConnectNamedPipe(hNewHwPipe, 0) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        Error = GetLastError();
        LogItem(NULL, L"SETUP: ConnectNamedPipe() failed. Error = %d", Error);
        Result = FALSE;
        goto Exit;
    }

  #ifndef __REACTOS__
    ProgressPerPercent = 5000 / (EndProgress - StartProgress);

    SendMessageW(hWndProgress, 0x800C, 50, 0);
    SendMessageW(hWndProgress, 0x401, 0, (WORD)ProgressPerPercent << 16);
    SendMessageW(hWndProgress, 0x402, (StartProgress * ProgressPerPercent / 100), 0);
    SendMessageW(hWndProgress, 0x404, 1, 0);
  #endif

    for (ix = 0; ; ix++)
    {
        DPRINT("InstallEnumeratedDevices: ix %d\n", ix);

      #ifndef __REACTOS__
        if (ix && ix < 50)
            SendMessageW(hWndProgress, 0x405, 0, 0);
      #endif

        if (!ReadFile(hNewHwPipe, DeviceId, sizeof(DeviceId), &BytesRead, 0))
        {
            if (GetLastError() != ERROR_BROKEN_PIPE)
            {
                Error = GetLastError();
                LogItem(NULL, L"SETUP: ReadFile(hPipe) failed. Error = %d", Error);
                Result = FALSE;
            }

            goto Exit;
        }

        if (!lstrlenW(DeviceId))
        {
            SetEvent(hPnpProcessedEvent);
            continue;
        }

        LogItem(NULL, L"SETUP: ix = %d, DeviceId = %ls", ix, DeviceId);

        ReturnedString[0] = 0;
        if (GetPrivateProfileStringW(szEnumDevSection, DeviceId, L"", ReturnedString, (256 + 1), PnpLogFileName))
        {
            //wcslen(ReturnedString); ??
        }

        LogItem(L"BEGIN_SECTION", ReturnedString);

        if (DeviceInfoSet == INVALID_HANDLE_VALUE)
        {
            DeviceInfoSet = SetupDiCreateDeviceInfoList(0, hWndParent);
            if (DeviceInfoSet == INVALID_HANDLE_VALUE)
            {
                Result = FALSE;
                Error = GetLastError();
                LogItem(NULL, L"SETUP: SetupDiCreateDeviceInfoList() failed. Error = %d", Error);
                goto Exit;
            }

            DeviceInfoData = pSetupMalloc(sizeof(*DeviceInfoData));
            if (!DeviceInfoData)
            {
                Result = FALSE;
                LogItem(NULL, L"SETUP: Unable to create pDeviceInfoData.  MyMalloc() failed.");
                goto Exit;
            }

            DeviceInfoData->cbSize = sizeof(*DeviceInfoData);
        }

        if (!SetupDiOpenDeviceInfoW(DeviceInfoSet, DeviceId, hWndParent, 0, DeviceInfoData))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP:             SetupDiOpenDeviceInfo() failed. Error = %d", Error);
            Result = FALSE;
            LogItem(L"END_SECTION", ReturnedString);
            continue;
        }

      #ifndef __REACTOS__
        if (SyssetupInstallAnswerFileDriver(AfDriverTable, DeviceInfoSet, DeviceInfoData, &AnswerFileDriver))
        {
            LogItem(NULL, L"SETUP:            Device was installed via answer file driver");
        }
        else
      #endif
        {
            LogItem(NULL, L"SETUP:            Device was NOT installed via answer file driver");

            if (!SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, 2))
            {
                Error = GetLastError();
                LogItem(NULL, L"SETUP:         SetupDiBuildDriverInfoList() failed. Error = %d", Error);
                Result = FALSE;
                continue;
            }

            if (!SelectBestDriver(DeviceInfoSet, DeviceInfoData, &IsOemDriver))
            {
                Error = GetLastError();
                if (Error == ERROR_NO_COMPAT_DRIVERS)
                {
                    LogItem(NULL, L"SETUP:            Compatible driver List is empty");
                    LogItem(NULL, L"SETUP:            Installing the null driver for this device");

                    if (!SyssetupInstallNullDriver(DeviceInfoSet, DeviceInfoData))
                        LogItem(NULL, L"SETUP:            Unable to install null driver");

                    LogItem(L"END_SECTION", ReturnedString);
                    continue;
                }

                LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV) failed. Error = %d", Error);

                Result = FALSE;

                LogItem(L"END_SECTION", ReturnedString);
                continue;
            }

            if (RebuildListWithoutOldInternetDrivers(DeviceInfoSet, DeviceInfoData))
            {
                SetupDiDestroyDriverInfoList(DeviceInfoSet, DeviceInfoData, 2);

                DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);

                if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
                {
                    DeviceInstallParams.FlagsEx |= 0x800000;
                    SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams);
                }

                if (!SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, 2))
                {
                    Error = GetLastError();
                    LogItem(NULL, L"SETUP:         SetupDiBuildDriverInfoList() failed. Error = %d", Error);
                    Result = FALSE;
                    continue;
                }

                if (!SelectBestDriver(DeviceInfoSet, DeviceInfoData, &IsOemDriver))
                {
                    Error = GetLastError();
                    if (Error == ERROR_NO_COMPAT_DRIVERS)
                    {
                        LogItem(NULL, L"SETUP:            Compatible driver List is empty");
                        LogItem(NULL, L"SETUP:            Installing the null driver for this device");

                        if (!SyssetupInstallNullDriver(DeviceInfoSet, DeviceInfoData))
                            LogItem(NULL, L"SETUP:            Unable to install null driver");

                        LogItem(L"END_SECTION", ReturnedString);
                        continue;
                    }

                    LogItem(NULL, L"SETUP:            SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV) failed. Error = %d", Error);
                    Result = FALSE;
                    LogItem(L"END_SECTION", ReturnedString);
                    continue;
                }
            }
        }

        DriverInfoData.cbSize = sizeof(DriverInfoData);

        if (!SetupDiGetSelectedDriverW(DeviceInfoSet, DeviceInfoData, &DriverInfoData))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP:            SetupDiGetSelectedDriver() failed. Error = %d", Error);
            Result = FALSE;
            continue;
        }

        Guid[0] = 0;
        pSetupStringFromGuid(&DeviceInfoData->ClassGuid, Guid, 64);

        LogItem(NULL, L"SETUP:            DriverType = %lx", DriverInfoData.DriverType);
        LogItem(NULL, L"SETUP:            Description = %ls", DriverInfoData.Description);
        LogItem(NULL, L"SETUP:            MfgName = %ls", DriverInfoData.MfgName);
        LogItem(NULL, L"SETUP:            ProviderName = %ls", DriverInfoData.ProviderName);
        LogItem(NULL, L"SETUP:            Guid = %ls", Guid);

        DeviceClass[0] = 0;
        if (!SetupDiGetClassDescriptionW(&DeviceInfoData->ClassGuid, DeviceClass, (256 + 1), 0))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: SetupDiGetClassDescription() failed. Error = %lx", Error);
            DeviceClass[0] = 0;
        }

        LogItem(NULL, L"SETUP:            DeviceClass = %ls", DeviceClass);

        PnPFlags = SyssetupGetPnPFlags(DeviceInfoSet, DeviceInfoData, &DriverInfoData);

        if (SkipDeviceInstallation(DeviceInfoSet, DeviceInfoData, hSetupInf, Guid))
        {
            LogItem(NULL, L"SETUP:            Skipping installation of this device");
            LogItem(L"END_SECTION", ReturnedString);
            continue;
        }

        if (PnPFlags & 1)
        {
            DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);
            if (SetupDiGetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
            {
                DeviceInstallParams.Flags |= 0x20000;
                if (!SetupDiSetDeviceInstallParamsW(DeviceInfoSet, DeviceInfoData, &DeviceInstallParams))
                {
                    Error = GetLastError();

                    if ((LONG)Error >= 0)
                        LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %d", Error);
                    else
                        LogItem(NULL, L"SETUP:            SetupDiSetDeviceInstallParams() failed. Error = %lx", Error);
                }
            }
            else
            {
                Error = GetLastError();

                if ((LONG)Error >= 0)
                    LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %d", Error);
                else
                    LogItem(NULL, L"SETUP:            SetupDiGetDeviceInstallParams() failed. Error = %lx", Error);
            }
        }

        EnumDevContext = pSetupMalloc(sizeof(*EnumDevContext));
        EnumDevContext->Info = DeviceInfoSet;

        RtlCopyMemory(&EnumDevContext->InfoData, DeviceInfoData, sizeof(EnumDevContext->InfoData));

        EnumDevContext->Description = pSetupDuplicateString(DriverInfoData.Description);
        EnumDevContext->DeviceId = pSetupDuplicateString(DeviceId);

        IsInstallSuccess = FALSE;

        hHandle = CreateThread(NULL, 0, pInstallPnpEnumeratedDeviceThread, EnumDevContext, 0, &ThreadId);
        if (!hHandle)
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP:            CreateThread() failed (enumerated device). Error = %d", Error);

            if (pInstallPnpEnumeratedDeviceThread(EnumDevContext))
            {
                LogItem(NULL, L"SETUP:            Device not successfully installed.");
                Result = FALSE;
            }
            else
            {
                IsInstallSuccess = TRUE;
            }

            pSetupFree(EnumDevContext->Description);
            pSetupFree(EnumDevContext->DeviceId);
            pSetupFree(EnumDevContext);

            if (IsInstallSuccess)
            {
              #ifndef __REACTOS__
                if (AnswerFileDriver)
                    SyssetupFixAnswerFileDriverPath(AnswerFileDriver, DeviceInfoSet, DeviceInfoData);
              #endif

                if (IsOemDriver)
                {
                  #ifndef __REACTOS__
                    AddOemF6DriversToSfcIgnoreFilesList(DeviceInfoSet, DeviceInfoData);
                  #else
                    AssertFail_s(__FILE__, __LINE__, "FIXME IsOemDriver");
                  #endif
                }
            }

            LogItem(L"END_SECTION", ReturnedString);
            continue;
        }

        for (IsCycleRun = TRUE; IsCycleRun; )
        {
            if (_wcsicmp(Guid, L"{4D36E972-E325-11CE-BFC1-08002BE10318}"))
                Milliseconds = 120000;
            else
                Milliseconds = 600000;

            WaitResult = WaitForSingleObject(hHandle, Milliseconds);
            if (WaitResult == WAIT_TIMEOUT)
            {
                hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"MS_SETUPAPI_DIALOG");
                if (hEvent)
                {
                    IsCycleRun = TRUE;
                    CloseHandle(hEvent);
                    break;
                }

                LogItem(NULL, L"SETUP:    Class Installer appears to be hung. Device = %ls", DriverInfoData.Description);

                WaitResult = WaitForSingleObject(hHandle, 0);
                if (WaitResult != WAIT_OBJECT_0)
                {
                    IsCycleRun = FALSE;
                    LogItem(NULL, L"SETUP:    Skipping installation of enumerated device. Device = %ls", DriverInfoData.Description);
                    Result = FALSE;

                    WritePrivateProfileStringW(szEnumDevSection, DeviceId, DriverInfoData.Description, PnpLogFileName);

                    DeviceInfoSet = INVALID_HANDLE_VALUE;
                    DeviceInfoData = NULL;
                }
            }
            else if (WaitResult == WAIT_OBJECT_0)
            {
                IsCycleRun = FALSE;

                pSetupFree(EnumDevContext->Description);
                pSetupFree(EnumDevContext->DeviceId);
                pSetupFree(EnumDevContext);

                if (GetExitCodeThread(hHandle, &ExitCode))
                {
                    if (ExitCode != 0)
                    {
                        LogItem(NULL, L"SETUP:            Device not successfully installed.");
                        Result = FALSE;
                    }
                    else
                    {
                        IsInstallSuccess = TRUE;
                        LogItem(NULL, L"SETUP:            Device successfully installed.");
                    }
                }
                else
                {
                    Error = GetLastError();
                    LogItem(NULL, L"SETUP:            GetExitCode() failed. Error = %d", Error);
                    LogItem(NULL, L"SETUP:            Unable to retrieve thread exit code. Assuming device successfully installed.");
                }
            }
            else
            {
                IsCycleRun = FALSE;
                LogItem(NULL, L"SETUP:            WaitForSingleObject() returned %d", WaitResult);
                Result = FALSE;
            }

            CloseHandle(hHandle);

            if (IsInstallSuccess)
            {
              #ifndef __REACTOS__
                if (AnswerFileDriver)
                    SyssetupFixAnswerFileDriverPath(AnswerFileDriver, DeviceInfoSet, DeviceInfoData);
              #endif

                if (IsOemDriver)
                {
                  #ifndef __REACTOS__
                    AddOemF6DriversToSfcIgnoreFilesList(DeviceInfoSet, DeviceInfoData);
                  #else
                    DPRINT1("InstallEnumeratedDevices: IsOemDriver\n");
                    AssertFail_s(__FILE__, __LINE__, "FIXME IsOemDriver");
                  #endif
                }
            }

            LogItem(L"END_SECTION", ReturnedString);
        }
    }

Exit:

    LogItem(L"BEGIN_SECTION", L"InstallEnumeratedDevices cleanup");

  #ifndef __REACTOS__
    SendMessageW(hWndProgress, 0x402, (EndProgress * ProgressPerPercent / 100), 0);
  #endif

    if (hNewHwPipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(hNewHwPipe);
        CloseHandle(hNewHwPipe);
    }

    if (hPnpPipeEvent)
        CloseHandle(hPnpPipeEvent);

    if (hPnpProcessedEvent)
        CloseHandle(hPnpProcessedEvent);

    if (DeviceInfoSet != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DeviceInfoSet);

  #ifndef __REACTOS__
    DestroyAfDriverTable(AfDriverTable);
  #endif

    if (DeviceInfoData)
        pSetupFree(DeviceInfoData);

    LogItem(NULL, L"SETUP: Leaving InstallEnumeratedDevices()");
    LogItem(L"END_SECTION", L"InstallEnumeratedDevices cleanup");

    return Result;
}

BOOL
WINAPI
CallRunOnceAndWait(VOID)
{
    DPRINT("CallRunOnceAndWait()\n");
    ASSERT(FALSE);
    return FALSE;
}

BOOL
WINAPI
InstallLegacyDevices(
    HWND hWndParent,
    HWND hWndProgress,
    ULONG StartProgress,
    ULONG EndProgress)
{
    DPRINT("InstallLegacyDevices()\n");
    ASSERT(FALSE);
    return FALSE;
}

DWORD
WINAPI
pInstallPnpDevicesThread(
    LPVOID InContext)
{
    PPNP_DEVICES_THREAD_CONTEXT Context = InContext;
    ULONG ProgressQuarter;
    ULONG OldFlags;
    BOOL Result=0;
  #ifndef __REACTOS__
    DWORD Error;
  #endif

    OldFlags = pSetupGetGlobalFlags();
    pSetupSetGlobalFlags(OldFlags | 1);

    DPRINT("pInstallPnpDevicesThread: OldFlags %X\n", OldFlags);

    ProgressQuarter = ((Context->EndProgress - Context->StartProgress) / 4);

  #ifndef __REACTOS__
    RemainingTime = CalcTimeRemaining(2);
    SetRemainingTime(RemainingTime);
  #endif

    LogItem(L"BEGIN_SECTION", L"Installing OEM infs");
  #ifndef __REACTOS__
    InstallOEMInfs();
    SfcExcludeMigratedDrivers();
  #endif
    LogItem(L"END_SECTION", L"Installing OEM infs");

    LogItem(L"BEGIN_SECTION", L"Precompiling infs");
    PrecompileInfFiles(Context->hWndProgress, Context->StartProgress, (Context->StartProgress + ProgressQuarter));
    LogItem(L"END_SECTION", L"Precompiling infs");

    if (!MiniSetup)
    {
        LogItem(L"BEGIN_SECTION", L"Mark PnP devices for reinstall");
        MarkPnpDevicesAsNeedReinstall();
        LogItem(L"END_SECTION", L"Mark PnP devices for reinstall");
    }

    DPRINT1("pInstallPnpDevicesThread: FIXME PnPInitializationThread()\n");
    //PnPInitializationThread(0);

  #ifndef __REACTOS__
    RemainingTime = CalcTimeRemaining(3);
    SetRemainingTime(RemainingTime);
  #endif

    LogItem(L"BEGIN_SECTION", L"Installing enumerated devices");
    Result = InstallEnumeratedDevices(Context->hWndParent,
                                      Context->hSetupInf,
                                      Context->hWndProgress,
                                      (Context->StartProgress + (1 * ProgressQuarter)),
                                      (Context->StartProgress + (2 * ProgressQuarter)));
    DPRINT("pInstallPnpDevicesThread: Result %X\n", Result);
    CallRunOnceAndWait();
    LogItem(L"END_SECTION", L"Installing enumerated devices");
    DPRINT("pInstallPnpDevicesThread: END_SECTION 'Installing enumerated devices'\n");

    LogItem(L"BEGIN_SECTION", L"Installing legacy devices");
  #ifndef __REACTOS__
    RemainingTime = CalcTimeRemaining(4);
    SetRemainingTime(RemainingTime);
  #endif

    Result = (InstallLegacyDevices(Context->hWndParent,
                                   Context->hWndProgress,
                                   (Context->StartProgress + (2 * ProgressQuarter)),
                                   (Context->StartProgress + (3 * ProgressQuarter))) && Result);
    DPRINT("pInstallPnpDevicesThread: Result %X\n", Result);
    CallRunOnceAndWait();
    LogItem(L"END_SECTION", L"Installing legacy devices");
    DPRINT("pInstallPnpDevicesThread: END_SECTION 'Installing legacy devices'\n");

    LogItem(L"BEGIN_SECTION", L"Install enumerated devices triggered by legacy devices");
  #ifndef __REACTOS__
    RemainingTime = CalcTimeRemaining(5);
    SetRemainingTime(RemainingTime);
  #endif
    Result = (InstallEnumeratedDevices(Context->hWndParent,
                                       Context->hSetupInf,
                                       Context->hWndProgress,
                                       (Context->StartProgress + (3 * ProgressQuarter)),
                                       Context->EndProgress) && Result);
    DPRINT("pInstallPnpDevicesThread: Result %X\n", Result);
    OldFlags = pSetupGetGlobalFlags();
    pSetupSetGlobalFlags(OldFlags & ~1);
    CallRunOnceAndWait();
    LogItem(L"END_SECTION", L"Install enumerated devices triggered by legacy devices");
    DPRINT("pInstallPnpDevicesThread: END_SECTION 'Install enumerated devices triggered by legacy devices'\n");

    if (!MiniSetup)
        MarkPnpDevicesAsNeedReinstall();

    DPRINT("pInstallPnpDevicesThread: MiniSetup %X\n", MiniSetup);

  #ifndef __REACTOS__
    if (!Context->IsOwnThread)
        return Result;

    for (Error = 0; Error;)
    {
        if (!PostThreadMessageW(Context->ThreadId, 0x12, Result, 0))
        {
            Error = GetLastError();
            LogItem(NULL, L"SETUP: PostThreadMessage(WM_QUIT) failed. Error = %d", Error);
        }
    }
  #endif

    DPRINT("pInstallPnpDevicesThread: exit Result %X\n", Result);
    return Result;
}

VOID
WINAPI
InstallPnpDevices(
    HWND hWndParent,
    HINF SetupInf,
    HWND hWndProgress,
    ULONG StartProgress,
    ULONG EndProgress)
{
    PNP_DEVICES_THREAD_CONTEXT Context;
  #ifndef __REACTOS__
    DWORD ThreadId;
    HANDLE Thread;
    MSG Msg;
  #endif

    DPRINT("InstallPnpDevices: %d - %d\n", StartProgress, EndProgress);

    Context.ThreadId = GetCurrentThreadId();
    Context.StartProgress = StartProgress;
    Context.EndProgress = EndProgress;
    Context.hWndProgress = hWndProgress;
    Context.hSetupInf = SetupInf;
    Context.hWndParent = hWndParent;

  #ifdef __REACTOS__

    Context.IsOwnThread = FALSE;
    pInstallPnpDevicesThread(&Context);
    DPRINT("InstallPnpDevices: exit\n");
    return;

  #else

    Context.IsOwnThread = TRUE;

    Thread = CreateThread(NULL, 0, pInstallPnpDevicesThread, &Context, 0, &ThreadId);
    if (!Thread)
    {
        Context.IsOwnThread = FALSE;
        pInstallPnpDevicesThread(&Context);
        return;
    }

    CloseHandle(Thread);
    do
    {
        GetMessageW(&Msg, NULL, 0, 0);

        if (Msg.message == 18)
            break;

        DispatchMessageW(&Msg);
    }
    while (Msg.message != 18);

  #endif
}

static
VOID
InstallReactOS(VOID)
{
    WCHAR szBuffer[MAX_PATH];
    HANDLE token;
    TOKEN_PRIVILEGES privs;
    HKEY hKey;
    HINF hShortcutsInf;
  #if 0
    HANDLE hHotkeyThread;
  #endif
    DWORD OldFlags;
    BOOL ret;

    DPRINT("InstallReactOS()\n");

    InitializeSetupLog(FALSE);

    LogItem(L"BEGIN_SECTION", L"Initialization");
    LogItem(NULL, L"Installing ReactOS");

    OldFlags = pSetupGetGlobalFlags();
    pSetupSetGlobalFlags(OldFlags | (0x02 | 0x10));

    CreateTempDir(L"TEMP");
    CreateTempDir(L"TMP");

    if (!InitializeProgramFilesDir())
    {
        FatalError("InitializeProgramFilesDir() failed");
        return;
    }

    if (!InitializeProfiles())
    {
        FatalError("InitializeProfiles() failed");
        return;
    }

    InitializeDefaultUserLocale();

    if (GetWindowsDirectoryW(szBuffer, ARRAYSIZE(szBuffer)))
    {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
        {
            RegSetValueExW(hKey, L"PathName", 0, REG_SZ, (LPBYTE)szBuffer, (wcslen(szBuffer) + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, L"SystemRoot", 0, REG_SZ, (LPBYTE)szBuffer, (wcslen(szBuffer) + 1) * sizeof(WCHAR));

            RegCloseKey(hKey);
        }

        PathAddBackslash(szBuffer);
        wcscat(szBuffer, L"system");
        CreateDirectory(szBuffer, NULL);
    }

    if (SaveDefaultUserHive() != ERROR_SUCCESS)
    {
        FatalError("SaveDefaultUserHive() failed");
        return;
    }

    if (!CopySystemProfile(0))
    {
        FatalError("CopySystemProfile() failed");
        return;
    }

  #if 0
    hHotkeyThread = CreateThread(NULL, 0, HotkeyThread, NULL, 0, NULL);
  #endif

    if (!CommonInstall())
    {
        DPRINT1("InstallReactOS: CommonInstall() failed \n");
        return;
    }

    /* ? For NT, InstallPnpDevices() called from the Wizard... ? */
    DPRINT("InstallReactOS: call InstallPnpDevices()\n");
    InstallPnpDevices(NULL, hSysSetupInf, NULL, 30, 100);
    DPRINT("InstallReactOS: InstallPnpDevices() end\n");

    if (MiniSetup)
    {
        /* Install the TCP/IP protocol driver */
        DPRINT1("InstallReactOS: call InstallNetworkComponent()\n");
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
    }

    LogItem(L"END_SECTION", L"Initialization");
    DPRINT1("InstallReactOS: call InstallWizard()\n");

    InstallWizard();

    DPRINT1("InstallReactOS: call InstallSecurity()\n");
    InstallSecurity();

    DPRINT1("InstallReactOS: call SetAutoAdminLogon()\n");
    SetAutoAdminLogon();

    hShortcutsInf = SetupOpenInfFileW(L"shortcuts.inf", NULL, INF_STYLE_WIN4, NULL);
    if (hShortcutsInf == INVALID_HANDLE_VALUE)
    {
        FatalError("Failed to open shortcuts.inf");
        return;
    }

    if (!CreateShortcuts(hShortcutsInf, L"ShortcutFolders"))
    {
        FatalError("CreateShortcuts() failed");
        return;
    }

    SetupCloseInfFile(hShortcutsInf);

    hShortcutsInf = SetupOpenInfFileW(L"rosapps_shortcuts.inf", NULL, INF_STYLE_WIN4, NULL);
    if (hShortcutsInf != INVALID_HANDLE_VALUE)
    {
        if (!CreateShortcuts(hShortcutsInf, L"ShortcutFolders"))
        {
            FatalError("CreateShortcuts(rosapps) failed");
            return;
        }
        SetupCloseInfFile(hShortcutsInf);
    }

    SetupCloseInfFile(hSysSetupInf);
    SetSetupType(0);

  #if 0
    if (hHotkeyThread)
    {
        PostThreadMessage(GetThreadId(hHotkeyThread), WM_QUIT, 0, 0);
        CloseHandle(hHotkeyThread);
    }
  #endif

    LogItem(NULL, L"Installing ReactOS done");
    TerminateSetupLog();

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
        return;
    }

    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privs.Privileges[0].Luid))
    {
        FatalError("LookupPrivilegeValue() failed!");
        return;
    }

    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(token, FALSE, &privs, 0, (PTOKEN_PRIVILEGES)NULL, NULL) == 0)
    {
        FatalError("AdjustTokenPrivileges() failed!");
        return;
    }

    ExitWindowsEx(EWX_REBOOT, 0);
    return;
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
