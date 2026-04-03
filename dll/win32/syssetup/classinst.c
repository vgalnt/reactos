/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll/win32/syssetup/classinst.c
 * PURPOSE:     Class installers
 * PROGRAMMERS: Copyright 2006 Hervé Poussineau (hpoussin@reactos.org)
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

/*
 * @unimplemented
 */
DWORD
WINAPI
ComputerClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT1("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}

PWCHAR
WINAPI
ReplaceSlashWithHash(
    PWCHAR DeviceId)
{
    PWCHAR Ptr;

    for (Ptr = DeviceId; *Ptr; Ptr++)
    {
        if (*Ptr == '\\')
            *Ptr = '#';
    }

    return Ptr;
}

HKEY
WINAPI
OpenCDDRegistryKey(
    PWCHAR DeviceId,
    BOOL IsCreate)
{
    WCHAR DeviceIdBuffer[200];
    HKEY hDatabaseKey;
    HKEY hDeviceKey;
    DWORD dwError;

    DPRINT("OpenCDDRegistryKey: IsCreate %X ('%ls')\n", IsCreate, DeviceId);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                        L"System\\CurrentControlSet\\Control\\CriticalDeviceDatabase",
                        0,
                        NULL,
                        REG_OPTION_NON_VOLATILE,
                        (KEY_READ | KEY_WRITE),
                        NULL,
                        &hDatabaseKey,
                        NULL))
    {
        DPRINT1("OpenCDDRegistryKey: INVALID_HANDLE_VALUE\n");
        return INVALID_HANDLE_VALUE;
    }

    lstrcpyW(DeviceIdBuffer, DeviceId);
    ReplaceSlashWithHash(DeviceIdBuffer);

    if (IsCreate)
    {
        dwError = RegCreateKeyExW(hDatabaseKey,
                                  DeviceIdBuffer,
                                  0,
                                  NULL,
                                  REG_OPTION_NON_VOLATILE,
                                  (KEY_READ | KEY_WRITE),
                                  NULL,
                                  &hDeviceKey,
                                  NULL);

        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("OpenCDDRegistryKey: dwError %X ('%ls')\n", dwError, DeviceId);
        }
    }
    else
    {
        dwError = RegOpenKeyExW(hDatabaseKey,
                                DeviceIdBuffer,
                                0,
                                (KEY_READ | KEY_WRITE),
                                &hDeviceKey);

        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("OpenCDDRegistryKey: dwError %X ('%ls')\n", dwError, DeviceId);
        }
    }

    if (dwError != ERROR_SUCCESS)
        hDeviceKey = INVALID_HANDLE_VALUE;

    RegCloseKey(hDatabaseKey);

    return hDeviceKey;
}

typedef struct
{
    WCHAR DeviceId[200];
    WCHAR ServiceName[256];
} PRIVATE_BUFFER, *PPRIVATE_BUFFER;

/*
 * @implemented
 */
DWORD
WINAPI
CriticalDeviceCoInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL,
    IN OUT PCOINSTALLER_CONTEXT_DATA Context)
{
    PPRIVATE_BUFFER ServiceString;
    PPRIVATE_BUFFER PrivateData;
    WCHAR szDeviceId[200];
    WCHAR szServiceName[256];
    WCHAR szClassGUID[39];
    DWORD dwRequiredSize;
    HKEY hDriverKey = NULL;
    HKEY hDeviceKey = NULL;
    LPWSTR LowerFilters;
    LPWSTR UpperFilters;
    DWORD RequiredSize;
    DWORD UpperFiltersSize;
    DWORD LowerFiltersSize;
    DWORD ClassGuidResult;
    DWORD ServiceNameSize;
    DWORD ClassGuidSize;
    DWORD dwError;
    DWORD cbData;
    DWORD Size;
    BOOL IsUpperFilters;
    BOOL ServiceResult;
    BOOL IsCddKey;

    DPRINT1("CriticalDeviceCoInstaller(%lu %p %p %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData, Context);

    if (InstallFunction != DIF_INSTALLDEVICE)
    {
        ASSERT(!Context->PostProcessing);
        return ERROR_SUCCESS;
    }

    if (!Context->PostProcessing)
    {
        /* Get the MatchingDeviceId property */
        hDriverKey = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
        if (hDriverKey == INVALID_HANDLE_VALUE)
        {
            DPRINT("CriticalDeviceCoInstaller: Failed to open the driver key! Postprocessing required!\n");
            return ERROR_DI_POSTPROCESSING_REQUIRED;
        }

        dwRequiredSize = sizeof(szDeviceId);
        dwError = RegQueryValueExW(hDriverKey, L"MatchingDeviceId", NULL, NULL, (PBYTE)szDeviceId, &dwRequiredSize);
        RegCloseKey(hDriverKey);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("CriticalDeviceCoInstaller: Failed to read the MatchingDeviceId value! Postprocessing required!\n");
            return ERROR_DI_POSTPROCESSING_REQUIRED;
        }

        DPRINT1("CriticalDeviceCoInstaller: MatchingDeviceId: %S\n", szDeviceId);

        hDeviceKey = OpenCDDRegistryKey(szDeviceId, FALSE);
        if (hDeviceKey == INVALID_HANDLE_VALUE)
        {
            DPRINT("CriticalDeviceCoInstaller: OpenCDDRegistryKey() ret INVALID_HANDLE_VALUE\n");
            return ERROR_DI_POSTPROCESSING_REQUIRED;
        }

        PrivateData = pSetupMalloc(sizeof(*PrivateData));
        if (!PrivateData)
        {
            RegCloseKey(hDeviceKey);
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        lstrcpyW(PrivateData->DeviceId, szDeviceId);

        RequiredSize = sizeof(PrivateData->ServiceName);

        if (RegQueryValueExW(hDeviceKey, L"Service", NULL, NULL, (LPBYTE)PrivateData->ServiceName, &RequiredSize))
            PrivateData->ServiceName[0] = 0;
        else
            RegDeleteValueW(hDeviceKey, L"Service");

        RegCloseKey(hDeviceKey);

        Context->PrivateData = PrivateData;

        return ERROR_DI_POSTPROCESSING_REQUIRED;
    }

    IsCddKey = FALSE;
    LowerFilters = NULL;
    szDeviceId[0] = 0;

    ServiceString = Context->PrivateData;

    if (Context->InstallResult != ERROR_SUCCESS)
    {
        goto Finish;
    }

    ServiceResult = SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                                      DeviceInfoData,
                                                      SPDRP_SERVICE,
                                                      NULL,
                                                      (PBYTE)szServiceName,
                                                      0x200,
                                                      &RequiredSize);
    if (ServiceResult)
    {
        Size = wcslen(L"\\Driver");
        ServiceNameSize = wcslen(szServiceName);

        if ((ServiceNameSize >= Size) && _wcsnicmp(szServiceName, L"\\Driver", Size))
        {
            goto Finish;
        }
    }

    LowerFilters = NULL;
    UpperFilters = NULL;

    ClassGuidResult = SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                                        DeviceInfoData,
                                                        SPDRP_CLASSGUID,
                                                        NULL,
                                                        (PBYTE)szClassGUID,
                                                        78,
                                                        &ClassGuidSize);
    if (ClassGuidResult)
    {
        DPRINT("CriticalDeviceCoInstaller: szClassGUID '%S'\n", szClassGUID);
    }

    if (!SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                           DeviceInfoData,
                                           SPDRP_LOWERFILTERS,
                                           NULL,
                                           NULL,
                                           0,
                                           &LowerFiltersSize))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && LowerFiltersSize > 2)
        {
            Size = 1;

            LowerFilters = pSetupMalloc(LowerFiltersSize);
            if (!LowerFilters)
            {
                DPRINT1("CriticalDeviceCoInstaller: pSetupMalloc() is failed\n");
                goto Finish;
            }

            if (!SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                                   DeviceInfoData,
                                                   SPDRP_LOWERFILTERS,
                                                   NULL,
                                                   (PBYTE)LowerFilters,
                                                   LowerFiltersSize,
                                                   NULL))
            {
                goto done;
            }

            DPRINT("CriticalDeviceCoInstaller: LowerFilters '%S'\n", LowerFilters);
        }
    }
    else
    {
        Size = 0;
    }

    if (!SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                           DeviceInfoData,
                                           SPDRP_UPPERFILTERS,
                                           NULL,
                                           NULL,
                                           0,
                                           &UpperFiltersSize))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && UpperFiltersSize > 2)
        {
            IsUpperFilters = TRUE;

            UpperFilters = pSetupMalloc(UpperFiltersSize);
            if (!UpperFilters)
            {
                goto done;
            }

            if (!SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                                   DeviceInfoData,
                                                   SPDRP_UPPERFILTERS,
                                                   NULL,
                                                   (PBYTE)UpperFilters,
                                                   UpperFiltersSize,
                                                   NULL))
            {
                goto done;
            }

            DPRINT("CriticalDeviceCoInstaller: UpperFilters '%S'\n", UpperFilters);
        }
    }
    else
    {
        IsUpperFilters = FALSE;
    }

    hDriverKey = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (hDriverKey == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CriticalDeviceCoInstaller: INVALID_HANDLE_VALUE\n");
        goto done;
    }

    cbData = sizeof(szDeviceId);
    dwError = RegQueryValueExW(hDriverKey, L"MatchingDeviceId", NULL, NULL, (LPBYTE)szDeviceId, &cbData);
    RegCloseKey(hDriverKey);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("CriticalDeviceCoInstaller: dwError %X\n", dwError);
        szDeviceId[0] = 0;
        goto done;
    }
    DPRINT("CriticalDeviceCoInstaller: szDeviceId '%S'\n", szDeviceId);

    hDeviceKey = OpenCDDRegistryKey(szDeviceId, TRUE);
    if (hDeviceKey == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CriticalDeviceCoInstaller: INVALID_HANDLE_VALUE\n");
        goto done;
    }

    if (ServiceResult)
        RegSetValueExW(hDeviceKey, L"Service", 0, REG_SZ, (PBYTE)szServiceName, RequiredSize);
    else
        RegDeleteValueW(hDeviceKey, L"Service");

    if (ClassGuidResult)
        RegSetValueExW(hDeviceKey, L"ClassGUID", 0, REG_SZ, (PBYTE)szClassGUID, ClassGuidSize);
    else
        RegDeleteValueW(hDeviceKey, L"ClassGUID");

    if (Size)
        RegSetValueExW(hDeviceKey, L"LowerFilters", 0, REG_MULTI_SZ, (PBYTE)LowerFilters, LowerFiltersSize);
    else
        RegDeleteValueW(hDeviceKey, L"LowerFilters");

    if (IsUpperFilters)
        RegSetValueExW(hDeviceKey, L"UpperFilters", 0, REG_MULTI_SZ, (PBYTE)UpperFilters, UpperFiltersSize);
    else
        RegDeleteValueW(hDeviceKey, L"UpperFilters");

    RegCloseKey(hDeviceKey);

    IsCddKey = TRUE;

done:

    if (LowerFilters)
        pSetupFree(LowerFilters);

    if (UpperFilters)
        pSetupFree(UpperFilters);

Finish:

    if (!ServiceString)
        return Context->InstallResult;

    if (!lstrcmpiW(szDeviceId, ServiceString->DeviceId) && IsCddKey)
        goto Exit;

    hDeviceKey = OpenCDDRegistryKey(ServiceString->DeviceId, FALSE);
    if (hDeviceKey == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CriticalDeviceCoInstaller: INVALID_HANDLE_VALUE\n");
        goto Exit;
    }

    if (ServiceString->ServiceName[0])
    {
        RegSetValueExW(hDeviceKey,
                       L"Service",
                       0,
                       REG_SZ,
                       (PBYTE)ServiceString->ServiceName,
                       ((lstrlenW(ServiceString->ServiceName) + 1) * sizeof(WCHAR)));
    }
    else
    {
        RegDeleteValueW(hDeviceKey, L"Service");
    }

    RegCloseKey(hDeviceKey);

Exit:

    pSetupFree(ServiceString);

    return Context->InstallResult;
}

/*
 * @unimplemented
 */
DWORD
WINAPI
DeviceBayClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}


/*
 * @unimplemented
 */
DWORD
WINAPI
EisaUpHalCoInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL,
    IN OUT PCOINSTALLER_CONTEXT_DATA Context)
{
    switch (InstallFunction)
    {
        default:
            DPRINT1("Install function %u ignored\n", InstallFunction);
            return ERROR_SUCCESS;
    }
}


/*
 * @implemented
 */
DWORD
WINAPI
HdcClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    DPRINT("HdcClassInstaller()\n");
    return ERROR_DI_DO_DEFAULT;
}


/*
 * @unimplemented
 */
DWORD
WINAPI
KeyboardClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}


/*
 * @unimplemented
 */
DWORD
WINAPI
MouseClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}


/*
 * @unimplemented
 */
DWORD
WINAPI
NtApmClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}


/*
 * @unimplemented
 */
DWORD
WINAPI
ScsiClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    switch (InstallFunction)
    {
        default:
            DPRINT("Install function %u ignored\n", InstallFunction);
            return ERROR_DI_DO_DEFAULT;
    }
}


/*
 * @unimplemented
 */
DWORD
WINAPI
StorageCoInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL,
    IN OUT PCOINSTALLER_CONTEXT_DATA Context)
{
    DPRINT1("StorageCoInstaller: InstallFunction %u\n", InstallFunction);

    switch (InstallFunction)
    {
        case DIF_INSTALLDEVICE:
        {
            if (Context->PostProcessing)
            {
                DPRINT1("StorageCoInstaller: PostProcessing %X\n", Context->PostProcessing);
                UNIMPLEMENTED;
                return Context->InstallResult;
            }

            if (!DeviceInfoData)
            {
                DPRINT1("StorageCoInstaller: DeviceInfoData is NULL\n", InstallFunction);
                return ERROR_SUCCESS;
            }

            UNIMPLEMENTED;
            //return ERROR_DI_POSTPROCESSING_REQUIRED;
            return ERROR_SUCCESS;
        }
        default:
        {
            DPRINT1("StorageCoInstaller: Install function %u ignored\n", InstallFunction);
            ASSERT(!Context->PostProcessing);
            return ERROR_SUCCESS;
        }
    }
}


/*
 * @implemented
 */
DWORD
WINAPI
TapeClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    DPRINT("TapeClassInstaller()\n");
    return ERROR_DI_DO_DEFAULT;
}


/*
 * @implemented
 */
DWORD
WINAPI
VolumeClassInstaller(
    IN DI_FUNCTION InstallFunction,
    IN HDEVINFO DeviceInfoSet,
    IN PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    DPRINT("VolumeClassInstaller()\n");
    return ERROR_DI_DO_DEFAULT;
}

/* EOF */
