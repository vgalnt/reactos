/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dlls\win32\msports\classinst.c
 * PURPOSE:     Ports class installer
 * PROGRAMMERS: Copyright 2011 Eric Kohl
 */

#include "precomp.h"

#include <wchar.h>

#define NTOS_MODE_USER
#include <ndk/cmtypes.h>

typedef enum _PORT_TYPE
{
    ParallelPort,
    SerialPort,
    OtherPort
} PORT_TYPE;

LPWSTR pszCom = L"COM";
LPWSTR pszLpt = L"LPT";

DWORD PollingPeriods[7] = { 0xFFFFFFFF, 0, 10, 50, 100, 300, 600 };

DWORD 
WINAPI
myatoi(_In_ PWCHAR String)
{
    PWCHAR Ptr;
    DWORD Result = 0;
    WCHAR Number;

    for (Ptr = String; *Ptr; Ptr++)
    {
        Number = (*Ptr - L'0');
        if (Number > 9)
            break;

        Result = (Number + (Result * 10));
    }

    return Result;
}

/* It is HACK!
   DetermineComNumberFromResources() from NT5.x
   use CM_Get_First_Log_Conf(), CM_Get_Next_Res_Des(), CM_Get_Res_Des_Data() instead.
*/
#ifdef __REACTOS__
BOOL
WINAPI
GetBootResourceList(HDEVINFO DeviceInfoSet,
                    PSP_DEVINFO_DATA DeviceInfoData,
                    PCM_RESOURCE_LIST *ppResourceList)
{
    WCHAR DeviceInstanceIdBuffer[128];
    HKEY hEnumKey = NULL;
    HKEY hDeviceKey = NULL;
    HKEY hConfigKey = NULL;
    LPBYTE lpBuffer = NULL;
    DWORD dwDataSize;
    LONG lError;
    BOOL ret = FALSE;

    FIXME("GetBootResourceList()\n");

    *ppResourceList = NULL;

    if (!SetupDiGetDeviceInstanceIdW(DeviceInfoSet,
                                     DeviceInfoData,
                                     DeviceInstanceIdBuffer,
                                     ARRAYSIZE(DeviceInstanceIdBuffer),
                                     &dwDataSize))
    {
        ERR("SetupDiGetDeviceInstanceIdW() failed\n");
        return FALSE;
    }

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Enum",
                           0,
                           KEY_QUERY_VALUE,
                           &hEnumKey);
    if (lError != ERROR_SUCCESS)
    {
        ERR("RegOpenKeyExW() failed (Error %lu)\n", lError);
        goto done;
    }

    lError = RegOpenKeyExW(hEnumKey,
                           DeviceInstanceIdBuffer,
                           0,
                           KEY_QUERY_VALUE,
                           &hDeviceKey);
    if (lError != ERROR_SUCCESS)
    {
        ERR("RegOpenKeyExW() failed (Error %lu)\n", lError);
        goto done;
    }

    lError = RegOpenKeyExW(hDeviceKey,
                           L"LogConf",
                           0,
                           KEY_QUERY_VALUE,
                           &hConfigKey);
    if (lError != ERROR_SUCCESS)
    {
        ERR("RegOpenKeyExW() failed (Error %lu)\n", lError);
        goto done;
    }

    /* Get the configuration data size */
    lError = RegQueryValueExW(hConfigKey,
                              L"BootConfig",
                              NULL,
                              NULL,
                              NULL,
                              &dwDataSize);
    if (lError != ERROR_SUCCESS)
    {
        ERR("RegQueryValueExW() failed (Error %lu)\n", lError);
        goto done;
    }

    /* Allocate the buffer */
    lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwDataSize);
    if (lpBuffer == NULL)
    {
        ERR("Failed to allocate the resource list buffer\n");
        goto done;
    }

    /* Retrieve the configuration data */
    lError = RegQueryValueExW(hConfigKey,
                              L"BootConfig",
                              NULL,
                              NULL,
                             (LPBYTE)lpBuffer,
                              &dwDataSize);
    if (lError == ERROR_SUCCESS)
    {
        ERR("RegQueryValueExW() failed (Error %lu)\n", lError);
        ret = TRUE;
    }

done:
    if (ret == FALSE && lpBuffer != NULL)
        HeapFree(GetProcessHeap(), 0, lpBuffer);

    if (hConfigKey)
        RegCloseKey(hConfigKey);

    if (hDeviceKey)
        RegCloseKey(hDeviceKey);

    if (hEnumKey)
        RegCloseKey(hEnumKey);

    if (ret != FALSE)
        *ppResourceList = (PCM_RESOURCE_LIST)lpBuffer;

    return ret;
}

DWORD
WINAPI
GetSerialPortNumber(IN HDEVINFO DeviceInfoSet,
                    IN PSP_DEVINFO_DATA DeviceInfoData)
{
    PCM_RESOURCE_LIST lpResourceList = NULL;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR lpResDes;
    ULONG i;
    DWORD dwBaseAddress = 0;
    DWORD dwPortNumber = 0;

    TRACE("GetSerialPortNumber(%p, %p)\n",
          DeviceInfoSet, DeviceInfoData);

    if (GetBootResourceList(DeviceInfoSet,
                            DeviceInfoData,
                            &lpResourceList))
    {
        TRACE("Full resource descriptors: %ul\n", lpResourceList->Count);
        if (lpResourceList->Count > 0)
        {
            TRACE("Partial resource descriptors: %ul\n", lpResourceList->List[0].PartialResourceList.Count);

            for (i = 0; i < lpResourceList->List[0].PartialResourceList.Count; i++)
            {
                lpResDes = &lpResourceList->List[0].PartialResourceList.PartialDescriptors[i];
                TRACE("Type: %u\n", lpResDes->Type);

                switch (lpResDes->Type)
                {
                    case CmResourceTypePort:
                        TRACE("Port: Start: %I64x  Length: %lu\n",
                              lpResDes->u.Port.Start.QuadPart,
                              lpResDes->u.Port.Length);
                        if ((lpResDes->u.Port.Start.HighPart == 0) && (dwBaseAddress == 0))
                            dwBaseAddress = (DWORD)lpResDes->u.Port.Start.LowPart;
                        break;

                    case CmResourceTypeInterrupt:
                        TRACE("Interrupt: Level: %lu  Vector: %lu\n",
                              lpResDes->u.Interrupt.Level,
                              lpResDes->u.Interrupt.Vector);
                        break;
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, lpResourceList);
    }

    switch (dwBaseAddress)
    {
        case 0x3f8:
            dwPortNumber = 1;
            break;

        case 0x2f8:
            dwPortNumber = 2;
            break;

        case 0x3e8:
            dwPortNumber = 3;
            break;

        case 0x2e8:
            dwPortNumber = 4;
            break;
    }

    return dwPortNumber;
}
#else
  #error FIXME DetermineComNumberFromResources()
#endif

DWORD
WINAPI
InstallPnPSerialPort(_In_ HDEVINFO DeviceInfoSet,
                     _In_ PSP_DEVINFO_DATA DeviceInfoData)
{
    HCOMDB ComDB = HCOMDB_INVALID_HANDLE_VALUE;
    WCHAR DeviceDescription[256];
    WCHAR ReturnedString[260];
    WCHAR PropertyBuffer[260];
    WCHAR FriendlyName[256];
    WCHAR NameBuffer[40];
    WCHAR PortName[40];
    PWCHAR PortPtr;
    HKEY Key;
    DWORD FirmwareId;
    DWORD FirmwareIdSize;
    DWORD MaxPortsReported;
    DWORD PortNumber = 0;
    DWORD PollingPeriod;
    DWORD Size;
    CONFIGRET Cr;
    ULONG Status;
    ULONG Problem;
    LONG Error;
    BYTE PortUsage[32];
    BOOL IsFound = FALSE;
    BOOL Result;

    TRACE("InstallPnPSerialPort: %p, %p\n", DeviceInfoSet, DeviceInfoData);

    ZeroMemory(NameBuffer, sizeof(NameBuffer));

    /* Open the com port database */
    ComDBOpen(&ComDB);

    /* Try to read the value from REG and determine the port number */
    Key = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
    if (Key != INVALID_HANDLE_VALUE)
    {
        Size = sizeof(NameBuffer);
        Error = RegQueryValueExW(Key, L"PortName", NULL, NULL, (LPBYTE)NameBuffer, &Size);

        if (Error == NO_ERROR)
        {
           ERR("InstallPnPSerialPort: COM port found '%S'\n", NameBuffer);
           IsFound = TRUE;
        }
        else
        {
            Size = sizeof(NameBuffer);
            Error = RegQueryValueExW(Key, L"DosDeviceName", NULL, NULL, (LPBYTE)NameBuffer, &Size);

            if (Error == NO_ERROR)
            {
                ERR("InstallPnPSerialPort: COM port found '%S'\n", NameBuffer);
                IsFound = TRUE;
            }
            else
            {
                Result = SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                                           DeviceInfoData,
                                                           SPDRP_ENUMERATOR_NAME,
                                                           NULL,
                                                           (LPBYTE)PropertyBuffer,
                                                           sizeof(PropertyBuffer),
                                                           NULL);
                if (Result)
                {
                    if (!lstrcmpiW(PropertyBuffer, L"ACPI"))
                    {
                        ERR("InstallPnPSerialPort: COM port found '%S'\n", PropertyBuffer);
                        IsFound = TRUE;
                    }
                    else if (!lstrcmpiW(PropertyBuffer, L"Root"))
                    {
                        Cr = CM_Get_DevNode_Status(&Status, &Problem, DeviceInfoData->DevInst, 0);
                        if (Cr == CR_SUCCESS)
                        {
                            if (!(Status & DN_ROOT_ENUMERATED))
                            {
                                ERR("InstallPnPSerialPort: COM port found '%S'\n", PropertyBuffer);
                                IsFound = TRUE;
                            }
                        }
                    }
                }

                if (!IsFound)
                {
                    FirmwareIdSize = sizeof(FirmwareId);

                    Error = RegQueryValueExW(Key, L"FirmwareIdentified", NULL, NULL, (LPBYTE)&FirmwareId, &FirmwareIdSize);
                    if (Error == NO_ERROR)
                    {
                        ERR("InstallPnPSerialPort: FirmwareId found %lu\n", FirmwareId);
                        IsFound = TRUE;
                    }
                }
            }
        }

        RegCloseKey(Key);

        if (IsFound)
        {
            if (NameBuffer[0])
            {
                _wcsupr(NameBuffer);

                PortPtr = wcsstr(NameBuffer, pszCom);
                if (PortPtr)
                    PortNumber = myatoi(&PortPtr[wcslen(pszCom)]);
            }

            if (PortNumber == 0)
            {
              /* Determine the port number from its resources ... */
              #ifdef __REACTOS__
                PortNumber = GetSerialPortNumber(DeviceInfoSet, DeviceInfoData);
                ERR("InstallPnPSerialPort: PortNumber %lu\n", PortNumber);
                if (PortNumber == 0 && ComDB != HCOMDB_INVALID_HANDLE_VALUE)
                {
                    Error = ComDBGetCurrentPortUsage(ComDB, PortUsage, 32, 0, &MaxPortsReported);
                    if (Error == NO_ERROR)
                    {
                        if (!(PortUsage[0] & 0x1))
                            PortNumber = 1;
                        else if (!(PortUsage[0] & 0x2))
                            PortNumber = 2;
                        else if (!(PortUsage[0] & 0x4))
                            PortNumber = 3;
                        else if (!(PortUsage[0] & 0x8))
                            PortNumber = 4;
                        else
                            PortNumber = 0;
                    }
                }
              #else
                #error FIXME!
                #if 0
                Result = DetermineComNumberFromResources(DeviceInfoData->DevInst, &PortNumber);
                if (!Result && ComDB != HCOMDB_INVALID_HANDLE_VALUE)
                {
                    Error = ComDBGetCurrentPortUsage(ComDB, PortUsage, 32, 0, &MaxPortsReported);
                    if (Error == NO_ERROR)
                    {
                        if (!(PortUsage[0] & 0x1))
                            PortNumber = 1;
                        else if (!(PortUsage[0] & 0x2))
                            PortNumber = 2;
                        else if (!(PortUsage[0] & 0x4))
                            PortNumber = 3;
                        else if (!(PortUsage[0] & 0x8))
                            PortNumber = 4;
                        else
                            PortNumber = 0;
                    }
                }
                #endif
              #endif
            }
        }
    }

    if (PortNumber)
        /* Claim the port number in the database */
        ComDBClaimPort(ComDB, PortNumber, TRUE, NULL);
    else if (ComDB != HCOMDB_INVALID_HANDLE_VALUE)
        /* Claim the next free port number */
        ComDBClaimNextFreePort(ComDB, &PortNumber);
    else
        PortNumber = 5;

    /* Close the com port database */
    if (ComDB != HCOMDB_INVALID_HANDLE_VALUE)
        ComDBClose(ComDB);

    /* Build the name of the port device */
    wsprintf(PortName, L"%s%d", pszCom, PortNumber);

    /* Set the 'PortName' value */
    Key = SetupDiCreateDevRegKeyW(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, NULL, NULL);
    if (Key != INVALID_HANDLE_VALUE)
    {
        PollingPeriod = PollingPeriods[1];

        RegSetValueExW(Key, L"PortName", 0, REG_SZ, (LPBYTE)PortName, ((lstrlenW(PortName) + 1) * sizeof(WCHAR)));
        RegSetValueExW(Key, L"PollingPeriod", 0, REG_DWORD, (LPBYTE)&PollingPeriod, sizeof(DWORD));

        RegCloseKey(Key);
    }

    /* Install the device */
    if (!SetupDiInstallDevice(DeviceInfoSet, DeviceInfoData))
    {
        ERR("InstallPnPSerialPort: Device installation failed (%lu)\n", GetLastError());
        return GetLastError();
    }

    /* Get the device description... */
    Result = SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                               DeviceInfoData,
                                               SPDRP_DEVICEDESC,
                                               NULL,
                                               (LPBYTE)DeviceDescription,
                                               sizeof(DeviceDescription),
                                               NULL);
    if (Result)
        /* ... and use it to build a new friendly name */
        wsprintfW(FriendlyName, L"%s (%s)", DeviceDescription, PortName);
    else
        /* ... or build a generic friendly name */
        lstrcpyW(FriendlyName, PortName);

    /* Set the friendly name for the device */
    SetupDiSetDeviceRegistryPropertyW(DeviceInfoSet,
                                      DeviceInfoData,
                                      SPDRP_FRIENDLYNAME,
                                      (LPBYTE)FriendlyName,
                                      (lstrlenW(FriendlyName) + 1) * sizeof(WCHAR));

    wcscat(PortName, L":");
    ReturnedString[0] = 0;

    Size = (sizeof(ReturnedString) / sizeof(WCHAR));
    GetProfileString(L"Ports", PortName, L"", ReturnedString, Size);

    if (ReturnedString[0] == 0)
        WriteProfileString(L"Ports", PortName, L"9600,n,8,1");

    return NO_ERROR;
}

// FIXME! Not changed code. Need test it.
#ifdef __REACTOS__
DWORD
WINAPI
GetParallelPortNumber(IN HDEVINFO DeviceInfoSet,
                      IN PSP_DEVINFO_DATA DeviceInfoData)
{
    PCM_RESOURCE_LIST lpResourceList = NULL;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR lpResDes;
    ULONG i;
    DWORD dwBaseAddress = 0;
    DWORD dwPortNumber = 0;

    TRACE("GetParallelPortNumber(%p, %p)\n",
          DeviceInfoSet, DeviceInfoData);

    if (GetBootResourceList(DeviceInfoSet,
                            DeviceInfoData,
                            &lpResourceList))
    {
        TRACE("Full resource descriptors: %ul\n", lpResourceList->Count);
        if (lpResourceList->Count > 0)
        {
            TRACE("Partial resource descriptors: %ul\n", lpResourceList->List[0].PartialResourceList.Count);

            for (i = 0; i < lpResourceList->List[0].PartialResourceList.Count; i++)
            {
                lpResDes = &lpResourceList->List[0].PartialResourceList.PartialDescriptors[i];
                TRACE("Type: %u\n", lpResDes->Type);

                switch (lpResDes->Type)
                {
                    case CmResourceTypePort:
                        TRACE("Port: Start: %I64x  Length: %lu\n",
                              lpResDes->u.Port.Start.QuadPart,
                              lpResDes->u.Port.Length);
                        if ((lpResDes->u.Port.Start.HighPart == 0) && (dwBaseAddress == 0))
                            dwBaseAddress = (DWORD)lpResDes->u.Port.Start.LowPart;
                        break;

                    case CmResourceTypeInterrupt:
                        TRACE("Interrupt: Level: %lu  Vector: %lu\n",
                              lpResDes->u.Interrupt.Level,
                              lpResDes->u.Interrupt.Vector);
                        break;
                }

            }

        }

        HeapFree(GetProcessHeap(), 0, lpResourceList);
    }

    switch (dwBaseAddress)
    {
        case 0x378:
            dwPortNumber = 1;
            break;

        case 0x278:
            dwPortNumber = 2;
            break;
    }

    return dwPortNumber;
}

DWORD
WINAPI
InstallPnPParallelPort(IN HDEVINFO DeviceInfoSet,
                       IN PSP_DEVINFO_DATA DeviceInfoData)
{
    WCHAR szDeviceDescription[256];
    WCHAR szFriendlyName[256];
    WCHAR szPortName[8];
    DWORD dwPortNumber = 0;
    DWORD dwSize;
    DWORD dwValue;
    LONG lError;
    HKEY hKey;

    TRACE("InstallParallelPort(%p, %p)\n",
          DeviceInfoSet, DeviceInfoData);

    /* Try to read the 'PortName' value and determine the port number */
    hKey = SetupDiCreateDevRegKeyW(DeviceInfoSet,
                                   DeviceInfoData,
                                   DICS_FLAG_GLOBAL,
                                   0,
                                   DIREG_DEV,
                                   NULL,
                                   NULL);
    if (hKey != INVALID_HANDLE_VALUE)
    {
        dwSize = sizeof(szPortName);
        lError = RegQueryValueEx(hKey,
                                 L"PortName",
                                 NULL,
                                 NULL,
                                 (PBYTE)szPortName,
                                 &dwSize);
        if (lError  == ERROR_SUCCESS)
        {
            if (_wcsnicmp(szPortName, pszLpt, wcslen(pszLpt)) == 0)
            {
                dwPortNumber = _wtoi(szPortName + wcslen(pszLpt));
                TRACE("LPT port number found: %lu\n", dwPortNumber);
            }
        }

        RegCloseKey(hKey);
    }

    /* ... try to determine the port number from its resources */
    if (dwPortNumber == 0)
    {
        dwPortNumber = GetParallelPortNumber(DeviceInfoSet,
                                             DeviceInfoData);
        TRACE("GetParallelPortNumber() returned port number: %lu\n", dwPortNumber);
    }

    if (dwPortNumber == 0)
    {
        /* FIXME */
        FIXME("Got no valid port numer!\n");
    }

    if (dwPortNumber != 0)
    {
        swprintf(szPortName, L"%s%u", pszLpt, dwPortNumber);
    }
    else
    {
        wcscpy(szPortName, L"LPTx");
    }

    if (dwPortNumber != 0)
    {
        /* Set the 'PortName' value */
        hKey = SetupDiCreateDevRegKeyW(DeviceInfoSet,
                                       DeviceInfoData,
                                       DICS_FLAG_GLOBAL,
                                       0,
                                       DIREG_DEV,
                                       NULL,
                                       NULL);
        if (hKey != INVALID_HANDLE_VALUE)
        {
            RegSetValueExW(hKey,
                           L"PortName",
                           0,
                           REG_SZ,
                           (LPBYTE)szPortName,
                           (wcslen(szPortName) + 1) * sizeof(WCHAR));

            /*
             * FIXME / HACK:
             * This is to get the w2k3 parport.sys to work until we have our own.
             * This setting makes the driver accept resources with an IRQ instead
             * of only resources without an IRQ.
             *
             * We should probably also fix IO manager to actually give devices a
             * chance to register without an IRQ. CORE-9645
             */
            dwValue = 0;
            RegSetValueExW(hKey,
                           L"FilterResourceMethod",
                           0,
                           REG_DWORD,
                           (LPBYTE)&dwValue, 
                           sizeof(dwValue));

            RegCloseKey(hKey);
        }
    }

    /* Install the device */
    if (!SetupDiInstallDevice(DeviceInfoSet,
                              DeviceInfoData))
    {
        return GetLastError();
    }

    /* Get the device description... */
    if (SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet,
                                          DeviceInfoData,
                                          SPDRP_DEVICEDESC,
                                          NULL,
                                          (LPBYTE)szDeviceDescription,
                                          256 * sizeof(WCHAR),
                                          NULL))
    {
        /* ... and use it to build a new friendly name */
        swprintf(szFriendlyName,
                 L"%s (%s)",
                 szDeviceDescription,
                 szPortName);
    }
    else
    {
        /* ... or build a generic friendly name */
        swprintf(szFriendlyName,
                 L"Parallel Port (%s)",
                 szPortName);
    }

    TRACE("Friendly name: %S\n", szFriendlyName);

    /* Set the friendly name for the device */
    SetupDiSetDeviceRegistryPropertyW(DeviceInfoSet,
                                      DeviceInfoData,
                                      SPDRP_FRIENDLYNAME,
                                      (LPBYTE)szFriendlyName,
                                      (wcslen(szFriendlyName) + 1) * sizeof(WCHAR));

    return ERROR_SUCCESS;
}
#else
  #error FIXME
#endif

DWORD
WINAPI
GetPortType(_In_ HDEVINFO DeviceInfoSet,
            _In_ PSP_DEVINFO_DATA DeviceInfoData,
            _In_ BOOLEAN IsInfInstall)
{
    HINF InfHandle = INVALID_HANDLE_VALUE;
    SP_DRVINFO_DETAIL_DATA_W DriverInfoDetailData;
    SP_DRVINFO_DATA_W DriverInfoData;
    PORT_TYPE PortType = SerialPort;
    WCHAR InfSectionWithExt[0x100];
    HKEY Key;
    DWORD Type;
    DWORD Size;
    BYTE PortSubClass = 0;
    BOOL Result;
    LONG Error;

    ERR("GetPortType: %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);

    Key = SetupDiCreateDevRegKeyW(DeviceInfoSet,
                                   DeviceInfoData,
                                   DICS_FLAG_GLOBAL,
                                   0,
                                   DIREG_DRV,
                                   NULL,
                                   NULL);
    if (!Key)
    {
        ERR("GetPortType: ret PortType\n");
        return PortType;
    }

    if (IsInfInstall)
    {
        DriverInfoData.cbSize = sizeof(DriverInfoData);

        Result = SetupDiGetSelectedDriverW(DeviceInfoSet, DeviceInfoData, &DriverInfoData);
        if (!Result)
        {
            ERR("GetPortType: exit %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);
            goto Exit;
        }

        DriverInfoDetailData.cbSize = sizeof(DriverInfoDetailData);

        Result = SetupDiGetDriverInfoDetailW(DeviceInfoSet,
                                             DeviceInfoData,
                                             &DriverInfoData,
                                             &DriverInfoDetailData,
                                             sizeof(DriverInfoDetailData),
                                             NULL);

        if (!Result && GetLastError() != 122)
        {
            ERR("GetPortType: exit with error %X (%p, %p, %X)\n", GetLastError(), DeviceInfoSet, DeviceInfoData, IsInfInstall);
            goto Exit;
        }

        TRACE("GetPortType: Inf '%S'\n", DriverInfoDetailData.InfFileName);

        InfHandle = SetupOpenInfFileW(DriverInfoDetailData.InfFileName, NULL, INF_STYLE_WIN4, NULL);
        if (InfHandle == INVALID_HANDLE_VALUE)
        {
            ERR("GetPortType: exit %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);
            goto Exit;
        }

        TRACE("GetPortType: Section '%S'\n", DriverInfoDetailData.SectionName);

        SetupDiGetActualSectionToInstallW(InfHandle, DriverInfoDetailData.SectionName, InfSectionWithExt, 0x100, NULL, NULL);

        TRACE("GetPortType: Section ext '%S'\n", InfSectionWithExt);

        SetupInstallFromInfSectionW(NULL, InfHandle, InfSectionWithExt, SPINST_REGISTRY, Key, NULL, 0, NULL, NULL, NULL, NULL);
    }

    Size = sizeof(PortSubClass);
    Error = RegQueryValueExW(Key, L"PortSubClassOther", NULL, &Type, &PortSubClass, &Size);

    if (!Error && Size == sizeof(PortSubClass) && Type == REG_BINARY && PortSubClass != 0)
    {
        ERR("GetPortType: OtherPort %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);
        PortType = OtherPort;
        goto Exit;
    }

    Size = sizeof(PortSubClass);
    Error = RegQueryValueExW(Key, L"PortSubClass", NULL, &Type, &PortSubClass, &Size);

    if (Error == NO_ERROR && Size == sizeof(PortSubClass) && Type == REG_BINARY)
    {
        if (PortSubClass)
        {
            ERR("GetPortType: SerialPort %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);
            PortType = SerialPort;
        }
        else
        {
            ERR("GetPortType: ParallelPort %p, %p, %X\n", DeviceInfoSet, DeviceInfoData, IsInfInstall);
            PortType = ParallelPort;
        }
    }

Exit:

    RegCloseKey(Key);

    if (InfHandle != INVALID_HANDLE_VALUE)
        SetupCloseInfFile(InfHandle);

    return PortType;
}

DWORD
WINAPI
InstallSerialOrParallelPort(_In_ HDEVINFO DeviceInfoSet,
                            _In_ PSP_DEVINFO_DATA DeviceInfoData)
{
    PORT_TYPE PortType = GetPortType(DeviceInfoSet, DeviceInfoData, TRUE);

    switch (PortType)
    {
        case ParallelPort:
            return InstallPnPParallelPort(DeviceInfoSet, DeviceInfoData);

        case SerialPort:
            return InstallPnPSerialPort(DeviceInfoSet, DeviceInfoData);

        default:
            return ERROR_DI_DO_DEFAULT;
    }
}

DWORD
WINAPI
PortsClassInstaller(_In_ DI_FUNCTION InstallFunction,
                    _In_ HDEVINFO DeviceInfoSet,
                    _In_ PSP_DEVINFO_DATA DeviceInfoData OPTIONAL)
{
    HCOMDB ComDB;
    HKEY Key;
    WCHAR PortName[20];
    DWORD PortNameSize;
    DWORD PortNumber;
    DWORD ErrorCode;

    ERR("PortsClassInstaller(%lu, %p, %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData);

    if (InstallFunction == DIF_INSTALLDEVICE)
        return InstallSerialOrParallelPort(DeviceInfoSet, DeviceInfoData);

    if (InstallFunction == DIF_REMOVE)
    {
        /* If we are removing a serial port ... */
        if (GetPortType(DeviceInfoSet, DeviceInfoData, 0) == SerialPort)
        {
            /* Open the port database */
            if (ComDBOpen(&ComDB) == NO_ERROR)
            {
                /* Open the device key */
                Key = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                if (Key != INVALID_HANDLE_VALUE)
                {
                    /* Query the port name */
                    PortNameSize = sizeof(PortName);
                    ErrorCode = RegQueryValueExW(Key, L"PortName", NULL, NULL, (LPBYTE)PortName, &PortNameSize);

                    /* Close the device key */
                    RegCloseKey(Key);

                    /* If we got a valid port name ...*/
                    if (!ErrorCode)
                    {
                        /* Get the port number */
                        PortNumber = myatoi(&PortName[wcslen(pszCom)]);

                        /* Release the port */
                        ComDBReleasePort(ComDB, PortNumber);
                    }
                }

                /* Close the port database */
                ComDBClose(ComDB);
            }
        }

        /* Remove the device */
        if (!SetupDiRemoveDevice(DeviceInfoSet, DeviceInfoData))
        {
            ERR("PortsClassInstaller: SetupDiRemoveDevice() fail %lu\n", GetLastError());
            return GetLastError();
        }

        return NO_ERROR;
    }

    if (InstallFunction == DIF_FIRSTTIMESETUP)
    {
        ERR("PortsClassInstaller: NOT IMPEMENTED! (%lu, %p, %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData);
        return ERROR_DI_DO_DEFAULT;
    }

    if (InstallFunction == DIF_MOVEDEVICE)
    {
        ERR("PortsClassInstaller: NOT IMPEMENTED! (%lu, %p, %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData);
        return ERROR_DI_DO_DEFAULT;
    }

    if (InstallFunction == DIF_DETECT)
    {
        ERR("PortsClassInstaller: NOT IMPEMENTED! (%lu, %p, %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData);
        return ERROR_DI_DO_DEFAULT;
    }

    if (InstallFunction == DIF_REGISTERDEVICE)
    {
        ERR("PortsClassInstaller: NOT IMPEMENTED! (%lu, %p, %p)\n", InstallFunction, DeviceInfoSet, DeviceInfoData);
        return ERROR_DI_DO_DEFAULT;
    }

    return ERROR_DI_DO_DEFAULT;
}

/* EOF */
