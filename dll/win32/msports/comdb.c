/*
 * PROJECT:     Ports installer library
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll\win32\msports\comdb.c
 * PURPOSE:     COM port database
 * COPYRIGHT:   Copyright 2011 Eric Kohl
 */

#include "precomp.h"

#define BITS_PER_BYTE 8
#define BITMAP_SIZE_INCREMENT 0x400
#define BITMAP_SIZE_INVALID_BITS 0x3FF

typedef struct _COM_PORTS_DATA
{
    HANDLE Event;
    HANDLE Mutex;
    HKEY Key;
    PBYTE ComDB;
    ULONG ComDBSize;
} COM_PORTS_DATA, *PCOM_PORTS_DATA;

BOOL
WINAPI
ResizeDatabase(_In_ PCOM_PORTS_DATA ComPortsData,
               _In_ DWORD PortCount)
{
    PBYTE NewDatabase;

    if (!ComPortsData->ComDB)
    {
        ComPortsData->ComDBSize = (PortCount / BITS_PER_BYTE);
        ComPortsData->ComDB = LocalAlloc(LMEM_ZEROINIT, ComPortsData->ComDBSize);

        return (ComPortsData->ComDB != NULL);
    }

    NewDatabase = LocalAlloc(LMEM_ZEROINIT, (PortCount / BITS_PER_BYTE));
    if (!NewDatabase)
    {
        ERR("ResizeDatabase: Failed to allocate the database!\n");
        return FALSE;
    }

    CopyMemory(NewDatabase, ComPortsData->ComDB, ComPortsData->ComDBSize);

    LocalFree(ComPortsData->ComDB);

    ComPortsData->ComDB = NewDatabase;
    ComPortsData->ComDBSize = (PortCount / BITS_PER_BYTE);

    return TRUE;
}

VOID
WINAPI
RegisterForNotification(_In_ PCOM_PORTS_DATA ComPortsData)
{
    LONG Error;

    ResetEvent(ComPortsData->Event);

    Error = RegNotifyChangeKeyValue(ComPortsData->Key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, ComPortsData->Event, TRUE);
    if (Error != NO_ERROR)
    {
        ERR("RegisterForNotification: Error %lu (%p)\n", Error, ComPortsData);
        CloseHandle(ComPortsData->Event);
        ComPortsData->Event = INVALID_HANDLE_VALUE;
    }
}

VOID
WINAPI
DestroyDBInfo(_In_ PCOM_PORTS_DATA ComPortsData)
{
    if (ComPortsData->Mutex && ComPortsData->Mutex != INVALID_HANDLE_VALUE)
        CloseHandle(ComPortsData->Mutex);

    if (ComPortsData->Event && ComPortsData->Event != INVALID_HANDLE_VALUE)
        CloseHandle(ComPortsData->Event);

    if (ComPortsData->Key && ComPortsData->Key != INVALID_HANDLE_VALUE)
        RegCloseKey(ComPortsData->Key);

    if (ComPortsData->ComDB)
        LocalFree(ComPortsData->ComDB);

    LocalFree(ComPortsData);
}

BOOL
WINAPI
EnterDB(_In_ PCOM_PORTS_DATA ComPortsData)
{
    DWORD WaitStatus;
    DWORD Size;
    DWORD Type;
    LONG Error;
    BOOL IsNotify;

    WaitForSingleObject(ComPortsData->Mutex, INFINITE);

    if (ComPortsData->Event != INVALID_HANDLE_VALUE)
    {
        WaitStatus = WaitForSingleObject(ComPortsData->Event, 0);
        if (WaitStatus != WAIT_OBJECT_0)
            return TRUE;

        IsNotify = TRUE;
    }
    else
    {
        IsNotify = FALSE;
    }

    Size = 0;

    Error = RegQueryValueExW(ComPortsData->Key, L"ComDB", 0, &Type, 0, &Size);
    if (Error != NO_ERROR)
    {
        ERR("EnterDB: Error %lu (%p)\n", Error, ComPortsData);
        ReleaseMutex(ComPortsData->Mutex);
        return FALSE;
    }

    if (Type != REG_BINARY)
    {
        ERR("EnterDB: Type %lu (%p)\n", Type, ComPortsData);
        ReleaseMutex(ComPortsData->Mutex);
        return FALSE;
    }

    if (Size != ComPortsData->ComDBSize)
        ResizeDatabase(ComPortsData, (Size * BITS_PER_BYTE));

    RegQueryValueExW(ComPortsData->Key, L"ComDB", 0, &Type, ComPortsData->ComDB, &Size);

    if (IsNotify)
        RegisterForNotification(ComPortsData);

    return TRUE;
}

DWORD
WINAPI
LeaveDB(_In_ PCOM_PORTS_DATA ComPortsData,
        _In_ BOOL IsFound)
{
    DWORD ErrorCode = NO_ERROR;
    LONG Error;

    if (!IsFound)
    {
        goto Exit;
    }

    Error = RegSetValueExW(ComPortsData->Key, L"ComDB", 0, REG_BINARY, ComPortsData->ComDB, ComPortsData->ComDBSize);
    if (Error != NO_ERROR)
    {
        ERR("LeaveDB: ERROR_CANTWRITE %lu (%p, %lu)\n", Error, ComPortsData, IsFound);
        ErrorCode = ERROR_CANTWRITE;
    }

    if (ComPortsData->Event != INVALID_HANDLE_VALUE)
        RegisterForNotification(ComPortsData);

Exit:

    ReleaseMutex(ComPortsData->Mutex);

    return ErrorCode;
}

VOID
WINAPI
GetByteAndMask(_In_ PCOM_PORTS_DATA ComPortsData,
               _In_ DWORD ComNumber,
               _Out_ PBYTE* OutByte,
               _Out_ BYTE* OutMask)
{
    *OutByte = &ComPortsData->ComDB[(ComNumber - 1) >> 3];
    *OutMask = (1 << ((ComNumber - 1) & 7));
}

LONG
WINAPI
ComDBClaimNextFreePort(_In_ HCOMDB hComDB,
                       _Out_ DWORD* OutComNumber)
{
    PCOM_PORTS_DATA ComPortsData;
    PBYTE Byte;
    PBYTE Buffer;
    PBYTE End;
    DWORD ErrorCode;
    DWORD ComNumber;
    BYTE BitMask;
    BOOL IsFound = FALSE;

    ERR("ComDBClaimNextFreePort: %p\n", hComDB);

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBClaimNextFreePort: ERROR_INVALID_PARAMETER (%p)\n", hComDB);
        return ERROR_INVALID_PARAMETER;
    }

    ComPortsData = (PCOM_PORTS_DATA)hComDB;

    if (!EnterDB(ComPortsData))
    {
        ERR("ComDBClaimNextFreePort: ERROR_NOT_CONNECTED (%p)\n", ComPortsData);
        return ERROR_NOT_CONNECTED;
    }

    Buffer = Byte = ComPortsData->ComDB;
    End = &Buffer[ComPortsData->ComDBSize];

    BitMask = 4;

    for (ComNumber = 3; Buffer != End; ComNumber++)
    {
        if (!(BitMask & *Buffer))
        {
            *OutComNumber = ComNumber;
            *Buffer |= BitMask;

            ERR("ComDBClaimNextFreePort: %X, %X\n", *OutComNumber, *Buffer);

            IsFound = TRUE;
            break;
        }

        if (BitMask & 0x80)
        {
            BitMask = 1;
            Buffer++;
            Byte = Buffer;
        }
        else
        {
            BitMask <<= 1;
        }
    }

    if (Buffer == End && !IsFound && ComNumber < 4096)
    {
        ResizeDatabase(ComPortsData, ((ComNumber >> 10) + 1) << 10);
        GetByteAndMask(ComPortsData, ComNumber, &Byte, &BitMask);

        *OutComNumber = ComNumber;
        *Byte |= BitMask;

        ERR("ComDBClaimNextFreePort: %X, %X\n", *OutComNumber, *Buffer);

        IsFound = TRUE;
    }

    ErrorCode = LeaveDB(ComPortsData, IsFound);

    if (!IsFound)
    {
        ERR("ComDBClaimNextFreePort: ERROR_NO_LOG_SPACE (%p)\n", ComPortsData);
        ErrorCode = ERROR_NO_LOG_SPACE;
    }

    return ErrorCode;
}

LONG
WINAPI
ComDBClaimPort(_In_ HCOMDB hComDB,
               _In_ DWORD ComNumber,
               _In_ BOOL IsForceClaim,
               _Out_ BOOL* OutIsForced)
{
    PCOM_PORTS_DATA ComPortsData;
    PBYTE Byte;
    LONG Error;
    BYTE Mask;
    BOOL dummy;

    ERR("ComDBClaimPort: %p, %lu, %X\n", hComDB, ComNumber, IsForceClaim);

    if (!OutIsForced)
        OutIsForced = &dummy;

    if (ComNumber > 0x1000)
    {
        ERR("ComDBClaimPort: ERROR_INVALID_PARAMETER (%p, %lu, %X)\n", hComDB, ComNumber, IsForceClaim);
        return ERROR_INVALID_PARAMETER;
    }

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBClaimPort: ERROR_INVALID_PARAMETER (%p, %lu, %X)\n", hComDB, ComNumber, IsForceClaim);
        return ERROR_INVALID_PARAMETER;
    }

    ComPortsData = (PCOM_PORTS_DATA)hComDB;

    if (!EnterDB(ComPortsData))
    {
        ERR("ComDBClaimPort: ERROR_INVALID_PARAMETER (%p, %lu, %X)\n", ComPortsData, ComNumber, IsForceClaim);
        return ERROR_NOT_CONNECTED;
    }

    if (ComNumber > (ComPortsData->ComDBSize * BITS_PER_BYTE))
        ResizeDatabase(ComPortsData, (((ComNumber >> 10) + 1) << 10));

    GetByteAndMask(ComPortsData, ComNumber, &Byte, &Mask);

    if (!(*Byte & Mask))
    {
        if (OutIsForced)
            *OutIsForced = FALSE;

        *Byte |= Mask;

        return LeaveDB(ComPortsData, TRUE);
    }

    if (IsForceClaim)
    {
        if (OutIsForced)
            *OutIsForced = TRUE;

        return LeaveDB(ComPortsData, FALSE);
    }

    Error = LeaveDB(ComPortsData, FALSE);
    if (Error != NO_ERROR)
    {
        ERR("ComDBClaimPort: Error %lu (%p, %lu, %X)\n", Error, ComPortsData, ComNumber, IsForceClaim);
        return Error;
    }

    return ERROR_SHARING_VIOLATION;
}

LONG
WINAPI
ComDBClose(_In_ HCOMDB hComDB)
{
    ERR("ComDBClose: %p\n", hComDB);

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBClose: ERROR_INVALID_PARAMETER (%p)\n", hComDB);
        return ERROR_INVALID_PARAMETER;
    }

  #ifdef __REACTOS__
    if (hComDB == NULL)
    {
        ERR("ComDBClose: ERROR_INVALID_PARAMETER\n");
        return ERROR_INVALID_PARAMETER;
    }
  #endif

    DestroyDBInfo((PCOM_PORTS_DATA)hComDB);

    return NO_ERROR;
}

LONG
WINAPI
ComDBGetCurrentPortUsage(_In_ HCOMDB hComDB,
                         _Out_ BYTE* OutBuffer,
                         _In_ DWORD BufferSize,
                         _In_ DWORD ReportType,
                         _Out_ DWORD* OutMaxPortsReported)
{
    PCOM_PORTS_DATA ComPortsData;
    DWORD Size;
    PBYTE Byte;
    PBYTE End;
    BYTE Mask;

    ERR("ComDBGetCurrentPortUsage: %p, %p, %X, %X\n", hComDB, OutBuffer, BufferSize, ReportType);

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBGetCurrentPortUsage: ERROR_INVALID_PARAMETER\n");
        return ERROR_INVALID_PARAMETER;
    }

    ComPortsData = (PCOM_PORTS_DATA)hComDB;

    if (!EnterDB(ComPortsData))
    {
        ERR("ComDBGetCurrentPortUsage: ERROR_NOT_CONNECTED\n");
        return ERROR_NOT_CONNECTED;
    }

    if (!OutBuffer)
    {
        ERR("ComDBGetCurrentPortUsage: OutBuffer is NULL\n");

        if (OutMaxPortsReported)
        {
            *OutMaxPortsReported = (ComPortsData->ComDBSize * BITS_PER_BYTE);
            return LeaveDB(ComPortsData, FALSE);
        }
        else
        {
            ERR("ComDBGetCurrentPortUsage: ERROR_INVALID_PARAMETER\n");
            LeaveDB(ComPortsData, FALSE);
            return ERROR_INVALID_PARAMETER;
        }
    }

    if (ReportType == CDB_REPORT_BITS)
    {
        if (BufferSize > ComPortsData->ComDBSize)
            Size = ComPortsData->ComDBSize;
        else
            Size = BufferSize;

        CopyMemory(OutBuffer, ComPortsData->ComDB, Size);

        if (OutMaxPortsReported)
            *OutMaxPortsReported = (Size * BITS_PER_BYTE);

        return LeaveDB(ComPortsData, FALSE);
    }

    if (ReportType != CDB_REPORT_BYTES)
    {
        ERR("ComDBGetCurrentPortUsage: ERROR_INVALID_PARAMETER (%p, %p, %X, %X)\n", ComPortsData, OutBuffer, BufferSize, ReportType);
        LeaveDB(ComPortsData, FALSE);
        return ERROR_INVALID_PARAMETER;
    }

    /* CDB_REPORT_BYTES */

    if (BufferSize > (ComPortsData->ComDBSize * BITS_PER_BYTE))
        Size = (ComPortsData->ComDBSize * BITS_PER_BYTE);
    else
        Size = BufferSize;

    End = &OutBuffer[Size];
    Byte = ComPortsData->ComDB;
    Mask = 1;

    while (OutBuffer != End)
    {
        if (*Byte & Mask)
            *OutBuffer = 1;
        else
            *OutBuffer = 0;


        if (Mask & 0x80)
        {
            Mask = 1;
            Byte++;
        }
        else
        {
            Mask <<= 1;
        }

        OutBuffer++;
    }

    return LeaveDB(ComPortsData, FALSE);
}

DWORD
WINAPI
CreationFailure(_Out_ HCOMDB* OutHComDB,
                _In_ PCOM_PORTS_DATA ComPortsData)
{
    if (ComPortsData->Mutex)
        ReleaseMutex(ComPortsData->Mutex);

    DestroyDBInfo(ComPortsData);

    *OutHComDB = HCOMDB_INVALID_HANDLE_VALUE;

    return ERROR_ACCESS_DENIED;
}

LONG
WINAPI
ComDBOpen(_Out_ HCOMDB* OutHComDB)
{
    PCOM_PORTS_DATA ComPortsData;
    HKEY ServiceSerialKey;
    DWORD Disposition = 0;
    DWORD DataSize;
    DWORD Type;
    DWORD ix;
    LONG Error;
    BYTE MergeData[32];
    BOOL IsNewDbFromSerial;

    ERR("ComDBOpen: %p\n", OutHComDB);

    /* Allocate a new database */
    ComPortsData = LocalAlloc(LMEM_ZEROINIT, sizeof(*ComPortsData));
    if (!ComPortsData)
    {
        ERR("ComDBOpen: Failed to allocate the database!\n");
        *OutHComDB = HCOMDB_INVALID_HANDLE_VALUE;
        return ERROR_ACCESS_DENIED;
    }

    /* Create a mutex to protect the database */
    ComPortsData->Mutex = CreateMutexW(NULL, FALSE, L"ComPortNumberDatabaseMutexObject");
    if (!ComPortsData->Mutex)
    {
        ERR("ComDBOpen: Failed to create the mutex!\n");
        return CreationFailure(OutHComDB, ComPortsData);
    }

    /* Wait for the mutex */
    WaitForSingleObject(ComPortsData->Mutex, INFINITE);

    /* Create or open the database key */
    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                             L"System\\CurrentControlSet\\Control\\COM Name Arbiter",
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             KEY_ALL_ACCESS,
                             NULL,
                             &ComPortsData->Key,
                             &Disposition);

    if (Error == NO_ERROR)
    {
        ComPortsData->Event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ComPortsData->Event)
            ComPortsData->Event = INVALID_HANDLE_VALUE;
    }
    else
    {
        // Second call?
        Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                 L"System\\CurrentControlSet\\Control\\COM Name Arbiter",
                                 0,
                                 NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 KEY_ALL_ACCESS,
                                 NULL,
                                 &ComPortsData->Key,
                                 &Disposition);

        if (Error == NO_ERROR)
        {
            ComPortsData->Event = INVALID_HANDLE_VALUE;
        }
        else
        {
            ERR("ComDBOpen: Error %lu\n", Error);
            return CreationFailure(OutHComDB, ComPortsData);
        }
    }

    if (Disposition != REG_CREATED_NEW_KEY)
    {
        IsNewDbFromSerial = FALSE;
    }
    else
    {
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                               L"System\\CurrentControlSet\\Services\\Serial",
                               0,
                               KEY_ALL_ACCESS,
                               &ServiceSerialKey);

        if (Error != NO_ERROR)
        {
            IsNewDbFromSerial = FALSE;
        }
        else
        {
            Error = RegQueryValueExW(ServiceSerialKey, L"ComDB", 0, &Type, NULL, &ComPortsData->ComDBSize);

            if (Error != NO_ERROR)
                IsNewDbFromSerial = FALSE;
            else
                IsNewDbFromSerial = TRUE;
        }
    }

    if (IsNewDbFromSerial)
    {
        ResizeDatabase(ComPortsData, (ComPortsData->ComDBSize * BITS_PER_BYTE));

        DataSize = ComPortsData->ComDBSize;
        RegQueryValueExW(ServiceSerialKey, L"ComDB", 0, &Type, ComPortsData->ComDB, &DataSize);

        RegDeleteValueW(ServiceSerialKey, L"ComDB");

        Error = RegSetValueExW(ComPortsData->Key, L"ComDB", 0, REG_BINARY, ComPortsData->ComDB, ComPortsData->ComDBSize);
        if (Error != NO_ERROR)
        {
            ERR("ComDBOpen: Error %lu\n", Error);
            RegCloseKey(ServiceSerialKey);
            return CreationFailure(OutHComDB, ComPortsData);
        }

        RegCloseKey(ServiceSerialKey);
    }
    else
    {
        Error = RegQueryValueExW(ComPortsData->Key, L"ComDB", 0, &Type, NULL, &ComPortsData->ComDBSize);

        if (Error == ERROR_FILE_NOT_FOUND)
        {
            ResizeDatabase(ComPortsData, 0x100);

            Error = RegSetValueExW(ComPortsData->Key, L"ComDB", 0, REG_BINARY, ComPortsData->ComDB, ComPortsData->ComDBSize);
            if (Error != NO_ERROR)
            {
                ERR("ComDBOpen: Error %lu\n", Error);
                return CreationFailure(OutHComDB, ComPortsData);
            }
        }
        else
        {
            if (Error == ERROR_MORE_DATA)
            {
                ERR("ComDBOpen: ERROR_MORE_DATA\n");
                return CreationFailure(OutHComDB, ComPortsData);
            }

            if (Error != NO_ERROR)
            {
                ERR("ComDBOpen: Error %lu\n", Error);
                return CreationFailure(OutHComDB, ComPortsData);
            }

            if (Type != REG_BINARY)
            {
                ERR("ComDBOpen: Type %lu\n", Type);
                return CreationFailure(OutHComDB, ComPortsData);
            }

            ResizeDatabase(ComPortsData, (ComPortsData->ComDBSize * BITS_PER_BYTE));

            DataSize = ComPortsData->ComDBSize;
            RegQueryValueExW(ComPortsData->Key, L"ComDB", 0, &Type, ComPortsData->ComDB, &DataSize);
        }
    }

    DataSize = 32;
    Error = RegQueryValueExW(ComPortsData->Key, L"ComDB Merge", 0, &Type, MergeData, &DataSize);

    if (Error == NO_ERROR && DataSize <= ComPortsData->ComDBSize)
    {
        ix = 0;
        do
        {
            ComPortsData->ComDB[ix] |= MergeData[ix];
            ix++;
        }
        while (ix < 32);

        RegDeleteValueW(ComPortsData->Key, L"ComDB Merge");
        RegSetValueExW(ComPortsData->Key, L"ComDB", 0, REG_BINARY, ComPortsData->ComDB, ComPortsData->ComDBSize);
    }

    if (ComPortsData->Event != INVALID_HANDLE_VALUE)
        RegisterForNotification(ComPortsData);

    /* Release the mutex */
    ReleaseMutex(ComPortsData->Mutex);

    *OutHComDB = (HCOMDB)ComPortsData;

    return NO_ERROR;
}

LONG
WINAPI
ComDBReleasePort(_In_ HCOMDB hComDB,
                 _In_ DWORD ComNumber)
{
    PCOM_PORTS_DATA ComPortsData;
    PBYTE Byte;
    BYTE BitMask;

    ERR("ComDBReleasePort: %p, %lu\n", hComDB, ComNumber);

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBReleasePort: ERROR_INVALID_PARAMETER\n");
        return ERROR_INVALID_PARAMETER;
    }

    ComPortsData = (PCOM_PORTS_DATA)hComDB;

    if (!EnterDB(ComPortsData))
    {
        ERR("ComDBReleasePort: ERROR_NOT_CONNECTED (%p, %lu)\n", ComPortsData, ComNumber);
        return ERROR_NOT_CONNECTED;
    }

    if (ComNumber > (ComPortsData->ComDBSize * BITS_PER_BYTE))
    {
        ERR("ComDBReleasePort: ERROR_INVALID_PARAMETER (%p, %lu, %lu)\n", ComPortsData, ComNumber, ComPortsData->ComDBSize);
        LeaveDB(ComPortsData, FALSE);
        return ERROR_INVALID_PARAMETER;
    }

    GetByteAndMask(ComPortsData, ComNumber, &Byte, &BitMask);

    *Byte &= ~BitMask;

    return LeaveDB(ComPortsData, TRUE);
}

LONG
WINAPI
ComDBResizeDatabase(_In_ HCOMDB hComDB,
                    _In_ DWORD NewSize)
{
    PCOM_PORTS_DATA ComPortsData;

    ERR("ComDBResizeDatabase: %p, %lu\n", hComDB, NewSize);

    if (hComDB == HCOMDB_INVALID_HANDLE_VALUE)
    {
        ERR("ComDBResizeDatabase: ERROR_INVALID_PARAMETER (%p, %lu)\n", hComDB, NewSize);
        return ERROR_INVALID_PARAMETER;
    }

    ComPortsData = (PCOM_PORTS_DATA)hComDB;

    if (NewSize & BITMAP_SIZE_INVALID_BITS)
    {
        ERR("ComDBResizeDatabase: ERROR_INVALID_PARAMETER (%p, %lu)\n", ComPortsData, NewSize);
        return ERROR_INVALID_PARAMETER;
    }

    if (!EnterDB(ComPortsData))
    {
        ERR("ComDBResizeDatabase: ERROR_NOT_CONNECTED (%p, %lu)\n", ComPortsData, NewSize);
        return ERROR_NOT_CONNECTED;
    }

    if (NewSize > 4096)
    {
        ERR("ComDBResizeDatabase: ERROR_BAD_LENGTH (%p, %lu)\n", ComPortsData, NewSize);
        LeaveDB(ComPortsData, FALSE);
        return ERROR_BAD_LENGTH;
    }

    if (NewSize < (ComPortsData->ComDBSize * BITS_PER_BYTE))
    {
        ERR("ComDBResizeDatabase: ERROR_BAD_LENGTH (%p, %lu, %lu)\n", ComPortsData, NewSize, ComPortsData->ComDBSize);
        LeaveDB(ComPortsData, FALSE);
        return ERROR_BAD_LENGTH;
    }

    ResizeDatabase(ComPortsData, NewSize);

    return LeaveDB(ComPortsData, TRUE);
}
/* EOF */
