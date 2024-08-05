/*
 * PROJECT:     ACPI driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Working with the registry
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#include "acpi.h"

#define NDEBUG
#include <debug.h>

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, OSCloseHandle)
  #pragma alloc_text(PAGE, OSOpenUnicodeHandle)
  #pragma alloc_text(PAGE, OSOpenHandle)
  #pragma alloc_text(PAGE, OSReadRegValue)
  #pragma alloc_text(PAGE, OSGetRegistryValue)
  #pragma alloc_text(PAGE, OSReadAcpiConfigurationData)
#endif

/* GLOBALS *******************************************************************/

ANSI_STRING AcpiProcessorString;
ULONG AcpiOverrideAttributes;
UCHAR DoAcpiTableDump = 0xFF;

extern PACPI_INFORMATION AcpiInformation;

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
OSCloseHandle(
    _In_ HANDLE Handle)
{
    PAGED_CODE();
    DPRINT("OSCloseHandle: %p\n", Handle);
    return ZwClose(Handle);
}

NTSTATUS
NTAPI
OSOpenUnicodeHandle(
    _In_ PUNICODE_STRING Name,
    _In_ HANDLE ParentKeyHandle,
    _In_ PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSOpenUnicodeHandle: '%wZ'\n", Name);

    InitializeObjectAttributes(&ObjectAttributes,
                               Name,
                               (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE),
                               ParentKeyHandle,
                               NULL);

    Status = ZwOpenKey(KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("OSOpenUnicodeHandle: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
OSOpenHandle(
    _In_ PSZ NameString,
    _In_ HANDLE ParentKeyHandle,
    _In_ PHANDLE KeyHandle)
{
    UNICODE_STRING Name;
    ANSI_STRING AnsiName;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSOpenHandle: '%s'\n", NameString);

    RtlInitAnsiString(&AnsiName, NameString);

    Status = RtlAnsiStringToUnicodeString(&Name, &AnsiName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSOpenHandle: Status %X\n", Status);
        return Status;
    }

    Status = OSOpenUnicodeHandle(&Name, ParentKeyHandle, KeyHandle);

    RtlFreeUnicodeString(&Name);

    return Status;
}

NTSTATUS
NTAPI
OSReadRegValue(
    _In_ PSZ NameString,
    _In_ HANDLE Handle,
    _Out_ PVOID OutValue,
    _Out_ ULONG* OutMaximumLength)
{
    PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 KeyValueInfo = NULL;
    UNICODE_STRING ValueName;
    ANSI_STRING AnsiName;
    HANDLE KeyHandle = NULL;
    ULONG ResultLength = 0;
    ULONG Length;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSReadRegValue: '%s', %p\n", NameString, Handle);

    if (Handle)
    {
        KeyHandle = Handle;
    }
    else
    {
        Status = OSOpenHandle("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ACPI\\Parameters", NULL, &KeyHandle);
        if (!NT_SUCCESS(Status) || !KeyHandle)
        {
            DPRINT("OSReadRegValue: Status %X\n", Status);
            return Status;
        }
    }

    RtlInitAnsiString(&AnsiName, NameString);

    Status = RtlAnsiStringToUnicodeString(&ValueName, &AnsiName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSReadRegValue: Status %X\n", Status);

        if (!Handle)
            OSCloseHandle(KeyHandle);

        return Status;
    }

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformationAlign64, NULL, 0, &ResultLength);

    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
    {
        DPRINT1("OSReadRegValue: Status %X\n", Status);

        RtlFreeUnicodeString(&ValueName);

        if (!Handle)
            OSCloseHandle(KeyHandle);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("OSReadRegValue: Status %X\n", Status);
            return Status;
        }

        return STATUS_UNSUCCESSFUL;
    }

    while (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
    {
        Length = ResultLength;

        KeyValueInfo = ExAllocatePoolWithTag(PagedPool, ResultLength, 'MpcA');
        if (!KeyValueInfo)
        {
            DPRINT1("OSReadRegValue: Allocate failed\n");

            RtlFreeUnicodeString(&ValueName);

            if (!Handle)
                OSCloseHandle(KeyHandle);

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformationAlign64, KeyValueInfo, Length, &ResultLength);

        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
        {
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("OSReadRegValue: Status %X\n", Status);

                RtlFreeUnicodeString(&ValueName);

                if (!Handle)
                    OSCloseHandle(KeyHandle);

                ExFreePool(KeyValueInfo);
                return Status;
            }

            break;
        }

        ExFreePool(KeyValueInfo);
    }

    RtlFreeUnicodeString(&ValueName);

    if (!Handle)
        OSCloseHandle(KeyHandle);

    if (KeyValueInfo->Type != REG_SZ && KeyValueInfo->Type != REG_MULTI_SZ)
    {
        if (*OutMaximumLength >= KeyValueInfo->DataLength)
        {
            RtlCopyMemory(OutValue, KeyValueInfo->Data, KeyValueInfo->DataLength);
            *OutMaximumLength = KeyValueInfo->DataLength;

            ExFreePool(KeyValueInfo);
            return STATUS_SUCCESS;
        }

        ExFreePool(KeyValueInfo);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlInitUnicodeString(&ValueName, (PWSTR)KeyValueInfo->Data);

    Status = RtlUnicodeStringToAnsiString(&AnsiName, &ValueName, TRUE);

    DPRINT("OSReadRegValue: '%s'\n", AnsiName.Buffer);

    ExFreePool(KeyValueInfo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSReadRegValue: Status %X\n", Status);
        return Status;
    }

    if (*OutMaximumLength >= AnsiName.MaximumLength)
    {
        *OutMaximumLength = AnsiName.MaximumLength;
        RtlCopyMemory(OutValue, AnsiName.Buffer, AnsiName.MaximumLength);

        RtlFreeAnsiString(&AnsiName);
        return STATUS_SUCCESS;
    }

    DPRINT("OSReadRegValue: %X < %X\n", *OutMaximumLength, AnsiName.MaximumLength);

    RtlFreeAnsiString(&AnsiName);

    return STATUS_BUFFER_OVERFLOW;
}

NTSTATUS
NTAPI
OSGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PWSTR NameString,
    _In_ PVOID* OutValue)
{
    UNICODE_STRING Name;
    ULONG ResultLength;
    PVOID Value;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSGetRegistryValue: '%S', %p\n", NameString, KeyHandle);

    RtlInitUnicodeString(&Name, NameString);

    Status = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformationAlign64, NULL, 0, &ResultLength);

    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
    {
        return Status;
    }

    Value = ExAllocatePoolWithTag(0, ResultLength, 'SpcA');
    if (!Value)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return Status;
    }

    Status = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformationAlign64, Value, ResultLength, &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Value, 'SpcA');
        return Status;
    }

    *OutValue = Value;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
OSReadAcpiConfigurationData(
    _Out_ PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64* OutKeyInfo)
{
    PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 KeyInfo;
    UNICODE_STRING AcpiBiosName;
    UNICODE_STRING CurrentName;
    UNICODE_STRING KeyName;
    WCHAR AcpiBiosStrBuffer[4];
    HANDLE Handle;
    HANDLE KeyHandle;
    ULONG Value;
    ULONG ix;
    NTSTATUS Status;
    BOOLEAN Result;

    DPRINT("OSReadAcpiConfigurationData()\n");

    if (!OutKeyInfo)
    {
        ASSERT(OutKeyInfo != NULL);
        return STATUS_INVALID_PARAMETER;
    }

    *OutKeyInfo = NULL;

    RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\Hardware\\Description\\System\\MultiFunctionAdapter");

    Status = OSOpenUnicodeHandle(&KeyName, NULL, &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSReadAcpiConfigurationData: Cannot open MFA Handle = %08lx\n", Status);
        DbgBreakPoint();
        return Status;
    }

    RtlInitUnicodeString(&AcpiBiosName, L"ACPI BIOS");

    KeyName.MaximumLength = 8;
    KeyName.Buffer = AcpiBiosStrBuffer;

    for (Value = 0; Value < 0x3E7; Value++) // 999
    {
        RtlIntegerToUnicodeString(Value, 0xA, &KeyName);

        Status = OSOpenUnicodeHandle(&KeyName, Handle, &KeyHandle);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("OSReadAcpiConfigurationData: Cannot open MFA %ws = %08lx\n", KeyName.Buffer, Status);
            DbgBreakPoint();
            OSCloseHandle(Handle);
            return Status;
        }

        Status = OSGetRegistryValue(KeyHandle, L"Identifier", (PVOID *)OutKeyInfo);
        if (!NT_SUCCESS(Status))
        {
            OSCloseHandle(Handle);
            continue;
        }

        KeyInfo = *OutKeyInfo;

        CurrentName.Buffer = (PWSTR)KeyInfo->Data;
        CurrentName.MaximumLength = (USHORT)KeyInfo->DataLength;

        for (ix = (CurrentName.MaximumLength / sizeof(WCHAR)); ix; ix--)
        {
            if (CurrentName.Buffer[ix - 1])
                break;
        }

        CurrentName.Length = (ix * sizeof(WCHAR));

        Result = RtlEqualUnicodeString(&AcpiBiosName, &CurrentName, TRUE);
        ExFreePool(*OutKeyInfo);

        if (!Result)
        {
            OSCloseHandle(KeyHandle);
            continue;
        }

        Status = OSGetRegistryValue(KeyHandle, L"Configuration Data", (PVOID *)OutKeyInfo);
        OSCloseHandle(KeyHandle);

        if (NT_SUCCESS(Status))
        {
            OSCloseHandle(Handle);
            return STATUS_SUCCESS;
        }
    }

    DPRINT1("OSReadAcpiConfigurationData - Could not find entry\n");
    DbgBreakPoint();
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

VOID
NTAPI
ACPIInitReadRegistryKeys(VOID)
{
    PCHAR VendorIdentifier = NULL;
    PCHAR Identifier = NULL;
    HANDLE KeyHandle = NULL;
    PCHAR PtrToStepping;
    PCHAR Buffer;
    ULONG VendorIdentifierSize;
    ULONG IdentifierSize;
    ULONG MaximumLength;
    ULONG Length;
    ULONG Size;
    NTSTATUS Status;

    DPRINT("ACPIInitReadRegistryKeys()\n");

    MaximumLength = sizeof(AcpiOverrideAttributes);

    Status = OSReadRegValue("Attributes", NULL, &AcpiOverrideAttributes, &MaximumLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIInitReadRegistryKeys: Status %X\n", Status);
        AcpiOverrideAttributes = 0;
    }

    AcpiProcessorString.Length = 0;
    AcpiProcessorString.MaximumLength = 0;
    AcpiProcessorString.Buffer = NULL;

    Status = OSOpenHandle("\\Registry\\Machine\\Hardware\\Description\\System\\CentralProcessor\\0", NULL, &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitReadRegistryKeys: Status %X\n", Status);
    }

    IdentifierSize = 0x28;

    while (TRUE)
    {
        if (Identifier)
            ExFreePoolWithTag(Identifier, 'SpcA');

        Identifier = ExAllocatePoolWithTag(PagedPool, IdentifierSize, 'SpcA');
        if (!Identifier)
            break;

        RtlZeroMemory(Identifier, IdentifierSize);

        MaximumLength = IdentifierSize;
        IdentifierSize += 0xA;

        Status = OSReadRegValue("Identifier", KeyHandle, Identifier, &MaximumLength);
        if (Status == STATUS_BUFFER_OVERFLOW)
            continue;

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIInitReadRegistryKeys: Status %X\n", Status);
            break;
        }

        PtrToStepping = strstr(Identifier, "Stepping");
        if (PtrToStepping)
            *(PtrToStepping - 1) = 0;

        Size = strlen(Identifier);
        VendorIdentifierSize = 0xA;

        while (TRUE)
        {
            if (VendorIdentifier)
                ExFreePoolWithTag(VendorIdentifier, 'SpcA');

            VendorIdentifier = ExAllocatePoolWithTag(PagedPool, VendorIdentifierSize, 'SpcA');
            if (!VendorIdentifier)
                break;

            RtlZeroMemory(VendorIdentifier, VendorIdentifierSize);

            MaximumLength = VendorIdentifierSize;
            VendorIdentifierSize += 0xA;

            Status = OSReadRegValue("VendorIdentifier", KeyHandle, VendorIdentifier, &MaximumLength);
            if (Status == STATUS_BUFFER_OVERFLOW)
                continue;

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPIInitReadRegistryKeys: Status %X\n", Status);
                goto Exit;
            }

            Length = (Size + MaximumLength + 3);

            Buffer = ExAllocatePoolWithTag(0, Length, 'SpcA');
            if (!Buffer)
            {
                DPRINT1("ACPIInitReadRegistryKeys: Allocate failed\n");
                goto Exit;
            }

            sprintf(Buffer, "%s - %s", VendorIdentifier, Identifier);

            AcpiProcessorString.Buffer = Buffer;
            AcpiProcessorString.MaximumLength = Length;
            AcpiProcessorString.Length = Length;

            goto Exit;
        }

        break;
    }

Exit:

    if (KeyHandle)
        OSCloseHandle(KeyHandle);

    if (VendorIdentifier)
        ExFreePoolWithTag(VendorIdentifier, 'SpcA');

    if (Identifier)
        ExFreePoolWithTag(Identifier, 'SpcA');
}

BOOLEAN
NTAPI
ACPIRegReadAMLRegistryEntry(
    _In_ PDESCRIPTION_HEADER* OutTableHeader,
    _In_ BOOLEAN IsNeedUnmap)
{
    UNIMPLEMENTED_ONCE;
    return FALSE;
}

NTSTATUS
NTAPI
OSWriteRegValue(
    _In_ PSZ NameString,
    _In_ HANDLE KeyHandle,
    _In_ PVOID Data,
    _In_ ULONG DataSize)
{
    STRING AnsiName;
    UNICODE_STRING ValueName;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSWriteRegValue: NameString '%s'\n", NameString);

    RtlInitAnsiString(&AnsiName, NameString);

    Status = RtlAnsiStringToUnicodeString(&ValueName, &AnsiName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSWriteRegValue: Status %X\n", Status);
        return Status;
    }

    Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_BINARY, Data, DataSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSRegWriteValue: Status %X\n", Status);
    }

    RtlFreeUnicodeString(&ValueName);

    return Status;
}

NTSTATUS
NTAPI
OSCreateHandle(
    _In_ PSZ NameString,
    _In_ HANDLE ParentKeyHandle,
    _Out_ HANDLE* OutKeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    STRING AnsiName;
    UNICODE_STRING Name;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSCreateHandle: NameString '%s'\n", NameString);

    RtlInitAnsiString(&AnsiName, NameString);

    Status = RtlAnsiStringToUnicodeString(&Name, &AnsiName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSCreateHandle: Status %X\n", Status);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &Name,
                               (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE),
                               ParentKeyHandle,
                               NULL);
    *OutKeyHandle = NULL;

    Status = ZwCreateKey(OutKeyHandle, KEY_WRITE, &ObjectAttributes, 0, NULL, 0, NULL);

    RtlFreeUnicodeString(&Name);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSCreateHandle: Status %X\n", Status);
    }

    return Status;
}

PCHAR
NTAPI
ACPIRegLocalCopyString(
    _In_ PCHAR DestString,
    _In_ PCHAR SourceStr,
    _In_ ULONG Length)
{
    ULONG ix;

    for (ix = 0; ix < Length; ix++)
    {
        if (!SourceStr[ix])
            break;

        if (SourceStr[ix] == ' ')
            DestString[ix] = '_';
        else
            DestString[ix] = SourceStr[ix];
    }

    DestString[ix] = 0;

    return &DestString[ix];
}

VOID
NTAPI
ACPIRegDumpAcpiTable(
    _In_ PCHAR NameString,
    _In_ PVOID WriteData,
    _In_ ULONG DataSize,
    _In_ PDESCRIPTION_HEADER Header)
{
    HANDLE ParentKeyHandle;
    HANDLE KeyHandle;
    CHAR NameBuffer[0x50];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIRegDumpAcpiTable: Table '%s'\n", NameString);

    RtlZeroMemory(NameBuffer, sizeof(NameBuffer));
    RtlCopyMemory(NameBuffer, "\\Registry\\Machine\\Hardware\\ACPI", sizeof("\\Registry\\Machine\\Hardware\\ACPI"));

    Status = OSCreateHandle(NameBuffer, NULL, &ParentKeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRegDumpAcpiTable: Status %X\n", Status);
        return;
    }

    Status = OSCreateHandle(NameString, ParentKeyHandle, &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRegDumpAcpiTable: Status %X\n", Status);
        OSCloseHandle(ParentKeyHandle);
        return;
    }

    if (Header)
    {
        OSCloseHandle(ParentKeyHandle);
        ParentKeyHandle = KeyHandle;

        ACPIRegLocalCopyString(NameBuffer, (PCHAR)Header->OEMID, 6);

        Status = OSCreateHandle(NameBuffer, ParentKeyHandle, &KeyHandle);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIRegDumpAcpiTable: Status %X\n", Status);
            OSCloseHandle(ParentKeyHandle);
            return;
        }

        OSCloseHandle(ParentKeyHandle);
        ParentKeyHandle = KeyHandle;

        ACPIRegLocalCopyString(NameBuffer, (PCHAR)Header->OEMTableID, 8),

        Status = OSCreateHandle(NameBuffer, ParentKeyHandle, &KeyHandle);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIRegDumpAcpiTable: Status %X\n", Status);
            OSCloseHandle(ParentKeyHandle);
            return;
        }

        OSCloseHandle(ParentKeyHandle);
        ParentKeyHandle = KeyHandle;

        sprintf(NameBuffer, "%.8x", (unsigned int)Header->OEMRevision),

        Status = OSCreateHandle(NameBuffer, ParentKeyHandle, &KeyHandle);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIRegDumpAcpiTable: Status %X\n", Status);
            OSCloseHandle(ParentKeyHandle);
            return;
        }
    }

    OSWriteRegValue("00000000", KeyHandle, WriteData, DataSize);

    OSCloseHandle(KeyHandle);
    OSCloseHandle(KeyHandle);
}

VOID
NTAPI
ACPIRegDumpAcpiTables(VOID)
{
    PFADT Fadt;
    PDSDT Dsdt;
    PFACS Facs;
    PRSDT Rsdt;

    Fadt = AcpiInformation->FixedACPIDescTable;
    Dsdt = AcpiInformation->DiffSystemDescTable;
    Facs = AcpiInformation->FirmwareACPIControlStructure;
    Rsdt = AcpiInformation->RootSystemDescTable;

    if (!DoAcpiTableDump)
    {
        return;
    }

    DPRINT("DumpAcpiTables: Writing DSDT/FACS/FADT/RSDT to registry\n");

    if (Dsdt)
        ACPIRegDumpAcpiTable("DSDT", Dsdt, Dsdt->Header.Length, &Dsdt->Header);

    if (Facs)
        ACPIRegDumpAcpiTable("FACS", Facs, Facs->Length, NULL);

    if (Fadt)
        ACPIRegDumpAcpiTable("FADT", Fadt, Fadt->Header.Length, &Fadt->Header);

    if (Rsdt)
        ACPIRegDumpAcpiTable("RSDT", Rsdt, Rsdt->Header.Length, &Rsdt->Header);
}

/* EOF */
