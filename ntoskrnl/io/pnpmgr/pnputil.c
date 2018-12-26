/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnputil.c
 * PURPOSE:         PnP Utility Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

extern RTL_AVL_TABLE PpDeviceReferenceTable;
extern KGUARDED_MUTEX PpDeviceReferenceTableLock;

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PnpAllocateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_ USHORT Size)
{
    PWCHAR Buffer;

    PAGED_CODE();

    String->Length = 0;
    String->MaximumLength = Size + sizeof(WCHAR);

    Buffer = ExAllocatePoolWithTag(PagedPool, String->MaximumLength, '  pP');
    String->Buffer = Buffer;

    if (Buffer)
    {
        return STATUS_SUCCESS;
    }

    ASSERT(FALSE);
    String->MaximumLength = 0;
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NTAPI
PnpConcatenateUnicodeStrings(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ PUNICODE_STRING AppendString)
{
    USHORT Length;
    NTSTATUS Status;

    PAGED_CODE();

    Length = SourceString->Length;

    if (AppendString)
    {
        Length += AppendString->Length;
    }

    Status = PnpAllocateUnicodeString(DestinationString, Length);
    if (!NT_SUCCESS(Status))
    {
        ASSERT(FALSE);
        return Status;
    }

    RtlCopyUnicodeString(DestinationString, SourceString);

    if (AppendString)
    {
        RtlAppendUnicodeStringToString(DestinationString, AppendString);
    }

    return Status;
}

VOID
NTAPI
PnpFreeUnicodeStringList(IN PUNICODE_STRING UnicodeStringList,
                         IN ULONG StringCount)
{
    ULONG i;

    /* Go through the list */
    if (UnicodeStringList)
    {
        /* Go through each string */
        for (i = 0; i < StringCount; i++)
        {
            /* Check if it exists */
            if (UnicodeStringList[i].Buffer)
            {
                /* Free it */
                ExFreePool(UnicodeStringList[i].Buffer);
            }
        }

        /* Free the whole list */
        ExFreePool(UnicodeStringList);
    }
}

NTSTATUS
NTAPI
PnpRegMultiSzToUnicodeStrings(IN PKEY_VALUE_FULL_INFORMATION KeyValueInformation,
                              OUT PUNICODE_STRING *UnicodeStringList,
                              OUT PULONG UnicodeStringCount)
{
    PWCHAR p, pp, ps;
    ULONG i = 0;
    SIZE_T n;
    ULONG Count = 0;

    /* Validate the key information */
    if (KeyValueInformation->Type != REG_MULTI_SZ) return STATUS_INVALID_PARAMETER;

    /* Set the pointers */
    p = (PWCHAR)((ULONG_PTR)KeyValueInformation +
                 KeyValueInformation->DataOffset);
    pp = (PWCHAR)((ULONG_PTR)p + KeyValueInformation->DataLength);

    /* Loop the data */
    while (p != pp)
    {
        /* If we find a NULL, that means one string is done */
        if (!*p)
        {
            /* Add to our string count */
            Count++;

            /* Check for a double-NULL, which means we're done */
            if (((p + 1) == pp) || !(*(p + 1))) break;
        }

        /* Go to the next character */
        p++;
    }

    /* If we looped the whole list over, we missed increment a string, do it */
    if (p == pp) Count++;

    /* Allocate the list now that we know how big it is */
    *UnicodeStringList = ExAllocatePoolWithTag(PagedPool,
                                               sizeof(UNICODE_STRING) * Count,
                                               'sUpP');
    if (!(*UnicodeStringList)) return STATUS_INSUFFICIENT_RESOURCES;

    /* Set pointers for second loop */
    ps = p = (PWCHAR)((ULONG_PTR)KeyValueInformation +
                     KeyValueInformation->DataOffset);

    /* Loop again, to do the copy this time */
    while (p != pp)
    {
        /* If we find a NULL, that means one string is done */
        if (!*p)
        {
            /* Check how long this string is */
            n = (ULONG_PTR)p - (ULONG_PTR)ps + sizeof(UNICODE_NULL);

            /* Allocate the buffer */
            (*UnicodeStringList)[i].Buffer = ExAllocatePoolWithTag(PagedPool,
                                                                   n,
                                                                   'sUpP');
            if (!(*UnicodeStringList)[i].Buffer)
            {
                /* Back out of everything */
                PnpFreeUnicodeStringList(*UnicodeStringList, i);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Copy the string into the buffer */
            RtlCopyMemory((*UnicodeStringList)[i].Buffer, ps, n);

            /* Set the lengths */
            (*UnicodeStringList)[i].MaximumLength = (USHORT)n;
            (*UnicodeStringList)[i].Length = (USHORT)(n - sizeof(UNICODE_NULL));

            /* One more entry done */
            i++;

            /* Check for a double-NULL, which means we're done */
            if (((p + 1) == pp) || !(*(p + 1))) break;

            /* New string */
            ps = p + 1;
        }

        /* New string */
        p++;
    }

    /* Check if we've reached the last string */
    if (p == pp)
    {
        /* Calculate the string length */
        n = (ULONG_PTR)p - (ULONG_PTR)ps;

        /* Allocate the buffer for it */
        (*UnicodeStringList)[i].Buffer = ExAllocatePoolWithTag(PagedPool,
                                                               n +
                                                               sizeof(UNICODE_NULL),
                                                               'sUpP');
        if (!(*UnicodeStringList)[i].Buffer)
        {
            /* Back out of everything */
            PnpFreeUnicodeStringList(*UnicodeStringList, i);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Make sure there's an actual string here */
        if (n) RtlCopyMemory((*UnicodeStringList)[i].Buffer, ps, n);

        /* Null-terminate the string ourselves */
        (*UnicodeStringList)[i].Buffer[n / sizeof(WCHAR)] = UNICODE_NULL;

        /* Set the lengths */
        (*UnicodeStringList)[i].Length = (USHORT)n;
        (*UnicodeStringList)[i].MaximumLength = (USHORT)(n + sizeof(UNICODE_NULL));
    }

    /* And we're done */
    *UnicodeStringCount = Count;
    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
PnpRegSzToString(IN PWCHAR RegSzData,
                 IN ULONG RegSzLength,
                 OUT PUSHORT StringLength OPTIONAL)
{
    PWCHAR p, pp;

    /* Find the end */
    pp = RegSzData + RegSzLength;
    for (p = RegSzData; p < pp; p++) if (!*p) break;

    /* Return it */
    if (StringLength) *StringLength = (USHORT)(p - RegSzData) * sizeof(WCHAR);
    return TRUE;
}

PDEVICE_OBJECT
NTAPI
IopDeviceObjectFromDeviceInstance(
    _In_ PUNICODE_STRING DeviceInstance)
{
    PPNP_DEVICE_INSTANCE_CONTEXT Entry;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_NODE DeviceNode;
    PNP_DEVICE_INSTANCE_CONTEXT MapContext;

    PAGED_CODE();
    DPRINT("IopDeviceObjectFromDeviceInstance: DeviceInstance %wZ\n", DeviceInstance);

    MapContext.DeviceObject = NULL;
    MapContext.InstancePath = DeviceInstance;

    KeAcquireGuardedMutex(&PpDeviceReferenceTableLock);

    Entry = RtlLookupElementGenericTableAvl(&PpDeviceReferenceTable, &MapContext);
    if (!Entry)
    {
        KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);
        return NULL;
    }

    DeviceObject = Entry->DeviceObject;
    ASSERT(DeviceObject);
    if (!DeviceObject)
    {
        KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);
        return NULL;
    }

    if (DeviceObject->Type != IO_TYPE_DEVICE)
    {
        ASSERT(DeviceObject->Type == IO_TYPE_DEVICE);
        KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);
        return NULL;
    }

    DeviceNode = IopGetDeviceNode(DeviceObject);

    ASSERT(DeviceNode && (DeviceNode->PhysicalDeviceObject == DeviceObject));

    if (!DeviceNode || DeviceNode->PhysicalDeviceObject != DeviceObject)
    {
        DeviceObject = NULL;
    }

    if (DeviceObject)
    {
        ObReferenceObject(DeviceObject);
    }

    KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);
    return DeviceObject;
}

NTSTATUS
NTAPI
IopMapDeviceObjectToDeviceInstance(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PUNICODE_STRING InstancePath)
{
    PDEVICE_OBJECT OldDeviceObject;
    NTSTATUS Status = STATUS_SUCCESS;
    PNP_DEVICE_INSTANCE_CONTEXT MapContext;
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    HANDLE EnumHandle;
    HANDLE ControlHandle;
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    PVOID Data;

    PAGED_CODE();

    DPRINT("IopMapDeviceObjectToDeviceInstance: DeviceObject - %p, InstancePath - %wZ\n",
           DeviceObject, InstancePath);

    OldDeviceObject = IopDeviceObjectFromDeviceInstance(InstancePath);
    ASSERT(!OldDeviceObject);
    if (OldDeviceObject)
    {
        ObDereferenceObject(OldDeviceObject);
    }

    MapContext.DeviceObject = DeviceObject;
    MapContext.InstancePath = InstancePath;

    KeAcquireGuardedMutex(&PpDeviceReferenceTableLock);

    Data = RtlInsertElementGenericTableAvl(&PpDeviceReferenceTable,
                                           &MapContext,
                                           sizeof(PNP_DEVICE_INSTANCE_CONTEXT),
                                           NULL);
    if (Data == NULL)
    {
        Status = STATUS_UNSUCCESSFUL;
    }

    KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopMapDeviceObjectToDeviceInstance: Status - %X\n", Status);
        return Status;
    }

    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  NULL,
                                  &EnumKeyName,
                                  KEY_READ);
    if (!NT_SUCCESS(Status))
    {
        ASSERT(NT_SUCCESS(Status));
        return STATUS_SUCCESS;
    }

    Status = IopOpenRegistryKeyEx(&EnumHandle,
                                  KeyHandle,
                                  InstancePath,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopMapDeviceObjectToDeviceInstance: Status - %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
        ZwClose(KeyHandle);
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&ValueName, L"Control");
    Status = IopCreateRegistryKeyEx(&ControlHandle,
                                    EnumHandle,
                                    &ValueName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_VOLATILE,
                                    NULL);
    if (NT_SUCCESS(Status))
    {
        ZwClose(InstancePath);
    }

    ZwClose(EnumHandle);
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopMapDeviceObjectToDeviceInstance: Status - %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopCleanupDeviceRegistryValues(
    _In_ PUNICODE_STRING InstancePath)
{
    PDEVICE_OBJECT DeviceObject;
    PNP_DEVICE_INSTANCE_CONTEXT MapContext;

    PAGED_CODE();
    DPRINT("IopCleanupDeviceRegistryValues: InstancePath - %wZ\n", InstancePath);

    MapContext.DeviceObject = 0;
    MapContext.InstancePath = InstancePath;

    KeAcquireGuardedMutex(&PpDeviceReferenceTableLock);
    RtlDeleteElementGenericTableAvl(&PpDeviceReferenceTable, &MapContext);
    KeReleaseGuardedMutex(&PpDeviceReferenceTableLock);

    DeviceObject = IopDeviceObjectFromDeviceInstance(InstancePath);
    if (DeviceObject)
    {
        ASSERT(!DeviceObject);
        ObDereferenceObject(DeviceObject);
    }

    return PpDeviceRegistration(InstancePath, FALSE, NULL);
}

NTSTATUS
NTAPI
PipApplyFunctionToSubKeys(
    _In_opt_ HANDLE RootHandle,
    _In_opt_ PUNICODE_STRING KeyName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UCHAR Flags,
    _In_ PIP_FUNCTION_TO_SUBKEYS Function,
    _In_ PVOID Context)
{
    PKEY_BASIC_INFORMATION KeyInfo = NULL;
    UNICODE_STRING SubKeyName;
    HANDLE KeyHandle;
    HANDLE SubKeyHandle;
    SIZE_T KeyInfoLen;
    ULONG ResultLength = 0;
    ULONG Index;
    NTSTATUS Status;
    NTSTATUS status;
    BOOLEAN IsOpenedKey = FALSE;
    BOOLEAN Result;

    DPRINT("PipApplyFunctionToSubKeys: RootHandle - %X, KeyName - %wZ, Flags - %X\n",
           RootHandle, KeyName, Flags);

    KeyHandle = RootHandle;

    if (KeyName)
    {
        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      RootHandle,
                                      KeyName,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PipApplyFunctionToSubKeys: error\n");
            return Status;
        }

        IsOpenedKey = TRUE;
    }

    Index = 0;
    KeyInfoLen = sizeof(KEY_BASIC_INFORMATION) + 20 * sizeof(WCHAR);

    while (TRUE)
    {
        while (TRUE)
        {
            if (!KeyInfo)
            {
                KeyInfo = ExAllocatePoolWithTag(PagedPool, KeyInfoLen, 'uspP');
                if (!KeyInfo)
                {
                    DPRINT("PipApplyFunctionToSubKeys: error\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Exit;
                }
            }

            status = ZwEnumerateKey(KeyHandle,
                                    Index,
                                    KeyBasicInformation,
                                    KeyInfo,
                                    KeyInfoLen,
                                    &ResultLength);

            DPRINT("PipApplyFunctionToSubKeys: Index - %X, KeyInfoLen - %X, ResultLength - %X\n",
                   Index, KeyInfoLen, ResultLength);

            if (!NT_SUCCESS(status))
            {
                DPRINT("PipApplyFunctionToSubKeys: status %X\n", status);
                break;
            }

            SubKeyName.Length = KeyInfo->NameLength;
            SubKeyName.MaximumLength = KeyInfo->NameLength;
            SubKeyName.Buffer = KeyInfo->Name;

            DPRINT("PipApplyFunctionToSubKeys: SubKeyName - %wZ\n", &SubKeyName);

            if (DesiredAccess)
            {
                Status = IopOpenRegistryKeyEx(&SubKeyHandle,
                                              KeyHandle,
                                              &SubKeyName,
                                              DesiredAccess);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipApplyFunctionToSubKeys: Status - %X\n", Status);

                    if (Flags & PIP_SUBKEY_FLAG_SKIP_ERROR)
                    {
                        goto Next;
                    }
                    else
                    {
                        DPRINT("PipApplyFunctionToSubKeys: error\n");
                        goto Exit;
                    }
                }
            }

            Result = Function(SubKeyHandle, &SubKeyName, Context);

            if (DesiredAccess)
            {
                if (Result && (Flags & PIP_SUBKEY_FLAG_DELETE_KEY))
                {
                    ZwDeleteKey(SubKeyHandle);
                }

                ZwClose(SubKeyHandle);
            }

            if (!Result)
            {
                Status = STATUS_SUCCESS;
                goto Exit;
            }

Next:
            if (!(Flags & PIP_SUBKEY_FLAG_DELETE_KEY))
            {
                Index++;
            }
        }

        if (status != STATUS_BUFFER_OVERFLOW &&
            status != STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }

        ExFreePoolWithTag(KeyInfo, 'uspP');

        KeyInfo = NULL;
        KeyInfoLen = ResultLength;
    }

    if (status == STATUS_NO_MORE_ENTRIES)
    {
        Status = STATUS_SUCCESS;
    }

Exit:

    if (KeyInfo)
    {
        ExFreePoolWithTag(KeyInfo, 'uspP');
    }
    if (IsOpenedKey)
    {
        ZwClose(KeyHandle);
    }

    return Status;
}

NTSTATUS
NTAPI
IopGetDeviceInstanceCsConfigFlags(
    _In_ PUNICODE_STRING InstanceName,
    _Out_ PULONG OutConfigFlagsValue)
{
    NTSTATUS Status;
    UNICODE_STRING KeyName;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    HANDLE KeyHandle;
    HANDLE Handle;
    UNICODE_STRING HwProfileKeyName = RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");

    PAGED_CODE();
    DPRINT("IopGetDeviceInstanceCsConfigFlags: InstanceName - %wZ\n",
           InstanceName);

    *OutConfigFlagsValue = 0;

    Status = IopOpenRegistryKeyEx(&Handle,
                                  NULL,
                                  &HwProfileKeyName,
                                  KEY_READ);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceInstanceCsConfigFlags: Status - %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&KeyName, L"System\\CurrentControlSet");

    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  Handle,
                                  &KeyName,
                                  KEY_READ);

    ZwClose(Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceInstanceCsConfigFlags: Status - %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ENUM);

    Status = IopOpenRegistryKeyEx(&Handle,
                                  KeyHandle,
                                  &KeyName,
                                  KEY_READ);
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceInstanceCsConfigFlags: Status - %X\n", Status);
        return Status;
    }

    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  Handle,
                                  InstanceName,
                                  KEY_READ);
    ZwClose(Handle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceInstanceCsConfigFlags: Status - %X\n", Status);
        return Status;
    }

    Status = IopGetRegistryValue(KeyHandle,
                                 REGSTR_VAL_CSCONFIGFLAGS,
                                 &ValueInfo);
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceInstanceCsConfigFlags: Status - %X\n", Status);
        return Status;
    }

    if (ValueInfo->Type == REG_DWORD &&
        ValueInfo->DataLength >= sizeof(ULONG))
    {
        *OutConfigFlagsValue = *(PULONG)((ULONG_PTR)ValueInfo +
                                         ValueInfo->DataOffset);
    }

    ExFreePoolWithTag(ValueInfo, 'uspP');

    return Status;
}

NTSTATUS
NTAPI
PipOpenServiceEnumKeys(
    _In_ PUNICODE_STRING ServiceString,
    _In_ ACCESS_MASK Access,
    _Out_ PHANDLE OutServiceHandle,
    _Out_ PHANDLE OutEnumHandle,
    _In_ BOOLEAN IsCreateKey)
{
    NTSTATUS Status;
    UNICODE_STRING EnumName;
    HANDLE Handle;
    HANDLE EnumHandle;
    HANDLE ServiceHandle;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\");

    DPRINT("PipOpenServiceEnumKeys: ServiceString %wZ\n", ServiceString);

    Status = IopOpenRegistryKeyEx(&Handle,
                                  NULL,
                                  &KeyName,
                                  Access);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IopOpenRegistryKeyEx(&ServiceHandle,
                                  Handle,
                                  ServiceString,
                                  Access);

    ZwClose(Handle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipOpenServiceEnumKeys: Status - %X\n", Status);
        return Status;
    }

    if (!OutEnumHandle && !IsCreateKey)
    {
        if (OutServiceHandle)
        {
            *OutServiceHandle = ServiceHandle;
        }
        else
        {
            ZwClose(ServiceHandle);
        }

        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&EnumName, REGSTR_KEY_ENUM);

    if (IsCreateKey)
    {
        Status = IopCreateRegistryKeyEx(&EnumHandle,
                                        ServiceHandle,
                                        &EnumName,
                                        Access,
                                        REG_OPTION_VOLATILE,
                                        NULL);
    }
    else
    {
        Status = IopOpenRegistryKeyEx(&EnumHandle,
                                      ServiceHandle,
                                      &EnumName,
                                      Access);
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipOpenServiceEnumKeys: Status - %X\n", Status);
        ZwClose(ServiceHandle);
        return Status;
    }

    if (OutEnumHandle)
    {
        *OutEnumHandle = EnumHandle;
    }
    else
    {
        ZwClose(EnumHandle);
    }

    if (OutServiceHandle)
    {
        *OutServiceHandle = ServiceHandle;
    }
    else
    {
        ZwClose(ServiceHandle);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopOpenDeviceParametersSubkey(
    _Out_ PHANDLE OutHandle,
    _In_opt_ HANDLE ParentKey,
    _In_ PUNICODE_STRING NameString,
    _In_ ACCESS_MASK Access)
{
    UNICODE_STRING ParametersName;
    ULONG Disposition;
    HANDLE KeyHandle;
    ULONG ReturnLength;
    NTSTATUS Status;

    DPRINT("IopOpenDeviceParametersSubkey: NameString - %wZ\n", NameString);

    Status = IopOpenRegistryKeyEx(&KeyHandle, ParentKey, NameString, KEY_WRITE);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopOpenDeviceParametersSubkey: Status - %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&ParametersName, L"Device Parameters");

    Status = IopCreateRegistryKeyEx(OutHandle,
                                    KeyHandle,
                                    &ParametersName,
                                    Access | (WRITE_DAC | READ_CONTROL),
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition );
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopOpenDeviceParametersSubkey: Status - %X\n", Status);
        return Status;
    }

    if (Disposition != REG_CREATED_NEW_KEY)
    {
        return STATUS_SUCCESS;
    }

    Status = ZwQuerySecurityObject(*OutHandle,
                                   DACL_SECURITY_INFORMATION,
                                   NULL,
                                   0,
                                   &ReturnLength);

    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        DPRINT("IopOpenDeviceParametersSubkey: Status - %X\n", Status);
        return STATUS_SUCCESS;
    }

    DPRINT("IopOpenDeviceParametersSubkey: FIXME SecurityObject\n");
    //ASSERT(FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopReplaceSeparatorWithPound(
    _Out_ PUNICODE_STRING OutString,
    _In_ PUNICODE_STRING InString)
{
    NTSTATUS Status;
    PWSTR InChar;
    PWSTR OutChar;
    USHORT InStringLen;
    ULONG ix;

    PAGED_CODE();

    ASSERT(InString);
    ASSERT(OutString);

    if (InString->Length > OutString->MaximumLength)
    {
        Status = STATUS_BUFFER_TOO_SMALL;
        return Status;
    }

    InChar = InString->Buffer;
    OutChar = OutString->Buffer;

    InStringLen = InString->Length / sizeof(WCHAR);

    for (ix = 0; ix < InStringLen; ix++, InChar++, OutChar++)
    {
        if (*InChar == '\\' || *InChar == '//')
        {
            *OutChar = '#';
        }
        else
        {
            *OutChar = *InChar;
        }
    }

    OutString->Length = InString->Length;

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
IopIsDeviceInstanceEnabled(
    _In_ HANDLE InstanceKeyHandle,
    _In_ PUNICODE_STRING Instance,
    _In_ BOOLEAN IsDisableDevice)
{
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING ControlName;
    PKEY_VALUE_FULL_INFORMATION KeyInfo;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_NODE DeviceNode;
    HANDLE EnumKeyHandle;
    HANDLE KeyHandle;
    ULONG DisableCountValue;
    ULONG ConfigFlags;
    NTSTATUS Status;
    BOOLEAN IsOpenedEnum = FALSE;
    BOOLEAN Result = TRUE;

    PAGED_CODE();
    DPRINT("IopIsDeviceInstanceEnabled: Instance - %wZ, IsDisableDevice - %X\n",
           Instance, IsDisableDevice);

    DeviceObject = IopDeviceObjectFromDeviceInstance(Instance);

    if (DeviceObject)
    {
        DeviceNode = IopGetDeviceNode(DeviceObject);
    }
    else
    {
        DeviceNode = NULL;
    }

    if (DeviceNode)
    {
        if ((DeviceNode->Flags & DNF_HAS_PROBLEM &&
             DeviceNode->Problem == CM_PROB_DISABLED) ||
            (DeviceNode->Flags & DNF_HAS_PROBLEM &&
             DeviceNode->Problem == CM_PROB_HARDWARE_DISABLED))
        {
            Result = FALSE;
            goto Exit;
        }
    }

    if (!InstanceKeyHandle)
    {
        Status = IopOpenRegistryKeyEx(&EnumKeyHandle,
                                      NULL,
                                      &EnumKeyName,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            Result = FALSE;
            goto Exit;
        }

        Status = IopOpenRegistryKeyEx(&InstanceKeyHandle,
                                      EnumKeyHandle,
                                      Instance,
                                      KEY_READ);
        ZwClose(EnumKeyHandle);

        if (!NT_SUCCESS(Status))
        {
            Result = FALSE;
            goto Exit;
        }

        IsOpenedEnum = TRUE;
    }

    ConfigFlags = 0;

    Status = IopGetRegistryValue(InstanceKeyHandle,
                                 L"ConfigFlags",
                                 &KeyInfo);

    if (NT_SUCCESS(Status))
    {
        if (KeyInfo->Type == REG_DWORD &&
            KeyInfo->DataLength == sizeof(ULONG))
        {
            ConfigFlags = *(PULONG)((ULONG_PTR)&KeyInfo->TitleIndex +
                                    KeyInfo->DataOffset);
        }

        ExFreePoolWithTag(KeyInfo, 'uspP');
    }

    if (ConfigFlags & 1)
    {
        ConfigFlags = 1;
    }
    else
    {
        IopGetDeviceInstanceCsConfigFlags(Instance, &ConfigFlags);
    }

    if (!(ConfigFlags & 7))
    {
        RtlInitUnicodeString(&ControlName, L"Control");

        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      InstanceKeyHandle,
                                      &ControlName,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }

        DisableCountValue = 0;

        Status = IopGetRegistryValue(KeyHandle,
                                     L"DisableCount",
                                     &KeyInfo);
        if (NT_SUCCESS(Status))
        {
            if (KeyInfo->Type == REG_DWORD &&
                KeyInfo->DataLength == sizeof(ULONG))
            {
                DisableCountValue = *(PULONG)((ULONG_PTR)&KeyInfo->TitleIndex +
                                              KeyInfo->DataOffset);
            }

            ExFreePoolWithTag(KeyInfo, 'uspP');
        }

        ZwClose(KeyHandle);

        if (!DisableCountValue)
        {
            goto Exit;
        }
    }

    Result = FALSE;

    if (IsDisableDevice &&
        DeviceNode &&
        DeviceNode->State != DeviceNodeUninitialized)
    {
        DPRINT("IopIsDeviceInstanceEnabled: FIXME IopDisableDevice()\n");
        ASSERT(FALSE);
        //IopDisableDevice(DeviceNode);
    }

Exit:

    if (DeviceObject)
    {
        ObDereferenceObject(DeviceObject);
    }

    if (IsOpenedEnum)
    {
        ZwClose(InstanceKeyHandle);
    }

    return Result;
}

NTSTATUS
NTAPI
IopGetDriverNameFromKeyNode(
    _In_ HANDLE KeyHandle,
    _Inout_ PUNICODE_STRING OutDriverName)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PKEY_BASIC_INFORMATION KeyBasicInfo;
    UNICODE_STRING DriverNameString;
    PWSTR DriverName;
    PWCHAR Buffer;
    PWCHAR pChar;
    ULONG ResultLength;
    ULONG ServiceType;
    ULONG Len;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopGetDriverNameFromKeyNode()\n");

    Status = IopGetRegistryValue(KeyHandle, L"ObjectName", &ValueInfo);

    if (NT_SUCCESS(Status))
    {
        if (ValueInfo->DataLength == 0 || ValueInfo->DataLength == 1)
        {
            ExFreePoolWithTag(ValueInfo, 'uspP');
            return STATUS_ILL_FORMED_SERVICE_ENTRY;
        }

        OutDriverName->Length = ValueInfo->DataLength - sizeof(WCHAR);
        OutDriverName->MaximumLength = ValueInfo->DataLength;

        Buffer = (PWCHAR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);
        Len = OutDriverName->Length / sizeof(WCHAR);

        for (pChar = (PWCHAR)ValueInfo; Len; Len--)
        {
            *pChar = *Buffer;
            pChar++;
            Buffer++;
        }

        OutDriverName->Buffer = (PWSTR)ValueInfo;

        return STATUS_SUCCESS;
    }

    Status = IopGetRegistryValue(KeyHandle, L"Type", &ValueInfo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDriverNameFromKeyNode: Status - %X\n", Status);
        return STATUS_ILL_FORMED_SERVICE_ENTRY;
    }

    if (!ValueInfo->DataLength)
    {
        ExFreePoolWithTag(ValueInfo, 'uspP');
        return STATUS_ILL_FORMED_SERVICE_ENTRY;
    }

    ServiceType = *(PULONG)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);

    if (ServiceType == SERVICE_FILE_SYSTEM_DRIVER ||
        ServiceType == SERVICE_RECOGNIZER_DRIVER)
    {
        DriverName = L"\\FileSystem\\";
    }
    else
    {
        DriverName = L"\\Driver\\";
    }

    OutDriverName->Length = wcslen(DriverName) * sizeof(WCHAR);

    ZwQueryKey(KeyHandle, KeyBasicInformation, NULL, 0, &ResultLength);

    KeyBasicInfo = ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG_IO);

    if (!KeyBasicInfo)
    {
        DPRINT1("IopGetDriverNameFromKeyNode: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ValueInfo, 'uspP');
        return Status;
    }

    Status = ZwQueryKey(KeyHandle,
                        KeyBasicInformation,
                        KeyBasicInfo,
                        ResultLength,
                        &ResultLength);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDriverNameFromKeyNode: Status - %X\n", Status);
        goto Exit;
    }

    OutDriverName->MaximumLength = KeyBasicInfo->NameLength +
                                   OutDriverName->Length;

    OutDriverName->Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                                  OutDriverName->MaximumLength,
                                                  TAG_IO);
    if (!OutDriverName->Buffer)
    {
        DPRINT1("IopGetDriverNameFromKeyNode: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    OutDriverName->Length = 0;
    RtlAppendUnicodeToString(OutDriverName, DriverName);

    DriverNameString.Length = KeyBasicInfo->NameLength;
    DriverNameString.MaximumLength = DriverNameString.Length;
    DriverNameString.Buffer = KeyBasicInfo->Name;

    RtlAppendUnicodeStringToString(OutDriverName, &DriverNameString);

    Status = STATUS_SUCCESS;

Exit:

    ExFreePoolWithTag(KeyBasicInfo, TAG_IO);
    ExFreePoolWithTag(ValueInfo, 'uspP');

    return Status;
}

NTSTATUS
NTAPI
PipServiceInstanceToDeviceInstance(
    _In_ HANDLE ServiceKeyHandle,
    _In_ PUNICODE_STRING ServiceKeyName,
    _In_ ULONG InstanceNum,
    _Out_ PUNICODE_STRING OutInstanceName,
    _Out_ PHANDLE OutHandle,
    _In_ ACCESS_MASK DesiredAccess)
{
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING InstanceName;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    HANDLE Handle;
    WCHAR Buffer[20];
    NTSTATUS Status;
    USHORT Length;

    DPRINT("PipServiceInstanceToDeviceInstance: ServiceKeyName - %wZ, InstanceNum - %X\n",
           ServiceKeyName, InstanceNum);

    if (ServiceKeyHandle)
    {
        RtlInitUnicodeString(&InstanceName, L"Enum");

        Status = IopOpenRegistryKeyEx(&Handle,
                                      ServiceKeyHandle,
                                      &InstanceName,
                                      KEY_READ);
    }
    else
    {
        Status = PipOpenServiceEnumKeys(ServiceKeyName,
                                        KEY_READ,
                                        NULL,
                                        &Handle,
                                        FALSE);
    }

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    RtlStringCbPrintfW(Buffer,
                       20 * sizeof(WCHAR),
                       L"%u",
                       InstanceNum);

    Status = IopGetRegistryValue(Handle, Buffer, &ValueInfo);

    ZwClose(Handle);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (ValueInfo->Type == REG_SZ)
    {
        PnpRegSzToString((PWCHAR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset),
                                  ValueInfo->DataLength,
                                  &Length);

        InstanceName.Length = Length;
        InstanceName.MaximumLength = ValueInfo->DataLength;

        InstanceName.Buffer = (PWSTR)((ULONG_PTR)ValueInfo +
                                      ValueInfo->DataOffset);

        if (!Length)
        {
            Status = STATUS_OBJECT_PATH_NOT_FOUND;
        }
    }
    else
    {
        Status = STATUS_INVALID_PLUGPLAY_DEVICE_PATH;
    }

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (OutHandle)
    {
        Status = IopOpenRegistryKeyEx(&Handle,
                                      NULL,
                                      &EnumKeyName,
                                      KEY_READ);

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }

        Status = IopOpenRegistryKeyEx(OutHandle,
                                      Handle,
                                      &InstanceName,
                                      DesiredAccess);

        ZwClose(Handle);

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }
    }

    if (!OutInstanceName)
    {
        goto Exit;
    }

    Status = PnpConcatenateUnicodeStrings(OutInstanceName,
                                          &InstanceName,
                                          NULL);

    if (!NT_SUCCESS(Status))
    {
        if (OutHandle)
        {
            ZwClose(*OutHandle);
        }
    }

Exit:

    ExFreePoolWithTag(ValueInfo, 'uspP');
    return Status;
}

BOOLEAN
NTAPI
IopIsAnyDeviceInstanceEnabled(
    _In_ PUNICODE_STRING ServiceKeyName,
    _In_ HANDLE ServiceKeyHandle,
    _In_ BOOLEAN IsLegacyDriver)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING DeviceInstance;
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    HANDLE LegacyHandle;
    HANDLE EnumHandle;
    ULONG LegacyValue;
    ULONG Count;
    ULONG ix;
    NTSTATUS Status;
    BOOLEAN IsEnabled;
    BOOLEAN Result = FALSE;
    BOOLEAN IsOpenService = FALSE;

    PAGED_CODE();
    DPRINT("IopIsAnyDeviceInstanceEnabled: ServiceKeyName - %wZ, IsLegacyDriver - %X\n",
           ServiceKeyName, IsLegacyDriver);

    if (ServiceKeyHandle)
    {
        RtlInitUnicodeString(&ValueName, L"Enum");

        Status = IopOpenRegistryKeyEx(&EnumHandle,
                                      ServiceKeyHandle,
                                      &ValueName,
                                      KEY_READ);
    }
    else
    {
        Status = PipOpenServiceEnumKeys(ServiceKeyName,
                                        KEY_READ,
                                        &ServiceKeyHandle,
                                        &EnumHandle,
                                        FALSE);
        if (!NT_SUCCESS(Status))
        {
            return Result;
        }

        IsOpenService = TRUE;
    }

    if (!NT_SUCCESS(Status))
    {
        if (IsOpenService)
        {
            ZwClose(ServiceKeyHandle);
        }

        return Result;
    }

    Count = 0;

    Status = IopGetRegistryValue(EnumHandle, L"Count", &ValueInfo);

    if (NT_SUCCESS(Status))
    {
        if (ValueInfo->Type == REG_DWORD &&
            ValueInfo->DataLength >= sizeof(ULONG))
        {
            Count = *(PULONG)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);
        }

        ExFreePoolWithTag(ValueInfo, 'uspP');
    }
    else
    {
        DPRINT("IopIsAnyDeviceInstanceEnabled: Status - %X\n", Status);
    }

    ZwClose(EnumHandle);

    if (!Count)
    {
        if (IsOpenService)
        {
            ZwClose(ServiceKeyHandle);
        }
        return Result;
    }

    for (ix = 0; ix < Count; ix++)
    {
        Status = PipServiceInstanceToDeviceInstance(ServiceKeyHandle,
                                                    NULL,
                                                    ix,
                                                    &DeviceInstance,
                                                    &LegacyHandle,
                                                    KEY_ALL_ACCESS);
        if (!NT_SUCCESS(Status))
        {
            continue;
        }

        IsEnabled = IopIsDeviceInstanceEnabled(NULL, &DeviceInstance, TRUE);

        ExFreePoolWithTag(DeviceInstance.Buffer, '  pP');

        if (!IsEnabled)
        {
            ZwClose(LegacyHandle);
            continue;
        }

        LegacyValue = 0;

        if (!IsLegacyDriver)
        {
            Status = IopGetRegistryValue(LegacyHandle,
                                         L"Legacy",
                                         &ValueInfo);

            if (NT_SUCCESS(Status))
            {
                if (ValueInfo->Type == REG_DWORD &&
                    ValueInfo->DataLength == sizeof(ULONG))
                {
                    LegacyValue = *(PULONG)((ULONG_PTR)ValueInfo +
                                            ValueInfo->DataOffset);
                }

                ExFreePoolWithTag(ValueInfo, 'uspP');

                if (LegacyValue)
                {
                    ZwClose(LegacyHandle);
                    continue;
                }
            }
        }

        RtlInitUnicodeString(&ValueName, L"Control");

        Status = IopCreateRegistryKeyEx(&KeyHandle,
                                        LegacyHandle,
                                        &ValueName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_VOLATILE,
                                        NULL);
        if (NT_SUCCESS(Status))
        {
            RtlInitUnicodeString(&ValueName, L"ActiveService");

            ZwSetValueKey(KeyHandle,
                          &ValueName,
                          0,
                          REG_SZ,
                          ServiceKeyName->Buffer,
                          ServiceKeyName->Length + sizeof(WCHAR));

            ZwClose(KeyHandle);
        }
        else
        {
            DPRINT("IopIsAnyDeviceInstanceEnabled: Status - %X\n", Status);
        }

        Result = TRUE;

        ZwClose(LegacyHandle);
    }

    if (IsOpenService)
    {
        ZwClose(ServiceKeyHandle);
    }

    return Result;
}

PIO_RESOURCE_REQUIREMENTS_LIST
NTAPI
IopCmResourcesToIoResources(
    _In_ ULONG Slot,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG Priority)
{
    PCM_FULL_RESOURCE_DESCRIPTOR CmFullList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor0;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    INTERFACE_TYPE InterfaceType;
    ULONG PartialCount = 0;
    ULONG IoResourceSize;
    ULONG IoCount;
    ULONG ix;
    ULONG jx;

    PAGED_CODE();
    DPRINT("IopCmResourcesToIoResources: Slot - %X, CmResource - %p, CmResourceCount - %X, Priority - %X\n",
           Slot, CmResource, CmResource->Count, Priority);

    if (CmResource->Count <= 0)
    {
        ASSERT(FALSE);
        return NULL;
    }

    CmFullList = &CmResource->List[0];

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        CmDescriptor = CmFullList->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < CmFullList->PartialResourceList.Count; jx++)
        {
            PartialCount++;
            CmDescriptor = IopGetNextCmPartialDescriptor(CmDescriptor);
        }

        CmFullList = (PCM_FULL_RESOURCE_DESCRIPTOR)CmDescriptor;
    }

    if (!PartialCount)
    {
        IopDumpCmResourceList(CmResource);
        ASSERT(FALSE);
        return NULL;
    }

    IoCount = CmResource->Count + PartialCount;

    IoResourceSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) +
                     IoCount * sizeof(IO_RESOURCE_DESCRIPTOR);

    IoResource = ExAllocatePoolWithTag(PagedPool, IoResourceSize, 'uspP');

    if (!IoResource)
    {
        DPRINT1("IopCmResourcesToIoResources: Allocate failed!\n");
        ASSERT(FALSE);
        return NULL;
    }

    DPRINT("IopCmResourcesToIoResources: [%p] IoCount - %X, IoResourceSize - %X\n",
           IoResource, IoCount, IoResourceSize);

    CmFullList = CmResource->List;

    IoResource->InterfaceType = CmResource->List[0].InterfaceType;
    IoResource->BusNumber = CmResource->List[0].BusNumber;
    IoResource->SlotNumber = Slot;
    IoResource->AlternativeLists = 1;

    IoResource->List[0].Version = 1;
    IoResource->List[0].Revision = 1;
    IoResource->List[0].Count = IoCount;

    IoResource->Reserved[0] = 0;
    IoResource->Reserved[1] = 0;
    IoResource->Reserved[2] = 0;

    IoDescriptor0 = &IoResource->List[0].Descriptors[0];

    IoDescriptor0->Option = IO_RESOURCE_PREFERRED;
    IoDescriptor0->Type = CmResourceTypeConfigData;
    IoDescriptor0->ShareDisposition = CmResourceShareShared;
    IoDescriptor0->Flags = 0;
    IoDescriptor0->Spare1 = 0;
    IoDescriptor0->Spare2 = 0;
    IoDescriptor0->u.ConfigData.Priority = Priority;

    IoDescriptor = &IoResource->List[0].Descriptors[1];

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        if (ix > 0)
        {
            IoDescriptor->Option = IO_RESOURCE_PREFERRED;
            IoDescriptor->Type = 0xF0;
            IoDescriptor->ShareDisposition = CmResourceShareUndetermined;
            IoDescriptor->Flags = 0;
            IoDescriptor->Spare1 = 0;
            IoDescriptor->Spare2 = 0;

            if (CmFullList->InterfaceType == InterfaceTypeUndefined)
            {
                InterfaceType = PnpDefaultInterfaceType;
            }
            else
            {
                InterfaceType = CmFullList->InterfaceType;
            }

            IoDescriptor->u.Port.Length = InterfaceType;
            IoDescriptor->u.Port.Alignment = CmFullList->BusNumber;
            IoDescriptor->u.Port.MinimumAddress.LowPart = 0;

            IoDescriptor++;
        }

        CmDescriptor = CmFullList->PartialResourceList.PartialDescriptors;

        if (CmFullList->PartialResourceList.Count > 0)
        {
            for (jx = 0; jx < CmFullList->PartialResourceList.Count; jx++)
            {
                IoDescriptor->Option = IO_RESOURCE_PREFERRED;
                IoDescriptor->Type = CmDescriptor->Type;
                IoDescriptor->ShareDisposition = CmDescriptor->ShareDisposition;
                IoDescriptor->Flags = CmDescriptor->Flags;
                IoDescriptor->Spare1 = 0;
                IoDescriptor->Spare2 = 0;

                if (CmDescriptor->Type == CmResourceTypeDeviceSpecific)
                {
                    /* Not used within IO_RESOURCE_DESCRIPTOR */

                    CmDescriptor = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)
                                    ((ULONG_PTR)CmDescriptor +
                                     sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) +
                                     CmDescriptor->u.DeviceSpecificData.DataSize);
                    continue;
                }

                switch (CmDescriptor->Type)
                {
                    case 1:
                    case 3:
                        IoDescriptor->u.Generic.Length = CmDescriptor->u.Generic.Length;
                        IoDescriptor->u.Generic.Alignment = 1;
                        IoDescriptor->u.Generic.MinimumAddress.QuadPart = CmDescriptor->u.Generic.Start.QuadPart;
                        IoDescriptor->u.Generic.MaximumAddress.QuadPart = CmDescriptor->u.Generic.Start.QuadPart +
                                                                          (ULONG)(CmDescriptor->u.Generic.Length - 1);
                        break;
                    case 2:
                        IoDescriptor->u.Interrupt.MinimumVector = CmDescriptor->u.Interrupt.Vector;
                        IoDescriptor->u.Interrupt.MaximumVector = CmDescriptor->u.Interrupt.Vector;
                        break;
                    case 4:
                        IoDescriptor->u.Dma.MinimumChannel = CmDescriptor->u.Dma.Channel;
                        IoDescriptor->u.Dma.MaximumChannel = CmDescriptor->u.Dma.Channel;
                        break;
                    case 6:
                        IoDescriptor->u.BusNumber.Length = CmDescriptor->u.BusNumber.Length;
                        IoDescriptor->u.BusNumber.MinBusNumber = CmDescriptor->u.BusNumber.Start;
                        IoDescriptor->u.BusNumber.MaxBusNumber = CmDescriptor->u.BusNumber.Start +
                                                                 CmDescriptor->u.BusNumber.Length - 1;
                        break;
                    default:
                        IoDescriptor->u.DevicePrivate.Data[0] = CmDescriptor->u.DevicePrivate.Data[0];
                        IoDescriptor->u.DevicePrivate.Data[1] = CmDescriptor->u.DevicePrivate.Data[1];
                        IoDescriptor->u.DevicePrivate.Data[2] = CmDescriptor->u.DevicePrivate.Data[2];
                        break;
                }

                IoDescriptor++;

                CmDescriptor = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)
                                ((ULONG_PTR)CmDescriptor +
                                 sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
            }
        }

        CmFullList = (PCM_FULL_RESOURCE_DESCRIPTOR)CmDescriptor;
    }

    IoResource->ListSize = (ULONG_PTR)IoDescriptor - (ULONG_PTR)IoResource;

    DPRINT("IopCmResourcesToIoResources: AlternativeLists - %X, ListSize - %X\n",
           IoResource->AlternativeLists, IoResource->ListSize);

    return IoResource;
}

/* EOF */
