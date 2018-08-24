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
    DPRINT("IopIsAnyDeviceInstanceEnabled: InstancePath - %wZ\n", InstancePath);

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

/* EOF */
