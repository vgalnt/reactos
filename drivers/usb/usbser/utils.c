/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver utils functions.
 * COPYRIGHT:   Copyright 2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES ******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

/* GLOBALS ********************************************************************/

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
UsbSerSyncCompletion(IN PDEVICE_OBJECT DeviceObject,
                     IN PIRP Irp,
                     IN PVOID Context)
{
    PKEVENT Event = Context;

    DPRINT("UsbSerSyncCompletion: DeviceObject %p, Irp %p\n", DeviceObject, Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
UsbSerGetRegistryKeyValue(IN HANDLE KeyHandle,
                          IN PWSTR ValueString,
                          IN ULONG ValueStringSize,
                          OUT PWSTR OutKeyValue,
                          IN ULONG MaxDataLength)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING ValueName;
    ULONG Length;
    NTSTATUS Status;

    DPRINT("UsbSerGetRegistryKeyValue: ValueString '%S'\n", ValueString);
    PAGED_CODE();

    RtlInitUnicodeString(&ValueName, ValueString);

    Length = ValueStringSize + MaxDataLength + sizeof(KEY_VALUE_FULL_INFORMATION);

    ValueInfo = ExAllocatePoolWithTag(PagedPool, Length, USBSER_TAG);
    if (!ValueInfo)
    {
        DPRINT1("UsbSerGetRegistryKeyValue: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValueFullInformation,
                             ValueInfo,
                             Length,
                             &Length);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("UsbSerGetRegistryKeyValue: Status %X\n", Status);
        ExFreePoolWithTag(ValueInfo, USBSER_TAG);
        return Status;
    }

    if (ValueInfo->DataLength > MaxDataLength)
    {
        DPRINT1("UsbSerGetRegistryKeyValue: Status %X, Length %X, MaxLength %X\n", Status, ValueInfo->DataLength, MaxDataLength);
        ExFreePoolWithTag(ValueInfo, USBSER_TAG);
        return Status;
    }

    RtlCopyMemory(OutKeyValue,
                  (PCHAR)ValueInfo + ValueInfo->DataOffset,
                  ValueInfo->DataLength);

    ExFreePoolWithTag(ValueInfo, USBSER_TAG);

    return Status;
}

/* EOF */
