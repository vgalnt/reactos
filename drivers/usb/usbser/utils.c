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

VOID
NTAPI
UsbSerFetchBooleanLocked(OUT BOOLEAN * OutBoolean,
                         IN BOOLEAN BooleanValue,
                         IN PKSPIN_LOCK SpinLock)
{
    KIRQL Irql;

    KeAcquireSpinLock(SpinLock, &Irql);
    *OutBoolean = BooleanValue;
    KeReleaseSpinLock(SpinLock, Irql);
}

VOID
NTAPI
UsbSerFetchPVoidLocked(OUT PVOID * OutPVoid,
                       IN PVOID PVoid,
                       IN PKSPIN_LOCK SpinLock)
{
    KIRQL Irql;

    KeAcquireSpinLock(SpinLock, &Irql);
    *OutPVoid = PVoid;
    KeReleaseSpinLock(SpinLock, Irql);
}

NTSTATUS
NTAPI
UsbSerSyncCompletion(IN PDEVICE_OBJECT DeviceObject,
                     IN PIRP Irp,
                     IN PVOID Context)
{
    PKEVENT Event = Context;

    //DPRINT("UsbSerSyncCompletion: DeviceObject %p, Irp %p\n", DeviceObject, Irp);

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

/* DPC FUNCTIONS *************************************************************/

VOID
NTAPI
UsbSerReadTimeout(IN PKDPC Dpc,
                  IN PVOID DeferredContext,
                  IN PVOID SystemArgument1,
                  IN PVOID SystemArgument2)
{
    PUSBSER_DEVICE_EXTENSION Extension = DeferredContext;
    KIRQL Irql;

    DPRINT("UsbSerReadTimeout: Extension %X\n", Extension);

    IoAcquireCancelSpinLock(&Irql);

    Extension->CountOnLastRead = -2;
    UsbSerGrabReadFromRx(Extension);

    UsbSerTryToCompleteCurrent(Extension,
                               Irql,
                               STATUS_TIMEOUT,
                               &Extension->CurrentReadIrp,
                               &Extension->ReadQueueList,
                               &Extension->ReadRequestIntervalTimer,
                               &Extension->ReadRequestTotalTimer,
                               UsbSerStartRead,
                               UsbSerGetNextIrp,
                               4,
                               TRUE);
}

VOID
NTAPI
UsbSerIntervalReadTimeout(IN PKDPC Dpc,
                          IN PVOID DeferredContext,
                          IN PVOID SystemArgument1,
                          IN PVOID SystemArgument2)
{
    DPRINT1("UsbSerIntervalReadTimeout: FIXME UsbSerIntervalReadTimeout()\n");
}

VOID
NTAPI
UsbSerWriteTimeout(IN PKDPC Dpc,
                   IN PVOID DeferredContext,
                   IN PVOID SystemArgument1,
                   IN PVOID SystemArgument2)
{
    PUSBSER_WRITE_CONTEXT WriteCtx = DeferredContext;
    BOOLEAN Result;

    DPRINT("UsbSerWriteTimeout: WriteCtx %p, Irp %p\n", WriteCtx, WriteCtx->Irp);

    Result = IoCancelIrp(WriteCtx->Irp);
    if (Result)
    {
        DPRINT1("UsbSerWriteTimeout: Irp is cancelled\n");
        WriteCtx->Status = STATUS_TIMEOUT;
    }
}

/* EOF */
