/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver pnp functions.
 * COPYRIGHT:   Copyright 2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES ******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

/* GLOBALS ********************************************************************/

extern KSPIN_LOCK GlobalSpinLock;
extern BOOLEAN Slots[0x100];
extern ULONG NumDevices;

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
UsbSerDoExternalNaming(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    UNICODE_STRING SymLinkName;
    PWSTR RegSymbolicName;
    HANDLE KeyHandle;
    USHORT MaxLength;
    USHORT MaximumSize;
    NTSTATUS Status;

    DPRINT("UsbSerDoExternalNaming: Extension %p\n", Extension);
    PAGED_CODE();

    MaxLength = (USBSER_MAX_SYMBOLIC_NAME_LENGTH * sizeof(WCHAR));
    MaximumSize = (MaxLength + sizeof(WCHAR));

    SymLinkName.Length = 0;
    SymLinkName.MaximumLength = MaxLength;

    SymLinkName.Buffer = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!SymLinkName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(SymLinkName.Buffer, MaximumSize);

    RegSymbolicName = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!RegSymbolicName)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    Status = IoOpenDeviceRegistryKey(Extension->PhysicalDevice,
                                     PLUGPLAY_REGKEY_DEVICE,
                                     STANDARD_RIGHTS_READ,
                                     &KeyHandle);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT("UsbSerDoExternalNaming: Status %p\n", Status);
        goto ErrorExit;
    }

    Status = UsbSerGetRegistryKeyValue(KeyHandle,
                                       L"PortName",
                                       sizeof(L"PortName"),
                                       RegSymbolicName,
                                       MaxLength);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);

        Status = UsbSerGetRegistryKeyValue(KeyHandle,
                                           L"Identifier",
                                           sizeof(L"Identifier"),
                                           RegSymbolicName,
                                           MaxLength);
        if (Status != STATUS_SUCCESS)
        {
            DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);
            ZwClose(KeyHandle);
            goto ErrorExit;
        }
    }

    ZwClose(KeyHandle);

    DPRINT("UsbSerDoExternalNaming: FIXME WmiId\n");

    RtlAppendUnicodeToString(&SymLinkName, L"\\");
    RtlAppendUnicodeToString(&SymLinkName, L"DosDevices");
    RtlAppendUnicodeToString(&SymLinkName, L"\\");
    RtlAppendUnicodeToString(&SymLinkName, RegSymbolicName);

    MaxLength = (SymLinkName.Length + sizeof(WCHAR));
    Extension->SymLinkName.MaximumLength = MaxLength;

    Extension->SymLinkName.Buffer = ExAllocatePoolWithTag(PagedPool, MaxLength, USBSER_TAG);
    if (!Extension->SymLinkName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(Extension->SymLinkName.Buffer, MaxLength);

    RtlAppendUnicodeStringToString(&Extension->SymLinkName, &SymLinkName);

    DPRINT1("UsbSerDoExternalNaming: '%wZ', '%wZ'\n", &Extension->DeviceName, &Extension->SymLinkName);

    Status = IoCreateSymbolicLink(&Extension->SymLinkName, &Extension->DeviceName);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);
        goto ErrorExit;
    }

    Extension->IsSymLinkCreated = TRUE;

    MaxLength = (USBSER_MAX_DOS_NAME_LENGTH * sizeof(WCHAR));
    MaximumSize = (MaxLength + sizeof(WCHAR));

    Extension->DosName.Buffer = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!Extension->DosName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(Extension->DosName.Buffer, MaxLength);

    Extension->DosName.Length = 0;
    Extension->DosName.MaximumLength = MaximumSize;
    Extension->DosName.Buffer[USBSER_MAX_DOS_NAME_LENGTH] = 0;

    RtlAppendUnicodeToString(&Extension->DosName, RegSymbolicName);
    Extension->DosName.Buffer[Extension->DosName.Length] = 0;

    DPRINT1("UsbSerDoExternalNaming: DosName '%wZ'\n", &Extension->DosName);

    Status = RtlWriteRegistryValue(RTL_REGISTRY_DEVICEMAP,
                                   L"SERIALCOMM",
                                   Extension->DeviceName.Buffer,
                                   REG_SZ,
                                   Extension->DosName.Buffer,
                                   Extension->DosName.Length + sizeof(WCHAR));
    if (Status == STATUS_SUCCESS)
        goto Exit;

    DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);

ErrorExit:

    if (Extension->DosName.Buffer)
    {
        ExFreePoolWithTag(Extension->DosName.Buffer, USBSER_TAG);
        Extension->DosName.Buffer = NULL;
    }

    if (Extension->IsSymLinkCreated)
    {
        IoDeleteSymbolicLink(&Extension->SymLinkName);
        Extension->IsSymLinkCreated = FALSE;
    }

    if (Extension->SymLinkName.Buffer)
    {
        ExFreePoolWithTag(Extension->SymLinkName.Buffer, USBSER_TAG);
        Extension->SymLinkName.Buffer = NULL;
    }

    if (Extension->DeviceName.Buffer)
        RtlDeleteRegistryValue(RTL_REGISTRY_DEVICEMAP, L"SERIALCOMM", Extension->DeviceName.Buffer);

Exit:

    if (SymLinkName.Buffer)
        ExFreePoolWithTag(SymLinkName.Buffer, USBSER_TAG);

    if (RegSymbolicName)
        ExFreePoolWithTag(RegSymbolicName, USBSER_TAG);

    return Status;
}

VOID
NTAPI
UsbSerUndoExternalNaming(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PAGED_CODE();

    if (Extension->SymLinkName.Buffer)
    {
        if (Extension->IsSymLinkCreated)
            IoDeleteSymbolicLink(&Extension->SymLinkName);

        ExFreePoolWithTag(Extension->SymLinkName.Buffer, USBSER_TAG);
        RtlInitUnicodeString(&Extension->SymLinkName, NULL);
    }

    if (Extension->DosName.Buffer)
    {
        ExFreePoolWithTag(Extension->DosName.Buffer, USBSER_TAG);
        RtlInitUnicodeString(&Extension->DosName, NULL);
    }

    if (Extension->DeviceName.Buffer)
    {
        RtlDeleteRegistryValue(RTL_REGISTRY_DEVICEMAP, L"SERIALCOMM", Extension->DeviceName.Buffer);

        ExFreePoolWithTag(Extension->DeviceName.Buffer, USBSER_TAG);
        RtlInitUnicodeString(&Extension->DeviceName, NULL);
    }
}

NTSTATUS
NTAPI
StartDevice(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("StartDevice: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Extension = DeviceObject->DeviceExtension;

    KeInitializeTimer(&Extension->WriteRequestTotalTimer);
    KeInitializeTimer(&Extension->ReadRequestTotalTimer);
    KeInitializeTimer(&Extension->ReadRequestIntervalTimer);

    KeInitializeDpc(&Extension->ReadTimeoutDpc, UsbSerReadTimeout, Extension);
    KeInitializeDpc(&Extension->IntervalReadTimeoutDpc, UsbSerIntervalReadTimeout, Extension);
    KeInitializeDpc(&Extension->WriteTimeoutDpc, UsbSerWriteTimeout, Extension);

    Extension->LongIntervalAmount.QuadPart = 1000 * -10000; // 1 sec
    Extension->ShortIntervalAmount.QuadPart = -1;

    Extension->CutOverAmount.QuadPart = 200000000;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, UsbSerSyncCompletion, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(Extension->LowerDevice, Irp);
    DPRINT("StartDevice: Status %X\n", Status);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("StartDevice: Status %X\n", Irp->IoStatus.Status);
        goto Exit;
    }

    Status = GetDeviceDescriptor(DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("StartDevice: Status %X\n", Status);
        goto Exit;
    }

    Status = ConfigureDevice(DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("StartDevice: Status %X\n", Status);
        goto Exit;
    }

    ResetDevice(DeviceObject);

    Extension->HandFlow.ControlHandShake = 0;
    Extension->HandFlow.FlowReplace = SERIAL_RTS_CONTROL;

    Extension->DeviceIsRunning = TRUE;

    InitializeListHead(&Extension->ReadQueueList);

    UsbSerDoExternalNaming(Extension);

    SetClrDtr(DeviceObject, FALSE);
    ClrRts(DeviceObject);

    StartRead(Extension);
    StartNotifyRead(Extension);

    Extension->PnpState = 1;
    DPRINT("StartDevice: Device %p is started\n", DeviceObject);

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

VOID
NTAPI
CancelPendingWaitMasks(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PIRP Irp;
    KIRQL Irql;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    if (!Extension->MaskIrp)
    {
        KeReleaseSpinLock(&Extension->SpinLock, Irql);
        return;
    }

    Irp = Extension->MaskIrp;
    Extension->MaskIrp = NULL;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_CANCELLED;

    IoSetCancelRoutine(Irp, NULL);
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
NTAPI
DeleteObjectAndLink(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;

    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;

    IoDeleteSymbolicLink(&Extension->SymLinkName);

    if (Extension->DeviceIndex < 0x100)
    {
        UsbSerFetchBooleanLocked(&Slots[Extension->DeviceIndex], FALSE, &GlobalSpinLock);

        NumDevices--;
        if (!NumDevices)
        {
            DPRINT("DeleteObjectAndLink: NumDevices is 0\n");
        }
    }

    IoDeleteDevice(DeviceObject);
}

NTSTATUS
NTAPI
RemoveDevice(IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    NTSTATUS Status;

    Extension = DeviceObject->DeviceExtension;

    PAGED_CODE();

    UsbSerFetchBooleanLocked(&Extension->DeviceIsRunning, FALSE, &Extension->SpinLock);

    CancelPendingWaitMasks(Extension);

    if (Extension->PnpState == 1)
        UsbSerAbortPipes(DeviceObject);

    if (Extension->ReadIrp)
    {
        IoFreeIrp(Extension->ReadIrp);
        Extension->ReadIrp = NULL;
    }

    if (Extension->NotifyIrp)
    {
        IoFreeIrp(Extension->NotifyIrp);
        Extension->NotifyIrp = NULL;
    }

    if (Extension->NotifyUrb)
    {
        ExFreePoolWithTag(Extension->NotifyUrb, USBSER_TAG);
        Extension->NotifyUrb = NULL;
    }

    if (Extension->ReadUrb)
    {
        ExFreePoolWithTag(Extension->ReadUrb, USBSER_TAG);
        Extension->ReadUrb = NULL;
    }

    if (Extension->DeviceDescriptor)
    {
        ExFreePoolWithTag(Extension->DeviceDescriptor, USBSER_TAG);
        Extension->DeviceDescriptor = NULL;
    }

    if (Extension->RxBuffer)
    {
        ExFreePoolWithTag(Extension->RxBuffer, USBSER_TAG);
        Extension->RxBuffer = NULL;
    }

    if (Extension->ReadBuffer)
    {
        ExFreePoolWithTag(Extension->ReadBuffer, USBSER_TAG);
        Extension->ReadBuffer = NULL;
    }

    if (Extension->NotifyBuffer)
    {
        ExFreePoolWithTag(Extension->NotifyBuffer, USBSER_TAG);
        Extension->NotifyBuffer = NULL;
    }

    UsbSerUndoExternalNaming(Extension);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    Status = IoCallDriver(Extension->LowerDevice, Irp);

    IoDetachDevice(Extension->LowerDevice);
    DeleteObjectAndLink(DeviceObject);

    Extension->PnpState = 2;

    return Status;
}

NTSTATUS
NTAPI
StopDevice(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
QueryCapabilities(IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PDEVICE_CAPABILITIES Capabilities;
    PIO_STACK_LOCATION IoStack;
    PKEVENT Event;
    NTSTATUS Status;

    //DPRINT("QueryCapabilities: DeviceObject %p, Irp %p\n", DeviceObject, Irp);

    Event = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Event), USBSER_TAG);
    if (!Event)
    {
        DPRINT1("QueryCapabilities: STATUS_INSUFFICIENT_RESOURCES\n");
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, UsbSerSyncCompletion, Event, TRUE, TRUE, TRUE);

    Extension = DeviceObject->DeviceExtension;

    Status = IoCallDriver(Extension->LowerDevice, Irp);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);

    ExFreePoolWithTag(Event, USBSER_TAG);

    Status = Irp->IoStatus.Status;

    if (!DeviceObject->ReferenceCount)
    {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;
    Capabilities->SurpriseRemovalOK = 1;

    Extension->SystemWake = Capabilities->SystemWake;
    Extension->DeviceWake = Capabilities->DeviceWake;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

VOID
NTAPI
SurpriseRemoval(IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIRP MaskIrp;
    KIRQL Irql;

    Extension = DeviceObject->DeviceExtension;

    IoAcquireCancelSpinLock(&Irql);
    UsbSerFetchBooleanLocked(&Extension->DeviceIsRunning, FALSE, &Extension->SpinLock);

    MaskIrp = Extension->MaskIrp;
    if (!MaskIrp)
    {
        IoReleaseCancelSpinLock(Irql);
        goto Exit;
    }

    if (!(Extension->IsrWaitMask & 0x20))
    {
        IoReleaseCancelSpinLock(Irql);
        goto Exit;
    }

    if (!(Extension->ModemStatus & 0x80))
    {
        IoReleaseCancelSpinLock(Irql);
        goto Exit;
    }

    Extension->ModemStatus &= ~0x80;
    Extension->HistoryMask |= 0x20;

    MaskIrp->IoStatus.Status = STATUS_SUCCESS;
    MaskIrp->IoStatus.Information = sizeof(Extension->HistoryMask);

    Extension->MaskIrp = NULL;

    *(PULONG)MaskIrp->AssociatedIrp.SystemBuffer = Extension->HistoryMask;
    Extension->HistoryMask = 0;

    IoSetCancelRoutine(MaskIrp, NULL);
    IoReleaseCancelSpinLock(Irql);

    IoCompleteRequest(MaskIrp, IO_NO_INCREMENT);

Exit:

    Irp->IoStatus.Status = STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UsbSerPnP(IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    //DPRINT("UsbSerPnP: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_START_DEVICE\n");
            Status = StartDevice(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_REMOVE_DEVICE\n");
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_REMOVE_DEVICE\n");
            IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_DEREGISTER);
            Status = RemoveDevice(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_CANCEL_REMOVE_DEVICE\n");
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_STOP_DEVICE\n");
            StopDevice(DeviceObject, Irp);
            break;

        case IRP_MN_QUERY_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_STOP_DEVICE\n");
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_CANCEL_STOP_DEVICE\n");
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_DEVICE_RELATIONS\n");
            break;

        case IRP_MN_QUERY_INTERFACE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_INTERFACE\n");
            break;

        case IRP_MN_QUERY_CAPABILITIES:
            //DPRINT("UsbSerPnP: IRP_MN_QUERY_CAPABILITIES\n");
            Status = QueryCapabilities(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_QUERY_RESOURCES:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_RESOURCES\n");
            break;

        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_QUERY_DEVICE_TEXT:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_DEVICE_TEXT\n");
            break;

        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            DPRINT("UsbSerPnP: IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_READ_CONFIG:
            DPRINT("UsbSerPnP: IRP_MN_READ_CONFIG\n");
            break;

        case IRP_MN_WRITE_CONFIG:
            DPRINT("UsbSerPnP: IRP_MN_WRITE_CONFIG\n");
            break;

        case IRP_MN_EJECT:
            DPRINT("UsbSerPnP: IRP_MN_EJECT\n");
            break;

        case IRP_MN_SET_LOCK:
            DPRINT("UsbSerPnP: IRP_MN_SET_LOCK\n");
            break;

        case IRP_MN_QUERY_ID:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_ID\n");
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_PNP_DEVICE_STATE\n");
            break;

        case IRP_MN_QUERY_BUS_INFORMATION:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_BUS_INFORMATION\n");
            break;

        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            DPRINT("UsbSerPnP: IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            DPRINT("UsbSerPnP: IRP_MN_SURPRISE_REMOVAL\n");
            SurpriseRemoval(DeviceObject, Irp);
            break;

        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_LEGACY_BUS_INFORMATION\n");
            break;

        default:
            DPRINT1("UsbSerPnP: Unknown MinorFunction %X\n", IoStack->MinorFunction);
            break;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    Status = IoCallDriver(Extension->LowerDevice, Irp);

Exit:

    return Status;
}

/* EOF */
