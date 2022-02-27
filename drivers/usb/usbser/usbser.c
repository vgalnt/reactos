/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver main functions.
 * COPYRIGHT:   2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

KSPIN_LOCK GlobalSpinLock;
UCHAR Slots[0x100];
ULONG NumDevices;

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
PutData(IN PUSBSER_DEVICE_EXTENSION Extension,
        IN ULONG BufferLength)
{
    ULONG Offset;
    ULONG Size;
    ULONG Remain;
    KIRQL Irql;

    DPRINT("PutData: Extension %p BufferLength %X\n", Extension, BufferLength);

    if (!BufferLength)
    {
        DPRINT1("PutData: BufferLength is 0\n");
        return;
    }

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    Offset = (Extension->CharsInReadBuffer + Extension->ReadBufferOffset) % Extension->RxBufferSize;

    if (BufferLength < (Extension->RxBufferSize - Offset))
        Size = BufferLength;
    else
        Size = (Extension->RxBufferSize - Offset);

    RtlCopyMemory(((PCHAR)Extension->RxBuffer + Offset), Extension->ReadBuffer, Size);

    Extension->CharsInReadBuffer += Size;
    Extension->ReadByIsr += Size;

    Remain = (BufferLength - Size);
    if (Remain)
    {
        RtlCopyMemory(Extension->RxBuffer, ((PCHAR)Extension->ReadBuffer + Size), Remain);

        Extension->CharsInReadBuffer += Remain;
        Extension->ReadByIsr += Remain;
    }

    KeReleaseSpinLock(&Extension->SpinLock, Irql);
}

NTSTATUS
NTAPI
ReadCompletion(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp,
               IN PVOID Context)
{
    PUSBSER_DEVICE_EXTENSION Extension = Context;
    KIRQL Irql;
    ULONG Offset;
    ULONG BufferLength;
    BOOLEAN IsRestartRead;

    DPRINT("ReadCompletion: Extension %p\n", Extension);

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    BufferLength = Extension->ReadUrb->UrbBulkOrInterruptTransfer.TransferBufferLength;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        Extension->ReadingState = 2;
        Extension->ReadingIsOn = FALSE;
        Extension->DeviceIsRunning = FALSE;

        KeReleaseSpinLock(&Extension->SpinLock, Irql);

        goto Exit;
    }

    Extension->HistoryMask |= (SERIAL_EV_RX80FULL | SERIAL_EV_RXCHAR);
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    if (Extension->IsrWaitMask & SERIAL_EV_RXFLAG)
    {
        for (Offset = 0; Offset < BufferLength; Offset++)
        {
            if (*((PUCHAR)Extension->ReadBuffer + Offset) == Extension->Chars.EventChar)
            {
                Extension->HistoryMask |= SERIAL_EV_RXFLAG;
                break;
            }
        }
    }

    PutData(Extension, BufferLength);

    DPRINT1("ReadCompletion: FIXME CheckForQueuedReads()\n");

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    IsRestartRead = (Extension->ReadingState == 3);
    Extension->ReadingState = 2;
    Extension->ReadingIsOn = FALSE;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    if (IsRestartRead)
        RestartRead(Extension);

Exit:

    if (!InterlockedDecrement(&Extension->DataInCount))
        KeSetEvent(&Extension->EventDataIn, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
RestartRead(PUSBSER_DEVICE_EXTENSION Extension)
{
    PIO_STACK_LOCATION IoStack;
    PIRP Irp;
    PURB Urb;
    BOOLEAN IsContinueRead;
    BOOLEAN IsAllowNextRead;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("RestartRead: Extension %p\n", Extension);

    do
    {
        IsAllowNextRead = FALSE;

        KeAcquireSpinLock(&Extension->SpinLock, &Irql);

        if (Extension->ReadingIsOn == FALSE &&
            Extension->CharsInReadBuffer <= 0x3000 &&
            Extension->DeviceIsRunning == TRUE)
        {
            IsAllowNextRead = TRUE;
            Extension->ReadingIsOn = TRUE;
            Extension->ReadingState = 1;
        }

        KeReleaseSpinLock(&Extension->SpinLock, Irql);

        if (!IsAllowNextRead)
            break;

        Urb = Extension->ReadUrb;
        Irp = Extension->ReadIrp;

        RtlZeroMemory(Urb, sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER));

        Urb->UrbHeader.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
        Urb->UrbHeader.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;

        Urb->UrbBulkOrInterruptTransfer.PipeHandle = Extension->DataInPipeHandle;
        Urb->UrbBulkOrInterruptTransfer.TransferBuffer = Extension->ReadBuffer;
        Urb->UrbBulkOrInterruptTransfer.TransferBufferLength = 0x1000;
        Urb->UrbBulkOrInterruptTransfer.TransferFlags = (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK);

        Urb->UrbBulkOrInterruptTransfer.TransferBufferMDL = NULL;
        Urb->UrbBulkOrInterruptTransfer.UrbLink = NULL;

        IoStack = IoGetNextIrpStackLocation(Irp);
        IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
        IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
        IoStack->Parameters.Others.Argument1 = Urb;

        IoSetCompletionRoutine(Irp, ReadCompletion, Extension, TRUE, TRUE, TRUE);

        InterlockedIncrement(&Extension->DataInCount);

        Status = IoCallDriver(Extension->LowerDevice, Irp);

        if (!NT_SUCCESS(Status) && !InterlockedDecrement(&Extension->DataInCount))
        {
            KeSetEvent(&Extension->EventDataIn, IO_NO_INCREMENT, FALSE);
        }

        KeAcquireSpinLock(&Extension->SpinLock, &Irql);
        IsContinueRead = (Extension->ReadingState == 2);
        Extension->ReadingState = 3;
        KeReleaseSpinLock(&Extension->SpinLock, Irql);
    }
    while (IsContinueRead);
}

VOID
NTAPI
StartRead(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    struct _URB_BULK_OR_INTERRUPT_TRANSFER * Urb;
    PIRP Irp;

    DPRINT("StartRead: Extension %p\n", Extension);
    PAGED_CODE();

    Irp = IoAllocateIrp((Extension->LowerDevice->StackSize + 1), FALSE);
    if (!Irp)
    {
        DPRINT1("StartRead: allocate irp failed\n");
        return;
    }

    Urb = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER), USBSER_TAG);
    if (!Urb)
    {
        DPRINT1("StartRead: allocate Urb failed\n");
        return;
    }

    UsbSerFetchPVoidLocked((PVOID *)&Extension->ReadIrp, Irp, &Extension->SpinLock);
    UsbSerFetchPVoidLocked((PVOID *)&Extension->ReadUrb, Urb, &Extension->SpinLock);

    RestartRead(Extension);
}

NTSTATUS
NTAPI
NotifyCompletion(IN PDEVICE_OBJECT DeviceObject,
                 IN PIRP Irp,
                 IN PVOID Context)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
RestartNotifyRead(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PIO_STACK_LOCATION IoStack;
    PURB Urb;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("RestartNotifyRead: Extension %p\n", Extension);

    Urb = Extension->NotifyUrb;
    Irp = Extension->NotifyIrp;

    if (!Extension->DeviceIsRunning)
    {
        goto Exit;
    }

    RtlZeroMemory(Urb, sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER));

    Urb->UrbHeader.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    Urb->UrbHeader.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;

    Urb->UrbBulkOrInterruptTransfer.PipeHandle = Extension->NotifyPipeHandle;
    Urb->UrbBulkOrInterruptTransfer.TransferBuffer = Extension->NotifyBuffer;
    Urb->UrbBulkOrInterruptTransfer.TransferBufferLength = sizeof(USBSER_CDC_NOTIFICATION);
    Urb->UrbBulkOrInterruptTransfer.TransferFlags = (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK);

    Urb->UrbBulkOrInterruptTransfer.TransferBufferMDL = NULL;
    Urb->UrbBulkOrInterruptTransfer.UrbLink = NULL;

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    IoStack->Parameters.Others.Argument1 = Urb;

    IoSetCompletionRoutine(Irp, NotifyCompletion, Extension, TRUE, TRUE, TRUE);

    InterlockedIncrement(&Extension->NotifyCount);

    Status = IoCallDriver(Extension->LowerDevice, Irp);
    if (NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (!InterlockedDecrement(&Extension->NotifyCount))
    {
        KeSetEvent(&Extension->EventNotify, IO_NO_INCREMENT, FALSE);
    }

Exit:

    return;
}

VOID
NTAPI
StartNotifyRead(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PURB Urb;
    PIRP Irp;

    DPRINT("StartNotifyRead: Extension %p\n", Extension);
    PAGED_CODE();

    Irp = IoAllocateIrp((Extension->LowerDevice->StackSize + 1), FALSE);
    if (!Irp)
    {
        DPRINT1("StartNotifyRead: allocate Irp failed\n");
        return;
    }

    Urb = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER), USBSER_TAG);
    if (!Urb)
    {
        DPRINT1("StartNotifyRead: allocate Urb failed\n");
        return;
    }

    UsbSerFetchPVoidLocked((PVOID *)&Extension->NotifyIrp, Irp, &Extension->SpinLock);
    UsbSerFetchPVoidLocked((PVOID *)&Extension->NotifyUrb, Urb, &Extension->SpinLock);

    RestartNotifyRead(Extension);
}

/* IRP_MJ FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
UsbSerCreate(IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp)
{
    DPRINT("UsbSerCreate: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerClose(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerClose: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerRead(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    DPRINT("UsbSerRead: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI 
UsbSerWrite(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerWrite: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerMajorNotSupported(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("UsbSerMajorNotSupported: Device %p, Irp %p, Major %X\n", DeviceObject, Irp, IoStack->MajorFunction);
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
UsbSerFlush(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerFlush: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerDispatch(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{
    DPRINT("UsbSerDispatch: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerCleanup(IN PDEVICE_OBJECT DeviceObject,
              IN PIRP Irp)
{
    DPRINT("UsbSerCleanup: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerProcessPowerIrp(IN PDEVICE_OBJECT DeviceObject,
                      IN PIRP Irp)
{
    DPRINT("UsbSerProcessPowerIrp: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerSystemControlDispatch(IN PDEVICE_OBJECT DeviceObject,
                            IN PIRP Irp)
{
    DPRINT("UsbSerSystemControlDispatch: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
UsbSerUnload(IN PDRIVER_OBJECT DriverObject)
{
    DPRINT("UsbSerUnload: DriverObject %p\n", DriverObject);
    PAGED_CODE();
}

NTSTATUS
NTAPI
UsbSerPnPAddDevice(IN PDRIVER_OBJECT DriverObject,
                   IN PDEVICE_OBJECT TargetDevice)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    NTSTATUS Status;
    ULONG FreeIdx;
    KIRQL Irql;
    PDEVICE_OBJECT NewDevice = NULL;
    WCHAR CharName[64];
    UNICODE_STRING DeviceName;
    WCHAR CharSymLink[64];
    UNICODE_STRING SymLinkName;
    ULONG ExtSize;

    PAGED_CODE();
    DPRINT("UsbSerPnPAddDevice: DriverObject %p, TargetDevice %p\n", DriverObject, TargetDevice);

    KeAcquireSpinLock(&GlobalSpinLock, &Irql);
    for (FreeIdx = 0; FreeIdx < USBSER_MAX_SLOT; FreeIdx++)
    {
        /* Find free record */
        if (!Slots[FreeIdx])
            break;
    }
    KfReleaseSpinLock(&GlobalSpinLock, Irql);

    if (FreeIdx == USBSER_MAX_SLOT)
    {
        DPRINT1("UsbSer_PnPAddDevice: FreeIdx == USBSER_MAX_SLOT\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Construct device name */
    RtlStringCbPrintfW(CharName, sizeof(CharName), L"\\Device\\USBSER%03d", FreeIdx);
    RtlInitUnicodeString(&DeviceName, CharName);

    /* Create device */
    ExtSize = sizeof(USBSER_DEVICE_EXTENSION);

    Status = IoCreateDevice(DriverObject,
                            ExtSize,
                            &DeviceName,
                            FILE_DEVICE_MODEM,
                            0,
                            TRUE,
                            &NewDevice);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("UsbSer_PnPAddDevice: Status %X\n", Status);
        goto Exit;
    }

    /* Create symbolic link */
    RtlStringCbPrintfW(CharSymLink, sizeof(CharSymLink), L"\\DosDevices\\USBSER%03d", FreeIdx);
    RtlInitUnicodeString(&SymLinkName, CharSymLink);

    Status = IoCreateUnprotectedSymbolicLink(&SymLinkName, &DeviceName);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT("UsbSer_PnPAddDevice: Status %X\n", Status);
        goto Exit;
    }

    Extension = NewDevice->DeviceExtension;
    RtlZeroMemory(Extension, ExtSize);

    Extension->DeviceName.Length = DeviceName.Length;
    Extension->DeviceName.MaximumLength = DeviceName.MaximumLength;

    Extension->DeviceName.Buffer = ExAllocatePool(PagedPool, Extension->DeviceName.MaximumLength);
    if (!Extension->DeviceName.Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        DPRINT("UsbSer_PnPAddDevice: Status %X\n", Status);
        goto Exit;
    }

    RtlCopyMemory(&Extension->DeviceName.Buffer, DeviceName.Buffer, Extension->DeviceName.MaximumLength);

    Extension->DeviceIndex = FreeIdx;

    KeAcquireSpinLock(&GlobalSpinLock, &Irql);
    NumDevices++;
    Slots[FreeIdx] = 1;
    KeReleaseSpinLock(&GlobalSpinLock, Irql);

    KeInitializeSpinLock(&Extension->SpinLock);

    KeInitializeEvent(&Extension->EventDataIn, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Extension->EventDataOut, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Extension->EventNotify, SynchronizationEvent, FALSE);

    Extension->DataInCount = 1;
    Extension->DataOutCount = 1;
    Extension->NotifyCount = 1;

    if (!TargetDevice)
    {
        DPRINT1("UsbSer_PnPAddDevice: TargetDevice is NULL\n");
        goto Exit;
    }

    Extension->PhysicalDevice = TargetDevice;
    Extension->LowerDevice = IoAttachDeviceToDeviceStack(NewDevice, TargetDevice);

    if (!Extension->LowerDevice)
    {
        DPRINT1("UsbSer_PnPAddDevice: STATUS_NO_SUCH_DEVICE. Extension->LowerDevice is NULL\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    DPRINT("UsbSer_PnPAddDevice: TargetDevice %p, LowerDevice %p\n", TargetDevice, Extension->LowerDevice);

    NewDevice->StackSize = (Extension->LowerDevice->StackSize + 1);

    NewDevice->Flags |= DO_BUFFERED_IO; // IO system copies the users data to and from system supplied buffers
    NewDevice->Flags |= DO_POWER_PAGABLE;
    NewDevice->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:

    RtlFreeUnicodeString(&DeviceName);
    RtlFreeUnicodeString(&SymLinkName);

    if (Status != STATUS_SUCCESS && NewDevice)
    {
        DPRINT("UsbSer_PnPAddDevice: Status %X, delete Device %p\n", Status, NewDevice);
        IoDeleteDevice(NewDevice);
    }

    return Status;
}

NTSTATUS
NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject,
            IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT1("DriverEntry: USB modem driver\n");

    PAGED_CODE();
    DPRINT("DriverEntry: DriverObject %p, RegistryPath %wZ\n", DriverObject, RegistryPath);

    DriverObject->DriverUnload = UsbSerUnload;
    DriverObject->DriverExtension->AddDevice = UsbSerPnPAddDevice;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = UsbSerCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UsbSerClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = UsbSerRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = UsbSerWrite;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = UsbSerMajorNotSupported;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = UsbSerMajorNotSupported;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = UsbSerFlush;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UsbSerDispatch;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = UsbSerDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = UsbSerCleanup;
    DriverObject->MajorFunction[IRP_MJ_POWER] = UsbSerProcessPowerIrp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = UsbSerSystemControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_PNP] = UsbSerPnP;

    KeInitializeSpinLock(&GlobalSpinLock);

    return Status;
}

/* EOF */
