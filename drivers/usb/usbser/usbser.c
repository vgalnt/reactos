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

    if (!NT_SUCCESS(Irp->IoStatus.Status) ||
        Extension->DevicePowerState != PowerDeviceD0)
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

/* IRP_MJ_READ FUNCTIONS ******************************************************/

VOID
NTAPI
UsbSerCancelQueued(IN PDEVICE_OBJECT DeviceObject,
                   IN PIRP Irp)
{
    DPRINT("UsbSerCancelQueued: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_CANCELLED;

    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);

    IoReleaseCancelSpinLock(Irp->CancelIrql);
    IoCompleteRequest(Irp, IO_SERIAL_INCREMENT);
}

VOID
NTAPI
UsbSerGetNextIrp(IN PUSBSER_DEVICE_EXTENSION Extension,
                 IN OUT PIRP * CurrentOpIrp,
                 IN PLIST_ENTRY QueueToProcess,
                 OUT PIRP * OutNextIrp,
                 IN BOOLEAN CompleteCurrent)
{
    PIRP OldIrp;
    PLIST_ENTRY Head;
    KIRQL Irql;

    DPRINT("UsbSerGetNextIrp: QueueToProcess %p, CompleteCurrent %X\n", QueueToProcess, CompleteCurrent);
    PAGED_CODE();

    IoAcquireCancelSpinLock(&Irql);
    OldIrp = *CurrentOpIrp;

    if (OldIrp && CompleteCurrent && OldIrp->CancelRoutine)
    {
        DPRINT1("UsbSerGetNextIrp: OldIrp->CancelRoutine should be is NULL!\n");
    }

    if (IsListEmpty(QueueToProcess))
    {
        *CurrentOpIrp = NULL;
    }
    else
    {
        Head = RemoveHeadList(QueueToProcess);
        *CurrentOpIrp = CONTAINING_RECORD(Head, IRP, Tail.Overlay.ListEntry);
        IoSetCancelRoutine(*CurrentOpIrp, NULL);
    }

    *OutNextIrp = *CurrentOpIrp;

    IoReleaseCancelSpinLock(Irql);

    if (OldIrp && CompleteCurrent)
        IoCompleteRequest(OldIrp, IO_SERIAL_INCREMENT);
}

NTSTATUS
NTAPI
UsbSerStartOrQueue(IN PDEVICE_OBJECT DeviceObject,
                   IN PIRP Irp,
                   IN PLIST_ENTRY List,
                   OUT PIRP * OutIrp,
                   IN PUSBSER_START_READ StartReadRoutine)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("UsbSerStartOrQueue: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoAcquireCancelSpinLock(&Irql);

    if (IsListEmpty(List) && (*OutIrp == NULL))
    {
        /* Queue is empty */
        *OutIrp = Irp;
        IoReleaseCancelSpinLock(Irql);
        Extension = DeviceObject->DeviceExtension;

        Status = StartReadRoutine(Extension);
        DPRINT("UsbSerStartOrQueue: Status %X\n", Status);
        return Status;
    }

    if (Irp->Cancel)
    {
        IoReleaseCancelSpinLock(Irql);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_CANCELLED;
    }

    /* Add to Queue */

    IoMarkIrpPending(Irp);

    Irp->IoStatus.Status = STATUS_PENDING;

    InsertTailList(List, &Irp->Tail.Overlay.ListEntry);

    IoSetCancelRoutine(Irp, UsbSerCancelQueued);
    IoReleaseCancelSpinLock(Irql);

    return STATUS_PENDING;
}

VOID
NTAPI
GetData(IN PUSBSER_DEVICE_EXTENSION Extension,
        IN PVOID DataBuffer,
        IN ULONG DataBufferSize,
        OUT ULONG * OutLength)
{
    ULONG Offset;
    ULONG Size;
    ULONG Remain;
    KIRQL Irql;

    DPRINT("GetData: DataBuffer %p, DataBufferSize %X\n", DataBuffer, DataBufferSize);

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    if (DataBufferSize > Extension->CharsInReadBuffer)
        DataBufferSize = Extension->CharsInReadBuffer;

    if (!DataBufferSize)
    {
        DPRINT("GetData: DataBufferSize is 0\n");
        goto Exit;
    }

    Offset = Extension->ReadBufferOffset;

    if ((DataBufferSize + Offset) >= Extension->RxBufferSize)
    {
        Size = Extension->RxBufferSize - Offset;
    }
    else
    {
        Size = DataBufferSize;
    }

    RtlCopyMemory(DataBuffer, (PVOID)((ULONG_PTR)Extension->RxBuffer + Offset), Size);

    Extension->ReadBufferOffset += Size;
    Extension->CharsInReadBuffer -= Size;
    Extension->ReadLength -= Size;

    *OutLength += Size;

    Remain = (DataBufferSize - Size);
    if (!Remain)
        goto Exit;

    DataBuffer = (PVOID)((ULONG_PTR)DataBuffer + Size);

    RtlCopyMemory(DataBuffer, Extension->RxBuffer, Remain);

    Extension->CharsInReadBuffer -= Remain;
    Extension->ReadLength -= Remain;
    Extension->ReadBufferOffset = Remain;

    *OutLength += Remain;

Exit:

    KeReleaseSpinLock(&Extension->SpinLock, Irql);
    RestartRead(Extension);
}

VOID
NTAPI
UsbSerGrabReadFromRx(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PIO_STACK_LOCATION IoStack;
    PULONG_PTR Argument4;

    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Extension->CurrentReadIrp);

    Argument4 = (PULONG_PTR)&IoStack->Parameters.Others.Argument4;
    *Argument4 &= ~1;
}

VOID
NTAPI
UsbSerRundownIrpRefs(IN PUSBSER_DEVICE_EXTENSION Extension,
                     IN PIRP * CurrentOpIrp,
                     IN PKTIMER IntervalTimer,
                     IN PKTIMER TotalTimer)
{
    PIO_STACK_LOCATION IoStack;

    DPRINT("UsbSerRundownIrpRefs: Extension %p\n", Extension);

    IoStack = IoGetCurrentIrpStackLocation(*CurrentOpIrp);

    if ((*CurrentOpIrp)->CancelRoutine)
    {
        IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG_PTR)IoStack->Parameters.Others.Argument4 & ~2);
        IoSetCancelRoutine(*CurrentOpIrp, NULL);
    }

    if (IntervalTimer && KeCancelTimer(IntervalTimer))
    {
        IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG_PTR)IoStack->Parameters.Others.Argument4 & ~8);
    }

    if (TotalTimer && KeCancelTimer(TotalTimer))
    {
        IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG_PTR)IoStack->Parameters.Others.Argument4 & ~4);
    }
}

VOID
NTAPI
UsbSerTryToCompleteCurrent(IN PUSBSER_DEVICE_EXTENSION Extension,
                           IN KIRQL IrqlForRelease,
                           IN NTSTATUS Status,
                           IN PIRP * CurrentOpIrp,
                           IN PLIST_ENTRY QueueToProcess,
                           IN PKTIMER IntervalTimer,
                           IN PKTIMER Timer,
                           IN PUSBSER_START_READ Starter,
                           IN PUSBSER_GET_NEXT_IRP GetNextIrp,
                           IN LONG RefType,
                           IN BOOLEAN CompleteCurrent)
{
    PIO_STACK_LOCATION IoStack;
    PIRP NextIrp;
    PIRP currentIrp;

    DPRINT("UsbSerTryToCompleteCurrent: Extension %p\n", Extension);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(*CurrentOpIrp);

    IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG_PTR)IoStack->Parameters.Others.Argument4 & ~RefType);

    UsbSerRundownIrpRefs(Extension, CurrentOpIrp, IntervalTimer, Timer);

    if (IoStack->Parameters.Others.Argument4)
    {
        IoReleaseCancelSpinLock(IrqlForRelease);
        return;
    }

    (*CurrentOpIrp)->IoStatus.Status = Status;

    if (Status == STATUS_CANCELLED)
        (*CurrentOpIrp)->IoStatus.Information = 0;

    if (GetNextIrp)
    {
        IoReleaseCancelSpinLock(IrqlForRelease);

        GetNextIrp(Extension, CurrentOpIrp, QueueToProcess, &NextIrp, CompleteCurrent);

        if (NextIrp)
            Starter(Extension);

        return;
    }

    currentIrp = *CurrentOpIrp;
    *CurrentOpIrp = NULL;

    IoReleaseCancelSpinLock(IrqlForRelease);

    if (CompleteCurrent)
        IoCompleteRequest(currentIrp, IO_SERIAL_INCREMENT);
}

VOID
NTAPI
UsbSerCancelCurrentRead(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;

    DPRINT("UsbSerCancelCurrentRead: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;

    Extension->CountOnLastRead = 0xFFFFFFFF;

    UsbSerGrabReadFromRx(Extension);

    UsbSerTryToCompleteCurrent(Extension,
                               Irp->CancelIrql,
                               STATUS_CANCELLED,
                               &Extension->CurrentReadIrp,
                               &Extension->ReadQueueList,
                               &Extension->ReadRequestIntervalTimer,
                               &Extension->ReadRequestTotalTimer,
                               UsbSerStartRead,
                               UsbSerGetNextIrp,
                               2,                // LONG RefType
                               TRUE);            // BOOLEAN CompleteCurrent
}

NTSTATUS
NTAPI
UsbSerStartRead(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    PIO_STACK_LOCATION IoStack;
    LARGE_INTEGER TotalTime;
    PIRP CurrentReadIrp;
    PIRP NewIrp;
    PIRP Irp;
    ULONG IntervalTimeout;
    ULONG TotalTimeoutMultiplier;
    ULONG TotalTimeoutConstant;
    ULONG Multiplier;
    ULONG Length;
    ULONG Constant = 0;
    BOOLEAN UseIntervalTimer;
    BOOLEAN CrunchDownToOne;
    BOOLEAN ReturnWithWhatsPresent;
    BOOLEAN Os2ssreturn;
    BOOLEAN IsSetStatus = FALSE;
    BOOLEAN UseTotalTimer;
    KIRQL CancelIrql;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("UsbSerStartRead: Extension %p\n", Extension);
    PAGED_CODE();

    do
    {
        Irp = Extension->CurrentReadIrp;
        IoStack = IoGetCurrentIrpStackLocation(Irp);
        Length = IoStack->Parameters.Read.Length;
        Extension->ReadLength = Length;

        UseTotalTimer = FALSE;
        ReturnWithWhatsPresent = FALSE;
        Os2ssreturn = FALSE;
        CrunchDownToOne = FALSE;
        UseIntervalTimer = FALSE;

        KeAcquireSpinLock(&Extension->SpinLock, &Irql);
        IntervalTimeout = Extension->Timeouts.ReadIntervalTimeout;
        TotalTimeoutMultiplier = Extension->Timeouts.ReadTotalTimeoutMultiplier;
        TotalTimeoutConstant = Extension->Timeouts.ReadTotalTimeoutConstant;
        Extension->CountOnLastRead = 0;
        KeReleaseSpinLock(&Extension->SpinLock, Irql);

        if (IntervalTimeout && (IntervalTimeout != MAXULONG))
        {
            UseIntervalTimer = TRUE;

            Extension->IntervalTime.QuadPart = UInt32x32To64(IntervalTimeout, 10000);

            if (Extension->IntervalTime.QuadPart < Extension->CutOverAmount.QuadPart)
            {
                Extension->IntervalTimeToUse = &Extension->ShortIntervalAmount;
            }
            else
            {
                Extension->IntervalTimeToUse = &Extension->LongIntervalAmount;
            }
        }

        if (IntervalTimeout != MAXULONG)
        {
            if (TotalTimeoutMultiplier || TotalTimeoutConstant)
            {
                UseTotalTimer = TRUE;

                Multiplier = TotalTimeoutMultiplier;
                Constant = TotalTimeoutConstant;
            }
        }
        else
        {
            if (!TotalTimeoutConstant && !TotalTimeoutMultiplier)
            {
                ReturnWithWhatsPresent = TRUE;
            }
            else if ((TotalTimeoutConstant != MAXULONG) && (TotalTimeoutMultiplier != MAXULONG))
            {
                UseTotalTimer = TRUE;
                Os2ssreturn = TRUE;

                Multiplier = TotalTimeoutMultiplier;
                Constant = TotalTimeoutConstant;
            }
            else if ((TotalTimeoutConstant != MAXULONG) && (TotalTimeoutMultiplier == MAXULONG))
            {
                UseTotalTimer = TRUE;
                Os2ssreturn = TRUE;
                CrunchDownToOne = TRUE;

                Multiplier = 0;
                Constant = TotalTimeoutConstant;
            }
        }

        if (UseTotalTimer)
        {
            TotalTime.QuadPart = ((LONGLONG)(UInt32x32To64(Extension->ReadLength, Multiplier) + Constant)) * -10000;
        }

        CurrentReadIrp = Irp;

        if (Extension->CharsInReadBuffer)
        {
            ULONG Offset = (Length - Extension->ReadLength);

            DPRINT("UsbSerStartRead: Offset %X\n", Offset);

            GetData(Extension,
                    ((char *)Irp->AssociatedIrp.SystemBuffer + Offset),
                    Extension->ReadLength,
                    &Irp->IoStatus.Information);
        }

        if (ReturnWithWhatsPresent ||
            !Extension->ReadLength ||
            (Os2ssreturn && CurrentReadIrp->IoStatus.Information))
        {
            CurrentReadIrp->IoStatus.Status = STATUS_SUCCESS;

            if (!IsSetStatus)
            {
                Status = STATUS_SUCCESS;
                IsSetStatus = TRUE;
            }
        }
        else
        {
            IoStack = IoGetCurrentIrpStackLocation(CurrentReadIrp);
            IoStack->Parameters.Others.Argument4 = NULL;

            IoAcquireCancelSpinLock(&CancelIrql);
            if (!CurrentReadIrp->Cancel)
                break;
            IoReleaseCancelSpinLock(CancelIrql);

            CurrentReadIrp->IoStatus.Status = STATUS_CANCELLED;
            CurrentReadIrp->IoStatus.Information = 0;

            if (!IsSetStatus)
            {
                Status = STATUS_CANCELLED;
                IsSetStatus = TRUE;
            }
        }

        UsbSerGetNextIrp(Extension,
                         &Extension->CurrentReadIrp,
                         &Extension->ReadQueueList,
                         &NewIrp,
                         TRUE);
        if (!NewIrp)
            return Status;

        DPRINT("UsbSerStartRead: NewIrp %p\n", NewIrp);
    }
    while (TRUE);

    IoStack = IoGetCurrentIrpStackLocation(CurrentReadIrp);

    if (CrunchDownToOne)
    {
        IoStack->Parameters.Read.Length = 1;
        Extension->ReadLength = 1;
    }

    IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG)IoStack->Parameters.Others.Argument4 | 1);
    IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG)IoStack->Parameters.Others.Argument4 | 2);

    if (UseTotalTimer)
    {
        IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG)IoStack->Parameters.Others.Argument4 | 4);

        KeSetTimer(&Extension->ReadRequestTotalTimer,
                   TotalTime,
                   &Extension->ReadTimeoutDpc);
    }

    if (UseIntervalTimer)
    {
        IoStack->Parameters.Others.Argument4 = (PVOID)((ULONG)IoStack->Parameters.Others.Argument4 | 8);

        KeQuerySystemTime(&Extension->LastReadTime);

        KeSetTimer(&Extension->ReadRequestIntervalTimer,
                   *Extension->IntervalTimeToUse,
                   &Extension->IntervalReadTimeoutDpc);
    }

    IoSetCancelRoutine(CurrentReadIrp, UsbSerCancelCurrentRead);
    IoMarkIrpPending(CurrentReadIrp);

    IoReleaseCancelSpinLock(CancelIrql);

    if (!IsSetStatus)
        Status = STATUS_PENDING;

    return Status;
}

NTSTATUS
NTAPI
UsbSerRead(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("UsbSerRead: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.Read.Length)
    {
        Status = UsbSerStartOrQueue(DeviceObject,
                                    Irp,
                                    &Extension->ReadQueueList,
                                    &Extension->CurrentReadIrp,
                                    UsbSerStartRead);

        DPRINT("UsbSerRead: Status %X\n", Status);
        return Status;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/* IRP_MJ_WRITE FUNCTIONS *****************************************************/

NTSTATUS
NTAPI
UsbSerGiveWriteToUsb(IN PUSBSER_DEVICE_EXTENSION Extension,
                     IN PIRP Irp,
                     IN LARGE_INTEGER WriteTimeOut)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerWrite(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    LARGE_INTEGER WriteTimeOut;
    SERIAL_TIMEOUTS timeouts;
    ULONGLONG wTimeout;
    ULONG WriteLength;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("UsbSerWrite: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.Write.Length == 0)
    {
        DPRINT("UsbSerWrite: Length for write is 0\n");
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    if (Extension->DevicePowerState != PowerDeviceD0)
    {
        DPRINT1("UsbSerWrite: DevicePowerState %X\n", Extension->DevicePowerState);
        KeReleaseSpinLock(&Extension->SpinLock, Irql);

        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    RtlCopyMemory(&timeouts, &Extension->Timeouts, sizeof(timeouts));

    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    if (timeouts.WriteTotalTimeoutConstant ||
        timeouts.WriteTotalTimeoutMultiplier)
    {
        if (IoStack->MajorFunction == IRP_MJ_WRITE)
            WriteLength = IoStack->Parameters.Write.Length;
        else
            WriteLength = 1;

        wTimeout = timeouts.WriteTotalTimeoutConstant;
        wTimeout += (WriteLength * timeouts.WriteTotalTimeoutMultiplier);

        WriteTimeOut.QuadPart = wTimeout * -10000;
    }
    else
    {
        WriteTimeOut.QuadPart = 0;
    }

    IoStack->Parameters.Others.Argument4 = NULL;

    IoAcquireCancelSpinLock(&Irql);
    if (Irp->Cancel)
    {
        DPRINT("UsbSerWrite: Irp %X cancelled\n", Irp);
        IoReleaseCancelSpinLock(Irql);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        return STATUS_CANCELLED;
    }
    IoSetCancelRoutine(Irp, NULL);
    IoReleaseCancelSpinLock(Irql);

    Status = UsbSerGiveWriteToUsb(Extension, Irp, WriteTimeOut);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("UsbSerWrite: Status %X\n", Status);
    }

    return Status;
}

/* IRP_MJ FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
UsbSerCreate(IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("UsbSer_Create: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    if (InterlockedIncrement(&Extension->OpenCount) != 1)
    {
        InterlockedDecrement(&Extension->OpenCount);
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (IoStack->Parameters.Create.Options & FILE_DIRECTORY_FILE)
    {
        InterlockedDecrement(&Extension->OpenCount);
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_NOT_A_DIRECTORY;
        Status = STATUS_NOT_A_DIRECTORY;
        goto Exit;
    }

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    Extension->IsrWaitMask = 0;

    RtlZeroMemory(&Extension->Stats, sizeof(Extension->Stats));

    Extension->CharsInReadBuffer = 0;
    Extension->ReadBufferOffset = 0;
    Extension->HistoryMask = 0;
    Extension->IsWaitWake = FALSE;

    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    RestartRead(Extension);

Exit:

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
UsbSerClose(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    LONG OpenCount;

    DPRINT("UsbSer_Close: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    SetClrDtr(DeviceObject, FALSE);

    Extension->IsWaitWake = FALSE;

    if (Extension->WakeIrp)
        IoCancelIrp(Extension->WakeIrp);

    OpenCount = InterlockedDecrement(&Extension->OpenCount);
    ASSERT(OpenCount == 0);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
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
    KeReleaseSpinLock(&GlobalSpinLock, Irql);

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

    RtlCopyMemory(Extension->DeviceName.Buffer, DeviceName.Buffer, Extension->DeviceName.MaximumLength);

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

    Extension->DevicePowerState = PowerDeviceD0;

    NewDevice->StackSize = (Extension->LowerDevice->StackSize + 1);

    NewDevice->Flags |= DO_BUFFERED_IO; // IO system copies the users data to and from system supplied buffers
    NewDevice->Flags |= DO_POWER_PAGABLE;
    NewDevice->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:

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
