/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver ioctl functions.
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
GetBaudRate(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_BAUD_RATE Data;
    KIRQL Irql;

    DPRINT("GetBaudRate: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 4)
    {
        DPRINT1("GetBaudRate: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    GetLineControlAndBaud(DeviceObject);

    Extension = DeviceObject->DeviceExtension;
    Data = Irp->AssociatedIrp.SystemBuffer;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    Data->BaudRate = Extension->BaudRate.BaudRate;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    Irp->IoStatus.Information = 4;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetBaudRate(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_BAUD_RATE Data;
    KIRQL Irql;

    DPRINT("SetBaudRate: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < 4)
    {
        DPRINT1("SetBaudRate: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Data = Irp->AssociatedIrp.SystemBuffer;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    Extension->BaudRate.BaudRate = Data->BaudRate;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return SetLineControlAndBaud(DeviceObject);
}

NTSTATUS
NTAPI
GetLineControl(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PSERIAL_LINE_CONTROL LineControl;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;

    DPRINT("GetLineControl: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 3)
    {
        DPRINT1("GetLineControl: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    GetLineControlAndBaud(DeviceObject);

    Extension = DeviceObject->DeviceExtension;
    LineControl = Irp->AssociatedIrp.SystemBuffer;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(LineControl, &Extension->LineControl, sizeof(*LineControl));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    Irp->IoStatus.Information = 3;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetLineControl(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_LINE_CONTROL LineControl;
    KIRQL Irql;

    DPRINT("SetLineControl: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength >= 3)
    {
        DPRINT1("SetLineControl: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Extension = DeviceObject->DeviceExtension;
    LineControl = Irp->AssociatedIrp.SystemBuffer;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(&Extension->LineControl, LineControl, sizeof(*LineControl));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return SetLineControlAndBaud(DeviceObject);
}

NTSTATUS
NTAPI
GetChars(IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_CHARS Chars;
    KIRQL Irql;

    DPRINT("GetChars: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    Chars = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 6)
    {
        DPRINT1("GetChars: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(Chars, &Extension->Chars, sizeof(*Chars));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    Irp->IoStatus.Information = 6;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetChars(IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_CHARS Chars;
    KIRQL Irql;
  
    DPRINT("GetChars: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    Chars = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < 6)
    {
        DPRINT1("SetChars: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(&Extension->Chars, Chars, sizeof(*Chars));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
GetHandflow(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PSERIAL_HANDFLOW HandFlow;
    KIRQL Irql;

    DPRINT("GetHandflow: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    HandFlow = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 0x10)
    {
        DPRINT1("GetHandflow: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(HandFlow, &Extension->HandFlow, sizeof(*HandFlow));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    Irp->IoStatus.Information = 0x10;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetHandflow(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PSERIAL_HANDFLOW HandFlow;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;
  
    DPRINT("SetHandflow: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    HandFlow = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < 0x10)
    {
        DPRINT1("SetHandflow: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(&Extension->HandFlow, HandFlow, sizeof(*HandFlow));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetTimeouts(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PSERIAL_TIMEOUTS Timeouts;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;

    DPRINT("SetTimeouts: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    Timeouts = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < 0x14)
    {
        DPRINT1("SetTimeouts: STATUS_BUFFER_TOO_SMALL. Length %X\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_BUFFER_TOO_SMALL;
    }

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    RtlCopyMemory(&Extension->Timeouts, Timeouts, sizeof(Extension->Timeouts));
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UsbSerDeviceControl(IN PDEVICE_OBJECT DeviceObject,
                    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    ULONG ControlCode;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("UsbSerDeviceControl: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ControlCode)
    {
        case IOCTL_SERIAL_GET_BAUD_RATE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_BAUD_RATE\n");
            Status = GetBaudRate(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_PURGE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_PURGE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_CLR_DTR:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_CLR_DTR\n");
            Status = SetClrDtr(DeviceObject, FALSE);
            break;
        }
        case IOCTL_SERIAL_RESET_DEVICE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_RESET_DEVICE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_RTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_RTS\n");
            Status = SetRts(DeviceObject);
            break;
        }
        case IOCTL_SERIAL_CLR_RTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_CLR_RTS\n");
            Status = ClrRts(DeviceObject);
            break;
        }
        case IOCTL_SERIAL_SET_DTR:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_DTR\n");
            Status = SetClrDtr(DeviceObject, TRUE);
            break;
        }
        case IOCTL_SERIAL_SET_TIMEOUTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_TIMEOUTS\n");
            Status = SetTimeouts(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_SET_BREAK_OFF:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_BREAK_OFF\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_BAUD_RATE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_BAUD_RATE\n");
            Status = SetBaudRate(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_SET_LINE_CONTROL:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_LINE_CONTROL\n");
            Status = SetLineControl(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_SET_BREAK_ON:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_BREAK_ON\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_GET_COMMSTATUS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_COMMSTATUS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_HANDFLOW:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_HANDFLOW\n");
            Status = SetHandflow(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_GET_LINE_CONTROL:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_LINE_CONTROL\n");
            Status = GetLineControl(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_GET_CHARS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_CHARS\n");
            Status = GetChars(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_SET_CHARS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_CHARS\n");
            Status = SetChars(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_GET_HANDFLOW:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_HANDFLOW\n");
            Status = GetHandflow(DeviceObject, Irp);
            break;
        }
        case IOCTL_SERIAL_CONFIG_SIZE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_CONFIG_SIZE\n");ASSERT(FALSE);
            break;
        }
        default:
        {
            DPRINT1("UsbSerDeviceControl: Unknown ControlCode [%X] \n", ControlCode);ASSERT(FALSE);
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    if (Status != STATUS_PENDING)
    {
Exit:
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS
NTAPI
UsbSerInternalDeviceControl(IN PDEVICE_OBJECT DeviceObject,
                            IN PIRP Irp)
{
    DPRINT("UsbSerInternalDeviceControl: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerDispatch(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    //DPRINT("UsbSerDispatch: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    if (Extension->DevicePowerState != PowerDeviceD0)
    {
        DPRINT("UsbSerDispatch: Extension->DevicePowerState %X\n", Extension->DevicePowerState);
        KeReleaseSpinLock(&Extension->SpinLock, Irql);
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
    {
        return UsbSerDeviceControl(DeviceObject, Irp);
    }
    else if (IoStack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL)
    {
        return UsbSerInternalDeviceControl(DeviceObject, Irp);
    }

    DPRINT1("UsbSerDispatch: IoStack->MajorFunction %X, STATUS_INVALID_PARAMETER\n", IoStack->MajorFunction);

    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    return Status;
}

/* EOF */
