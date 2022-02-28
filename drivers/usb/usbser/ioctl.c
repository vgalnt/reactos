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
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_BAUD_RATE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_PURGE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_PURGE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_CLR_DTR:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_CLR_DTR\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_RESET_DEVICE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_RESET_DEVICE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_RTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_RTS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_CLR_RTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_CLR_RTS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_DTR:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_DTR\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_TIMEOUTS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_TIMEOUTS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_BREAK_OFF:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_BREAK_OFF\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_BAUD_RATE:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_BAUD_RATE\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_LINE_CONTROL:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_LINE_CONTROL\n");ASSERT(FALSE);
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
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_HANDFLOW\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_GET_LINE_CONTROL:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_LINE_CONTROL\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_GET_CHARS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_CHARS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_SET_CHARS:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_SET_CHARS\n");ASSERT(FALSE);
            break;
        }
        case IOCTL_SERIAL_GET_HANDFLOW:
        {
            DPRINT1("UsbSerDeviceControl: IOCTL_SERIAL_GET_HANDFLOW\n");ASSERT(FALSE);
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
