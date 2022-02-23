/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver usb functions.
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
CallUSBD(IN PDEVICE_OBJECT DeviceObject,
         IN PURB Urb)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIRP Irp;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    LARGE_INTEGER Timeout;

    DPRINT("CallUSBD: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    Extension = DeviceObject->DeviceExtension;

    Irp = IoAllocateIrp(Extension->LowerDevice->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("CallUSBD: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    IoStack->Parameters.Others.Argument1 = Urb;

    IoSetCompletionRoutine(Irp, UsbSerSyncCompletion, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(Extension->LowerDevice, Irp);
    if (Status != STATUS_PENDING)
    {
        goto Exit;
    }

    /* Set timeout 30 sec */
    Timeout.QuadPart = (30 * 1000) * -10000;

    Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout);
    if (Status != STATUS_TIMEOUT)
    {
        Status = Irp->IoStatus.Status;
        goto Exit;
    }

    /* End of timeout ... cancel this IRP */
    Status = STATUS_IO_TIMEOUT;
    IoCancelIrp(Irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

Exit:

    IoFreeIrp(Irp);
    return Status;
}

/* EOF */
