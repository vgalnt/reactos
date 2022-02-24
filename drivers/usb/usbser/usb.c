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

NTSTATUS
NTAPI
GetDeviceDescriptor(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    struct _URB_CONTROL_DESCRIPTOR_REQUEST * Urb;
    PUSB_DEVICE_DESCRIPTOR Descriptor;
    PUSB_DEVICE_DESCRIPTOR OldDescriptor;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("GetDeviceDescriptor: DeviceObject %p\n", DeviceObject);

    Extension = DeviceObject->DeviceExtension;
    Urb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Urb), USBSER_TAG);
    if (!Urb)
    {
        DPRINT1("GetDeviceDescriptor: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Descriptor = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Descriptor), USBSER_TAG);
    if (!Descriptor)
    {
        DPRINT1("GetDeviceDescriptor: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(Urb, USBSER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Urb->Hdr.Function = URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE;
    Urb->Hdr.Length = sizeof(*Urb);

    Urb->DescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
    Urb->TransferBufferLength = sizeof(*Descriptor);
    Urb->TransferBuffer = Descriptor;
    Urb->TransferBufferMDL = NULL;

    Urb->Index = 0;
    Urb->LanguageId = 0;
    Urb->UrbLink = NULL;

    Status = CallUSBD(DeviceObject, (PURB)Urb);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("GetDeviceDescriptor: Status %X\n", Status);

        if (Descriptor)
            ExFreePoolWithTag(Descriptor, USBSER_TAG);

        ExFreePoolWithTag(Urb, USBSER_TAG);

        return Status;
    }

    OldDescriptor = NULL;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    if (Extension->DeviceDescriptor)
        OldDescriptor = Extension->DeviceDescriptor;
    Extension->DeviceDescriptor = Descriptor;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    if (OldDescriptor)
        ExFreePoolWithTag(OldDescriptor, USBSER_TAG);

    ExFreePoolWithTag(Urb, USBSER_TAG);

    return Status;
}

/* EOF */
