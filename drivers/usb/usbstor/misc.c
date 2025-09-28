/*
 * PROJECT:     ReactOS Universal Serial Bus Bulk Storage Driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB block storage device driver.
 * COPYRIGHT:   2005-2006 James Tabor
 *              2011-2012 Michael Martin (michael.martin@reactos.org)
 *              2011-2013 Johannes Anderwald (johannes.anderwald@reactos.org)
 */

#include "usbstor.h"

#define NDEBUG
#include <debug.h>


IO_COMPLETION_ROUTINE SyncForwardIrpCompletionRoutine;

NTSTATUS
NTAPI
USBSTOR_SyncForwardIrpCompletionRoutine(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context)
{
    if (Irp->PendingReturned)
    {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
USBSTOR_SyncForwardIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KEVENT Event;
    NTSTATUS Status;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, USBSTOR_SyncForwardIrpCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING)
    {
        // wait for the request to finish
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    return Status;
}

NTSTATUS
NTAPI
USBSTOR_GetBusInterface(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PUSB_BUS_INTERFACE_USBDI_V2 BusInterface)
{
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatus;
    PIO_STACK_LOCATION Stack;

    ASSERT(DeviceObject);
    ASSERT(BusInterface);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       DeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &IoStatus);
    if (Irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // initialize request
    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_PNP;
    Stack->MinorFunction = IRP_MN_QUERY_INTERFACE;
    Stack->Parameters.QueryInterface.Size = sizeof(BUS_INTERFACE_STANDARD);
    Stack->Parameters.QueryInterface.InterfaceType = (LPGUID)&USB_BUS_INTERFACE_USBDI_GUID;
    Stack->Parameters.QueryInterface.Version = 2;
    Stack->Parameters.QueryInterface.Interface = (PINTERFACE)BusInterface;
    Stack->Parameters.QueryInterface.InterfaceSpecificData = NULL;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    return Status;
}

NTSTATUS
USBSTOR_SyncUrbRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PURB Urb)
{
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    DPRINT("USBSTOR_SyncUrbRequest: %p, %p\n", DeviceObject, Urb);
    PAGED_CODE();

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("USBSTOR_SyncUrbRequest: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoStack = IoGetNextIrpStackLocation(Irp);

    // initialize stack location
    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    IoStack->Parameters.Others.Argument1 = Urb;
    IoStack->Parameters.DeviceIoControl.InputBufferLength = Urb->UrbHeader.Length;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSetCompletionRoutine(Irp, USBSTOR_SyncForwardIrpCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING)
    {
        Timeout.QuadPart = (5000 * -10000);

        if (KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT)
        {
            DPRINT1("USBSTOR_SyncUrbRequest: STATUS_IO_TIMEOUT (%p, %p)\n", DeviceObject, Irp);
            Status = STATUS_IO_TIMEOUT;

            IoCancelIrp(Irp);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        }
        else
        {
            Status = Irp->IoStatus.Status;
        }
    }

    IoFreeIrp(Irp);
    return Status;
}

PVOID
AllocateItem(
    IN POOL_TYPE PoolType,
    IN ULONG ItemSize)
{
    PVOID Item = ExAllocatePoolWithTag(PoolType, ItemSize, USB_STOR_TAG);

    if (Item)
    {
        RtlZeroMemory(Item, ItemSize);
    }

    return Item;
}

VOID
FreeItem(
    IN PVOID Item)
{
    ExFreePoolWithTag(Item, USB_STOR_TAG);
}

NTSTATUS
USBSTOR_ClassRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PFDO_DEVICE_EXTENSION DeviceExtension,
    IN UCHAR RequestType,
    IN USHORT Index,
    IN ULONG TransferFlags,
    IN ULONG TransferBufferLength,
    IN PVOID TransferBuffer)

{
    PURB Urb;
    NTSTATUS Status;

    Urb = (PURB)AllocateItem(NonPagedPool, sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST));
    if (!Urb)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Urb->UrbControlVendorClassRequest.Hdr.Length = sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
    Urb->UrbControlVendorClassRequest.Hdr.Function = URB_FUNCTION_CLASS_INTERFACE;
    Urb->UrbControlVendorClassRequest.TransferFlags = TransferFlags;
    Urb->UrbControlVendorClassRequest.TransferBufferLength = TransferBufferLength;
    Urb->UrbControlVendorClassRequest.TransferBuffer = TransferBuffer;
    Urb->UrbControlVendorClassRequest.Request = RequestType;
    Urb->UrbControlVendorClassRequest.Index = Index;

    Status = USBSTOR_SyncUrbRequest(DeviceObject, Urb);

    FreeItem(Urb);
    return Status;
}

NTSTATUS
USBSTOR_GetMaxLUN(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PFDO_DEVICE_EXTENSION DeviceExtension)
{
    PUCHAR Buffer;
    PURB Urb;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("USBSTOR_GetMaxLUN: %p, %p\n", DeviceObject, DeviceExtension);

    Urb = ExAllocatePoolWithTag(NonPagedPool, (sizeof(*Urb) + sizeof(*Buffer)), USB_STOR_TAG);
    if (!Urb)
    {
        DPRINT1("USBSTOR_GetMaxLUN: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Buffer = (PUCHAR)&Urb[1];

    for (ix = 0; ix < 2; ix++)
    {
        RtlZeroMemory(Urb, (sizeof(*Urb) + sizeof(*Buffer)));

        Urb->UrbHeader.Length = sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
        Urb->UrbHeader.Function = URB_FUNCTION_CLASS_INTERFACE;

        Urb->UrbControlVendorClassRequest.Request = USB_BULK_GET_MAX_LUN;
        Urb->UrbControlVendorClassRequest.Index = DeviceExtension->InterfaceInformation->InterfaceNumber;

        Urb->UrbControlVendorClassRequest.TransferFlags = USBD_TRANSFER_DIRECTION_IN;
        Urb->UrbControlVendorClassRequest.TransferBuffer = Buffer;
        Urb->UrbControlVendorClassRequest.TransferBufferLength = sizeof(*Buffer);

        Status = USBSTOR_SyncUrbRequest(DeviceObject, Urb);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("USBSTOR_GetMaxLUN: Status %X\n", Status);

            if (USBD_STATUS(Urb->UrbHeader.Status) == USBD_STATUS(USBD_STATUS_STALL_PID))
            {
                /* "USB Mass Storage Class. Bulk-Only Transport. Revision 1.0"
                   3.2  Get Max LUN (class-specific request) :
                   Devices that do not support multiple LUNs may STALL this command.
                */

                RtlZeroMemory(Urb, sizeof(*Urb));

                Urb->UrbHeader.Length = sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
                Urb->UrbHeader.Function = URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT;

                Urb->UrbControlFeatureRequest.FeatureSelector = 0;

                USBSTOR_SyncUrbRequest(DeviceObject, Urb);
            }

            continue;
        }

        if (Urb->UrbControlVendorClassRequest.TransferBufferLength == 1)
        {
            if (*Buffer > 0xF)
            {
                DPRINT1("USBSTOR_GetMaxLUN: STATUS_DEVICE_DATA_ERROR (%X)\n", *Buffer);

                /* invalid response documented in usb mass storage specification */
                Status = STATUS_DEVICE_DATA_ERROR;
            }
            else
            {
                /* store maxlun */
                DeviceExtension->MaxLUN = *Buffer;

                if (DeviceExtension->MaxLUN)
                {
                    DPRINT("USBSTOR_GetMaxLUN: MaxLUN %X (%p)\n", *Buffer, DeviceObject);
                }
            }

            break;
        }

        DPRINT1("USBSTOR_GetMaxLUN: STATUS_DEVICE_DATA_ERROR\n");
        Status = STATUS_DEVICE_DATA_ERROR;
    }

    ExFreePoolWithTag(Urb, USB_STOR_TAG);

Exit:

    DPRINT("USBSTOR_GetMaxLUN: ret %X\n", Status);

    return Status;
}

NTSTATUS
USBSTOR_ResetDevice(
    IN PDEVICE_OBJECT DeviceObject,
    IN PFDO_DEVICE_EXTENSION DeviceExtension)
{
    NTSTATUS Status;

    Status = USBSTOR_ClassRequest(DeviceObject, DeviceExtension, USB_BULK_RESET_DEVICE, DeviceExtension->InterfaceInformation->InterfaceNumber, USBD_TRANSFER_DIRECTION_OUT, 0, NULL);
    return Status;
}

// if somebody wants to add UFI support, here is a useful function
#if 0
BOOLEAN
USBSTOR_IsFloppy(
    IN PUCHAR Buffer,
    IN ULONG BufferLength,
    OUT PUCHAR MediumTypeCode)
{
    PUFI_CAPACITY_FORMAT_HEADER FormatHeader;
    PUFI_CAPACITY_DESCRIPTOR Descriptor;
    ULONG Length, Index, BlockCount, BlockLength;

    FormatHeader = (PUFI_CAPACITY_FORMAT_HEADER)Buffer;
    ASSERT(FormatHeader->Reserved1 == 0x00);
    ASSERT(FormatHeader->Reserved2 == 0x00);
    ASSERT(FormatHeader->Reserved3 == 0x00);

    // is there capacity data
    if (!FormatHeader->CapacityLength)
    {
        DPRINT1("[USBSTOR] No capacity length\n");
        return FALSE;
    }

    // the format header are always 8 bytes in length
    ASSERT((FormatHeader->CapacityLength & 0x7) == 0);
    DPRINT1("CapacityLength %x\n", FormatHeader->CapacityLength);

    // grab length and locate first descriptor
    Length = FormatHeader->CapacityLength;
    Descriptor = (PUFI_CAPACITY_DESCRIPTOR)(FormatHeader + 1);
    for (Index = 0; Index < Length / sizeof(UFI_CAPACITY_DESCRIPTOR); Index++)
    {
        // blocks are little endian format
        BlockCount = NTOHL(Descriptor->BlockCount);
        BlockLength = NTOHL((Descriptor->BlockLengthByte0 << 24 | Descriptor->BlockLengthByte1 << 16 | Descriptor->BlockLengthByte2 << 8));

        DPRINT1("BlockCount %x BlockLength %x Code %x\n", BlockCount, BlockLength, Descriptor->Code);

        if (BlockLength == 512 && BlockCount == 1440)
        {
            // 720 KB DD
            *MediumTypeCode = 0x1E;
            return TRUE;
        }
        else if (BlockLength == 1024 && BlockCount == 1232)
        {
            // 1,25 MB
            *MediumTypeCode = 0x93;
            return TRUE;
        }
        else if (BlockLength == 512 && BlockCount == 2880)
        {
            // 1,44MB KB DD
            *MediumTypeCode = 0x94;
            return TRUE;
        }

        Descriptor++;
    }

    return FALSE;
}
#endif
