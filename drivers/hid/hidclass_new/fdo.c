/*
 * PROJECT:     ReactOS Universal Serial Bus Human Interface Device Driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/hid/hidclass/fdo.c
 * PURPOSE:     HID Class Driver
 * PROGRAMMERS:
 *              Michael Martin (michael.martin@reactos.org)
 *              Johannes Anderwald (johannes.anderwald@reactos.org)
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

NTSTATUS
NTAPI
HidClassFDO_QueryCapabilitiesCompletionRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    //
    // set event
    //
    KeSetEvent(Context, 0, FALSE);

    //
    // completion is done in the HidClassFDO_QueryCapabilities routine
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
HidClassFDO_QueryCapabilities(
    IN PDEVICE_OBJECT DeviceObject,
    IN OUT PDEVICE_CAPABILITIES Capabilities)
{
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    //
    // init event
    //
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    //
    // now allocate the irp
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp)
    {
        //
        // no memory
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // get next stack location
    //
    IoStack = IoGetNextIrpStackLocation(Irp);

    //
    // init stack location
    //
    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStack->Parameters.DeviceCapabilities.Capabilities = Capabilities;

    //
    // set completion routine
    //
    IoSetCompletionRoutine(Irp, HidClassFDO_QueryCapabilitiesCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    //
    // init capabilities
    //
    RtlZeroMemory(Capabilities, sizeof(DEVICE_CAPABILITIES));
    Capabilities->Size = sizeof(DEVICE_CAPABILITIES);
    Capabilities->Version = 1; // FIXME hardcoded constant
    Capabilities->Address = MAXULONG;
    Capabilities->UINumber = MAXULONG;

    //
    // pnp irps have default completion code
    //
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    //
    // call lower  device
    //
    Status = IoCallDriver(FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        //
        // wait for completion
        //
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    //
    // get status
    //
    Status = Irp->IoStatus.Status;

    //
    // complete request
    //
    IoFreeIrp(Irp);

    //
    // done
    //
    return Status;
}

NTSTATUS
NTAPI
HidClassFDO_DispatchRequestSynchronousCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    //
    // signal event
    //
    KeSetEvent(Context, 0, FALSE);

    //
    // done
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
HidClassFDO_DispatchRequestSynchronous(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    KEVENT Event;
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;

    //
    // init event
    //
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    //
    // set completion routine
    //
    IoSetCompletionRoutine(Irp, HidClassFDO_DispatchRequestSynchronousCompletion, &Event, TRUE, TRUE, TRUE);

    ASSERT(Irp->CurrentLocation > 0);
    //
    // create stack location
    //
    IoSetNextIrpStackLocation(Irp);

    //
    // get next stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // store device object
    //
    IoStack->DeviceObject = DeviceObject;

    //
    // sanity check
    //
    ASSERT(CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction] != NULL);

    //
    // call minidriver (hidusb)
    //
    Status = CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction](DeviceObject, Irp);

    //
    // wait for the request to finish
    //
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        //
        // update status
        //
        Status = Irp->IoStatus.Status;
    }

    //
    // done
    //
    return Status;
}

NTSTATUS
HidClassFDO_DispatchRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    ASSERT(Irp->CurrentLocation > 0);

    //
    // create stack location
    //
    IoSetNextIrpStackLocation(Irp);

    //
    // get next stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // store device object
    //
    IoStack->DeviceObject = DeviceObject;

    //
    // sanity check
    //
    ASSERT(CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction] != NULL);

    //
    // call driver
    //
    Status = CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction](DeviceObject, Irp);

    //
    // done
    //
    return Status;
}

NTSTATUS
HidClassFDO_GetDescriptors(
    IN PDEVICE_OBJECT DeviceObject)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;
    PHID_DESCRIPTOR HidDescriptor;
    PHIDP_REPORT_DESCRIPTOR ReportDesc;
    SIZE_T ReportLength;
    ULONG nx;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);
    HidDescriptor = &FDODeviceExtension->HidDescriptor;
    //
    // let's allocate irp
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp)
    {
        //
        // no memory
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // get stack location
    //
    IoStack = IoGetNextIrpStackLocation(Irp);

    //
    // init stack location
    //
    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_DEVICE_DESCRIPTOR;
    IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(HID_DESCRIPTOR);
    IoStack->Parameters.DeviceIoControl.InputBufferLength = 0;
    IoStack->Parameters.DeviceIoControl.Type3InputBuffer = NULL;
    Irp->UserBuffer = HidDescriptor;

    //
    // send request
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed to get device descriptor
        //
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_DESCRIPTOR failed with %x\n", Status);
        IoFreeIrp(Irp);
        return Status;
    }

    if (Irp->IoStatus.Information != sizeof(HID_DESCRIPTOR))
    {
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_DESCRIPTOR: not valid size %x\n",
                Irp->IoStatus.Information);

        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    //
    // let's get device attributes
    //
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_DEVICE_ATTRIBUTES;
    IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(HID_DEVICE_ATTRIBUTES);
    Irp->UserBuffer = &FDODeviceExtension->Common.Attributes;

    //
    // send request
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed to get device descriptor
        //
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_ATTRIBUTES failed with %x\n", Status);
        IoFreeIrp(Irp);
        return Status;
    }

    //
    // sanity checks
    //
    ASSERT(HidDescriptor->bLength == sizeof(HID_DESCRIPTOR));
    ASSERT(HidDescriptor->bNumDescriptors > 0);

    if (HidDescriptor->DescriptorList[0].bReportType != HID_REPORT_DESCRIPTOR_TYPE)
    {
        DPRINT1("[HIDCLASS] bReportType != HID_REPORT_DESCRIPTOR_TYPE (%x)\n",
                HidDescriptor->DescriptorList[0].bReportType);

        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    ReportLength = HidDescriptor->DescriptorList[0].wReportLength;

    if (!ReportLength)
    {
        DPRINT1("[HIDCLASS] wReportLength == 0 \n");
        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    /* allocate report descriptor */ 
    ReportDesc = ExAllocatePoolWithTag(NonPagedPool, ReportLength, HIDCLASS_TAG);

    if (!ReportDesc)
    {
        DPRINT1("[HIDCLASS] report descriptor not allocated \n");
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    nx = 0;

    while (TRUE)
    {
        IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_REPORT_DESCRIPTOR;
        IoStack->Parameters.DeviceIoControl.OutputBufferLength = ReportLength;
        Irp->UserBuffer = ReportDesc;

        Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

        if (NT_SUCCESS(Status))
        {
            break;
        }

  Retry:
        ++nx;

        if (nx >= 3)
        {
            goto Exit;
        }
    }

    if (Irp->IoStatus.Information != ReportLength)
    {
        Status = STATUS_DEVICE_DATA_ERROR;
        goto Retry;
    }

    /* save pointer on report descriptor in extension */ 
    FDODeviceExtension->ReportDescriptor = ReportDesc;

Exit:

    /* deallocate report descriptor if not success */ 
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ReportDesc, 0);
    }

    IoFreeIrp(Irp);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HidClassInitializeCollection(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN ULONG CollectionIdx)
{
    PHIDCLASS_COLLECTION HIDCollection;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    HID_COLLECTION_INFORMATION CollectionInfo;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG CollectionNumber;

    DPRINT("[HIDCLASS] HidClassAllocCollectionResources (%x)\n", CollectionIdx);

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;
    HIDCollection = &FDODeviceExtension->HidCollections[CollectionIdx];

    RtlZeroMemory(HIDCollection, sizeof(HIDCLASS_COLLECTION));

    CollectionNumber = DeviceDescription->CollectionDesc[CollectionIdx].CollectionNumber;
    HIDCollection->CollectionNumber = CollectionNumber;
    HIDCollection->CollectionIdx = CollectionIdx;
    HIDCollection->CloseFlag = 0;

    InitializeListHead(&HIDCollection->InterruptReportList);
    KeInitializeSpinLock(&HIDCollection->CollectSpinLock);
    KeInitializeSpinLock(&HIDCollection->CollectCloseSpinLock);

    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension, CollectionNumber);

    if (!HidCollectionDesc)
    {
        DPRINT1("[HIDCLASS] No HidCollectionDesc (%x)\n", CollectionNumber);
        return STATUS_DATA_ERROR;
    }

    CollectionInfo.DescriptorSize = HidCollectionDesc->PreparsedDataLength;
    CollectionInfo.Polled = FDODeviceExtension->Common.DriverExtension->DevicesArePolled;
    CollectionInfo.VendorID = FDODeviceExtension->Common.Attributes.VendorID;
    CollectionInfo.ProductID = FDODeviceExtension->Common.Attributes.ProductID;
    CollectionInfo.VersionNumber = FDODeviceExtension->Common.Attributes.VersionNumber;

    RtlCopyMemory(&HIDCollection->HidCollectInfo,
                  &CollectionInfo,
                  sizeof(HID_COLLECTION_INFORMATION));

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HidClassFDO_StartDevice(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    ULONG OldFdoState;
    PHIDCLASS_COLLECTION HidCollections;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG CollectionIdx;
    ULONG CollectionNumber;
    SIZE_T Length;

    /* Get device extension */
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    /* Begin FDO start */
    OldFdoState = FDODeviceExtension->HidFdoState;
    FDODeviceExtension->HidFdoState = HIDCLASS_STATE_STARTING;

    /* Query capabilities */
    Status = HidClassFDO_QueryCapabilities(DeviceObject,
                                           &FDODeviceExtension->Capabilities);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("[HIDCLASS] Failed to retrieve capabilities %x\n", Status);
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        goto ExitError;
    }

    /* Let's start the lower device too */
    IoSkipCurrentIrpStackLocation(Irp);
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("[HIDCLASS] Failed to start lower device with %x\n", Status);
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        goto ExitError;
    }

    /* Only first time initialize needed */
    if (OldFdoState == HIDCLASS_STATE_NOT_INIT)
    {
        /* Let's get the descriptors */
        Status = HidClassFDO_GetDescriptors(DeviceObject);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed to retrieve the descriptors %x\n", Status);
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            FDODeviceExtension->ReportDescriptor = HIDCLASS_NULL_POINTER;
            goto ExitError;
        }

        DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;

        /* Now get the the collection description */
        Status = HidP_GetCollectionDescription(FDODeviceExtension->ReportDescriptor,
                                               FDODeviceExtension->HidDescriptor.DescriptorList[0].wReportLength,
                                               NonPagedPool,
                                               DeviceDescription);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed to retrieve the collection description %x\n", Status);
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            goto ExitError;
        }

        /* Device resources alloceted successful */
        FDODeviceExtension->IsDeviceResourcesAlloceted = TRUE;

        /* Now allocete array of HIDCLASS_COLLECTION */
        Length = DeviceDescription->CollectionDescLength * sizeof(HIDCLASS_COLLECTION);
        HidCollections = ExAllocatePoolWithTag(NonPagedPool, Length, HIDCLASS_TAG);
        FDODeviceExtension->HidCollections = HidCollections;

        if (HidCollections)
        {
            RtlZeroMemory(HidCollections, Length);
        }
        else
        {
            DPRINT1("[HIDCLASS] HidCollections not allocated\n");
            FDODeviceExtension->ReportDescriptor = HIDCLASS_NULL_POINTER;
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ExitError;
        }

        /* Initialize collections array */
        if (DeviceDescription->CollectionDescLength)
        {
            CollectionIdx = 0;

            do
            {
                Status = HidClassInitializeCollection(FDODeviceExtension,
                                                      CollectionIdx);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed initialize Collection (Idx %x)\n",
                            CollectionIdx);
                    break;
                }

                CollectionNumber = DeviceDescription->CollectionDesc[CollectionIdx].CollectionNumber;

                /* Allocete resources for current collection */
                Status = HidClassAllocCollectionResources(FDODeviceExtension,
                                                          CollectionNumber);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed alloc Collection (Idx %x) resources\n",
                            CollectionIdx);
                    break;
                }

                ++CollectionIdx;
            }
            while (CollectionIdx < DeviceDescription->CollectionDescLength);
        }

        /* For polled devices shuttles not needed */
        if (FDODeviceExtension->Common.DriverExtension->DevicesArePolled)
        {
            DPRINT("[HIDCLASS] DevicesArePolled \n");
            FDODeviceExtension->ShuttleCount = 0;
            FDODeviceExtension->Shuttles = HIDCLASS_NULL_POINTER;
        }

        /* Initialize shuttle IRPs for first time */
        if (!FDODeviceExtension->NotAllocCollectResources &&
            !FDODeviceExtension->Common.DriverExtension->DevicesArePolled)
        {
            HidClassDestroyShuttles(FDODeviceExtension);

            if (HidClassSetMaxReportSize(FDODeviceExtension))
            {
                FDODeviceExtension->ShuttleCount = HIDCLASS_MINIMUM_SHUTTLE_IRPS;

                Status = HidClassInitializeShuttleIrps(FDODeviceExtension);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed initialize ShuttleIrps\n");
                    FDODeviceExtension->ShuttleCount = 0;
                }
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed alloc Collection (Idx %x) resources\n",
                    CollectionIdx);

            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            goto ExitError;
        }

        /* Re-enumerate PhysicalDeviceObject */
        IoInvalidateDeviceRelations(FDODeviceExtension->Common.HidDeviceExtension.PhysicalDeviceObject,
                                    BusRelations);
    }
    else if (OldFdoState != HIDCLASS_STATE_DISABLED)
    {
        DPRINT1("[HIDCLASS] FDO (%p) should be stopped before starting.\n",
                DeviceObject);

        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        Status = STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (!NT_SUCCESS(Status))
    {
ExitError:
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        return Status;
    }

    /* FDO start successful */
    FDODeviceExtension->HidFdoState = HIDCLASS_STATE_STARTED;

    /* Complete request */
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
HidClassFDO_RemoveDevice(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    /* FIXME cleanup */

    //
    // dispatch to minidriver
    //
    IoSkipCurrentIrpStackLocation(Irp);
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

    //
    // complete request
    //
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);

    //
    // detach and delete device
    //
    IoDetachDevice(FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject);
    IoDeleteDevice(DeviceObject);

    return Status;
}

NTSTATUS
HidClassFDO_CopyDeviceRelations(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PDEVICE_RELATIONS *OutRelations)
{
    PDEVICE_RELATIONS DeviceRelations;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    ULONG Index;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    //
    // allocate result
    //
    DeviceRelations = ExAllocatePoolWithTag(NonPagedPool,
                                            sizeof(DEVICE_RELATIONS) + (FDODeviceExtension->DeviceRelations->Count - 1) * sizeof(PDEVICE_OBJECT),
                                            HIDCLASS_TAG);
    if (!DeviceRelations)
    {
        //
        // no memory
        //
        *OutRelations = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // copy device objects
    //
    for (Index = 0; Index < FDODeviceExtension->DeviceRelations->Count; Index++)
    {
        //
        // reference pdo
        //
        ObReferenceObject(FDODeviceExtension->DeviceRelations->Objects[Index]);

        //
        // store object
        //
        DeviceRelations->Objects[Index] = FDODeviceExtension->DeviceRelations->Objects[Index];
    }

    //
    // set object count
    //
    DeviceRelations->Count = FDODeviceExtension->DeviceRelations->Count;

    //
    // store result
    //
    *OutRelations = DeviceRelations;
    return STATUS_SUCCESS;
}

NTSTATUS
HidClassFDO_DeviceRelations(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;
    PDEVICE_RELATIONS DeviceRelations;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    //
    // get current irp stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // check relations type
    //
    if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
    {
        //
        // only bus relations are handled
        //
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject, Irp);
    }

    if (FDODeviceExtension->DeviceRelations == NULL)
    {
        //
        // time to create the pdos
        //
        Status = HidClassPDO_CreatePDO(DeviceObject, &FDODeviceExtension->DeviceRelations);
        if (!NT_SUCCESS(Status))
        {
            //
            // failed
            //
            DPRINT1("[HIDCLASS] HidClassPDO_CreatePDO failed with %x\n", Status);
            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        //
        // sanity check
        //
        ASSERT(FDODeviceExtension->DeviceRelations->Count > 0);
    }

    //
    // now copy device relations
    //
    Status = HidClassFDO_CopyDeviceRelations(DeviceObject, &DeviceRelations);
    //
    // store result
    //
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;

    //
    // complete request
    //
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
HidClassFDO_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    NTSTATUS Status;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    //
    // get current irp stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    DPRINT1("[HIDCLASS]: FDO IoStack->MinorFunction %x\n", IoStack->MinorFunction);
    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
             return HidClassFDO_StartDevice(DeviceObject, Irp);
        }
        case IRP_MN_REMOVE_DEVICE:
        {
             return HidClassFDO_RemoveDevice(DeviceObject, Irp);
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
             return HidClassFDO_DeviceRelations(DeviceObject, Irp);
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_QUERY_STOP_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        {
            //
            // set status to success and fall through
            //
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        default:
        {
            //
            // dispatch to mini driver
            //
           IoCopyCurrentIrpStackLocationToNext(Irp);
           Status = HidClassFDO_DispatchRequest(DeviceObject, Irp);
           return Status;
        }
    }
}
