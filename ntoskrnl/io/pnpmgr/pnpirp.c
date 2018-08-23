/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpirp.c
 * PURPOSE:         Code for IRP_MJ_PNP requests
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
IopSynchronousCall(IN PDEVICE_OBJECT DeviceObject,
                   IN PIO_STACK_LOCATION IoStackLocation,
                   OUT PVOID *Information)
{
    PIRP Irp;
    PIO_STACK_LOCATION IrpStack;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    NTSTATUS Status;
    PDEVICE_OBJECT TopDeviceObject;
    PAGED_CODE();

    /* Call the top of the device stack */
    TopDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    /* Allocate an IRP */
    Irp = IoAllocateIrp(TopDeviceObject->StackSize, FALSE);
    if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

    /* Initialize to failure */
    Irp->IoStatus.Status = IoStatusBlock.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = IoStatusBlock.Information = 0;

    /* Special case for IRP_MN_FILTER_RESOURCE_REQUIREMENTS */
    if (IoStackLocation->MinorFunction == IRP_MN_FILTER_RESOURCE_REQUIREMENTS)
    {
        /* Copy the resource requirements list into the IOSB */
        Irp->IoStatus.Information =
        IoStatusBlock.Information = (ULONG_PTR)IoStackLocation->Parameters.FilterResourceRequirements.IoResourceRequirementList;
    }

    /* Initialize the event */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Set them up */
    Irp->UserIosb = &IoStatusBlock;
    Irp->UserEvent = &Event;

    /* Queue the IRP */
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    IoQueueThreadIrp(Irp);

    /* Copy-in the stack */
    IrpStack = IoGetNextIrpStackLocation(Irp);
    *IrpStack = *IoStackLocation;

    /* Call the driver */
    Status = IoCallDriver(TopDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        /* Wait for it */
        KeWaitForSingleObject(&Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        Status = IoStatusBlock.Status;
    }

    /* Remove the reference */
    ObDereferenceObject(TopDeviceObject);

    /* Return the information */
    if (Information)
    {
        *Information = (PVOID)IoStatusBlock.Information;
    }

    return Status;
}

NTSTATUS
NTAPI
IopQueryDeviceRelations(
    _In_ DEVICE_RELATION_TYPE RelationsType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PDEVICE_RELATIONS * OutPendingDeviceRelations)
{
    PDEVICE_NODE DeviceNode;
    IO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    RtlZeroMemory(&IoStack, sizeof(IO_STACK_LOCATION));
    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS;

    IoStack.Parameters.QueryDeviceRelations.Type = RelationsType;

    Status = IopSynchronousCall(DeviceObject,
                                &IoStack,
                                (PVOID *)OutPendingDeviceRelations);

    if (RelationsType == BusRelations)
    {
        DeviceNode = IopGetDeviceNode(DeviceObject);
        DeviceNode->CompletionStatus = Status;

        PipSetDevNodeState(DeviceNode, DeviceNodeEnumerateCompletion, NULL);
        Status = STATUS_SUCCESS;
    }
    else
    {
        DPRINT("IopQueryDeviceRelations: RelationsType - %X, Status %X\n",
               RelationsType, Status);
    }

    return Status;
}

NTSTATUS
NTAPI
PpIrpQueryID(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PWCHAR *OutID)
{
    IO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpIrpQueryID: DeviceObject - %p, IdType - %X\n", DeviceObject, IdType);

    ASSERT(IdType == BusQueryDeviceID ||
           IdType == BusQueryInstanceID ||
           IdType == BusQueryHardwareIDs ||
           IdType == BusQueryCompatibleIDs ||
           IdType == BusQueryDeviceSerialNumber);
    
    *OutID = NULL;

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_ID;

    IoStack.Parameters.QueryId.IdType = IdType;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)OutID);

    if (!NT_SUCCESS(Status))
    {
        ASSERT(NT_SUCCESS(Status) || (*OutID == NULL));
        *OutID = NULL;
    }
    else if (*OutID == NULL)
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    DPRINT("PpIrpQueryID: DeviceNode - %X, IdType - %XPiFailQueryID\n");

    return Status;
}

NTSTATUS
NTAPI
PpIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_CAPABILITIES DeviceCapabilities)
{
    IO_STACK_LOCATION IoStack;

    PAGED_CODE();
    DPRINT("PpIrpQueryCapabilities: DeviceCapabilities %p\n", DeviceCapabilities);

    RtlZeroMemory(DeviceCapabilities, sizeof(DEVICE_CAPABILITIES));

    DeviceCapabilities->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapabilities->Version = 1;

    DeviceCapabilities->Address = -1;
    DeviceCapabilities->UINumber = -1;

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_CAPABILITIES;

    IoStack.Parameters.DeviceCapabilities.Capabilities = DeviceCapabilities;

    return IopSynchronousCall(DeviceObject, &IoStack, NULL);
}

NTSTATUS
NTAPI
IopQueryDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PNP_DEVICE_STATE *OutState)
{
    PNP_DEVICE_STATE State;
    IO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopQueryDeviceState: DeviceObject - %p\n", DeviceObject);

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_PNP_DEVICE_STATE;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)&State);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopQueryDeviceState: Status - %X\n", Status);
        return Status;
    }

    *OutState = State;

    return Status;
}

NTSTATUS
NTAPI
PpIrpQueryDeviceText(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_TEXT_TYPE DeviceTextType,
    _In_ LCID LocaleId,
    _Out_ PWCHAR * OutDeviceText)
{
    NTSTATUS Status;
    IO_STACK_LOCATION IoStack;

    PAGED_CODE();
    DPRINT("PpIrpQueryDeviceText: DeviceObject - %p\n", DeviceObject);

    ASSERT(DeviceTextType == DeviceTextDescription ||
           DeviceTextType == DeviceTextLocationInformation);

    *OutDeviceText = NULL;

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_DEVICE_TEXT;

    IoStack.Parameters.QueryDeviceText.DeviceTextType = DeviceTextType;
    IoStack.Parameters.QueryDeviceText.LocaleId = LocaleId;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)OutDeviceText);

    ASSERT(NT_SUCCESS(Status) || (*OutDeviceText == NULL));

    if (!NT_SUCCESS(Status))
    {
        *OutDeviceText = NULL;
        return Status;
    }

    if (*OutDeviceText == NULL)
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    return Status;
}

/* EOF */
