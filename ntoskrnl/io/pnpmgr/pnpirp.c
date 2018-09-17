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
    DPRINT("PpIrpQueryID: DeviceNode - %X, IdType - %XPiFailQueryID\n");

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

    DPRINT("PpIrpQueryID: DeviceNode - %X, IdType - %X\n");

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

NTSTATUS
NTAPI
PpIrpQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST * IoResource)
{
    NTSTATUS Status;
    IO_STACK_LOCATION IoStack;

    PAGED_CODE();
    DPRINT("PpIrpQueryResourceRequirements: DeviceObject - %p\n", DeviceObject);

    *IoResource = NULL;

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_RESOURCE_REQUIREMENTS;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)IoResource);

    ASSERT(NT_SUCCESS(Status) || (*IoResource == NULL));

    if (!NT_SUCCESS(Status))
    {
        *IoResource = NULL;
        return Status;
    }

    if (*IoResource == NULL)
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    return Status;
}

NTSTATUS
NTAPI
PpIrpQueryBusInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PPNP_BUS_INFORMATION * OutInformation)
{
    IO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpIrpQueryBusInformation: DeviceObject %p\n", DeviceObject);

    *OutInformation = NULL;
    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_BUS_INFORMATION;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)OutInformation);

    if (!NT_SUCCESS(Status))
    {
        *OutInformation = NULL;
    }

    return Status;
}

NTSTATUS
NTAPI
PpIrpQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PCM_RESOURCE_LIST * OutResourceList,
    _Out_ PULONG OutSize)
{
    IO_STACK_LOCATION IoStack;
    PDEVICE_NODE DeviceNode;
    ULONG ConfigTypes;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpIrpQueryResources: DeviceObject %p\n", DeviceObject);

    *OutResourceList = NULL;
    *OutSize = 0;

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    DeviceNode = IopGetDeviceNode(DeviceObject);

    if (DeviceNode->Flags & DNF_MADEUP)
    {
        DPRINT("PpIrpQueryResources: DeviceNode->Flags & DNF_MADEUP\n");

        ConfigTypes = PIP_CONFIG_TYPE_BOOT +
                      PIP_CONFIG_TYPE_FORCED +
                      PIP_CONFIG_TYPE_ALLOC;

        Status = IopGetDeviceResourcesFromRegistry(DeviceObject,
                                                   FALSE, // PCM_RESOURCE_LIST
                                                   ConfigTypes,
                                                   (PVOID *)OutResourceList,
                                                   OutSize);

        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            return Status;
        }

        return STATUS_SUCCESS;
    }

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_RESOURCES;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID*)OutResourceList);

    if (Status == STATUS_NOT_SUPPORTED)
    {
        DPRINT("PpIrpQueryResources: Status == STATUS_NOT_SUPPORTED\n");
        *OutResourceList = NULL;
        Status = STATUS_SUCCESS;
    }

    if (NT_SUCCESS(Status))
    {
        *OutSize = PnpDetermineResourceListSize(*OutResourceList);
         DPRINT("PpIrpQueryResources: OutSize %X\n", *OutSize);
    }

    return Status;
}

NTSTATUS
NTAPI
IopQueryLegacyBusInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ GUID * OutBusTypeGuid,
    _Out_ INTERFACE_TYPE * OutInterfaceType,
    _Out_ PULONG OutBusNumber)
{
    PLEGACY_BUS_INFORMATION BusInfo;
    PDEVICE_NODE ParentDeviceNode;
    PDEVICE_NODE DeviceNode;
    IO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopQueryLegacyBusInformation: DeviceObject - %p\n", DeviceObject);

    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_LEGACY_BUS_INFORMATION;

    Status = IopSynchronousCall(DeviceObject, &IoStack, (PVOID *)&BusInfo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopQueryLegacyBusInformation: Status - %X\n", Status);
        return Status;
    }

    if (!BusInfo)
    {
        DeviceNode = IopGetDeviceNode(DeviceObject);

        if (!DeviceNode)
        {
            ASSERT(BusInfo);
            return Status;
        }

        ParentDeviceNode = DeviceNode->Parent;

        if (!ParentDeviceNode)
        {
            ASSERT(BusInfo);
            return Status;
        }

        if (ParentDeviceNode->ServiceName.Buffer)
        {
            DPRINT("IopQueryLegacyBusInformation: STATUS_SUCCESS and BusInfo == NULL! Driver - %wZ\n",
                   &ParentDeviceNode->ServiceName);
        }

        ASSERT(BusInfo != NULL);

        return Status;
    }

    if (OutBusTypeGuid)
    {
        RtlCopyMemory(OutBusTypeGuid, &BusInfo->BusTypeGuid, sizeof(GUID));
    }

    if (OutInterfaceType)
    {
        *OutInterfaceType = BusInfo->LegacyBusType;
    }

    if (OutBusNumber)
    {
        *OutBusNumber = BusInfo->BusNumber;
    }

    ExFreePool(BusInfo);

    return Status;
}

NTSTATUS
NTAPI
IopQueryResourceHandlerInterface(
    _In_ ULONG InterfaceType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR InterfaceSpecificData,
    _Out_ PVOID * OutInterface)
{
    PLEGACY_DEVICE_DETECTION_INTERFACE LegacyInterface;
    PTRANSLATOR_INTERFACE TranslatorInterface;
    PARBITER_INTERFACE ArbiterInterface;
    PDEVICE_NODE DeviceNode;
    IO_STACK_LOCATION IoStack;
    PINTERFACE Interface;
    GUID GuidInterfaceType;
    NTSTATUS Status;
    USHORT InterfaceSize;

    PAGED_CODE();
    DeviceNode = IopGetDeviceNode(DeviceObject);
    DPRINT("IopQueryResourceHandlerInterface: InterfaceType - %X, DeviceNode - %p, InterfaceSpecificData - %X\n",
           InterfaceType, DeviceNode, InterfaceSpecificData);

    if (DeviceNode->DuplicatePDO == (PDEVICE_OBJECT)DeviceObject->DriverObject) // Yes, see IopFindLegacyDeviceNode()
    {
        ASSERT(FALSE);
        return STATUS_NOT_SUPPORTED;
    }

    if (!(DeviceObject->Flags & DO_BUS_ENUMERATED_DEVICE))
    {
        ASSERT(FALSE);
        return STATUS_NOT_SUPPORTED;
    }

    switch (InterfaceType)
    {
        case IOP_RES_HANDLER_TYPE_TRANSLATOR:
            InterfaceSize = sizeof(TRANSLATOR_INTERFACE);
            break;

        case IOP_RES_HANDLER_TYPE_ARBITER:
            InterfaceSize = sizeof(ARBITER_INTERFACE);
            break;

        case IOP_RES_HANDLER_TYPE_LEGACY:
            InterfaceSize = sizeof(LEGACY_DEVICE_DETECTION_INTERFACE);
            break;

        default:
            ASSERT(FALSE);
            return STATUS_INVALID_PARAMETER;
    }

    Interface = ExAllocatePoolWithTag(PagedPool, InterfaceSize, '  pP');

    if (!Interface)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Interface, InterfaceSize);
    RtlZeroMemory(&IoStack, sizeof(IoStack));

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    Interface->Version = 0;
    Interface->Size = InterfaceSize;

    switch (InterfaceType)
    {
        case IOP_RES_HANDLER_TYPE_TRANSLATOR:
            RtlCopyMemory(&GuidInterfaceType, &GUID_TRANSLATOR_INTERFACE_STANDARD, sizeof(GUID));
            DPRINT("IopQueryResourceHandlerInterface: GUID_TRANSLATOR_INTERFACE_STANDARD\n");
            break;

        case IOP_RES_HANDLER_TYPE_ARBITER:
            RtlCopyMemory(&GuidInterfaceType, &GUID_ARBITER_INTERFACE_STANDARD, sizeof(GUID));
            DPRINT("IopQueryResourceHandlerInterface: GUID_ARBITER_INTERFACE_STANDARD\n");
            break;

        case IOP_RES_HANDLER_TYPE_LEGACY:
            RtlCopyMemory(&GuidInterfaceType, &GUID_LEGACY_DEVICE_DETECTION_STANDARD, sizeof(GUID));
            DPRINT("IopQueryResourceHandlerInterface: GUID_LEGACY_DEVICE_DETECTION_STANDARD\n");
            break;

        default:
            ASSERT(FALSE);
            return STATUS_INVALID_PARAMETER;
    }

    IoStack.Parameters.QueryInterface.InterfaceType = &GuidInterfaceType;

    IoStack.Parameters.QueryInterface.Size = InterfaceSize;
    IoStack.Parameters.QueryInterface.Version = 0;
    IoStack.Parameters.QueryInterface.Interface = Interface;
    IoStack.Parameters.QueryInterface.InterfaceSpecificData =
                                      ULongToPtr((ULONG)InterfaceSpecificData);

    Status = IopSynchronousCall(DeviceObject, &IoStack, NULL);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopQueryResourceHandlerInterface: Status - %X\n", Status);
        goto ErrorExit;
    }

    switch (InterfaceType)
    {
        case IOP_RES_HANDLER_TYPE_TRANSLATOR:
        {
            TranslatorInterface = (PTRANSLATOR_INTERFACE)Interface;

            if (!TranslatorInterface->TranslateResources ||
                !TranslatorInterface->TranslateResourceRequirements)
            {
                DPRINT("IopQueryResourceHandlerInterface: TranslateResources - %p, TranslateResourceRequirements - %p\n",
                       TranslatorInterface->TranslateResources,
                       TranslatorInterface->TranslateResourceRequirements);

                ASSERT(!NT_SUCCESS(Status));
                Status = STATUS_UNSUCCESSFUL;
            }

            break;
        }
        case IOP_RES_HANDLER_TYPE_ARBITER:
        {
            ArbiterInterface = (PARBITER_INTERFACE)Interface;

            if (!ArbiterInterface->ArbiterHandler)
            {
                DPRINT("IopQueryResourceHandlerInterface: ArbiterHandler == NULL\n");

                ASSERT(!NT_SUCCESS(Status));
                Status = STATUS_UNSUCCESSFUL;
            }

            break;
        }
        case IOP_RES_HANDLER_TYPE_LEGACY:
        {
            LegacyInterface = (PLEGACY_DEVICE_DETECTION_INTERFACE)Interface;

            if (!LegacyInterface->LegacyDeviceDetection)
            {
                DPRINT("IopQueryResourceHandlerInterface: LegacyDeviceDetection == NULL\n");
                ASSERT(!NT_SUCCESS(Status));
                Status = STATUS_UNSUCCESSFUL;
            }

            break;
        }
        default:
        {
            DPRINT("IopQueryResourceHandlerInterface: Unknown InterfaceType - %X\n", InterfaceType);
            ASSERT(FALSE);
            Status = STATUS_INVALID_PARAMETER;
            goto ErrorExit;
        }
    }

    if (NT_SUCCESS(Status))
    {
        *OutInterface = Interface;
        return Status;
    }

ErrorExit:

    ExFreePoolWithTag(Interface, '  pP');
    return Status;
}

NTSTATUS
NTAPI
IopFilterResourceRequirementsCall(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResources,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST * OutRequirementsList)
{
    PDEVICE_OBJECT TopDeviceObject;
    PIO_STACK_LOCATION IoStack;
    IO_STATUS_BLOCK IoSb;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopFilterResourceRequirementsCall: DeviceObject - %p, IoResources - %p\n",
           DeviceObject, IoResources);

    TopDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    Irp = IoAllocateIrp(TopDeviceObject->StackSize, FALSE);

    if (!Irp)
    {
        DPRINT1("IopFilterResourceRequirementsCall: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(TopDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (IoResources)
    {
        IoSb.Status = STATUS_SUCCESS;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        IoSb.Information = (ULONG_PTR)IoResources;
        Irp->IoStatus.Information = (ULONG_PTR)IoResources;
    }
    else
    {
        IoSb.Status = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    Irp->UserIosb = &IoSb;
    Irp->UserEvent = &Event;

    Irp->Tail.Overlay.Thread = PsGetCurrentThread();

    KeEnterCriticalRegion();
    IoQueueThreadIrp(Irp);
    KeLeaveCriticalRegion();

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList = IoResources;

    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_FILTER_RESOURCE_REQUIREMENTS;

    Status = IoCallDriver(TopDeviceObject, Irp);

    if (!NT_SUCCESS(Status) || Status == STATUS_PENDING)
    {
        DPRINT("IopFilterResourceRequirementsCall: IRP_MN_FILTER_RESOURCE_REQUIREMENTS. Driver %wZ return Status - %X\n",
               &TopDeviceObject->DriverObject->DriverName, Status);

        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoSb.Status;
        }
    }

    *OutRequirementsList = (PIO_RESOURCE_REQUIREMENTS_LIST)IoSb.Information;

    ObDereferenceObject(TopDeviceObject);

    return Status;
}

/* EOF */
