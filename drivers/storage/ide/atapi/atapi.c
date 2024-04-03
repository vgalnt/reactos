/*
 * PROJECT:         ReactOS Storage Stack
 * LICENSE:         See COPYING in the top level directory
 * FILE:            drivers/storage/atapi/atapi.c
 * PURPOSE:         ATAPI IDE miniport driver
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include "atapi.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

//ATAPI_FDO_LIST IdeGlobalFdoList = {-1, {NULL, NULL}, 0};
ULONG FdoIndex = 0;

PDRIVER_DISPATCH FdoPnpDispatchTable[] =
{
    ChannelStartDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelRemoveDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelStopDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelQueryDeviceRelations,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    ChannelFilterResourceRequirements,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    ChannelQueryId,
    ChannelQueryPnPDeviceState,
    IdePortPassDownToNextDriver,
    ChannelUsageNotification,
    ChannelSurpriseRemoveDevice,
    IdePortPassDownToNextDriver
};

PDRIVER_DISPATCH FdoPowerDispatchTable[] =
{
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortSetFdoPowerState,
    ChannelQueryPowerState
};

PCHAR PnpMinorNames[] =
{
    "IRP_MN_START_DEVICE",
    "IRP_MN_QUERY_REMOVE_DEVICE",
    "IRP_MN_REMOVE_DEVICE",
    "IRP_MN_CANCEL_REMOVE_DEVICE",
    "IRP_MN_STOP_DEVICE",
    "IRP_MN_QUERY_STOP_DEVICE",
    "IRP_MN_CANCEL_STOP_DEVICE",
    "IRP_MN_QUERY_DEVICE_RELATIONS",
    "IRP_MN_QUERY_INTERFACE",
    "IRP_MN_QUERY_CAPABILITIES",
    "IRP_MN_QUERY_RESOURCES",
    "IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
    "IRP_MN_QUERY_DEVICE_TEXT",
    "IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
    "an undefined PnP IRP",
    "IRP_MN_READ_CONFIG",
    "IRP_MN_WRITE_CONFIG",
    "IRP_MN_EJECT",
    "IRP_MN_SET_LOCK",
    "IRP_MN_QUERY_ID",
    "IRP_MN_QUERY_PNP_DEVICE_STATE",
    "IRP_MN_QUERY_BUS_INFORMATION",
    "IRP_MN_DEVICE_USAGE_NOTIFICATION",
    "IRP_MN_SURPRISE_REMOVAL",
    "IRP_MN_QUERY_LEGACY_BUS_INFORMATION"
};

/* PRIVATE FUNCTIONS ********************************************************/

VOID
NTAPI
IdePortUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ChannelAddChannel(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo,
    _Out_ PFDO_DEVICE_EXTENSION* OutFdoExtension)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    UNICODE_STRING FdoName;
    WCHAR NameBuffer[0x40];
    PDEVICE_OBJECT Fdo;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelAddChannel: %p, %p\n", DriverObject, LowerPdo);

    swprintf(NameBuffer, L"\\Device\\Ide\\IdePort%d", FdoIndex);
    RtlInitUnicodeString(&FdoName, NameBuffer);

    Status = IoCreateDevice(DriverObject, sizeof(*FdoExtension), &FdoName, 4, 0x100, 0, &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelAddChannel: Status %X\n", Status);
        return Status;
    }

    FdoExtension = Fdo->DeviceExtension;
    RtlZeroMemory(FdoExtension, sizeof(*FdoExtension));

    FdoExtension->HwDeviceExtension = &FdoExtension->AtaExt;
    FdoExtension->LowPdo = LowerPdo;
    FdoExtension->DriverObject = DriverObject;
    FdoExtension->SelfDevice = Fdo;
    FdoExtension->PassDownToNextDriver = IdePortPassDownToNextDriver;
    FdoExtension->FdoPnpDispatchTable = FdoPnpDispatchTable;
    FdoExtension->FdoPowerDispatchTable = FdoPowerDispatchTable;
    //FdoExtension->FdoWmiDispatchTable = FdoWmiDispatchTable;

    FdoExtension->LowDevice = IoAttachDeviceToDeviceStack(Fdo, LowerPdo);
    if (!FdoExtension->LowDevice)
    {
        DPRINT1("ChannelAddChannel: STATUS_UNSUCCESSFUL\n");
        IoDeleteDevice(Fdo);
        return STATUS_UNSUCCESSFUL;
    }

    if (FdoExtension->LowDevice->AlignmentRequirement < 1)
        Fdo->AlignmentRequirement = 1;
    else
        Fdo->AlignmentRequirement = FdoExtension->LowDevice->AlignmentRequirement;

    FdoExtension->FdoIndex = FdoIndex++;

    *OutFdoExtension = FdoExtension;

    //IdeAddToFdoList(&IdeGlobalFdoList, FdoExtension);

    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT("ChannelAddChannel: DeviceObject %p returnd status %X from Addevice\n", LowerPdo, Status);

    return Status;
}

NTSTATUS
NTAPI
ChannelAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PFDO_DEVICE_EXTENSION dummy;
    return ChannelAddChannel(DriverObject, LowerPdo, &dummy);
}

VOID
NTAPI
IdePortStartIo(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* SCSI FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
IdePortDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* POWER FUNCTIONS **********************************************************/

/* FDO POWER FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
IdePortSetFdoPowerState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PNP FUNCTIONS ************************************************************/

NTSTATUS
NTAPI
IdePortStatusSuccessAndPassDownToNextDriver(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortPassDownToNextDriver(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("IdePortPassDownToNextDriver: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    ASSERT(FdoExtension->LowDevice);

    if ((IoGetCurrentIrpStackLocation(Irp))->MajorFunction == IRP_MJ_POWER)
    {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(FdoExtension->LowDevice, Irp);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
IdePortNoSupportIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* FDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ChannelStartDeviceCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortGenericCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PRKEVENT Event = Context;

    DPRINT("IdePortGenericCompletionRoutine: %p\n", Context);

    KeSetEvent(Event, EVENT_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IdePortSyncSendIrp(
    _In_ PDEVICE_OBJECT LowDevice,
    _In_ PIO_STACK_LOCATION IoStack,
    _Out_ PIO_STATUS_BLOCK OutIoStatus)
{
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    ASSERT(LowDevice);
    ASSERT(IoStack);

    DPRINT("IdePortSyncSendIrp: %p, %p, %p\n", LowDevice, IoStack, OutIoStatus);
    Irp = IoAllocateIrp(LowDevice->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("IdePortSyncSendIrp: Unable to get allocate an irp");
        return STATUS_NO_MEMORY;
    }
    RtlMoveMemory(IoGetNextIrpStackLocation(Irp), IoStack, sizeof(*IoStack));

    if (OutIoStatus)
        Irp->IoStatus.Status = OutIoStatus->Status;
    else
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(Irp, IdePortGenericCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    if (IoCallDriver(LowDevice, Irp) == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;

    if (OutIoStatus)
    {
        OutIoStatus->Status = Status;
        OutIoStatus->Information = Irp->IoStatus.Information;
    }

    IoFreeIrp(Irp);

    return Status;
}

NTSTATUS
NTAPI
ChannelStartChannel(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelStartDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PCM_RESOURCE_LIST CmResources;
    PCM_FULL_RESOURCE_DESCRIPTOR CmList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_RESOURCE_LIST NewCmResources;
    PCM_FULL_RESOURCE_DESCRIPTOR NewCmList;
    PCM_RESOURCE_LIST ParentCmResources;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    PIRP irp;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    ULONG PartialSize;
    ULONG Size1 = 0;
    ULONG Size2;
    ULONG size;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    DPRINT("ChannelStartDevice: %p, %p\n", Fdo, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    FdoExtension = Fdo->DeviceExtension;
    ASSERT(!(FdoExtension->FdoState & 2));//FDOS_STARTED

    CmResources = IoStack->Parameters.StartDevice.AllocatedResourcesTranslated;
    if (CmResources)
    {
      #if DBG
        DPRINT1("ChannelStartDevice: %p, %p\n", Fdo, CmResources);
        RosDumpCmResources(CmResources, 0);
      #endif

        CmList = CmResources->List;

        for (ix = 0; ix < CmResources->Count; ix = (jx + 1))
        {
            CmDescriptor = CmList->PartialResourceList.PartialDescriptors;
            PartialSize = 0;

            for (jx = 0; jx < CmList->PartialResourceList.Count; jx++)
            {
                PartialSize += sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

                if (CmDescriptor[jx].Type == 5)
                    PartialSize += CmDescriptor[jx].u.DeviceSpecificData.DataSize;
            }

            Size1 += PartialSize + FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList.PartialDescriptors);

            CmList = Add2Ptr(CmList, Size1);
        }

        Size1 += FIELD_OFFSET(CM_RESOURCE_LIST, List);
    }

    size = (sizeof(CM_RESOURCE_LIST) + (2 * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)));

    ParentCmResources = ExAllocatePoolWithTag(PagedPool, size, 'PedI');
    if (!ParentCmResources)
    {
        DPRINT1("ChannelStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(ParentCmResources, size);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    irp = IoBuildDeviceIoControlRequest(0x41414,
                                        FdoExtension->LowDevice,
                                        ParentCmResources,
                                        size,
                                        ParentCmResources,
                                        size,
                                        TRUE,
                                        &Event,
                                        &IoStatusBlock);
    if (!irp)
    {
        DPRINT1("ChannelStartDevice: Unable to allocate Irp to bind with busmaster parent\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    Status = IoCallDriver(FdoExtension->LowDevice, irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: %p, %p\n", Fdo, ParentCmResources);
        RosDumpCmResources(ParentCmResources, 0);
        Size2 = IoStatusBlock.Information;
    }
    else
    {
        DPRINT("ChannelStartDevice: Status %X\n", Status);
        Size2 = 0;
    }

    if (Size1 + Size2)
        NewCmResources = ExAllocatePoolWithTag(NonPagedPool, (Size1 + Size2), 'PedI');
    else
        NewCmResources = NULL;

    if (!NewCmResources)
    {
        DPRINT1("ChannelStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    NewCmResources->Count = 0;

    if (Size1)
    {
        RtlCopyMemory(NewCmResources->List, CmResources->List, (Size1 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmList = Add2Ptr(NewCmResources->List, (Size1 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmResources->Count = CmResources->Count;
    }
    else
    {
        NewCmList = NewCmResources->List;
    }

    if (Size2)
    {
        RtlCopyMemory(NewCmList, ParentCmResources->List, (Size2 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmList = Add2Ptr(NewCmList, (Size2 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmResources->Count += ParentCmResources->Count;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ChannelStartDeviceCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(FdoExtension->LowDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: Status %X\n", Status);
        ExFreePoolWithTag(NewCmResources, 'PedI');
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    Status = ChannelStartChannel(FdoExtension, NewCmResources);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: Status %X\n", Status);
        ExFreePoolWithTag(NewCmResources, 'PedI');
    }

    ExFreePoolWithTag(ParentCmResources, 'PedI');

Exit:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelFilterResourceRequirements(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_DESCRIPTOR CommandPortDescriptor;
    PIO_RESOURCE_DESCRIPTOR ControlPortDescriptor;
    PIO_RESOURCE_DESCRIPTOR InterruptDescriptor;
    PIO_RESOURCE_DESCRIPTOR FirstDescriptor;
    PIO_RESOURCE_DESCRIPTOR NewDescriptor;
    PIO_RESOURCE_DESCRIPTOR CurrentDescriptor;
    PIO_RESOURCE_REQUIREMENTS_LIST NewIoResources;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PIO_RESOURCE_LIST NewIoList;
    PIO_RESOURCE_LIST IoList;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    IDE_TRANSFER_MODE_INTERFACE Iface;
    IO_STACK_LOCATION ioStack;
    ULONG Length;
    ULONG Size;
    ULONG ix;
    ULONG jx;
    ULONG kx;
    NTSTATUS Status;

    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("AtaFdoFilterResourceRequirements: %p, %p\n",
           Fdo, IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList);

    RosDumpIoResources(IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList, 0);

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.Size = sizeof(Iface);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_XFER_MODE_INTERFACE;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&Iface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    FdoExtension = Fdo->DeviceExtension;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("AtaFdoFilterResourceRequirements: Irp->IoStatus.Status %X\n", Irp->IoStatus.Status);
        IoResources = IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList;
    }
    else
    {
        ASSERT(Irp->IoStatus.Information);
        IoResources = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    }

    if (!IoResources)
    {
        DPRINT("AtaFdoFilterResourceRequirements: IoResources is NULL\n");
        goto Exit;
    }

    if (!IoResources->AlternativeLists)
    {
        DPRINT("AtaFdoFilterResourceRequirements: IoResources->AlternativeLists is 0\n");
        goto Exit;
    }

    Size = (IoResources->ListSize + (IoResources->AlternativeLists * sizeof(IO_RESOURCE_DESCRIPTOR)));

    NewIoResources = ExAllocatePoolWithTag(PagedPool, Size, 'PedI');
    if (!NewIoResources)
    {
        DPRINT1("AtaFdoFilterResourceRequirements: Allocate failed\n");
        goto Exit;
    }
    RtlCopyMemory(NewIoResources, IoResources, sizeof(IO_RESOURCE_REQUIREMENTS_LIST));

    NewIoResources->ListSize = Size;

    IoList = IoResources->List;
    NewIoList = NewIoResources->List;

    for (ix = 0; ix < IoResources->AlternativeLists; ix++)
    {
        InterruptDescriptor = 0;
        CommandPortDescriptor = 0;
        ControlPortDescriptor = 0;

        FirstDescriptor = IoList->Descriptors;

        for (jx = 0; jx < IoList->Count; jx++)
        {
            if (IoList->Descriptors[jx].Type == 1)
            {
                Length = IoList->Descriptors[jx].u.Port.Length;

                if (Length == 8 && !CommandPortDescriptor)
                {
                    CommandPortDescriptor = &IoList->Descriptors[jx];
                }
                else if ((Length == 1 || Length == 2 || Length == 4) && !ControlPortDescriptor)
                {
                    ControlPortDescriptor = &IoList->Descriptors[jx];
                }
                else if (Length >= 0x10 && !CommandPortDescriptor && !ControlPortDescriptor)
                {
                    CommandPortDescriptor = ControlPortDescriptor = &IoList->Descriptors[jx];
                }
            }
            else if (IoList->Descriptors[jx].Type == 2 && !InterruptDescriptor)
            {
                InterruptDescriptor = &IoList->Descriptors[jx];
            }
        }

        RtlCopyMemory(NewIoList, IoList, sizeof(IO_RESOURCE_LIST));

        if (CommandPortDescriptor && 
            (CommandPortDescriptor->u.Port.MaximumAddress.QuadPart - CommandPortDescriptor->u.Port.MinimumAddress.QuadPart) == 7 &&
            !ControlPortDescriptor)
        {
            NewDescriptor = NewIoList->Descriptors;
            CurrentDescriptor = FirstDescriptor;

            for (jx = 0; jx < NewIoList->Count; jx++)
            {
                RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                NewDescriptor++;

                if (CurrentDescriptor == CommandPortDescriptor)
                {
                    RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                    NewDescriptor->u.Port.Length = 1;
                    NewDescriptor->u.Port.Alignment = 1;
                    NewDescriptor->u.Port.MaximumAddress.QuadPart = (CommandPortDescriptor->u.Port.MinimumAddress.QuadPart + 0x206);//518
                    NewDescriptor++;
                }

                CurrentDescriptor++;
            }

            NewIoList->Count++;
        }
        else
        {
            NewDescriptor = NewIoList->Descriptors;
            CurrentDescriptor = FirstDescriptor;

            for (kx = 0; kx < NewIoList->Count; kx++)
            {
                RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                NewDescriptor++;
                CurrentDescriptor++;
            }
        }

        IoList = (PIO_RESOURCE_LIST)&FirstDescriptor[IoList->Count];
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
        Irp->IoStatus.Status = STATUS_SUCCESS;
    else
        ExFreePool((PVOID)Irp->IoStatus.Information);

    Irp->IoStatus.Information = (ULONG_PTR)NewIoResources;

Exit:

    return IdePortPassDownToNextDriver(Fdo, Irp);
}

NTSTATUS
NTAPI
ChannelQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelSurpriseRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
IdePortDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    ULONG CmdBlockBase;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    PAGED_CODE();
    DPRINT("IdePortDispatchPnp: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        CmdBlockBase = FdoExtension->ResourceData.CmdBlockBase;
        DPRINT("IdePortDispatchPnp: FDO %X (%X) got '%s'\n", FdoExtension->FdoIndex, CmdBlockBase, PnpMinorNames[MinorFunction]);
        IsFdo = TRUE;
    }
    else
    {
        ASSERT(FALSE);
        IsFdo = FALSE;
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            ASSERT(FALSE);
    }

    if (MinorFunction != 0xFF)
        ASSERT(!"ATAPI: PnP Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassDownToNextDriver(DeviceObject, Irp);
    else
        {ASSERT(FALSE);return 0;}
}

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
IdePortDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortDispatchSystemControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
IdePortWmiInit(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
IdeCreateIdeDirectory(VOID)
{
    UNICODE_STRING DirectoryName = RTL_CONSTANT_STRING(L"\\Device\\Ide");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    PVOID Object;
    NTSTATUS Status;

    PAGED_CODE();

    InitializeObjectAttributes(&ObjectAttributes,
                               &DirectoryName,
                               (OBJ_CASE_INSENSITIVE | OBJ_PERMANENT),
                               NULL,
                               NULL);

    Status = ZwCreateDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        ObReferenceObjectByHandle(Handle, 0x80, NULL, KernelMode, &Object, NULL);
        ZwClose(Handle);
    }
}

BOOLEAN
NTAPI
IdePortOkToDetectLegacy(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Pnp");
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    ULONG Value;
    NTSTATUS Status;

    DPRINT("IdePortOkToDetectLegacy: %p\n", DriverObject);

    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(QueryTable, sizeof(QueryTable));

        Value = 0;

        QueryTable[0].Name = L"DisableFirmwareMapper";
        QueryTable[0].EntryContext = &Value;
        QueryTable[0].DefaultData = &Value;
        QueryTable[0].QueryRoutine = NULL;
        QueryTable[0].Flags = 0x34;
        QueryTable[0].DefaultType = 4;
        QueryTable[0].DefaultLength = 4;

        RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, NULL, NULL);
        ZwClose(KeyHandle);

        if (Value)
            return FALSE;
    }

    UNIMPLEMENTED_DBGBREAK();

    return FALSE;
}

VOID
NTAPI
IdePortDetectLegacyController(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DPRINT("IdePortDetectLegacyController: %p, %p\n", DriverObject, RegistryPath);

    if (!IdePortOkToDetectLegacy(DriverObject))
        return;

    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PATAPI_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    if (!DriverObject)
    {
        UNIMPLEMENTED_DBGBREAK();
        //AtapiCrashDumpDriverEntry(RegistryPath);
        return STATUS_NOT_IMPLEMENTED;
    }

    Status = IoAllocateDriverObjectExtension(DriverObject, DriverEntry, sizeof(*DriverExtension), (PVOID*)&DriverExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

    ASSERT(DriverExtension);
    RtlZeroMemory(DriverExtension, sizeof(*DriverExtension));

    DriverExtension->RegistryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, (RegistryPath->Length * 2), 'PedI');
    if (!DriverExtension->RegistryPath.Buffer)
    {
        DPRINT1("DriverEntry: Unable to allocate memory for registry path\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DriverExtension->RegistryPath.Length = 0;
    DriverExtension->RegistryPath.MaximumLength = RegistryPath->Length;

    RtlCopyUnicodeString(&DriverExtension->RegistryPath, RegistryPath);

    DriverObject->DriverExtension->AddDevice = ChannelAddDevice;
    DriverObject->DriverStartIo = IdePortStartIo;
    DriverObject->DriverUnload = IdePortUnload;

    //DriverObject->MajorFunction[IRP_MJ_CREATE] = IdePortAlwaysStatusSuccessIrp;
    //DriverObject->MajorFunction[IRP_MJ_CLOSE] = IdePortAlwaysStatusSuccessIrp;
    DriverObject->MajorFunction[IRP_MJ_SCSI] = IdePortDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IdePortDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = IdePortDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_PNP] = IdePortDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = IdePortDispatchSystemControl;

    //IdePortWmiInit();
    IdeCreateIdeDirectory();
    //IdeInitializeFdoList(&IdeGlobalFdoList);
    IdePortDetectLegacyController(DriverObject, RegistryPath);
    //PortRegisterBugcheckCallback(&ATAPI_DUMP_ID, AtapiDumpCallback);

    return STATUS_SUCCESS;
}
