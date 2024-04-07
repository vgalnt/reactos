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

PCHAR PowerMinorNames[] =
{
    "IRP_MN_WAIT_WAKE",
    "IRP_MN_POWER_SEQUENCE",
    "IRP_MN_SET_POWER",
    "IRP_MN_QUERY_POWER"
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
IdePortPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortIssueSetPowerState(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ POWER_STATE_TYPE PowerType,
    _In_ POWER_STATE State,
    _In_ BOOLEAN IsWait)
{
    PIO_STACK_LOCATION IoStack;
    IDE_WAIT_CONTEXT Context;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("IdePortIssueSetPowerState: %p, %X, %X, %X\n", FdoExtension, PowerType, State.SystemState, IsWait);

    if (IsWait)
        KeInitializeEvent(&Context.Event, NotificationEvent, FALSE);

    Irp = IoAllocateIrp(FdoExtension->SelfDevice->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("IdePortIssueSetPowerState: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack = IoGetNextIrpStackLocation(Irp);

    IoStack->MajorFunction = IRP_MJ_POWER;
    IoStack->MinorFunction = IRP_MN_SET_POWER;

    IoStack->Parameters.Power.SystemContext = 0;
    IoStack->Parameters.Power.Type = PowerType;
    IoStack->Parameters.Power.State = State;

    IoSetCompletionRoutine(Irp, IdePortPowerCompletionRoutine, (IsWait ? &Context : NULL), TRUE, TRUE, TRUE);

    Status = PoCallDriver(FdoExtension->SelfDevice, Irp);

    if (IsWait)
    {
        KeWaitForSingleObject(&Context.Event, Executive, KernelMode, FALSE, NULL);
        Status = Context.Status;
    }

    return Status;
}

VOID
NTAPI
FdoContingentPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
FdoPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp,
    _In_ PVOID context)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortSetFdoPowerState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PATAPI_SET_POWER_CONTEXT PowerContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    POWER_STATE State;
    BOOLEAN SystemPowerContext = FALSE;
    BOOLEAN DevicePowerContext = FALSE;
    NTSTATUS Status;
    BOOLEAN IsNeedChangeState;

    DPRINT("IdePortSetFdoPowerState: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type == 0)
    {
        SystemPowerContext = TRUE;
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 1, 0) == 0);
        PowerContext = &FdoExtension->PowerContext[0];
    }
    else
    {
        DevicePowerContext = TRUE;
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 1, 0) == 0);
        PowerContext = &FdoExtension->PowerContext[1];
    }

    if (!PowerContext)
    {
        DPRINT1("IdePortSetFdoPowerState: STATUS_NO_MEMORY\n");
        ASSERT(PowerContext);
        Status = STATUS_NO_MEMORY;
        goto ErrorExit;
    }

    PowerContext->Unknown1 = 0;
    PowerContext->Irp = Irp;
    PowerContext->Type = IoStack->Parameters.Power.Type;
    PowerContext->State = IoStack->Parameters.Power.State;

    if (IoStack->Parameters.Power.Type == 0)
    {
        if (FdoExtension->SystemPowerState != IoStack->Parameters.Power.State.SystemState)
        {
            ASSERT(FdoExtension->PendingSystemPowerIrp == NULL);
            FdoExtension->PendingSystemPowerIrp = Irp;

            if (FdoExtension->SystemPowerState == 1)
            {
                if (IoStack->Parameters.Power.State.SystemState == PowerSystemShutdown &&
                    IoStack->Parameters.Power.ShutdownType == PowerActionShutdownReset)
                {
                    State.SystemState = 1;
                }
                else
                {
                    State.SystemState = 4;
                }

                IoMarkIrpPending(Irp);

                PoRequestPowerIrp(FdoExtension->SelfDevice, 2, State, FdoContingentPowerCompletionRoutine, PowerContext, 0);
                return STATUS_PENDING;
            }

            IsNeedChangeState = 1;
        }
    }
    else if (IoStack->Parameters.Power.Type == 1)
    {
        if (FdoExtension->DevicePowerState != IoStack->Parameters.Power.State.DeviceState)
        {
            DPRINT("IdePortSetFdoPowerState: New Fdo %X device power state %X\n", FdoExtension->ResourceData.CmdBlockBase, IoStack->Parameters.Power.State.DeviceState);

            ASSERT(FdoExtension->PendingDevicePowerIrp == NULL);
            FdoExtension->PendingDevicePowerIrp = Irp;

            if (FdoExtension->DevicePowerState == 1)
                PoSetPowerState(Fdo, DevicePowerState, IoStack->Parameters.Power.State);

            IsNeedChangeState = TRUE;
        }
        else
        {
            IsNeedChangeState = FALSE;
        }
    }
    else 
    {
        DPRINT1("IdePortSetFdoPowerState: STATUS_NOT_IMPLEMENTED\n");
        ASSERT(FALSE);
        Status = STATUS_NOT_IMPLEMENTED;
        goto ErrorExit;
    }

    IoMarkIrpPending(Irp);
    IoCopyCurrentIrpStackLocationToNext(Irp);

    if (IsNeedChangeState)
    {
        IoSetCompletionRoutine(Irp, FdoPowerCompletionRoutine, PowerContext, TRUE, TRUE, TRUE);
    }
    else
    {
        if (SystemPowerContext)
        {
            ASSERT(DevicePowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        }
        if (DevicePowerContext)
        {
            ASSERT(SystemPowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
        }

        PoStartNextPowerIrp(Irp);
    }

    PoCallDriver(FdoExtension->LowDevice, Irp);
    return STATUS_PENDING;

ErrorExit:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    if (PowerContext)
    {
        if (SystemPowerContext)
        {
            ASSERT(DevicePowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        }
        if (DevicePowerContext)
        {
            ASSERT(SystemPowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
        }
    }

    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, 0);

    return Status;
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
    PFDO_DEVICE_EXTENSION FdoExtension;
    ULONG CmdBlockBase;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    DPRINT("IdePortDispatchPower: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        CmdBlockBase = FdoExtension->ResourceData.CmdBlockBase;
        DPRINT("IdePortDispatchPower: FDO %d (%X) got %s\n", FdoExtension->FdoIndex, CmdBlockBase, PowerMinorNames[MinorFunction]);
        IsFdo = TRUE;
    }
    else
    {
        DPRINT1("IdePortDispatchPower: FIXME\n");
        ASSERT(FALSE);
        IsFdo = FALSE;
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPowerDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            {ASSERT(FALSE);return 0;}
    }

    if (MinorFunction >= 4)
        ASSERT(!"ATAPI: Power Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassDownToNextDriver(DeviceObject, Irp);
    else
        {ASSERT(FALSE);return 0;}
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
    PRKEVENT Event = Context;
    DPRINT("ChannelStartDeviceCompletionRoutine: %p\n", Context);
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
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

BOOLEAN
NTAPI
IdePortInterrupt(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID ServiceContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
AtapiBuildIoAddress(
    _In_ PUCHAR CmdBlockBase,
    _In_ PUCHAR CtrlBlockBase,
    _Out_ IDE_CMD_BLOCK_REGS* BaseIoAddress1,
    _Out_ IDE_CTRL_BLOCK_REGS* BaseIoAddress2,
    _Out_ ULONG* OutBaseIoAddress1Length,
    _Out_ ULONG* OutBaseIoAddress2Length,
    _Out_ ULONG* OutMaxIdeDevice,
    _Out_ ULONG* OutMaxIdeTargetId)
{
    DPRINT("AtapiBuildIoAddress: %p, %p\n", CmdBlockBase, CtrlBlockBase);

    if (BaseIoAddress1)
    {
        BaseIoAddress1->CmdBlockBase = CmdBlockBase;

        BaseIoAddress1->Data = (PUSHORT)CmdBlockBase;
        BaseIoAddress1->Error = (CmdBlockBase + 1);
        BaseIoAddress1->SectorCount = (CmdBlockBase + 2);
        BaseIoAddress1->LbaLow = (CmdBlockBase + 3);
        BaseIoAddress1->LbaMid = (CmdBlockBase + 4);
        BaseIoAddress1->LbaHigh = (CmdBlockBase + 5);
        BaseIoAddress1->DeviceSelect = (CmdBlockBase + 6);
        BaseIoAddress1->Status = (CmdBlockBase + 7);
    }

    if (BaseIoAddress2)
    {
        BaseIoAddress2->CtrlBlockBase = CtrlBlockBase;

        BaseIoAddress2->AltStatus = CtrlBlockBase;
        BaseIoAddress2->Control = (CtrlBlockBase + 1);
    }

    if (OutBaseIoAddress1Length)
        *OutBaseIoAddress1Length = 8;

    if (OutBaseIoAddress2Length)
        *OutBaseIoAddress2Length = 1;

    if (OutMaxIdeDevice)
        *OutMaxIdeDevice = 2;

    if (OutMaxIdeTargetId)
        *OutMaxIdeTargetId = 2;
}

NTSTATUS
NTAPI
DigestResourceList(
    _In_ PIDE_RESOURCE_DATA ResourceData,
    _In_ PCM_RESOURCE_LIST CmResources,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR* OutInterruptDesc)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR FirstDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_FULL_RESOURCE_DESCRIPTOR CmList;
    IDE_CMD_BLOCK_REGS BaseIoAddress1;
    PHYSICAL_ADDRESS Start;
    SIZE_T BaseIoAddress1Length;
    ULONG Length;
    ULONG ix;
    ULONG jx;
    UCHAR Type;
    BOOLEAN IsFoundPrimary = FALSE;
    BOOLEAN IsFoundSecond = FALSE;
    BOOLEAN IsFoundCmdBlockBase = FALSE;
    BOOLEAN IsFoundCtrlBlockBase = FALSE;
    BOOLEAN IsFoundInterrupt = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("DigestResourceList: %p\n", CmResources);

    CmList = CmResources->List;

    *OutInterruptDesc = NULL;

    for (ix = 0; ix < CmResources->Count; ix++)
    {
        if (!NT_SUCCESS(Status))
            break;

        CmDescriptor = CmList->PartialResourceList.PartialDescriptors;

        AtapiBuildIoAddress((PUCHAR)CmDescriptor[0].u.Port.Start.LowPart,
                            NULL,
                            &BaseIoAddress1,
                            NULL,
                            &BaseIoAddress1Length,
                            NULL,
                            NULL,
                            NULL);

        FirstDescriptor = CmDescriptor;

        for (jx = 0; jx < CmList->PartialResourceList.Count; jx++)
        {
            if (!NT_SUCCESS(Status))
                break;

            Type = CmDescriptor[jx].Type;
            Start = CmDescriptor[jx].u.Generic.Start;
            Length = CmDescriptor[jx].u.Generic.Length;

            if ((Type == 1 || Type == 3) && Length == BaseIoAddress1Length && !IsFoundCmdBlockBase)
            {
                if (Start.QuadPart == 0x1F0)
                    IsFoundPrimary = TRUE;
                else if (Start.QuadPart == 0x170)
                    IsFoundSecond = TRUE;

                if (Type == 1)
                {
                    ResourceData->CmdBlockBase = Start.LowPart;
                    ResourceData->TypeResForCmdBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CmdBlockBase = (ULONG)MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);
                    ResourceData->TypeResForCmdBlock = 0;
                }
                else
                {
                    ASSERT(FALSE);
                    ResourceData->CmdBlockBase = 0;
                }

                if (ResourceData->CmdBlockBase)
                    IsFoundCmdBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
            else if ((Type == 1 || Type == 3) && (Length == 1 || Length == 2 || Length == 4) && !IsFoundCtrlBlockBase)
            {
                if (Length == 4)
                    Start.QuadPart += 2;

                if (Type == 1)
                {
                    ResourceData->CtrlBlockBase = Start.LowPart;
                    ResourceData->TypeResForCtrlBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CtrlBlockBase = (ULONG)MmMapIoSpace(Start, 1, MmNonCached);
                    ResourceData->TypeResForCtrlBlock = 0;
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);
                    ResourceData->CtrlBlockBase = 0;
                }

                if (ResourceData->CtrlBlockBase)
                    IsFoundCtrlBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
            else if (Type == 2 && !IsFoundInterrupt)
            {
                IsFoundInterrupt = TRUE;

                ResourceData->Vector = CmDescriptor[jx].u.Interrupt.Level;
                ResourceData->IntResFlags = (CmDescriptor[jx].Flags & 1);

                *OutInterruptDesc = &CmDescriptor[jx];
            }
            else if ((Type == 1 || Type == 3) && Length >= 0x10 && Length <= 0x20 && !IsFoundCmdBlockBase && !IsFoundCtrlBlockBase)
            {
                if (Type == 1)
                {
                    ResourceData->TypeResForCmdBlock = 1;
                    ResourceData->CmdBlockBase = Start.LowPart;

                    ResourceData->TypeResForCtrlBlock = 1;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = Start.LowPart;
                }
                else if (Type == 3)
                {
                    ResourceData->TypeResForCmdBlock = 0;
                    ResourceData->CmdBlockBase = (ULONG)MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);

                    ResourceData->TypeResForCtrlBlock = 0;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = (ULONG)MmMapIoSpace(Start, 1, MmNonCached);
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);

                    ResourceData->CmdBlockBase = 0;
                    ResourceData->CtrlBlockBase = 0;
                }

                if (ResourceData->CmdBlockBase)
                    IsFoundCmdBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;

                if (ResourceData->CtrlBlockBase)
                    IsFoundCtrlBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
        }

        CmList = (PCM_FULL_RESOURCE_DESCRIPTOR)&FirstDescriptor[CmList->PartialResourceList.Count];
    }

    if (IsFoundCmdBlockBase && IsFoundCtrlBlockBase && NT_SUCCESS(Status))
    {
        ResourceData->PrimaryClaimed = IsFoundPrimary;
        ResourceData->SecondaryClaimed = IsFoundSecond;

        return STATUS_SUCCESS;
    }

    DPRINT1("DigestResourceList: pnp manager gave me bad ressources!\n");

    if (IsFoundCmdBlockBase && !ResourceData->TypeResForCmdBlock)
    {
        MmUnmapIoSpace((PVOID)ResourceData->CmdBlockBase, BaseIoAddress1Length);
        ResourceData->CmdBlockBase = 0;
    }

    if (IsFoundCtrlBlockBase && !ResourceData->TypeResForCtrlBlock)
    {
        MmUnmapIoSpace((PVOID)ResourceData->CtrlBlockBase, 1);
        ResourceData->CtrlBlockBase = 0;
    }

    return STATUS_INVALID_PARAMETER;
}

VOID
NTAPI
IdePortInitFdo(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
IdePreAllocEnumStructs(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
ChannelEnableInterrupt(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ChannelCreateSymblicLinks(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelStartChannel(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    NTSTATUS (NTAPI* IntControl)(PVOID Context, ULONG IsDisconnectOrReconnect);
    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    PCONFIGURATION_INFORMATION ConfigInfo;
    PCM_FULL_RESOURCE_DESCRIPTOR List;
    PULONG TimingTable;
    IO_STACK_LOCATION ioStack;
    POWER_STATE State;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    DPRINT("ChannelStartChannel: %p\n", FdoExtension);

  #if DBG
    DPRINT1("ChannelStartChannel: %p\n", CmResources);
    RosDumpCmResources(CmResources, 0);
  #endif

    List = CmResources->List;
    for (ix = 0; ix < CmResources->Count; ix++)
    {
        for (jx = 0; jx < List->PartialResourceList.Count; jx++)
        {
            Descriptor = List->PartialResourceList.PartialDescriptors;

            if (Descriptor[jx].Type == 1)
            {
                DPRINT("ChannelStartChannel: IO Port %I64X, Lenght %X\n",
                       Descriptor[jx].u.Port.Start.QuadPart, Descriptor[jx].u.Port.Length);
            }
            else if (Descriptor[jx].Type == 2)
            {
                DPRINT("ChannelStartChannel: Int Level %X, Vector %X\n",
                       Descriptor[jx].u.Interrupt.Level, Descriptor[jx].u.Interrupt.Vector);
            }
            else
            {
                DPRINT("ChannelStartChannel: Unknown resource\n");
            }
        }

        List = (PCM_FULL_RESOURCE_DESCRIPTOR)&List->PartialResourceList.PartialDescriptors[jx];
    }

    Status = DigestResourceList(&FdoExtension->ResourceData, CmResources, &InterruptDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    ConfigInfo = IoGetConfigurationInformation();

    if (FdoExtension->ResourceData.PrimaryClaimed)
    {
        FdoExtension->HwDeviceExtension->IsPrimary = TRUE;
        FdoExtension->HwDeviceExtension->IsSecondary = FALSE;
        ConfigInfo->AtDiskPrimaryAddressClaimed = TRUE;
    }

    if (FdoExtension->ResourceData.SecondaryClaimed)
    {
        FdoExtension->HwDeviceExtension->IsPrimary = FALSE;
        FdoExtension->HwDeviceExtension->IsSecondary = TRUE;
        ConfigInfo->AtDiskSecondaryAddressClaimed = TRUE;
    }

    AtapiBuildIoAddress((PUCHAR)FdoExtension->ResourceData.CmdBlockBase,
                        (PUCHAR)FdoExtension->ResourceData.CtrlBlockBase,
                        &FdoExtension->HwDeviceExtension->CmdBlock,
                        &FdoExtension->HwDeviceExtension->CtrlBlock,
                        &FdoExtension->HwDeviceExtension->CmdBlockLength,
                        &FdoExtension->HwDeviceExtension->CtrlBlockLength,
                        &FdoExtension->HwDeviceExtension->MaxIdeDevice,
                        &FdoExtension->HwDeviceExtension->MaxIdeTargetId);

    //IdePortIsThisAPanasonicPCMCIACard(FdoExtension);
    //IdePortIsThisAnATIController(FdoExtension);

    State.SystemState = 1;
    Status = IdePortIssueSetPowerState(FdoExtension, SystemPowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        DPRINT1("ChannelStartChannel: STATUS_INVALID_DEVICE_REQUEST\n");
        FdoExtension->SystemPowerState = 1;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    State.DeviceState = 1;
    Status = IdePortIssueSetPowerState(FdoExtension, DevicePowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        DPRINT1("ChannelStartChannel: STATUS_INVALID_DEVICE_REQUEST\n");
        FdoExtension->DevicePowerState = 1;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    FdoExtension->HwDeviceExtension->IntResFlags = FdoExtension->ResourceData.IntResFlags;

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_INTERRUPT_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_INTERRUPT_INTERFACE);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->InterruptInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    DPRINT("ChannelStartChannel: Querying interrupt interface for Fdoe %X\n", FdoExtension);

    IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);

    if (InterruptDescriptor)
    {
        Status = IoConnectInterrupt(&FdoExtension->InterruptObject,                    // OUT PKINTERRUPT* InterruptObject
                                    IdePortInterrupt,                                  // PKSERVICE_ROUTINE ServiceRoutine
                                    FdoExtension->SelfDevice,                          // IN PVOID  ServiceContext,
                                    NULL,                                              // PKSPIN_LOCK SpinLock OPTIONAL,
                                    InterruptDescriptor->u.Interrupt.Vector,           // IN ULONG Vector,
                                    InterruptDescriptor->u.Interrupt.Level,            // IN KIRQL Irql,
                                    InterruptDescriptor->u.Interrupt.Level,            // IN KIRQL SynchronizeIrql,
                                    (InterruptDescriptor->Flags & 1),                  // IN KINTERRUPT_MODE InterruptMode,
                                    InterruptDescriptor->ShareDisposition == 3,        // IN BOOLEAN ShareVector,
                                    InterruptDescriptor->u.Interrupt.Affinity,         // IN KAFFINITY ProcessorEnableMask,
                                    FALSE);                                            // IN BOOLEAN FloatingSave
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel:  Can't connect interrupt %X\n", InterruptDescriptor->u.Interrupt.Vector);
            FdoExtension->InterruptObject = NULL;
            goto ErrorExit;
        }

        if (FdoExtension->InterruptInterface.InterruptControl)
        {
            DPRINT("ChannelStartChannel: %X fdoe %X Invoking disconnect\n", InterruptDescriptor->u.Interrupt.Vector, FdoExtension);

            IntControl = FdoExtension->InterruptInterface.InterruptControl;
            Status = IntControl(FdoExtension->InterruptInterface.Context, 1);
            ASSERT(NT_SUCCESS(Status));
        }

        ChannelEnableInterrupt(FdoExtension);
    }

    RtlZeroMemory(&ioStack, sizeof(ioStack));
    RtlZeroMemory(&FdoExtension->SyncAccessInterface, sizeof(FdoExtension->SyncAccessInterface));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_SYNC_ACCESS_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(IDE_SYNC_ACCESS_INTERFACE);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->SyncAccessInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        FdoExtension->SyncAccessInterface.AllocateAccessToken = NULL;
        FdoExtension->SyncAccessInterface.Context = NULL;
    }

    if (FdoExtension->FdoState & 4)
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        RtlZeroMemory(&ioStack, sizeof(ioStack));

        ioStack.MajorFunction = IRP_MJ_PNP;
        ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

        ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_BUSMASTER_INTERFACE;
        ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_BUS_MASTER_INTERFACE);
        ioStack.Parameters.QueryInterface.Version = 1;
        ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->HwDeviceExtension->BusMasterInterface;
        ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

        Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
        DPRINT("ChannelStartChannel: Status %X\n", Status);

        if (!NT_SUCCESS(Status))
            FdoExtension->IsBmIfaceReceived = FALSE;
        else
            FdoExtension->IsBmIfaceReceived = TRUE;

        if (!FdoExtension->DefaultTransferModeTimingTable)
        {
            TimingTable = ExAllocatePoolWithTag(NonPagedPool, (18 * sizeof(ULONG)), 'PedI');
            if (!TimingTable)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                DPRINT1("ChannelStartChannel: Status %X\n", Status);
                goto ErrorExit;
            }

            TimingTable[0] = 600;
            TimingTable[1] = 383;
            TimingTable[2] = 240;
            TimingTable[3] = 180;
            TimingTable[4] = 120;
            TimingTable[5] = 960;
            TimingTable[6] = 480;
            TimingTable[7] = 240;
            TimingTable[8] = 480;
            TimingTable[9] = 150;
            TimingTable[10] = 120;
            TimingTable[11] = 120;
            TimingTable[12] = 80;
            TimingTable[13] = 60;
            TimingTable[14] = 45;
            TimingTable[15] = 30;
            TimingTable[16] = 20;
            TimingTable[17] = 15;

            FdoExtension->DefaultTransferModeTimingTable = TimingTable;
            ASSERT(FdoExtension->DefaultTransferModeTimingTable);
        }

        RtlZeroMemory(&ioStack, sizeof(ioStack));
        FdoExtension->ProperResources.ChannelRequestProperResources = NULL;

        ioStack.MajorFunction = IRP_MJ_PNP;
        ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

        ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_REQUEST_PROPER_RESOURCES;
        ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_PROPER_RESOURCES);
        ioStack.Parameters.QueryInterface.Version = 1;
        ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->ProperResources;
        ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

        IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);

        Status = ChannelCreateSymblicLinks(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel: Status %X\n", Status);
            goto ErrorExit;
        }

        IdePortInitFdo(FdoExtension);

        for (ix = 0; ix < 2; ix++)
        {
            if (!FdoExtension->ErrorLog[ix])
                FdoExtension->ErrorLog[ix] = IoAllocateErrorLogEntry(FdoExtension->SelfDevice, 0x40);//FIXME
        }

        if (!IdePreAllocEnumStructs(FdoExtension))
        {
            DPRINT1("ChannelStartChannel: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit;
        }

        if (!FdoExtension->ReservedPages)
        {
            FdoExtension->ReservedPages = MmAllocateMappingAddress(PAGE_SIZE, 'PedI');
            ASSERT(FdoExtension->ReservedPages);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel: Status %X\n", Status);
            goto ErrorExit;
        }
    }

    FdoExtension->FdoState = ((FdoExtension->FdoState & ~4) | 2);

    if (FdoExtension->ChannelResources)
    {
        ExFreePool(FdoExtension->ChannelResources);
        FdoExtension->ChannelResources = NULL;
    }

    FdoExtension->ChannelResources = CmResources;

    return Status;

ErrorExit:

    DPRINT1("ChannelStartChannel: FIXME ChannelRemoveChannel()! Status %X\n", Status);
    ASSERT(FALSE);
    return Status;
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
