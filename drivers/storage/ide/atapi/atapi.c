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
LONG PdoIndex = 0;

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

PDRIVER_DISPATCH PdoPnpDispatchTable[] =
{
    DeviceStartDevice,
    DeviceQueryStopRemoveDevice,
    DeviceRemoveDevice,
    IdePortAlwaysStatusSuccessIrp,
    DeviceStopDevice,
    DeviceQueryStopRemoveDevice,
    IdePortAlwaysStatusSuccessIrp,
    DeviceQueryDeviceRelations,
    IdePortNoSupportIrp,
    DeviceQueryCapabilities,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    DeviceQueryText,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    DeviceQueryId,
    DeviceQueryPnPDeviceState,
    IdePortNoSupportIrp,
    DeviceUsageNotification,
    DeviceRemoveDevice,
    IdePortNoSupportIrp
};

PDRIVER_DISPATCH FdoPowerDispatchTable[] =
{
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortSetFdoPowerState,
    ChannelQueryPowerState
};

PDRIVER_DISPATCH PdoPowerDispatchTable[] =
{
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortSetPdoPowerState,
    DeviceQueryPowerState
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

PWCHAR UserDeviceString[] =
{
    L"UserMasterDeviceType",
    L"UserSlaveDeviceType",
    L"UserMasterDeviceType2",
    L"UserSlaveDeviceType2",
    L"UserMasterDeviceTimingModeAllowed",
    L"UserSlaveDeviceTimingModeAllowed",
    L"UserMasterDeviceTimingModeAllowed2",
    L"UserSlaveDeviceTimingModeAllowed2"
};

PWSTR TypeName[] =
{
    L"MasterDeviceType",
    L"SlaveDeviceType",
    L"MasterDeviceType2",
    L"SlaveDeviceType2"
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

VOID
NTAPI
IdeInterlockedIncrement(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PLONG Addend,
    _In_ PVOID TagLock)
{
    DPRINT(">>>>>>>>>>>>>>>>>>>> Acquire PdoLock with tag = 0x%x\n", TagLock);
    //FIXME
    InterlockedIncrement(Addend);
}

PPDO_DEVICE_EXTENSION
NTAPI
RefPdo(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PPDO_DEVICE_EXTENSION
NTAPI
RefLogicalUnitExtension(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION RetExtension = NULL;
    PPDO_DEVICE_EXTENSION PdoExt;
    KIRQL Irql;

    DPRINT("RefLogicalUnitExtension: %p, (%X:%X:%X)\n", FdoExtension, PathId, TargetId, Lun);

    if (TargetId >= FdoExtension->HwDeviceExtension->MaxIdeTargetId)
        return NULL;

    KeAcquireSpinLock(&FdoExtension->PdoArrayLock, &Irql);

    PdoExt = FdoExtension->PdoArray[(TargetId + Lun) % 8];
    while (PdoExt)
    {
        if (PdoExt->TargetId == TargetId && PdoExt->Lun == Lun && PdoExt->PathId == PathId)
            break;

        PdoExt = PdoExt->LinkPdoExt;
    }

    if (PdoExt)
        RetExtension = RefPdo(PdoExt->SelfDevice, IsForceRef, TagLock);

    KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

    return RetExtension;
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

/* PDO POWER FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
IdePortSetPdoPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* FDO POWER FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
IdePortPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PIDE_WAIT_CONTEXT WaitContext = Context;

    DPRINT("IdePortPowerCompletionRoutine: %p, %X, %X\n", DeviceObject, Irp, Context);

    if (WaitContext)
    {
        WaitContext->Status = Irp->IoStatus.Status;
        KeSetEvent(&WaitContext->Event, EVENT_INCREMENT, FALSE);
    }

    IoFreeIrp(Irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
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

VOID
NTAPI
FdoSystemPowerUpCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatus)
{
    PIRP Irp = Context;

    DPRINT("FdoSystemPowerUpCompletionRoutine: %p, %X, %p\n", Fdo, MinorFunction, Context);

    ((PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension)->PendingSystemPowerIrp = NULL;

    PoStartNextPowerIrp(Irp);

    if (!NT_SUCCESS(IoStatus->Status))
    {
        DPRINT1("FdoSystemPowerUpCompletionRoutine: %X\n", IoStatus->Status);
        Irp->IoStatus.Status = IoStatus->Status;
    }

    IoCompleteRequest(Irp, 0);
}

VOID
NTAPI
ChannelRestoreTimingCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ NTSTATUS Status,
    _In_ PATAPI_SET_POWER_CONTEXT Context)
{
    DPRINT("ChannelRestoreTimingCompletionRoutine: %p, %X, %p\n", Fdo, Status, Context);

    Context->IsTimingsRestored = TRUE;
    Context->Irp->IoStatus.Status = Status;

    FdoPowerCompletionRoutine(IoGetCurrentIrpStackLocation(Context->Irp)->DeviceObject, Context->Irp, Context);

    IoCompleteRequest(Context->Irp, 0);
}

NTSTATUS
NTAPI
ChannelRestoreTiming(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PVOID CallBack,
    _In_ PATAPI_SET_POWER_CONTEXT Context)
{
    VOID (NTAPI* callBack)(PDEVICE_OBJECT, NTSTATUS, PATAPI_SET_POWER_CONTEXT) = CallBack;
    PIDE_ACPI_TIMING_MODE_BLOCK TimingBlock;
    PIDENTIFY_DATA identify[2];
    ULONG ix;

    DPRINT("ChannelRestoreTiming: %p, %X, %X\n", FdoExtension, FdoExtension->PdoCount1, identify);

    if (FdoExtension->PdoCount1)
    {
        TimingBlock = &FdoExtension->TimingBlock;

        if (TimingBlock->Drive[0].PioSpeed != 0xFFFFFFFF ||
            FdoExtension->TimingBlock.Drive[1].PioSpeed != 0xFFFFFFFF)
        {
            for (ix = 0; ix < 2; ix++)
            {
                if (FdoExtension->HwDeviceExtension->DeviceFlags[ix] & 1)
                {
                    identify[ix] =  &FdoExtension->HwDeviceExtension->IdentifyData[ix];
                }
                else
                {
                    identify[ix] =  NULL;
                }
            }

            DPRINT1("ChannelRestoreTiming: FIXME\n");
            ASSERT(FALSE);
        }

        DPRINT1("ChannelRestoreTiming: FIXME\n");
        ASSERT(FALSE);
    }

    callBack(FdoExtension->SelfDevice, STATUS_SUCCESS, Context);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FdoPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp,
    _In_ PVOID context)
{
    PATAPI_SET_POWER_CONTEXT Context = context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    POWER_STATE State;
    BOOLEAN IsSetSystemWorking = FALSE;
    BOOLEAN IsSetDeviceSet;
    NTSTATUS Status;

    DPRINT("FdoPowerCompletionRoutine: %p, %p, %p\n", Fdo, Irp, Context);

    FdoExtension = Fdo->DeviceExtension;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT("FdoPowerCompletionRoutine: devobj %p failed power irp %p\n", FdoExtension->LowDevice, Irp);

        if (Context->Type == SystemPowerState)
        {
            ASSERT(FdoExtension->PendingSystemPowerIrp == Irp);
            FdoExtension->PendingSystemPowerIrp = NULL;
        }
        else if (Context->Type == DevicePowerState)
        {
            ASSERT(FdoExtension->PendingDevicePowerIrp == Irp);
            FdoExtension->PendingDevicePowerIrp = NULL;
        }
    }
    else
    {
        if (Context->Type == SystemPowerState)
        {
            FdoExtension->SystemPowerState = Context->State.SystemState;

            if (Context->State.SystemState == PowerSystemWorking)
            {
                ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
                ASSERT(FdoExtension->PendingSystemPowerIrp == Irp);

                IsSetSystemWorking = TRUE;
                State.SystemState = PowerSystemWorking;

                Status = PoRequestPowerIrp(FdoExtension->SelfDevice, IRP_MN_SET_POWER, State, FdoSystemPowerUpCompletionRoutine, Irp, NULL);
                ASSERT(Status == STATUS_PENDING);

                DPRINT("FdoPowerCompletionRoutine: New Fdo %X system power state %X\n", FdoExtension->ResourceData.CmdBlockBase, FdoExtension->SystemPowerState);

                PoSetPowerState(Fdo, Context->Type, Context->State);
                goto Exit;
            }
            else
            {
                FdoExtension->PendingSystemPowerIrp = NULL;

                DPRINT("FdoPowerCompletionRoutine: New Fdo %X system power state %X\n", FdoExtension->ResourceData.CmdBlockBase, FdoExtension->SystemPowerState);

                PoSetPowerState(Fdo, Context->Type, Context->State);
            }
        }
        else if (Context->Type == DevicePowerState)
        {
            if (Context->State.DeviceState == PowerDeviceD0 && (FdoExtension->HackFlags & 1))
            {
                DPRINT1("FdoPowerCompletionRoutine: FIXME\n");
                ASSERT(FALSE);
            }

            if (Context->State.DeviceState == PowerDeviceD0 && !Context->IsTimingsRestored)
            {
                Status = ChannelRestoreTiming(FdoExtension, ChannelRestoreTimingCompletionRoutine, Context);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("FdoPowerCompletionRoutine: FIXME\n");
                    ASSERT(FALSE);
                }

                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            ASSERT(FdoExtension->PendingDevicePowerIrp == Irp);
            FdoExtension->PendingDevicePowerIrp = NULL;

            if (FdoExtension->DevicePowerState == PowerDeviceD0)
                IsSetDeviceSet = FALSE;
            else
                IsSetDeviceSet = TRUE;

            FdoExtension->DevicePowerState = Context->State.DeviceState;

            if (FdoExtension->DevicePowerState == PowerDeviceD0 && FdoExtension->FdoState & 2)
                IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);

            if (IsSetDeviceSet)
            {
                PoSetPowerState(Fdo, Context->Type, Context->State);

                if (Context->Type == SystemPowerState && Context->State.SystemState == PowerSystemWorking)
                    goto Exit;
            }
        }
    }

    if (Context->Type == SystemPowerState)
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
    else
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);

Exit:

    if (IsSetSystemWorking)
    {
        Status = STATUS_MORE_PROCESSING_REQUIRED;
    }
    else
    {
        PoStartNextPowerIrp(Irp);
        Status = Irp->IoStatus.Status;
    }

    return Status;
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

    PowerContext->IsTimingsRestored = FALSE;
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

NTSTATUS
NTAPI
IdePortAlwaysStatusSuccessIrp(
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
IdePortCompletionDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
IdePortTickHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
IdeMiniPortTimerDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IdePortGetDeviceParameter(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PWCHAR Name,
    _In_ ULONG* OutParameter)
{
    NTSTATUS Status;
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    HANDLE DevInstRegKey;
    ULONG OldParameter;

    PAGED_CODE();
    DPRINT("IdePortGetDeviceParameter: %p, '%S'\n", FdoExtension, Name);

    Status = IoOpenDeviceRegistryKey(FdoExtension->LowPdo, PLUGPLAY_REGKEY_DRIVER, KEY_READ, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortGetDeviceParameter: Status %X\n", Status);
        return Status;
    }

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    OldParameter = *OutParameter;

    QueryTable[0].Name = Name;
    QueryTable[0].DefaultType = 4;
    QueryTable[0].DefaultLength = 4;
    QueryTable[0].Flags = 0x24;
    QueryTable[0].EntryContext = OutParameter;
    QueryTable[0].DefaultData = &OldParameter;

    Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, DevInstRegKey, QueryTable, NULL, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortGetDeviceParameter: Status %X\n", Status);
        *OutParameter = OldParameter;
    }

    ZwClose(DevInstRegKey);

    return Status;
}

VOID
NTAPI
IdePortInitFdo(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    ULONG ix;

    DPRINT("IdePortInitFdo: %p\n", FdoExtension);

    FdoExtension->HwDeviceExtension = &FdoExtension->AtaExt;
    FdoExtension->SelfDevice->Flags |= 0x10;
    FdoExtension->MaxPdoCount = 8;
    FdoExtension->TimeOutValue = -1;

    KeInitializeSpinLock(&FdoExtension->SpinLock);
    KeInitializeSpinLock(&FdoExtension->PdoArrayLock);

    KeInitializeDpc(&FdoExtension->SelfDevice->Dpc, IdePortCompletionDpc, FdoExtension->SelfDevice);
    IoInitializeTimer(FdoExtension->SelfDevice, IdePortTickHandler, NULL);
    KeInitializeTimer(&FdoExtension->Timer);
    KeInitializeDpc(&FdoExtension->Dpc, IdeMiniPortTimerDpc, FdoExtension->SelfDevice);
    IoStartTimer(FdoExtension->SelfDevice);

    FdoExtension->Flags |= 0x1000;

    if (FdoExtension->InterruptData.Flags & 0x40)
    {
        DPRINT("IdePortInitFdo: FIXME\n");
        ASSERT(FALSE);
    }

    FdoExtension->IoScsicapabilities.Length = 0x18;

    if (FdoExtension->IsBmIfaceReceived)
    {
        if (FdoExtension->HwDeviceExtension->BusMasterInterface.MaximumPhysicalSize >= 0x20000)
            FdoExtension->IoScsicapabilities.MaximumTransferLength = 0x20000;
        else
            FdoExtension->IoScsicapabilities.MaximumTransferLength = FdoExtension->HwDeviceExtension->BusMasterInterface.MaximumPhysicalSize;
    }
    else
    {
        FdoExtension->IoScsicapabilities.MaximumTransferLength = 0x20000;
    }

    FdoExtension->IoScsicapabilities.TaggedQueuing = 0;
    FdoExtension->IoScsicapabilities.AdapterScansDown = 0;
    FdoExtension->IoScsicapabilities.AlignmentMask = FdoExtension->SelfDevice->AlignmentRequirement;
    FdoExtension->IoScsicapabilities.MaximumPhysicalPages = BYTES_TO_PAGES(FdoExtension->IoScsicapabilities.MaximumTransferLength);

    if (FdoExtension->ResourceData.CmdBlockBase)
    {
        DPRINT("IdePortInitFdo: Translated IO Base address %x\n", FdoExtension->ResourceData.CmdBlockBase);
    }

    for (ix = 0; ix < 4; ix++)
    {
        FdoExtension->DeviceParameter[ix] = 0;
        IdePortGetDeviceParameter(FdoExtension, UserDeviceString[ix], &FdoExtension->DeviceParameter[ix]);
    }

    for (ix = 0; ix < 2; ix++)
    {
        FdoExtension->TimingBlock0.Drive[ix].PioSpeed = 0xFFFFFFFF;
        FdoExtension->TimingBlock0.Drive[ix].DmaSpeed = 0xFFFFFFFF;
    }

    FdoExtension->DmaDetectionLevel = 1;
    IdePortGetDeviceParameter(FdoExtension, L"DmaDetectionLevel", &FdoExtension->DmaDetectionLevel);

    DPRINT("IdePortInitFdo: FIXME ChannelQueryPcmciaParent()\n");
    FdoExtension->PcmciaIdeHasSlaveDevice = 1;

    FdoExtension->ResetErrorCountersOnSuccess = 0;
    IdePortGetDeviceParameter(FdoExtension, L"ResetErrorCountersOnSuccess", &FdoExtension->ResetErrorCountersOnSuccess);
}

BOOLEAN
NTAPI
IdePreAllocEnumStructs(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PATAPI_PRE_ALLOC_ENUM_STRUCT enumStruct;

    PAGED_CODE();
    DPRINT("IdePreAllocEnumStructs: %p\n", FdoExtension);

    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 1, 0) == 0);

    if (FdoExtension->PreAllocEnumStruct)
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
        return TRUE;
    }

    enumStruct = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct), 'PedI');
    if (!enumStruct)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
        ASSERT(FdoExtension->EnumStructLock == 0);
    }
    RtlZeroMemory(enumStruct, sizeof(*enumStruct));

    enumStruct->AtaPassThrContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->AtaPassThrContext), 'PedI');
    if (!enumStruct->AtaPassThrContext)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    ASSERT(enumStruct->EnumWorkItemContext == NULL);

    enumStruct->EnumWorkItemContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->EnumWorkItemContext), 'PedI');
    if (!enumStruct->EnumWorkItemContext)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->EnumWorkItemContext->WorkItem = IoAllocateWorkItem(FdoExtension->SelfDevice);
    if (!enumStruct->EnumWorkItemContext->WorkItem)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    //enumStruct->Unknown = ExAllocatePoolWithTag(..);

    enumStruct->SenseInfoBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(*enumStruct->SenseInfoBuffer), 'PedI');
    if (!enumStruct->SenseInfoBuffer)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->Srb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->Srb), 'PedI');
    if (!enumStruct->Srb)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->Irp = IoAllocateIrp(1, FALSE);
    if (!enumStruct->Irp)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->DataBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 0x234, 'PedI'); // ?
    if (!enumStruct->DataBuffer)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        enumStruct->DataBufferSize = 0;
        goto ErrorExit;
    }
    else
    {
        enumStruct->DataBufferSize = 0x234;
    }

    enumStruct->Mdl = IoAllocateMdl(enumStruct->DataBuffer, enumStruct->DataBufferSize, FALSE, FALSE, NULL);
    if (!enumStruct->Mdl)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }
    MmBuildMdlForNonPagedPool(enumStruct->Mdl);

    FdoExtension->PreAllocEnumStruct = enumStruct;
    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
    return TRUE;

ErrorExit:

    DPRINT1("IdePreAllocEnumStructs: FIXME IdeFreeEnumStructs\n");
    ASSERT(FALSE);

    FdoExtension->PreAllocEnumStruct = NULL;
    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);

    return FALSE;
}

VOID
NTAPI
ChannelEnableInterrupt(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    ULONG ix;

    for (ix = 0; ix < (FdoExtension->HwDeviceExtension->MaxIdeDevice / 2); ix++)
    {
        DPRINT("ChannelEnableInterrupt: DeviceControl %X\n", FdoExtension->HwDeviceExtension->CtrlBlock.DeviceControl);
        WRITE_PORT_UCHAR(FdoExtension->HwDeviceExtension->CtrlBlock.DeviceControl, 0);
    }
}

NTSTATUS
NTAPI
ChannelCreateSymblicLinks(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNICODE_STRING SymbolicLinkName;
    UNICODE_STRING DeviceName;
    WCHAR DeviceNameBuffer[64];
    WCHAR ScsiNameBuffer[64];
    ULONG ix;
    NTSTATUS Status;

    DPRINT("ChannelCreateSymblicLinks: %p\n", FdoExtension);

    swprintf(DeviceNameBuffer, L"\\Device\\Ide\\IdePort%d", FdoExtension->FdoIndex);
    RtlInitUnicodeString(&DeviceName, DeviceNameBuffer);

    for (ix = 0; ix <= IoGetConfigurationInformation()->ScsiPortCount; ix++)
    {
        swprintf(ScsiNameBuffer, L"\\Device\\ScsiPort%d", ix);
        RtlInitUnicodeString(&SymbolicLinkName, ScsiNameBuffer);

        Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
        if (NT_SUCCESS(Status))
        {
            swprintf(ScsiNameBuffer, L"\\DosDevices\\Scsi%d:", ix);
            RtlInitUnicodeString(&SymbolicLinkName, ScsiNameBuffer);
            IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
            break;
        }
    }

    if (NT_SUCCESS(Status))
    {
        FdoExtension->SymlinkCreated = TRUE;
        FdoExtension->ScsiPortCount = ix;

        IoGetConfigurationInformation()->ScsiPortCount++;
    }

    return Status;
}

NTSTATUS
NTAPI
ChannelStartChannel(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    NTSTATUS (NTAPI* IntControl)(PVOID Context, BOOLEAN IsDisconnectOrReconnect);
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
            Status = IntControl(FdoExtension->InterruptInterface.Context, TRUE);
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
DeviceQueryACPISettingsCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;

    if (!NT_ERROR(Irp->IoStatus.Status))
        RtlCopyMemory(Irp->UserBuffer, Irp->AssociatedIrp.MasterIrp, Irp->IoStatus.Information);

    KeSetEvent(Event, EVENT_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
DeviceQueryACPISettings(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ACPI_EVAL_SIGNATURE MethodSign,
    _Out_ PACPI_EVAL_OUTPUT_BUFFER* OutQueryResult)
{
    PACPI_EVAL_OUTPUT_BUFFER QueryResult;
    PACPI_EVAL_INPUT_BUFFER AcpiInput;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_OBJECT LowDevice;
    KEVENT Event;
    PIRP Irp = NULL;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("DeviceQueryACPISettings: '%c%c%c%c'\n", MethodSign.Char[0], MethodSign.Char[1], MethodSign.Char[2], MethodSign.Char[3]);

    LowDevice = IoGetAttachedDeviceReference(FdoExtension->SelfDevice);

    for (ix = 0; ix < 2; ix++)
    {
        DPRINT("DeviceQueryACPISettings: _GTM try %X\n", ix);

        QueryResult = ExAllocatePoolWithTag(NonPagedPool, sizeof(*QueryResult), 'PedI');
        if (!QueryResult)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoAllocateIrp(LowDevice->StackSize, FALSE);
        if (!Irp)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(ACPI_EVAL_OUTPUT_BUFFER), 'PedI');
        if (!Irp->AssociatedIrp.SystemBuffer)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        IoStack = IoGetNextIrpStackLocation(Irp);
        IoStack->MajorFunction = IRP_MJ_DEVICE_CONTROL;

        IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(ACPI_EVAL_OUTPUT_BUFFER);
        IoStack->Parameters.DeviceIoControl.InputBufferLength = sizeof(ACPI_EVAL_INPUT_BUFFER);
        IoStack->Parameters.DeviceIoControl.IoControlCode = 0x32C000;

        AcpiInput = Irp->AssociatedIrp.SystemBuffer;
        AcpiInput->Signature = 'BieA';
        AcpiInput->MethodNameAsUlong = MethodSign.AsULONG;

        Irp->Flags = 0x50;
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        Irp->UserBuffer = QueryResult;

        IoSetCompletionRoutine(Irp, DeviceQueryACPISettingsCompletionRoutine, &Event, TRUE, TRUE, TRUE);

        Status = IoCallDriver(LowDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Irp->IoStatus.Status;
        }

        if (NT_SUCCESS(Status) && QueryResult->Signature != 'BoeA')
        {
            ASSERT(QueryResult->Signature == ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE);

            if (QueryResult->Signature != 'BoeA')
                Status = STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(Irp->AssociatedIrp.SystemBuffer, 'PedI');
        IoFreeIrp(Irp);
        Irp = NULL;

        if (!NT_SUCCESS(Status))
        {
            QueryResult->Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER);
            ExFreePoolWithTag(QueryResult, 'PedI');
            QueryResult = NULL;

            if (Status != STATUS_BUFFER_OVERFLOW)
            {
                DPRINT1("DeviceQueryACPISettings: Status %X\n", Status);
                break;
            }
        }
    }

    ObDereferenceObject(LowDevice);

    if (Irp)
    {
        if (Irp->AssociatedIrp.SystemBuffer)
            ExFreePoolWithTag(Irp->AssociatedIrp.SystemBuffer, 'PedI');

        IoFreeIrp(Irp);
    }

    *OutQueryResult = QueryResult;

    return Status;
}

VOID
NTAPI
DeviceQueryChannelTimingSettings(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDE_ACPI_TIMING_MODE_BLOCK TimingBlock)
{
    PACPI_EVAL_OUTPUT_BUFFER QueryResult;
    ACPI_EVAL_SIGNATURE Signature;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("DeviceQueryChannelTimingSettings: %p, %p\n", FdoExtension, TimingBlock);

    Signature.AsULONG = 'MTG_';

    Status = DeviceQueryACPISettings(FdoExtension, Signature, &QueryResult);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceQueryChannelTimingSettings: Status %X\n", Status);
        goto ErrorExit;
    }

    if (QueryResult->Count != 1)
    {
        DPRINT1("DeviceQueryChannelTimingSettings: QueryResult->Count %X\n", QueryResult->Count);
        ASSERT(QueryResult->Count == 1);
        Status = STATUS_UNSUCCESSFUL;
        goto ErrorExit;
    }

    if (QueryResult->Argument[0].Type != 2 ||
        QueryResult->Argument[0].DataLength < sizeof(IDE_ACPI_TIMING_MODE_BLOCK))
    {
        DPRINT1("DeviceQueryChannelTimingSettings: Type %X\n", QueryResult->Argument[0].Type);
        ASSERT(QueryResult->Argument[0].Type == 2);//ACPI_METHOD_ARGUMENT_BUFFER
        Status = STATUS_UNSUCCESSFUL;
        goto ErrorExit;
    }

    RtlCopyMemory(TimingBlock, &QueryResult->Argument[0].Argument, sizeof(*TimingBlock));

    DPRINT("DeviceQueryChannelTimingSettings: _GTM Data:\n");

    for (ix = 0; ix < 2; ix++)
    {
        DPRINT("PIO Speed [%d] %X\n", ix, TimingBlock->Drive[ix].PioSpeed);
        DPRINT("DMA Speed [%d] %X\n", ix, TimingBlock->Drive[ix].DmaSpeed);
    }

    DPRINT("Flags %X\n", TimingBlock->ModeFlags);

    if (QueryResult)
        ExFreePool(QueryResult);

    return;

ErrorExit:

    for (ix = 0; ix < 2; ix++)
    {
        TimingBlock->Drive[ix].PioSpeed = 0xFFFFFFFF;
        TimingBlock->Drive[ix].DmaSpeed = 0xFFFFFFFF;
    }
}

NTSTATUS
NTAPI
ChannelAcpiTransferModeSelect(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPCIIDE_TRANSFER_MODE_SELECT Xmode)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ChannelQueryTransferModeInterface(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    IO_STACK_LOCATION ioStack;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryTransferModeInterface: %p\n", FdoExtension);

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_XFER_MODE_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(FdoExtension->TransferModeInterface);
    ioStack.Parameters.QueryInterface.Version = 1;

    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->TransferModeInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (NT_SUCCESS(Status))
    {
        if (FdoExtension->TransferModeInterface.IsTransferModeSelect != 1)
        {
            for (ix = 0; ix < 2; ix++)
            {
                if (FdoExtension->TimingBlock.Drive[ix].PioSpeed != 0xFFFFFFFF)
                    Status = STATUS_UNSUCCESSFUL;
            }
        }

        ASSERT(FdoExtension->TransferModeInterface.TransferModeTimingTable);
    }

    for (ix = 0; ix < 2; ix++)
    {
        if (FdoExtension->TimingBlock.Drive[ix].PioSpeed != 0xFFFFFFFF)
            Status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(Status))
    {
        FdoExtension->TransferModeInterface.Context = FdoExtension;
        FdoExtension->TransferModeInterface.TransferModeSelect = ChannelAcpiTransferModeSelect;

        FdoExtension->TransferModeInterface.IsTransferModeSelect = FdoExtension->TimingBlock.Drive[0].PioSpeed != 0xFFFFFFFF ||
                                                                   FdoExtension->TimingBlock.Drive[1].PioSpeed != 0xFFFFFFFF;

        if (!FdoExtension->TransferModeInterface.TransferModeTimingTable)
        {
            FdoExtension->TransferModeInterface.TransferModeTimingTable = FdoExtension->DefaultTransferModeTimingTable;
            FdoExtension->TransferModeInterface.TableLength = 0x12;//(18)
        }
    }

    if (!FdoExtension->TransferModeInterface.IsTransferModeSelect)
        FdoExtension->HwDeviceExtension->IsTransferModeNotSelected = TRUE;

    ASSERT(FdoExtension->TransferModeInterface.TransferModeSelect);
    ASSERT(FdoExtension->TransferModeInterface.TransferModeTimingTable);
}

PDEVICE_OBJECT
NTAPI
DeviceCreatePhysicalDeviceObject(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PUNICODE_STRING DeviceName)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_OBJECT Pdo = NULL;
    NTSTATUS Status;

    Status = IoCreateDevice(DriverObject, sizeof(PDO_DEVICE_EXTENSION), DeviceName, 0x2D, 0x100, 0, &Pdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AllocatePdo: Status %X\n", Status);
        return Pdo;
    }

    Pdo->Flags |= 0x4010;

    Pdo->AlignmentRequirement = FdoExtension->SelfDevice->AlignmentRequirement;
    if (Pdo->AlignmentRequirement < 1)
        Pdo->AlignmentRequirement = 1;

    PdoExtension = Pdo->DeviceExtension;
    RtlZeroMemory(PdoExtension, sizeof(*PdoExtension));

    PdoExtension->DriverObject = DriverObject;
    PdoExtension->SelfDevice = Pdo;
    PdoExtension->SystemPowerState = 1;
    PdoExtension->DevicePowerState = 1;
    PdoExtension->FdoExtension = FdoExtension;

    PdoExtension->NoSupportIrp = IdePortNoSupportIrp;
    PdoExtension->PdoPnpDispatchTable = PdoPnpDispatchTable;
    PdoExtension->PdoPowerDispatchTable = PdoPowerDispatchTable;
    //PdoExtension->PdoWmiDispatchTable = PdoWmiDispatchTable;

    return Pdo;
}

PPDO_DEVICE_EXTENSION
NTAPI
AllocatePdo(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ATA_SCSI_ADDRESS ScsiAddress,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    UNICODE_STRING PdoName;
    PDEVICE_OBJECT Pdo;
    ULONG Idx;
    WCHAR NameBuffer[64];
    KIRQL Irql;

    PAGED_CODE();
    DPRINT("AllocatePdo: scan bus %X\n", FdoExtension->ResourceData.CmdBlockBase);

    swprintf(NameBuffer,
             L"\\Device\\Ide\\IdeDeviceP%dT%dL%d-%x",
             FdoExtension->FdoIndex,
             ScsiAddress.TargetId,
             ScsiAddress.Lun,
             (InterlockedIncrement(&PdoIndex) - 1));

    RtlInitUnicodeString(&PdoName, NameBuffer);

    Pdo = DeviceCreatePhysicalDeviceObject(FdoExtension->DriverObject, FdoExtension, &PdoName);
    if (!Pdo)
    {
        DPRINT1("AllocatePdo: Unable to create device object\n", NameBuffer);
        return NULL;
    }

    PdoExtension = Pdo->DeviceExtension;
    PdoExtension->TimeOut = -1;
    PdoExtension->PdoFlags |= 0x8000;
    PdoExtension->Pdo = Pdo;

    PdoExtension->PathId = ScsiAddress.PathId;
    PdoExtension->TargetId = ScsiAddress.TargetId;
    PdoExtension->Lun = ScsiAddress.Lun;

    KeInitializeSpinLock(&PdoExtension->PdoLock);
    InitializeListHead(&PdoExtension->PdoxSrbData.Requests);
    KeInitializeEvent(&PdoExtension->Event, NotificationEvent, FALSE);

    Idx = ((ScsiAddress.Lun + ScsiAddress.TargetId) & 7);

    KeAcquireSpinLock(&FdoExtension->PdoArrayLock, &Irql);

    PdoExtension->LinkPdoExt = FdoExtension->PdoArray[Idx];
    //IdeLogOpenCommandLog(..);
    FdoExtension->PdoArray[Idx] = PdoExtension;

    FdoExtension->PdoCount1++;
    FdoExtension->PdoCount2++;

    IdeInterlockedIncrement(PdoExtension, &PdoExtension->ReferenceCount, TagLock);

    KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

    DPRINT("AllocatePdo: %p %X\n", PdoExtension, PdoExtension->TimeOut);
    return PdoExtension;
}

VOID
NTAPI
SyncAtaPassThroughCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIDE_WAIT_CONTEXT WaitContext,
    _In_ NTSTATUS InStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IssueAsyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ BOOLEAN IsDataIn,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IssueSyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ UCHAR IsDataIn,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed)
{
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    IDE_WAIT_CONTEXT WaitContext;
    ULONG ix;

    DPRINT("IssueSyncAtaPassThroughSafe: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    if (MustSucceed)
    {
        ASSERT(InterlockedCompareExchange(&FdoExtension->EnumStructLock, 1, 0) == 0);
    }

    for (ix = 0; ix < 0xA; ix++)
    {
        KeInitializeEvent(&WaitContext.Event, NotificationEvent, FALSE);

        Status = IssueAsyncAtaPassThroughSafe(FdoExtension,
                                              PdoExtension,
                                              AtaPassThr,
                                              IsDataIn,
                                              SyncAtaPassThroughCompletionRoutine,
                                              &WaitContext,
                                              SrbFunctionType,
                                              TimeOutValue,
                                              MustSucceed);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&WaitContext.Event,  Executive, KernelMode, FALSE, NULL);
            Status = WaitContext.Status;
        }

        if (Status == STATUS_UNSUCCESSFUL)
        {
            DPRINT1("Retrying flushed request\n");
        }

        if (Status != STATUS_UNSUCCESSFUL && Status != STATUS_INSUFFICIENT_RESOURCES)
            break;
    }

    if (MustSucceed)
    {
        ASSERT(InterlockedCompareExchange(&FdoExtension->EnumStructLock, 0, 1) == 1);
    }

    if (NT_SUCCESS(Status))
        return WaitContext.Status;

    DPRINT("IssueSyncAtaPassThroughSafe: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
IdePortSaveDeviceParameter(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PWSTR ValueName,
    _In_ ULONG ValueData)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

ULONG
NTAPI
AtapiDetectDevice(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIDENTIFY_DATA Identify,
    _In_ BOOLEAN MustSucceed)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
IdePortScanBus(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PVOID ImageSectionHandle;
    ATA_SCSI_ADDRESS ScsiAddress;
    ATA_PASS_THROUGH AtaPassThr;
    IDENTIFY_DATA Identify[4];
    ULONG DeviceType[4];
    ULONG ix;
    BOOLEAN IsEmptyChannelCheck;
    BOOLEAN IsNewDevice;
    NTSTATUS Status;

    ImageSectionHandle = MmLockPagableDataSection(IdePortScanBus);

    ASSERT("FdoExtension");
    ASSERT("FdoExtension->PreAllocEnumStruct");

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    if (!FdoExtension->InterruptObject)
    {
        UNIMPLEMENTED_DBGBREAK();
        goto Exit;
    }

    DPRINT("IdePortScanBus: scan bus %X\n", FdoExtension->ResourceData.CmdBlockBase);

    IsEmptyChannelCheck = TRUE;
    ScsiAddress.AsULONG = 0;

    for (ix = 0; ix < HwDeviceExtension->MaxIdeTargetId; ix++)
    {
        ScsiAddress.Lun = 0;
        ScsiAddress.TargetId = ix;

        PdoExtension = RefLogicalUnitExtension(FdoExtension,
                                               ScsiAddress.PathId,
                                               ScsiAddress.TargetId,
                                               ScsiAddress.Lun,
                                               TRUE,
                                               IdePortScanBus);
        if (PdoExtension)
        {
            if (PdoExtension->PdoState & 0x40)
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            IsNewDevice = FALSE;
        }
        else
        {
            PdoExtension = AllocatePdo(FdoExtension, ScsiAddress, IdePortScanBus);
            IsNewDevice = TRUE;
        }

        DPRINT("IdePortScanBus: IsNewDevice %X\n", IsNewDevice);

        if (PdoExtension)
        {
            if (IsEmptyChannelCheck)
            {
                IsEmptyChannelCheck = FALSE;

                RtlZeroMemory(&AtaPassThr, sizeof(AtaPassThr));
                AtaPassThr.IdeReg.bReserved = 4;

                Status = IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &AtaPassThr, 0, 0, 0x1E, TRUE);//30

                DPRINT("IdePortScanBus: Empty Channel check for fdoe %p took 0 ms\n", FdoExtension);
            }

            DPRINT("IdePortScanBus: Status %X\n", Status);

            if (NT_SUCCESS(Status))
            {
                DPRINT("IdePortScanBus: IdeDevicePresent %x detected no device %d\n", FdoExtension->ResourceData.CmdBlockBase, ix);

                IdePortSaveDeviceParameter(FdoExtension, TypeName[PdoExtension->TargetId], 0);
                DeviceType[ix] = 3;
            }
            else
            {
                DeviceType[ix] = AtapiDetectDevice(FdoExtension, PdoExtension, &Identify[ix], 1);

                if (DeviceType[ix] == 3)
                {
                    DPRINT("IdePortScanBus: Didn't detect the device %X\n", ix);
                }
                else
                {
                    DPRINT("IdePortScanBus: Status %X\n", Status);
                    UNIMPLEMENTED_DBGBREAK();
                }
            }

            DPRINT("IdePortScanBus: Status %X\n", Status);
            UNIMPLEMENTED_DBGBREAK();
        }
        else
        {
            DPRINT("IdePortScanBus: IdePortScanBus() is unable to get pdo (%X,%X,%X)\n", ScsiAddress.PathId, ScsiAddress.TargetId, ScsiAddress.Lun);
        }
    }

    UNIMPLEMENTED_DBGBREAK();

    DPRINT("IdePortScanBus: detect a change of device...re-initializing\n");

Exit:

    MmUnlockPagableImageSection(ImageSectionHandle);
}

PDEVICE_RELATIONS
NTAPI
ChannelBuildDeviceRelationList(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
ChannelQueryBusRelation(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PVOID Context)
{
    PATAPI_ENUM_WORKITEM_CONTEXT WorkerContext = Context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PDEVICE_RELATIONS DeviceRelations;
    PIRP Irp;

    DPRINT("ChannelQueryBusRelation: %p, %p\n", Fdo, Context);

    Irp = WorkerContext->Irp;
    FdoExtension = IoGetCurrentIrpStackLocation(Irp)->DeviceObject->DeviceExtension;

    DeviceQueryChannelTimingSettings(FdoExtension, &FdoExtension->TimingBlock);
    ChannelQueryTransferModeInterface(FdoExtension);
    IdePortScanBus(FdoExtension);

    DeviceRelations = ChannelBuildDeviceRelationList(FdoExtension);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;

    IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
ChannelQueryDeviceRelations(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PATAPI_ENUM_WORKITEM_CONTEXT WorkerContext;

    DPRINT("ChannelQueryDeviceRelations: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;

    if (!(FdoExtension->FdoState & 2))
    {
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        IoCompleteRequest(Irp, 0);
        return Irp->IoStatus.Status;
    }

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceRelations.Type != 0)
    {
        DPRINT("ChannelQueryDeviceRelations: Unsupported device relation\n");
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(FdoExtension->LowDevice, Irp);
    }

    DPRINT("ChannelQueryDeviceRelations: bus relations\n");

    ASSERT(FdoExtension->PreAllocEnumStruct);
    WorkerContext = FdoExtension->PreAllocEnumStruct->EnumWorkItemContext;

    ASSERT(WorkerContext);
    ASSERT(WorkerContext->WorkItem);

    WorkerContext->Irp = Irp;

    Irp->IoStatus.Status = STATUS_PENDING;
    IoMarkIrpPending(Irp);

    IoQueueWorkItem(WorkerContext->WorkItem, ChannelQueryBusRelation, DelayedWorkQueue, WorkerContext);

    return STATUS_PENDING;
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
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension = Fdo->DeviceExtension;

    DPRINT("ChannelQueryPnPDeviceState: QUERY_DEVICE_STATE for FDOE %p\n", FdoExtension);

    if (FdoExtension->Paging)
        Irp->IoStatus.Information |= 0x20;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(FdoExtension->LowDevice, Irp);
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
DeviceStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryStopRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryText(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

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
ChannelDeviceIoControl(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PSTORAGE_PROPERTY_QUERY PropertyQuery;
    PFDO_DEVICE_EXTENSION FdoExtension;
    STORAGE_ADAPTER_DESCRIPTOR Adapter;
    PIO_STACK_LOCATION IoStack;
    ULONG Size;
    NTSTATUS Status;

    DPRINT("ChannelDeviceIoControl: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY)
    {
        if (IoStack->DeviceObject == Fdo)
        {
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(FdoExtension->LowDevice, Irp);
        }

        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    PropertyQuery = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(STORAGE_PROPERTY_QUERY))
    {
        DPRINT1("ChannelDeviceIoControl: STATUS_INVALID_PARAMETER\n");
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (PropertyQuery->PropertyId != StorageAdapterProperty)
    {
        DPRINT1("ChannelDeviceIoControl: STATUS_NOT_IMPLEMENTED\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    if (PropertyQuery->QueryType == PropertyExistsQuery)
    {
        DPRINT("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyExistsQuery\n");
        Irp->IoStatus.Status = STATUS_SUCCESS;
        goto Exit;
    }

    if (PropertyQuery->QueryType == PropertyMaskQuery)
    {
        DPRINT1("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyMaskQuery\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    if (PropertyQuery->QueryType != PropertyStandardQuery)
    {
        DPRINT1("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY unknown type\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    DPRINT("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyStandardQuery\n");

    Size = sizeof(Adapter);
    RtlZeroMemory(&Adapter, Size);

    Adapter.Version = Size;
    Adapter.Size = Size;
    Adapter.MaximumTransferLength = FdoExtension->IoScsicapabilities.MaximumTransferLength;
    Adapter.MaximumPhysicalPages = FdoExtension->IoScsicapabilities.MaximumPhysicalPages;
    Adapter.AlignmentMask = Fdo->AlignmentRequirement;
    Adapter.AdapterUsesPio = TRUE;
    Adapter.AdapterScansDown = FALSE;
    Adapter.CommandQueueing = FALSE;
    Adapter.AcceleratedTransfer = FALSE;
    Adapter.BusType = 3;
    Adapter.BusMajorVersion = 1;
    Adapter.BusMinorVersion = 0;

    if (Size > IoStack->Parameters.DeviceIoControl.OutputBufferLength)
        Size = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Adapter, Size);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = Size;

Exit:

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
IdePortDeviceControl(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    ULONG ix;
    NTSTATUS Status;

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    DPRINT("IdePortDeviceControl: %p, %p, %X\n", Fdo, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

    if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_GET_INQUIRY_DATA)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_GET_CAPABILITIES)
    {
        if (IoStack->Parameters.Read.Length < sizeof(FdoExtension->IoScsicapabilities))
        {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            FdoExtension->IoScsicapabilities.AdapterUsesPio = FALSE;

            for (ix = 0; ix < FdoExtension->HwDeviceExtension->MaxIdeDevice; ix++)
            {
                if (!(FdoExtension->HwDeviceExtension->DeviceFlags[ix] & 0x200))
                    FdoExtension->IoScsicapabilities.AdapterUsesPio = TRUE;
            }

            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                          &FdoExtension->IoScsicapabilities,
                          sizeof(FdoExtension->IoScsicapabilities));

            Irp->IoStatus.Information = sizeof(FdoExtension->IoScsicapabilities);
            Status = STATUS_SUCCESS;
        }
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_RESCAN_BUS)
    {
        IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
        Status = STATUS_SUCCESS;
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_MINIPORT)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        return ChannelDeviceIoControl(Fdo, Irp);
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
DeviceDeviceIoControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    if (((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowDevice)
        Status = IdePortDeviceControl(DeviceObject, Irp);
    else
        Status = DeviceDeviceIoControl(DeviceObject, Irp);

    return Status;
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
