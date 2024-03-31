/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         PCI IDE bus driver extension
 * FILE:            drivers/storage/pciidex/pciidex.c
 * PURPOSE:         Main file
 * PROGRAMMERS:     
 */

#include "pciidex.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

ULONG PciIdeDebug = 0;
ULONG ControllerNumber = 0;
ULONG ChannelNumber = 0;

PDRIVER_DISPATCH FdoPnpDispatchTable[] =
{
    ControllerStartDevice,
    StatusSuccessAndPassDownToNextDriver,
    ControllerRemoveDevice,
    StatusSuccessAndPassDownToNextDriver,
    ControllerStopDevice,
    StatusSuccessAndPassDownToNextDriver,
    StatusSuccessAndPassDownToNextDriver,
    ControllerQueryDeviceRelations,
    ControllerQueryInterface,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    ControllerQueryPnPDeviceState,
    PassDownToNextDriver,
    ControllerUsageNotification,
    ControllerSurpriseRemoveDevice,
    PassDownToNextDriver
};

PDRIVER_DISPATCH PdoPnpDispatchTable[] =
{
    ChannelStartDevice,
    ChannelQueryStopRemoveDevice,
    ChannelRemoveDevice,
    PciIdeXAlwaysStatusSuccessIrp,
    ChannelStopDevice,
    ChannelQueryStopRemoveDevice,
    PciIdeXAlwaysStatusSuccessIrp,
    ChannelQueryDeviceRelations,
    PciIdeChannelQueryInterface,
    ChannelQueryCapabitilies,
    ChannelQueryResources,
    ChannelQueryResourceRequirements,
    ChannelQueryText,
    ChannelFilterResourceRequirements,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    ChannelQueryId,
    ChannelQueryPnPDeviceState,
    NoSupportIrp,
    ChannelUsageNotification,
    ChannelRemoveDevice,
    NoSupportIrp
};

PDRIVER_DISPATCH FdoPowerDispatchTable[] =
{
    PassDownToNextDriver,
    PassDownToNextDriver,
    PciIdeSetFdoPowerState,
    PciIdeXQueryPowerState
};

PDRIVER_DISPATCH PdoPowerDispatchTable[] =
{
    NoSupportIrp,
    NoSupportIrp,
    PciIdeSetPdoPowerState,
    PciIdeXQueryPowerState
};

PDRIVER_DISPATCH FdoWmiDispatchTable[] =
{
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver,
    PassDownToNextDriver
};

PDRIVER_DISPATCH PdoWmiDispatchTable[] =
{
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp,
    NoSupportIrp
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

PWCHAR OnMaskStr[2] = {L"MasterOnMask", L"SlaveOnMask"};
PWCHAR OnConfigOffsetStr[2] = {L"MasterOnConfigOffset", L"SlaveOnConfigOffset"};

/* PRIVATE FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
PciIdeBusData(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _In_ BOOLEAN IsGetOrSet)
{
    ULONG Result;

    if (IsGetOrSet)
        Result = FdoExtension->StdInterface.GetBusData(FdoExtension->StdInterface.Context, 0, Buffer, Offset, Length);
    else
        Result = FdoExtension->StdInterface.SetBusData(FdoExtension->StdInterface.Context, 0, Buffer, Offset, Length);

    if (Result != Length)
    {
        DPRINT1("PciIdeBusData: %p, %X, %X, %X, %X\n", FdoExtension, IsGetOrSet, Offset, Length, Result);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
PciIdeUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PciIdeXGetDeviceParameter(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PWSTR ParameterName,
    _In_ ULONG* OutParameter)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    HANDLE DevInstRegKey;
    ULONG OldValue;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeXGetDeviceParameter: %p, '%S'\n", DeviceObject, ParameterName);

    for (ix = 0; ix < 2; ix++)
    {
        Status = IoOpenDeviceRegistryKey(DeviceObject,
                                         (PLUGPLAY_REGKEY_DRIVER | (!ix ? PLUGPLAY_REGKEY_CURRENT_HWPROFILE : 0)),
                                         KEY_READ,
                                         &DevInstRegKey);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PciIdeXGetDeviceParameter: Status %X\n", Status);
            continue;
        }

        OldValue = *OutParameter;

        RtlZeroMemory(QueryTable, sizeof(QueryTable));

        QueryTable[0].Name = ParameterName;
        QueryTable[0].DefaultType = 0;
        QueryTable[0].DefaultData = NULL;
        QueryTable[0].DefaultLength = 0;
        QueryTable[0].Flags = 0x24;
        QueryTable[0].EntryContext = OutParameter;

        Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, DevInstRegKey, QueryTable, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PciIdeXGetDeviceParameter: Status %X\n", Status);
            *OutParameter = OldValue;
        }

        ZwClose(DevInstRegKey);

        if (NT_SUCCESS(Status))
            break;
    }

    return Status;
}

NTSTATUS
NTAPI
PciIdeXRegQueryRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext)
{
    PVOID* OutValueData = EntryContext;

    PAGED_CODE();
    DPRINT("PciIdeXRegQueryRoutine: '%S', %X\n", ValueName, ValueType);

    if (ValueType == 7)
    {
        *OutValueData = ExAllocatePoolWithTag(PagedPool, ValueLength, 'XedI');
        if (*OutValueData)
        {
            RtlMoveMemory(*OutValueData, ValueData, ValueLength);
            return STATUS_SUCCESS;
        }
    }
    else if (ValueType == 4)
    {
        *OutValueData = *((PVOID *)ValueData);
        return STATUS_SUCCESS;
    }

    DPRINT1("PciIdeXRegQueryRoutine: STATUS_UNSUCCESSFUL ('%S', %X)\n", ValueName, ValueType);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
PciIdeXGetDeviceParameterEx(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PWSTR ParameterName,
    _In_ PVOID* OutParameter)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    HANDLE DevInstRegKey;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeXGetDeviceParameterEx: %p, '%S'\n", DeviceObject, ParameterName);

    *OutParameter = NULL;

    for (ix = 0; ix < 2; ix++)
    {
        Status = IoOpenDeviceRegistryKey(DeviceObject,
                                         (PLUGPLAY_REGKEY_DRIVER | (!ix ? PLUGPLAY_REGKEY_CURRENT_HWPROFILE : 0)),
                                         KEY_READ,
                                         &DevInstRegKey);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciIdeXGetDeviceParameterEx: Status %X\n", Status);
            continue;
        }

        RtlZeroMemory(QueryTable, sizeof(QueryTable));

        QueryTable[0].Name = ParameterName;
        QueryTable[0].QueryRoutine = PciIdeXRegQueryRoutine;
        QueryTable[0].Flags = 0x14;
        QueryTable[0].EntryContext = OutParameter;
        QueryTable[0].DefaultType = 0;
        QueryTable[0].DefaultData = NULL;
        QueryTable[0].DefaultLength = 0;

        Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, DevInstRegKey, QueryTable, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PciIdeXGetDeviceParameterEx: Status %X\n", Status);
            *OutParameter = NULL;
        }

        ZwClose(DevInstRegKey);

        if (NT_SUCCESS(Status))
            break;
    }

    return Status;
}

NTSTATUS
NTAPI
PciIdeGetBusStandardInterface(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("PciIdeGetBusStandardInterface: %p\n", FdoExtension);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, FdoExtension->LowDevice, NULL, 0, NULL, &Event, &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PciIdeGetBusStandardInterface: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MinorFunction = IRP_MN_QUERY_INTERFACE;

    IoStack->Parameters.QueryInterface.Size = sizeof(FdoExtension->StdInterface);
    IoStack->Parameters.QueryInterface.Version = 1;
    IoStack->Parameters.QueryInterface.InterfaceSpecificData = 0;
    IoStack->Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->StdInterface;
    IoStack->Parameters.QueryInterface.InterfaceType = &GUID_BUS_INTERFACE_STANDARD;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    Status = IoCallDriver(FdoExtension->LowDevice, Irp);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeGetBusStandardInterface: Status %X\n", Status);
        return Status;
    }

    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    if (NT_SUCCESS(IoStatusBlock.Status))
    {
        ASSERT(FdoExtension->StdInterface.SetBusData);
        ASSERT(FdoExtension->StdInterface.GetBusData);
    }

    return IoStatusBlock.Status;
}

VOID
NTAPI
ControllerOpMode(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PCI_COMMON_CONFIG PciConfig;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ControllerOpMode: %p\n", FdoExtension);

    FdoExtension->NativeMode[0] = 0;
    FdoExtension->NativeMode[1] = 0;

    Status = PciIdeBusData(FdoExtension, &PciConfig, 0, sizeof(PciConfig), 1);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerOpMode: Status %X\n", Status);
        return;
    }

    if ((PciConfig.BaseClass == PCI_CLASS_MASS_STORAGE_CTLR && PciConfig.SubClass == PCI_SUBCLASS_MSC_RAID_CTLR) ||
        ((PciConfig.ProgIf & 1) && (PciConfig.ProgIf & 4)))
    {
        FdoExtension->NativeMode[0] = 1;
        FdoExtension->NativeMode[1] = 1;
    }

    ASSERT((FdoExtension->NativeMode[0] == FALSE) == (FdoExtension->NativeMode[1] == FALSE));
}

NTSTATUS
NTAPI
PciIdeGetNativeModeInterface(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ControllerAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PPCIIDEX_DRIVER_EXTENSION DriverObjectExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PDEVICE_OBJECT Fdo;
    UNICODE_STRING FdoName;
    ULONG FdoIndex;
    ULONG Size;
    WCHAR NameBuffer[64];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ControllerAddDevice: %p, %p\n", DriverObject, LowerPdo);

    DriverObjectExtension = IoGetDriverObjectExtension(DriverObject, DriverEntry);
    ASSERT(DriverObjectExtension);

    FdoIndex = (InterlockedIncrement((PLONG)&ControllerNumber) - 1);
    swprintf(NameBuffer, L"\\Device\\Ide\\PciIde%d", FdoIndex);

    RtlInitUnicodeString(&FdoName, NameBuffer);
    Size = (DriverObjectExtension->MiniControllerExtensionSize + sizeof(*FdoExtension));

    Status = IoCreateDevice(DriverObject, Size, &FdoName, FILE_DEVICE_BUS_EXTENDER, FILE_DEVICE_SECURE_OPEN, FALSE, &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerAddDevice: Status %X\n", Status);
        return Status;
    }
    RtlZeroMemory(Fdo->DeviceExtension, Size);

    FdoExtension = Fdo->DeviceExtension;

    FdoExtension->LowPdo = LowerPdo;
    FdoExtension->SelfDevice = Fdo;
    FdoExtension->DriverObject = DriverObject;
    FdoExtension->MiniControllerExtension = &FdoExtension[1];
    FdoExtension->DeviceControlFlags = 0;
    FdoExtension->FdoIndex = FdoIndex;

    FdoExtension->PassToNextDriver = PassDownToNextDriver;
    FdoExtension->FdoPnpDispatchTable = FdoPnpDispatchTable;
    FdoExtension->FdoPowerDispatchTable = FdoPowerDispatchTable;
    FdoExtension->FdoWmiDispatchTable = FdoWmiDispatchTable;

    Status = PciIdeXGetDeviceParameter(LowerPdo, L"DeviceControlFlags", &FdoExtension->DeviceControlFlags);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerAddDevice: Unable to get DeviceControlFlags from the registry\n");
        Status = STATUS_SUCCESS;
    }

    FdoExtension->LowDevice = IoAttachDeviceToDeviceStack(Fdo, LowerPdo);
    if (!FdoExtension->LowDevice)
    {
        DPRINT1("ControllerAddDevice: %p, %p\n", Fdo, LowerPdo);
        IoDeleteDevice(Fdo);
        return Status;
    }

    if (FdoExtension->LowDevice->AlignmentRequirement < 1)
        Fdo->AlignmentRequirement = 1;
    else
        Fdo->AlignmentRequirement = FdoExtension->LowDevice->AlignmentRequirement;

    Status = PciIdeGetBusStandardInterface(FdoExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerAddDevice: Status %X\n", Status);
        IoDetachDevice(FdoExtension->LowDevice);
        IoDeleteDevice(Fdo);
        return Status;
    }

    ControllerOpMode(FdoExtension);

    if (FdoExtension->NativeMode[0])
    {
        if (FdoExtension->NativeMode[1])
            PciIdeGetNativeModeInterface(FdoExtension);
    }

    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS
NTAPI
PciIdeInternalDeviceIoControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DispatchWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
EnablePCIBusMastering(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PCI_COMMON_CONFIG Buffer;
    NTSTATUS Status;

    DPRINT("EnablePCIBusMastering: %p\n", FdoExtension);

    Status = PciIdeBusData(FdoExtension, &Buffer, 0, 0x40, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("EnablePCIBusMastering: Status %X\n", Status);
        return Status;
    }

    if (!(Buffer.ProgIf & 0x80))
        return Status;

    if (Buffer.Command & 4)
        return Status;

    Buffer.Command |= 4;

    return PciIdeBusData(FdoExtension, &Buffer.Command, 4, 2, FALSE);
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

    PoStartNextPowerIrp(Irp);

    if (!NT_SUCCESS(IoStatus->Status))
    {
        DPRINT1("FdoSystemPowerUpCompletionRoutine: %X\n", IoStatus->Status);
        Irp->IoStatus.Status = IoStatus->Status;
    }

    IoCompleteRequest(Irp, 0);
}

NTSTATUS
NTAPI
FdoPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PIDE_SET_POWER_CONTEXT IdeContext = Context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    POWER_STATE state;
    BOOLEAN IsSystemWorkingState = FALSE;
    BOOLEAN IsChangeDeviceState = TRUE;
    NTSTATUS Status;

    DPRINT("FdoPowerCompletionRoutine: %p, %p, %p\n", Fdo, Irp, Context);

    FdoExtension = Fdo->DeviceExtension;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        if (IdeContext->Type)
        {
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
        }
        else
        {
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        }

        goto Finish;
    }

    if (IdeContext->Type == SystemPowerState)
    {
        FdoExtension->SystemPowerState = IdeContext->State.SystemState;

        if (IdeContext->State.SystemState == PowerSystemWorking)
        {
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);

            IsSystemWorkingState = TRUE;
            state.SystemState = PowerSystemWorking;

            Status = PoRequestPowerIrp(FdoExtension->SelfDevice, 2, state, FdoSystemPowerUpCompletionRoutine, Irp, 0);
            ASSERT(Status == STATUS_PENDING);
        }

        DPRINT("FdoPowerCompletionRoutine: New Fdo system power state %X\n", FdoExtension->SystemPowerState);

        PoSetPowerState(Fdo, IdeContext->Type, IdeContext->State);

        if (!IsSystemWorkingState)
        {
            if (IdeContext->Type)
            {
                ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
            }
            else
            {
                ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
            }
        }

        goto Finish;
    }

    if (IdeContext->Type == DevicePowerState)
    {
        if (FdoExtension->DevicePowerState == PowerDeviceD0)
            IsChangeDeviceState = FALSE;

        FdoExtension->DevicePowerState = IdeContext->State.DeviceState;

        if (IdeContext->State.DeviceState == PowerDeviceD0)
        {
            EnablePCIBusMastering(FdoExtension);
            IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
        }

        DPRINT("FdoPowerCompletionRoutine: New Fdo device power state %X\n", FdoExtension->DevicePowerState);

        if (IsChangeDeviceState)
            PoSetPowerState(Fdo, IdeContext->Type, IdeContext->State);
    }
    else
    {
        DPRINT1("FdoPowerCompletionRoutine: %p, %p, %p, %X\n", Fdo, Irp, Context, IdeContext->Type);
        PoSetPowerState(Fdo, IdeContext->Type, IdeContext->State);
    }

    if (IdeContext->Type)
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
    }
    else
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
    }

Finish:

    if (IsSystemWorkingState)
        return STATUS_MORE_PROCESSING_REQUIRED;

    PoStartNextPowerIrp(Irp);

    return Irp->IoStatus.Status;
}

/* POWER FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
PciIdeSetFdoPowerState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIDE_SET_POWER_CONTEXT PowerContext;
    PIO_STACK_LOCATION IoStack;
    POWER_STATE state;
    BOOLEAN SystemPowerContext = FALSE;
    BOOLEAN DevicePowerContext = FALSE;
    BOOLEAN IsOldState = FALSE;

    DPRINT("PciIdeSetFdoPowerState: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type)
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 1, 0) == 0);
        PowerContext = &FdoExtension->PowerContext[1];
        DevicePowerContext = TRUE;
    }
    else
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 1, 0) == 0);
        PowerContext = FdoExtension->PowerContext;
        SystemPowerContext = TRUE;
    }

    if (PowerContext)
    {
        PowerContext->Irp = Irp;
        PowerContext->Type = IoStack->Parameters.Power.Type;
        PowerContext->State = IoStack->Parameters.Power.State;

        if (IoStack->Parameters.Power.Type == SystemPowerState)
        {
            if (FdoExtension->SystemPowerState != IoStack->Parameters.Power.State.SystemState)
            {
                if (IoStack->Parameters.Power.State.SystemState == PowerSystemShutdown &&
                    IoStack->Parameters.Power.ShutdownType == PowerActionShutdownReset)
                {
                    IoMarkIrpPending(Irp);
                    state.SystemState = 1;
                    PoRequestPowerIrp(FdoExtension->SelfDevice, 2, state, FdoContingentPowerCompletionRoutine, PowerContext, 0);
                    return STATUS_PENDING;
                }
                else if (FdoExtension->SystemPowerState == PowerSystemWorking)
                {
                    IoMarkIrpPending(Irp);
                    state.SystemState = PowerSystemSleeping3;
                    PoRequestPowerIrp(FdoExtension->SelfDevice, 2, state, FdoContingentPowerCompletionRoutine, PowerContext, 0);
                    return STATUS_PENDING;
                }
            }
            else
            {
                IsOldState = TRUE;
            }
        }
        else if (IoStack->Parameters.Power.Type == DevicePowerState)
        {
            if (FdoExtension->DevicePowerState != IoStack->Parameters.Power.State.DeviceState)
            {
                if (FdoExtension->DevicePowerState == PowerDeviceD0)
                    PoSetPowerState(Fdo, DevicePowerState, IoStack->Parameters.Power.State);
            }
            else
            {
                IsOldState = TRUE;
            }
        }
        else
        {
            ASSERT(FALSE);

            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;

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

            return STATUS_NOT_IMPLEMENTED;
        }


        IoMarkIrpPending(Irp);
        IoCopyCurrentIrpStackLocationToNext(Irp);

        if (IsOldState)
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
        else
        {
            IoSetCompletionRoutine(Irp, FdoPowerCompletionRoutine, PowerContext, TRUE, TRUE, TRUE);
        }

        PoCallDriver(FdoExtension->LowDevice, Irp);

        return STATUS_PENDING;
    }

    ASSERT(PowerContext);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NO_MEMORY;

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

    return STATUS_NO_MEMORY;
}

NTSTATUS
NTAPI
PciIdeSetPdoPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PciIdeXQueryPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    DPRINT("DispatchPower: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        IsFdo = TRUE;
        DPRINT("DispatchPower: FDO %d got '%s'\n", FdoExtension->FdoIndex, PowerMinorNames[MinorFunction]);
    }
    else
    {
        IsFdo = FALSE;
        PdoExtension = DeviceObject->DeviceExtension;
        DPRINT("DispatchPower: PDO %d got '%s'\n", PdoExtension->PdoIndex, PowerMinorNames[MinorFunction]);
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPowerDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            return PdoExtension->PdoPowerDispatchTable[MinorFunction](DeviceObject, Irp);
    }

    if (MinorFunction >= 4)
        ASSERT(!"ATAPI: Power Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassToNextDriver(DeviceObject, Irp);
    else
        return PdoExtension->NoSupportIrp(DeviceObject, Irp);
}

/* PNP FUNCTIONS ************************************************************/

NTSTATUS
NTAPI
StatusSuccessAndPassDownToNextDriver(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PassDownToNextDriver(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("PassDownToNextDriver: %p, %p\n", Fdo, Irp);

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
NoSupportIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ControllerStartDeviceCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PRKEVENT Event = Context;

    DPRINT("ControllerStartDeviceCompletionRoutine: %p, %X, %X\n", DeviceObject, Irp, Context);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
PciIdePowerCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PIDE_WAIT_CONTEXT WaitContext = Context;

    DPRINT("PciIdePowerCompletionRoutine: %p, %X, %X\n", DeviceObject, Irp, Context);

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
PciIdeIssueSetPowerState(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ POWER_STATE_TYPE PowerType,
    _In_ POWER_STATE State,
    _In_ BOOLEAN IsWait)
{
    PIO_STACK_LOCATION IoStack;
    IDE_WAIT_CONTEXT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeIssueSetPowerState: %p, %X, %X, %X\n", FdoExtension, PowerType, State.SystemState, IsWait);

    if (IsWait)
        KeInitializeEvent(&Event.Event, NotificationEvent, FALSE);

    Irp = IoAllocateIrp((FdoExtension->SelfDevice->StackSize + 1), FALSE);
    if (!Irp)
    {
        DPRINT1("PciIdeIssueSetPowerState: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack = IoGetNextIrpStackLocation(Irp);

    IoStack->MajorFunction = IRP_MJ_POWER;
    IoStack->MinorFunction = IRP_MN_SET_POWER;

    IoStack->Parameters.Power.SystemContext = 0;
    IoStack->Parameters.Power.Type = PowerType;
    IoStack->Parameters.Power.State = State;

    IoSetCompletionRoutine(Irp, PciIdePowerCompletionRoutine, (IsWait ? &Event : NULL), TRUE, TRUE, TRUE);

    Status = PoCallDriver(FdoExtension->SelfDevice, Irp);
    if (IsWait)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Event.Status;
    }

    return Status;
}

NTSTATUS
NTAPI
AnalyzeResourceList(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST InCmResource)
{
    PCM_FULL_RESOURCE_DESCRIPTOR InFullDesc;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR InDesc;
    PCM_RESOURCE_LIST PdoResources[2];
    PCM_FULL_RESOURCE_DESCRIPTOR PdoFullDesc[2];
    PCM_PARTIAL_RESOURCE_LIST PdoPartialList[2];
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PdoDesc[2];
    PVOID PdoResourcesEnd[2];
    PCM_RESOURCE_LIST BmResources;
    PCM_FULL_RESOURCE_DESCRIPTOR BmFullDesc;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR BmDesc;
    PVOID BmResourcesEnd;
    ULONG BusMaster;
    ULONG CtrlIdx;
    ULONG CmdIdx;
    ULONG IntIdx;
    ULONG Size;
    ULONG ix;
    ULONG jx;
    ULONG kx;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AnalyzeResourceList: %p, %p\n", FdoExtension, InCmResource);

    if (!InCmResource)
        return STATUS_SUCCESS;

  #if DBG
    DPRINT1("AnalyzeResourceList: Dump %p\n", InCmResource);
    RosDumpCmResources(InCmResource, 0);
  #endif

    Size = (InCmResource->Count * sizeof(CM_RESOURCE_LIST));

    BmResources = ExAllocatePoolWithTag(NonPagedPool, Size, 'XedI');
    if (!BmResources)
    {
        DPRINT1("AnalyzeResourceList: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(BmResources, Size);

    Size += (2 * sizeof(CM_PARTIAL_RESOURCE_LIST));

    for (ix = 0; ix < 2; ix++)
    {
        PdoResources[ix] = ExAllocatePoolWithTag(NonPagedPool, Size, 'XedI');
        if (!PdoResources[ix])
        {
            DPRINT1("AnalyzeResourceList: Unable to allocate resourceList for PDOs\n");

            for (jx = 0; jx < ix; jx++)
                ExFreePoolWithTag(PdoResources[jx], 'XedI');

            ExFreePoolWithTag(BmResources, 'XedI');

            return STATUS_NO_MEMORY;
        }
        RtlZeroMemory(PdoResources[ix], Size);
    }

    for (ix = 0; ix < 2; ix++)
    {
        PdoResources[ix]->Count = 0;
        PdoFullDesc[ix] = PdoResources[ix]->List;
    }

    IntIdx = 0;
    CtrlIdx = 0;
    CmdIdx = 0;

    BusMaster = 0;
    BmResources->Count = 0;

    InFullDesc = InCmResource->List;
    BmFullDesc = BmResources->List;

    for (ix = 0; ix < InCmResource->Count; ix++)
    {
        BmFullDesc->InterfaceType = InFullDesc->InterfaceType;
        BmFullDesc->BusNumber = InFullDesc->BusNumber;

        BmFullDesc->PartialResourceList.Version = InFullDesc->PartialResourceList.Version;
        BmFullDesc->PartialResourceList.Revision = InFullDesc->PartialResourceList.Revision;
        BmFullDesc->PartialResourceList.Count = 0;

        for (jx = 0; jx < 2; jx++)
        {
            PdoFullDesc[jx]->InterfaceType = InFullDesc->InterfaceType;
            PdoFullDesc[jx]->BusNumber = InFullDesc->BusNumber;
            PdoFullDesc[jx]->PartialResourceList.Version = InFullDesc->PartialResourceList.Version;
            PdoFullDesc[jx]->PartialResourceList.Revision = InFullDesc->PartialResourceList.Revision;
            PdoFullDesc[jx]->PartialResourceList.Count = 0;

            PdoPartialList[jx] = &PdoFullDesc[jx]->PartialResourceList;
            PdoDesc[jx] = PdoFullDesc[jx]->PartialResourceList.PartialDescriptors;
        }

        InDesc = InFullDesc->PartialResourceList.PartialDescriptors;
        BmDesc = BmFullDesc->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < InFullDesc->PartialResourceList.Count; jx++)
        {
            if (InDesc[ix].Type == 1 || InDesc[ix].Type == 3)
            {
                if (InDesc[jx].u.Generic.Length == 8 && CmdIdx < 2)
                {
                    RtlCopyMemory((PdoDesc[CmdIdx] + PdoPartialList[CmdIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                    PdoPartialList[CmdIdx]->Count++;
                    CmdIdx++;
                }
                else if (InDesc[jx].u.Generic.Length == 4 && CtrlIdx < 2)
                {
                    RtlCopyMemory((PdoDesc[CtrlIdx] + PdoPartialList[CmdIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                    PdoPartialList[CtrlIdx]->Count++;
                    CtrlIdx++;
                }
                else if (InDesc[jx].u.Generic.Length == 0x10 && BusMaster < 1)
                {
                    RtlCopyMemory(&BmDesc[BmFullDesc->PartialResourceList.Count], &InDesc[jx], sizeof(BmDesc[0]));
                    BmFullDesc->PartialResourceList.Count++;
                    BusMaster++;
                }
            }
            else if (InDesc[jx].Type == 2 && IntIdx < 2)
            {
                RtlCopyMemory((PdoDesc[IntIdx] + PdoPartialList[IntIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                PdoPartialList[IntIdx]->Count++;

                if (!IntIdx && FdoExtension->NativeMode[1])
                {
                    RtlCopyMemory((PdoDesc[1] + PdoPartialList[1]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                    IntIdx = 1;
                }

                IntIdx++;
            }
            else if (InDesc[jx].Type == 5)
            {
                InDesc = Add2Ptr(InDesc, InDesc[jx].u.DeviceSpecificData.DataSize);
            }
        }

        if (BmFullDesc->PartialResourceList.Count)
        {
            BmResources->Count++;
            BmResourcesEnd = &BmDesc[BmFullDesc->PartialResourceList.Count];
        }

        for (kx = 0; kx < 2; kx++)
        {
            if (PdoPartialList[kx]->Count)
            {
                PdoResources[kx]->Count++;
                PdoResourcesEnd[kx] = (PdoDesc[kx] + PdoPartialList[kx]->Count);
            }
        }

        InFullDesc = (PCM_FULL_RESOURCE_DESCRIPTOR)&InDesc[jx];
    }

    Status = STATUS_SUCCESS;

    for (ix = 0; ix < 2; ix++)
    {
        if (FdoExtension->NativeMode[ix] && (ix >= CmdIdx || ix >= CtrlIdx || ix >= IntIdx))
        {
            CmdIdx = 0;
            CtrlIdx = 0;
            IntIdx = 0;

            BusMaster = 0;
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!FdoExtension->NativeMode[0] && !FdoExtension->NativeMode[1])
    {
        CmdIdx = 0;
        CtrlIdx = 0;
        IntIdx = 0;
    }

    if (BusMaster)
    {
        FdoExtension->BusMasterResourcesSize = ((ULONG_PTR)BmResourcesEnd - (ULONG_PTR)BmResources);
        FdoExtension->BusMasterResources = BmResources;

        if (BmResources->List[0].PartialResourceList.PartialDescriptors[0].Type == 1)
        {
            FdoExtension->TranslatedBusMasterBaseAddress = 
                (PVOID)BmResources->List[0].PartialResourceList.PartialDescriptors[0].u.Port.Start.LowPart;

            FdoExtension->BusMasterResType = 1;
        }
        else if (BmResources->List[0].PartialResourceList.PartialDescriptors[0].Type == 3)
        {
            FdoExtension->TranslatedBusMasterBaseAddress = 
                MmMapIoSpace(BmResources->List[0].PartialResourceList.PartialDescriptors[0].u.Memory.Start, 0x10, 0);

            ASSERT(FdoExtension->TranslatedBusMasterBaseAddress);
            FdoExtension->BusMasterResType = 0;
        }
        else
        {
            FdoExtension->TranslatedBusMasterBaseAddress = NULL;
            ASSERT(FALSE);
        }
    }
    else
    {
        FdoExtension->TranslatedBusMasterBaseAddress = NULL;
    }

    if (!FdoExtension->TranslatedBusMasterBaseAddress)
    {
        ExFreePoolWithTag(BmResources, 'XedI');
        FdoExtension->BusMasterResources = NULL;
    }

    for (ix = 0; ix < 2; ix++)
    {
        if (ix < CmdIdx || ix < CtrlIdx || ix < IntIdx)
        {
            FdoExtension->ChannelResourceSize[ix] = ((ULONG_PTR)PdoResourcesEnd[ix] - (ULONG_PTR)PdoResources[ix]);

            if (ix < CmdIdx)
                FdoExtension->IsCmdBlockResource[ix] = TRUE;

            if (ix < CtrlIdx)
                FdoExtension->IsCtrlBlockResource[ix] = TRUE;

            if (ix < IntIdx)
                FdoExtension->IsIntResource[ix] = TRUE;
        }
        else
        {
            ExFreePoolWithTag(PdoResources[ix], 'XedI');
            PdoResources[ix] = NULL;
        }

        FdoExtension->ChannelResources[ix] = PdoResources[ix];
    }

    return Status;
}

NTSTATUS
NTAPI
PciIdeInitControllerProperties(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PPCIIDEX_DRIVER_EXTENSION DriverExtension;

    PAGED_CODE();
    DPRINT("PciIdeInitControllerProperties: %p\n", FdoExtension);

    DriverExtension = IoGetDriverObjectExtension(FdoExtension->DriverObject, DriverEntry);
    ASSERT(DriverExtension);

    FdoExtension->ControllerProperties.Size = sizeof(FdoExtension->ControllerProperties);
    FdoExtension->ControllerProperties.DefaultPIO = 0;

    DriverExtension->HwGetControllerProperties(FdoExtension->MiniControllerExtension, &FdoExtension->ControllerProperties);

    FdoExtension->EnableUDMA66 = 0;

    return PciIdeXGetDeviceParameter(FdoExtension->LowPdo, L"EnableUDMA66", &FdoExtension->EnableUDMA66);
}

BOOLEAN
NTAPI
PciIdeSyncAccessRequired(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    ULONG SyncAccess = 0;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeSyncAccessRequired: %p\n", FdoExtension);

    Status = PciIdeXGetDeviceParameter(FdoExtension->LowPdo, L"SyncAccess", &SyncAccess);
    if (NT_SUCCESS(Status))
    {
        return (SyncAccess != 0);
    }

    DPRINT("PciIdeSyncAccessRequired: Unable to get SyncAccess flag from the registry\n");

    if (FdoExtension->ControllerProperties.PciIdeSyncAccessRequired)
        return FdoExtension->ControllerProperties.PciIdeSyncAccessRequired(FdoExtension->MiniControllerExtension);

    DPRINT("PciIdeSyncAccessRequired: assume sync access not required\n");

    return FALSE;
}

NTSTATUS
NTAPI
PciIdeCreateSyncChildAccess(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PUCHAR Port;

    PAGED_CODE();
    DPRINT("PciIdeCreateSyncChildAccess: %p\n", FdoExtension);

    Port = FdoExtension->TranslatedBusMasterBaseAddress;

    if (!Port || !(READ_PORT_UCHAR(Port + 2) & 0x80))
    {
        if (!PciIdeSyncAccessRequired(FdoExtension))
            return STATUS_SUCCESS;
    }

    DPRINT("PciIdeCreateSyncChildAccess: Serialize access to both channels\n");

    FdoExtension->ControllerObject = IoCreateController(0);
    ASSERT(FdoExtension->ControllerObject);

    return (FdoExtension->ControllerObject ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES);
}

NTSTATUS
NTAPI
PciIdeCreateTimingTable(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNICODE_STRING TimingString;
    PVOID RegTimingList = 0;
    PULONG TimingTable = 0;
    PCWSTR Current;
    ULONG ix;
    ULONG idx;
    ULONG TimingTableLength = 0;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeCreateTimingTable: %p\n", FdoExtension);

    Status = PciIdeXGetDeviceParameterEx(FdoExtension->LowPdo, L"TransferModeTiming", &RegTimingList);

    if (!NT_SUCCESS(Status) || !RegTimingList)
    {
        DPRINT("PciIdeCreateTimingTable: Unsuccessful regop (%X), RegTimingList %p\n", Status, RegTimingList);

        TimingTable = ExAllocatePoolWithTag(NonPagedPool, (18 * sizeof(ULONG)), 'XedI');
        if (!TimingTable)
        {
            DPRINT1("PciIdeCreateTimingTable: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            TimingTableLength = 0;
            goto Exit;
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

        TimingTableLength = 18;

        Status = 0;
        goto Exit;
    }

    Current = RegTimingList;

    if (Current[0])
    {
        for (ix = 0; ; ix++)
        {
            RtlInitUnicodeString(&TimingString, Current);
            RtlUnicodeStringToInteger(&TimingString, 10, &TimingTableLength);

            if (ix == 0)
            {
                if (TimingTableLength > 31)
                {
                    ASSERT(TimingTableLength <= 31);
                    TimingTableLength = 31;
                }

                if (TimingTableLength < 18)
                    TimingTableLength = 18;

                TimingTable = ExAllocatePoolWithTag(NonPagedPool, (TimingTableLength * sizeof(ULONG)), 'XedI');
                if (!TimingTable)
                {
                    DPRINT1("PciIdeCreateTimingTable: STATUS_INSUFFICIENT_RESOURCES\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
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

                for (idx = 18; idx < TimingTableLength; idx++)
                {
                    TimingTable[idx] = TimingTable[17];
                    idx++;
                }
            }
            else
            {
                if (ix > TimingTableLength)
                {
                    DPRINT1("PciIdeCreateTimingTable: Timing table overflow\n");
                    break;
                }

                if (TimingTableLength)
                    TimingTable[ix - 1] = TimingTableLength;
            }

            if (!Current[(TimingString.Length / 2) + 1])
                break;

            Current += ((TimingString.Length / 2) + 1);
        }
    }

    if (TimingTableLength < 18)
        TimingTableLength = 18;

    ExFreePool(RegTimingList);

Exit:

    FdoExtension->TimingTable = TimingTable;
    FdoExtension->TimingTableLength = TimingTableLength;

    return Status;
}

/* FDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ControllerStartDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PCM_RESOURCE_LIST CmResources;
    POWER_STATE State;
    KEVENT Event;
    ULONG ix;
    ULONG jx;
    ULONG kx;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ControllerStartDevice: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;

    CmResources = (IoGetCurrentIrpStackLocation(Irp))->Parameters.StartDevice.AllocatedResourcesTranslated;
    if (!CmResources)
    {
        DPRINT1("ControllerStartDevice: Starting with no resource\n");
    }

    if (FdoExtension->NativeMode[0] && FdoExtension->NativeMode[1])
    {
        if (FdoExtension->PciNativeIdeInterface)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSetCompletionRoutine(Irp, ControllerStartDeviceCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(FdoExtension->LowDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    State.SystemState = PowerSystemWorking;
    Status = PciIdeIssueSetPowerState(FdoExtension, SystemPowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        FdoExtension->SystemPowerState = PowerSystemWorking;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    State.DeviceState = PowerDeviceD0;
    Status = PciIdeIssueSetPowerState(FdoExtension, DevicePowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        FdoExtension->DevicePowerState = PowerDeviceD0;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    if (!FdoExtension->NativeMode[0] || !FdoExtension->NativeMode[1])
        EnablePCIBusMastering(FdoExtension);

    KeInitializeSpinLock(&FdoExtension->SpinLock);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    Status = AnalyzeResourceList(FdoExtension, CmResources);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    PciIdeInitControllerProperties(FdoExtension);

    if (FdoExtension->NativeMode[0] && FdoExtension->NativeMode[1])
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    Status = PciIdeCreateSyncChildAccess(FdoExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    Status = PciIdeCreateTimingTable(FdoExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
        goto Exit;
    }

    DPRINT("ControllerStartDevice: Starting device\n");

    for (ix = 0; ix < 3; ix++)
    {
        if (ix == 0 || ix == 1)
        {
            DPRINT("ControllerStartDevice: PDO %d resources:\n", ix);
            CmResources = FdoExtension->ChannelResources[ix];
        }
        else if (ix == 2)
        {
            DPRINT("ControllerStartDevice: Busmaster resources:\n");
            CmResources = FdoExtension->BusMasterResources;
        }

        if (!CmResources)
            continue;

        FullList = &CmResources->List[0];

        for (jx = 0; jx < CmResources->Count; jx++)
        {
            Descriptor = FullList->PartialResourceList.PartialDescriptors;

            for (kx = 0; kx < FullList->PartialResourceList.Count; kx++)
            {
                switch (Descriptor[kx].Type)
                {
                    case 1:
                        DPRINT("ControllerStartDevice: IO Port = 0x%x. Lenght = 0x%x\n", Descriptor[kx].u.Port.Start.LowPart, Descriptor[kx].u.Port.Length);
                        break;

                    case 3:
                        DPRINT("ControllerStartDevice: Memory Port = 0x%x. Lenght = 0x%x\n", Descriptor[kx].u.Memory.Start.LowPart, Descriptor[kx].u.Memory.Length);
                        break;

                    case 2:
                        DPRINT("ControllerStartDevice: Int Level = 0x%x. Int Vector = 0x%x\n", Descriptor[kx].u.Interrupt.Level, Descriptor[kx].u.Interrupt.Vector);
                        break;

                    default:
                        DPRINT("ControllerStartDevice: Unknown resource\n");
                        break;
                }
            }

            FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)&Descriptor[kx];
        }
    }

Exit:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ControllerRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ControllerStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

ULONG
NTAPI
PciIdeChannelEnabled(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ULONG Channel)
{
    ULONG Offset;
    ULONG State;
    ULONG Mask = 0;
    UCHAR Buffer;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeChannelEnabled: %p, %X\n", FdoExtension, Channel);

    // FIXME PciIdeXDebugFakeMissingChild

    Status = PciIdeXGetDeviceParameter(FdoExtension->LowPdo, OnMaskStr[Channel], &Mask);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeChannelEnabled: Unable to get OnMaskStr from the registry\n");
        goto ErrorExit;
    }

    Offset = 0;

    Status = PciIdeXGetDeviceParameter(FdoExtension->LowPdo, OnConfigOffsetStr[Channel], &Offset);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeChannelEnabled: Unable to get OnConfigOffsetStr from the registry\n");
        goto ErrorExit;
    }

    Status = PciIdeBusData(FdoExtension, &Buffer, Offset, 1, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeChannelEnabled: Status %X\n", Status);
        goto ErrorExit;
    }

    return ((Buffer & (UCHAR)Mask) != 0);

ErrorExit:

    if (FdoExtension->ControllerProperties.PciIdeChannelEnabled)
        State = FdoExtension->ControllerProperties.PciIdeChannelEnabled(FdoExtension->MiniControllerExtension, Channel);
    else
        State = 2;

    return State;
}

VOID
NTAPI
ChannelUpdatePdoState(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG OrState,
    _In_ ULONG AndState)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ControllerQueryDeviceRelations(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PCONFIGURATION_INFORMATION ConfigurationInformation;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_RELATIONS DeviceRelations;
    PDEVICE_OBJECT Pdo;
    LARGE_INTEGER TickCount;
    UNICODE_STRING PdoName;
    ULONG LastRescan;
    ULONG TimePassed;
    ULONG ChannelState;
    ULONG Size;
    ULONG ix;
    WCHAR NameBuffer[256];
    BOOLEAN IdDoRescan;
    NTSTATUS Status = 0;

    PAGED_CODE();
    DPRINT("ControllerQueryDeviceRelations: %p, %p\n", Fdo, Irp);

    ConfigurationInformation = IoGetConfigurationInformation();

    FdoExtension = Fdo->DeviceExtension;

    if ((IoGetCurrentIrpStackLocation(Irp))->Parameters.QueryDeviceRelations.Type != 0)
    {
        DPRINT("ControllerQueryDeviceRelations: Unsupported device relation\n");
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(FdoExtension->LowDevice, Irp);
    }

    DPRINT("ControllerQueryDeviceRelations: bus relations\n");

    Size = (sizeof(*DeviceRelations) + sizeof(PDEVICE_OBJECT));

    DeviceRelations = ExAllocatePoolWithTag(PagedPool, Size, 'XedI');
    if (!DeviceRelations)
    {
        DPRINT1("ControllerQueryDeviceRelations: Unable to allocate DeviceRelations structures\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(DeviceRelations, Size);

    KeQueryTickCount(&TickCount);
    LastRescan = ((KeQueryTimeIncrement() * TickCount.QuadPart) / 10000000);
    TimePassed = (LastRescan - FdoExtension->LastRescan);

    DPRINT("ControllerQueryDeviceRelations: Last rescan was %d seconds ago.\n", TimePassed);

    if (TimePassed >= 90 || FdoExtension->LastRescan == 0)
        IdDoRescan = 1;
    else
        IdDoRescan = 0;

    FdoExtension->LastRescan = LastRescan;

    for (ix = 0; ix < 2; ix++)
    {
        ChannelState = PciIdeChannelEnabled(FdoExtension, ix);

        PdoExtension = FdoExtension->PdoExtension[ix];

        if (PdoExtension)
        {
            if (ChannelState == ChannelDisabled)
                ChannelUpdatePdoState(PdoExtension, 2, 0);

            if (PdoExtension->PdoState & 2)
            {
                continue;
            }

            ASSERT(ChannelState != ChannelDisabled);

            Pdo = PdoExtension->SelfDevice;
        }
        else
        {
          if (ChannelState != 1 && (ChannelState != 2 || !IdDoRescan))
          {
              continue;
          }
          if (!FdoExtension->NativeMode[ix])
          {
              if (ix)
                  ConfigurationInformation->AtDiskSecondaryAddressClaimed = 1;
              else
                  ConfigurationInformation->AtDiskPrimaryAddressClaimed = 1;
          }

          swprintf(NameBuffer, L"\\Device\\Ide\\PciIde%dChannel%d-%x", FdoExtension->FdoIndex, ix, InterlockedIncrement((PLONG)&ChannelNumber) - 1);
          RtlInitUnicodeString(&PdoName, NameBuffer);

          Status = IoCreateDevice(FdoExtension->DriverObject, sizeof(PDO_DEVICE_EXTENSION), &PdoName, 4, 0x100, 0, &Pdo);
          if (!NT_SUCCESS(Status))
          {
              continue;
          }
          RtlZeroMemory(Pdo->DeviceExtension, sizeof(PDO_DEVICE_EXTENSION));

          PdoExtension = Pdo->DeviceExtension;
          PdoExtension->SelfDevice = Pdo;
          PdoExtension->DriverObject = FdoExtension->DriverObject;
          PdoExtension->FdoExtension = FdoExtension;
          PdoExtension->PdoIndex = ix;
          PdoExtension->NoSupportIrp = NoSupportIrp;
          PdoExtension->PdoPnpDispatchTable = PdoPnpDispatchTable;
          PdoExtension->PdoPowerDispatchTable = PdoPowerDispatchTable;
          PdoExtension->PdoWmiDispatchTable = PdoWmiDispatchTable;
          KeInitializeSpinLock(&PdoExtension->SpinLock);
          FdoExtension->PdoExtension[ix] = PdoExtension;
          Pdo->Flags &= ~0x80;
          //FdoExtension->IdeXFdo006C++;//?
          InterlockedExchangeAdd((PLONG)&FdoExtension->NumberOfChildrenPowerUp, 1);
          Pdo->AlignmentRequirement = FdoExtension->ControllerProperties.AlignmentRequirement;
          if (Pdo->AlignmentRequirement < FdoExtension->LowDevice->AlignmentRequirement)
              Pdo->AlignmentRequirement = FdoExtension->SelfDevice->AlignmentRequirement;
          if (Pdo->AlignmentRequirement < 1)
              Pdo->AlignmentRequirement = 1;
        }

        if (Pdo)
        {
            DeviceRelations->Objects[DeviceRelations->Count] = Pdo;
            ObReferenceObjectByPointer(Pdo, 0, NULL, KernelMode);
            DeviceRelations->Count++;
        }
    }

Exit:

    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;
    Irp->IoStatus.Status = Status;

    if (!NT_SUCCESS(Status))
    {
        IoCompleteRequest(Irp, 0);
        return Status;
    }

    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
ControllerQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ControllerQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension = Fdo->DeviceExtension;
  
    DPRINT("ControllerQueryPnPDeviceState: QUERY_DEVICE_STATE for FDOE %p\n", FdoExtension);

    if (FdoExtension->Paging)
        Irp->IoStatus.Information |= 0x20;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
ControllerUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ControllerSurpriseRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PDO PNP FUNCTIONS ********************************************************/

PPDO_DEVICE_EXTENSION
NTAPI
ChannelGetPdoExtension(
    _In_ PDEVICE_OBJECT Pdo)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    KIRQL Irql;

    PdoExtension = Pdo->DeviceExtension;

    KeAcquireSpinLock(&PdoExtension->SpinLock, &Irql);

    if (PdoExtension->PdoState & 2 && PdoExtension->PdoState & 8)
        PdoExtension = NULL;

    KeReleaseSpinLock(&PdoExtension->SpinLock, Irql);

    return PdoExtension;
}

NTSTATUS
NTAPI
ChannelStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryStopRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
PciIdeXAlwaysStatusSuccessIrp(
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
PciIdeChannelQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryCapabitilies(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryText(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelFilterResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

PWCHAR
NTAPI
ChannelBuildDeviceId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    WCHAR IdBuffer[] = L"PCIIDE\\IDEChannel";
    ULONG IdLen;
    PWCHAR Id;

    PAGED_CODE();
    DPRINT("ChannelBuildDeviceId: %p\n", PdoExtension);

    IdLen = wcslen(IdBuffer);

    Id = ExAllocatePoolWithTag(PagedPool, ((IdLen + 1) * 2), 'XedI');
    if (Id)
        wcscpy(Id, IdBuffer);

    return Id;
}

PWCHAR
NTAPI
ChannelBuildHardwareId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PWCHAR
NTAPI
ChannelBuildCompatibleId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PWCHAR
NTAPI
ChannelBuildInstanceId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

NTSTATUS
NTAPI
ChannelQueryId(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    ULONG IdType;
    PWCHAR Id;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();
    DPRINT("ChannelQueryId: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryId: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    IdType = IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryId.IdType;

    if (IdType == 0)
    {
        Id = ChannelBuildDeviceId(PdoExtension);
    }
    else if (IdType == 1)
    {
        Id = ChannelBuildHardwareId(PdoExtension);
    }
    else if (IdType == 2)
    {
        Id = ChannelBuildCompatibleId(PdoExtension);
    }
    else if (IdType == 3)
    {
        Id = ChannelBuildInstanceId(PdoExtension);
    }
    else
    {
        DPRINT("ChannelQueryId: QueryID type %X not supported\n", IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryId.IdType);
        Status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (Id)
    {
        Irp->IoStatus.Information = (ULONG_PTR)Id;
        Status = STATUS_SUCCESS;
    }

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
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
DispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    PAGED_CODE();
    DPRINT("DispatchPnp: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        IsFdo = TRUE;
        DPRINT("DispatchPnp: FDO %d got '%s'\n", FdoExtension->FdoIndex, PnpMinorNames[MinorFunction]);
    }
    else
    {
        IsFdo = FALSE;
        PdoExtension = DeviceObject->DeviceExtension;
        DPRINT("DispatchPnp: PDO %d got '%s'\n", PdoExtension->PdoIndex, PnpMinorNames[MinorFunction]);
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            return PdoExtension->PdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
    }

    if (MinorFunction != 0xFF)
        ASSERT(!"ATAPI: PnP Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassToNextDriver(DeviceObject, Irp);
    else
        return PdoExtension->NoSupportIrp(DeviceObject, Irp);
}

/* FUNCTIONS ****************************************************************/

VOID
PciIdeXDebugPrint(
    _In_ ULONG DebugPrintLevel,
    _In_z_ _Printf_format_string_ PCCHAR DebugMessage,
    ...)
{
    va_list ap;
    UNIMPLEMENTED_DBGBREAK();
    va_end(ap);
}

NTSTATUS
NTAPI
PciIdeXGetBusData(
    _In_ PVOID MiniExtension,
    _Out_ PVOID Buffer,
    _In_ ULONG ConfigDataOffset,
    _In_ ULONG BufferLength)
{
    DPRINT("PciIdeXGetBusData(%p %p %X %X)\n", MiniExtension, Buffer, ConfigDataOffset, BufferLength);

    return PciIdeBusData((PFDO_DEVICE_EXTENSION)((ULONG_PTR)MiniExtension - sizeof(FDO_DEVICE_EXTENSION)),
                         Buffer,
                         ConfigDataOffset,
                         BufferLength,
                         TRUE);
}

NTSTATUS
NTAPI
PciIdeXSetBusData(
    _In_ PVOID DeviceExtension,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_reads_bytes_(BufferLength) PVOID DataMask,
    _In_ ULONG ConfigDataOffset,
    _In_ ULONG BufferLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS
NTAPI
PciIdeXInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PCONTROLLER_PROPERTIES HwGetControllerProperties,
    _In_ ULONG ExtensionSize)
{
    PPCIIDEX_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status;

    PAGED_CODE();

    DPRINT("PciIdeXInitialize: %p, '%wZ', %p, %X\n", DriverObject, RegistryPath, HwGetControllerProperties, ExtensionSize);

    Status = IoAllocateDriverObjectExtension(DriverObject, DriverEntry, sizeof(*DriverExtension), (PVOID*)&DriverExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeXInitialize: Status %X\n", Status);
        return Status;
    }

    RtlZeroMemory(DriverExtension, sizeof(*DriverExtension));

    DriverExtension->MiniControllerExtensionSize = ExtensionSize;
    DriverExtension->HwGetControllerProperties = HwGetControllerProperties;

    DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = DispatchWmi;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = PciIdeInternalDeviceIoControl;

    DriverObject->DriverExtension->AddDevice = ControllerAddDevice;
    DriverObject->DriverUnload = PciIdeUnload;

    IdeCreateIdeDirectory();

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PAGED_CODE();
    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);
    return STATUS_SUCCESS;
}
