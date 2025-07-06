/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         PCI IDE bus driver extension
 * FILE:            drivers/storage/pciidex/pciidex.c
 * PURPOSE:         Main file
 * PROGRAMMERS:     
 */

#include "pciidex.h"

#define NDEBUG
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
PWCHAR ChannelInternalCompatibleId[2] = {L"Primary_IDE_Channel", L"Secondary_IDE_Channel"};
WCHAR ChannelCompatibleId[] = {L"*PNP0600"};

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
            DPRINT("PciIdeXGetDeviceParameterEx: Status %X\n", Status);
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
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT1("PciIdeGetNativeModeInterface: %p\n", FdoExtension);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, FdoExtension->LowDevice, NULL, 0, NULL, &Event, &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PciIdeGetNativeModeInterface: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MinorFunction = IRP_MN_QUERY_INTERFACE;

    IoStack->Parameters.QueryInterface.Size = sizeof(PCI_NATIVE_IDE_INTERFACE);
    IoStack->Parameters.QueryInterface.Version = 1;
    IoStack->Parameters.QueryInterface.InterfaceType = &GUID_PCI_NATIVE_IDE_INTERFACE;
    IoStack->Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->PciNativeIdeInterface;
    IoStack->Parameters.QueryInterface.InterfaceSpecificData = 0;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    Status = IoCallDriver(FdoExtension->LowDevice, Irp);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeGetNativeModeInterface: Status %X\n", Status);
        return Status;
    }

    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    if (NT_SUCCESS(IoStatusBlock.Status))
    {
        ASSERT(FdoExtension->PciNativeIdeInterface.InterruptControl);
    }

    return IoStatusBlock.Status;
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
        DPRINT("ControllerAddDevice: Unable to get DeviceControlFlags from the registry\n");
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
ChannelInternalDeviceIoControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PCM_RESOURCE_LIST CmResources;
    PIO_STACK_LOCATION IoStack;
    ULONG IoCtl;
    ULONG Size;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelInternalDeviceIoControl: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelInternalDeviceIoControl: STATUS_NO_SUCH_DEVICE %p\n", Pdo);
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoCtl = IoStack->Parameters.DeviceIoControl.IoControlCode;

    if (IoCtl != 0x41414)
    {
        DPRINT1("ChannelInternalDeviceIoControl: Channel PDO got Unknown IoControlCode %X\n", IoCtl);
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    FdoExtension = PdoExtension->FdoExtension;
    Size = FdoExtension->ChannelResourceSize[PdoExtension->PdoIndex];

    CmResources = Irp->AssociatedIrp.SystemBuffer;
    ASSERT(CmResources);

    RtlCopyMemory(CmResources, FdoExtension->ChannelResources[PdoExtension->PdoIndex], Size);

    Irp->IoStatus.Information = Size;
    Status = STATUS_SUCCESS;

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
PciIdeInternalDeviceIoControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("PciIdeInternalDeviceIoControl: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;

    if (FdoExtension->LowDevice)
    {
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(Irp, 0);
        return STATUS_NOT_SUPPORTED;
    }

    return ChannelInternalDeviceIoControl(DeviceObject, Irp);
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

  #if DBG
    DPRINT1("DigestResourceList: %p\n", CmResources);
    RosDumpCmResources(CmResources, 0);
  #endif

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

            DPRINT("DigestResourceList: %X %X %X\n", Type, Start, Length);

            if ((Type == 1 || Type == 3) && Length == BaseIoAddress1Length && !IsFoundCmdBlockBase)
            {
                if (Start.QuadPart == 0x1F0)
                    IsFoundPrimary = TRUE;
                else if (Start.QuadPart == 0x170)
                    IsFoundSecond = TRUE;

                if (Type == 1)
                {
                    ResourceData->CmdBlockBase = (PUCHAR)Start.LowPart;
                    ResourceData->TypeResForCmdBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CmdBlockBase = MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);
                    ResourceData->TypeResForCmdBlock = 0;
                }
                else
                {
                    ASSERT(FALSE);
                    ResourceData->CmdBlockBase = NULL;
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
                    ResourceData->CtrlBlockBase = (PUCHAR)Start.LowPart;
                    ResourceData->TypeResForCtrlBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CtrlBlockBase = MmMapIoSpace(Start, 1, MmNonCached);
                    ResourceData->TypeResForCtrlBlock = 0;
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);
                    ResourceData->CtrlBlockBase = NULL;
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
                    ResourceData->CmdBlockBase = (PUCHAR)Start.LowPart;

                    ResourceData->TypeResForCtrlBlock = 1;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = (PUCHAR)Start.LowPart;
                }
                else if (Type == 3)
                {
                    ResourceData->TypeResForCmdBlock = 0;
                    ResourceData->CmdBlockBase = MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);

                    ResourceData->TypeResForCtrlBlock = 0;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = MmMapIoSpace(Start, 1, MmNonCached);
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);

                    ResourceData->CmdBlockBase = NULL;
                    ResourceData->CtrlBlockBase = NULL;
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
FdoChildReportPowerDown(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
FdoChildRequestPowerUp(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PciIdeSetPdoPowerState(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("PciIdeSetPdoPowerState: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("PciIdeSetPdoPowerState: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto ErrorExit;
    }

    Status = STATUS_SUCCESS;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type == SystemPowerState)
    {
        if (PdoExtension->SystemPowerState != IoStack->Parameters.Power.State.SystemState)
        {
            PdoExtension->SystemPowerState = IoStack->Parameters.Power.State.SystemState;
            DPRINT("PciIdeSetPdoPowerState: New Pdo %X system power state %X\n", PdoExtension->PdoIndex, IoStack->Parameters.Power.State.SystemState);
        }

        Irp->IoStatus.Information = IoStack->Parameters.Power.State.SystemState;
    }
    else if (IoStack->Parameters.Power.Type == DevicePowerState)
    {
        if (PdoExtension->DevicePowerState == IoStack->Parameters.Power.State.DeviceState)
        {
            Irp->IoStatus.Information = IoStack->Parameters.Power.State.SystemState;
        }
        else if (PdoExtension->DevicePowerState == 4)
        {
            IoMarkIrpPending(Irp);
            Irp->IoStatus.Information = IoStack->Parameters.Power.State.DeviceState;

            Status = FdoChildRequestPowerUp(PdoExtension->FdoExtension, PdoExtension, Irp);
            ASSERT(NT_SUCCESS(Status));

            return STATUS_PENDING;
        }
        else
        {
            if (PdoExtension->DevicePowerState == 1)
                PoSetPowerState(Pdo, DevicePowerState, IoStack->Parameters.Power.State);

            PdoExtension->DevicePowerState = IoStack->Parameters.Power.State.DeviceState;

            DPRINT("PciIdeSetPdoPowerState: New Pdo %X device power state %X\n", PdoExtension->PdoIndex, PdoExtension->DevicePowerState);

            if (PdoExtension->DevicePowerState == 4)
                FdoChildReportPowerDown(PdoExtension->FdoExtension, PdoExtension);

            Irp->IoStatus.Information = IoStack->Parameters.Power.State.SystemState;
        }
    }
    else
    {
        DPRINT1("PciIdeSetPdoPowerState: STATUS_NOT_IMPLEMENTED\n");
        ASSERT(FALSE);
        Status = STATUS_NOT_IMPLEMENTED;
    }

ErrorExit:

    Irp->IoStatus.Status = Status;

    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, 0);

    return Status;
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
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("StatusSuccessAndPassDownToNextDriver: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    return IoCallDriver(FdoExtension->LowDevice, Irp);
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
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Status = Irp->IoStatus.Status;

    if (IoStack->MajorFunction == IRP_MJ_POWER)
        PoStartNextPowerIrp(Irp);

    DPRINT("NoSupportIrp: DO %p failing unsupported Irp (%X, %X) with status %X\n",
           Pdo, IoStack->MajorFunction, IoStack->MinorFunction, Status);

    IoCompleteRequest(Irp, 0);

    return Status;
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
            if ((InDesc[ix].Type == 1 || InDesc[ix].Type == 3) && InDesc[jx].u.Generic.Length == 8 && CmdIdx < 2)
            {
                RtlCopyMemory((PdoDesc[CmdIdx] + PdoPartialList[CmdIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                PdoPartialList[CmdIdx]->Count++;
                CmdIdx++;
            }
            else if ((InDesc[ix].Type == 1 || InDesc[ix].Type == 3) && InDesc[jx].u.Generic.Length == 4 && CtrlIdx < 2)
            {
                RtlCopyMemory((PdoDesc[CtrlIdx] + PdoPartialList[CtrlIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                PdoPartialList[CtrlIdx]->Count++;
                CtrlIdx++;
            }
            else if ((InDesc[ix].Type == 1 || InDesc[ix].Type == 3) && InDesc[jx].u.Generic.Length == 0x10 && BusMaster < 1)
            {
                RtlCopyMemory(&BmDesc[BmFullDesc->PartialResourceList.Count], &InDesc[jx], sizeof(BmDesc[0]));
                BmFullDesc->PartialResourceList.Count++;
                BusMaster++;
            }
            else if (InDesc[jx].Type == 2 && IntIdx < 2)
            {
                RtlCopyMemory((PdoDesc[IntIdx] + PdoPartialList[IntIdx]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                PdoPartialList[IntIdx]->Count++;

                if (!IntIdx && FdoExtension->NativeMode[1])
                {
                    IntIdx = 1;
                    RtlCopyMemory((PdoDesc[1] + PdoPartialList[1]->Count), &InDesc[jx], sizeof(*PdoDesc[0]));
                    PdoPartialList[IntIdx]->Count++;
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
            DPRINT1("AnalyzeResourceList: [%X] %X, %X, %X\n", ix, CmdIdx, CtrlIdx, IntIdx);

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
                MmMapIoSpace(BmResources->List[0].PartialResourceList.PartialDescriptors[0].u.Memory.Start, 0x10, MmNonCached);

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

BOOLEAN
NTAPI
ControllerInterrupt(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID ServiceContext)
{
    PIDE_INTERRUPT_SERVICE_CONTEXT IsrContext = ServiceContext;
    PBUS_MASTER_IDE_REGISTERS BusMasterBase;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIDE_CMD_BLOCK_REGS CmdBlock;
    ULONG BmStatus;
    ULONG Channel;
    BOOLEAN Result = FALSE;

    FdoExtension = IsrContext->FdoExtension;
    Channel = IsrContext->Channel;

    DPRINT("ControllerInterrupt: ISR called for channel %X\n", Channel);

    if (FdoExtension->NativeInterruptEnabled)
    {
        if (!FdoExtension->ControllerIsrInstalled)
        {
            if (FdoExtension->PciNativeIdeInterface.InterruptControl)
                FdoExtension->PciNativeIdeInterface.InterruptControl(FdoExtension->PciNativeIdeInterface.StdInterface.Context, TRUE);
        }
    }
    else
    {
        if (!FdoExtension->ControllerIsrInstalled)
            return FALSE;

        if (FdoExtension->PciNativeIdeInterface.InterruptControl)
            FdoExtension->PciNativeIdeInterface.InterruptControl(FdoExtension->PciNativeIdeInterface.StdInterface.Context, TRUE);

        FdoExtension->NativeInterruptEnabled = TRUE;
    }

    ASSERT(FdoExtension->NativeInterruptEnabled);

    CmdBlock = &FdoExtension->CmdBlock[Channel];
    READ_PORT_UCHAR(CmdBlock->Status);

    if (!FdoExtension->BmMissing[Channel])
    {
        BusMasterBase = Add2Ptr(FdoExtension->TranslatedBusMasterBaseAddress, (Channel * 8)); // FIXME (split to 2?)
        BmStatus = READ_PORT_UCHAR(&BusMasterBase->StatusPrimary);

        DPRINT1("ControllerInterrupt: BmStatus %X\n", BmStatus);

        if (BmStatus & 4)
        {
            WRITE_PORT_UCHAR(&BusMasterBase->CommandPrimary, 0);
            WRITE_PORT_UCHAR(&BusMasterBase->StatusPrimary, 4);

            Result = TRUE;
        }
    }

    DPRINT1("ControllerInterrupt: ISR for %X returning %X\n", Channel, Result != FALSE);

    if (!FdoExtension->ControllerIsrInstalled)
    {
        if (FdoExtension->PciNativeIdeInterface.InterruptControl)
            FdoExtension->PciNativeIdeInterface.InterruptControl(FdoExtension->PciNativeIdeInterface.StdInterface.Context, FALSE);

        FdoExtension->NativeInterruptEnabled = FALSE;
    }

    return Result;
}

NTSTATUS
NTAPI
ControllerInterruptControl(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ULONG Channel,
    _In_ BOOLEAN IsDisconnectOrReconnect)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDesc;
    PIDE_INTERRUPT_SERVICE_CONTEXT ServiceContext;
    PKINTERRUPT* OutInterruptObject;
    NTSTATUS Status = STATUS_SUCCESS;

    if (IsDisconnectOrReconnect)
    {
        DPRINT1("ControllerInterruptControl: Interrupt control for %X (disconnect)\n", Channel);

        if (FdoExtension->InterruptObject[Channel])
        {
            IoDisconnectInterrupt(FdoExtension->InterruptObject[Channel]);
            FdoExtension->InterruptObject[Channel] = NULL;
        }

        return Status;
    }

    DPRINT1("ControllerInterruptControl: Interrupt control for %X (reconnect)\n", Channel);

    InterruptDesc = FdoExtension->InterruptDesc[Channel];
    if (!InterruptDesc)
    {
        DPRINT1("ControllerInterruptControl: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    ServiceContext = &FdoExtension->ServiceContext[Channel];
    ServiceContext->FdoExtension = FdoExtension;
    ServiceContext->Channel = Channel;

    OutInterruptObject = &FdoExtension->InterruptObject[Channel];

    Status = IoConnectInterrupt(OutInterruptObject,
                                ControllerInterrupt,
                                ServiceContext,
                                NULL,
                                InterruptDesc->u.Interrupt.Vector,
                                InterruptDesc->u.Interrupt.Level,
                                InterruptDesc->u.Interrupt.Level,
                                (InterruptDesc->Flags & 1),
                                (InterruptDesc->ShareDisposition == 3),
                                InterruptDesc->u.Interrupt.Affinity,
                                FALSE);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ControllerInterruptControl: Can't connect interrupt %X\n", InterruptDesc->u.Interrupt.Vector);
        *OutInterruptObject = NULL;
    }

    return Status;
}

NTSTATUS
NTAPI
ControllerStartDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PBUS_MASTER_IDE_REGISTERS BusMasterBase;
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

    if (FdoExtension->NativeMode[0] && FdoExtension->NativeMode[1] && FdoExtension->PciNativeIdeInterface.InterruptControl)
    {
        FdoExtension->PciNativeIdeInterface.InterruptControl(FdoExtension->PciNativeIdeInterface.StdInterface.Context, FALSE);
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
        DPRINT1("ControllerStartDevice: Starting native mode device (%p)\n", FdoExtension);

        FullList = CmResources->List;

        for (ix = 0; ix < CmResources->Count; ix++)
        {
            Descriptor = &FullList->PartialResourceList.PartialDescriptors[0];

            for (jx = 0; jx >= FullList->PartialResourceList.Count; jx++)
            {
                if (Descriptor[jx].Type == 1)
                {
                    DPRINT1("ControllerStartDevice: IO %X, %X\n",
                            Descriptor[jx].u.Port.Start.LowPart, Descriptor[jx].u.Port.Length);
                }
                else if (Descriptor[jx].Type == 2)
                {
                    DPRINT1("ControllerStartDevice: Int %X, %X\n",
                            Descriptor[jx].u.Interrupt.Level, Descriptor[jx].u.Interrupt.Vector);
                }
                else
                {
                    DPRINT1("ControllerStartDevice: Unknown resource\n");
                }
            }

            FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)&Descriptor[jx];
        }

        for (ix = 0; ix < 2; ix++)
        {
            Status = DigestResourceList(&FdoExtension->ResourceData,
                                        FdoExtension->ChannelResources[ix],
                                        &FdoExtension->InterruptDesc[ix]);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
                goto Exit;
            }

            if (!FdoExtension->InterruptDesc[ix])
            {
                DPRINT1("ControllerStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            DPRINT("ControllerStartDevice: Connecting interrupt for channel %X interrupt vector %X\n",
                   ix, FdoExtension->InterruptDesc[ix]->u.Interrupt.Vector);

            if (PciIdeChannelEnabled(FdoExtension, ix))
            {
                    AtapiBuildIoAddress(FdoExtension->ResourceData.CmdBlockBase,
                                        FdoExtension->ResourceData.CtrlBlockBase,
                                        &FdoExtension->CmdBlock[ix],
                                        &FdoExtension->CtrlBlock[ix],
                                        &FdoExtension->CmdBlockLength[ix],
                                        &FdoExtension->CtrlBlockLength[ix],
                                        &FdoExtension->MaxIdeDevice[ix],
                                        NULL);

                    Status = ControllerInterruptControl(FdoExtension, ix, FALSE);
                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
                        break;
                    }
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ControllerStartDevice: (%p, %p) Status %X\n", Fdo, Irp, Status);
            goto Exit;
        }

        FdoExtension->ControllerIsrInstalled = TRUE;

        if (FdoExtension->PciNativeIdeInterface.InterruptControl)
            FdoExtension->PciNativeIdeInterface.InterruptControl(FdoExtension->PciNativeIdeInterface.StdInterface.Context, TRUE);

        FdoExtension->NativeInterruptEnabled = TRUE;

        ASSERT(FdoExtension->ControllerIsrInstalled == TRUE);
        ASSERT(FdoExtension->NativeInterruptEnabled == TRUE);

        EnablePCIBusMastering(FdoExtension);

        BusMasterBase = (PBUS_MASTER_IDE_REGISTERS)FdoExtension->TranslatedBusMasterBaseAddress;

        if (READ_PORT_UCHAR(&BusMasterBase->StatusPrimary) & 0x18)
            FdoExtension->BmMissing[0] = TRUE;

        if (READ_PORT_UCHAR(&BusMasterBase->StatusSecondary) & 0x18)
            FdoExtension->BmMissing[1] = TRUE;
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
                        DPRINT("ControllerStartDevice: IO Port %X, Lenght %X\n",
                               Descriptor[kx].u.Port.Start.LowPart, Descriptor[kx].u.Port.Length);
                        break;

                    case 3:
                        DPRINT("ControllerStartDevice: Memory Port %X, Lenght %X\n",
                               Descriptor[kx].u.Memory.Start.LowPart, Descriptor[kx].u.Memory.Length);
                        break;

                    case 2:
                        DPRINT("ControllerStartDevice: Int Level %X, Int Vector %X\n",
                               Descriptor[kx].u.Interrupt.Level, Descriptor[kx].u.Interrupt.Vector);
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
        DPRINT("PciIdeChannelEnabled: Unable to get OnMaskStr from the registry\n");
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
    _In_ ULONG SetState,
    _In_ ULONG ResetState)
{
    KIRQL Lock;

    ASSERT(PdoExtension);

    KeAcquireSpinLock(&PdoExtension->SpinLock, &Lock);
    PdoExtension->PdoState |= SetState;
    PdoExtension->PdoState &= ~ResetState;
    KeReleaseSpinLock(&PdoExtension->SpinLock, Lock);
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
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    ULONG Dummy;
    NTSTATUS Status;
  
    PAGED_CODE();
    DPRINT("ControllerQueryInterface: %p, %p\n", Fdo, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    FdoExtension = Fdo->DeviceExtension;
    Status = Irp->IoStatus.Status;

    if (IsEqualGUID(&GUID_TRANSLATOR_INTERFACE_STANDARD, IoStack->Parameters.QueryInterface.InterfaceType))
    {
        if (IoStack->Parameters.QueryInterface.Size >= sizeof(TRANSLATOR_INTERFACE) &&
            IoStack->Parameters.QueryInterface.InterfaceSpecificData == ULongToPtr(2) &&
            !FdoExtension->NativeMode[0] && !FdoExtension->NativeMode[1])
        {
            Status = HalGetInterruptTranslator(5,
                                               0,
                                               0xFFFFFFFF,
                                               IoStack->Parameters.QueryInterface.Size,
                                               IoStack->Parameters.QueryInterface.Version,
                                               (PVOID)IoStack->Parameters.QueryInterface.Interface,
                                               &Dummy);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = Status;

    return IoCallDriver(FdoExtension->LowDevice, Irp);
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
BusMasterUninitialize(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    KIRQL Irql;

    ASSERT(PdoExtension->BmState == 0);//BmIdle

    if (!PdoExtension->DmaAdapter)
        return STATUS_SUCCESS;

    if (PdoExtension->PhysicalRegionDescriptorTable.QuadPart)
    {
        PdoExtension->DmaAdapter->DmaOperations->
            FreeCommonBuffer(PdoExtension->DmaAdapter,
                             (PdoExtension->MaximumPhysicalPages * sizeof(PHYSICAL_REGION_DESCRIPTOR)),
                             PdoExtension->PhysicalRegionDescriptorTable,
                             PdoExtension->RegionDescriptors,
                             FALSE);

        PdoExtension->RegionDescriptors = NULL;
        PdoExtension->PhysicalRegionDescriptorTable.QuadPart = 0;
    }

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    PdoExtension->DmaAdapter->DmaOperations->PutDmaAdapter(PdoExtension->DmaAdapter);
    KeLowerIrql(Irql);

    PdoExtension->DmaAdapter = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
BusMasterInitialize(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    DEVICE_DESCRIPTION DeviceDescription;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PDMA_ADAPTER DmaAdapter;
    ULONG IgnoreBusMasterStatusZeroBits;
    ULONG NumberOfMapRegisters;
    BOOLEAN IsNoBmBase = FALSE;
    UCHAR BmStatus;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("BusMasterInitialize: %p\n", PdoExtension);

    FdoExtension = PdoExtension->FdoExtension;

    if (!FdoExtension->TranslatedBusMasterBaseAddress)
    {
        DPRINT1("BusMasterInitialize: STATUS_INSUFFICIENT_RESOURCES\n");
        BusMasterUninitialize(PdoExtension);
        IsNoBmBase = TRUE;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    if (PdoExtension->PdoIndex == 0)
    {
        PdoExtension->BusMasterBase = (ULONG)FdoExtension->TranslatedBusMasterBaseAddress;
    }
    else if (PdoExtension->PdoIndex == 1)
    {
        PdoExtension->BusMasterBase = ((ULONG)FdoExtension->TranslatedBusMasterBaseAddress + 8);
    }
    else
    {
        ASSERT(FALSE);
    }

    BmStatus = READ_PORT_UCHAR((PUCHAR)(PdoExtension->BusMasterBase + 2));

    if (BmStatus & 0x18)
    {
        IgnoreBusMasterStatusZeroBits = 0;

        Status = PciIdeXGetDeviceParameter(FdoExtension->LowPdo, L"IgnoreBusMasterStatusZeroBits", &IgnoreBusMasterStatusZeroBits);
        if (!IgnoreBusMasterStatusZeroBits)
        {
            DPRINT1("BusMasterInitialize: bad busmaster status register value %X (%X). Will never do busmastering ide\n",
                    BmStatus, PdoExtension->BusMasterBase);

            PdoExtension->BusMasterBase = 0;
            IsNoBmBase = TRUE;
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        IsNoBmBase = FALSE;
        Status = STATUS_SUCCESS;
    }

    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("BusMasterInitialize: Status %X\n", Status);
        BusMasterUninitialize(PdoExtension);
        goto Exit;
    }

    RtlZeroMemory(&DeviceDescription, sizeof(DeviceDescription));

    DeviceDescription.Version = 0;
    DeviceDescription.Master = 1;
    DeviceDescription.ScatterGather = 1;
    DeviceDescription.DemandMode = 0;
    DeviceDescription.AutoInitialize = 0;
    DeviceDescription.Dma32BitAddresses = 1;
    DeviceDescription.IgnoreCount = 0;
    DeviceDescription.BusNumber = FdoExtension->BusMasterResources->List[0].BusNumber;
    DeviceDescription.InterfaceType = 5;
    DeviceDescription.MaximumLength = 0x20000;

    PdoExtension->DmaAdapter = DmaAdapter = IoGetDmaAdapter(FdoExtension->LowPdo, &DeviceDescription, &NumberOfMapRegisters);
    PdoExtension->MaximumPhysicalPages = NumberOfMapRegisters;

    if (!DmaAdapter)
    {
        DPRINT1("BusMasterInitialize: STATUS_INSUFFICIENT_RESOURCES\n");
        BusMasterUninitialize(PdoExtension);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    PdoExtension->RegionDescriptors =
        DmaAdapter->DmaOperations->AllocateCommonBuffer(DmaAdapter,
                                                        (NumberOfMapRegisters * sizeof(PHYSICAL_REGION_DESCRIPTOR)),
                                                        &PdoExtension->PhysicalRegionDescriptorTable,
                                                        FALSE);
    if (!PdoExtension->RegionDescriptors)
    {
        DPRINT1("BusMasterInitialize: STATUS_INSUFFICIENT_RESOURCES\n");
        BusMasterUninitialize(PdoExtension);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    ASSERT(PdoExtension->PhysicalRegionDescriptorTable.QuadPart);

    RtlZeroMemory(PdoExtension->RegionDescriptors, (NumberOfMapRegisters * sizeof(PHYSICAL_REGION_DESCRIPTOR)));

Exit:

    if (IsNoBmBase)
        Status = STATUS_SUCCESS;

    return Status;
}

NTSTATUS
NTAPI
PciIdeXSaveDeviceParameter(
    _In_ PVOID MiniExtension,
    _In_ PWSTR ValueName,
    _In_ ULONG ValueData)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    HANDLE DevInstRegKey;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeXSaveDeviceParameter: %p, '%S', %p\n", MiniExtension, ValueName, ValueData);

    FdoExtension = (PFDO_DEVICE_EXTENSION)((ULONG_PTR)MiniExtension - sizeof(FDO_DEVICE_EXTENSION));

    Status = IoOpenDeviceRegistryKey(FdoExtension->LowDevice, 2, KEY_WRITE, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PciIdeXSaveDeviceParameter: IoOpenDeviceRegistryKey() returns %X\n", Status);
        return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE, DevInstRegKey, ValueName, REG_DWORD, &ValueData, 4);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PciIdeXSaveDeviceParameter: RtlWriteRegistryValue() returns %X\n", Status);
    }

    ZwClose(DevInstRegKey);

    return Status;
}

NTSTATUS
NTAPI
IdePortpWaitOnBusyEx(
   _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
   _Out_ UCHAR* OutIdeStatus,
   _In_ UCHAR InStatus)
{
    UCHAR IdeStatus;
    ULONG ix;
    ULONG jx;

    for (ix = 0; ix < 2; )
    {
        jx = 0;

        while (TRUE)
        {
            IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);

            if (IdeStatus == InStatus || !(IdeStatus & 0x80))
            {
                ix = 2;
                break;
            }

            KeStallExecutionProcessor(5);

            jx++;
            if (jx < 200000)
                continue;

            if (!(IdeStatus & 0x80))
            {
                ix = 2;
                break;
            }

            DPRINT("ATAPI: after 1 sec wait, device is still busy with %X, status %X\n", CmdBlock->CmdBlockBase, IdeStatus);

            ix++;
            break;
        }
    }

    *OutIdeStatus = IdeStatus;

    if (!(IdeStatus & 0x80) || IdeStatus == InStatus)
        return STATUS_SUCCESS;

    DPRINT("WaitOnBusy failed. (%X) status %X\n", CmdBlock->CmdBlockBase, IdeStatus);

    return STATUS_UNSUCCESSFUL;
}

BOOLEAN
NTAPI
IdePortIdentifyDevice(
    _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
    _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
    _In_ ULONG MaxIdeDevice)
{
    ULONG Device = 0;
    ULONG ix = 4;
    ULONG jx;
    UCHAR status;
    BOOLEAN Result = TRUE;

    DPRINT("IdePortIdentifyDevice: %X, %X, %X\n", CmdBlock->CmdBlockBase, CtrlBlock->CtrlBlockBase, MaxIdeDevice);

    while (TRUE)
    {
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
        WRITE_PORT_UCHAR(CmdBlock->BytesHigh, 0xAA);
        WRITE_PORT_UCHAR(CmdBlock->BytesLow, 0x55);

        if (READ_PORT_UCHAR(CmdBlock->LbaHigh) == 0xAA && READ_PORT_UCHAR(CmdBlock->LbaMid) == 0x55)
        {
            DPRINT("IdePortIdentifyDevice: Result = 0\n");
            Result = FALSE;
        }
        else
        {
            status = READ_PORT_UCHAR(CmdBlock->Status);

            DPRINT("IdePortIdentifyDevice: status read back from Master (%X)\n", status);

            if (status & 0x80)
            {
                for (jx = 0; jx < 0xA; jx++)
                {
                    KeStallExecutionProcessor(1000);
                    status = READ_PORT_UCHAR(CmdBlock->Status);

                    DPRINT("IdePortIdentifyDevice: First access to status %X\n", status);

                    if (!(status & 0x80))
                        break;
                }

                ix--;
                if (ix != 0 && !(status & 0x80))
                    continue;
            }

            Device++;

            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
            WRITE_PORT_UCHAR(CmdBlock->BytesHigh, 0xAA);
            WRITE_PORT_UCHAR(CmdBlock->BytesLow, 0x55);

            if (READ_PORT_UCHAR(CmdBlock->LbaHigh) != 0xAA || READ_PORT_UCHAR(CmdBlock->LbaMid) != 0x55)
            {
                status = READ_PORT_UCHAR(CmdBlock->Status);
                DPRINT("IdePortIdentifyDevice: status read back from Slave (%X)\n", status);
            }
            else
            {
                DPRINT("IdePortIdentifyDevice: Result = 0\n");
                Result = FALSE;
            }
        }

        Device++;
        if (Device >= MaxIdeDevice || !Result)
            return Result;
    }
}

BOOLEAN
NTAPI
IdePortChannelEmpty(
   _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
   _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
   _In_ ULONG MaxIdeDevice)
{
    ULONG ix;
    UCHAR IdeStatus;
    BOOLEAN IsDoIdentifyDevice = FALSE;

    DPRINT("IdePortChannelEmpty: %X\n", CmdBlock->CmdBlockBase, MaxIdeDevice);

    if (!MaxIdeDevice)
        return TRUE;

    for (ix = 0; ix < MaxIdeDevice; ix++)
    {
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((ix & 0x1) << 4) | IDE_DRIVE_SELECT));
        IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);

        if (IdeStatus == 0xFF || IdeStatus == 0xFE)
            continue;

        IdePortpWaitOnBusyEx(CmdBlock, &IdeStatus, 0xFF);

        if ((IdeStatus & 0x80) && IdeStatus != 0xFE)
        {
            if (IdeStatus == 0xFF)
                continue;

            DPRINT("IdePortChannelEmpty: Channel looks busy %X. Try a reset\n", IdeStatus);

            WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 4);
            KeStallExecutionProcessor(10);
            WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 0);

            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((ix & 0x1) << 4) | IDE_DRIVE_SELECT));
            IdePortpWaitOnBusyEx(CmdBlock, &IdeStatus, 0xFF);
        }

        if (IdeStatus != 0xFF)
            IsDoIdentifyDevice = TRUE;
    }

    if (IsDoIdentifyDevice)
        return IdePortIdentifyDevice(CmdBlock, CtrlBlock, MaxIdeDevice);

    return TRUE;
}

NTSTATUS
NTAPI
ChannelStartDevice(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR IntCmDescriptor;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PVOID MiniExtension;
    IDE_RESOURCE_DATA ResourceData;
    IDE_CMD_BLOCK_REGS CmdBlock;
    IDE_CTRL_BLOCK_REGS CtrlBlock;
    ULONG CmdBlockLength;
    ULONG CtrlBlockLength;
    ULONG MaxIdeDevice;
    USHORT Parameter;
    USHORT VendorId;
    USHORT DeviceId;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelStartDevice: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelStartDevice: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    FdoExtension = PdoExtension->FdoExtension;

    if (!FdoExtension->NativeMode[PdoExtension->PdoIndex] &&
        PciIdeChannelEnabled(FdoExtension, PdoExtension->PdoIndex) == 2)
    {
        Status = DigestResourceList(&ResourceData,
                                    IoGetCurrentIrpStackLocation(Irp)->Parameters.StartDevice.AllocatedResourcesTranslated,
                                    &IntCmDescriptor);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartDevice: Status %X\n", Status);
            PdoExtension->IsChannelEmpty = 0;
            goto Exit;
        }

        AtapiBuildIoAddress(ResourceData.CmdBlockBase,
                            ResourceData.CtrlBlockBase,
                            &CmdBlock,
                            &CtrlBlock,
                            &CmdBlockLength,
                            &CtrlBlockLength,
                            &MaxIdeDevice,
                            NULL);

        if (!ResourceData.TypeResForCmdBlock && ResourceData.CmdBlockBase)
            MmUnmapIoSpace(ResourceData.CmdBlockBase, CmdBlockLength);

        if (!ResourceData.TypeResForCtrlBlock && ResourceData.CtrlBlockBase)
            MmUnmapIoSpace(ResourceData.CtrlBlockBase, CtrlBlockLength);

        if (IdePortChannelEmpty(&CmdBlock, &CtrlBlock, MaxIdeDevice))
        {
            PdoExtension->IsChannelEmpty = 1;

            if (IntCmDescriptor)
            {
                PdoExtension->PnPDeviceState |= 0x14;
                IoInvalidateDeviceState(Pdo);
            }
        }
        else
        {
            PdoExtension->IsChannelEmpty = 0;
        }
    }

    PdoExtension->DmaDetectionLevel = 1;
    PciIdeXGetDeviceParameter(PdoExtension->SelfDevice, L"DmaDetectionLevel", &PdoExtension->DmaDetectionLevel);

    Status = BusMasterInitialize(PdoExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: Status %X\n", Status);
        goto Exit;
    }

    if (PdoExtension->BusMasterBase)
        PdoExtension->BmStatus = READ_PORT_UCHAR((PUCHAR)(PdoExtension->BusMasterBase + 2));

    ChannelUpdatePdoState(PdoExtension, 1, 0xE);

    MiniExtension = PdoExtension->FdoExtension->MiniControllerExtension;

    VendorId = 0;
    DeviceId = 0;

    PciIdeXGetBusData(MiniExtension, &VendorId, 0, 2);
    PciIdeXGetBusData(MiniExtension, &DeviceId, 2, 2);

    if (VendorId == 0x8086)
    {
        Parameter = 0;
        PciIdeXGetBusData(MiniExtension, &Parameter, 0x40, 2);
        PciIdeXSaveDeviceParameter(MiniExtension, L"Old IDETIM0", Parameter);

        Parameter = 0;
        PciIdeXGetBusData(MiniExtension, &Parameter, 0x42, 2);
        PciIdeXSaveDeviceParameter(MiniExtension, L"Old IDETIM1", Parameter);

        if (DeviceId != 0x1230)
        {
            Parameter = 0;
            PciIdeXGetBusData(MiniExtension, &Parameter, 0x44, 1);
            PciIdeXSaveDeviceParameter(MiniExtension, L"Old SIDETIM", Parameter);
        }

        if (DeviceId == 0x7111)
        {
            Parameter = 0;
            PciIdeXGetBusData(MiniExtension, &Parameter, 0x48, 1);
            PciIdeXSaveDeviceParameter(MiniExtension, L"Old SDMACTL", Parameter);

            Parameter = 0;
            PciIdeXGetBusData(MiniExtension, &Parameter, 0x4A, 1);
            PciIdeXSaveDeviceParameter(MiniExtension, L"Old SDMATIM0", Parameter);

            Parameter = 0;
            PciIdeXGetBusData(MiniExtension, &Parameter, 0x4B, 1);
            PciIdeXSaveDeviceParameter(MiniExtension, L"Old SDMATIM1", Parameter);
        }
    }

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
ChannelQueryStopRemoveDevice(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ChannelQueryStopRemoveDevice: %p\n", Pdo);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryStopRemoveDevice: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Finish;
    }

    if (PdoExtension->Paging)
    {
        DPRINT1("ChannelQueryStopRemoveDevice: STATUS_UNSUCCESSFUL\n");
        Status = STATUS_UNSUCCESSFUL;
        goto Finish;
    }

    if (PdoExtension->DumpFile)
    {
        DPRINT1("ChannelQueryStopRemoveDevice: STATUS_UNSUCCESSFUL\n");
        Status = STATUS_UNSUCCESSFUL;
    }

Finish:

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
PciIdeXAlwaysStatusSuccessIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ChannelStopChannel(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = BusMasterUninitialize(PdoExtension);
    ASSERT(NT_SUCCESS(Status));

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ChannelStopDevice(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelStopDevice: %p\n", Pdo);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelStopDevice: STATUS_NO_SUCH_DEVICE (%p)\n", Pdo);
        Status = STATUS_NO_SUCH_DEVICE;
        goto Finish;
    }

    Status = ChannelStopChannel(PdoExtension);
    ASSERT(NT_SUCCESS(Status));

    ChannelUpdatePdoState(PdoExtension, 4, 1);
    Status = STATUS_SUCCESS;

Finish:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelQueryDeviceRelations(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryDeviceRelations: %p\n", Pdo);

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceRelations.Type != 4)
        goto Finish;

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;

Finish:

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

VOID
NTAPI
BmRebuildScatterGatherList(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PSCATTER_GATHER_LIST ScatterGather)
{
    PSCATTER_GATHER_ELEMENT SgElements;
    ULONG Address;
    ULONG ElementSize;
    ULONG Size;
    ULONG ix;
    ULONG jx = 0;

    ASSERT(ScatterGather);
    ASSERT(PdoExtension);
    ASSERT(PdoExtension->TransferLength);
    ASSERT(PdoExtension->Mdl);

    DPRINT("BmRebuildScatterGatherList: %X, %X, %X\n",
           PdoExtension->TransferDataBuffer, PdoExtension->TransferLength, ScatterGather->NumberOfElements);

    PdoExtension->ScatterGather = ScatterGather;

    for (ix = 0; ix < ScatterGather->NumberOfElements; ix++)
    {
        SgElements = &ScatterGather->Elements[ix];
        Address = SgElements->Address.LowPart;

        ASSERT(!(Address & 0x1));
        ASSERT(!SgElements->Address.HighPart);

        for (ElementSize = SgElements->Length; ElementSize; jx++)
        {
            ASSERT(jx < PdoExtension->MaximumPhysicalPages);

            PdoExtension->RegionDescriptors[jx].Prd[0].BaseAddress = Address;

            Size = (0x10000 - (USHORT)Address);

            if (Size < ElementSize)
            {
                PdoExtension->RegionDescriptors[jx].Prd[0].ByteCount = Size;
                Address += Size;
                ElementSize -= Size;
            }
            else if (ElementSize <= 0x10000)
            {
                PdoExtension->RegionDescriptors[jx].Prd[0].ByteCount = (ElementSize & 0xFFFE);
                Address += (ElementSize & 0xFFFE);
                ElementSize = 0;
            }
            else
            {
                PdoExtension->RegionDescriptors[jx].Prd[0].ByteCount = 0;
                Address += 0x10000;
                ElementSize -= 0x10000;
            }

            PdoExtension->RegionDescriptors[jx].Prd[0].EndTable = 0;
        }
    }

    PdoExtension->RegionDescriptors[jx - 1].Prd[0].EndTable = 1;
}

VOID
NTAPI
BmPrepareController(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PUCHAR BmBase;

    BmBase = (PUCHAR)PdoExtension->BusMasterBase;
    DPRINT("BmPrepareController: (%X) %I64X\n", BmBase, PdoExtension->PhysicalRegionDescriptorTable.QuadPart);

    WRITE_PORT_UCHAR((BmBase + 0), 0);
    WRITE_PORT_UCHAR((BmBase + 2), 6);
    WRITE_PORT_ULONG((PULONG)(BmBase + 4), PdoExtension->PhysicalRegionDescriptorTable.LowPart);

    PdoExtension->BmState = 1;
}

VOID
NTAPI
BmReceiveScatterGatherList(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PSCATTER_GATHER_LIST ScatterGather,
    _In_ PVOID Context)
{
    PPDO_DEVICE_EXTENSION PdoExtension = Context;
    VOID (NTAPI* BmCallback)(PVOID Context);

    DPRINT("BmReceiveScatterGatherList: %p\n", ScatterGather);

    ASSERT(PdoExtension);

    BmRebuildScatterGatherList(PdoExtension, ScatterGather);
    BmPrepareController(PdoExtension);

    BmCallback = PdoExtension->BmCallback;
    BmCallback(PdoExtension->BmCallbackContext);
}

NTSTATUS
NTAPI
BmSetup(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID DataBuffer,
    _In_ ULONG Length,
    _In_ PMDL Mdl,
    _In_ UCHAR DataInFlag,
    _In_ PVOID Callback,
    _In_ PVOID Context)
{
    DPRINT("BmSetup: (%X) %X %X %X %X\n", PdoExtension->BusMasterBase, DataBuffer, Length, Mdl, DataInFlag);

    ASSERT(PdoExtension->BmState == 0);//BmIdle

    PdoExtension->DataInFlag = DataInFlag;
    PdoExtension->Mdl = Mdl;
    PdoExtension->BmCallback = Callback;
    PdoExtension->BmCallbackContext = Context;
    PdoExtension->TransferDataBuffer = DataBuffer;
    PdoExtension->TransferLength = Length;

    return PdoExtension->DmaAdapter->DmaOperations->GetScatterGatherList(PdoExtension->DmaAdapter,
                                                                         PdoExtension->SelfDevice,
                                                                         Mdl,
                                                                         DataBuffer,
                                                                         Length,
                                                                         BmReceiveScatterGatherList,
                                                                         PdoExtension,
                                                                         (DataInFlag == 0));
}

VOID
NTAPI
BmArm(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    ASSERT((PdoExtension->BmState == 1) || (PdoExtension->BmState == 3));//BmSet BmDisarmed

    if (PdoExtension->DataInFlag)
        WRITE_PORT_UCHAR((PUCHAR)PdoExtension->BusMasterBase, 9);
    else
        WRITE_PORT_UCHAR((PUCHAR)PdoExtension->BusMasterBase, 1);

    PdoExtension->BmState = 2;

    DPRINT("BmArm()\n");
}

ULONG
NTAPI
BmDisarm(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    ULONG bmStatus;

    bmStatus = BmStatus(PdoExtension);

    WRITE_PORT_UCHAR((PUCHAR)(PdoExtension->BusMasterBase + 0), 0);
    WRITE_PORT_UCHAR((PUCHAR)(PdoExtension->BusMasterBase + 2), 4);

    if (PdoExtension->BmState)
        PdoExtension->BmState = 3;

    if (bmStatus)
    {
        DPRINT("BmDisarm: BM %X status %X\n", PdoExtension->BusMasterBase, bmStatus);
    }

    return bmStatus;
}

NTSTATUS
NTAPI
BmFlush(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    ASSERT(PdoExtension->BmState != 2);//BmArmed

    PdoExtension->DmaAdapter->DmaOperations->PutScatterGatherList(PdoExtension->DmaAdapter,
                                                                  PdoExtension->ScatterGather,
                                                                  (PdoExtension->DataInFlag == 0));
    PdoExtension->ScatterGather = NULL;
    PdoExtension->TransferDataBuffer = NULL;
    PdoExtension->TransferLength = 0;
    PdoExtension->Mdl = NULL;
    PdoExtension->BmState = 0;

    DPRINT("BmFlush()\n");

    return STATUS_SUCCESS;
}

ULONG
NTAPI
BmStatus(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    ULONG RetStatus;
    UCHAR status;

    status = READ_PORT_UCHAR(((PUCHAR)PdoExtension->BusMasterBase + 2));
    if (status == 0xFF)
    {
        return 0;
    }

    RetStatus = 0;

    if (status & 1)
        RetStatus = 1;

    if (status & 2)
        RetStatus |= 2;

    if (status & 4)
        RetStatus |= 4;

    return RetStatus;
}

NTSTATUS
NTAPI
BmTimingSetup(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
BmSetupOnePage(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID DataBuffer,
    _In_ ULONG ByteCount,
    _In_ PMDL Mdl,
    _In_ UCHAR DataInFlag,
    _In_ PVOID BaseAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
BmCrashDumpInitialize(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
BmFlushAdapterBuffers(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID DataBuffer,
    _In_ ULONG ByteCount,
    _In_ PMDL Mdl,
    _In_ UCHAR DataInFlag)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
BmQueryInterface(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _Out_ PVOID OutInterface)
{
    PPCIIDE_BUS_MASTER_INTERFACE Interface = OutInterface;
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("BmQueryInterface: %p\n", PdoExtension);

    if (!PdoExtension->BusMasterBase)
    {
        DPRINT1("BmQueryInterface: STATUS_NOT_IMPLEMENTED\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    FdoExtension = PdoExtension->FdoExtension;

    Interface->Size = sizeof(PCIIDE_BUS_MASTER_INTERFACE);
    Interface->SupportedTransferMode[0] = FdoExtension->ControllerProperties.SupportedTransferMode[PdoExtension->PdoIndex][0];
    Interface->SupportedTransferMode[1] = FdoExtension->ControllerProperties.SupportedTransferMode[PdoExtension->PdoIndex][1];
    Interface->MaximumPhysicalSize = (PdoExtension->MaximumPhysicalPages * PAGE_SIZE);
    Interface->Context = PdoExtension;
    Interface->ContextSize = sizeof(*PdoExtension);
    Interface->BmSetup = BmSetup;
    Interface->BmArm = BmArm;
    Interface->BmDisarm = BmDisarm;
    Interface->BmFlush = BmFlush;
    Interface->BmStatus = BmStatus;
    Interface->BmTimingSetup = BmTimingSetup;
    Interface->BmSetupOnePage = BmSetupOnePage;
    Interface->BmCrashDumpInitialize = BmCrashDumpInitialize;
    Interface->BmFlushAdapterBuffers = BmFlushAdapterBuffers;
    Interface->IgnoreActiveBitForAtaDevice = FdoExtension->ControllerProperties.IgnoreActiveBitForAtaDevice;

    if (FdoExtension->ControllerProperties.AlwaysClearBusMasterInterrupt ||
        (FdoExtension->NativeMode[0] && FdoExtension->NativeMode[1]))
    {
        Interface->AlwaysClearBusMasterInterrupt = TRUE;
    }
    else
    {
        Interface->AlwaysClearBusMasterInterrupt = FALSE;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
PciIdeAllocateAccessToken(
    _In_ PVOID Token,
    _In_ PDRIVER_CONTROL ExecutionRoutine,
    _In_ PVOID Context)
{
    PPDO_DEVICE_EXTENSION PdoExtension = Token;
    PFDO_DEVICE_EXTENSION FdoExtension;

    ASSERT(Token);
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    FdoExtension = PdoExtension->FdoExtension;

    IoAllocateController(FdoExtension->ControllerObject, PdoExtension->SelfDevice, ExecutionRoutine, Context);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciIdeFreeAccessToken(
    _In_ PVOID Token)
{
    PPDO_DEVICE_EXTENSION PdoExtension = Token;

    IoFreeController(PdoExtension->FdoExtension->ControllerObject);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciIdeQuerySyncAccessInterface(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _Out_ PVOID OutInterface)
{
    PIDE_SYNC_ACCESS_INTERFACE Interface = OutInterface;

    PAGED_CODE();
    DPRINT("PciIdeQuerySyncAccessInterface: %p\n", PdoExtension);

    if (!Interface)
    {
        DPRINT1("PciIdeQuerySyncAccessInterface: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (PdoExtension->FdoExtension->ControllerObject)
    {
        Interface->AllocateAccessToken = PciIdeAllocateAccessToken;
        Interface->FreeAccessToken = PciIdeFreeAccessToken;
        Interface->Context = PdoExtension;
    }
    else
    {
        Interface->AllocateAccessToken = NULL;
        Interface->FreeAccessToken = NULL;
        Interface->Context = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciIdeChannelTransferModeSelect(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PPCIIDE_TRANSFER_MODE_SELECT XferMode)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    ULONG ix;
    UCHAR RawStatus;
    NTSTATUS Status;

    DPRINT("PciIdeChannelTransferModeSelect: %p\n", PdoExtension);

    if (PdoExtension->DmaDetectionLevel == 0)
    {
        RawStatus = 0;

        for (ix = 0; ix < 4; ix++)
        {
            XferMode->DeviceTransferModeSupported[ix] &= 0x1F;
            XferMode->DeviceTransferModeCurrent[ix] &= 0x1F;
        }
    }
    else if (PdoExtension->DmaDetectionLevel == 1)
    {
        if (PdoExtension->BusMasterBase)
            RawStatus = PdoExtension->BmStatus;
    }
    else if (PdoExtension->DmaDetectionLevel == 2)
    {
        RawStatus = (PdoExtension->BusMasterBase == 0 ? 0 : 0x60);
    }
    else
    {
        RawStatus = 0;
    }

    Status = STATUS_UNSUCCESSFUL;
    FdoExtension = PdoExtension->FdoExtension;

    if (PdoExtension->DmaDetectionLevel != 0)
    {
        XferMode->Channel = PdoExtension->PdoIndex;
        XferMode->EnableUDMA66 = PdoExtension->FdoExtension->EnableUDMA66;

        if (FdoExtension->ControllerProperties.PciIdeTransferModeSelect)
            Status = FdoExtension->ControllerProperties.PciIdeTransferModeSelect(FdoExtension->MiniControllerExtension, XferMode);
    }

    DPRINT("PciIdeChannelTransferModeSelect: RawStatus=%x, current[0]=%x, current[1]=%x\n",
           RawStatus, XferMode->DeviceTransferModeCurrent[0], XferMode->DeviceTransferModeCurrent[1]);

    if (NT_SUCCESS(Status))
        return Status;

    Status = STATUS_SUCCESS;

    XferMode->DeviceTransferModeSelected[0] = XferMode->DeviceTransferModeCurrent[0];

    if (!(RawStatus & 0x20))
        XferMode->DeviceTransferModeSelected[0] &= 0x1F;

    XferMode->DeviceTransferModeSelected[1] = XferMode->DeviceTransferModeCurrent[1];

    if (!(RawStatus & 0x40))
        XferMode->DeviceTransferModeSelected[1] &= 0x1F;

    for (ix = 0; ix < 2; ix++)
    {
        DPRINT("PciIdeChannelTransferModeSelect: xfermode[%d]=%x\n",
               ix, PdoExtension->FdoExtension->ControllerProperties.SupportedTransferMode[PdoExtension->PdoIndex][ix]);

        if (FdoExtension->ControllerProperties.DefaultPIO != 1 || (XferMode->UserChoiceTransferMode[ix] & 0x80000000))
            XferMode->DeviceTransferModeSelected[ix] &= FdoExtension->ControllerProperties.SupportedTransferMode[PdoExtension->PdoIndex][ix];
        else
            XferMode->DeviceTransferModeSelected[ix] &= 0x1F;
    }

    return Status;
}

NTSTATUS
NTAPI
PciIdeChannelTransferModeInterface(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _Out_ PVOID OutInterface)
{
    IDE_TRANSFER_MODE_INTERFACE* Interface = OutInterface;

    DPRINT("PciIdeChannelTransferModeInterface: %p\n", PdoExtension);

    Interface->TransferModeSelect = PciIdeChannelTransferModeSelect;
    Interface->TransferModeTimingTable = PdoExtension->FdoExtension->TimingTable;
    Interface->TableLength = PdoExtension->FdoExtension->TimingTableLength;
    Interface->Context = PdoExtension;
    Interface->MiniControllerExtension = PdoExtension->FdoExtension->MiniControllerExtension;
    Interface->PciIdeUdmaModesSupported = PdoExtension->FdoExtension->ControllerProperties.PciIdeUdmaModesSupported;
    Interface->PciIdeUseDma = PdoExtension->FdoExtension->ControllerProperties.PciIdeUseDma;
    Interface->IsTransferModeSelect = (PdoExtension->FdoExtension->ControllerProperties.PciIdeTransferModeSelect != NULL);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciIdeInterruptControl(
    _In_ PPDO_DEVICE_EXTENSION Context,
    _In_ BOOLEAN IsDisconnectOrReconnect)
{
    return ControllerInterruptControl(Context->FdoExtension, Context->PdoIndex, IsDisconnectOrReconnect);
}

NTSTATUS
NTAPI
PciIdeChannelInterruptInterface(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _Out_ PVOID OutInterface)
{
    PPCIIDE_INTERRUPT_INTERFACE InterruptIface = OutInterface;
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("PciIdeChannelInterruptInterface: %p\n", PdoExtension);

    FdoExtension = PdoExtension->FdoExtension;

    if (FdoExtension->NativeMode[0] && FdoExtension->NativeMode[1])
    {
        InterruptIface->Context = PdoExtension;
        InterruptIface->InterruptControl = PciIdeInterruptControl;

        DPRINT("PciIdeChannelInterruptInterface: returing interrupt interface for channel %X\n", PdoExtension->PdoIndex);
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
PciIdeChannelRequestProperResources(
    _In_ PDEVICE_OBJECT PhysicalDeviceObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PciIdeChannelQueryInterface(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    UNICODE_STRING GuidString;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIdeChannelQueryInterface: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("PciIdeChannelQueryInterface: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Status = Irp->IoStatus.Status;

    if (IsEqualGUID(&GUID_PCIIDE_BUSMASTER_INTERFACE, IoStack->Parameters.QueryInterface.InterfaceType) &&
        IoStack->Parameters.QueryInterface.Size >= sizeof(PCIIDE_BUS_MASTER_INTERFACE))
    {
        Status = BmQueryInterface(PdoExtension, IoStack->Parameters.QueryInterface.Interface);
    }
    else if (IsEqualGUID(&GUID_PCIIDE_SYNC_ACCESS_INTERFACE, IoStack->Parameters.QueryInterface.InterfaceType) &&
             IoStack->Parameters.QueryInterface.Size >= sizeof(IDE_SYNC_ACCESS_INTERFACE))
    {
        Status = PciIdeQuerySyncAccessInterface(PdoExtension, IoStack->Parameters.QueryInterface.Interface);
    }
    else if (IsEqualGUID(&GUID_PCIIDE_XFER_MODE_INTERFACE, IoStack->Parameters.QueryInterface.InterfaceType) &&
             IoStack->Parameters.QueryInterface.Size >= sizeof(IDE_TRANSFER_MODE_INTERFACE))
    {
        Status = PciIdeChannelTransferModeInterface(PdoExtension, IoStack->Parameters.QueryInterface.Interface);
    }
    else if (IsEqualGUID(&GUID_PCIIDE_INTERRUPT_INTERFACE, IoStack->Parameters.QueryInterface.InterfaceType) &&
             IoStack->Parameters.QueryInterface.Size >= sizeof(PCIIDE_INTERRUPT_INTERFACE))
    {
        Status = PciIdeChannelInterruptInterface(PdoExtension, IoStack->Parameters.QueryInterface.Interface);
    }
    else if (IsEqualGUID(&GUID_PCIIDE_REQUEST_PROPER_RESOURCES, IoStack->Parameters.QueryInterface.InterfaceType) &&
             IoStack->Parameters.QueryInterface.Size >= sizeof(PCIIDE_PROPER_RESOURCES))
    {
        ((PPCIIDE_PROPER_RESOURCES)IoStack->Parameters.QueryInterface.Interface)->ChannelRequestProperResources =
            PciIdeChannelRequestProperResources;

        Status = STATUS_SUCCESS;
    }
    else
    {
        Status = RtlStringFromGUID(IoStack->Parameters.QueryInterface.InterfaceType, &GuidString);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciIdeChannelQueryInterface: RtlStringFromGUID() failed\n", &GuidString);
        }

        DPRINT1("PciIdeChannelQueryInterface: unsupported '%wZ'\n", Pdo, &GuidString);

        RtlFreeUnicodeString(&GuidString);
        Status = Irp->IoStatus.Status;
    }

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
IdeGetDeviceCapabilities(
    _In_ PDEVICE_OBJECT ControllerPdo,
    _In_ PDEVICE_CAPABILITIES Capabilities)
{
    IO_STATUS_BLOCK ioStatusBlock;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_OBJECT AttachedDo;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdeGetDeviceCapabilities: %p, %p\n", ControllerPdo, Capabilities);

    RtlZeroMemory(Capabilities, sizeof(*Capabilities));

    Capabilities->Size = sizeof(*Capabilities);
    Capabilities->Version = 1;
    Capabilities->Address = 0xFFFFFFFF;
    Capabilities->UINumber = 0xFFFFFFFF;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    AttachedDo = IoGetAttachedDeviceReference(ControllerPdo);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDo, NULL, 0, NULL, &Event, &ioStatusBlock);
    if (!Irp)
    {
        DPRINT1("IdeGetDeviceCapabilities: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;

    IoStack = IoGetNextIrpStackLocation(Irp);
    if (!IoStack)
    {
        DPRINT1("IdeGetDeviceCapabilities: STATUS_INVALID_PARAMETER\n");
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    RtlZeroMemory(IoStack, sizeof(*IoStack));

    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;

    IoStack->Parameters.DeviceCapabilities.Capabilities = Capabilities;

    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    Status = IoCallDriver(AttachedDo, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = ioStatusBlock.Status;
    }

Exit:

    ObDereferenceObject(AttachedDo);
    return Status;
}

NTSTATUS
NTAPI
ChannelQueryCapabitilies(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_CAPABILITIES Capabilities;
    DEVICE_CAPABILITIES capabilities;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryCapabitilies: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryCapabitilies: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    Status = IdeGetDeviceCapabilities(PdoExtension->FdoExtension->LowPdo, &capabilities);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelQueryCapabitilies: Status %X\n", Status);
        goto Exit;
    }

    Capabilities = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceCapabilities.Capabilities;

    RtlCopyMemory(Capabilities, &capabilities, sizeof(*Capabilities));

    Capabilities->Address = PdoExtension->PdoIndex;
    Capabilities->UniqueID = FALSE;

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelQueryResources(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PCM_RESOURCE_LIST CmResource = NULL;
    ULONG Channel;
    ULONG Count;
    ULONG Size;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryResources: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryResources: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    FdoExtension = PdoExtension->FdoExtension;
    Channel = PdoExtension->PdoIndex;

    if (FdoExtension->NativeMode[Channel] || !PciIdeChannelEnabled(FdoExtension, Channel))
    {
        CmResource = NULL;
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    Size = (sizeof(CM_RESOURCE_LIST) + (2 * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)));

    CmResource = ExAllocatePoolWithTag(PagedPool, Size, 'XedI');
    if (!CmResource)
    {
        DPRINT1("ChannelQueryResources: STATUS_NO_MEMORY\n");
        Status = STATUS_NO_MEMORY;
        goto Exit;
    }
    RtlZeroMemory(CmResource, Size);

    CmResource->Count = 1;
    Status = STATUS_SUCCESS;

    CmResource->List[0].PartialResourceList.Count = Count = 0;
    CmResource->List[0].InterfaceType = 1;
    CmResource->List[0].BusNumber = 0;

    if (!PdoExtension->PdoIndex)
    {
        if (!FdoExtension->IsCmdBlockResource[0])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 0x11;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Port.Start.QuadPart = 0x1F0;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Port.Length = 8;
        }

        if (!FdoExtension->IsCtrlBlockResource[0])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 0x11;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Port.Start.QuadPart = 0x3F6;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Port.Length = 1;
        }

        if (!FdoExtension->IsIntResource[0])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 2;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Interrupt.Level = 0xE;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Interrupt.Vector = 0xE;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Interrupt.Affinity = 1;
        }
    }
    else
    {
        if (!FdoExtension->IsCmdBlockResource[1])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 0x11;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Port.Start.QuadPart = 0x170;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Port.Length = 8;
        }

        if (!FdoExtension->IsCtrlBlockResource[1])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 0x11;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Port.Start.QuadPart = 0x376;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Port.Length = 1;
        }

        if (!FdoExtension->IsIntResource[1])
        {
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Type = 2;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].ShareDisposition = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].Flags = 1;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Interrupt.Level = 0xF;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count].u.Interrupt.Vector = 0xF;
            CmResource->List[0].PartialResourceList.PartialDescriptors[Count++].u.Interrupt.Affinity = 1;
        }
    }

    if (!Count)
    {
        ExFreePoolWithTag(CmResource, 'XedI');
        CmResource = NULL;
    }

    CmResource->List[0].PartialResourceList.Count = Count;

Exit:

    Irp->IoStatus.Information = (ULONG_PTR)CmResource;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelQueryResourceRequirements(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources = NULL;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    ULONG State;
    ULONG Count;
    ULONG Size;
    BOOLEAN IsChannelNotEmpty;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryResourceRequirements: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryResourceRequirements: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    FdoExtension = PdoExtension->FdoExtension;

    if (FdoExtension->NativeMode[PdoExtension->PdoIndex])
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    State = PciIdeChannelEnabled(FdoExtension, PdoExtension->PdoIndex);

    if (State == 2)
    {
        IsChannelNotEmpty = (PdoExtension->IsChannelEmpty == 0);
    }
    else if (State == 0)
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    Size = (sizeof(IO_RESOURCE_REQUIREMENTS_LIST) + (2 * sizeof(IO_RESOURCE_DESCRIPTOR)));

    IoResources = ExAllocatePoolWithTag(PagedPool, Size, 'XedI');
    if (!IoResources)
    {
        DPRINT1("ChannelQueryResourceRequirements: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_MEMORY;
        goto Exit;
    }
    RtlZeroMemory(IoResources, Size);

    Status = STATUS_SUCCESS;

    IoResources->ListSize = Size;
    IoResources->InterfaceType = 1;
    IoResources->BusNumber = 0;
    IoResources->SlotNumber = 0;
    IoResources->AlternativeLists = 1;

    IoResources->List[0].Version = 1;
    IoResources->List[0].Revision = 1;
    IoResources->List[0].Count = 0;

    if (!PdoExtension->PdoIndex)
    {
        if (!FdoExtension->IsCmdBlockResource[0])
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 1;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 0x11;
            IoResources->List[0].Descriptors[Count].u.Port.Length = 8;
            IoResources->List[0].Descriptors[Count].u.Port.Alignment = 1;
            IoResources->List[0].Descriptors[Count].u.Port.MinimumAddress.QuadPart = 0x1F0;
            IoResources->List[0].Descriptors[Count].u.Port.MaximumAddress.QuadPart = 0x1F7;
            IoResources->List[0].Count++;
        }

        if (!FdoExtension->IsCtrlBlockResource[0])
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 1;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 0x11;
            IoResources->List[0].Descriptors[Count].u.Port.Length = 1;
            IoResources->List[0].Descriptors[Count].u.Port.Alignment = 1;
            IoResources->List[0].Descriptors[Count].u.Port.MinimumAddress.QuadPart = 0x3F6;
            IoResources->List[0].Descriptors[Count].u.Port.MaximumAddress.QuadPart = 0x3F6;
            IoResources->List[0].Count++;
        }

        if (!FdoExtension->IsIntResource[0] && IsChannelNotEmpty)
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 2;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 1;
            IoResources->List[0].Descriptors[Count].u.Interrupt.MinimumVector = 0xE;
            IoResources->List[0].Descriptors[Count].u.Interrupt.MaximumVector = 0xE;
            IoResources->List[0].Count++;
        }
    }
    else
    {
        if (!FdoExtension->IsCmdBlockResource[1])
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 1;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 0x11;
            IoResources->List[0].Descriptors[Count].u.Port.Length = 8;
            IoResources->List[0].Descriptors[Count].u.Port.Alignment = 1;
            IoResources->List[0].Descriptors[Count].u.Port.MinimumAddress.QuadPart = 0x170;
            IoResources->List[0].Descriptors[Count].u.Port.MaximumAddress.QuadPart = 0x177;
            IoResources->List[0].Count++;
        }

        if (!FdoExtension->IsCtrlBlockResource[1])
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 1;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 0x11;
            IoResources->List[0].Descriptors[Count].u.Port.Length = 1;
            IoResources->List[0].Descriptors[Count].u.Port.Alignment = 1;
            IoResources->List[0].Descriptors[Count].u.Port.MinimumAddress.QuadPart = 0x376;
            IoResources->List[0].Descriptors[Count].u.Port.MaximumAddress.QuadPart = 0x376;
            IoResources->List[0].Count++;
        }

        if (!FdoExtension->IsIntResource[1] && IsChannelNotEmpty)
        {
            Count = IoResources->List[0].Count;
            IoResources->List[0].Descriptors[Count].Option = 1;
            IoResources->List[0].Descriptors[Count].Type = 2;
            IoResources->List[0].Descriptors[Count].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Count].Flags = 1;
            IoResources->List[0].Descriptors[Count].u.Interrupt.MinimumVector = 0xF;
            IoResources->List[0].Descriptors[Count].u.Interrupt.MaximumVector = 0xF;
            IoResources->List[0].Count++;
        }
    }

    if (!IoResources->List[0].Count)
    {
        ExFreePoolWithTag(IoResources, 'XedI');
        IoResources = NULL;
    }

Exit:

    Irp->IoStatus.Information = (ULONG_PTR)IoResources;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelQueryText(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PMESSAGE_RESOURCE_ENTRY MessageEntry;
    PPDO_DEVICE_EXTENSION PdoExtension;
    DEVICE_TEXT_TYPE DeviceTextType;
    ANSI_STRING MessageString;
    UNICODE_STRING String;
    PWCHAR DeviceText = NULL;
    ULONG Size;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    DPRINT("ChannelQueryText: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryText: STATUS_NO_SUCH_DEVICE\n");
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, 0);
        return STATUS_NO_SUCH_DEVICE;
    }

    Irp->IoStatus.Information = 0;

    DeviceTextType = IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceText.DeviceTextType;

    if (DeviceTextType != DeviceTextDescription &&
        DeviceTextType != DeviceTextLocationInformation)
    {
        DPRINT1("ChannelQueryText: %p, %p\n", Pdo, Irp);
        goto Exit;
    }

    if (DeviceTextType == DeviceTextLocationInformation)
    {
        DeviceText = ExAllocatePoolWithTag(PagedPool, 0x64, 'XedI');
        if (!DeviceText)
        {
            DPRINT1("ChannelQueryText: %p, %p\n", Pdo, Irp);
            goto Exit;
        }

        swprintf(DeviceText, L"%ws Channel", (PdoExtension->PdoIndex ? L"Secondary" : L"Primary"));

        RtlInitUnicodeString(&String, DeviceText);
        String.Buffer[String.Length / 2] = 0;

        goto Exit;
    }

    /* DeviceTextType == DeviceTextDescription */

    Status = RtlFindMessage(PdoExtension->DriverObject->DriverStart, 0xB, 0, 1, &MessageEntry);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ChannelQueryText: %p, %p\n", Pdo, Irp);
        DeviceText = NULL;
        goto Exit;
    }

    if (!(MessageEntry->Flags & 1))
    {
        RtlInitAnsiString(&MessageString, (PCHAR)MessageEntry->Text);
        MessageString.Length -= 2;

        RtlAnsiStringToUnicodeString(&String, &MessageString, TRUE);
        DeviceText = String.Buffer;

        goto Exit;
    }

    if (MessageEntry->Text[MessageEntry->Length - 8])
        Size = (MessageEntry->Length - 8);
    else
        Size = (MessageEntry->Length - 0xA);

    DeviceText = ExAllocatePoolWithTag(PagedPool, Size, 'XedI');
    if (!DeviceText)
    {
        DPRINT1("ChannelQueryText: %p, %p\n", Pdo, Irp);
        goto Exit;
    }

    Size -= 2;

    RtlCopyMemory(DeviceText, MessageEntry->Text, Size);

    DeviceText[Size / 2] = 0;
    Status = STATUS_SUCCESS;

Exit:

    Irp->IoStatus.Information = (ULONG_PTR)DeviceText;

    if (!DeviceText)
        Status = Irp->IoStatus.Status;

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelFilterResourceRequirements(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_RESOURCE_LIST OldList;
    PIO_RESOURCE_DESCRIPTOR OldDesc;
    PIO_RESOURCE_LIST NewList;
    PIO_RESOURCE_DESCRIPTOR NewDesc;
    ULONG OldIdx;
    ULONG NewIdx;
    ULONG ix;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    PAGED_CODE();
    DPRINT("ChannelFilterResourceRequirements: %p, %p\n", Pdo, Irp);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelFilterResourceRequirements: PdoExtension is NULL\n");
        goto Exit;
    }

    if (!PdoExtension->IsChannelEmpty)
    {
        DPRINT("ChannelFilterResourceRequirements: Channel not empty\n");
        goto Exit;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT("ChannelFilterResourceRequirements: Irp->IoStatus.Status %X\n", Irp->IoStatus.Status);
        IoResource = IoGetCurrentIrpStackLocation(Irp)->Parameters.FilterResourceRequirements.IoResourceRequirementList;
    }
    else
    {
        IoResource = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    }

    if (!IoResource)
    {
        DPRINT1("ChannelFilterResourceRequirements: IoResource is NULL\n");
        goto Exit;
    }

    if (!IoResource->AlternativeLists)
    {
        DPRINT1("ChannelFilterResourceRequirements: AlternativeLists is 0\n");
        goto Exit;
    }

    NewList = OldList = IoResource->List;

    for (ix = 0; ix < IoResource->AlternativeLists; ix++)
    {
        RtlMoveMemory(NewList, OldList, FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors));

        OldDesc = OldList->Descriptors;
        NewDesc = NewList->Descriptors;

        for (NewIdx = OldIdx = 0; OldIdx < OldList->Count; OldIdx++)
        {
            if (OldDesc[OldIdx].Type == 2)
            {
                DPRINT("ChannelFilterResourceRequirements: STATUS_SUCCESS\n");
                Status = STATUS_SUCCESS;
            }
            else
            {
                NewDesc[NewIdx] = OldDesc[OldIdx];
                NewIdx++;
            }
        }

        OldList = (PIO_RESOURCE_LIST)&OldDesc[OldList->Count];

        NewList->Count = NewIdx;
        NewList = (PIO_RESOURCE_LIST)&NewDesc[NewList->Count];
    }

    if (Status != STATUS_NOT_SUPPORTED)
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = (ULONG_PTR)IoResource;
        IoCompleteRequest(Irp, 0);
        return Status;
    }

Exit:

    DPRINT("ChannelFilterResourceRequirements: STATUS_NOT_SUPPORTED\n");
    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);
    return Status;
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

    Id = ExAllocatePoolWithTag(PagedPool, ((IdLen + 1) * sizeof(WCHAR)), 'XedI');
    if (Id)
        wcscpy(Id, IdBuffer);

    return Id;
}

PWCHAR
NTAPI
ChannelBuildHardwareId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    WCHAR DefaultIdBuffer[10];
    WCHAR FullIdBuffer[10];
    USHORT VendorDevice[2];
    PWCHAR VendorId;
    PWCHAR DeviceId;
    PWCHAR Id;
    ULONG InternalLen;
    ULONG IdLen;
    BOOLEAN IsPIIX = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelBuildHardwareId: %p\n", PdoExtension);

    Status = PciIdeBusData(PdoExtension->FdoExtension, VendorDevice, 0, 4, 1);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelBuildHardwareId: Status %X\n", Status);
        return NULL;
    }

    switch (VendorDevice[0])
    {
        case 0xE11:
            VendorId = L"Compaq";
            break;

        case 0x1039:
            VendorId = L"SiS";
            break;

        case 0x1095:
            VendorId = L"CMD";
            break;

        case 0x10AD:
            VendorId = L"WinBond";
            break;

        case 0x10B9:
            VendorId = L"ALi";
            break;

        case 0x8086:
            VendorId = L"Intel";

            if (VendorDevice[1] == 0x1230)
            {
                DeviceId = L"PIIX";
                IsPIIX = TRUE;
            }
            else if (VendorDevice[1] == 0x7010)
            {
                DeviceId = L"PIIX3";
                IsPIIX = TRUE;
            }
            else if (VendorDevice[1] == 0x7111)
            {
                DeviceId = L"PIIX4";
                IsPIIX = TRUE;
            }
            break;

        default:
            swprintf(DefaultIdBuffer, L"%04x", VendorDevice[0]);
            VendorId = DefaultIdBuffer;
            break;
    }

    if (!IsPIIX)
    {
        swprintf(FullIdBuffer, L"%04x", VendorDevice[1]);
        DeviceId = FullIdBuffer;
    }

    Id = ExAllocatePoolWithTag(PagedPool, 0x212, 'XedI');
    if (!Id)
    {
        DPRINT1("ChannelBuildHardwareId: Allocate id failed!\n");
        return NULL;
    }

    swprintf(Id, L"%ws-%ws", VendorId, DeviceId);

    IdLen = wcslen(Id);
    Id[IdLen++] = 0;

    InternalLen = wcslen(ChannelInternalCompatibleId[PdoExtension->PdoIndex]);

    RtlCopyMemory(&Id[IdLen], ChannelInternalCompatibleId[PdoExtension->PdoIndex], (InternalLen * sizeof(WCHAR)));

    IdLen += InternalLen;
    Id[IdLen++] = 0;

    RtlCopyMemory(&Id[IdLen], ChannelCompatibleId, sizeof(ChannelCompatibleId));

    IdLen += 9;
    Id[IdLen++] = 0;
    Id[IdLen] = 0;

    return Id;
}

PWCHAR
NTAPI
ChannelBuildCompatibleId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PWCHAR Id;

    PAGED_CODE();
    DPRINT("ChannelBuildCompatibleId: %p\n", PdoExtension);

    Id = ExAllocatePoolWithTag(PagedPool, 0x16, 'XedI');
    if (!Id)
    {
        DPRINT1("ChannelBuildCompatibleId: Allocate id failed!\n");
        return NULL;
    }
    RtlZeroMemory(Id, 0x16);

    RtlCopyMemory(Id, ChannelCompatibleId, sizeof(ChannelCompatibleId));

    return Id;
}

PWCHAR
NTAPI
ChannelBuildInstanceId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PWCHAR Id;

    PAGED_CODE();
    DPRINT("ChannelBuildInstanceId: %p\n", PdoExtension);

    Id = ExAllocatePoolWithTag(PagedPool, 0x16, 'XedI');
    if (!Id)
    {
        DPRINT1("ChannelBuildInstanceId: Allocate id failed!\n");
        return NULL;
    }
    RtlZeroMemory(Id, 0x16);

    swprintf(Id, L"%d", PdoExtension->PdoIndex);

    return Id;
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
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    NTSTATUS Status;

    DPRINT("ChannelQueryPnPDeviceState: %p\n", Pdo);

    PdoExtension = ChannelGetPdoExtension(Pdo);
    if (!PdoExtension)
    {
        DPRINT1("ChannelQueryPnPDeviceState: STATUS_DEVICE_DOES_NOT_EXIST\n");
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto Exit;
    }

    Irp->IoStatus.Information |= PdoExtension->PnPDeviceState;
    PdoExtension->PnPDeviceState &= ~0x14;
    Status = STATUS_SUCCESS;

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
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
    _In_ PVOID MiniExtension,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_reads_bytes_(BufferLength) PVOID DataMask,
    _In_ ULONG ConfigDataOffset,
    _In_ ULONG BufferLength)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PUCHAR CurrentData;
    PUCHAR SetData;
    ULONG ix;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("PciIdeXSetBusData(%p %p %X %X)\n", MiniExtension, Buffer, ConfigDataOffset, BufferLength);

    CurrentData = ExAllocatePool(NonPagedPool, BufferLength);
    if (!CurrentData)
    {
        DPRINT1("PciIdeXSetBusData: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    FdoExtension = (PFDO_DEVICE_EXTENSION)((ULONG_PTR)MiniExtension - sizeof(FDO_DEVICE_EXTENSION));
    KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);

    Status = PciIdeBusData(FdoExtension, CurrentData, ConfigDataOffset, BufferLength, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeXSetBusData: Status %X\n", Status);
        goto Exit;
    }

    SetData = Buffer;

    for (ix = 0; ix < BufferLength; ix++)
    {
        CurrentData[ix] &= ~((PUCHAR)DataMask)[ix];
        CurrentData[ix] |= (SetData[ix] & ((PUCHAR)DataMask)[ix]);
    }

    Status = PciIdeBusData(FdoExtension, CurrentData, ConfigDataOffset, BufferLength, FALSE);

Exit:

    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);

    ExFreePool(CurrentData);

    return Status;

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
