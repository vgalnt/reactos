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

/* POWER FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
PciIdeSetFdoPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

/* FDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ControllerStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS
NTAPI
ControllerQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
DispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PVOID DeviceExtension,
    _Out_writes_bytes_all_(BufferLength) PVOID Buffer,
    _In_ ULONG ConfigDataOffset,
    _In_ ULONG BufferLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

    Status = IoAllocateDriverObjectExtension(DriverObject, DriverObject, sizeof(*DriverExtension), (PVOID*)&DriverExtension);
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
