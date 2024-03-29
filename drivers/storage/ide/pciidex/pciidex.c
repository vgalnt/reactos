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

VOID
NTAPI
PciIdeUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ControllerAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    UNIMPLEMENTED_DBGBREAK();
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
