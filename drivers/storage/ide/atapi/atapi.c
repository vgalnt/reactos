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
ChannelAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
ChannelStartDevice(
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
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
