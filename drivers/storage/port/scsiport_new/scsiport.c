/*
 * PROJECT:     ReactOS Storage Stack
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSIPORT storage port library
 * COPYRIGHT:   
 */

/* INCLUDES *****************************************************************/

#include "scsiport.h"

//#define NDEBUG
//#include <debug.h>
#include "debug.h"

/* GLOBALS *******************************************************************/

ULONG ScsiDebug = 0;
LONG SpVrfyLevel = 0;

PDEVICE_OBJECT* ScsiGlobalAdapterList = ULongToPtr(0xFFFFFFFF);
ULONG ScsiGlobalAdapterListElements = 0;
KSPIN_LOCK ScsiGlobalAdapterListSpinLock;
PVOID ScsiDirectory = NULL;
PSCSI_PORT_GUID_INTERFACE_MAPPING SpGuidInterfaceMappingList;
HANDLE ScsiDeviceMapKey = ULongToPtr(0xFFFFFFFF);

BOOLEAN Sp64BitPhysicalAddresses = FALSE;
BOOLEAN SpLegacyInstanceId = FALSE;

PDRIVER_DISPATCH DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH Scsi1DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH AdapterMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];

/* FUNCTIONS *****************************************************************/

VOID
NTAPI
SpCreateScsiDirectory(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DirectoryName;
    HANDLE Handle;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpCreateScsiDirectory: called!\n");

    RtlInitUnicodeString(&DirectoryName, L"\\Device\\Scsi");
    InitializeObjectAttributes(&ObjectAttributes, &DirectoryName, (OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE), 0, NULL);

    Status = ZwCreateDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        ObReferenceObjectByHandle(Handle, 0x80, NULL, KernelMode, &ScsiDirectory, NULL);
        ZwClose(Handle);
    }
}

NTSTATUS
NTAPI
SpInitializeGuidInterfaceMapping(VOID)
{
    PAGED_CODE();
    DPRINT("SpInitializeGuidInterfaceMapping()\n");

    ASSERT(SpGuidInterfaceMappingList == NULL);

    SpGuidInterfaceMappingList = ExAllocatePoolWithTag(PagedPool, (5 * sizeof(SCSI_PORT_GUID_INTERFACE_MAPPING)), 'TPcS');
    if (!SpGuidInterfaceMappingList)
    {
        DPRINT1("SpInitializeGuidInterfaceMapping: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(SpGuidInterfaceMappingList, (5 * sizeof(SCSI_PORT_GUID_INTERFACE_MAPPING)));

    SpGuidInterfaceMappingList[0].Guid = GUID_BUS_TYPE_PCMCIA;
    SpGuidInterfaceMappingList[0].InterfaceType = Isa;

    SpGuidInterfaceMappingList[1].Guid = GUID_BUS_TYPE_PCI;
    SpGuidInterfaceMappingList[1].InterfaceType = PCIBus;

    SpGuidInterfaceMappingList[2].Guid = GUID_BUS_TYPE_ISAPNP;
    SpGuidInterfaceMappingList[2].InterfaceType = Isa;

    SpGuidInterfaceMappingList[3].Guid = GUID_BUS_TYPE_EISA;
    SpGuidInterfaceMappingList[3].InterfaceType = Eisa;

    SpGuidInterfaceMappingList[4].InterfaceType = InterfaceTypeUndefined;

    return STATUS_SUCCESS;
}

VOID
NTAPI
SpInitDeviceMap(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DeviceMapName;
    HANDLE KeyHandle;
    ULONG Disposition;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpInitDeviceMap()\n");

    RtlInitUnicodeString(&DeviceMapName, L"\\Registry\\Machine\\Hardware\\DeviceMap\\Scsi");
    InitializeObjectAttributes(&ObjectAttributes, &DeviceMapName, OBJ_CASE_INSENSITIVE, 0, NULL);

    Status = ZwCreateKey(&KeyHandle, (KEY_READ | KEY_WRITE), &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);

    if (NT_SUCCESS(Status))
        ScsiDeviceMapKey = KeyHandle;
    else
        ScsiDeviceMapKey = NULL;
}

BOOLEAN
NTAPI
SpDetermine64BitSupport(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
SpDetermineLegacyInstanceId(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS
NTAPI
SpAllocateDriverExtension(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ PSCSI_PORT_DRIVER_EXTENSION* OutSpDriverExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ScsiPortStartIo(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ScsiPortAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ScsiPortUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();
    DPRINT1("ScsiPortUnload: %p\n", DriverObject);
    UNIMPLEMENTED_DBGBREAK();
}

ULONG
NTAPI
SpQueryPnpInterfaceFlags(
    _In_ PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension,
    _In_ ULONG InterfaceType)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

/* (PDO) PORT DISPATCH FUNCTIONS *********************************************/

NTSTATUS
NTAPI
ScsiPortPdoDeviceControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortPdoPnp(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortPdoCreateClose(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortPdoScsi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortScsi1PdoScsi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* (FDO) ADAPTER DISPATCH FUNCTIONS ******************************************/

NTSTATUS
NTAPI
ScsiPortFdoCreateClose(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortFdoDeviceControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortFdoDispatch(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortFdoPnp(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* DISPATCH FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ScsiPortGlobalDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortDispatchUnimplemented(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortSystemControlIrp(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortDispatchPower(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ScsiPortInitializeDispatchTables(VOID)
{
    ULONG ix;

    for (ix = 0; ix <= IRP_MJ_MAXIMUM_FUNCTION; ix++)
        DeviceMajorFunctionTable[ix] = ScsiPortDispatchUnimplemented;

    DeviceMajorFunctionTable[IRP_MJ_DEVICE_CONTROL] = ScsiPortPdoDeviceControl;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_DEVICE_CONTROL] = ScsiPortPdoDeviceControl;

    DeviceMajorFunctionTable[IRP_MJ_PNP] = ScsiPortPdoPnp;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_PNP] = ScsiPortPdoPnp;

    DeviceMajorFunctionTable[IRP_MJ_CREATE] = ScsiPortPdoCreateClose;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_CREATE] = ScsiPortPdoCreateClose;

    DeviceMajorFunctionTable[IRP_MJ_CLOSE] = ScsiPortPdoCreateClose;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_CLOSE] = ScsiPortPdoCreateClose;

    for (ix = 0; ix <= IRP_MJ_MAXIMUM_FUNCTION; ix++)
        AdapterMajorFunctionTable[ix] = ScsiPortDispatchUnimplemented;

    DeviceMajorFunctionTable[IRP_MJ_SYSTEM_CONTROL] = ScsiPortSystemControlIrp;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_SYSTEM_CONTROL] = ScsiPortSystemControlIrp;
    AdapterMajorFunctionTable[IRP_MJ_SYSTEM_CONTROL] = ScsiPortSystemControlIrp;

    DeviceMajorFunctionTable[IRP_MJ_SCSI] = ScsiPortPdoScsi;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_SCSI] = ScsiPortScsi1PdoScsi;

    DeviceMajorFunctionTable[IRP_MJ_POWER] = ScsiPortDispatchPower;
    Scsi1DeviceMajorFunctionTable[IRP_MJ_POWER] = ScsiPortDispatchPower;

    AdapterMajorFunctionTable[IRP_MJ_CREATE] = ScsiPortFdoCreateClose;
    AdapterMajorFunctionTable[IRP_MJ_CLOSE] = ScsiPortFdoCreateClose;
    AdapterMajorFunctionTable[IRP_MJ_DEVICE_CONTROL] = ScsiPortFdoDeviceControl;
    AdapterMajorFunctionTable[IRP_MJ_SCSI] = ScsiPortFdoDispatch;
    AdapterMajorFunctionTable[IRP_MJ_POWER] = ScsiPortDispatchPower;
    AdapterMajorFunctionTable[IRP_MJ_PNP] = ScsiPortFdoPnp;
}

/* EXPORT FUNCTIONS **********************************************************/

ULONG
NTAPI
DllInitialize(
    _In_ ULONG Unknown)
{
    if (SpVrfyLevel != -1)
    {
        UNIMPLEMENTED;
    }

    return 0;
}

VOID
ScsiDebugPrint(
    _In_ ULONG DebugPrintLevel,
    _In_ PCHAR DebugMessage,
    ...)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ScsiPortCompleteRequest(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ UCHAR SrbStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

#undef ScsiPortConvertPhysicalAddressToUlong

ULONG
NTAPI
ScsiPortConvertPhysicalAddressToUlong(
    _In_ SCSI_PHYSICAL_ADDRESS Address)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
ScsiPortFlushDma(
    _In_ PVOID HwDeviceExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ScsiPortFreeDeviceBase(
    _In_ PVOID HwDeviceExtension,
    _In_ PVOID MappedAddress)
{
    UNIMPLEMENTED_DBGBREAK();
}

ULONG
NTAPI
ScsiPortGetBusData(
    _In_ PVOID DeviceExtension,
    _In_ ULONG BusDataType,
    _In_ ULONG SystemIoBusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

PVOID
NTAPI
ScsiPortGetDeviceBase(
    _In_ PVOID HwDeviceExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG SystemIoBusNumber,
    _In_ SCSI_PHYSICAL_ADDRESS IoAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PVOID
NTAPI
ScsiPortGetLogicalUnit(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

SCSI_PHYSICAL_ADDRESS
NTAPI
ScsiPortGetPhysicalAddress(
    _In_ PVOID HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb OPTIONAL,
    _In_ PVOID VirtualAddress,
    _Out_ ULONG *Length)
{
    SCSI_PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = 0;
    UNIMPLEMENTED_DBGBREAK();
    return PhysicalAddress;
}

PSCSI_REQUEST_BLOCK
NTAPI
ScsiPortGetSrb(
    _In_ PVOID DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ LONG QueueTag)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PVOID
NTAPI
ScsiPortGetUncachedExtension(
    _In_ PVOID HwDeviceExtension,
    _In_ PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    _In_ ULONG NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PVOID
NTAPI
ScsiPortGetVirtualAddress(
    _In_ PVOID HwDeviceExtension,
    _In_ SCSI_PHYSICAL_ADDRESS PhysicalAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

ULONG
NTAPI
ScsiPortInitialize(
    _In_ PVOID Argument1,
    _In_ PVOID Argument2,
    _In_ PHW_INITIALIZATION_DATA HwInitializationData,
    _In_ PVOID HwContext)
{
    PDRIVER_OBJECT DriverObject = Argument1;
    PUNICODE_STRING RegistryPath = Argument2;
    PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension;
    PSCSI_HW_CHAIN_ENTRY* OutHwDataEntry;
    PSCSI_HW_CHAIN_ENTRY ChainEntry;
    ULONG iFlags;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ScsiPortInitialize: %p, '%wZ'\n", DriverObject, RegistryPath);

    if (ScsiGlobalAdapterList == ULongToPtr(0xFFFFFFFF))
    {
        ScsiGlobalAdapterList = NULL;
        ScsiGlobalAdapterListElements = 0;

        KeInitializeSpinLock(&ScsiGlobalAdapterListSpinLock);

        ScsiPortInitializeDispatchTables();
        SpCreateScsiDirectory();

        Status = SpInitializeGuidInterfaceMapping();
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ScsiPortInitialize: Status %X\n", Status);
            return Status;
        }

        SpInitDeviceMap();

        Sp64BitPhysicalAddresses = SpDetermine64BitSupport();
        SpLegacyInstanceId = SpDetermineLegacyInstanceId();
    }

    if (HwInitializationData->HwInitializationDataSize > sizeof(HW_INITIALIZATION_DATA))
    {
        //ScsiDebugPrintInt(0, "ScsiPortInitialize: Miniport driver wrong version\n");
        DPRINT1("ScsiPortInitialize: Miniport driver wrong version (%X)\n", HwInitializationData->HwInitializationDataSize);
        return STATUS_REVISION_MISMATCH;
    }

    if (!HwInitializationData->HwInitialize ||
        !HwInitializationData->HwFindAdapter ||
        !HwInitializationData->HwStartIo ||
        !HwInitializationData->HwResetBus)
    {
        //ScsiDebugPrintInt(0, "ScsiPortInitialize: Miniport driver missing required entry\n");
        DPRINT1("ScsiPortInitialize: Miniport driver missing required entry\n");
        return STATUS_REVISION_MISMATCH;
    }

    SpDriverExtension = IoGetDriverObjectExtension(DriverObject, ScsiPortInitialize);
    if (!SpDriverExtension)
    {
        Status = SpAllocateDriverExtension(DriverObject, RegistryPath, &SpDriverExtension);
        if (!NT_SUCCESS(Status))
        {
            //ScsiDebugPrintInt(0, "ScsiPortInitialize: Error %#08lx allocating driver extension - cannot continue\n", Status);
            DPRINT1("ScsiPortInitialize: Status %X\n", Status);
            return Status;
        }
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_SCSI] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_POWER] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = ScsiPortGlobalDispatch;
    DriverObject->MajorFunction[IRP_MJ_PNP] = ScsiPortGlobalDispatch;

    DriverObject->DriverStartIo = ScsiPortStartIo;
    DriverObject->DriverExtension->AddDevice = ScsiPortAddDevice;
    DriverObject->DriverUnload = ScsiPortUnload;

    iFlags = SpQueryPnpInterfaceFlags(SpDriverExtension, HwInitializationData->AdapterInterfaceType);

    if (HwInitializationData->AdapterInterfaceType == Internal && !(iFlags & 1))
    {
        DPRINT1("ScsiPortInitialize: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (iFlags & 1)
    {
          for (OutHwDataEntry = &SpDriverExtension->ChainHeader;
               *OutHwDataEntry;
               OutHwDataEntry = &ChainEntry->Next)
          {
              ChainEntry = *OutHwDataEntry;

              if (ChainEntry->HwInitializationData.AdapterInterfaceType == HwInitializationData->AdapterInterfaceType)
                  return STATUS_SUCCESS;
          }

          ChainEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ChainEntry), 'IPcS');
          if (!ChainEntry)
          {
              //ScsiDebugPrintInt(1, "ScsiPortInitialize: couldn't allocate chain entry\n");
              DPRINT1("ScsiPortInitialize: couldn't allocate chain entry\n");
              return STATUS_INSUFFICIENT_RESOURCES;
          }

          RtlCopyMemory(ChainEntry, HwInitializationData, sizeof(*HwInitializationData));

          ChainEntry->Next = NULL;

          *OutHwDataEntry = ChainEntry;
    }

    if (!(iFlags & 1) || (SpDriverExtension->LegacyAdapterDetection && (iFlags & 2)))
    {
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: flags = %#08lx & LegacyAdapterDetection = %d\n", iFlags, SpDriverExtension->LegacyAdapterDetection);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: Doing Legacy Adapter detection\n");
        DPRINT1("ScsiPortInitialize: Doing Legacy Adapter detection (%X, %X)\n", iFlags, SpDriverExtension->LegacyAdapterDetection);
        UNIMPLEMENTED_DBGBREAK();
        Status = STATUS_NOT_IMPLEMENTED;//ScsiPortInitLegacyAdapter(SpDriverExtension, HwInitializationData, HwContext);
    }

    if (SpDriverExtension->IgnoreInitLegacyStatus)
        Status = STATUS_SUCCESS;

    HwInitializationData->ReservedUshort |= 0x10;

    return Status;
}

VOID
NTAPI
ScsiPortIoMapTransfer(
    _In_ PVOID HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PVOID LogicalAddress,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ScsiPortLogError(
    _In_ PVOID HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb OPTIONAL,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ ULONG ErrorCode,
    _In_ ULONG UniqueId)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ScsiPortMoveMemory(
    _Out_ PVOID Destination,
    _In_ PVOID Source,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
ScsiPortNotification(
    _In_ SCSI_NOTIFICATION_TYPE NotificationType,
    _In_ PVOID HwDeviceExtension,
    ...)
{
    UNIMPLEMENTED_DBGBREAK();
}

ULONG
NTAPI
ScsiPortSetBusDataByOffset(
    _In_ PVOID DeviceExtension,
    _In_ ULONG BusDataType,
    _In_ ULONG SystemIoBusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

BOOLEAN
NTAPI
ScsiPortValidateRange(
    _In_ PVOID HwDeviceExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG SystemIoBusNumber,
    _In_ SCSI_PHYSICAL_ADDRESS IoAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
