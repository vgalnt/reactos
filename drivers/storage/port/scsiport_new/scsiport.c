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

BOOLEAN ScsiPortLegacyAdapterDetection = FALSE;
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
    PAGED_CODE();
    DPRINT("SpDetermine64BitSupport()\n");

    if ((BOOLEAN)(ULONG_PTR)Mm64BitPhysicalAddress == TRUE)
    {
        DPRINT1("SpDetermine64BitSupport: Mm64BitPhysicalAddress is TRUE\n");
        return TRUE;
    }

    return FALSE;
}

BOOLEAN
NTAPI
SpDetermineLegacyInstanceId(VOID)
{
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING NameString;
    HANDLE ScsiPortKey = NULL;
    ULONG ResultLength;
    BOOLEAN Result = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpDetermineLegacyInstanceId()\n");

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    RtlInitUnicodeString(&NameString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ScsiPort\\");
    InitializeObjectAttributes(&ObjectAttributes, &NameString, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), 0, NULL);

    Status = ZwOpenKey(&ScsiPortKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpDetermineLegacyInstanceId: Status %X\n", Status);
        return FALSE;
    }

    ASSERT(ScsiPortKey != 0);

    RtlInitUnicodeString(&NameString, L"UseLegacyInstanceId");

    Status = ZwQueryValueKey(ScsiPortKey, &NameString, KeyValuePartialInformation, KeyValueInfo, sizeof(Buffer), &ResultLength);
    if (NT_SUCCESS(Status))
    {
        DPRINT("SpDetermineLegacyInstanceId: ResultLength %X\n", ResultLength);

        if (KeyValueInfo->Type == REG_DWORD &&
            ResultLength >= sizeof(ULONG) &&
            *(PULONG)KeyValueInfo->Data == 1)
        {
            Result = TRUE;
        }
    }

    if (ScsiPortKey)
        ZwClose(ScsiPortKey);

    return Result;
}

NTSTATUS
NTAPI
SpReadNumericValue(
    _In_ HANDLE Root,
    _In_ PUNICODE_STRING KeyName,
    _In_ PUNICODE_STRING ValueName,
    _Out_ ULONG* OutValue)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpAllocateDriverExtension(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ PSCSI_PORT_DRIVER_EXTENSION* OutSpDriverExtension)
{
    UCHAR PnpInterfaceBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) + 0xE6];//?
    UCHAR LegacyDetectBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION LegacyDetectInfo;
    PKEY_VALUE_FULL_INFORMATION PnpInterfaceInfo;
    PSCSI_PNP_INTERFACE Interface;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING GuidString;
    UNICODE_STRING ValueName;
    UNICODE_STRING KeyName;
    HANDLE ParametersHandle = NULL;
    HANDLE InterfaceHandle = NULL;
    HANDLE DriverHandle = NULL;
    HANDLE GuidStringHandle;
    HANDLE ClassHandle;
    ULONG ResultLength;
    ULONG BusType;
    ULONG Value;
    ULONG Size;
    ULONG Data;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpAllocateDriverExtension: Allocating extension for '%wZ'\n", &DriverObject->DriverName);

    *OutSpDriverExtension = NULL;

    //_SEH2_TRY

    InitializeObjectAttributes(&ObjectAttributes, RegistryPath, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), NULL, NULL);

    Status = ZwOpenKey(&DriverHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpAllocateDriverExtension: Unable to open registry key %wZ [%X]\n", RegistryPath, Status);
        goto Finish;
    }

    RtlInitUnicodeString(&KeyName, L"Parameters");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), DriverHandle, NULL);

    Status = ZwOpenKey(&ParametersHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpAllocateDriverExtension: Unable to open parameters key of %wZ [%X]\n", RegistryPath, Status);
        goto Finish;
    }

    RtlInitUnicodeString(&KeyName, L"BusType");
    Status = SpReadNumericValue(ParametersHandle, NULL, &KeyName, &BusType);

    if (!NT_SUCCESS(Status))
    {
        BusType = Isa;
    }
    else if (BusType == Isa || BusType == Eisa || BusType == MicroChannel || BusType == PCIBus || BusType == VMEBus ||
             BusType == PCMCIABus || BusType == CBus || BusType == MPIBus || BusType == MPSABus)
    {
        DPRINT("SpAllocateDriverExtension: Bus type set to %X\n", BusType);
    }

    RtlInitUnicodeString(&KeyName, L"PnpInterface");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), ParametersHandle, NULL);

    Status = ZwOpenKey(&InterfaceHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpAllocateDriverExtension: Unable to open PnpInterface key of %wZ [%X]\n", &RegistryPath, Status);
        goto Finish;
    }

    for (ix = 0; ix < 2; ix++)
    {
        Status = STATUS_SUCCESS;

        for (jx = 0; ; jx++)
        {
            PnpInterfaceInfo = (PKEY_VALUE_FULL_INFORMATION)&PnpInterfaceBuffer;

            ASSERTMSG("ScsiPort configuration error - possibly too many count entries: ", jx != MaximumInterfaceType);

            RtlZeroMemory(PnpInterfaceInfo, sizeof(PnpInterfaceBuffer));

            Status = ZwEnumerateValueKey(InterfaceHandle,
                                         jx,
                                         ((ix == 0) ? KeyValueBasicInformation : KeyValueFullInformation),
                                         PnpInterfaceInfo,
                                         sizeof(PnpInterfaceBuffer),
                                         &ResultLength);

            if (Status == STATUS_NO_MORE_ENTRIES)
            {
                Status = STATUS_SUCCESS;
                if (ix == 0)
                {
                    //DPRINT("SpAllocateDriverExtension: Driver has %d interface entries\n", jx);

                    Size = sizeof(SCSI_PORT_DRIVER_EXTENSION) + (jx * 8);
                    //DPRINT("SpAllocateDriverExtension: Driver extension will be %d bytes\n", Size);

                    Status = IoAllocateDriverObjectExtension(DriverObject, ScsiPortInitialize, Size, (PVOID *)&SpDriverExtension);
                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT("SpAllocateDriverExtension: Fatal error %X allocating driver extension\n", Status);
                        goto Finish;
                    }
                    RtlZeroMemory(SpDriverExtension, Size);

                    SpDriverExtension->PnpInterfaceCount = jx;
                }

                break;
            }
            else if (!NT_SUCCESS(Status))
            {
                DPRINT("SpAllocateDriverExtension: Fatal error %X enumerating PnpInterface key under %wZ.", Status, RegistryPath);
                goto Finish;
            }
            else if (ix == 1)
            {
                Interface = (PSCSI_PNP_INTERFACE)((ULONG_PTR)&SpDriverExtension[1] + (jx * 8));

                ASSERTMSG("ScsiPort internal error - too many pnpinterface entries on second pass: ", jx <= SpDriverExtension->PnpInterfaceCount);

                RtlInitUnicodeString(&KeyName, PnpInterfaceInfo->Name);

                if (PnpInterfaceInfo->Type != REG_DWORD && PnpInterfaceInfo->Type != REG_NONE)
                {
                    DPRINT1("SpAllocateDriverExtension: Fatal error %X parsing PnpInterface under '%wZ' - entry '%wZ' is not a REG_DWORD or REG_NONE entry\n", Status, RegistryPath, &KeyName);
                    Status = STATUS_DEVICE_CONFIGURATION_ERROR;
                    goto Finish;
                }

                Status = RtlUnicodeStringToInteger(&KeyName, 0, &Value);// ValueName
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("SpAllocateDriverExtension: Fatal error %X parsing PnpInterface under '%wZ' - entry '%wZ' is not a valid interface type name\n", Status, RegistryPath, &KeyName);
                    goto Finish;
                }

                if (Value > MaximumInterfaceType)
                {
                    DPRINT1("SpAllocateDriverExtension: Fatal error %X parsing PnpInterface under '%wZ' - entry '%wZ' is > MaximumInterfaceType (%X)\n", Status, RegistryPath, &KeyName, Value);
                    Interface->InterfaceType = 0xFFFFFFFF;
                    Status = STATUS_DEVICE_CONFIGURATION_ERROR;
                    goto Finish;
                }

                Interface->InterfaceType = Value;

                if (PnpInterfaceInfo->Type == REG_NONE)
                {
                    Interface->Flags = 0;
                }
                else
                {
                    Interface->Flags = *((PUCHAR)PnpInterfaceInfo + PnpInterfaceInfo->DataOffset);
                    if (Interface->Flags & 1)
                    {
                        ASSERT(SpDriverExtension != NULL);
                        SpDriverExtension->IgnoreInitLegacyStatus++;
                    }

                    if (Interface->InterfaceType != Internal)
                    {
                        if (Interface->InterfaceType == PCIBus)
                        {
                            Interface->Flags |= 4;
                            Interface->Flags |= 8;
                            Interface->Flags &= ~2;
                        }
                        else if (Interface->InterfaceType != PCMCIABus &&
                                 Interface->InterfaceType != 14)//PNPISABus
                        {
                            if (!(Interface->Flags & 0x10))
                                Interface->Flags |= 2;
                        }
                        else
                        {
                            Interface->Flags &= ~2;
                        }
                    }
                    else
                    {
                        Interface->Flags &= ~2;
                    }
                }

                DPRINT("SpAllocateDriverExtension: Interface %X has flags %X\n", Interface->InterfaceType, Interface->Flags);
            }
        }
    }

    ASSERTMSG("ScsiPortAllocateDriverExtension internal error: left first section with non-success status: ", NT_SUCCESS(Status));

Finish:
    //_SEH2_FINALLY

    if (SpDriverExtension)
    {
        SpDriverExtension->BusType = BusType;
        Status = STATUS_SUCCESS;
    }
    else
    {
        DPRINT("SpAllocateDriverExtension: Driver has 0 interface entries\n");
        DPRINT("SpAllocateDriverExtension: Driver extension will be %X bytes\n", sizeof(SCSI_PORT_DRIVER_EXTENSION));

        Status = IoAllocateDriverObjectExtension(DriverObject, ScsiPortInitialize, sizeof(SCSI_PORT_DRIVER_EXTENSION), (PVOID *)&SpDriverExtension);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("SpAllocateDriverExtension: Fatal error %X allocating driver extension\n", Status);
        }
        else
        {
            RtlZeroMemory(SpDriverExtension, sizeof(SCSI_PORT_DRIVER_EXTENSION));
            Status = STATUS_SUCCESS;
        }
    }

    if (Status != STATUS_SUCCESS)
        goto Exit;

    //_SEH2_END

    //SpDriverExtension->LogEntry = SpAllocateErrorLogEntry(DriverObject);

    SpDriverExtension->DriverObject = DriverObject;

    SpDriverExtension->RegistryPath = *RegistryPath;
    SpDriverExtension->RegistryPath.MaximumLength += 2;

    SpDriverExtension->RegistryPath.Buffer = ExAllocatePoolWithTag(PagedPool, SpDriverExtension->RegistryPath.MaximumLength, 'RPcS');
    if (!SpDriverExtension->RegistryPath.Buffer)
    {
        DPRINT1("SpAllocateDriverExtension: Fatal error allocating copy of registry path\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlCopyUnicodeString(&SpDriverExtension->RegistryPath, RegistryPath);

    if (ScsiPortLegacyAdapterDetection)
    {
        SpDriverExtension->LegacyAdapterDetection = 1;
        goto Exit;
    }

    if (ParametersHandle)
    {
        LegacyDetectInfo = (PKEY_VALUE_PARTIAL_INFORMATION)&LegacyDetectBuffer;
        RtlInitUnicodeString(&ValueName, L"LegacyAdapterDetection");

        Status = ZwQueryValueKey(ParametersHandle, &ValueName, KeyValuePartialInformation, LegacyDetectInfo, sizeof(LegacyDetectBuffer), &ResultLength);

        if (NT_SUCCESS(Status) && ResultLength >= sizeof(KEY_VALUE_PARTIAL_INFORMATION) && LegacyDetectInfo->Type == REG_DWORD)
        {
            SpDriverExtension->LegacyAdapterDetection = (*(PULONG)LegacyDetectInfo->Data == 1);
            Data = 0;

            Status = ZwSetValueKey(ParametersHandle, &ValueName, LegacyDetectInfo->TitleIndex, REG_DWORD, &Data, sizeof(Data));
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("SpAllocateDriverExtension: Error %X setting LegacyAdapterDetection value to zero\n", Status);
            }
        }
        else
        {
            SpDriverExtension->LegacyAdapterDetection = 0;
        }
    }

    if (SpDriverExtension->LegacyAdapterDetection)
    {
        goto Exit;
    }

    ClassHandle = 0;
    GuidStringHandle = 0;

    RtlInitUnicodeString(&GuidString, NULL);
    RtlInitUnicodeString(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class");

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), NULL, NULL);

    //_SEH2_TRY

    Status = ZwOpenKey(&ClassHandle, KEY_READ, &ObjectAttributes);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpAllocateDriverExtension: Error %X opening key '%wZ'\n", Status, &KeyName);
    }
    else
    {
        Status = RtlStringFromGUID(&GUID_DEVCLASS_SCSIADAPTER, &GuidString);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("SpAllocateDriverExtension: Error %X converting GUID to unicode string\n", Status);
        }
        else
        {
            InitializeObjectAttributes(&ObjectAttributes, &GuidString, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), ClassHandle, NULL);

            Status = ZwOpenKey(&GuidStringHandle, KEY_READ, &ObjectAttributes);

            if (!NT_SUCCESS(Status))
            {
                DPRINT("SpAllocateDriverExtension: Error %X opening class key '%wZ'\n", Status, &GuidString);
            }
            else
            {
                LegacyDetectInfo = (PKEY_VALUE_PARTIAL_INFORMATION)&LegacyDetectBuffer;
                RtlInitUnicodeString(&KeyName, L"LegacyAdapterDetection");

                Status = ZwQueryValueKey(GuidStringHandle, &KeyName, KeyValuePartialInformation, LegacyDetectInfo, sizeof(LegacyDetectBuffer), &ResultLength);

                if (NT_SUCCESS(Status))
                {
                    SpDriverExtension->LegacyAdapterDetection = (*(PULONG)LegacyDetectInfo->Data != 0);
                }
                else
                {
                    DPRINT("SpAllocateDriverExtension: Error %X reading key '%wZ'\n", Status, &KeyName);
                    Status = STATUS_SUCCESS;
                }
            }
        }
    }

    //_SEH2_FINALLY

    if (ClassHandle)
        ZwClose(ClassHandle);
    if (GuidStringHandle)
        ZwClose(GuidStringHandle);

    RtlFreeUnicodeString(&GuidString);

    //_SEH2_END

    Status = STATUS_SUCCESS;

Exit:

    if (DriverHandle)
        ZwClose(DriverHandle);
    if (ParametersHandle)
        ZwClose(ParametersHandle);
    if (InterfaceHandle)
        ZwClose(InterfaceHandle);

    if (NT_SUCCESS(Status))
        *OutSpDriverExtension = SpDriverExtension;

    return Status;
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
            //ScsiDebugPrintInt(0, "ScsiPortInitialize: Error %X allocating driver extension - cannot continue\n", Status);
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
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: flags = %X & LegacyAdapterDetection = %d\n", iFlags, SpDriverExtension->LegacyAdapterDetection);
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
