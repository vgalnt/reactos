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
LONG LockLowWatermark = 0;

BOOLEAN ScsiPortLegacyAdapterDetection = FALSE;
BOOLEAN Sp64BitPhysicalAddresses = FALSE;
BOOLEAN SpLegacyInstanceId = FALSE;

PDRIVER_DISPATCH DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH Scsi1DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH AdapterMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];

/* FUNCTIONS *****************************************************************/

ULONG
FASTCALL
SpAcquireRemoveLockEx(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Tag,
    _In_ PSTR File,
    _In_ ULONG Line)
{
    PCOMMON_EXTENSION CommonExtension = DeviceObject->DeviceExtension;
    InterlockedIncrement(&CommonExtension->RemoveLock);
    return CommonExtension->IsRemoved;
}

VOID
FASTCALL
SpReleaseRemoveLock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Tag) // ? PIRP
{
    PCOMMON_EXTENSION CommonExtension = DeviceObject->DeviceExtension;
    LONG LockValue;

    LockValue = InterlockedDecrement(&CommonExtension->RemoveLock);

    //DebugPrint((4, "SpReleaseRemoveLock: Released for Object %#p & irp %#p - count is %d\n", DeviceObject, Tag, LockValue));
    DPRINT("SpReleaseRemoveLock: (%p %p) %X\n", DeviceObject, Tag, LockValue);

    ASSERT(LockValue >= 0);
    ASSERTMSG("RemoveLock decreased to meet LockLowWatermark", ((LockLowWatermark == 0) || !(LockValue == LockLowWatermark)));

    if (LockValue)
        return;

    ASSERT(CommonExtension->IsRemoved);

    //DebugPrint((3, "SpReleaseRemoveLock: Release for object %#p & irp %#p caused lock to go to zero\n", DeviceObject, Tag));
    DPRINT("SpReleaseRemoveLock: (%p %p) to zero\n", DeviceObject, Tag);

    KeSetEvent(&CommonExtension->Event, IO_NO_INCREMENT, FALSE);
}

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
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle = Root;
    ULONG ResultLength;
    ULONG Value = 0;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpReadNumericValue: '%wZ' '%wZ'\n", KeyName, ValueName);

    ASSERT(OutValue != NULL);
    ASSERT(ValueName != NULL);
    ASSERT((KeyName != NULL) || (Root != NULL));

    if (KeyName)
    {
        InitializeObjectAttributes(&ObjectAttributes, KeyName, (OBJ_CASE_INSENSITIVE | OBJ_OPENIF), Root, NULL);

        Status = ZwOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("SpReadNumericValue: Status %X\n", Status);
            goto Exit;
        }
    }

    RtlZeroMemory(Buffer, sizeof(Buffer));
    KeyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;

    Status = ZwQueryValueKey(KeyHandle, ValueName, KeyValuePartialInformation, KeyValueInfo, sizeof(Buffer), &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpReadNumericValue: Status %X\n", Status);
        goto Exit;
    }

    if (KeyValueInfo->Type == REG_DWORD)
    {
        Value = ((PULONG)KeyValueInfo->Data)[0];
        DPRINT("SpReadNumericValue: Value %X\n", Value);
    }
    else
    {
        Status = STATUS_UNSUCCESSFUL;
    }

Exit:

    *OutValue = Value;

    if (KeyHandle != Root)
        ZwClose(KeyHandle);

    return Status;
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

VOID
FASTCALL
SpCompleteRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context,
    _In_ CCHAR PriorityBoost)
{
    //PSCSI_PORT_SRB_DATA SrbData = Context;
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpSignalCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;
    DPRINT("SpSignalCompletion: %p\n", DeviceObject);
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
SpEnumerationWorker(
    _In_ PVOID Parameter)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpCreateAdapter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT* OutFdo)
{
    PSCSI_PORT_DRIVER_EXTENSION DriverExtension;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PUNICODE_STRING RegistryPath;
    WCHAR RegistryPathBuffer[128];
    WCHAR DeviceNameBuffer[64];
    UNICODE_STRING DeviceName;
    ULONG Offset = 0;
    ULONG Count = 0;
    ULONG PathLength;
    ULONG Length;
    ULONG ix;
    ULONG Port;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpCreateAdapter: %p\n", DriverObject);

    DriverExtension = IoGetDriverObjectExtension(DriverObject, ScsiPortInitialize);
    Port = InterlockedIncrement(&DriverExtension->Counter);

    RtlZeroMemory(RegistryPathBuffer, sizeof(RegistryPathBuffer));

    RegistryPath = &DriverExtension->RegistryPath;
    PathLength = (RegistryPath->Length / 2);

    DPRINT("SpCreateAdapter: RegistryPath '%wZ'\n", RegistryPath);

    for (ix = 0; ix < PathLength; ix++)
    {
        if (!RegistryPath->Buffer[ix])
        {
            ix--;
            Count = ix;
            break;
        }

        if (RegistryPath->Buffer[ix] == '\\' || RegistryPath->Buffer[ix] == '/')
            Offset = (ix + 1);

        Count = ix;
    }

    Length = (ix - Offset + 1);

    //ScsiDebugPrintInt(2, "SpCreateAdapter: Registry buffer %p\n", RegistryPath);
    //ScsiDebugPrintInt(2, "SpCreateAdapter: Starting offset %d chars\n", Offset);
    //ScsiDebugPrintInt(2, "SpCreateAdapter: Ending offset %d chars\n", Count);
    //ScsiDebugPrintInt(2, "SpCreateAdapter: %d chars or %d bytes will be copied\n", Length, (Length * 2));

    DPRINT("SpCreateAdapter: Registry buffer %p\n", RegistryPath);
    DPRINT("SpCreateAdapter: Starting offset %d chars\n", Offset);
    DPRINT("SpCreateAdapter: Ending offset %d chars\n", Count);
    DPRINT("SpCreateAdapter: %d chars or %d bytes will be copied\n", Length, (Length * 2));
    DPRINT("SpCreateAdapter: Name is \"");

    for (ix = (Offset * 2); Length; ix += 2, Length--)
    {
        DbgPrint("%wc", *(PUSHORT)Add2Ptr(RegistryPath->Buffer, ix));
    }
    DbgPrint("\"\n");

    RtlCopyMemory(RegistryPathBuffer, &RegistryPath->Buffer[Offset], (Length * 2));
    swprintf(DeviceNameBuffer, L"\\Device\\Scsi\\%ws%d", RegistryPathBuffer, Port);

    RtlInitUnicodeString(&DeviceName, DeviceNameBuffer);
    DPRINT("SpCreateFdo: Device object name is '%wZ'\n", &DeviceName);

    Status = IoCreateDevice(DriverObject,
                            (sizeof(*DeviceExtension) + DeviceName.MaximumLength),
                            &DeviceName,
                            FILE_DEVICE_CONTROLLER,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            OutFdo);

    ASSERTMSG("Name isn't unique: ", Status != STATUS_OBJECT_NAME_COLLISION);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpCreateFdo: couldn't allocate new FDO [%X]\n", Status);
        return Status;
    }

    DeviceExtension = (*OutFdo)->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(*DeviceExtension));

    DeviceExtension->CommonExtension.SelfDevice = *OutFdo;

    DeviceExtension->CommonExtension.CurrentDeviceState = 1;
    DeviceExtension->CommonExtension.CurrentSystemState = 1;

    DeviceExtension->CommonExtension.CurrentPnpState = 0xFF;
    DeviceExtension->CommonExtension.MajorFunction = AdapterMajorFunctionTable;

    KeInitializeEvent(&DeviceExtension->CommonExtension.Event, SynchronizationEvent, FALSE);

    ExInitializeNPagedLookasideList(&DeviceExtension->CommonExtension.LookAsideList, NULL, NULL, 0, 0x18, 'lPcS', 0x40);//?

    SpAcquireRemoveLockEx(*OutFdo, *OutFdo, __FILE__, __LINE__);

    for (ix = 0; ix < 8; ix++)
        KeInitializeSpinLock(&DeviceExtension->LunList[ix].SpinLock);

    DeviceExtension->PortScsi = Port;
    DeviceExtension->PortScsiPort = 0xFFFFFFFF;

    DeviceExtension->DeviceNameBuffer = (PVOID)&DeviceExtension[1];
    RtlCopyMemory(DeviceExtension->DeviceNameBuffer, DeviceName.Buffer, DeviceName.MaximumLength);

    KeInitializeMutex(&DeviceExtension->EnumMutex, 0);
    ExInitializeFastMutex(&DeviceExtension->EnumFastMutex);
    ExInitializeFastMutex(&DeviceExtension->PoFastMutex);

    ExInitializeWorkItem(&DeviceExtension->EnumWorkItem, SpEnumerationWorker, DeviceExtension);

    DeviceExtension->MaximumUCXAddress.LowPart = 0xFFFFFFFF;
    DeviceExtension->MaximumUCXAddress.HighPart = 0;

    DeviceExtension->BlockedLun = (PVOID)&DeviceExtension->BlockedLun;

    (*OutFdo)->Flags |= 0x10;
    (*OutFdo)->Flags &= ~0x80;

    return Status;
}

NTSTATUS
NTAPI
ScsiPortAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT Fdo;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ScsiPortAddDevice: %p, %p\n", DriverObject, LowerPdo);

    Status = SpCreateAdapter(DriverObject, &Fdo);
    if (!Fdo)
    {
        DPRINT1("ScsiPortAddDevice: Status %X\n", Status);
        return Status;
    }

    DeviceExtension = Fdo->DeviceExtension;

    DeviceExtension->Flags2 &= ~1;
    DeviceExtension->Flags2 &= ~0x30;
    DeviceExtension->Flags2 |= 4;

    DeviceExtension->CommonExtension.LowDevice = IoAttachDeviceToDeviceStack(Fdo, LowerPdo);
    DeviceExtension->LowerPdo = LowerPdo;

    Status = (DeviceExtension->CommonExtension.LowDevice ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
    return Status;
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
    PSCSI_PNP_INTERFACE PnpInterface;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpQueryPnpInterfaceFlags: %p, %X\n", SpDriverExtension, InterfaceType);

    PnpInterface = (PSCSI_PNP_INTERFACE)&SpDriverExtension[1];

    for (ix = 0; ix < SpDriverExtension->PnpInterfaceCount; ix++)
    {
        if (PnpInterface[ix].InterfaceType == InterfaceType)
        {
            DPRINT("SpQueryPnpInterfaceFlags: interface %X has flags %X\n", InterfaceType, PnpInterface[ix].Flags);
            return PnpInterface[ix].Flags;
        }
    }

    DPRINT("SpQueryPnpInterfaceFlags: No interface flags for %X\n", InterfaceType);

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
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortFdoDeviceControl(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ScsiPortFdoDispatch(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpGetBusTypeGuid(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    ULONG ResultLength;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpGetBusTypeGuid: %p\n", DeviceExtension);

    Status = IoGetDeviceProperty(DeviceExtension->LowerPdo,
                                 DevicePropertyBusTypeGuid,
                                 sizeof(GUID),
                                 &DeviceExtension->BusTypeGuid,
                                 &ResultLength);
    if (NT_SUCCESS(Status))
        return Status;

    RtlZeroMemory(&DeviceExtension->BusTypeGuid, sizeof(GUID));

    DPRINT1("SpGetBusTypeGuid: Status %X\n", Status);
    return Status;
}

BOOLEAN
NTAPI
SpGetInterrupt(
    _In_ PCM_RESOURCE_LIST CmResources,
    _Out_ ULONG* OutLevel,
    _Out_ ULONG* OutVector,
    _Out_ ULONG* OutAffinity)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpGetInterrupt: %p\n", CmResources);

    if (!CmResources->List[0].PartialResourceList.Count)
        return FALSE;

    ix = 0;
    Descriptor = &CmResources->List[0].PartialResourceList.PartialDescriptors[0];

    while (Descriptor->Type != CmResourceTypeInterrupt)
    {
        ix++;
        Descriptor++;

        if (ix >= CmResources->List[0].PartialResourceList.Count)
            return FALSE;
    }

    *OutLevel = Descriptor->u.Interrupt.Level;
    *OutVector = Descriptor->u.Interrupt.Vector;
    *OutAffinity = Descriptor->u.Interrupt.Affinity;

    return TRUE;
}

NTSTATUS
NTAPI
SpStartLowerDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PKEVENT Event;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpStartLowerDevice: %p, %p\n", Fdo, Irp);

    DeviceExtension = Fdo->DeviceExtension;

    Event = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Event), 'vPcS');
    if (!Event)
    {
        DPRINT1("SpStartLowerDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, SpSignalCompletion, Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceExtension->CommonExtension.LowDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpStartLowerDevice: Status %X\n", Status);
        ExFreePoolWithTag(Event, 'vPcS');
        return Status;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack = IoGetNextIrpStackLocation(Irp);

    IoStack->Parameters.QueryInterface.Size = sizeof(BUS_INTERFACE_STANDARD);
    IoStack->Parameters.QueryInterface.Version = 1;
    IoStack->Parameters.QueryInterface.InterfaceType = &GUID_BUS_INTERFACE_STANDARD;
    IoStack->Parameters.QueryInterface.Interface = (PVOID)&DeviceExtension->Interface;

    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_INTERFACE;

    KeResetEvent(Event);
    IoSetCompletionRoutine(Irp, SpSignalCompletion, Event, TRUE, TRUE, TRUE);

    IoCallDriver(DeviceExtension->CommonExtension.LowDevice, Irp);
    KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        //ScsiDebugPrintInt(1, "LowerBusInterfaceStandard request returned %#08lx\n", Irp->IoStatus.Status);
        DPRINT1("SpStartLowerDevice: LowerBusInterfaceStandard request returned %X\n", Irp->IoStatus.Status);

        DeviceExtension->LowerBusInterfaceStandardRetrieved = FALSE;
    }
    else
    {
        DeviceExtension->LowerBusInterfaceStandardRetrieved = TRUE;
    }

    Irp->IoStatus.Status = Status;
    ExFreePoolWithTag(Event, 'vPcS');

    return Status;
}

ULONG
NTAPI
RtlSizeOfCmResourceList(
    _In_ PCM_RESOURCE_LIST CmResources)
{
    ULONG RetSize = sizeof(CM_RESOURCE_LIST);
    ULONG ix;
    ULONG jx;

    PAGED_CODE();
    DPRINT("RtlSizeOfCmResourceList: %p\n", CmResources);

    for (ix = 0; ix < CmResources->Count; ix++)
    {
        if (ix)
            RetSize += sizeof(CM_FULL_RESOURCE_DESCRIPTOR);

        for (jx = 0; jx < CmResources->List[ix].PartialResourceList.Count; jx++)
        {
            if (jx)
                RetSize += sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
        }
    }

    return RetSize;
}

PCM_RESOURCE_LIST
NTAPI
RtlDuplicateCmResourceList(
    _In_ POOL_TYPE PoolType,
    _In_ PCM_RESOURCE_LIST InCmResources,
    _In_ ULONG Tag)
{
    PCM_RESOURCE_LIST CmResources;
    ULONG Size;

    PAGED_CODE();
    DPRINT("RtlDuplicateCmResourceList: %X %p\n", PoolType, InCmResources);

    Size = RtlSizeOfCmResourceList(InCmResources);

    CmResources = ExAllocatePoolWithTag(PoolType, Size, Tag);
    if (CmResources)
        RtlCopyMemory(CmResources, InCmResources, Size);

    return CmResources;
}

NTSTATUS
NTAPI
SpReadNumericInstanceValue(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PWCHAR ValueNameString,
    _Out_ ULONG* OutValue)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

INTERFACE_TYPE
NTAPI
SpGetPdoInterfaceType(
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PSCSI_PORT_GUID_INTERFACE_MAPPING Entry;
    INTERFACE_TYPE InterfaceType;
    GUID Guid;
    ULONG InstanceValue;
    ULONG ResultLength;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpGetPdoInterfaceType: %p\n", LowerPdo);

    Status = SpReadNumericInstanceValue(LowerPdo, L"LegacyInterfaceType", &InstanceValue);
    if (NT_SUCCESS(Status))
        return InstanceValue;

    InterfaceType = InterfaceTypeUndefined;

    Status = IoGetDeviceProperty(LowerPdo, DevicePropertyBusTypeGuid, sizeof(Guid), &Guid, &ResultLength);
    if (NT_SUCCESS(Status))
    {
        Entry = SpGuidInterfaceMappingList;

        for (ix = 0; Entry[ix].InterfaceType != InterfaceTypeUndefined; ix++)
        {
            if (IsEqualGUID(&Entry[ix].Guid, &Guid))
            {
                InterfaceType = SpGuidInterfaceMappingList[ix].InterfaceType;
                break;
            }
        }
    }

    if (InterfaceType != InterfaceTypeUndefined)
        return InterfaceType;

    Status = IoGetDeviceProperty(LowerPdo, DevicePropertyLegacyBusType, sizeof(InterfaceType), &InterfaceType, &ResultLength);
    if (NT_SUCCESS(Status))
    {
        ASSERT(ResultLength == sizeof(INTERFACE_TYPE));

        if (InterfaceType == PCMCIABus)
            InterfaceType = Isa;
    }

    if (InterfaceType == InterfaceTypeUndefined)
    {
        //ScsiDebugPrintInt(1, "SpGetPdoInterfaceType: Status %#08lx getting legacy bus type - assuming device is ISA\n", Status);
        DPRINT("SpGetPdoInterfaceType: Status %X getting legacy bus type - assuming device is ISA\n", Status);
        InterfaceType = Isa;
    }

    return InterfaceType;
}

PSCSI_HW_CHAIN_ENTRY
NTAPI
SpFindInitData(
    _In_ PSCSI_PORT_DRIVER_EXTENSION DriverExtension,
    _In_ INTERFACE_TYPE InterfaceType)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
SpInitializeAdapterExtension(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PSCSI_PORT_HW_DATA SpHwData)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpInitializeConfiguration(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PSCSI_PORT_CONFIG_CONTEXT CfgContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SpBuildConfiguration(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
SpGetSlotNumber(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig,
    _In_ PCM_RESOURCE_LIST AllocatedResources)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpCallHwFindAdapter(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PVOID HwContext,
    _In_ PSCSI_PORT_CONFIG_CONTEXT CfgContext,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig,
    _In_ BOOLEAN *OutIsAgain)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpAllocateAdapterResources(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpCallHwInitialize(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SpGetSupportedAdapterControlFunctions(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ScsiPortInitPnpAdapter(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PPORT_CONFIGURATION_INFORMATION PortConfig;
    PSCSI_HW_CHAIN_ENTRY ChainEntry;
    PSCSI_PORT_HW_DATA SpHwData;
    PVOID ImageSectionHandle;
    SCSI_PORT_CONFIG_CONTEXT CfgContext;
    ULONG SpHwInitDataSize;
    ULONG AccessRangesSize;
    ULONG InterfaceType;
    ULONG Size;
    KIRQL Irql;
    BOOLEAN IsAgain;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ScsiPortInitPnpAdapter: %p\n", DeviceObject);

    DeviceExtension = DeviceObject->DeviceExtension;
    SpDriverExtension = IoGetDriverObjectExtension(DeviceObject->DriverObject, ScsiPortInitialize);

    InterfaceType = SpGetPdoInterfaceType(DeviceExtension->LowerPdo);

    ChainEntry = SpFindInitData(SpDriverExtension, InterfaceType);
    if (!ChainEntry)
    {
        DPRINT1("ScsiPortInitPnpAdapter: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    RtlZeroMemory(&CfgContext, sizeof(CfgContext));

    if (ChainEntry->HwInitializationData.NumberOfAccessRanges)
    {
        AccessRangesSize = (ChainEntry->HwInitializationData.NumberOfAccessRanges * sizeof(ACCESS_RANGE));

        CfgContext.AccessRanges = ExAllocatePoolWithTag(PagedPool, AccessRangesSize, 'APcS');
        if (!CfgContext.AccessRanges)
        {
            DPRINT1("ScsiPortInitPnpAdapter: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    SpHwInitDataSize = (sizeof(SCSI_PORT_HW_DATA) + ChainEntry->HwInitializationData.DeviceExtensionSize);

    //_SEH2_TRY;

    SpHwData = ExAllocatePoolWithTag(NonPagedPool, SpHwInitDataSize, 'hPcS');

    if (!SpHwData)
    {
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: Could not allocate HwDeviceExtension\n");
        DPRINT1("ScsiPortInitialize: Could not allocate HwDeviceExtension\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        UNIMPLEMENTED_DBGBREAK();
    }
    else
    {
        RtlZeroMemory(SpHwData, SpHwInitDataSize);
        SpInitializeAdapterExtension(DeviceExtension, ChainEntry, SpHwData);

        Status = SpInitializeConfiguration(DeviceExtension, &SpDriverExtension->RegistryPath, ChainEntry, &CfgContext);

        if (!NT_SUCCESS(Status))
        {
            UNIMPLEMENTED_DBGBREAK();
        }
        else
        {
            Size = ((sizeof(*PortConfig) + (ChainEntry->HwInitializationData.NumberOfAccessRanges * sizeof(ACCESS_RANGE)) + 7) & ~7);
            PortConfig = ExAllocatePoolWithTag(NonPagedPool, Size, 'PpcS');

            if (!PortConfig)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                UNIMPLEMENTED_DBGBREAK();
            }
            else
            {
                DeviceExtension->PortConfig = PortConfig;

                RtlCopyMemory(PortConfig, &CfgContext.PortConfig, sizeof(*PortConfig));

                PortConfig->SrbExtensionSize = DeviceExtension->SrbExtensionSize;
                PortConfig->SpecificLuExtensionSize = DeviceExtension->SpecificLuExtensionSize;

                if (ChainEntry->HwInitializationData.NumberOfAccessRanges)
                {
                    PortConfig->AccessRanges = (PVOID)(((ULONG_PTR)&PortConfig[1] + 7) & ~7);
                    RtlCopyMemory(PortConfig->AccessRanges, CfgContext.AccessRanges, (ChainEntry->HwInitializationData.NumberOfAccessRanges * sizeof(ACCESS_RANGE)));
                }

                PortConfig->AdapterInterfaceType = InterfaceType;

                SpBuildConfiguration(DeviceExtension, ChainEntry, PortConfig);
                SpGetSlotNumber(DeviceObject, PortConfig, DeviceExtension->AllocatedResources);

                Status = SpCallHwFindAdapter(DeviceObject, ChainEntry, 0, &CfgContext, PortConfig, &IsAgain);

                if (Status == STATUS_DEVICE_DOES_NOT_EXIST)
                {
                    DeviceExtension->PortConfig = NULL;
                    ExFreePoolWithTag(PortConfig, 'PpcS');
                }
                else if (NT_SUCCESS(Status))
                {
                    Status = SpAllocateAdapterResources(DeviceObject);
                    if (NT_SUCCESS(Status))
                    {
                        if (DeviceExtension->CommonExtension.CurrentPnpState == 4)
                        {
                            ASSERT(DeviceExtension->CommonExtension.PreviousPnpState == 0);//IRP_MN_START_DEVICE

                            ASSERT(DeviceExtension->DisableCount == 1);
                            DeviceExtension->DisableCount = 0;

                            DeviceExtension->InterruptData.Flags &= ~0x4000;
                        }

                        Status = SpCallHwInitialize(DeviceObject);

                        if (DeviceExtension->CommonExtension.CurrentPnpState == 4)
                        {
                            ImageSectionHandle = MmLockPagableDataSection(ScsiPortInitPnpAdapter);

                            KeRaiseIrql(DISPATCH_LEVEL, &Irql);
                            IoStartNextPacket(DeviceObject, FALSE);
                            KeLowerIrql(Irql);

                            MmUnlockPagableImageSection(ImageSectionHandle);
                        }
                    }
                }
            }
        }
    }

    //_SEH2_FINALLY;

    if (NT_SUCCESS(Status))
    {
        SpGetSupportedAdapterControlFunctions(DeviceExtension);
    }
    else
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    return Status;
}

NTSTATUS
NTAPI
ScsiPortStartAdapter(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SpQueryDeviceRelationsCompletion(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_ENUM_REQUEST EnumRequest,
    _In_ NTSTATUS Unused)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
SpEnumerateAdapterAsynchronous(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_ENUM_REQUEST EnumRequest,
    _In_ BOOLEAN Unknown)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ScsiPortFdoPnp(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension;
    PCM_RESOURCE_LIST AllocatedResourcesTranslated;
    PCM_RESOURCE_LIST AllocatedResources;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PIO_STACK_LOCATION IoStack;
    ULONG PnpInterfaceFlags;
    ULONG Level;
    ULONG Vector;
    ULONG Affinity;
    LONG IsRemoved;
    BOOLEAN IsComplete = TRUE;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    PAGED_CODE();

    DeviceExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    IsRemoved = SpAcquireRemoveLockEx(Fdo, Irp, __FILE__, __LINE__);

    //ScsiDebugPrintInt(2, "ScsiPortFdoPnp: FDO %p IRP %p MinorFunction %x IsRemoved %d\n", Fdo, Irp, IoStack->MinorFunction, IsRemoved);
    DPRINT("ScsiPortFdoPnp: FDO %p IRP %p MinorFunction %X IsRemoved %X\n", Fdo, Irp, IoStack->MinorFunction, IsRemoved);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            DPRINT("ScsiPortFdoPnp: IRP_MN_START_DEVICE\n");

            SpDriverExtension = IoGetDriverObjectExtension(Fdo->DriverObject, ScsiPortInitialize);

            AllocatedResources = IoStack->Parameters.StartDevice.AllocatedResources;
            AllocatedResourcesTranslated = IoStack->Parameters.StartDevice.AllocatedResourcesTranslated;

            if (!(DeviceExtension->Flags2 & 4))
            {
                //ScsiDebugPrintInt(1, "ScsiPortFdoPnp - asked to start non-pnp adapter\n");
                DPRINT1("ScsiPortFdoPnp: asked to start non-pnp adapter\n");
                Status = STATUS_UNSUCCESSFUL;
                break;
            }

            if (!DeviceExtension->CommonExtension.CurrentPnpState)
            {
                //ScsiDebugPrintInt(1, "ScsiPortFdoPnp - already started - nothing to do\n");
                DPRINT("ScsiPortFdoPnp: already started - nothing to do\n");
                Status = STATUS_SUCCESS;
                break;
            }

            if (!AllocatedResources)
            {
                Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
                break;
            }

            ASSERT(AllocatedResources->Count);

            PnpInterfaceFlags = SpQueryPnpInterfaceFlags(SpDriverExtension, AllocatedResources->List[0].InterfaceType);
            if (!PnpInterfaceFlags)
            {
                //ScsiDebugPrintInt(1, "ScsiPortFdoPnp - Miniport cannot be run in pnp mode for interface type %#08lx\n", AllocatedResources->List[0].InterfaceType);
                DPRINT1("ScsiPortFdoPnp: Miniport cannot be run in pnp mode for interface type %X\n", AllocatedResources->List[0].InterfaceType);
                DeviceExtension->Flags2 &= ~4;
                Status = STATUS_UNSUCCESSFUL;
                break;
            }

            if (!(PnpInterfaceFlags & 4))
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            if (SpGetBusTypeGuid(DeviceExtension) == STATUS_OBJECT_NAME_NOT_FOUND &&
                SpDriverExtension->LegacyAdapterDetection == 1 &&
                (PnpInterfaceFlags & 2))
            {
                DPRINT1("ScsiPortFdoPnp: device has no pnp bus type but was not found as a duplicate during detection\n");
                //DbgPrint("ScsiPortFdoPnp: device has no pnp bus type but was not found as a duplicate during detection\n");
                DeviceExtension->Flags2 &= ~4;
                Status = STATUS_UNSUCCESSFUL;
                break;
            }

            if ((PnpInterfaceFlags & 8) && !SpGetInterrupt(AllocatedResources, &Level, &Vector, &Affinity))
            {
                DPRINT1("ScsiPortFdoPnp: STATUS_DEVICE_CONFIGURATION_ERROR\n");
                Status = STATUS_DEVICE_CONFIGURATION_ERROR;
                UNIMPLEMENTED_DBGBREAK();
                break;
            }

            Status = SpStartLowerDevice(Fdo, Irp);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ScsiPortFdoPnp: Status %X\n", Status);
                break;
            }

            if (!DeviceExtension->CommonExtension.IsInitialized)
            {
                //ScsiDebugPrintInt(1, "ScsiPortFdoPnp - find and init adapter %p\n", Fdo);
                DPRINT("ScsiPortFdoPnp: find and init adapter %p\n", Fdo);

                DeviceExtension->AllocatedResources = RtlDuplicateCmResourceList(NonPagedPool, AllocatedResources, 'rPcS');
                DeviceExtension->AllocatedResourcesTranslated = RtlDuplicateCmResourceList(NonPagedPool, AllocatedResourcesTranslated, 'rPcS');

                DeviceExtension->CommonExtension.IsInitialized = 1;

                Status = ScsiPortInitPnpAdapter(Fdo);
                if (!NT_SUCCESS(Status))
                {
                    //ScsiDebugPrintInt(1, "ScsiPortInitializeAdapter failed %#08lx\n", Status);
                    DPRINT1("ScsiPortFdoPnp: Status %X\n", Status);
                    break;
                }
            }

            Status = ScsiPortStartAdapter(Fdo);

            if (NT_SUCCESS(Status))
            {
                DeviceExtension->CommonExtension.PreviousPnpState = 0xFF;
                DeviceExtension->CommonExtension.CurrentPnpState = 0;
            }
            else
            {
                DPRINT1("ScsiPortFdoPnp: Status %X\n", Status);
            }

            break;
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_QUERY_REMOVE_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_REMOVE_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_CANCEL_REMOVE_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_STOP_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_QUERY_STOP_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_QUERY_STOP_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_CANCEL_STOP_DEVICE\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            PSCSI_PORT_ENUM_REQUEST EnumRequest;

            DPRINT("ScsiPortFdoPnp: IRP_MN_QUERY_DEVICE_RELATIONS\n");

            //ScsiDebugPrintInt(1, "ScsiPortFdoPnp - got IRP_MJ_QUERY_DEVICE_RELATIONS\n");
            //ScsiDebugPrintInt(1, "\ttype is %d\n", IoStack->Parameters.QueryDeviceRelations.Type);
            DPRINT1("ScsiPortFdoPnp - got IRP_MJ_QUERY_DEVICE_RELATIONS (type is %X)\n", IoStack->Parameters.QueryDeviceRelations.Type);

            if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
            {
                IsComplete = FALSE;
                break;
            }

            EnumRequest = InterlockedCompareExchangePointer((PVOID*)&DeviceExtension->AsyncEnumRequest, NULL, &DeviceExtension->EnumRequest);
            if (!EnumRequest)
            {
                ASSERT(FALSE && "Unexpected!! Concurrent QDR requests");
                Irp->IoStatus.Information = 0;
                Irp->IoStatus.Status = STATUS_DEVICE_BUSY;
                break;
            }
            RtlZeroMemory(EnumRequest, sizeof(*EnumRequest));

            EnumRequest->Irp = Irp;
            EnumRequest->IoStatus = &Irp->IoStatus;
            EnumRequest->CompletionRoutine = SpQueryDeviceRelationsCompletion;

            IoMarkIrpPending(Irp);

            SpEnumerateAdapterAsynchronous(DeviceExtension, EnumRequest, FALSE);

            return STATUS_PENDING;
        }
        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
        {
            DPRINT("ScsiPortFdoPnp: IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");

            IoResources = IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList;
            if (IoResources)
            {
                DeviceExtension->BusNumber = IoResources->BusNumber;
                DeviceExtension->SlotNumber = IoResources->SlotNumber;
            }

            IsComplete = FALSE;
            break;
        }
        case IRP_MN_QUERY_ID:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_QUERY_ID\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE:
        {
            DPRINT("ScsiPortFdoPnp: IRP_MN_QUERY_PNP_DEVICE_STATE\n");

            Irp->IoStatus.Information = DeviceExtension->PnpDeviceState;

            if (DeviceExtension->CommonExtension.PagingPathCount)
                Irp->IoStatus.Information = (DeviceExtension->PnpDeviceState | 0x20);

            IsComplete = FALSE;
            break;
        }
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            DPRINT1("ScsiPortFdoPnp: IRP_MN_SURPRISE_REMOVAL\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        default:
            //ScsiDebugPrintInt(1, "ScsiPortFdoPnp: Unimplemented PNP/POWER minor code %d\n", IoStack->MinorFunction);
            DPRINT1("ScsiPortFdoPnp: Unimplemented PNP/POWER minor code %X\n", IoStack->MinorFunction);
            IsComplete = FALSE;
            break;
    }

    if (IsComplete)
    {
        SpReleaseRemoveLock(Fdo, Irp);
        Irp->IoStatus.Status = Status;
        SpCompleteRequest(Fdo, Irp, NULL, IO_NO_INCREMENT);
        return Status;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    SpReleaseRemoveLock(Fdo, Irp);

    return IoCallDriver(DeviceExtension->CommonExtension.LowDevice, Irp);
}

/* DISPATCH FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ScsiPortGlobalDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PCOMMON_EXTENSION CommonExtension;
    CommonExtension = DeviceObject->DeviceExtension;
    return (CommonExtension->MajorFunction[IoGetCurrentIrpStackLocation(Irp)->MajorFunction])(DeviceObject, Irp);
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
