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
ULONG ScsiPortVerifierInitialized = 0;

PDEVICE_OBJECT* ScsiGlobalAdapterList = ULongToPtr(0xFFFFFFFF);
ULONG ScsiGlobalAdapterListElements = 0;
KSPIN_LOCK ScsiGlobalAdapterListSpinLock;
PVOID ScsiDirectory = NULL;
PSCSI_PORT_GUID_INTERFACE_MAPPING SpGuidInterfaceMappingList;
HANDLE ScsiDeviceMapKey = ULongToPtr(0xFFFFFFFF);
LONG SpPAGELOCKLockCount = 0;
LONG LockLowWatermark = 0;
BOOLEAN ScsiPortLegacyAdapterDetection = FALSE;
BOOLEAN Sp64BitPhysicalAddresses = FALSE;
BOOLEAN SpRemapBuffersByDefault = FALSE;
BOOLEAN SpLegacyInstanceId = FALSE;
BOOLEAN SpLunIoLogActive = FALSE;

PDRIVER_DISPATCH DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH Scsi1DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH AdapterMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];

DEFINE_GUID(GUID_DEVINTERFACE_STORAGEPORT, 0x2ACCFE60, 0xC130, 0x11D2, 0xB0, 0x82, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B);

SCSI_PORT_LUN_LIST ScsiPortDefaultLunList =
{
    {0, 0, 0, 0x80},
    {0, 0, 0, 0},
    {{ 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 1, 0, 0, 0, 0, 0, 0},
     { 0, 2, 0, 0, 0, 0, 0, 0},
     { 0, 3, 0, 0, 0, 0, 0, 0},
     { 0, 4, 0, 0, 0, 0, 0, 0},
     { 0, 5, 0, 0, 0, 0, 0, 0},
     { 0, 6, 0, 0, 0, 0, 0, 0},
     { 0, 7, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0},
     { 0, 0, 0, 0, 0, 0, 0, 0}
    }
};

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
SpWaitForRemoveLock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Tag)
{
    UNIMPLEMENTED_DBGBREAK();
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
SpFreeSrbData(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_SRB_DATA SrbData)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
FASTCALL
SpFreeBypassSrbData(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_SRB_DATA SrbData)
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
    PSCSI_PORT_SRB_DATA SrbData = Context;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_LUN_EXTENSION LunExtension;

    DeviceExtension = DeviceObject->DeviceExtension;

    DPRINT("SpCompleteRequest: %p, %p\n", DeviceExtension, SrbData);

    if (SrbData)
    {
        ASSERT(SrbData->Type == 0x7770);//SRB_DATA_TYPE
        ASSERT(SrbData->ScatterGatherList == NULL);
        ASSERT(SrbData->CurrentIrp == Irp);

        LunExtension = SrbData->LunExtension;
        ASSERT(LunExtension != NULL);

        ASSERT(LunExtension->CurrentUntaggedRequest != SrbData);
        ASSERT((((PCOMMON_EXTENSION) (LunExtension->CommonExtension.SelfDevice)->DeviceExtension)->IsPdo));

        ASSERT(SrbData->RemappedMdl == NULL);

        ASSERTMSG("Attempt to complete blocked request: ", ((LunExtension->ActiveFailedRequest != SrbData) && (LunExtension->BlockedFailedRequest != SrbData)));

        if (SrbData->CurrentSrb->Function == 0x18 || SrbData->CurrentSrb->Function == 0x19)
        {
            ASSERT(LunExtension->CurrentLockRequest == SrbData);
            UNIMPLEMENTED_DBGBREAK();
        }

        SrbData->CurrentSrb->OriginalRequest = SrbData->CurrentIrp;
        SrbData->CurrentIrp = NULL;
        SrbData->CurrentSrb = NULL;

        ASSERT(SrbData->FreeRoutine != NULL);
        ASSERT((SrbData->FreeRoutine == SpFreeSrbData) || (SrbData->FreeRoutine == SpFreeBypassSrbData));

        SrbData->FreeRoutine(LunExtension->DeviceExtension, SrbData);
        SpReleaseRemoveLock(LunExtension->CommonExtension.SelfDevice, Irp);
    }

    IoCompleteRequest(Irp, PriorityBoost);
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
SpCompleteEnumRequest(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpCreateLogicalUnit(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR Path,
    _In_ UCHAR Target,
    _In_ UCHAR Lun,
    _In_ BOOLEAN IsTemporary,
    _In_ BOOLEAN IsScsi1,
    _Out_ PSCSI_PORT_LUN_EXTENSION* OutLunExtension)
{
    PSCSI_PORT_SRB_DATA SpecificLuExtension = NULL;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    PVOID DeviceIdentifierPage = NULL;
    UNICODE_STRING DestinationString;
    PCHAR SerialNumber = NULL;
    PDEVICE_OBJECT Pdo = NULL;
    WCHAR SourceString[64];
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpCreateLogicalUnit: Beginning scan of adapter %p\n", DeviceExtension);

    Irp = IoAllocateIrp(1, FALSE);
    if (!Irp)
    {
        //ScsiDebugPrintInt(0, "SpCreateLogicalUnit: Could not allocate request sense irp\n");
        DPRINT1("SpCreateLogicalUnit: Could not allocate request sense irp\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("SpCreateLogicalUnit: Request sense Irp %p\n", Irp);

    if (IsTemporary)
    {
        swprintf(SourceString, L"%wsPort%xRescan", DeviceExtension->DeviceNameBuffer, DeviceExtension->PortScsiPort);
        ASSERT(DeviceExtension->RescanLun == NULL);
    }
    else
    {
        swprintf(SourceString, L"%wsPort%xPath%xTarget%xLun%x", DeviceExtension->DeviceNameBuffer, DeviceExtension->PortScsiPort, Path, Target, Lun);
    }

    RtlInitUnicodeString(&DestinationString, SourceString);

    if (DeviceExtension->SpecificLuExtensionSize)
    {
        SpecificLuExtension = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, DeviceExtension->SpecificLuExtensionSize, 'HPcS');
        if (!SpecificLuExtension)
        {
            DPRINT1("SpCreateLogicalUnit: STATUS_INSUFFICIENT_RESOURCES\n");
            IoFreeIrp(Irp);
            *OutLunExtension = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(SpecificLuExtension, DeviceExtension->SpecificLuExtensionSize);

        DPRINT("SpCreateLogicalUnit: SpecificLuExtension %p, SpecificLuExtensionSize %X\n", SpecificLuExtension, DeviceExtension->SpecificLuExtensionSize);
    }

    if (IsTemporary)
    {
        SerialNumber = ExAllocatePoolWithTag(PagedPool, 0xFF, 'yPcS');
        if (!SerialNumber)
        {
            DPRINT1("SpCreateLogicalUnit: STATUS_INSUFFICIENT_RESOURCES\n");

            if (SpecificLuExtension)
                ExFreePoolWithTag(SpecificLuExtension, 'HPcS');

            IoFreeIrp(Irp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DeviceIdentifierPage = ExAllocatePoolWithTag(PagedPool, 0xFF, 'yPcS');
        if (!DeviceIdentifierPage)
        {
            DPRINT1("SpCreateLogicalUnit: STATUS_INSUFFICIENT_RESOURCES\n");

            if (SpecificLuExtension)
                ExFreePoolWithTag(SpecificLuExtension, 'HPcS');

            IoFreeIrp(Irp);
            ExFreePoolWithTag(SerialNumber, 'yPcS');

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(SerialNumber, 0xFF);
        RtlZeroMemory(DeviceIdentifierPage, 0xFF);
    }

    Status = IoCreateDevice(DeviceExtension->CommonExtension.SelfDevice->DriverObject,
                            sizeof(SCSI_PORT_LUN_EXTENSION),
                            &DestinationString,
                            FILE_DEVICE_MASS_STORAGE,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &Pdo);
    if (!NT_SUCCESS(Status))
    {
        //ScsiDebugPrintInt(1, "ScsiBusCreatePdo: Error %#08lx creating device object\n", Status);
        DPRINT1("SpCreateLogicalUnit: Status %X\n", Status);

        if (SpecificLuExtension)
            ExFreePoolWithTag(SpecificLuExtension, 'HPcS');

        IoFreeIrp(Irp);

        ExFreePoolWithTag(SerialNumber, 'yPcS');
        ExFreePoolWithTag(DeviceIdentifierPage, 'yPcS');

        *OutLunExtension = NULL;

        return Status;
    }

    Pdo->StackSize = 1;
    Pdo->Flags |= 0x1000;
    Pdo->Flags |= 0x10;

    Pdo->AlignmentRequirement = DeviceExtension->CommonExtension.SelfDevice->AlignmentRequirement;

    LunExtension = Pdo->DeviceExtension;
    RtlZeroMemory(LunExtension, sizeof(*LunExtension));

    LunExtension->CommonExtension.IsPdo = 1;
    LunExtension->CommonExtension.SelfDevice = Pdo;
    LunExtension->CommonExtension.LowDevice = DeviceExtension->CommonExtension.SelfDevice;

    if (IsScsi1)
        LunExtension->CommonExtension.MajorFunction = Scsi1DeviceMajorFunctionTable;
    else
        LunExtension->CommonExtension.MajorFunction = DeviceMajorFunctionTable;

    LunExtension->CommonExtension.WmiInitialized = 0;

    if (DeviceExtension->CommonExtension.WmiDataProvider)
        LunExtension->CommonExtension.WmiDataProvider = 1;

    ExInitializeNPagedLookasideList(&LunExtension->CommonExtension.LookAsideList, NULL, NULL, 0, 0x18, 'lPcS', 0x40);//FIXME

    LunExtension->CommonExtension.CurrentPnpState = 0xFF;
    LunExtension->CommonExtension.PreviousPnpState = 0xFF;

    KeInitializeEvent(&LunExtension->CommonExtension.Event, SynchronizationEvent, FALSE);

    LunExtension->RequestTimeoutCounter = 0xFFFFFFFF;
    LunExtension->Port = DeviceExtension->PortScsiPort;
    LunExtension->SpecificLuExtension = SpecificLuExtension;

    LunExtension->PathId = 0xFF;
    LunExtension->TargetId = 0xFF;
    LunExtension->Lun = 0xFF;

    LunExtension->DeviceExtension = DeviceExtension;
    LunExtension->QueueDepth = 0xFF;

    InitializeListHead(&LunExtension->SrbDataList);
    InitializeListHead(&LunExtension->BlockedRequests);

    LunExtension->CommonExtension.CurrentDeviceState = 1;
    LunExtension->CommonExtension.CurrentSystemState = 1;

    LunExtension->Capacity = 0xFFFFFFFF;
    LunExtension->IsTemporary = IsTemporary;

    LunExtension->QueueZoneCount = 4;
    LunExtension->QueueZoneLength = 0x3FFFFFFF;

    LunExtension->MinQueueSector[0] = 0;
    LunExtension->MinQueueSector[1] = 0x3FFFFFFF;
    LunExtension->MinQueueSector[2] = 0x7FFFFFFE;
    LunExtension->MinQueueSector[3] = 0xBFFFFFFD;

    LunExtension->MaxQueueSector[0] = 0x3FFFFFFE;
    LunExtension->MaxQueueSector[1] = 0x7FFFFFFD;
    LunExtension->MaxQueueSector[2] = 0xBFFFFFFC;
    LunExtension->MaxQueueSector[3] = 0xFFFFFFFE;

    LunExtension->QueueZones[0] = 1;
    LunExtension->QueueZones[1] = 2;
    LunExtension->QueueZones[2] = 3;
    LunExtension->QueueZones[3] = 0;

    RtlInitAnsiString(&LunExtension->SerialNumber, SerialNumber);

    if (SerialNumber)
        LunExtension->SerialNumber.MaximumLength = 0xFF;

    LunExtension->DeviceIdentifierPage = DeviceIdentifierPage;

    Pdo->Flags &= ~DO_DEVICE_INITIALIZING;

    *OutLunExtension = LunExtension;

    return Status;
}

VOID
FASTCALL
GetNextLuRequest(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
GetNextLuRequestWithoutLock(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PWSTR SourceString,
    _Out_ PKEY_VALUE_FULL_INFORMATION* OutKeyValueInfo)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueInfo;
    UNICODE_STRING DestinationString;
    ULONG ResultLength;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpGetRegistryValue: '%S'\n", SourceString);

    RtlInitUnicodeString(&DestinationString, SourceString);

    Status = ZwQueryValueKey(KeyHandle, &DestinationString, KeyValueFullInformation, 0, 0, &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
    {
        DPRINT1("SpGetRegistryValue: Status %X\n", Status);
        *OutKeyValueInfo = NULL;
        return Status;
    }

    KeyValueInfo = ExAllocatePoolWithTag(NonPagedPool, ResultLength, 'RPcS');
    if (!KeyValueInfo)
    {
        DPRINT1("SpGetRegistryValue: STATUS_INSUFFICIENT_RESOURCES\n");
        *OutKeyValueInfo = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryValueKey(KeyHandle, &DestinationString, KeyValueFullInformation, KeyValueInfo, ResultLength, &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpGetRegistryValue: Status %X\n", Status);
        ExFreePoolWithTag(KeyValueInfo, 'RPcS');
        *OutKeyValueInfo = NULL;
        return Status;
    }

    *OutKeyValueInfo = KeyValueInfo;

    return STATUS_SUCCESS;
}

VOID
NTAPI
SpSignalPowerCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _Out_ IO_STATUS_BLOCK* IoStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpRequestValidAdapterPowerStateSynchronous(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    SCSI_PORT_COMPLETION_CONTEXT Context;
    POWER_STATE State;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("SpRequestValidAdapterPowerStateSynchronous: %p\n", DeviceExtension);

    ExAcquireFastMutex(&DeviceExtension->PoFastMutex);

    //_SEH2_TRY;

    if (DeviceExtension->CommonExtension.CurrentSystemState != 1)
    {
        DPRINT1("SpRequestValidAdapterPowerStateSynchronous: STATUS_UNSUCCESSFUL\n");
        Status = STATUS_UNSUCCESSFUL;
    }
    else if (DeviceExtension->CommonExtension.CurrentDeviceState != 1)
    {
        //ScsiDebugPrintInt(1, "SpRequestValidAdapterPowerState: Requesting D0 power irp for adapter %p\n", DeviceExtension);
        DPRINT("SpRequestValidAdapterPowerState: Requesting D0 power irp for adapter %p\n", DeviceExtension);

        KeInitializeEvent(&Context.Event, SynchronizationEvent, FALSE);
 
        State.DeviceState = 1;

        Status = PoRequestPowerIrp(DeviceExtension->CommonExtension.SelfDevice,
                                   IRP_MN_SET_POWER,
                                   State,
                                   SpSignalPowerCompletion,
                                   &Context,
                                   NULL);

        if (Status == STATUS_PENDING)
           KeWaitForSingleObject(&Context.Event, Executive, KernelMode, FALSE, NULL);

        Status = Context.Status;
    }

    //_SEH2_FINALLY;

    ExReleaseFastMutex(&DeviceExtension->PoFastMutex);

    return Status;
}

PSCSI_PORT_LUN_EXTENSION
NTAPI
SpCreateInitiatorLU(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
SpSetVerificationMarks(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId)
{
    PSCSI_PORT_LUN_ENTRY LunEntry;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    KIRQL Irql;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpSetVerificationMarks: %p, %X, %X\n", DeviceExtension, PathId, TargetId);

    ASSERT(SpPAGELOCKLockCount != 0);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    LunEntry = DeviceExtension->LunList;
    ix = 8;
    do
    {
        KeAcquireSpinLockAtDpcLevel(&LunEntry->SpinLock);

        for (LunExtension = LunEntry->LunExtension; LunExtension; LunExtension = LunExtension->NextLogicalUnit)
        {
            ASSERT(LunExtension->IsTemporary == FALSE);

            if (LunExtension->PathId == PathId && LunExtension->TargetId == TargetId)
                LunExtension->NeedsVerification = 1;
        }

        KeReleaseSpinLockFromDpcLevel(&LunEntry->SpinLock);

        LunEntry++;
        ix--;
    }
    while (ix);

    KeLowerIrql(Irql);
}

PSCSI_PORT_LUN_EXTENSION
NTAPI
GetLogicalUnitExtensionEx(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ PVOID Tag,
    _In_ BOOLEAN IsLock,
    _In_ PSTR File,
    _In_ ULONG Line)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
SpSetLogicalUnitAddress(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IssueInquiry(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension,
    _In_ BOOLEAN EnableVitalProductData,
    _In_ UCHAR PageCode,
    _Out_ PVOID OutInquiry,
    _Out_ UCHAR* OutBytesReturned)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SpCheckSpecialDeviceFlags(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension,
    _In_ PINQUIRYDATA InquiryData)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
SpGetDeviceIdentifiers(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension,
    _In_ BOOLEAN IsNewDevice)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
SpClearLogicalUnitAddress(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
SpRemoveLogicalUnit(
    _In_ PSCSI_PORT_LUN_EXTENSION logicalUnit, UCHAR Minor)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS
NTAPI
SpCloneAndSwapLogicalUnit(
    _In_ PSCSI_PORT_LUN_EXTENSION TemplateLun,
    _In_ PINQUIRYDATA InquiryData,
    _In_ ULONG InquiryDataSize,
    _Out_ PSCSI_PORT_LUN_EXTENSION* OutLunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpInquireLogicalUnit(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ BOOLEAN Param5,
    _In_ PSCSI_PORT_LUN_EXTENSION RescanLun,
    _Out_ PSCSI_PORT_LUN_EXTENSION* OutLunExtension,
    _Out_ BOOLEAN* OutIsCheckingNext)
{
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    PSCSI_PORT_LUN_EXTENSION LunForSwap;
    INQUIRYDATA InquiryData;
    UCHAR InquiryDataSize;
    BOOLEAN IsMismatchedDevice = FALSE;
    BOOLEAN IsExistingDevice;
    BOOLEAN IsNewDevice = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpInquireLogicalUnit: %p (%X:%X:%X) %p\n", DeviceExtension, PathId, TargetId, Lun, RescanLun);

    *OutLunExtension = NULL;
    *OutIsCheckingNext = TRUE;

    //ASSERT("TargetId != BreakOnTarget");

    LunExtension = GetLogicalUnitExtensionEx(DeviceExtension, PathId, TargetId, Lun, SpInquireLogicalUnit, TRUE, __FILE__, __LINE__);

    if (LunExtension)
    {
        if (LunExtension->IsMissing)
        {
            //ScsiDebugPrintInt(1, "SpInquireLogicalUnit: logical unit @ (%d,%d,%d) (%#p) is marked as missing and will not be rescanned\n", PathId, TargetId, Lun, LunExtension->CommonExtension.SelfDevice);
            DPRINT1("SpInquireLogicalUnit: logical unit @ (%X,%X,%X) (%p) is marked as missing and will not be rescanned\n", PathId, TargetId, Lun, LunExtension->CommonExtension.SelfDevice);
            SpReleaseRemoveLock(LunExtension->CommonExtension.SelfDevice, SpInquireLogicalUnit);
            return STATUS_DEVICE_DOES_NOT_EXIST;
        }
    }
    else
    {
        if (!RescanLun)
        {
            DPRINT1("SpInquireLogicalUnit: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ASSERT(RescanLun->IsTemporary == TRUE);

        SpAcquireRemoveLockEx(RescanLun->CommonExtension.SelfDevice, ULongToPtr(0xABCDABCD), __FILE__, __LINE__);
        SpAcquireRemoveLockEx(RescanLun->CommonExtension.SelfDevice, SpInquireLogicalUnit, __FILE__, __LINE__);

        SpSetLogicalUnitAddress(RescanLun, PathId, TargetId, Lun);

        LunForSwap = LunExtension = RescanLun;
        IsNewDevice = TRUE;
    }

    //ScsiDebugPrintInt(2, "SpInquireTarget: Try %s device @ Bus %d, Target %d, Lun %d\n", (LunExtension ? "existing" : "new"), PathId, TargetId, Lun);
    DPRINT("SpInquireLogicalUnit: Try %s device @ Bus %X, Target %X, Lun %X\n", (LunExtension ? "existing" : "new"), PathId, TargetId, Lun);

    Status = IssueInquiry(LunExtension, FALSE, 0, &InquiryData, &InquiryDataSize);
    DPRINT("SpInquireLogicalUnit: %p (%X:%X:%X) %X\n", DeviceExtension, PathId, TargetId, Lun, InquiryDataSize);

    if (!NT_SUCCESS(Status))
    {
        *OutIsCheckingNext = FALSE;
    }
    else
    {
        SpCheckSpecialDeviceFlags(LunExtension, &InquiryData);

        if (InquiryData.DeviceTypeQualifier == 0)
        {
            IsExistingDevice = TRUE;
        }
        else if (InquiryData.DeviceTypeQualifier == 1)
        {
            if (Lun == 0)
            {
               if (InquiryData.HiSupport || LunExtension->SpecialTargetList[2] == 1)
                   IsExistingDevice = TRUE;
               else
                   IsExistingDevice = FALSE;
            }
            else
            {
                IsExistingDevice = Param5;
            }
        }
        else if (InquiryData.DeviceTypeQualifier == 3)
        {
            IsExistingDevice = FALSE;
        }
        else
        {
            IsExistingDevice = TRUE;
        }

        if (!IsExistingDevice)
        {
            Status = STATUS_NO_SUCH_DEVICE;
        }
        else if (!IsNewDevice)
        {
            IsMismatchedDevice = FALSE;

            if (InquiryData.DeviceType != LunExtension->InquiryData.DeviceType)
            {
                //ScsiDebugPrintInt(1, "SpInquireTarget: Found different type of device @ (%d,%d,%d)\n", PathId, TargetId, Lun);
                DPRINT1("SpInquireLogicalUnit: Found different type of device @ (%X,%X,%X)\n", PathId, TargetId, Lun);

                IsMismatchedDevice = TRUE;
                Status = STATUS_NO_SUCH_DEVICE;
            }
            else if (InquiryData.DeviceTypeQualifier != LunExtension->InquiryData.DeviceTypeQualifier)
            {
                //ScsiDebugPrintInt(1, "SpInquireLogicalUnit: Device @ (%d,%d,%d) type qualifier was %d is now %d\n", PathId, TargetId, Lun, LunExtension->InquiryData.DeviceTypeQualifier, InquiryData.DeviceTypeQualifier);
                DPRINT1("SpInquireLogicalUnit: Device @ (%X,%X,%X) type qualifier was %X is now %X\n", PathId, TargetId, Lun, LunExtension->InquiryData.DeviceTypeQualifier, InquiryData.DeviceTypeQualifier);

                UNIMPLEMENTED_DBGBREAK();
            }
        }
        else
        {
            //ScsiDebugPrintInt((1, "SpInquireTarget: Found new %sDevice at address (%d,%d,%d)\n", (InquiryData.RemovableMedia ? "Removable " : ""), PathId, TargetId, Lun));
            DPRINT("SpInquireTarget: Found new %sDevice at address (%X,%X,%X)\n", (InquiryData.RemovableMedia ? "Removable " : ""), PathId, TargetId, Lun);
        }

        if (NT_SUCCESS(Status) && !IsMismatchedDevice)
        {
            IsMismatchedDevice = SpGetDeviceIdentifiers(LunExtension, IsNewDevice);
            if (!IsMismatchedDevice)
            {
                UNIMPLEMENTED_DBGBREAK();
            }
        }
    }

    if (!NT_SUCCESS(Status))
    {
        LunExtension->IsMissing = FALSE;

        DPRINT("SpInquireLogicalUnit: (%X:%X:%X) %X IsNewDevice %X\n", PathId, TargetId, Lun, Status, IsNewDevice);

        if (IsNewDevice)
        {
            SpReleaseRemoveLock(LunExtension->CommonExtension.SelfDevice, SpInquireLogicalUnit);
            LunExtension = NULL;

            SpWaitForRemoveLock(RescanLun->CommonExtension.SelfDevice, ULongToPtr(0xABCDABCD));
            SpClearLogicalUnitAddress(RescanLun);
        }
        else if (!LunExtension->IsEnumerated)
        {
            LunExtension->CommonExtension.CurrentPnpState = 2;

            SpReleaseRemoveLock(LunExtension->CommonExtension.SelfDevice, SpInquireLogicalUnit);

            LunExtension->IsVisible = TRUE;

            ASSERT(LunExtension->IsEnumerated == FALSE);
            ASSERT(LunExtension->IsMissing == TRUE);
            ASSERT(LunExtension->IsVisible == TRUE);

            SpRemoveLogicalUnit(LunExtension, IRP_MN_REMOVE_DEVICE);

            if (IsMismatchedDevice)
                Status = SpInquireLogicalUnit(DeviceExtension, PathId, TargetId, Lun, Param5, RescanLun, OutLunExtension, OutIsCheckingNext);

            DPRINT("SpInquireLogicalUnit: Status %X\n", Status);
            return Status;
        }
        else if (IsMismatchedDevice)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }
    else
    {
        LunExtension->IsMissing = FALSE;

        if (IsNewDevice)
        {
            Status = SpCloneAndSwapLogicalUnit(LunExtension, &InquiryData, InquiryDataSize, &LunForSwap);

            if (NT_SUCCESS(Status))
                LunExtension = LunForSwap;
            else
                LunExtension = NULL;

            ASSERT(LunExtension != RescanLun);

            IsNewDevice = FALSE;
        }
        else
        {
            if (InquiryData.DeviceTypeQualifier != LunExtension->InquiryData.DeviceTypeQualifier)
            {
                LunExtension->InquiryData.DeviceTypeQualifier = InquiryData.DeviceTypeQualifier;
                UNIMPLEMENTED_DBGBREAK();
            }
        }

        if (LunExtension)
        {
            if (LunExtension->InquiryData.DeviceTypeQualifier == 1)
            {
                LunExtension->IsVisible = FALSE;
                SpBuildDeviceMapEntry(LunExtension);
            }
            else
            {
                LunExtension->IsVisible = TRUE;
            }

            if (InquiryData.RemovableMedia & 0x80)
                LunExtension->CommonExtension.SelfDevice->Characteristics |= 1;

            ASSERT(LunExtension->IsTemporary != TRUE);
        }

        *OutLunExtension = LunExtension;
    }

    if (LunExtension)
    {
        ASSERT(LunExtension != RescanLun);
        SpReleaseRemoveLock(LunExtension->CommonExtension.SelfDevice, SpInquireLogicalUnit);
    }

    DPRINT("SpInquireLogicalUnit: Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
SpPrepareLogicalUnitForReuse(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SpClearVerificationMark(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IssueReportLuns(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension,
    _Out_ PLUN_LIST* OutLunList)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpScanTarget(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ BOOLEAN IsScanDisconnectedDevices,
    _In_ PSCSI_PORT_LUN_EXTENSION RescanLun)
{
    PSCSI_PORT_LUN_EXTENSION LunExtensionZero;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    PLUN_LIST LunList = NULL;
    LUN_LIST_ENTRY Entry;
    LUN_LIST_LENGTH Luns;
    ULONG ix = 0;
    USHORT Lun;
    BOOLEAN IsCheckingNext;
    BOOLEAN IsSavingLunList;
    BOOLEAN IsSparseLuns;
    NTSTATUS status;
    NTSTATUS Status;

    //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:   Beginning scan of target %x\n", TargetId);
    DPRINT("SpScanTarget: Beginning scan of target %X\n", TargetId);

    ASSERT(RescanLun->CommonExtension.MajorFunction == DeviceMajorFunctionTable);

    status = SpInquireLogicalUnit(DeviceExtension, PathId, TargetId, 0, 1, RescanLun, &LunExtensionZero, &IsCheckingNext);
    DPRINT("SpScanTarget: status %X\n", status);

    Status = SpPrepareLogicalUnitForReuse(RescanLun);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("SpScanTarget: Status %X\n", Status);
        RescanLun = 0;
    }

    if (!NT_SUCCESS(status) && (!IsCheckingNext || !LunExtensionZero))
    {
        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Lun 0 not found - terminating scan (status %#08lx)\n", status);
        DPRINT("SpScanTarget: Lun 0 not found - terminating scan (status %X)\n", status);
        return Status;
    }

    SpClearVerificationMark(LunExtensionZero);

    if (LunExtensionZero->SpecialTargetList[1])
    {
        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) is listed as having only one lun\n", PathId, TargetId);
        DPRINT("SpScanTarget: Target (%X,%X,*) is listed as having only one lun\n", PathId, TargetId);
        return Status;
    }

    RescanLun->CommonExtension.MajorFunction = LunExtensionZero->CommonExtension.MajorFunction;

    if (LunExtensionZero->SpecialTargetList[0] != 0)
    {
        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) will be checked for sparse luns\n", PathId, TargetId);
        DPRINT("SpScanTarget: Target (%X:%X:*) will be checked for sparse luns\n", PathId, TargetId);
    }

    if (LunExtensionZero->InquiryData.HiSupport || LunExtensionZero->SpecialTargetList[2])
    {
         //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) may support REPORT_LUNS\n", PathId, TargetId);
         DPRINT("SpScanTarget: Target (%X:%X:*) may support REPORT_LUNS\n", PathId, TargetId);

         IsSavingLunList = 1;

         status = IssueReportLuns(LunExtensionZero, &LunList);
         if (!NT_SUCCESS(status))
         {
             //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) returned  %#08lx to REPORT_LUNS command - using old list\n", PathId, TargetId, status);
             DPRINT("SpScanTarget: Target (%X:%X:*) returned  %X to REPORT_LUNS command - using old list\n", PathId, TargetId, status);

             LunList = LunExtensionZero->TargetLunList;
         }

        if (LunList)
        {
            //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) will be checked for sparse luns(2)\n", PathId, TargetId);
            DPRINT("SpScanTarget:    Target (%X,%X,*) will be checked for sparse luns(2)\n", PathId, TargetId);
            IsSparseLuns = 1;
        }
    }

    if (!LunList)
    {
        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) will use default lun list\n", PathId, TargetId);
        DPRINT("SpScanTarget: Target (%X,%X,*) will use default lun list\n", PathId, TargetId);

        LunList = (PLUN_LIST)&ScsiPortDefaultLunList;

        IsSavingLunList = 0;
        IsSparseLuns = (LunExtensionZero->SpecialTargetList[0] != 0);
    }

    Luns.LunListLength[0]  = LunList->LunListLength[3];
    Luns.LunListLength[1] |= LunList->LunListLength[2];
    Luns.LunListLength[2] |= LunList->LunListLength[1];
    Luns.LunListLength[3] |= LunList->LunListLength[0];
    Luns.AsUlong /= 8;

    //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:    Target (%x,%x,*) has reported %d luns\n", PathId, TargetId, Luns.AsUlong);
    DPRINT("SpScanTarget: Target (%X,%X,*) has reported %X luns (%X, %X)\n", PathId, TargetId, Luns.AsUlong, IsSparseLuns, IsSavingLunList);

    for (ix = 0; ix < Luns.AsUlong; ix++)
    {
        Entry.LunListEntry[0] = LunList->LunListLength[1];
        Entry.LunListEntry[1] = LunList->LunListLength[0];

        Lun = Entry.AsUshort & 0x3FFF;

        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:     Checking lun %I64lx (%x): ", *(PULONGLONG)(LunList->Lun[ix]), Lun);
        DPRINT("SpScanTarget: Checking lun %I64X (%X): ", *(PULONGLONG)(LunList->Lun[ix]), Lun);

        if (!Lun)
        {
            //ScsiDebugPrintInt(EnumDebug, "Skipping LUN 0\n");
            DPRINT("Skipping LUN 0\n");
            continue;
        }

        if (Lun < DeviceExtension->PortConfig->MaximumNumberOfLogicalUnits)
        {
            status = SpInquireLogicalUnit(DeviceExtension, PathId, TargetId, Lun, IsScanDisconnectedDevices, RescanLun, &LunExtension, &IsCheckingNext);
            if (RescanLun)
            {
                Status = SpPrepareLogicalUnitForReuse(RescanLun);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("SpScanTarget: Status %X\n", Status);
                    RescanLun = 0;
                }
            }

            if (!NT_SUCCESS(status))
            {
                //ScsiDebugPrintInt(EnumDebug, "inquiry returned %#08lx.", status);
                DPRINT("inquiry returned %#08lx.", status);

                if (!IsSparseLuns && !IsCheckingNext)
                {
                    //ScsiDebugPrintInt(EnumDebug, "Aborting\n");
                    DPRINT("Aborting\n");
                    break;
                }

                //ScsiDebugPrintInt(EnumDebug, " - checking next (%c%c)\n", IsSparseLuns != 0 ? 0x73 : 0x20, IsCheckingNext != 0 ? 0x63 : 0x20);//'s' 'c'
                DPRINT(" - checking next (%c%c)\n", IsSparseLuns != 0 ? 's' : ' ', IsCheckingNext != 0 ? 'c' : ' ');
            }
            else
            {
                //ScsiDebugPrintInt(EnumDebug, "Inquiry succeeded\n");
                DPRINT("Inquiry succeeded\n");
                SpClearVerificationMark(LunExtension);
            }
        }
        else
        {
            //ScsiDebugPrintInt(EnumDebug, "Skipping LUN out of range (> %x)\n", DeviceExtension->PortConfig->MaximumNumberOfLogicalUnits);
            DPRINT("Skipping LUN out of range (> %X)\n", DeviceExtension->PortConfig->MaximumNumberOfLogicalUnits);
        }
    }

    if (IsSavingLunList)
    {
        //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:   Saving LUN list %#08lx\n", LunList);
        DPRINT("SpScanTarget: Saving LUN list %p\n", LunList);

        ASSERT(LunExtensionZero->TargetLunList != (PLUN_LIST) &(ScsiPortDefaultLunList));

        if (LunExtensionZero->TargetLunList && LunExtensionZero->TargetLunList != LunList)
        {
            //ScsiDebugPrintInt(EnumDebug, "SpScanTarget:   Freeing old LUN list %#08lx\n", LunExtensionZero->TargetLunList);
            DPRINT("SpScanTarget:   Freeing old LUN list %X\n", LunExtensionZero->TargetLunList);

            ExFreePoolWithTag(LunExtensionZero->TargetLunList, 0);
        }

        LunExtensionZero->TargetLunList = LunList;
    }
    else
    {
        ASSERT(LunList == (PLUN_LIST) &(ScsiPortDefaultLunList));
    }

    RescanLun->CommonExtension.MajorFunction = DeviceMajorFunctionTable;

    return Status;
}

VOID
NTAPI
SpPurgeTarget(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpScanBus(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR Bus,
    _In_ BOOLEAN IsScanDisconnectedDevices,
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UCHAR TargetId;
    UCHAR TargetIndex;
    NTSTATUS Status = STATUS_SUCCESS;

    //ScsiDebugPrintInt(EnumDebug, "SpScanBus: Beginning scan of bus %x\n", Bus);
    DPRINT1("SpScanBus: Beginning scan of bus %X\n", Bus);

    for (TargetIndex = 0; TargetIndex < DeviceExtension->MaximumNumberOfTargets; TargetIndex++)
    {
        if (DeviceExtension->IoScsiCapabilities.AdapterScansDown)
            TargetId = (DeviceExtension->MaximumNumberOfTargets - TargetIndex - 1);
        else
            TargetId = TargetIndex;

        //ScsiDebugPrintInt(EnumDebug, "SpScanBus: TargetIndex = %x -> targetId = %x\n", TargetIndex, TargetId);
        DPRINT("SpScanBus: TargetIndex %X -> targetId %X\n", TargetIndex, TargetId);

        ASSERT(TargetId != 0xFF);
        ASSERT(DeviceExtension->PortConfig);

        DbgPrint("SpScanBus: %X, %X\n", TargetId, DeviceExtension->PortConfig->InitiatorBusId[Bus]);

        if (TargetId == DeviceExtension->PortConfig->InitiatorBusId[Bus])
        {
            //ScsiDebugPrintInt(EnumDebug, "SpScanBus:   Target ID matches initiator ID - skipping\n");
            DPRINT("SpScanBus: Target ID matches initiator ID - skipping\n");
        }
        else
        {
            SpSetVerificationMarks(DeviceExtension, Bus, TargetId);
            LunExtension->NeedsVerification = TRUE;

            Status = SpScanTarget(DeviceExtension, Bus, TargetId, IsScanDisconnectedDevices, LunExtension);

            SpPurgeTarget(DeviceExtension, Bus, TargetId);

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("SpScanBus: ret Status %X\n", Status);
                return Status;
            }
        }
    }

    DPRINT1("SpScanBus: ret Status %X\n", Status);
    return Status;
}

VOID
NTAPI
SpDeleteLogicalUnit(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
SpScanAdapter(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueInfo;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PVOID ImageSectionHandle;
    PWSTR NameString[3];
    UNICODE_STRING KeyName;
    HANDLE DevInstRegKey;
    HANDLE KeyHandle;
    UCHAR ix;
    BOOLEAN IsScanDisconnectedDevices = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    //ScsiDebugPrintInt(EnumDebug, "SpScanAdapter: Beginning scan of adapter %#p\n", DeviceExtension);
    DPRINT("SpScanAdapter: %p\n", DeviceExtension);

    Status = SpCreateLogicalUnit(DeviceExtension, 0xFF, 0xFF, 0xFF, TRUE, FALSE, &LunExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpScanAdapter: Status %X\n", Status);
        return;
    }

    DPRINT("SpScanAdapter: LunExtension %p\n", LunExtension);

    ImageSectionHandle = MmLockPagableDataSection(GetNextLuRequestWithoutLock);
    InterlockedIncrement(&SpPAGELOCKLockCount);

    NameString[0] = L"Scsiport";
    NameString[1] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ScsiPort\\";
    NameString[2] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Disk";

    for (ix = 0; ix < 3; ix++)
    {
        DevInstRegKey = NULL;
        KeyValueInfo = NULL;

        if (!ix)
        {
            Status = IoOpenDeviceRegistryKey(DeviceExtension->LowerPdo, PLUGPLAY_REGKEY_DEVICE, KEY_READ, &DevInstRegKey);
            if (!NT_SUCCESS(Status))
            {
                //ScsiDebugPrintInt(2, "SpScanAdapter: Error %#08lx opening device registry key\n", Status);
                DPRINT1("SpScanAdapter: Status %X\n", Status);
                continue;
            }
        }

        RtlInitUnicodeString(&KeyName, NameString[ix]);
        InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE), DevInstRegKey, NULL);

        Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            //ScsiDebugPrintInt(2, "SpScanAdapter: Error %#08lx opening %wZ key\n", Status, &KeyName);
            DPRINT1("SpScanAdapter: Status %X, '%wZ'\n", Status, &KeyName);

            if (DevInstRegKey)
                ZwClose(DevInstRegKey);

            continue;
        }

        Status = SpGetRegistryValue(KeyHandle, L"ScanDisconnectedDevices", &KeyValueInfo);

        ZwClose(KeyHandle);

        if (DevInstRegKey)
        {
            ZwClose(DevInstRegKey);
            DevInstRegKey = NULL;
        }

        if (!NT_SUCCESS(Status))
        {
            //ScsiDebugPrintInt(2, "SpScanAdapter: Error %#08lx opening %wZ\\ScanDisconnectedDevices value\n", Status, &KeyName);
            DPRINT1("SpScanAdapter: Status %X, '%wZ\\ScanDisconnectedDevices'\n", Status, &KeyName);
            continue;
        }

        if (KeyValueInfo->Type == REG_DWORD && *(PULONG)Add2Ptr(KeyValueInfo, KeyValueInfo->DataOffset))
            IsScanDisconnectedDevices = TRUE;

        ExFreePool(KeyValueInfo);
    }

    Status = SpRequestValidAdapterPowerStateSynchronous(DeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpScanAdapter: Status %X\n", Status);
    }
    else
    {
        DPRINT("SpScanAdapter: %X, %X\n", DeviceExtension->CreateInitiatorLU, DeviceExtension->InitiatorLun);

        if (DeviceExtension->CreateInitiatorLU == 1 && !DeviceExtension->InitiatorLun)
        {
            DeviceExtension->InitiatorLun = SpCreateInitiatorLU(DeviceExtension, (DeviceExtension->NumberOfBuses - 1));
            if (!DeviceExtension->InitiatorLun)
            {
                //ScsiDebugPrintInt(0, "SpScanBus: failed to create initiator LUN for FDO %p bus %d\n", DeviceExtension->CommonExtension.SelfDevice, DeviceExtension->NumberOfBuses - 1);
                DPRINT1("SpScanAdapter: failed to create initiator LUN for FDO %p bus %X\n", DeviceExtension->CommonExtension.SelfDevice, (DeviceExtension->NumberOfBuses - 1));
            }
        }

        for (ix = 0; ix < DeviceExtension->NumberOfBuses; ix++)
        {
            Status = SpScanBus(DeviceExtension, ix, IsScanDisconnectedDevices, LunExtension);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("SpScanAdapter: Status %X\n", Status);
                break;
            }
        }
    }

    InterlockedDecrement(&SpPAGELOCKLockCount);
    MmUnlockPagableImageSection(ImageSectionHandle);

    SpDeleteLogicalUnit(LunExtension);

    ASSERT(DeviceExtension->RescanLun == NULL);
}

VOID
NTAPI
SpEnumerationWorker(
    _In_ PVOID Parameter)
{
    VOID (NTAPI* CallBack)(PSCSI_PORT_DEVICE_EXTENSION, PSCSI_PORT_ENUM_REQUEST, NTSTATUS);
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension = Parameter;
    PSCSI_PORT_ENUM_REQUEST EnumRequest;
    LIST_ENTRY list;
    PIRP Irp;

    PAGED_CODE();
    DPRINT("SpEnumerationWorker: %p\n", Parameter);

    ASSERT(!(((PCOMMON_EXTENSION) (DeviceExtension->CommonExtension.SelfDevice)->DeviceExtension)->IsPdo));
    ASSERT(DeviceExtension->EnumerationRunning == TRUE);

    InitializeListHead(&list);

    DeviceExtension->CurrentThread = KeGetCurrentThread();

    KeWaitForSingleObject(&DeviceExtension->EnumMutex, UserRequest, KernelMode, FALSE, NULL);
    SpScanAdapter(DeviceExtension);
    KeReleaseMutex(&DeviceExtension->EnumMutex, FALSE);

    ExAcquireFastMutex(&DeviceExtension->EnumFastMutex);

    KeQuerySystemTime(&DeviceExtension->EnumTime);

    SpAcquireRemoveLockEx(DeviceExtension->CommonExtension.SelfDevice, &DeviceExtension->EnumWorkItem, __FILE__, __LINE__);

    for (EnumRequest = DeviceExtension->RequestHead; EnumRequest; EnumRequest = DeviceExtension->RequestHead)
    {
        DeviceExtension->RequestHead = EnumRequest->NextRequest;
        EnumRequest->NextRequest = NULL;

        if (!EnumRequest->IsNotCompleteEnumRequest)
            InsertTailList(&list, &EnumRequest->Irp->Tail.Overlay.ListEntry);

        SpReleaseRemoveLock(DeviceExtension->CommonExtension.SelfDevice, EnumRequest);

        CallBack = EnumRequest->CompletionRoutine;
        CallBack(DeviceExtension, EnumRequest, STATUS_SUCCESS);
    }

    DeviceExtension->EnumerationRunning = FALSE;
    DeviceExtension->CurrentThread = NULL;

    ExReleaseFastMutex(&DeviceExtension->EnumFastMutex);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    while (!IsListEmpty(&list))
    {
        Irp = CONTAINING_RECORD(RemoveHeadList(&list), IRP, Tail.Overlay.ListEntry);
        SpCompleteEnumRequest(DeviceExtension, Irp);
    }

    SpReleaseRemoveLock(DeviceExtension->CommonExtension.SelfDevice, &DeviceExtension->EnumWorkItem);
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
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyNameString;
    UNICODE_STRING ValueName;
    HANDLE DevInstRegKey = NULL;
    HANDLE KeyHandle = NULL;
    ULONG ResultLength;
    ULONG Value;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpReadNumericInstanceValue: (%p) '%S'\n", Pdo, ValueNameString);

    ASSERT(OutValue != NULL);
    ASSERT(ValueNameString != NULL);
    ASSERT(Pdo != NULL);

    Status = IoOpenDeviceRegistryKey(Pdo, PLUGPLAY_REGKEY_DEVICE, KEY_READ, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpReadNumericInstanceValue: Status %X\n", Status);
        return Status;
    }

    //_SEH2_TRY;

    RtlInitUnicodeString(&KeyNameString, L"Scsiport");
    InitializeObjectAttributes(&ObjectAttributes, &KeyNameString, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        KeyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)&Buffer;
        RtlInitUnicodeString(&ValueName, ValueNameString);

        Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, KeyValueInfo, sizeof(Buffer), &ResultLength);
        if (NT_SUCCESS(Status))
        {
            if (KeyValueInfo->Type != REG_DWORD || ResultLength < sizeof(ULONG))
                Status = STATUS_OBJECT_TYPE_MISMATCH;
            else
                Value = *(PULONG)&KeyValueInfo->Data[0];
        }
    }

    //_SEH2_FINALLY;

    if (DevInstRegKey)
        ZwClose(DevInstRegKey);

    if (KeyHandle)
        ZwClose(KeyHandle);

    *OutValue = Value;

    return Status;
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
    PSCSI_HW_CHAIN_ENTRY ChainEntry;

    PAGED_CODE();
    DPRINT("SpFindInitData: %p, %X\n", DriverExtension, InterfaceType);

    for (ChainEntry = DriverExtension->ChainHeader; ChainEntry; ChainEntry = ChainEntry->Next)
    {
        if (ChainEntry->HwInitializationData.AdapterInterfaceType == InterfaceType)
            return ChainEntry;
    }

    return NULL;
}

VOID
NTAPI
SpInitializeAdapterExtension(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PSCSI_PORT_HW_DATA SpHwData)
{
    PAGED_CODE();
    DPRINT("SpInitializeAdapterExtension: %p, %X\n", DeviceExtension, ChainEntry);

    DeviceExtension->HwFindAdapter = ChainEntry->HwInitializationData.HwFindAdapter;
    DeviceExtension->HwInitialize = ChainEntry->HwInitializationData.HwInitialize;
    DeviceExtension->HwStartIo = ChainEntry->HwInitializationData.HwStartIo;
    DeviceExtension->HwInterrupt = ChainEntry->HwInitializationData.HwInterrupt;
    DeviceExtension->HwResetBus = ChainEntry->HwInitializationData.HwResetBus;
    DeviceExtension->HwDmaStarted = ChainEntry->HwInitializationData.HwDmaStarted;

    if (ChainEntry->HwInitializationData.HwInitializationDataSize >= sizeof(HW_INITIALIZATION_DATA))
        DeviceExtension->HwAdapterControl = ChainEntry->HwInitializationData.HwAdapterControl;
    else
        DeviceExtension->HwAdapterControl = NULL;

    //FIXME SpDoVerifierInit(..);

    DeviceExtension->SpecificLuExtensionSize = ChainEntry->HwInitializationData.SpecificLuExtensionSize;
    DeviceExtension->SrbExtensionSize = ((ChainEntry->HwInitializationData.SrbExtensionSize + 7) & ~7);
    DeviceExtension->MaximumLogicalUnit = 8;
    DeviceExtension->NumberOfRequests = 0x10;

    if (SpHwData)
    {
        SpHwData->DeviceExtension = DeviceExtension;
        DeviceExtension->HwDeviceExtension = &SpHwData->HwDeviceExtension;
    }

    DeviceExtension->ReservedMapping = MmAllocateMappingAddress((4 * PAGE_SIZE), 'mPcS');
    DeviceExtension->ReservedMdl = IoAllocateMdl(NULL, (4 * PAGE_SIZE), FALSE, FALSE, NULL);
    DeviceExtension->TimeoutValue = 0xA;
    DeviceExtension->ResetHoldTime = (ScsiPortVerifierInitialized ? 0x3C : 4);
}

HANDLE
NTAPI
SpOpenParametersKey(
    _In_ PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    HANDLE RootKeyHandle = NULL;
    HANDLE KeyHandle = NULL;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpOpenParametersKey: %p\n", RegistryPath);

    InitializeObjectAttributes(&ObjectAttributes, RegistryPath, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);

    Status = ZwOpenKey(&RootKeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        //ScsiDebugPrintInt(1, "SpOpenParameterKey: cannot open service key node for driver.  Name: %wZ Status: %08lx\n", RegistryPath, Status);
        DPRINT1("SpOpenParametersKey: cannot open service key node for driver. Name '%wZ' Status %X\n", RegistryPath, Status);
    }

    if (!RootKeyHandle)
        return NULL;

    RtlInitUnicodeString(&KeyName, L"Parameters");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), RootKeyHandle, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpOpenParametersKey: Status: %X\n", Status);
        return RootKeyHandle;
    }

    ZwClose(RootKeyHandle);

    return KeyHandle;
}

HANDLE
NTAPI
SpOpenDeviceKey(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ ULONG AdapterNumber)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ParametersHandle;
    UNICODE_STRING KeyName;
    HANDLE KeyHandle = NULL;
    WCHAR KeyString[64];

    PAGED_CODE();
    DPRINT("SpOpenDeviceKey: %X\n", AdapterNumber);

    ParametersHandle = SpOpenParametersKey(RegistryPath);
    if (!ParametersHandle)
    {
        DPRINT("SpOpenDeviceKey: ret NULL\n");
        return NULL;
    }

    if (AdapterNumber == 0xFFFFFFFF)
        swprintf(KeyString, L"Device");
    else
        swprintf(KeyString, L"Device%d", AdapterNumber);

    RtlInitUnicodeString(&KeyName, KeyString);
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), ParametersHandle, NULL);

    ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    ZwClose(ParametersHandle);

    return KeyHandle;
}

VOID
NTAPI
SpParseDevice(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ HANDLE KeyHandle,
    _In_ PSCSI_PORT_CONFIG_CONTEXT CfgContext,
    _In_ PKEY_VALUE_FULL_INFORMATION FullInfoBuffer)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueInfo;
    ULONG NumberOfRequests;
    ULONG ResultLength;
    ULONG NameLength;
    ULONG Index = 0;
    NTSTATUS Status1;
    NTSTATUS Status2;

    DPRINT("SpParseDevice: %p\n", DeviceExtension);

    KeyValueInfo = FullInfoBuffer;

    while (TRUE)
    {
        while (TRUE)
        {
            if (KeyValueInfo != FullInfoBuffer)
            {
                ExFreePoolWithTag(KeyValueInfo, 'cPcS');
                KeyValueInfo = FullInfoBuffer;
            }

            Status1 = ZwEnumerateValueKey(KeyHandle, Index++, KeyValueFullInformation, KeyValueInfo, 0x200, &ResultLength);
            if (NT_SUCCESS(Status1))
                break;

            if (Status1 == STATUS_NO_MORE_ENTRIES)
                return;

            if (Status1 != STATUS_BUFFER_OVERFLOW && Status1 != STATUS_BUFFER_TOO_SMALL)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice: ZwEnumerateValueKey failed. Status: %lx", Status1);
                DPRINT1("SpParseDevice: ZwEnumerateValueKey failed. Status: %X", Status1);
                continue;
            }

            KeyValueInfo = ExAllocatePoolWithTag(PagedPool, ResultLength, 'cPcS');
            if (!KeyValueInfo)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice: Failed to allocated paged pool of size %lx", ResultLength);
                DPRINT1("SpParseDevice: Failed to allocated paged pool of size %X", ResultLength);
                KeyValueInfo = FullInfoBuffer;
                continue;
            }

            Status2 = ZwEnumerateValueKey(KeyHandle, (Index - 1), KeyValueFullInformation, KeyValueInfo, ResultLength, &ResultLength);
            if (NT_SUCCESS(Status2))
                break;

            if (Status2 == STATUS_NO_MORE_ENTRIES)
            {
                ExFreePoolWithTag(KeyValueInfo, 'cPcS');
                return;
            }

            if (Status2 == STATUS_BUFFER_OVERFLOW || Status2 == STATUS_BUFFER_TOO_SMALL)
                continue;

            //ScsiDebugPrintInt(1, "SpParseDevice: ZwEnumerateValueKey failed. Status2: %lx", Status2);
            DPRINT1("SpParseDevice: ZwEnumerateValueKey failed. Status2: %X", Status2);
        }

        NameLength = (KeyValueInfo->NameLength / 2);

        if (KeyValueInfo->Type == REG_DWORD && KeyValueInfo->DataLength != sizeof(ULONG))
            continue;

        if (!_wcsnicmp(KeyValueInfo->Name, L"MaximumLogicalUnit", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"InitiatorTargetId", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"ScsiDebug", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"BreakPointOnEntry", NameLength))
        {
            //ScsiDebugPrintInt(0, "SpParseDevice: Break point requested on entry.\n");
            DPRINT1("SpParseDevice: Break point requested on entry.\n");
            DbgBreakPoint();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"DisableSynchronousTransfers", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"DisableDisconnects", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"DisableTaggedQueuing", NameLength))
        {
            //ScsiDebugPrintInt(1, "SpParseDevice: Disabling tagged queueing\n");
            DPRINT("SpParseDevice: Disabling tagged queueing\n");
            CfgContext->DisableTaggedQueuing = 1;
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"DisableMultipleRequests", NameLength))
        {
            //ScsiDebugPrintInt(1, "SpParseDevice: Disabling multiple requests\n");
            DPRINT("SpParseDevice: Disabling multiple requests\n");
            CfgContext->DisableMultipleRequests = 1;
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"MinimumUCXAddress", NameLength) && KeyValueInfo->Type == REG_BINARY)
        {
            DeviceExtension->MinimumUCXAddress.QuadPart = *(PULONGLONG)((ULONG_PTR)KeyValueInfo + KeyValueInfo->DataOffset);
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"MaximumUCXAddress", NameLength) && KeyValueInfo->Type == REG_BINARY)
        {
            DeviceExtension->MaximumUCXAddress.QuadPart = *(PULONGLONG)((ULONG_PTR)KeyValueInfo + KeyValueInfo->DataOffset);
        }

        if (!DeviceExtension->MaximumUCXAddress.QuadPart)
            DeviceExtension->MaximumUCXAddress.QuadPart = 0xFFFFFFFF;

        if (DeviceExtension->MinimumUCXAddress.QuadPart >= (DeviceExtension->MaximumUCXAddress.QuadPart - PAGE_SIZE))
        {
            //ScsiDebugPrintInt(0, "SpParseDevice: MinimumUCXAddress %I64x is invalid\n", DeviceExtension->MinimumUCXAddress.QuadPart);
            DPRINT1("SpParseDevice: MinimumUCXAddress %I64X is invalid\n", DeviceExtension->MinimumUCXAddress.QuadPart);
            DeviceExtension->MinimumUCXAddress.QuadPart = 0;
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"DriverParameters", NameLength))
        {
            if (!KeyValueInfo->DataLength)
                continue;

            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"MaximumSGList", NameLength))
        {
            if (KeyValueInfo->Type != REG_DWORD)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice:  Bad data type for MaximumSGList.\n");
                DPRINT("SpParseDevice: Bad data type for MaximumSGList.\n");
                continue;
            }
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"NumberOfRequests", NameLength))
        {
            if (KeyValueInfo->Type != REG_DWORD)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice:  Bad data type for NumberOfRequests.\n");
                DPRINT("SpParseDevice: Bad data type for NumberOfRequests.\n");
                continue;
            }

            NumberOfRequests = *(PULONG)Add2Ptr(KeyValueInfo, KeyValueInfo->DataOffset);

            if (NumberOfRequests >= 0x10)
            {
                if (NumberOfRequests <= 0xFF)
                    DeviceExtension->NumberOfRequests = NumberOfRequests;
                else
                    DeviceExtension->NumberOfRequests = 0xFF;
            }
            else
            {
                DeviceExtension->NumberOfRequests = 0x10;
            }

            //ScsiDebugPrintInt(1, "SpParseDevice:  Number Of Requests = %d found.\n", DeviceExtension->NumberOfRequests);
            DPRINT("SpParseDevice: Number Of Requests %X found.\n", DeviceExtension->NumberOfRequests);
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"ResourceList", NameLength) ||
            !_wcsnicmp(KeyValueInfo->Name, L"Configuration Data", NameLength))
        {
            if (KeyValueInfo->Type != REG_FULL_RESOURCE_DESCRIPTOR || KeyValueInfo->DataLength < 4)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice:  Bad data type for ResourceList.\n");
                DPRINT("SpParseDevice: Bad data type for ResourceList.\n");
                continue;
            }

            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"UncachedExtAlignment", NameLength))
        {
            if (KeyValueInfo->Type != REG_DWORD)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice:  Bad data type for UncachedExtAlignment.\n");
                DPRINT("SpParseDevice: Bad data type for UncachedExtAlignment.\n");
                continue;
            }

            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"ResetHoldTime", NameLength))
        {
            if (KeyValueInfo->Type != REG_DWORD)
            {
                //ScsiDebugPrintInt(1, "SpParseDevice:  Bad data type for ResetHoldTime.\n");
                DPRINT("SpParseDevice: Bad data type for ResetHoldTime.\n");
                continue;
            }

            UNIMPLEMENTED_DBGBREAK();
        }

        if (!_wcsnicmp(KeyValueInfo->Name, L"CreateInitiatorLU", NameLength))
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    ASSERT(FALSE);
}

NTSTATUS
NTAPI
PortGetDiskTimeoutValue(
    _Out_ ULONG* OutTimeoutValue)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    ULONG TimeoutValue;
    ULONG ResultLength;
    UCHAR Buffer[0x200];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PortGetDiskTimeoutValue()\n");

    RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Disk");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PortGetDiskTimeoutValue: Status %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&ValueName, L"TimeoutValue");
    KeyValueInfo = (PKEY_VALUE_FULL_INFORMATION)Buffer;

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValueFullInformation, &KeyValueInfo, 0x200, &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PortGetDiskTimeoutValue: Status %X\n", Status);
        return Status;
    }

    if (KeyValueInfo->Type == REG_DWORD && KeyValueInfo->DataLength != sizeof(ULONG))
    {
        DPRINT1("PortGetDiskTimeoutValue: Status %X\n", Status);
        return Status;
    }

    Status = _wcsnicmp(KeyValueInfo->Name, L"TimeoutValue", (KeyValueInfo->NameLength / 2));
    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("PortGetDiskTimeoutValue: Status %X\n", Status);
        return Status;
    }

    if (!KeyValueInfo->DataLength || KeyValueInfo->Type != REG_DWORD)
    {
        DPRINT1("PortGetDiskTimeoutValue: Status %X\n", Status);
        return Status;
    }

    TimeoutValue = *(PULONG)((ULONG_PTR)KeyValueInfo + KeyValueInfo->DataOffset);
    if (TimeoutValue)
        *OutTimeoutValue = TimeoutValue;

    return Status;
}

NTSTATUS
NTAPI
SpConfigurationCallout(
    _In_ PVOID Context,
    _In_ PUNICODE_STRING PathName,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _Out_ PKEY_VALUE_FULL_INFORMATION* BusInformation,
    _In_ CONFIGURATION_TYPE ControllerType,
    _In_ ULONG ControllerNumber,
    _Out_ PKEY_VALUE_FULL_INFORMATION* ControllerInformation,
    _In_ CONFIGURATION_TYPE PeripheralType,
    _In_ ULONG PeripheralNumber,
    _Out_ PKEY_VALUE_FULL_INFORMATION* PeripheralInformation)
{
    BOOLEAN* OutResult = Context;

    PAGED_CODE();
    DPRINT("SpConfigurationCallout: %X\n", BusNumber);

    *OutResult = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SpInitializeConfiguration(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PSCSI_PORT_CONFIG_CONTEXT CfgContext)
{
    PCONFIGURATION_INFORMATION ConfigInfo;
    INTERFACE_TYPE BusType;
    HANDLE KeyHandle;
    UCHAR FullInfoBuffer[0x200];
    ULONG ix;
    BOOLEAN Result;

    DPRINT("SpInitializeConfiguration: %p\n", DeviceExtension);

    RtlZeroMemory(&CfgContext->PortConfig, sizeof(CfgContext->PortConfig));

    ASSERT(CfgContext->AccessRanges != NULL);
    RtlZeroMemory(CfgContext->AccessRanges, (ChainEntry->HwInitializationData.NumberOfAccessRanges * sizeof(ACCESS_RANGE)));

    BusType = ChainEntry->HwInitializationData.AdapterInterfaceType;

    CfgContext->PortConfig.Length = sizeof(CfgContext->PortConfig);
    CfgContext->PortConfig.AdapterInterfaceType = BusType;
    CfgContext->PortConfig.InterruptMode = 1;
    CfgContext->PortConfig.MaximumTransferLength = 0xFFFFFFFF;
    CfgContext->PortConfig.DmaChannel = 0xFFFFFFFF;
    CfgContext->PortConfig.DmaPort = 0xFFFFFFFF;
    CfgContext->PortConfig.NumberOfAccessRanges = ChainEntry->HwInitializationData.NumberOfAccessRanges;
    CfgContext->PortConfig.MaximumNumberOfTargets = 8;
    CfgContext->PortConfig.MaximumNumberOfLogicalUnits = 8;
    CfgContext->PortConfig.WmiDataProvider = 0;
    CfgContext->PortConfig.Dma64BitAddresses = (Sp64BitPhysicalAddresses == 1 ? 0x80 : 0);
    CfgContext->PortConfig.NeedPhysicalAddresses = ChainEntry->HwInitializationData.NeedPhysicalAddresses;
    CfgContext->PortConfig.MapBuffers = ChainEntry->HwInitializationData.MapBuffers;
    CfgContext->PortConfig.AutoRequestSense = ChainEntry->HwInitializationData.AutoRequestSense;
    CfgContext->PortConfig.ReceiveEvent = ChainEntry->HwInitializationData.ReceiveEvent;
    CfgContext->PortConfig.TaggedQueuing = ChainEntry->HwInitializationData.TaggedQueuing;
    CfgContext->PortConfig.MultipleRequestPerLu = ChainEntry->HwInitializationData.MultipleRequestPerLu;

    ConfigInfo = IoGetConfigurationInformation();
    CfgContext->PortConfig.AtdiskPrimaryClaimed = ConfigInfo->AtDiskPrimaryAddressClaimed;
    CfgContext->PortConfig.AtdiskSecondaryClaimed = ConfigInfo->AtDiskSecondaryAddressClaimed;

    for (ix = 0; ix < 8; ix++)
        CfgContext->PortConfig.InitiatorBusId[ix] = 0xFF;

    CfgContext->PortConfig.SystemIoBusNumber = CfgContext->BusNumber;
    CfgContext->PortConfig.NumberOfPhysicalBreaks = 0x11;

    CfgContext->DisableTaggedQueuing = 0;
    CfgContext->DisableMultipleRequests = 0;

    CfgContext->AdapterNumber = (DeviceExtension->PortScsi - 1);
    ASSERT((LONG)CfgContext->AdapterNumber > -1);

    if (CfgContext->DriverParameters)
    {
        ExFreePoolWithTag(CfgContext->DriverParameters, 0);
        CfgContext->DriverParameters = 0;
    }

    KeyHandle = SpOpenDeviceKey(RegistryPath, 0xFFFFFFFF);
    if (KeyHandle)
    {
        SpParseDevice(DeviceExtension, KeyHandle, CfgContext, (PVOID)FullInfoBuffer);
        ZwClose(DeviceExtension);
    }

    KeyHandle = SpOpenDeviceKey(RegistryPath, CfgContext->AdapterNumber);
    if (KeyHandle)
    {
        SpParseDevice(DeviceExtension, KeyHandle, CfgContext, (PVOID)FullInfoBuffer);
        ZwClose(DeviceExtension);
    }

    DeviceExtension->TimeoutValue = 0xA;
    PortGetDiskTimeoutValue(&DeviceExtension->TimeoutValue);

    if (BusType == PNPBus)
        return STATUS_SUCCESS;

    Result = FALSE;

    if (BusType != MicroChannel)
    {
        IoQueryDeviceDescription(&BusType, &CfgContext->BusNumber, NULL, NULL, NULL, NULL, SpConfigurationCallout, &Result);
        if (Result)
            return STATUS_SUCCESS;
    }

    if (BusType != Isa)
    {
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    BusType = Eisa;
    IoQueryDeviceDescription(&BusType, &CfgContext->BusNumber, NULL, NULL, NULL, NULL, SpConfigurationCallout, &Result);

    return (Result == FALSE ? STATUS_DEVICE_DOES_NOT_EXIST : STATUS_SUCCESS);
}

VOID
NTAPI
SpBuildConfiguration(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig)
{
    PCM_FULL_RESOURCE_DESCRIPTOR CmList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PACCESS_RANGE AccessRanges;
    ULONG AccessNumber = 0;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpBuildConfiguration: %p\n", DeviceExtension);

    ASSERT((DeviceExtension->Flags2 & 1) == 0);//IsMiniportDetected
    ASSERT(DeviceExtension->AllocatedResources);

    CmList = &DeviceExtension->AllocatedResources->List[0];

    for (ix = 0; ix < CmList->PartialResourceList.Count; ix++)
    {
        CmDescriptor = &CmList->PartialResourceList.PartialDescriptors[ix];

        if (CmDescriptor->Type == CmResourceTypePort)
        {
            if (AccessNumber < ChainEntry->HwInitializationData.NumberOfAccessRanges)
            {
                AccessRanges = Add2Ptr(PortConfig->AccessRanges, (AccessNumber * sizeof(ACCESS_RANGE)));
                AccessRanges->RangeStart = CmDescriptor->u.Port.Start;
                AccessRanges->RangeLength = CmDescriptor->u.Port.Length;
                AccessRanges->RangeInMemory = 0;
                AccessNumber++;
            }
        }
        else if (CmDescriptor->Type == CmResourceTypeInterrupt)
        {
            PortConfig->BusInterruptLevel = CmDescriptor->u.Interrupt.Level;
            PortConfig->BusInterruptVector = CmDescriptor->u.Interrupt.Vector;

            if (CmDescriptor->ShareDisposition == 1)
                PortConfig->InterruptMode = 1;
            else if (CmDescriptor->ShareDisposition == 0)
                PortConfig->InterruptMode = 0;

            DeviceExtension->Flags2 |= 8;
        }
        else if (CmDescriptor->Type == CmResourceTypeMemory)
        {
            if (AccessNumber < ChainEntry->HwInitializationData.NumberOfAccessRanges)
            {
                AccessRanges = Add2Ptr(PortConfig->AccessRanges, (AccessNumber * sizeof(ACCESS_RANGE)));
                AccessRanges->RangeStart = CmDescriptor->u.Memory.Start;
                AccessRanges->RangeLength = CmDescriptor->u.Memory.Length;
                AccessRanges->RangeInMemory = 1;
                AccessNumber++;
            }
        }
        else if (CmDescriptor->Type == CmResourceTypeDma)
        {
            PortConfig->DmaChannel = CmDescriptor->u.Dma.Channel;
            PortConfig->DmaPort = CmDescriptor->u.Dma.Port;
        }
    }
}

NTSTATUS
NTAPI
SpQueryCapabilities(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    DEVICE_CAPABILITIES Capabilities;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpQueryCapabilities: %p\n", DeviceExtension);

    RtlZeroMemory(&Capabilities, sizeof(Capabilities));

    Capabilities.Size = sizeof(Capabilities);
    Capabilities.Version = 1;
    Capabilities.Address = 0xFFFFFFFF;
    Capabilities.UINumber = 0xFFFFFFFF;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    Irp = IoAllocateIrp((DeviceExtension->CommonExtension.SelfDevice->StackSize + 1), FALSE);
    if (!Irp)
    {
        DPRINT1("SpQueryCapabilities: Allocate failed\n");
        UNIMPLEMENTED_DBGBREAK();
        //SpLogAllocationFailureFn(..);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStack->Parameters.DeviceCapabilities.Capabilities = &Capabilities;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoSetCompletionRoutine(Irp, SpSignalCompletion, &Event, TRUE, TRUE, TRUE);

    IoCallDriver(DeviceExtension->CommonExtension.SelfDevice, Irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("SpQueryCapabilities: Irp->IoStatus.Status %X\n", Irp->IoStatus.Status);
        DeviceExtension->PciSlotNumber.u.AsULONG = 0;
    }
    else
    {
        DeviceExtension->PciSlotNumber.u.bits.DeviceNumber = ((Capabilities.Address >> 16) & 0x1F);
        DeviceExtension->PciSlotNumber.u.bits.FunctionNumber = (Capabilities.Address & 7);
    }

    IoFreeIrp(Irp);

    return Status;
}

VOID
NTAPI
SpGetSlotNumber(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig,
    _In_ PCM_RESOURCE_LIST AllocatedResources)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    RTL_QUERY_REGISTRY_TABLE QueryTable[3];
    UNICODE_STRING KeyValueName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE DevInstRegKey = NULL;
    HANDLE KeyHandle = NULL;
    ULONG BusNumber;
    ULONG DefaultData;
    ULONG SlotNumber;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpGetSlotNumber: %p\n", DeviceObject);

    DeviceExtension = DeviceObject->DeviceExtension;
    DeviceExtension->Flags2 &= ~2;

    //_SEH2_TRY;

    Status = IoOpenDeviceRegistryKey(DeviceExtension->LowerPdo, PLUGPLAY_REGKEY_DEVICE, KEY_READ, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpGetSlotNumber: Status %X\n", Status);
        goto Finish;
    }

    RtlInitUnicodeString(&KeyValueName, L"Scsiport");
    InitializeObjectAttributes(&ObjectAttributes, &KeyValueName, OBJ_CASE_INSENSITIVE, DevInstRegKey, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpGetSlotNumber: Status %X\n", Status);
        goto Finish;
    }

    DefaultData = 0xFFFFFFFF;
    BusNumber = 0xFFFFFFFF;
    SlotNumber = 0xFFFFFFFF;

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[0].Name = L"SlotNumber";
    QueryTable[0].EntryContext = &SlotNumber;
    QueryTable[0].DefaultType = REG_DWORD;
    QueryTable[0].DefaultData = &DefaultData;
    QueryTable[0].DefaultLength = sizeof(ULONG);

    QueryTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[1].Name = L"BusNumber";
    QueryTable[1].EntryContext = &BusNumber;
    QueryTable[1].DefaultType = REG_DWORD;
    QueryTable[1].DefaultData = &DefaultData;
    QueryTable[1].DefaultLength = sizeof(ULONG);

    Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, NULL, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpGetSlotNumber: Status %X\n", Status);
        goto Finish;
    }

    if (BusNumber == DefaultData && SlotNumber == DefaultData)
    {
        DPRINT1("SpGetSlotNumber: STATUS_UNSUCCESSFUL\n");
        Status = STATUS_UNSUCCESSFUL;
        goto Finish;
    }

    if (BusNumber != DefaultData && SlotNumber != DefaultData)
    {
        PortConfig->SystemIoBusNumber = BusNumber;
        PortConfig->SlotNumber = SlotNumber;

        DeviceExtension->Flags2 &= ~2;
    }
    else
    {
        PortConfig->SystemIoBusNumber = AllocatedResources->List[0].BusNumber;
        PortConfig->SlotNumber = 0;

        DeviceExtension->Flags2 |= 2;
    }

Finish:
    //_SEH2_FINALLY;

    if (!NT_SUCCESS(Status))
    {
        Status = SpQueryCapabilities(DeviceExtension);
        if (NT_SUCCESS(Status))
        {
            PortConfig->SystemIoBusNumber = AllocatedResources->List[0].BusNumber;
            PortConfig->SlotNumber = DeviceExtension->PciSlotNumber.u.AsULONG;

            DPRINT("SpGetSlotNumber: %X, %X\n", PortConfig->SystemIoBusNumber, PortConfig->SlotNumber);

            DeviceExtension->Flags2 |= 2;
        }
    }

    if (DevInstRegKey)
        ZwClose(DevInstRegKey);

    if (KeyHandle)
        ZwClose(KeyHandle);
}

VOID
NTAPI
SpPreallocateAddressMapping(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ UCHAR Count)
{
    PSCSI_PORT_ADDRESS_MAPPING AddressMapping;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpPreallocateAddressMapping: %X\n", Count);

    for (ix = 0; ix < Count; ix++)
    {
        AddressMapping = ExAllocatePoolWithTag(NonPagedPool, sizeof(*AddressMapping), 'mPcS');
        if (!AddressMapping)
        {
            DPRINT1("SpPreallocateAddressMapping: Allocate failed\n");
            break;
        }
        RtlZeroMemory(AddressMapping, sizeof(*AddressMapping));

        AddressMapping->Next = DeviceExtension->AddressMapping;
        DeviceExtension->AddressMapping = AddressMapping;
    }
}

VOID
NTAPI
SpPurgeFreeMappedAddressList(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    PSCSI_PORT_ADDRESS_MAPPING AddressMapping;

    PAGED_CODE();
    DPRINT("SpPurgeFreeMappedAddressList: %p\n", DeviceExtension);
 
    while (DeviceExtension->AddressMapping)
    {
        AddressMapping = DeviceExtension->AddressMapping;
        DeviceExtension->AddressMapping = DeviceExtension->AddressMapping->Next;
        ExFreePoolWithTag(AddressMapping, 'mPcS');
    }
}

NTSTATUS
NTAPI
SpCallHwFindAdapter(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PSCSI_HW_CHAIN_ENTRY ChainEntry,
    _In_ PVOID HwContext,
    _In_ PSCSI_PORT_CONFIG_CONTEXT CfgContext,
    _In_ PPORT_CONFIGURATION_INFORMATION PortConfig,
    _Out_ BOOLEAN* OutIsAgain)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    ULONG Result;
    NTSTATUS Status;

    DPRINT("SpCallHwFindAdapter: %p\n", DeviceObject);

    DeviceExtension = DeviceObject->DeviceExtension;

    *OutIsAgain = FALSE;

    SpPreallocateAddressMapping(DeviceExtension, 0x14);

    Result = DeviceExtension->HwFindAdapter(DeviceExtension->HwDeviceExtension,
                                            HwContext,
                                            NULL, // BusInformation
                                            CfgContext->DriverParameters,
                                            PortConfig,
                                            OutIsAgain);

    if (DeviceExtension->InterruptData.Flags & 0x40)
    {
        DeviceExtension->InterruptData.Flags &= ~0x44;
        UNIMPLEMENTED;
        //LogErrorEntry(..);
    }

    if (DeviceExtension->MapRegisterBase)
    {
        ExFreePool(DeviceExtension->MapRegisterBase);
        DeviceExtension->MapRegisterBase = NULL;
    }

    if (Result == 1)
    {
        if (!PortConfig->Master && Sp64BitPhysicalAddresses == 1)
        {
            //ScsiDebugPrintInt(0, "SpCallHwFindAdapter: Driver does not support bus mastering for adapter %#08lx - this type of adapter is not supported on systems with 64-bit physical addresses\n", DeviceExtension);
            DPRINT1("SpCallHwFindAdapter: Driver does not support bus mastering for adapter %X - this type of adapter is not supported on systems with 64-bit physical addresses\n", DeviceExtension);
            return STATUS_NOT_SUPPORTED;
        }

        SpPurgeFreeMappedAddressList(DeviceExtension);

        //ScsiDebugPrintInt(1, "SpFindAdapter: SCSI Adapter ID is %d\n", PortConfig->InitiatorBusId[0]);
        DPRINT("SpCallHwFindAdapter: SCSI Adapter ID is %d\n", PortConfig->InitiatorBusId[0]);

        if (DeviceExtension->Flags2 & 4)
        {
            Status = STATUS_SUCCESS;
        }
        else
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (!DeviceExtension->UncachedExtension)
        {
            if (PortConfig->SrbExtensionSize != DeviceExtension->SrbExtensionSize)
                DeviceExtension->SrbExtensionSize = (PortConfig->SrbExtensionSize + 8) & ~7;
        }

        if (DeviceExtension->SpecificLuExtensionSize != PortConfig->SpecificLuExtensionSize)
            DeviceExtension->SpecificLuExtensionSize = PortConfig->SpecificLuExtensionSize;

        if (PortConfig->MaximumNumberOfTargets <= 0x80)
            DeviceExtension->MaximumNumberOfTargets = PortConfig->MaximumNumberOfTargets;
        else
            DeviceExtension->MaximumNumberOfTargets = 0x80;

        DeviceExtension->NumberOfBuses = PortConfig->NumberOfBuses;
        DeviceExtension->CachesData = PortConfig->CachesData;
        DeviceExtension->ReceiveEvent = PortConfig->ReceiveEvent;
        DeviceExtension->TaggedQueuing = PortConfig->TaggedQueuing;
        DeviceExtension->MultipleRequestPerLu = PortConfig->MultipleRequestPerLu;
        DeviceExtension->CommonExtension.WmiDataProvider = PortConfig->WmiDataProvider;

        if (CfgContext->DisableMultipleRequests)
        {
            PortConfig->MultipleRequestPerLu = 0;
            DeviceExtension->MultipleRequestPerLu = 0;
        }

        if (CfgContext->DisableTaggedQueuing)
        {
            PortConfig->MultipleRequestPerLu = 0;
            PortConfig->TaggedQueuing = 0;
            DeviceExtension->TaggedQueuing = 0;
        }

        DeviceExtension->IsRequestQueue = (DeviceExtension->TaggedQueuing || DeviceExtension->MultipleRequestPerLu);

        return Status;
    }

    //ScsiDebugPrintInt(1, "SpFindAdapter: miniport find adapter routine reported an error %d\n", Result);
    DPRINT1("SpCallHwFindAdapter: miniport find adapter routine reported an error %X\n", Result);

    if (Result == 0)
    {
        *OutIsAgain = 0;
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
    }
    else if (Result == 2)
    {
        Status = STATUS_ADAPTER_HARDWARE_ERROR;
    }
    else if (Result == 3)
    {
        Status = STATUS_INVALID_PARAMETER;
    }
    else
    {
        Status = STATUS_INTERNAL_ERROR;
    }

    return Status;
}

NTSTATUS
NTAPI
SpAllocateQueueTagList(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    PSCSI_PORT_QUEUETAGS_ENTRY List;
    PSLIST_HEADER ListHead;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpAllocateQueueTagList: %p\n", DeviceExtension);

    if (DeviceExtension->MaxQueueTag)
    {
        if (DeviceExtension->MaxQueueTag < DeviceExtension->NumberOfRequests)
        {
            DbgPrint("SpAllocateTagBitmap: MaxQueueTag %d < NumberOfRequests %d\nThis will negate the advantage of having increased the number of requests.\n", DeviceExtension->MaxQueueTag, DeviceExtension->NumberOfRequests);
        }
    }
    else
    {
        DeviceExtension->MaxQueueTag = 0xFE;
    }

    //ScsiDebugPrintInt(1, "SpAllocateAdapterResources: %d bits in queue tag bitMap\n", DeviceExtension->MaxQueueTag);
    DPRINT("SpAllocateQueueTagList: %X bits in queue tag bitMap\n", DeviceExtension->MaxQueueTag);

    List = ExAllocatePoolWithTag(NonPagedPool, (sizeof(*List) * DeviceExtension->MaxQueueTag), 'LTcS');
    if (!List)
    {
        DPRINT1("SpAllocateQueueTagList: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ListHead = &DeviceExtension->QueueTagsListHead;
    ListHead->Next.Next = 0;
    ListHead->Depth = 0;
    ListHead->Sequence = 0;

    DeviceExtension->QueueTagsList = List;

    for (ix = 0; ix < DeviceExtension->MaxQueueTag; ix++)
    {
        List[ix].Tag = (ix + 1);
        InterlockedPushEntrySList(ListHead, &List[ix].Link);
    }

    return STATUS_SUCCESS;
}

PVOID
NTAPI
SpAllocateSrbDataBackend(
     _In_ POOL_TYPE PoolType,
     _In_ SIZE_T NumberOfBytes,
     _In_ ULONG Tag)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_QUEUETAGS_ENTRY QueueEntry;
    PSCSI_PORT_SRB_DATA SrbData;
    LONG QueueTag;
    KIRQL Irql;

    KeAcquireSpinLock(&ScsiGlobalAdapterListSpinLock, &Irql);
    DeviceExtension = ScsiGlobalAdapterList[Tag]->DeviceExtension;
    KeReleaseSpinLock(&ScsiGlobalAdapterListSpinLock, Irql);

    ASSERT(!(((PCOMMON_EXTENSION)(DeviceExtension->CommonExtension.SelfDevice)->DeviceExtension)->IsPdo));

    QueueEntry = (PSCSI_PORT_QUEUETAGS_ENTRY)InterlockedPopEntrySList(&DeviceExtension->QueueTagsListHead);
    if (!QueueEntry)
        return NULL;

    QueueTag = QueueEntry->Tag;
    ASSERT(QueueTag != -1);

    QueueEntry->Tag = -1;

    if (QueueTag == -1)
        return NULL;

    DPRINT("SpAllocateSrbDataBackend: %X\n", NumberOfBytes);

    SrbData = ExAllocatePoolWithTag(PoolType, NumberOfBytes, 'DPcS');
    if (!SrbData)
    {
        QueueEntry = &DeviceExtension->QueueTagsList[QueueTag - 1];
        ASSERT(QueueEntry->Tag == -1);

        QueueEntry->Tag = QueueTag;
        InterlockedPushEntrySList(&DeviceExtension->QueueTagsListHead, &QueueEntry->Link);

        return NULL;
    }
    RtlZeroMemory(SrbData, sizeof(*SrbData));

    DPRINT("SpAllocateSrbDataBackend: SrbData %X\n", SrbData);

    SrbData->Type = 0x7770;//SRB_DATA_TYPE
    SrbData->Size = sizeof(*SrbData);
    SrbData->FreeRoutine = SpFreeSrbData;
    SrbData->Flags = 0;
    SrbData->DeviceExtension = DeviceExtension;
    SrbData->QueueTag = QueueTag;

    return SrbData;
}

VOID
NTAPI
SpFreeSrbDataBackend(
    _In_ PVOID Buffer)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
SpInitializeSrbDataLookasideList(
    _In_ PDEVICE_OBJECT Fdo)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT* AdapterList;
    PDEVICE_OBJECT* OldAdapterList;
    PVOID ImageSectionHandle;
    ULONG OldElements;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("SpInitializeSrbDataLookasideList: %p\n", Fdo);

    ImageSectionHandle = MmLockPagableDataSection(SpInitializeSrbDataLookasideList);
    InterlockedIncrement(&SpPAGELOCKLockCount);
    KeAcquireSpinLock(&ScsiGlobalAdapterListSpinLock, &Irql);

    OldElements = ScsiGlobalAdapterListElements;

    if (ScsiGlobalAdapterListElements == 0xFFFFFFFF)
    {
        DPRINT1("SpInitializeSrbDataLookasideList: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Finish;
    }

    AdapterList = ExAllocatePoolWithTag(NonPagedPool, ((OldElements + 1) * sizeof(PDEVICE_OBJECT)), 'GPcS');
    if (!AdapterList)
    {
        DPRINT1("SpInitializeSrbDataLookasideList: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Finish;
    }

    ScsiGlobalAdapterListElements++;

    if (ScsiGlobalAdapterList)
        RtlCopyMemory(AdapterList, ScsiGlobalAdapterList, (OldElements * sizeof(PDEVICE_OBJECT))); 

    AdapterList[OldElements] = Fdo;

    OldAdapterList = ScsiGlobalAdapterList;
    ScsiGlobalAdapterList = AdapterList;

    DPRINT("SpInitializeSrbDataLookasideList: %p %p\n", OldAdapterList, AdapterList);

    if (OldAdapterList)
        ExFreePoolWithTag(OldAdapterList, 'GPcS');

Finish:

    KeReleaseSpinLock(&ScsiGlobalAdapterListSpinLock, Irql);
    MmUnlockPagableImageSection(ImageSectionHandle);
    InterlockedDecrement(&SpPAGELOCKLockCount);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpInitializeSrbDataLookasideList: Status %X\n", Status);
        return Status;
    }

    DeviceExtension = Fdo->DeviceExtension;

    ExInitializeNPagedLookasideList(&DeviceExtension->SrbDataLookAsideList,
                                    SpAllocateSrbDataBackend,
                                    SpFreeSrbDataBackend,
                                    0,
                                    sizeof(SCSI_PORT_SRB_DATA),
                                    OldElements,
                                    0x14);//20

    DeviceExtension->IsSrbDataList = TRUE;

    return Status;
}

PSCSI_PORT_SRB_DATA
NTAPI
SpAllocateSrbData(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PIRP Irp,
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    PSCSI_PORT_SRB_DATA SrbData;

    DPRINT("SpAllocateSrbData: %p\n", DeviceExtension);

    SrbData = ExAllocateFromNPagedLookasideList(&DeviceExtension->SrbDataLookAsideList);
    if (!SrbData && Irp)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    return SrbData;
}

NTSTATUS
NTAPI
SpAllocateAdapterResources(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PPORT_CONFIGURATION_INFORMATION PortConfig;
    PIO_SCSI_CAPABILITIES IoScsiCapabilities;
    PVOID SrbExtensionBuffer;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpAllocateAdapterResources: %p\n", DeviceObject);

    DeviceExtension = DeviceObject->DeviceExtension;
    PortConfig = DeviceExtension->PortConfig;

    DeviceExtension->MapBuffers = PortConfig->MapBuffers;

    IoScsiCapabilities = &DeviceExtension->IoScsiCapabilities;
    IoScsiCapabilities->AdapterUsesPio = PortConfig->MapBuffers;

    if (!DeviceExtension->DmaAdapter)
    {
        if (PortConfig->Master || PortConfig->DmaChannel != 0xFFFFFFFF)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    Status = SpAllocateQueueTagList(DeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpAllocateAdapterResources: Status %X\n", Status);
        return Status;
    }

    SpInitializePowerParams(DeviceExtension);
    SpInitializePerformanceParams(DeviceExtension);

    SrbExtensionBuffer = SpGetSrbExtensionBuffer(DeviceExtension);

    if ((DeviceExtension->SrbExtensionSize || PortConfig->AutoRequestSense) && !SrbExtensionBuffer)
    {
        SpInitializeRequestSenseParams(DeviceExtension);

        DeviceExtension->AutoRequestSense = PortConfig->AutoRequestSense;
        DeviceExtension->IsSrbExtensions = TRUE;

        Status = SpGetCommonBuffer(DeviceExtension, 0);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("SpAllocateAdapterResources: Status %X\n", Status);
            return Status;
        }
    }

    Status = SpInitializeSrbDataLookasideList(DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpAllocateAdapterResources: Status %X\n", Status);
        return Status;
    }

    DeviceExtension->SrbData = SpAllocateSrbData(DeviceExtension, NULL, NULL);
    if (!DeviceExtension->SrbData)
    {
        DPRINT1("SpAllocateAdapterResources: Status %X\n", Status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceExtension->BlockedRequestList.Flink && !DeviceExtension->BlockedRequestList.Blink)
        InitializeListHead(&DeviceExtension->BlockedRequestList);

    KeInitializeSpinLock(&DeviceExtension->SrbDataSpinLock);

    DeviceExtension->AsyncEnumRequest = &DeviceExtension->EnumRequest;

    if (!DeviceExtension->InquiryData)
    {
        DeviceExtension->InquiryData = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 0x100, 'qPcS'); // ?
        if (!DeviceExtension->InquiryData)
        {
            DPRINT1("SpAllocateAdapterResources: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        DPRINT("SpAllocateAdapterResources: DeviceExtension->InquiryData %p\n", DeviceExtension->InquiryData);

        DeviceExtension->InquirySenseData = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, (sizeof(SENSE_DATA) + DeviceExtension->SenseDataBytes), 'qPcS');
        if (!DeviceExtension->InquirySenseData)
        {
            DPRINT1("SpAllocateAdapterResources: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        DPRINT("SpAllocateAdapterResources: DeviceExtension->InquirySenseData %p\n", DeviceExtension->InquirySenseData);

        DeviceExtension->InquiryIrp = IoAllocateIrp(1, FALSE);
        if (!DeviceExtension->InquiryIrp)
        {
            DPRINT1("SpAllocateAdapterResources: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        DPRINT("SpAllocateAdapterResources: DeviceExtension->InquiryIrp %p\n", DeviceExtension->InquiryIrp);

        DeviceExtension->InquiryMdl = IoAllocateMdl(DeviceExtension->InquiryData, INQUIRYDATABUFFERSIZE, FALSE, FALSE, NULL);
        if (!DeviceExtension->InquiryMdl)
        {
            DPRINT1("SpAllocateAdapterResources: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        DPRINT("SpAllocateAdapterResources: DeviceExtension->InquiryMdl %p\n", DeviceExtension->InquiryMdl);

        MmBuildMdlForNonPagedPool(DeviceExtension->InquiryMdl);
    }

    IoScsiCapabilities->Length = sizeof(*IoScsiCapabilities);
    IoScsiCapabilities->MaximumTransferLength = PortConfig->MaximumTransferLength;

    if (PortConfig->ReceiveEvent)
        IoScsiCapabilities->SupportedAsynchronousEvents |= 2;

    IoScsiCapabilities->TaggedQueuing = DeviceExtension->TaggedQueuing;
    IoScsiCapabilities->AdapterScansDown = PortConfig->AdapterScansDown;

    if (PortConfig->AlignmentMask > DeviceObject->AlignmentRequirement)
        DeviceObject->AlignmentRequirement = PortConfig->AlignmentMask;

    IoScsiCapabilities->AlignmentMask = DeviceObject->AlignmentRequirement;

    if (!IoScsiCapabilities->MaximumPhysicalPages)
    {
        IoScsiCapabilities->MaximumPhysicalPages = BYTES_TO_PAGES(IoScsiCapabilities->MaximumTransferLength);

        if (IoScsiCapabilities->MaximumPhysicalPages > PortConfig->NumberOfPhysicalBreaks)
            IoScsiCapabilities->MaximumPhysicalPages = PortConfig->NumberOfPhysicalBreaks;
    }

    return Status;
}

BOOLEAN
NTAPI
SpGetInterruptState(
    _In_ PVOID InContext)
{
    PSCSI_PORT_GET_INT_STATE_CONTEXT Context = InContext;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    PSCSI_PORT_SRB_DATA SrbData;
    PSCSI_REQUEST_BLOCK Srb;
    ULONG OldDpcFlags;
    ULONG ix;

    DeviceExtension = Context->DeviceExtension;

    DPRINT("SpGetInterruptState: %p %X\n", DeviceExtension, Context->DeviceExtension->InterruptData.Flags);

    if (!(Context->DeviceExtension->InterruptData.Flags & 4))
    {
        DeviceExtension->DpcFlags &= 0x20000;
        DPRINT("SpGetInterruptState: DpcFlags %X\n", DeviceExtension->DpcFlags);
        return FALSE;
    }

    RtlCopyMemory(Context->InterruptData, &Context->DeviceExtension->InterruptData, sizeof(*Context->InterruptData));

    Context->DeviceExtension->InterruptData.Flags &= 0x84180;

    DeviceExtension->InterruptData.CompletedRequests = 0;
    DeviceExtension->InterruptData.ReadyLogicalUnit = 0;
    DeviceExtension->InterruptData.AbortLogicalUnit = 0;

    OldDpcFlags = InterlockedExchange((PLONG)&DeviceExtension->DpcFlags, 0x20000);
    ASSERT(OldDpcFlags == 0x20004);//(PD_NOTIFICATION_REQUIRED | PD_DPC_RUNNING)

    ix = 0;

    for (SrbData = Context->InterruptData->CompletedRequests;
         SrbData;
         SrbData = SrbData->CompletedRequests)
    {
        if (ix > DeviceExtension->ActiveRequestCount)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        ix++;

        ASSERT(SrbData->CurrentSrb != NULL);
        Srb = SrbData->CurrentSrb;
        ASSERT(!(Srb->SrbFlags & SRB_FLAGS_IS_ACTIVE));

        LunExtension = SrbData->LunExtension;

        if (Srb->SrbStatus != 1)
        {
            if (Srb->ScsiStatus == 2 && !(Srb->SrbStatus & 0x80) && Srb->SenseInfoBuffer && Srb->SenseInfoBufferLength)
            {
                if (LunExtension->LuFlags & 4)
                {
                    Srb->ScsiStatus = 0;
                    Srb->SrbStatus = 0x10;
                }
                else
                {
                    UNIMPLEMENTED_DBGBREAK();
                }
            }

            if (Srb->ScsiStatus == 0x28)
            {
                UNIMPLEMENTED_DBGBREAK();
            }
        }

        if (Srb->QueueTag != 0xFF)
        {
            if (LunExtension->SrbDataList.Flink != &SrbData->Link)
            {
                RemoveEntryList(&SrbData->Link);
                continue;
            }

            RemoveEntryList(&SrbData->Link);
        }

        if (IsListEmpty(&LunExtension->SrbDataList))
        {
            LunExtension->RequestTimeoutCounter = -1;
            continue;
        }

        UNIMPLEMENTED_DBGBREAK();
    }

    return TRUE;
}

VOID
NTAPI
SpProcessCompletedRequest(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_SRB_DATA SrbData,
    _Out_ BOOLEAN* OutIsStartIo)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ScsiPortCompletionDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PDEVICE_OBJECT DeviceObject = DeferredContext;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_LUN_EXTENSION ReadyLunExt;
    PSCSI_PORT_LUN_EXTENSION PrevReadyLunExt;
    PSCSI_PORT_SRB_DATA SrbData;
    SCSI_PORT_GET_INT_STATE_CONTEXT Context;
    SCSI_PORT_INTERRUPT_DATA IntData;
    LARGE_INTEGER DueTime;
    BOOLEAN IsStartIo;

    DeviceExtension = DeviceObject->DeviceExtension;

    DPRINT("ScsiPortCompletionDpc: %p\n", DeviceExtension);

    do
    {
        KeAcquireSpinLockAtDpcLevel(&DeviceExtension->SpinLock);

        Context.InterruptData = &IntData;
        Context.DeviceExtension = DeviceExtension;

        if (!DeviceExtension->SynchronizeFunction(DeviceExtension->InterruptObject, SpGetInterruptState, &Context))
        {
            KeReleaseSpinLockFromDpcLevel(&DeviceExtension->SpinLock);
            continue;
        }

        if (IntData.Flags & 0x170030)
        {
            if (IntData.Flags & 0x10)
            {
                if (Sp64BitPhysicalAddresses)
                {
                    KeBugCheckEx(0x2C, 3, 0xC00000BB, (ULONG_PTR)DeviceExtension->HwDeviceExtension, (ULONG_PTR)DeviceExtension->CommonExtension.SelfDevice->DriverObject);
                }

                UNIMPLEMENTED_DBGBREAK();
            }

            if ((IntData.Flags & 0x20) && !(IntData.Flags & 0x80000))
            {
                if (Sp64BitPhysicalAddresses)
                {
                    KeBugCheckEx(0x2C, 4, 0xC00000BB, (ULONG_PTR)DeviceExtension->HwDeviceExtension, (ULONG_PTR)DeviceExtension->CommonExtension.SelfDevice->DriverObject);
                }

                UNIMPLEMENTED_DBGBREAK();
            }

            if ((IntData.Flags & 0x10000) && !(IntData.Flags & 0x80000))
            {
                if (DeviceExtension->VerifierExtension)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }
                else
                {
                    DeviceExtension->HwTimerInt = IntData.HwTimerInt;
                }

                if (IntData.MiniportTimerValue)
                {
                    if (!(DeviceExtension->Flags & 0x800000))
                    {
                        DueTime.QuadPart = -10;
                        DueTime.QuadPart *= IntData.MiniportTimerValue;
                        KeSetTimer(&DeviceExtension->MiniPortTimer, DueTime, &DeviceExtension->MiniPortDpc);
                        DPRINT("ScsiPortCompletionDpc: DueTime %I64X\n", DueTime.QuadPart);
                    }
                }
                else
                {
                    KeCancelTimer(&DeviceExtension->MiniPortTimer);
                }
            }

            if (IntData.Flags & 0x20000)
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            if (IntData.Flags & 0x40000)
            {
                DPRINT1("ScsiPortCompletionDpc: call IoInvalidateDeviceRelations(BusRelations)\n");
                DeviceExtension->RunEnumSync = 1;
                IoInvalidateDeviceRelations(DeviceExtension->LowerPdo, 0);
            }

            if (IntData.Flags & 0x100000)
            {
                UNIMPLEMENTED_DBGBREAK();
            }
        }

        if (IntData.Flags & 8)
        {
            if ((DeviceExtension->Flags & 0x1001) == 0x1001)
            {
                DeviceExtension->Flags &= ~1;

                if (!(IntData.Flags & 0x80))
                    DeviceExtension->TimeOut = 0xFFFFFFFF;
            }
            else
            {
                DeviceExtension->Flags &= ~1;
                IntData.Flags &= ~8;
            }
        }

        if (IntData.Flags & 0x200)
            DeviceExtension->TimeOut = DeviceExtension->ResetHoldTime;

        ReadyLunExt = IntData.ReadyLogicalUnit;
        while (ReadyLunExt)
        {
            GetNextLuRequest(ReadyLunExt);

            KeAcquireSpinLockAtDpcLevel(&DeviceExtension->SpinLock);

            PrevReadyLunExt = ReadyLunExt;
            ReadyLunExt = ReadyLunExt->ReadyLogicalUnit;
            PrevReadyLunExt->ReadyLogicalUnit = NULL;
        }

        KeReleaseSpinLockFromDpcLevel(&DeviceExtension->SpinLock);

        if ((IntData.Flags & 8) && !(IntData.Flags & 0x100))
        {
            //ASSERT(!(TEST_FLAG(ext->Flags, PD_PENDING_DEVICE_REQUEST)));
            ASSERT(!(DeviceExtension->Flags & 0x800));
            IoStartNextPacket(DeviceExtension->CommonExtension.SelfDevice, 0);
        }

        if (IntData.Flags & 0x40)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        IsStartIo = FALSE;

        while (IntData.CompletedRequests)
        {
            SrbData = IntData.CompletedRequests;
            ASSERT(SrbData->Type == 0x7770);//SRB_DATA_TYPE
            IntData.CompletedRequests = SrbData->CompletedRequests;
            SrbData->CompletedRequests = 0;
            SpProcessCompletedRequest(DeviceExtension, SrbData, &IsStartIo);
        }

        if (IsStartIo)
        {
            ASSERT(DeviceObject->CurrentIrp != NULL);
        }

        while (IntData.AbortLogicalUnit)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (IsStartIo)
        {
            ASSERT(DeviceObject->CurrentIrp != NULL);
            ScsiPortStartIo(DeviceObject, DeviceObject->CurrentIrp);
        }

        if ((IntData.Flags & 0x8000) && !(IntData.Flags & 0x80000))
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        DPRINT("ScsiPortCompletionDpc: %X\n", DeviceExtension->DpcFlags);
    }
    while (((InterlockedCompareExchange((PLONG)&DeviceExtension->DpcFlags, 0, 0x20000)) & 4) == 4);
}

VOID
NTAPI
ScsiPortTickHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
SpMiniPortTimerDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
ScsiPortInterrupt(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID ServiceContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
SpRequestCompletionDpc(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;

    DeviceExtension = DeviceObject->DeviceExtension;

    DPRINT("SpRequestCompletionDpc: %p, %X\n", DeviceExtension, DeviceExtension->DpcFlags);

    if (!(InterlockedExchange((PLONG)&DeviceExtension->DpcFlags, 0x20004) & 0x20000))
    {
        DPRINT("SpRequestCompletionDpc: %p %X\n", DeviceExtension, DeviceExtension->DpcFlags);
        KeInsertQueueDpc(&DeviceObject->Dpc, NULL, NULL);
    }
}

NTSTATUS
NTAPI
SpCallHwInitialize(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PSCSI_PORT_SYNCHRONIZE_EXECUTION SynchronizeFunction;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PPORT_CONFIGURATION_INFORMATION PortConfig;
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    PACCESS_RANGE AccessRange;
    KAFFINITY Affinity;
    ULONG Vector;
    ULONG ix;
    ULONG jx;
    KIRQL SynchronizeIrql;
    KIRQL Irql;
    KIRQL Irql2;
    BOOLEAN IsSecondInterrupt;
    BOOLEAN IsShareVector;
    BOOLEAN Result;
    NTSTATUS status;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("SpCallHwInitialize: %p\n", DeviceObject);

    DeviceExtension = DeviceObject->DeviceExtension;
    PortConfig = DeviceExtension->PortConfig;

    KeInitializeSpinLock(&DeviceExtension->SpinLock);
    KeInitializeDpc(&DeviceExtension->CommonExtension.SelfDevice->Dpc, ScsiPortCompletionDpc, DeviceExtension->CommonExtension.SelfDevice);
    DeviceExtension->TimeOut = -1;

    if (!DeviceObject->Timer)
        IoInitializeTimer(DeviceObject, ScsiPortTickHandler, 0);

    KeInitializeTimer(&DeviceExtension->MiniPortTimer);
    KeInitializeDpc(&DeviceExtension->MiniPortDpc, SpMiniPortTimerDpc, DeviceObject);
    KeInitializeSpinLock(&DeviceExtension->MiniPortLock);

    if (DeviceExtension->HwInterrupt && (DeviceExtension->Flags2 & 8))
    {
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: Interrupt Info for adapter %#p\n", DeviceObject);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: AdapterInterfaceType = %d\n", PortConfig->AdapterInterfaceType);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: BusInterruptLevel = %d\n", PortConfig->BusInterruptLevel);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: BusInterruptVector = %d\n", PortConfig->BusInterruptVector);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: BusInterruptLevel2 = %d\n", PortConfig->BusInterruptLevel2);
        //ScsiDebugPrintInt(1, "ScsiPortInitialize: BusInterruptVector2 = %d\n", PortConfig->BusInterruptVector2);

        DPRINT("SpCallHwInitialize: Interrupt Info for adapter %p\n", DeviceObject);
        DPRINT("SpCallHwInitialize: AdapterInterfaceType %X\n", PortConfig->AdapterInterfaceType);
        DPRINT("SpCallHwInitialize: BusInterruptLevel %X\n", PortConfig->BusInterruptLevel);
        DPRINT("SpCallHwInitialize: BusInterruptVector %X\n", PortConfig->BusInterruptVector);
        DPRINT("SpCallHwInitialize: BusInterruptLevel2 %X\n", PortConfig->BusInterruptLevel2);
        DPRINT("SpCallHwInitialize: BusInterruptVector2 %X\n", PortConfig->BusInterruptVector2);

        Irql = 0;
        Irql2 = 0;
        Vector = 0;
        Affinity = 0;
        IsShareVector = FALSE;
        IsSecondInterrupt = FALSE;

        if (DeviceExtension->HwInterrupt &&
            (PortConfig->BusInterruptLevel || PortConfig->BusInterruptVector) &&
            (PortConfig->BusInterruptLevel2 || PortConfig->BusInterruptVector2))
        {
            IsSecondInterrupt = TRUE;
        }

        DeviceExtension->BusInterruptLevel = PortConfig->BusInterruptLevel;
        DeviceExtension->SynchronizeFunction = KeSynchronizeExecution;

        if (!(DeviceExtension->Flags2 & 1))
        {
            ASSERT(IsSecondInterrupt == FALSE);

            for (ix = 0; ix < DeviceExtension->AllocatedResourcesTranslated->Count; ix++)
            {
                FullList = &DeviceExtension->AllocatedResourcesTranslated->List[ix];

                for (jx = 0; jx < FullList->PartialResourceList.Count; jx++)
                {
                    CmDescriptor = &FullList->PartialResourceList.PartialDescriptors[jx];

                    if (CmDescriptor->Type == CmResourceTypeInterrupt)
                    {
                        Vector = CmDescriptor->u.Interrupt.Vector;
                        Affinity = CmDescriptor->u.Interrupt.Affinity;
                        Irql = (KIRQL)CmDescriptor->u.Interrupt.Level;

                        if (CmDescriptor->ShareDisposition == CmResourceShareShared)
                            IsShareVector = TRUE;

                        break;
                    }
                }
            }
        }
        else
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (Irql > Irql2)
            SynchronizeIrql = Irql;
        else
            SynchronizeIrql = Irql2;

        //ScsiDebugPrintInt(1, "SpCallHwInitialize: vector = %d\n", Vector);
        //ScsiDebugPrintInt(1, "SpCallHwInitialize: irql = %d\n", Irql);
        //ScsiDebugPrintInt(1, "SpCallHwInitialize: affinity = %#08lx\n", Affinity);

        DPRINT("SpCallHwInitialize: Vector %X\n", Vector);
        DPRINT("SpCallHwInitialize: Irql %X\n", Irql);
        DPRINT("SpCallHwInitialize: Affinity %X\n", Affinity);

        status = IoConnectInterrupt(&DeviceExtension->InterruptObject,
                                    ScsiPortInterrupt,
                                    DeviceObject,
                                    (IsSecondInterrupt ? &DeviceExtension->IrqLock : NULL),
                                    Vector,
                                    Irql,
                                    SynchronizeIrql,
                                    PortConfig->InterruptMode,
                                    IsShareVector,
                                    Affinity,
                                    FALSE);
        if (!NT_SUCCESS(status))
        {
            //ScsiDebugPrintInt(1, "SpInitializeAdapter: Can't connect interrupt %d\n", Vector);
            DPRINT1("SpCallHwInitialize: Can't connect interrupt %X\n", Vector);
            DeviceExtension->InterruptObject = 0;
            return status;
        }

        if (IsSecondInterrupt)
        {
            //ScsiDebugPrintInt(1, "SpInitializeAdapter: SCSI adapter second IRQ is %d\n", PortConfig->BusInterruptLevel2);
            //ScsiDebugPrintInt(1, "SpInitializeAdapter: vector = %d\n", Vector);
            //ScsiDebugPrintInt(1, "SpInitializeAdapter: irql = %d\n", Irql);
            //ScsiDebugPrintInt(1, "SpInitializeAdapter: affinity = %#08lx\n", Affinity);

            DPRINT("SpCallHwInitialize: SCSI adapter second IRQ is %X\n", PortConfig->BusInterruptLevel2);
            DPRINT("SpCallHwInitialize: Vector %X\n", Vector);
            DPRINT("SpCallHwInitialize: Irql %X\n", Irql);
            DPRINT("SpCallHwInitialize: Affinity %X\n", Affinity);

            UNIMPLEMENTED_DBGBREAK();
        }

        Status = STATUS_SUCCESS;
    }
    else
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (PortConfig->NumberOfAccessRanges)
    {
        AccessRange = &((*PortConfig->AccessRanges)[0]);
        DeviceExtension->IoAddress = AccessRange->RangeStart.LowPart;

        //ScsiDebugPrintInt(1, "SpInitializeAdapter: IO Base address %x\n", DeviceExtension->IoAddress);
        DPRINT("SpCallHwInitialize: IO Base address %X\n", DeviceExtension->IoAddress);
    }

    DeviceExtension->Flags |= 0x1000;
    DeviceExtension->ActiveRequestCount = -1;
    DeviceExtension->NeedPhAddrForMasterDma = (DeviceExtension->DmaAdapter && PortConfig->Master && PortConfig->NeedPhysicalAddresses);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    SynchronizeFunction = DeviceExtension->SynchronizeFunction;

    Result = SynchronizeFunction(DeviceExtension->InterruptObject, DeviceExtension->HwInitialize, DeviceExtension->HwDeviceExtension);
    if (Result)
    {
        if (DeviceExtension->InterruptData.Flags & 4)
            SpRequestCompletionDpc(DeviceObject);
    }
    else
    {
        //ScsiDebugPrintInt(1, "SpInitializeAdapter: initialization failed\n");
        DPRINT1("SpCallHwInitialize: initialization failed\n");
        Status = STATUS_ADAPTER_HARDWARE_ERROR;
    }

    KeLowerIrql(Irql);

    return Status;
}

VOID
NTAPI
SpGetSupportedAdapterControlFunctions(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    SCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpGetSupportedAdapterControlFunctions: %p\n", DeviceExtension);

    RtlInitializeBitMap(&DeviceExtension->ScsiControlBitMap, &DeviceExtension->ScsiControlBitMapBuffer, ScsiAdapterControlMax);
    RtlClearAllBits(&DeviceExtension->ScsiControlBitMap);

    if (!DeviceExtension->HwAdapterControl)
        return;

    if (!(DeviceExtension->Flags2 & 4))
        return;

    RtlZeroMemory(&ControlTypeList, sizeof(ControlTypeList)); 

    ControlTypeList.MaxControlType = ScsiAdapterControlMax;
    ControlTypeList.SupportedTypeList[ScsiAdapterControlMax] = 0x63;

    if (DeviceExtension->HwAdapterControl(DeviceExtension->HwDeviceExtension, ScsiQuerySupportedControlTypes, &ControlTypeList))
        return;

    ASSERT(ControlTypeList.SupportedTypeList[ScsiAdapterControlMax] == 0x63);

    for (ix = 0; ix < ScsiAdapterControlMax; ix++)
    {
        if (ControlTypeList.SupportedTypeList[ix] == 1)
            RtlSetBits(&DeviceExtension->ScsiControlBitMap, ix, 1);
    }
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

                Status = SpCallHwFindAdapter(DeviceObject, ChainEntry, NULL, &CfgContext, PortConfig, &IsAgain);

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

VOID
NTAPI
SpWmiInitializeSpRegInfo(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    UNIMPLEMENTED;
}

NTSTATUS
NTAPI
SpBuildLogicalUnitDeviceMapEntry(
    _In_ PSCSI_PORT_LUN_EXTENSION LunExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SpCreateNumericKey(
    _In_ HANDLE RootKeyHandle,
    _In_ ULONG NumericValue,
    _In_ PWSTR String,
    _In_ BOOLEAN IsNewKey,
    _Out_ HANDLE* OutHandle,
    _Out_ ULONG* OutDisposition)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING NumericKeyName;
    UNICODE_STRING IntegerUnicode;
    WCHAR NumericKeyBuffer[0x40];
    WCHAR IntegerBuffer[0x10];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpCreateNumericKey: %d, '%S'\n", NumericValue, String);

    NumericKeyName.Length = 0;
    NumericKeyName.MaximumLength = 0x40;
    NumericKeyName.Buffer = NumericKeyBuffer;

    RtlInitUnicodeString(&IntegerUnicode, String);
    RtlCopyUnicodeString(&NumericKeyName, &IntegerUnicode);

    IntegerUnicode.Length = 0;
    IntegerUnicode.MaximumLength = 0x10;
    IntegerUnicode.Buffer = IntegerBuffer;

    Status = RtlIntegerToUnicodeString(NumericValue, 10, &IntegerUnicode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpCreateNumericKey: Status %X\n", Status);
        return Status;
    }

    RtlAppendUnicodeStringToString(&NumericKeyName, &IntegerUnicode);
    InitializeObjectAttributes(&ObjectAttributes, &NumericKeyName, OBJ_CASE_INSENSITIVE, RootKeyHandle, NULL);

    if (IsNewKey)
    {
        return ZwCreateKey(OutHandle, (KEY_READ | KEY_WRITE), &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, OutDisposition);
    }

    Status = ZwOpenKey(OutHandle, (KEY_READ | KEY_WRITE), &ObjectAttributes);

    *OutDisposition = REG_OPENED_EXISTING_KEY;

    return Status;
}

NTSTATUS
NTAPI
SpBuildAdapterDeviceMap(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    PSCSI_PORT_DRIVER_EXTENSION DriverExtension;
    PSCSI_PORT_DEVICE_MAP_ENTRY CurrentEntry;
    PUNICODE_STRING ServicePath;
    UNICODE_STRING ValueName;
    WCHAR NameBuffer[0x20];
    PWCHAR pChar;
    ULONG Disposition;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpBuildAdapterDeviceMap: %p\n", DeviceExtension);

    DriverExtension = IoGetDriverObjectExtension(DeviceExtension->CommonExtension.SelfDevice->DriverObject, ScsiPortInitialize);
    ASSERT(DriverExtension != NULL);

    if (!ScsiDeviceMapKey)
    {
        DPRINT1("SpBuildAdapterDeviceMap: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    Status = SpCreateNumericKey(ScsiDeviceMapKey,
                                DeviceExtension->PortScsiPort,
                                L"Scsi Port ",
                                1,
                                &DeviceExtension->ScsiPortKeyHandle,
                                &Disposition);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SpBuildAdapterDeviceMap: %p\n", Status);
        return Status;
    }

    if (IsEqualGUID(&GUID_BUS_TYPE_PCMCIA, &DeviceExtension->BusTypeGuid))
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    ServicePath = &DriverExtension->RegistryPath;
    ASSERT(ServicePath != NULL);

    RtlInitUnicodeString(&ValueName, L"Driver");

    pChar = Add2Ptr(ServicePath->Buffer, (ServicePath->Length - 2));
    while (*pChar != L'\\')
    {
        if (pChar <= ServicePath->Buffer)
            break;

        pChar--;
    }

    if (*pChar == '\\')
    {
        pChar++;

        for (ix = 0; ix < 30; ix++)
        {
            NameBuffer[ix] = *pChar;

            pChar++;
            if (pChar >= &ServicePath->Buffer[ServicePath->Length / 2])
                break;
        }

        ix++;

        NameBuffer[ix] = 0;

        ZwSetValueKey(DeviceExtension->ScsiPortKeyHandle, &ValueName, 0, REG_SZ, NameBuffer, ((ix + 1) * sizeof(WCHAR)));
    }

    DeviceExtension->DeviceMapEntry = ExAllocatePoolWithTag(PagedPool,
                                                            (DeviceExtension->NumberOfBuses * sizeof(SCSI_PORT_DEVICE_MAP_ENTRY)),
                                                            'VPcS');
    if (!DeviceExtension->DeviceMapEntry)
    {
        DPRINT1("SpBuildAdapterDeviceMap: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(DeviceExtension->DeviceMapEntry, (DeviceExtension->NumberOfBuses * sizeof(SCSI_PORT_DEVICE_MAP_ENTRY)));

    for (ix = 0; ix < DeviceExtension->NumberOfBuses; ix++)
    {
        CurrentEntry = &DeviceExtension->DeviceMapEntry[ix];

        Status = SpCreateNumericKey(DeviceExtension->ScsiPortKeyHandle,
                                    ix,
                                    L"Scsi Bus ",
                                    1,
                                    &CurrentEntry->ScsiBusHandle,
                                    &Disposition);
        if (NT_SUCCESS(Status))
        {
            SpCreateNumericKey(CurrentEntry->ScsiBusHandle,
                               DeviceExtension->PortConfig->InitiatorBusId[ix],
                               L"Initiator Id ",
                               1,
                               &CurrentEntry->InitiatorIdHandle,
                               &Disposition);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SpBuildDeviceMapEntry(
    _In_ PVOID DeviceObjectExtension)
{
    PCOMMON_EXTENSION CommonExtension = DeviceObjectExtension;

    PAGED_CODE();
    DPRINT("SpBuildDeviceMapEntry: %p\n", DeviceObjectExtension);

    if (CommonExtension->IsPdo)
        return SpBuildLogicalUnitDeviceMapEntry(DeviceObjectExtension);

    return SpBuildAdapterDeviceMap(DeviceObjectExtension);
}

NTSTATUS
NTAPI
ScsiPortStartAdapter(
    _In_ PDEVICE_OBJECT Fdo)
{
    PSCSI_PORT_DRIVER_EXTENSION SpDriverExtension;
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PCONFIGURATION_INFORMATION ConfigInfo;
    UNICODE_STRING SymbolicLinkName;
    UNICODE_STRING DeviceName;
    WCHAR Buffer[64];
    ULONG Port = 0;
    NTSTATUS Status;

    PAGED_CODE();

    SpDriverExtension = IoGetDriverObjectExtension(Fdo->DriverObject, ScsiPortInitialize);
    DeviceExtension = Fdo->DeviceExtension;

    ASSERT(SpDriverExtension != NULL);
    ASSERT(!(DeviceExtension->CommonExtension.IsPdo));
    ASSERT(DeviceExtension->CommonExtension.CurrentPnpState != 0);//IRP_MN_START_DEVICE
    ASSERT(DeviceExtension->CommonExtension.IsInitialized);
    ASSERT(((Fdo->Flags & DO_DEVICE_INITIALIZING) == 0));

    //ScsiDebugPrintInt(1, "ScsiPortStartAdapter - starting adapter %#p\n", Fdo);
    DPRINT("ScsiPortStartAdapter: %p\n", Fdo);

    IoStartTimer(Fdo);

    if (!DeviceExtension->CommonExtension.WmiInitialized)
        SpWmiInitializeSpRegInfo(Fdo);

    if (DeviceExtension->PortScsiPort != 0xFFFFFFFF)
        goto Exit;

    RtlInitUnicodeString(&DeviceName, DeviceExtension->DeviceNameBuffer);

    do
    {
        swprintf(Buffer, L"\\Device\\ScsiPort%d", Port);
        RtlInitUnicodeString(&SymbolicLinkName, Buffer);

        Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
        if (!NT_SUCCESS(Status))
        {
            Port++;
            continue;
        }

        DeviceExtension->PortScsiPort = Port;

        swprintf(Buffer, L"\\DosDevices\\Scsi%d:", Port);
        RtlInitUnicodeString(&SymbolicLinkName, Buffer);

        IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    }
    while (Status == STATUS_OBJECT_NAME_COLLISION);

    ConfigInfo = IoGetConfigurationInformation();
    ConfigInfo->ScsiPortCount++;

    SpBuildDeviceMapEntry(DeviceExtension);

    Status = IoRegisterDeviceInterface(DeviceExtension->LowerPdo, &GUID_DEVINTERFACE_STORAGEPORT, NULL, &SymbolicLinkName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ScsiPortStartAdapter: Status %X\n", Status);
        goto Exit;
    }

    DeviceExtension->SymbolicLinkName = SymbolicLinkName;

    Status = IoSetDeviceInterfaceState(&SymbolicLinkName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ScsiPortStartAdapter: Status %X\n", Status);
        RtlFreeUnicodeString(&SymbolicLinkName);
        RtlInitUnicodeString(&DeviceExtension->SymbolicLinkName, NULL);
    }

Exit:

    DeviceExtension->RunEnumSync = 1;

    DPRINT("ScsiPortStartAdapter: return STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
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
    _In_ BOOLEAN Param3)
{
    VOID (NTAPI* CallBack)(PSCSI_PORT_DEVICE_EXTENSION, PSCSI_PORT_ENUM_REQUEST, NTSTATUS);
    PIRP RequestIrp;
    LARGE_INTEGER CurrentTime;
    LONG RunEnumSync;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT1("SpEnumerateAdapterAsynchronous: %p, %p, %X\n", DeviceExtension, EnumRequest, Param3);

    ASSERT(EnumRequest->CompletionRoutine != NULL);
    ASSERT(EnumRequest->NextRequest == NULL);

    ExAcquireFastMutex(&DeviceExtension->EnumFastMutex);
    RunEnumSync = InterlockedExchange(&DeviceExtension->RunEnumSync, 0);

    if (!Param3 && !RunEnumSync && !DeviceExtension->EnumerationRunning)
    {
        KeQuerySystemTime(&CurrentTime);
        CurrentTime.QuadPart -= DeviceExtension->EnumTime.QuadPart;
    }

    if (!Param3 && !RunEnumSync && !DeviceExtension->EnumerationRunning && CurrentTime.QuadPart <= 300000000)
    {
        RequestIrp = NULL;

        ASSERT(DeviceExtension->EnumerationRunning == FALSE);

        ExReleaseFastMutex(&DeviceExtension->EnumFastMutex);

        Status = KeWaitForSingleObject(&DeviceExtension->EnumMutex, UserRequest, KernelMode, FALSE, NULL);

        if (!EnumRequest->IsNotCompleteEnumRequest)
            RequestIrp = EnumRequest->Irp;

        CallBack = EnumRequest->CompletionRoutine;
        CallBack(DeviceExtension, EnumRequest, Status);

        if (Status == STATUS_SUCCESS)
            KeReleaseMutex(&DeviceExtension->EnumMutex, FALSE);

        if (RequestIrp)
            SpCompleteEnumRequest(DeviceExtension, RequestIrp);
    }
    else
    {
        SpAcquireRemoveLockEx(DeviceExtension->CommonExtension.SelfDevice, &EnumRequest->NextRequest, __FILE__, __LINE__);

        EnumRequest->NextRequest = DeviceExtension->RequestHead;
        DeviceExtension->RequestHead = EnumRequest;

        if (!DeviceExtension->EnumerationRunning)
        {
            DeviceExtension->EnumerationRunning = TRUE;
            ExQueueWorkItem(&DeviceExtension->EnumWorkItem, DelayedWorkQueue);
        }

        ExReleaseFastMutex(&DeviceExtension->EnumFastMutex);
    }

    DPRINT1("SpEnumerateAdapterAsynchronous: exit %p, %p, %X\n", DeviceExtension, EnumRequest, Param3);
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
SpGetBusData(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_OBJECT AttachedToDevice,
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Length)
{
    DPRINT("SpGetBusData: %X\n", BusNumber);

    if (!AttachedToDevice)
        return HalGetBusData(BusDataType, BusNumber, SlotNumber, Buffer, Length);

    if (BusDataType == PCIConfiguration)
    {
        ASSERT(DeviceExtension->LowerBusInterfaceStandardRetrieved == TRUE);
        return DeviceExtension->Interface.GetBusData(DeviceExtension->Interface.Context, 0, Buffer, 0, Length);
    }

    ASSERT(FALSE && "Invalid PCI_WHICHSPACE_ parameter");
    return 0;
}

ULONG
NTAPI
ScsiPortGetBusData(
    _In_ PVOID MiniportExtension,
    _In_ ULONG BusDataType,
    _In_ ULONG SystemIoBusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Length)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT AttachedToDevice;
    PSCSI_PORT_HW_DATA SpHwData;

    DPRINT("ScsiPortGetBusData: %X\n", BusDataType);

    SpHwData = CONTAINING_RECORD(MiniportExtension, SCSI_PORT_HW_DATA, HwDeviceExtension);
    DeviceExtension = SpHwData->DeviceExtension;

    if (!(DeviceExtension->Flags2 & 2))
    {
        AttachedToDevice = NULL;
    }
    else if (SlotNumber != DeviceExtension->PciSlotNumber.u.AsULONG)
    {
        ASSERT(BusDataType == PCIConfiguration);
        return 2;
    }
    else
    {
        AttachedToDevice = DeviceExtension->CommonExtension.LowDevice;
    }

    if (Length)
        return SpGetBusData(DeviceExtension, AttachedToDevice, BusDataType, SystemIoBusNumber, SlotNumber, Buffer, Length);


    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

BOOLEAN
NTAPI
SpFindAddressTranslation(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ PHYSICAL_ADDRESS Address,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR OutDescriptor)
{
    PCM_RESOURCE_LIST CmResources;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedDescriptor;
    ULONGLONG Start;
    ULONG ix;
    ULONG jx;

    DPRINT("SpFindAddressTranslation: %X, %X\n", BusType, NumberOfBytes);

    CmResources = DeviceExtension->AllocatedResources;

    ASSERT(!(DeviceExtension->Flags2 & 1));//IsMiniportDetected
    ASSERT(DeviceExtension->AllocatedResources);
    ASSERT(DeviceExtension->AllocatedResourcesTranslated);//TranslatedResources

    for (ix = 0; ix < CmResources->Count; ix++)
    {
        if (CmResources->List[ix].InterfaceType != BusType)
            continue;

        if (CmResources->List[ix].BusNumber != BusNumber)
            continue;

        for (jx = 0; jx < CmResources->List[ix].PartialResourceList.Count; jx++)
        {
            Descriptor = &CmResources->List[ix].PartialResourceList.PartialDescriptors[jx];

            if (Descriptor->Type != (InIoSpace ? CmResourceTypePort : CmResourceTypeMemory))
                continue;

            Start = Descriptor->u.Generic.Start.QuadPart;

            if ((ULONGLONG)Address.QuadPart < Start)
                continue;

            if ((ULONGLONG)Address.QuadPart >= (Start + Descriptor->u.Generic.Length))
                continue;

            if (((ULONGLONG)Address.QuadPart + NumberOfBytes) > (Start + Descriptor->u.Generic.Length))
                continue;

            TranslatedDescriptor = &DeviceExtension->AllocatedResourcesTranslated->List[ix].PartialResourceList.PartialDescriptors[jx];

            OutDescriptor->Type = TranslatedDescriptor->Type;
            OutDescriptor->ShareDisposition = TranslatedDescriptor->ShareDisposition;
            OutDescriptor->Flags = TranslatedDescriptor->Flags;

            OutDescriptor->u.Generic.Start.QuadPart = (TranslatedDescriptor->u.Generic.Start.QuadPart + ((ULONGLONG)Address.QuadPart - Start));
            OutDescriptor->u.Generic.Length = TranslatedDescriptor->u.Generic.Length;

            return TRUE;
        }
    }

    return FALSE;
}

PSCSI_PORT_ADDRESS_MAPPING
NTAPI
SpAllocateAddressMapping(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    PSCSI_PORT_ADDRESS_MAPPING CurrentAddressMapping;

    PAGED_CODE();
    DPRINT("SpAllocateAddressMapping: %p\n", DeviceExtension);

    CurrentAddressMapping = DeviceExtension->AddressMapping;

    if (CurrentAddressMapping)
        DeviceExtension->AddressMapping = CurrentAddressMapping->Next;
    else
        CurrentAddressMapping = ExAllocatePoolWithTag(NonPagedPool, sizeof(*CurrentAddressMapping), 'mPcS');

    if (!CurrentAddressMapping)
    {
        //ScsiDebugPrintInt(0, "SpAllocateAddressMapping: Unable to allocate mapping\n");
        DPRINT1("SpAllocateAddressMapping: Unable to allocate mapping\n");
        return NULL;
    }

    RtlZeroMemory(CurrentAddressMapping, sizeof(*CurrentAddressMapping));

    CurrentAddressMapping->Next = DeviceExtension->CurrentAddressMapping;
    DeviceExtension->CurrentAddressMapping = CurrentAddressMapping;

    return CurrentAddressMapping;
}

PSCSI_PORT_ADDRESS_MAPPING
NTAPI
SpFindMappedAddress(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ SCSI_PHYSICAL_ADDRESS Address,
    _In_ ULONG NumberOfBytes,
    _In_ ULONG BusNumber)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

PVOID
NTAPI
ScsiPortGetDeviceBase(
    _In_ PVOID MiniportExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG SystemIoBusNumber,
    _In_ SCSI_PHYSICAL_ADDRESS IoAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_ADDRESS_MAPPING AddressMapping;
    PSCSI_PORT_HW_DATA SpHwData;
    PVOID MappedAddress;
    PCHAR IoSpaceName;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    LARGE_INTEGER TranslatedAddress;
    ULONG AddressSpace = InIoSpace;
    BOOLEAN Result = FALSE;

    DPRINT("ScsiPortGetDeviceBase: %X, %X\n", BusType, NumberOfBytes);

    SpHwData = CONTAINING_RECORD(MiniportExtension, SCSI_PORT_HW_DATA, HwDeviceExtension);
    DeviceExtension = SpHwData->DeviceExtension;

    if (!(DeviceExtension->Flags2 & 1))
    {
        Result = SpFindAddressTranslation(DeviceExtension, BusType, SystemIoBusNumber, IoAddress, NumberOfBytes, InIoSpace, &Descriptor);

        if (Result)
        {
            TranslatedAddress.QuadPart = Descriptor.u.Port.Start.QuadPart;
            AddressSpace = (Descriptor.Type == 1);
        }
        else
        {
            if (!InIoSpace)
                IoSpaceName = "Memory";
            else
                IoSpaceName = "I/O";
  
            //ScsiDebugPrintInt(1, "ScsiPortGetDeviceBase: SpFindAddressTranslation failed. %s Address = %lx\n", IoSpaceName, IoAddress.LowPart);
            DPRINT("ScsiPortGetDeviceBase: SpFindAddressTranslation failed. '%s' Address = %X\n", IoSpaceName, IoAddress.LowPart);
        }
    }

    if ((DeviceExtension->Flags & 0x40000) != 0x40000 && !Result)
    {
        Result = HalTranslateBusAddress(BusType, SystemIoBusNumber, IoAddress, &AddressSpace, &TranslatedAddress);
    }

    if (!Result)
    {
        if (!InIoSpace)
            IoSpaceName = "Memory";
        else
            IoSpaceName = "I/O";

        //ScsiDebugPrintInt(1, "ScsiPortGetDeviceBase: Translate bus address failed. %s Address = %lx\n", IoSpaceName, IoAddress.LowPart);
        DPRINT1("ScsiPortGetDeviceBase: Translate bus address failed. '%s' Address = %X\n", IoSpaceName, IoAddress.LowPart);

        return NULL;
    }

    if ((DeviceExtension->Flags & 0x40000) != 0x40000)
    {
        if (!AddressSpace)
        {
            MappedAddress = MmMapIoSpace(TranslatedAddress, NumberOfBytes, 0);
            if (!MappedAddress)
            {
                DPRINT1("ScsiPortGetDeviceBase: ret NULL\n");
                return NULL;
            }

            AddressMapping = SpAllocateAddressMapping(DeviceExtension);
            if (!AddressMapping)
            {
                //ScsiDebugPrintInt(0, "ScsiPortGetDeviceBase: could not find free block to track address mapping - returning NULL\n");
                DPRINT1("ScsiPortGetDeviceBase: could not find free block to track address mapping - returning NULL\n");
                MmUnmapIoSpace(MappedAddress, NumberOfBytes);
                return NULL;
            }

            AddressMapping->NumberOfBytes = NumberOfBytes;
            AddressMapping->Address.QuadPart = IoAddress.QuadPart;
            AddressMapping->MappedAddress = MappedAddress;
            AddressMapping->SystemIoBusNumber = SystemIoBusNumber;

            return MappedAddress;
        }

        return (PVOID)TranslatedAddress.LowPart;
    }

    if ((DeviceExtension->Flags & 0x40000) != 0x40000 || AddressSpace)
        return (PVOID)TranslatedAddress.LowPart;

    AddressMapping = SpFindMappedAddress(DeviceExtension, IoAddress, NumberOfBytes, SystemIoBusNumber);
    if (!AddressMapping)
    {
        DPRINT1("ScsiPortGetDeviceBase: KeBugCheckEx(PORT_DRIVER_INTERNAL)!\n");
        KeBugCheckEx(PORT_DRIVER_INTERNAL, 0, 0, 0, 0);
    }

    return AddressMapping->MappedAddress;
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
    _In_ PVOID MiniportExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb OPTIONAL,
    _In_ PVOID VirtualAddress,
    _Out_ ULONG* OutLength)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCATTER_GATHER_ELEMENT ScatterList;
    SCSI_PHYSICAL_ADDRESS PhAddress;
    PSCSI_PORT_HW_DATA SpHwData;
    PSCSI_PORT_SRB_DATA SrbData;
    ULONG ByteOffset;
    ULONG Length;

    SpHwData = CONTAINING_RECORD(MiniportExtension, SCSI_PORT_HW_DATA, HwDeviceExtension);
    DeviceExtension = SpHwData->DeviceExtension;

    DPRINT("ScsiPortGetPhysicalAddress: %p, %X\n", DeviceExtension, Srb);


    if (!Srb || (Srb->SenseInfoBuffer && Srb->SenseInfoBuffer == VirtualAddress))
    {
        ByteOffset = ((ULONG_PTR)VirtualAddress - (ULONG_PTR)DeviceExtension->CommonBuffer);
        ASSERT(ByteOffset < DeviceExtension->CommonBufferSize);

        Length = (DeviceExtension->CommonBufferSize - ByteOffset);
        PhAddress.QuadPart = (DeviceExtension->PhysicalCommonBuffer.LowPart + ByteOffset);
    }
    else if (DeviceExtension->NeedPhAddrForMasterDma)
    {
        SrbData = Srb->OriginalRequest;
       
        ASSERT(SrbData->Type == 0x7770); // SRB_DATA_TYPE

        ScatterList = SrbData->ScatterGatherList;
        ByteOffset = ((ULONG_PTR)VirtualAddress - (ULONG_PTR)Srb->DataBuffer);

        while (TRUE)
        {
            if (!ScatterList->Length || ByteOffset < ScatterList->Length)
                break;

            ByteOffset -= ScatterList->Length;
            ScatterList++;
        }

        ASSERT(ByteOffset <= ScatterList->Length);

        if (ByteOffset <= ScatterList->Length)
        {
            Length = (ScatterList->Length - ByteOffset);
            PhAddress.QuadPart = (ScatterList->Address.QuadPart + ByteOffset);
        }
        else
        {
            Length = 0;
            PhAddress.QuadPart = 0xFFFFFFFF;
        }
    }
    else
    {
        Length = 0;
        PhAddress.QuadPart = 0xFFFFFFFF;
    }

    *OutLength = Length;

    return PhAddress;
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
SpGetSrbExtensionBuffer(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    DPRINT("SpGetSrbExtensionBuffer: %p\n", DeviceExtension);

    if (DeviceExtension->VerifierExtension)
    {
        UNIMPLEMENTED_DBGBREAK();
        return NULL;
    }

    return DeviceExtension->CommonBuffer;
}

VOID
NTAPI
SpInitializePowerParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    ULONG InstanceValue;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpInitializePowerParams: %p\n", DeviceExtension);

    if (!(DeviceExtension->Flags2 & 4))
    {
        DeviceExtension->Flags2 &= ~0x40;
        return;
    }

    Status = SpReadNumericInstanceValue(DeviceExtension->LowerPdo, L"NeedsSystemShutdownNotification", &InstanceValue);
    if (!NT_SUCCESS(Status) || !InstanceValue)
    {
        DeviceExtension->Flags2 &= ~0x40;
    }

    DeviceExtension->Flags2 |= 0x40;
}

VOID
NTAPI
SpInitializePerformanceParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    ULONG InstanceValue;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpInitializePerformanceParams: %p\n", DeviceExtension);

    if (!(DeviceExtension->Flags2 & 4))
    {
        DeviceExtension->RemainInReducedMaxQueueState = 0xFFFFFFFF;
        return;
    }

    Status = SpReadNumericInstanceValue(DeviceExtension->LowerPdo, L"RemainInReducedMaxQueueState", &InstanceValue);
    if (!NT_SUCCESS(Status))
    {
        DeviceExtension->RemainInReducedMaxQueueState = 0xFFFFFFFF;
        return;
    }

    DeviceExtension->RemainInReducedMaxQueueState = InstanceValue;
}

VOID
NTAPI
SpInitializeRequestSenseParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension)
{
    ULONG InstanceValue;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("SpInitializeRequestSenseParams: %p\n", DeviceExtension);

    if (!(DeviceExtension->Flags2 & 4))
    {
        DeviceExtension->SenseDataBytes = 0;
        return;
    }

    Status = SpReadNumericInstanceValue(DeviceExtension->LowerPdo, L"TotalSenseDataBytes", &InstanceValue);
    if (!NT_SUCCESS(Status))
    {
        DeviceExtension->SenseDataBytes = 0;
        return;
    }

    if (InstanceValue <= sizeof(SENSE_DATA))
    {
        DeviceExtension->SenseDataBytes = 0;
        return;
    }

    if (InstanceValue < 0xFF)
        DeviceExtension->SenseDataBytes = (InstanceValue - sizeof(SENSE_DATA));
    else
        DeviceExtension->SenseDataBytes = (0xFF - sizeof(SENSE_DATA));
}

ULONG
NTAPI
SpGetCommonBufferSize(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG NumberOfBytes,
    _Out_ ULONG* OutSrbExtensionSize)
{
    ULONG SrbExtensionSize;
    ULONG BufferSize;

    DPRINT("SpGetCommonBufferSize: %p, %X\n", DeviceExtension, NumberOfBytes);

    if (!DeviceExtension->SrbExtensionSize)
        DeviceExtension->SrbExtensionSize = 0x10;

    SrbExtensionSize = DeviceExtension->SrbExtensionSize;

    if (DeviceExtension->AutoRequestSense)
        SrbExtensionSize += (DeviceExtension->SenseDataBytes + sizeof(SENSE_DATA));

    SrbExtensionSize = (SrbExtensionSize + 7) & ~7;
    BufferSize = ((SrbExtensionSize * DeviceExtension->NumberOfRequests + NumberOfBytes + 0xFFF) & 0xFFFFF000);

    if (OutSrbExtensionSize)
        *OutSrbExtensionSize = SrbExtensionSize;

    DPRINT("SpGetCommonBufferSize: ret %X\n", BufferSize);
    return BufferSize;
}

NTSTATUS
NTAPI
SpGetCommonBuffer(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG NumberOfBytes)
{
    PHYSICAL_ADDRESS BoundaryAddressMultiple;
    PVOID* SrbExtensionEntry;
    PVOID CommonBuffer;
    ULONG UncachedExtAlignment = 0;
    ULONG PageAlignedSize;
    ULONG SrbExtensionSize;
    ULONG CommonBufferSize;
    ULONG Size;
    ULONG ix;

    PAGED_CODE();
    DPRINT("SpGetCommonBuffer: %p, %X\n", DeviceExtension, NumberOfBytes);

    if (NumberOfBytes)
    {
        UncachedExtAlignment = DeviceExtension->UncachedExtAlignment;
        NumberOfBytes = ((NumberOfBytes + 0xFFF) & 0xFFFFF000);
        DeviceExtension->UncachedExtensionSize = NumberOfBytes;

        PageAlignedSize = ((NumberOfBytes + 0xFFF) & 0xFFFFF000);
    }
    else
    {
        PageAlignedSize = 0;
    }

    if (DeviceExtension->VerifierExtension)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    CommonBufferSize = SpGetCommonBufferSize(DeviceExtension, PageAlignedSize, &SrbExtensionSize);

    if (UncachedExtAlignment && PageAlignedSize)
    {
        CommonBufferSize = ((CommonBufferSize + UncachedExtAlignment - 1) & ~(UncachedExtAlignment - 1));
    }

    if (DeviceExtension->DmaAdapter)
    {
        if ((Sp64BitPhysicalAddresses && DeviceExtension->Dma64BitAddresses == 1) || UncachedExtAlignment)
        {
            if (UncachedExtAlignment)
                BoundaryAddressMultiple.QuadPart = CommonBufferSize;
            else
                BoundaryAddressMultiple.QuadPart = 0x0000000100000000;

            CommonBuffer = MmAllocateContiguousMemorySpecifyCache(CommonBufferSize,
                                                                  DeviceExtension->MinimumUCXAddress,
                                                                  DeviceExtension->MaximumUCXAddress,
                                                                  BoundaryAddressMultiple,
                                                                  MmCached);

            if (CommonBuffer)
                DeviceExtension->PhysicalCommonBuffer.QuadPart = MmGetPhysicalAddress(CommonBuffer).QuadPart;

            DeviceExtension->IsNotCacheAlignedCommonBuffer = FALSE;
        }
        else
        {
            DeviceExtension->IsNotCacheAlignedCommonBuffer = TRUE;
            CommonBuffer = DeviceExtension->DmaAdapter->DmaOperations->AllocateCommonBuffer(DeviceExtension->DmaAdapter, CommonBufferSize, &DeviceExtension->PhysicalCommonBuffer, 0);
        }
    }
    else
    {
        CommonBuffer = ExAllocatePoolWithTag(NonPagedPool, CommonBufferSize, 'cPcS');
    }

    //ScsiDebugPrintInt(1, "SpGetCommonBuffer: buffer:%p PhysicalCommonBuffer:%p\n", CommonBuffer, DeviceExtension->PhysicalCommonBuffer.QuadPart);
    DPRINT("SpGetCommonBuffer: %p %I64X\n", CommonBuffer, DeviceExtension->PhysicalCommonBuffer.QuadPart);

    if (!CommonBuffer)
    {
        DPRINT1("SpGetCommonBuffer: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CommonBuffer, CommonBufferSize);

    DeviceExtension->CommonBufferSize = CommonBufferSize;
    DeviceExtension->CommonBuffer = CommonBuffer;

    DeviceExtension->UncachedExtension = (NumberOfBytes ? CommonBuffer : NULL);

    if (!DeviceExtension->IsSrbExtensions)
        return STATUS_SUCCESS;

    Size = (CommonBufferSize - DeviceExtension->UncachedExtensionSize);

    DeviceExtension->SrbExtensionList = SrbExtensionEntry = (PVOID *)Add2Ptr(CommonBuffer, DeviceExtension->UncachedExtensionSize);

    for (ix = 0; Size >= (2 * SrbExtensionSize); ix++)
    {
        *SrbExtensionEntry = Add2Ptr(SrbExtensionEntry, SrbExtensionSize);
        Size -= SrbExtensionSize;
        SrbExtensionEntry = (PVOID *)Add2Ptr(SrbExtensionEntry, SrbExtensionSize);
    }

    //ScsiDebugPrintInt(1, "SpGetCommonBuffer: %d entries put onto SrbExtension list\n", ix);
    DPRINT("SpGetCommonBuffer: %X entries put onto SrbExtension list\n", ix);

    DeviceExtension->NumberOfRequests = ix;

    return STATUS_SUCCESS;
}

PVOID
NTAPI
ScsiPortGetUncachedExtension(
    _In_ PVOID MiniportExtension,
    _In_ PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    _In_ ULONG NumberOfBytes)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    DEVICE_DESCRIPTION DeviceDescription;
    PSCSI_PORT_HW_DATA SpHwData;
    ULONG NumberOfMapRegisters;
    NTSTATUS Status;

    SpHwData = CONTAINING_RECORD(MiniportExtension, SCSI_PORT_HW_DATA, HwDeviceExtension);
    DeviceExtension = SpHwData->DeviceExtension;

    DPRINT("ScsiPortGetUncachedExtension: %p, %p\n", MiniportExtension, DeviceExtension);

    if (DeviceExtension->Flags & 0x40000)
    {
        //ScsiDebugPrintInt(1, "ScsiPortGetUncachedExtension - miniport is reinitializing returning %#p\n", DeviceExtension->UncachedExtension);
        DPRINT("ScsiPortGetUncachedExtension - miniport is reinitializing returning %p\n", DeviceExtension->UncachedExtension);

        if (!(DeviceExtension->Flags & 0x80000))
        {
            DeviceExtension->Flags |= 0x80000;
            return DeviceExtension->UncachedExtension;
        }

        return 0;
    }

    if (SpGetSrbExtensionBuffer(DeviceExtension))
        return NULL;

    if (!DeviceExtension->DmaAdapter)
    {
        RtlZeroMemory(&DeviceDescription, sizeof(DeviceDescription));

        DeviceDescription.Version = 0;
        DeviceDescription.DmaChannel = ConfigInfo->DmaChannel;
        DeviceDescription.InterfaceType = ConfigInfo->AdapterInterfaceType;
        DeviceDescription.DmaWidth = ConfigInfo->DmaWidth;
        DeviceDescription.DmaSpeed = ConfigInfo->DmaSpeed;
        DeviceDescription.ScatterGather = ConfigInfo->ScatterGather;
        DeviceDescription.Master = ConfigInfo->Master;
        DeviceDescription.DmaPort = ConfigInfo->DmaPort;
        DeviceDescription.Dma32BitAddresses = ConfigInfo->Dma32BitAddresses;

        DeviceExtension->Dma32BitAddresses = DeviceDescription.Dma32BitAddresses;

        //ScsiDebugPrintInt(1, "ScsiPortGetUncachedExtension: Dma64BitAddresses = %#0x\n", ConfigInfo->Dma64BitAddresses);
        DPRINT("ScsiPortGetUncachedExtension: Dma64BitAddresses = %#0x\n", ConfigInfo->Dma64BitAddresses);

        DeviceExtension->IsRemapBuffers = (SpRemapBuffersByDefault != FALSE);

        if (ConfigInfo->Dma64BitAddresses & 0x7F)
        {
            //ScsiDebugPrintInt(1, "ScsiPortGetUncachedExtension: will request 64-bit PA's\n");
            DPRINT("ScsiPortGetUncachedExtension: will request 64-bit PA's\n");

            DeviceDescription.Dma64BitAddresses = 1;
            DeviceExtension->Dma64BitAddresses = 1;
        }
        else if (Sp64BitPhysicalAddresses == 1)
        {
            //ScsiDebugPrintInt(1, "ScsiPortGetUncachedExtension: Will remap buffers for adapter %#p\n", DeviceExtension);
            DPRINT("ScsiPortGetUncachedExtension: Will remap buffers for adapter %p\n", DeviceExtension);

            DeviceExtension->IsRemapBuffers = 1;
        }

        DeviceDescription.BusNumber = ConfigInfo->SystemIoBusNumber;
        DeviceDescription.MaximumLength = ConfigInfo->MaximumTransferLength;
        DeviceDescription.AutoInitialize = 0;
        DeviceDescription.DemandMode = 0;

        DeviceExtension->DmaAdapter = IoGetDmaAdapter(DeviceExtension->LowerPdo, &DeviceDescription, &NumberOfMapRegisters);
        if (!DeviceExtension->DmaAdapter)
            return NULL;

        if (NumberOfMapRegisters > ConfigInfo->NumberOfPhysicalBreaks && ConfigInfo->NumberOfPhysicalBreaks != 0)
            DeviceExtension->IoScsiCapabilities.MaximumPhysicalPages = ConfigInfo->NumberOfPhysicalBreaks;
        else
            DeviceExtension->IoScsiCapabilities.MaximumPhysicalPages = NumberOfMapRegisters;
    }

    DeviceExtension->AutoRequestSense = ConfigInfo->AutoRequestSense;

    SpInitializePowerParams(DeviceExtension);
    SpInitializePerformanceParams(DeviceExtension);
    SpInitializeRequestSenseParams(DeviceExtension);

    if (DeviceExtension->SrbExtensionSize != ConfigInfo->SrbExtensionSize)
        DeviceExtension->SrbExtensionSize = ConfigInfo->SrbExtensionSize;

    if (DeviceExtension->SrbExtensionSize || ConfigInfo->AutoRequestSense)
        DeviceExtension->IsSrbExtensions = 1;

    Status = SpGetCommonBuffer(DeviceExtension, NumberOfBytes);
    if (!NT_SUCCESS(Status))
        return NULL;

    return DeviceExtension->UncachedExtension;
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
    _In_ PVOID MiniportExtension,
    ...)
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
    PSCSI_PORT_HW_DATA SpHwData;
    PSCSI_PORT_SRB_DATA SrbData;
    PSCSI_REQUEST_BLOCK Srb;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    va_list ap;

    if (MiniportExtension)
    {
        SpHwData = CONTAINING_RECORD(MiniportExtension, SCSI_PORT_HW_DATA, HwDeviceExtension);
        DeviceExtension = SpHwData->DeviceExtension;
    }
    else
    {
        DeviceExtension = NULL;
    }

    DPRINT("ScsiPortNotification: %p, %X\n", DeviceExtension, NotificationType);

    va_start(ap, MiniportExtension);

    switch (NotificationType)
    {
        case 0x0:
        {
            DPRINT("ScsiPortNotification: RequestComplete\n");

            Srb = va_arg(ap, PSCSI_REQUEST_BLOCK);

            ASSERT(Srb->SrbStatus != SRB_STATUS_PENDING);
            ASSERT(Srb->SrbStatus != SRB_STATUS_SUCCESS || Srb->ScsiStatus == SCSISTAT_GOOD || Srb->Function != SRB_FUNCTION_EXECUTE_SCSI);

            if (!(Srb->SrbFlags & 0x10000))
                return;

            Srb->SrbFlags &= ~0x10000;

            if (Srb->Function == 0x10)
            {
                ASSERT(FALSE);
                UNIMPLEMENTED_DBGBREAK();
            }
            else
            {
                SrbData = Srb->OriginalRequest;

                ASSERT(SrbData->Type == 0x7770);//SRB_DATA_TYPE
                ASSERT(SrbData->CurrentSrb == Srb);
                ASSERT(SrbData->CurrentSrb != NULL && SrbData->CompletedRequests == NULL);

                if (Srb->SrbStatus == 1 && (Srb->Cdb[0] == 0x28 || Srb->Cdb[0] == 0x2A))
                {
                    ASSERT(Srb->DataTransferLength);
                }

                if (SpLunIoLogActive == 1 && Srb->Function == 0)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }

                if (Srb->SrbStatus == 5)
                {
                    //ScsiDebugPrintInt(0, "ScsiPortNotification: lun is busy (Srb %p)\n", Srb);
                    DPRINT("ScsiPortNotification: lun is busy (%p)\n", Srb);
                }

                if ((Srb->SrbStatus == 1 || Srb->SrbStatus == 0x12) && (Srb->SrbFlags & 0xC0))
                {
                    ASSERT(SrbData->OriginalDataTransferLength >= Srb->DataTransferLength);
                }

                SrbData->CompletedRequests = DeviceExtension->InterruptData.CompletedRequests;
                DeviceExtension->InterruptData.CompletedRequests = SrbData;

                DeviceExtension->SrbDataLunExt = SrbData->LunExtension;
            }

            break;
        }
        case 0x1:
            DPRINT("ScsiPortNotification: NextRequest\n");
            DeviceExtension->InterruptData.Flags |= 8;
            break;

        case 0x2:
        {
            PathId = (UCHAR)va_arg(ap, int);
            TargetId = (UCHAR)va_arg(ap, int);
            Lun = (UCHAR)va_arg(ap, int);


            LunExtension = DeviceExtension->SrbDataLunExt;
            DeviceExtension->InterruptData.Flags |= 8;

            DPRINT("ScsiPortNotification: NextLuRequest (%X)\n", DeviceExtension->InterruptData.Flags);

            if (!LunExtension ||
                LunExtension->TargetId != TargetId ||
                LunExtension->PathId != PathId ||
                LunExtension->Lun != Lun)
            {
                LunExtension = GetLogicalUnitExtensionEx(DeviceExtension, PathId, TargetId, Lun, NULL, FALSE, __FILE__, __LINE__);
            }

            if (LunExtension && !LunExtension->ReadyLogicalUnit && !LunExtension->CurrentUntaggedRequest)
            {
                LunExtension->ReadyLogicalUnit = DeviceExtension->InterruptData.ReadyLogicalUnit;
                DeviceExtension->InterruptData.ReadyLogicalUnit = LunExtension;
            }

            break;
        }
        case 0x3:
            DPRINT1("ScsiPortNotification: ResetDetected\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0x4:
            DPRINT1("ScsiPortNotification: CallDisableInterrupts\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0x5:
            DPRINT1("ScsiPortNotification: CallEnableInterrupts\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0x6:
            DPRINT("ScsiPortNotification: RequestTimerCall\n");
            DeviceExtension->InterruptData.Flags |= 0x10000;
            DeviceExtension->InterruptData.HwTimerInt = va_arg(ap, PHW_INTERRUPT);
            DeviceExtension->InterruptData.MiniportTimerValue = va_arg(ap, ULONG);
            DPRINT("ScsiPortNotification: MiniportTimerValue %X\n", DeviceExtension->InterruptData.MiniportTimerValue);
            break;

        case 0x7:
            DPRINT1("ScsiPortNotification: BusChangeDetected\n");
            DbgBreakPoint();
            DeviceExtension->InterruptData.Flags |= 0x40000;
            break;

        case 0x8:
            DPRINT1("ScsiPortNotification: WMIEvent\n");
            UNIMPLEMENTED_ONCE;
            break;

        case 0x9:
            DPRINT1("ScsiPortNotification: WMIReregister\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0xA:
            DPRINT1("ScsiPortNotification: LinkUp\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0xB:
            DPRINT1("ScsiPortNotification: LinkDown\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0xC:
            DPRINT1("ScsiPortNotification: QueryTickCount\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0xD:
            DPRINT1("ScsiPortNotification: BufferOverrunDetected\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 0xE:
            DPRINT1("ScsiPortNotification: TraceNotification\n");
            UNIMPLEMENTED_DBGBREAK();
            break;

        default:
            DPRINT1("ScsiPortNotification: Unsupported notification %X\n", NotificationType);
            UNIMPLEMENTED_DBGBREAK();
            break;
    }

    va_end(ap);

    if (DeviceExtension)
        DeviceExtension->InterruptData.Flags |= 4;
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
    return TRUE;
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
