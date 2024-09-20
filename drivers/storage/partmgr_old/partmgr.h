/*
 * PROJECT:     Partition manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2018, 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#ifndef _PARTMGR_H_
#define _PARTMGR_H_

#include <ntifs.h>
#include <ntdddisk.h>
#include <wdmguid.h>
#include <stdio.h>

typedef struct _PM_DRIVER_EXTENSION
{
    PDRIVER_OBJECT SelfDriverObject;
    LIST_ENTRY NotifyList;
    LIST_ENTRY ExtensionList;
    PVOID NotificationEntry;
    KMUTEX Mutex;
    LONG IsReinitialized;
    RTL_AVL_TABLE TableSignature;
    RTL_AVL_TABLE TableGuid;
    UNICODE_STRING RegistryPath;
} PM_DRIVER_EXTENSION, *PPM_DRIVER_EXTENSION;

typedef struct _PM_DEVICE_EXTENSION
{
    BOOLEAN Reserved00;
    BOOLEAN Reserved01;
    BOOLEAN Reserved02;
    BOOLEAN IsDeviceRunning;
    BOOLEAN IsPartitionNotFound;
    PDEVICE_OBJECT PartitionFido; // self device object (filter device object for partition)
    PPM_DRIVER_EXTENSION DriverExtension;
    PDEVICE_OBJECT AttachedToDevice; // the topmost device object on the stack to which the current device is attached
    PDEVICE_OBJECT WholeDiskPdo; // PDO created for the disk device stack
    LIST_ENTRY PartitionList;
    LIST_ENTRY Link;
    LONG PagingPathCount; // IRP_MN_DEVICE_USAGE_NOTIFICATION
    KEVENT Event;
    ULONG MbrSignature;
    LIST_ENTRY ListOfSignatures;
    LIST_ENTRY ListOfGuids;
    ULONG DeviceNumber;
    UNICODE_STRING NameString;
    WCHAR NameBuffer[64];
    BOOLEAN IsDeviceIdRequested;
    IO_REMOVE_LOCK RemoveLock;
} PM_DEVICE_EXTENSION, *PPM_DEVICE_EXTENSION;

typedef struct _PM_SIGNATURE
{
    LIST_ENTRY Link;
    PPM_DEVICE_EXTENSION DeviceExtension;
    ULONG Value;
} PM_SIGNATURE, *PPM_SIGNATURE;

typedef struct _PM_NOTIFICATION_DATA
{
    LIST_ENTRY Link;
    UNICODE_STRING ObjectName;
    LONG Counter;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
} PM_NOTIFICATION_DATA, *PPM_NOTIFICATION_DATA;

typedef struct _PM_PARTITION_DATA
{
    LIST_ENTRY Link;
    PDEVICE_OBJECT PartitionPdo;
    PDEVICE_OBJECT WholeDiskPdo;
    PPM_NOTIFICATION_DATA NotifyData;
} PM_PARTITION_DATA, *PPM_PARTITION_DATA;

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
NTAPI
PmAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DiskPdo
);

NTSTATUS
NTAPI
PmDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PmPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PmWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PmPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

RTL_GENERIC_COMPARE_RESULTS
NTAPI
PmTableSignatureCompareRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
);

RTL_GENERIC_COMPARE_RESULTS
NTAPI
PmTableGuidCompareRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
);

PVOID
NTAPI
PmTableAllocateRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize
);

VOID
NTAPI
PmTableFreeRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
);

VOID
NTAPI
PmDriverReinit(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PVOID Context,
    _In_ ULONG Count
);

NTSTATUS
NTAPI
PmQueryDeviceRelations(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PmDetermineDeviceNameAndNumber(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG* OutPartitionData
);

NTSTATUS
NTAPI
PmReadPartitionTableEx(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDRIVE_LAYOUT_INFORMATION_EX* OutDriveLayout
);

BOOLEAN
NTAPI
LockDriverWithTimeout(
    _In_ PPM_DRIVER_EXTENSION DriverExtension
);

NTSTATUS
NTAPI
PmQueryDeviceId(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PSTORAGE_DEVICE_DESCRIPTOR* OutDeviceId
);

VOID
NTAPI
PmAddSignatures(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PDRIVE_LAYOUT_INFORMATION_EX DriveLayout
);

NTSTATUS
NTAPI
PmCheckAndUpdateSignature(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ BOOLEAN Param2,
    _In_ BOOLEAN Param3
);

NTSTATUS
NTAPI
PmRegisterDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG PartitionData
);

NTSTATUS
NTAPI
PmStartPartition(
    _In_ PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
PmGivePartition(
    _In_ PPM_NOTIFICATION_DATA NotifyData,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PDEVICE_OBJECT WholeDiskPdo
);

NTSTATUS
NTAPI
PmVolumeManagerNotification(
    _In_ PVOID NotificationStructure,
    _In_ PVOID Context
);

#endif /* _PARTMGR_H_ */

/* EOF */
