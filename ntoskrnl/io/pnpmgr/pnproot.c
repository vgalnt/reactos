/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnproot.c
 * PURPOSE:         PnP manager root device
 * PROGRAMMERS:     Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                  Copyright 2007 Herv? Poussineau (hpoussin@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

#define ENUM_NAME_ROOT L"Root"

/* DATA **********************************************************************/

typedef struct _PNPROOT_DEVICE
{
    // Entry on device list
    LIST_ENTRY ListEntry;
    // Physical Device Object of device
    PDEVICE_OBJECT Pdo;
    // Device ID
    UNICODE_STRING DeviceID;
    // Instance ID
    UNICODE_STRING InstanceID;
    // Device description
    UNICODE_STRING DeviceDescription;
    // Resource requirement list
    PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirementsList;
    // Associated resource list
    PCM_RESOURCE_LIST ResourceList;
    ULONG ResourceListSize;
} PNPROOT_DEVICE, *PPNPROOT_DEVICE;

/* Physical Device Object device extension for a child device */
typedef struct _PNPROOT_PDO_DEVICE_EXTENSION
{
    // Informations about the device
    PPNPROOT_DEVICE DeviceInfo;
} PNPROOT_PDO_DEVICE_EXTENSION, *PPNPROOT_PDO_DEVICE_EXTENSION;

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
IopGetRootDevices(
    _Out_ ULONG_PTR * OutInformation)
{
    DPRINT("IopGetRootDevices: *OutInformation - %p\n", *OutInformation);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryDeviceRelations(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PDEVICE_RELATIONS Relations;
    DEVICE_RELATION_TYPE Type;
    ULONG_PTR Information = 0;
    NTSTATUS Status;

    Type = IrpSp->Parameters.QueryDeviceRelations.Type;

    if (DeviceObject == IopRootDeviceNode->PhysicalDeviceObject &&
        Type == BusRelations)
    {
        Status = IopGetRootDevices(&Information);
        Irp->IoStatus.Information = Information;
    }
    else if (Type == TargetDeviceRelation)
    {
        DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / TargetDeviceRelation\n");
        Relations = (PDEVICE_RELATIONS)ExAllocatePool(PagedPool, sizeof(DEVICE_RELATIONS));
        if (!Relations)
        {
            DPRINT("ExAllocatePoolWithTag() failed\n");
            Status = STATUS_NO_MEMORY;
        }
        else
        {
            ObReferenceObject(DeviceObject);
            Relations->Count = 1;
            Relations->Objects[0] = DeviceObject;
            Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = (ULONG_PTR)Relations;
        }
    }
    else
    {
        Status = Irp->IoStatus.Status;
    }

    return Status;
}

static NTSTATUS
PdoQueryCapabilities(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PDEVICE_CAPABILITIES DeviceCapabilities;

    DeviceCapabilities = IrpSp->Parameters.DeviceCapabilities.Capabilities;

    if (DeviceCapabilities->Version != 1)
        return STATUS_REVISION_MISMATCH;

    DeviceCapabilities->UniqueID = TRUE;
    /* FIXME: Fill other fields */

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryResources(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PPNPROOT_PDO_DEVICE_EXTENSION DeviceExtension;
    PCM_RESOURCE_LIST ResourceList;

    DeviceExtension = (PPNPROOT_PDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (DeviceExtension->DeviceInfo->ResourceList)
    {
        /* Copy existing resource requirement list */
        ResourceList = ExAllocatePool(
            PagedPool,
            DeviceExtension->DeviceInfo->ResourceListSize);
        if (!ResourceList)
            return STATUS_NO_MEMORY;

        RtlCopyMemory(
            ResourceList,
            DeviceExtension->DeviceInfo->ResourceList,
            DeviceExtension->DeviceInfo->ResourceListSize);

        Irp->IoStatus.Information = (ULONG_PTR)ResourceList;

        return STATUS_SUCCESS;
    }
    else
    {
        /* No resources so just return without changing the status */
        return Irp->IoStatus.Status;
    }
}

static NTSTATUS
PdoQueryResourceRequirements(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PPNPROOT_PDO_DEVICE_EXTENSION DeviceExtension;
    PIO_RESOURCE_REQUIREMENTS_LIST ResourceList;

    DeviceExtension = (PPNPROOT_PDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (DeviceExtension->DeviceInfo->ResourceRequirementsList)
    {
        /* Copy existing resource requirement list */
        ResourceList = ExAllocatePool(PagedPool, DeviceExtension->DeviceInfo->ResourceRequirementsList->ListSize);
        if (!ResourceList)
            return STATUS_NO_MEMORY;

        RtlCopyMemory(
            ResourceList,
            DeviceExtension->DeviceInfo->ResourceRequirementsList,
            DeviceExtension->DeviceInfo->ResourceRequirementsList->ListSize);

        Irp->IoStatus.Information = (ULONG_PTR)ResourceList;

        return STATUS_SUCCESS;
    }
    else
    {
        /* No resource requirements so just return without changing the status */
        return Irp->IoStatus.Status;
    }
}

static NTSTATUS
PdoQueryDeviceText(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PPNPROOT_PDO_DEVICE_EXTENSION DeviceExtension;
    DEVICE_TEXT_TYPE DeviceTextType;
    NTSTATUS Status = Irp->IoStatus.Status;

    DeviceExtension = (PPNPROOT_PDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DeviceTextType = IrpSp->Parameters.QueryDeviceText.DeviceTextType;

    switch (DeviceTextType)
    {
        case DeviceTextDescription:
        {
            UNICODE_STRING String;
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_TEXT / DeviceTextDescription\n");

            if (DeviceExtension->DeviceInfo->DeviceDescription.Buffer != NULL)
            {
                Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                                   &DeviceExtension->DeviceInfo->DeviceDescription,
                                                   &String);
                Irp->IoStatus.Information = (ULONG_PTR)String.Buffer;
            }
            break;
        }

        case DeviceTextLocationInformation:
        {
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_TEXT / DeviceTextLocationInformation\n");
            break;
        }

        default:
        {
            DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_TEXT / unknown query id type 0x%lx\n", DeviceTextType);
        }
    }

    return Status;
}

static NTSTATUS
PdoQueryId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PPNPROOT_PDO_DEVICE_EXTENSION DeviceExtension;
    BUS_QUERY_ID_TYPE IdType;
    NTSTATUS Status = Irp->IoStatus.Status;

    DeviceExtension = (PPNPROOT_PDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    IdType = IrpSp->Parameters.QueryId.IdType;

    switch (IdType)
    {
        case BusQueryDeviceID:
        {
            UNICODE_STRING String;
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryDeviceID\n");

            Status = RtlDuplicateUnicodeString(
                RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                &DeviceExtension->DeviceInfo->DeviceID,
                &String);
            Irp->IoStatus.Information = (ULONG_PTR)String.Buffer;
            break;
        }

        case BusQueryHardwareIDs:
        case BusQueryCompatibleIDs:
        {
            /* Optional, do nothing */
            break;
        }

        case BusQueryInstanceID:
        {
            UNICODE_STRING String;
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryInstanceID\n");

            Status = RtlDuplicateUnicodeString(
                RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                &DeviceExtension->DeviceInfo->InstanceID,
                &String);
            Irp->IoStatus.Information = (ULONG_PTR)String.Buffer;
            break;
        }

        default:
        {
            DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_ID / unknown query id type 0x%lx\n", IdType);
        }
    }

    return Status;
}

static NTSTATUS
PdoQueryBusInformation(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_STACK_LOCATION IrpSp)
{
    PPNP_BUS_INFORMATION BusInfo;
    NTSTATUS Status;

    BusInfo = (PPNP_BUS_INFORMATION)ExAllocatePoolWithTag(PagedPool, sizeof(PNP_BUS_INFORMATION), TAG_PNP_ROOT);
    if (!BusInfo)
        Status = STATUS_NO_MEMORY;
    else
    {
        RtlCopyMemory(
            &BusInfo->BusTypeGuid,
            &GUID_BUS_TYPE_INTERNAL,
            sizeof(BusInfo->BusTypeGuid));
        BusInfo->LegacyBusType = PNPBus;
        /* We're the only root bus enumerator on the computer */
        BusInfo->BusNumber = 0;
        Irp->IoStatus.Information = (ULONG_PTR)BusInfo;
        Status = STATUS_SUCCESS;
    }

    return Status;
}

/*
 * FUNCTION: Handle Plug and Play IRPs for Root device
 * ARGUMENTS:
 *     DeviceObject = Pointer to physical device object
 *     Irp          = Pointer to IRP that should be handled
 * RETURNS:
 *     Status
 */
NTSTATUS
NTAPI
PnpRootPnpControl(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp)
{
    PPNPROOT_PDO_DEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;

    DeviceExtension = DeviceObject->DeviceExtension;
    Status = Irp->IoStatus.Status;
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("PnpRootPdoPnpControl: DeviceObject - %p, Irp - %p\n", DeviceObject, Irp);

    switch (IrpSp->MinorFunction)
    {
        case IRP_MN_START_DEVICE: /* 0x00 */
            DPRINT("IRP_MJ_PNP / IRP_MN_START_DEVICE\n");
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS: /* 0x07 */
            Status = PdoQueryDeviceRelations(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_QUERY_CAPABILITIES: /* 0x09 */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_CAPABILITIES\n");
            Status = PdoQueryCapabilities(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_QUERY_RESOURCES: /* 0x0a */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_RESOURCES\n");
            Status = PdoQueryResources(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS: /* 0x0b */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n");
            Status = PdoQueryResourceRequirements(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_QUERY_DEVICE_TEXT: /* 0x0c */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n");
            Status = PdoQueryDeviceText(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS: /* 0x0d */
            DPRINT("IRP_MJ_PNP / IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_REMOVE_DEVICE:
            /* Remove the device from the device list and decrement the device count*/
            RemoveEntryList(&DeviceExtension->DeviceInfo->ListEntry);

            /* Free some strings we created */
            RtlFreeUnicodeString(&DeviceExtension->DeviceInfo->DeviceDescription);
            RtlFreeUnicodeString(&DeviceExtension->DeviceInfo->DeviceID);
            RtlFreeUnicodeString(&DeviceExtension->DeviceInfo->InstanceID);

            /* Free the resource requirements list */
            if (DeviceExtension->DeviceInfo->ResourceRequirementsList != NULL)
            ExFreePool(DeviceExtension->DeviceInfo->ResourceRequirementsList);

            /* Free the boot resources list */
            if (DeviceExtension->DeviceInfo->ResourceList != NULL)
            ExFreePool(DeviceExtension->DeviceInfo->ResourceList);

            /* Free the device info */
            ExFreePool(DeviceExtension->DeviceInfo);

            /* Finally, delete the device object */
            IoDeleteDevice(DeviceObject);

            /* Return success */
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_ID: /* 0x13 */
            Status = PdoQueryId(DeviceObject, Irp, IrpSp);
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE: /* 0x14 */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_PNP_DEVICE_STATE\n");
            break;

        case IRP_MN_QUERY_BUS_INFORMATION: /* 0x15 */
            DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_BUS_INFORMATION\n");
            Status = PdoQueryBusInformation(DeviceObject, Irp, IrpSp);
            break;

        default:
            DPRINT1("IRP_MJ_PNP / Unknown minor function 0x%lx\n", IrpSp->MinorFunction);
            break;
    }

    if (Status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    else
    {
        ASSERT(FALSE);
    }

    return Status;
}

/*
 * FUNCTION: Handle Power IRPs
 * ARGUMENTS:
 *     DeviceObject = Pointer to PDO or FDO
 *     Irp          = Pointer to IRP that should be handled
 * RETURNS:
 *     Status
 */
static NTSTATUS NTAPI
PnpRootPowerControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;

    Status = Irp->IoStatus.Status;
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MinorFunction)
    {
        case IRP_MN_QUERY_POWER:
        case IRP_MN_SET_POWER:
            Status = STATUS_SUCCESS;
            break;
    }
    Irp->IoStatus.Status = Status;
    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

static NTSTATUS NTAPI
PnpRootSystemControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    DPRINT1("PnpRootSystemControl(DeviceObject %p, Irp %p)\n", DeviceObject, Irp);
    ASSERT(FALSE);
    return Status = STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpRootAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    DPRINT("PnpRootAddDevice(DriverObject %p, Pdo %p)\n", DriverObject, PhysicalDeviceObject);
    ASSERT(FALSE);
    
    return STATUS_SUCCESS;
}

#if MI_TRACE_PFNS
PDEVICE_OBJECT IopPfnDumpDeviceObject;

NTSTATUS NTAPI
PnpRootCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;

    if (DeviceObject != IopPfnDumpDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    if (IoStack->MajorFunction == IRP_MJ_CREATE)
    {
        MmDumpArmPfnDatabase(TRUE);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
#endif

NTSTATUS NTAPI
PnpRootDriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
#if MI_TRACE_PFNS
    NTSTATUS Status;
    UNICODE_STRING PfnDumpDeviceName = RTL_CONSTANT_STRING(L"\\Device\\PfnDump");
#endif

    DPRINT("PnpRootDriverEntry(%p %wZ)\n", DriverObject, RegistryPath);

    IopRootDriverObject = DriverObject;

    DriverObject->DriverExtension->AddDevice = PnpRootAddDevice;

#if MI_TRACE_PFNS
    DriverObject->MajorFunction[IRP_MJ_CREATE] = PnpRootCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PnpRootCreateClose;
#endif
    DriverObject->MajorFunction[IRP_MJ_PNP] = PnpRootPnpControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = PnpRootPowerControl;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PnpRootSystemControl;

#if MI_TRACE_PFNS
    Status = IoCreateDevice(DriverObject,
                            0,
                            &PfnDumpDeviceName,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &IopPfnDumpDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Creating PFN Dump device failed with %lx\n", Status);
    }
    else
    {
        IopPfnDumpDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    }
#endif

    return STATUS_SUCCESS;
}
