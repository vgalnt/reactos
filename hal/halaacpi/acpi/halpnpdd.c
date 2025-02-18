
/* INCLUDES *******************************************************************/

#include <hal.h>
#include "apic.h"

#define NDEBUG
#include <debug.h>

/* INCLUDES *******************************************************************/

typedef enum _EXTENSION_TYPE
{
    PdoExtensionType = 0xC0,
    FdoExtensionType
} EXTENSION_TYPE;

typedef enum _PDO_TYPE
{
    AcpiPdo = 0x81,
    WdPdo = 0x82
} PDO_TYPE;

typedef struct _FDO_EXTENSION
{
    EXTENSION_TYPE ExtensionType;
    struct _PDO_EXTENSION* ChildPdoList;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PDEVICE_OBJECT FunctionalDeviceObject;
    PDEVICE_OBJECT AttachedDeviceObject;
} FDO_EXTENSION, *PFDO_EXTENSION;

typedef struct _PDO_EXTENSION
{
    EXTENSION_TYPE ExtensionType;
    struct _PDO_EXTENSION* Next;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PFDO_EXTENSION ParentFdoExtension;
    PDO_TYPE PdoType;
    PDESCRIPTION_HEADER WdTable;
    LONG InterfaceReferenceCount;
} PDO_EXTENSION, *PPDO_EXTENSION;

/* GLOBALS ********************************************************************/

PDRIVER_OBJECT HalpDriverObject;
PWCHAR HalHardwareIdString = L"acpiapic_up";

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
HalpAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT TargetDevice
);

NTSTATUS
NTAPI
HalpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_RELATION_TYPE RelationType,
    _Out_ PDEVICE_RELATIONS* DeviceRelations
);

VOID NTAPI HalTranslatorDereference(_In_ PVOID Context);

NTSTATUS
NTAPI
HalpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ CONST GUID* InterfaceType,
    _In_ ULONG InterfaceBufferSize,
    _In_ PVOID InterfaceSpecificData,
    _In_ USHORT Version,
    _In_ PINTERFACE Interface,
    _Out_ PULONG_PTR OutInformation
);

NTSTATUS
NTAPI
HalpQueryIdFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PUSHORT* BusQueryId
);

NTSTATUS
NTAPI
HalpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_CAPABILITIES Capabilities
);

NTSTATUS
NTAPI
HalpQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PCM_RESOURCE_LIST* Resources
);

NTSTATUS
NTAPI
HalpQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* Requirements
);

NTSTATUS
NTAPI
HalpQueryIdPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PUSHORT* BusQueryId
);

NTSTATUS
NTAPI
HalpDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
HalpDispatchWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
HalpDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
HalpDriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, HalpAddDevice)
  #pragma alloc_text(PAGE, HalpQueryDeviceRelations)
  #pragma alloc_text(PAGE, HalTranslatorDereference)
  #pragma alloc_text(PAGE, HalpQueryInterface)
  #pragma alloc_text(PAGE, HalpQueryIdFdo)
  #pragma alloc_text(PAGE, HalpQueryCapabilities)
  #pragma alloc_text(PAGE, HalpQueryResources)
  #pragma alloc_text(PAGE, HalpQueryResourceRequirements)
  #pragma alloc_text(PAGE, HalpQueryIdPdo)
  #pragma alloc_text(PAGE, HalpDispatchPnp)
  #pragma alloc_text(PAGE, HalpDispatchWmi)
  #pragma alloc_text(PAGELK, HalpDispatchPower)
  #pragma alloc_text(PAGE, HalpDriverEntry)
  #pragma alloc_text(PAGE, HaliInitPnpDriver)
#endif

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT TargetDevice)
{
    PDEVICE_OBJECT FdoDeviceObject;
    PDEVICE_OBJECT AttachedDevice;
    PDEVICE_OBJECT PdoDeviceObject;
    PDEVICE_OBJECT WdDeviceObject;
    PFDO_EXTENSION FdoExtension;
    PPDO_EXTENSION PdoExtension;
    PPDO_EXTENSION WdExtension;
    PDESCRIPTION_HEADER Wdrt;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpAddDevice: Driver %p, Pdo %p\n", DriverObject, TargetDevice);

    /* Create the FDO */
    Status = IoCreateDevice(DriverObject,
                            sizeof(FDO_EXTENSION),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            0,
                            FALSE,
                            &FdoDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        /* Should not happen */
        DPRINT1("HalpAddDevice: Status %X\n", Status);
        ASSERT(FALSE);//HalpDbgBreakPointEx();
        return Status;
    }

    DPRINT("HalpAddDevice: Fdo %p\n", FdoDeviceObject);

    /* Setup the FDO extension */
    FdoExtension = FdoDeviceObject->DeviceExtension;
    FdoExtension->ExtensionType = FdoExtensionType;
    FdoExtension->PhysicalDeviceObject = TargetDevice;
    FdoExtension->FunctionalDeviceObject = FdoDeviceObject;
    FdoExtension->ChildPdoList = NULL;

    /* FDO is done initializing */
    FdoDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Attach to the physical device object (the bus) */
    AttachedDevice = IoAttachDeviceToDeviceStack(FdoDeviceObject, TargetDevice);
    if (!AttachedDevice)
    {
        /* Failed, undo everything */
        DPRINT("HalpAddDevice: return STATUS_NO_SUCH_DEVICE\n");
        IoDeleteDevice(FdoDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    DPRINT("HalpAddDevice: AttachedDevice %p\n", AttachedDevice);

    /* Save the attachment */
    FdoExtension->AttachedDeviceObject = AttachedDevice;

    /* Create the PDO */
    Status = IoCreateDevice(DriverObject,
                            sizeof(PDO_EXTENSION),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &PdoDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        DPRINT1("HalpAddDevice: Not created ACPI PDO. Sts %X\n", Status);
        return Status;
    }

    DPRINT("HalpAddDevice: IoCreateDevice ACPI PDO %p\n", PdoDeviceObject);

    /* Setup the PDO device extension */
    PdoExtension = PdoDeviceObject->DeviceExtension;
    PdoExtension->ExtensionType = PdoExtensionType;
    PdoExtension->PhysicalDeviceObject = PdoDeviceObject;
    PdoExtension->ParentFdoExtension = FdoExtension;
    PdoExtension->PdoType = AcpiPdo;

    /* Add the PDO to the head of the list */
    PdoExtension->Next = NULL;

    /* Find the ACPI watchdog table */
    Wdrt = HalAcpiGetTable(0, 'TRDW');
    if ( !Wdrt )
    {
        /* Initialization is finished */
        DPRINT1("HalpAddDevice: No Watchdog.\n");
        goto Exit;
    }

    /* FIXME: TODO */
    DPRINT1("HalpAddDevice: You have an ACPI Watchdog.  ... \n");
    ASSERT(FALSE);//HalpDbgBreakPointEx();

    Status = IoCreateDevice(DriverObject,
                            sizeof(PDO_EXTENSION),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &WdDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpAddDevice: Not created WD DO. Status %X\n", Status);
        IoDeleteDevice(PdoDeviceObject);
        return Status;
    }

    DPRINT("HalpAddDevice: IoCreateDevice Wd DO %p\n", WdDeviceObject);

    WdExtension = WdDeviceObject->DeviceExtension;
    WdExtension->ExtensionType = PdoExtensionType;
    WdExtension->PhysicalDeviceObject = WdDeviceObject;
    WdExtension->ParentFdoExtension = FdoExtension;
    WdExtension->PdoType = WdPdo;
    WdExtension->WdTable = Wdrt;

    WdExtension->Next = NULL;
    PdoExtension->Next = WdExtension;

    WdDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:

    PdoDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    FdoExtension->ChildPdoList = PdoExtension;

    DPRINT("HalpAddDevice: return STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HalpPassIrpFromFdoToPdo(
    _In_ PDEVICE_OBJECT FdoDeviceObject,
    _In_ PIRP Irp)
{
    PFDO_EXTENSION FdoDeviceExtension;
    NTSTATUS Status;

    DPRINT("HalpPassIrpFromFdoToPdo: %p, %p\n", FdoDeviceObject, Irp);

    FdoDeviceExtension = FdoDeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);

    Status = IoCallDriver(FdoDeviceExtension->AttachedDeviceObject, Irp);
    DPRINT("HalpPassIrpFromFdoToPdo: AttachedDevice %p, Status %X\n", FdoDeviceExtension->AttachedDeviceObject, Status);

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_RELATION_TYPE RelationType,
    _Out_ PDEVICE_RELATIONS* DeviceRelations)
{
    PPDO_EXTENSION PdoExtension;
    PFDO_EXTENSION FdoExtension;
    PDEVICE_RELATIONS PdoRelations;
    PDEVICE_RELATIONS FdoRelations;
    PDEVICE_OBJECT* ObjectEntry;
    EXTENSION_TYPE ExtensionType;
    ULONG PdoCount = 0;
    ULONG Size;
    ULONG ix = 0;

    DPRINT("HalpQueryDeviceRelations: RelationType %X\n", RelationType);

    /* Get FDO device extension and PDO count */
    FdoExtension = DeviceObject->DeviceExtension;
    ExtensionType = FdoExtension->ExtensionType;

    /* What do they want? */
    if (RelationType != BusRelations)
    {
        /* The only other thing we support is a target relation for the PDO */
        if ((RelationType != TargetDeviceRelation) || (ExtensionType != PdoExtensionType))
            return STATUS_NOT_SUPPORTED;

        /* Only one entry */
        PdoRelations = ExAllocatePoolWithTag(PagedPool, sizeof(DEVICE_RELATIONS), TAG_HAL);
        if (!PdoRelations)
        {
            DPRINT1("STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Fill it out and reference us */
        PdoRelations->Count = 1;
        PdoRelations->Objects[0] = DeviceObject;
        ObReferenceObject(DeviceObject);

        /* Return it */
        *DeviceRelations = PdoRelations;
        return STATUS_SUCCESS;
    }

    /* This better be an FDO */
    if (ExtensionType != FdoExtensionType)
        return STATUS_NOT_SUPPORTED;

    /* Count how many PDOs we have */
    PdoExtension = FdoExtension->ChildPdoList;
    while (PdoExtension)
    {
        /* Next one */
        PdoExtension = PdoExtension->Next;
        PdoCount++;
    }

    /* Add the PDOs that already exist in the device relations */
    if (*DeviceRelations)
        PdoCount += (*DeviceRelations)->Count;

    /* Allocate our structure */
    Size = FIELD_OFFSET(DEVICE_RELATIONS, Objects) + PdoCount * sizeof(PDEVICE_OBJECT);

    FdoRelations = ExAllocatePoolWithTag(PagedPool, Size, TAG_HAL);
    if (!FdoRelations)
    {
        DPRINT1("STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Save our count */
    FdoRelations->Count = PdoCount;

    /* Query existing relations */
    ObjectEntry = FdoRelations->Objects;
    if (*DeviceRelations)
    {
        /* Check if there were any */
        if ((*DeviceRelations)->Count)
        {
            /* Loop them all */
            do
            {
                /* Copy into our structure */
                *ObjectEntry++ = (*DeviceRelations)->Objects[ix];
            }
            while (++ix < (*DeviceRelations)->Count);
        }

        /* Free existing structure */
        ExFreePool(*DeviceRelations);
    }

    /* Now check if we have a PDO list */
    PdoExtension = FdoExtension->ChildPdoList;
    if (PdoExtension)
    {
        /* Loop the PDOs */
        do
        {
            /* Save our own PDO and reference it */
            *ObjectEntry++ = PdoExtension->PhysicalDeviceObject;
            ObReferenceObject(PdoExtension->PhysicalDeviceObject);

            /* Go to our next PDO */
            PdoExtension = PdoExtension->Next;
        }
        while (PdoExtension);
    }

    /* Return the new structure */
    *DeviceRelations = FdoRelations;
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
VOID
NTAPI
HalTranslatorDereference(
    _In_ PVOID Context)
{
    ;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ CONST GUID* InterfaceType,
    _In_ ULONG InterfaceBufferSize,
    _In_ PVOID InterfaceSpecificData,
    _In_ USHORT Version,
    _In_ PINTERFACE Interface,
    _Out_ PULONG_PTR OutInformation)
{
    PTRANSLATOR_INTERFACE TranslatorInterface = (PTRANSLATOR_INTERFACE)Interface;
    UNICODE_STRING  GuidString;
    NTSTATUS Status;

    DPRINT("HalpQueryInterface: [%p] Size %X, Data %X\n", DeviceObject, InterfaceBufferSize, InterfaceSpecificData);

    Status = RtlStringFromGUID(InterfaceType, &GuidString);
    ASSERT(NT_SUCCESS(Status));

    DPRINT("HalpQueryInterface: Guid '%wZ', Version %X, Interface %p\n", &GuidString, Version, Interface);

    if (RtlCompareMemory(&GUID_TRANSLATOR_INTERFACE_STANDARD, InterfaceType, sizeof(GUID)) != sizeof(GUID))
    {
        DPRINT("HalpQueryInterface: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    if (InterfaceBufferSize < sizeof(TRANSLATOR_INTERFACE))
    {
        DPRINT("Return STATUS_BUFFER_TOO_SMALL\n");
        *OutInformation = sizeof(TRANSLATOR_INTERFACE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (InterfaceSpecificData != ULongToPtr(2))
    {
        DPRINT("InterfaceSpecificData != ULongToPtr(2)\n");
        return STATUS_NOT_SUPPORTED;
    }

    TranslatorInterface->Version = 0;
    TranslatorInterface->Size = sizeof(TRANSLATOR_INTERFACE);
    TranslatorInterface->Context = DeviceObject;

    TranslatorInterface->InterfaceReference = HalTranslatorDereference;
    TranslatorInterface->InterfaceDereference = HalTranslatorDereference;

    TranslatorInterface->TranslateResources = HalIrqTranslateResourcesRoot;
    TranslatorInterface->TranslateResourceRequirements = HalIrqTranslateResourceRequirementsRoot;

    *OutInformation = sizeof(TRANSLATOR_INTERFACE);

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryIdFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PUSHORT* BusQueryId)
{
    PWCHAR Buffer;
    PWCHAR Id;
    SIZE_T Length;

    PAGED_CODE();

    /* What kind of ID is being requested? */
    switch (IdType)
    {
        case BusQueryDeviceID:
            DPRINT1("HalpQueryIdFdo: BusQueryDeviceID\n");
            Id = HalHardwareIdString;
            break;

        case BusQueryHardwareIDs:
            DPRINT1("HalpQueryIdFdo: BusQueryHardwareIDs\n");
            Id = HalHardwareIdString;
            break;

        case BusQueryInstanceID:
            DPRINT1("HalpQueryIdFdo: BusQueryInstanceID not support\n");
            return STATUS_NOT_SUPPORTED;

        case BusQueryCompatibleIDs:
            DPRINT1("HalpQueryIdFdo: BusQueryCompatibleIDs\n");
            Id = L"0";
            break;

        default:
            /* We don't support anything else */
            DPRINT1("HalpQueryIdFdo: unknown IdType %X\n", IdType);
            return STATUS_NOT_SUPPORTED;
    }

    Length = ((wcslen(Id) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));

    Buffer = ExAllocatePoolWithTag(PagedPool, (Length + sizeof(UNICODE_NULL)), TAG_HAL);
    if (!Buffer)
    {
        DPRINT1("HalpQueryIdFdo: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Buffer, Id, Length);
    Buffer[Length / sizeof(WCHAR)] = UNICODE_NULL;

    *BusQueryId = Buffer;
    DPRINT1("HalpQueryIdFdo: BusQueryId '%S'\n", *BusQueryId);

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_CAPABILITIES Capabilities)
{
    DPRINT("HalpQueryCapabilities: Device %X\n", DeviceObject);
    PAGED_CODE();

    /* Get the extension and check for valid version */
    if (Capabilities->Version != 1)
    {
        DPRINT1("HalpQueryCapabilities: Capabilities->Version %X\n", Capabilities->Version);
        ASSERT(Capabilities->Version == 1);
        return STATUS_NOT_SUPPORTED;
    }

    /* Can't lock or eject us */
    Capabilities->LockSupported = FALSE;
    Capabilities->EjectSupported = FALSE;

    /* Can't remove or dock us */
    Capabilities->Removable = FALSE;
    Capabilities->DockDevice = FALSE;

    /* Can't access us raw */
    Capabilities->RawDeviceOK = FALSE;

    /* We have a unique ID, and don't bother the user */
    Capabilities->UniqueID = TRUE;
    Capabilities->SilentInstall = TRUE;

    /* Fill out the adress */
    Capabilities->Address = InterfaceTypeUndefined;
    Capabilities->UINumber = InterfaceTypeUndefined;

    /* Fill out latencies */
    Capabilities->D1Latency = 0;
    Capabilities->D2Latency = 0;
    Capabilities->D3Latency = 0;

    /* Fill out supported device states */
    Capabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;
    Capabilities->DeviceState[PowerSystemHibernate] = PowerDeviceD3;
    Capabilities->DeviceState[PowerSystemShutdown] = PowerDeviceD3;
    //Capabilities->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PCM_RESOURCE_LIST* Resources)
{
    PPDO_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDesc;
    PIO_RESOURCE_DESCRIPTOR Descriptor;
    PCM_RESOURCE_LIST ResourceList;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("HalpQueryResources: Device %p\n", DeviceObject);
    PAGED_CODE();

    if (DeviceExtension->PdoType == WdPdo)
    {
        /* Watchdog doesn't */
        DPRINT1("HalpQueryResources: Ext->PdoType == WdPdo \n");
        return STATUS_SUCCESS;
    }

    /* Only the ACPI PDO has requirements */
    if (DeviceExtension->PdoType != AcpiPdo)
    {
        /* This shouldn't happen */
        DPRINT1("HalpQueryResources: Ext->PdoType %X\n", DeviceExtension->PdoType);
        return STATUS_NOT_SUPPORTED;
    }

    /* Query ACPI requirements */
    Status = HalpQueryAcpiResourceRequirements(&RequirementsList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpQueryResources: Status %X\n", Status);
        return Status;
    }

    ASSERT(RequirementsList->AlternativeLists == 1);

    /* Allocate the resourcel ist */
    ResourceList = ExAllocatePoolWithTag(PagedPool, sizeof(CM_RESOURCE_LIST), TAG_HAL);
    if (!ResourceList )
    {
        DPRINT1("HalpQueryResources: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(RequirementsList, TAG_HAL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Initialize it */
    RtlZeroMemory(ResourceList, sizeof(CM_RESOURCE_LIST));
    ResourceList->Count = 1;

    /* Setup the list fields */
    ResourceList->List[0].BusNumber = -1;
    ResourceList->List[0].InterfaceType = PNPBus;
    ResourceList->List[0].PartialResourceList.Version = 1;
    ResourceList->List[0].PartialResourceList.Revision = 1;
    ResourceList->List[0].PartialResourceList.Count = 0;

    /* Setup the first descriptor */
    PartialDesc = ResourceList->List[0].PartialResourceList.PartialDescriptors;

    /* Find the requirement descriptor for the SCI */
    for (ix = 0; ix < RequirementsList->List[0].Count; ix++)
    {
        /* Get this descriptor */
        Descriptor = &RequirementsList->List[0].Descriptors[ix];

        DPRINT("HalpQueryResources: Desc %X, Type %X\n", Descriptor, Descriptor->Type);

        if (Descriptor->Type != CmResourceTypeInterrupt)
            continue;

        /* Copy requirements descriptor into resource descriptor */
        PartialDesc->Type = CmResourceTypeInterrupt;
        PartialDesc->ShareDisposition = Descriptor->ShareDisposition;
        PartialDesc->Flags = Descriptor->Flags;

        ASSERT(Descriptor->u.Interrupt.MinimumVector == Descriptor->u.Interrupt.MaximumVector);

        PartialDesc->u.Interrupt.Vector = Descriptor->u.Interrupt.MinimumVector;
        PartialDesc->u.Interrupt.Level = Descriptor->u.Interrupt.MinimumVector;
        PartialDesc->u.Interrupt.Affinity = 0xFFFFFFFF;

        ResourceList->List[0].PartialResourceList.Count++;
        break;
    }

    /* Return resources and success */
    *Resources = ResourceList;

    ExFreePoolWithTag(RequirementsList, TAG_HAL);

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* Requirements)
{
    PPDO_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    DPRINT("HalpQueryResourceRequirements: Device %X\n", DeviceObject);
    PAGED_CODE();

    /* Only the ACPI PDO has requirements */
    if (DeviceExtension->PdoType == AcpiPdo)
        return HalpQueryAcpiResourceRequirements(Requirements);

    if (DeviceExtension->PdoType == WdPdo)
    {
        /* Watchdog doesn't */
        DPRINT1("HalpQueryResourceRequirements: Watchdog ... FIXME\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        return STATUS_NOT_IMPLEMENTED;
    }

    /* This shouldn't happen */
    DPRINT1("HalpQueryResourceRequirements: unknown PdoType %X\n", DeviceExtension->PdoType);
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_SUPPORTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpQueryIdPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PUSHORT* BusQueryId)
{
    PPDO_EXTENSION PdoExtension;
    PDO_TYPE PdoType;
    PWCHAR CurrentId;
    WCHAR Id[100];
    NTSTATUS Status;
    SIZE_T Length = 0;
    PWCHAR Buffer;

    DPRINT("HalpQueryIdPdo: IdType %X\n", IdType);
    PAGED_CODE();

    /* Get the PDO type */
    PdoExtension = DeviceObject->DeviceExtension;
    PdoType = PdoExtension->PdoType;

    /* What kind of ID is being requested? */
    DPRINT("ID: %d\n", IdType);
    switch (IdType)
    {
        case BusQueryDeviceID:
        case BusQueryHardwareIDs:

            /* What kind of PDO is this? */
            if (PdoType == AcpiPdo)
            {
                /* ACPI ID */
                CurrentId = L"ACPI_HAL\\PNP0C08";
                RtlCopyMemory(Id, CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

                CurrentId = L"*PNP0C08";
                RtlCopyMemory(&Id[wcslen(Id) + 1], CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
            }
            else if (PdoType == WdPdo)
            {
                /* WatchDog ID */
                CurrentId = L"ACPI_HAL\\PNP0C18";
                RtlCopyMemory(Id, CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

                CurrentId = L"*PNP0C18";
                RtlCopyMemory(&Id[wcslen(Id) + 1], CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
            }
            else
            {
                /* Unknown */
                return STATUS_NOT_SUPPORTED;
            }
            break;

        case BusQueryInstanceID:

            /* Instance ID */
            CurrentId = L"0";
            RtlCopyMemory(Id, CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
            Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
            break;

        case BusQueryCompatibleIDs:
        default:

            /* We don't support anything else */
            return STATUS_NOT_SUPPORTED;
    }


    /* Allocate the buffer */
    Buffer = ExAllocatePoolWithTag(PagedPool,
                                   Length + sizeof(UNICODE_NULL),
                                   TAG_HAL);
    if (Buffer)
    {
        /* Copy the string and null-terminate it */
        RtlCopyMemory(Buffer, Id, Length);
        Buffer[Length / sizeof(WCHAR)] = UNICODE_NULL;

        /* Return string */
        *BusQueryId = Buffer;
        Status = STATUS_SUCCESS;
        DPRINT("Returning: %S\n", *BusQueryId);
    }
    else
    {
        /* Fail */
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Return status */
    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStackLocation;
    PFDO_EXTENSION FdoExtension;
    NTSTATUS Status;
    UCHAR Minor;

    DPRINT("HalpDispatchPnp: %p, %p\n", DeviceObject, Irp);
    PAGED_CODE();

    FdoExtension = DeviceObject->DeviceExtension;
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    Minor = IoStackLocation->MinorFunction;

    /* FDO? */
    if (FdoExtension->ExtensionType == FdoExtensionType)
    {
        /* Query the IRP type */
        switch (Minor)
        {
            case IRP_MN_QUERY_DEVICE_RELATIONS:
                DPRINT("HalpDispatchPnp: Querying device relations for FDO\n");
                Status = HalpQueryDeviceRelations(DeviceObject,
                                                  IoStackLocation->Parameters.QueryDeviceRelations.Type,
                                                  (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_INTERFACE:
                DPRINT("HalpDispatchPnp: Querying interface for FDO\n");
                Status = HalpQueryInterface(DeviceObject,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceType,
                                            IoStackLocation->Parameters.QueryInterface.Size,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceSpecificData,
                                            IoStackLocation->Parameters.QueryInterface.Version,
                                            IoStackLocation->Parameters.QueryInterface.Interface,
                                            (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_ID:
                DPRINT("HalpDispatchPnp: Querying ID for FDO\n");
                Status = HalpQueryIdFdo(DeviceObject,
                                        IoStackLocation->Parameters.QueryId.IdType,
                                        (PVOID)&Irp->IoStatus.Information);
                break;

            default:
                DPRINT("HalpDispatchPnp: [FDO] not supp. Minor %X\n", Minor);
                return HalpPassIrpFromFdoToPdo(DeviceObject, Irp);
        }

        if (!NT_SUCCESS(Status) && Status != STATUS_NOT_SUPPORTED)
        {
            DPRINT1("HalpDispatchPnp: [FDO] Status %X\n", Status);
            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Status;
        }

        if (Status != STATUS_NOT_SUPPORTED)
        {
            DPRINT("HalpDispatchPnp: [FDO] Status %X\n", Status);
            Irp->IoStatus.Status = Status;
        }
        else
        {
            DPRINT("HalpDispatchPnp: [FDO] Status %X\n", Status);
        }

        Status = HalpPassIrpFromFdoToPdo(DeviceObject, Irp);
        DPRINT("HalpDispatchPnp:  [FDO] Status %X\n", Status);

        return Status;
    }

    if (FdoExtension->ExtensionType != PdoExtensionType)
    {
        DPRINT1("HalpDispatchPnp: unknown ExtType %X\n", FdoExtension->ExtensionType);
        ASSERT(FALSE);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Status = Status;
        goto Exit;
    }

    /* This is a PDO instead */
    ASSERT(FdoExtension->ExtensionType == PdoExtensionType);

    /* Query the IRP type */
    switch (Minor)
    {
        case IRP_MN_START_DEVICE:
            /* We only care about a PCI PDO */
            DPRINT1("HalpDispatchPnp: [PDO] Start Device\n");
            Status = STATUS_SUCCESS; /* Complete the IRP normally */
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Query Remove Device\n");
            Status = STATUS_UNSUCCESSFUL;
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Remove Device\n");
            /* We're done */
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Cancel Remove Device\n");
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Stop Device\n");
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_STOP_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Query Stop Device\n");
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
            DPRINT1("HalpDispatchPnp: [PDO] Cancel Stop Device\n");
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            /* Inherit whatever status we had */
            DPRINT1("HalpDispatchPnp: [PDO] Surprise removal IRP\n");
            Status = Irp->IoStatus.Status;
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            /* Query the device relations */
            DPRINT("HalpDispatchPnp: Querying PDO relations\n");
            Status = HalpQueryDeviceRelations(DeviceObject,
                                              IoStackLocation->Parameters.QueryDeviceRelations.Type,
                                              (PVOID)&Irp->IoStatus.Information);
            break;

        case IRP_MN_QUERY_INTERFACE:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: Querying interface for PDO\n");
            Status = HalpQueryInterface(DeviceObject,
                                        IoStackLocation->Parameters.QueryInterface.InterfaceType,
                                        IoStackLocation->Parameters.QueryInterface.Size,
                                        IoStackLocation->Parameters.QueryInterface.InterfaceSpecificData,
                                        IoStackLocation->Parameters.QueryInterface.Version,
                                        IoStackLocation->Parameters.QueryInterface.Interface,
                                        &Irp->IoStatus.Information);
            break;

        case IRP_MN_QUERY_CAPABILITIES:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: Querying the capabilities for the PDO\n");
            Status = HalpQueryCapabilities(DeviceObject, IoStackLocation->Parameters.DeviceCapabilities.Capabilities);
            break;

        case IRP_MN_QUERY_RESOURCES:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: Querying the resources for the PDO\n");
            Status = HalpQueryResources(DeviceObject, (PVOID)&Irp->IoStatus.Information);
            break;

        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: Querying the resource requirements for the PDO\n");
            Status = HalpQueryResourceRequirements(DeviceObject, (PVOID)&Irp->IoStatus.Information);
            break;

        case IRP_MN_QUERY_ID:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: Query the ID for the PDO\n");
            Status = HalpQueryIdPdo(DeviceObject,
                                    IoStackLocation->Parameters.QueryId.IdType,
                                    (PVOID)&Irp->IoStatus.Information);
            break;

        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            /* Call the worker */
            DPRINT("HalpDispatchPnp: DEVICE_USAGE for the PDO\n");
            Status = STATUS_SUCCESS;
            Irp->IoStatus.Status = Status;
            break;

        default:
            /* We don't handle anything else, so inherit the old state */
            DPRINT("HalpDispatchPnp: [PDO] not supp. Minor %X\n", Minor);
            Status = Irp->IoStatus.Status;
            DPRINT("HalpDispatchPnp: IRP completed with status %X\n", Status);
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Status;
    }

    /* If it's not supported, inherit the old status */
    if (Status == STATUS_NOT_SUPPORTED)
        Status = Irp->IoStatus.Status;

    /* Complete the IRP */
    DPRINT("HalpDispatchPnp: Completed with Status %X\n", Status);
    Irp->IoStatus.Status = Status;

Exit:

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpDispatchWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
HalpDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpDriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    PDEVICE_OBJECT TargetDevice = NULL;

    PAGED_CODE();
    DPRINT("HalpDriverEntry: DriverObject %p, '%wZ'\n", DriverObject, RegistryPath);

    /* This is us */
    HalpDriverObject = DriverObject;

    /* Set up add device */
    DriverObject->DriverExtension->AddDevice = HalpAddDevice;

    /* Set up the callouts */
    DriverObject->MajorFunction[IRP_MJ_PNP] = HalpDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = HalpDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = HalpDispatchWmi;

    /* Tell the PnP manager about us */
    Status = IoReportDetectedDevice(DriverObject,
                                    InterfaceTypeUndefined,
                                    -1,
                                    -1,
                                    NULL,
                                    NULL,
                                    FALSE,
                                    &TargetDevice);

    DPRINT("HalpDriverEntry: TargetDevice %p\n", TargetDevice);
    ASSERT(TargetDevice);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpDriverEntry: Status %X\n", Status);
        ASSERT(FALSE);
        return Status;
    }

    HalpAddDevice(DriverObject, TargetDevice);

    /* Return to kernel */
    return STATUS_SUCCESS;
}

/* FUNCTIONS ******************************************************************/

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HaliInitPnpDriver(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING DriverString;

    DPRINT("HaliInitPnpDriver()\n");
    PAGED_CODE();

    /* Create the driver */
    RtlInitUnicodeString(&DriverString, L"\\Driver\\ACPI_HAL");

    Status = IoCreateDriver(&DriverString, HalpDriverEntry);
    ASSERT(NT_SUCCESS(Status));

    /* Return status */
    return Status;
}

/* EOF */
