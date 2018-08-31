/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            hal/halx86/legacy/halpnpdd.c
 * PURPOSE:         HAL Plug and Play Device Driver
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <hal.h>
#include "legacy.h"
#include "ranges.h"

//#define NDEBUG
#include <debug.h>

typedef enum _EXTENSION_TYPE
{
    PdoExtensionType = 0xC0,
    FdoExtensionType
} EXTENSION_TYPE;

typedef enum _PDO_TYPE
{
    HalPdo = 0x80,
    PciPdo,
    IsaPdo,
    McaPdo
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
    PBUS_HANDLER BusHandler;
    ULONG MaxBusNumber;
    ULONG PdoNumber;
} PDO_EXTENSION, *PPDO_EXTENSION;

/* GLOBALS ********************************************************************/

PDRIVER_OBJECT HalpDriverObject;

ULONG HalpIrqMiniportInitialized = 0;
PCI_INT_ROUTE_INTERFACE PciIrqRoutingInterface;

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
HalpRemoveAssignedResources(
    IN PBUS_HANDLER BusHandler)
{
    UNICODE_STRING ResourceMapName = 
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP");
    UNICODE_STRING NameString;
    PKEY_BASIC_INFORMATION KeyInfo;
    PKEY_FULL_INFORMATION FullKeyInfo;
    //PKEY_VALUE_BASIC_INFORMATION ValueInfo;
    PKEY_VALUE_FULL_INFORMATION FullValueInfo;
    PCM_RESOURCE_LIST CmResource;
    PCM_FULL_RESOURCE_DESCRIPTOR CmFullList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    HANDLE ResourceMapKeyHandle;
    HANDLE KeyHandle = NULL;
    HANDLE SubKeyHandle = NULL;
    ULONG Length = PAGE_SIZE;
    ULONG TranslatedNameSize;
    ULONG BusTranslatedNameSize;
    ULONG ResultLength;
    ULONG FullKeyInfoSize;
    ULONG ix, jx, kx, mx, nx;
    ULONG NameLength;
    ULONG EqualLength;
    NTSTATUS Status;

    PAGED_CODE();

    HalpRemoveRange(&BusHandler->BusAddresses->Memory, 0ll, 0xFFFll);

    FullValueInfo = ExAllocatePoolWithTag(PagedPool, Length, ' laH');

    if (!FullValueInfo)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeyInfo = (PKEY_BASIC_INFORMATION)FullValueInfo;
    FullKeyInfo = (PKEY_FULL_INFORMATION)FullValueInfo;
    //ValueInfo = (PKEY_VALUE_BASIC_INFORMATION)FullValueInfo;

    TranslatedNameSize = wcslen(L".Translated") * sizeof(WCHAR);
    BusTranslatedNameSize = wcslen(L".Bus.Translated") * sizeof(WCHAR);

    Status = HalpOpenRegistryKey(&ResourceMapKeyHandle,
                                 NULL,
                                 &ResourceMapName,
                                 KEY_READ,
                                 FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpRemoveAssignedResources: ...RESOURCEMAP not opened. Status - %X\n",
                Status);

        ASSERT(FALSE);
        ExFreePoolWithTag(FullValueInfo, ' laH');
        return Status;
    }

    for (ix = 0; NT_SUCCESS(Status); ix++)
    {
        Status = ZwEnumerateKey(ResourceMapKeyHandle,
                                ix,
                                KeyBasicInformation,
                                KeyInfo,
                                Length,
                                &ResultLength);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("HalpRemoveAssignedResources: Status - %X\n", Status);
            break;
        }

        NameString.Buffer = KeyInfo->Name;
        NameString.Length = KeyInfo->NameLength;
        NameString.MaximumLength = KeyInfo->NameLength;
        DPRINT("HalpRemoveAssignedResources: NameString - %wZ\n", &NameString);

        Status = HalpOpenRegistryKey(&KeyHandle,
                                     ResourceMapKeyHandle,
                                     &NameString,
                                     KEY_READ,
                                     FALSE);

        for (jx = 0; NT_SUCCESS(Status); jx++)
        {
            Status = ZwEnumerateKey(KeyHandle,
                                    jx,
                                    KeyBasicInformation,
                                    KeyInfo,
                                    Length,
                                    &ResultLength);

            if (!NT_SUCCESS(Status))
            {
                DPRINT("HalpRemoveAssignedResources: Status - %X\n", Status);
                break;
            }

            NameString.Buffer = KeyInfo->Name;
            NameString.Length = KeyInfo->NameLength;
            NameString.MaximumLength = KeyInfo->NameLength;
            DPRINT("HalpRemoveAssignedResources: NameString - %wZ\n", &NameString);

            Status = HalpOpenRegistryKey(&SubKeyHandle,
                                         KeyHandle,
                                         &NameString,
                                         KEY_READ,
                                         FALSE);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("HalpRemoveAssignedResources: Status - %X\n", Status);
                break;
            }

            Status = ZwQueryKey(SubKeyHandle,
                                KeyFullInformation,
                                FullKeyInfo,
                                Length,
                                &ResultLength);

            if (!NT_SUCCESS(Status))
            {
                DPRINT("HalpRemoveAssignedResources: Status - %X\n", Status);
                break;
            }

            FullKeyInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) +
                              FullKeyInfo->MaxValueNameLen + sizeof(WCHAR) +
                              FullKeyInfo->MaxValueDataLen;

            if (Length < FullKeyInfoSize)
            {
                /* Allocate FullValueInfo with new length */
                DPRINT1("HalpRemoveAssignedResources: FIXME. Length < FullKeyInfoSize\n");
                ASSERT(FALSE);
            }

            Status = ZwEnumerateValueKey(SubKeyHandle,
                                         0,
                                         KeyValueFullInformation,
                                         FullValueInfo,
                                         Length,
                                         &ResultLength);
            DPRINT("HalpRemoveAssignedResources: Status - %X\n", Status);

            for (kx = 1; NT_SUCCESS(Status); kx++)
            {
                NameLength = FullValueInfo->NameLength;

                if (NameLength < TranslatedNameSize)
                {
                    DPRINT("HalpRemoveAssignedResources: NameLength < TranslatedNameSize\n");
                    goto NextValueKey;
                }

                EqualLength = RtlCompareMemory((PUCHAR)FullValueInfo->Name + (NameLength - TranslatedNameSize),
                                               L".Translated",
                                               TranslatedNameSize);

                if (EqualLength != TranslatedNameSize)
                {
                    DPRINT("HalpRemoveAssignedResources: EqualLength != TranslatedNameSize\n");
                    goto NextValueKey;
                }

                EqualLength = RtlCompareMemory((PUCHAR)FullValueInfo->Name + (NameLength - BusTranslatedNameSize),
                                               L".Bus.Translated",
                                               BusTranslatedNameSize); 

                if (EqualLength == BusTranslatedNameSize)
                {
                    DPRINT("HalpRemoveAssignedResources: EqualLength == TranslatedNameSize\n");
                    goto NextValueKey;
                }

                CmResource = (PCM_RESOURCE_LIST)((ULONG_PTR)FullValueInfo +
                                                 FullValueInfo->DataOffset);

                HalpDumpCmResourceList(CmResource);

                CmFullList = &CmResource->List[0];

                for (mx = 0; mx < CmResource->Count; mx++)
                {
                    DPRINT("HalpRemoveAssignedResources: mx - %X, CmResource->Count - %X, Count - %X\n",
                           mx, CmResource->Count, CmFullList->PartialResourceList.Count);

                    CmDescriptor = &CmFullList->PartialResourceList.PartialDescriptors[0];

                    for (nx = 0;
                         nx < CmFullList->PartialResourceList.Count;
                         nx++)
                    {
                        CmDescriptor = &CmFullList->PartialResourceList.PartialDescriptors[nx];

                        //HalpDumpCmResourceDescriptor("    ", CmDescriptor);

                        switch (CmDescriptor->Type)
                        {
                            case CmResourceTypePort:
                                DPRINT("HalpRemoveAssignedResources: CmResourceTypePort\n");
                                HalpRemoveRange(&BusHandler->BusAddresses->IO,
                                                CmDescriptor->u.Port.Start.QuadPart,
                                                CmDescriptor->u.Port.Start.QuadPart + CmDescriptor->u.Port.Length - 1);
                                break;

                            case CmResourceTypeMemory:
                                DPRINT("HalpRemoveAssignedResources: CmResourceTypeMemory\n");
                                HalpRemoveRange(&BusHandler->BusAddresses->IO,
                                                CmDescriptor->u.Memory.Start.QuadPart,
                                                CmDescriptor->u.Memory.Start.QuadPart + CmDescriptor->u.Memory.Length - 1);
                                break;

                            default:
                                ASSERT(CmDescriptor->Type != CmResourceTypeDeviceSpecific);
                                break;
                        }
                    }

                    CmFullList = (PCM_FULL_RESOURCE_DESCRIPTOR)
                                 (CmFullList->PartialResourceList.PartialDescriptors + 
                                  CmFullList->PartialResourceList.Count);
                }

NextValueKey:
                Status = ZwEnumerateValueKey(SubKeyHandle,
                                             kx,
                                             KeyValueFullInformation,
                                             FullValueInfo,
                                             Length,
                                             &ResultLength);
            }

            if (SubKeyHandle)
            {
                ZwClose(SubKeyHandle);
                SubKeyHandle = NULL;
            }

            if (Status == STATUS_NO_MORE_ENTRIES)
            {
                Status = STATUS_SUCCESS;
            }
        }

        if (KeyHandle)
        {
            ZwClose(KeyHandle);
            KeyHandle = NULL;
        }

        if (Status == STATUS_NO_MORE_ENTRIES)
        {
            Status = STATUS_SUCCESS;
        }
    }

    if (Status == STATUS_NO_MORE_ENTRIES)
    {
        Status = STATUS_SUCCESS;
    }

    if (ResourceMapKeyHandle)
    {
        ZwClose(ResourceMapKeyHandle);
    }

    ExFreePoolWithTag(FullValueInfo, ' laH');

    HalpConsolidateRanges(BusHandler->BusAddresses);

    return Status;
}

NTSTATUS
NTAPI
HalpAddDevice(IN PDRIVER_OBJECT DriverObject,
              IN PDEVICE_OBJECT TargetDevice)
{
    NTSTATUS Status;
    PFDO_EXTENSION FdoExtension;
    PPDO_EXTENSION PdoExtension;
    PDEVICE_OBJECT Fdo;
    PDEVICE_OBJECT AttachedDevice;
    PDEVICE_OBJECT Pdo;
    PBUS_HANDLER BusHandler;
    PBUS_HANDLER ParentHandler;
    UNICODE_STRING HalPdoName;
    PDO_TYPE PdoType;
    ULONG ix;
    WCHAR Buffer[40];

    DPRINT("HalpAddDevice: PnP Driver ADD!\n");

    /* Create the FDO */
    Status = IoCreateDevice(DriverObject,
                            sizeof(FDO_EXTENSION),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            0,
                            FALSE,
                            &Fdo);
    if (!NT_SUCCESS(Status))
    {
        /* Should not happen */
        DbgBreakPoint();
        return Status;
    }

    /* Setup the FDO extension */
    FdoExtension = Fdo->DeviceExtension;
    FdoExtension->ExtensionType = FdoExtensionType;
    FdoExtension->PhysicalDeviceObject = TargetDevice;
    FdoExtension->FunctionalDeviceObject = Fdo;
    FdoExtension->ChildPdoList = NULL;

    /* Attach to the physical device object (the bus) */
    AttachedDevice = IoAttachDeviceToDeviceStack(Fdo, TargetDevice);
    if (!AttachedDevice)
    {
        /* Failed, undo everything */
        DPRINT("HalpAddDevice: Couldn't attach to the PDO");
        IoDeleteDevice(Fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    /* FDO is done initializing */
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Save the attachment */
    FdoExtension->AttachedDeviceObject = AttachedDevice;

    /* For legacy hals (hal, halapic, halmps) looking for bus:
      first pci, then (if pci was not found) continue the search
      for isa | eisa or for mca bus. */

    for (ix = 0; ; ix++)
    {
        BusHandler = HaliReferenceHandlerForBus(PCIBus, ix);
        if (!BusHandler)
        {
            break;
        }

        DPRINT("HalpAddDevice: found PCI bus - %X\n", BusHandler);

        ParentHandler = BusHandler->ParentHandler;
        if (ParentHandler && ParentHandler->InterfaceType == PCIBus)
        {
            DPRINT("HalpAddDevice: close PCI bus - %X\n", BusHandler);
            HaliDereferenceBusHandler(BusHandler);
            continue;
        }

        Status = HalpRemoveAssignedResources(BusHandler);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("HalpAddDevice: HalpRemoveAssignedResources return - %X\n", Status);
            HaliDereferenceBusHandler(BusHandler);
            return Status;
        }

        swprintf(Buffer, L"\\Device\\Hal Pci %d", ix);
        RtlInitUnicodeString(&HalPdoName, Buffer);

        Status = IoCreateDevice(DriverObject,
                                sizeof(PDO_EXTENSION),
                                &HalPdoName,
                                FILE_DEVICE_BUS_EXTENDER,
                                0,
                                FALSE,
                                &Pdo);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("HalpAddDevice: IoCreateDevice return - %X\n", Status);
            DbgBreakPoint();
            HaliDereferenceBusHandler(BusHandler);
            return Status;
        }

        PdoExtension = Pdo->DeviceExtension;

        /* Setup the PDO device extension */
        PdoExtension = Pdo->DeviceExtension;
        PdoExtension->ExtensionType = PdoExtensionType;
        PdoExtension->PhysicalDeviceObject = Pdo;
        PdoExtension->ParentFdoExtension = FdoExtension;
        PdoExtension->PdoType = PciPdo;
        PdoExtension->BusHandler = BusHandler;
        PdoExtension->MaxBusNumber = 255;
        PdoExtension->PdoNumber = ix;

        /* Add the PDO to the head of the list */
        PdoExtension->Next = FdoExtension->ChildPdoList;
        FdoExtension->ChildPdoList = PdoExtension;

        /* Initialization is finished */
        Pdo->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    /* If pci bus was not found */
    if (ix == 0)
    {
        BusHandler = HaliReferenceHandlerForBus(Isa, 0);
        if (BusHandler ||
            (BusHandler = HaliReferenceHandlerForBus(Eisa, 0)))
        {
            RtlInitUnicodeString(&HalPdoName, L"\\Device\\Hal Isa 0");
            PdoType = IsaPdo;
        }
        else
        {
            BusHandler = HaliReferenceHandlerForBus(MicroChannel, 0);
            RtlInitUnicodeString(&HalPdoName, L"\\Device\\Hal Mca 0");
            PdoType = McaPdo;
        }

        if (!BusHandler)
        {
            DPRINT("HalpAddDevice: No bus found !!!");
            ASSERT(BusHandler);
            return STATUS_NO_SUCH_DEVICE;
        }

        Status = IoCreateDevice(DriverObject,
                                sizeof(PDO_EXTENSION),
                                &HalPdoName,
                                FILE_DEVICE_BUS_EXTENDER,
                                0,
                                FALSE,
                                &Pdo);

        if (!NT_SUCCESS(Status))
        {
            DbgBreakPoint();
            HaliDereferenceBusHandler(BusHandler);
            return Status;
        }

        /* Setup the PDO device extension */
        PdoExtension = Pdo->DeviceExtension;
        PdoExtension->ExtensionType = PdoExtensionType;
        PdoExtension->PhysicalDeviceObject = Pdo;
        PdoExtension->ParentFdoExtension = FdoExtension;
        PdoExtension->PdoType = PdoType;
        PdoExtension->BusHandler = BusHandler;
        PdoExtension->MaxBusNumber = 0;
        PdoExtension->PdoNumber = 0;

        /* Add the PDO to the head of the list */
        FdoExtension->ChildPdoList = PdoExtension;

        /* Initialization is finished */
        Pdo->Flags &= DO_DEVICE_INITIALIZING;
    }

    /* Return status */
    DPRINT("HalpAddDevice: return - %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
HalpQueryInterface(IN PDEVICE_OBJECT DeviceObject,
                   IN CONST GUID* InterfaceType,
                   IN USHORT Version,
                   IN PVOID InterfaceSpecificData,
                   IN ULONG InterfaceBufferSize,
                   IN PINTERFACE Interface,
                   OUT PULONG Length)
{
    UNIMPLEMENTED;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
HalpQueryDeviceRelations(IN PDEVICE_OBJECT DeviceObject,
                         IN DEVICE_RELATION_TYPE RelationType,
                         OUT PDEVICE_RELATIONS* DeviceRelations)
{
    EXTENSION_TYPE ExtensionType;
    PPDO_EXTENSION PdoExtension;
    PFDO_EXTENSION FdoExtension;
    PDEVICE_RELATIONS PdoRelations, FdoRelations;
    PDEVICE_OBJECT* ObjectEntry;
    ULONG i = 0, PdoCount = 0;

    /* Get FDO device extension and PDO count */
    FdoExtension = DeviceObject->DeviceExtension;
    ExtensionType = FdoExtension->ExtensionType;

    /* What do they want? */
    if (RelationType == BusRelations)
    {
        /* This better be an FDO */
        if (ExtensionType == FdoExtensionType)
        {
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
            {
                PdoCount += (*DeviceRelations)->Count;
            }

            /* Allocate our structure */
            FdoRelations = ExAllocatePoolWithTag(PagedPool,
                                                 FIELD_OFFSET(DEVICE_RELATIONS,
                                                              Objects) +
                                                 sizeof(PDEVICE_OBJECT) * PdoCount,
                                                 TAG_HAL);
            if (!FdoRelations) return STATUS_INSUFFICIENT_RESOURCES;

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
                        *ObjectEntry++ = (*DeviceRelations)->Objects[i];
                    }
                    while (++i < (*DeviceRelations)->Count);
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
    }
    else
    {
        /* The only other thing we support is a target relation for the PDO */
        if ((RelationType == TargetDeviceRelation) &&
            (ExtensionType == PdoExtensionType))
        {
            /* Only one entry */
            PdoRelations = ExAllocatePoolWithTag(PagedPool,
                                                 sizeof(DEVICE_RELATIONS),
                                                 TAG_HAL);
            if (!PdoRelations) return STATUS_INSUFFICIENT_RESOURCES;

            /* Fill it out and reference us */
            PdoRelations->Count = 1;
            PdoRelations->Objects[0] = DeviceObject;
            ObReferenceObject(DeviceObject);

            /* Return it */
            *DeviceRelations = PdoRelations;
            return STATUS_SUCCESS;
        }
    }

    /* We don't support anything else */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
HalpQueryCapabilities(IN PDEVICE_OBJECT DeviceObject,
                      OUT PDEVICE_CAPABILITIES Capabilities)
{
    //PPDO_EXTENSION PdoExtension;
    NTSTATUS Status;
    PAGED_CODE();

    /* Get the extension and check for valid version */
    //PdoExtension = DeviceObject->DeviceExtension;
    ASSERT(Capabilities->Version == 1);
    if (Capabilities->Version == 1)
    {
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
        Capabilities->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;

        /* Done */
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* Fail */
        Status = STATUS_NOT_SUPPORTED;
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
HalpQueryResources(IN PDEVICE_OBJECT DeviceObject,
                   OUT PCM_RESOURCE_LIST * OutCmResource)
{
    PPDO_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor0;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    PCM_RESOURCE_LIST CmResource;
    PSUPPORTED_RANGES BusAddresses;
    PSUPPORTED_RANGE Io;
    PSUPPORTED_RANGE MemoryAddresses;
    PSUPPORTED_RANGE PrfMemoryAddresses;
    ULONG ListSize;
    ULONG Count = 1; // one add. BusNumber descriptor
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpQueryResources: PdoType - %X\n", DeviceExtension->PdoType);

    if (DeviceExtension->PdoType != PciPdo)
    {
        ASSERT(FALSE);
        *OutCmResource = NULL;
        return STATUS_SUCCESS;
    }

    BusAddresses = DeviceExtension->BusHandler->BusAddresses;

    for (Io = &BusAddresses->IO;
         Io;
         Io = Io->Next)
    {
        DPRINT("HalpQueryResources: Count - %X, Io->Limit - %X\n",
               Count, Io->Limit);

        if (Io->Limit)
        {
            Count++;
        }
    }

    for (MemoryAddresses = &BusAddresses->Memory;
         MemoryAddresses;
         MemoryAddresses = MemoryAddresses->Next)
    {
        DPRINT("HalpQueryResources: Count - %X, MemoryAddresses->Limit - %X\n",
               Count, MemoryAddresses->Limit);

        if (MemoryAddresses->Limit)
        {
            Count++;
        }
    }

    for (PrfMemoryAddresses = &BusAddresses->PrefetchMemory;
         PrfMemoryAddresses;
         PrfMemoryAddresses = PrfMemoryAddresses->Next)
    {
        DPRINT("HalpQueryResources: Count - %X, PrfMemoryAddresses->Limit - %X\n",
               Count, PrfMemoryAddresses->Limit);

        if (PrfMemoryAddresses->Limit)
        {
            Count++;
        }
    }

    DPRINT("HalpQueryResources: Count - %X\n", Count);

    ListSize = sizeof(CM_RESOURCE_LIST) +
               (Count - 1) * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

    /* Allocate the resourcel ist */
    CmResource = ExAllocatePoolWithTag(PagedPool, ListSize, TAG_HAL);

    if (!CmResource)
    {
        /* Fail, no memory */
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return Status;
    }

    /* Initialize it */
    RtlZeroMemory(CmResource, ListSize);

    /* Setup the list fields */
    CmResource->Count = 1;

    CmResource->List[0].BusNumber = -1;
    CmResource->List[0].InterfaceType = PNPBus;
    CmResource->List[0].PartialResourceList.Version = 1;
    CmResource->List[0].PartialResourceList.Revision = 1;
    CmResource->List[0].PartialResourceList.Count = Count;

    Descriptor0 = &CmResource->List[0].PartialResourceList.PartialDescriptors[0];

    Descriptor0->Type = CmResourceTypeBusNumber;
    Descriptor0->ShareDisposition = CmResourceShareShared;

    Descriptor0->u.BusNumber.Start = DeviceExtension->PdoNumber;
    Descriptor0->u.BusNumber.Length = DeviceExtension->MaxBusNumber -
                                      DeviceExtension->PdoNumber + 1;

    Descriptor = &CmResource->List[0].PartialResourceList.PartialDescriptors[1];

    for (Io = &BusAddresses->IO;
         Io;
         Io = Io->Next)
    {
        if (Io->Limit)
        {
            Descriptor->Type = CmResourceTypePort;
            Descriptor->ShareDisposition = CmResourceShareShared;
            Descriptor->Flags = CM_RESOURCE_PORT_IO;

            Descriptor->u.Port.Length = (ULONG)(Io->Limit - Io->Base + 1);
            Descriptor->u.Port.Start.QuadPart = Io->Base;

            DPRINT("HalpQueryResources: (Io) Limit - %I64X, Base -  %I64X, Length - %X\n",
                   Io->Limit, Io->Base, Descriptor->u.Port.Length);

            Descriptor++;
        }
    }

    for (MemoryAddresses = &BusAddresses->Memory;
         MemoryAddresses;
         MemoryAddresses = MemoryAddresses->Next)
    {
        if (MemoryAddresses->Limit)
        {
            Descriptor->Type = CmResourceTypeMemory;
            Descriptor->ShareDisposition = CmResourceShareShared;
            Descriptor->Flags = CM_RESOURCE_MEMORY_READ_WRITE;

            Descriptor->u.Memory.Length = (ULONG)(MemoryAddresses->Limit -
                                                  MemoryAddresses->Base + 1);

            Descriptor->u.Memory.Start.QuadPart = MemoryAddresses->Base;

            DPRINT("HalpQueryResources: (Memory) Limit - %I64X, Base -  %I64X, Length - %X\n",
                   MemoryAddresses->Limit, MemoryAddresses->Base, Descriptor->u.Memory.Length);

            Descriptor++;
        }
    }

    for (PrfMemoryAddresses = &BusAddresses->PrefetchMemory;
         PrfMemoryAddresses;
         PrfMemoryAddresses = PrfMemoryAddresses->Next)
    {
        if (PrfMemoryAddresses->Limit)
        {
            Descriptor->Type = CmResourceTypeMemory;
            Descriptor->ShareDisposition = CmResourceShareShared;
            Descriptor->Flags = CM_RESOURCE_MEMORY_READ_WRITE +
                                CM_RESOURCE_MEMORY_PREFETCHABLE;

            Descriptor->u.Memory.Length = (ULONG)(PrfMemoryAddresses->Limit -
                                                  PrfMemoryAddresses->Base + 1);

            Descriptor->u.Memory.Start.QuadPart = PrfMemoryAddresses->Base;

            DPRINT("HalpQueryResources: (PrfMemory) Limit - %I64X, Base -  %I64X, Length - %X\n",
                   PrfMemoryAddresses->Limit, PrfMemoryAddresses->Base, Descriptor->u.Memory.Length);

            Descriptor++;
        }
    }

    *OutCmResource = CmResource;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HalpQueryResourceRequirements(IN PDEVICE_OBJECT DeviceObject,
                              OUT PIO_RESOURCE_REQUIREMENTS_LIST * OutIoResource)
{
    PPDO_EXTENSION DeviceExtension;
    PSUPPORTED_RANGES BusAddresses;
    PSUPPORTED_RANGE Io;
    PSUPPORTED_RANGE IoBusAddr;
    PSUPPORTED_RANGE Memory;
    PSUPPORTED_RANGE MemoryBusAddr;
    PSUPPORTED_RANGE PrfMemory;
    PSUPPORTED_RANGE PrefetchMemoryBusAddr;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource;
    PIO_RESOURCE_DESCRIPTOR Descriptor;
    ULONG ListSize;
    ULONG Count = 0;

    DeviceExtension = DeviceObject->DeviceExtension;

    if (DeviceExtension->PdoType != PciPdo)
    {
        ASSERT(FALSE);
        *OutIoResource = NULL;
        return STATUS_SUCCESS;
    }

    BusAddresses = DeviceExtension->BusHandler->BusAddresses;

    for (Io = &BusAddresses->IO;
         Io;
         Io = Io->Next)
    {
        DPRINT("HalpQueryResourceRequirements: Count - %X, Io->Limit - %X\n",
               Count, Io->Limit);

        if (Io->Limit)
        {
            Count++;
        }
    }

    for (Memory = &BusAddresses->Memory;
         Memory;
         Memory = Memory->Next)
    {
        DPRINT("HalpQueryResourceRequirements: Count - %X, Memory->Limit - %X\n",
               Count, Memory->Limit);

        if (Memory->Limit)
        {
            Count++;
        }
    }

    for (PrfMemory = &BusAddresses->PrefetchMemory;
         PrfMemory;
         PrfMemory = PrfMemory->Next)
    {
        DPRINT("HalpQueryResourceRequirements: Count - %X, PrfMemory->Limit - %X\n",
               Count, PrfMemory->Limit);

        if (PrfMemory->Limit)
        {
            Count++;
        }
    }

    DPRINT("HalpQueryResourceRequirements: Count - %X\n", Count);

    ListSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) +
               (Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR);

    IoResource = ExAllocatePoolWithTag(PagedPool, ListSize, ' laH');

    if (!IoResource)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(IoResource, ListSize);

    IoResource->ListSize = ListSize;
    IoResource->InterfaceType = PNPBus;
    IoResource->BusNumber = -1;
    IoResource->AlternativeLists = 1;

    IoResource->List[0].Version = 1;
    IoResource->List[0].Revision = 1;
    IoResource->List[0].Count = Count;

    Descriptor = IoResource->List[0].Descriptors;

    for (IoBusAddr = &BusAddresses->IO;
         IoBusAddr;
         IoBusAddr = IoBusAddr->Next)
    {
        if (IoBusAddr->Limit == 0)
        {
            continue;
        }

        Descriptor->Type = CmResourceTypePort;
        Descriptor->ShareDisposition = CmResourceShareShared;
        Descriptor->Flags = CM_RESOURCE_PORT_IO;

        Descriptor->u.Port.Alignment = 1;
        Descriptor->u.Port.Length = IoBusAddr->Limit - IoBusAddr->Base + 1;
        Descriptor->u.Port.MinimumAddress.QuadPart = IoBusAddr->Base;
        Descriptor->u.Port.MaximumAddress.QuadPart = IoBusAddr->Limit;

        Descriptor++;
    }

    for (MemoryBusAddr = &BusAddresses->Memory;
         MemoryBusAddr;
         MemoryBusAddr = MemoryBusAddr->Next)
    {
        if (MemoryBusAddr->Limit == 0)
        {
            continue;
        }

        Descriptor->Type = CmResourceTypeMemory;
        Descriptor->ShareDisposition = CmResourceShareShared;
        Descriptor->Flags = CM_RESOURCE_MEMORY_READ_WRITE;

        Descriptor->u.Memory.Alignment = 1;
        Descriptor->u.Memory.Length = MemoryBusAddr->Limit - MemoryBusAddr->Base + 1;
        Descriptor->u.Memory.MinimumAddress.LowPart = MemoryBusAddr->Base;
        Descriptor->u.Memory.MaximumAddress.LowPart = MemoryBusAddr->Limit;

        Descriptor++;
    }

    for (PrefetchMemoryBusAddr = &BusAddresses->PrefetchMemory;
         PrefetchMemoryBusAddr;
         PrefetchMemoryBusAddr = PrefetchMemoryBusAddr->Next)
    {
        if (PrefetchMemoryBusAddr->Limit == 0)
        {
            continue;
        }

        Descriptor->Type = CmResourceTypeMemory;
        Descriptor->ShareDisposition = CmResourceShareShared;
        Descriptor->Flags = CM_RESOURCE_MEMORY_READ_WRITE +
                            CM_RESOURCE_MEMORY_PREFETCHABLE;

        Descriptor->u.Memory.Alignment = 1;
        Descriptor->u.Memory.Length = MemoryBusAddr->Limit - MemoryBusAddr->Base + 1;
        Descriptor->u.Memory.MinimumAddress.LowPart = MemoryBusAddr->Base;
        Descriptor->u.Memory.MaximumAddress.LowPart = MemoryBusAddr->Limit;

        Descriptor++;
    }

    *OutIoResource = IoResource;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HalpQueryIdPdo(IN PDEVICE_OBJECT DeviceObject,
               IN BUS_QUERY_ID_TYPE IdType,
               OUT PUSHORT *BusQueryId)
{
    PPDO_EXTENSION PdoExtension;
    PDO_TYPE PdoType;
    PWCHAR CurrentId;
    WCHAR Id[100];
    NTSTATUS Status;
    ULONG Length = 0;
    PWCHAR Buffer;

    DPRINT("HalpQueryIdPdo: IdType - %X\n", IdType);

    /* Get the PDO type */
    PdoExtension = DeviceObject->DeviceExtension;
    PdoType = PdoExtension->PdoType;

    switch (IdType)
    {
        case BusQueryDeviceID:
        case BusQueryHardwareIDs:

            if (PdoType == PciPdo)
            {
                /* PCI bus */
                CurrentId = L"PCI_HAL\\PNP0A03";
                RtlCopyMemory(Id, CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

                CurrentId = L"*PNP0A03";
                RtlCopyMemory(&Id[wcslen(Id) + 1], CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
            }
            else if (PdoType == IsaPdo || PdoType == McaPdo)
            {
                DPRINT1("HalpQueryIdPdo: FIXME IsaPdo | McaPdo !\n");
                ASSERT(FALSE);
#if 0
                /* ISA bus */ // ISA_HAL\\PNP0A00
                /* EISA bus */ // ISA_HAL\PNP0A02
                CurrentId = L"ISA_HAL\\PNP0A00";
                RtlCopyMemory(Id, CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

                CurrentId = L"*PNP0A00";
                RtlCopyMemory(&Id[wcslen(Id) + 1], CurrentId, (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL));
                Length += (wcslen(CurrentId) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
#endif
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

NTSTATUS
NTAPI
HalpQueryIdFdo(IN PDEVICE_OBJECT DeviceObject,
               IN BUS_QUERY_ID_TYPE IdType,
               OUT PUSHORT *BusQueryId)
{
    NTSTATUS Status;
    ULONG Length;
    PWCHAR Id;
    PWCHAR Buffer;

    /* What kind of ID is being requested? */
    DPRINT("ID: %d\n", IdType);
    switch (IdType)
    {
        case BusQueryDeviceID:
            /* HACK */
            Id = L"Root\\PCI_HAL";
            break;

        case BusQueryHardwareIDs:

            /* This is our hardware ID */
            Id = HalHardwareIdString;
            break;

        case BusQueryInstanceID:

            /* And our instance ID */
            Id = L"0";
            break;

        default:

            /* We don't support anything else */
            return STATUS_NOT_SUPPORTED;
    }

    /* Calculate the length */
    Length = (wcslen(Id) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

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

NTSTATUS
NTAPI
HalpDispatchPnp(IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStackLocation;
    //PPDO_EXTENSION PdoExtension;
    PFDO_EXTENSION FdoExtension;
    NTSTATUS Status;
    UCHAR Minor;

    /* Get the device extension and stack location */
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

                /* Call the worker */
                DPRINT("Querying device relations for FDO\n");
                Status = HalpQueryDeviceRelations(DeviceObject,
                                                  IoStackLocation->Parameters.QueryDeviceRelations.Type,
                                                  (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_INTERFACE:

                /* Call the worker */
                DPRINT("Querying interface for FDO\n");
                Status = HalpQueryInterface(DeviceObject,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceType,
                                            IoStackLocation->Parameters.QueryInterface.Size,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceSpecificData,
                                            IoStackLocation->Parameters.QueryInterface.Version,
                                            IoStackLocation->Parameters.QueryInterface.Interface,
                                            (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_ID:

                /* Call the worker */
                DPRINT("Querying ID for FDO\n");
                Status = HalpQueryIdFdo(DeviceObject,
                                        IoStackLocation->Parameters.QueryId.IdType,
                                        (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_CAPABILITIES:

                /* Call the worker */
                DPRINT("Querying the capabilities for the FDO\n");
                Status = HalpQueryCapabilities(DeviceObject,
                                               IoStackLocation->Parameters.DeviceCapabilities.Capabilities);
                break;

            default:

                DPRINT("Other IRP: %lx\n", Minor);
                Status = Irp->IoStatus.Status;
                break;
        }

        /* Nowhere for the IRP to go since we also own the PDO */
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }
    else
    {
        /* This is a PDO instead */
        ASSERT(FdoExtension->ExtensionType == PdoExtensionType);
        //PdoExtension = (PPDO_EXTENSION)FdoExtension;

        /* Query the IRP type */
        Status = STATUS_SUCCESS;
        switch (Minor)
        {
            case IRP_MN_START_DEVICE:

                /* We only care about a PCI PDO */
                DPRINT("Start device received\n");
                /* Complete the IRP normally */
                break;

            case IRP_MN_REMOVE_DEVICE:

                /* Check if this is a PCI device */
                DPRINT("Remove device received\n");

                /* We're done */
                Status = STATUS_SUCCESS;
                break;

            case IRP_MN_SURPRISE_REMOVAL:

                /* Inherit whatever status we had */
                DPRINT("Surprise removal IRP\n");
                Status = Irp->IoStatus.Status;
                break;

            case IRP_MN_QUERY_DEVICE_RELATIONS:

                /* Query the device relations */
                DPRINT("Querying PDO relations\n");
                Status = HalpQueryDeviceRelations(DeviceObject,
                                                  IoStackLocation->Parameters.QueryDeviceRelations.Type,
                                                  (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_INTERFACE:

                /* Call the worker */
                DPRINT("Querying interface for PDO\n");
                Status = HalpQueryInterface(DeviceObject,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceType,
                                            IoStackLocation->Parameters.QueryInterface.Size,
                                            IoStackLocation->Parameters.QueryInterface.InterfaceSpecificData,
                                            IoStackLocation->Parameters.QueryInterface.Version,
                                            IoStackLocation->Parameters.QueryInterface.Interface,
                                            (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_CAPABILITIES:

                /* Call the worker */
                DPRINT("Querying the capabilities for the PDO\n");
                Status = HalpQueryCapabilities(DeviceObject,
                                               IoStackLocation->Parameters.DeviceCapabilities.Capabilities);
                break;

            case IRP_MN_QUERY_RESOURCES:

                /* Call the worker */
                DPRINT("Querying the resources for the PDO\n");
                Status = HalpQueryResources(DeviceObject, (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:

                /* Call the worker */
                DPRINT("Querying the resource requirements for the PDO\n");
                Status = HalpQueryResourceRequirements(DeviceObject,
                                                       (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_ID:

                /* Call the worker */
                DPRINT("Query the ID for the PDO\n");
                Status = HalpQueryIdPdo(DeviceObject,
                                        IoStackLocation->Parameters.QueryId.IdType,
                                        (PVOID)&Irp->IoStatus.Information);
                break;

            case IRP_MN_QUERY_DEVICE_TEXT:

                /* Inherit whatever status we had */
                DPRINT("Query text for the PDO\n");
                Status = Irp->IoStatus.Status;
                break;

            case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:

                /* Inherit whatever status we had */
                DPRINT("Filter resource requirements for the PDO\n");
                Status = Irp->IoStatus.Status;
                break;

            case IRP_MN_QUERY_PNP_DEVICE_STATE:

                /* Inherit whatever status we had */
                DPRINT("Query device state for the PDO\n");
                Status = Irp->IoStatus.Status;
                break;

            case IRP_MN_QUERY_BUS_INFORMATION:

                /* Inherit whatever status we had */
                DPRINT("Query bus information for the PDO\n");
                Status = Irp->IoStatus.Status;
                break;

            default:

                /* We don't handle anything else, so inherit the old state */
                DPRINT1("Illegal IRP: %lx\n", Minor);
                Status = Irp->IoStatus.Status;
                break;
        }

        /* If it's not supported, inherit the old status */
        if (Status == STATUS_NOT_SUPPORTED) Status = Irp->IoStatus.Status;

        /* Complete the IRP */
        DPRINT("IRP completed with status: %lx\n", Status);
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }
}

NTSTATUS
NTAPI
HalpDispatchWmi(IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK("HAL: PnP Driver WMI!\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HalpDispatchPower(IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp)
{
    PFDO_EXTENSION FdoExtension;

    DPRINT1("HAL: PnP Driver Power!\n");
    FdoExtension = DeviceObject->DeviceExtension;
    if (FdoExtension->ExtensionType == FdoExtensionType)
    {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(FdoExtension->AttachedDeviceObject, Irp);
    }
    else
    {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
}

NTSTATUS
NTAPI
HalpDriverEntry(IN PDRIVER_OBJECT DriverObject,
                IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    PDEVICE_OBJECT TargetDevice = NULL;

    DPRINT("HAL: PnP Driver ENTRY!\n");

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
    ASSERT(TargetDevice);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpDriverEntry: IoReportDetectedDevice() failed!\n");
        return Status;
    }

    /* Set up the device stack */
    Status = HalpAddDevice(DriverObject, TargetDevice);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpDriverEntry: Add device failed!\n");
        IoDeleteDevice(TargetDevice);
    }

    RtlZeroMemory(&PciIrqRoutingInterface, sizeof(PCI_INT_ROUTE_INTERFACE));
    RtlZeroMemory(&HalpPciIrqRoutingInfo, sizeof(HAL_PCI_IRQ_ROUTING_INFO));

    /* Return to kernel */
    return Status;
}

NTSTATUS
NTAPI
HaliInitPnpDriver(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING DriverString;
    PAGED_CODE();

    /* Create the driver */
    RtlInitUnicodeString(&DriverString, L"\\Driver\\PCI_HAL");
    Status = IoCreateDriver(&DriverString, HalpDriverEntry);

    /* Return status */
    return Status;
}

/* EOF */
