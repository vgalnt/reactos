
/* INCLUDES *******************************************************************/

#include <hal.h>
#include "apic.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

extern ULONG HalpPicVectorRedirect[HAL_PIC_VECTORS];
extern BUS_HANDLER HalpFakePciBusHandler;
extern BOOLEAN HalpPCIConfigInitialized;
extern ULONG HalpMinPciBus;
extern ULONG HalpMaxPciBus;
extern FADT HalpFixedAcpiDescTable;

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
TranslateGlobalVectorToIsaVector(
    _In_ ULONG GlobalVector,
    _Out_ PULONG IsaVector
);

NTSTATUS
NTAPI 
HalacpiIrqTranslateResourcesIsa(
     _Inout_opt_ PVOID Context,
     _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Source,
     _In_ RESOURCE_TRANSLATION_DIRECTION Direction,
     _In_opt_ ULONG AlternativesCount,
     _In_opt_ IO_RESOURCE_DESCRIPTOR Alternatives[],
     _In_ PDEVICE_OBJECT PhysicalDeviceObject,
     _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Target
);

NTSTATUS
NTAPI 
HalacpiIrqTranslateResourceRequirementsIsa(
    _Inout_opt_ PVOID Context,
    _In_ PIO_RESOURCE_DESCRIPTOR Source,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject,
    _Out_ PULONG TargetCount,
    _Out_ PIO_RESOURCE_DESCRIPTOR* Target
);

NTSTATUS
NTAPI
HalacpiGetInterruptTranslator(
    _In_ INTERFACE_TYPE ParentInterfaceType,
    _In_ ULONG ParentBusNumber,
    _In_ INTERFACE_TYPE BridgeInterfaceType,
    _In_ USHORT Size,
    _In_ USHORT Version,
    _Out_ PTRANSLATOR_INTERFACE Translator,
    _Out_ PULONG BridgeBusNumber
);

NTSTATUS
NTAPI
HalpAssignSlotResources(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING DriverClassName,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Inout_ PCM_RESOURCE_LIST* AllocatedResources
);

NTSTATUS
NTAPI
HalAssignSlotResources(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING DriverClassName,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Inout_ PCM_RESOURCE_LIST* AllocatedResources
);

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, TranslateGlobalVectorToIsaVector)
  #pragma alloc_text(PAGE, HalacpiIrqTranslateResourcesIsa)
  #pragma alloc_text(PAGE, HalacpiIrqTranslateResourceRequirementsIsa)
  #pragma alloc_text(PAGE, HalacpiGetInterruptTranslator)
  #pragma alloc_text(PAGE, HalpAssignSlotResources)
  #pragma alloc_text(PAGE, HalAssignSlotResources)
#endif

CODE_SEG("PAGE")
NTSTATUS
NTAPI
TranslateGlobalVectorToIsaVector(
    _In_ ULONG GlobalVector,
    _Out_ PULONG IsaVector)
{
    UCHAR ix;

    DPRINT("TranslateGlobalVectorToIsaVector: Global %X, Isa %X\n", GlobalVector, IsaVector);

    for (ix = 0; ix < 0x10; ix++)
    {
        if (HalpPicVectorRedirect[ix] == GlobalVector)
        {
            DPRINT("TranslateGlobalVectorToIsaVector: Vector %X\n", ix);
            *IsaVector = ix;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI 
HalacpiIrqTranslateResourcesIsa(
     _Inout_opt_ PVOID Context,
     _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Source,
     _In_ RESOURCE_TRANSLATION_DIRECTION Direction,
     _In_opt_ ULONG AlternativesCount,
     _In_opt_ IO_RESOURCE_DESCRIPTOR Alternatives[],
     _In_ PDEVICE_OBJECT PhysicalDeviceObject,
     _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Target)
{
    ULONG Level;
    ULONG Vector;
    ULONG ix;
    BOOLEAN IsFound = FALSE;
    NTSTATUS Status;

    DPRINT("HalacpiIrqTranslateResourcesIsa: Direction %X, AltCount %X\n", Direction, AlternativesCount);
    PAGED_CODE();

    ASSERT(Source->Type == CmResourceTypeInterrupt);

    RtlCopyMemory(Target, Source, sizeof(*Target));

    if (Direction == TranslateChildToParent)
    {
        Target->u.Interrupt.Level = HalpPicVectorRedirect[Source->u.Interrupt.Level];
        Target->u.Interrupt.Vector = HalpPicVectorRedirect[Source->u.Interrupt.Vector];

        DPRINT("HalacpiIrqTranslateResourcesIsa: Lvl %X, Vec %X\n",
               Target->u.Interrupt.Level, Target->u.Interrupt.Vector);

        return STATUS_SUCCESS;
    }

    if (Direction != 1)
    {
        ASSERT(FALSE);
        return STATUS_SUCCESS;
    }

    Status = TranslateGlobalVectorToIsaVector(Source->u.Interrupt.Level, &Level);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalacpiIrqTranslateResourcesIsa: Status %X\n", Status);
        ASSERT(FALSE);
        return Status;
    }

    Target->u.Interrupt.Level = Level;

    Status = TranslateGlobalVectorToIsaVector(Source->u.Interrupt.Vector, &Vector);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalacpiIrqTranslateResourcesIsa: Status %X\n", Status);
        ASSERT(FALSE);
        return Status;
    }

    Target->u.Interrupt.Vector = Vector;

    if (!Target->u.Interrupt.Level == 9 || AlternativesCount <= 0)
    {
        DPRINT("HalacpiIrqTranslateResourcesIsa: Level %X, Vector %X\n",
               Target->u.Interrupt.Level, Target->u.Interrupt.Vector);
        ASSERT(FALSE);
        return STATUS_SUCCESS;
    }

    for (ix = 0; ix < AlternativesCount; ix++)
    {
        if (Alternatives[ix].u.Interrupt.MinimumVector >= 9 &&
            Alternatives[ix].u.Interrupt.MaximumVector <= 9)
        {
            IsFound = FALSE;
            break;
        }

        if (Alternatives[ix].u.Interrupt.MinimumVector >= 2 &&
            Alternatives[ix].u.Interrupt.MaximumVector <= 2)
        {
            IsFound = TRUE;
        }
    }

    if (IsFound)
    {
        DPRINT("HalacpiIrqTranslateResourcesIsa: Level 2, Vector 2\n");

        Target->u.Interrupt.Level = 2;
        Target->u.Interrupt.Vector = 2;
        return STATUS_SUCCESS;
    }

    DPRINT("HalacpiIrqTranslateResourcesIsa: Level %X, Vector %X\n",
           Target->u.Interrupt.Level, Target->u.Interrupt.Vector);

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI 
HalacpiIrqTranslateResourceRequirementsIsa(
    _Inout_opt_ PVOID Context,
    _In_ PIO_RESOURCE_DESCRIPTOR Source,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject,
    _Out_ PULONG TargetCount,
    _Out_ PIO_RESOURCE_DESCRIPTOR* Target)
{
    PIO_RESOURCE_DESCRIPTOR TempIoDesc;
    PIO_RESOURCE_DESCRIPTOR NewIoDesc;
    ULONG IoDescCount;
    ULONG VectorMin;
    ULONG VectorMax;
    ULONG VectorCount;
    ULONG MinimumVector;
    ULONG CurrentVector;
    ULONG Size;
    ULONG jx;
    ULONG ix;
    USHORT SciVector;

    VectorMin = Source->u.Interrupt.MinimumVector;
    VectorMax = Source->u.Interrupt.MaximumVector;
    VectorCount = (VectorMax - VectorMin);

    DPRINT("HalacpiIrqTranslateResourceRequirementsIsa: Min %X, Max %X\n", VectorMin, VectorMax);

    PAGED_CODE();
    ASSERT(Source->Type == CmResourceTypeInterrupt);

    Size = ((VectorCount + 3) * sizeof(IO_RESOURCE_DESCRIPTOR));

    TempIoDesc = ExAllocatePoolWithTag(PagedPool, Size, ' laH');
    if (!TempIoDesc)
    {
        DPRINT1("HalacpiIrqTranslateResourceRequirementsIsa: TempIoDesc is NULL\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(TempIoDesc, Size);

    ix = 0;

    if (VectorMin > 2 || VectorMax < 2)
    {
        RtlCopyMemory(&TempIoDesc[ix], Source, sizeof(IO_RESOURCE_DESCRIPTOR));
        ix++;
    }
    else
    {
        if (VectorMin < 2)
        {
            RtlCopyMemory(&TempIoDesc[ix], Source, sizeof(IO_RESOURCE_DESCRIPTOR));
            TempIoDesc->u.Interrupt.MinimumVector = VectorMin;
            TempIoDesc->u.Interrupt.MaximumVector = 1;
            ix++;
        }
        if (VectorMax > 2)
        {
            RtlCopyMemory(&TempIoDesc[ix], Source, sizeof(IO_RESOURCE_DESCRIPTOR));
            TempIoDesc[ix].u.Interrupt.MinimumVector = 3;
            TempIoDesc[ix].u.Interrupt.MaximumVector = VectorMax;
            ix++;
        }
        if (VectorMin > 9 || VectorMax < 9)
        {
            RtlCopyMemory(&TempIoDesc[ix++], Source, sizeof(IO_RESOURCE_DESCRIPTOR));
            TempIoDesc[ix].u.Interrupt.MinimumVector = 9;
            TempIoDesc[ix].u.Interrupt.MaximumVector = 9;
            ix++;
        }
    }

    IoDescCount = 0;
    SciVector = HalpFixedAcpiDescTable.sci_int_vector;

    for (jx = 0; jx < ix; jx++)
    {
        VectorMin = TempIoDesc[jx].u.Interrupt.MinimumVector;
        VectorMax = TempIoDesc[jx].u.Interrupt.MaximumVector;

        if (VectorMax >= 0x10) // PIC max
        {
            DPRINT1("HalacpiIrqTranslateResourceRequirementsIsa: STATUS_UNSUCCESSFUL\n");
            ExFreePoolWithTag(TempIoDesc, ' laH');
            return STATUS_UNSUCCESSFUL;
        }

        if (VectorMin >= 0x10)
        {
            DPRINT1("HalacpiIrqTranslateResourceRequirementsIsa: STATUS_UNSUCCESSFUL\n");
            ExFreePoolWithTag(TempIoDesc, ' laH');
            return STATUS_UNSUCCESSFUL;
        }

        if (VectorMin > SciVector || VectorMax < SciVector)
            continue;

        if (VectorMin < SciVector)
        {
            TempIoDesc[ix].u.Interrupt.MinimumVector = VectorMin;
            TempIoDesc[ix].u.Interrupt.MaximumVector = (SciVector - 1);
            ix++;
        }

        if (VectorMax > SciVector)
        {
            TempIoDesc[ix].u.Interrupt.MinimumVector = (SciVector + 1);
            TempIoDesc[ix].u.Interrupt.MaximumVector = VectorMax;
            ix++;
        }

        RtlMoveMemory(&TempIoDesc[jx], &TempIoDesc[jx+1], ((ix - jx) * sizeof(IO_RESOURCE_DESCRIPTOR)));

        ix--;
    }

    NewIoDesc = ExAllocatePoolWithTag(PagedPool, Size, ' laH');
    if (!NewIoDesc)
    {
        DPRINT1("HalacpiIrqTranslateResourceRequirementsIsa: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(TempIoDesc, ' laH');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewIoDesc, Size);

    for (jx = 0; jx < ix; jx++)
    {
        CurrentVector = TempIoDesc[jx].u.Interrupt.MinimumVector;
        VectorMax = TempIoDesc[jx].u.Interrupt.MaximumVector;

        do
        {
            MinimumVector = CurrentVector;
            while (CurrentVector < VectorMax)
            {
                if ((HalpPicVectorRedirect[CurrentVector] + 1) !=
                     HalpPicVectorRedirect[CurrentVector + 1])
                {
                    break;
                }

                CurrentVector++;
            }

            RtlCopyMemory(&NewIoDesc[IoDescCount], Source, sizeof(IO_RESOURCE_DESCRIPTOR));

            NewIoDesc[IoDescCount].u.Interrupt.MinimumVector = HalpPicVectorRedirect[MinimumVector];
            NewIoDesc[IoDescCount].u.Interrupt.MaximumVector = HalpPicVectorRedirect[CurrentVector];

            ASSERT(NewIoDesc[IoDescCount].u.Interrupt.MinimumVector <=
                   NewIoDesc[IoDescCount].u.Interrupt.MaximumVector);

            IoDescCount++;
        }
        while (CurrentVector != VectorMax);
    }

    *TargetCount = IoDescCount;

    if (IoDescCount)
        *Target = NewIoDesc;
    else
        ExFreePoolWithTag(NewIoDesc, ' laH');

    ExFreePoolWithTag(TempIoDesc, ' laH');
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalacpiGetInterruptTranslator(
    _In_ INTERFACE_TYPE ParentInterfaceType,
    _In_ ULONG ParentBusNumber,
    _In_ INTERFACE_TYPE BridgeInterfaceType,
    _In_ USHORT Size,
    _In_ USHORT Version,
    _Out_ PTRANSLATOR_INTERFACE Translator,
    _Out_ PULONG BridgeBusNumber)
{
    PAGED_CODE();

    ASSERT(Version == 0);
    ASSERT(Size >= sizeof(TRANSLATOR_INTERFACE));

    if (BridgeInterfaceType != -1 &&
        BridgeInterfaceType != 1 &&
        BridgeInterfaceType != 2)
    {
        DPRINT1("HalacpiGetInterruptTranslator: STATUS_NOT_IMPLEMENTED. BridgeInterfaceType %X\n", BridgeInterfaceType);
        return STATUS_NOT_IMPLEMENTED;
    }

    RtlZeroMemory(Translator, sizeof(TRANSLATOR_INTERFACE));

    Translator->Size = sizeof(TRANSLATOR_INTERFACE);
    Translator->Version = 0;

    Translator->InterfaceReference = HalTranslatorDereference;
    Translator->InterfaceDereference = HalTranslatorDereference;

    Translator->TranslateResources = HalacpiIrqTranslateResourcesIsa;
    Translator->TranslateResourceRequirements = HalacpiIrqTranslateResourceRequirementsIsa;

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpAssignSlotResources(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING DriverClassName,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Inout_ PCM_RESOURCE_LIST* AllocatedResources)
{
    BUS_HANDLER BusHandler;

    DPRINT("HalpAssignSlotResources: BusType %X, BusNumber %X, SlotNumber %X\n", BusType, BusNumber, SlotNumber);
    PAGED_CODE();

    /* Only PCI is supported */
    if (BusType != PCIBus)
        return STATUS_NOT_IMPLEMENTED;

    /* Setup fake PCI Bus handler */
    RtlCopyMemory(&BusHandler, &HalpFakePciBusHandler, sizeof(BUS_HANDLER));
    BusHandler.BusNumber = BusNumber;

    /* Call the PCI function */
    return HalpAssignPCISlotResources(&BusHandler,
                                      &BusHandler,
                                      RegistryPath,
                                      DriverClassName,
                                      DriverObject,
                                      DeviceObject,
                                      SlotNumber,
                                      AllocatedResources);
}

BOOLEAN
NTAPI
HalpFindBusAddressTranslation(
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ OUT PULONG AddressSpace,
    _Out_ PPHYSICAL_ADDRESS TranslatedAddress,
    _In_ OUT PULONG_PTR Context,
    _In_ BOOLEAN NextBus)
{
    /* Make sure we have a context */
    if (!Context)
        return FALSE;

    /* If we have data in the context, then this shouldn't be a new lookup */
    if (*Context && NextBus)
        return FALSE;

    /* Return bus data */
    TranslatedAddress->QuadPart = BusAddress.QuadPart;

    /* Set context value and return success */
    *Context = 1;
    return TRUE;
}

BOOLEAN
NTAPI
HalpTranslateBusAddress(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG BusNumber,
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ OUT PULONG AddressSpace,
    _Out_ PPHYSICAL_ADDRESS TranslatedAddress)
{
    /* Translation is easy */
    TranslatedAddress->QuadPart = BusAddress.QuadPart;
    return TRUE;
}

/* PUBLIC FUNCTIONS **********************************************************/

ULONG
NTAPI
HalGetInterruptVector(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG BusNumber,
    _In_ ULONG BusInterruptLevel,
    _In_ ULONG BusInterruptVector,
    _Out_ PKIRQL OutIrql,
    _Out_ PKAFFINITY OutAffinity)
{
    BUS_HANDLER BusHandler;
    ULONG SystemVector;
    ULONG Vector;
    ULONG Level;

    if (InterfaceType == Isa)
    {
        if (BusInterruptVector >= HAL_PIC_VECTORS)
        {
            DPRINT1("HalGetInterruptVector: BusInterruptVector %X\n", BusInterruptVector);
            ASSERT(BusInterruptVector < HAL_PIC_VECTORS); // DbgBreakPoint();
        }

        Vector = HalpPicVectorRedirect[BusInterruptVector];
        Level = HalpPicVectorRedirect[BusInterruptLevel];
    }
    else
    {
        Vector = BusInterruptVector;
        Level = BusInterruptLevel;
    }

    RtlCopyMemory(&BusHandler, &HalpFakePciBusHandler, sizeof(BusHandler));

    BusHandler.BusNumber = BusNumber;
    BusHandler.InterfaceType = InterfaceType;
    BusHandler.ParentHandler = &BusHandler;

    SystemVector = HalpGetSystemInterruptVector(&BusHandler,
                                                &BusHandler,
                                                Level,
                                                Vector,
                                                OutIrql,
                                                OutAffinity);
    return SystemVector;
}

BOOLEAN
NTAPI
HalTranslateBusAddress(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG BusNumber,
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ OUT PULONG AddressSpace,
    _Out_ PPHYSICAL_ADDRESS TranslatedAddress)
{
    /* Look as the bus type */
    if (InterfaceType == PCIBus)
    {
        /* Call the PCI registered function */
        return HalPciTranslateBusAddress(PCIBus,
                                         BusNumber,
                                         BusAddress,
                                         AddressSpace,
                                         TranslatedAddress);
    }
    else
    {
        /* Translation is easy */
        TranslatedAddress->QuadPart = BusAddress.QuadPart;
        return TRUE;
    }
}

ULONG
NTAPI
HalGetBusDataByOffset(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    BUS_HANDLER BusHandler;

    /* Look as the bus type */
    if (BusDataType == Cmos)
        return HalpGetCmosData(0, SlotNumber, Buffer, Length);

    if (BusDataType == EisaConfiguration)
    {
        /* FIXME: TODO */
        ASSERT(FALSE);
        return 0;
    }

    if (BusDataType != PCIConfiguration)
        /* Invalid bus */
        return 0;

    if (!HalpPCIConfigInitialized)
        /* Invalid bus */
        return 0;

    if ((BusNumber < HalpMinPciBus) || (BusNumber > HalpMaxPciBus))
        /* Invalid bus */
        return 0;


    /* Setup fake PCI Bus handler */
    RtlCopyMemory(&BusHandler, &HalpFakePciBusHandler, sizeof(BUS_HANDLER));
    BusHandler.BusNumber = BusNumber;

    /* Call PCI function */
    return HalpGetPCIData(&BusHandler, &BusHandler, SlotNumber, Buffer, Offset, Length);
}

ULONG
NTAPI
HalGetBusData(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Length)
{
    /* Call the extended function */
    return HalGetBusDataByOffset(BusDataType,
                                 BusNumber,
                                 SlotNumber,
                                 Buffer,
                                 0,
                                 Length);
}

ULONG
NTAPI
HalSetBusDataByOffset(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    BUS_HANDLER BusHandler;

    /* Look as the bus type */
    if (BusDataType == Cmos)
        return HalpSetCmosData(0, SlotNumber, Buffer, Length);

    if (BusDataType != PCIConfiguration)
        return 0;

    if (!HalpPCIConfigInitialized)
        return 0;

    /* Setup fake PCI Bus handler */
    RtlCopyMemory(&BusHandler, &HalpFakePciBusHandler, sizeof(BUS_HANDLER));
    BusHandler.BusNumber = BusNumber;

    /* Call PCI function */
    return HalpSetPCIData(&BusHandler, &BusHandler, SlotNumber, Buffer, Offset, Length);
}

ULONG
NTAPI
HalSetBusData(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Length)
{
    /* Call the extended function */
    return HalSetBusDataByOffset(BusDataType,
                                 BusNumber,
                                 SlotNumber,
                                 Buffer,
                                 0,
                                 Length);
}

NTSTATUS
NTAPI
HalAdjustResourceList(
    _Inout_ PIO_RESOURCE_REQUIREMENTS_LIST* pRequirementsList)
{
    /* Deprecated, return success */
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalAssignSlotResources(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING DriverClassName,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Inout_ PCM_RESOURCE_LIST* AllocatedResources)
{
    /* Check the bus type */
    if (BusType != PCIBus)
    {
        /* Call our internal handler */
        DPRINT("HalAssignSlotResources: BusType %X, BusNumber %X, SlotNumber %X\n", BusType, BusNumber, SlotNumber);

        return HalpAssignSlotResources(RegistryPath,
                                       DriverClassName,
                                       DriverObject,
                                       DeviceObject,
                                       BusType,
                                       BusNumber,
                                       SlotNumber,
                                       AllocatedResources);
    }
    else
    {
        /* Call the PCI registered function */
        DPRINT("HalAssignSlotResources: BusType %X, BusNumber %X, SlotNumber %X\n", BusType, BusNumber, SlotNumber);

        return HalPciAssignSlotResources(RegistryPath,
                                         DriverClassName,
                                         DriverObject,
                                         DeviceObject,
                                         PCIBus,
                                         BusNumber,
                                         SlotNumber,
                                         AllocatedResources);
    }
}

/* EOF */
