/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/ar_memiono.c
 * PURPOSE:         Memory and I/O Port Resource Arbitration
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE ArbiterInterfaceMemory =
{
    &GUID_ARBITER_INTERFACE_STANDARD,
    sizeof(ARBITER_INTERFACE),
    0,
    0,
    PCI_INTERFACE_FDO,
    0,
    PciArb_Memory,
    armem_Constructor,
    armem_Initializer
};

PCI_INTERFACE ArbiterInterfaceIo =
{
    &GUID_ARBITER_INTERFACE_STANDARD,
    sizeof(ARBITER_INTERFACE),
    0,
    0,
    PCI_INTERFACE_FDO,
    0,
    PciArb_Io,
    ario_Constructor,
    ario_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
armemio_UnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("armemio_UnpackRequirement: %p\n", IoDescriptor);
    PAGED_CODE();

    ASSERT(IoDescriptor);
    ASSERT((IoDescriptor->Type == CmResourceTypePort) || (IoDescriptor->Type == CmResourceTypeMemory));

    *OutMinimumAddress = IoDescriptor->u.Memory.MinimumAddress.QuadPart;
    *OutMaximumAddress = IoDescriptor->u.Memory.MaximumAddress.QuadPart;

    *OutLength = IoDescriptor->u.Memory.Length;

    *OutAlignment = IoDescriptor->u.Memory.Alignment;
    if (!IoDescriptor->u.Memory.Alignment)
        *OutAlignment = 1;

    if (IoDescriptor->Type != CmResourceTypeMemory)
        return Status;

    if (!(IoDescriptor->Flags & 0x10))
        return Status;

    if (IoDescriptor->u.Memory.MaximumAddress.QuadPart <= 0xFFFFFF)
        return Status;

    if (IoDescriptor->u.Memory.MinimumAddress.QuadPart <= 0xFFFFFF)
    {
          *OutMaximumAddress = 0xFFFFFF;
          return Status;
    }

    DPRINT1("armemio_UnpackRequirement: 24 bit decode specified but both min and max are greater than 0xFFFFFF, most probably due to broken INF!\n");

    ASSERT(IoDescriptor->u.Memory.MinimumAddress.QuadPart <= 0xFFFFFF);

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
armemio_PackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ ULONGLONG Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
armemio_UnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG Start,
    _Out_ PULONG OutLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

LONG
NTAPI
armemio_ScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

NTSTATUS
NTAPI
PciExcludeRangesFromWindow(
    _In_ ULONGLONG Start,
    _In_ ULONGLONG End,
    _In_ PRTL_RANGE_LIST RangeList,
    _In_ PRTL_RANGE_LIST ExcludeRangeList)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ario_StartArbiter(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PPCI_ARBITER_INSTANCE PciArbiter;
    PPCI_FDO_EXTENSION FdoExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    PRTL_RANGE_LIST RangeList = NULL;
    ULONGLONG dummyStart;
    ULONG Count;
    NTSTATUS Status;

    DPRINT("ario_StartArbiter: %p\n", Arbiter);

    KeWaitForSingleObject(Arbiter->MutexEvent, Executive, KernelMode, FALSE, NULL);

    FdoExtension = Arbiter->BusDeviceObject->DeviceExtension;
    ASSERT((FdoExtension)->ExtensionType == PciFdoExtensionType);

    if (!CmResource)
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    ASSERT(CmResource->Count == 1);

    if (FdoExtension == FdoExtension->BusRootFdoExtension)
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;

    if (PdoExtension->Dependent.type1.IsaBitSet)
    {
        DPRINT1("ario_StartArbiter: FIXME\n");
        ASSERT(FALSE);
    }

    PartialDescriptors = CmResource->List[0].PartialResourceList.PartialDescriptors;
    Count = CmResource->List[0].PartialResourceList.Count;

    for (CmDescriptor = PartialDescriptors;
         CmDescriptor < &PartialDescriptors[Count];
         CmDescriptor++)
    {
        if (CmDescriptor->Type != 1)
            continue;

        if (RangeList)
        {
            Status = PciExcludeRangesFromWindow(CmDescriptor->u.Port.Start.QuadPart,
                                                (CmDescriptor->u.Port.Length + CmDescriptor->u.Port.Start.QuadPart - 1),
                                                Arbiter->Allocation,
                                                RangeList);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ario_StartArbiter: Status %X\n", Status);
                return Status;
            }
        }

        PciArbiter = (PVOID)PciFindNextSecondaryExtension(FdoExtension->ParentFdoExtension->BusRootFdoExtension->
                                                          SecondaryExtension.Next, PciArb_Io);
        if (!PciArbiter)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        KeWaitForSingleObject(PciArbiter->CommonInstance.MutexEvent, Executive, KernelMode, FALSE, NULL);

        PciExcludeRangesFromWindow(CmDescriptor->u.Port.Start.QuadPart,
                                   (CmDescriptor->u.Port.Start.QuadPart + CmDescriptor->u.Port.Length - 1),
                                   Arbiter->Allocation,
                                   PciArbiter->CommonInstance.Allocation);

        KeSetEvent(PciArbiter->CommonInstance.MutexEvent, 0, FALSE);

        Status = RtlFindRange(Arbiter->Allocation, 0, 0xFFFFFFFFFFFFFFFF, 4, 4, 0, 0, 0, 0, &dummyStart);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ario_StartArbiter: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        goto Exit;
    }

Exit:

    KeSetEvent(Arbiter->MutexEvent, 0, FALSE);

    DPRINT("ario_StartArbiter: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
ario_PreprocessEntry(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
NTAPI
ario_GetNextAllocationRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
ario_FindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
ario_AddAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ario_BacktrackAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
}

/*  Not correct yet, FIXME! */
NTSTATUS
NTAPI
ario_OverrideConflict(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PVOID Param2)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ario_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    DPRINT("ario_Initializer: %p\n", Instance);

    PAGED_CODE();
    ASSERT(!(Instance->BusFdoExtension->BrokenVideoHackApplied));

    RtlZeroMemory(&Instance->CommonInstance, sizeof(Instance->CommonInstance));

    Instance->CommonInstance.UnpackRequirement = armemio_UnpackRequirement;
    Instance->CommonInstance.PackResource = armemio_PackResource;
    Instance->CommonInstance.UnpackResource = armemio_UnpackResource;
    Instance->CommonInstance.ScoreRequirement = armemio_ScoreRequirement;
    Instance->CommonInstance.StartArbiter = ario_StartArbiter;
    Instance->CommonInstance.PreprocessEntry = ario_PreprocessEntry;
    Instance->CommonInstance.GetNextAllocationRange = ario_GetNextAllocationRange;
    Instance->CommonInstance.FindSuitableRange = ario_FindSuitableRange;
    Instance->CommonInstance.AddAllocation = ario_AddAllocation;
    Instance->CommonInstance.BacktrackAllocation = ario_BacktrackAllocation;
    Instance->CommonInstance.OverrideConflict = ario_OverrideConflict;

    return ArbInitializeArbiterInstance(&Instance->CommonInstance,
                                        Instance->BusFdoExtension->FunctionalDeviceObject,
                                        CmResourceTypePort,
                                        Instance->InstanceName,
                                        L"Pci",
                                        NULL);
}

NTSTATUS
NTAPI
ario_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID PciInterface,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PARBITER_INTERFACE ArbInterface = (PVOID)Interface;
    PPCI_FDO_EXTENSION FdoExtension = DeviceExtension;

    DPRINT("ario_Constructor: %p\n", Interface);
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypePort)
    {
        /* Not the right interface */
        DPRINT1("ario_Constructor: STATUS_INVALID_PARAMETER_5\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    if (!FdoExtension->ArbitersInitialized)
    {
        DPRINT1("ario_Constructor: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    ArbInterface->Version = 0;
    ArbInterface->Flags = 0;
    ArbInterface->Size = sizeof(ARBITER_INTERFACE);
    ArbInterface->InterfaceReference = PciReferenceArbiter;
    ArbInterface->InterfaceDereference = PciDereferenceArbiter;
    ArbInterface->ArbiterHandler = ArbArbiterHandler;

    return PciArbiterInitializeInterface(DeviceExtension, PciArb_Io, ArbInterface);
}

VOID
NTAPI
ario_ApplyBrokenVideoHack(IN PPCI_FDO_EXTENSION FdoExtension)
{
    PPCI_ARBITER_INSTANCE PciArbiter;
    //PARBITER_INSTANCE CommonInstance;
    //NTSTATUS Status;

    /* Only valid for root FDOs who are being applied the hack for the first time */
    ASSERT(!FdoExtension->BrokenVideoHackApplied);
    ASSERT(PCI_IS_ROOT_FDO(FdoExtension));

    /* Find the I/O arbiter */
    PciArbiter = (PVOID)PciFindNextSecondaryExtension(FdoExtension->
                                                      SecondaryExtension.Next,
                                                      PciArb_Io);
    ASSERT(PciArbiter);
#if 0 // when arb exist
    /* Get the Arb instance */
    CommonInstance = &PciArbiter->CommonInstance;

    /* Free the two lists, enabling full VGA access */
    ArbFreeOrderingList(&CommonInstance->OrderingList);
    ArbFreeOrderingList(&CommonInstance->ReservedList);

    /* Build the ordering for broken video PCI access */
    Status = ArbBuildAssignmentOrdering(CommonInstance,
                                        L"Pci",
                                        L"BrokenVideo",
                                        NULL);
    ASSERT(NT_SUCCESS(Status));
#else
    //Status = STATUS_SUCCESS;
    UNIMPLEMENTED_DBGBREAK();
    while (TRUE);
#endif
    /* Now the hack has been applied */
    FdoExtension->BrokenVideoHackApplied = TRUE;
}

NTSTATUS
NTAPI
armem_StartArbiter(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PPCI_ARB_MEM_EXTENTION ArbExtension;
    PPCI_FDO_EXTENSION FdoExtension;
    PARBITER_ORDERING Orderings;
    ULONGLONG Start;
    ULONGLONG End;
    ULONG Count;
    NTSTATUS Status;

    DPRINT("armem_StartArbiter: %p\n", Arbiter);
    PAGED_CODE();

    ArbExtension = Arbiter->Extension;

    if (!ArbExtension->IsStarted)
    {
        ArbExtension->ArbiterOrderingList = Arbiter->OrderingList;
        RtlZeroMemory(&Arbiter->OrderingList, sizeof(Arbiter->OrderingList));
    }
    else if (ArbExtension->IsPrefetchable)
    {
        ArbFreeOrderingList(&ArbExtension->PrefetchOrderingList);
        ArbFreeOrderingList(&ArbExtension->OrderingList);
    }

    ArbExtension->IsPrefetchable = FALSE;
    ArbExtension->Prefetches = 0;

    if (CmResource)
    {
        ASSERT(CmResource->Count == 1);

        PartialDescriptors = CmResource->List[0].PartialResourceList.PartialDescriptors;
        Count = CmResource->List[0].PartialResourceList.Count;

        for (CmDescriptor = PartialDescriptors;
             CmDescriptor < &PartialDescriptors[Count];
             CmDescriptor++)
        {
            if (CmDescriptor->Type == CmResourceTypeMemory &&
                (CmDescriptor->Flags & CM_RESOURCE_MEMORY_PREFETCHABLE))
            {
                ArbExtension->IsPrefetchable = TRUE;
                break;
            }
        }
    }

    if (PciSystemWideHackFlags & 1)
    {
        FdoExtension = Arbiter->BusDeviceObject->DeviceExtension;
        ASSERT((FdoExtension)->ExtensionType == PciFdoExtensionType);

        if (FdoExtension == FdoExtension->BusRootFdoExtension)
            ArbExtension->IsPrefetchable = FALSE;
    }

    if (!ArbExtension->IsPrefetchable)
    {
        Arbiter->OrderingList = ArbExtension->ArbiterOrderingList;
        return STATUS_SUCCESS;
    }

    Status = ArbInitializeOrderingList(&ArbExtension->PrefetchOrderingList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("armem_StartArbiter: Status %X\n", Status);
        return Status;
    }

    Status = ArbCopyOrderingList(&ArbExtension->OrderingList, &ArbExtension->ArbiterOrderingList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("armem_StartArbiter: Status %X\n", Status);
        return Status;
    }

    Status = ArbAddOrdering(&ArbExtension->OrderingList, 0, 0xFFFFFFFFFFFFFFFF);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("armem_StartArbiter: Status %X\n", Status);
        return Status;
    }

    for (CmDescriptor = CmResource->List[0].PartialResourceList.PartialDescriptors;
         CmDescriptor < (CmResource->List[0].PartialResourceList.PartialDescriptors + CmResource->List[0].PartialResourceList.Count);
         CmDescriptor++)
    {
        if (CmDescriptor->Type == CmResourceTypeMemory &&
            (CmDescriptor->Flags & CM_RESOURCE_MEMORY_PREFETCHABLE))
        {
            ArbExtension->Prefetches++;

            Start = CmDescriptor->u.Memory.Start.QuadPart,
            End = (CmDescriptor->u.Memory.Start.QuadPart + CmDescriptor->u.Memory.Length - 1);

            Status = ArbAddOrdering(&ArbExtension->PrefetchOrderingList, Start, End);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("armem_StartArbiter: Status %X\n", Status);
                return Status;
            }

            Status = ArbPruneOrdering(&ArbExtension->OrderingList, Start, End);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("armem_StartArbiter: Status %X\n", Status);
                return Status;
            }

            DPRINT("armem_StartArbiter: Processed prefetchable range %I64X-%I64X\n", Start, End);
        }
    }

    for (Orderings = Arbiter->ReservedList.Orderings;
         Orderings < (Arbiter->ReservedList.Orderings + Arbiter->ReservedList.Count);
         Orderings++)
    {
        Status = ArbPruneOrdering(&ArbExtension->PrefetchOrderingList, Orderings->Start, Orderings->End);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("armem_StartArbiter: Status %X\n", Status);
            return Status;
        }
    }

    for (Orderings = ArbExtension->OrderingList.Orderings;
         Orderings < (ArbExtension->OrderingList.Orderings + ArbExtension->OrderingList.Count);
         Orderings++)
    {
        Status = ArbAddOrdering(&ArbExtension->PrefetchOrderingList, Orderings->Start, Orderings->End);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("armem_StartArbiter: Status %X\n", Status);
            return Status;
        }
    }

    ArbExtension->IsStarted = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
armem_PreprocessEntry(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
NTAPI
armem_GetNextAllocationRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
armem_FindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS
NTAPI
armem_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    DPRINT("armem_Initializer: %p\n", Instance);

    PAGED_CODE();

    RtlZeroMemory(&Instance->CommonInstance, sizeof(Instance->CommonInstance));

    Instance->CommonInstance.UnpackRequirement = armemio_UnpackRequirement;
    Instance->CommonInstance.PackResource = armemio_PackResource;
    Instance->CommonInstance.UnpackResource = armemio_UnpackResource;
    Instance->CommonInstance.ScoreRequirement = armemio_ScoreRequirement;
    Instance->CommonInstance.StartArbiter = armem_StartArbiter;
    Instance->CommonInstance.PreprocessEntry = armem_PreprocessEntry;
    Instance->CommonInstance.GetNextAllocationRange = armem_GetNextAllocationRange;
    Instance->CommonInstance.FindSuitableRange = armem_FindSuitableRange;

    Instance->CommonInstance.Extension = ExAllocatePoolWithTag(PagedPool, sizeof(PCI_ARB_MEM_EXTENTION), 'BicP'); // POOL_TYPE 0x101
    if (!Instance->CommonInstance.Extension)
    {
        DPRINT1("armem_Initializer: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Instance->CommonInstance.Extension, sizeof(PCI_ARB_MEM_EXTENTION));

    return ArbInitializeArbiterInstance(&Instance->CommonInstance,
                                        Instance->BusFdoExtension->FunctionalDeviceObject,
                                        CmResourceTypeMemory,
                                        Instance->InstanceName,
                                        L"Pci",
                                        NULL);
}

NTSTATUS
NTAPI
armem_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID PciInterface,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PARBITER_INTERFACE ArbInterface = (PVOID)Interface;
    PPCI_FDO_EXTENSION FdoExtension = DeviceExtension;

    DPRINT("armem_Constructor: %p\n", Interface);
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypeMemory)
    {
        /* Not the right interface */
        DPRINT1("armem_Constructor: STATUS_INVALID_PARAMETER_5\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    if (!FdoExtension->ArbitersInitialized)
    {
        DPRINT1("armem_Constructor: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    ArbInterface->Version = 0;
    ArbInterface->Flags = 0;
    ArbInterface->Size = sizeof(ARBITER_INTERFACE);
    ArbInterface->InterfaceReference = PciReferenceArbiter;
    ArbInterface->InterfaceDereference = PciDereferenceArbiter;
    ArbInterface->ArbiterHandler = ArbArbiterHandler;

    return PciArbiterInitializeInterface(DeviceExtension, PciArb_Memory, ArbInterface);
}

/* EOF */
