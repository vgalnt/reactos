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
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

/*  Not correct yet, FIXME! */
NTSTATUS
NTAPI
ario_StartArbiter(
    _In_ PARBITER_INSTANCE Arbiter)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
ario_Constructor(IN PVOID DeviceExtension,
                 IN PVOID PciInterface,
                 IN PVOID InterfaceData,
                 IN USHORT Version,
                 IN USHORT Size,
                 IN PINTERFACE Interface)
{
    PPCI_FDO_EXTENSION FdoExtension = (PPCI_FDO_EXTENSION)DeviceExtension;
    NTSTATUS Status;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Interface);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypePort)
    {
        /* Arbiter support must have been initialized first */
        if (FdoExtension->ArbitersInitialized)
        {
            /* Not yet implemented */
            UNIMPLEMENTED;
            while (TRUE);
        }
        else
        {
            /* No arbiters for this FDO */
            Status = STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        /* Not the right interface */
        Status = STATUS_INVALID_PARAMETER_5;
    }

    /* Return the status */
    return Status;
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
    UNIMPLEMENTED;
    while (TRUE);
#endif
    /* Now the hack has been applied */
    FdoExtension->BrokenVideoHackApplied = TRUE;
}

NTSTATUS
NTAPI
armem_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);

    /* Not yet implemented */
    UNIMPLEMENTED;
    //while (TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
armem_Constructor(IN PVOID DeviceExtension,
                  IN PVOID PciInterface,
                  IN PVOID InterfaceData,
                  IN USHORT Version,
                  IN USHORT Size,
                  IN PINTERFACE Interface)
{
    PPCI_FDO_EXTENSION FdoExtension = (PPCI_FDO_EXTENSION)DeviceExtension;
    NTSTATUS Status;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Interface);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypeMemory)
    {
        /* Arbiter support must have been initialized first */
        if (FdoExtension->ArbitersInitialized)
        {
            /* Not yet implemented */
            UNIMPLEMENTED;
            while (TRUE);
        }
        else
        {
            /* No arbiters for this FDO */
            Status = STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        /* Not the right interface */
        Status = STATUS_INVALID_PARAMETER_5;
    }

    /* Return the status */
    return Status;
}

/* EOF */
