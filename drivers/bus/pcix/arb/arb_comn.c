/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/arb_comn.c
 * PURPOSE:         Common Arbitration Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCHAR PciArbiterNames[] =
{
    "I/O Port",
    "Memory",
    "Interrupt",
    "Bus Number"
};

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
PciArbiterDestructor(IN PPCI_ARBITER_INSTANCE Arbiter)
{
    UNREFERENCED_PARAMETER(Arbiter);
    /* This function is not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
    while (TRUE);
}

NTSTATUS
NTAPI
PciInitializeArbiters(
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PPCI_ARBITER_INSTANCE ArbiterInterface;
    PPCI_PDO_EXTENSION PdoExtension;
    PPCI_INTERFACE CurrentInterface;
    PPCI_INTERFACE* Interfaces;
    PCI_SIGNATURE ArbiterType;
    NTSTATUS Status;

    DPRINT("PciInitializeArbiters: %p\n", FdoExtension);
    ASSERT_FDO(FdoExtension);

    /* Loop all the arbiters */
    for (ArbiterType = PciArb_Io; ArbiterType <= PciArb_BusNumber; ArbiterType++)
    {
        /* Check if this is the extension for the Root PCI Bus */
        if (!PCI_IS_ROOT_FDO(FdoExtension))
        {
            /* Get the PDO extension */
            PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;
            ASSERT_PDO(PdoExtension);

            /* Skip this bus if it does subtractive decode */
            if (PdoExtension->Dependent.type1.SubtractiveDecode)
            {
                DPRINT1("PciInitializeArbiters: PCI Not creating arbiters for subtractive bus %X\n", PdoExtension->Dependent.type1.SubtractiveDecode);
                continue;
            }
        }

        /* Query all the registered arbiter interfaces */
        for (Interfaces = PciInterfaces; *Interfaces; Interfaces++)
        {
            /* Find the one that matches the arbiter currently being setup */
            CurrentInterface = *Interfaces;
            if (CurrentInterface->Signature == ArbiterType)
                break;
        }

        /* Check if the required arbiter was not found in the list */
        if (!*Interfaces)
        {
            /* Skip this arbiter and try the next one */
            DPRINT1("PciInitializeArbiters: (%p) no '%s' arbiter\n", FdoExtension, PciArbiterNames[ArbiterType - PciArb_Io]);
            continue;
        }

        /* An arbiter was found, allocate an instance for it */
        ArbiterInterface = ExAllocatePoolWithTag(PagedPool, sizeof(PCI_ARBITER_INSTANCE), PCI_POOL_TAG);
        if (!ArbiterInterface)
        {
            DPRINT("PciInitializeArbiters: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Setup the instance */
        ArbiterInterface->BusFdoExtension = FdoExtension;
        ArbiterInterface->Interface = CurrentInterface;

        swprintf(ArbiterInterface->InstanceName, L"PCI %S (b=%02x)", PciArbiterNames[ArbiterType - PciArb_Io], FdoExtension->BaseBus);

        /* Call the interface initializer for it */
        Status = CurrentInterface->Initializer(ArbiterInterface);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciInitializeArbiters: Status %X\n", Status);
            break;
        }

        /* Link it with this FDO */
        PcipLinkSecondaryExtension(&FdoExtension->SecondaryExtension,
                                   &FdoExtension->SecondaryExtLock,
                                   &ArbiterInterface->Header,
                                   ArbiterType,
                                   PciArbiterDestructor);

        /* This arbiter is now initialized, move to the next one */
        DPRINT1("PciInitializeArbiters: %p, '%S', %p\n", FdoExtension, ArbiterInterface->CommonInstance.Name, ArbiterInterface);

        Status = STATUS_SUCCESS;
    }

    /* Return to caller */
    return Status;
}

NTSTATUS
NTAPI
PciRangeListFromResourceList(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG DesiredType,
    _In_ PRTL_RANGE_LIST RangeList)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PciInitializeArbiterRanges(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PPCI_PDO_EXTENSION PdoExtension;
    CM_RESOURCE_TYPE DesiredType;
    PPCI_ARBITER_INSTANCE PciArbiter;
    PCI_SIGNATURE ArbiterType;
    NTSTATUS Status;

    DPRINT("PciInitializeArbiterRanges: %p, %p\n", FdoExtension, CmResource);

    UNREFERENCED_PARAMETER(CmResource);

    /* Arbiters should not already be initialized */
    if (FdoExtension->ArbitersInitialized)
    {
        /* Duplicated start request, fail initialization */
        DPRINT1("PciInitializeArbiterRanges: Warning hot start FDOx %p, resource ranges not checked.\n", FdoExtension);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Check for non-root FDO */
    if (!PCI_IS_ROOT_FDO(FdoExtension))
    {
        /* Grab the PDO */
        PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;
        ASSERT_PDO(PdoExtension);

        /* Check if this is a subtractive bus */
        if (PdoExtension->Dependent.type1.SubtractiveDecode)
        {
            /* There is nothing to do regarding arbitration of resources */
            DPRINT1("PciInitializeArbiterRanges: Skipping arbiter initialization for subtractive bridge FDOX %p\n", FdoExtension);
            return STATUS_SUCCESS;
        }
    }

    /* Loop all arbiters */
    for (ArbiterType = PciArb_Io; ArbiterType <= PciArb_Memory; ArbiterType++)
    {
        /* Pick correct resource type for each arbiter */
        if (ArbiterType == PciArb_Io)
        {
            /* I/O Port */
            DesiredType = CmResourceTypePort;
        }
        else if (ArbiterType == PciArb_Memory)
        {
            /* Device RAM */
            DesiredType = CmResourceTypeMemory;
        }
        else
        {
            /* Ignore anything else */
            continue;
        }

        /* Find an arbiter of this type */
        PciArbiter = (PVOID)PciFindNextSecondaryExtension(&FdoExtension->SecondaryExtension, ArbiterType);
        if (PciArbiter)
        {
            Status = PciRangeListFromResourceList(FdoExtension, CmResource, DesiredType, PciArbiter->CommonInstance.Allocation);
            if (NT_SUCCESS(Status))
            {
                ASSERT(PciArbiter->CommonInstance.StartArbiter);

                Status = PciArbiter->CommonInstance.StartArbiter(&PciArbiter->CommonInstance, CmResource);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("PciInitializeArbiterRanges: Status %X\n", Status);
                    return Status;
                }
            }
        }
        else
        {
            /* The arbiter was not found, this is an error! */
            DPRINT1("PciInitializeArbiterRanges: FDO ext %p '%s' arbiter (REQUIRED) is missing.\n", FdoExtension, PciArbiterNames[ArbiterType - PciArb_Io]);
        }
    }

    /* Arbiters are now initialized */
    FdoExtension->ArbitersInitialized = TRUE;

    return STATUS_SUCCESS;
}

/* EOF */
