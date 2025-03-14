/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/arb_comn.c
 * PURPOSE:         Common Arbitration Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
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
PciReferenceArbiter(
    _In_ PVOID Context)
{
    PPCI_ARBITER_INSTANCE Instance;

    DPRINT("PciReferenceArbiter: %p\n", Context);

    Instance = CONTAINING_RECORD(Context, PCI_ARBITER_INSTANCE, CommonInstance);
    InterlockedIncrement(&Instance->CommonInstance.ReferenceCount);
}

VOID
NTAPI
PciDereferenceArbiter(
    _In_ PVOID Context)
{
    PPCI_ARBITER_INSTANCE Instance;

    DPRINT("PciDereferenceArbiter: %p\n", Context);

    Instance = CONTAINING_RECORD(Context, PCI_ARBITER_INSTANCE, CommonInstance);
    InterlockedDecrement(&Instance->CommonInstance.ReferenceCount);
}

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
    NTSTATUS Status = STATUS_SUCCESS;

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
                DPRINT("PciInitializeArbiters: PCI Not creating arbiters for subtractive bus %X\n", PdoExtension->Dependent.type1.SubtractiveDecode);
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
            DPRINT("PciInitializeArbiters: (%p) no '%s' arbiter\n", FdoExtension, PciArbiterNames[ArbiterType - PciArb_Io]);
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
        DPRINT("PciInitializeArbiters: %p, '%S', %p\n", FdoExtension, ArbiterInterface->CommonInstance.Name, ArbiterInterface);

        Status = STATUS_SUCCESS;
    }

    /* Return to caller */
    return Status;
}

VOID
NTAPI
PcipInitializePartialListContext(
    _In_ PPCI_PARTIAL_LIST_CONTEXT Context,
    _In_ PCM_PARTIAL_RESOURCE_LIST PartialResourceList,
    _In_ CM_RESOURCE_TYPE DesiredType)
{
    ASSERT(DesiredType != CmResourceTypeNull);

    Context->PartialList = PartialResourceList;
    Context->DesiredType = DesiredType;
    Context->Count = PartialResourceList->Count;
    Context->PointToNextDescriptor = PartialResourceList->PartialDescriptors;
    Context->CurrentDescriptor.Type = 0;

    DPRINT("PcipInitializePartialListContext: Count %X, DesiredType %X\n", Context->Count, DesiredType);
}

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
PcipGetNextRangeFromList(
    _In_ PPCI_PARTIAL_LIST_CONTEXT Context)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG Start;

    DPRINT("PcipGetNextRangeFromList: Context %p, DesiredType %X\n", Context, Context->DesiredType);

    if (Context->CurrentDescriptor.Type == Context->DesiredType)
    {
        if (Context->CurrentDescriptor.Flags & 4)
            Start = (Context->CurrentDescriptor.u.Generic.Start.LowPart + 0x400);
        else
            Start = (Context->CurrentDescriptor.u.Generic.Start.LowPart + 0x1000);

        if (Start < 0x10000)
        {
            Context->CurrentDescriptor.u.Generic.Start.LowPart = Start;
            return &Context->CurrentDescriptor;
        }

        Context->CurrentDescriptor.Type = CmResourceTypeNull;
    }

    do
    {
        if (!Context->Count)
            return NULL;

        CmDescriptor = Context->PointToNextDescriptor;
        Context->PointToNextDescriptor = PciGetNextCmPartialDescriptor(CmDescriptor);
        Context->Count--;
    }
    while (CmDescriptor->Type != Context->DesiredType);

    if (CmDescriptor->Type == CmResourceTypePort && (CmDescriptor->Flags & 0xC))
        RtlCopyMemory(&Context->CurrentDescriptor, CmDescriptor, sizeof(Context->CurrentDescriptor));

    return CmDescriptor;
}

NTSTATUS
NTAPI
PciRangeListFromResourceList(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG DesiredType,
    _In_ PRTL_RANGE_LIST RangeList)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor = NULL;
    PCM_FULL_RESOURCE_DESCRIPTOR CmFullList;
    PCI_PARTIAL_LIST_CONTEXT Context;
    PPCI_RANGE_LIST InitialPciRanges;
    PPCI_RANGE_LIST CurrentPciRange;
    PPCI_RANGE_LIST LowerPciRange;
    PPCI_RANGE_LIST UpperPciRange;
    PPCI_RANGE_LIST PciRangeList;
    PPCI_RANGE_LIST NextPciRange;
    ULONG Elements = 2;
    ULONG PartialCount;
    ULONG FullCount;
    ULONGLONG Start;
    ULONGLONG End;
    ULONG nx;
    NTSTATUS Status;

    DPRINT("PciRangeListFromResourceList: %p, %X\n", CmResource, DesiredType);

    PAGED_CODE();
    ASSERT((DesiredType == CmResourceTypeMemory) || (DesiredType == CmResourceTypePort));

    if (CmResource)
    {
        FullCount = CmResource->Count;
        CmFullList = CmResource->List;

        while (FullCount--)
        {
            PartialCount = CmFullList->PartialResourceList.Count;
            CmDescriptor = CmFullList->PartialResourceList.PartialDescriptors;

            while (PartialCount--)
            {
                if (CmDescriptor->Type == DesiredType)
                {
                    if (DesiredType == CmResourceTypePort)
                    {
                        if (CmDescriptor->Flags & 4)
                            Elements += 0x3F;
                        else if (CmDescriptor->Flags & 8)
                            Elements += 0xF;
                    }

                    Elements++;
                }

                CmDescriptor = PciGetNextCmPartialDescriptor(CmDescriptor);
            }

            CmFullList = (PCM_FULL_RESOURCE_DESCRIPTOR)CmDescriptor;
        }
    }

    DPRINT("PciRangeListFromResourceList: processing %X elements\n", (Elements - 2));

    if (DesiredType == CmResourceTypeMemory && FdoExtension && !FdoExtension->BaseBus)
        Elements += 3;

    PciRangeList = ExAllocatePoolWithTag(PagedPool, (Elements * sizeof(PCI_RANGE_LIST)), 'BicP'); // POOL_TYPE 0x101
    if (!PciRangeList)
    {
        DPRINT1("PciRangeListFromResourceList: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    nx = 2;
    CurrentPciRange = (PciRangeList + 1);

    PciRangeList[1].Start = 0;
    PciRangeList[1].End = 0;
    PciRangeList[1].Next = PciRangeList;
    PciRangeList[1].Previous = PciRangeList;
    PciRangeList[1].IsActive = FALSE;

    PciRangeList[0].Start = 0xFFFFFFFFFFFFFFFF;
    PciRangeList[0].End = 0xFFFFFFFFFFFFFFFF;
    PciRangeList[0].Next = (PciRangeList + 1);
    PciRangeList[0].Previous = (PciRangeList + 1);
    PciRangeList[0].IsActive = FALSE;

    if (DesiredType == CmResourceTypeMemory && FdoExtension && !FdoExtension->BaseBus)
    {
        PciRangeList[2].Start = 0x70;
        PciRangeList[2].End = 0x70;
        PciRangeList[2].IsActive = 1;
        PciRangeList[2].Next = (PciRangeList + 3);
        PciRangeList[2].Previous = CurrentPciRange;

        PciRangeList[3].Start = 0x400;
        PciRangeList[3].End = 0x4FF;
        PciRangeList[3].IsActive = 1;
        PciRangeList[3].Next = (PciRangeList + 4);
        PciRangeList[3].Previous = (PciRangeList + 2);

        PciRangeList[4].Start = 0xA0000;
        PciRangeList[4].End = 0xBFFFF;
        PciRangeList[4].IsActive = 1;
        PciRangeList[4].Next = PciRangeList;
        PciRangeList[4].Previous = (PciRangeList + 3);

        nx = 5;
        CurrentPciRange->Next = (PciRangeList + 2);

        PciRangeList[0].Previous = (PciRangeList + 4);
        InitialPciRanges = PciRangeList + 1;

        DPRINT("    === PCI added default initial ranges ===\n");

        do
        {
            if (InitialPciRanges->IsActive == 1)
                DPRINT("    %I64X .. %I64X\n", InitialPciRanges->Start, InitialPciRanges->End);

            InitialPciRanges = InitialPciRanges->Next;
        }
        while (InitialPciRanges != CurrentPciRange);

        DPRINT("    === end added default initial ranges ===\n");
    }

    if (CmResource)
    {
        CmFullList = CmResource->List;
        FullCount = CmResource->Count;

        while (FullCount)
        {
            DPRINT("PciRangeListFromResourceList: CmFullList %p, FullCount %X\n", CmFullList, FullCount);

            PcipInitializePartialListContext(&Context, &CmFullList->PartialResourceList, DesiredType);

            while (TRUE)
            {
                CmDescriptor = PcipGetNextRangeFromList(&Context);
                if (!CmDescriptor)
                    break;

                ASSERT(CmDescriptor->Type == DesiredType);

                Start = (ULONGLONG)CmDescriptor->u.Generic.Start.QuadPart;
                End = (Start + CmDescriptor->u.Generic.Length - 1);

                DPRINT("PciRangeListFromResourceList: %p, %I64X, %I64X\n", CmDescriptor, Start, End);

                LowerPciRange = CurrentPciRange;

                while (Start > LowerPciRange->End)
                    LowerPciRange = LowerPciRange->Next;

                while (Start <= LowerPciRange->End)
                {
                    if (Start >= LowerPciRange->Start)
                        break;

                    LowerPciRange = LowerPciRange->Previous;
                }

                if (Start >= LowerPciRange->Start && End <= LowerPciRange->End)
                {
                    DPRINT("    -- (%I64X .. %I64X) swallows (%I64X .. %I64X)\n", LowerPciRange->Start, LowerPciRange->End, Start, End);
                    CurrentPciRange = LowerPciRange;
                    CurrentPciRange->IsActive = TRUE;
                    continue;
                }

                UpperPciRange = LowerPciRange;

                while (End > UpperPciRange->Start)
                {
                    if (End <= UpperPciRange->End)
                        break;

                    UpperPciRange = UpperPciRange->Next;
                }

                CurrentPciRange = &PciRangeList[nx];

                CurrentPciRange->Start = Start;
                CurrentPciRange->End = End;
                CurrentPciRange->IsActive = TRUE;

                nx++;

                DPRINT("    (%I64X .. %I64X) <= (%I64X .. %I64X) <= (%I64X .. %I64X)\n", LowerPciRange->Start, LowerPciRange->End, Start, End, UpperPciRange->Start, UpperPciRange->End);

                CurrentPciRange->Next = UpperPciRange;
                CurrentPciRange->Previous = LowerPciRange;

                UpperPciRange->Previous = CurrentPciRange;
                LowerPciRange->Next = CurrentPciRange;

                if (LowerPciRange->IsActive && Start > 0)
                    Start--;

                if (LowerPciRange->End >= Start)
                {
                    CurrentPciRange->Start = LowerPciRange->Start;
                    CurrentPciRange->Previous = LowerPciRange->Previous;

                    LowerPciRange = LowerPciRange->Previous;
                    LowerPciRange->Next = CurrentPciRange;

                    DPRINT("    -- Overlaps lower, merged to (%I64X .. %I64X)\n", CurrentPciRange->Start, CurrentPciRange->End);
                }

                if (UpperPciRange->IsActive && End < 0xFFFFFFFFFFFFFFFF)
                    End++;

                if (End >= UpperPciRange->Start && CurrentPciRange != UpperPciRange)
                {
                    CurrentPciRange->End = UpperPciRange->End;
                    CurrentPciRange->Next = UpperPciRange->Next;

                    UpperPciRange = UpperPciRange->Next;
                    UpperPciRange->Previous = CurrentPciRange;

                    DPRINT("    -- Overlaps upper, merged to (%I64X .. %I64X)\n", CurrentPciRange->Start, CurrentPciRange->End);
                }
            }

            CmFullList = (PCM_FULL_RESOURCE_DESCRIPTOR)Context.PointToNextDescriptor;

            FullCount--;
            if (!FullCount)
                break;
        }
    }

    while (CurrentPciRange->IsActive)
    {
        LowerPciRange = CurrentPciRange->Previous;

        if (!LowerPciRange->IsActive || LowerPciRange->Start > CurrentPciRange->Start) 
            break;

        CurrentPciRange = LowerPciRange;
    }

    LowerPciRange = CurrentPciRange;

    if (!CurrentPciRange->IsActive)
    {
        DPRINT("    ==== No ranges in results list. ====\n");
    }
    else
    {
        DPRINT("    === ranges ===\n");

        do
        {
            if (CurrentPciRange->IsActive)
            {
                DPRINT("    %I64X .. %I64X\n", CurrentPciRange->Start, CurrentPciRange->End);
            }

            CurrentPciRange = CurrentPciRange->Next;
        }
        while (CurrentPciRange != LowerPciRange);
    }

    if (!CurrentPciRange->IsActive)
    {
        DPRINT("    Adding to RtlRange  %I64X thru %I64X\n", Start, End);                                                         \

        Status = RtlAddRange(RangeList, 0, 0xFFFFFFFFFFFFFFFF, 0, 0, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciRangeListFromResourceList: Status %X\n", Status);
            ASSERT(NT_SUCCESS(Status));
            goto Exit;
        }

        Status = STATUS_SUCCESS;
        goto Exit;
    }

    if (CurrentPciRange->Start)
    {
        DPRINT("    Adding to RtlRange  %I64X thru %I64X\n", Start, End);                                                         \

        Status = RtlAddRange(RangeList, 0, (CurrentPciRange->Start - 1), 0, 0, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            ASSERT(NT_SUCCESS(Status));
            goto Exit;
        }
    }

    do
    {
        NextPciRange = CurrentPciRange->Next;

        if (CurrentPciRange->IsActive)
        {
            Start = (CurrentPciRange->End + 1);
            End = (NextPciRange->Start - 1);

            if (End < Start || NextPciRange == PciRangeList)
                End = 0xFFFFFFFFFFFFFFFF;

            DPRINT("    Adding to RtlRange  %I64X thru %I64X\n", Start, End);  

            Status = RtlAddRange(RangeList, Start, End, 0, 0, NULL, NULL);
            if (!NT_SUCCESS(Status))
            {
                ASSERT(NT_SUCCESS(Status));
                goto Exit;
            }
        }

        CurrentPciRange = NextPciRange;
    }
    while (CurrentPciRange != LowerPciRange);

    Status = STATUS_SUCCESS;

Exit:

    ExFreePoolWithTag(PciRangeList, 'BicP');
    return Status;
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
            DPRINT("PciInitializeArbiterRanges: Skipping arbiter initialization for subtractive bridge FDOX %p\n", FdoExtension);
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

NTSTATUS
NTAPI
PciArbiterInitializeInterface(
    _In_ PVOID DeviceExtension,
    _In_ PCI_SIGNATURE Signature,
    _In_ PARBITER_INTERFACE ArbInterface)
{
    PPCI_FDO_EXTENSION FdoExtension = DeviceExtension;
    PPCI_ARBITER_INSTANCE PciArbiter;
    PPCI_PDO_EXTENSION PdoExtension;

    DPRINT("PciArbiterInitializeInterface: %p\n", DeviceExtension);

    PciArbiter = (PVOID)PciFindNextSecondaryExtension(FdoExtension->SecondaryExtension.Next, Signature);
    if (PciArbiter)
    {
        DPRINT("PciArbiterInitializeInterface: '%S' Arbiter Interface Initialized\n", PciArbiter->CommonInstance.Name);
        ArbInterface->Context = &PciArbiter->CommonInstance;
        return STATUS_SUCCESS;
    }

    if (FdoExtension != FdoExtension->BusRootFdoExtension)
    {
        PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;
        ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);

        if (PdoExtension->Dependent.type1.SubtractiveDecode)
        {
            DPRINT1("PciArbiterInitializeInterface: STATUS_INVALID_PARAMETER_2");
            return STATUS_INVALID_PARAMETER_2;
        }
    }

    DPRINT1("PciArbiterInitializeInterface: STATUS_INVALID_PARAMETER_5");
    ASSERTMSG("PciArbiterInitializeInterface: couldn't locate arbiter for resource.", PciArbiter);

    return STATUS_INVALID_PARAMETER_5;
}

/* EOF */
