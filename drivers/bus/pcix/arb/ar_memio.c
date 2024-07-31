/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/ar_memiono.c
 * PURPOSE:         Memory and I/O Port Resource Arbitration
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
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

ARBITER_ORDERING PciBridgeOrderings[2] =
{
    {0x0000000000010000, 0xFFFFFFFFFFFFFFFF},
    {0x0000000000000000, 0x000000000000FFFF}
};

ARBITER_ORDERING_LIST PciBridgeOrderingList =
{
    0x0002, 0x0002, PciBridgeOrderings
};

extern RTL_RANGE_LIST PciIsaBitExclusionList;
extern RTL_RANGE_LIST PciVgaAndIsaBitExclusionList;

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
    PAGED_CODE();
    DPRINT("armemio_PackResource: %p, %I64X\n", IoDescriptor, Start);

    ASSERT(CmDescriptor);
    ASSERT(IoDescriptor);
    ASSERT((IoDescriptor->Type == CmResourceTypePort) || (IoDescriptor->Type == CmResourceTypeMemory));

    CmDescriptor->Type = IoDescriptor->Type;
    CmDescriptor->Flags = IoDescriptor->Flags;
    CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;

    CmDescriptor->u.Generic.Start.QuadPart = Start;
    CmDescriptor->u.Generic.Length = IoDescriptor->u.Generic.Length;

    return STATUS_SUCCESS;
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
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE Range;
    NTSTATUS Status;

    DPRINT("PciExcludeRangesFromWindow: %I64X-%I64X\n", Start, End);

    RtlGetFirstRange(ExcludeRangeList, &Iterator, &Range);

    while (TRUE)
    {
        if (!Range)
            return STATUS_SUCCESS;

        if (!Range->Owner)
        {
            if ((Start <= Range->Start || Start <= Range->End) &&
                (Start >= Range->Start || End >= Range->Start))
            {
                Status = RtlAddRange(RangeList, Range->Start, Range->End, 0, 1, NULL, NULL);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("PciExcludeRangesFromWindow: (%I64X-%I64X) Status %X\n", Start, End, Status);
                    break;
                }
            }
        }

        RtlGetNextRange(&Iterator, &Range, TRUE);
    }

    ASSERT(NT_SUCCESS(Status));

    return Status;
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
        if (PdoExtension->Dependent.type1.VgaBitSet)
            RangeList = &PciVgaAndIsaBitExclusionList;
        else
            RangeList = &PciIsaBitExclusionList;
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

    Status = STATUS_SUCCESS;

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
    PPCI_PDO_EXTENSION PdoExtension;
    PARBITER_ALTERNATIVE Current;
    PDEVICE_OBJECT DeviceObject;
    INTERFACE_TYPE InterfaceType;
    PCI_DEVICE_TYPES Type;
    ULONGLONG Maximum = 0;
    USHORT Flags;
    BOOLEAN IsNotPciDecode = FALSE;
    BOOLEAN WindowDetected = FALSE;

    DPRINT("ario_PreprocessEntry: %p\n", Arbiter);
    PAGED_CODE();

    if (ArbState->WorkSpace & 1)
        return STATUS_SUCCESS;

    ArbState->WorkSpace |= 1;

    DeviceObject = ArbState->Entry->PhysicalDeviceObject;

    if (DeviceObject->DriverObject == PciDriverObject &&
        ArbState->Entry->RequestSource == 4)
    {
        PdoExtension = DeviceObject->DeviceExtension;
        ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

        if (PdoExtension->LegacyDriver)
            return STATUS_DEVICE_BUSY;
    }

    Current = ArbState->Alternatives;
    while (Current < &ArbState->Alternatives[ArbState->AlternativeCount])
    {
        ASSERT(Current->Descriptor->Type == CmResourceTypePort);
        ASSERT(Current->Descriptor->Flags == ArbState->Alternatives->Descriptor->Flags);

        if (Current->Maximum > Maximum)
            Maximum = Current->Maximum;

        if (Current->Descriptor->Flags & CM_RESOURCE_PORT_WINDOW_DECODE)
        {
            if (Current != ArbState->Alternatives)
                ASSERT(WindowDetected);

            WindowDetected = TRUE;
        }

        if (!(Current->Descriptor->Flags & (CM_RESOURCE_PORT_10_BIT_DECODE |
                                            CM_RESOURCE_PORT_12_BIT_DECODE |
                                            CM_RESOURCE_PORT_16_BIT_DECODE |
                                            CM_RESOURCE_PORT_POSITIVE_DECODE)))
        {
            IsNotPciDecode = TRUE;
        }

        Current++;
    }

    if (!IsNotPciDecode)
    {
        Current = ArbState->Alternatives;
        while (Current < &ArbState->Alternatives[ArbState->AlternativeCount])
        {
            if ((Current->Descriptor->Flags & CM_RESOURCE_PORT_10_BIT_DECODE) && Maximum > 0x3FF)
            {
                Current->Descriptor->Flags &= ~CM_RESOURCE_PORT_10_BIT_DECODE;
                Current->Descriptor->Flags |= CM_RESOURCE_PORT_16_BIT_DECODE;
            }

            Current++;
        }
    }
    else
    {
        ArbState->WorkSpace |= 2;
        InterfaceType = ArbState->Entry->InterfaceType;

        if (InterfaceType == Isa || InterfaceType == PNPISABus)
        {
            if (SharedUserData->AlternativeArchitecture != 1 && Maximum <= 0x3FF)
                Flags = CM_RESOURCE_PORT_10_BIT_DECODE;
        }
        else if (InterfaceType == PCIBus)
        {
            Flags = CM_RESOURCE_PORT_POSITIVE_DECODE;
        }
        else
        {
            Flags = CM_RESOURCE_PORT_16_BIT_DECODE;
        }

        Current = ArbState->Alternatives;
        while (Current < &ArbState->Alternatives[ArbState->AlternativeCount])
        {
            Current->Descriptor->Flags |= Flags;
            Current++;
        }
    }

    if (WindowDetected)
    {
        DeviceObject = ArbState->Entry->PhysicalDeviceObject;
        if (DeviceObject->DriverObject != PciDriverObject)
        {
            ASSERT(ArbState->Entry->PhysicalDeviceObject->DriverObject == PciDriverObject);
            return STATUS_INVALID_PARAMETER;
        }

        PdoExtension = DeviceObject->DeviceExtension;
        if (PdoExtension->ExtensionType != PciPdoExtensionType)
        {
            ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);
            return STATUS_INVALID_PARAMETER;
        }

        Type = PciClassifyDeviceType(DeviceObject->DeviceExtension);
        if (Type != PciTypePciBridge && Type != PciTypeCardbusBridge)
        {
            ASSERT(Type == PciTypePciBridge || Type == PciTypeCardbusBridge);
            return STATUS_INVALID_PARAMETER;
        }

        if (PdoExtension->Dependent.type1.IsaBitSet)
        {
            if (Type == PciTypePciBridge)
                ArbState->WorkSpace |= 4;
            else
                ASSERT(Type == PciTypePciBridge);
        }

        ArbState->WorkSpace |= 8;
    }

    if (ArbState->Alternatives->Descriptor->Flags & CM_RESOURCE_PORT_POSITIVE_DECODE)
        ArbState->RangeAttributes |= 0x20;

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
ario_GetNextAllocationRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    ARBITER_ORDERING_LIST orderingList;
    BOOLEAN Result;

    DPRINT("ario_GetNextAllocationRange: %p\n", Arbiter);

    RtlZeroMemory(&orderingList, sizeof(orderingList));

    if ((ArbState->WorkSpace & 0xC) == 0xC)
    {
        orderingList = Arbiter->OrderingList;
        Arbiter->OrderingList = PciBridgeOrderingList;
    }

    Result = ArbGetNextAllocationRange(Arbiter, ArbState);

    if ((ArbState->WorkSpace & 0xC) != 0xC)
        return Result;

    if (Result && ArbState->CurrentAlternative->Priority > 0x7FFFFFFD)
        Result = FALSE;

    Arbiter->OrderingList = orderingList;

    return Result;
}

BOOLEAN
NTAPI
ario_GetNextAlias(
    _In_ ULONG Flags,
    _In_ ULONGLONG Start,
    _Out_ ULONGLONG* OutNewStart)
{
    ULONGLONG NewStart;

    DPRINT("ario_GetNextAlias: %I64X, %X\n", Start, Flags);
    PAGED_CODE();

    if (Flags & CM_RESOURCE_PORT_10_BIT_DECODE)
    {
        NewStart = (Start + 0x400);
        goto Finish;
    }

    if (Flags & CM_RESOURCE_PORT_12_BIT_DECODE)
    {
        NewStart = (Start + 0x1000);
        goto Finish;
    }

    if (Flags & CM_RESOURCE_PORT_POSITIVE_DECODE)
        return FALSE;

    if (Flags & CM_RESOURCE_PORT_16_BIT_DECODE)
        return FALSE;

    DPRINT("ario_GetNextAlias: FIXME\n");
    ASSERT(FALSE);
    return FALSE;

Finish:

    if (NewStart > 0xFFFF)
        return FALSE;

     *OutNewStart = NewStart;

     return TRUE;
}

BOOLEAN
NTAPI
ario_IsAliasedRangeAvailable(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE ArbState)
{
    ARBITER_ALLOCATION_STATE NewState;
    ULONGLONG Start;
    NTSTATUS Status;
    UCHAR AttributeAvailableMask;
    BOOLEAN Available;
    BOOLEAN Result;

    DPRINT("ario_IsAliasedRangeAvailable: %p\n", Arbiter);
    PAGED_CODE();

    if (ArbState->WorkSpace & 2)
        return TRUE;

    if (ArbState->Entry->RequestSource == ArbiterRequestLegacyReported ||
        ArbState->Entry->RequestSource == ArbiterRequestLegacyAssigned ||
        (ArbState->Entry->Flags & 1))
    {
        AttributeAvailableMask = 0x21;
    }
    else
    {
        AttributeAvailableMask = 0x20;
    }

    Start = ArbState->Start;

    for (Result = ario_GetNextAlias(ArbState->CurrentAlternative->Descriptor->Flags, Start, &Start);
         Result;
         Result = ario_GetNextAlias(ArbState->CurrentAlternative->Descriptor->Flags, Start, &Start))
    {
        Status = RtlIsRangeAvailable(Arbiter->PossibleAllocation,
                                     Start,
                                     (Start + ArbState->CurrentAlternative->Length - 1),
                                     ((ArbState->CurrentAlternative->Flags & 1) | 2),
                                     AttributeAvailableMask,
                                     Arbiter->ConflictCallbackContext,
                                     Arbiter->ConflictCallback,
                                     &Available);

        ASSERT(NT_SUCCESS(Status));

        if (Available)
            continue;

        RtlCopyMemory(&NewState, ArbState, sizeof(NewState));

        NewState.CurrentMinimum = Start;
        NewState.CurrentMaximum = (Start + ArbState->CurrentAlternative->Length - 1);

        if (!Arbiter->OverrideConflict(Arbiter, &NewState))
            return FALSE;
    }
 
    return TRUE;
}

BOOLEAN
NTAPI
ario_FindWindowWithIsaBit(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE ArbState)
{
    ULONGLONG Minimum;
    ULONGLONG Maximum;
    ULONGLONG Start;
    ULONGLONG Offset;
    ULONG RangeFlags = 0;
    ULONG Length;
    ULONG Alignment;
    NTSTATUS Status;
    BOOLEAN Result = FALSE;

    ASSERT((ArbState->Entry->PhysicalDeviceObject)->DriverObject == PciDriverObject);
    ASSERT(PciClassifyDeviceType(((PPCI_PDO_EXTENSION) ArbState->Entry->PhysicalDeviceObject->DeviceExtension)) == PciTypePciBridge);
    ASSERT(ArbState->CurrentAlternative->Descriptor->Flags & CM_RESOURCE_PORT_POSITIVE_DECODE);

    ArbState->RangeAvailableAttributes |= 0x10;

    Minimum = ArbState->CurrentMinimum;
    Maximum = ArbState->CurrentMaximum;

    Length = ArbState->CurrentAlternative->Length;
    Alignment = ArbState->CurrentAlternative->Alignment;

    ASSERT((Length % Alignment) == 0);
    ASSERT((Minimum % Alignment) == 0);
    ASSERT(((Maximum + 1) % Alignment) == 0);

    if (ArbState->Flags & 8)
        RangeFlags = 2;

    if (ArbState->CurrentAlternative->Flags & 1)
        RangeFlags |= 1;

    if (Maximum < (Length + 1))
        return FALSE;

    Start = (Maximum - Length + 1);

    while (TRUE)
    {
        if (Result)
            break;

        if (Start < Minimum)
            break;

        Offset = Start;

        while (TRUE)
        {
            if (Offset >= (Start + Length - 1))
                break;

            if (Offset >= 0xFFFF)
                break;

            Status = RtlIsRangeAvailable(Arbiter->PossibleAllocation,
                                         Offset,
                                         (Offset + 0xFF),
                                         RangeFlags,
                                         ArbState->RangeAvailableAttributes,
                                         Arbiter->ConflictCallbackContext,
                                         Arbiter->ConflictCallback,
                                         &Result);
            ASSERT(NT_SUCCESS(Status));

            if (!Result)
                break;

            Offset += 0x400;
        }

        if (Result)
        {
            ArbState->Start = Start;
            ArbState->End = (Start + Length - 1);

            ASSERT(ArbState->Start >= Minimum);
            ASSERT(ArbState->End <= Maximum);

            break;
        }

        if (Start < 0x1000)
            break;

        Start -= 0x1000;
    }

    return Result;
}

BOOLEAN
NTAPI
ario_FindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PPCI_FDO_EXTENSION ParentFdoExtension;
    PPCI_PDO_EXTENSION ParentPdoExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    PARBITER_LIST_ENTRY ArbEntry;

    PAGED_CODE();
    DPRINT("ario_FindSuitableRange: %p\n", Arbiter);

    ArbState->Flags &= ~8;
    ArbEntry = ArbState->Entry;

    if (ArbState->WorkSpace & 8)
    {
        ASSERT(ArbEntry->PhysicalDeviceObject->DriverObject == PciDriverObject);

        PdoExtension = ArbEntry->PhysicalDeviceObject->DeviceExtension;
        ParentFdoExtension = PdoExtension->ParentFdoExtension;

        if (ParentFdoExtension != ParentFdoExtension->BusRootFdoExtension)
        {
            ParentPdoExtension = ParentFdoExtension->PhysicalDeviceObject->DeviceExtension;
            ASSERT(ParentPdoExtension);
        }
        else
        {
            ParentPdoExtension = NULL;
        }

        if (!ParentPdoExtension ||
            (ParentPdoExtension->HeaderType == 1 && !ParentPdoExtension->MovedDevice))
        {
            if (ArbState->CurrentAlternative->Flags & 2)
                ArbState->Flags |= 8;
        }

        if ((ArbState->WorkSpace & 4) && ArbState->CurrentMaximum <= 0xFFFF)
            return ario_FindWindowWithIsaBit(Arbiter, ArbState);
    }

    if (ArbEntry->RequestSource == ArbiterRequestLegacyReported ||
        ArbEntry->RequestSource == ArbiterRequestLegacyAssigned ||
        (ArbEntry->Flags & 1))
    {
        ArbState->RangeAvailableAttributes |= 1;
    }

    if (ArbState->CurrentAlternative->Descriptor->Flags & 0x20)
        ArbState->RangeAvailableAttributes |= 0x10;

    while (TRUE)
    {
        if (ArbState->CurrentMaximum < ArbState->CurrentMinimum)
            break;

        if (!ArbFindSuitableRange(Arbiter, ArbState))
            break;

        if (!ArbState->CurrentAlternative->Length)
        {
            ArbEntry->Result = 2;
            return TRUE;
        }

        if (ario_IsAliasedRangeAvailable(Arbiter, ArbState))
            return TRUE;

        if (ArbState->Start < (ArbState->Start - 1))
            break;

        ArbState->CurrentMaximum = (ArbState->Start - 1);
    }

    return FALSE;
}

VOID
NTAPI
ario_AddOrBacktrackAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState,
    _In_ PARB_ADD_ALLOCATION Function)
{
    ARBITER_ALLOCATION_STATE NewAllocation;

    PAGED_CODE();
    DPRINT("ario_AddOrBacktrackAllocation: %p\n", Arbiter);

    ASSERT(Arbiter);
    ASSERT(ArbState);

    RtlCopyMemory(&NewAllocation, ArbState, sizeof(NewAllocation));

    if ((ArbState->WorkSpace & 8) && (ArbState->WorkSpace & 4) && ArbState->Start < 0xFFFF)
    {
        ASSERT(ArbState->End <= 0xFFFF);

        for (;
             NewAllocation.Start < ArbState->End && NewAllocation.Start < 0xFFFF;
             NewAllocation.Start += 0x400)
        {
            NewAllocation.End = (NewAllocation.Start + 0xFF);
            Function(Arbiter, &NewAllocation);
        }

        return;
    }

    Function(Arbiter, ArbState);

    if (!(ArbState->CurrentAlternative->Descriptor->Flags & CM_RESOURCE_PORT_POSITIVE_DECODE))
        NewAllocation.RangeAttributes |= 0x10;

    while (ario_GetNextAlias(ArbState->CurrentAlternative->Descriptor->Flags, NewAllocation.Start, &NewAllocation.Start))
    {
        NewAllocation.End = NewAllocation.Start + ArbState->CurrentAlternative->Length - 1;
        Function(Arbiter, &NewAllocation);
    }
}

VOID
NTAPI
ario_AddAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PAGED_CODE();
    DPRINT("ario_AddAllocation: %p\n", Arbiter);
    ario_AddOrBacktrackAllocation(Arbiter, ArbState, ArbAddAllocation);
}

VOID
NTAPI
ario_BacktrackAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PAGED_CODE();
    DPRINT("ario_BacktrackAllocation: %p\n", Arbiter);
    ario_AddOrBacktrackAllocation(Arbiter, ArbState, ArbBacktrackAllocation);
}

NTSTATUS
NTAPI
ario_OverrideConflict(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE Range;
    BOOLEAN Result = FALSE;

    PAGED_CODE();
    DPRINT("ario_OverrideConflict: %p\n", ArbState);

    if (!(ArbState->CurrentAlternative->Flags & 2))
        return FALSE;

    for (RtlGetFirstRange(Arbiter->PossibleAllocation, &Iterator, &Range);
         Range;
         RtlGetNextRange(&Iterator, &Range, TRUE))
    {
        if ((Range->Start < ArbState->CurrentMinimum && Range->End < ArbState->CurrentMinimum) ||
            (Range->Start > ArbState->CurrentMinimum && Range->Start > ArbState->CurrentMaximum)) // IsRangesIntersection
        {
            return Result;
        }

        if (Range->Attributes & ArbState->RangeAvailableAttributes)
            continue;

        if (Range->Owner == ArbState->Entry->PhysicalDeviceObject && (ArbState->CurrentAlternative->Flags & 2))
        {
            DPRINT1("ario_OverrideConflict: Device reported self-conflicting requirement\n");

            ArbState->Start = ArbState->CurrentMinimum;
            ArbState->End = ArbState->CurrentMaximum;

            Result = TRUE;
            continue;
        }

        if (!(ArbState->CurrentAlternative->Descriptor->Flags & 0x40))
            return FALSE;

        UNIMPLEMENTED_DBGBREAK();
    }

    return Result;
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
        DPRINT("ario_Constructor: STATUS_INVALID_PARAMETER_5\n");
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
    PPCI_ARB_MEM_EXTENTION ArbExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    PARBITER_ALTERNATIVE Current;
    BOOLEAN IsPrefetchable;

    PAGED_CODE();
    DPRINT("armem_PreprocessEntry: %p\n", Arbiter);

    ArbExtension = Arbiter->Extension;
    ASSERT(ArbExtension);

    if (ArbState->Entry->PhysicalDeviceObject->DriverObject == PciDriverObject &&
        ArbState->Entry->RequestSource == ArbiterRequestPnpEnumerated)
    {
        PdoExtension = ArbState->Entry->PhysicalDeviceObject->DeviceExtension;    
        ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

        if (PdoExtension->LegacyDriver)
        {
            DPRINT1("armem_PreprocessEntry: STATUS_DEVICE_BUSY\n");
            return STATUS_DEVICE_BUSY;
        }
    }

    if ((ArbState->Alternatives[0].Descriptor->Flags & CM_RESOURCE_MEMORY_READ_ONLY) ||
        ((ArbState->Alternatives[0].Flags & 2) && ArbState->AlternativeCount == 1 && ArbState->Entry->RequestSource == ArbiterRequestLegacyReported))
    {
        if (ArbState->Alternatives[0].Descriptor->Flags & CM_RESOURCE_MEMORY_READ_ONLY)
        {
            ASSERT(ArbState->Alternatives[0].Flags & 2);//ARBITER_ALTERNATIVE_FLAG_FIXED
        }

        ArbState->RangeAvailableAttributes |= 0x10;
        ArbState->RangeAttributes |= 0x10;
        ArbState->Flags |= 8;
    }

    if (!ArbExtension->IsPrefetchable)
    {
        Arbiter->OrderingList = ArbExtension->ArbiterOrderingList;
        return STATUS_SUCCESS;
    }

    IsPrefetchable = ((ArbState->Alternatives[0].Descriptor->Flags & CM_RESOURCE_MEMORY_PREFETCHABLE) == CM_RESOURCE_MEMORY_PREFETCHABLE);

    if (IsPrefetchable)
        Arbiter->OrderingList = ArbExtension->PrefetchOrderingList;
    else
        Arbiter->OrderingList = ArbExtension->OrderingList;

    Current = ArbState->Alternatives;
    while (Current < &ArbState->Alternatives[ArbState->AlternativeCount])
    {
        ASSERT(((Current->Descriptor->Flags & CM_RESOURCE_MEMORY_PREFETCHABLE) == CM_RESOURCE_MEMORY_PREFETCHABLE) == IsPrefetchable);
        Current++;
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
armem_GetNextAllocationRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PPCI_ARB_MEM_EXTENTION ArbExtension = Arbiter->Extension;

    DPRINT("armem_GetNextAllocationRange: %p\n", Arbiter);

    if (!ArbGetNextAllocationRange(Arbiter, ArbState))
        return FALSE;

    if (ArbExtension->IsPrefetchable &&
        ArbState->Entry->RequestSource != ArbiterRequestLegacyReported &&
        ArbState->CurrentAlternative->Priority > 0x7FFFFFFD)
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
NTAPI
armem_FindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    if (ArbState->Entry->Flags & 1)
        ArbState->RangeAvailableAttributes |= 1;

    return ArbFindSuitableRange(Arbiter, ArbState);
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
        DPRINT("armem_Constructor: STATUS_INVALID_PARAMETER_5\n");
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
