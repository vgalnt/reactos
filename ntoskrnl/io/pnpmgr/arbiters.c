/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/arbiters.c
 * PURPOSE:         Root arbiters the PnP manager
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"
#include "../arbiter/arbiter.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern ARBITER_INSTANCE IopRootBusNumberArbiter;
extern ARBITER_INSTANCE IopRootIrqArbiter;
extern ARBITER_INSTANCE IopRootDmaArbiter;
extern ARBITER_INSTANCE IopRootMemArbiter;
extern ARBITER_INSTANCE IopRootPortArbiter;

/* DATA **********************************************************************/

/* FUNCTIONS *****************************************************************/

//--- BusNumber arbiter ---------------------------
NTSTATUS
NTAPI
IopBusNumberUnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    PAGED_CODE();
    DPRINT("BusNumberUnpackIo: [%p] Min %X Max %X Len %X\n",
            IoDescriptor,
            IoDescriptor->u.BusNumber.MinBusNumber,
            IoDescriptor->u.BusNumber.MaxBusNumber,
            IoDescriptor->u.BusNumber.Length);

    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeBusNumber);

    *OutMinimumAddress = IoDescriptor->u.BusNumber.MinBusNumber;
    *OutMaximumAddress = IoDescriptor->u.BusNumber.MaxBusNumber;

    *OutLength = IoDescriptor->u.Generic.Length;
    *OutAlignment = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopBusNumberPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ ULONGLONG Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    DPRINT("BusNumberPack: [%p] Start %X\n", IoDescriptor, (ULONG)Start);

    ASSERT(CmDescriptor);
    ASSERT(Start < ((ULONG)-1));
    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeBusNumber);

    CmDescriptor->Type = CmResourceTypeBusNumber;
    CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;
    CmDescriptor->Flags = IoDescriptor->Flags;

    CmDescriptor->u.BusNumber.Start = Start;
    CmDescriptor->u.BusNumber.Length = IoDescriptor->u.BusNumber.Length;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopBusNumberUnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    DPRINT("IopBusNumberUnpackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

LONG
NTAPI
IopBusNumberScoreRequirement(PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    DPRINT("IopBusNumberScoreRequirement: IoDescriptor - %p\n", IoDescriptor);
    PAGED_CODE();
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopBusNumberInitialize(VOID)
{
    NTSTATUS Status;
    DPRINT("IopBusNumberInitialize: IopRootBusNumberArbiter - %p\n", &IopRootBusNumberArbiter);

    IopRootBusNumberArbiter.UnpackRequirement = IopBusNumberUnpackRequirement;
    IopRootBusNumberArbiter.PackResource = IopBusNumberPackResource;
    IopRootBusNumberArbiter.UnpackResource = IopBusNumberUnpackResource;
    IopRootBusNumberArbiter.ScoreRequirement = IopBusNumberScoreRequirement;

    Status = ArbInitializeArbiterInstance(&IopRootBusNumberArbiter,
                                          NULL,
                                          CmResourceTypeBusNumber,
                                          L"RootBusNumber",
                                          L"Root",
                                          NULL);

    if (!NT_SUCCESS(Status))
    {
        ASSERT(FALSE);
        return Status;
    }

    Status = RtlAddRange(IopRootBusNumberArbiter.Allocation,
                         0x100ull,
                         0xFFFFFFFFFFFFFFFFull,
                         0,
                         0,
                         NULL,
                         NULL);

    return Status;
}

//--- Irq arbiter -------------------------------------
NTSTATUS
NTAPI
IopIrqUnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumVector,
    _Out_ PULONGLONG OutMaximumVector,
    _Out_ PULONG OutParam1,
    _Out_ PULONG OutParam2)
{
    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeInterrupt);

    DPRINT("IopIrqUnpackRequirement: IoDescriptor - %p, MinimumVector - %X, MaximumVector - %X\n",
            IoDescriptor,
            IoDescriptor->u.Interrupt.MinimumVector,
            IoDescriptor->u.Interrupt.MaximumVector);

    *OutMinimumVector = IoDescriptor->u.Interrupt.MinimumVector;
    *OutMaximumVector = IoDescriptor->u.Interrupt.MaximumVector;

    *OutParam1 = 1;
    *OutParam2 = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopIrqPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ PHYSICAL_ADDRESS Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    DPRINT("IopIrqPackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopIrqUnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG OutMinimumVector,
    _Out_ PULONGLONG OutMaximumVector,
    _Out_ PULONG OutParam1,
    _Out_ PULONG OutParam2)
{
    DPRINT("IopIrqUnpackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

LONG
NTAPI
IopIrqScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    DPRINT("IopIrqScoreRequirement: IoDescriptor - %p\n", IoDescriptor);
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopIrqTranslateOrdering(
    _Out_ PIO_RESOURCE_DESCRIPTOR OutIoDescriptor,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    ULONG InterruptVector;
    KAFFINITY Affinity;
    KIRQL Irql;

    DPRINT("IopIrqTranslateOrdering: IoDescriptor - %p\n", IoDescriptor);
    PAGED_CODE();

    RtlCopyMemory(OutIoDescriptor, IoDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

    if (IoDescriptor->Type != CmResourceTypeInterrupt)
    {
        return STATUS_SUCCESS;
    }

    InterruptVector = HalGetInterruptVector(Isa,
                                            0,
                                            IoDescriptor->u.Interrupt.MinimumVector,
                                            IoDescriptor->u.Interrupt.MinimumVector,
                                            &Irql,
                                            &Affinity);

    OutIoDescriptor->u.Interrupt.MinimumVector = InterruptVector;

    if (Affinity == 0)
    {
        RtlCopyMemory(OutIoDescriptor, IoDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));
    }
    else
    {
        InterruptVector = HalGetInterruptVector(Isa,
                                                0,
                                                IoDescriptor->u.Interrupt.MaximumVector,
                                                IoDescriptor->u.Interrupt.MaximumVector,
                                                &Irql,
                                                &Affinity);

        OutIoDescriptor->u.Interrupt.MaximumVector = InterruptVector;

        if (Affinity == 0)
        {
            RtlCopyMemory(OutIoDescriptor, IoDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopIrqInitialize(VOID)
{
    DPRINT("IopIrqInitialize: &IopRootIrqArbiter - %p\n", &IopRootIrqArbiter);

    IopRootIrqArbiter.UnpackRequirement = IopIrqUnpackRequirement;
    IopRootIrqArbiter.PackResource = IopIrqPackResource;
    IopRootIrqArbiter.UnpackResource = IopIrqUnpackResource;
    IopRootIrqArbiter.ScoreRequirement = IopIrqScoreRequirement;

    return ArbInitializeArbiterInstance(&IopRootIrqArbiter,
                                        NULL,
                                        CmResourceTypeInterrupt,
                                        L"RootIRQ",
                                        L"Root",
                                        IopIrqTranslateOrdering);
}

//--- Dma arbiter -------------------------------------
NTSTATUS
NTAPI
IopDmaUnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumChannel,
    _Out_ PULONGLONG OutMaximumChannel,
    _Out_ PULONG OutParam1,
    _Out_ PULONG OutParam2)
{
    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeDma);

    DPRINT("IopDmaUnpackRequirement: IoDescriptor - %p, MinimumChannel - %X, MaximumChannel - %X\n",
            IoDescriptor,
            IoDescriptor->u.Dma.MinimumChannel,
            IoDescriptor->u.Dma.MaximumChannel);

    *OutMinimumChannel = IoDescriptor->u.Dma.MinimumChannel;
    *OutMaximumChannel = IoDescriptor->u.Dma.MaximumChannel;

    *OutParam1 = 1;
    *OutParam2 = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopDmaPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ PHYSICAL_ADDRESS Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    DPRINT("IopDmaPackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopDmaUnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG OutMinimumChannel,
    _Out_ PULONGLONG OutMaximumChannel,
    _Out_ PULONG OutParam1,
    _Out_ PULONG OutParam2)
{
    DPRINT("IopDmaUnpackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

LONG
NTAPI
IopDmaScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    DPRINT("IopDmaScoreRequirement: ...\n");
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopDmaOverrideConflict()
{
    DPRINT("IopDmaOverrideConflict: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopDmaInitialize(VOID)
{
    DPRINT("IopDmaInitialize: &IopRootDmaArbiter - %p\n", &IopRootDmaArbiter);

    IopRootDmaArbiter.UnpackRequirement = IopDmaUnpackRequirement;
    IopRootDmaArbiter.PackResource = IopDmaPackResource;
    IopRootDmaArbiter.UnpackResource = IopDmaUnpackResource;
    IopRootDmaArbiter.ScoreRequirement = IopDmaScoreRequirement;

    IopRootDmaArbiter.OverrideConflict = IopDmaOverrideConflict;

    return ArbInitializeArbiterInstance(&IopRootDmaArbiter,
                                        NULL,
                                        CmResourceTypeDma,
                                        L"RootDMA",
                                        L"Root",
                                        NULL);
}

//--- Common for Memory and Port arbiters -------------
NTSTATUS
NTAPI
IopGenericUnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    PAGED_CODE();

    DPRINT("IopGenericUnpackRequirement: IoDescriptor - %p, MinimumAddress - %I64X, MaximumAddress - %I64X, Length - %X\n",
            IoDescriptor,
            IoDescriptor->u.Generic.MinimumAddress.QuadPart,
            IoDescriptor->u.Generic.MaximumAddress.QuadPart,
            IoDescriptor->u.Generic.Length);

    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypePort ||
           IoDescriptor->Type == CmResourceTypeMemory);

    *OutLength = IoDescriptor->u.Generic.Length;
    *OutAlignment = IoDescriptor->u.Generic.Alignment;

    *OutMinimumAddress = IoDescriptor->u.Generic.MinimumAddress.QuadPart;
    *OutMaximumAddress = IoDescriptor->u.Generic.MaximumAddress.QuadPart;

    if (IoDescriptor->u.Generic.Alignment == 0)
    {
        *OutAlignment = 1;
    }

    if (IoDescriptor->Type == CmResourceTypeMemory &&
        IoDescriptor->Flags & CM_RESOURCE_MEMORY_24 &&
        IoDescriptor->u.Generic.MaximumAddress.QuadPart > 0xFFFFFF)
    {
        ASSERT(FALSE);
        *OutMaximumAddress = 0xFFFFFF;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopGenericPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ PHYSICAL_ADDRESS Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    PAGED_CODE();
    DPRINT("IopGenericPackResource: IoDescriptor - %p, Start.QuadPart - %I64X\n", IoDescriptor, Start.QuadPart);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopGenericUnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    DPRINT("IopGenericUnpackResource: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

LONG
NTAPI
IopGenericScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PAGED_CODE();
    DPRINT("IopGenericScoreRequirement: IoDescriptor - %p, MinimumAddress - %I64X, MaximumAddress - %I64X, Length - %X, Alignment - %X\n",
           IoDescriptor,
           IoDescriptor->u.Generic.MinimumAddress.QuadPart,
           IoDescriptor->u.Generic.MaximumAddress.QuadPart,
           IoDescriptor->u.Generic.Length,
           IoDescriptor->u.Generic.Alignment);

    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopTranslateBusAddress(
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ CM_RESOURCE_TYPE Type,
    _In_ PPHYSICAL_ADDRESS TranslatedAddress,
    _Out_ CM_RESOURCE_TYPE * OutType)
{
    ULONG AddressSpace;

    PAGED_CODE();

    if (Type == CmResourceTypeMemory)
    {
        AddressSpace = 0;
    }
    else if (Type == CmResourceTypePort)
    {
        AddressSpace = 1;
    }
    else
    {
        DPRINT("IopTranslateBusAddress: STATUS_INVALID_PARAMETER. Type - %X\n", Type);
        return STATUS_INVALID_PARAMETER;
    }

    if (!HalTranslateBusAddress(Isa,
                                0,
                                BusAddress,
                                &AddressSpace,
                                TranslatedAddress))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (AddressSpace == 0)
    {
        *OutType = CmResourceTypeMemory;
    }
    else if (AddressSpace == 1)
    {
        *OutType = CmResourceTypePort;
    }
    else
    {
        DPRINT("IopTranslateBusAddress: STATUS_INVALID_PARAMETER. AddressSpace - %X\n", AddressSpace);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopGenericTranslateOrdering(
    _Out_ PIO_RESOURCE_DESCRIPTOR OutIoDescriptor,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    CM_RESOURCE_TYPE ResourceTypeMinAddr;
    CM_RESOURCE_TYPE ResourceTypeMaxAddr;
    NTSTATUS Status;

    PAGED_CODE();

    RtlCopyMemory(OutIoDescriptor, IoDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

    if (IoDescriptor->Type != CmResourceTypeMemory &&
        IoDescriptor->Type != CmResourceTypePort)
    {
        DPRINT("IopGenericTranslateOrdering: Exit. Type - %X\n", IoDescriptor->Type);
        return STATUS_SUCCESS;
    }
    else
    {
        DPRINT("IopGenericTranslateOrdering: [%p] Type - %X\n", IoDescriptor, IoDescriptor->Type);
    }

    DPRINT("IopGenericTranslateOrdering: MinimumAddress - %I64X, MaximumAddress - %I64X\n",
           IoDescriptor->u.Generic.MinimumAddress, IoDescriptor->u.Generic.MaximumAddress);

    Status = IopTranslateBusAddress(IoDescriptor->u.Generic.MinimumAddress,
                                    IoDescriptor->Type,
                                    &OutIoDescriptor->u.Generic.MinimumAddress,
                                    &ResourceTypeMinAddr);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGenericTranslateOrdering: Status - %X\n", Status);
        OutIoDescriptor->Type = CmResourceTypeNull;
        return STATUS_SUCCESS;
    }

    Status = IopTranslateBusAddress(IoDescriptor->u.Generic.MaximumAddress,
                                    IoDescriptor->Type,
                                    &OutIoDescriptor->u.Generic.MaximumAddress,
                                    &ResourceTypeMaxAddr);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGenericTranslateOrdering: Status - %X\n", Status);
        OutIoDescriptor->Type = CmResourceTypeNull;
        return STATUS_SUCCESS;
    }

    ASSERT(ResourceTypeMinAddr == ResourceTypeMaxAddr);
    OutIoDescriptor->Type = ResourceTypeMinAddr;

    return STATUS_SUCCESS;
}

//--- Memory arbiter ----------------------------------
BOOLEAN
NTAPI
IopMemFindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE State)
{
    BOOLEAN Result;
    DPRINT("IopMemFindSuitableRange: Arbiter - %p, State - %p\n", Arbiter, State);
    ASSERT(FALSE);
    return Result=0;
}

NTSTATUS
NTAPI
IopMemInitialize(VOID)
{
    NTSTATUS Status;
    PAGED_CODE();
    DPRINT("IopMemInitialize: IopRootMemArbiter - %p\n", &IopRootMemArbiter);

    IopRootMemArbiter.UnpackRequirement = IopGenericUnpackRequirement;
    IopRootMemArbiter.PackResource = IopGenericPackResource;
    IopRootMemArbiter.UnpackResource = IopGenericUnpackResource;
    IopRootMemArbiter.ScoreRequirement = IopGenericScoreRequirement;

    IopRootMemArbiter.FindSuitableRange = IopMemFindSuitableRange;

    Status = ArbInitializeArbiterInstance(&IopRootMemArbiter,
                                          NULL,
                                          CmResourceTypeMemory,
                                          L"RootMemory",
                                          L"Root",
                                          IopGenericTranslateOrdering);

    if (!NT_SUCCESS(Status))
    {
        ASSERT(FALSE);
        return Status;
    }

    Status = RtlAddRange(IopRootMemArbiter.Allocation,
                         0ull,
                         0xFFFull,
                         0,
                         0,
                         NULL,
                         NULL);

    return Status;
}

//--- Port arbiter ------------------------------------
BOOLEAN
NTAPI
IopPortFindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE State)
{
    PAGED_CODE();
    DPRINT("IopPortFindSuitableRange: ...\n");
    ASSERT(FALSE);
    return 0;
}

BOOLEAN
NTAPI
IopPortGetNextAlias(
    _In_ UCHAR Flags,
    _In_ ULONGLONG Start,
    _Out_ PULONGLONG OutNextStart)
{
    LARGE_INTEGER start;
    ULONG NextStart;
    UCHAR CarryFlag;

    PAGED_CODE();
    DPRINT("IopPortGetNextAlias: Start - %I64X\n", Start);

    start.QuadPart = Start;

    if (Flags & CM_RESOURCE_PORT_10_BIT_DECODE)
    {
        CarryFlag = start.LowPart > start.LowPart + (1 << 10);
        NextStart = start.LowPart + (1 << 10);
    }
    else if (Flags & CM_RESOURCE_PORT_12_BIT_DECODE)
    {
        CarryFlag = start.LowPart > start.LowPart + (1 << 12);
        NextStart = start.LowPart + (1 << 12);
    }
    else
    {
        return FALSE;
    }

    if (!(CarryFlag + start.HighPart) && NextStart <= MAXUSHORT)
    {
        *OutNextStart = NextStart;
        return TRUE;
    }

    return FALSE;
}

VOID
NTAPI
IopPortAddAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE ArbState)
{
    ULONGLONG Start;
    ULONG Flags;
    NTSTATUS Status;
    UCHAR Result;

    PAGED_CODE();
    DPRINT("IopPortAddAllocation: Arbiter - %p\n", Arbiter);

    ASSERT(Arbiter);
    ASSERT(ArbState);

    Flags = RTL_RANGE_LIST_ADD_IF_CONFLICT;

    if (ArbState->CurrentAlternative->Flags & 1)
    {
        Flags |= RTL_RANGE_LIST_ADD_SHARED;
    }

    Status = RtlAddRange(Arbiter->PossibleAllocation,
                         ArbState->Start,
                         ArbState->End,
                         ArbState->RangeAttributes,
                         Flags,
                         NULL,
                         ArbState->Entry->PhysicalDeviceObject);

    ASSERT(NT_SUCCESS(Status));

    Start = ArbState->Start;

    while (TRUE)
    {
        Result = IopPortGetNextAlias(ArbState->CurrentAlternative->Descriptor->Flags,
                                     Start,
                                     &Start);

        if (!Result)
        {
            break;
        }

        Flags = RTL_RANGE_LIST_ADD_IF_CONFLICT;

        if (ArbState->CurrentAlternative->Flags & 1)
        {
            Flags |= RTL_RANGE_LIST_ADD_SHARED;
        }

        Status = RtlAddRange(Arbiter->PossibleAllocation,
                             Start,
                             Start + ArbState->CurrentAlternative->Length - 1,
                             ArbState->RangeAttributes | 0x10,
                             Flags,
                             NULL,
                             ArbState->Entry->PhysicalDeviceObject);

        ASSERT(NT_SUCCESS(Status));
    }
}

NTSTATUS
NTAPI
IopPortBacktrackAllocation()
{
    DPRINT("IopPortBacktrackAllocation: ...\n");
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopPortInitialize(VOID)
{
    PAGED_CODE();
    DPRINT("IopPortInitialize: IopRootPortArbiter - %p\n", &IopRootPortArbiter);

    IopRootPortArbiter.UnpackRequirement = IopGenericUnpackRequirement;
    IopRootPortArbiter.PackResource = IopGenericPackResource;
    IopRootPortArbiter.UnpackResource = IopGenericUnpackResource;
    IopRootPortArbiter.ScoreRequirement = IopGenericScoreRequirement;

    IopRootPortArbiter.FindSuitableRange = IopPortFindSuitableRange;
    IopRootPortArbiter.AddAllocation = IopPortAddAllocation;
    IopRootPortArbiter.BacktrackAllocation = IopPortBacktrackAllocation;

    return ArbInitializeArbiterInstance(&IopRootPortArbiter,
                                        NULL,
                                        CmResourceTypePort,
                                        L"RootPort",
                                        L"Root",
                                        IopGenericTranslateOrdering);
}

/* EOF */
