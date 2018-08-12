/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/arbiters.c
 * PURPOSE:         Root arbiters the PnP manager
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../arbiter/arbiter.h"

//#define NDEBUG
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
    DPRINT("IopBusNumberUnpackRequirement: IoDescriptor - %p, MinBusNumber - %X, MaxBusNumber - %X, Length - %X\n",
            IoDescriptor,
            IoDescriptor->u.BusNumber.MinBusNumber,
            IoDescriptor->u.BusNumber.MaxBusNumber,
            IoDescriptor->u.BusNumber.Length);

    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopBusNumberPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ PHYSICAL_ADDRESS Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    PAGED_CODE();
    DPRINT("IopBusNumberPackResource: IoDescriptor - %p, Start.QuadPart - %I64X\n", IoDescriptor, Start.QuadPart);
    ASSERT(FALSE);
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

    ASSERT(FALSE);

    return Status=STATUS_SUCCESS;
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
    DPRINT("IopIrqUnpackRequirement: IoDescriptor - %p\n", IoDescriptor);
    ASSERT(FALSE);
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
IopIrqInitialize(VOID)
{
    DPRINT("IopIrqInitialize: &IopRootIrqArbiter - %p\n", &IopRootIrqArbiter);

    IopRootIrqArbiter.UnpackRequirement = IopIrqUnpackRequirement;
    IopRootIrqArbiter.PackResource = IopIrqPackResource;
    IopRootIrqArbiter.UnpackResource = IopIrqUnpackResource;
    IopRootIrqArbiter.ScoreRequirement = IopIrqScoreRequirement;

    ASSERT(FALSE);
    return STATUS_SUCCESS;
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
    DPRINT("IopDmaUnpackRequirement: ...\n");
    ASSERT(FALSE);
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

    ASSERT(FALSE);
    return STATUS_SUCCESS;
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
            IoDescriptor->u.Port.MinimumAddress.QuadPart,
            IoDescriptor->u.Port.MaximumAddress.QuadPart,
            IoDescriptor->u.Port.Length);

    ASSERT(FALSE);
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

//--- Memory arbiter ----------------------------------
BOOLEAN
NTAPI
IopMemFindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE State)
{
    BOOLEAN Result;
    DPRINT("IopMemFindSuitableRange: Arbiter - %p, State - %p\n", Arbiter, State);
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

    ASSERT(FALSE);
    return Status=0;
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
    _Out_ PULONGLONG pStart)
{
    PAGED_CODE();
    DPRINT("IopPortGetNextAlias: ...\n");
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
IopPortAddAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE ArbState)
{
    PAGED_CODE();
    DPRINT("IopPortAddAllocation: ...\n");
    ASSERT(FALSE);
    return 0;
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
IopGenericTranslateOrdering(
    _Out_ PIO_RESOURCE_DESCRIPTOR OutIoDescriptor,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PAGED_CODE();
    DPRINT("IopGenericTranslateOrdering: ... \n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
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
