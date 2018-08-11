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
NTSTATUS NTAPI IopBusNumberInitialize()
{
    DPRINT("IopBusNumberInitialize: IopRootBusNumberArbiter - %p\n", &IopRootBusNumberArbiter);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

//--- Irq arbiter ---------------------------------
NTSTATUS NTAPI IopIrqInitialize()
{
    DPRINT("IopIrqInitialize: &IopRootIrqArbiter - %p\n", &IopRootIrqArbiter);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

//--- Dma arbiter ---------------------------------
NTSTATUS NTAPI IopDmaInitialize()
{
    DPRINT("IopDmaInitialize: &IopRootDmaArbiter - %p\n", &IopRootDmaArbiter);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

//--- Memory arbiter ------------------------------
NTSTATUS NTAPI IopMemInitialize()
{
    PAGED_CODE();
    DPRINT("IopMemInitialize: IopRootMemArbiter - %p\n", &IopRootMemArbiter);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

//--- Port arbiter --------------------------------
NTSTATUS NTAPI IopPortInitialize()
{
    PAGED_CODE();
    DPRINT("IopPortInitialize: IopRootPortArbiter - %p\n", &IopRootPortArbiter);
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

/* EOF */
