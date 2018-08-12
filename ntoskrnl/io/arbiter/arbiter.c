/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/arbiter/arbiter.c
 * PURPOSE:         Arbiter of hardware resources library
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
ArbInitializeArbiterInstance(
    _Inout_ PARBITER_INSTANCE Arbiter,
    _In_ PDEVICE_OBJECT BusDeviceObject,
    _In_ CM_RESOURCE_TYPE ResourceType,
    _In_ PWSTR ArbiterName,
    _In_ PCWSTR OrderName,
    _In_ PARB_TRANSLATE_ORDERING TranslateOrderingFunction)
{
    //PAGED_CODE();
    DPRINT("ArbInitializeArbiterInstance: Initializing %S Arbiter\n", ArbiterName);
    ASSERT(FALSE);
    return 0;
}

/* EOF */
