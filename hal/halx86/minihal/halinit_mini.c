/*
 * COPYRIGHT:     See COPYING in the top level directory
 * PROJECT:       ReactOS kernel
 * FILE:          hal/halx86/up/halinit_mini.c
 * PURPOSE:       Initialize the x86 hal
 * PROGRAMMER:    David Welch (welch@cwcom.net)
 * UPDATE HISTORY:
 *              11/06/98: Created
 */

/* INCLUDES *****************************************************************/

#include <hal.h>
#define NDEBUG
#include <debug.h>

/* FUNCTIONS ***************************************************************/

VOID
NTAPI
HalpInitProcessor(
    IN ULONG ProcessorNumber,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    DPRINT1("HalpInitProcessor: LoaderBlock - %p\n", LoaderBlock);
    ASSERT(FALSE);
}

VOID
HalpInitPhase0(IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    DPRINT1("HalpInitPhase0: LoaderBlock - %p\n", LoaderBlock);
    ASSERT(FALSE);
}

VOID
HalpInitPhase1(IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    DPRINT1("HalpInitPhase1: LoaderBlock - %p\n", LoaderBlock);
    ASSERT(FALSE);
}

/* EOF */
