
/* INCLUDES ******************************************************************/

#include <hal.h>
//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/


/* PRIVATE FUNCTIONS *********************************************************/


/* FUNCTIONS *****************************************************************/

#if defined(ALLOC_PRAGMA) && !defined(_MINIHAL_)
  BOOLEAN NTAPI HalAllProcessorsStarted(VOID);
  #pragma alloc_text(INIT, HalAllProcessorsStarted)
#endif

CODE_SEG("INIT")
BOOLEAN
NTAPI
HalAllProcessorsStarted(VOID)
{
    return TRUE;
}

BOOLEAN
NTAPI
HalStartNextProcessor(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ PKPROCESSOR_STATE ProcessorState)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return FALSE;
}

VOID
NTAPI
HalProcessorIdle(VOID)
{
    /* Enable interrupts and halt the processor */
    _enable();
    __halt();
}

VOID
NTAPI
HalRequestIpi(
    _In_ KAFFINITY TargetProcessors)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
}

/* EOF */
