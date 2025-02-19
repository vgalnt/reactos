
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/


/* FUNCTIONS ******************************************************************/


/* PUBLIC FUNCTIONS ***********************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MmAllocateNonCachedMemory)
  #pragma alloc_text(PAGE, MmFreeNonCachedMemory)
#endif

CODE_SEG("PAGE")
PVOID
NTAPI
MmAllocateNonCachedMemory(
    _In_ SIZE_T NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGE")
VOID
NTAPI
MmFreeNonCachedMemory(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* EOF */
