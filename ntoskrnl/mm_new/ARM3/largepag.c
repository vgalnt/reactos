
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG MiLargePageRangeIndex;
PMMPTE MiLargePageHyperPte;
LIST_ENTRY MmProcessList;
LIST_ENTRY MiLargePageDriverList;
ULONG MmLargePageDriverBufferLength = -1;
WCHAR MmLargePageDriverBuffer[512] = {0};
BOOLEAN MiLargePageAllDrivers;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiInitializeLargePageSupport)
  #pragma alloc_text(INIT, MiSyncCachedRanges)
  #pragma alloc_text(INIT, MiInitializeDriverLargePageList)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeLargePageSupport(VOID)
{
#if _MI_PAGING_LEVELS > 2
    DPRINT1("MiInitializeLargePageSupport: PAE/x64 Not Implemented\n");
    ASSERT(FALSE);
#else
    /* Initialize the large-page hyperspace PTE used for initial mapping */
    MiLargePageHyperPte = MiReserveSystemPtes(1, SystemPteSpace);
    ASSERT(MiLargePageHyperPte);
    MiLargePageHyperPte->u.Long = 0;

    /* Initialize the process tracking list, and insert the system process */
    InitializeListHead(&MmProcessList);
    InsertTailList(&MmProcessList, &PsGetCurrentProcess()->MmProcessLinks);
#endif
}

CODE_SEG("INIT")
VOID
NTAPI
MiSyncCachedRanges(VOID)
{
    ULONG ix;

    /* Scan every range */
    for (ix = 0; ix < MiLargePageRangeIndex; ix++)
    {
        UNIMPLEMENTED_DBGBREAK("No support for large pages\n");
    }
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeDriverLargePageList(VOID)
{
    PWCHAR pChar;
    PWCHAR pLastChar;

    /* Initialize the list */
    InitializeListHead(&MiLargePageDriverList);

    /* Bail out if there's nothing */
    if (MmLargePageDriverBufferLength == 0xFFFFFFFF)
        return;

    /* Loop from start to finish */
    pChar = MmLargePageDriverBuffer;
    pLastChar = (MmLargePageDriverBuffer + (MmLargePageDriverBufferLength / sizeof(WCHAR)));

    while (pChar < pLastChar)
    {
        /* Skip whitespaces */
        if ((*pChar == L' ') || (*pChar == L'\n') || (*pChar == L'\r') || (*pChar == L'\t'))
        {
            /* Skip the character */
            pChar++;
            continue;
        }

        /* A star means everything */
        if (*pChar == L'*')
        {
            /* No need to keep going */
            MiLargePageAllDrivers = TRUE;
            break;
        }

        DPRINT1("Large page drivers not supported\n");
        ASSERT(FALSE);
    }
}

/* EOF */
