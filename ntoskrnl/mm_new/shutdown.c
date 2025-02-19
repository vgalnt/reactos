
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>
#include "ARM3/miarm.h"

/* GLOBALS ********************************************************************/

extern PMMPAGING_FILE MmPagingFile[MAX_PAGING_FILES];
extern ULONG MmNumberOfPagingFiles;

/* FUNCTIONS ******************************************************************/

VOID MiShutdownSystem(VOID);

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiShutdownSystem)
  #pragma alloc_text(PAGE, MmShutdownSystem)
#endif

CODE_SEG("PAGELK")
VOID
MiShutdownSystem(VOID)
{
    ULONG ix;

    /* Loop through all the paging files */
    for (ix = 0; ix < MmNumberOfPagingFiles; ix++)
    {
        /* Free page file name */
        ASSERT(MmPagingFile[ix]->PageFileName.Buffer != NULL);

        ExFreePoolWithTag(MmPagingFile[ix]->PageFileName.Buffer, TAG_MM);
        MmPagingFile[ix]->PageFileName.Buffer = NULL;

        /* And close them */
        ZwClose(MmPagingFile[ix]->FileHandle);
    }

    UNIMPLEMENTED;
}

CODE_SEG("PAGELK")
VOID
MmShutdownSystem(
    _In_ ULONG Phase)
{
    ULONG ix;

    if (Phase == 0)
    {
        MiShutdownSystem();
    }
    else if (Phase == 1)
    {
        /* Loop through all the paging files */
        for (ix = 0; ix < MmNumberOfPagingFiles; ix++)
        {
            /* And dereference them */
            ObDereferenceObject(MmPagingFile[ix]->FileObject);
        }
    }
    else
    {
        ASSERT(Phase == 2);
        UNIMPLEMENTED;
    }
}

/* EOF */
