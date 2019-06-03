
/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/* DATA **********************************************************************/

/* FUNCTIONS *****************************************************************/

PVOID
NTAPI
PiAllocateCriticalMemory(
    _In_ PIP_TYPE_REMOVAL_DEVICE DeleteType,
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag)
{
    PVOID Block;
    LARGE_INTEGER Interval;

    PAGED_CODE();
    DPRINT("PiAllocateCriticalMemory: DeleteType - %X, NumberOfBytes - %X\n", DeleteType, NumberOfBytes);

    ASSERT(KeGetCurrentIrql() != DISPATCH_LEVEL);

    while (TRUE)
    {
        Block = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

        if (Block || DeleteType == PipQueryRemove || DeleteType == PipEject)
        {
            break;
        }

        Interval.QuadPart = -10000ll * 1; // 1 msec
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    return Block;
}


/* EOF */
