
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "ARM3/miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PMMSUPPORT MmKernelAddressSpace;
PMMPTE MmSharedUserDataPte;

extern PVOID MmNonPagedSystemStart;
extern PVOID MmNonPagedPoolStart;
extern PVOID MmNonPagedPoolExpansionStart;
extern PVOID MmSystemCacheStart;
extern PVOID MmSystemCacheEnd;
extern PVOID MiSystemViewStart;
extern SIZE_T MmBootImageSize;
extern SIZE_T MmSystemViewSize;
extern SIZE_T MmSizeOfNonPagedPoolInBytes;
extern SIZE_T MmSizeOfPagedPoolInBytes;
extern ULONG_PTR MxPfnAllocation;

extern MM_AVL_TABLE MmSectionBasedRoot;
extern KGUARDED_MUTEX MmSectionBasedMutex;
//extern PMMPTE MmSharedUserDataPte;
extern MMPTE ValidKernelPte;

/* FUNCTIONS ******************************************************************/

VOID NTAPI MiDbgDumpAddressSpace(VOID);
NTSTATUS NTAPI MmInitBsmThread(VOID);

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiDbgDumpAddressSpace)
  #pragma alloc_text(INIT, MmInitBsmThread)
  #pragma alloc_text(INIT, MmInitSystem)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiDbgDumpAddressSpace(VOID)
{
    ULONG_PTR _BootImageEnd        = ((ULONG_PTR)KSEG0_BASE                   +            MmBootImageSize);
    SIZE_T    _PfnDatabaseSize     = (MxPfnAllocation << PAGE_SHIFT);
    ULONG_PTR _PfnDatabaseEnd      = ((ULONG_PTR)MmPfnDatabase                +           _PfnDatabaseSize);
    ULONG_PTR _NPagedPoolEnd       = ((ULONG_PTR)MmNonPagedPoolStart          +            MmSizeOfNonPagedPoolInBytes);
    ULONG_PTR _SystemViewEnd       = ((ULONG_PTR)MiSystemViewStart            +            MmSystemViewSize);
    SIZE_T    _SessionSize         = ((ULONG_PTR)MiSessionSpaceEnd            - (ULONG_PTR)MmSessionBase);
    SIZE_T    _PageTablesSize      = ((ULONG_PTR)PTE_TOP                      - (ULONG_PTR)PTE_BASE);
    SIZE_T    _PageDirectoriesSize = ((ULONG_PTR)PDE_TOP                      - (ULONG_PTR)PDE_BASE);
    SIZE_T    _HyperspaceSize      = ((ULONG_PTR)HYPER_SPACE_END              - (ULONG_PTR)HYPER_SPACE);
    SIZE_T    _SystemCacheSize     = ((ULONG_PTR)MmSystemCacheEnd             - (ULONG_PTR)MmSystemCacheStart);
    ULONG_PTR _PagedPoolEnd        = ((ULONG_PTR)MmPagedPoolStart             +            MmSizeOfPagedPoolInBytes);
    SIZE_T    _SystemPteSize       = ((ULONG_PTR)MmNonPagedPoolExpansionStart - (ULONG_PTR)MmNonPagedSystemStart);
    SIZE_T    _NPagedPoolExtSize   = ((ULONG_PTR)MmNonPagedPoolEnd            - (ULONG_PTR)MmNonPagedPoolExpansionStart);

#ifdef _M_AMD64

    DPRINT1("MiDbgDumpAddressSpace: FIXME _M_AMD64\n");
    ASSERT(FALSE);

#else /* _X86_ */

/* Print the memory layout */

DPRINT1("%p - %p (%X) %s\n", KSEG0_BASE,          _BootImageEnd,       MmBootImageSize,             "Boot Loaded Image");
DPRINT1("%p - %p (%X) %s\n", MmPfnDatabase,       _PfnDatabaseEnd,    _PfnDatabaseSize,             "PFN Database");
DPRINT1("%p - %p (%X) %s\n", MmNonPagedPoolStart, _NPagedPoolEnd,      MmSizeOfNonPagedPoolInBytes, "ARM3 Non Paged Pool");
DPRINT1("%p - %p (%X) %s\n", MiSystemViewStart,   _SystemViewEnd,      MmSystemViewSize,            "System View Space");
DPRINT1("%p - %p (%X) %s\n", MmSessionBase,        MiSessionSpaceEnd, _SessionSize,                 "Session Space");
DPRINT1("%p - %p (%X) %s\n", PTE_BASE,             PTE_TOP,           _PageTablesSize,              "Page Tables");
DPRINT1("%p - %p (%X) %s\n", PDE_BASE,             PDE_TOP,           _PageDirectoriesSize,         "Page Directories");
DPRINT1("%p - %p (%X) %s\n", HYPER_SPACE,          HYPER_SPACE_END,   _HyperspaceSize,              "Hyperspace");
DPRINT1("%p - %p (%X) %s\n", MmSystemCacheStart,   MmSystemCacheEnd,  _SystemCacheSize,             "System Cache");
DPRINT1("%p - %p (%X) %s\n", MmPagedPoolStart,    _PagedPoolEnd,       MmSizeOfPagedPoolInBytes,    "ARM3 Paged Pool");

DPRINT1("%p - %p (%X) %s\n", MmNonPagedSystemStart, MmNonPagedPoolExpansionStart, _SystemPteSize,   "System PTE Space");
DPRINT1("%p - %p (%X) %s\n", MmNonPagedPoolExpansionStart, MmNonPagedPoolEnd, _NPagedPoolExtSize,   "Non Paged Pool Expansion PTE Space");

#endif

}

CODE_SEG("INIT")
NTSTATUS
NTAPI
MmInitBsmThread(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle;
    NTSTATUS Status;

    /* Create the thread */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    Status = PsCreateSystemThread(&ThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  &ObjectAttributes,
                                  NULL,
                                  NULL,
                                  KeBalanceSetManager,
                                  NULL);

    /* Close the handle and return status */
    ZwClose(ThreadHandle);

    return Status;
}

CODE_SEG("INIT")
BOOLEAN
NTAPI
MmInitSystem(
    _In_ ULONG Phase,
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PLDR_DATA_TABLE_ENTRY DataTableEntry;
    PLIST_ENTRY ListEntry;
    MMPTE TempPte = ValidKernelPte;
    PMMPTE Pte;
    PMMPFN Pfn;
    PFN_NUMBER PageFrameNumber;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT1("MmInitSystem: Phase %X, LoaderBlock %X\n", Phase, LoaderBlock);

    /* Initialize the kernel address space */
    ASSERT(Phase == 1);

    MmKernelAddressSpace = &PsIdleProcess->Vm;

    /* Dump the address space */
    MiDbgDumpAddressSpace();

    MmInitGlobalKernelPageDirectory();

    MiInitializeUserPfnBitmap();
    MmInitializeMemoryConsumer(MC_USER, MmTrimUserMemory);

    Status = MmInitSectionImplementation();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmInitSystem: Status %X\n", Status);
        return FALSE;
    }

    MmInitPagingFile();

    /* Create a PTE to double-map the shared data section.
       We allocate it from paged pool so that we can't fault when trying to touch the PTE itself (to map it),
       since paged pool addresses will already be mapped by the fault handler.
    */
    MmSharedUserDataPte = ExAllocatePoolWithTag(PagedPool, sizeof(MMPTE), TAG_MM);
    if (!MmSharedUserDataPte)
    {
        DPRINT1("MmInitSystem: Allocate failed\n");
        return FALSE;
    }

    /* Now get the PTE for shared data, and read the PFN that holds it */
    Pte = MiAddressToPte((PVOID)KI_USER_SHARED_DATA);
    ASSERT(Pte->u.Hard.Valid == 1);
    PageFrameNumber = PFN_FROM_PTE(Pte);

    /* Build the PTE */

    /* Only valid for kernel, non-session PTEs */
    ASSERT(Pte > MiHighestUserPte);
    ASSERT(!MI_IS_SESSION_PTE(Pte));
    ASSERT((Pte < (PMMPTE)PDE_BASE) || (Pte > (PMMPTE)PDE_TOP));

    /* Start fresh */
    TempPte.u.Long = 0;
    TempPte.u.Hard.Valid = 1;
    TempPte.u.Hard.Accessed = 1;

    /* Set the protection and page */
    TempPte.u.Hard.PageFrameNumber = PageFrameNumber;
    TempPte.u.Long |= MmProtectToPteMask[MM_READONLY];
    //FIXME MmPteGlobal

    /* Write the PTE */
    *MmSharedUserDataPte = TempPte;
    DPRINT1("MmInitSystem: %p, %p, %X, %X\n", KI_USER_SHARED_DATA, Pte, PageFrameNumber, TempPte.u.Long);

    Pfn = MI_PFN_ELEMENT(PageFrameNumber);

    OldIrql = MiLockPfnDb(APC_LEVEL);
    MI_MAKE_SOFTWARE_PTE(&Pfn->OriginalPte, MM_READWRITE);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    DPRINT1("MmInitSystem: %p, %X\n", Pfn, Pfn->OriginalPte.u.Long);

    if (MmHighestUserAddress < (PVOID)MM_SHARED_USER_DATA_VA)
    {
        DPRINT1("MmInitSystem: FIXME\n");
        ASSERT(FALSE);
    }

    /* Initialize wide addresses of session  */
    MiInitializeSessionWideAddresses();

    /* Initialize session working set support */
    MiInitializeSessionWsSupport();

    /* Setup session IDs */
    MiInitializeSessionIds();

    /* Setup the memory threshold events */
    if (!MiInitializeMemoryEvents())
        return FALSE;

    /* Unmap low memory */
    MiInitBalancerThread();

    /* Initialize the balance set manager */
    MmInitBsmThread();

    /* Loop the boot loaded images */
    for (ListEntry = PsLoadedModuleList.Flink;
         ListEntry != &PsLoadedModuleList;
         ListEntry = ListEntry->Flink)
    {
        /* Get the data table entry */
        DataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        /* Set up the image protection */
        MiWriteProtectSystemImage(DataTableEntry->DllBase);
    }

    return TRUE;
}

/* EOF */
