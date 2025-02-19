
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

KEVENT MmZeroingPageEvent;

extern MM_MEMORY_CONSUMER MiMemoryConsumers[MC_MAXIMUM];
extern ULONG MmSecondaryColorMask;
extern MMPFNLIST MmFreePageListHead;
extern MMPFNLIST MmZeroedPageListHead;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGELK, MiFreeInitializationCode)
  #pragma alloc_text(INIT, MiFindInitializationCode)
#endif

CODE_SEG("PAGELK")
VOID
NTAPI
MiFreeInitializationCode(
    _In_ PVOID InitStart,
    _In_ PVOID InitEnd)
{
    PMMPTE Pte;
    PFN_NUMBER PagesFreed;

    DPRINT("MiFreeInitializationCode: ... \n");

    /* Get the start PTE */
    Pte = MiAddressToPte(InitStart);

    if (MI_IS_PHYSICAL_ADDRESS(InitStart))
    {
        DPRINT1("MiFreeInitializationCode: FIXME\n");
        ASSERT(MI_IS_PHYSICAL_ADDRESS(InitStart) == FALSE);
    }

    /*  Compute the number of pages we expect to free */
    PagesFreed = (PFN_NUMBER)(MiAddressToPte(InitEnd) - Pte);

    /* Try to actually free them */
    PagesFreed = MiDeleteSystemPageableVm(Pte, PagesFreed, 0, NULL);
}

CODE_SEG("INIT")
VOID
NTAPI
MiFindInitializationCode(
    _Out_ PVOID* OutStartVa,
    _Out_ PVOID* OutEndVa)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PIMAGE_SECTION_HEADER Section;
    PIMAGE_SECTION_HEADER LastSection;
    PIMAGE_SECTION_HEADER InitSection;
    PIMAGE_NT_HEADERS NtHeader;
    PLIST_ENTRY NextEntry;
    ULONG_PTR DllBase;
    ULONG_PTR InitStart;
    ULONG_PTR InitEnd;
    ULONG_PTR ImageEnd;
    ULONG_PTR InitCode;
    ULONG Size;
    ULONG SectionCount;
    ULONG Alignment;
    BOOLEAN InitFound;

    DBG_UNREFERENCED_LOCAL_VARIABLE(InitSection);

    DPRINT("MiFindInitializationCode()\n");

    /* So we don't free our own code yet */
    InitCode = (ULONG_PTR)&MiFindInitializationCode;

    /* Assume failure */
    *OutStartVa = NULL;

    /* Enter a critical region while we loop the list */
    KeEnterCriticalRegion();

    /* Loop all loaded modules */
    NextEntry = PsLoadedModuleList.Flink;
    while (NextEntry != &PsLoadedModuleList)
    {
        /* Get the loader entry and its DLL base */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        /* Only process boot loaded images. Other drivers are processed by MmFreeDriverInitialization */
        if (LdrEntry->Flags & LDRP_MM_LOADED)
        {
            /* Keep going */
            NextEntry = NextEntry->Flink;
            continue;
        }

        DllBase = (ULONG_PTR)LdrEntry->DllBase;

        /* Get the NT header */
        NtHeader = RtlImageNtHeader((PVOID)DllBase);
        if (!NtHeader)
        {
            /* Keep going */
            NextEntry = NextEntry->Flink;
            continue;
        }

        /* Get the first section, the section count, and scan them all */
        Section = IMAGE_FIRST_SECTION(NtHeader);

        InitStart = 0;

        SectionCount = NtHeader->FileHeader.NumberOfSections;
        while (SectionCount > 0)
        {
            /* Assume failure */
            InitFound = FALSE;

            /* Is this the INIT section or a discardable section? */
            if ((strncmp((PCCH)Section->Name, "INIT", 5) == 0) ||
                ((Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)))
            {
                /* Remember this */
                InitFound = TRUE;
                InitSection = Section;
            }
            else if (*(PULONG)Section->Name == 'EGAP')
            {
                if (Section->Name[4] == 'V' &&
                    Section->Name[5] == 'R' &&
                    Section->Name[6] == 'F')
                {
                    DPRINT1("MiFindInitializationCode: FIXME\n");
                    //ASSERT(FALSE);
                    UNIMPLEMENTED_ONCE;
                }
                else if (*(PULONG)&Section->Name[4] == 'CEPS')
                {
                    DPRINT1("MiFindInitializationCode: FIXME\n");
                    ASSERT(FALSE);
                }
            }

            if (!InitFound)
                goto Next;

            /* Pick the biggest size -- either raw or virtual */
            Size = max(Section->SizeOfRawData, Section->Misc.VirtualSize);

            /* Read the section alignment */
            Alignment = NtHeader->OptionalHeader.SectionAlignment;

            /* Get the start and end addresses */
            InitStart = (DllBase + Section->VirtualAddress);
            InitEnd = ALIGN_UP_BY((InitStart + Size), Alignment);

            /* Align the addresses to PAGE_SIZE */
            InitStart = ALIGN_UP_BY(InitStart, PAGE_SIZE);
            InitEnd = ALIGN_DOWN_BY(InitEnd, PAGE_SIZE);

            /* Have we reached the last section? */
            if (SectionCount == 1)
            {
                /* Remember this */
                LastSection = Section;
            }
            else
            {
                /* We have not, loop all the sections */
                LastSection = NULL;

                do
                {
                    /* Keep going until we find a non-discardable section range */
                    SectionCount--;
                    Section++;

                    if (Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                        /* Discardable, so record it, then keep going */
                        LastSection = Section;
                    else
                        /* Non-contigous discard flag, or no flag, break out */
                        break;
                }
                while (SectionCount > 1);
            }

            /* Have we found a discardable or init section? */
            if (LastSection)
            {
                /* Pick the biggest size -- either raw or virtual */
                Size = max(LastSection->SizeOfRawData, LastSection->Misc.VirtualSize);

                /* Use this as the end of the section address */
                InitEnd = (DllBase + LastSection->VirtualAddress + Size);

                /* Have we reached the last section yet? */
                if (SectionCount != 1)
                {
                    /* Then align this accross the session boundary */
                    InitEnd = ALIGN_UP_BY(InitEnd, Alignment);
                    InitEnd = ALIGN_DOWN_BY(InitEnd, PAGE_SIZE);
                }
            }

            /* Make sure we don't let the init section go past the image */
            ImageEnd = DllBase + LdrEntry->SizeOfImage;

            if (InitEnd > ImageEnd)
                InitEnd = ALIGN_UP_BY(ImageEnd, PAGE_SIZE);

            /* Make sure we have a valid, non-zero init section */
            if (InitStart >= InitEnd)
                goto Next;

            /* Make sure we are not within this code itself */
            if (InitCode >= InitStart && InitCode < InitEnd)
            {
                /* Return it, we can't free ourselves now */
                ASSERT(*OutStartVa == NULL);

                *OutStartVa = (PVOID)InitStart;
                *OutEndVa = (PVOID)InitEnd;

                goto Next;
            }

            /* This isn't us -- go ahead and free it */
            if (!MI_IS_PHYSICAL_ADDRESS((PVOID)InitStart))
            {
                DPRINT("Freeing init code: %p-%p ('%wZ' @%p : '%s')\n",
                       (PVOID)InitStart, (PVOID)InitEnd, &LdrEntry->BaseDllName, LdrEntry->DllBase, InitSection->Name);

                MiFreeInitializationCode((PVOID)InitStart, (PVOID)InitEnd);
            }
            else
            {
                DPRINT1("MiFindInitializationCode: FIXME\n");
                ASSERT(MI_IS_PHYSICAL_ADDRESS((PVOID)InitStart) == FALSE);
            }
Next:
            /* Move to the next section */
            SectionCount--;
            Section++;
        }

        /* Move to the next module */
        NextEntry = NextEntry->Flink;
    }

    /* Leave the critical region and return */
    KeLeaveCriticalRegion();
}

VOID
NTAPI
MmZeroPageThread(VOID)
{
    PKTHREAD Thread = KeGetCurrentThread();
    PVOID StartAddress, EndAddress;
    PVOID WaitObjects[2];
    KIRQL OldIrql;
    PVOID ZeroAddress;
    PFN_NUMBER PageIndex, FreePage;
    PMMPFN Pfn1;

    /* Get the discardable sections to free them */
    MiFindInitializationCode(&StartAddress, &EndAddress);

    if (StartAddress)
        MiFreeInitializationCode(StartAddress, EndAddress);

    DPRINT("Free non-cache pages: %lx\n", MmAvailablePages + MiMemoryConsumers[MC_CACHE].PagesUsed);

    /* Set our priority to 0 */
    Thread->BasePriority = 0;
    KeSetPriorityThread(Thread, 0);

    /* Setup the wait objects */
    WaitObjects[0] = &MmZeroingPageEvent;
//    WaitObjects[1] = &PoSystemIdleTimer; FIXME: Implement idle timer

    while (TRUE)
    {
        KeWaitForMultipleObjects(1, // 2
                                 WaitObjects,
                                 WaitAny,
                                 WrFreePage,
                                 KernelMode,
                                 FALSE,
                                 NULL,
                                 NULL);

        OldIrql = MiLockPfnDb(APC_LEVEL);

        while (TRUE)
        {
            if (!MmFreePageListHead.Total)
            {
                KeClearEvent(&MmZeroingPageEvent);
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                break;
            }

            PageIndex = MmFreePageListHead.Flink;
            ASSERT(PageIndex != LIST_HEAD);
            Pfn1 = MiGetPfnEntry(PageIndex);
            MI_SET_USAGE(MI_USAGE_ZERO_LOOP);
            MI_SET_PROCESS2("Kernel 0 Loop");

            FreePage = MiRemoveAnyPage(MI_GET_PAGE_COLOR(PageIndex));

            /* The first global free page should also be the first on its own list */
            if (FreePage != PageIndex)
            {
                KeBugCheckEx(PFN_LIST_CORRUPT, 0x8F, FreePage, PageIndex, 0);
            }

            Pfn1->u1.Flink = LIST_HEAD;
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            ZeroAddress = MiMapPagesInZeroSpace(Pfn1, 1);
            ASSERT(ZeroAddress);
            RtlZeroMemory(ZeroAddress, PAGE_SIZE);
            MiUnmapPagesInZeroSpace(ZeroAddress, 1);

            OldIrql = MiLockPfnDb(APC_LEVEL);

            MiInsertPageInList(&MmZeroedPageListHead, PageIndex);
        }
    }
}

/* EOF */
