
#pragma once

/* TYPES *********************************************************************/

/* Make the code cleaner with some definitions for size multiples */
#define _1KB (1024u)
#define _1MB (1024 * _1KB)
#define _1GB (1024 * _1MB)
#define _1TB (1024ull * _1GB)
#define _1PB (1024ull * _1TB)

/* Everyone loves 64K */
#define _64K (64 * _1KB)

/* System views are binned into 64K chunks*/
#define MI_SYSTEM_VIEW_BUCKET_SIZE  _64K

/* Number of pages in one unit of the system cache */
#define MM_PAGES_PER_VACB  (VACB_MAPPING_GRANULARITY / PAGE_SIZE)

#define MI_LOWEST_VAD_ADDRESS (PVOID)MM_LOWEST_USER_ADDRESS

/* Number of bytes for subsection sector of image file */
#define MM_SECTOR_SIZE (0x200)

/* Protection Bits part of the internal memory manager Protection Mask, from:
   http://reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel
   https://www.reactos.org/wiki/Techwiki:Memory_Protection_constants
   and public assertions.
*/
#define MM_ZERO_ACCESS         0
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7
#define MM_PROTECT_ACCESS      7

/* These are flags on top of the actual protection mask */
#define MM_NOCACHE            0x08
#define MM_GUARDPAGE          0x10
#define MM_WRITECOMBINE       0x18
#define MM_PROTECT_SPECIAL    0x18

/* These are special cases */
#define MM_DECOMMIT           (MM_ZERO_ACCESS | MM_GUARDPAGE)
#define MM_NOACCESS           (MM_ZERO_ACCESS | MM_WRITECOMBINE)
#define MM_OUTSWAPPED_KSTACK  (MM_EXECUTE_WRITECOPY | MM_WRITECOMBINE)
#define MM_INVALID_PROTECTION  0xFFFFFFFF

/* Specific PTE Definitions that map to the Memory Manager's Protection Mask Bits.
   The Memory Manager's definition define the attributes that must be preserved
   and these PTE definitions describe the attributes in the hardware sense.
   This helps deal with hardware differences between the actual boolean expression of the argument.

   For example, in the logical attributes, we want to express read-only as a flag but on x86,
   it is writability that must be set. On the other hand, on x86, just like in the kernel,
   it is disabling the caches that requires a special flag, while on certain architectures such as ARM,
   it is enabling the cache which requires a flag.
*/

#if defined(_M_IX86)

/* Access Flags */
#define PTE_READONLY            0 // Doesn't exist on x86
#define PTE_EXECUTE             0 // Not worrying about NX yet
#define PTE_EXECUTE_READ        0 // Not worrying about NX yet
#if defined(ONE_CPU)
#define PTE_READWRITE           0x2
#define PTE_EXECUTE_READWRITE   0x2
#else
#define PTE_READWRITE           0x800
#define PTE_EXECUTE_READWRITE   0x800
#endif
#define PTE_WRITECOPY           0x200
#define PTE_EXECUTE_WRITECOPY   0x200
#define PTE_PROTOTYPE           0x400

/* State Flags */
#define PTE_VALID               0x1
#define PTE_ACCESSED            0x20
#if defined(ONE_CPU)
#define PTE_DIRTY               0x40
#else
#define PTE_DIRTY               0x42
#endif

/* Cache flags */
#define PTE_ENABLE_CACHE        0
#define PTE_DISABLE_CACHE       0x10
#define PTE_WRITECOMBINED_CACHE 0x10
#define PTE_PROTECT_MASK        0x612

#else
  #error Define these please!
#endif

extern const ULONG_PTR MmProtectToPteMask[32];
extern const ULONG MmProtectToValue[32];
extern PMMPTE MiSessionBasePte;
extern PMMPTE MiSessionLastPte;
extern PVOID MmSessionBase;
extern PVOID MiSessionSpaceEnd;

#define HYDRA_PROCESS (PEPROCESS)1

/* Assertions for session images, addresses, and PTEs */
#define MI_IS_SESSION_IMAGE_ADDRESS(Address) \
    (((Address) >= MiSessionImageStart) && ((Address) < MiSessionImageEnd))

#define MI_IS_SESSION_ADDRESS(Address) \
    (((Address) >= MmSessionBase) && ((Address) < MiSessionSpaceEnd))

#define MI_IS_SESSION_PTE(Pte) \
    ((((PMMPTE)Pte) >= MiSessionBasePte) && (((PMMPTE)Pte) < MiSessionLastPte))

#define MI_IS_PAGE_TABLE_ADDRESS(Address) \
    (((PVOID)(Address) >= (PVOID)PTE_BASE) && ((PVOID)(Address) <= (PVOID)PTE_TOP))

#define MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address) \
    (((Address) >= (PVOID)MiAddressToPte(MmSystemRangeStart)) && ((Address) <= (PVOID)PTE_TOP))

#define MI_IS_PAGE_TABLE_OR_HYPER_ADDRESS(Address) \
    (((PVOID)(Address) >= (PVOID)PTE_BASE) && ((PVOID)(Address) <= (PVOID)MmHyperSpaceEnd))

#define InterlockedExchangePte(Pte, Value) \
    InterlockedExchange((PLONG)(Pte), Value)

/* Creates a software PTE with the given protection */
#define MI_MAKE_SOFTWARE_PTE(p, x)  ((p)->u.Long = (x << MM_PTE_SOFTWARE_PROTECTION_BITS))

/* Marks a PTE as deleted */
#define MI_SET_PFN_DELETED(x)       ((x)->PteAddress = (PMMPTE)((ULONG_PTR)(x)->PteAddress | 1))
#define MI_IS_PFN_DELETED(x)        ((ULONG_PTR)((x)->PteAddress) & 1)

#ifdef __REACTOS__
  #define MI_IS_ROS_PFN(x)          ((x)->u4.AweAllocation == TRUE)
#endif

/* Special values for LoadedImports */
#ifdef _WIN64
  #define MM_SYSLDR_NO_IMPORTS   (PVOID)0xFFFFFFFFFFFFFFFEULL
  #define MM_SYSLDR_BOOT_LOADED  (PVOID)0xFFFFFFFFFFFFFFFFULL
#else
  #define MM_SYSLDR_NO_IMPORTS   (PVOID)0xFFFFFFFE
  #define MM_SYSLDR_BOOT_LOADED  (PVOID)0xFFFFFFFF
#endif

#define MM_SYSLDR_SINGLE_ENTRY 0x1

#if defined(_M_IX86) || defined(_M_ARM)
  /* PFN List Sentinel */
  #define LIST_HEAD 0xFFFFFFFF

  /* Because GCC cannot automatically downcast 0xFFFFFFFF to lesser-width bits,
     we need a manual definition suited to the number of bits in the PteFrame.
     This is used as a LIST_HEAD for the colored list
  */
  #define COLORED_LIST_HEAD ((1 << 25) - 1)    // 0x1FFFFFF
#elif defined(_M_AMD64)
  #define LIST_HEAD 0xFFFFFFFFFFFFFFFFLL
  #define COLORED_LIST_HEAD ((1ULL << 57) - 1) // 0x1FFFFFFFFFFFFFFLL
#else
  #error Define these please!
#endif

/* Returns the color of a page */
#define MI_GET_PAGE_COLOR(x)          ((x) & MmSecondaryColorMask)
#if defined(ONE_CPU)
  #define MI_GET_NEXT_COLOR()         (MI_GET_PAGE_COLOR(++MmSystemPageColor))
#else
  #define MI_GET_NEXT_COLOR()         (MI_GET_PAGE_COLOR(++KeGetCurrentPrcb()->PageColor))
#endif
#define MI_GET_NEXT_PROCESS_COLOR(x)  (MI_GET_PAGE_COLOR(++(x)->NextPageColor))

FORCEINLINE
ULONG
MiGetColor(VOID)
{
  #if !defined(ONE_CPU)
    PKPRCB Prcb = KeGetCurrentPrcb();
  #endif
    ULONG Color;

  #if defined(ONE_CPU)
    Color = MI_GET_PAGE_COLOR(++MmSystemPageColor);
  #else
    Prcb->PageColor++;
    Color = ((Prcb->PageColor & Prcb->SecondaryColorMask) | Prcb->NodeShiftedColor);
  #endif

   return Color;
}

/* Prototype PTEs that don't yet have a pagefile association */
#ifdef _WIN64
  #define MI_PTE_LOOKUP_NEEDED 0xffffffffULL
#else
  #define MI_PTE_LOOKUP_NEEDED 0xFFFFF
#endif

/* Used by MiCheckSecuredVad */
#define MM_READ_WRITE_ALLOWED   11
#define MM_READ_ONLY_ALLOWED    10
#define MM_NO_ACCESS_ALLOWED    01
#define MM_DELETE_CHECK         85

/* These two mappings are actually used by Windows itself, based on the ASSERTS */
#define StartOfAllocation ReadInProgress
#define EndOfAllocation WriteInProgress

#define MiGetPteContents(Pte) \
    (ULONGLONG)((Pte != NULL) ? (Pte->u.Long) : (0))

#define WSLE_NULL_INDEX     0x0FFFFFFF
#define MM_WS_NOT_LISTED    NULL
#define MM_FREE_WSLE_SHIFT  4

/* FIXFIX: These should go in ex.h after the pool merge */

#ifdef _WIN64
  #define POOL_BLOCK_SIZE 16
#else
  #define POOL_BLOCK_SIZE  8
#endif

#define POOL_LISTS_PER_PAGE (PAGE_SIZE / POOL_BLOCK_SIZE)
#define BASE_POOL_TYPE_MASK 1
#define POOL_MAX_ALLOC      (PAGE_SIZE - (sizeof(POOL_HEADER) + POOL_BLOCK_SIZE))

/* Pool debugging/analysis/tracing flags */
#define POOL_FLAG_CHECK_TIMERS         0x01
#define POOL_FLAG_CHECK_WORKERS        0x02
#define POOL_FLAG_CHECK_RESOURCES      0x04
#define POOL_FLAG_VERIFIER             0x08
#define POOL_FLAG_CHECK_DEADLOCK       0x10
#define POOL_FLAG_SPECIAL_POOL         0x20
#define POOL_FLAG_DBGPRINT_ON_FAILURE  0x40
#define POOL_FLAG_CRASH_ON_FAILURE     0x80

/* BAD_POOL_HEADER codes during pool bugcheck */
#define POOL_CORRUPTED_LIST                3
#define POOL_SIZE_OR_INDEX_MISMATCH        5
#define POOL_ENTRIES_NOT_ALIGNED_PREVIOUS  6
#define POOL_HEADER_NOT_ALIGNED            7
#define POOL_HEADER_IS_ZERO                8
#define POOL_ENTRIES_NOT_ALIGNED_NEXT      9
#define POOL_ENTRY_NOT_FOUND               10

/* BAD_POOL_CALLER codes during pool bugcheck */
#define POOL_ENTRY_CORRUPTED         1
#define POOL_ENTRY_ALREADY_FREE      6
#define POOL_ENTRY_NOT_ALLOCATED     7
#define POOL_ALLOC_IRQL_INVALID      8
#define POOL_FREE_IRQL_INVALID       9
#define POOL_BILLED_PROCESS_INVALID  13
#define POOL_HEADER_SIZE_INVALID     32

typedef struct _POOL_DESCRIPTOR
{
    POOL_TYPE PoolType;
    ULONG PoolIndex;
    ULONG RunningAllocs;
    ULONG RunningDeAllocs;
    ULONG TotalPages;
    ULONG TotalBigPages;
    ULONG Threshold;
    PVOID LockAddress;
    PVOID PendingFrees;
    LONG PendingFreeDepth;
    SIZE_T TotalBytes;
    SIZE_T Spare0;
    LIST_ENTRY ListHeads[POOL_LISTS_PER_PAGE];
} POOL_DESCRIPTOR, *PPOOL_DESCRIPTOR;

typedef struct _POOL_HEADER
{
    union
    {
        struct
        {
          #ifdef _WIN64
            USHORT PreviousSize:8;
            USHORT PoolIndex:8;
            USHORT BlockSize:8;
            USHORT PoolType:8;
          #else
            USHORT PreviousSize:9;
            USHORT PoolIndex:7;
            USHORT BlockSize:9;
            USHORT PoolType:7;
          #endif
        };
        ULONG Ulong1;
    };
  #ifdef _WIN64
    ULONG PoolTag;
  #endif
    union
    {
      #ifdef _WIN64
        PEPROCESS ProcessBilled;
      #else
        ULONG PoolTag;
      #endif
        struct
        {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER, *PPOOL_HEADER;

C_ASSERT(sizeof(POOL_HEADER) == POOL_BLOCK_SIZE);
C_ASSERT(POOL_BLOCK_SIZE == sizeof(LIST_ENTRY));

typedef struct _POOL_TRACKER_TABLE
{
    ULONG Key;
    LONG NonPagedAllocs;
    LONG NonPagedFrees;
    SIZE_T NonPagedBytes;
    LONG PagedAllocs;
    LONG PagedFrees;
    SIZE_T PagedBytes;
} POOL_TRACKER_TABLE, *PPOOL_TRACKER_TABLE;

/* END FIXFIX */

typedef enum _MMSYSTEM_PTE_POOL_TYPE
{
    SystemPteSpace,
    NonPagedPoolExpansion,
    MaximumPtePoolTypes
} MMSYSTEM_PTE_POOL_TYPE;

typedef enum _MI_PFN_CACHE_ATTRIBUTE
{
    MiNonCached,
    MiCached,
    MiWriteCombined,
    MiNotMapped
} MI_PFN_CACHE_ATTRIBUTE, *PMI_PFN_CACHE_ATTRIBUTE;

typedef struct _PHYSICAL_MEMORY_RUN
{
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
} PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR
{
    ULONG NumberOfRuns;
    PFN_NUMBER NumberOfPages;
    PHYSICAL_MEMORY_RUN Run[1];
} PHYSICAL_MEMORY_DESCRIPTOR, *PPHYSICAL_MEMORY_DESCRIPTOR;

typedef struct _MMCOLOR_TABLES
{
    PFN_NUMBER Flink;
    PVOID Blink;
    PFN_NUMBER Count;
} MMCOLOR_TABLES, *PMMCOLOR_TABLES;

typedef struct _MMVIEW
{
    ULONG_PTR Entry;
    PCONTROL_AREA ControlArea;
} MMVIEW, *PMMVIEW;

typedef struct _MMSESSION
{
    KGUARDED_MUTEX SystemSpaceViewLock;
    PKGUARDED_MUTEX SystemSpaceViewLockPointer;
    PCHAR SystemSpaceViewStart;
    PMMVIEW SystemSpaceViewTable;
    ULONG SystemSpaceHashSize;
    ULONG SystemSpaceHashEntries;
    ULONG SystemSpaceHashKey;
    ULONG BitmapFailures;
    PRTL_BITMAP SystemSpaceBitMap;
} MMSESSION, *PMMSESSION;

typedef struct _MM_SESSION_SPACE_FLAGS
{
    ULONG Initialized:1;
    ULONG DeletePending:1;
    ULONG Filler:30;
} MM_SESSION_SPACE_FLAGS;

typedef struct _MM_SESSION_SPACE
{
    struct _MM_SESSION_SPACE *GlobalVirtualAddress;
    LONG ReferenceCount;
    union
    {
        ULONG LongFlags;
        MM_SESSION_SPACE_FLAGS Flags;
    } u;
    ULONG SessionId;
    LIST_ENTRY ProcessList;
    LARGE_INTEGER LastProcessSwappedOutTime;
    PFN_NUMBER SessionPageDirectoryIndex;
    SIZE_T NonPageablePages;
    SIZE_T CommittedPages;
    PVOID PagedPoolStart;
    PVOID PagedPoolEnd;
    PMMPDE PagedPoolBasePde;
    ULONG Color;
    LONG ResidentProcessCount;
    ULONG SessionPoolAllocationFailures[4];
    LIST_ENTRY ImageList;
    LCID LocaleId;
    ULONG AttachCount;
    KEVENT AttachEvent;
    PEPROCESS LastProcess;
    LONG ProcessReferenceToSession;
    LIST_ENTRY WsListEntry;
    GENERAL_LOOKASIDE Lookaside[SESSION_POOL_LOOKASIDES];
    MMSESSION Session;
    KGUARDED_MUTEX PagedPoolMutex;
    MM_PAGED_POOL_INFO PagedPoolInfo;
    MMSUPPORT Vm;
    PMMWSLE Wsle;
    PDRIVER_UNLOAD Win32KDriverUnload;
    POOL_DESCRIPTOR PagedPool;
  #if defined (_M_AMD64)
    MMPDE PageDirectory;
  #else
    PMMPDE PageTables;
  #endif
  #if defined (_M_AMD64)
    PMMPTE SpecialPoolFirstPte;
    PMMPTE SpecialPoolLastPte;
    PMMPTE NextPdeForSpecialPoolExpansion;
    PMMPTE LastPdeForSpecialPoolExpansion;
    PFN_NUMBER SpecialPagesInUse;
  #endif
    LONG ImageLoadingCount;
} MM_SESSION_SPACE, *PMM_SESSION_SPACE;

#define MI_ASSERT_PFN_LOCK_HELD()  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL)

#if MI_TRACE_PFNS
  #error Define these please!
#else
  #define MI_SET_USAGE(x)
  #define MI_SET_PROCESS2(x)
#endif

/* Signature of a freed block */
#define MM_FREE_POOL_SIGNATURE 'ARM3'

/* Entry describing free pool memory */
typedef struct _MMFREE_POOL_ENTRY
{
    LIST_ENTRY List;
    PFN_COUNT Size;
    ULONG Signature;
    struct _MMFREE_POOL_ENTRY *Owner;
} MMFREE_POOL_ENTRY, *PMMFREE_POOL_ENTRY;

typedef struct _POOL_TRACKER_BIG_PAGES
{
    PVOID Va;
    ULONG Key;
    ULONG NumberOfPages;
    PVOID QuotaObject;
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

typedef struct _MI_PAGE_SUPPORT_BLOCK_FLAGS
{
  #ifdef _M_AMD64
     ULONGLONG InPageComplete : 1;
     ULONGLONG ReservedBit1 : 1;
     ULONGLONG ReservedBit2 : 1;
     ULONGLONG PrefetchMdlHighBits : 61;
  #else
     ULONG InPageComplete : 1;
     ULONG ReservedBit1 : 1;
     ULONG ReservedBit2 : 1;
     ULONG PrefetchMdlHighBits : 29;
  #endif
} MI_PAGE_SUPPORT_BLOCK_FLAGS;

typedef struct _MI_PAGE_SUPPORT_BLOCK
{
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER StartingOffset;
    ULONG WaitCount;
    PETHREAD CurrentThread;
    PFILE_OBJECT FilePointer;
    PMMPTE StartProto;
    PMMPFN Pfn;
    union
    {
      #ifdef _M_AMD64
        ULONGLONG LongFlags;
      #else
        ULONG LongFlags;
      #endif
        MI_PAGE_SUPPORT_BLOCK_FLAGS e1;
    } u1;
    MDL Mdl;
    PFN_NUMBER MdlPages[16];
    SINGLE_LIST_ENTRY ListEntry;
} MI_PAGE_SUPPORT_BLOCK, *PMI_PAGE_SUPPORT_BLOCK;

typedef struct _MM_PHYSICAL_VIEW
{
    union
    {
        LONG_PTR Balance:2;
        PMMVAD Parent;
    } u1;
    PMMVAD LeftChild;
    PMMVAD RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    PMMVAD Vad;
    MI_VAD_TYPE VadType;
    PVOID Reserved1;
    PVOID Reserved2;
} MM_PHYSICAL_VIEW, *PMM_PHYSICAL_VIEW;

typedef struct _MMPTE_FLUSH_LIST
{
    ULONG Count;
    PVOID FlushVa[0x21];
} MMPTE_FLUSH_LIST, *PMMPTE_FLUSH_LIST;

typedef struct _MI_LARGE_PAGE_DRIVER_ENTRY
{
    LIST_ENTRY Links;
    UNICODE_STRING BaseName;
} MI_LARGE_PAGE_DRIVER_ENTRY, *PMI_LARGE_PAGE_DRIVER_ENTRY;

#define MAX_PAGING_FILES (0x10)

/* Page file information */
typedef struct _MMPAGING_FILE
{
    PFN_NUMBER Size;
    PFN_NUMBER MaximumSize;
    PFN_NUMBER MinimumSize;
    PFN_NUMBER FreeSpace;
    PFN_NUMBER CurrentUsage;
    PFILE_OBJECT FileObject;
    UNICODE_STRING PageFileName;
    PRTL_BITMAP Bitmap;
    HANDLE FileHandle;
}
MMPAGING_FILE, *PMMPAGING_FILE;

extern PMMCOLOR_TABLES MmFreePagesByColor[FreePageList + 1];
extern PVOID MmPagedPoolStart;
extern PVOID MmNonPagedPoolEnd;
extern ULONG_PTR MmSubsectionBase;
extern ULONG MmSystemPageColor;
extern PMMPDE MiHighestUserPde;
extern PMMPTE MiHighestUserPte;
extern MMPTE MmPteGlobal;
extern MMPTE ValidKernelPte;
extern MMSUPPORT MmSystemCacheWs;
extern PMMWSL MmWorkingSetList;
extern SIZE_T MmSystemLockPagesCount;
extern ULONG MmUnusedSubsectionCount;
extern ULONG MmUnusedSubsectionCountPeak;
extern SIZE_T MiUnusedSubsectionPagedPool;
extern PFN_NUMBER MmResidentAvailablePages;

#if (_MI_PAGING_LEVELS <= 3)
  extern PFN_NUMBER MmSystemPageDirectory[PD_COUNT];
  extern PMMPDE MmSystemPagePtes;
#else
  #error FIXME
#endif

/* FUNCTIONS *****************************************************************/

#ifndef _M_AMD64

/* Builds a Prototype PTE from the poiner to section proto structure */
FORCEINLINE
VOID
MI_MAKE_PROTOTYPE_PTE(
    _In_ PMMPTE ProtoPte,
    _In_ PMMPTE SectionProto)
{
    ULONG_PTR Offset;

    /* Mark this as a prototype */
    ProtoPte->u.Long = 0;
    ProtoPte->u.Proto.Prototype = 1;

  #if !defined(_X86PAE_)
    /* Section proto structures are only valid in paged pool by design,
       this little trick lets us only use 30 bits for the adress of the PTE,
       as long as the area stays 1024 MB at most.
    */
    Offset = ((ULONG_PTR)SectionProto - (ULONG_PTR)MmPagedPoolStart);

    /* 9 bits go in the "low" (we assume the bottom 2 are zero and trim it) */
    ASSERT((Offset % 4) == 0);
    ProtoPte->u.Proto.ProtoAddressLow = ((Offset & 0x1FF) >> 2);

    /* and the other 21 bits go in the "high" field. */
    ProtoPte->u.Proto.ProtoAddressHigh = ((Offset & 0x3FFFFE00) >> 9);
  #else
    ProtoPte->u.Proto.ProtoAddress = (ULONG_PTR)SectionProto;
  #endif
}

/* Decodes a Prototype PTE into the poiner to section proto structure */
FORCEINLINE
PMMPTE
MiGetProtoPtr(
    _In_ PMMPTE SectionProto)
{
    ULONG_PTR Offset;

    /* Do MI_MAKE_PROTOTYPE_PTE() in the opposite direction. */

  #if !defined(_X86PAE_)
    Offset = (SectionProto->u.Proto.ProtoAddressHigh << 9);
    Offset += (SectionProto->u.Proto.ProtoAddressLow << 2);

    return (PMMPTE)((ULONG_PTR)MmPagedPoolStart + Offset);
  #else
    return (PMMPTE)SectionProto->u.Proto.ProtoAddress;
  #endif
}

/* Builds a Subsection PTE for the address of the Subsection */
FORCEINLINE
VOID
MI_MAKE_SUBSECTION_PTE(
    _In_ PMMPTE NewPte,
    _In_ PVOID Subsection)
{
    ULONG_PTR Offset;

    /* Mark this as a prototype */
    NewPte->u.Long = 0;
    NewPte->u.Subsect.Prototype = 1;

  #if !defined(_X86PAE_)
    /* Subsections are only in nonpaged pool (NP).
       We use the 27-bit difference either from the top or bottom of NP,
       giving a maximum of 128 MB to each delta, meaning NP cannot exceed 256 MB.
    */
    if ((ULONG_PTR)Subsection < ((ULONG_PTR)MmSubsectionBase + (128 * _1MB)))
    {
        /* MmNonPagedPoolStart ... + MmSizeOfNonPagedPoolInBytes */
        Offset = ((ULONG_PTR)Subsection - (ULONG_PTR)MmSubsectionBase);
        NewPte->u.Subsect.WhichPool = 1;
    }
    else
    {
        /* MmNonPagedPoolExpansionStart ... MmNonPagedPoolEnd */
        Offset = ((ULONG_PTR)MmNonPagedPoolEnd - (ULONG_PTR)Subsection);
        NewPte->u.Subsect.WhichPool = 0;
    }

    /* 7 bits go in the "low" (we assume the bottom 3 are zero and trim it) */
    ASSERT((Offset % 8) == 0);
    NewPte->u.Subsect.SubsectionAddressLow = ((Offset & 0x7F) >> 3);

    /* and the other 20 bits go in the "high" field */
    NewPte->u.Subsect.SubsectionAddressHigh = ((Offset & 0xFFFFF80) >> 7);
  #else
    NewPte->u.Subsect.SubsectionAddress = (ULONG_PTR)Subsection;
  #endif
}

/* Get a pointer to a Subsection from the Subsection PTE */
FORCEINLINE
PVOID
MiSubsectionPteToSubsection(
    _In_ PMMPTE SubsectionPte)
{
    ULONG_PTR Offset;

    /* Do MI_MAKE_SUBSECTION_PTE() in the opposite direction. */

  #if !defined(_X86PAE_)
    Offset = (SubsectionPte->u.Subsect.SubsectionAddressHigh << 7);
    Offset += (SubsectionPte->u.Subsect.SubsectionAddressLow << 3);

    if (SubsectionPte->u.Subsect.WhichPool == 1)
    {
        /* MmNonPagedPoolStart ... + MmSizeOfNonPagedPoolInBytes */
        return (PVOID)((ULONG_PTR)MmSubsectionBase + Offset);
    }
    else
    {
        /* MmNonPagedPoolExpansionStart ... MmNonPagedPoolEnd */
        return (PVOID)((ULONG_PTR)MmNonPagedPoolEnd - Offset);
    }
  #else
    return (PVOID)OutPte->u.Subsect.SubsectionAddress;
  #endif
}

FORCEINLINE
BOOLEAN
MI_IS_MAPPED_PTE(
    _In_ PMMPTE Pte)
{
    if (Pte->u.Soft.Valid ||
        Pte->u.Soft.Prototype ||
        Pte->u.Soft.Transition ||
      #if defined(_X86PAE_)
        Pte->u.Soft.Unused ||
      #endif
        Pte->u.Soft.PageFileHigh)
    {
        return TRUE;
    }
    else
    {
        /* Demand zero PTE */
        return FALSE;
    }
}

#endif

FORCEINLINE
VOID
MiReleasePfnLockFromDpcLevel(VOID)
{
    PKSPIN_LOCK_QUEUE LockQueue;

    ASSERT(MmPfnOwner == KeGetCurrentThread());
    MmPfnOwner = NULL;

    LockQueue = &KeGetCurrentPrcb()->LockQueue[LockQueuePfnLock];
    KeReleaseQueuedSpinLockFromDpcLevel(LockQueue);
    ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);
}

FORCEINLINE
KIRQL 
MiLockPfnDb(
    _In_ KIRQL MaximumLevel)
{
    KIRQL OldIrql;

    if (MaximumLevel == APC_LEVEL)
        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    else if (MaximumLevel == DISPATCH_LEVEL)
        ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    OldIrql = KeAcquireQueuedSpinLock(LockQueuePfnLock);

    ASSERT(MmPfnOwner == NULL);
    MmPfnOwner = KeGetCurrentThread();

    return OldIrql;
}

FORCEINLINE
VOID 
MiUnlockPfnDb(
    _In_ KIRQL OldIrql,
    _In_ KIRQL MaximumLevel)
{
    if (MaximumLevel == APC_LEVEL)
        ASSERT(OldIrql <= APC_LEVEL);
    else if (MaximumLevel == DISPATCH_LEVEL)
        ASSERT(OldIrql <= DISPATCH_LEVEL);

    ASSERT(MmPfnOwner == KeGetCurrentThread());
    MmPfnOwner = NULL;

    KeReleaseQueuedSpinLock(LockQueuePfnLock, OldIrql);

    if (MaximumLevel == APC_LEVEL)
        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    else if (MaximumLevel == DISPATCH_LEVEL)
        ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
}

FORCEINLINE
VOID 
MiUnlockPfnWithWait(KIRQL OldIrql)
{
    PKTHREAD CurrentThread;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(OldIrql <= APC_LEVEL);

    KiAcquireDispatcherLock();

    ASSERT(MmPfnOwner == KeGetCurrentThread());
    MmPfnOwner = NULL;

    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueuePfnLock]);

    CurrentThread = KeGetCurrentThread();
    CurrentThread->WaitIrql = OldIrql;
    CurrentThread->WaitNext = TRUE;
}

FORCEINLINE
KIRQL
MiAcquirePfnLock(VOID)
{
    return KeAcquireQueuedSpinLock(LockQueuePfnLock);
}

FORCEINLINE
VOID
MiReleasePfnLock(
    _In_ KIRQL OldIrql)
{
    KeReleaseQueuedSpinLock(LockQueuePfnLock, OldIrql);
}

FORCEINLINE
VOID
MiAcquirePfnLockAtDpcLevel(VOID)
{
    PKSPIN_LOCK_QUEUE LockQueue;

    ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);
    LockQueue = &KeGetCurrentPrcb()->LockQueue[LockQueuePfnLock];
    KeAcquireQueuedSpinLockAtDpcLevel(LockQueue);

    ASSERT(MmPfnOwner == NULL);
    MmPfnOwner = KeGetCurrentThread();
}

FORCEINLINE
VOID
MmLockAddressSpace(
    _In_ PMMSUPPORT AddressSpace)
{
    KeAcquireGuardedMutex(&CONTAINING_RECORD(AddressSpace, EPROCESS, Vm)->AddressCreationLock);
}

FORCEINLINE
VOID
MmUnlockAddressSpace(
    _In_ PMMSUPPORT AddressSpace)
{
    KeReleaseGuardedMutex(&CONTAINING_RECORD(AddressSpace, EPROCESS, Vm)->AddressCreationLock);
}

/* Checks if the thread already owns a working set */
FORCEINLINE
BOOLEAN
MM_ANY_WS_LOCK_HELD(
    _In_ PETHREAD Thread)
{
    /* If any of these are held, return TRUE */
    return (Thread->OwnsProcessWorkingSetExclusive ||
            Thread->OwnsProcessWorkingSetShared ||
            Thread->OwnsSystemWorkingSetExclusive ||
            Thread->OwnsSystemWorkingSetShared ||
            Thread->OwnsSessionWorkingSetExclusive ||
            Thread->OwnsSessionWorkingSetShared);
}

/* Checks if the process owns the working set lock */
FORCEINLINE
BOOLEAN
MI_WS_OWNER(
    _In_ PEPROCESS Process)
{
#if 0
    /* Check if this process is the owner, and that the thread owns the WS */
    if (!PsGetCurrentThread()->OwnsProcessWorkingSetExclusive)
    {
        DbgPrint("Thread: %p is not an owner\n", PsGetCurrentThread());
    }
#endif

    if (KeGetCurrentThread()->ApcState.Process != &Process->Pcb)
    {
        DbgPrint("Current thread %p is attached to another process %p\n", PsGetCurrentThread(), Process);
    }

    return (KeGetCurrentThread()->ApcState.Process == &Process->Pcb &&
            (PsGetCurrentThread()->OwnsProcessWorkingSetExclusive || PsGetCurrentThread()->OwnsProcessWorkingSetShared));
}

FORCEINLINE
BOOLEAN
MI_IS_WS_UNSAFE(
    _In_ PEPROCESS Process)
{
    return (Process->Vm.Flags.AcquiredUnsafe == TRUE);
}

/* Locks the working set for the given process */
FORCEINLINE
VOID
MiLockProcessWorkingSet(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Shouldn't already be owning the process working set */
    ASSERT(Thread->OwnsProcessWorkingSetShared == FALSE);
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    /* Block APCs, make sure that still nothing is already held */
    KeEnterGuardedRegion();
    ASSERT(!MM_ANY_WS_LOCK_HELD(Thread));

    /* Lock the working set */
    ExAcquirePushLockExclusive(&Process->Vm.WorkingSetMutex);

    /* Now claim that we own the lock */
    ASSERT(!MI_IS_WS_UNSAFE(Process));
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    Thread->OwnsProcessWorkingSetExclusive = TRUE;
}

FORCEINLINE
VOID
MiLockProcessWorkingSetShared(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Shouldn't already be owning the process working set */
    ASSERT(Thread->OwnsProcessWorkingSetShared == FALSE);
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    /* Block APCs, make sure that still nothing is already held */
    KeEnterGuardedRegion();
    ASSERT(!MM_ANY_WS_LOCK_HELD(Thread));

    /* Lock the working set */
    ExAcquirePushLockShared(&Process->Vm.WorkingSetMutex);

    /* Now claim that we own the lock */
    ASSERT(!MI_IS_WS_UNSAFE(Process));
    ASSERT(Thread->OwnsProcessWorkingSetShared == FALSE);
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    Thread->OwnsProcessWorkingSetShared = TRUE;
}

FORCEINLINE
VOID
MiLockProcessWorkingSetUnsafe(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Shouldn't already be owning the process working set */
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    /* APCs must be blocked, make sure that still nothing is already held */
    ASSERT(KeAreAllApcsDisabled() == TRUE);
    ASSERT(!MM_ANY_WS_LOCK_HELD(Thread));

    /* Lock the working set */
    ExAcquirePushLockExclusive(&Process->Vm.WorkingSetMutex);

    /* Now claim that we own the lock */
    ASSERT(!MI_IS_WS_UNSAFE(Process));
    Process->Vm.Flags.AcquiredUnsafe = 1;
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    Thread->OwnsProcessWorkingSetExclusive = TRUE;
}

/* Unlocks the working set for the given process */
FORCEINLINE
VOID
MiUnlockProcessWorkingSet(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Make sure we are the owner of a safe acquisition */
    ASSERT(MI_WS_OWNER(Process));
    ASSERT(!MI_IS_WS_UNSAFE(Process));

    /* The thread doesn't own it anymore */
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == TRUE);
    Thread->OwnsProcessWorkingSetExclusive = FALSE;

    /* Release the lock and re-enable APCs */
    ExReleasePushLockExclusive(&Process->Vm.WorkingSetMutex);
    KeLeaveGuardedRegion();
}

/* Unlocks the working set for the given process */
FORCEINLINE
VOID
MiUnlockProcessWorkingSetShared(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Make sure we are the owner of a safe acquisition (because shared) */
    ASSERT(MI_WS_OWNER(Process));
    ASSERT(!MI_IS_WS_UNSAFE(Process));

    /* Ensure we are in a shared acquisition */
    ASSERT(Thread->OwnsProcessWorkingSetShared == TRUE);
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    /* Don't claim the lock anylonger */
    Thread->OwnsProcessWorkingSetShared = FALSE;

    /* Release the lock and re-enable APCs */
    ExReleasePushLockShared(&Process->Vm.WorkingSetMutex);
    KeLeaveGuardedRegion();
}

FORCEINLINE
VOID
MiUnlockProcessWorkingSetUnsafe(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    /* Make sure we are the owner of an unsafe acquisition */
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(KeAreAllApcsDisabled() == TRUE);
    ASSERT(MI_WS_OWNER(Process));
    ASSERT(MI_IS_WS_UNSAFE(Process));

    /* No longer unsafe */
    Process->Vm.Flags.AcquiredUnsafe = 0;

    /* The thread doesn't own it anymore */
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == TRUE);
    Thread->OwnsProcessWorkingSetExclusive = FALSE;

    /* Release the lock but don't touch APC state */
    ExReleasePushLockExclusive(&Process->Vm.WorkingSetMutex);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
}

/* Locks the working set */
FORCEINLINE
VOID
MiLockWorkingSet(
    _In_ PETHREAD Thread,
    _In_ PMMSUPPORT WorkingSet)
{
    /* Block APCs */
    KeEnterGuardedRegion();

    /* Working set should be in global memory */
    ASSERT(MI_IS_SESSION_ADDRESS((PVOID)WorkingSet) == FALSE);

    /* Thread shouldn't already be owning something */
    ASSERT(!MM_ANY_WS_LOCK_HELD(Thread));

    /* Lock this working set */
    ExAcquirePushLockExclusive(&WorkingSet->WorkingSetMutex);

    /* Which working set is this? */
    if (WorkingSet == &MmSystemCacheWs)
    {
        /* Own the system working set */
        ASSERT((Thread->OwnsSystemWorkingSetExclusive == FALSE) &&
               (Thread->OwnsSystemWorkingSetShared == FALSE));
        Thread->OwnsSystemWorkingSetExclusive = TRUE;
    }
    else if (WorkingSet->Flags.SessionSpace)
    {
        /* Own the session working set */
        ASSERT((Thread->OwnsSessionWorkingSetExclusive == FALSE) &&
               (Thread->OwnsSessionWorkingSetShared == FALSE));
        Thread->OwnsSessionWorkingSetExclusive = TRUE;
    }
    else
    {
        /* Own the process working set */
        ASSERT((Thread->OwnsProcessWorkingSetExclusive == FALSE) &&
               (Thread->OwnsProcessWorkingSetShared == FALSE));
        Thread->OwnsProcessWorkingSetExclusive = TRUE;
    }
}

/* Unlocks the working set */
FORCEINLINE
VOID
MiUnlockWorkingSet(
    _In_ PETHREAD Thread,
    _In_ PMMSUPPORT WorkingSet)
{
    /* Working set should be in global memory */
    ASSERT(MI_IS_SESSION_ADDRESS((PVOID)WorkingSet) == FALSE);

    /* Which working set is this? */
    if (WorkingSet == &MmSystemCacheWs)
    {
        /* Release the system working set */
        ASSERT((Thread->OwnsSystemWorkingSetExclusive == TRUE) ||
               (Thread->OwnsSystemWorkingSetShared == TRUE));
        Thread->OwnsSystemWorkingSetExclusive = FALSE;
    }
    else if (WorkingSet->Flags.SessionSpace)
    {
        /* Release the session working set */
        ASSERT((Thread->OwnsSessionWorkingSetExclusive == TRUE) ||
               (Thread->OwnsSessionWorkingSetShared == TRUE));
        Thread->OwnsSessionWorkingSetExclusive = 0;
    }
    else
    {
        /* Release the process working set */
        ASSERT((Thread->OwnsProcessWorkingSetExclusive) ||
               (Thread->OwnsProcessWorkingSetShared));
        Thread->OwnsProcessWorkingSetExclusive = FALSE;
    }

    /* Release the working set lock */
    ExReleasePushLockExclusive(&WorkingSet->WorkingSetMutex);

    /* Unblock APCs */
    KeLeaveGuardedRegion();
}

FORCEINLINE
VOID
MiUnlockProcessWorkingSetForFault(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread,
    _Out_ PBOOLEAN Safe,
    _Out_ PBOOLEAN Shared)
{
    ASSERT(MI_WS_OWNER(Process));

    /* Check if the current owner is unsafe */
    if (MI_IS_WS_UNSAFE(Process))
    {
        /* Release unsafely */
        MiUnlockProcessWorkingSetUnsafe(Process, Thread);
        *Safe = FALSE;
        *Shared = FALSE;
    }
    else if (Thread->OwnsProcessWorkingSetExclusive == 1)
    {
        /* Owner is safe and exclusive, release normally */
        MiUnlockProcessWorkingSet(Process, Thread);
        *Safe = TRUE;
        *Shared = FALSE;
    }
    else
    {
        /* Owner is shared (implies safe), release normally */
        MiUnlockProcessWorkingSetShared(Process, Thread);
        *Safe = TRUE;
        *Shared = TRUE;
    }
}

FORCEINLINE
VOID
MiLockProcessWorkingSetForFault(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread,
    _In_ BOOLEAN Safe,
    _In_ BOOLEAN Shared)
{
    /* Check if this was a safe lock or not */
    if (!Safe)
    {
        /* Unsafe lock cannot be shared */
        ASSERT(Shared == FALSE);

        /* Reacquire unsafely */
        MiLockProcessWorkingSetUnsafe(Process, Thread);
        return;
    }

    if (Shared)
        /* Reacquire safely & shared */
        MiLockProcessWorkingSetShared(Process, Thread);
    else
        /* Reacquire safely */
        MiLockProcessWorkingSet(Process, Thread);
}

/* Returns the PFN Database entry for the given page number.
   Warning: This is not necessarily a valid PFN database entry!
*/
FORCEINLINE
PMMPFN
MI_PFN_ELEMENT(
    _In_ PFN_NUMBER Pfn)
{
    /* Get the entry */
    return &MmPfnDatabase[Pfn];
};

/* Drops a locked page without dereferencing it */
FORCEINLINE
VOID
MiDropLockCount(IN PMMPFN Pfn)
{
    /* This page shouldn't be locked, but it should be valid */
    ASSERT(Pfn->u3.e2.ReferenceCount != 0);
    ASSERT(Pfn->u2.ShareCount == 0);

    /* Is this the last reference to the page */
    if (Pfn->u3.e2.ReferenceCount != 1)
        return;

    /* It better not be valid */
    ASSERT(Pfn->u3.e1.PageLocation != ActiveAndValid);

    /* Is it a prototype PTE? */
    if (Pfn->u3.e1.PrototypePte &&
        Pfn->OriginalPte.u.Soft.Prototype)
    {
        InterlockedDecrementSizeT(&MmTotalCommittedPages);
    }

    /* Update the counter */
    InterlockedDecrementSizeT(&MmSystemLockPagesCount);
}

FORCEINLINE
PFN_NUMBER
MiGetPfnEntryIndex(
    _In_ PMMPFN Pfn)
{
    /* This will return the Page Frame Number (PFN) from the MMPFN */
    return (Pfn - MmPfnDatabase);
}

VOID
NTAPI
MiDecrementReferenceCount(
    _In_ PMMPFN Pfn,
    _In_ PFN_NUMBER PageFrameIndex
);

/* Drops a locked page and dereferences it */
FORCEINLINE
VOID
MiDereferencePfnAndDropLockCount(
    _In_ PMMPFN Pfn)
{
    PFN_NUMBER PageFrameIndex;
    USHORT RefCount;
    USHORT OldRefCount;

    /* Loop while we decrement the page successfully */
    do
    {
        /* There should be at least one reference */
        OldRefCount = Pfn->u3.e2.ReferenceCount;
        ASSERT(OldRefCount != 0);

        /* Are we the last one */
        if (OldRefCount == 1)
        {
            /* The page shoudln't be shared not active at this point */
            ASSERT(Pfn->u3.e2.ReferenceCount == 1);
            ASSERT(Pfn->u3.e1.PageLocation != ActiveAndValid);
            ASSERT(Pfn->u2.ShareCount == 0);

            /* Is it a prototype PTE? */
            if (Pfn->u3.e1.PrototypePte && Pfn->OriginalPte.u.Soft.Prototype)
            {
                ASSERT(MmTotalCommittedPages >= 1);
                InterlockedDecrementSizeT(&MmTotalCommittedPages);
            }

            /* Update the counter, and drop a reference the long way */
            InterlockedDecrementSizeT(&MmSystemLockPagesCount);
            PageFrameIndex = MiGetPfnEntryIndex(Pfn);
            MiDecrementReferenceCount(Pfn, PageFrameIndex);

            return;
        }

        /* Drop a reference the short way, and that's it */
        RefCount = InterlockedCompareExchange16((PSHORT)&Pfn->u3.e2.ReferenceCount, (OldRefCount - 1), OldRefCount);
        ASSERT(RefCount != 0);
    }
    while (OldRefCount != RefCount);

    /* If we got here, there should be more than one reference */
    ASSERT(RefCount > 1);

    if (RefCount != 2)
        return;

    /* Is it still being shared? */
    if (Pfn->u2.ShareCount < 1)
        return;

    /* Then it should be valid */
    ASSERT(Pfn->u3.e1.PageLocation == ActiveAndValid);

    /* Is it a prototype PTE? */
    if (Pfn->u3.e1.PrototypePte && Pfn->OriginalPte.u.Soft.Prototype)
    {
        //ASSERT(MiLockedCommit > 0);
        //MiLockedCommit--;
        ASSERT(MmTotalCommittedPages >= 1);
        InterlockedDecrementSizeT(&MmTotalCommittedPages);
    }

    /* Update the counter */
    InterlockedDecrementSizeT(&MmSystemLockPagesCount);
}

/* References a locked page and updates the counter.
   Used in MmProbeAndLockPages to handle different edge cases
*/
FORCEINLINE
VOID
MiReferenceProbedPageAndBumpLockCount(
    _In_ PMMPFN Pfn)
{
    USHORT RefCount;
    USHORT OldRefCount;
    BOOLEAN IsCommitted = FALSE;

    if (Pfn->u3.e1.PrototypePte && Pfn->OriginalPte.u.Soft.Prototype)
    {
        if (MmTotalCommittedPages > (MmTotalCommitLimit - 0x40))
        {
            if (!PsGetCurrentThread()->MemoryMaker || KeIsExecutingDpc())
            {
               DbgPrint("MiReferenceProbedPageAndBumpLockCount: Not charging commit for prototype PTE\n");
               return;
            }
        }

        InterlockedIncrementSizeT(&MmTotalCommittedPages);
        IsCommitted = TRUE;
    }

    /* More locked pages! */
    InterlockedIncrementSizeT(&MmSystemLockPagesCount);

    if (MmResidentAvailablePages <= MmSystemLockPagesCount)
    {
        InterlockedDecrementSizeT(&MmSystemLockPagesCount);

        if (IsCommitted)
        {
            ASSERT(MmTotalCommittedPages >= 1);
            InterlockedDecrementSizeT(&MmTotalCommittedPages);
        }

        DbgPrint("MiReferenceProbedPageAndBumpLockCount: Not bumping\n");
        return;
    }

    /* Loop trying to update the reference count */
    do
    {
        /* Get the current reference count, make sure it's valid */
        OldRefCount = Pfn->u3.e2.ReferenceCount;

        ASSERT(OldRefCount != 0);
        ASSERT(OldRefCount < 2500);

        /* Bump it up by one */
        RefCount = InterlockedCompareExchange16((PSHORT)&Pfn->u3.e2.ReferenceCount,
                                                (OldRefCount + 1),
                                                OldRefCount);
        ASSERT(RefCount != 0);
    }
    while (OldRefCount != RefCount);

    /* Was this the first lock attempt? If not, undo our bump */
    if (OldRefCount != 1)
    {
        InterlockedDecrementSizeT(&MmSystemLockPagesCount);

        if (IsCommitted)
        {
            ASSERT(MmTotalCommittedPages >= 1);
            InterlockedDecrementSizeT(&MmTotalCommittedPages);
        }
    }
}

/* References a locked page and updates the counter.
   Used in all other cases except MmProbeAndLockPages.
*/
FORCEINLINE
VOID
MiReferenceUsedPageAndBumpLockCount(
    _In_ PMMPFN Pfn)
{
    USHORT NewRefCount;
    BOOLEAN IsCommitted = FALSE;

    if (Pfn->u3.e1.PrototypePte && Pfn->OriginalPte.u.Soft.Prototype)
    {
        InterlockedIncrementSizeT(&MmTotalCommittedPages);
        IsCommitted = TRUE;
    }

    /* More locked pages! */
    InterlockedIncrementSizeT(&MmSystemLockPagesCount);

    /* Update the reference count */
    NewRefCount = InterlockedIncrement16((PSHORT)&Pfn->u3.e2.ReferenceCount);

    if (NewRefCount == 2)
    {
        /* Is it locked or shared? */
        if (Pfn->u2.ShareCount)
        {
            /* It's shared, so make sure it's active */
            ASSERT(Pfn->u3.e1.PageLocation == ActiveAndValid);
        }
        else
        {
            /* It's locked, so we shouldn't lock again */
            InterlockedDecrementSizeT(&MmSystemLockPagesCount);

            if (IsCommitted)
            {
                ASSERT(MmTotalCommittedPages >= 1);
                InterlockedDecrementSizeT(&MmTotalCommittedPages);
            }
        }
    }
    else
    {
        /* Someone had already locked the page, so undo our bump */
        ASSERT(NewRefCount < 2500); // ASSERT(NewRefCount < (MmReferenceCountCheck + 0x400));

        InterlockedDecrementSizeT(&MmSystemLockPagesCount);

        if (IsCommitted)
        {
            ASSERT(MmTotalCommittedPages >= 1);
            InterlockedDecrementSizeT(&MmTotalCommittedPages);
        }
    }
}

/* References a locked page and updates the counter
   Used in all other cases except MmProbeAndLockPages
*/
FORCEINLINE
VOID
MiReferenceUnusedPageAndBumpLockCount(
    _In_ PMMPFN Pfn)
{
    USHORT NewRefCount;
    BOOLEAN IsCommitted = FALSE;

    /* Make sure the page isn't used yet */
    ASSERT(Pfn->u2.ShareCount == 0);
    ASSERT(Pfn->u3.e1.PageLocation != ActiveAndValid);

    if (Pfn->u3.e1.PrototypePte && Pfn->OriginalPte.u.Soft.Prototype)
    {
        InterlockedIncrementSizeT(&MmTotalCommittedPages);
        IsCommitted = TRUE;
    }

    /* More locked pages! */
    InterlockedIncrementSizeT(&MmSystemLockPagesCount);

    /* Update the reference count */
    NewRefCount = InterlockedIncrement16((PSHORT)&Pfn->u3.e2.ReferenceCount);
    if (NewRefCount != 1)
    {
        /* Someone had already locked the page, so undo our bump */
        ASSERT(NewRefCount < 2500); // ASSERT(NewRefCount < (MmReferenceCountCheck + 0x400));

        InterlockedDecrementSizeT(&MmSystemLockPagesCount);

        if (IsCommitted)
        {
            ASSERT(MmTotalCommittedPages >= 1);
            InterlockedDecrementSizeT(&MmTotalCommittedPages);
        }
    }
}

#ifdef _M_AMD64
  #error FIXME
#else
FORCEINLINE
BOOLEAN
MiIsUserPde(PVOID Address)
{
    return ((Address >= (PVOID)MiAddressToPde(NULL)) &&
            (Address <= (PVOID)MiHighestUserPde));
}

FORCEINLINE
BOOLEAN
MiIsUserPte(PVOID Address)
{
    return (Address <= (PVOID)MiHighestUserPte);
}
#endif

FORCEINLINE
VOID
MI_MAKE_TRANSITION_PTE(
    _Out_ PMMPTE NewPte,
    _In_ PFN_NUMBER Page,
    _In_ ULONG Protection)
{
    NewPte->u.Long = 0;
    NewPte->u.Trans.Transition = 1;
    NewPte->u.Trans.Protection = Protection;
    NewPte->u.Trans.PageFrameNumber = Page;
}

/* Returns if the page is physically resident (ie: a large page). FIXFIX: CISC/x86 only? */
FORCEINLINE
BOOLEAN
MI_IS_PHYSICAL_ADDRESS(
    _In_ PVOID Address)
{
    PMMPDE Pde;

    /* Large pages are never paged out, always physically resident */
    Pde = MiAddressToPde(Address);

    return (Pde->u.Hard.LargePage && Pde->u.Hard.Valid);
}

/* Figures out the hardware bits for a PTE */
FORCEINLINE
ULONG_PTR
MiDetermineUserGlobalPteMask(
    _In_ PVOID Pte)
{
    MMPTE TempPte;

    /* Start fresh */
    TempPte.u.Long = 0;

    /* Make it valid and accessed */
    TempPte.u.Hard.Valid = TRUE;
    MI_MAKE_ACCESSED_PAGE(&TempPte);

    /* Is this for user-mode? */
    if (
      #if (_MI_PAGING_LEVELS >= 3)
        #error FIXME
      #endif
        MiIsUserPde(Pte) ||
        MiIsUserPte(Pte))
    {
        /* Set the owner bit */
        MI_MAKE_OWNER_PAGE(&TempPte);
    }

    /* FIXME: We should also set the global bit */

    /* Return the protection */
    return TempPte.u.Long;
}

/* Creates a valid PTE with the given protection */
FORCEINLINE
VOID
MI_MAKE_HARDWARE_PTE(
    _In_ PMMPTE NewPte,
    _In_ PMMPTE MappingPte,
    _In_ ULONG_PTR ProtectionMask,
    _In_ PFN_NUMBER PageFrameNumber)
{
    /* Set the protection and page */
    NewPte->u.Long = MiDetermineUserGlobalPteMask(MappingPte);
    NewPte->u.Long |= MmProtectToPteMask[ProtectionMask];
    NewPte->u.Hard.PageFrameNumber = PageFrameNumber;
}

/* Creates a valid kernel PTE with the given protection */
FORCEINLINE
VOID
MI_MAKE_HARDWARE_PTE_KERNEL(
    _In_ PMMPTE NewPte,
    _In_ PMMPTE MappingPte,
    _In_ ULONG_PTR ProtectionMask,
    _In_ PFN_NUMBER PageFrameNumber)
{
    /* Only valid for kernel, non-session PTEs */
    ASSERT(MappingPte > MiHighestUserPte);
    ASSERT(!MI_IS_SESSION_PTE(MappingPte));
    ASSERT((MappingPte < (PMMPTE)PDE_BASE) || (MappingPte > (PMMPTE)PDE_TOP));

    /* Start fresh */
    NewPte->u.Long = 0;
    NewPte->u.Hard.Valid = 1;
    NewPte->u.Hard.Accessed = 1;

    /* Set the protection and page */
    NewPte->u.Hard.PageFrameNumber = PageFrameNumber;
    NewPte->u.Long |= MmPteGlobal.u.Long;
    NewPte->u.Long |= MmProtectToPteMask[ProtectionMask];
}

/* Creates a valid user PTE with the given protection */
FORCEINLINE
VOID
MI_MAKE_HARDWARE_PTE_USER(
    _In_ PMMPTE NewPte,
    _In_ PMMPTE MappingPte,
    _In_ ULONG_PTR ProtectionMask,
    _In_ PFN_NUMBER PageFrameNumber)
{
    /* Only valid for kernel, non-session PTEs */
    ASSERT(MappingPte <= MiHighestUserPte);

    /* Start fresh */
    NewPte->u.Long = 0;

    /* Set the protection and page */
    NewPte->u.Hard.Valid = TRUE;
    NewPte->u.Hard.Owner = TRUE;
    NewPte->u.Hard.Accessed = TRUE;
    NewPte->u.Hard.PageFrameNumber = PageFrameNumber;
    NewPte->u.Long |= MmProtectToPteMask[ProtectionMask];
}

/* Updates a valid PTE */
FORCEINLINE
VOID
MI_UPDATE_VALID_PTE(
    _In_ PMMPTE Pte,
    _In_ MMPTE TempPte)
{
    /* Write the valid PTE */
    ASSERT(Pte->u.Hard.Valid == 1);
    ASSERT(TempPte.u.Hard.Valid == 1);
    ASSERT(Pte->u.Hard.PageFrameNumber == TempPte.u.Hard.PageFrameNumber);

    *Pte = TempPte;
}

/* Writes a valid PTE */
FORCEINLINE
VOID
MI_WRITE_VALID_PTE(
    _In_ PMMPTE Pte,
    _In_ MMPTE TempPte)
{
    /* Write the valid PTE */
    ASSERT(Pte->u.Hard.Valid == 0);
    ASSERT(TempPte.u.Hard.Valid == 1);
    *Pte = TempPte;
}

/* Writes an invalid PTE */
FORCEINLINE
VOID
MI_WRITE_INVALID_PTE(
    _In_ PMMPTE Pte,
    _In_ MMPTE InvalidPte)
{
    ASSERT(InvalidPte.u.Hard.Valid == 0);
    ASSERT(InvalidPte.u.Long != 0);

    /* Write the invalid PTE */
    *Pte = InvalidPte;
}

/* Erase the PTE completely */
FORCEINLINE
VOID
MI_ERASE_PTE(
    _In_ PMMPTE Pte)
{
    /* Zero out the PTE */
    ASSERT(Pte->u.Long != 0);
    Pte->u.Long = 0;
}

/* Writes a valid PDE */
FORCEINLINE
VOID
MI_WRITE_VALID_PDE(
    _In_ PMMPDE Pde,
    _In_ MMPDE TempPde)
{
    /* Write the valid PDE */
    ASSERT(Pde->u.Hard.Valid == 0);
    ASSERT(TempPde.u.Hard.Valid == 1);

    *Pde = TempPde;
}

#if (_MI_PAGING_LEVELS <= 3)
FORCEINLINE
BOOLEAN
MiSynchronizeSystemPde(
    _Inout_ PMMPDE Pde)
{
    /* Copy the PDE from the double-mapped system page directory */
    *Pde = MmSystemPagePtes[MiGetPdeOffset(Pde)];

    /* Make sure we re-read the PDE and PTE */
    KeMemoryBarrierWithoutFence();

    /* Return, if we had success */
    return (Pde->u.Hard.Valid != 0);
}
#endif

PMMPTE
NTAPI
MiGetProtoPteAddressExtended(
    _In_ PMMVAD Vad,
    _In_ ULONG_PTR Vpn
);

/* Returns the ProtoPTE inside a VAD for the given VPN */
FORCEINLINE
PMMPTE
MI_GET_PROTOTYPE_PTE_FOR_VPN(
    _In_ PMMVAD Vad,
    _In_ ULONG_PTR Vpn)
{
    PMMPTE PrototypePte;

    /* Find the offset within the VAD's prototype PTEs */
    PrototypePte = (Vad->FirstPrototypePte + (Vpn - Vad->StartingVpn));

    if (PrototypePte <= Vad->LastContiguousPte)
        return PrototypePte;

    return MiGetProtoPteAddressExtended(Vad, Vpn);
}

FORCEINLINE
USHORT
MiQueryPageTableReferences(
    _In_ PVOID Address)
{
    PUSHORT RefCount = &MmWorkingSetList->UsedPageTableEntries[MiAddressToPdeOffset(Address)];
    return (*RefCount);
}

FORCEINLINE
VOID
MiIncrementPageTableReferences(
    _In_ PVOID Address)
{
    PUSHORT RefCount;

    RefCount = &MmWorkingSetList->UsedPageTableEntries[MiAddressToPdeOffset(Address)];

    *RefCount += 1;
    ASSERT(*RefCount <= PTE_PER_PAGE);
}

FORCEINLINE
VOID
MiAddPageTableReferences(
    _In_ PVOID Address,
    _In_ ULONG AddCount)
{
    PUSHORT RefCount;

    RefCount = &MmWorkingSetList->UsedPageTableEntries[MiAddressToPdeOffset(Address)];

    *RefCount += AddCount;
    ASSERT(*RefCount <= PTE_PER_PAGE);
}

FORCEINLINE
VOID
MiDecrementPageTableReferences(
    _In_ PVOID Address)
{
    PUSHORT RefCount;

    RefCount = &MmWorkingSetList->UsedPageTableEntries[MiAddressToPdeOffset(Address)];

    *RefCount -= 1;
    ASSERT(*RefCount < PTE_PER_PAGE);
}

FORCEINLINE
VOID
AlloccatePoolForSubsectionPtes(
    _In_ ULONG PtesInSubsection)
{
    ULONG AlloccateSize;
    ULONG SubsectionPagedPool;

    MmUnusedSubsectionCount--;

    AlloccateSize = (PtesInSubsection * sizeof(MMPTE));

    if (AlloccateSize <= (PAGE_SIZE - (2 * POOL_BLOCK_SIZE)))
    {
        SubsectionPagedPool = ((AlloccateSize + POOL_BLOCK_SIZE + (POOL_BLOCK_SIZE - 1)) & ~(POOL_BLOCK_SIZE - 1));
    }
    else
    {
        SubsectionPagedPool = ROUND_TO_PAGES(AlloccateSize);
    }

    MiUnusedSubsectionPagedPool -= SubsectionPagedPool;
}

FORCEINLINE
VOID
FreePoolForSubsectionPtes(
    _In_ ULONG PtesInSubsection)
{
    ULONG AlloccateSize;
    ULONG SubsectionPagedPool;

    MmUnusedSubsectionCount++;

    if (MmUnusedSubsectionCount > MmUnusedSubsectionCountPeak)
        MmUnusedSubsectionCountPeak = MmUnusedSubsectionCount;

    AlloccateSize = (PtesInSubsection * sizeof(MMPTE));

    if (AlloccateSize <= (PAGE_SIZE - (2 * POOL_BLOCK_SIZE)))
    {
        SubsectionPagedPool = ((AlloccateSize + POOL_BLOCK_SIZE + (POOL_BLOCK_SIZE - 1)) & ~(POOL_BLOCK_SIZE - 1));
    }
    else
    {
        SubsectionPagedPool = ROUND_TO_PAGES(AlloccateSize);
    }

    MiUnusedSubsectionPagedPool += SubsectionPagedPool;
}

FORCEINLINE
PMMSUPPORT
MmGetCurrentAddressSpace(VOID)
{
    return &((PEPROCESS)KeGetCurrentThread()->ApcState.Process)->Vm;
}

extern KSPIN_LOCK MmExpansionLock;
extern PETHREAD MiExpansionLockOwner;

FORCEINLINE
KIRQL
MiAcquireExpansionLock(VOID)
{
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    KeAcquireSpinLock(&MmExpansionLock, &OldIrql);
    ASSERT(MiExpansionLockOwner == NULL);
    MiExpansionLockOwner = PsGetCurrentThread();
    return OldIrql;
}

FORCEINLINE
VOID
MiReleaseExpansionLock(
    _In_ KIRQL OldIrql)
{
    ASSERT(MiExpansionLockOwner == PsGetCurrentThread());
    MiExpansionLockOwner = NULL;
    KeReleaseSpinLock(&MmExpansionLock, OldIrql);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
}

VOID
NTAPI
MiDecrementShareCount(
    _In_ PMMPFN Pfn,
    _In_ PFN_NUMBER PageFrameIndex
);

FORCEINLINE
VOID
MiDecrementPfnShare(
    _In_ PMMPFN Pfn,
    _In_ PFN_NUMBER PageNumber)
{
    if (Pfn->u2.ShareCount == 1)
    {
        MiDecrementShareCount(Pfn, PageNumber);
        return;
    }

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());
    ASSERT(PageNumber > 0);

    ASSERT(MiGetPfnEntry(PageNumber) == Pfn);
    ASSERT(Pfn->u2.ShareCount != 0);

    if (Pfn->u3.e1.PageLocation != ActiveAndValid &&
        Pfn->u3.e1.PageLocation != StandbyPageList)
    {
        DbgPrint("MiDecrementPfnShare: KeBugCheckEx(0x4E)\n");
        KeBugCheckEx(0x4E, 0x99, PageNumber, Pfn->u3.e1.PageLocation, 0); // FIXME
    }

    Pfn->u2.ShareCount--;
    ASSERT(Pfn->u2.ShareCount < 0xF000000);
}

/* ARM3\i386\init.c */
//INIT_FUNCTION
VOID
NTAPI
MiInitializeSessionSpaceLayout(
    VOID
);

//INIT_FUNCTION
NTSTATUS
NTAPI
MiInitMachineDependent(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock
);

/* ARM3\drvmgmt.c */
VOID
NTAPI
MiInitializeDriverVerifierList(
    VOID
);

/* ARM3\expool.c */
//INIT_FUNCTION
VOID
NTAPI
InitializePool(
    _In_ POOL_TYPE PoolType,
    _In_ ULONG Threshold
);

VOID
NTAPI
ExInitializePoolDescriptor(
    _In_ PPOOL_DESCRIPTOR PoolDescriptor,
    _In_ POOL_TYPE PoolType,
    _In_ ULONG PoolIndex,
    _In_ ULONG Threshold,
    _In_ PVOID PoolLock
);

/* ARM3\hypermap.c */
PVOID
NTAPI
MiMapPageInHyperSpace(
    _In_ PEPROCESS Process,
    _In_ PFN_NUMBER Page,
    _In_ PKIRQL OldIrql
);

PVOID
NTAPI
MiMapPageInHyperSpaceAtDpc(
    _In_ PEPROCESS Process,
    _In_ PFN_NUMBER PageNumber
);

VOID
NTAPI
MiUnmapPageInHyperSpace(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ KIRQL OldIrql
);

VOID
NTAPI
MiUnmapPageInHyperSpaceFromDpc(
    _In_ PEPROCESS Process,
    _In_ PVOID Address
);

PVOID
NTAPI
MiMapPagesInZeroSpace(
    _In_ PMMPFN Pfn,
    _In_ PFN_NUMBER NumberOfPages
);

VOID
NTAPI
MiUnmapPagesInZeroSpace(
    _In_ PVOID VirtualAddress,
    _In_ PFN_NUMBER NumberOfPages
);

/* ARM3\largepag.c */
//INIT_FUNCTION
VOID
NTAPI
MiSyncCachedRanges(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
MiInitializeLargePageSupport(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
MiInitializeDriverLargePageList(
    VOID
);

/* ARM3\mminit.c */
//INIT_FUNCTION
PPHYSICAL_MEMORY_DESCRIPTOR
NTAPI
MmInitializeMemoryLimits(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ PBOOLEAN IncludeType
);

//INIT_FUNCTION
PFN_NUMBER
NTAPI
MxGetNextPage(
    _In_ PFN_NUMBER PageCount
);

//INIT_FUNCTION
BOOLEAN
NTAPI
MiInitializeMemoryEvents(
    VOID
);

/* ARM3\mmsup.c */
BOOLEAN
NTAPI
MiIsAddressValid(
    _In_ PVOID Address
);

VOID
FASTCALL
MiRestoreTransitionPte(
    _In_ PMMPFN Pfn
);

/* ARM3\pagfault.c */
NTSTATUS
FASTCALL
MiCheckPdeForPagedPool(
    _In_ PVOID Address
);

BOOLEAN
NTAPI
MiCopyOnWrite(
    _In_ PVOID Address,
    _In_ PMMPTE Pte
);

PMI_PAGE_SUPPORT_BLOCK
NTAPI
MiGetInPageSupportBlock(
    _In_ KIRQL OldIrql,
    _Out_ NTSTATUS* OutStatus
);

VOID
NTAPI
MiFreeInPageSupportBlock(
    _In_ PMI_PAGE_SUPPORT_BLOCK Support
);

VOID
NTAPI
MiTrimPte(
     _In_ PVOID VirtualAddress,
     _Inout_ PMMPTE Pte,
     _In_ PMMPFN Pfn,
     _In_ PEPROCESS Process,
     _In_ MMPTE NewPteContents
);

/* ARM3\pfnlist.c */
PFN_NUMBER
NTAPI
MiRemoveAnyPage(
    _In_ ULONG Color
);

VOID
NTAPI
MiInsertPageInFreeList(
    _In_ PFN_NUMBER PageFrameIndex
);

VOID
NTAPI
MiZeroPhysicalPage(
    _In_ PFN_NUMBER PageFrameIndex
);

VOID
NTAPI
MiInitializePfnForOtherProcess(
    _In_ PFN_NUMBER PageFrameIndex,
    _In_ PVOID PteAddress,
    _In_ PFN_NUMBER PteFrame
);

VOID
NTAPI
MiInitializePfn(
    _In_ PFN_NUMBER PageFrameIndex,
    _In_ PMMPTE Pte,
    _In_ BOOLEAN Modified
);

VOID
NTAPI
MiInitializePfnAndMakePteValid(
    _In_ PFN_NUMBER PageFrameIndex,
    _In_ PMMPTE Pte,
    _In_ MMPTE TempPte
);

PFN_NUMBER
NTAPI
MiRemoveZeroPage(
    _In_ ULONG Color
);

VOID
NTAPI
MiUnlinkFreeOrZeroedPage(
    _In_ PMMPFN Entry
);

VOID
NTAPI
MiUnlinkPageFromList(
    _In_ PMMPFN Pfn
);

VOID
NTAPI
MiInsertPageInList(
    _In_ PMMPFNLIST ListHead,
    _In_ PFN_NUMBER PageFrameIndex
);

BOOLEAN
NTAPI
MiEnsureAvailablePageOrWait(
    _In_ PEPROCESS Process,
    _In_ KIRQL OldIrql
);

NTSTATUS
NTAPI
MiInitializeAndChargePfn(
    OUT PPFN_NUMBER PageFrameIndex,
    IN PMMPDE PointerPde,
    IN PFN_NUMBER ContainingPageFrame,
    IN BOOLEAN SessionAllocation
);

/* ARM3\pool.c */
//INIT_FUNCTION
VOID
NTAPI
MiInitializeNonPagedPool(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
MiInitializeNonPagedPoolThresholds(
    VOID
);

PVOID
NTAPI
MiAllocatePoolPages(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T SizeInBytes
);

ULONG
NTAPI
MiFreePoolPages(
    _In_ PVOID StartingVa
);

POOL_TYPE
NTAPI
MmDeterminePoolType(
    _In_ PVOID PoolAddress
);

//INIT_FUNCTION
VOID
NTAPI
MiInitializePoolEvents(
    VOID
);

NTSTATUS
NTAPI
MiInitializeSessionPool(
    VOID
);

/* ARM3\section.c */
BOOLEAN
NTAPI
MiInitializeSystemSpaceMap(
    _In_ PMMSESSION InputSession OPTIONAL
);

PSUBSECTION
NTAPI
MiLocateSubsection(
    _In_ PMMVAD Vad,
    _In_ ULONG_PTR Vpn
);

VOID
NTAPI
MiCheckControlArea(
    _In_ PCONTROL_AREA ControlArea,
    _In_ KIRQL OldIrql
);

NTSTATUS
NTAPI
MiAddViewsForSection(
    _In_ PMSUBSECTION StartMappedSubsection,
    _In_ ULONGLONG LastPteOffset,
    _In_ KIRQL OldIrql
);

VOID
NTAPI
MiRemoveViewsFromSection(
    _In_ PMSUBSECTION MappedSubsection,
    _In_ ULONGLONG PteCount
);

NTSTATUS
NTAPI
MiUnmapViewOfSection(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ ULONG Flags
);

VOID
NTAPI
MiDereferenceControlAreaBySection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ ULONG UserReference
);

ULONG
NTAPI
MiMakeProtectionMask(
    IN ULONG Protect
);

NTSTATUS
NTAPI
MiQueryMemorySectionName(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_ SIZE_T* ReturnLength
);

VOID
NTAPI
MiRemoveMappedView(
    _In_ PEPROCESS Process,
    _In_ PMMVAD Vad
);

VOID
NTAPI
MiCheckForControlAreaDeletion(
    _In_ PCONTROL_AREA ControlArea
);

VOID
NTAPI
MiInitializeTransitionPfn(
    _In_ PFN_NUMBER PageNumber,
    _In_ OUT PMMPTE SectionProto
);

//INIT_FUNCTION
NTSTATUS
NTAPI
MmInitSectionImplementation(
VOID
);

VOID
NTAPI
MiCleanSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ BOOLEAN Parameter2
);

BOOLEAN
NTAPI
MiIsPteProtectionCompatible(
    _In_ ULONG PteProtection,
    _In_ ULONG NewProtection
);

/* ARM3\session.c */
VOID
NTAPI
MiInitializeSessionWideAddresses(
    VOID
);

VOID
NTAPI
MiInitializeSessionWsSupport(
    VOID
);

VOID
NTAPI
MiInitializeSessionIds(
    VOID
);

VOID
NTAPI
MiSessionAddProcess(
    _In_ PEPROCESS NewProcess
);

VOID
NTAPI
MiSessionRemoveProcess(
    VOID
);

VOID
NTAPI
MiReleaseProcessReferenceToSessionDataPage(
    _In_ PMM_SESSION_SPACE SessionGlobal
);

/* ARM3\special.c */
PVOID
NTAPI
MmAllocateSpecialPool(
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _In_ POOL_TYPE PoolType,
    _In_ ULONG SpecialType
);

VOID
NTAPI
MmFreeSpecialPool(
    _In_ PVOID P
);

VOID
NTAPI
MiInitializeSpecialPool(
    VOID
);

/* ARM3\syscache.c */
VOID
NTAPI
MiInitializeSystemCache(
    _In_ ULONG MinimumWorkingSetSize,
    _In_ ULONG MaximumWorkingSetSize
);

/* ARM3\sysldr.c */
//INIT_FUNCTION
VOID
NTAPI
MiReloadBootLoadedDrivers(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock
);

//INIT_FUNCTION
BOOLEAN
NTAPI
MiInitializeLoadedModuleList(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock
);

VOID
NTAPI
MiWriteProtectSystemImage(
    _In_ PVOID ImageBase
);

/* ARM3\syspte.c */
//INIT_FUNCTION
VOID
NTAPI
MiInitializeSystemPtes(
    _In_ PMMPTE StartingPte,
    _In_ ULONG NumberOfPtes,
    _In_ MMSYSTEM_PTE_POOL_TYPE PoolType
);

PMMPTE
NTAPI
MiReserveSystemPtes(
    _In_ ULONG NumberOfPtes,
    _In_ MMSYSTEM_PTE_POOL_TYPE SystemPtePoolType
);

VOID
NTAPI
MiReleaseSystemPtes(
    _In_ PMMPTE StartingPte,
    _In_ ULONG NumberOfPtes,
    _In_ MMSYSTEM_PTE_POOL_TYPE SystemPtePoolType
);

PMMPTE
NTAPI
MiReserveAlignedSystemPtes(
    _In_ ULONG NumberOfPtes,
    _In_ MMSYSTEM_PTE_POOL_TYPE SystemPtePoolType,
    _In_ ULONG Alignment
);

/* ARM3\vadnode.c */
BOOLEAN
NTAPI
MiCheckForConflictingVadExistence(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress
);

NTSTATUS
NTAPI
MiFindEmptyAddressRange(
    _In_ SIZE_T Size,
    _In_ ULONG_PTR Alignment,
    _In_ ULONG ZeroBits,
    _Out_ PULONG_PTR OutBaseAddress
);

NTSTATUS
NTAPI
MiFindEmptyAddressRangeDownTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR BoundaryAddress,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ ULONG_PTR* Base
);

NTSTATUS
NTAPI
MiInsertVadCharges(
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process
);

VOID
NTAPI
MiInsertVad(
    _In_ PMMVAD Vad,
    _In_ PMM_AVL_TABLE VadRoot
);

PMMVAD
NTAPI
MiLocateAddress(
    _In_ PVOID VirtualAddress
);

PMM_AVL_TABLE
NTAPI
MiCreatePhysicalVadRoot(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN IsLocked
);

NTSTATUS
NTAPI
MiCheckSecuredVad(
    _In_ PMMVAD Vad,
    _In_ PVOID Base,
    _In_ SIZE_T Size,
    _In_ ULONG ProtectionMask
);

VOID
NTAPI
MiRemoveVadCharges(
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process
);

VOID
NTAPI
MiRemoveNode(
    _In_ PMMADDRESS_NODE Node,
    _In_ PMM_AVL_TABLE Table
);

VOID
NTAPI
MiPhysicalViewRemover(
    _In_ PEPROCESS Process,
    _In_ PMMVAD Vad
);

NTSTATUS
NTAPI
MiFindEmptyAddressRangeInTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ PMMADDRESS_NODE* PreviousVad,
    _Out_ PULONG_PTR Base
);

PMMADDRESS_NODE
NTAPI
MiCheckForConflictingNode(
    _In_ ULONG_PTR StartVpn,
    _In_ ULONG_PTR EndVpn,
    _In_ PMM_AVL_TABLE Table
);

PMMADDRESS_NODE
NTAPI
MiGetNextNode(
    _In_ PMMADDRESS_NODE Node
);

PMMADDRESS_NODE
NTAPI
MiGetPreviousNode(
    _In_ PMMADDRESS_NODE Node
);

NTSTATUS
NTAPI
MiFindEmptyAddressRangeDownBasedTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR BoundaryAddress,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ ULONG_PTR* OutBase
);

VOID
NTAPI
MiInsertBasedSection(
    _In_ PSECTION Section
);

VOID
NTAPI
MiReturnPageTablePageCommitment(
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress,
    _In_ PEPROCESS Process,
    _In_ PMMADDRESS_NODE PreviousNode,
    _In_ PMMADDRESS_NODE NextNode
);

/* ARM3\virtual.c */
PFN_COUNT
NTAPI
MiDeleteSystemPageableVm(
    _In_ PMMPTE Pte,
    _In_ PFN_NUMBER PageCount,
    _In_ ULONG Flags,
    _Out_ PPFN_NUMBER ValidPages
);

VOID
NTAPI
MiMakePdeExistAndMakeValid(
    _In_ PMMPDE Pde,
    _In_ PEPROCESS TargetProcess,
    _In_ KIRQL OldIrql
);

VOID
NTAPI
MiDeleteVirtualAddresses(
    _In_ ULONG_PTR Va,
    _In_ ULONG_PTR EndingAddress,
    _In_ PMMVAD Vad
);

BOOLEAN
NTAPI
MiMakeSystemAddressValidPfn(
    _In_ PVOID VirtualAddress,
    _In_ KIRQL OldIrql
);

ULONG
NTAPI
MiDeletePte(
    _In_ PMMPTE Pte,
    _In_ PVOID Va,
    _In_ BOOLEAN IsNotTerminateWsle,
    _In_ PEPROCESS CurrentProcess,
    _In_ PMMPTE Proto,
    _In_ PMMPTE_FLUSH_LIST FlushList,
    _In_ KIRQL OldIrql
);

/* ARM3\workset.c */
BOOLEAN
NTAPI
MiRemovePageFromWorkingSet(
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ PMMSUPPORT WorkingSet
);

VOID
NTAPI
MiInitializeWorkingSetList(
    _In_ PEPROCESS CurrentProcess
);

ULONG
NTAPI
MiLocateWsle(
    _In_ PVOID Address,
    _In_ PMMWSL WsList,
    _In_ ULONG InWsIndex,
    _In_ BOOLEAN IsResetHash
);

VOID
NTAPI
MiAllowWorkingSetExpansion(
    _In_ PMMSUPPORT WorkSet
);

VOID
NTAPI
MiUnlinkWorkingSet(
    _In_ PMMSUPPORT WorkSet
);

ULONG
NTAPI
MiAddValidPageToWorkingSet(
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ MMWSLE Wsle
);

ULONG
NTAPI
MiAllocateWsle(
    _In_ PMMSUPPORT WorkSet,
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ MMWSLE InWsle
);

VOID
NTAPI
MiGrowWsleHash(
    _In_ PMMSUPPORT WorkSet
);

VOID
NTAPI
MiTerminateWsle(
    _In_ PVOID Address,
    _In_ PMMSUPPORT WorkSet,
    _In_ ULONG InWsIndex
);

VOID
FASTCALL 
MiRemoveWsle(
    _In_ ULONG WsIndex,
    _In_ PMMWSL WsList
);

VOID
FASTCALL 
MiReleaseWsle(
    _In_ ULONG WsIndex,
    _In_ PMMSUPPORT WorkSet
);

VOID
NTAPI
MiSwapWslEntries(
    IN ULONG NewIndex,
    IN ULONG OldIndex,
    IN PMMSUPPORT WorkSet,
    IN BOOLEAN Param4
);

/* i386\page.c */
/* i386\pagepae.c */
//INIT_FUNCTION
VOID
NTAPI
MmInitGlobalKernelPageDirectory(
    VOID
);

BOOLEAN
NTAPI
MmCreateProcessAddressSpace(
    _In_ ULONG MinWs,
    _In_ PEPROCESS Dest,
    _In_ PULONG_PTR DirectoryTableBase
);

/* balance.c */
//INIT_FUNCTION
VOID
NTAPI
MmInitializeBalancer(
    ULONG NrAvailablePages,
    ULONG NrSystemPages
);

BOOLEAN
MmRosNotifyAvailablePage(
    PFN_NUMBER Page
);

VOID
NTAPI
MmRebalanceMemoryConsumers(
    VOID
);

NTSTATUS
MmTrimUserMemory(
    ULONG Target,
    ULONG Priority,
    PULONG NrFreedPages
);

//INIT_FUNCTION
VOID
NTAPI
MmInitializeMemoryConsumer(
    ULONG Consumer,
    PMM_MEMORY_CONSUMER_TRIM Trim
);

VOID
//INIT_FUNCTION
NTAPI
MiInitBalancerThread(
    VOID
);

VOID
NTAPI
MiBalancerThread(
    PVOID Unused
);

/* freelist.c */
BOOLEAN
NTAPI
MiIsPfnInUse(
    _In_ PMMPFN Pfn
);

VOID
NTAPI
MiInitializeUserPfnBitmap(
    VOID
);

PFN_NUMBER
NTAPI
MmGetLRUFirstUserPage(
    VOID
);

PFN_NUMBER
NTAPI
MmGetLRUNextUserPage(
    PFN_NUMBER PreviousPfn
);

BOOLEAN
NTAPI
MiChargeCommitment(
    _In_ SIZE_T QuotaCharge,
    _In_ PEPROCESS Process
);

BOOLEAN
NTAPI
MiChargeCommitmentCantExpand(
    _In_ SIZE_T QuotaCharge,
    _In_ BOOLEAN IsParam2
);

/* pagefile.c */
//INIT_FUNCTION
VOID
NTAPI
MmInitPagingFile(
    VOID
);

BOOLEAN
NTAPI
MiReleasePageFileSpace(
    _In_ MMPTE PteContents
);

/* MiRemoveZeroPage will use inline code to zero out the page manually if only free pages are available.
   In some scenarios, we don't/can't run that piece of code and would rather only have a real zero page.
   If we can't have a zero page, then we'd like to have our own code to grab a free page and zero it out,
   by using MiRemoveAnyPage. This macro implements this.
*/
FORCEINLINE
PFN_NUMBER
MiRemoveZeroPageSafe(
    _In_ ULONG Color)
{
    if (MmFreePagesByColor[ZeroedPageList][Color].Flink == LIST_HEAD)
        return 0;

    return MiRemoveZeroPage(Color);
}

/* EOF */
