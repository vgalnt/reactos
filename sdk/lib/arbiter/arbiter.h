#ifndef _ARBITER_H
#define _ARBITER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _NTOSKRNL_
#include <ntifs.h>
#include <wdm.h>

/* C Headers */
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

/* PSDK/NDK Headers */
#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#define COBJMACROS
#define CONST_VTABLE

#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/kefuncs.h>
#include <ndk/ldrfuncs.h>
#include <ndk/mmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/setypes.h>
#include <ndk/sefuncs.h>
#include <ndk/umfuncs.h>

/* SEH support with PSEH */
#include <pseh/pseh2.h>
#endif

#include <arc/arc.h>

#define ARB_ORDERING_LIST_DEFAULT_COUNT  16
#define ARB_ORDERING_LIST_ADD_COUNT      8

/* FIXME for NT >= 6.0 */

typedef struct _ARBITER_ORDERING {
    ULONGLONG Start;
    ULONGLONG End;
} ARBITER_ORDERING, *PARBITER_ORDERING;

typedef struct _ARBITER_ORDERING_LIST {
    USHORT Count;
    USHORT Maximum;
  #if defined(_M_AMD64)
    ULONG Padding;
  #endif
    PARBITER_ORDERING Orderings;
} ARBITER_ORDERING_LIST, *PARBITER_ORDERING_LIST;

#if defined(_M_AMD64)
    C_ASSERT(sizeof(ARBITER_ORDERING_LIST) == 0x10);
#else
    C_ASSERT(sizeof(ARBITER_ORDERING_LIST) == 0x08);
#endif

typedef struct _ARBITER_ALTERNATIVE {
    ULONGLONG Minimum;
    ULONGLONG Maximum;
    ULONG Length;
    ULONG Alignment;
    LONG Priority;
    ULONG Flags;
    PIO_RESOURCE_DESCRIPTOR Descriptor;
    ULONG Reserved[3];
  #if defined(_M_AMD64)
    ULONG Padding;
  #endif
} ARBITER_ALTERNATIVE, *PARBITER_ALTERNATIVE;

#if defined(_M_AMD64)
    C_ASSERT(sizeof(ARBITER_ALTERNATIVE) == 0x38);
#else
    C_ASSERT(sizeof(ARBITER_ALTERNATIVE) == 0x30);
#endif

typedef struct _ARBITER_ALLOCATION_STATE {
    ULONGLONG Start;
    ULONGLONG End;
    ULONGLONG CurrentMinimum;
    ULONGLONG CurrentMaximum;
    PARBITER_LIST_ENTRY Entry;
    PARBITER_ALTERNATIVE CurrentAlternative;
    ULONG AlternativeCount;
    PARBITER_ALTERNATIVE Alternatives;
  #if defined(_M_AMD64)
    ULONG Padding0;
  #endif
    USHORT Flags;
    UCHAR RangeAttributes;
    UCHAR RangeAvailableAttributes;
  #if defined(_M_AMD64)
    ULONG Padding1;
  #endif
    ULONG WorkSpace;
} ARBITER_ALLOCATION_STATE, *PARBITER_ALLOCATION_STATE;

#if defined(_M_AMD64)
    C_ASSERT(sizeof(ARBITER_ALLOCATION_STATE) == 0x50);
#else
    C_ASSERT(sizeof(ARBITER_ALLOCATION_STATE) == 0x38);
#endif

typedef struct _ARBITER_INSTANCE ARBITER_INSTANCE, *PARBITER_INSTANCE;

typedef NTSTATUS
(NTAPI * PARB_UNPACK_REQUIREMENT)(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment
);

typedef NTSTATUS
(NTAPI * PARB_PACK_RESOURCE)(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ ULONGLONG Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor
);

typedef NTSTATUS
(NTAPI * PARB_UNPACK_RESOURCE)(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG Start,
    _Out_ PULONG OutLength
);

typedef LONG
(NTAPI * PARB_SCORE_REQUIREMENT)(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

typedef NTSTATUS
(NTAPI * PARB_TEST_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList
);

typedef NTSTATUS
(NTAPI * PARB_RETEST_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList
);

typedef NTSTATUS
(NTAPI * PARB_COMMIT_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter
);

typedef NTSTATUS
(NTAPI * PARB_ROLLBACK_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter
);

typedef NTSTATUS
(NTAPI * PARB_BOOT_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList
);

typedef NTSTATUS
(NTAPI * PARB_PREPROCESS_ENTRY)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef NTSTATUS
(NTAPI * PARB_ALLOCATE_ENTRY)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef BOOLEAN
(NTAPI * PARB_GET_NEXT_ALLOCATION_RANGE)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef BOOLEAN
(NTAPI * PARB_FIND_SUITABLE_RANGE)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef VOID
(NTAPI * PARB_ADD_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef VOID
(NTAPI * PARB_BACKTRACK_ALLOCATION)(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

typedef struct _ARBITER_INSTANCE {
    ULONG Signature;
  #if defined(_M_AMD64)
    ULONG Padding0;
  #endif
    PKEVENT MutexEvent;
    PUSHORT Name;
    CM_RESOURCE_TYPE ResourceType;
  #if defined(_M_AMD64)
    ULONG Padding1;
  #endif
    PRTL_RANGE_LIST Allocation;
    PRTL_RANGE_LIST PossibleAllocation;
    ARBITER_ORDERING_LIST OrderingList;
    ARBITER_ORDERING_LIST ReservedList;
    LONG ReferenceCount;
  #if defined(_M_AMD64)
    ULONG Padding2;
  #endif
    PARBITER_INTERFACE Interface;
    ULONG AllocationStackMaxSize;
  #if defined(_M_AMD64)
    ULONG Padding3;
  #endif
    PARBITER_ALLOCATION_STATE AllocationStack;
    PARB_UNPACK_REQUIREMENT UnpackRequirement;
    PARB_PACK_RESOURCE PackResource;
    PARB_UNPACK_RESOURCE UnpackResource;
    PARB_SCORE_REQUIREMENT ScoreRequirement;
    PARB_TEST_ALLOCATION TestAllocation;
    PARB_RETEST_ALLOCATION RetestAllocation;
    PARB_COMMIT_ALLOCATION CommitAllocation;
    PARB_ROLLBACK_ALLOCATION RollbackAllocation;
    PARB_BOOT_ALLOCATION BootAllocation;
    PVOID QueryArbitrate; /* FIXME PARB_QUERY_ARBITRATE */
    PVOID QueryConflict; /* FIXME PARB_QUERY_CONFLICT */
    PVOID AddReserved; /* FIXME PARB_ADD_RESERVED */
    PVOID StartArbiter; /* FIXME PARB_START_ARBITER */
    PARB_PREPROCESS_ENTRY PreprocessEntry;
    PARB_ALLOCATE_ENTRY AllocateEntry;
    PARB_GET_NEXT_ALLOCATION_RANGE GetNextAllocationRange;
    PARB_FIND_SUITABLE_RANGE FindSuitableRange;
    PARB_ADD_ALLOCATION AddAllocation;
    PARB_BACKTRACK_ALLOCATION BacktrackAllocation;
    PVOID OverrideConflict; // FIXME PARB_OVERRIDE_CONFLICT
    BOOLEAN TransactionInProgress;
  #if defined(_M_AMD64)
    UCHAR Padding4[0x7];
  #else
    UCHAR Padding4[0x3];
  #endif
    PVOID Extension;
    PDEVICE_OBJECT BusDeviceObject;
    PVOID ConflictCallbackContext;
    PVOID ConflictCallback;
} ARBITER_INSTANCE, *PARBITER_INSTANCE;

#if defined(_M_AMD64)
    C_ASSERT(sizeof(ARBITER_INSTANCE) == 0x138);
#else
    C_ASSERT(sizeof(ARBITER_INSTANCE) == 0x9C);
#endif

typedef NTSTATUS
(NTAPI * PARB_TRANSLATE_ORDERING)(
    _Out_ PIO_RESOURCE_DESCRIPTOR OutIoDescriptor,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

NTSTATUS
NTAPI
ArbInitializeArbiterInstance(
    _Inout_ PARBITER_INSTANCE Arbiter,
    _In_ PDEVICE_OBJECT BusDeviceObject,
    _In_ CM_RESOURCE_TYPE ResourceType,
    _In_ PWSTR ArbiterName,
    _In_ PCWSTR OrderName,
    _In_ PARB_TRANSLATE_ORDERING TranslateOrderingFunction
);

NTSTATUS
NTAPI
ArbArbiterHandler(
    _In_ PVOID Context,
    _In_ ARBITER_ACTION Action,
    _Out_ PARBITER_PARAMETERS Params
);

BOOLEAN
NTAPI
ArbFindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState
);

NTSTATUS
NTAPI
ArbBootAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList
);

NTSTATUS
NTAPI
ArbTestAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList
);

NTSTATUS
NTAPI
ArbCommitAllocation(
    _In_ PARBITER_INSTANCE Arbiter
);

#ifdef __cplusplus
}
#endif
#endif  /* _ARBITER_H */
