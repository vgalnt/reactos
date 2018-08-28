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

#define ARB_ORDERING_LIST_DEFAULT_COUNT  16
#define ARB_ORDERING_LIST_ADD_COUNT      8

/* FIXME structures changes for NT >= 6.0 */

typedef struct _ARBITER_ORDERING {
    ULONGLONG Start;
    ULONGLONG End;
} ARBITER_ORDERING, *PARBITER_ORDERING;

typedef struct _ARBITER_ORDERING_LIST {
    USHORT Count;
    USHORT Maximum;
#if defined(_M_X64)
    ULONG Padding;
#endif
    PARBITER_ORDERING Orderings;
} ARBITER_ORDERING_LIST, *PARBITER_ORDERING_LIST;

#if defined(_M_X64)
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
#if defined(_M_X64)
    ULONG Padding;
#endif
} ARBITER_ALTERNATIVE, *PARBITER_ALTERNATIVE;

#if defined(_M_X64)
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
#if defined(_M_X64)
    ULONG Padding0;
#endif
    USHORT Flags;
    UCHAR RangeAttributes;
    UCHAR RangeAvailableAttributes;
#if defined(_M_X64)
    ULONG Padding1;
#endif
    ULONG WorkSpace;
} ARBITER_ALLOCATION_STATE, *PARBITER_ALLOCATION_STATE;

#if defined(_M_X64)
    C_ASSERT(sizeof(ARBITER_ALLOCATION_STATE) == 0x50);
#else
    C_ASSERT(sizeof(ARBITER_ALLOCATION_STATE) == 0x38);
#endif

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
    _In_ PHYSICAL_ADDRESS Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor
);

typedef NTSTATUS
(NTAPI * PARB_UNPACK_RESOURCE)(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment
);

typedef LONG
(NTAPI * PARB_SCORE_REQUIREMENT)(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

//typedef struct _RTL_RANGE_LIST RTL_RANGE_LIST, *PRTL_RANGE_LIST;

typedef struct _ARBITER_INSTANCE {
    ULONG Signature;
#if defined(_M_X64)
    ULONG Padding0;
#endif
    PKEVENT MutexEvent;
    PUSHORT Name;
    ULONG ResourceType;
#if defined(_M_X64)
    ULONG Padding1;
#endif
    PRTL_RANGE_LIST Allocation;
    PRTL_RANGE_LIST PossibleAllocation;
    ARBITER_ORDERING_LIST OrderingList;
    ARBITER_ORDERING_LIST ReservedList;
    LONG ReferenceCount;
#if defined(_M_X64)
    ULONG Padding2;
#endif
    PARBITER_INTERFACE Interface;
    ULONG AllocationStackMaxSize;
#if defined(_M_X64)
    ULONG Padding3;
#endif
    PARBITER_ALLOCATION_STATE AllocationStack;
    PARB_UNPACK_REQUIREMENT UnpackRequirement;
    PARB_PACK_RESOURCE PackResource;
    PARB_UNPACK_RESOURCE UnpackResource;
    PARB_SCORE_REQUIREMENT ScoreRequirement;
    // FIXME next funcs
    PVOID TestAllocation; // PARB_TEST_ALLOCATION
    PVOID RetestAllocation; // PARB_RETEST_ALLOCATION
    PVOID CommitAllocation; // PARB_COMMIT_ALLOCATION
    PVOID RollbackAllocation; // PARB_ROLLBACK_ALLOCATION
    PVOID BootAllocation; // PARB_BOOT_ALLOCATION
    PVOID QueryArbitrate; // PARB_QUERY_ARBITRATE
    PVOID QueryConflict; // PARB_QUERY_CONFLICT
    PVOID AddReserved; // PARB_ADD_RESERVED
    PVOID StartArbiter; // PARB_START_ARBITER
    PVOID PreprocessEntry; // PARB_PREPROCESS_ENTRY
    PVOID AllocateEntry; // PARB_ALLOCATE_ENTRY
    PVOID GetNextAllocationRange; // PARB_GET_NEXT_ALLOCATION_RANGE
    PVOID FindSuitableRange; // PARB_FIND_SUITABLE_RANGE
    PVOID AddAllocation; // PARB_ADD_ALLOCATION
    PVOID BacktrackAllocation; // PARB_BACKTRACK_ALLOCATION
    PVOID OverrideConflict; // PARB_OVERRIDE_CONFLICT
    BOOLEAN TransactionInProgress;
#if defined(_M_X64)
    UCHAR Padding4[0x7];
#else
    UCHAR Padding4[0x3];
#endif
    PVOID Extension;
    PDEVICE_OBJECT BusDeviceObject;
    PVOID ConflictCallbackContext;
    PVOID ConflictCallback;
} ARBITER_INSTANCE, *PARBITER_INSTANCE;

#if defined(_M_X64)
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

#ifdef __cplusplus
}
#endif
#endif  /* _ARBITER_H */
