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
    PVOID UnpackRequirement;
    PVOID PackResource;
    PVOID UnpackResource;
    PVOID ScoreRequirement;
    PVOID TestAllocation;
    PVOID RetestAllocation;
    PVOID CommitAllocation;
    PVOID RollbackAllocation;
    PVOID BootAllocation;
    PVOID QueryArbitrate;
    PVOID QueryConflict;
    PVOID AddReserved;
    PVOID StartArbiter;
    PVOID PreprocessEntry;
    PVOID AllocateEntry;
    PVOID GetNextAllocationRange;
    PVOID FindSuitableRange;
    PVOID AddAllocation;
    PVOID BacktrackAllocation;
    PVOID OverrideConflict;
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

#ifdef __cplusplus
}
#endif
#endif  /* _ARBITER_H */
