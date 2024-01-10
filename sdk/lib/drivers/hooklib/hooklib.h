/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Header file for hooking library.
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

/* Only x86 suport now! */

#pragma once

#include <stdlib.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#if DBG
  #ifdef __GNUC__
    #define HkDbgBreakPoint()  DbgBreakPoint()
  #else
    #define HkDbgBreakPoint()  __asm int 3
  #endif
#else
  #define HkDbgBreakPoint()
#endif

#define HOOKLIB_POOL_TAG  (ULONG)'tNkH'
#define CHAR_PER_LINE     0x100

/*===================================*/
/* Draft! Get from MM headers. FIXME */
/* Only 32 bit (non PAE)             */
/*===================================*/

#if 1

#if !defined(_X86PAE_)

typedef struct _MMPTE_HARDWARE_VG
{
    ULONG Valid:1;
  #ifndef CONFIG_SMP
    ULONG Write:1;
  #else
    ULONG Writable:1;
  #endif
    ULONG Owner:1;
    ULONG WriteThrough:1;
    ULONG CacheDisable:1;
    ULONG Accessed:1;
    ULONG Dirty:1;
    ULONG LargePage:1;
    ULONG Global:1;
    ULONG CopyOnWrite:1;
    ULONG Prototype:1;
  #ifndef CONFIG_SMP
    ULONG reserved:1;
  #else
    ULONG Write:1;
  #endif
    ULONG PageFrameNumber:20;
} MMPTE_HARDWARE_VG, *PMMPTE_HARDWARE_VG;

#else
  #error Fixme
#endif

typedef struct _MMPTE_VG
{
    union
    {
      #if !defined(_X86PAE_)
        ULONG Long;
      #else
        ULONGLONG Long;
        struct
        {
            ULONG LowPart;
            ULONG HighPart;
        } HighLow;
      #endif
        MMPTE_HARDWARE_VG Hard;
    } u;
} MMPTE_VG, *PMMPTE_VG,
  MMPDE_VG, *PMMPDE_VG;

#if !defined(_X86PAE_)
  C_ASSERT(sizeof(MMPTE_VG) == sizeof(ULONG));
#else
  C_ASSERT(sizeof(MMPTE_VG) == sizeof(ULONGLONG));
#endif

/* Maximum number of page directories pages */
#ifndef _X86PAE_
  #define PD_COUNT 1        /* Only one page directory page */
#else
  #define PD_COUNT (1 << 2) /* The two most significant bits in the VA */
#endif

/* PAE not yet implemented. */
C_ASSERT(PD_COUNT == 1);

/* The number of PTEs on one page of the PT */
#define PTE_PER_PAGE (PAGE_SIZE / sizeof(MMPTE_VG))

/* The number of PDEs on one page of the PD */
#define PDE_PER_PAGE (PAGE_SIZE / sizeof(MMPDE_VG))

/* Maximum number of PDEs */
#define PDE_PER_SYSTEM (PD_COUNT * PDE_PER_PAGE)

/* Maximum number of pages for 4 GB of virtual space */
#define MI_MAX_PAGES ((1ull << 32) / PAGE_SIZE)

/* Base addresses for page tables */
#define PTE_BASE (ULONG_PTR)0xC0000000
#define PTE_TOP  (ULONG_PTR)(PTE_BASE + (MI_MAX_PAGES * sizeof(MMPTE_VG)) - 1)
#define PTE_MASK (PTE_TOP - PTE_BASE)

/* Base addreses for page directories */
#define PDE_BASE (ULONG_PTR)MiPteToPde(PTE_BASE)
#define PDE_TOP  (ULONG_PTR)(PDE_BASE + (PDE_PER_SYSTEM * sizeof(MMPDE_VG)) - 1)
#define PDE_MASK (PDE_TOP - PDE_BASE)

/* The size of the virtual memory area that is mapped using a single PDE */
#define PDE_MAPPED_VA (PTE_PER_PAGE * PAGE_SIZE)

/* Maps the virtual address to the corresponding PTE */
#define MiAddressToPte(Va) \
    ((PMMPTE_VG)(PTE_BASE + ((((ULONG_PTR)(Va)) / PAGE_SIZE) * sizeof(MMPTE_VG))))

/* Maps the virtual address to the corresponding PDE */
#define MiAddressToPde(Va) \
    ((PMMPDE_VG)(PDE_BASE + ((MiAddressToPdeOffset(Va)) * sizeof(MMPDE_VG))))

/* Takes the PDE offset (within all PDs pages) from the virtual address */
#define MiAddressToPdeOffset(Va) (((ULONG_PTR)(Va)) / PDE_MAPPED_VA)

/* Finds a PDE pointing to the PT that contains this PTE */
#define MiPteToPde(_Pte) ((PMMPDE_VG)MiAddressToPte(_Pte))

#endif

/* FUNCTIONS *****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

typedef
BOOLEAN
(__fastcall* PHOOK_ALLOW_ACTION)(
    _In_ ULONG ReturnAddress,
    _Out_ PCHAR* OutOwnerName
);

NTSTATUS
NTAPI
HkLibMain(
    _In_ PUNICODE_STRING DriverPath,
    _In_ PCHAR HookModuleName,
    _In_ PCHAR Hooked,
    _In_ PHOOK_ALLOW_ACTION InHookAllow,
    _In_ ULONG HookStart,
    _In_ ULONG HookMaxCount
);

BOOLEAN
__fastcall
HookIsAllowPrint(
   _In_ ULONG ReturnAddress,
   _Out_ PCHAR* OutOwnerName
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInfoClass,
    _Out_ PVOID SystemInfoBuffer,
    _In_ ULONG SystemInfoBufferSize,
    _Out_ PULONG BytesReturned
);

/* EOF */
