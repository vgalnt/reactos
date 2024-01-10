/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Specific driver for hooking.
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

#include "hookdrv.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS *****************************************************************/

ULONG HookStart = 0;
ULONG HookMaxCount = -1;

/* FUNCTIONS ****************************************************************/

BOOLEAN
__fastcall
HookIsAllowPrint(
   _In_ ULONG ReturnAddress,
   _Out_ PCHAR* OutOwnerName)
{
    if (OutOwnerName)
        *OutOwnerName = "";

    return TRUE;
}

NTSTATUS
NTAPI
HookMain(
   _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();
    DPRINT("HookMain: '%wZ'\n", RegistryPath);

    /* 8.3 file names are preferred */
    Status = HkLibMain(RegistryPath, "hookntfs.sys", "ntfs.sys", HookIsAllowPrint, HookStart, HookMaxCount);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HookMain: HkLibMain failed (%X)\n", Status);
        HkDbgBreakPoint();
    }

    DPRINT("HookMain: Finish\n");
    return STATUS_SUCCESS;
}

/* EOF */
