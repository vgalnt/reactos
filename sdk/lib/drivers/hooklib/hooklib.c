/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Library for hooking functions (use hot-patching on NT).
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

/* Only x86 suport now! */

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ndk/rtlfuncs.h>
#include "hooklib.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

PHOOK_ALLOW_ACTION HkAllowHook = NULL;

ULONG HkStartNumber = 0;
ULONG HkMaxCount = -1;

PVOID HkModuleBase = NULL;
ULONG_PTR HkModuleEnd = 0;
ULONG HkModuleSize = 0;

PVOID HkHookedBase = NULL;

ULONG DbhOffset = 0x01000000;

/* FUNCTIONS *****************************************************************/

static
PVOID
NTAPI
HkLibParseString(
    _In_ PCHAR Ptr,
    _In_ PCHAR TxtEnd,
    _Out_ PCHAR* OutIndexStr,
    _Out_ PCHAR* OutAddressStr,
    _Out_ PCHAR* OutNameStr,
    _Out_ ULONG* OutCallingType,
    _Out_ ULONG* OutNumberOfParams)
{
    PCHAR NameString = Ptr;
    PCHAR IndexString = NULL;
    PCHAR AddressString = NULL;
    PCHAR StringEnd = NULL;
    ULONG ix;

    ASSERT(Ptr);
    ASSERT(TxtEnd);

    //DPRINT("HkLibParseString: (%p, %p) '%s'\n", Ptr, TxtEnd, Ptr);

    *OutIndexStr = NULL;
    *OutAddressStr = NULL;
    *OutNameStr = NULL;

    *OutCallingType = 0;
    *OutNumberOfParams = 0;

    if (*Ptr == ';')
    {
        DPRINT1("HkLibParseString: (%p, %p) '%s'\n", Ptr, TxtEnd, Ptr);
        HkDbgBreakPoint();
        return NULL;
    }

    for (ix = 0; Ptr < TxtEnd; Ptr++, ix++)
    {
        if (*Ptr == 0x00) // End String
        {
            StringEnd = Ptr;
            break;
        }

        if (*Ptr == 0x20) // End SubString
        {
            *Ptr = 0x00;

            if (!IndexString)
            {
                ASSERT(AddressString == NULL);
                IndexString = (Ptr + 1);
            }
            else if (!AddressString)
            {
                ASSERT(IndexString != NULL);
                AddressString = (Ptr + 1);
            }
            else
            {
                DPRINT1("HkLibParseString: (%p, %p) '%s'\n", Ptr, TxtEnd, Ptr);

                ASSERT(IndexString);
                ASSERT(AddressString);

                HkDbgBreakPoint();
                continue;
            }
        }
    }

    if (!StringEnd)
    {
        DPRINT1("HkLibParseString: StringEnd == NULL\n");
        return NULL;
    }

    if (*Ptr != 0x00)
    {
        DPRINT1("HkLibParseString: *StringEnd != %X\n", (UCHAR)*Ptr);
        return NULL;
    }

    ASSERT(NameString < IndexString);
    ASSERT(IndexString < AddressString);
    ASSERT(AddressString < StringEnd);
    ASSERT(StringEnd < TxtEnd);

    if (NameString[0] == ';')
    {
        DPRINT1("HkLibParseString: (%p, %p) '%s'\n", Ptr, TxtEnd, Ptr);
        HkDbgBreakPoint();
        return NULL;
    }

    if (NameString[0] == '@')
    {
        /* __fastcall */
        *OutCallingType = 1;
    }
    else if (NameString[0] == '_')
    {
        /* __stdcall */
        *OutCallingType = 2;
    }
    else
    {
        /* unsupported (FIXME) */
        DPRINT1("HkLibParseString: Unsupported calling type %X\n", NameString[0]);
    }

    for (Ptr = &NameString[1];
         *Ptr != 0x20 && *Ptr != 0x00;
         Ptr++)
    {
        if (*Ptr == '@')
        {
            Ptr++;
            ASSERT(*Ptr >= 0x30 && *Ptr <= 0x39);

            *OutNumberOfParams = (strtoul(Ptr, NULL, 10) / 4);

            break;
        }
    }

    *OutNameStr = NameString;
    *OutIndexStr = IndexString;
    *OutAddressStr = AddressString;

    //DPRINT1("[%X] NameString '%s', IndexString '%s', AddressString '%s'\n", ix, NameString, IndexString, AddressString);

    return StringEnd;
}

static
VOID
NTAPI
HkLibUnDecorateSymbolName(
    _In_ PCHAR NameString,
    _In_ PCHAR UnDecorateName,
    _In_ PCHAR UnDecorateEnd)
{
    if (*NameString == '_' || *NameString == '@')
        NameString++;

    while (*NameString != '@')
    {
        *UnDecorateName = *NameString;

        ASSERT(UnDecorateName < UnDecorateEnd);

        UnDecorateName++;
        NameString++;
    }

    *UnDecorateName = 0;
}

static
VOID
NTAPI
HkLibGetNameCallingTypeChar(
    _In_ ULONG CallingType,
    _Out_ CHAR* OutCallingTypeChar)
{
    if (CallingType == 1)
    {
        OutCallingTypeChar[0] = 0; // '@'
    }
    else if (CallingType == 2)
    {
        OutCallingTypeChar[0] = '_';
    }
    else
    {
        DPRINT1("HkLibGetNameCallingTypeChar: !!! Unsupported CallingType %X\n", CallingType);
        OutCallingTypeChar[0] = '?';
    }

    OutCallingTypeChar[1] = 0;
}

//-----------------------------------------------------------------------------

VOID
NTAPI
HkLibDump(
    _In_ PVOID Ptr,
    _In_ ULONG Length)
{
    PCHAR Hexof = "0123456789ABCDEF";
    PUCHAR uPtr = Ptr;
    CHAR Msg[128];
    ULONG ix;
    ULONG jx;

return;

    DPRINT1("HkLibDump: Ptr %p, Length %X\n", Ptr, Length);

    for (ix = 0; ix < Length; ix += 0x10)
    {
        RtlStringCchPrintfA(Msg, sizeof(Msg),"%08x: ", ix);
        RtlFillMemory((Msg + 10), (3 * 0x10 + 1 + 0x10), ' ');

        for (jx = 0; jx < min(0x10, (Length - ix)); jx++)
        {
            Msg[10 + 3 * jx + 0] = Hexof[uPtr[ix + jx] >> 4];
            Msg[10 + 3 * jx + 1] = Hexof[uPtr[ix + jx] & 0x0F];
            Msg[10 + 3 * jx + 2] = ' ';

            if (uPtr[ix + jx] >= 0x20 && uPtr[ix + jx] < 0x7F)
            {
                Msg[10 + 3 * 0x10 + 1 + jx] = uPtr[ix + jx];
            }
            else
            {
                Msg[10 + 3 * 0x10 + 1 + jx] = ('.');
            }
        }

        Msg[10 + 3 * 0x10] = ' ';
        Msg[10 + 3 * 0x10 + 1 + 0x10] = '\0';

        DbgPrint("%s\n", Msg);
    }
}

NTSTATUS
NTAPI
HkLibGetModuleBase(
    _In_ PCHAR ModuleName,
    _Out_ PVOID* OutBase,
    _Out_ ULONG* OutBaseSize)
{
    PRTL_PROCESS_MODULE_INFORMATION ModuleEntry;
    PRTL_PROCESS_MODULES ModulesInfo;
    PULONG SystemInfoBuffer;
    PCHAR Name;
    ULONG SystemInfoBufferSize = 0;
    ULONG Size;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("HkLibGetModuleBase: ModuleName '%s'\n", ModuleName);

    Status = ZwQuerySystemInformation(SystemModuleInformation, &SystemInfoBufferSize, 0, &SystemInfoBufferSize);
    if (!SystemInfoBufferSize)
    {
        DPRINT1("HkLibGetModuleBase: failed status (%X)\n", Status);
        return Status;
    }

    Size = (SystemInfoBufferSize * 2);

    SystemInfoBuffer = ExAllocatePoolWithTag(NonPagedPool, Size, HOOKLIB_POOL_TAG);
    if (!SystemInfoBuffer)
    {
        DPRINT1("HkLibGetModuleBase: allocate failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(SystemInfoBuffer, Size);

    Status = ZwQuerySystemInformation(SystemModuleInformation, SystemInfoBuffer, Size, &SystemInfoBufferSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkLibGetModuleBase: failed status (%X)\n", Status);
        goto Exit;
    }

    ModulesInfo = (PRTL_PROCESS_MODULES)(SystemInfoBuffer);
    ModuleEntry = ModulesInfo->Modules;

    for (ix = 0; ix < ModulesInfo->NumberOfModules; ix++)
    {
        Name = (ModuleEntry[ix].FullPathName + ModuleEntry[ix].OffsetToFileName);

        DPRINT("HkLibGetModuleBase: [%X] '%s'\n", ix, Name);

        if (!_stricmp(Name, ModuleName))
        {
            DPRINT("HkLibGetModuleBase: found module %X\n", ix);

            *OutBase = ModuleEntry[ix].ImageBase;
            *OutBaseSize = ModuleEntry[ix].ImageSize;

            break;
        }
    }

Exit:

    if (SystemInfoBuffer)
        ExFreePoolWithTag(SystemInfoBuffer, HOOKLIB_POOL_TAG);

    return Status;
}

static
NTSTATUS
NTAPI
HkLibOpenRegistryKey(
    _In_ PWCHAR KeyName,
    _In_ HANDLE RootKey,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ HANDLE* OutKeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyString;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HkLibOpenRegistryKey: KeyName %S\n", KeyName);

    /* Initialize the object attributes */
    RtlInitUnicodeString(&KeyString, KeyName);
    InitializeObjectAttributes(&ObjectAttributes, &KeyString, OBJ_CASE_INSENSITIVE, RootKey, NULL);

    /* Open the key, returning the status */
    Status = ZwOpenKey(OutKeyHandle, DesiredAccess, &ObjectAttributes);

    DPRINT("HkLibOpenRegistryKey: Status %X\n", Status);

    return Status;
}

/* Get address for exported function */
static
PVOID
NTAPI
HkLibGetExportedFunction(
    _In_ PVOID DllBase,
    _In_ PCHAR FunctionName)
{
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PUSHORT OrdinalTable;
    PULONG ExportTable;
    PULONG NameTable;
    PVOID Function;
    ULONG ExportSize;
    LONG Low = 0;
    LONG Mid = 0;
    LONG High;
    LONG Ret;
    USHORT Ordinal;

    //DPRINT("HkLibGetExportedFunction: DllBase %X, Function '%s'\n", DllBase, FunctionName);

    /* Get the export directory */
    ExportDirectory = RtlImageDirectoryEntryToData(DllBase,
                                                   TRUE,
                                                   IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                   &ExportSize);
    if (!ExportDirectory)
    {
        DPRINT1("HkLibGetExportedFunction: ExportDirectory == NULL\n");
        return NULL;
    }

    /* Setup name tables */
    NameTable = Add2Ptr(DllBase, ExportDirectory->AddressOfNames);
    OrdinalTable = Add2Ptr(DllBase, ExportDirectory->AddressOfNameOrdinals);

    /* Do a binary search */
    High = (ExportDirectory->NumberOfNames - 1);

    while (High >= Low)
    {
        /* Get new middle value */
        Mid = ((Low + High) >> 1);

        /* Compare name */
        Ret = strcmp(FunctionName, ((PCHAR)DllBase + NameTable[Mid]));

        if (Ret < 0)
        {
            /* Update high */
            High = (Mid - 1);
        }
        else if (Ret > 0)
        {
            /* Update low */
            Low = (Mid + 1);
        }
        else
        {
            /* We got it */
            break;
        }
    }

    /* Check if we couldn't find it */
    if (High < Low)
    {
        DPRINT1("HkLibGetExportedFunction: High < Low\n");
        return NULL;
    }

    /* Otherwise, this is the ordinal */
    Ordinal = OrdinalTable[Mid];

    /* Validate the ordinal */
    if (Ordinal >= ExportDirectory->NumberOfFunctions)
    {
        DPRINT1("HkLibGetExportedFunction: Ordinal >= ExportDirectory->NumberOfFunctions\n");
        return NULL;
    }

    /* Resolve the address and write it */
    ExportTable = Add2Ptr(DllBase, ExportDirectory->AddressOfFunctions);
    Function = Add2Ptr(DllBase, ExportTable[Ordinal]);

    /* We found it! */
    ASSERT((Function < (PVOID)ExportDirectory) ||
           (Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize)));

    return Function;
}

/* Draft! */
static
BOOLEAN
NTAPI
HkLibCheckPte(PVOID Address)
{
    PMMPTE_VG Pte;
    PMMPDE_VG Pde;
    ULONG dummy = 0;
    ULONG ix = 0;
    KIRQL OldIrql;
    BOOLEAN IsRaisedIrql = 0;

    Pde = MiAddressToPde(Address);
    Pte = MiAddressToPte(Address);

    while (!Pde->u.Hard.Valid)
    {
        if (*(PCHAR)Address) {dummy++;}

        ix++;
        if (ix > 100)
        {
            DPRINT1("HkLibCheckPte: Address %p, Pde %p [%p]\n", Address, Pde, Pde->u.Long);
          #if DBG
            HkLibDump(Address, 0x20);
            HkLibDump(Pde, 0x50);
            HkDbgBreakPoint();
          #endif
            return FALSE;
        }
    }

    ix = 0;
    while (!Pde->u.Hard.Write)
    {
        if (KeGetCurrentIrql() < 2) // FIXME...
        {
            KeRaiseIrql(2, &OldIrql);
            IsRaisedIrql = 1;          
        }

        Pde->u.Hard.Write = 1;

        if (IsRaisedIrql)
            KeLowerIrql(OldIrql);

        ix++;
        if (ix > 100)
        {
            DPRINT1("HkLibCheckPte: Address %p, Pde %p [%p]\n", Address, Pde, Pde->u.Long);
          #if DBG
            HkLibDump(Address, 0x20);
            HkLibDump(Pde, 0x50);
            HkDbgBreakPoint();
          #endif
            return FALSE;
        }
    }

    if (Pde->u.Hard.LargePage)
        return TRUE;

    ix = 0;
    while (!Pte->u.Hard.Valid)
    {
        if (*(PCHAR)Address) {dummy++;}

        if (KeGetCurrentIrql() < 2)
        {
            KeRaiseIrql(2, &OldIrql);
            IsRaisedIrql = 1;          
        }

        Pte->u.Hard.Valid = 1;

        if (IsRaisedIrql)
            KeLowerIrql(OldIrql);

        ix++;
        if (ix > 100)
        {
            DPRINT1("HkLibCheckPte: Address %p, Pte %p [%p]\n", Address, Pte, Pte->u.Long);
          #if DBG
            HkLibDump(Address, 0x20);
            HkLibDump(Pte, 0x50);
            HkDbgBreakPoint();
          #endif
            return FALSE;
        }
    }

    ix = 0;
    while (!Pte->u.Hard.Write)
    {
        if (KeGetCurrentIrql() < 2)
        {
            KeRaiseIrql(2, &OldIrql);
            IsRaisedIrql = 1;          
        }

        Pte->u.Hard.Write = 1;

        if (IsRaisedIrql)
            KeLowerIrql(OldIrql);

        ix++;
        if (ix > 100)
        {
            DPRINT1("HkLibCheckPte: Address %p, Pte %p [%p]\n", Address, Pte, Pte->u.Long);
          #if DBG
            HkLibDump(Address, 0x20);
            HkLibDump(Pte, 0x50);
            HkDbgBreakPoint();
          #endif
            return FALSE;
        }
    }

    return TRUE;
}

/* Draft! */
static
NTSTATUS
NTAPI
HkLibAddHook(
    _In_ ULONG HookedOffset, // for Hooked module
    _In_ PVOID HookFuncVa,   // @hook from Hook module
    _In_ ULONG DbhOffset,
    _In_ ULONG CallType,
    _In_ ULONG NumberOfParams)
{
    PUCHAR HookedAddress;  // address target function for the hooking
    PUCHAR JmpAddress;     // place for [call @hook] (or [jmp @hook]) insruction 
    PUCHAR HookAddress;    // address @hook function from the Hook module
    ULONG HookNextPage;
    LONG JmpOffset;
    //PUCHAR PushAddress;
    PUCHAR CallAddress;
    PUCHAR ReturnAddress;
    LONG dummy = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    DPRINT("HkLibAddHook: HookedOffset %p, HookFuncVa %X, DbhOffset %X, CallType %X, NumberOfParams %X\n", HookedOffset, HookFuncVa, DbhOffset, CallType, NumberOfParams);

    HookedAddress = Add2Ptr(HkHookedBase, (HookedOffset - DbhOffset));
    JmpAddress = (HookedAddress - 5);

  #if DBG
    HkLibDump((HookedAddress - 0x10), 0x20);
    HkLibDump(HookFuncVa, 0x50);
  #endif

    /* Test PTE */

    if (*(PUCHAR)HookedAddress) {dummy++;} // Hooked

    if ((0x1000 - ((ULONG)HookedAddress & (0x1000 - 1))) < 0x20)
    {
        if (*(HookedAddress + 0x1000)) {dummy++;}
        if (!HkLibCheckPte(HookedAddress + 0x1000)) {return STATUS_ACCESS_DENIED;}
    }
   
    if (*(PUCHAR)HookFuncVa) {dummy++;} // Hook

    HookNextPage = (((ULONG)HookFuncVa + 0x1000) & ~(0x1000 - 1));
    if (HookNextPage <= (HkModuleEnd & ~(0x1000 - 1)))
    {
        if (*((PUCHAR)HookNextPage)) {dummy++;}
        if (!HkLibCheckPte((PUCHAR)HookNextPage)) {return STATUS_ACCESS_DENIED;}
    }

    /* Test Jmp Address */

    if ((*(JmpAddress+0) == 0x90 && *(JmpAddress+1) == 0x90 && *(JmpAddress+2) == 0x90 && *(JmpAddress+3) == 0x90 && *(JmpAddress+4) == 0x90) ||
        (*(JmpAddress+0) == 0xCC && *(JmpAddress+1) == 0xCC && *(JmpAddress+2) == 0xCC && *(JmpAddress+3) == 0xCC && *(JmpAddress+4) == 0xCC))
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
      #if DBG
        DPRINT1("HkLibAddHook: place for patch not free ...\n");
        HkLibDump((JmpAddress-11), 0x20);
      #endif
        return Status;
    }

    /* Hooking */

    if (*(HookedAddress+0) == 0x8B && *(HookedAddress+1) == 0xFF) // mov edi, edi
    {
        /* Calculate offset */
        JmpOffset = ((LONG)HookFuncVa - (LONG)(JmpAddress+5));

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*JmpAddress) {dummy++;}
        if (!HkLibCheckPte(JmpAddress)) {return STATUS_ACCESS_DENIED;}

        *(JmpAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(JmpAddress+1) = JmpOffset;

        /* Save old values in Hooks space */
        //---------------------------------------------------------------------
        HookAddress = HookFuncVa;

        if (*HookAddress) {dummy++;}
        if (!HkLibCheckPte(HookAddress)) {return STATUS_ACCESS_DENIED;}

        if (*(HookAddress+0) == 0x8B && *(HookAddress+1) == 0xFF) // mov edi, edi
        {
            *(HookAddress+0) = 0x90;
            *(HookAddress+1) = 0x90;
        }
        for (; ; HookAddress++) {
            if (*(HookAddress+0) == 0x90 &&
                *(HookAddress+1) == 0x90 &&
                *(HookAddress+2) == 0x90 &&
                *(HookAddress+3) == 0x90 &&
                *(HookAddress+4) == 0x90)
            {
                break;
            }
        }

        ReturnAddress = HookAddress;
        CallAddress = (HookAddress + 10);

        //---------------------------------------------------------------------
        if (*ReturnAddress) {dummy++;}
        if (!HkLibCheckPte(ReturnAddress)) {return STATUS_ACCESS_DENIED;}

        *(ReturnAddress+0) = 0x68; // push (ReturnAddress+15)
        *(PLONG)(ReturnAddress+1) = (LONG)(ReturnAddress+15);

        /* Calculate offset */
        JmpOffset = ((LONG)(HookedAddress+2) - (LONG)(CallAddress+5));

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*CallAddress) {dummy++;}
        if (!HkLibCheckPte(CallAddress)) {return STATUS_ACCESS_DENIED;}

        *(CallAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(CallAddress+1) = JmpOffset;

        /* Replace with (jmp $-5) */
        //---------------------------------------------------------------------
        if (*HookedAddress) {dummy++;}
        if (!HkLibCheckPte(HookedAddress)) {return STATUS_ACCESS_DENIED;}

        *(HookedAddress+0) = 0xEB;
        *(HookedAddress+1) = 0xF9;

      #if DBG
        HkLibDump((HookedAddress-0x10), 0x20);
        HkLibDump(HookFuncVa, 0x50);
      #endif

        Status = STATUS_SUCCESS;
    }
#if 0
    else if (*(HookedAddress+0) == 0x6A && *(HookedAddress+2) == 0x68) // push BYTE, push OFFSET
    {
        /* Calculate offset */
        JmpOffset = (LONG)HookFuncVa - (LONG)(JmpAddress+5);

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*JmpAddress) {dummy++;}
        if (!HkLibCheckPte(JmpAddress)) {return STATUS_ACCESS_DENIED;}

        *(JmpAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(JmpAddress+1) = JmpOffset;

        /* Save old values in Hooks space */
        //---------------------------------------------------------------------
        HookAddress = HookFuncVa;

        if (*HookAddress) {dummy++;}
        if (!HkLibCheckPte(HookAddress)) {return STATUS_ACCESS_DENIED;}

        if (*(HookAddress+0) == 0x8B && // mov edi, edi
            *(HookAddress+1) == 0xFF)
        {
            *(HookAddress+0) = 0x90;
            *(HookAddress+1) = 0x90;
        }
        for (; ; HookAddress++) {
            if (*(HookAddress+0) == 0x90 &&
                *(HookAddress+1) == 0x90 &&
                *(HookAddress+2) == 0x90 &&
                *(HookAddress+3) == 0x90 &&
                *(HookAddress+4) == 0x90)
            {
                break;
            }
        }

        ReturnAddress = HookAddress;
        PushAddress = (HookAddress + 5);
        CallAddress = (HookAddress + 10);

        //---------------------------------------------------------------------
        if (*ReturnAddress) {dummy++;}
        if (!HkLibCheckPte(ReturnAddress)) {return STATUS_ACCESS_DENIED;}

        *(ReturnAddress+0) = 0x68; // push (ReturnAddress+15)
        *(PLONG)(ReturnAddress+1) = (LONG)(ReturnAddress+15);

        /* Save Push in Hooks space */
        //---------------------------------------------------------------------
        if (*PushAddress) {dummy++;}
        if (!HkLibCheckPte(PushAddress)) {return STATUS_ACCESS_DENIED;}

        *(PushAddress+0) = *(HookedAddress+0); // push 0xnn (offset)
        *(PushAddress+1) = *(HookedAddress+1);

        //---------------------------------------------------------------------
        /* Calculate offset */
        JmpOffset = ((LONG)(HookedAddress+2) - (LONG)(CallAddress+5));

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*CallAddress) {dummy++;}
        if (!HkLibCheckPte(CallAddress)) {return STATUS_ACCESS_DENIED;}

        *(CallAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(CallAddress+1) = JmpOffset;

        /* Replace with (jmp $-5) */
        //---------------------------------------------------------------------
        if (*HookedAddress) {dummy++;}
        if (!HkLibCheckPte(HookedAddress)) {return STATUS_ACCESS_DENIED;}

        *(HookedAddress+0) = 0xEB;
        *(HookedAddress+1) = 0xF9;

      #if DBG
        HkLibDump((HookedAddress-0x10), 0x20);
        HkLibDump(HookFuncVa, 0x50);
      #endif

        Status = STATUS_SUCCESS;
    }
    else if (*(HookedAddress+0) == 0x68 && *(HookedAddress+5) == 0x68) // push DWORD, push OFFSET
    {
        /* Calculate offset */
        JmpOffset = (LONG)HookFuncVa - (LONG)(JmpAddress+5);

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*JmpAddress) {dummy++;}
        if (!HkLibCheckPte(JmpAddress)) {return STATUS_ACCESS_DENIED;}

        *(JmpAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(JmpAddress+1) = JmpOffset;

        /* Save old values in Hooks space */
        //---------------------------------------------------------------------
        HookAddress = HookFuncVa;

        if (*HookAddress) {dummy++;}
        if (!HkLibCheckPte(HookAddress)) {return STATUS_ACCESS_DENIED;}

        if (*(HookAddress+0) == 0x8B && *(HookAddress+1) == 0xFF) // mov edi, edi
        {
            *(HookAddress+0) = 0x90;
            *(HookAddress+1) = 0x90;
        }
        for (; ; HookAddress++) {
            if (*(HookAddress+0) == 0x90 &&
                *(HookAddress+1) == 0x90 &&
                *(HookAddress+2) == 0x90 &&
                *(HookAddress+3) == 0x90 &&
                *(HookAddress+4) == 0x90)
            {
                break;
            }
        }

        ReturnAddress = HookAddress;
        PushAddress = (HookAddress + 5);
        CallAddress = (HookAddress + 10);

        //---------------------------------------------------------------------
        if (*ReturnAddress) {dummy++;}
        if (!HkLibCheckPte(ReturnAddress)) {return STATUS_ACCESS_DENIED;}

        *(ReturnAddress+0) = 0x68; // push (ReturnAddress+15)
        *(PLONG)(ReturnAddress+1) = (LONG)(ReturnAddress+15);

        //---------------------------------------------------------------------
        /* Save Push in Hooks space */
        if (*PushAddress) {dummy++;}
        if (!HkLibCheckPte(PushAddress)) {return STATUS_ACCESS_DENIED;}

        *(PushAddress+0) = *(HookedAddress+0); // push 0xnnnnnnnn
        *(PushAddress+1) = *(HookedAddress+1);
        *(PushAddress+2) = *(HookedAddress+2);
        *(PushAddress+3) = *(HookedAddress+3);
        *(PushAddress+4) = *(HookedAddress+4);

        //---------------------------------------------------------------------
        /* Calculate offset */
        JmpOffset = ((LONG)(HookedAddress+5) - (LONG)(CallAddress+5));

        /* Replace with (jmp ptr adr offset) - jump to new patch code */
        if (*CallAddress) {dummy++;}
        if (!HkLibCheckPte(CallAddress)) {return STATUS_ACCESS_DENIED;}

        *(CallAddress+0) = 0xE9; // jmp 0xnnnnnnnn (offset)
        *(PLONG)(CallAddress+1) = JmpOffset;

        //---------------------------------------------------------------------
        /* Replace with (jmp $-5) */
        if (*HookedAddress) {dummy++;}
        if (!HkLibCheckPte(HookedAddress)) {return STATUS_ACCESS_DENIED;}

        *(HookedAddress+0) = 0xEB;
        *(HookedAddress+1) = 0xF9;

      #if DBG
        HkLibDump((HookedAddress-0x10), 0x20);
        HkLibDump(HookFuncVa, 0x50);
      #endif

        if (dummy) {HkLibCheckPte(HookedAddress);}

        Status = STATUS_SUCCESS;
    }
#endif
    else
    {
        DPRINT1("HkLibAddHook: not implemented\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    return Status;
}

static
NTSTATUS
NTAPI
HkLibTestHook(
    ULONG HookedOffset, // for Hooked module
    PVOID HookFuncVa,   // @hook from HookDrv
    ULONG DbhOffset,
    ULONG CallType,
    ULONG NumberOfParams)
{
    PUCHAR HookedAddress; // address target function for the hooking
    PUCHAR JmpAddress;    // place the calling patch
    NTSTATUS Status;

    //DPRINT("HkLibTestHook: HookedOffset %p, HookFuncVa %X, DbhOffset %X, CallType %X, NumberOfParams %X\n", HookedOffset, HookFuncVa, DbhOffset, CallType, NumberOfParams);

    if (HookedOffset <= DbhOffset)
    {
        DPRINT1("HkLibTestHook: HookedOffset <= DbhOffset, return\n");
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    HookedAddress = Add2Ptr(HkHookedBase, (HookedOffset - DbhOffset));
    JmpAddress = (HookedAddress - 5);

    if ((*(JmpAddress+0) == 0x90 && *(JmpAddress+1) == 0x90 && *(JmpAddress+2) == 0x90 && *(JmpAddress+3) == 0x90 && *(JmpAddress+4) == 0x90) ||
        (*(JmpAddress+0) == 0xCC && *(JmpAddress+1) == 0xCC && *(JmpAddress+2) == 0xCC && *(JmpAddress+3) == 0xCC && *(JmpAddress+4) == 0xCC))
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        DPRINT1("HkLibTestHook: no free space for patch %X\n", JmpAddress);
        Status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (*(HookedAddress+0) == 0x8B && *(HookedAddress+1) == 0xFF) {
        ;
    }
#if 0
    else if (*(HookedAddress+0) == 0x6A && *(HookedAddress+2) == 0x68) {
        ;
    }
    else if (*(HookedAddress+0) == 0x68 && *(HookedAddress+5) == 0x68) {
        ;
    }
#endif
    else {

      #if DBG
        DPRINT1("HkLibTestHook: not implemented\n");
        //HkLibDump(HookedAddress - 0x10, 0x20);
      #endif
        Status = STATUS_NOT_IMPLEMENTED;
    }

Exit:
    return Status;
}

static
NTSTATUS
NTAPI
HkLibPatchEntry(
    _In_ PCHAR Ptr,
    _In_ PCHAR PtrEnd)
{
    PVOID HookFuncVa;
    PCHAR StringEnd;
    PCHAR NameString;
    PCHAR IndexString;
    PCHAR AddressString;
    ULONG HookedOffset;
    CHAR UnDecorateName[CHAR_PER_LINE];
    CHAR HkFunctionString[CHAR_PER_LINE];
    ULONG NumberOfParams;
    ULONG CallingType;
    CHAR CallingTypeChar[2];
    NTSTATUS Status;

    if (*Ptr == ';')
    {
        DPRINT("HkLibPatchEntry: skip line '%s'\n", Ptr);
        return STATUS_SUCCESS;
    }

    StringEnd = HkLibParseString(Ptr, PtrEnd, &IndexString, &AddressString, &NameString, &CallingType, &NumberOfParams);
    if (!StringEnd)
    {
        DPRINT1("HkLibPatchEntry: StringEnd == NULL. Ptr %p\n", Ptr);
        HkDbgBreakPoint();
        return STATUS_UNSUCCESSFUL;
    }

    DPRINT("HkLibPatchEntry: Index '%s', Address '%s', Name '%s'\n", IndexString, AddressString, NameString);

    ASSERT(IndexString);
    ASSERT(AddressString);
    ASSERT(NameString);

    RtlZeroMemory(UnDecorateName, CHAR_PER_LINE);
    HkLibUnDecorateSymbolName(NameString, UnDecorateName, (UnDecorateName + CHAR_PER_LINE));

    RtlZeroMemory(HkFunctionString, CHAR_PER_LINE);
    HkLibGetNameCallingTypeChar(CallingType, CallingTypeChar);

    Status = RtlStringCbPrintfA(HkFunctionString, CHAR_PER_LINE, "%s%d%s%s", "Hk", (NumberOfParams * 4), CallingTypeChar, UnDecorateName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkLibPatchEntry: RtlStringCbPrintfA() fail (%X)\n", Status);
        HkDbgBreakPoint();
        return Status;
    }

    HookFuncVa = HkLibGetExportedFunction(HkModuleBase, HkFunctionString);
    if (!HookFuncVa)
    {
        DPRINT1("HkLibPatchEntry: '%s' not found\n", HkFunctionString);
        HkDbgBreakPoint();
        return STATUS_NOT_FOUND;
    }

    DPRINT("HkLibPatchEntry: Ptr %X, End %X, Idx '%s', Off '%s', Name '%s', Exp %X\n",
           Ptr, StringEnd, IndexString, AddressString, NameString, HookFuncVa);

    ASSERT(AddressString != NULL);
    HookedOffset = strtoul(AddressString, NULL, 16);

    Status = HkLibTestHook(HookedOffset, HookFuncVa, DbhOffset, CallingType, NumberOfParams);
    if (!NT_SUCCESS(Status))
    {
        switch (Status)
        {
            case STATUS_INVALID_PARAMETER:
              DPRINT1("'%s' - invalid parameter\n", Ptr);
              break;

            case STATUS_NOT_SUPPORTED:
              DPRINT1("'%s' - not suported\n", Ptr);
              break;

            case STATUS_NOT_IMPLEMENTED:
              DPRINT1("'%s' - not implemented\n", Ptr);
              break;

            default:
              DPRINT1("HkLibPatchEntry: HkLibTestHook failed (%X)\n", Status);
              break;
        }

        return Status;
    }

    Status = HkLibAddHook(HookedOffset, HookFuncVa, DbhOffset, CallingType, NumberOfParams);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkLibPatchEntry: HkLibAddHook failed (%X)\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
HkLibEnumHookList(
    _In_ HANDLE ParametersKey)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo = NULL;
    ANSI_STRING DestinationString;
    UNICODE_STRING SourceString;
    PWCHAR Ptr;
    PCHAR PtrEnd;
    ULONG ResultLength;
    ULONG Size;
    ULONG Idx;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();
    DPRINT("HkLibEnumHookList: RootKey %p\n", ParametersKey);

    /* Allocate the space needed to hold the full value information */
    Size = (sizeof(KEY_VALUE_FULL_INFORMATION) + 260);

    ValueInfo = ExAllocatePoolWithTag(NonPagedPool, Size, HOOKLIB_POOL_TAG);
    if (!ValueInfo)
    {
        DPRINT1("HkLibEnumHookList: allocate failed\n");
        goto Exit;
    }

    for (Idx = 0; ; Idx++, HkStartNumber++)
    {
        if (HkStartNumber >= HkMaxCount)
            return STATUS_SUCCESS;

        /* Query the value in the key */
        Status = ZwEnumerateValueKey(ParametersKey, Idx, KeyValueFullInformation, ValueInfo, Size, &ResultLength);
        if (!NT_SUCCESS(Status))
        {
            if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
                continue;

            goto Exit;
        }

        if (ValueInfo->Type != REG_SZ || ValueInfo->DataLength > 260)
            continue;

        if (ValueInfo->NameLength > (9 * sizeof(WCHAR)))
        {
            DPRINT("HkLibEnumHookList: invalid length name\n");
            continue;
        }

        Ptr = Add2Ptr(ValueInfo, ValueInfo->DataOffset);
        if (*Ptr == 0x003B)  // Skip if ';' 
            continue;

        DPRINT("HkLibEnumHookList: %S\n", Ptr);

        RtlInitUnicodeString(&SourceString, Ptr);
        RtlInitAnsiString(&DestinationString, " ");

        Status = RtlUnicodeStringToAnsiString(&DestinationString, &SourceString, TRUE);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("HkLibEnumHookList: RtlUnicodeStringToAnsiString() fail\n");
            goto Exit;
        }

        PtrEnd = (DestinationString.Buffer + DestinationString.Length + 1);

        Status = HkLibPatchEntry(DestinationString.Buffer, PtrEnd);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("HkLibEnumHookList: HkLibPatchEntry for '%s' fail (%X)\n", DestinationString.Buffer, Status);
        }

        RtlFreeAnsiString(&DestinationString);
    }

Exit:

    if (NT_SUCCESS(Status))
        Status = STATUS_SUCCESS;

    if (ValueInfo)
        ExFreePoolWithTag(ValueInfo, HOOKLIB_POOL_TAG);

    return Status;
}

static
NTSTATUS
NTAPI
HkLibEnum(
    _In_ PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE RootKey = NULL;
    HANDLE ParametersKey = NULL;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HkLibEnum: RegistryPath '%wZ'\n", RegistryPath);

    /* Open the PCI key */
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&RootKey, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkLibEnum: ZwOpenKey() failed (%X)\n", Status);
        goto Exit;
    }

    /* Open the Parameters subkey */
    Status = HkLibOpenRegistryKey(L"Parameters", RootKey, KEY_QUERY_VALUE, &ParametersKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkLibEnum: HkLibOpenRegistryKey() failed (%X)\n", Status);
        goto Exit;
    }

    /* Enum the list of all known hooks */
    Status = HkLibEnumHookList(ParametersKey);

    if (!NT_SUCCESS(Status) && (Status != STATUS_NO_MORE_ENTRIES))
    {
        DPRINT1("HkLibEnum: HkLibEnumHookList() failed (%X)\n", Status);
        goto Exit;
    }

Exit:

    return Status;
}

NTSTATUS
NTAPI
HkLibMain(
    _In_ PUNICODE_STRING DriverPath,
    _In_ PCHAR HookModuleName,
    _In_ PCHAR HookedModuleName,
    _In_ PHOOK_ALLOW_ACTION InHookAllow,
    _In_ ULONG HookStart,
    _In_ ULONG HookMaxCount)
{
    ULONG dummySize;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    DPRINT1("HkLibMain: '%wZ', '%s', '%s', %p, %X, %X\n",
            DriverPath, HookModuleName, HookedModuleName, InHookAllow, HookStart, HookMaxCount);

    HkAllowHook = InHookAllow;
    HkStartNumber = HookStart;
    HkMaxCount = HookMaxCount;

    Status = HkLibGetModuleBase(HookModuleName, &HkModuleBase, &HkModuleSize);

    if (!NT_SUCCESS(Status) || !HkModuleBase || !HkModuleSize)
    {
        DPRINT1("HkLibMain: '%s' not found (%X)\n", HookModuleName, Status);
        HkDbgBreakPoint();
        goto Exit;
    }

    HkModuleEnd = ((ULONG_PTR)HkModuleBase + HkModuleSize);

    Status = HkLibGetModuleBase(HookedModuleName, &HkHookedBase, &dummySize);

    if (!NT_SUCCESS(Status) || !HkHookedBase || !dummySize)
    {
        DPRINT1("HkLibMain: '%s' not found (%X)\n", HookedModuleName, Status);
        DPRINT1("HkLibMain: HkHookedBase %p (%X)\n", HkHookedBase, dummySize);
        HkDbgBreakPoint();
        goto Exit;
    }

    Status = HkLibEnum(DriverPath);

    if (!NT_SUCCESS(Status) && (Status != STATUS_NO_MORE_ENTRIES))
    {
        DPRINT1("HkLibMain: HkLibEnum() failed (%X)\n", Status);
        goto Exit;
    }

Exit:

    DPRINT1("HkLibMain: Finish\n");

    return STATUS_SUCCESS;
}

/* EOF */
