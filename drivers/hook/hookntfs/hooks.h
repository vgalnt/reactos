/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Specific driver header for hooking.
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

/* Only x86 suport now! */

#pragma once

/* prolog */
#define HookProlog() \
    __asm push ebp \
    __asm mov ebp, esp

/* epilog */
#define HookEpilog() \
    __asm mov esp, ebp \
    __asm pop ebp

/* save processor registers */
#define HookSaveRegs() \
    __asm push edi  __asm push esi \
    __asm push eax  __asm push ebx  __asm push ecx  __asm push edx

/* restore processor registers */
#define HookRestoreRegs() \
    __asm pop edx  __asm pop ecx  __asm pop ebx  __asm pop eax \
    __asm pop esi  __asm pop edi

/* add nops for:
       push $+10
       push @
       jmp @
*/
#define HookAddNops() \
    __asm nop __asm  nop  __asm nop  __asm nop  __asm nop \
    __asm nop __asm  nop  __asm nop  __asm nop  __asm nop \
    __asm nop __asm  nop  __asm nop  __asm nop  __asm nop \

/* EOF */


