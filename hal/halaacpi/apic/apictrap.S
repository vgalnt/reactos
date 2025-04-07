
/* INCLUDES ******************************************************************/

#include <asm.inc>
#include <ks386.inc>
#include <internal/i386/asmmacro.S>

MACRO(HAL_GENERATE_INT_ENTRY, Vector)
    int &Vector
    ret
    nop
ENDM

.code

TRAP_ENTRY HalpClockInterrupt, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpClockInterruptStub, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpProfileInterrupt, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpApicRebootService, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpBroadcastCallService, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpPerfInterrupt, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpIpiHandler, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpLocalApicErrorService, KI_PUSH_FAKE_ERROR_CODE
TRAP_ENTRY HalpTrap0D, 0

PUBLIC _PicSpuriousService37
_PicSpuriousService37:
    /* iret */
    .byte HEX(CF), HEX(90)

PUBLIC _ApicSpuriousService
_ApicSpuriousService:
    /* iret */
    .byte HEX(CF), HEX(90)

PUBLIC _HwInterruptTable
_HwInterruptTable:
HAL_GENERATE_INT_ENTRY 0
HAL_GENERATE_INT_ENTRY 1
HAL_GENERATE_INT_ENTRY 2
.long HEX(90C303CD) // HACK hardcode due compilator - {int 3, ret, nop}
i = HEX(4)
REPEAT 251
    HAL_GENERATE_INT_ENTRY %i
    i = i + 1
ENDR
.long HEX(CCCCCCCC) // int [255] -> {int 3} (Debugger Trap)
.long HEX(CCCCCCCC) // for HotPatching next function

END
