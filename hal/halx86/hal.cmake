
list(APPEND HAL_ASM_SOURCE
    generic/systimer.S
    generic/trap.S
    up/pic.S)

list(APPEND HAL_SOURCE
    generic/clock.c
    generic/profil.c
    generic/spinlock.c
    generic/timer.c
    up/halinit.c
    up/irql.c
    up/pic.c
    up/processor.c)

add_asm_files(lib_hal_hal_asm ${HAL_ASM_SOURCE})
add_object_library(lib_hal_hal ${HAL_SOURCE} ${lib_hal_hal_asm})
add_dependencies(lib_hal_hal asm bugcodes xdk)
