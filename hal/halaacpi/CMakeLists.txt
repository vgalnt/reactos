
add_definitions(
    -D_NTHALDLL_
    -D_NTHAL_)

add_definitions(-DMM_NEW)

include_directories(include ${REACTOS_SOURCE_DIR}/ntoskrnl/include)

# Handle the spec file for the dll name
spec2def(halaacpi.dll halaacpi.spec ADD_IMPORTLIB)

# The components generic
list(APPEND HAL_SOURCE
    acpi/acpitimer.c
    acpi/busemul.c
    acpi/dispatch.c
    acpi/halacpi.c
    acpi/halpnpdd.c
    apic/apic.c
    apic/apicacpi.c
    apic/apictimer.c
    apic/rtctimer.c
    bus/kdpci.c
    bus/pcibus.c
    generic/i386/bios.c
    generic/i386/portio.c
    generic/beep.c
    generic/cmos.c
    generic/display.c
    generic/dma.c
    generic/drive.c
    generic/halinit.c
    generic/memory.c
    generic/misc.c
    generic/reboot.c
    generic/spinlock.c
    generic/sysinfo.c
    generic/usage.c
    pic/pic.c
    up/processor.c
)

list(APPEND HAL_ASM_SOURCE
    apic/apictrap.S
    generic/v86.S
)
	
add_library(halaacpi MODULE
    ${HAL_SOURCE}
    ${HAL_ASM_SOURCE}
    version/halaacpi.rc
    ${CMAKE_CURRENT_BINARY_DIR}/halaacpi.def)

set_module_type(halaacpi kerneldll ENTRYPOINT HalInitSystem 8)
target_link_libraries(halaacpi libcntpr wdmguid)
add_dependencies(halaacpi asm psdk bugcodes xdk)
add_importlibs(halaacpi ntoskrnl)
#add_pch(halaacpi include/hal.h SOURCE)
add_cd_file(TARGET halaacpi DESTINATION reactos/system32 NO_CAB FOR all)
