
include_directories(
    ${REACTOS_SOURCE_DIR}/sdk/lib/arbiter)

list(APPEND HAL_LEGACY_SOURCE
    legacy/bus/bushndlr.c
    legacy/bus/cmosbus.c
    legacy/bus/eisabus.c
    legacy/bus/isabus.c
    legacy/bus/pcibus.c
    ${CMAKE_CURRENT_BINARY_DIR}/pci_classes.c
    ${CMAKE_CURRENT_BINARY_DIR}/pci_vendors.c
    legacy/bus/sysbus.c
    legacy/irq/irqarb.c
    legacy/bussupp.c
    legacy/halpnpdd.c
    legacy/halpcat.c
    legacy/ranges.c)

add_object_library(lib_hal_legacy_r ${HAL_LEGACY_SOURCE})
add_target_compile_definitions(lib_hal_legacy_r HAL_LEGACY_R)
add_dependencies(lib_hal_legacy_r bugcodes xdk)
#add_pch(lib_hal_legacy_r include/hal.h)

if(MSVC)
    target_link_libraries(lib_hal_legacy_r lib_hal_generic)
endif()
