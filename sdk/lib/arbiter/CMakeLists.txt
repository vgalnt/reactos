# arbiter library for bus drivers (PCI) and for legacy HAL (only PIC version)

remove_definitions(-D_NTOSKRNL_)

include_directories(${REACTOS_SOURCE_DIR}/sdk/lib/rtl)

list(APPEND SOURCE
    ${REACTOS_SOURCE_DIR}/ntoskrnl/io/arbiter/arbiter.c
    arbiter.h)

add_library(arblib STATIC ${SOURCE})

add_pch(arblib arbiter.h SOURCE)
add_dependencies(arblib xdk)

