
include_directories(
    ${REACTOS_SOURCE_DIR}/sdk/lib/drivers/hooklib
    ${REACTOS_SOURCE_DIR}/sdk/include/reactos/drivers)

spec2def(hookntfs.sys hookx.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    hookdrv.c
    hookx.c
    hooks.c
    hooks.h)

add_library(hookntfs MODULE ${SOURCE} hookx.rc ${CMAKE_CURRENT_BINARY_DIR}/hookntfs.def)
target_link_libraries(hookntfs hooklib strtol)
set_module_type(hookntfs kernelmodedriver)
add_importlibs(hookntfs ntoskrnl hal)
