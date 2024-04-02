
spec2def(pciidex.sys pciidex.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    pciidex.c
    pciidex.h)

add_library(pciidex MODULE
    ${SOURCE}
    pciidex.rc
    ${CMAKE_CURRENT_BINARY_DIR}/pciidex.def)

target_link_libraries(pciidex wdmguid memcmp)
add_pch(pciidex pciidex.h SOURCE)
set_module_type(pciidex kernelmodedriver)
add_importlibs(pciidex ntoskrnl hal)
add_cd_file(TARGET pciidex DESTINATION reactos/system32/drivers NO_CAB FOR all)
