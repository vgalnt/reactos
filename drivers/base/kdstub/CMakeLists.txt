
spec2def(kdstub.dll kdstub.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    kdstub.c
    kdstub.h)

add_library(kdstub MODULE
    ${SOURCE}
    kdstub.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kdstub.def)

set_module_type(kdstub kerneldll ENTRYPOINT 0)
set_subsystem(kdstub native)
add_importlibs(kdstub ntoskrnl hal)
add_dependencies(kdstub psdk bugcodes)
#add_pch(kdstub kddll.h SOURCE)
add_cd_file(TARGET kdstub DESTINATION reactos/system32 NO_CAB FOR all)
