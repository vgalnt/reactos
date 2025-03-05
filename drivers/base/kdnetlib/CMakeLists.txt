
spec2def(kdnetlib.dll kdnetlib.spec ADD_IMPORTLIB)

# NTDDI_WIN8
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x602)
#add_definitions(-DNTDDI_VERSIONT=0x06020000)

list(APPEND SOURCE
    kdnetlib.c
    kdnetlib.h)

add_library(kdnetlib MODULE
    ${SOURCE}
    kdnetlib.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kdnetlib.def)

set_module_type(kdnetlib kerneldll ENTRYPOINT 0)
set_subsystem(kdnetlib native)
target_link_libraries(kdnetlib libcntpr)
add_importlibs(kdnetlib ntoskrnl hal)
add_dependencies(kdnetlib psdk bugcodes)
#add_pch(kdnetlib kddll.h SOURCE)
add_cd_file(TARGET kdnetlib DESTINATION reactos/system32 NO_CAB FOR all)
