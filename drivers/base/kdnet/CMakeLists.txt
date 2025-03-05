
spec2def(kdnet.dll kdnet.spec ADD_IMPORTLIB)

# NTDDI_WIN8
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x602)
#add_definitions(-DNTDDI_VERSIONT=0x06020000)

list(APPEND SOURCE
    kdnet.c
    kdnet.h)

add_library(kdnet MODULE
    ${SOURCE}
    kdnet.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kdnet.def)

set_module_type(kdnet kerneldll ENTRYPOINT 0)
set_subsystem(kdnet native)
target_link_libraries(kdnet libcntpr)
add_importlibs(kdnet kdstub kdnetlib ntoskrnl hal)
add_dependencies(kdnet psdk bugcodes)
#add_pch(kdnet kdnet.h SOURCE)
add_cd_file(TARGET kdnet DESTINATION reactos/system32 NO_CAB FOR all)
