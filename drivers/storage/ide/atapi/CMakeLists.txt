
list(APPEND SOURCE
    atapi.c
    atapi.h)

add_library(atapi MODULE ${SOURCE} atapi.rc)

set_module_type(atapi kernelmodedriver)
target_link_libraries(atapi memcmp)
# add_pch(atapi atapi.h SOURCE) # TODO
add_importlibs(atapi ntoskrnl hal wmilib)
add_cd_file(TARGET atapi DESTINATION reactos/system32/drivers NO_CAB FOR all)
#add_registry_inf(atapi_reg.inf)
