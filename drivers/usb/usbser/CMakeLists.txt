
list(APPEND SOURCE
    usbser.c
    usbser.h)

list(APPEND PCH_SKIP_SOURCE
    guid.c)

add_library(usbser MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    usbser.rc)

set_module_type(usbser kernelmodedriver)
add_importlibs(usbser usbd ntoskrnl hal)
add_pch(usbser usbser.h "${PCH_SKIP_SOURCE}")
add_cd_file(TARGET usbser DESTINATION reactos/system32/drivers NO_CAB FOR all)
