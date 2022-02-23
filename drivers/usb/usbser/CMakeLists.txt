
list(APPEND SOURCE
    ioctl.c
    pnp.c
    power.c
    serial.c
    usb.c
    usbser.c
    utils.c
    wmi.c
    usbser.h)

list(APPEND PCH_SKIP_SOURCE
    guid.c)

add_library(usbser MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    usbser.rc)

set_module_type(usbser kernelmodedriver)
add_importlibs(usbser usbd wmilib ntoskrnl hal)
add_pch(usbser usbser.h "${PCH_SKIP_SOURCE}")
add_cd_file(TARGET usbser DESTINATION reactos/system32/drivers NO_CAB FOR all)
