
add_definitions(-D_NTSYSTEM_)

list(APPEND SOURCE
    hooklib.c)

add_library(hooklib ${SOURCE})
add_dependencies(hooklib bugcodes xdk)
