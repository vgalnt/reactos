
#include <hal.h>
#include <arbiter.h>
#include "legacy.h"
//#include "pciirqmp.h"

NTSTATUS
NTAPI
QueryInterfaceFdo(
    IN PDEVICE_OBJECT DeviceObject,
    IN CONST GUID* InterfaceType,
    IN ULONG InterfaceBufferSize,
    IN PVOID InterfaceSpecificData,
    IN USHORT Version,
    IN PVOID Interface,
    OUT PULONG_PTR OutInformation
);

/* EOF */
