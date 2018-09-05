/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         
 * FILE:            hal/halx86/legacy/irq/irqarb.c
 * PURPOSE:         Legacy HAL arbiter for interrupt resources
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include "irqarb.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* DATA **********************************************************************/

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
QueryInterfaceFdo(IN PDEVICE_OBJECT DeviceObject,
                  IN CONST GUID* InterfaceType,
                  IN ULONG InterfaceBufferSize,
                  IN PVOID InterfaceSpecificData,
                  IN USHORT Version,
                  IN PVOID Interface,
                  OUT PULONG_PTR OutInformation)
{
    DPRINT("QueryInterfaceFdo: DeviceObject - %p, BufferSize - %X, SpecificData - %X, Version - %X, Interface - %X\n", DeviceObject, InterfaceBufferSize, InterfaceSpecificData, Version, Interface);
    ASSERT(0);
    return 0;
}

/* EOF */
