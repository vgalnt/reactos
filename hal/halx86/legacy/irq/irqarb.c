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
QueryInterfaceFdo(
    IN PDEVICE_OBJECT DeviceObject,
    IN CONST GUID * InterfaceType,
    IN ULONG InterfaceBufferSize,
    IN PVOID InterfaceSpecificData,
    IN USHORT Version,
    IN PVOID Interface)
{
    NTSTATUS Status;

    PAGED_CODE();

    DPRINT("QueryInterfaceFdo: DeviceObject - %p, BufferSize - %X, SpecificData - %X, Version - %X, Interface - %X\n",
           DeviceObject, InterfaceBufferSize, InterfaceSpecificData, Version, Interface);

    Status = STATUS_NOT_SUPPORTED;

    if (InterfaceSpecificData != ULongToPtr(CmResourceTypeInterrupt))
    {
        DPRINT("QueryInterfaceFdo: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    if (HalpPciIrqRoutingInfo.PciIrqRoutingTable == NULL ||
        HalpPciIrqRoutingInfo.PciIrqRouteInterface == NULL)
    {
        DPRINT("QueryInterfaceFdo: PciIrqRoutingTable - %X, PciIrqRouteInterface - %X\n",
               HalpPciIrqRoutingInfo.PciIrqRoutingTable,
               HalpPciIrqRoutingInfo.PciIrqRouteInterface);

        return STATUS_NOT_SUPPORTED;
    }

    if (RtlCompareMemory(&GUID_ARBITER_INTERFACE_STANDARD, InterfaceType, sizeof(GUID)) == sizeof(GUID))
    {
        ASSERT(FALSE);
        return Status;
    }

    if (RtlCompareMemory(&GUID_TRANSLATOR_INTERFACE_STANDARD, InterfaceType, sizeof(GUID)) != sizeof(GUID))
    {
        DPRINT("QueryInterfaceFdo: STATUS_NOT_SUPPORTED\n");
        ASSERT(FALSE);
        return STATUS_NOT_SUPPORTED;
    }

    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

/* EOF */
