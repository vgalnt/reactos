/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/legacy/bus/eisabus.c
 * PURPOSE:
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include <hal.h>
//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* PRIVATE FUNCTIONS **********************************************************/

ULONG
NTAPI
HalpGetEisaData(IN PBUS_HANDLER BusHandler,
                IN PBUS_HANDLER RootHandler,
                IN ULONG SlotNumber,
                IN PVOID Buffer,
                IN ULONG Offset,
                IN ULONG Length)
{
    /* Not implemented */
    DPRINT1("STUB HalpGetEisaData\n");
    ASSERT(FALSE);
    return 0;
}

ULONG
NTAPI
HalpGetEisaInterruptVector(IN PBUS_HANDLER BusHandler,
                           IN PBUS_HANDLER RootHandler,
                           IN ULONG BusInterruptLevel,
                           IN ULONG BusInterruptVector,
                           OUT PKIRQL Irql,
                           OUT PKAFFINITY Affinity)
{
    /* Not implemented */
    DPRINT1("STUB HalpGetEisaInterruptVector\n");
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
HalpAdjustEisaResourceList(IN PBUS_HANDLER BusHandler,
                           IN PBUS_HANDLER RootHandler,
                           IN OUT PIO_RESOURCE_REQUIREMENTS_LIST *Resources)
{
    /* Not implemented */
    DPRINT1("STUB HalpAdjustEisaResourceList\n");
    ASSERT(FALSE);
    return 0;
}

BOOLEAN
NTAPI
HalpTranslateEisaBusAddress(IN PBUS_HANDLER BusHandler,
                            IN PBUS_HANDLER RootHandler, 
                            IN PHYSICAL_ADDRESS BusAddress,
                            IN OUT PULONG AddressSpace,
                            OUT PPHYSICAL_ADDRESS TranslatedAddress)
{
    BOOLEAN Result;
    DPRINT("HalpTranslateEisaBusAddress: InterfaceType - %X, BusNumber - %X, BusAddress - %I64X\n",
           BusHandler->InterfaceType, BusHandler->BusNumber, BusAddress.QuadPart);

    Result = HalpTranslateSystemBusAddress(BusHandler,
                                           RootHandler,
                                           BusAddress,
                                           AddressSpace,
                                           TranslatedAddress);

    if (Result == TRUE &&
        (*AddressSpace) != 0 && /* 0 - Memory, 1 - Port*/ 
        BusAddress.QuadPart >= 0xA0000 &&
        BusAddress.QuadPart < 0xFFFFF)
    {
        return Result;
    }

    Result = HalTranslateBusAddress(Internal,
                                    0,
                                    BusAddress,
                                    AddressSpace,
                                    TranslatedAddress);

    return Result;
}

/* EOF */
