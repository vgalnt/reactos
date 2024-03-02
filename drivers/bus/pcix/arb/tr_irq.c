/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/tr_irq.c
 * PURPOSE:         IRQ Translator Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE TranslatorInterfaceInterrupt =
{
    &GUID_TRANSLATOR_INTERFACE_STANDARD,
    sizeof(TRANSLATOR_INTERFACE),
    0,
    0,
    PCI_INTERFACE_FDO,
    0,
    PciTrans_Interrupt,
    tranirq_Constructor,
    tranirq_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
tranirq_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI tranirq_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
tranirq_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PPCI_FDO_EXTENSION FdoExtension = DeviceExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    INTERFACE_TYPE ParentInterface;
    ULONG ParentBus;
    ULONG BaseBus;

    DPRINT("tranirq_Constructor: %p\n", Interface);

    ASSERT_FDO(FdoExtension);
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);

    /* Make sure it's the right resource type */
    if ((ULONG_PTR)InterfaceData != CmResourceTypeInterrupt)
    {
        /* Fail this invalid request */
        DPRINT("tranirq_Constructor: doesn't like %p in InterfaceSpecificData\n", InterfaceData);
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Get the bus, and use this as the interface-specific data */
    BaseBus = FdoExtension->BaseBus;
    InterfaceData = UlongToPtr(BaseBus);

    /* Check if this is the root bus */
    if (PCI_IS_ROOT_FDO(FdoExtension))
    {
        /* It is, so there is no parent, and it's connected on the system bus */
        ParentBus = 0;
        ParentInterface = Internal;

        DPRINT1("      Is root FDO\n");
    }
    else
    {
        PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;
        ParentBus = PdoExtension->ParentFdoExtension->BaseBus;
        ParentInterface = PCIBus;

        DPRINT1("      Is bridge FDO, parent bus %X, secondary bus %X\n", ParentBus, BaseBus);
    }

    /* Now call the legacy HAL interface to get the correct translator */
    return HalGetInterruptTranslator(ParentInterface,
                                     ParentBus,
                                     PCIBus,
                                     sizeof(TRANSLATOR_INTERFACE),
                                     0,
                                     (PTRANSLATOR_INTERFACE)Interface,
                                     (PULONG)&InterfaceData);
}

/* EOF */
