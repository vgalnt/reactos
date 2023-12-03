/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/device.c
 * PURPOSE:         Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
Device_SaveCurrentSettings(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PPCI_FUNCTION_RESOURCES Resources;
    PPCI_COMMON_HEADER PciData;
    PULONG BarArray;
    ULONG BarMask;
    ULONG Bar;
    ULONG ix;

    DPRINT("Device_SaveCurrentSettings: %p\n", Context);

    /* Get variables from context */
    PciData = Context->Current;
    Resources = Context->PdoExtension->Resources;

    /* Loop all the PCI BARs */
    BarArray = PciData->u.type0.BaseAddresses;
    for (ix = 0; ix <= PCI_TYPE0_ADDRESSES; ix++)
    {
        /* Get the resource descriptor and limit descriptor for this BAR */
        CmDescriptor = &Resources->Current[ix];
        IoDescriptor = &Resources->Limit[ix];

        /* Build the resource descriptor based on the limit descriptor */
        CmDescriptor->Type = IoDescriptor->Type;
        if (CmDescriptor->Type == CmResourceTypeNull)
            continue;

        CmDescriptor->Flags = IoDescriptor->Flags;
        CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;
        CmDescriptor->u.Generic.Start.HighPart = 0;
        CmDescriptor->u.Generic.Length = IoDescriptor->u.Generic.Length;

        /* Check if we're handling PCI BARs, or the ROM BAR */
        if (ix < PCI_TYPE0_ADDRESSES)
        {
            /* Read the actual BAR value */
            Bar = BarArray[ix];

            /* Check if this is an I/O BAR */
            if (Bar & PCI_ADDRESS_IO_SPACE)
            {
                /* Use the right mask to get the I/O port base address */
                ASSERT(CmDescriptor->Type == CmResourceTypePort);
                BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;
            }
            else
            {
                /* It's a RAM BAR, use the right mask to get the base address */
                ASSERT(CmDescriptor->Type == CmResourceTypeMemory);
                BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

                /* Check if it's a 64-bit BAR */
                if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT)
                    /* The next BAR value is actually the high 32-bits */
                    CmDescriptor->u.Memory.Start.HighPart = BarArray[ix + 1];
                else if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT)
                    /* Legacy BAR, don't read more than 20 bits of the address */
                    BarMask = 0xFFFF0;
            }
        }
        else
        {
            /* Actually a ROM BAR, so read the correct register */
            Bar = PciData->u.type0.ROMBaseAddress;

            /* Apply the correct mask for ROM BARs */
            BarMask = PCI_ADDRESS_ROM_ADDRESS_MASK;

            /* Make sure it's enabled */
            if (!(Bar & PCI_ROMADDRESS_ENABLED))
            {
                /* If it isn't, then a descriptor won't be built for it */
                CmDescriptor->Type = CmResourceTypeNull;
                continue;
            }
        }

        /* Now we have the right mask, read the actual address from the BAR */
        Bar &= BarMask;
        CmDescriptor->u.Memory.Start.LowPart = Bar;

        /* And check for invalid BAR addresses */
        if (!(CmDescriptor->u.Memory.Start.HighPart | Bar))
        {
            /* Skip these descriptors */
            CmDescriptor->Type = CmResourceTypeNull;
            DPRINT1("Device_SaveCurrentSettings: Invalid BAR\n");
        }
    }

    /* Also save the sub-IDs that came directly from the PCI header */
    Context->PdoExtension->SubsystemVendorId = PciData->u.type0.SubVendorID;
    Context->PdoExtension->SubsystemId = PciData->u.type0.SubSystemID;
}

VOID
NTAPI
Device_SaveLimits(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    PPCI_PDO_EXTENSION PdoExtension;
    PIO_RESOURCE_DESCRIPTOR Limit;
    PPCI_COMMON_HEADER Current;
    PPCI_COMMON_HEADER PciData;
    PULONG BarArray;
    ULONG ix;

    DPRINT("Device_SaveLimits: %p\n", Context);

    /* Get pointers from the context */
    PdoExtension = Context->PdoExtension;
    Current = Context->Current;
    PciData = Context->PciData;

    /* And get the array of bARs */
    BarArray = PciData->u.type0.BaseAddresses;

    /* First, check for IDE controllers that are not in native mode */
    if (PdoExtension->BaseClass == PCI_CLASS_MASS_STORAGE_CTLR &&
        PdoExtension->SubClass == PCI_SUBCLASS_MSC_IDE_CTLR &&
        (PdoExtension->ProgIf & 5) != 5)
    {
        /* They should not be using any non-legacy resources */
        BarArray[0] = 0;
        BarArray[1] = 0;
        BarArray[2] = 0;
        BarArray[3] = 0;
    }
    else if (PdoExtension->VendorId == 0x5333 &&
             (PdoExtension->DeviceId == 0x88F0 || PdoExtension->DeviceId == 0x8880))
    {
        /*
         * The problem is caused by the S3 Vision 968/868 video controller which
         * is used on the Diamond Stealth 64 Video 3000 series, Number Nine 9FX
         * motion 771, and other popular video cards, all containing a memory bug.
         * The 968/868 claims to require 32 MB of memory, but it actually decodes
         * 64 MB of memory.
         */
        for (ix = 0; ix < PCI_TYPE0_ADDRESSES; ix++)
        {
            /* Find its 32MB RAM BAR */
            if (BarArray[ix] == 0xFE000000)
            {
                /* Increase it to 64MB to make sure nobody touches the buffer */
                BarArray[ix] = 0xFC000000;
                DPRINT1("Device_SaveLimits: Adjusted broken S3 requirement from 32MB to 64MB\n");
            }
        }
    }

    /* Check for Cirrus Logic GD5430/5440 cards */
    if (PdoExtension->VendorId == 0x1013 && PdoExtension->DeviceId == 0x00A0)
    {
        /* Check for the I/O port requirement */
        if (BarArray[1] == 0xFC01)
        {
            /* Check for completely bogus BAR */
            if (Current->u.type0.BaseAddresses[1] == 1)
            {
                /* Ignore it */
                BarArray[1] = 0;
                DPRINT1("Device_SaveLimits: Ignored Cirrus GD54xx broken IO requirement (400 ports)\n");
            }
            else
            {
                /* Otherwise, this BAR seems okay */
                DPRINT1("Device_SaveLimits: Cirrus GD54xx 400 port IO requirement has a valid setting (%X)\n",
                        Current->u.type0.BaseAddresses[1]);
            }
        }
        else if (BarArray[1])
        {
            /* Strange, the I/O BAR was not found as expected (or at all) */
            DPRINT1("Device_SaveLimits: Warning Cirrus Adapter 101300a0 has unexpected resource requirement (%X)\n", BarArray[1]);
        }
    }

    /* Finally, process all the limit descriptors */
    Limit = PdoExtension->Resources->Limit;
    for (ix = 0; ix < PCI_TYPE0_ADDRESSES; ix++)
    {
        /* And build them based on the BARs */
        if (PciCreateIoDescriptorFromBarLimit(&Limit[ix], &BarArray[ix], FALSE))
        {
            /* This function returns TRUE if the BAR was 64-bit, handle this */
            ASSERT((ix + 1) < PCI_TYPE0_ADDRESSES);
            ix++;
            Limit[ix].Type = CmResourceTypeNull;
        }
    }

    /* Create the last descriptor based on the ROM address */
    PciCreateIoDescriptorFromBarLimit(&Limit[ix], &PciData->u.type0.ROMBaseAddress, TRUE);
}

VOID
NTAPI
Device_MassageHeaderForLimitsDetermination(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    PPCI_PDO_EXTENSION PdoExtension;
    PPCI_COMMON_HEADER PciData;
    PULONG BarArray;
    ULONG ix = 0;

    DPRINT("Device_MassageHeaderForLimitsDetermination: %p\n", Context);

    /* Get pointers from context data */
    PdoExtension = Context->PdoExtension;
    PciData = Context->PciData;

    /* Get the array of BARs */
    BarArray = PciData->u.type0.BaseAddresses;

    /* Check for IDE controllers that are not in native mode */
    if (PdoExtension->BaseClass == PCI_CLASS_MASS_STORAGE_CTLR &&
        PdoExtension->SubClass == PCI_SUBCLASS_MSC_IDE_CTLR &&
        (PdoExtension->ProgIf & 5) != 5)
    {
        /* These controllers only use legacy resources */
        ix = 4;
    }

    /* Set all the bits on, which will allow us to recover the limit data */
    do
    {
        BarArray[ix] = 0xFFFFFFFF;
        ix++;
    }
    while (ix < PCI_TYPE0_ADDRESSES);

    /* Do the same for the PCI ROM BAR */
    PciData->u.type0.ROMBaseAddress = PCI_ADDRESS_ROM_ADDRESS_MASK;
}

VOID
NTAPI
Device_RestoreCurrent(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    /* Nothing to do for devices */
    return;
}

VOID
NTAPI
Device_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
                                        IN PPCI_COMMON_HEADER PciData,
                                        IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(PciData);
    UNREFERENCED_PARAMETER(IoDescriptor);
    /* Not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
Device_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
                   IN PPCI_COMMON_HEADER PciData)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(PciData);
    /* Not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
Device_ChangeResourceSettings(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG* OutBaseAddr;
    ULONG LowPart;
    ULONG ix;
    ULONG Type;

    DPRINT("Device_ChangeResourceSettings: %p, %p\n", PdoExtension, PdoExtension->Resources);

    if (!PdoExtension->Resources)
        return;

    CmDescriptor = PdoExtension->Resources->Current;
    OutBaseAddr = PciData->u.type0.BaseAddresses;

    for (ix = 0;
         ix <= PCI_TYPE0_ADDRESSES;
         ix++, CmDescriptor++, OutBaseAddr++)
    {
        if (CmDescriptor->Type == CmResourceTypeNull)
            continue;

        LowPart = CmDescriptor->u.Generic.Start.LowPart;

        if (ix == PCI_TYPE0_ADDRESSES)
        {
            ASSERT(CmDescriptor->Type == CmResourceTypeMemory);

            PciData->u.type0.ROMBaseAddress &= ~0x7FF;
            PciData->u.type0.ROMBaseAddress |= (LowPart & PCI_ADDRESS_ROM_ADDRESS_MASK);
        }
        else if (*OutBaseAddr & PCI_ADDRESS_IO_SPACE)
        {
            ASSERT(CmDescriptor->Type == CmResourceTypePort);
            *OutBaseAddr = LowPart;
        }
        else
        {
            ASSERT(CmDescriptor->Type == CmResourceTypeMemory);

            Type = *OutBaseAddr;
            *OutBaseAddr = LowPart;

            if ((Type & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT)
            {
                OutBaseAddr++;
                *OutBaseAddr = CmDescriptor->u.Generic.Start.HighPart;

                CmDescriptor++;
                ix++;
            }
            else if ((Type & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT)
            {
                ASSERT((LowPart & 0xFFF00000) == 0);
            }
        }
    }
}

/* EOF */
