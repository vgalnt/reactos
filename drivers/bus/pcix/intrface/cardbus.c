/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/cardbus.c
 * PURPOSE:         CardBus Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE PciCardbusPrivateInterface =
{
    &GUID_PCI_CARDBUS_INTERFACE_PRIVATE,
    sizeof(PCI_CARDBUS_INTERFACE_PRIVATE),
    PCI_CB_INTRF_VERSION,
    PCI_CB_INTRF_VERSION,
    PCI_INTERFACE_PDO,
    0,
    PciInterface_PciCb,
    pcicbintrf_Constructor,
    pcicbintrf_Initializer
};

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
Cardbus_SaveCurrentSettings(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc;
    PIO_RESOURCE_DESCRIPTOR IoDesc;
    PPCI_COMMON_HEADER Current;
    ULONG Align;
    ULONG Limit;
    ULONG Base;
    ULONG ix;

    DPRINT("Cardbus_SaveCurrentSettings: %p\n", Context);

    Current = Context->Current;

    CmDesc = Context->PdoExtension->Resources->Current;
    IoDesc = Context->PdoExtension->Resources->Limit;

    for (ix = 0; ix < 6; ix++, CmDesc++, IoDesc++)
    {
        CmDesc->Type = IoDesc->Type;

        if (CmDesc->Type == CmResourceTypeNull)
            continue;

        CmDesc->Flags = IoDesc->Flags;
        CmDesc->ShareDisposition = IoDesc->ShareDisposition;

        if (ix == 0)
        {
            Base = (Current->u.type2.SocketRegistersBaseAddress & ~(IoDesc->u.Generic.Length - 1));
            CmDesc->u.Generic.Start.QuadPart = Base;

            CmDesc->u.Generic.Length = IoDesc->u.Generic.Length;
            continue;
        }

        if (ix == 5)
            continue;

        Base = Current->u.type2.Range[ix - 1].Base;
        Limit = Current->u.type2.Range[ix - 1].Limit;

        if (ix < 3)
        {
            Align = 0xFFF;
        }
        else
        {
            if (!(Current->u.type2.Range[ix].Base & 0x3))
            {
                Base &= ~0xFFFF0000;
                Limit &= ~0xFFFF0000;
            }

            Align = 0x3;
        }

        Base &= ~Align;
        Limit |= Align;

        if (Base && (Base < Limit))
        {
            CmDesc->u.Generic.Start.QuadPart = Base;
            CmDesc->u.Generic.Length = (Limit - Base + 1);
        }
        else
        {
            CmDesc->Type = CmResourceTypeNull;
        }
    }

    Context->PdoExtension->Dependent.type2.IsaBitSet = FALSE;

    if (Current->u.type2.BridgeControl & 0x304)
        Context->PdoExtension->UpdateHardware = TRUE;

    Context->PdoExtension->Dependent.type2.PrimaryBus = Current->u.type2.PrimaryBus;
    Context->PdoExtension->Dependent.type2.SecondaryBus = Current->u.type2.SecondaryBus;
    Context->PdoExtension->Dependent.type2.SubordinateBus = Current->u.type2.SubordinateBus;
}

VOID
NTAPI
Cardbus_SaveLimits(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    PPCI_FUNCTION_RESOURCES Resources;
    PPCI_COMMON_HEADER PciData;
    ULONG Align;
    ULONG Base;
    ULONG Limit;
    ULONG ix;
    USHORT IDs[4];
    BOOLEAN DbgChk64Bit;

    DPRINT("Cardbus_SaveLimits: %p\n", Context);

    Resources = Context->PdoExtension->Resources;
    PciData = Context->PciData;

    DbgChk64Bit = PciCreateIoDescriptorFromBarLimit(Resources->Limit, &PciData->u.type2.SocketRegistersBaseAddress, FALSE);
    ASSERT(!DbgChk64Bit);

    for (ix = 0; ix < 4; ix++)
    {
        if (ix >= 2)
        {
            if (!(PciData->u.type2.Range[ix].Base & 0x3))
            {
                ASSERT((PciData->u.type2.Range[ix].Limit & 0x3) == 0x0);

                PciData->u.type2.Range[ix].Base &= ~0xFFFF0000;
                PciData->u.type2.Range[ix].Limit &= ~0xFFFF0000;
            }

            Resources->Limit[ix + 1].Type = 1;
            Resources->Limit[ix + 1].Flags = 0xA1;

            Align = 3;
        }
        else
        {
            Resources->Limit[ix + 1].Type = 3;
            Resources->Limit[ix + 1].Flags = 0;

            Align = 0xFFF;
        }

        Base = (PciData->u.type2.Range[ix].Base & ~Align);
        Limit = (PciData->u.type2.Range[ix].Limit | Align);

        if (Base && Base < Limit)
        {
            Resources->Limit[ix + 1].u.Generic.MinimumAddress.QuadPart = 0;
            Resources->Limit[ix + 1].u.Generic.MaximumAddress.QuadPart = Limit;
            Resources->Limit[ix + 1].u.Generic.Length = 0;
            Resources->Limit[ix + 1].u.Generic.Alignment = (Align + 1);
        }
        else
        {
            Resources->Limit[ix + 1].Type = CmResourceTypeNull;
        }
    }

    PciReadDeviceConfig(Context->PdoExtension, IDs, 0x40, 8);

    Context->PdoExtension->SubsystemVendorId = IDs[0];
    Context->PdoExtension->SubsystemId = IDs[1];

    ASSERT(Context->PdoExtension->Resources->Limit[1].u.Generic.Length == 0);
    Context->PdoExtension->Resources->Limit[1].u.Generic.Length = 0x1000;
}

VOID
NTAPI
Cardbus_MassageHeaderForLimitsDetermination(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    PPCI_COMMON_HEADER PciData;
    PPCI_COMMON_HEADER Current;
    ULONG DefaultBase;
    ULONG ix;

    DPRINT("Cardbus_MassageHeaderForLimitsDetermination: %p\n", Context);

    PciData = Context->PciData;
    Current = Context->Current;

    PciData->u.type2.SocketRegistersBaseAddress = 0xFFFFFFFF;

    for (ix = 0; ix <= 4; ix++)
    {
        PciData->u.type2.Range[ix].Limit = 0xFFFFFFFF;
        PciData->u.type2.Range[ix].Base  = 0xFFFFFFFF;
    }

    Context->SecondaryStatus = Context->Current->u.type2.SecondaryStatus;

    Context->Current->u.type2.SecondaryStatus = 0;
    Context->PciData->u.type2.SecondaryStatus = 0;

    if (Context->PdoExtension->OnDebugPath)
        return;

    DefaultBase = 0xFFFFF000;

    for (ix = 0; ix <= 4; ix++)
    {
        Current->u.type2.Range[ix].Limit = 0;
        Current->u.type2.Range[ix].Base = DefaultBase;

        if (ix == 2)
            DefaultBase = 0xFFFFFFFC;
    }
}

VOID
NTAPI
Cardbus_RestoreCurrent(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context)
{
    Context->Current->u.type2.SecondaryStatus = Context->SecondaryStatus;
}

VOID
NTAPI
Cardbus_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
                                         IN PPCI_COMMON_HEADER PciData,
                                         IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(PciData);
    UNREFERENCED_PARAMETER(IoDescriptor);
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
Cardbus_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
                    IN PPCI_COMMON_HEADER PciData)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(PciData);
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
Cardbus_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
                               IN PPCI_COMMON_HEADER PciData)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(PciData);
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
pcicbintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI pcicbintrf_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
pcicbintrf_Constructor(IN PVOID DeviceExtension,
                       IN PVOID Instance,
                       IN PVOID InterfaceData,
                       IN USHORT Version,
                       IN USHORT Size,
                       IN PINTERFACE Interface)
{
    UNREFERENCED_PARAMETER(DeviceExtension);
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(InterfaceData);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Interface);

    /* Not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
