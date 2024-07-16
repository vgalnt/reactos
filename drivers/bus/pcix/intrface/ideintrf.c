/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/ideintrf.c
 * PURPOSE:         IDE Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

typedef VOID (NTAPI* PNATIVE_IDE_INTERRUPT_CONTROL)(PVOID Context, BOOLEAN IsEnableOrDisable);

typedef struct _PCI_NATIVE_IDE_INTERFACE
{
    INTERFACE StdInterface;
    PNATIVE_IDE_INTERRUPT_CONTROL InterruptControl;
} PCI_NATIVE_IDE_INTERFACE, *PPCI_NATIVE_IDE_INTERFACE;

/* GLOBALS ********************************************************************/

PCI_INTERFACE PciNativeIdeInterface =
{
    &GUID_PCI_NATIVE_IDE_INTERFACE,
    sizeof(PCI_NATIVE_IDE_INTERFACE),
    1,
    1,
    PCI_INTERFACE_PDO,
    0,
    PciInterface_NativeIde,
    nativeIde_Constructor,
    nativeIde_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
nativeIde_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI nativeIde_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
nativeIde_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PPCI_PDO_EXTENSION PdoExtension = DeviceExtension;

    DPRINT("nativeIde_Constructor: %p, %X\n", Interface, Version);

    ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);

    if (PdoExtension->BaseClass != 1)
    {
        DPRINT1("nativeIde_Constructor: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (PdoExtension->SubClass != 1)
    {
        DPRINT1("nativeIde_Constructor: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if ((PdoExtension->ProgIf & 0xA) != 0xA)
    {
        DPRINT1("nativeIde_Constructor: STATUS_INVALID_DEVICE_REQUEST (%X)\n", PdoExtension->ProgIf);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
