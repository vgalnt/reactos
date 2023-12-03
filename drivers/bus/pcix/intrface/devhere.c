/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/devhere.c
 * PURPOSE:         Device Presence Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE PciDevicePresentInterface =
{
    &GUID_PCI_DEVICE_PRESENT_INTERFACE,
    sizeof(PCI_DEVICE_PRESENT_INTERFACE),
    PCI_DEVICE_PRESENT_INTERFACE_VERSION,
    PCI_DEVICE_PRESENT_INTERFACE_VERSION,
    PCI_INTERFACE_PDO,
    0,
    PciInterface_DevicePresent,
    devpresent_Constructor,
    devpresent_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
devpresent_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI devpresent_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
PciRefDereferenceNoop(
    _In_ PVOID Context)
{
    PAGED_CODE();
}

BOOLEAN
NTAPI
devpresent_IsDevicePresent(
   _In_ USHORT VendorID,
   _In_ USHORT DeviceID,
   _In_ UCHAR RevisionID,
   _In_ USHORT SubVendorID,
   _In_ USHORT SubSystemID,
   _In_ ULONG Flags)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
devpresent_IsDevicePresentEx(
   _In_ PVOID Context,
   _In_ PPCI_DEVICE_PRESENCE_PARAMETERS Parameters)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS
NTAPI
devpresent_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PPCI_DEVICE_PRESENT_INTERFACE DevPresentInterface = (PVOID)Interface;

    PAGED_CODE();
    DPRINT("devpresent_Constructor: %p, %p\n", DeviceExtension, Interface);

    DevPresentInterface->Version = 1;
    DevPresentInterface->Context = DeviceExtension;
    DevPresentInterface->InterfaceReference = PciRefDereferenceNoop;
    DevPresentInterface->InterfaceDereference = PciRefDereferenceNoop;
    DevPresentInterface->IsDevicePresent = devpresent_IsDevicePresent;

    if (Size < sizeof(PCI_DEVICE_PRESENT_INTERFACE))
    {
        DevPresentInterface->Size = 0x14;
        return STATUS_SUCCESS;
    }

    DevPresentInterface->IsDevicePresentEx = devpresent_IsDevicePresentEx;
    DevPresentInterface->Size = sizeof(PCI_DEVICE_PRESENT_INTERFACE);

    return STATUS_SUCCESS;
}
/* EOF */
