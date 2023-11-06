/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/pmeintf.c
 * PURPOSE:         Power Management Event# Signal Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE PciPmeInterface =
{
    &GUID_PCI_PME_INTERFACE,
    sizeof(PCI_PME_INTERFACE),
    PCI_PME_INTRF_STANDARD_VER,
    PCI_PME_INTRF_STANDARD_VER,
    PCI_INTERFACE_FDO | PCI_INTERFACE_ROOT,
    0,
    PciInterface_PmeHandler,
    PciPmeInterfaceConstructor,
    PciPmeInterfaceInitializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PciPmeInterfaceInitializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI PciPmeInterfaceInitializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
PciPmeGetInformation(
  IN PDEVICE_OBJECT Pdo,
  OUT PBOOLEAN PmeCapable,
  OUT PBOOLEAN PmeStatus,
  OUT PBOOLEAN PmeEnable)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
PciPmeClearPmeStatus(
  IN PDEVICE_OBJECT Pdo)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
PciPmeUpdateEnable(
  IN PDEVICE_OBJECT Pdo,
  IN BOOLEAN PmeEnable)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PciPmeInterfaceConstructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PPCI_PME_INTERFACE PmeInterface = (PVOID)Interface;

    DPRINT("PciPmeInterfaceConstructor: %p, %X\n", Interface, Version);

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(InterfaceData);
    UNREFERENCED_PARAMETER(Size);

    /* Only version 1 is supported */
    if (Version != PCI_PME_INTRF_STANDARD_VER)
        return STATUS_NOINTERFACE;

    PmeInterface->Size = sizeof(*PmeInterface);
    PmeInterface->Version = Version;
    PmeInterface->Context = DeviceExtension;
    PmeInterface->InterfaceReference = pcicbintrf_Dereference;
    PmeInterface->InterfaceDereference = pcicbintrf_Dereference;

    PmeInterface->GetPmeInformation = PciPmeGetInformation;
    PmeInterface->ClearPmeStatus = PciPmeClearPmeStatus;
    PmeInterface->UpdateEnable = PciPmeUpdateEnable;

    return STATUS_SUCCESS;
}

/* EOF */
