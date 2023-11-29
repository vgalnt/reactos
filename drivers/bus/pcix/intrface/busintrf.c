/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/busintrf.c
 * PURPOSE:         Bus Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE BusHandlerInterface =
{
    &GUID_BUS_INTERFACE_STANDARD,
    sizeof(BUS_INTERFACE_STANDARD),
    1,
    1,
    PCI_INTERFACE_PDO,
    0,
    PciInterface_BusHandler,
    busintrf_Constructor,
    busintrf_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
busintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI busintrf_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
busintrf_Reference(
    _In_ PVOID Context)
{
    PPCI_PDO_EXTENSION PdoExtension = Context;

    DPRINT("busintrf_Reference: %p\n", Context);

    ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);
    InterlockedIncrement(&PdoExtension->BusInterfaceReferenceCount);
}

VOID
NTAPI
busintrf_Dereference(
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
PciPnpTranslateBusAddress(
    _Inout_opt_ PVOID Context,
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ ULONG Length,
    _Out_ ULONG* OutAddressSpace,
    _Out_ PHYSICAL_ADDRESS* OutTranslatedAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

PDMA_ADAPTER
NTAPI
PciPnpGetDmaAdapter(
    _Inout_opt_ PVOID Context,
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor,
    _Out_ ULONG* OutNumberOfMapRegisters)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

NTSTATUS
NTAPI
PciExternalReadDeviceConfig(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PciReadDeviceSpace(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ ULONG DataType,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _Out_ ULONG* OutLenght)
{
    NTSTATUS Status;

    DPRINT("PciReadDeviceSpace: %p\n", PdoExtension);

    *OutLenght = 0;

    if (DataType)
    {
        DPRINT1("PciReadDeviceSpace: FIXME (%X)\n", DataType);
        ASSERT(FALSE);
    }

    Status = PciExternalReadDeviceConfig(PdoExtension, Buffer, Offset, Length);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciReadDeviceSpace: %p\n", Status);
        return Status;
    }

    *OutLenght = Length;

    return Status;
}

ULONG
NTAPI
PciPnpReadConfig(
    _Inout_opt_ PVOID Context,
    _In_ ULONG DataType,
    _Inout_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PPCI_PDO_EXTENSION PdoExtension = Context;
    ULONG RetLength;

    DPRINT("PciPnpReadConfig: %p\n", PdoExtension);

    ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

    PciReadDeviceSpace(PdoExtension, DataType, Buffer, Offset, Length, &RetLength);

    return RetLength;
}

ULONG
NTAPI
PciPnpWriteConfig(
    _Inout_opt_ PVOID Context,
    _In_ ULONG DataType,
    _Inout_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

NTSTATUS
NTAPI
busintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PBUS_INTERFACE_STANDARD BusInterface = (PVOID)Interface;

    DPRINT("busintrf_Constructor: %p, %p\n", DeviceExtension, Interface);

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(InterfaceData);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);

    BusInterface->Size = sizeof(*BusInterface);
    BusInterface->Version = 1;
    BusInterface->Context = DeviceExtension;
    BusInterface->InterfaceReference = busintrf_Reference;
    BusInterface->InterfaceDereference = busintrf_Dereference;
    BusInterface->TranslateBusAddress = PciPnpTranslateBusAddress;
    BusInterface->GetDmaAdapter = PciPnpGetDmaAdapter;
    BusInterface->SetBusData = PciPnpWriteConfig;
    BusInterface->GetBusData = PciPnpReadConfig;

    return STATUS_SUCCESS;
}

/* EOF */
