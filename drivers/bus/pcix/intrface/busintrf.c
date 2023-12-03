/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/busintrf.c
 * PURPOSE:         Bus Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
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
    PPCI_PDO_EXTENSION PdoExtension = Context;

    DPRINT("busintrf_Dereference: %p\n", Context);

    ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);
    InterlockedDecrement(&PdoExtension->BusInterfaceReferenceCount);
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
    PPCI_PDO_EXTENSION PdoExtension = Context;

    PAGED_CODE();
    DPRINT("PciPnpGetDmaAdapter: %p\n", Context);

    ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);

    if (DeviceDescriptor->InterfaceType == PCIBus)
        DeviceDescriptor->BusNumber = PdoExtension->ParentFdoExtension->BaseBus;

    return IoGetDmaAdapter(PdoExtension->ParentFdoExtension->PhysicalDeviceObject, DeviceDescriptor, OutNumberOfMapRegisters);
}

NTSTATUS
NTAPI
PciExternalReadDeviceConfig(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PCI_COMMON_CONFIG Config;

    DPRINT("PciExternalReadDeviceConfig: %p\n", PdoExtension);

    if ((Offset + Length) > 0x100)
    {
        DPRINT1("PciReadDeviceSpace: %X, %X\n", Offset, Length);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PciReadDeviceConfig(PdoExtension, Add2Ptr(&Config, Offset), Offset, Length);

    if (PdoExtension->InterruptPin &&
        Offset <= FIELD_OFFSET(PCI_COMMON_CONFIG,u.type0.InterruptLine) &&
        (Offset + Length) > FIELD_OFFSET(PCI_COMMON_CONFIG,u.type0.InterruptLine))
    {
        Config.u.type0.InterruptLine = PdoExtension->AdjustedInterruptLine;
    }

    RtlCopyMemory(Buffer, Add2Ptr(&Config, Offset), Length);

    return STATUS_SUCCESS;
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

NTSTATUS
NTAPI
PciExternalWriteDeviceConfig(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PPCI_VERIFIER_DATA VerifierData;
    PCI_COMMON_CONFIG Config;
    ULONG StartBaseAddresses;
    ULONG EndBaseAddresses;
    ULONG StartROMBaseAddress;
    ULONG EndROMBaseAddress;
    ULONG EndOffset;
    BOOLEAN IsVerifier = FALSE;

    DPRINT("PciExternalWriteDeviceConfig: %p (%X), %p, %X, %X\n", PdoExtension, PdoExtension->HeaderType, Buffer, Offset, Length);

    if ((Offset + Length) > 0x100)
    {
        DPRINT1("PciExternalWriteDeviceConfig: %X, %X\n", Offset, Length);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (PdoExtension->HeaderType == 0)
    {
        EndOffset = (Offset + Length);
        DPRINT("PciExternalWriteDeviceConfig: EndOffset %X\n", EndOffset);

        if (EndOffset > sizeof(PCI_COMMON_CONFIG))
        {
            DPRINT1("PciExternalWriteDeviceConfig: STATUS_INVALID_DEVICE_REQUEST\n");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        if (PdoExtension->HeaderType == 0)
        {
            StartBaseAddresses = FIELD_OFFSET(PCI_COMMON_CONFIG, u.type0.BaseAddresses);
            EndBaseAddresses = (StartBaseAddresses + RTL_FIELD_SIZE(PCI_COMMON_CONFIG, u.type0.BaseAddresses) - 1);

            DPRINT("PciExternalWriteDeviceConfig: StartBaseAddresses %X, EndBaseAddresses %X\n", StartBaseAddresses, EndBaseAddresses);

            StartROMBaseAddress = FIELD_OFFSET(PCI_COMMON_CONFIG, u.type0.ROMBaseAddress);
            EndROMBaseAddress = (StartROMBaseAddress + RTL_FIELD_SIZE(PCI_COMMON_CONFIG, u.type0.ROMBaseAddress) - 1);

            DPRINT("PciExternalWriteDeviceConfig: StartROMBaseAddress %X, EndROMBaseAddress %X\n", StartROMBaseAddress, EndROMBaseAddress);

            if ((Offset >= StartBaseAddresses || (EndOffset - 1) >= StartBaseAddresses) &&
                (Offset <= StartBaseAddresses || Offset <= EndBaseAddresses))
            {
                DPRINT("PciExternalWriteDeviceConfig: IsVerifier = TRUE\n");
                IsVerifier = TRUE;
            }
            else if (Offset < StartROMBaseAddress && (EndOffset - 1) < StartROMBaseAddress)
            {
                goto Finish;
            }
            else if (Offset <= StartROMBaseAddress)
            {
                DPRINT("PciExternalWriteDeviceConfig: IsVerifier = TRUE\n");
                IsVerifier = TRUE;
            }
            else if (Offset <= EndROMBaseAddress)
            {
                DPRINT("PciExternalWriteDeviceConfig: IsVerifier = TRUE\n");
                IsVerifier = TRUE;
            }
            else
            {
                DPRINT("PciExternalWriteDeviceConfig: IsVerifier = FALSE\n");
                IsVerifier = FALSE;
            }
        }
    }
    else if (PdoExtension->HeaderType == 1)
    {
        DPRINT1("PciExternalWriteDeviceConfig: FIXME\n");
        ASSERT(FALSE);
    }
    else if (PdoExtension->HeaderType == 2)
    {
        DPRINT1("PciExternalWriteDeviceConfig: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        DPRINT1("PciExternalWriteDeviceConfig: %p, %X\n", PdoExtension, PdoExtension->HeaderType);
        DPRINT1("PciExternalWriteDeviceConfig: FIXME\n");
        ASSERT(FALSE);
        goto Finish;
    }

    if (IsVerifier)
    {
        VerifierData = PciVerifierRetrieveFailureData(3);
        ASSERT(VerifierData);
        DPRINT("PciExternalWriteDeviceConfig: VerifierData %X\n", VerifierData);

        VfFailDeviceNode(PdoExtension->PhysicalDeviceObject,
                         0xF6,
                         3,
                         VerifierData->FailureClass,
                         &VerifierData->AssertionControl,
                         VerifierData->DebuggerMessageText,
                         "%DevObj%Ulong%Ulong",
                         PdoExtension->PhysicalDeviceObject,
                         Offset,
                         Length);
    }

Finish:

    RtlCopyMemory(&Config, Buffer, Length);

    DPRINT("PciExternalWriteDeviceConfig: %X, %X\n", PdoExtension->InterruptPin, PdoExtension->RawInterruptLine);

    if (PdoExtension->InterruptPin &&
        Offset <= FIELD_OFFSET(PCI_COMMON_CONFIG,u.type0.InterruptLine) &&
        (Offset + Length) > FIELD_OFFSET(PCI_COMMON_CONFIG,u.type0.InterruptLine))
    {
        DPRINT("PciExternalWriteDeviceConfig: %X, %X\n", Config, ((PUCHAR)&Config.u.type0.InterruptLine - Offset));
        *((PUCHAR)&Config.u.type0.InterruptLine - Offset) = PdoExtension->RawInterruptLine;
    }

    PciWriteDeviceConfig(PdoExtension, &Config, Offset, Length);

    DPRINT("PciExternalWriteDeviceConfig: ret STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciWriteDeviceSpace(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ ULONG DataType,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _Out_ ULONG* OutLenght)
{
    PPCI_VERIFIER_DATA VerifierData;
    NTSTATUS Status;

    DPRINT("PciWriteDeviceSpace: %p\n", PdoExtension);

    *OutLenght = 0;

    if (DataType)
    {
        if (DataType == 'RicP')
        {
            DPRINT1("PciWriteDeviceSpace: (%p) WRITE_CONFIG IRP for ROM, failing.\n", PdoExtension);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            goto Exit;
        }

        VerifierData = PciVerifierRetrieveFailureData(4);
        ASSERT(VerifierData);

        VfFailDeviceNode(PdoExtension->PhysicalDeviceObject,
                         0xF6,
                         4,
                         VerifierData->FailureClass,
                         &VerifierData->AssertionControl,
                         VerifierData->DebuggerMessageText,
                         "%DevObj%Ulong",
                         PdoExtension->PhysicalDeviceObject,
                         DataType);
    }

    Status = PciExternalWriteDeviceConfig(PdoExtension, Buffer, Offset, Length);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciWriteDeviceSpace: %X\n", Status);
        return Status;
    }

Exit:

    *OutLenght = Length;

    return Status;
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
    PPCI_PDO_EXTENSION PdoExtension = Context;
    ULONG RetLength;

    DPRINT("PciPnpWriteConfig: %p\n", PdoExtension);

    ASSERT((PdoExtension)->ExtensionType == PciPdoExtensionType);

    PciWriteDeviceSpace(PdoExtension, DataType, Buffer, Offset, Length, &RetLength);

    return RetLength;
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
