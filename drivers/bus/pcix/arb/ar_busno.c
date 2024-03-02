/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/ar_busno.c
 * PURPOSE:         Bus Number Arbitration
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PCI_INTERFACE ArbiterInterfaceBusNumber =
{
    &GUID_ARBITER_INTERFACE_STANDARD,
    sizeof(ARBITER_INTERFACE),
    0,
    0,
    PCI_INTERFACE_FDO,
    0,
    PciArb_BusNumber,
    arbusno_Constructor,
    arbusno_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
arbusno_UnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
arbusno_PackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ ULONGLONG Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
arbusno_UnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG Start,
    _Out_ PULONG OutLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

LONG
NTAPI
arbusno_ScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}


NTSTATUS
NTAPI
arbusno_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    NTSTATUS Status;

    DPRINT("arbusno_Initializer: %p\n", Instance);
    PAGED_CODE();

    RtlZeroMemory(&Instance->CommonInstance, sizeof(Instance->CommonInstance));

    Instance->CommonInstance.UnpackRequirement = arbusno_UnpackRequirement;
    Instance->CommonInstance.PackResource = arbusno_PackResource;
    Instance->CommonInstance.UnpackResource = arbusno_UnpackResource;
    Instance->CommonInstance.ScoreRequirement = arbusno_ScoreRequirement;

    Status = ArbInitializeArbiterInstance(&Instance->CommonInstance,
                                          Instance->BusFdoExtension->FunctionalDeviceObject,
                                          CmResourceTypeBusNumber,
                                          Instance->InstanceName,
                                          L"Pci",
                                          NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("arbusno_Initializer: init arbiter return %X", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
arbusno_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID PciInterface,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PARBITER_INTERFACE ArbInterface = (PVOID)Interface;

    DPRINT("arbusno_Constructor: %p\n", Interface);
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypeBusNumber)
    {
        /* Not the right interface */
        DPRINT("arbusno_Constructor: STATUS_INVALID_PARAMETER_5\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    ArbInterface->Version = 0;
    ArbInterface->Flags = 0;
    ArbInterface->Size = sizeof(*ArbInterface);
    ArbInterface->InterfaceReference = PciReferenceArbiter;
    ArbInterface->InterfaceDereference = PciDereferenceArbiter;
    ArbInterface->ArbiterHandler = ArbArbiterHandler;

    return PciArbiterInitializeInterface(DeviceExtension, PciArb_BusNumber, ArbInterface);
}

/* EOF */
