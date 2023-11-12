/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/arb/ar_busno.c
 * PURPOSE:         Bus Number Arbitration
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

//#define NDEBUG
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
arbusno_Constructor(IN PVOID DeviceExtension,
                    IN PVOID PciInterface,
                    IN PVOID InterfaceData,
                    IN USHORT Version,
                    IN USHORT Size,
                    IN PINTERFACE Interface)
{
    PPCI_FDO_EXTENSION FdoExtension = (PPCI_FDO_EXTENSION)DeviceExtension;
    NTSTATUS Status;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PciInterface);
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Interface);

    /* Make sure it's the expected interface */
    if ((ULONG_PTR)InterfaceData != CmResourceTypeBusNumber)
    {
        /* Arbiter support must have been initialized first */
        if (FdoExtension->ArbitersInitialized)
        {
            /* Not yet implemented */
            UNIMPLEMENTED_DBGBREAK();
            while (TRUE);
        }
        else
        {
            /* No arbiters for this FDO */
            Status = STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        /* Not the right interface */
        Status = STATUS_INVALID_PARAMETER_5;
    }

    /* Return the status */
    return Status;
}

/* EOF */
