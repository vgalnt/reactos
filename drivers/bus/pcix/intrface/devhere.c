/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/devhere.c
 * PURPOSE:         Device Presence Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
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
PcipDevicePresentOnBus(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_DEVICE_PRESENCE_PARAMETERS Parameters)
{
    PPCI_PDO_EXTENSION ChildPdoExtension;
    BOOLEAN IsDevicePresent = FALSE;

    DPRINT("PcipDevicePresentOnBus: %p, %p\n", FdoExtension, PdoExtension);

    KeEnterCriticalRegion();
    KeWaitForSingleObject(&FdoExtension->ChildListLock, Executive, KernelMode, FALSE, NULL);

    for (ChildPdoExtension = FdoExtension->ChildPdoList;
         ChildPdoExtension;
         ChildPdoExtension = ChildPdoExtension->Next)
    {
        if (PdoExtension &&
            (Parameters->Flags & 0x40) &&
            PdoExtension->Slot.u.bits.DeviceNumber != ChildPdoExtension->Slot.u.bits.DeviceNumber)
        {
            continue;
        }

        if (Parameters->Flags & 0x04)
        {
            if (ChildPdoExtension->VendorId != Parameters->VendorID)
                continue;

            if (ChildPdoExtension->DeviceId != Parameters->DeviceID)
                continue;

            if ((Parameters->Flags & 0x01))
            {
                if (ChildPdoExtension->SubsystemVendorId != Parameters->SubVendorID)
                    continue;

                if (ChildPdoExtension->SubsystemId != Parameters->SubSystemID)
                    continue;
            }

            if ((Parameters->Flags & 0x02) &&
                ChildPdoExtension->RevisionId != Parameters->RevisionID)
            {
                continue;
            }
        }

        if (!(Parameters->Flags & 0x08))
        {
            IsDevicePresent = TRUE;
            break;
        }

        if (ChildPdoExtension->BaseClass != Parameters->BaseClass)
            continue;

        if (ChildPdoExtension->SubClass != Parameters->SubClass)
            continue;

        if ((Parameters->Flags & 0x10) && ChildPdoExtension->ProgIf != Parameters->ProgIf)
            continue;

        IsDevicePresent = TRUE;
        break;
    }

    KeSetEvent(&FdoExtension->ChildListLock, IO_NO_INCREMENT, FALSE);
    KeLeaveCriticalRegion();

    return IsDevicePresent;
}

BOOLEAN
NTAPI
devpresent_IsDevicePresentEx(
   _In_ PVOID Context,
   _In_ PPCI_DEVICE_PRESENCE_PARAMETERS Parameters)
{
    PPCI_PDO_EXTENSION PdoExtension = Context;
    PSINGLE_LIST_ENTRY Entry;
    BOOLEAN IsDevicePresent = FALSE;

    PAGED_CODE();
    DPRINT("devpresent_IsDevicePresentEx: %p, %p\n", Context, Parameters);

    if (!Parameters)
    {
        ASSERT(ARGUMENT_PRESENT(Parameters));
        return FALSE;
    }

    if (Parameters->Size < sizeof(PCI_DEVICE_PRESENCE_PARAMETERS))
    {
        ASSERT(Parameters->Size >= sizeof(PCI_DEVICE_PRESENCE_PARAMETERS));
        return FALSE;
    }

    if (!(Parameters->Flags & 0xC))
    {
        ASSERT(Parameters->Flags & (PCI_USE_VENDEV_IDS | PCI_USE_CLASS_SUBCLASS));
        return FALSE;
    }

    if (Parameters->Flags & 3 && !(Parameters->Flags & 4))
    {
        ASSERT(Parameters->Flags & PCI_USE_VENDEV_IDS);
        return FALSE;
    }

    if (Parameters->Flags & 0x10 && !(Parameters->Flags & 8))
    {
        ASSERT(Parameters->Flags & PCI_USE_CLASS_SUBCLASS);
        return FALSE;
    }

    KeEnterCriticalRegion();
    KeWaitForSingleObject(&PciGlobalLock, Executive, KernelMode, FALSE, NULL);

    if (Parameters->Flags & 0x60)
    {
        if (PdoExtension)
            IsDevicePresent = PcipDevicePresentOnBus(PdoExtension->ParentFdoExtension, PdoExtension, Parameters);
        else
            ASSERT(PdoExtension != NULL);
    }
    else
    {
        for (Entry = PciFdoExtensionListHead.Next; Entry; Entry = Entry->Next)
        {
            IsDevicePresent = PcipDevicePresentOnBus(CONTAINING_RECORD(Entry, PCI_FDO_EXTENSION, List), NULL, Parameters);
            if (IsDevicePresent)
                break;
        }
    }

    KeSetEvent(&PciGlobalLock, IO_NO_INCREMENT, FALSE);
    KeLeaveCriticalRegion();

    return IsDevicePresent;
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
