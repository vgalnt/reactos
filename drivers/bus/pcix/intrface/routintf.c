/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/routinf.c
 * PURPOSE:         Routing Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PPCI_LEGACY_DEVICE PciLegacyDeviceHead;

PCI_INTERFACE PciRoutingInterface =
{
    &GUID_INT_ROUTE_INTERFACE_STANDARD,
    sizeof(INT_ROUTE_INTERFACE_STANDARD),
    PCI_INT_ROUTE_INTRF_STANDARD_VER,
    PCI_INT_ROUTE_INTRF_STANDARD_VER,
    PCI_INTERFACE_FDO,
    0,
    PciInterface_IntRouteHandler,
    routeintrf_Constructor,
    routeintrf_Initializer
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
routeintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
    /* PnP Interfaces don't get Initialized */
    ASSERTMSG("PCI routeintrf_Initializer, unexpected call.\n", FALSE);
    return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
pcicbintrf_Dereference(
    _In_ PVOID Context)
{
    ;
}

NTSTATUS
NTAPI
PciFindLegacyDevice(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_ ULONG* OutBus,
    _Out_ ULONG* OutPciSlot,
    _Out_ UCHAR* OutInterruptLine,
    _Out_ UCHAR* OutInterruptPin,
    _Out_ UCHAR* OutClassCode,
    _Out_ UCHAR* OutSubClassCode,
    _Out_ PDEVICE_OBJECT* OutParentPdo,
    _Out_ ROUTING_TOKEN* OutRoutingToken)
{
    PPCI_LEGACY_DEVICE LegacyDevice;
    NTSTATUS Status = STATUS_NOT_FOUND;

    PAGED_CODE();
    DPRINT("PciFindLegacyDevice: %p\n", Pdo);

    LegacyDevice = PciLegacyDeviceHead;
    if (!LegacyDevice)
        return Status;

    DPRINT1("PciFindLegacyDevice: FIXME\n");
    ASSERT(FALSE);

    return Status;
}

NTSTATUS
NTAPI
PciGetInterruptRoutingInfo(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_ ULONG* OutBus,
    _Out_ ULONG* OutPciSlot,
    _Out_ UCHAR* OutInterruptLine,
    _Out_ UCHAR* OutInterruptPin,
    _Out_ UCHAR* OutClassCode,
    _Out_ UCHAR* OutSubClassCode,
    _Out_ PDEVICE_OBJECT* OutParentPdo,
    _Out_ ROUTING_TOKEN* OutRoutingToken)
{
    PPCI_ROUTING_EXTENSION RoutingExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    NTSTATUS Status;

    DPRINT("PciGetInterruptRoutingInfo: %p\n", Pdo);

    PdoExtension = Pdo->DeviceExtension;

    ASSERT(OutBus);
    ASSERT(OutPciSlot);
    ASSERT(OutInterruptLine);
    ASSERT(OutInterruptPin);
    ASSERT(OutClassCode);
    ASSERT(OutSubClassCode);
    ASSERT(OutParentPdo);
    ASSERT(OutRoutingToken);

    Status = PciFindLegacyDevice(Pdo,
                                 OutBus,
                                 OutPciSlot,
                                 OutInterruptLine,
                                 OutInterruptPin,
                                 OutClassCode,
                                 OutSubClassCode,
                                 OutParentPdo,
                                 OutRoutingToken);
    if (NT_SUCCESS(Status))
        return Status;

    DPRINT("PciGetInterruptRoutingInfo: Status %X\n", Status);

    if (!PdoExtension)
    {
        DPRINT1("PciGetInterruptRoutingInfo: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    if (PdoExtension->ExtensionType != PciPdoExtensionType)
    {
        DPRINT("PciGetInterruptRoutingInfo: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    *OutBus = PdoExtension->ParentFdoExtension->BaseBus;
    *OutPciSlot = PdoExtension->Slot.u.AsULONG;
    *OutInterruptLine = PdoExtension->RawInterruptLine;
    *OutInterruptPin = PdoExtension->InterruptPin;
    *OutClassCode = PdoExtension->BaseClass;
    *OutSubClassCode = PdoExtension->SubClass;
    *OutParentPdo = PdoExtension->ParentFdoExtension->PhysicalDeviceObject;

    RoutingExtension = (PVOID)PciFindNextSecondaryExtension(PdoExtension->SecondaryExtension.Next, PciInterface_IntRouteHandler);

    if (RoutingExtension)
    {
        *OutRoutingToken = RoutingExtension->RoutingToken;
    }
    else
    {
        OutRoutingToken->LinkNode = NULL;
        OutRoutingToken->StaticVector = 0;
        OutRoutingToken->Flags = 0;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciGetInterruptRoutingInfoEx(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_ ULONG* OutBus,
    _Out_ ULONG* OutPciSlot,
    _Out_ UCHAR* OutInterruptLine,
    _Out_ UCHAR* OutInterruptPin,
    _Out_ UCHAR* OutClassCode,
    _Out_ UCHAR* OutSubClassCode,
    _Out_ PDEVICE_OBJECT* OutParentPdo,
    _Out_ ROUTING_TOKEN* OutRoutingToken,
    _Out_ UCHAR* OutFlags)
{
    NTSTATUS Status;

    DPRINT("PciGetInterruptRoutingInfoEx: %p\n", Pdo);

    Status = PciGetInterruptRoutingInfo(Pdo,
                                        OutBus,
                                        OutPciSlot,
                                        OutInterruptLine,
                                        OutInterruptPin,
                                        OutClassCode,
                                        OutSubClassCode,
                                        OutParentPdo,
                                        OutRoutingToken);
    *OutFlags = 0;

    DPRINT("PciGetInterruptRoutingInfoEx: ret %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
PciSetLegacyDeviceToken(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PROUTING_TOKEN RoutingToken)
{
    PPCI_LEGACY_DEVICE LegacyDevice;

    PAGED_CODE();
    DPRINT("PciSetLegacyDeviceToken: %p\n", Pdo);

    for (LegacyDevice = PciLegacyDeviceHead;
         LegacyDevice;
         LegacyDevice = LegacyDevice->Next)
    {
        if (LegacyDevice->DeviceObject == Pdo)
        {
            LegacyDevice->RoutingToken = *RoutingToken;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS
NTAPI
PciSetRoutingToken(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PROUTING_TOKEN RoutingToken)
{
    PPCI_ROUTING_EXTENSION RoutingExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    NTSTATUS status;

    DPRINT("PciSetRoutingToken: %p\n", Pdo);

    status = PciSetLegacyDeviceToken(Pdo, RoutingToken);
    if (NT_SUCCESS(status))
        return STATUS_SUCCESS;

    PdoExtension = Pdo->DeviceExtension;

    RoutingExtension = (PVOID)PciFindNextSecondaryExtension(PdoExtension->SecondaryExtension.Next, PciInterface_IntRouteHandler);
    if (RoutingExtension)
    {
        DPRINT("PciSetRoutingToken: *** redundant PCI routing extesion being created ***\n");
    }
    ASSERT(RoutingExtension == NULL);

    RoutingExtension = ExAllocatePool(PagedPool, sizeof(*PdoExtension)); // POOL_TYPE 0x101
    if (!RoutingExtension)
    {
        DPRINT1("PciSetRoutingToken: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RoutingExtension->RoutingToken = *RoutingToken;

    PcipLinkSecondaryExtension(&PdoExtension->SecondaryExtension,
                               &PdoExtension->SecondaryExtLock,
                               &RoutingExtension->SecondaryExtension,
                               PciInterface_IntRouteHandler,
                               NULL);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciSetRoutingTokenEx(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PROUTING_TOKEN RoutingToken)
{
    return PciSetRoutingToken(Pdo, RoutingToken);
}

VOID
NTAPI
PciUpdateInterruptLine(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ UCHAR LineRegister)
{
    PPCI_PDO_EXTENSION PdoExtension = NULL;
    PPCI_LEGACY_DEVICE LegacyDevice;
    PCI_COMMON_HEADER PciData;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciUpdateInterruptLine: %p, %X\n", Pdo, LineRegister);

    for (LegacyDevice = PciLegacyDeviceHead;
         LegacyDevice;
         LegacyDevice = LegacyDevice->Next)
    {
        if (LegacyDevice->DeviceObject == Pdo)
        {
            PdoExtension = LegacyDevice->PdoExtension;
            break;
        }
    }

    if (!PdoExtension)
        PdoExtension = Pdo->DeviceExtension;

    ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

    PdoExtension->AdjustedInterruptLine = LineRegister;
    PdoExtension->RawInterruptLine = LineRegister;

    PciWriteDeviceConfig(PdoExtension, &LineRegister, FIELD_OFFSET(PCI_COMMON_CONFIG, u.type0.InterruptLine), 1);

    Status = PciGetBiosConfig(PdoExtension, &PciData);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciUpdateInterruptLine: Status %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
        return;
    }

    if (PciData.u.type0.InterruptLine == LineRegister)
        return;

    PciData.u.type0.InterruptLine = LineRegister;

    Status = PciSaveBiosConfig(PdoExtension, &PciData);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciUpdateInterruptLine: Status %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
    }
}

NTSTATUS
NTAPI
routeintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface)
{
    PINT_ROUTE_INTERFACE_STANDARD RouteInterface = (PVOID)Interface;

    DPRINT("routeintrf_Constructor: %p, %X\n", Interface, Version);

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(InterfaceData);
    UNREFERENCED_PARAMETER(Size);

    /* Only version 1 is supported */
    if (Version != PCI_INT_ROUTE_INTRF_STANDARD_VER)
        return STATUS_NOINTERFACE;

    RouteInterface->Size = sizeof(*RouteInterface);
    RouteInterface->Version = Version;
    RouteInterface->Context = DeviceExtension;
    RouteInterface->InterfaceReference = pcicbintrf_Dereference;
    RouteInterface->InterfaceDereference = pcicbintrf_Dereference;
    RouteInterface->GetInterruptRouting = PciGetInterruptRoutingInfoEx;
    RouteInterface->SetInterruptRoutingToken = PciSetRoutingTokenEx;
    RouteInterface->UpdateInterruptLine = PciUpdateInterruptLine;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciCacheLegacyDeviceRouting(IN PDEVICE_OBJECT DeviceObject,
                            IN ULONG BusNumber,
                            IN ULONG SlotNumber,
                            IN UCHAR InterruptLine,
                            IN UCHAR InterruptPin,
                            IN UCHAR BaseClass,
                            IN UCHAR SubClass,
                            IN PDEVICE_OBJECT PhysicalDeviceObject,
                            IN PPCI_PDO_EXTENSION PdoExtension,
                            OUT PDEVICE_OBJECT *pFoundDeviceObject)
{
    PPCI_LEGACY_DEVICE *Link;
    PPCI_LEGACY_DEVICE LegacyDevice;
    PDEVICE_OBJECT FoundDeviceObject;
    PAGED_CODE();

    /* Scan current registered devices */
    LegacyDevice = PciLegacyDeviceHead;
    Link = &PciLegacyDeviceHead;
    while (LegacyDevice)
    {
        /* Find a match */
        if ((BusNumber == LegacyDevice->BusNumber) &&
            (SlotNumber == LegacyDevice->SlotNumber))
        {
            /* We already know about this routing */
            break;
        }

        /* We know about device already, but for a different location */
        if (LegacyDevice->DeviceObject == DeviceObject)
        {
            /* Free the existing structure, move to the next one */
            *Link = LegacyDevice->Next;
            ExFreePoolWithTag(LegacyDevice, 0);
            LegacyDevice = *Link;
        }
        else
        {
            /* Keep going */
            Link = &LegacyDevice->Next;
            LegacyDevice = LegacyDevice->Next;
        }
    }

    /* Did we find a match? */
    if (!LegacyDevice)
    {
        /* Allocate a new cache structure */
        LegacyDevice = ExAllocatePoolWithTag(PagedPool,
                                             sizeof(PCI_LEGACY_DEVICE),
                                             'PciR');
        if (!LegacyDevice) return STATUS_INSUFFICIENT_RESOURCES;

        /* Save all the data in it */
        RtlZeroMemory(LegacyDevice, sizeof(PCI_LEGACY_DEVICE));
        LegacyDevice->BusNumber = BusNumber;
        LegacyDevice->SlotNumber = SlotNumber;
        LegacyDevice->InterruptLine = InterruptLine;
        LegacyDevice->InterruptPin = InterruptPin;
        LegacyDevice->BaseClass = BaseClass;
        LegacyDevice->SubClass = SubClass;
        LegacyDevice->PhysicalDeviceObject = PhysicalDeviceObject;
        LegacyDevice->DeviceObject = DeviceObject;
        LegacyDevice->PdoExtension = PdoExtension;

        /* Link it in the list */
        LegacyDevice->Next = PciLegacyDeviceHead;
        PciLegacyDeviceHead = LegacyDevice;
    }

    /* Check if we found, or created, a matching caching structure */
    FoundDeviceObject = LegacyDevice->DeviceObject;
    if (FoundDeviceObject == DeviceObject)
    {
        /* Return the device object and success */
        if (pFoundDeviceObject) *pFoundDeviceObject = DeviceObject;
        return STATUS_SUCCESS;
    }

    /* Otherwise, this is a new device object for this location */
    LegacyDevice->DeviceObject = DeviceObject;
    if (pFoundDeviceObject) *pFoundDeviceObject = FoundDeviceObject;
    return STATUS_SUCCESS;
}

/* EOF */
