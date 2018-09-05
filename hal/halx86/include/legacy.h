#ifndef _HAL_LEGACY_H
#define _HAL_LEGACY_H

typedef struct _PCI_INT_ROUTE_INTERFACE {
    INTERFACE StdInterface;
    PVOID GetInterruptRoutingInfo;
    PVOID SetRoutingToken;
    PVOID UpdateInterruptLine;
} PCI_INT_ROUTE_INTERFACE, *PPCI_INT_ROUTE_INTERFACE;

typedef struct _HAL_PCI_IRQ_ROUTING_INFO
{
    PPCI_IRQ_ROUTING_TABLE PciIrqRoutingTable;
    PPCI_INT_ROUTE_INTERFACE PciIrqRouteInterface;
    PVOID LinkNode;
    ULONG Parameters;
} HAL_PCI_IRQ_ROUTING_INFO, *PHAL_PCI_IRQ_ROUTING_INFO;

PBUS_HANDLER
FASTCALL
HaliReferenceHandlerForBus(
    IN INTERFACE_TYPE InterfaceType,
    IN ULONG BusNumber
);

VOID
FASTCALL
HaliDereferenceBusHandler(
    IN PBUS_HANDLER Handler
);

ULONG
NTAPI
HaliPciInterfaceWriteConfig(
    IN IN PVOID Context,
    IN ULONG BusNumber,
    IN ULONG SlotNumber,
    IN PVOID Buffer,
    IN ULONG Offset,
    IN ULONG Length
);

extern PCI_INT_ROUTE_INTERFACE PciIrqRoutingInterface;
extern HAL_PCI_IRQ_ROUTING_INFO HalpPciIrqRoutingInfo;
extern ULONG HalpIrqMiniportInitialized;

#endif  /* _HAL_LEGACY_H */

