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

extern PCI_INT_ROUTE_INTERFACE PciIrqRoutingInterface;
extern HAL_PCI_IRQ_ROUTING_INFO HalpPciIrqRoutingInfo;
extern ULONG HalpIrqMiniportInitialized;

#endif  /* _HAL_LEGACY_H */

