/*
 * PROJECT:     ReactOS USB EHCI Miniport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     USBEHCI debugging functions
 * COPYRIGHT:   Copyright 2017-2018, 2025 Vadim Galyant <vgal@rambler.ru>
 */

#include "usbehci.h"

#define NDEBUG
#include <debug.h>

VOID
NTAPI
EHCI_DumpHwTD(IN PEHCI_HCD_TD TD)
{
    if (!TD)
        return;

    while (TD)
    {
        DPRINT("TD              %p %p %p %p\n", TD, TD->PhysicalAddress, TD->HwTD.NextTD, TD->HwTD.AlternateNextTD);
    if (TD->HwTD.Token.AsULONG)
        DPRINT("Token           %p (dt %X tb %X ioc %X cp %X ec %X pc %X st %X)\n",
               TD->HwTD.Token.AsULONG,
               TD->HwTD.Token.DataToggle,
               TD->HwTD.Token.TransferBytes,
               TD->HwTD.Token.InterruptOnComplete,
               TD->HwTD.Token.CurrentPage,
               TD->HwTD.Token.ErrorCounter,
               TD->HwTD.Token.PIDCode,
               TD->HwTD.Token.Status);

        TD = TD->NextHcdTD;
    }
}

VOID
NTAPI
EHCI_DumpHwQH(IN PEHCI_HCD_QH QH)
{
    if (!QH)
        return;

    DPRINT("EHCI_DumpHwQH:  %p %p\n", QH, QH->sqh.HwQH.HorizontalLink.AsULONG);
    //DPRINT("HorizontalLink  %p\n");
    DPRINT("EndpointParams  %p nak %X %X len %X %X dt %X %X num %X %X %X\n",
           QH->sqh.HwQH.EndpointParams.AsULONG,
           QH->sqh.HwQH.EndpointParams.NakCountReload,
           QH->sqh.HwQH.EndpointParams.ControlEndpointFlag,
           QH->sqh.HwQH.EndpointParams.MaximumPacketLength,
           QH->sqh.HwQH.EndpointParams.HeadReclamationListFlag,
           QH->sqh.HwQH.EndpointParams.DataToggleControl,
           QH->sqh.HwQH.EndpointParams.EndpointSpeed,
           QH->sqh.HwQH.EndpointParams.EndpointNumber,
           QH->sqh.HwQH.EndpointParams.InactivateOnNextTransaction,
           QH->sqh.HwQH.EndpointParams.DeviceAddress);
    //DPRINT("EndpointCaps    %p\n", QH->sqh.HwQH.EndpointCaps.AsULONG);
    DPRINT("TD Cur Next Alt %p %p %p\n", QH->sqh.HwQH.CurrentTD, QH->sqh.HwQH.NextTD, QH->sqh.HwQH.AlternateNextTD);
if (QH->sqh.HwQH.Token.AsULONG)
    DPRINT("Token           %p (dt %X tb %X ioc %X cp %X ec %X pc %X st %X)\n",
           QH->sqh.HwQH.Token.AsULONG,
           QH->sqh.HwQH.Token.DataToggle,
           QH->sqh.HwQH.Token.TransferBytes,
           QH->sqh.HwQH.Token.InterruptOnComplete,
           QH->sqh.HwQH.Token.CurrentPage,
           QH->sqh.HwQH.Token.ErrorCounter,
           QH->sqh.HwQH.Token.PIDCode,
           QH->sqh.HwQH.Token.Status);
}
