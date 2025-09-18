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

    DPRINT(": QH->sqh.HwQH.CurrentTD       - %lx\n", QH->sqh.HwQH.CurrentTD);
    DPRINT(": QH->sqh.HwQH.NextTD          - %lx\n", QH->sqh.HwQH.NextTD);
    DPRINT(": QH->sqh.HwQH.AlternateNextTD - %lx\n", QH->sqh.HwQH.AlternateNextTD);
    DPRINT(": QH->sqh.HwQH.Token.AsULONG   - %lx\n", QH->sqh.HwQH.Token.AsULONG);
}
