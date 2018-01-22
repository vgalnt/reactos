/*
 * PROJECT:     ReactOS USB Hub Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     USBHub, "black list" for USB devices not yet supported
 * COPYRIGHT:   Copyright 2018 Vadim Galyant <vgal@rambler.ru>
 */

#include "usbhub.h"

#define NDEBUG
#include <debug.h>

BOOLEAN
NTAPI
USBH_IsVidPidFromBlackList(IN USHORT IdVendor,
                           IN USHORT IdProduct,
                           IN USHORT Revision)
{
    BOOLEAN Result = FALSE;

    DPRINT1("USBH_IsVidPidFromBlackList: IdVendor - %X, IdProduct - %X\n",
           IdVendor,
           IdProduct);
   
    return Result;
}

