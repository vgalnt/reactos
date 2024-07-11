/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include <ntddk.h>
#include <ide.h>

typedef struct _INTEL_CONTROLLER_EXTENSION
{
    USHORT DeviceId;
    UCHAR Pad[2];
    ULONG SupportedTransferMode[2][2];
    ULONG UdmaSpeed;
} INTEL_CONTROLLER_EXTENSION, *PINTEL_CONTROLLER_EXTENSION;
