/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include <ntddk.h>
#include <ide.h>

/* See ICH IDE Controller Programmer’s Reference Manual */

#include <pshpack1.h>

typedef struct _INTEL_MODES_TIMING_AND_CONTROL
{
    union
    {
        struct
        {
            USHORT TIME0:1; // Fast Timing Bank Drive Select 0
            USHORT IE0:1; // IORDY Sample Point Enable Select 0
            USHORT PPE0:1; // Pre-fetch and Posting Enable Select 0
            USHORT DTE0:1; // DMA Timing Enable Only Select 0
            USHORT TIME1:1; // Fast Timing Bank Drive Select 1
            USHORT IE1:1; // IORDY Sample Point Enable Select 1
            USHORT PPE1:1; // Pre-fetch and Posting Enable Select 1
            USHORT DTE1:1; // DMA Timing Enable Only Select 1
            USHORT RecoveryTime:2;
            USHORT Reserved:2; // 00
            USHORT ISP:2; // IORDY Sample Point
            USHORT SITRE:1; // Slave IDE Timing Register Enable
            USHORT IdeDecodeEnable:1;
        };

        USHORT AsUSHORT;                        
    };
} INTEL_MODES_TIMING_AND_CONTROL, *PINTEL_MODES_TIMING_AND_CONTROL;

#include <poppack.h>

typedef struct _INTEL_CONTROLLER_EXTENSION
{
    USHORT DeviceId;
    UCHAR Pad[2];
    ULONG SupportedTransferMode[2][2];
    ULONG UdmaSpeed;
} INTEL_CONTROLLER_EXTENSION, *PINTEL_CONTROLLER_EXTENSION;
