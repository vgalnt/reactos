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

typedef struct _INTEL_SLAVE_IDE_TIMING
{
    union
    {
        struct
        {
            UCHAR RecoveryTime1:2;
            UCHAR IordySamplePoint1:2;
            UCHAR RecoveryTime2:2;
            UCHAR IordySamplePoint2:2;
        };

        UCHAR AsUCHAR;                        
    };
} INTEL_SLAVE_IDE_TIMING, *PINTEL_SLAVE_IDE_TIMING;

typedef struct _INTEL_ULTRA_DMA_CONTROL
{
    union
    {
        struct
        {
            UCHAR PSDE0:1; // Primary Drive 0 Ultra DMA Mode Enable
            UCHAR PSDE1:1; // Primary Drive 1 Ultra DMA Mode Enable
            UCHAR SSDE0:1; // Secondary Drive 0 Ultra DMA Mode Enable
            UCHAR SSDE1:1; // Secondary Drive 1 Ultra DMA Mode Enable
            UCHAR Reserved:4; // 0000h
        };

        UCHAR AsUCHAR;                        
    };
} INTEL_ULTRA_DMA_CONTROL, *PINTEL_ULTRA_DMA_CONTROL;

typedef struct _INTEL_ULTRA_DMA_TIMING
{
    union
    {
        struct
        {
            USHORT PCT0:2; // Primary Drive 0 Ultra DMA Cycle Time
            USHORT Reserved1:2; // 00h
            USHORT PCT1:2; // Primary Drive 1 Ultra DMA Cycle Time
            USHORT Reserved2:2; // 00h
            USHORT SCT0:2; // Secondary Drive 0 Ultra DMA Cycle Time
            USHORT Reserved3:2; // 00h
            USHORT SCT1:2; //  Secondary Drive 1 Ultra DMA Cycle Time
            USHORT Reserved4:2; // 00h
        };

        USHORT AsUSHORT;                        
    };
} INTEL_ULTRA_DMA_TIMING, *PINTEL_ULTRA_DMA_TIMING;

#include <poppack.h>

typedef struct _INTEL_CONTROLLER_EXTENSION
{
    USHORT DeviceId;
    UCHAR Pad[2];
    ULONG SupportedTransferMode[2][2];
    UCHAR CableReporting[2][2];
    ULONG UdmaSpeed;
    IDENTIFY_DATA IdentifyData[2];
} INTEL_CONTROLLER_EXTENSION, *PINTEL_CONTROLLER_EXTENSION;
