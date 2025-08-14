/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include <ntddk.h>
#include <ide.h>

/* See ICH IDE Controller Programmer’s Reference Manual */

#define IS_UDMA33_CONTROLLER(Id) (Id == 0x7111 || Id == 0x2421 || Id == 0x7601 || Id == 0x2411 || Id == 0x7199 || \
                                  Id == 0x2441 || Id == 0x244A || Id == 0x244B || Id == 0x248A || Id == 0x248B || \
                                  Id == 0x24C1 || Id == 0x24CA || Id == 0x24CB || Id == 0x24D1 || Id == 0x24DB || \
                                  Id == 0x25A2 || Id == 0x25A3 || Id == 0x2651 || Id == 0x2652 || Id == 0x2653 || \
                                  Id == 0x266F)

#define IS_UDMA66_CONTROLLER(Id) (Id == 0x2411 || Id == 0x2441 || Id == 0x244A || Id == 0x244B || Id == 0x248A || \
                                  Id == 0x248B || Id == 0x24C1 || Id == 0x24CA || Id == 0x24CB || Id == 0x24D1 || \
                                  Id == 0x24DB || Id == 0x25A2 || Id == 0x25A3 || Id == 0x2651 || Id == 0x2652 || \
                                  Id == 0x2653 || Id == 0x266F)

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

typedef struct _INTEL_IDE_IO_CONFIGURATION
{
    union
    {
        struct
        {
            /* Base Clock */
            USHORT PCB0:1; // Primary
            USHORT PCB1:1;
            USHORT SCB0:1; // Slave
            USHORT SCB1:1;
            /* Cable Reporting */
            USHORT PCR0:1; // Primary
            USHORT PCR1:1;
            USHORT SCR0:1; // Slave
            USHORT SCR1:1;
            USHORT Reserved1:2;
            USHORT WrPingPongEn:1; // enable a performance enhancement feature for PIO transfers
            USHORT Reserved2:1;
            /* FAST Base Clock */
            USHORT FAST_PCB0:1; // Primary
            USHORT FAST_PCB1:1;
            USHORT FAST_SCB0:1; // Slave
            USHORT FAST_SCB1:1;
        };
        USHORT AsUSHORT;                        
    };
} INTEL_IDE_IO_CONFIGURATION, *PINTEL_IDE_IO_CONFIGURATION;

typedef struct _INTEL_PCI_CONFIGURATION
{
    USHORT VendorID;       // 00-01 Vendor ID  RO
    USHORT DeviceID;       // 02-03 Device ID  RO
    USHORT Command;        // 04-05 Command Register  R/W
    USHORT Status;         // 06-07 Device Status  R/W
    UCHAR RevisionID;      // 08    Revision ID  RO
    UCHAR ProgIf;          // 09    Programming Interface (Read-Only for ICH0, ICH, and ICH2, but Read-Write for ICH5, ICH4 and ICH3)  RO or RW
    UCHAR SubClass;        // 0A    Sub Class Code  RO
    UCHAR BaseClass;       // 0B    Base Class Code  RO
    UCHAR CacheLineSize;   // 0C    Reserved (Cache Line Size)  RO
    UCHAR LatencyTimer;    // 0D    Master Latency Timer  R/W
    UCHAR HeaderType;      // 0E    Header Type  RO
    UCHAR BIST;            // 0F    Reserved  RO
    ULONG CommandTask1;    // 10-13 Primary Command Task File Base Address Register (new for ICH5, ICH4 and ICH3)  R/W
    ULONG ControlTask1;    // 14-17 Primary Control Task File Base Address Register (new for ICH5, ICH4 and ICH3)  R/W
    ULONG CommandTask2;    // 18-1B Secondary Command Task File Base Address Register (new for ICH5, ICH4 and ICH3) R/W
    ULONG ControlTask2;    // 1C-1F Secondary Control Task File Base Address Register (new for ICH5, ICH4 and ICH3) R/W
    ULONG BusMasterIde;    // 20–23 Bus Master IDE Base Address Register  R/W 24–27 Expansion BAR  R/W
    ULONG ExpansionBAR;    // 24–27
    ULONG Reserved2;       // 28-2B Reserved  RO
    USHORT SubVendorID;    // 2C-2D Subsystem Vendor ID (ICH2, ICH3, ICH4, and ICH5)  R/W-Once
    USHORT SubSystemID;    // 2E-2F Subsystem ID (ICH2, ICH3, ICH4, and ICH5)  R/W-Once
    UCHAR Reserved3[12];   // 24–3B Reserved  RO
    UCHAR InterruptLine;   // 3C    Interrupt Line (new for ICH5, ICH4 and ICH3)  R/W
    UCHAR InterruptPin;    // 3D    Interrupt Pin (new for ICH5, ICH4 and ICH3)  RO
    UCHAR Reserved4[2];    // 3F    Reserved  RO
    USHORT IdeTiming1;     // 40–41 IDE TIMING (Primary)  R/W
    USHORT IdeTiming2;     // 42–43 IDE TIMING (Secondary)  R/W
    UCHAR SlaveIdeTiming;  // 44    Slave IDE Timing (Primary and Secondary)  R/W
    UCHAR Reserved5[3];    // 45-47 Reserved  RO
    UCHAR UltraDmaControl; // 48    Ultra DMA Control Register  R/W
    UCHAR Reserved6;       // 49    Reserved  RO
    USHORT UltraDmaTiming; // 4A-4B Ultra DMA Timing Register  R/W
    UCHAR Reserved7[8];    // 4C-53 Reserved  RO
    INTEL_IDE_IO_CONFIGURATION IdeIoConfiguration; // 54-55 IDE I/O Configuration (New for the “ICH family,” changes for ICH2, ICH3, ICH4, and ICH5) R/W
} INTEL_PCI_CONFIGURATION, *PINTEL_PCI_CONFIGURATION;

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
