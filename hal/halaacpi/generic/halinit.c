
/* INCLUDES ******************************************************************/

#include <hal.h>
//#define NDEBUG
#include <debug.h>
#include "apic.h"
#include "pic.h"

#if defined(ALLOC_PRAGMA) && !defined(_MINIHAL_)
  #pragma alloc_text(INIT, HalInitializeProcessor)
  #pragma alloc_text(INIT, HalInitSystem)
  #pragma alloc_text(INIT, HalpGetParameters)
#endif

/* GLOBALS *******************************************************************/

ADDRESS_USAGE HalpDefaultIoSpace =
{
    NULL, CmResourceTypePort, IDT_INTERNAL,
    {
        {0x00,  0x20}, /* DMA 1 */
        {0xC0,  0x20}, /* DMA 2 */
        {0x80,  0x10}, /* DMA EPAR */
        {0x20,  0x2},  /* PIC 1 */
        {0xA0,  0x2},  /* PIC 2 */
        {0x40,  0x4},  /* PIT 1 */
        {0x48,  0x4},  /* PIT 2 */
        {0x92,  0x1},  /* System Control Port A */
        {0x70,  0x2},  /* CMOS  */
        {0xF0,  0x10}, /* x87 Coprocessor */
        {0xCF8, 0x8},  /* PCI 0 */
        {0,0},
    }
};

ADDRESS_USAGE HalpEisaIoSpace =
{
    NULL, CmResourceTypePort, IDT_INTERNAL,
    {
        {0x0D0, 0x10},
        {0x400, 0x10},
        {0x480, 0x10},
        {0x4C2, 0x0E},
        {0x4D4, 0x2C},
        {0x461, 0x02},
        {0x464, 0x02},
        {0x4D0, 0x02},
        {0xC84, 0x01},
        {0,0},
    }
};

ADDRESS_USAGE HalpImcrIoSpace =
{
    NULL, CmResourceTypeMemory, IDT_INTERNAL,
    {
        {0x22, 0x02},
        {0,0},
    }
};

PADDRESS_USAGE HalpAddressUsageList;

PKPCR HalpProcessorPCR[32];
KAFFINITY HalpActiveProcessors;
KAFFINITY HalpDefaultInterruptAffinity;
ULONGLONG HalpProc0TSCHz;
ULONG HalpBusType;
ULONG HalpDefaultApicDestinationModeMask = 0x800;
BOOLEAN HalpUsePmTimer = FALSE;
BOOLEAN HalpPciLockSettings;
UCHAR HalpInitLevel = 0xFF;

extern BOOLEAN HalpForceApicPhysicalDestinationMode;
extern KSPIN_LOCK HalpSystemHardwareLock;
extern KSPIN_LOCK HalpAccountingLock;
extern BOOLEAN HalpForceClusteredApicMode;
extern UCHAR HalpMaxProcsPerCluster;
extern HALP_MP_INFO_TABLE HalpMpInfoTable;
extern APIC_ADDRESS_USAGE HalpApicUsage;
extern ULONG HalpPicVectorRedirect[HAL_PIC_VECTORS];
extern USHORT HalpVectorToINTI[MAX_CPUS * MAX_INT_VECTORS];
extern KSPIN_LOCK HalpDmaAdapterListLock;
extern LIST_ENTRY HalpDmaAdapterList;
extern BOOLEAN LessThan16Mb;
extern BOOLEAN HalpPhysicalMemoryMayAppearAbove4GB;
extern HALP_DMA_MASTER_ADAPTER MasterAdapter24;
extern HALP_DMA_MASTER_ADAPTER MasterAdapter32;

/* PRIVATE FUNCTIONS *********************************************************/

//INIT_FUNCTION
VOID
NTAPI
HalpGetParameters(
    _In_ PCHAR CommandLine)
{
    /* Check if PCI is locked */
    if (strstr(CommandLine, "PCILOCK"))
        HalpPciLockSettings = TRUE;

    /* Check for initial breakpoint */
    if (strstr(CommandLine, "BREAK"))
    {
        DPRINT1("HalpGetParameters: FIXME parameters [BREAK]. DbgBreakPoint()\n");
        DbgBreakPoint();
    }

    if (strstr(CommandLine, "ONECPU"))
    {
        DPRINT1("HalpGetParameters: FIXME parameters [ONECPU]. DbgBreakPoint()\n");
        DbgBreakPoint();
        //HalpDontStartProcessors++;
    }

  #ifdef CONFIG_SMP // halmacpi only
    if (strstr(CommandLine, "USEPMTIMER"))
    {
        HalpUsePmTimer = TRUE;
    }
  #endif

    if (strstr(CommandLine, "INTAFFINITY"))
    {
        DPRINT1("HalpGetParameters: FIXME parameters [INTAFFINITY]. DbgBreakPoint()\n");
        DbgBreakPoint();
        //HalpStaticIntAffinity = TRUE;
    }

    if (strstr(CommandLine, "USEPHYSICALAPIC"))
    {
        HalpDefaultApicDestinationModeMask = 0;
        HalpForceApicPhysicalDestinationMode = TRUE;
    }

    if (strstr(CommandLine, "MAXPROCSPERCLUSTER"))
    {
        DPRINT1("HalpGetParameters: FIXME parameters [MAXPROCSPERCLUSTER]. DbgBreakPoint()\n");
        DbgBreakPoint();
    }

    if (strstr(CommandLine, "MAXAPICCLUSTER"))
    {
        DPRINT1("HalpGetParameters: FIXME parameters [MAXAPICCLUSTER]. DbgBreakPoint()\n");
        DbgBreakPoint();
    }
}

/* FUNCTIONS *****************************************************************/

//INIT_FUNCTION
VOID
NTAPI
HalInitializeProcessor(
    IN ULONG ProcessorNumber,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PKPCR Pcr = KeGetPcr();
    //LONG Comparand;
    //LONG Exchange = -1;
    BOOLEAN IsMpSystem;
    BOOLEAN Result;

    Pcr->IDR = 0xFFFFFFFF;                         /* Set default IDR */
    Pcr->StallScaleFactor = INITIAL_STALL_COUNT;   /* Set default stall count */

    *(PUCHAR)(Pcr->HalReserved) = ProcessorNumber; // FIXME
    HalpProcessorPCR[ProcessorNumber] = Pcr;

    /* Update the processors mask */
    InterlockedBitTestAndSet((PLONG)&HalpActiveProcessors, ProcessorNumber);

#if 0 /* Support '/INTAFFINITY' key in boot.ini */

    for (Comparand = HalpDefaultInterruptAffinity;
         Comparand != Exchange;
         )
    {
        if (!HalpStaticIntAffinity)
            Exchange = Comparand;
        else
            Exchange = 0;

        BitTestAndSet(&Exchange, ProcessorNumber);

        if (Exchange < Comparand)
            /* If true 'INTAFFINITY' key, then exit if InterruptAffinity != 0 */
            break;

        /* Update the interrupt affinity */
        Comparand = InterlockedCompareExchange((PLONG)&HalpDefaultInterruptAffinity, Exchange, Comparand);
    }
#else
    /* By default, the HAL allows interrupt requests to be received by all processors */
    InterlockedBitTestAndSet((PLONG)&HalpDefaultInterruptAffinity, ProcessorNumber);
#endif

    if (ProcessorNumber == 0)
    {
        Result = DetectAcpiMP(&IsMpSystem, KeLoaderBlock);
        if (!Result)
        {
            HalDisplayString("\n\nHAL: This HAL.DLL requires an MPS version 1.1 system\nReplace HAL.DLL with the correct hal for this system\nThe system is halting");
            __halt();
        }

        /* Register routines for KDCOM */

        /* Register PCI Device Functions */
        KdSetupPciDeviceForDebugging = HalpSetupPciDeviceForDebugging;
        KdReleasePciDeviceforDebugging = HalpReleasePciDeviceForDebugging;

        /* Register ACPI stub */
        KdGetAcpiTablePhase0 = HalAcpiGetTable;
        KdCheckPowerButton = HalpCheckPowerButton;

        /* Register memory functions */
        KdMapPhysicalMemory64 = HalpMapPhysicalMemory64;
        KdUnmapVirtualAddress = HalpUnmapVirtualAddress;

        //HalpGlobal8259Mask = 0xFFFF; // FIXME

        WRITE_PORT_UCHAR(PIC1_DATA_PORT, 0xFF);
        WRITE_PORT_UCHAR(PIC2_DATA_PORT, 0xFF);
    }

    HalInitApicInterruptHandlers();
    HalpInitializeLocalUnit();
}

VOID
NTAPI
HalpInitNonBusHandler(VOID)
{
    DPRINT("HalpInitNonBusHandler()\n");

    /* These (HalPrivateDispatchTable) should be written by the PCI driver later, but we give defaults */
    HalPciTranslateBusAddress = HalpTranslateBusAddress;
    HalPciAssignSlotResources = HalpAssignSlotResources;
    HalFindBusAddressTranslation = HalpFindBusAddressTranslation;
}

//INIT_FUNCTION
BOOLEAN
NTAPI
HalInitSystem(IN ULONG BootPhase,
              IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PMEMORY_ALLOCATION_DESCRIPTOR MemDescriptor;
    PHALP_PCR_HAL_RESERVED HalReserved;
    PKPRCB Prcb = KeGetCurrentPrcb();
    ULONG PhysicalAddress;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    USHORT IntI;

    DPRINT1("HalInitSystem: Phase %X, Processor %X\n", BootPhase, Prcb->Number);

    /* Check the boot phase */
    if (BootPhase == 0)
    {
        HalpInitLevel = 0;

        /* Phase 0... save bus type */
        HalpBusType = (LoaderBlock->u.I386.MachineType & 0xFF);

        /* Get command-line parameters */
        HalpGetParameters(LoaderBlock->LoadOptions);

        /* Check for PRCB version mismatch */
        if (Prcb->MajorVersion != PRCB_MAJOR_VERSION) {
            /* No match, bugcheck */
            DPRINT1("HalInitSystem: MajorVersion %X - (%X)\n", Prcb->MajorVersion, PRCB_MAJOR_VERSION);
            KeBugCheckEx(MISMATCHED_HAL, 1, Prcb->MajorVersion, PRCB_MAJOR_VERSION, 0);
        }

      #if DBG 
        if ((Prcb->BuildType & PRCB_BUILD_DEBUG) == 0) {
            DPRINT1("HalInitSystem: BuildType %X - (%X)\n", Prcb->BuildType, PRCB_BUILD_DEBUG);
            KeBugCheckEx(MISMATCHED_HAL, 2, Prcb->BuildType, PRCB_BUILD_DEBUG, 0);
        }
        if ((Prcb->BuildType & PRCB_BUILD_UNIPROCESSOR) == PRCB_BUILD_UNIPROCESSOR) {
            DPRINT1("HalInitSystem: BuildType %X - (%X)\n", Prcb->BuildType, PRCB_BUILD_UNIPROCESSOR);
            KeBugCheckEx(MISMATCHED_HAL, 2, Prcb->BuildType, 0, 0);
        }
      #else 
        if ((Prcb->BuildType & PRCB_BUILD_DEBUG) == PRCB_BUILD_DEBUG) {
            DPRINT1("HalInitSystem: BuildType %X - (%X)\n", Prcb->BuildType, PRCB_BUILD_DEBUG);
            KeBugCheckEx(MISMATCHED_HAL, 2, Prcb->BuildType, PRCB_BUILD_DEBUG, 0);
        }
      #endif

        /* Do some HAL-specific initialization */ // HalpInitPhase0_0
        if (HalpBusType == MACHINE_TYPE_MCA) {
            DPRINT1("HalInitSystem: HalpBusType %X - (%X)\n", HalpBusType, MACHINE_TYPE_MCA);
            KeBugCheckEx(MISMATCHED_HAL, 3, MACHINE_TYPE_MCA, 0, 0);
        }

        KeInitializeSpinLock(&HalpAccountingLock);

        /* Initialize ACPI */
        HalpSetupAcpiPhase0(LoaderBlock);

        if (HalpForceClusteredApicMode)
            HalpMaxProcsPerCluster = 4;

        HalpInitializeApicAddressing();

        DPRINT1("HalInitSystem: FIXME HalpBuildIpiDestinationMap\n");
        //HalpBuildIpiDestinationMap(0);

        /* Fill out HalDispatchTable */
        HalQuerySystemInformation = HaliQuerySystemInformation;
        HalSetSystemInformation = HaliSetSystemInformation; // FIXME TODO: HalpSetSystemInformation

        if (HalDispatchTableVersion >= HAL_DISPATCH_VERSION)
        {
            /* Fill out HalDispatchTable */
            HalInitPnpDriver = HaliInitPnpDriver;
            HalGetDmaAdapter = HaliGetDmaAdapter;
            HalGetInterruptTranslator = HalacpiGetInterruptTranslator;
            HalInitPowerManagement = HaliInitPowerManagement;

            /* Fill out HalPrivateDispatchTable */
            HalLocateHiberRanges = HaliLocateHiberRanges;        // FIXME: TODO
            HalHaltSystem = HaliHaltSystem;
            HalResetDisplay = HalpBiosDisplayReset;
            HalAllocateMapRegisters = HalpAllocateMapRegisters;  // FIXME: TODO
        }

        /* Setup I/O space */
        HalpDefaultIoSpace.Next = HalpAddressUsageList;
        HalpAddressUsageList = &HalpDefaultIoSpace;

        if (HalpBusType == MACHINE_TYPE_EISA)
        {
            DPRINT1("HalInitSystem: HalpBusType == MACHINE_TYPE_EISA\n");
            HalpEisaIoSpace.Next = &HalpDefaultIoSpace;
            HalpAddressUsageList = &HalpEisaIoSpace;
        } 

        if (HalpMpInfoTable.ImcrPresent)
        {
            HalpImcrIoSpace.Next = HalpAddressUsageList;
            HalpAddressUsageList = &HalpImcrIoSpace;
        }

        RtlZeroMemory(&HalpApicUsage, APIC_ADDRESS_USAGE_SIZE);

        HalpInitIntiInfo();
        HalpInitializeIOUnits();

        /* Initialize the PICs */
        HalpInitializePICs(TRUE);

        OldIrql = KeGetCurrentIrql();
        KfRaiseIrql(OldIrql);

        /* Initialize CMOS lock */
        KeInitializeSpinLock(&HalpSystemHardwareLock);

        /* Initialize CMOS */
        HalpInitializeCmos();

        if (!HalpGetApicInterruptDesc(HalpPicVectorRedirect[APIC_CLOCK_INDEX], &IntI))
        {
            DPRINT1("HalInitSystem: No RTC device interrupt. DbgBreakPoint()\n");
            DbgBreakPoint();
            return FALSE;
        }

        DPRINT("HalInitSystem: IntI %X\n", IntI);

        if (!HalpPmTimerScaleTimers())
        {
            DPRINT1("HalInitSystem: FIXME HalpScaleTimers(). DbgBreakPoint()\n");
            DbgBreakPoint();
            //HalpScaleTimers();
        }

        HalReserved = (PHALP_PCR_HAL_RESERVED)KeGetPcr()->HalReserved;
        HalpProc0TSCHz = HalReserved->TscHz;

        KeRegisterInterruptHandler(0x50, HalpApicRebootService);
        KeRegisterInterruptHandler(APIC_GENERIC_VECTOR, HalpBroadcastCallService);
        KeRegisterInterruptHandler(APIC_CLOCK_VECTOR, HalpClockInterruptStub);

        /* Enable clock interrupt handler */
        DPRINT1("HalInitSystem: CLOCK2_LEVEL %X\n", CLOCK2_LEVEL);
        HalpVectorToINTI[APIC_CLOCK_VECTOR] = IntI;

        HalEnableSystemInterrupt(APIC_CLOCK_VECTOR, CLOCK_LEVEL, Latched);

        /* Initialize the clock */
        DPRINT1("HalInitSystem: Initialize the clock\n");
        HalpInitializeClock();

        HalpRegisterVector(IDT_INTERNAL, APIC_NMI_VECTOR, APIC_NMI_VECTOR, HIGH_LEVEL);
        HalpRegisterVector(IDT_INTERNAL, APIC_SPURIOUS_VECTOR, APIC_SPURIOUS_VECTOR, HIGH_LEVEL);

        KeSetProfileIrql(HIGH_LEVEL);

        /* We could be rebooting with a pending profile interrupt, so clear it here before interrupts are enabled */
        DPRINT1("HalInitSystem: clear profile interrupt\n");
        HalStopProfileInterrupt(ProfileTime);

        KeRegisterInterruptHandler(APIC_PROFILE_VECTOR, HalpProfileInterrupt);
        KeRegisterInterruptHandler(APIC_PERF_VECTOR, HalpPerfInterrupt);
        KeRegisterInterruptHandler(APIC_IPI_VECTOR, HalpIpiHandler);

        /* Fill out HalPrivateDispatchTable */
        HalFindBusAddressTranslation = HalpFindBusAddressTranslation;

        KeInitializeSpinLock(&HalpDmaAdapterListLock);
        InitializeListHead(&HalpDmaAdapterList);

        for (Entry = LoaderBlock->MemoryDescriptorListHead.Flink;
             Entry != &LoaderBlock->MemoryDescriptorListHead;
             Entry = Entry->Flink)
        {
            MemDescriptor = CONTAINING_RECORD(Entry, MEMORY_ALLOCATION_DESCRIPTOR, ListEntry);

            if (MemDescriptor->MemoryType != LoaderFirmwarePermanent &&
                MemDescriptor->MemoryType != LoaderSpecialMemory)
            {
                if (MemDescriptor->BasePage + MemDescriptor->PageCount > 0x1000) // 16 Mb
                    LessThan16Mb = FALSE;

                if (MemDescriptor->BasePage + MemDescriptor->PageCount > 0x100000) // 4 Gb
                {
                    HalpPhysicalMemoryMayAppearAbove4GB = TRUE;
                    break;
                }
            }
        }

        if (LessThan16Mb)
        {
            DPRINT1("HalInitSystem: LessThan16Mb is TRUE\n");
        }
        if (HalpPhysicalMemoryMayAppearAbove4GB)
        {
            DPRINT1("HalInitSystem: HalpPhysicalMemoryMayAppearAbove4GB is TRUE\n");
        }

        PhysicalAddress = HalpAllocPhysicalMemory(LoaderBlock, 0x1000000, 0x10, TRUE);

        if (!PhysicalAddress)
            MasterAdapter24.MapBufferSize = 0;
        else
            MasterAdapter24.MapBufferSize = (0x10 * PAGE_SIZE);

        MasterAdapter24.MapBufferPhysicalAddress.QuadPart = PhysicalAddress;
        MasterAdapter24.MapBufferMaxPages = 0x40;

        MasterAdapter32.MapBufferMaxPages = 0x4000;

        if (HalpPhysicalMemoryMayAppearAbove4GB)
        {
            PhysicalAddress = HalpAllocPhysicalMemory(LoaderBlock, MAXULONG, 0x30, TRUE);

            if (!PhysicalAddress)
                MasterAdapter32.MapBufferSize = 0;
            else
                MasterAdapter32.MapBufferSize = (0x30 * PAGE_SIZE);

            MasterAdapter32.MapBufferPhysicalAddress.QuadPart = PhysicalAddress;
        }

        DPRINT("HalInitSystem: FIXME! KeRegisterBugCheckCallback\n");
        //ASSERT(FALSE);// HalpDbgBreakPointEx();
        //KeRegisterBugCheckCallback(..);
    }
    else if (BootPhase == 1)
    {
        HalpInitLevel = 0;

        if (Prcb->Number != 0)
        {
            DPRINT1("HalInitSystem: Prcb->Number %X\n", Prcb->Number);
            return TRUE;
        }

        /* Initialize DMA. NT does this in Phase 0 */
        HalpInitDma();

        DPRINT1("HalpInitPhase1: FIXME HalpInitReservedPages()\n");

        /* Initialize bus handlers */
        HalpInitNonBusHandler();

        KeRegisterInterruptHandler(APIC_CLOCK_VECTOR, HalpClockInterrupt);

        //HalpGetFeatureBits()

        //DPRINT1("HalInitSystem: FIXME! BootPhase == 1\n");
        //ASSERT(FALSE);// HalpDbgBreakPointEx();
    }
    else
    {
        DPRINT1("HalInitSystem: Unknown BootPhase %X\n", BootPhase);
    }

    return TRUE;
}

/* EOF */
