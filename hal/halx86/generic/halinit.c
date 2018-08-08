/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/generic/halinit.c
 * PURPOSE:         HAL Entrypoint and Initialization
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <hal.h>
#define NDEBUG
#include <debug.h>

VOID
NTAPI
HalpGetParameters(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

#if defined(ALLOC_PRAGMA) && !defined(_MINIHAL_)
#pragma alloc_text(INIT, HalInitSystem)
#pragma alloc_text(INIT, HalpGetParameters)
#endif

/* GLOBALS *******************************************************************/

BOOLEAN HalpPciLockSettings;

/* PRIVATE FUNCTIONS *********************************************************/

BOOLEAN
NTAPI
HalpFindBusAddressTranslation(IN PHYSICAL_ADDRESS BusAddress,
                              IN OUT PULONG AddressSpace,
                              OUT PPHYSICAL_ADDRESS TranslatedAddress,
                              IN OUT PULONG_PTR Context,
                              IN BOOLEAN NextBus)
{
    /* Make sure we have a context */
    if (!Context) return FALSE;

    /* If we have data in the context, then this shouldn't be a new lookup */
    if ((*Context != 0) && (NextBus != FALSE)) return FALSE;

    /* Return bus data */
    TranslatedAddress->QuadPart = BusAddress.QuadPart;

    /* Set context value and return success */
    *Context = 1;
    return TRUE;
}

INIT_SECTION
VOID
NTAPI
HalpGetParameters(IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PCHAR CommandLine;

    /* Make sure we have a loader block and command line */
    if ((LoaderBlock) && (LoaderBlock->LoadOptions))
    {
        /* Read the command line */
        CommandLine = LoaderBlock->LoadOptions;

        /* Check if PCI is locked */
        if (strstr(CommandLine, "PCILOCK")) HalpPciLockSettings = TRUE;

        /* Check for initial breakpoint */
        if (strstr(CommandLine, "BREAK")) DbgBreakPoint();

        /* FIXME ?
           halapic.dll, halmps.dll - "ONECPU" "PCILOCK" "CLKLVL" "USE8254" "INTAFFINITY" "USEPHYSICALAPIC" "TIMERES" "BREAK" "MAXPROCSPERCLUSTER" "MAXAPICCLUSTER"
           halaacpi.dll - "ONECPU" "PCILOCK" "INTAFFINITY" "USEPHYSICALAPIC" "BREAK" "MAXPROCSPERCLUSTER" "MAXAPICCLUSTER"
           halmacpi.dll - "ONECPU" "PCILOCK" "USEPMTIMER" "INTAFFINITY" "USEPHYSICALAPIC" "BREAK" "MAXPROCSPERCLUSTER" "MAXAPICCLUSTER"
        */
    }
}

/* FUNCTIONS *****************************************************************/

VOID
NTAPI
HalInitializeProcessor(
    IN ULONG ProcessorNumber,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    /* Hal specific initialization for this cpu */
    HalpInitProcessor(ProcessorNumber, LoaderBlock);

    /* Set default stall count */
    KeGetPcr()->StallScaleFactor = INITIAL_STALL_COUNT;

    /* Update the interrupt affinity and processor mask */
    InterlockedBitTestAndSet((PLONG)&HalpActiveProcessors, ProcessorNumber);
    InterlockedBitTestAndSet((PLONG)&HalpDefaultInterruptAffinity,
                             ProcessorNumber);

    /* Register routines for KDCOM */
    HalpRegisterKdSupportFunctions();
}

/*
 * @implemented
 */
INIT_SECTION
BOOLEAN
NTAPI
HalInitSystem(IN ULONG BootPhase,
              IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PKPRCB Prcb = KeGetCurrentPrcb();

    /* Check the boot phase */
    if (BootPhase == 0)
    {
        /* Phase 0... save bus type */
        HalpBusType = LoaderBlock->u.I386.MachineType & 0xFF;

        /* Get command-line parameters */
        HalpGetParameters(LoaderBlock);

        /* Check for PRCB version mismatch */
        if (Prcb->MajorVersion != PRCB_MAJOR_VERSION)
        {
            /* No match, bugcheck */
            KeBugCheckEx(MISMATCHED_HAL, 1, Prcb->MajorVersion, PRCB_MAJOR_VERSION, 0);
        }

        /* Checked/free HAL requires checked/free kernel */
        if (Prcb->BuildType != HalpBuildType)
        {
            /* No match, bugcheck */
            KeBugCheckEx(MISMATCHED_HAL, 2, Prcb->BuildType, HalpBuildType, 0);
        }

        /* Initialize the PICs */
        HalpInitializePICs(TRUE);

        /* Initialize CMOS lock */
        KeInitializeSpinLock(&HalpSystemHardwareLock);

        /* Initialize CMOS */
        HalpInitializeCmos();

        /* Fill out HalDispatchTable */
        HalQuerySystemInformation = HaliQuerySystemInformation;
        HalInitPnpDriver = HaliInitPnpDriver;
        HalGetDmaAdapter = HalpGetDmaAdapter;

        HalpAssignGetInterruptTranslator();
        HalpAssignHaltSystem();

        /* Fill out HalPrivateDispatchTable */
        HalResetDisplay = HalpBiosDisplayReset;
        //HalAllocateMapRegisters = HalpAllocateMapRegisters  // FIXME: TODO
        //HalLocateHiberRanges = HaliLocateHiberRanges        // FIXME: TODO

        /* Initialize ACPI */
        HalpSetupAcpiPhase0(LoaderBlock);

        /* Do some HAL-specific initialization */
        HalpInitPhase0(LoaderBlock);

        /* Setup I/O space */
        HalpDefaultIoSpace.Next = HalpAddressUsageList;
        HalpAddressUsageList = &HalpDefaultIoSpace;

        // FIXME HalpEisaIoSpace
        if (HalpBusType == MACHINE_TYPE_EISA)
        {
            DPRINT1("HalInitSystem: HalpBusType == MACHINE_TYPE_EISA\n");
            ASSERT(FALSE);
        } 

        /* Setup busy waiting */
        HalpCalibrateStallExecution();

        /* Initialize the clock */
        HalpInitializeClock();

        /*
         * We could be rebooting with a pending profile interrupt,
         * so clear it here before interrupts are enabled
         */
        HalStopProfileInterrupt(ProfileTime);

        // FIXME LessThan16Mb and HalpPhysicalMemoryMayAppearAbove4GB
    }
    else if (BootPhase == 1)
    {
        /* Initialize bus handlers */
        HalpInitBusHandlers();

        /* Do some HAL-specific initialization */
        HalpInitPhase1(LoaderBlock);
    }

    /* All done, return */
    return TRUE;
}
