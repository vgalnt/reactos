
/* INCLUDES *******************************************************************/

#include <hal.h>
#include "apic.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

const UCHAR HalpClockVector = 0xD1;
BOOLEAN HalpClockSetMSRate;
UCHAR HalpNextMSRate;
UCHAR HalpCurrentRate = 9;  /* Initial rate  9: 128 Hz / 7.8 ms */
ULONG HalpCurrentTimeIncrement;

typedef struct _HAL_RTC_TIME_INCREMENT
{
    ULONG RTCRegisterA;
    ULONG ClockRateIn100ns;
    ULONG Reserved;
    ULONG ClockRateAdjustment;
    ULONG IpiRate;
} HAL_RTC_TIME_INCREMENT, *PHAL_RTC_TIME_INCREMENT;

/* CMOS 0Ah - RTC - STATUS REGISTER A (read/write) (usu 26h)

Bit(s)  Description     (Table C001)
 7      =1 time update cycle in progress, data ouputs undefined (bit 7 is read only)
 6-4    22 stage divider
        010 = 32768 Hz time base (default)
 3-0    rate selection bits for interrupt

        0000 none
 1      0001 256  30.517 microseconds
 2      0010 128  61.035 us
 3      0011 8192 122 us (minimum) 122.070
 4      0100 4096 244.140 us
 5      0101 2048 488.281 us
 6      0110 1024 976.562 us (default 1024 Hz) 976.562.5
 7      0111 512  1,953.125 milliseconds
 8      1000 256  3,906.25 ms
 9      1001 128  7,812.5 ms
 A      1010 64   15,625 ms
 B      1011 32   31,25 ms
 C      1100 16   62,5 ms
 D      1101 8    125 ms
 E      1110 4    250 ms
 F      1111 2    500 ms

*/
HAL_RTC_TIME_INCREMENT HalpRtcTimeIncrements[5] =
{
    {0x26, 0x02626, 0x26, 0x60, 0x010}, // 0 010 0110, ((default 1024 Hz) 976.562 microseconds )
    {0x27, 0x04C4C, 0x4B, 0xC0, 0x020}, // 0 010 0111, (512 Hz)
    {0x28, 0x09897, 0x32, 0x80, 0x040}, // 0 010 1000, (256 Hz)
    {0x29, 0x1312D, 0,    0,    0x080}, // 0 010 1001, (128 Hz)
    {0x2A, 0x2625A, 0,    0,    0x100}  // 0 010 1010, (64 Hz)
};

ULONG HalpInitialClockRateIndex = (5 - 1);

ULONG HalpCurrentRTCRegisterA;
ULONG HalpCurrentClockRateIn100ns;
ULONG HalpCurrentClockRateAdjustment;
ULONG HalpCurrentIpiRate;

ULONG HalpIpiClock = 0;
ULONG HalpIpiRateCounter = 0;
UCHAR HalpRateAdjustment = 0;

UCHAR HalpClockMcaQueueDpc;

BOOLEAN IsFirstCallClockInt = TRUE;
BOOLEAN IsFirstCallClockIntStub = TRUE;
BOOLEAN HalpTimerWatchdogEnabled = FALSE;
UCHAR ClockIntCalls = 0;
UCHAR HalpUse8254 = 0;

extern ULONG HalpWAETDeviceFlags;

/* FUNCTIONS ******************************************************************/

VOID NTAPI HalpSetInitialClockRate();
VOID NTAPI HalpInitializeClock(VOID);

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGELK, HalpSetInitialClockRate)
  #pragma alloc_text(PAGELK, HalpInitializeClock)
#endif

CODE_SEG("PAGELK")
VOID
NTAPI
HalpSetInitialClockRate()
{
    HalpClockSetMSRate = FALSE;
    HalpClockMcaQueueDpc = 0;

    HalpNextMSRate = HalpInitialClockRateIndex;

    HalpCurrentRTCRegisterA = HalpRtcTimeIncrements[HalpNextMSRate].RTCRegisterA;
    HalpCurrentClockRateIn100ns = HalpRtcTimeIncrements[HalpNextMSRate].ClockRateIn100ns;
    HalpCurrentClockRateAdjustment = HalpRtcTimeIncrements[HalpNextMSRate].ClockRateAdjustment;
    HalpCurrentIpiRate = HalpRtcTimeIncrements[HalpNextMSRate].IpiRate;

    DPRINT("HalpCurrentRTCRegisterA        - %X\n", HalpCurrentRTCRegisterA);
    DPRINT("HalpCurrentClockRateIn100ns    - %X\n", HalpCurrentClockRateIn100ns);
    DPRINT("HalpCurrentClockRateAdjustment - %X\n", HalpCurrentClockRateAdjustment);
    DPRINT("HalpCurrentIpiRate             - %X\n", HalpCurrentIpiRate);

    KeSetTimeIncrement(HalpRtcTimeIncrements[HalpNextMSRate].ClockRateIn100ns,
                       HalpRtcTimeIncrements[0].ClockRateIn100ns);
}

CODE_SEG("PAGELK")
VOID
NTAPI
HalpInitializeClock(VOID)
{
    ULONG EFlags;
    ULONG ix;
    UCHAR RegisterB;
    UCHAR NewRegisterB;
    UCHAR RegisterC;
    UCHAR RegisterD;

    DPRINT("HalpInitializeClock()\n");

    if (HalpTimerWatchdogEnabled)
    {
        DPRINT1("HalpInitializeClock: FIXME. DbgBreakPoint()\n");
        DbgBreakPoint();
    }

    /* Save EFlags and disable interrupts */
    EFlags = __readeflags();
    _disable();

    HalpSetInitialClockRate();

    /* Acquire CMOS lock */
    HalpAcquireCmosSpinLock();

    HalpWriteCmos(RTC_REGISTER_A, HalpCurrentRTCRegisterA);

    RegisterB = HalpReadCmos(RTC_REGISTER_B);
    NewRegisterB = (RTC_REG_B_PI | RTC_REG_B_HM | (RegisterB & RTC_REG_B_DS));
    HalpWriteCmos(RTC_REGISTER_B, NewRegisterB);

    RegisterC = HalpReadCmos(RTC_REGISTER_C);
    RegisterD = HalpReadCmos(RTC_REGISTER_D);

    DPRINT("HalpInitializeClock: A %X, B %X, C %X, D %X\n", HalpCurrentRTCRegisterA, RegisterB, RegisterC, RegisterD);

    for (ix = 0; ix < 10; ix++)
    {
        RegisterC = HalpReadCmos(RTC_REGISTER_C);
        if ((RegisterC & RTC_REG_C_IRQ) == 0)
        {
            break;
        }
    }

    /* Release CMOS lock */
    HalpReleaseCmosSpinLock();

    if (HalpUse8254)
    {
        DPRINT1("HalpInitializeClock: FIXME. DbgBreakPoint()\n");
        DbgBreakPoint();
    }

    __writeeflags(EFlags);

    DPRINT("HalpInitializeClock: Clock initialized\n");
}

VOID
FASTCALL
HalpClockInterruptStubHandler(
    _In_ PKTRAP_FRAME TrapFrame)
{
    UCHAR CmosData;

    /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

    /* Read register C, so that the next interrupt can happen */
    CmosData = HalpReadCmos(RTC_REGISTER_C);
    CmosData = HalpReadCmos(RTC_REGISTER_C);

    while (CmosData & RTC_REG_C_IRQ)
    {
        CmosData = HalpReadCmos(RTC_REGISTER_C);
    }

    ApicWrite(APIC_EOI, 0);

  #ifdef __REACTOS__
    KiEoiHelper(TrapFrame);
  #else
    #error FIXME call Kei386EoiHelper()
  #endif
}

VOID
FASTCALL
HalpClockInterruptHandler(
    _In_ PKTRAP_FRAME TrapFrame)
{
    ULONG LastIncrement;
    KIRQL OldIrql = 0;

    /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

    /* Start the interrupt */
    if (!HalBeginSystemInterrupt(CLOCK_LEVEL, HalpClockVector, &OldIrql))
    {
        /* Spurious, just end the interrupt */
      #ifdef __REACTOS__
        KiEoiHelper(TrapFrame);
      #else
        #error FIXME call Kei386EoiHelper()
      #endif
    }

    /* Emulated Device Flags Field (ULONG)

        0: RTC good
            Indicates whether the RTC has been enhanced not to require acknowledgment after it asserts an interrupt. With this bit set, an interrupt handler can bypass reading the RTC register C to unlatch the pending interrupt.	
        1: ACPI PM timer good
            Indicates whether the ACPI PM timer has been enhanced not to require multiple reads. With this bit set, only one read of the ACPI PM timer is necessary to obtain a reliable value.	
        2-31: Reserved; must return 0 when read.
    */
    if (!(HalpWAETDeviceFlags & 1))
    {
        HalpAcquireCmosSpinLock();
        HalpReadCmos(RTC_REGISTER_C);
        HalpReadCmos(RTC_REGISTER_C);
        HalpReleaseCmosSpinLock();
    }

    HalpRateAdjustment += (UCHAR)HalpCurrentClockRateAdjustment;

    if (HalpRateAdjustment < (UCHAR)HalpCurrentClockRateAdjustment)
    {
        LastIncrement = (HalpCurrentClockRateIn100ns - 1);
    }
    else
    {
        LastIncrement = HalpCurrentClockRateIn100ns;
    }


  #ifdef __REACTOS__
    RosKeUpdateSystemTime(TrapFrame, LastIncrement, HalpClockVector, OldIrql);
  #else
    #error FIXME call KeUpdateSystemTime()
  #endif

    DPRINT1("HalpClockInterruptHandler: DbgBreakPoint()\n");
    ASSERT(FALSE); // HalpDbgBreakPointEx();
}

/* EOF */
