
/* INCLUDES ******************************************************************/

#include <hal.h>
#include "timer.h"

//#define NDEBUG
#include <debug.h>

/* PUBLIC FUNCTIONS ***********************************************************/

BOOLEAN
NTAPI
HalMakeBeep(IN ULONG Frequency)
{
    SYSTEM_CONTROL_PORT_B_REGISTER SystemControl;
    TIMER_CONTROL_PORT_REGISTER TimerControl;
    ULONG Divider;
    BOOLEAN Result = FALSE;

    HalpAcquireCmosSpinLock();

    /* Turn the timer off by disconnecting its output pin and speaker gate. */
    SystemControl.Bits = READ_PORT_UCHAR(SYSTEM_CONTROL_PORT_B);
    SystemControl.SpeakerDataEnable = FALSE;
    SystemControl.Timer2GateToSpeaker = FALSE;
    WRITE_PORT_UCHAR(SYSTEM_CONTROL_PORT_B, SystemControl.Bits);

    if (!Frequency)
        goto Exit;

    Divider = (PIT_FREQUENCY / Frequency);

    if (Divider > 0x10000)
        goto Exit;

    /* Program the PIT for binary mode. */
    TimerControl.BcdMode = FALSE;

    /* Program the PIT to generate a square wave (Mode 3) on channel 2.
       Channel 0 is used for the IRQ0 clock interval timer, and channel
       1 is used for DRAM refresh.

       Mode 2 gives much better accuracy, but generates an output signal
       that drops to low for each input signal cycle at 0.8381 useconds.
       This is too fast for the PC speaker to process and would result
       in no sound being emitted.

       Mode 3 will generate a high pulse that is a bit longer and will
       allow the PC speaker to notice. Additionally, take note that on
       channel 2, when input goes low the counter will stop and output
       will go to high.
    */
    TimerControl.OperatingMode = PitOperatingMode3;
    TimerControl.Channel = PitChannel2;

    /* Set the access mode that we'll use to program the reload value. */
    TimerControl.AccessMode = PitAccessModeLowHigh;

    /* Now write the programming bits */
    WRITE_PORT_UCHAR(TIMER_CONTROL_PORT, TimerControl.Bits);

    /* Next we write the reload value for channel 2 */
    WRITE_PORT_UCHAR(TIMER_CHANNEL2_DATA_PORT, Divider & 0xFF);
    WRITE_PORT_UCHAR(TIMER_CHANNEL2_DATA_PORT, (Divider >> 8) & 0xFF);

    /* Reconnect the speaker to the timer and re-enable the output pin. */
    SystemControl.Bits = READ_PORT_UCHAR(SYSTEM_CONTROL_PORT_B);
    SystemControl.SpeakerDataEnable = TRUE;
    SystemControl.Timer2GateToSpeaker = TRUE;
    WRITE_PORT_UCHAR(SYSTEM_CONTROL_PORT_B, SystemControl.Bits);

    Result = TRUE;

Exit:
    HalpReleaseCmosSpinLock();

    return Result;
}
