
/* INCLUDES *******************************************************************/

#include <hal.h>
#include "pic.h"

//#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGELK, HalpInitializeLegacyPICs)
#endif

CODE_SEG("PAGELK")
VOID
NTAPI
HalpInitializeLegacyPICs(
    _In_ BOOLEAN InterruptMode)
{
    I8259_ICW1 Icw1;
    I8259_ICW2 Icw2;
    I8259_ICW3 Icw3;
    I8259_ICW4 Icw4;

    /* For APIC InterruptMode always is EdgeTriggered */
    ASSERT(InterruptMode == EdgeTriggered);

    ASSERT(!(__readeflags() & EFLAGS_INTERRUPT_MASK));

    /* Initialize ICW1 for master, interval 8, edge-triggered mode with ICW4 */
    Icw1.NeedIcw4 = TRUE;
    Icw1.OperatingMode = Cascade;
    Icw1.Interval = Interval8;
    Icw1.InterruptMode = (InterruptMode ? LevelTriggered : EdgeTriggered);
    Icw1.Init = TRUE;
    Icw1.InterruptVectorAddress = 0;
    WRITE_PORT_UCHAR(PIC1_CONTROL_PORT, Icw1.Bits);

    /* ICW2 - interrupt vector offset */
    Icw2.Bits = PRIMARY_VECTOR_BASE;
    WRITE_PORT_UCHAR(PIC1_DATA_PORT, Icw2.Bits);

    /* Connect slave to IRQ 2 */
    Icw3.Bits = 0;
    Icw3.SlaveIrq2 = TRUE;
    WRITE_PORT_UCHAR(PIC1_DATA_PORT, Icw3.Bits);

    /* Enable 8086 mode, non-automatic EOI, non-buffered mode, non special fully nested mode */
    Icw4.SystemMode = New8086Mode;
    Icw4.EoiMode = NormalEoi;
    Icw4.BufferedMode = NonBuffered;
    Icw4.SpecialFullyNestedMode = FALSE;
    Icw4.Reserved = 0;
    WRITE_PORT_UCHAR(PIC1_DATA_PORT, Icw4.Bits);

    /* Mask all interrupts */
    WRITE_PORT_UCHAR(PIC1_DATA_PORT, 0xFF);

    /* Initialize ICW1 for slave, interval 8, edge-triggered mode with ICW4 */
    Icw1.NeedIcw4 = TRUE;
    Icw1.InterruptMode = EdgeTriggered;
    Icw1.OperatingMode = Cascade;
    Icw1.Interval = Interval8;
    Icw1.Init = TRUE;
    Icw1.InterruptVectorAddress = 0; /* This is only used in MCS80/85 mode */
    WRITE_PORT_UCHAR(PIC2_CONTROL_PORT, Icw1.Bits);

    /* Set interrupt vector base */
    Icw2.Bits = PRIMARY_VECTOR_BASE + 8;
    WRITE_PORT_UCHAR(PIC2_DATA_PORT, Icw2.Bits);

    /* Slave ID */
    Icw3.Bits = 0;
    Icw3.SlaveId = 2;
    WRITE_PORT_UCHAR(PIC2_DATA_PORT, Icw3.Bits);

    /* Enable 8086 mode, non-automatic EOI, non-buffered mode, non special fully nested mode */
    Icw4.SystemMode = New8086Mode;
    Icw4.EoiMode = NormalEoi;
    Icw4.BufferedMode = NonBuffered;
    Icw4.SpecialFullyNestedMode = FALSE;
    Icw4.Reserved = 0;
    WRITE_PORT_UCHAR(PIC2_DATA_PORT, Icw4.Bits);

    /* Mask all interrupts */
    WRITE_PORT_UCHAR(PIC2_DATA_PORT, 0xFF);
}
