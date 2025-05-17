
/* INCLUDES *******************************************************************/

#include <hal.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PHALP_STALL_EXEC_PROC TimerStallExecProc = HalpPmTimerStallExecProc;
PHALP_CALIBRATE_PERF_COUNT TimerCalibratePerfCount = HalpPmTimerCalibratePerfCount;
PHALP_QUERY_PERF_COUNT TimerQueryPerfCount = HalpPmTimerQueryPerfCount;
PHALP_SET_TIME_INCREMENT TimerSetTimeIncrement = HalpPmTimerSetTimeIncrement;

PHALP_QUERY_TIMER QueryTimer = HalpQueryPerformanceCounter;
ULONG PMTimerFreq = 3579545;

HALP_TIMER_INFO TimerInfo;

#define HAL_STALL_LOOP  42
ULONG StallLoopValue = HAL_STALL_LOOP;
UCHAR StallExecCounter = 0;

/* Stall execute */
#define PmPause(OutTotalCount, Value) \
    *OutTotalCount += Value; \
    do { Value--; } while (Value);

/* PM TIMER FUNCTIONS *********************************************************/

VOID
NTAPI
HaliPmTimerQueryPerfCount(
    _Out_ LARGE_INTEGER* OutPerfCount,
    _Out_ LARGE_INTEGER* OutPerfFrequency)
{
    OutPerfCount->QuadPart = (TimerInfo.PerformanceCounter.QuadPart + QueryTimer());

    if (OutPerfFrequency)
        OutPerfFrequency->QuadPart = PMTimerFreq;
}

ULONGLONG
__cdecl
HalpQueryPerformanceCounter(VOID)
{
    LARGE_INTEGER TimeValue;
    LARGE_INTEGER PerfCounter;
    ULONG CurrentTime;
    ULONG ValueExt;

    do
    {
        YieldProcessor();
    }
    while (TimerInfo.AcpiTimeValue.HighPart != TimerInfo.TimerCarry);

    CurrentTime = READ_PORT_ULONG(TimerInfo.TimerPort);

    TimeValue = TimerInfo.AcpiTimeValue;
    ValueExt = TimerInfo.ValueExt;

    PerfCounter.HighPart = TimeValue.HighPart;
    PerfCounter.LowPart = ((CurrentTime & (~ValueExt)) | (TimeValue.LowPart & (~(ValueExt - 1))));

    PerfCounter.QuadPart += ((CurrentTime ^ TimeValue.LowPart) & ValueExt);

    return PerfCounter.QuadPart;
}

VOID
NTAPI
HalpStallExecutionProcessor(
    _In_ ULONG MicroSeconds)
{
    ULONG64 StartTime;
    ULONG64 EndTime;

    /* Get the initial time */
    StartTime = __rdtsc();

    /* Calculate the ending time */
    EndTime = (StartTime + (KeGetPcr()->StallScaleFactor * MicroSeconds));

    /* Loop until time is elapsed */
    while (__rdtsc() < EndTime)
        ;
}

VOID
NTAPI 
KeStallExecutionProcessor(
    _In_ ULONG MicroSeconds)
{
  #ifdef __REACTOS__
    if (TimerInfo.TimerPort)
        TimerStallExecProc(MicroSeconds);
    else
        HalpStallExecutionProcessor(MicroSeconds);
  #else
        TimerStallExecProc(MicroSeconds);
  #endif
}
VOID
NTAPI
HalpPmTimerStallExecProc(
    _In_ ULONG MicroSeconds)
{
    INT CpuInfo[4];
    ULONGLONG StartTick;
    ULONG StallTicks;
    LARGE_INTEGER TickCount;
    LARGE_INTEGER Next;
    ULONG TotalStall;
    ULONG StallCounter;

    //DPRINT1("HalpPmTimerStallExecProc: MicroSeconds %X\n", MicroSeconds);

    if (!MicroSeconds)
        goto Exit;

    /* Serializing instruction execution */
    __cpuid(CpuInfo, 0);

    /* Calculate the number of ticks for a given delay */
    StallTicks = ((PMTimerFreq * (ULONGLONG)MicroSeconds) / 1000000 - 1);

    /* Reading the starting value of ticks */
    StartTick = QueryTimer();

    TotalStall = 0;
    StallCounter = StallLoopValue;

    while (TRUE)
    {
        /* Do one microsecond stall */
        while (TRUE)
        {
           /* Do pause */
           PmPause(&TotalStall, StallCounter);

            /* How much time has passed? */
            TickCount.QuadPart = (QueryTimer() - StartTick);

            if (TickCount.HighPart)
                /* If the time delay is too long (due the debugger) */
                TickCount.LowPart = 0x7FFFFFFF;

            if (TickCount.LowPart >= 3)
                /* 1 MicroSeconds == ~3,579545 ticks of timer */
                break;

            /* Calculating the counter value for the next iteration */
            StallLoopValue += HAL_STALL_LOOP;
            StallCounter = StallLoopValue;
        }

        if (!TickCount.LowPart)
        {
            DPRINT1("KeBugCheckEx: ACPI_BIOS_ERROR()\n");
            KeBugCheckEx(ACPI_BIOS_ERROR, 0x20000, TickCount.HighPart, 0, 0);
        }

        if (TickCount.LowPart >= StallTicks)
            break;

        /* Calculating the counter value for the next iteration */
        Next.LowPart = ((StallTicks - TickCount.LowPart) * TotalStall);
        Next.HighPart = (((ULONGLONG)(StallTicks - TickCount.LowPart) * TotalStall) >> 32);
        Next.HighPart &= 3;

        StallCounter = ((ULONGLONG)Next.QuadPart / TickCount.LowPart + 1);
    }

Exit:

    StallExecCounter++;
    //HalpStallExecCounter++; // For statistics?

    if (!StallExecCounter && (StallLoopValue > HAL_STALL_LOOP))
        /* Every 256 calls this function, we decrease the value */
        StallLoopValue -= HAL_STALL_LOOP;
}

VOID
NTAPI 
HalCalibratePerformanceCounter(
    _In_ volatile PLONG Count,
    _In_ ULONGLONG NewCount)
{
    TimerCalibratePerfCount(Count, NewCount);
}
VOID
NTAPI
HalpPmTimerCalibratePerfCount(
    _In_ volatile PLONG Count,
    _In_ ULONGLONG NewCount)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
}

LARGE_INTEGER
NTAPI 
KeQueryPerformanceCounter(
    _Out_opt_ LARGE_INTEGER* OutPerfFrequency)
{
    return TimerQueryPerfCount(OutPerfFrequency);
}
LARGE_INTEGER
NTAPI
HalpPmTimerQueryPerfCount(
    _Out_opt_ LARGE_INTEGER* OutPerfFrequency)
{
    LARGE_INTEGER PerfCount;
    HaliPmTimerQueryPerfCount(&PerfCount, OutPerfFrequency);
    return PerfCount;
}

ULONG
NTAPI 
HalSetTimeIncrement(
    _In_ ULONG Increment)
{
    return TimerSetTimeIncrement(Increment);
}
ULONG
NTAPI
HalpPmTimerSetTimeIncrement(
    _In_ ULONG Increment)
{
    ULONG Result;
    UNIMPLEMENTED;
    ASSERT(FALSE);Result = 0;
    return Result;
}
/* EOF */
