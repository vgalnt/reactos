/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver declarations.
 * COPYRIGHT:   2022 Vadim Galyant <vgal@rambler.ru>
 */

#ifndef _USBSER_H_
#define _USBSER_H_

#include <ntddk.h>
#include <stdio.h>
#include <ntstrsafe.h>
#include <usb.h>
#include <usbioctl.h>
#include <usbdlib.h>
#include <ntddser.h>
#include <wmilib.h>
#include <wmidata.h>

#define USBSER_MAX_SYMBOLIC_NAME_LENGTH 128
#define USBSER_MAX_DOS_NAME_LENGTH 32
#define USBSER_MAX_SLOT 256

#define USBSER_TAG 'CBSU'
#define USBD_TAG   'DBSU'

/* Universal Serial Bus Class Definitions for Communications Devices
   Revision 1.2, November 3, 2010 (CDC120)
*/
/* Universal Serial Bus Communications Class Subclass Specification for PSTN Devices
   Revision 1.2, February 9, 2007 (PSTN120)
*/

/* (CDC120) "6 Communications Class Specific Messages"
   (PSTN120) "6.3 PSTN Subclass Specific Requests"
*/
#define USB_CDC_SET_LINE_CODING         0x20
#define USB_CDC_GET_LINE_CODING         0x21
#define USB_CDC_SET_CONTROL_LINE_STATE  0x22
#define USB_CDC_SEND_BREAK              0x23

#include <pshpack1.h>
typedef union _USBSER_CONTROL_LINE_STATE
{
    struct
    {
        USHORT DtePresent:1;     // Indicates to DCE if DTE is present or not. 0 - Not Present, 1 - Present
        USHORT CarrierControl:1; // Carrier control for half duplex modems. 0 - Deactivate carrier, 1 - Activate carrier.
        USHORT Reserved:14;
    };
    USHORT AsUSHORT;
} USBSER_CONTROL_LINE_STATE, *PUSBSER_CONTROL_LINE_STATE;

typedef union _USBSER_SERIAL_STATE
{
    struct
    {
        USHORT RxCarrier:1;  // State of receiver carrier detection mechanism of device. This corresponds to V.24 signal 109 and RS-232 signal DCD. 
        USHORT TxCarrier:1;  // State of transmission carrier. This signal corresponds to V.24 RS-232 signal DSR. 
        USHORT Break:1;      // State of break detection mechanism of the device. 
        USHORT RingSignal:1; // State of ring signal detection of the device. 
        USHORT Framing:1;    // A framing error has occurred. 
        USHORT Parity:1;     // A parity error has occurred. 
        USHORT OverRun:1;    // Received data has been discarded due to overrun in the device
        USHORT Reserved:9;
    };
    USHORT AsUSHORT;
} USBSER_SERIAL_STATE, *PUSBSER_SERIAL_STATE;

typedef struct _USBSER_CDC_NOTIFICATION
{
    UCHAR RequestType;
    UCHAR NotificationType;
    USHORT Value;
    USHORT Index;
    USHORT Length;
    USBSER_SERIAL_STATE SerialState;
} USBSER_CDC_NOTIFICATION, *PUSBSER_CDC_NOTIFICATION;

typedef struct _USBSER_CDC_LINE_CODING
{
    ULONG BaudRate;   // Data terminal rate, in bits per second
    UCHAR StopBits;
    UCHAR ParityType;
    UCHAR DataBits;   // Data bits (5, 6, 7, 8 or 16)
} USBSER_CDC_LINE_CODING, *PUSBSER_CDC_LINE_CODING;
#include <poppack.h>
C_ASSERT(sizeof(USBSER_CDC_NOTIFICATION) == 0xA);
C_ASSERT(sizeof(USBSER_CDC_LINE_CODING) == 0x7);

typedef struct _USBSER_DEVICE_EXTENSION
{
    PDEVICE_OBJECT PhysicalDevice;
    PDEVICE_OBJECT LowerDevice;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymLinkName;
    UNICODE_STRING DosName;
    ULONG DeviceIndex;
    KSPIN_LOCK SpinLock;
    PUSB_DEVICE_DESCRIPTOR DeviceDescriptor;
    USBD_CONFIGURATION_HANDLE ConfigurationHandle;
    USBD_PIPE_HANDLE DataInPipeHandle;
    USBD_PIPE_HANDLE DataOutPipeHandle;
    USBD_PIPE_HANDLE NotifyPipeHandle;
    KEVENT EventDataIn;
    KEVENT EventDataOut;
    KEVENT EventNotify;
    KEVENT EventFlush;
    LONG DataInCount;
    LONG DataOutCount;
    LONG NotifyCount;
    PVOID NotifyBuffer;
    PVOID ReadBuffer;
    ULONG CharsInReadBuffer;
    ULONG ReadBufferOffset;
    ULONG ReadingState;
    PVOID RxBuffer;
    USHORT RxBufferSize;
    USHORT ModemStatus;
    UCHAR InterfaceNumber;
    BOOLEAN IsSymLinkCreated;
    BOOLEAN DeviceIsRunning;
    BOOLEAN ReadingIsOn;
    BOOLEAN IsWaitWake;
    ULONG SupportedBauds;
    SERIAL_BAUD_RATE BaudRate;
    SERIAL_LINE_CONTROL LineControl;
    SERIAL_TIMEOUTS Timeouts;
    SERIAL_HANDFLOW HandFlow;
    SERIAL_CHARS Chars;
    SERIALPERF_STATS Stats;
    ULONG LineState;
    PIRP ReadIrp;
    PURB ReadUrb;
    PIRP NotifyIrp;
    PURB NotifyUrb;
    PIRP MaskIrp;
    ULONG HistoryMask;
    ULONG IsrWaitMask;
    ULONG ReadByIsr;
    SYSTEM_POWER_STATE SystemWake;
    DEVICE_POWER_STATE DeviceWake;
    PIRP WakeIrp;
    LONG OpenCount;
    DEVICE_POWER_STATE DevicePowerState;
    PIRP CurrentReadIrp;
    LIST_ENTRY ReadQueueList;
    ULONG ReadLength;
    LARGE_INTEGER IntervalTime;
    LARGE_INTEGER CutOverAmount;
    LARGE_INTEGER LastReadTime;
    KTIMER ReadRequestTotalTimer;
    KTIMER ReadRequestIntervalTimer;
    KTIMER WriteRequestTotalTimer;
    LARGE_INTEGER ShortIntervalAmount;
    LARGE_INTEGER LongIntervalAmount;
    PLARGE_INTEGER IntervalTimeToUse;
    KDPC ReadTimeoutDpc;
    KDPC IntervalReadTimeoutDpc;
    KDPC WriteTimeoutDpc;
    LONG CountOnLastRead;
    LONG TransmitCount;
    PIO_WORKITEM WorkItem;
    ULONG PnpState;
    WMILIB_CONTEXT WmiLibInfo;

} USBSER_DEVICE_EXTENSION, *PUSBSER_DEVICE_EXTENSION;

typedef struct _USBSER_WRITE_CONTEXT
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIRP Irp;
    KTIMER Timer;
    LARGE_INTEGER TimeOut;
    KDPC TimerDpc;
    NTSTATUS Status;
    struct _URB_BULK_OR_INTERRUPT_TRANSFER Urb;

} USBSER_WRITE_CONTEXT, *PUSBSER_WRITE_CONTEXT;

typedef NTSTATUS (NTAPI* PUSBSER_START_READ)(PUSBSER_DEVICE_EXTENSION Extension);
typedef VOID (NTAPI* PUSBSER_GET_NEXT_IRP)(PUSBSER_DEVICE_EXTENSION Extension, PIRP * CurrentOpIrp, PLIST_ENTRY QueueToProcess, PIRP * OutNextIrp, BOOLEAN CompleteCurrent);

/* ioctl.c */

NTSTATUS
NTAPI
UsbSerDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
);

VOID
NTAPI
UsbSerKillAllReadsOrWrites(
    IN PDEVICE_OBJECT DeviceObject,
    IN PLIST_ENTRY List,
    IN PIRP * pIrp
);

/* pnp.c */

NTSTATUS
NTAPI
UsbSerPnP(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

/* power.c */

/* serial.c */

NTSTATUS
NTAPI
GetLineControlAndBaud(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
SetLineControlAndBaud(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
SetClrDtr(
    IN PDEVICE_OBJECT DeviceObject,
    IN BOOLEAN SetOrClear
);

NTSTATUS
NTAPI
ClrRts(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
SetRts(
    IN PDEVICE_OBJECT DeviceObject
);

/* usb.c */

NTSTATUS
NTAPI
CallUSBD(
    IN PDEVICE_OBJECT DeviceObject,
    IN PURB Urb
);

NTSTATUS
NTAPI
ClassVendorCommand(
    IN PDEVICE_OBJECT DeviceObject,
    IN UCHAR Request,
    IN USHORT Value,
    IN USHORT Index,
    IN PVOID TransferBuffer,
    IN ULONG * OutLength,
    IN ULONG Direction,
    IN BOOLEAN IsClassFunction
);

NTSTATUS
NTAPI
GetDeviceDescriptor(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
ConfigureDevice(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
ResetDevice(
    IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
UsbSerAbortPipes(
    IN PDEVICE_OBJECT DeviceObject
);

/* usbser.c */

VOID
NTAPI
StartRead(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

VOID
NTAPI
RestartRead(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

VOID
NTAPI
StartNotifyRead(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

NTSTATUS
NTAPI
UsbSerStartRead(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

VOID
NTAPI
UsbSerGetNextIrp(
    IN PUSBSER_DEVICE_EXTENSION Extension,
    IN OUT PIRP * CurrentOpIrp,
    IN PLIST_ENTRY QueueToProcess,
    OUT PIRP * OutNextIrp,
    IN BOOLEAN CompleteCurrent
);

VOID
NTAPI
UsbSerGrabReadFromRx(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

VOID
NTAPI
UsbSerTryToCompleteCurrent(
    IN PUSBSER_DEVICE_EXTENSION Extension,
    IN KIRQL IrqlForRelease,
    IN NTSTATUS Status,
    IN PIRP * CurrentOpIrp,
    IN PLIST_ENTRY QueueToProcess,
    IN PKTIMER IntervalTimer,
    IN PKTIMER Timer,
    IN PUSBSER_START_READ Starter,
    IN PUSBSER_GET_NEXT_IRP GetNextIrp,
    IN LONG RefType,
    IN BOOLEAN CompleteCurrent
);

VOID
NTAPI
RestartNotifyRead(
    IN PUSBSER_DEVICE_EXTENSION Extension
);

/* utils.c */

NTSTATUS
NTAPI
UsbSerSyncCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
);

NTSTATUS
NTAPI
UsbSerGetRegistryKeyValue(
    IN HANDLE KeyHandle,
    IN PWSTR ValueString,
    IN ULONG ValueStringSize,
    OUT PWSTR OutKeyValue,
    IN ULONG MaxDataLength
);

VOID
NTAPI
UsbSerFetchBooleanLocked(
    OUT BOOLEAN * OutBoolean,
    IN BOOLEAN BooleanValue,
    IN PKSPIN_LOCK SpinLock
);

VOID
NTAPI
UsbSerFetchPVoidLocked(
    OUT PVOID * OutPVoid,
    IN PVOID PVoid,
    IN PKSPIN_LOCK SpinLock
);

VOID
NTAPI
UsbSerReadTimeout(
    IN PKDPC Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
);

VOID
NTAPI
UsbSerIntervalReadTimeout(
    IN PKDPC Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
);

VOID
NTAPI
UsbSerWriteTimeout(
    IN PKDPC Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
);

/* wmi.c */

NTSTATUS
NTAPI
UsbSerSetWmiDataItem(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP PIrp,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG DataItemId,
    IN ULONG BufferSize,
    IN PUCHAR PBuffer
);

NTSTATUS
NTAPI
UsbSerSetWmiDataBlock(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP PIrp,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG BufferSize,
    IN PUCHAR PBuffer
);

NTSTATUS
NTAPI
UsbSerQueryWmiDataBlock(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP PIrp,
    IN ULONG GuidIndex, 
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG OutBufferSize,
    OUT PUCHAR PBuffer
);

NTSTATUS
NTAPI
UsbSerQueryWmiRegInfo(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PULONG PRegFlags,
    OUT PUNICODE_STRING PInstanceName,
    OUT PUNICODE_STRING * PRegistryPath,
    OUT PUNICODE_STRING MofResourceName,
    OUT PDEVICE_OBJECT * Pdo
);

#endif // _USBSTOR_H_
