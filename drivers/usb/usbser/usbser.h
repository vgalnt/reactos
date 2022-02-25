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

#define USBSER_MAX_SLOT 256
#define USBSER_TAG 'CBSU'

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
    ULONG DeviceIndex;
    KSPIN_LOCK SpinLock;
    PUSB_DEVICE_DESCRIPTOR DeviceDescriptor;
    USBD_CONFIGURATION_HANDLE ConfigurationHandle;
    USBD_PIPE_HANDLE DataInPipeHandle;
    USBD_PIPE_HANDLE DataOutPipeHandle;
    USBD_PIPE_HANDLE NotifyPipeHandle;
    UCHAR InterfaceNumber;

} USBSER_DEVICE_EXTENSION, *PUSBSER_DEVICE_EXTENSION;


/* ioctl.c */

/* pnp.c */

NTSTATUS
NTAPI
UsbSerPnP(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

/* power.c */

/* serial.c */

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
    IN BOOLEAN Function
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

/* usbser.c */

/* utils.c */

NTSTATUS
NTAPI
UsbSerSyncCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
);

/* wmi.c */

#endif // _USBSTOR_H_
