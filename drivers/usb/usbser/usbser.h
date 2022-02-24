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

#define USBSER_MAX_SLOT 256
#define USBSER_TAG 'CBSU'

typedef struct _USBSER_DEVICE_EXTENSION
{
    PDEVICE_OBJECT PhysicalDevice;
    PDEVICE_OBJECT LowerDevice;
    UNICODE_STRING DeviceName;
    ULONG DeviceIndex;
    KSPIN_LOCK SpinLock;
    PUSB_DEVICE_DESCRIPTOR DeviceDescriptor;

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
