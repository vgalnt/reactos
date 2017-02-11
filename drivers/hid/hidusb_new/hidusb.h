#pragma once

#define _HIDPI_
#define _HIDPI_NO_FUNCTION_MACROS_
#define NDEBUG
#include <ntddk.h>
#include <hidport.h>
#include <debug.h>
#include <hubbusif.h>
#include <usbbusif.h>
#include <usbioctl.h>
#include <usb.h>
#include <usbdlib.h>

#include <hidport.h>

#define HIDUSB_STATE_STARTING 1
#define HIDUSB_STATE_RUNNING  2
#define HIDUSB_STATE_STOPPING 3
#define HIDUSB_STATE_STOPPED  4
#define HIDUSB_STATE_REMOVED  5
#define HIDUSB_STATE_FAILED   6

typedef struct
{
    //
    // event for completion
    //
    KEVENT Event;

    //
    // device descriptor
    //
    PUSB_DEVICE_DESCRIPTOR DeviceDescriptor;

    //
    // configuration descriptor
    //
    PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor;

    //
    // interface information
    //
    PUSBD_INTERFACE_INFORMATION InterfaceInfo;

    //
    // configuration handle
    //
    USBD_CONFIGURATION_HANDLE ConfigurationHandle;

    //
    // hid descriptor
    //
    PHID_DESCRIPTOR HidDescriptor;

    /* current state for device */
    ULONG HidState;
    /* current num pending requests */
    LONG RequestCount;
} HID_USB_DEVICE_EXTENSION, *PHID_USB_DEVICE_EXTENSION;

typedef struct
{
    //
    // request irp
    //
    PIRP Irp;

    //
    // work item
    //
    PIO_WORKITEM WorkItem;

    //
    // device object
    //
    PDEVICE_OBJECT DeviceObject;

} HID_USB_RESET_CONTEXT, *PHID_USB_RESET_CONTEXT;


NTSTATUS
Hid_GetDescriptor(
    IN PDEVICE_OBJECT DeviceObject,
    IN USHORT UrbFunction,
    IN USHORT UrbLength,
    IN OUT PVOID *UrbBuffer,
    IN OUT PULONG UrbBufferLength,
    IN UCHAR DescriptorType,
    IN UCHAR Index,
    IN USHORT LanguageIndex);

NTSTATUS
Hid_DispatchUrb(
    IN PDEVICE_OBJECT DeviceObject,
    IN PURB Urb);

#define USB_SET_IDLE_REQUEST 0xA
#define USB_GET_PROTOCOL_REQUEST 0x3

#define HIDUSB_TAG 'UdiH'
#define HIDUSB_URB_TAG 'rUiH'
