/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver serial functions.
 * COPYRIGHT:   Copyright 2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES ******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

UCHAR StopBits[3] = {STOP_BIT_1, STOP_BITS_1_5, STOP_BITS_2};
UCHAR ParityType[5] = {NO_PARITY, ODD_PARITY, EVEN_PARITY, MARK_PARITY, SPACE_PARITY};

/* GLOBALS ********************************************************************/

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
GetLineControlAndBaud(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    USBSER_CDC_LINE_CODING LineData;
    ULONG Length;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("GetLineControlAndBaud: DeviceObject %p\n", DeviceObject);

    Extension = DeviceObject->DeviceExtension;
    Length = sizeof(LineData);

    Status = ClassVendorCommand(DeviceObject,
                                USB_CDC_GET_LINE_CODING,
                                0,
                                Extension->InterfaceNumber,
                                &LineData,
                                &Length,
                                USBD_TRANSFER_DIRECTION_IN,
                                TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("GetLineControlAndBaud: Status %X\n", Status);
        return Status;
    }

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    Extension->BaudRate.BaudRate = LineData.BaudRate;

    Extension->LineControl.StopBits = StopBits[LineData.StopBits];
    Extension->LineControl.Parity = ParityType[LineData.ParityType];
    Extension->LineControl.WordLength = LineData.DataBits;

    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return Status;
}

NTSTATUS
NTAPI
SetLineControlAndBaud(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    USBSER_CDC_LINE_CODING LineData;
    ULONG Length;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("SetLineControlAndBaud: DeviceObject %p\n", DeviceObject);

    Extension = DeviceObject->DeviceExtension;
    Length = sizeof(USBSER_CDC_LINE_CODING);

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    LineData.BaudRate = Extension->BaudRate.BaudRate;
    LineData.DataBits = Extension->LineControl.WordLength;

    switch (Extension->LineControl.StopBits)
    {
        case 0:
            LineData.StopBits = STOP_BIT_1;
            break;

        case 1:
            LineData.StopBits = STOP_BITS_1_5;
            break;

        case 2:
            LineData.StopBits = STOP_BITS_2;
            break;

        default:
            DPRINT1("SetLineControlAndBaud: Extension->LineControl.StopBits %p\n", Extension->LineControl.StopBits);
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    switch (Extension->LineControl.Parity)
    {
        case 0:
            LineData.ParityType = NO_PARITY;
            break;

        case 1:
            LineData.ParityType = ODD_PARITY;
            break;

        case 2:
            LineData.ParityType = EVEN_PARITY;
            break;

        case 3:
            LineData.ParityType = MARK_PARITY;
            break;

        case 4:
            LineData.ParityType = SPACE_PARITY;
            break;

        default:
            DPRINT1("SetLineControlAndBaud: Extension->LineControl.Parity %p\n", Extension->LineControl.Parity);
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    if (NT_SUCCESS(Status))
    {
        Status = ClassVendorCommand(DeviceObject,
                                    USB_CDC_SET_LINE_CODING,
                                    0,
                                    Extension->InterfaceNumber,
                                    &LineData,
                                    &Length,
                                    USBD_TRANSFER_DIRECTION_OUT,
                                    TRUE);
    }

    GetLineControlAndBaud(DeviceObject);

    return Status;
}

NTSTATUS
NTAPI
SetClrDtr(IN PDEVICE_OBJECT DeviceObject,
          IN BOOLEAN SetOrClear)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    USBSER_CONTROL_LINE_STATE ControlSignal;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("SetClrDtr: DeviceObject %p, SetOrClear %d\n", DeviceObject, SetOrClear);
    PAGED_CODE();

    ControlSignal.AsUSHORT = 0;

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);

    if (Extension->LineState & SERIAL_RTS_STATE)
    {
        ControlSignal.CarrierControl = 1;
    }

    if (SetOrClear)
    {
        Extension->LineState |= SERIAL_DTR_STATE;
        ControlSignal.DtePresent |= 1;
    }
    else
    {
        Extension->LineState &= ~SERIAL_DTR_STATE;
    }

    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    Status = ClassVendorCommand(DeviceObject,
                                USB_CDC_SET_CONTROL_LINE_STATE,
                                ControlSignal.AsUSHORT,
                                Extension->InterfaceNumber,
                                NULL,
                                NULL,
                                USBD_TRANSFER_DIRECTION_OUT,
                                TRUE);
    if (!NT_SUCCESS(Status))
    {
        KeAcquireSpinLock(&Extension->SpinLock, &Irql);
        Extension->LineState &= ~SERIAL_DTR_STATE;
        KeReleaseSpinLock(&Extension->SpinLock, Irql);
    }

    return Status;
}

NTSTATUS
NTAPI
ClrRts(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    KIRQL Irql;

    DPRINT("ClrRts: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    Extension->LineState &= ~SERIAL_RTS_STATE;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SetRts(IN PDEVICE_OBJECT DeviceObject)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    KIRQL Irql;

    DPRINT("SetRts: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;

    KeAcquireSpinLock(&Extension->SpinLock, &Irql);
    Extension->LineState |= SERIAL_RTS_STATE;
    KeReleaseSpinLock(&Extension->SpinLock, Irql);

    return STATUS_SUCCESS;
}

/* EOF */
