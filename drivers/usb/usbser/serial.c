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

/* EOF */
