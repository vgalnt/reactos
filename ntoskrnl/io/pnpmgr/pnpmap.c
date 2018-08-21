/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpreport.c
 * PURPOSE:         PNP Mapper Functions
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/* TYPES *******************************************************************/

typedef struct _PNP_MAPPER_DEVICE_ID
{ 
    PWCHAR TypeName;
    PWCHAR PnPId;
} PNP_MAPPER_DEVICE_ID, *PPNP_MAPPER_DEVICE_ID; 

typedef struct _PNP_MAPPER_INFORMATION
{ 
    struct _PNP_MAPPER_INFORMATION * NextInfo;
    INTERFACE_TYPE BusType;
    ULONG BusNumber;
    CONFIGURATION_TYPE ControllerType;
    ULONG ControllerNumber;
    CONFIGURATION_TYPE PeripheralType;
    ULONG PeripheralNumber;
    ULONG CmFullDescriptorSize;
    PVOID CmFullDescriptor;
    ULONG IdentifierSize;
    ULONG IdentifierType;
    PVOID Identifier;
    PWCHAR PnPId;
    BOOLEAN IsCreatedNewKey;
    UCHAR Padded[3];
} PNP_MAPPER_INFORMATION, *PPNP_MAPPER_INFORMATION; 

typedef struct _PNP_MAPPER_DEVICE_EXTENSION
{ 
    PPNP_MAPPER_INFORMATION  MapperInfo;
} PNP_MAPPER_DEVICE_EXTENSION, *PPNP_MAPPER_DEVICE_EXTENSION; 

/* DATA **********************************************************************/

PNP_MAPPER_DEVICE_EXTENSION MapperDeviceExtension;

static
CONFIGURATION_TYPE TypeArray[] =
{
    PointerController,
    KeyboardController,
    ParallelController,
    DiskController,
    FloppyDiskPeripheral,
    SerialController // shoul be last !
};

static
PNP_MAPPER_DEVICE_ID PointerMap[] =
{
    { L"PS2 MOUSE", L"*PNP0F0E" },
    { L"SERIAL MOUSE", L"*PNP0F0C" },
    { L"MICROSOFT PS2 MOUSE", L"*PNP0F03" },
    { L"LOGITECH PS2 MOUSE", L"*PNP0F12" },
    { L"MICROSOFT INPORT MOUSE", L"*PNP0F02" },
    { L"MICROSOFT SERIAL MOUSE", L"*PNP0F01" },
    { L"MICROSOFT BALLPOINT SERIAL MOUSE", L"*PNP0F09" },
    { L"LOGITECH SERIAL MOUSE", L"*PNP0F08" },
    { L"MICROSOFT BUS MOUSE", L"*PNP0F00" },
    { L"NEC PC-9800 BUS MOUSE", L"*nEC1F00" },
    { NULL, NULL }
};

static
PNP_MAPPER_DEVICE_ID KeyboardMap[] =
{
    { L"XT_83KEY", L"*PNP0300" },
    { L"PCAT_86KEY", L"*PNP0301" },
    { L"PCXT_84KEY", L"*PNP0302" },
    { L"XT_84KEY", L"*PNP0302" },
    { L"101-KEY", L"*PNP0303" },
    { L"OLI_83KEY", L"*PNP0304" },
    { L"ATT_301", L"*PNP0304" },
    { L"OLI_102KEY", L"*PNP0305" },
    { L"OLI_86KEY", L"*PNP0306" },
    { L"OLI_A101_102KEY", L"*PNP0309" },
    { L"ATT_302", L"*PNP030a" },
    { L"PCAT_ENHANCED", L"*PNP030b" },
    { L"PC98_106KEY", L"*nEC1300" },
    { L"PC98_LaptopKEY", L"*nEC1300" },
    { L"PC98_N106KEY", L"*PNP0303" },
    { NULL, NULL }
};

/* PRIVATE FUNCTIONS *********************************************************/

PWSTR
NTAPI
MapperTranslatePnPId(
    _In_ CONFIGURATION_TYPE ControllerType,
    _In_ PKEY_VALUE_FULL_INFORMATION PeripheralValueInfo)
{
    PPNP_MAPPER_DEVICE_ID KeyboardId;
    PPNP_MAPPER_DEVICE_ID PointerId;
    PWCHAR Identifier = NULL;

    if (PeripheralValueInfo)
    {
        Identifier = (PWCHAR)((ULONG_PTR)PeripheralValueInfo +
                              PeripheralValueInfo->DataOffset);

        DPRINT("MapperTranslatePnPId: Identifier - %S\n", Identifier);
    }

    switch (ControllerType)
    {
        case DiskController:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "DiskController", DiskController, "*PNP0700");
            return L"*PNP0700";

        case SerialController:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "SerialController", SerialController, "*PNP0501");
            return L"*PNP0501";

        case ParallelController:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "ParallelController", ParallelController, "*PNP0400");
            return L"*PNP0400";

        case PointerController:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "PointerController", PointerController, "*PNP0F0E");
            return L"*PNP0F0E";

        case KeyboardController:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "KeyboardController", KeyboardController, "*PNP0300");
            return L"*PNP0300";

        case DiskPeripheral:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "DiskPeripheral", DiskPeripheral, "NULL");
            return NULL;

        case FloppyDiskPeripheral:
            DPRINT("MapperTranslatePnPId: %s (%d) - %s\n",
                   "FloppyDiskPeripheral", FloppyDiskPeripheral, "*PNP0700");
            return L"*PNP0700";

        case PointerPeripheral:
            if (!Identifier)
            {
                DPRINT("MapperTranslatePnPId: Identifier == NULL\n");
                return NULL;
            }

            PointerId = MapperFindIdentMatch(PointerMap, Identifier);

            if (!PointerId)
            {
                DPRINT("MapperTranslatePnPId: No PointerId for %S\n",
                       Identifier);
                return NULL;
            }

            DPRINT("MapperTranslatePnPId: PointerId->PnPId - %S\n",
                   PointerId->PnPId);
            return PointerId->PnPId;

        case KeyboardPeripheral:
            if (!Identifier)
            {
                DPRINT("MapperTranslatePnPId: Identifier == NULL\n");
                return NULL;
            }

            KeyboardId = MapperFindIdentMatch(KeyboardMap, Identifier);

            if (!KeyboardId)
            {
                DPRINT("MapperTranslatePnPId: No KeyboardId for %S\n",
                       Identifier);
                return NULL;
            }

            DPRINT("MapperTranslatePnPId: KeyboardId->PnPId - %S\n",
                   KeyboardId->PnPId);
            return KeyboardId->PnPId;

        default:
            DPRINT("MapperTranslatePnPId: Unknown ControllerType - %X\n",
                   ControllerType);
            return NULL;
    }
}

NTSTATUS
NTAPI
MapperPeripheralCallback(
    _In_ PVOID Context,
    _In_ PUNICODE_STRING PathName,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * BusInformation,
    _In_ CONFIGURATION_TYPE ControllerType,
    _In_ ULONG ControllerNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * ControllerInformation,
    _In_ CONFIGURATION_TYPE PeripheralType,
    _In_ ULONG PeripheralNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * PeripheralInformation)
{
    PPNP_MAPPER_INFORMATION MapperInfo = Context;
    PKEY_VALUE_FULL_INFORMATION IdentInfo;
    SIZE_T IdentInfoLength;
    PWCHAR Identifier;

    DPRINT("MapperPeripheralCallback: PathName - %S\n", PathName->Buffer);

    if (!ControllerInformation)
    {
        DPRINT("MapperPeripheralCallback: ControllerInformation == NULL\n");
    }

    if (!PeripheralInformation)
    {
        DPRINT("MapperPeripheralCallback: PeripheralInformation == NULL\n");
        return STATUS_SUCCESS;
    }

    IdentInfo = PeripheralInformation[0];

    if (!IdentInfo)
    {
        DPRINT("MapperPeripheralCallback: IdentInfo == NULL\n");
        goto Exit;
    }

    MapperInfo->PnPId = MapperTranslatePnPId(PeripheralType,
                                             PeripheralInformation[0]);
    if (!MapperInfo->PnPId)
    {
        DPRINT("MapperPeripheralCallback: MapperInfo->PnPId == NULL\n");
        goto Exit;
    }

    IdentInfoLength = IdentInfo->DataLength;

    if (IdentInfoLength <= sizeof(WCHAR) || IdentInfo->Type != REG_SZ)
    {
        DPRINT("MapperPeripheralCallback: IdentInfoLength - %S, IdentInfo->Type - %X\n",
               IdentInfoLength, IdentInfo->Type);
        goto Exit;
    }

    Identifier = (PWCHAR)((ULONG_PTR)IdentInfo + IdentInfo->DataOffset);

    if (*Identifier == UNICODE_NULL)
    {
        DPRINT("MapperPeripheralCallback: *IdentInfo == NULL\n");
        goto Exit;
    }

    if (MapperInfo->Identifier)
    {
        ExFreePoolWithTag(MapperInfo->Identifier, 'rpaM');
    }

    MapperInfo->Identifier = ExAllocatePoolWithTag(NonPagedPool,
                                                   IdentInfoLength,
                                                   'rpaM');
    if (!Identifier)
    {
        DPRINT1("MapperPeripheralCallback: STATUS_INSUFFICIENT_RESOURCES\n");
        goto Exit;
    }

    MapperInfo->IdentifierType = IdentInfo->Type;
    MapperInfo->IdentifierSize = IdentInfoLength;

    RtlCopyMemory(MapperInfo->Identifier, Identifier, IdentInfoLength);

Exit:

    MapperInfo->PeripheralType = PeripheralType;
    MapperInfo->PeripheralNumber = PeripheralNumber;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MapperCallback(
    _In_ PVOID Context,
    _In_ PUNICODE_STRING PathName,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * BusInformation,
    _In_ CONFIGURATION_TYPE ControllerType,
    _In_ ULONG ControllerNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * ControllerInformation,
    _In_ CONFIGURATION_TYPE PeripheralType,
    _In_ ULONG PeripheralNumber,
    _In_ PKEY_VALUE_FULL_INFORMATION * PeripheralInformation)
{
    PPNP_MAPPER_DEVICE_EXTENSION MapperContext = Context;
    PKEY_VALUE_FULL_INFORMATION DataInfo;
    PKEY_VALUE_FULL_INFORMATION IdentInfo;
    PPNP_MAPPER_INFORMATION MapperInfo;
    CONFIGURATION_TYPE peripheralType;
    PCM_FULL_RESOURCE_DESCRIPTOR CmFullDescriptor;
    PCM_FULL_RESOURCE_DESCRIPTOR cmFullDescriptor;
    PWCHAR Identifier;
    SIZE_T DataInfoLength;
    SIZE_T IdentInfoLength;

    DPRINT("MapperCallback: PathName - %wZ, ControllerType - %X\n",
           PathName, ControllerType);

    DataInfo = ControllerInformation[1];
    if (!DataInfo)
    {
        DPRINT("MapperCallback: DataInfo == NULL\n");
        return STATUS_SUCCESS;
    }

    DataInfoLength = DataInfo->DataLength;
    if (!DataInfoLength)
    {
        DPRINT("MapperCallback: DataInfoLength == 0\n");
        return STATUS_SUCCESS;
    }

    MapperInfo = ExAllocatePoolWithTag(NonPagedPool,
                                       sizeof(PNP_MAPPER_INFORMATION),
                                       'rpaM');
    if (!MapperInfo)
    {
        DPRINT1("MapperCallback: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(MapperInfo, sizeof(PNP_MAPPER_INFORMATION));

    MapperInfo->ControllerType = ControllerType;
    MapperInfo->ControllerNumber = ControllerNumber;

    MapperInfo->BusNumber = BusNumber;
    MapperInfo->BusType = BusType;

    CmFullDescriptor = ExAllocatePoolWithTag(NonPagedPool,
                                             DataInfoLength,
                                             'rpaM');
    if (!CmFullDescriptor)
    {
        DPRINT1("MapperCallback: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(MapperInfo, 'rpaM');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cmFullDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)
                       ((ULONG_PTR)DataInfo + DataInfo->DataOffset);

    RtlCopyMemory(CmFullDescriptor, cmFullDescriptor, DataInfoLength);

    MapperInfo->CmFullDescriptor = CmFullDescriptor;
    MapperInfo->CmFullDescriptorSize = DataInfoLength;

    IdentInfo = ControllerInformation[0];

    if (IdentInfo)
    {
        IdentInfoLength = IdentInfo->DataLength;

        if (IdentInfoLength)
        {
            Identifier = (PWCHAR)((ULONG_PTR)IdentInfo + IdentInfo->DataOffset);

            if (ControllerType == ParallelController)
            {
                DPRINT("MapperCallback: FIXME ControllerType - ParallelController\n");
                ASSERT(FALSE);
            }
            else
            {
                if (IdentInfoLength)
                {
                    MapperInfo->Identifier = ExAllocatePoolWithTag(NonPagedPool,
                                                                   IdentInfoLength,
                                                                   'rpaM');
                    if (MapperInfo->Identifier)
                    {
                        MapperInfo->IdentifierType = IdentInfo->Type;
                        MapperInfo->IdentifierSize = IdentInfoLength;

                        RtlCopyMemory(MapperInfo->Identifier,
                                      Identifier,
                                      IdentInfoLength);
                    }
                    else
                    {
                        DPRINT1("MapperCallback: STATUS_INSUFFICIENT_RESOURCES\n");
                    }
                }
            }
        }
    }

    switch (ControllerType)
    {
        case DiskController:
            peripheralType = FloppyDiskPeripheral;
            break;

        case SerialController:
        case ParallelController:
            peripheralType = ArcSystem;
            break;

        case PointerController:
            peripheralType = PointerPeripheral;
            break;

        case KeyboardController:
            peripheralType = KeyboardPeripheral;
            break;

        default:
            peripheralType = ArcSystem;
            break;
    }

    DPRINT("MapperCallback: PathName - %S, Ident[0] - %X, Data[1] - %X, Information[2] - %X\n",
           PathName->Buffer,
           ControllerInformation[0],
           ControllerInformation[1],
           ControllerInformation[2]);

    if (peripheralType != ArcSystem)
    {
        DPRINT("MapperCallback: peripheralType - %d\n", peripheralType);

        IoQueryDeviceDescription(&BusType,
                                 &BusNumber,
                                 &ControllerType,
                                 &ControllerNumber,
                                 &peripheralType,
                                 0,
                                 MapperPeripheralCallback,
                                 MapperInfo);
    }

    if (!MapperInfo->PnPId && !MapperInfo->PeripheralType)
    {
        MapperInfo->PnPId = MapperTranslatePnPId(ControllerType, NULL);

        if (!MapperInfo->PnPId)
        {
            DPRINT("MapperCallback: No PnPId for %S !\n", PathName->Buffer);
        }
    }

    DPRINT("MapperCallback: Constructed name - %d_%d_%d_%d_%d_%d\n",
           MapperInfo->BusType,
           MapperInfo->BusNumber,
           MapperInfo->ControllerType,
           MapperInfo->ControllerNumber,
           MapperInfo->PeripheralType,
           MapperInfo->PeripheralNumber);

    if (MapperInfo->PnPId)
    {
        MapperInfo->NextInfo = MapperContext->MapperInfo;
        MapperContext->MapperInfo = MapperInfo;
    }
    else
    {
        ExFreePoolWithTag(CmFullDescriptor, 'rpaM');

        if (MapperInfo->Identifier)
        {
            ExFreePoolWithTag(MapperInfo->Identifier, 'rpaM');
        }

        ExFreePoolWithTag(MapperInfo, 'rpaM');
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MapperProcessFirmwareTree(
    _In_ BOOLEAN IsDisableMapper)
{
    CONFIGURATION_TYPE ControllerType;
    INTERFACE_TYPE Interface;
    ULONG Index;
    ULONG ArraySize; 
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MapperProcessFirmwareTree: IsDisableMapper - %X\n", IsDisableMapper);

    ArraySize = *(&TypeArray + 1) - TypeArray;

    for (Interface = Internal;
         Interface < MaximumInterfaceType;
         Interface++)
    {
        if (IsDisableMapper)
        {
            /* Only SerialController */
            Index = ArraySize - 1;
        }
        else
        {
            Index = 0;
        }

        for (; Index < ArraySize; Index++)
        {
            ControllerType = TypeArray[Index];

            Status = IoQueryDeviceDescription(&Interface,
                                              NULL,
                                              &ControllerType,
                                              NULL,
                                              NULL,
                                              NULL,
                                              MapperCallback,
                                              &MapperDeviceExtension);
        }
    }

    return Status;
}

/* EOF */
