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

/* PRIVATE FUNCTIONS *********************************************************/

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
