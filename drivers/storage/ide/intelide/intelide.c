/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include "intelide.h"

//#define NDEBUG
#include <debug.h>

NTSTATUS
NTAPI
PiixIdeGetControllerProperties(
    _In_ PVOID InDeviceExtension,
    _Out_ IDE_CONTROLLER_PROPERTIES* OutProperties)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    Status = PciIdeXInitialize(DriverObject,
                               RegistryPath,
                               PiixIdeGetControllerProperties,
                               sizeof(INTEL_CONTROLLER_EXTENSION));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
    }

    return Status;
}

/* EOF*/
