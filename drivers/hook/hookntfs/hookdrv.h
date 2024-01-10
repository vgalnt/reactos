/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Header file for common bus driver.
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

#ifndef HOOKDRV_H
#define HOOKDRV_H

#include <string.h>
#include <ntddk.h>
#include <initguid.h>
#include <ntstrsafe.h>
#include <hooklib.h> // sdk/lib/drivers/hooklib/hooklib.h

#define HOOKDRV_POOL_TAG (ULONG) 'rDkH'

typedef struct _COMMON_DEVICE_EXTENSION
{
    PDEVICE_OBJECT SelfDevice;
    BOOLEAN IsFdo;
    UCHAR Pad0[3];
} COMMON_DEVICE_EXTENSION, *PCOMMON_DEVICE_EXTENSION;

typedef struct _FDO_DEVICE_EXTENSION
{
    COMMON_DEVICE_EXTENSION;
    PDEVICE_OBJECT LowerPdo;
    PDEVICE_OBJECT LowerDevice;
    ULONG PdoCount;
    FAST_MUTEX Lock;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

/* FUNCTIONS *****************************************************************/

  #if _X86_
NTSTATUS
NTAPI
HookMain(
   _In_ PUNICODE_STRING RegistryPath
);
  #else
#error FIXME!
  #endif

#endif

/* EOF */
