/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpinit.c
 * PURPOSE:         PnP Initialization Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

typedef struct _IOPNP_DEVICE_EXTENSION
{
    PWCHAR CompatibleIdList;
    ULONG CompatibleIdListSize;
} IOPNP_DEVICE_EXTENSION, *PIOPNP_DEVICE_EXTENSION;

PUNICODE_STRING PiInitGroupOrderTable;
USHORT PiInitGroupOrderTableCount;
INTERFACE_TYPE PnpDefaultInterfaceType;

KSPIN_LOCK IopPnPSpinLock;
LIST_ENTRY IopPnpEnumerationRequestList;
KEVENT PiEnumerationLock;

ERESOURCE PiEngineLock;
ERESOURCE PiDeviceTreeLock;

/* FUNCTIONS ******************************************************************/

INTERFACE_TYPE
NTAPI
IopDetermineDefaultInterfaceType(VOID)
{
    /* FIXME: ReactOS doesn't support MicroChannel yet */
    return Isa;
}

NTSTATUS
NTAPI
IopInitializeArbiters(VOID)
{
     /* FIXME: TODO */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
INIT_FUNCTION
PiInitCacheGroupInformation(VOID)
{
    HANDLE KeyHandle;
    NTSTATUS Status;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;
    PUNICODE_STRING GroupTable;
    ULONG Count;
    UNICODE_STRING GroupString =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet"
                            L"\\Control\\ServiceGroupOrder");

    /* Open the registry key */
    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  NULL,
                                  &GroupString,
                                  KEY_READ);
    if (NT_SUCCESS(Status))
    {
        /* Get the list */
        Status = IopGetRegistryValue(KeyHandle, L"List", &KeyValueInformation);
        ZwClose(KeyHandle);

        /* Make sure we got it */
        if (NT_SUCCESS(Status))
        {
            /* Make sure it's valid */
            if ((KeyValueInformation->Type == REG_MULTI_SZ) &&
                (KeyValueInformation->DataLength))
            {
                /* Convert it to unicode strings */
                Status = PnpRegMultiSzToUnicodeStrings(KeyValueInformation,
                                                       &GroupTable,
                                                       &Count);

                /* Cache it for later */
                PiInitGroupOrderTable = GroupTable;
                PiInitGroupOrderTableCount = (USHORT)Count;
            }
            else
            {
                /* Fail */
                Status = STATUS_UNSUCCESSFUL;
            }

            /* Free the information */
            ExFreePool(KeyValueInformation);
        }
    }

    /* Return status */
    return Status;
}

USHORT
NTAPI
PpInitGetGroupOrderIndex(IN HANDLE ServiceHandle)
{
    NTSTATUS Status;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;
    USHORT i;
    PVOID Buffer;
    UNICODE_STRING Group;
    PAGED_CODE();

    /* Make sure we have a cache */
    if (!PiInitGroupOrderTable) return -1;

    /* If we don't have a handle, the rest is easy -- return the count */
    if (!ServiceHandle) return PiInitGroupOrderTableCount + 1;

    /* Otherwise, get the group value */
    Status = IopGetRegistryValue(ServiceHandle, L"Group", &KeyValueInformation);
    if (!NT_SUCCESS(Status)) return PiInitGroupOrderTableCount;

    /* Make sure we have a valid string */
    ASSERT(KeyValueInformation->Type == REG_SZ);
    ASSERT(KeyValueInformation->DataLength);

    /* Convert to unicode string */
    Buffer = (PVOID)((ULONG_PTR)KeyValueInformation + KeyValueInformation->DataOffset);
    PnpRegSzToString(Buffer, KeyValueInformation->DataLength, &Group.Length);
    Group.MaximumLength = (USHORT)KeyValueInformation->DataLength;
    Group.Buffer = Buffer;

    /* Loop the groups */
    for (i = 0; i < PiInitGroupOrderTableCount; i++)
    {
        /* Try to find a match */
        if (RtlEqualUnicodeString(&Group, &PiInitGroupOrderTable[i], TRUE)) break;
    }

    /* We're done */
    ExFreePool(KeyValueInformation);
    return i;
}

USHORT
NTAPI
PipGetDriverTagPriority(IN HANDLE ServiceHandle)
{
    NTSTATUS Status;
    HANDLE KeyHandle = NULL;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation = NULL;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformationTag;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformationGroupOrderList;
    PVOID Buffer;
    UNICODE_STRING Group;
    PULONG GroupOrder;
    ULONG Count, Tag = 0;
    USHORT i = -1;
    UNICODE_STRING GroupString =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet"
                        L"\\Control\\ServiceGroupOrder");

    /* Open the key */
    Status = IopOpenRegistryKeyEx(&KeyHandle, NULL, &GroupString, KEY_READ);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Read the group */
    Status = IopGetRegistryValue(ServiceHandle, L"Group", &KeyValueInformation);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Make sure we have a group */
    if ((KeyValueInformation->Type == REG_SZ) &&
        (KeyValueInformation->DataLength))
    {
        /* Convert to unicode string */
        Buffer = (PVOID)((ULONG_PTR)KeyValueInformation + KeyValueInformation->DataOffset);
        PnpRegSzToString(Buffer, KeyValueInformation->DataLength, &Group.Length);
        Group.MaximumLength = (USHORT)KeyValueInformation->DataLength;
        Group.Buffer = Buffer;
    }

    /* Now read the tag */
    Status = IopGetRegistryValue(ServiceHandle, L"Tag", &KeyValueInformationTag);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Make sure we have a tag */
    if ((KeyValueInformationTag->Type == REG_DWORD) &&
        (KeyValueInformationTag->DataLength))
    {
        /* Read it */
        Tag = *(PULONG)((ULONG_PTR)KeyValueInformationTag +
                        KeyValueInformationTag->DataOffset);
    }

    /* We can get rid of this now */
    ExFreePool(KeyValueInformationTag);

    /* Now let's read the group's tag order */
    Status = IopGetRegistryValue(KeyHandle,
                                 Group.Buffer,
                                 &KeyValueInformationGroupOrderList);

    /* We can get rid of this now */
Quickie:
    if (KeyValueInformation) ExFreePool(KeyValueInformation);
    if (KeyHandle) NtClose(KeyHandle);
    if (!NT_SUCCESS(Status)) return -1;

    /* We're on the success path -- validate the tag order*/
    if ((KeyValueInformationGroupOrderList->Type == REG_BINARY) &&
        (KeyValueInformationGroupOrderList->DataLength))
    {
        /* Get the order array */
        GroupOrder = (PULONG)((ULONG_PTR)KeyValueInformationGroupOrderList +
                              KeyValueInformationGroupOrderList->DataOffset);

        /* Get the count */
        Count = *GroupOrder;
        ASSERT(((Count + 1) * sizeof(ULONG)) <=
               KeyValueInformationGroupOrderList->DataLength);

        /* Now loop each tag */
        GroupOrder++;
        for (i = 1; i <= Count; i++)
        {
            /* If we found it, we're out */
            if (Tag == *GroupOrder) break;

            /* Try the next one */
            GroupOrder++;
        }
    }

    /* Last buffer to free */
    ExFreePool(KeyValueInformationGroupOrderList);
    return i;
}

static
NTSTATUS
NTAPI
SetClassGuidValueKey(IN HANDLE ClassGuidHandle,
                     IN PUNICODE_STRING KeyName,
                     IN PUNICODE_STRING Key)
{
    return ZwSetValueKey(ClassGuidHandle,
                         KeyName,
                         0,
                         REG_SZ,
                         Key->Buffer,
                         Key->Length + sizeof(UNICODE_NULL));
}

NTSTATUS
NTAPI
PipCallDriverAddDevice(IN PDEVICE_NODE DeviceNode,
                       IN BOOLEAN LoadDriver,
                       IN PDRIVER_OBJECT DriverObject)
{
    NTSTATUS Status;
    HANDLE EnumRootKey, SubKey;
    HANDLE ControlKey, ClassKey = NULL, PropertiesKey;
    UNICODE_STRING ClassGuid, Properties;
    UNICODE_STRING EnumRoot = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING ControlClass =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class");
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation = NULL;
    PWCHAR Buffer;
    UNICODE_STRING ServiceName;
    LONG DevType = -1;

    /* Open enumeration root key */
    Status = IopOpenRegistryKeyEx(&EnumRootKey,
                                  NULL,
                                  &EnumRoot,
                                  KEY_READ);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IopOpenRegistryKeyEx() failed for '%wZ' with status 0x%lx\n",
                &EnumRoot, Status);
        return Status;
    }

    /* Open instance subkey */
    Status = IopOpenRegistryKeyEx(&SubKey,
                                  EnumRootKey,
                                  &DeviceNode->InstancePath,
                                  KEY_READ);
    ZwClose(EnumRootKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IopOpenRegistryKeyEx() failed for '%wZ' with status 0x%lx\n",
                &DeviceNode->InstancePath, Status);
        return Status;
    }

    RtlInitUnicodeString(&ServiceName, L"i8042prt");

    if (ExpInTextModeSetup)
    {
        if (wcsstr(DeviceNode->InstancePath.Buffer, L"PNP0303"))
        {
            DevType = 1; // keyboard ps\2
        }
        else if (wcsstr(DeviceNode->InstancePath.Buffer, L"PNP0F03"))
        {
            DevType = 2; // mouse ps\2
        }
        else if (wcsstr(DeviceNode->ServiceName.Buffer, L"kbdhid"))
        {
            DevType = 3; // usb keyboard
        }
        else if (wcsstr(DeviceNode->ServiceName.Buffer, L"mouhid"))
        {
            DevType = 4; // usb mouse
        }
    }

    if (DevType > 0)
    {
        UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"ClassGUID");
        UNICODE_STRING Key;
        ULONG Disposition = 0;
        HANDLE ClassHandle=NULL;
        HANDLE ClassGuidHandle=NULL;

        DPRINT1("PipCallDriverAddDevice: InstancePath -'%wZ'\n", &DeviceNode->InstancePath);
        DPRINT1("PipCallDriverAddDevice: ServiceName -'%wZ'\n", &DeviceNode->ServiceName);

        /* Create subkey ClassGUID for Device Instance key */
        if (DevType == 1 || DevType == 3)
        {
            RtlInitUnicodeString(&ClassGuid, L"{4D36E96B-E325-11CE-BFC1-08002BE10318}\0");
        }
        else if (DevType == 2 || DevType == 4)
        {
            RtlInitUnicodeString(&ClassGuid, L"{4D36E96F-E325-11CE-BFC1-08002BE10318}\0");
        }

        Status = ZwSetValueKey(SubKey,
                               &KeyName,
                               0,
                               REG_SZ,
                               ClassGuid.Buffer,
                               ClassGuid.Length + sizeof(UNICODE_NULL));

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
            goto Exit;
        }

        /* Open the key */
        Status = IopOpenRegistryKeyEx(&ControlKey,
                                      NULL,
                                      &ControlClass,
                                      KEY_READ);

        if (!NT_SUCCESS(Status))
        {
            /* No class key */
            DPRINT1("PipCallDriverAddDevice: No key for '%wZ'\n", &ControlClass);

            /* Create class key */
            Status = IopCreateRegistryKeyEx(&ClassHandle,
                                            NULL,
                                            &ControlClass,
                                            KEY_ALL_ACCESS,
                                            REG_OPTION_NON_VOLATILE,
                                            &Disposition);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                goto Exit;
            }

            if (DevType == 1 || DevType == 3)
            {
                RtlInitUnicodeString(&ClassGuid, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}");
            }
            else if (DevType == 2 || DevType == 4)
            {
                RtlInitUnicodeString(&ClassGuid, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E96F-E325-11CE-BFC1-08002BE10318}");
            }

            Status = IopCreateRegistryKeyEx(&ClassGuidHandle,
                                            NULL,
                                            &ClassGuid,
                                            KEY_ALL_ACCESS,
                                            REG_OPTION_NON_VOLATILE,
                                            &Disposition);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                goto Exit;
            }

            if (DevType == 1 || DevType == 3)
            {
                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}",,0x00000000,"Keyboard"
                RtlInitUnicodeString(&KeyName, L"");
                RtlInitUnicodeString(&Key, L"Keyboard");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}","Class",0x00000000,"Keyboard"
                RtlInitUnicodeString(&KeyName, L"Class");
                RtlInitUnicodeString(&Key, L"Keyboard");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}","Icon",0x00000000,"-3"
                RtlInitUnicodeString(&KeyName, L"Icon");
                RtlInitUnicodeString(&Key, L"-3");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}","Installer32",0x00000000,"SysSetup.Dll,KeyboardClassInstaller"
                RtlInitUnicodeString(&KeyName, L"Installer32");
                RtlInitUnicodeString(&Key, L"SysSetup.Dll,KeyboardClassInstaller");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}","NoInstallClass",0x00000000,"1"
                RtlInitUnicodeString(&KeyName, L"NoInstallClass");
                RtlInitUnicodeString(&Key, L"1");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}","UpperFilters",0x00010000,"kbdclass"
                RtlInitUnicodeString(&KeyName, L"UpperFilters");
                RtlInitUnicodeString(&Key, L"kbdclass");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }
            }
            else if (DevType == 2 || DevType == 4)
            {
                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}",,0x00000000,"Mouse"
                RtlInitUnicodeString(&KeyName, L"");
                RtlInitUnicodeString(&Key, L"Mouse");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}","Class",0x00000000,"Mouse"
                RtlInitUnicodeString(&KeyName, L"Class");
                RtlInitUnicodeString(&Key, L"Mouse");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}","Icon",0x00000000,"-2"
                RtlInitUnicodeString(&KeyName, L"Icon");
                RtlInitUnicodeString(&Key, L"-2");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}","Installer32",0x00000000,"SysSetup.Dll,MouseClassInstaller"
                RtlInitUnicodeString(&KeyName, L"Installer32");
                RtlInitUnicodeString(&Key, L"SysSetup.Dll,MouseClassInstaller");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}","NoInstallClass",0x00000000,"1"
                RtlInitUnicodeString(&KeyName, L"NoInstallClass");
                RtlInitUnicodeString(&Key, L"1");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }

                //HKLM,"SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}","UpperFilters",0x00010000,"mouclass"
                RtlInitUnicodeString(&KeyName, L"UpperFilters");
                RtlInitUnicodeString(&Key, L"mouclass");
                Status = SetClassGuidValueKey(ClassGuidHandle, &KeyName, &Key);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PipCallDriverAddDevice: Status -'%X'\n", Status);
                    goto Exit;
                }
            }
        }
    }

    /* Get class GUID */
    Status = IopGetRegistryValue(SubKey,
                                 REGSTR_VAL_CLASSGUID,
                                 &KeyValueInformation);
    if (NT_SUCCESS(Status))
    {
        /* Convert to unicode string */
        Buffer = (PVOID)((ULONG_PTR)KeyValueInformation + KeyValueInformation->DataOffset);
        PnpRegSzToString(Buffer, KeyValueInformation->DataLength, &ClassGuid.Length);
        ClassGuid.MaximumLength = (USHORT)KeyValueInformation->DataLength;
        ClassGuid.Buffer = Buffer;

        /* Open the key */
        Status = IopOpenRegistryKeyEx(&ControlKey,
                                      NULL,
                                      &ControlClass,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            /* No class key */
            DPRINT1("IopOpenRegistryKeyEx() failed for '%wZ' with status 0x%lx\n",
                    &ControlClass, Status);
        }
        else
        {
            /* Open the class key */
            Status = IopOpenRegistryKeyEx(&ClassKey,
                                          ControlKey,
                                          &ClassGuid,
                                          KEY_READ);
            ZwClose(ControlKey);
            if (!NT_SUCCESS(Status))
            {
                /* No class key */
                DPRINT1("IopOpenRegistryKeyEx() failed for '%wZ' with status 0x%lx\n",
                        &ClassGuid, Status);
            }
        }

        /* Check if we made it till here */
        if (ClassKey)
        {
            /* Get the device properties */
            RtlInitUnicodeString(&Properties, REGSTR_KEY_DEVICE_PROPERTIES);
            Status = IopOpenRegistryKeyEx(&PropertiesKey,
                                          ClassKey,
                                          &Properties,
                                          KEY_READ);
            if (!NT_SUCCESS(Status))
            {
                /* No properties */
                DPRINT("IopOpenRegistryKeyEx() failed for '%wZ' with status 0x%lx\n",
                       &Properties, Status);
                PropertiesKey = NULL;
            }
            else
            {
                ZwClose(PropertiesKey);
            }
        }

        /* Free the registry data */
        ExFreePool(KeyValueInformation);
    }

    /* Do ReactOS-style setup */
    Status = IopAttachFilterDrivers(DeviceNode, SubKey, ClassKey, TRUE);
    if (!NT_SUCCESS(Status))
    {
        IopRemoveDevice(DeviceNode);
        goto Exit;
    }

    Status = IopInitializeDevice(DeviceNode, DriverObject);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = IopAttachFilterDrivers(DeviceNode, SubKey, ClassKey, FALSE);
    if (!NT_SUCCESS(Status))
    {
        IopRemoveDevice(DeviceNode);
        goto Exit;
    }

    Status = IopStartDevice(DeviceNode);

Exit:
    /* Close keys and return status */
    ZwClose(SubKey);
    if (ClassKey != NULL)
    {
        ZwClose(ClassKey);
    }
    return Status;
}

NTSTATUS
NTAPI
INIT_FUNCTION
IopInitializePlugPlayServices(VOID)
{
    NTSTATUS Status;
    ULONG Disposition;
    HANDLE KeyHandle, EnumHandle, ParentHandle, TreeHandle, ControlHandle;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET");
    UNICODE_STRING PnpManagerDriverName = RTL_CONSTANT_STRING(DRIVER_ROOT_NAME L"PnpManager");
    PDEVICE_OBJECT Pdo;

    /* Initialize locks and such */
    KeInitializeSpinLock(&IopPnPSpinLock);
    KeInitializeSpinLock(&IopDeviceTreeLock);
    KeInitializeSpinLock(&IopDeviceActionLock);
    InitializeListHead(&IopPnpEnumerationRequestList);
    KeInitializeEvent(&PiEnumerationLock, NotificationEvent, TRUE);
    ExInitializeResourceLite(&PiEngineLock);
    ExInitializeResourceLite(&PiDeviceTreeLock);

    /* Get the default interface */
    PnpDefaultInterfaceType = IopDetermineDefaultInterfaceType();

    /* Initialize arbiters */
    Status = IopInitializeArbiters();
    if (!NT_SUCCESS(Status)) return Status;

    /* Setup the group cache */
    Status = PiInitCacheGroupInformation();
    if (!NT_SUCCESS(Status)) return Status;

    /* Open the current control set */
    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) return Status;

    /* Create the control key */
    RtlInitUnicodeString(&KeyName, L"Control");
    Status = IopCreateRegistryKeyEx(&ControlHandle,
                                    KeyHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    if (!NT_SUCCESS(Status)) return Status;

    /* Check if it's a new key */
    if (Disposition == REG_CREATED_NEW_KEY)
    {
        HANDLE DeviceClassesHandle;

        /* Create the device classes key */
        RtlInitUnicodeString(&KeyName, L"DeviceClasses");
        Status = IopCreateRegistryKeyEx(&DeviceClassesHandle,
                                        ControlHandle,
                                        &KeyName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        &Disposition);
        if (!NT_SUCCESS(Status)) return Status;

        ZwClose(DeviceClassesHandle);
    }

    ZwClose(ControlHandle);

    /* Create the enum key */
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ENUM);
    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    KeyHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    if (!NT_SUCCESS(Status)) return Status;

    /* Check if it's a new key */
    if (Disposition == REG_CREATED_NEW_KEY)
    {
        /* FIXME: DACLs */
    }

    /* Create the root key */
    ParentHandle = EnumHandle;
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ROOTENUM);
    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    ParentHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    NtClose(ParentHandle);
    if (!NT_SUCCESS(Status)) return Status;
    NtClose(EnumHandle);

    /* Open the root key now */
    RtlInitUnicodeString(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\ENUM");
    Status = IopOpenRegistryKeyEx(&EnumHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (NT_SUCCESS(Status))
    {
        /* Create the root dev node */
        RtlInitUnicodeString(&KeyName, REGSTR_VAL_ROOT_DEVNODE);
        Status = IopCreateRegistryKeyEx(&TreeHandle,
                                        EnumHandle,
                                        &KeyName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        NULL);
        NtClose(EnumHandle);
        if (NT_SUCCESS(Status)) NtClose(TreeHandle);
    }

    /* Create the root driver */
    Status = IoCreateDriver(&PnpManagerDriverName, PnpRootDriverEntry);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateDriverObject() failed\n");
        KeBugCheckEx(PHASE1_INITIALIZATION_FAILED, Status, 0, 0, 0);
    }

    /* Create the root PDO */
    Status = IoCreateDevice(IopRootDriverObject,
                            sizeof(IOPNP_DEVICE_EXTENSION),
                            NULL,
                            FILE_DEVICE_CONTROLLER,
                            0,
                            FALSE,
                            &Pdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateDevice() failed\n");
        KeBugCheckEx(PHASE1_INITIALIZATION_FAILED, Status, 0, 0, 0);
    }

    /* This is a bus enumerated device */
    Pdo->Flags |= DO_BUS_ENUMERATED_DEVICE;

    /* Create the root device node */
    IopRootDeviceNode = PipAllocateDeviceNode(Pdo);

    /* Set flags */
    IopRootDeviceNode->Flags |= DNF_STARTED + DNF_PROCESSED + DNF_ENUMERATED +
                                DNF_MADEUP + DNF_NO_RESOURCE_REQUIRED +
                                DNF_ADDED;

    /* Create instance path */
    RtlCreateUnicodeString(&IopRootDeviceNode->InstancePath,
                           REGSTR_VAL_ROOT_DEVNODE);

    /* Call the add device routine */
    IopRootDriverObject->DriverExtension->AddDevice(IopRootDriverObject,
                                                    IopRootDeviceNode->PhysicalDeviceObject);

    /* Initialize PnP-Event notification support */
    Status = IopInitPlugPlayEvents();
    if (!NT_SUCCESS(Status)) return Status;

    /* Report the device to the user-mode pnp manager */
    IopQueueTargetDeviceEvent(&GUID_DEVICE_ARRIVAL,
                              &IopRootDeviceNode->InstancePath);

    /* Initialize the Bus Type GUID List */
    PnpBusTypeGuidList = ExAllocatePool(PagedPool, sizeof(IO_BUS_TYPE_GUID_LIST));
    RtlZeroMemory(PnpBusTypeGuidList, sizeof(IO_BUS_TYPE_GUID_LIST));
    ExInitializeFastMutex(&PnpBusTypeGuidList->Lock);

    /* Launch the firmware mapper */
    Status = IopUpdateRootKey();
    if (!NT_SUCCESS(Status)) return Status;

    /* Close the handle to the control set */
    NtClose(KeyHandle);

    /* We made it */
    return STATUS_SUCCESS;
}

/* EOF */
