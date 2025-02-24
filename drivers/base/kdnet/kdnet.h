/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdnet.h
 * PURPOSE:         Base definitions for the kernel debugger over Net.
 * PROGRAMMER:      
 */

#ifndef _KDNET_H_
#define _KDNET_H_

/* NTDDI_WINBLUE */
#include <ntifs.h>
#include <windbgkd.h>
#include <arc/arc.h>

typedef enum
{
    KDP_PACKET_RECEIVED = 0,
    KDP_PACKET_TIMEOUT = 1,
    KDP_PACKET_RESEND = 2
} KDP_STATUS;

typedef struct _KD_NIC_DATA
{
    USHORT Version;
    USHORT Size;
    ULONG Reserved0;
    NTSTATUS Status;
    ULONG LinkSpeed1;
    ULONG Reserved1;
    ULONG Reserved2;
    SLIST_HEADER sListHead;
    SLIST_HEADER sListHead1;
    SLIST_HEADER sListHead2;
    UCHAR MacAddress[6];
    UCHAR LinkState;
    UCHAR Reserved3;
    ULONG LinkSpeed2;
    ULONG Reserved4;
} KD_NIC_DATA, *PKD_NIC_DATA;
C_ASSERT(sizeof(KD_NIC_DATA) == 0x40);


#endif /* _KDNET_H_ */

/* EOF */
