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


#endif /* _KDNET_H_ */

/* EOF */
