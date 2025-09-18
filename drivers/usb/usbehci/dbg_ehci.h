/*
 * PROJECT:     ReactOS USB EHCI Miniport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     USBEHCI debugging declarations
 * COPYRIGHT:   Copyright 2017-2018, 2025 Vadim Galyant <vgal@rambler.ru>
 */

#ifndef DBG_EHCI_H__
#define DBG_EHCI_H__

#if DBG

  #ifndef NDEBUG_EHCI_TRACE
    #define DPRINT_EHCI(fmt, ...) do { \
        if (DbgPrint("(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__))  \
            DbgPrint("(%s:%d) DbgPrint() failed!\n", __RELFILE__, __LINE__); \
    } while (0)
  #else
    #if defined(_MSC_VER)
      #define DPRINT_EHCI __noop
    #else
      #define DPRINT_EHCI(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
    #endif
  #endif

  #ifndef NDEBUG_EHCI_ROOT_HUB
    #define DPRINT_RH(fmt, ...) do { \
        if (DbgPrint("(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__))  \
            DbgPrint("(%s:%d) DbgPrint() failed!\n", __RELFILE__, __LINE__); \
    } while (0)
  #else
    #if defined(_MSC_VER)
      #define DPRINT_RH __noop
    #else
      #define DPRINT_RH(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
    #endif
  #endif

#else /* not DBG */

  #if defined(_MSC_VER)
    #define DPRINT_EHCI __noop
    #define DPRINT_RH __noop
  #else
    #define DPRINT_EHCI(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
    #define DPRINT_RH(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
  #endif /* _MSC_VER */

#endif /* not DBG */

#ifdef NODPRINT
  #undef DPRINT
  #if defined(_MSC_VER)
    #define DPRINT __noop
  #else
    #define DPRINT(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
  #endif /* _MSC_VER */
#endif

#ifdef NODPRINT1
  #undef DPRINT1
  #if defined(_MSC_VER)
    #define DPRINT1 __noop
  #else
    #define DPRINT1(...) do {if(0) {DbgPrint(__VA_ARGS__);}} while(0)
  #endif /* _MSC_VER */
#endif

#ifdef NOASSERT
  #undef ASSERT
  #define ASSERT(x) ((VOID) 0)
#endif

#endif /* DBG_EHCI_H__ */
