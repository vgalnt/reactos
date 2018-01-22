/*
 * PROJECT:     ReactOS USB Hub Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     USBHub, "black list" for USB devices not yet supported
 * COPYRIGHT:   Copyright 2018 Vadim Galyant <vgal@rambler.ru>
 */

#include "usbhub.h"

#define NDEBUG
#include <debug.h>

BOOLEAN
NTAPI
USBH_IsVidPidFromBlackList(IN USHORT IdVendor,
                           IN USHORT IdProduct,
                           IN USHORT Revision)
{
    BOOLEAN Result = FALSE;

    DPRINT1("USBH_IsVidPidFromBlackList: IdVendor - %X, IdProduct - %X\n",
           IdVendor,
           IdProduct);
   
    // This is hack - "black list" USB devices (in the main webcameras)

    switch (IdVendor)
    {
        case 0x03f0: // Hewlett-Packard
            switch (IdProduct)
            {
              case 0x1b07: // Premium Starter Webcam
              case 0x3724: // Webcam
              case 0x9207: // HD-4110 Webcam
              case 0xb116: // Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0408: // Quanta Computer, Inc.
            switch (IdProduct)
            {
              case 0x030c: // HP Webcam
              case 0x03b2: // HP Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x040a: // Kodak Co.
            switch (IdProduct)
            {
              case 0x0200: // Digital Camera
              case 0x0402: // Digital Camera
              case 0x0535: // EasyShare CX4230 Camera
              case 0x0581: // Digital Camera
              case 0x0582: // Digital Camera
              case 0x0583: // Digital Camera
              case 0x0585: // Digital Camera
              case 0x0587: // Digital Camera
              case 0x0588: // Digital Camera
              case 0x0589: // EasyShare C360
              case 0x058b: // Digital Camera
              case 0x0590: // Digital Camera
              case 0x0591: // Digital Camera
              case 0x0592: // Digital Camera
              case 0x0593: // Digital Camera
              case 0x0594: // Digital Camera
              case 0x0595: // Digital Camera
              case 0x0596: // Digital Camera
              case 0x0597: // Digital Camera
              case 0x0598: // EASYSHARE M1033 digital camera
              case 0x0599: // Digital Camera
              case 0x059a: // Digital Camera
              case 0x059b: // Digital Camera
              case 0x059c: // Digital Camera
              case 0x059d: // Digital Camera
              case 0x059e: // Digital Camera
              case 0x059f: // Digital Camera
              case 0x05a0: // Digital Camera
              case 0x05a1: // Digital Camera
              case 0x05a2: // Digital Camera
              case 0x05a3: // Digital Camera
              case 0x05a4: // Digital Camera
              case 0x05a5: // Digital Camera
              case 0x05a6: // Digital Camera
              case 0x05a7: // Digital Camera
              case 0x05a8: // Digital Camera
              case 0x05a9: // Digital Camera
              case 0x05aa: // Digital Camera
              case 0x05ab: // Digital Camera
              case 0x05ac: // Digital Camera
              case 0x05ad: // Digital Camera
              case 0x05ae: // Digital Camera
              case 0x05af: // Digital Camera
              case 0x05b0: // Digital Camera
              case 0x05b1: // Digital Camera
              case 0x05b2: // Digital Camera
              case 0x05b3: // EasyShare Z710 Camera
              case 0x05b4: // Digital Camera
              case 0x05b5: // Digital Camera
              case 0x05b6: // Digital Camera
              case 0x05b7: // Digital Camera
              case 0x05b8: // Digital Camera
              case 0x05b9: // Digital Camera
              case 0x05ba: // Digital Camera
              case 0x05bb: // Digital Camera
              case 0x05bc: // Digital Camera
              case 0x05bd: // Digital Camera
              case 0x05be: // Digital Camera
              case 0x05bf: // Digital Camera
              case 0x05c0: // Digital Camera
              case 0x05c1: // Digital Camera
              case 0x05c2: // Digital Camera
              case 0x05c3: // Digital Camera
              case 0x05c4: // Digital Camera
              case 0x05c5: // Digital Camera
              case 0x05c8: // EASYSHARE Z1485 IS Digital Camera
              case 0x05d3: // EasyShare M320 Camera
              case 0x05d4: // EasyShare C180 Digital Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x041e: // Creative Technology, Ltd
            switch (IdProduct)
            {
              case 0x4005: // Webcam Blaster Go ES
              case 0x400a: // PC-Cam 300
              case 0x400b: // PC-Cam 600
              case 0x400c: // Webcam 5 [pwc]
              case 0x400d: // Webcam PD1001
              case 0x400f: // PC-CAM 550 (Composite)
              case 0x4011: // Webcam PRO eX
              case 0x4012: // PC-CAM350
              case 0x4013: // PC-Cam 750
              case 0x4015: // CardCam Value
              case 0x4016: // CardCam
              case 0x4017: // Webcam Mobile [PD1090]
              case 0x4018: // Webcam Vista [PD1100]
              case 0x401a: // Webcam Vista [PD1100]
              case 0x401c: // Webcam NX [PD1110]
              case 0x401d: // Webcam NX Ultra
              case 0x401e: // Webcam NX Pro
              case 0x401f: // Webcam Notebook [PD1171]
              case 0x4020: // Webcam NX
              case 0x4021: // Webcam NX Ultra
              case 0x4022: // Webcam NX Pro
              case 0x4028: // Vista Plus cam [VF0090]
              case 0x4029: // Webcam Live!
              case 0x402f: // DC-CAM 3000Z
              case 0x4034: // Webcam Instant
              case 0x4035: // Webcam Instant
              case 0x4036: // Webcam Live!/Live! Pro
              case 0x4037: // Webcam Live!
              case 0x4038: // ORITE CCD Webcam [PC370R]
              case 0x4039: // Webcam Live! Effects
              case 0x403a: // Webcam NX Pro 2
              case 0x403b: // Creative Webcam Vista [VF0010]
              case 0x403c: // Webcam Live! Ultra
              case 0x403d: // Webcam Notebook Ultra
              case 0x403e: // Webcam Vista Plus
              case 0x4041: // Webcam Live! Motion
              case 0x4043: // Vibra Plus Webcam
              case 0x4045: // Live! Cam Voice
              case 0x4049: // Live! Cam Voice
              case 0x4051: // Live! Cam Notebook Pro [VF0250]
              case 0x4052: // Live! Cam Vista IM
              case 0x4053: // Live! Cam Video IM
              case 0x4054: // Live! Cam Video IM
              case 0x4055: // Live! Cam Video IM Pro
              case 0x4056: // Live! Cam Video IM Pro
              case 0x4057: // Live! Cam Optia
              case 0x4058: // Live! Cam Optia AF
              case 0x405f: // WebCam Vista (VF0330)
              case 0x4061: // Live! Cam Notebook Pro [VF0400]
              case 0x4063: // Live! Cam Video IM Pro
              case 0x4068: // Live! Cam Notebook [VF0470]
              case 0x406c: // Live! Cam Sync [VF0520]
              case 0x4083: // Live! Cam Socialize [VF0640]
              case 0x4087: // Live! Cam Socialize HD 1080 [VF0680]
              case 0x4088: // Live! Cam Chat HD [VF0700]
              case 0x4095: // Live! Cam Sync HD [VF0770]
              case 0x4097: // Live! Cam Chat HD [VF0700]
              case 0xffff: // Webcam Live! Ultra
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0458: // KYE Systems Corp. (Mouse Systems)
            switch (IdProduct)
            {
              case 0x7004: // VideoCAM Express V2
              case 0x7006: // Dsc 1.3 Smart Camera Device
              case 0x7007: // VideoCAM Web
              case 0x7009: // G-Shot G312 Still Camera Device
              case 0x700c: // VideoCAM Web V3
              case 0x700d: // G-Shot G511 Composite Device
              case 0x700f: // VideoCAM Web
              case 0x7012: // WebCAM USB2.0
              case 0x7014: // VideoCAM Live V3
              case 0x701c: // G-Shot G512 Still Camera
              case 0x7020: // Sim 321C
              case 0x7025: // Eye 311Q Camera
              case 0x7029: // Genius Look 320s (SN9C201 + HV7131R)
              case 0x702f: // Genius Slim 322
              case 0x7035: // i-Look 325T Camera
              case 0x7045: // Genius Look 1320 V2
              case 0x704c: // Genius i-Look 1321
              case 0x704d: // Slim 1322AF
              case 0x7055: // Slim 2020AF camera
              case 0x705a: // Asus USB2.0 Webcam
              case 0x705c: // Genius iSlim 1300AF
              case 0x7061: // Genius iLook 1321 V2
              case 0x7066: // Acer Crystal Eye Webcam
              case 0x7067: // Genius iSlim 1300AF V2
              case 0x7068: // Genius eFace 1325R
              case 0x706d: // Genius iSlim 2000AF V2
              case 0x7076: // Genius FaceCam 312
              case 0x7079: // FaceCam 2025R
              case 0x707f: // TVGo DVB-T03 [RTL2832]
              case 0x7088: // WideCam 1050
              case 0x7089: // Genius FaceCam 320
              case 0x708c: // Genius WideCam F100
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x045e: // Microsoft Corp.
            switch (IdProduct)
            {
              case 0x00f4: // LifeCam VX-6000 (SN9C20x + OV9650)
              case 0x00f5: // LifeCam VX-3000
              case 0x00f7: // LifeCam VX-1000
              case 0x00f8: // LifeCam NX-6000
              case 0x0721: // LifeCam NX-3000 (UVC-compliant)
              case 0x0723: // LifeCam VX-7000 (UVC-compliant)
              case 0x0728: // LifeCam VX-5000
              case 0x074a: // LifeCam VX-500 [1357]
              case 0x075d: // LifeCam Cinema // USB\VID_045E&PID_075D&REV_0105
              case 0x0761: // LifeCam VX-2000
              case 0x0766: // LifeCam VX-800
              case 0x076d: // LifeCam HD-5000
              case 0x0770: // LifeCam VX-700
              case 0x0772: // LifeCam Studio
              case 0x0779: // LifeCam HD-3000
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0461: // Primax Electronics, Ltd
            switch (IdProduct)
            {
              case 0x0813: // IBM UltraPort Camera
              case 0x0815: // Micro Innovations IC200 Webcam
              case 0x0819: // Fujifilm IX-30 Camera [webcam mode]
              case 0x081a: // Fujifilm IX-30 Camera [storage mode]
              case 0x081c: // Elitegroup ECS-C11 Camera
              case 0x0a00: // Micro Innovations Web Cam 320
              case 0x4de7: // webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x046d: // Logitech, Inc.
            switch (IdProduct)
            {
              case 0x0082: // Acer Aspire 5672 Webcam
              case 0x0801: // QuickCam Home
              case 0x0802: // Webcam C200
              case 0x0804: // Webcam C250
              case 0x0805: // Webcam C300
              case 0x0807: // Webcam B500
              case 0x0808: // Webcam C600
              case 0x0809: // Webcam Pro 9000
              case 0x080a: // Portable Webcam C905
              case 0x080f: // Webcam C120
              case 0x0810: // QuickCam Pro
              case 0x0819: // Webcam C210
              case 0x081b: // Webcam C310
              case 0x081d: // HD Webcam C510
              case 0x0820: // QuickCam VC
              case 0x0821: // HD Webcam C910
              case 0x0825: // Webcam C270
              case 0x0826: // HD Webcam C525
              case 0x0828: // HD Webcam B990
              case 0x082b: // Webcam C170
              case 0x082c: // HD Webcam C615
              case 0x082d: // HD Pro Webcam C920
              case 0x0836: // B525 HD Webcam
              case 0x0837: // BCC950 ConferenceCam
              case 0x0840: // QuickCam Express
              case 0x0843: // Webcam C930e
              case 0x0850: // QuickCam Web
              case 0x085c: // C922 Pro Stream Webcam
              case 0x0870: // QuickCam Express
              case 0x0890: // QuickCam Traveler
              case 0x0892: // OrbiCam
              case 0x0894: // CrystalCam
              case 0x0895: // QuickCam for Dell Notebooks
              case 0x0896: // OrbiCam
              case 0x0897: // QuickCam for Dell Notebooks
              case 0x0899: // QuickCam for Dell Notebooks
              case 0x089d: // QuickCam E2500 series
              case 0x08a0: // QuickCam IM
              case 0x08a1: // QuickCam IM with sound
              case 0x08a2: // Labtec Webcam Pro
              case 0x08a3: // QuickCam QuickCam Chat
              case 0x08a6: // QuickCam IM
              case 0x08a7: // QuickCam Image
              case 0x08ac: // QuickCam Cool
              case 0x08ad: // QuickCam Communicate STX
              case 0x08ae: // QuickCam for Notebooks
              case 0x08af: // QuickCam Easy/Cool
              case 0x08b0: // QuickCam 3000 Pro [pwc]
              case 0x08b1: // QuickCam Notebook Pro
              case 0x08b2: // QuickCam Pro 4000
              case 0x08b3: // QuickCam Zoom
              case 0x08b4: // QuickCam Zoom
              case 0x08b5: // QuickCam Sphere
              case 0x08b9: // QuickCam IM
              case 0x08c0: // QuickCam Pro 3000
              case 0x08c1: // QuickCam Fusion
              case 0x08c2: // QuickCam PTZ
              case 0x08c3: // Camera (Notebooks Pro)
              case 0x08c5: // QuickCam Pro 5000
              case 0x08c6: // QuickCam for DELL Notebooks
              case 0x08c7: // QuickCam OEM Cisco VT Camera II
              case 0x08c9: // QuickCam Ultra Vision
              case 0x08ce: // QuickCam Pro 5000
              case 0x08cf: // QuickCam UpdateMe
              case 0x08d0: // QuickCam Express
              case 0x08d7: // QuickCam Communicate STX
              case 0x08d8: // QuickCam for Notebook Deluxe
              case 0x08d9: // QuickCam IM/Connect
              case 0x08da: // QuickCam Messanger
              case 0x08dd: // QuickCam for Notebooks
              case 0x08e0: // QuickCam Express
              case 0x08e1: // Labtec Webcam
              case 0x08f0: // QuickCam Messenger
              case 0x08f1: // QuickCam Express
              case 0x08f3: // QuickCam Express
              case 0x08f4: // Labtec Webcam
              case 0x08f5: // QuickCam Messenger Communicate
              case 0x08f6: // QuickCam Messenger Plus
              case 0x0900: // ClickSmart 310
              case 0x0901: // ClickSmart 510
              case 0x0903: // ClickSmart 820
              case 0x0905: // ClickSmart 820
              case 0x0910: // QuickCam Cordless
              case 0x0920: // QuickCam Express
              case 0x0921: // Labtec Webcam
              case 0x0922: // QuickCam Live
              case 0x0928: // QuickCam Express
              case 0x0929: // Labtec Webcam Pro
              case 0x092a: // QuickCam for Notebooks
              case 0x092b: // Labtec Webcam Plus
              case 0x092c: // QuickCam Chat
              case 0x092d: // QuickCam Express / Go
              case 0x092e: // QuickCam Chat
              case 0x092f: // QuickCam Express Plus
              case 0x0950: // Pocket Camera
              case 0x0960: // ClickSmart 420
              case 0x0970: // Pocket750
              case 0x0990: // QuickCam Pro 9000
              case 0x0991: // QuickCam Pro for Notebooks
              case 0x0992: // QuickCam Communicate Deluxe
              case 0x0994: // QuickCam Orbit/Sphere AF
              case 0x09a1: // QuickCam Communicate MP/S5500
              case 0x09a2: // QuickCam Communicate Deluxe/S7500
              case 0x09a4: // QuickCam E 3500
              case 0x09a5: // Quickcam 3000 For Business
              case 0x09a6: // QuickCam Vision Pro
              case 0x09b0: // Acer OrbiCam
              case 0x09b2: // Fujitsu Webcam
              case 0x09c0: // QuickCam for Dell Notebooks Mic
              case 0x09c1: // QuickCam Deluxe for Notebooks
              case 0x8801: // Video Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0471: // Philips (or NXP)
            switch (IdProduct)
            {
              case 0x0302: // PCA645VC Webcam [pwc]
              case 0x0303: // PCA646VC Webcam [pwc]
              case 0x0304: // Askey VC010 Webcam [pwc]
              case 0x0307: // PCVC675K Webcam [pwc]
              case 0x0308: // PCVC680K Webcam [pwc]
              case 0x030b: // PC VGA Camera (Vesta Fun)
              case 0x030c: // PCVC690K Webcam [pwc]
              case 0x0310: // PCVC730K Webcam [pwc]
              case 0x0311: // PCVC740K ToUcam Pro [pwc]
              case 0x0312: // PCVC750K Webcam [pwc]
              case 0x0321: // FunCam
              case 0x0322: // DMVC1300K PC Camera
              case 0x0325: // SPC 200NC PC Camera
              case 0x0326: // SPC 300NC PC Camera
              case 0x0327: // Webcam SPC 6000 NC (Webcam w/ mic)
              case 0x0328: // SPC 700NC PC Camera
              case 0x0329: // SPC 900NC PC Camera / ORITE CCD Webcam(PC370R)
              case 0x032d: // SPC 210NC PC Camera
              case 0x032e: // SPC 315NC PC Camera
              case 0x0330: // SPC 710NC PC Camera
              case 0x0331: // SPC 1300NC PC Camera
              case 0x0332: // SPC 1000NC PC Camera
              case 0x0333: // SPC 620NC PC Camera
              case 0x0334: // SPC 520/525NC PC Camera
              case 0x2034: // Webcam SPC530NC
              case 0x2036: // Webcam SPC1030NC
              case 0x20d0: // SPZ2000 Webcam [PixArt PAC7332]
              case 0x262c: // SPC230NC Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0472: // Chicony Electronics Co., Ltd
            switch (IdProduct)
            {
              case 0xb086: // Asus USB2.0 Webcam
              case 0xb091: // Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x04ca: // Lite-On Technology Corp.
            switch (IdProduct)
            {
              case 0x300b: // Atheros AR3012 Bluetooth // USB\Vid_04ca&Pid_300b&Rev_0001
              case 0x7025: // HP HD Webcam
              case 0x7046: // TOSHIBA Web Camera - HD
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x04f2: // Chicony Electronics Co., Ltd
            switch (IdProduct)
            {
              case 0xa001: // E-Video DC-100 Camera
              case 0xa120: // ORITE CCD Webcam(PC370R)
              case 0xa121: // ORITE CCD Webcam(PC370R)
              case 0xa122: // ORITE CCD Webcam(PC370R)
              case 0xa123: // ORITE CCD Webcam(PC370R)
              case 0xa124: // ORITE CCD Webcam(PC370R)
              case 0xa133: // Gateway Webcam
              case 0xa136: // LabTec Webcam 5500
              case 0xa147: // Medion Webcam
              case 0xb008: // USB 2.0 Camera
              case 0xb009: // Integrated Camera
              case 0xb010: // Integrated Camera
              case 0xb012: // 1.3 MPixel UVC Webcam
              case 0xb013: // USB 2.0 Camera
              case 0xb015: // VGA 24fps UVC Webcam
              case 0xb016: // VGA 30fps UVC Webcam
              case 0xb018: // 2M UVC Webcam
              case 0xb021: // ViewSonic 1.3M, USB2.0 Webcam
              case 0xb022: // Gateway USB 2.0 Webcam
              case 0xb023: // Gateway USB 2.0 Webcam
              case 0xb024: // USB 2.0 Webcam
              case 0xb025: // Camera
              case 0xb027: // Gateway USB 2.0 Webcam
              case 0xb028: // VGA UVC Webcam
              case 0xb029: // 1.3M UVC Webcam
              case 0xb036: // Asus Integrated 0.3M UVC Webcam
              case 0xb044: // Acer CrystalEye Webcam
              case 0xb057: // integrated USB webcam
              case 0xb059: // CKF7037 HP webcam
              case 0xb064: // CNA7137 Integrated Webcam
              case 0xb070: // Camera
              case 0xb071: // 2.0M UVC Webcam / CNF7129 // USB\Vid_04f2&Pid_b071
              case 0xb083: // CKF7063 Webcam (HP)
              case 0xb091: // Webcam
              case 0xb104: // CNF7069 Webcam
              case 0xb107: // CNF7070 Webcam
              case 0xb14c: // CNF8050 Webcam
              case 0xb159: // CNF8243 Webcam
              case 0xb15c: // Sony Vaio Integrated Camera
              case 0xb1aa: // Webcam-101
              case 0xb1b4: // Lenovo Integrated Camera
              case 0xb1b9: // Asus Integrated Webcam
              case 0xb1cf: // Lenovo Integrated Camera
              case 0xb1d6: // CNF9055 Toshiba Webcam  // USB\Vid_04f2&Pid_b1d6
              case 0xb1d8: // 1.3M Webcam
              case 0xb1e4: // Toshiba Integrated Webcam
              case 0xb213: // Fujitsu Integrated Camera
              case 0xb217: // Lenovo Integrated Camera (0.3MP)
              case 0xb221: // integrated camera
              case 0xb230: // Integrated HP HD Webcam
              case 0xb257: // Lenovo Integrated Camera
              case 0xb26b: // Sony Visual Communication Camera
              case 0xb272: // Lenovo EasyCamera
              case 0xb2b0: // Camera
              case 0xb2b9: // Lenovo Integrated Camera UVC
              case 0xb2da: // thinkpad t430s camera
              case 0xb2ea: // Integrated Camera [ThinkPad]
              case 0xb330: // Asus 720p CMOS webcam
              case 0xb354: // UVC 1.00 device HD UVC WebCam
              case 0xb367: // webcamera // USB\Vid_04f2&Pid_b367&Rev_3114
              case 0xb394: // Integrated Camera
              case 0xb3d6: // webcamera // USB\Vid_04f2&Pid_b3d6&Rev_3907
              case 0xb3eb: // HP 720p HD Monitor Webcam
              case 0xb3f6: // HD WebCam (Acer)
              case 0xb3fd: // HD WebCam (Asus N-series)
              case 0xb40e: // HP Truevision HD camera
              case 0xb444: // Lenovo Integrated Webcam
              case 0xb469: // webcamera // USB\Vid_04f2&Pid_b469
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x04e8: // Samsung Electronics Co., Ltd
            switch (IdProduct)
            {
              case 0x1323: // WB700 Camera
              case 0x675b: // D900e Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x04fc: // Sunplus Technology Co., Ltd
            switch (IdProduct)
            {
              case 0x2080: // ASUS Webcam
              case 0x500c: // CA500C Digital Camera
              case 0x504a: // Aiptek Mini PenCam 1.3
              case 0x504b: // Aiptek Mega PockerCam 1.3/Maxell MaxPocket LE 1.3
              case 0x5331: // Vivitar Vivicam 10
              case 0x5360: // Sunplus Generic Digital Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x05c8: // Cheng Uei Precision Industry Co., Ltd (Foxlink)
            switch (IdProduct)
            {
              case 0x0103: // FO13FF-65 PC-CAM
              case 0x010b: // Webcam (UVC)
              case 0x021a: // HP Webcam
              case 0x0318: // Webcam
              case 0x0359: // Webcam // USB\Vid_05c8&Pid_0359
              case 0x0361: // SunplusIT INC. HP Truevision HD Webcam
              case 0x036e: // Webcam
              case 0x0403: // Webcam
              case 0x041b: // HP 2.0MP High Definition Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x064e: // Suyin Corp.
            switch (IdProduct)
            {
              case 0x2100: // Sony Visual Communication Camera
              case 0x9700: // Asus Integrated Webcam
              case 0xa100: // Acer OrbiCam
              case 0xa101: // Acer CrystalEye Webcam
              case 0xa102: // Acer/Lenovo Webcam [CN0316]
              case 0xa103: // Acer/HP Integrated Webcam [CN0314]
              case 0xa110: // HP Webcam
              case 0xa114: // Lemote Webcam
              case 0xa116: // UVC 1.3MPixel WebCam
              case 0xa136: // Asus Integrated Webcam [CN031B]
              case 0xa219: // 1.3M WebCam (notebook emachines E730, Acer sub-brand)
              case 0xc107: // HP webcam [dv6-1190en]
              case 0xc335: // HP TrueVision HD
              case 0xd101: // Acer CrystalEye Webcam // USB\Vid_064e&Pid_d101
              case 0xd213: // UVC HD Webcam
              case 0xd217: // HP TrueVision HD
              case 0xe201: // Lenovo Integrated Webcam
              case 0xe203: // Lenovo Integrated Webcam
              case 0xe258: // HP TrueVision HD Integrated Webcam
              case 0xe263: // HP TrueVision HD Integrated Webcam
              case 0xf102: // Lenovo Integrated Webcam [R5U877]
              case 0xf103: // Lenovo Integrated Webcam [R5U877]
              case 0xf209: // HP Webcam
              case 0xf300: // UVC 0.3M Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0a5c: // Broadcom Corp.
            switch (IdProduct)
            {
              case 0x219c: // Bluetooth Device // usb vid_0a5c&pid_219c&rev_0628
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0ac8: // Z-Star Microelectronics Corp.
            switch (IdProduct)
            {
              case 0x0301: // Web Camera
              case 0x0302: // ZC0302 Webcam
              case 0x0321: // Vimicro generic vc0321 Camera
              case 0x0323: // Luxya WC-1200 USB 2.0 Webcam
              case 0x301b: // ZC0301 Webcam
              case 0x303b: // ZC0303 Webcam
              case 0x305b: // ZC0305 Webcam
              case 0x307b: // USB 1.1 Webcam
              case 0x332d: // Vega USB 2.0 Camera
              case 0x3343: // Sirius USB 2.0 Camera
              case 0x3420: // Venus USB2.0 Camera
              case 0xc001: // Sony embedded vimicro Camera
              case 0xc002: // Visual Communication Camera VGP-VCC1
              case 0xc302: // Vega USB 2.0 Camera
              case 0xc303: // Saturn USB 2.0 Camera
              case 0xc326: // Namuga 1.3M Webcam
              case 0xc33f: // Webcam // USB\Vid_0ac8&Pid_c42b&Rev_0904
              case 0xc429: // Lenovo ThinkCentre Web Camera
              case 0xc42b: // Lenovo IdeaCentre Web Camera // USB\Vid_0ac8&Pid_c42b&Rev_0904
              case 0xc42d: // Lenovo IdeaCentre Web Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0bda: // Realtek Semiconductor Corp.
            switch (IdProduct)
            {
              case 0x570c: // Asus laptop camera
              case 0x5730: // HP 2.0MP High Definition Webcam
              case 0x5751: // Integrated Webcam
              case 0x5775: // HP "Truevision HD" laptop camera
              case 0x57b3: // Acer 640 × 480 laptop camera
              case 0x57b5: // laptop camera // USB\VID_0BDA&PID_57B5&REV_0012
              case 0x57da: // Built-In Video Camera
              case 0x58c0: // Webcam
              case 0x58c8: // Integrated Webcam HD
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x0c45: // Microdia
            switch (IdProduct)
            {
              case 0x6001: // Genius VideoCAM NB
              case 0x6005: // Sweex Mini Webcam
              case 0x6007: // VideoCAM Eye
              case 0x6009: // VideoCAM ExpressII
              case 0x600d: // TwinkleCam USB camera
              case 0x6011: // PC Camera (SN9C102)
              case 0x6019: // PC Camera (SN9C102)
              case 0x6024: // VideoCAM ExpressII
              case 0x6025: // VideoCAM ExpressII
              case 0x6028: // Typhoon Easycam USB 330K (older)
              case 0x6029: // Triplex i-mini PC Camera
              case 0x602a: // Meade ETX-105EC Camera
              case 0x602b: // VideoCAM NB 300
              case 0x602c: // Clas Ohlson TWC-30XOP Webcam
              case 0x602d: // VideoCAM ExpressII
              case 0x602e: // VideoCAM Messenger
              case 0x6030: // VideoCAM ExpressII
              case 0x603f: // VideoCAM ExpressII
              case 0x6040: // CCD PC Camera (PC390A)
              case 0x606a: // CCD PC Camera (PC390A)
              case 0x607a: // CCD PC Camera (PC390A)
              case 0x607b: // Win2 PC Camera
              case 0x607c: // CCD PC Camera (PC390A)
              case 0x607e: // CCD PC Camera (PC390A)
              case 0x6082: // VideoCAM Look
              case 0x6083: // VideoCAM Look
              case 0x608c: // VideoCAM Look
              case 0x608e: // VideoCAM Look
              case 0x608f: // PC Camera (SN9C103 + OV7630)
              case 0x60a8: // VideoCAM Look
              case 0x60aa: // VideoCAM Look
              case 0x60ab: // PC Camera
              case 0x60af: // VideoCAM Look
              case 0x60b0: // Genius VideoCam Look
              case 0x60c0: // PC Camera with Mic (SN9C105)
              case 0x60c8: // Win2 PC Camera
              case 0x60cc: // PC Camera with Mic (SN9C105)
              case 0x60ec: // PC Camera with Mic (SN9C105)
              case 0x60ef: // Win2 PC Camera
              case 0x60fa: // PC Camera with Mic (SN9C105)
              case 0x60fc: // PC Camera with Mic (SN9C105)
              case 0x6108: // Win2 PC Camera
              case 0x6122: // PC Camera (SN9C110)
              case 0x6123: // PC Camera (SN9C110)
              case 0x6128: // PC Camera (SN9C325 + OM6802)
              case 0x612a: // PC Camera (SN9C325)
              case 0x612c: // PC Camera (SN9C110)
              case 0x612e: // PC Camera (SN9C110)
              case 0x612f: // PC Camera (SN9C110)
              case 0x6130: // PC Camera (SN9C120)
              case 0x6138: // Win2 PC Camera
              case 0x613a: // PC Camera (SN9C120)
              case 0x613b: // Win2 PC Camera
              case 0x613c: // PC Camera (SN9C120)
              case 0x613e: // PC Camera (SN9C120)
              case 0x6143: // PC Camera (SN9C120 + SP80708)
              case 0x6240: // PC Camera (SN9C201 + MI1300)
              case 0x6242: // PC Camera (SN9C201 + MI1310)
              case 0x6243: // PC Camera (SN9C201 + S5K4AAFX)
              case 0x6248: // PC Camera (SN9C201 + OV9655)
              case 0x624b: // PC Camera (SN9C201 + CX1332)
              case 0x624c: // PC Camera (SN9C201 + MI1320)
              case 0x624e: // PC Camera (SN9C201 + SOI968)
              case 0x624f: // PC Camera (SN9C201 + OV9650)
              case 0x6251: // PC Camera (SN9C201 + OV9650)
              case 0x6253: // PC Camera (SN9C201 + OV9650)
              case 0x6260: // PC Camera (SN9C201 + OV7670ISP)
              case 0x6262: // PC Camera (SN9C201 + OM6802)
              case 0x6270: // PC Camera (SN9C201 + MI0360/MT9V011 or MI0360SOC/MT9V111) U-CAM PC Camera NE878, Whitcom WHC017, ...
              case 0x627a: // PC Camera (SN9C201 + S5K53BEB)
              case 0x627b: // PC Camera (SN9C201 + OV7660)
              case 0x627c: // PC Camera (SN9C201 + HV7131R)
              case 0x627f: // PC Camera (SN9C201 + OV965x + EEPROM)
              case 0x6280: // PC Camera with Microphone (SN9C202 + MI1300)
              case 0x6282: // PC Camera with Microphone (SN9C202 + MI1310)
              case 0x6283: // PC Camera with Microphone (SN9C202 + S5K4AAFX)
              case 0x6288: // PC Camera with Microphone (SN9C202 + OV9655)
              case 0x628a: // PC Camera with Microphone (SN9C202 + ICM107)
              case 0x628b: // PC Camera with Microphone (SN9C202 + CX1332)
              case 0x628c: // PC Camera with Microphone (SN9C202 + MI1320)
              case 0x628e: // PC Camera with Microphone (SN9C202 + SOI968)
              case 0x628f: // PC Camera with Microphone (SN9C202 + OV9650)
              case 0x62a0: // PC Camera with Microphone (SN9C202 + OV7670ISP)
              case 0x62a2: // PC Camera with Microphone (SN9C202 + OM6802)
              case 0x62b0: // PC Camera with Microphone (SN9C202 + MI0360/MT9V011 or MI0360SOC/MT9V111)
              case 0x62b3: // PC Camera with Microphone (SN9C202 + OV9655)
              case 0x62ba: // PC Camera with Microphone (SN9C202 + S5K53BEB)
              case 0x62bb: // PC Camera with Microphone (SN9C202 + OV7660)
              case 0x62bc: // PC Camera with Microphone (SN9C202 + HV7131R)
              case 0x62be: // PC Camera with Microphone (SN9C202 + OV7663)
              case 0x62c0: // Sonix USB 2.0 Camera
              case 0x6300: // PC Microscope camera
              case 0x6310: // Sonix USB 2.0 Camera
              case 0x6340: // Camera
              case 0x6341: // Defender G-Lens 2577 HD720p Camera
              case 0x63e0: // Sonix Integrated Webcam
              case 0x63f1: // Integrated Webcam
              case 0x63f8: // Sonix Integrated Webcam
              case 0x6409: // Webcam // USB\Vid_0c45&Pid_6409
              case 0x6413: // Integrated Webcam
              case 0x6417: // Integrated Webcam
              case 0x6419: // Integrated Webcam
              case 0x641d: // 1.3 MPixel Integrated Webcam
              case 0x6433: // Laptop Integrated Webcam HD (Composite Device)
              case 0x643f: // Dell Integrated HD Webcam
              case 0x644d: // 1.3 MPixel Integrated Webcam
              case 0x6480: // Sonix 1.3 MP Laptop Integrated Webcam
              case 0x648b: // Integrated Webcam
              case 0x64bd: // Sony Visual Communication Camera
              case 0x64d0: // Integrated Webcam
              case 0x64d2: // Integrated Webcam
              case 0x651b: // HP Webcam
              case 0x6705: // Integrated HD Webcam
              case 0x6710: // Integrated Webcam
              case 0x8006: // Dual Mode Camera (8006 VGA)
              case 0x800a: // Vivitar Vivicam3350B
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x174f: // Syntek
            switch (IdProduct)
            {
              case 0x110b: // HP Webcam
              case 0x1403: // Integrated Webcam
              case 0x1404: // USB Camera device, 1.3 MPixel Web Cam
              case 0x5212: // USB 2.0 UVC PC Camera
              case 0x5a11: // PC Camera // USB\Vid_174f&Pid_5a11
              case 0x5a31: // Sonix USB 2.0 Camera
              case 0x5a35: // Sonix 1.3MPixel USB 2.0 Camera
              case 0x6a31: // Web Cam - Asus A8J, F3S, F5R, VX2S, V1S
              case 0x6a33: // Web Cam - Asus F3SA, F9J, F9S
              case 0x6a51: // 2.0MPixel Web Cam - Asus Z96J, Z96S, S96S
              case 0x6a54: // Web Cam
              case 0x6d51: // 2.0Mpixel Web Cam - Eurocom D900C
              case 0x8a12: // Syntek 0.3MPixel USB 2.0 UVC PC Camera
              case 0x8a33: // Syntek USB 2.0 UVC PC Camera
              case 0xa311: // 1.3MPixel Web Cam - Asus A3A, A6J, A6K, A6M, A6R, A6T, A6V, A7T, A7sv, A7U
              case 0xa312: // 1.3MPixel Web Cam
              case 0xa821: // Web Cam - Packard Bell BU45, PB Easynote MX66-208W
              case 0xaa11: // Web Cam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x17ef: // Lenovo
            switch (IdProduct)
            {
              case 0x1004: // Integrated Webcam
              case 0x4802: // Lenovo Vc0323+MI1310_SOC Camera
              case 0x4807: // UVC Camera
              case 0x480c: // Integrated Webcam
              case 0x480d: // Integrated Webcam [R5U877]
              case 0x480e: // Integrated Webcam [R5U877]
              case 0x480f: // Integrated Webcam [R5U877]
              case 0x4810: // Integrated Webcam [R5U877]
              case 0x4811: // Integrated Webcam [R5U877]
              case 0x4812: // Integrated Webcam [R5U877]
              case 0x4813: // Integrated Webcam [R5U877]
              case 0x4814: // Integrated Webcam [R5U877]
              case 0x4815: // Integrated Webcam [R5U877]
              case 0x4816: // Integrated Webcam
              case 0x481c: // Integrated Webcam
              case 0x481d: // Integrated Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x1bcf: // Sunplus Innovation Technology Inc.
            switch (IdProduct)
            {
              case 0x2880: // Dell HD Webcam
              case 0x2885: // ASUS Webcam
              case 0x2888: // HP Universal Camera
              case 0x28a2: // Dell Integrated Webcam
              case 0x28a6: // DELL XPS Integrated Webcam
              case 0x28ae: // Laptop Integrated Webcam HD
              case 0x28bd: // Dell Integrated HD Webcam
              case 0x2985: // Laptop Integrated Webcam HD
              case 0x2b83: // Laptop Integrated Webcam FHD
              case 0x2c18: // HD WebCam USB\VID_1BCF&PID_2C18&REV_0009&MI_00
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x2232: // Silicon Motion
            switch (IdProduct)
            {
              case 0x1005: // WebCam SCB-0385N
              case 0x1020: // WebCam  // USB\Vid_2232&Pid_1020
              case 0x1028: // WebCam SC-03FFL11939N // USB\Vid_2232&Pid_1028&Rev_0001
              case 0x1029: // WebCam SC-13HDL11939N
              case 0x1037: // WebCam SC-03FFM12339N
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x5986: // Acer, Inc
            switch (IdProduct)
            {
              case 0x0100: // Orbicam
              case 0x0101: // USB2.0 Camera
              case 0x0102: // Crystal Eye Webcam
              case 0x01a6: // Lenovo Integrated Webcam
              case 0x01a7: // Lenovo Integrated Webcam
              case 0x01a9: // Lenovo Integrated Webcam
              case 0x0200: // OrbiCam
              case 0x0203: // BisonCam NB Pro 1300
              case 0x0241: // BisonCam, NB Pro
              case 0x02d0: // Lenovo Integrated Webcam [R5U877]
              case 0x03d0: // Lenovo Integrated Webcam [R5U877]
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0x8086: // Intel Corp.
            switch (IdProduct)
            {
              case 0x0110: // Easy PC Camera
              case 0x0120: // PC Camera CS120
              case 0x0630: // Pocket PC Camera
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        case 0xeb1a: // eMPIA Technology, Inc.
            switch (IdProduct)
            {
              case 0x2571: // M035 Compact Web Cam
              case 0x2710: // SilverCrest Webcam
              case 0x2750: // ECS Elitegroup G220 integrated Webcam
              case 0x2761: // EeePC 701 integrated Webcam
                  Result = TRUE;
                  break;
              default:
                  break;
            }
            break;

        default:
            break;
    }

    DPRINT1("USBH_IsVidPidFromBlackList: Result - %X\n", Result);

    return Result;
}

