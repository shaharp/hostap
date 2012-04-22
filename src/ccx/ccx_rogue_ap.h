/***************************************************************************
**+----------------------------------------------------------------------+**
**|                                ****                                  |**
**|                                ****                                  |**
**|                                ******o***                            |**
**|                          ********_///_****                           |**
**|                           ***** /_//_/ ****                          |**
**|                            ** ** (__/ ****                           |**
**|                                *********                             |**
**|                                 ****                                 |**
**|                                  ***                                 |**
**|                                                                      |**
**|     Copyright (c) 1998 - 2012 Texas Instruments Incorporated         |**
**|                        ALL RIGHTS RESERVED                           |**
**|                                                                      |**
**| Permission is hereby granted to licensees of Texas Instruments       |**
**| Incorporated (TI) products to use this computer program for the sole |**
**| purpose of implementing a licensee product based on TI products.     |**
**| No other rights to reproduce, use, or disseminate this computer      |**
**| program, whether in part or in whole, are granted.                   |**
**|                                                                      |**
**| TI makes no representation or warranties with respect to the         |**
**| performance of this computer program, and specifically disclaims     |**
**| any responsibility for any damages, special or consequential,        |**
**| connected with the use of this program.                              |**
**|                                                                      |**
**+----------------------------------------------------------------------+**
***************************************************************************/

#ifdef TI_CCX
#ifndef __CCX_ROGUE_AP_INCLUDED__
#define __CCX_ROGUE_AP_INCLUDED__

#include "ccx.h"
#include "l2_packet/l2_packet.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"

/** Defines **/
#define CCX_ROGUEAP_SNAP_HEADER_VALUE    ("\xAA\xAA\x03\x00\x40\x96\x00\x00")
#define CCX_ROGUEAP_SNAP_HEADER_LENGTH   (sizeof(CCX_ROGUEAP_SNAP_HEADER_VALUE))
#define CCX_ROGUEAP_REPORT_MESSAGE_TYPE  (0x40)
#define CCX_ROGUEAP_REPORT_FUNCTION_CODE (0x8e)
#define CCX_ROGUEAP_TIMEOUT              (60)

/* TODO : Check Endian for those Values */
typedef enum CCX_ROGUEAP_FAIL_REASON_e {
    CCX_ROGUEAP_FAIL_REASON_INVALID = 0x0001,       /* Invalid authentication type */
    CCX_ROGUEAP_FAIL_REASON_AUTH_TIMEOUT = 0x0002,  /* Authentication timeout */
    CCX_ROGUEAP_FAIL_REASON_FAUTH_FAILED = 0x0003,  /* Challenge from AP failed */
    CCX_ROGUEAP_FAIL_REASON_TAUTH_FAILED = 0x0004,  /* Challenge to AP failed */
} CCX_ROGUEAP_FAIL_REASON_t;

/** Structures **/
// Makes sure the Packing of the structe is minimal
#pragma pack(push, 1)
// Packet as defined in Cisco CCX Doc Rev 1.6
struct CCX_ROGUEAP_REPORT_PACKET_s {
	BYTE abSnapHeader[CCX_ROGUEAP_SNAP_HEADER_LENGTH];   /* Static (CCX_ROGUEAP_SNAP_HEADER_VALUE) */
	WORD wLength;                                       /* Htons of all fields after Length. */
	BYTE bMessageType;                                  /* Static (CCX_ROGUEAP_REPORT_MESSAGE_TYPE) */
	BYTE bFunctionCode;                                 /* Static (CCX_ROGUEAP_REPORT_FUNCTION_CODE) */
	BYTE abDestAddress[ETH_ALEN];
	BYTE abSourceAddress[ETH_ALEN];
	WORD wFailureReason;                                /* htons of CCX_ROGUEAP_FAIL_REASON_t. */
	BYTE abRogueApAddress[ETH_ALEN];
	BYTE abRogueApName[16];                             /* NULLs */
};

/* Linked list of Rogue APs */
struct CCX_ROGUEAP_LIST_s {
    BYTE abBssid[ETH_ALEN];
	CCX_ROGUEAP_FAIL_REASON_t eReason;
    struct CCX_ROGUEAP_LIST_s * pstNext;
};
/* Returns old packing. */
#pragma pack(pop)


/* FW Decleration of the structs */
struct wpa_supplicant; // wpa_supplicant_i.h

/*
 * This function will Add target BSSID to the RogueAP List.
 * Params :
 * pstWpaSupp => Pointer to wpa_supplicant struct.
 * pbBssid    => Target Bssid you want to ban.
 * eReason    => Reason for banning the AP.
 */
BOOL ccx_rogueap_add(struct wpa_supplicant * pstWpaSupp, const BYTE * pbBssid, CCX_ROGUEAP_FAIL_REASON_t eReason);

/*
 * this function will add self BSSID to RogueAP List.
 * This function is only a wrapper for ccx_rogueap_add.
 */
BOOL ccx_rogueap_add_self(struct wpa_supplicant * pstWpaSupp, CCX_ROGUEAP_FAIL_REASON_t eReason);

/*
 * this function will Remove target BSSID from RogueAP List.
 * Params :
 * pstWpaSupp => Pointer to wpa_supplicant struct.
 * pbBssid    => Target Bssid you want to unban.
 */
BOOL ccx_rogueap_remove(struct wpa_supplicant * pstWpaSupp, const BYTE * pbBssid);

/*
 * this function will Remove self BSSID from RogueAP List.
 * this function is only a wrapper for ccx_rogueap_remove.
 */
BOOL ccx_rogueap_remove_self(struct wpa_supplicant * pstWpaSupp);

/*
 * this function will clear all Rogue AP List.
 * Params :
 * pstWpaSupp => Pointer to wpa_supplicant struct.
 */
BOOL ccx_rogueap_clean_list(struct wpa_supplicant * pstWpaSupp);

/*
 * This function will send single report packet.
 * Params :
 * pstItem      => Pointer to target Rogue ap you want to report on.
 * pstL2        => l2 packet data from wpa_supplicant struct.
 * pbSourceAddr => Source Address (Client Address)
 * pbDestAddr   => Address of the ap you report to.
 */
BOOL _ccx_rogueap_report_single(struct CCX_ROGUEAP_LIST_s * pstItem, struct l2_packet_data * pstL2, const BYTE * pbSourceAddr, const BYTE * pbDestAddr);

/*
 * This function will send report of all the Rogue AP List.
 * Params :
 * pstWpaSupp => Pointer to wpa_supplicant struct.
 *
 * TODO : Elad sayed something about Fowared To driver,
 * But Aviram says its localy only.
 */
BOOL ccx_rogueap_send_list(struct wpa_supplicant * pstWpaSupp);

#endif /*__CCX_ROGUE_AP_INCLUDED__*/
#endif /* TI_CCX */
