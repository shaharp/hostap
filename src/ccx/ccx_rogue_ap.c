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
#include "ccx_rogue_ap.h"
#include "../../wpa_supplicant/config_ssid.h"
#include "drivers/driver.h"

BOOL ccx_rogueap_add(struct wpa_supplicant * pstWpaSupp, const BYTE * pbBssid, CCX_ROGUEAP_FAIL_REASON_t eReason)
{
    struct CCX_ROGUEAP_LIST_s * pstItem = NULL;
    BOOL bFound = FALSE;

	wpa_printf(MSG_INFO, "CCX: RogueAP Add(" MACSTR ", %04X)", MAC2STR(pbBssid), (unsigned short) eReason);

    /* Params validation */
    if ( NULL == pstWpaSupp ) {
        return FALSE;
    }
    if ( NULL == pbBssid ) {
        return FALSE;
    }

    /* Calls the driver Function. */
    if ( (NULL != pstWpaSupp->driver) && (NULL != pstWpaSupp->driver->ccx_rogueap_add) ) {
        pstWpaSupp->driver->ccx_rogueap_add(pstWpaSupp->drv_priv, pbBssid, (WORD) eReason);
    }

    /* Nothing in list, creates new. */
    if ( NULL == pstWpaSupp->pstRogueApList ) {
        pstWpaSupp->pstRogueApList = (struct CCX_ROGUEAP_LIST_s *) os_malloc(sizeof(struct CCX_ROGUEAP_LIST_s));
        if ( NULL == pstWpaSupp->pstRogueApList ) {
            return FALSE;
        }

        pstItem = pstWpaSupp->pstRogueApList;
    } else {
        /* Enumerates the Items */
        bFound = FALSE;
        pstItem = pstWpaSupp->pstRogueApList;
        while (NULL != pstItem->pstNext) {
            if ( 0 == os_memcmp(pstItem->abBssid, pbBssid, ETH_ALEN) ) {
                bFound = TRUE;
                break;
            }
            pstItem = pstItem->pstNext;
        }

        if ( FALSE == bFound ) {
            /* BSSID is not Present
             so pstItem points at the last item.*/

            /* Allocation new item */
            pstItem->pstNext = (struct CCX_ROGUEAP_LIST_s *) os_malloc(sizeof(struct CCX_ROGUEAP_LIST_s));
            if ( NULL == pstItem->pstNext ) {
                return FALSE;
            }

            /* Pointing pstItem to New Child. */
            pstItem = pstItem->pstNext;
            pstItem->pstNext = NULL;
        }
    }

    /* Filling the Params. */
    os_memcpy(pstItem->abBssid, pbBssid, ETH_ALEN);
    pstItem->eReason = eReason;
    return TRUE;
}

BOOL ccx_rogueap_add_self(struct wpa_supplicant * pstWpaSupp, CCX_ROGUEAP_FAIL_REASON_t eReason)
{
    return ccx_rogueap_add(pstWpaSupp, pstWpaSupp->bssid, eReason);
}

BOOL ccx_rogueap_remove(struct wpa_supplicant * pstWpaSupp, const BYTE * pbBssid)
{
    struct CCX_ROGUEAP_LIST_s * pstPrev = NULL;
    struct CCX_ROGUEAP_LIST_s * pstCurrent = NULL;

    /* Params validation */
    if ( NULL == pstWpaSupp ) {
        return FALSE;
    }
    if ( NULL == pbBssid ) {
        return FALSE;
    }

	wpa_printf(MSG_INFO, "CCX: RogueAP Remove(" MACSTR ")", MAC2STR(pbBssid));

    /* Calls the driver function */
    if ( (NULL != pstWpaSupp->driver) && (NULL != pstWpaSupp->driver->ccx_rogueap_remove) ) {
        pstWpaSupp->driver->ccx_rogueap_remove(pstWpaSupp->drv_priv, pbBssid);
    }

    pstPrev = NULL;
    pstCurrent = pstWpaSupp->pstRogueApList;
    while ( NULL != pstCurrent ) {
        if ( 0 == os_memcmp(pstCurrent->abBssid, pbBssid, ETH_ALEN) ) {
            break;
        }

        pstPrev = pstCurrent;
        pstCurrent = pstCurrent->pstNext;
    }
    if ( NULL == pstCurrent ) {
        /* Element not found */
        return FALSE;
    }

    if ( NULL == pstPrev ) {
        /* this is the First item ( Linked in wpa_supplicant ) */
        pstWpaSupp->pstRogueApList = pstCurrent->pstNext;
        os_free(pstCurrent);
        return TRUE;
    }

    /* Links out Current */
    pstPrev->pstNext = pstCurrent->pstNext;
    os_free(pstCurrent);
    return TRUE;
}

BOOL ccx_rogueap_remove_self(struct wpa_supplicant * pstWpaSupp) {
    return ccx_rogueap_remove(pstWpaSupp, pstWpaSupp->bssid);
}

BOOL _ccx_rogueap_report_single(struct CCX_ROGUEAP_LIST_s * pstItem, struct l2_packet_data * pstL2, const BYTE * pbSourceAddr, const BYTE * pbDestAddr)
{
    struct CCX_ROGUEAP_REPORT_PACKET_s stPacket;
    memset(&stPacket, 0, sizeof(stPacket));

    /* Length is only bytes after Length (Starts with bMessageType); */
    WORD wPacketLength = (sizeof(stPacket) - ((BYTE *)(&(stPacket.bMessageType)) - (BYTE *)(&stPacket)));

    /* Building the packet */
    os_memcpy(stPacket.abSnapHeader, CCX_ROGUEAP_SNAP_HEADER_VALUE, CCX_ROGUEAP_SNAP_HEADER_LENGTH);
    stPacket.wLength       = htons(wPacketLength);
    stPacket.bFunctionCode = CCX_ROGUEAP_REPORT_FUNCTION_CODE;
    stPacket.bMessageType  = CCX_ROGUEAP_REPORT_MESSAGE_TYPE;
    os_memcpy(stPacket.abDestAddress, pbDestAddr, ETH_ALEN);
    os_memcpy(stPacket.abSourceAddress, pbSourceAddr, ETH_ALEN);
    stPacket.wFailureReason = htons(pstItem->eReason);
    os_memcpy(stPacket.abRogueApAddress, pstItem->abBssid, ETH_ALEN);

    /* Sending the packet */
    if ( l2_packet_send(pstL2, pbDestAddr, sizeof(stPacket), (BYTE *) &stPacket, sizeof(stPacket)) < 0 ) {
        return FALSE;
    }
    return TRUE;
}

BOOL ccx_rogueap_send_list(struct wpa_supplicant * pstWpaSupp)
{
    BOOL bRetVal = TRUE;
    struct CCX_ROGUEAP_LIST_s * pstCurrentItem = NULL;

    /* Params validation */
    if ( NULL == pstWpaSupp ) {
        return FALSE;
    }

	wpa_printf(MSG_INFO, "CCX: RogueAP About to RogueAP list");
    if ( (NULL == pstWpaSupp->current_ssid) || ( FALSE == pstWpaSupp->current_ssid->leap ) ) {
        /* Shouldn't send (On non-LEAP).
         And can't send if current SSID is null. */
        return FALSE;
    }

    /* Calls the driver function */
    if ( (NULL != pstWpaSupp->driver) && (NULL != pstWpaSupp->driver->ccx_rogueap_send_list) ) {
        // This time, i don't want to send list twice, so if driver has the function
        // i'll give him to do it, else i'll.
        if ( pstWpaSupp->driver->ccx_rogueap_send_list(pstWpaSupp->drv_priv) < 0 ) {
            return FALSE;
        }

        return TRUE;
    }

    pstCurrentItem = pstWpaSupp->pstRogueApList;
    while(NULL != pstCurrentItem) {
        bRetVal = bRetVal & _ccx_rogueap_report_single(pstCurrentItem, pstWpaSupp->l2, pstWpaSupp->own_addr, pstWpaSupp->bssid);
        pstCurrentItem = pstCurrentItem->pstNext;
    }

    return bRetVal;
}

BOOL ccx_rogueap_clean_list(struct wpa_supplicant * pstWpaSupp)
{
    struct CCX_ROGUEAP_LIST_s * pstCurItem = NULL;
    struct CCX_ROGUEAP_LIST_s * pstItemToFree = NULL;

    if ( NULL == pstWpaSupp ) {
        return FALSE;
    }

    /* Calls the driver function */
    if ( (NULL != pstWpaSupp->driver) && (NULL != pstWpaSupp->driver->ccx_rogueap_clean_list) ) {
        pstWpaSupp->driver->ccx_rogueap_clean_list(pstWpaSupp->drv_priv);
    }

    /* Freeing all Blocks. */
    pstCurItem = pstWpaSupp->pstRogueApList;
    while ( NULL != pstCurItem ) {
        /* First getting the address of current item. */
        pstItemToFree = pstCurItem;

        /* Gets next item */
        pstCurItem = pstCurItem->pstNext;

        /* Freeing current. */
        os_free(pstItemToFree);
    }

    /* NULLing the Rogue AP list. */
    pstWpaSupp->pstRogueApList = NULL;
    return TRUE;
}

#endif /* TI_CCX */
