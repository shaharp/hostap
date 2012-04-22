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

#include "ccx.h"
#include "common/wpa_common.h"
#include "common/ieee802_11_defs.h"
#include "common/defs.h"
#include "utils/common.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_i.h"
#include "rsn_supp/wpa_ie.h"
#include "rsn_supp/pmksa_cache.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "drivers/driver.h"
#include "../../wpa_supplicant/driver_i.h"
#include "../../wpa_supplicant/scan.h"
#include "l2_packet/l2_packet.h"
#include "eloop.h"
#include "../../wpa_supplicant/blacklist.h"

const u8 CISCO_AIRONET_SNAP_HEADER[8] = {0xAA, 0xAA, 0x03, 0x00, 0x40, 0x96,
											0x00, 0x00};

/* CCX packet filter definition */
static struct sock_filter ccx_filter_insns[] = {

        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 14),			 /* load ethernet type	   */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, L2_SNAP, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),					     /* no, drop		   */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 16),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, L2_CMD, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),					     /* no, drop		   */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 17),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CCX_OUI_0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),					     /* no, drop		   */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 18),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CCX_OUI_1, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),					     /* no, drop		   */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 19),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CCX_OUI_2, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),					     /* no, drop		   */
        BPF_STMT(BPF_RET+BPF_K, (u32) -1),			 /* yes, return all packet */
};

static struct sock_fprog ccx_filter = {
	.len = sizeof(ccx_filter_insns)/sizeof(ccx_filter_insns[0]),
	.filter = ccx_filter_insns,
};

inline int ieee80211_channel_to_frequency(int chan, int band_5ghz)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (band_5ghz == 1) {
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
	} else { /* IEEE80211_BAND_2GHZ */
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		else
			return 0; /* not supported */
	}
}

inline int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else
		return (freq - 5000) / 5;
}


int ccx_init(struct wpa_supplicant *wpa_s, const u8* mac_addr)
{
	int i;
	wpa_s->ccx_l2 = l2_packet_init(wpa_s->ifname,
			   mac_addr,
			   ETH_P_ALL,
			   ccx_recv, wpa_s, 1);

	if (wpa_s->ccx_l2 == NULL)
		return -1;

	os_memset(wpa_s->prev_bssid, 0 , ETH_ALEN);
	for (i = 0; i < 8; i++)
		wpa_s->tspec_ie[i] = NULL;

	wpa_s->pstRogueApList = NULL;

	l2_packet_set_filter(wpa_s->ccx_l2, &ccx_filter);
	return 0;
}

void ccx_recv(void *ctx, const u8 *src_addr,
	     const u8 *buff, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	wpa_hexdump(MSG_DEBUG, "wpa_rx_ccx", (u8*)buff, len);

	if (!buff || !len || os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) != 0){
		return;
	}

	if (os_memcmp(buff+14, CISCO_AIRONET_SNAP_HEADER, 8) != 0) {
		return;
	}

	ccx_iapp_packet_handler(wpa_s, buff, len);
}

void ccx_iapp_packet_handler(struct wpa_supplicant* wpa_s, const u8* buff, size_t len){

	ccx_parse_iapp_packet(wpa_s, buff, len);
}

int ccx_handle_radio_measurement(struct wpa_supplicant* wpa_s,
		struct iapp_frame *frame) {

	struct ccx_measurement_request *request;
	int left;
	u16 length;
	int ret;

	if (!frame || frame->hdr.iapp_subtype != IAPP_SUBTYPE_RM_REQUEST)
		return -1;

	length = ((frame->hdr.iapp_id_length & 0xff) << 8) +
					((frame->hdr.iapp_id_length & 0xff00) >> 8);

	wpa_s->measurement_request_frame = os_malloc(length + 22);
		os_memcpy(wpa_s->measurement_request_frame, frame, length + 22);

	left = length - 16;

	request = (struct ccx_measurement_request*)wpa_s->measurement_request_frame->body;
	left -= 4;

	os_get_time(&wpa_s->scan_request_ts);
	ret = ccx_handle_next_request_ie(wpa_s,
			(struct ccx_measurement_request_ie*)request->measurement_request_ie, left);

	if ( ret < 0) {
		os_free(wpa_s->measurement_request_frame);
		return -1;
	} else if (ret == 0) { /* no more IEs left ==> this is the last measurement */
		wpa_s->measurement_complete = 1;
	}

	wpa_s->is_measurement_in_progress = 1;
	return 0;

}

static void ccx_measurement_beacon_table(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant*)eloop_ctx;
	struct wpa_scan_results *scan_res = (struct wpa_scan_results*)timeout_ctx;

	ccx_measurement_beacon_scan_complete(wpa_s, scan_res);
}


int ccx_handle_next_request_ie(struct wpa_supplicant *wpa_s,
		struct ccx_measurement_request_ie* request_ie,	int left)
{
	struct ccx_measurement_request_ie* curr_ie;
	u8* pos = (u8*) request_ie;

	while (left > 0) {
		curr_ie = (struct ccx_measurement_request_ie*)pos;
		if (request_ie->hdr.length + 4 > left)
			return -1;

		left -= curr_ie->hdr.length + 4;
		pos += curr_ie->hdr.length + 4;

		wpa_s->measurement_request_left = left;
		wpa_s->measurement_request_pos = pos;

		if (curr_ie->hdr.id != CCX_MEASUREMENT_REQ_ID)
			continue;

		switch (curr_ie->hdr.type) {
		case CCX_MSR_TYPE_BEACON: {
			int band_5ghz = (curr_ie->channel <= 14) ? 0 : 1;
			struct wpa_driver_scan_params params;
			os_memset(&params, 0, sizeof(params));
			params.freqs = os_zalloc(2 * sizeof(int));
			params.freqs[0] = ieee80211_channel_to_frequency(curr_ie->channel, band_5ghz);

			wpa_dbg(wpa_s, MSG_DEBUG, "CCX: %s: channel = %d, mode = %d, duration = %d\n", __FUNCTION__,
					curr_ie->channel, curr_ie->hdr.mode, curr_ie->duration);

			if (curr_ie->scan_mode == CCX_MEASUREMENT_PASSIVE_SCAN) {
				params.num_ssids = 0;

			} else if (curr_ie->scan_mode == CCX_MEASUREMENT_ACTIVE_SCAN) {
				params.num_ssids = 1;
				params.ssids[0].ssid_len = 0;
				params.ssids[0].ssid = NULL;

			} else if (curr_ie->scan_mode == CCX_MEASUREMENT_BEACON_TABLE) {
				struct wpa_scan_results *scan_res =
						wpa_drv_get_scan_results2(wpa_s);
				eloop_register_timeout(0, 100, ccx_measurement_beacon_table, wpa_s, scan_res);
				break;
			}

			params.min_dwell_time = curr_ie->duration * 1024;
			params.max_dwell_time = curr_ie->duration * 1024;

			/*wpa_s->measurement_scanning = 1;
			os_get_time(&wpa_s->scan_request_ts);*/
			os_memcpy(&wpa_s->request_in_progress , curr_ie, curr_ie->hdr.length+4);
			wpa_supplicant_trigger_scan(wpa_s, &params);
			return left;
			break;
		}
		break;

		default:
			wpa_dbg(wpa_s, MSG_DEBUG, "CCX: radio measurement request of type"
					" %d is not currently supported", request_ie->hdr.type);
			break;
		}
	}

	return left;
}

int ccx_parse_iapp_packet(struct wpa_supplicant* wpa_s, const u8* buff, size_t len){

	struct iapp_frame *frame = (struct iapp_frame*)buff;

	switch (frame->hdr.iapp_type) {
	case IAPP_TYPE_RADIO_MEASUREMENT:
		return ccx_handle_radio_measurement(wpa_s, frame);
	default:
		return -1;
	}
	return 0;
}

int ccx_measurement_beacon_scan_complete(struct wpa_supplicant *wpa_s,
		struct wpa_scan_results *scan_res)
{
	int ret;
	if (!wpa_s->is_measurement_in_progress)
		return -1;

	if (wpa_s->request_in_progress.hdr.type != CCX_MSR_TYPE_BEACON)
		return -1;

/*	wpa_ccx_handle_beacon_request(wpa_s, wpa_s->request_in_progress);*/

	if (wpa_s->measurement_complete) {

		int len, l;
		struct iapp_frame* frame;
		/* build measurement report */
		frame = ccx_build_measurement_report(wpa_s, &len, scan_res);
		/* send measurement report */
		l2_packet_send(wpa_s->ccx_l2, frame->hdr.dest_mac_addr, 0, (u8*)frame,
				len);

		for (l = 0; l < len; l += 20)
		{
			wpa_hexdump(MSG_DEBUG, "CCX: MEASUREMENT REPORT", ((u8*)frame)+l,20);
		}

		/* clear all the measurement's data*/
		wpa_s->is_measurement_in_progress = 0;
		wpa_s->measurement_complete = 0;
		wpa_s->measurement_request_left = 0;
		wpa_s->measurement_request_pos = NULL;
		os_free(wpa_s->measurement_request_frame);

		return 0;
	}

	ret = ccx_handle_next_request_ie(wpa_s,
			(struct ccx_measurement_request_ie*)wpa_s->measurement_request_pos,
			wpa_s->measurement_request_left);

	if (ret < 0) {
		return -1;
	} else if (ret == 0) { /* no more IEs left ==> this is the last measurement */
		wpa_s->measurement_complete = 1;
	}

	wpa_s->is_measurement_in_progress = 1;
	return 0;

}

struct iapp_frame* ccx_build_measurement_report(struct wpa_supplicant* wpa_s,
		int* len, struct wpa_scan_results *scan_res) {

	int request_length, left;
	u8* pos;
	/*struct wpa_scan_results *scan_res;*/
	struct ccx_measurement_report *report;
	struct ccx_measurement_request *request;
	struct iapp_frame *frame = os_zalloc(sizeof(struct iapp_frame) +
			MAX_CCX_MEASUREMENT_REPORT);
	int length_left = MAX_CCX_MEASUREMENT_REPORT;
	int offset = 0;
	if (frame == NULL) {
		return NULL;
	}

	*len = wpa_ccx_build_iapp_hdr(wpa_s, frame, 0x32, 0x81);

	request = (struct ccx_measurement_request*)
			wpa_s->measurement_request_frame->body;
	report = (struct ccx_measurement_report*)frame->body;
	report->dialog_token = request->dialog_token;

	*len += 2;

	/*scan_res = wpa_drv_get_scan_results2(wpa_s);*/
	request_length = ((wpa_s->measurement_request_frame->hdr.iapp_id_length & 0xff) << 8) +
					((wpa_s->measurement_request_frame->hdr.iapp_id_length & 0xff00) >> 8);
	left = request_length - 20; /* length(2) + type(1) + subtype(1) + dest_mac(6) + source_mac(6) = 20*/
	/* loop through all the elements in the measurement request */
	pos = request->measurement_request_ie;
	while (left > 0)
	{
		struct ccx_measurement_request_ie* curr_ie;
		int length_added;
		curr_ie = (struct ccx_measurement_request_ie*)pos;

		length_added = wpa_ccx_build_beacon_report(wpa_s,
				(struct ccx_measurement_request_ie*)pos,
				scan_res, ((u8*)(report->report_ie))+offset, length_left);
		*len += length_added;
		offset += length_added;
		length_left -= length_added;
		left -= curr_ie->hdr.length + 4;
		pos += curr_ie->hdr.length + 4;
	}

	frame->hdr.iapp_id_length = *len - 22; /*dest mac (6) + src mac (6) + spare (2) + snap hdr (8) = 22 */
	frame->hdr.iapp_id_length = be_to_host16(frame->hdr.iapp_id_length);
	return frame;
}

int wpa_ccx_build_iapp_hdr(struct wpa_supplicant *wpa_s,
		struct iapp_frame *frame, u8 type, u8 subtype)
{

	os_memcpy(frame->hdr.dst_addr, wpa_s->bssid, ETH_ALEN);
	os_memcpy(frame->hdr.src_addr, wpa_s->own_addr, ETH_ALEN);
	frame->hdr.spare = 0x0;
	os_memcpy(frame->hdr.snap_header, CISCO_AIRONET_SNAP_HEADER, 8);
	frame->hdr.iapp_id_length = 16; /* length of fixed header elements */
	frame->hdr.iapp_type = type; /*0x32*/
	frame->hdr.iapp_subtype = subtype; /*0x81*/
	os_memcpy(frame->hdr.dest_mac_addr, wpa_s->bssid, ETH_ALEN);
	os_memcpy(frame->hdr.source_mac_addr, wpa_s->own_addr, ETH_ALEN);

	return sizeof(struct iapp_hdr);
}

int wpa_ccx_build_beacon_report(struct wpa_supplicant *wpa_s,
		struct ccx_measurement_request_ie *req_ie,
		struct wpa_scan_results *scan_res,
		u8* buff, int length_limit) {

	u8 *pos;
	struct ccx_measurement_report_ie *report_ie =
			(struct ccx_measurement_report_ie*)buff;
	int len = 0, i, ies_len = 0;

	if (scan_res == NULL) {
		wpa_dbg(wpa_s, MSG_DEBUG, "CCX: FAIL scan results == NULL");
		return -1;
	}

	pos = (u8*)report_ie;

	for (i = 0; i < scan_res->num; i++) {
		const u8 element_to_add_ids[] = { WLAN_EID_SSID,
				WLAN_EID_SUPP_RATES, WLAN_EID_FH_PARAMS,
				WLAN_EID_DS_PARAMS, WLAN_EID_CF_PARAMS,
				WLAN_EID_IBSS_PARAMS, WLAN_EID_TIM, WLAN_EID_VENDOR_SPECIFIC };
		int j;

		if (req_ie->scan_mode != CCX_MEASUREMENT_BEACON_TABLE
				 && req_ie->channel != ieee80211_frequency_to_channel(scan_res->res[i]->freq))
			continue;

		{
			u8 temp_buff[1000];
			u8* p_temp = temp_buff;
			struct ccx_measurement_report_ie *ie =
					(struct ccx_measurement_report_ie*)p_temp;
			struct ccx_beacon_report *beacon_report =
					(struct ccx_beacon_report *)ie->measurement_report;
			struct wpa_scan_res *curr_res;

			curr_res = scan_res->res[i];
			/* ignore old results */
			if (req_ie->scan_mode != CCX_MEASUREMENT_BEACON_TABLE) {
				struct os_time now, received_time, age_t;
				os_get_time(&now);
				age_t.sec = curr_res->age / 1000;
				age_t.usec = (curr_res->age % 1000) * 1000;
				os_time_sub(&now, &age_t, &received_time);
				if (os_time_before(&received_time, &wpa_s->scan_request_ts))
					continue;
			}

			const u8 *beacon_ie = NULL;
			ie->hdr.id = 39; /* measurement report ie  */
			ie->hdr.length = 32; /* length of fixed fields */
			ie->hdr.token = req_ie->hdr.token;
			ie->hdr.mode = req_ie->hdr.mode;
			ie->hdr.type = req_ie->hdr.type;

			beacon_report->channel = ieee80211_frequency_to_channel(curr_res->freq);
			beacon_report->spare = 0;
			beacon_report->duration = req_ie->duration;

			beacon_report->phy_type = 0;
			beacon_report->received_signal_pwr = curr_res->level;
			os_memcpy(beacon_report->bssid, curr_res->bssid, ETH_ALEN);
			beacon_report->parent_tsf = curr_res->tsf;
			beacon_report->target_tsf = curr_res->tsf;
			beacon_report->beacon_interval = curr_res->beacon_int;
			beacon_report->capability_info = curr_res->caps;

			p_temp = (u8*)beacon_report->received_elements;
			for (j = 0; j < sizeof(element_to_add_ids); j++)
			{
				beacon_ie = wpa_scan_get_ie(curr_res, element_to_add_ids[j]);
				if (beacon_ie) {
					os_memcpy(p_temp, beacon_ie, beacon_ie[1] + 2);
					ie->hdr.length += beacon_ie[1] + 2;
					p_temp += beacon_ie[1] + 2;
				}
			}

			if (ie->hdr.length+2 + ies_len > length_limit)
			{
				wpa_dbg(wpa_s, MSG_DEBUG, "CCX: BEACON report: max size limit reached (%d bytes)\n", ies_len);
				break;
			}
			os_memcpy(pos, temp_buff, p_temp-temp_buff);
			pos += p_temp-temp_buff;
			ies_len += ie->hdr.length+2;
			{
				const u8* ssid_ie = wpa_scan_get_ie(curr_res, WLAN_EID_SSID);
				u8 ssid[32] = {0};
				os_memcpy(ssid, ssid_ie+2, ssid_ie[1]);
				wpa_dbg(wpa_s, MSG_DEBUG,"CCX: added to report: SSID %s,\t"
				"channel %d\t"
				"BSSID "MACSTR"\n",
				ssid, ieee80211_frequency_to_channel(curr_res->freq),
				MAC2STR(beacon_report->bssid));
			}
		}
	}
	len = pos - buff;

	return len;
}

/* TODO : Check this OUI */
static const BYTE CCKM_OUI_TYPE[] = { 0x00, 0x40, 0x96, 0x00 };
int ccx_create_cckm_reassoc_req(struct wpa_supplicant* pstWpaSupp,
               BYTE * pbWpaIe, DWORD dwWpaIeLen, BYTE* pbTimestamp, BYTE* pbBssid,
               BYTE* pbCCKMRequest, DWORD dwCCKMRequestLen) {

       struct wpa_sm* pstSm = pstWpaSupp->wpa;
       const BYTE* pabAddresses[5] = { 0 };
       DWORD adwLengths[5] = { 0 };
       BYTE abMd5Hash[MD5_HASH_SIZE];
       BYTE abShaHash[SHA1_HASH_SIZE];
       int iWpaIeId;
       BYTE abWpaLe32[4] = { 0 };
       BYTE* pbPosition = NULL;

       wpa_printf(MSG_DEBUG, "CCKM: Creating Reassoction Request");

       iWpaIeId = *pbWpaIe;

       wpa_printf(MSG_DEBUG, "CCKM: ccx_create_cckm_reassoc_req: "
				"Wpa IE ID: %d", iWpaIeId);

       pstSm->ccx.RN++;
       pabAddresses[0] = pstSm->own_addr;
       adwLengths[0] = ETH_ALEN;

       BYTE* a = pbBssid;
       wpa_printf(MSG_DEBUG, "CCKM: bssid is " MACSTR, MAC2STR(a));
       pabAddresses[1] = pbBssid ? pbBssid : pstSm->bssid;

       a = pstSm->bssid;
       wpa_printf(MSG_DEBUG, "CCKM: sm is " MACSTR, MAC2STR(a));
       adwLengths[1] = ETH_ALEN;

       pabAddresses[2] = pbWpaIe;
       adwLengths[2] = dwWpaIeLen;

       pabAddresses[3] = pbTimestamp;
       adwLengths[3] = 8;

       WPA_PUT_LE32(abWpaLe32, pstSm->ccx.RN);
       pabAddresses[4] = abWpaLe32;
       adwLengths[4] = sizeof(DWORD);

       if (iWpaIeId == 48) /* WPA2 */
       {
               hmac_sha1_vector(pstSm->ccx.gk.krk, sizeof(pstSm->ccx.gk.krk), 5,
                               pabAddresses, adwLengths, abShaHash);
       }
       else
       {
               hmac_md5_vector(pstSm->ccx.gk.krk, sizeof(pstSm->ccx.gk.krk), 5,
                               pabAddresses, adwLengths, abMd5Hash);
       }

       /* Compose CCKM request */
       os_memset(pbCCKMRequest, 0, CCKM_REQUEST_SIZE);
       pbPosition = pbCCKMRequest;

       /* Byte 1 */
       *pbPosition++ = CCKM_ELEMENT_ID;

       /* Byte 2 */
       *pbPosition++ = 24;

       /* Bytes 3-6 */
       os_memcpy(pbPosition, CCKM_OUI_TYPE,4);
       pbPosition += 4;

       /* Bytes 7-14 */
       os_memcpy(pbPosition,(BYTE*)pbTimestamp,8);
       pbPosition += 8;

       /* Bytes 15-18 */
       os_memcpy(pbPosition,abWpaLe32,4);
       pbPosition += 4;

       /* Bytes 19-26 */
       if (iWpaIeId == 48) /* WPA2 */
       {
               os_memcpy(pbPosition,(BYTE*)&abShaHash,8);
       }
       else
       {
               os_memcpy(pbPosition,(BYTE*)&abMd5Hash,8);
       }
       pbPosition += 8;

       return pbPosition - pbCCKMRequest;
}

int ccx_parse_cckm_response(struct wpa_supplicant* pstWpaSupp,
		const BYTE* pbResponseIes, DWORD dwResponseIesLen) {
	BYTE abBssid[ETH_ALEN] = { 0 };
	const BYTE *pbPosition = NULL;
	const BYTE *pbCCKM = NULL;
	DWORD dwLength = 0;
	DWORD dwIndex = 0;
	const struct ccx_aironet_ie *pstAironetIe = { 0 };
	struct wpa_sm* pstSm = pstWpaSupp->wpa;
	BYTE* pbOwnAddress = pstWpaSupp->own_addr;

	if (NULL == pstWpaSupp->driver->get_bssid) {
		wpa_printf(MSG_DEBUG, "CCKM: Driver don't have get BSSID!!");
		return -1;
	}

	if (pstWpaSupp->driver->get_bssid(pstWpaSupp->drv_priv, abBssid) < 0) {
		wpa_printf(MSG_DEBUG, "CCKM: Couldn't get BSSID from driver.");
		return -1;
	}

	if (pbResponseIes == NULL) {
		wpa_printf(MSG_DEBUG, "CCKM (Response Parser): There is no Responses");
		ccx_free(pstSm);
		return 0;
	}

	pstSm->ccx.ccx_cipher = 0;

	pbPosition = pbResponseIes;
	dwIndex = dwResponseIesLen;

	/* Copy the SFA IE and CCX IE, if present. */
	while (pbPosition && dwIndex >= 2 && (pbPosition + 1 < pbResponseIes
			+ dwResponseIesLen)) {

		dwLength = (pbPosition[1]) + 2;
		if (dwLength > dwIndex) {
			/* Length is higher then index ? possible attack..? */
			break;
		}

		if (((pbPosition[0] == WLAN_EID_VENDOR_SPECIFIC)
				&& (pbPosition[1] >= 5) && (memcmp(&pbPosition[2],
				CCKM_SFA_OUI, 4) == 0))) {
			if (pstSm->ccx.sfa_ie) {
				os_free(pstSm->ccx.sfa_ie);
			}
			pstSm->ccx.sfa_ie = os_malloc(dwLength);
			if (pstSm->ccx.sfa_ie) {
				pstSm->ccx.sfa_ie_len = dwLength;
				memcpy(pstSm->ccx.sfa_ie, pbPosition, dwLength);
				wpa_printf(MSG_DEBUG, "CCKM (Response Parser): SFA IE found");
			}
		} else if (((pbPosition[0] == WLAN_EID_VENDOR_SPECIFIC)
				&& (pbPosition[1] == 5) && (memcmp(&pbPosition[2],
				CCKM_CCX_OUI, 4) == 0))) {
			if (pstSm->ccx.ccx_ie) {
				os_free(pstSm->ccx.ccx_ie);
			}
			pstSm->ccx.ccx_ie = os_malloc(dwLength);
			if (pstSm->ccx.ccx_ie) {
				pstSm->ccx.ccx_ie_len = dwLength;
				memcpy(pstSm->ccx.ccx_ie, pbPosition, dwLength);
				wpa_printf(MSG_DEBUG, "CCKM (Response Parser): CCX IE found");
			}
		}
		dwIndex -= dwLength;
		pbPosition += dwLength;
	}

	/* Searchs for CCKM and Aironet */
	for (pbPosition = pbResponseIes; pbPosition + 1 < pbResponseIes
			+ dwResponseIesLen; pbPosition += 2 + pbPosition[1]) {

		wpa_printf(MSG_DEBUG,
				"CCKM (Response Parser): type is %d, length is %d",
				(BYTE) pbPosition[0], (BYTE) pbPosition[1]);

		if (pbPosition + 2 + pbPosition[1] > pbResponseIes + dwResponseIesLen) {
			/* No more IEs */
			break;
		}

		if ((pbPosition[0] == CCKM_ELEMENT_ID) && (pbPosition[1]
				>= sizeof(struct cckm_resp))) {
			wpa_printf(MSG_DEBUG, "CCKM (Response Parser): Found CCKM Element");
			pbCCKM = pbPosition;

			/* Skips CCKM Block */
			pbPosition += (2 + pbPosition[1]);
			continue;
		}

		if ((pbPosition[0] == WLAN_EID_AIRONET) && (pbPosition[1] < 28)) {
			wpa_printf(MSG_DEBUG,
					"CCKM (Response Parser): Found Aironet Element");
			pstAironetIe = (const struct ccx_aironet_ie *) (pbPosition + 2);
			if ((pstAironetIe->flags & (AIRONET_FLAGS_MIC | AIRONET_FLAGS_KP))
					== (AIRONET_FLAGS_MIC | AIRONET_FLAGS_KP)) {
				pstSm->ccx.ccx_cipher = WPA_CIPHER_CKIP_CMIC;
			} else if (pstAironetIe->flags & AIRONET_FLAGS_MIC) {
				pstSm->ccx.ccx_cipher = WPA_CIPHER_CMIC;
			} else if (pstAironetIe->flags & AIRONET_FLAGS_KP) {
				pstSm->ccx.ccx_cipher = WPA_CIPHER_CKIP;
			}
		}

		if (NULL != pbCCKM) {
			break;
		}
	}

	if (NULL != pbCCKM) {
		ccx_parse_cckm_ie(pstSm, pbCCKM, pbOwnAddress, abBssid);
	}
	return 0;
}

int ccx_event_cckm_assoc_handler(struct wpa_supplicant* pstWpaSupp) {
	struct wpa_sm* pstSm = pstWpaSupp->wpa;
	BYTE* pbBssid = pstWpaSupp->bssid;
	enum wpa_alg stAlg = { 0 };
	DWORD dwKeyLen = 0;
	BYTE rsc[8] = { 0 };
	int dwKeySourceLen = 0;
	BYTE abRC4Key[20] = { 0 };
	BYTE abBuff[32] = { 0 };
	BYTE * pbEgtk = NULL;
	BYTE * pbGtk = NULL;
	DWORD dwGtkLen = 0;
	BYTE * pbTempBssid = NULL;
	int bSuccess = 0;

	if (0 == pstSm->ccx.cckm_valid) {
		wpa_printf(MSG_ERROR, "CCKM: Can't Reassociate now");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CCKM: Register PTK To Driver");
	if (pstSm->pairwise_cipher == WPA_CIPHER_CCMP) {
		stAlg = WPA_ALG_CCMP;
		dwKeyLen = 16;
	}

	else if (pstSm->pairwise_cipher == WPA_CIPHER_TKIP) {
		stAlg = WPA_ALG_TKIP;
		dwKeyLen = 32;
	}

	else if (pstSm->pairwise_cipher == WPA_CIPHER_NONE) {
		dwKeyLen = 0;
	}

	else if (pstSm->pairwise_cipher == WPA_CIPHER_CKIP
			|| pstSm->pairwise_cipher == WPA_CIPHER_CKIP_CMIC) {
		stAlg = WPA_ALG_WEP;
		dwKeyLen = 16;
	}

	else if (pstSm->pairwise_cipher == WPA_CIPHER_WEP104
			|| pstSm->pairwise_cipher == WPA_CIPHER_CMIC) {
		stAlg = WPA_ALG_WEP;
		dwKeyLen = 13;
	}

	else if (pstSm->pairwise_cipher == WPA_CIPHER_WEP40) {
		stAlg = WPA_ALG_WEP;
		dwKeyLen = 5;
	}

	else {
		wpa_printf(MSG_ERROR, "CCKM: Unsupported pair-wise cipher %d",
				pstSm->pairwise_cipher);
		goto ccx_event_cckm_assoc_handler_fb;
	}

	pbTempBssid = pstSm->bssid;
	wpa_printf(MSG_DEBUG, "CCKM: set sm's bssid is " MACSTR,
			MAC2STR(pbTempBssid));
	if (dwKeyLen && wpa_sm_set_key(pstSm, stAlg, pbBssid,
			pstSm->ccx.resp->uni_key_id, 1, rsc, 6, (BYTE *) pstSm->tptk.tk1,
			dwKeyLen) < 0) {
		wpa_printf(MSG_DEBUG, "CCKM: failed to set PTK to driver");
		goto ccx_event_cckm_assoc_handler_fb;
	}

	wpa_printf(MSG_DEBUG, "CCKM: Updating driver with GTK");
	dwGtkLen = WPA_GET_LE16(pstSm->ccx.resp->key_length);

	if (wpa_supplicant_check_group_cipher(pstSm, pstSm->group_cipher, dwGtkLen,
			dwGtkLen, &dwKeySourceLen, &stAlg)) {

		wpa_printf(MSG_ERROR, "CCKM: Failed checking group cipher");
		goto ccx_event_cckm_assoc_handler_fb;
	}

	WPA_PUT_LE32(abRC4Key, pstSm->ccx.RN);
	os_memcpy(abRC4Key + 4, pstSm->tptk.kek, sizeof(pstSm->tptk.kek));

	pbEgtk = (BYTE *) &pstSm->ccx.resp[1];
	rc4_skip(abRC4Key, sizeof(abRC4Key), 256, pbEgtk, dwGtkLen);
	pbGtk = pbEgtk;
	wpa_hexdump_key(MSG_DEBUG, "CCKM: Group Key", pbGtk, dwGtkLen);

	if (pstSm->group_cipher == WPA_CIPHER_TKIP) {
		/* Swap Tx/Rx keys for Michael MIC */
		os_memcpy(abBuff, pbGtk, 16);
		os_memcpy(abBuff + 16, pbGtk + 24, 8);
		os_memcpy(abBuff + 24, pbGtk + 16, 8);
		pbGtk = abBuff;
	}

	if (pstSm->pairwise_cipher == WPA_CIPHER_NONE) {
		if (wpa_sm_set_key(pstSm, stAlg, (BYTE *) "\xff\xff\xff\xff\xff\xff",
				pstSm->ccx.resp->mul_key_id, 1, pstSm->ccx.resp->rsc,
				dwKeySourceLen, pbGtk, dwGtkLen) < 0) {
			wpa_printf(MSG_ERROR,
					"CCKM: Failed Notify GTK to driver (Group only)");
			goto ccx_event_cckm_assoc_handler_fb;
		}

	} else if (wpa_sm_set_key(pstSm, stAlg,
			(BYTE *) "\xff\xff\xff\xff\xff\xff", pstSm->ccx.resp->mul_key_id,
			0, pstSm->ccx.resp->rsc, dwKeySourceLen, pbGtk, dwGtkLen) < 0) {
		wpa_printf(MSG_ERROR, "CCKM: Failed Notify GTK to driver (Group only)");
		goto ccx_event_cckm_assoc_handler_fb;
	}

	/*
	 * Update the WPA state machine to use the new PTK for GTK
	 * rekeying.
	 */
	os_memcpy(&pstSm->ptk, &pstSm->tptk, sizeof(pstSm->tptk));
	bSuccess = 1;

	ccx_event_cckm_assoc_handler_fb: if (NULL != pstSm) {
		ccx_free(pstSm);
	}
	return bSuccess;
}

int ccx_save_wpa_ie(struct wpa_sm* pstSm, const BYTE* pbIe, DWORD dwIeLen) {
	if (pstSm->ccx.wpa_ie != NULL) {
		os_free(pstSm->ccx.wpa_ie);
	}

	pstSm->ccx.wpa_ie = os_malloc(dwIeLen);
	pstSm->ccx.wpa_ie_len = dwIeLen;

	if (NULL == pstSm->ccx.wpa_ie) {
		return -1;
	}

	os_memcpy(pstSm->ccx.wpa_ie, pbIe, dwIeLen);
	return 0;
}

u8* ccx_event_cckm_start_handler(void *pCtx,
		BYTE timestamp[8],
		BYTE bssid[ETH_ALEN],
		size_t *ccx_ie_len)
		/*union wpa_event_data *pstEventData) */{
	struct wpa_supplicant *wpa_s = pCtx;
	/*BYTE abCCKMRequest[CCKM_REQUEST_SIZE] = { 0 };*/
	DWORD dwCCKMRequestLen = 0;
	/*BOOL bFastHandoff = TRUE;*/
	BYTE *pbTempBssid = NULL;
	BYTE *abCCKMRequest = os_zalloc(CCKM_REQUEST_SIZE);

	if (abCCKMRequest == NULL) {
		wpa_printf(MSG_ERROR,
				"CCX: Failed to allocate memory");
		return NULL;

	}

	os_memset(abCCKMRequest, 0, CCKM_REQUEST_SIZE);

	if (wpa_s->cckm_available) {
		dwCCKMRequestLen = ccx_create_cckm_reassoc_req(wpa_s,
				/*wpa_s->wpa->ccx.wpa_ie, wpa_s->wpa->ccx.wpa_ie_len,*/
				wpa_s->sme.assoc_req_ie, wpa_s->sme.assoc_req_ie_len,
				timestamp,
				bssid, abCCKMRequest,
				CCKM_REQUEST_SIZE);

		if (dwCCKMRequestLen != CCKM_REQUEST_SIZE) {
			wpa_printf(MSG_ERROR, "CCKM: Failed to generate CCKM IE");
			wpa_printf(MSG_ERROR, "CCKM: dwCCKMRequestLen is %d and not %d",
					dwCCKMRequestLen, CCKM_REQUEST_SIZE);

			pbTempBssid = timestamp;
			wpa_printf(MSG_ERROR, "CCKM: In event_cckm: timestamp is " MACSTR,
					MAC2STR(pbTempBssid));

			pbTempBssid = bssid;
			wpa_printf(MSG_ERROR, "CCKM: In event_cckm: BSSID is " MACSTR,
					MAC2STR(pbTempBssid));

			return NULL;
		}
	} else {
		wpa_printf(MSG_ERROR, "CCX: CCKM Not Avilable, Can't do FAST-ROAM");
		dwCCKMRequestLen = 0;
	}

	*ccx_ie_len = dwCCKMRequestLen;
/*
	pstWpaSupp->driver->update_cckm_request(pstWpaSupp->drv_priv, bFastHandoff,
			dwCCKMRequestLen, abCCKMRequest);
*/
	return abCCKMRequest;
}

int ccx_parse_cckm_ie(struct wpa_sm* pstSm, const BYTE* pbCCKMIe,
               BYTE* pbOwnAddress, BYTE* pbBssid) {

       struct cckm_resp * pstHeader = (struct cckm_resp *) pbCCKMIe;
       struct wpa_ie_data stIeData = { 0 };
       DWORD dwKeyLen = 0;
       DWORD dwRN = 0;
       const unsigned char *pabAddresses[4] = { NULL };
       DWORD dwLengths[4] = { 0 };
       BYTE abMicMd[MD5_MAC_LEN] = { 0 };
       BYTE abMicSha[SHA1_MAC_LEN] = { 0 };
       BYTE abBuff[8] = { 0 };
       struct wpa_ptk *pstPtk = NULL;
       DWORD dwPtkLen = 0;

       if (NULL == pbCCKMIe) {
               wpa_printf(MSG_ERROR, "CCKM: No CCKM IE");
               return -1;
       }

       if (NULL == pstSm->assoc_wpa_ie) {
               wpa_printf(MSG_ERROR, "CCKM: Missing association request IE");
               return -1;
       } else if (-1 == wpa_parse_wpa_ie(pstSm->assoc_wpa_ie,
                       pstSm->assoc_wpa_ie_len, &stIeData)) {
               wpa_printf(MSG_ERROR, "CCKM: Invalid association Request IE");
               return -1;
       }

       if (FALSE == (stIeData.key_mgmt & KEY_MGMT_CCKM_BIT)) {
               wpa_printf(MSG_ERROR, "CCKM: CCKM was not Negotiated");
               return -1;
       }

       if (os_memcmp(pstHeader->oui, CCKM_OUI_TYPE, sizeof(DWORD))) {
               wpa_hexdump(MSG_ERROR, "CCKM: Invalid OUI type", pstHeader->oui,
                               sizeof(DWORD));
               return -1;
       }

       dwRN = WPA_GET_LE32(pstHeader->rn);
       if (pstSm->ccx.RN != dwRN) {
               wpa_printf(MSG_ERROR, "CCKM: RN mismatch: Response: %ld, "
                       "Request-expected >= %ld", (unsigned long) dwRN,
                               (unsigned long) pstSm->ccx.RN);
               return -1;
       }

       dwPtkLen = 64;
       if (pstSm->pairwise_cipher == WPA_CIPHER_CCMP) {
               dwPtkLen = 48;
               wpa_printf(MSG_DEBUG, "CCKM: Parsing IE : Ptk Length is 48 "
					"instead of 64 because chiper is CCMP");
       }

       ccx_btk_to_ptk(pstSm->ccx.gk.btk, sizeof(pstSm->ccx.gk.btk), pstSm->ccx.RN,
                       pbBssid, (BYTE *) &pstSm->tptk, dwPtkLen);
       wpa_printf(MSG_DEBUG, "CCKM: finished to calculate PTK again");

       dwKeyLen = WPA_GET_LE16(pstHeader->key_length);
       if ((BYTE) (pstHeader->length + 2) != (sizeof(struct cckm_resp) + dwKeyLen)) {
               wpa_printf(MSG_ERROR, "CCKM: invalid resp ie length: %d, expected: %d",
                               pstHeader->length, sizeof(struct cckm_resp) + dwKeyLen - 2);
               return -1;
       }

       /* STA-ID */
       pabAddresses[0] = pbOwnAddress;
       dwLengths[0] = ETH_ALEN;

       /* RSNIE (AP) */
       if (stIeData.proto == WPA_PROTO_RSN) {
               wpa_printf(MSG_DEBUG, "CCKM: proto is RSN");
               pabAddresses[1] = pstSm->ap_rsn_ie;
               dwLengths[1] = pstSm->ap_rsn_ie_len;
       } else {
               wpa_printf(MSG_DEBUG, "CCKM: proto is WPA");
               pabAddresses[1] = pstSm->ap_wpa_ie;
               dwLengths[1] = pstSm->ap_wpa_ie_len;
       }

       /* RN,KeyIdUnicast,KeyIdMulticast,RSC,MulticastKeyLen */
       pabAddresses[2] = pstHeader->rn;
       dwLengths[2] = pstHeader->mic - pstHeader->rn;

       if (dwKeyLen > 0) {
               /* EGTK */
               wpa_printf(MSG_DEBUG, "CCKM: EGTK Length is %d", dwKeyLen);
               pabAddresses[3] = (BYTE*) &pstHeader[1];
               dwLengths[3] = dwKeyLen;
       } else {
               wpa_printf(MSG_ERROR, "CCKM: Error with EGTK");
               return -1;
       }

       pstPtk = &pstSm->tptk;

       if (stIeData.proto == WPA_PROTO_RSN)
       {
               hmac_sha1_vector(pstPtk->kck, sizeof(pstPtk->kck), 4, pabAddresses,
                               dwLengths, abMicSha);

               if (os_memcmp(abMicSha, pstHeader->mic, sizeof(pstHeader->mic)) != 0) {
                       wpa_hexdump(MSG_ERROR, "CCKM: Computed mic mismatch", abMicSha, 8);
                       ccx_print_buf(MSG_ERROR, "CCKM: Calculated MIC: ", abMicSha, 20);
                       ccx_print_buf(MSG_ERROR, "CCKM: Should be MIC: ", pstHeader->mic, 8);
                       return -1;
               }
       }
       else
       {
               hmac_md5_vector(pstPtk->kck, sizeof(pstPtk->kck), 4, pabAddresses,
                               dwLengths, abMicMd);

               if (os_memcmp(abMicMd, pstHeader->mic, sizeof(pstHeader->mic)) != 0) {
                       wpa_hexdump(MSG_ERROR, "CCKM: Computed mic mismatch", abMicMd, 8);
                       ccx_print_buf(MSG_ERROR, "CCKM: Calculated MIC: ", abMicMd, 16);
                       ccx_print_buf(MSG_ERROR, "CCKM: Should be MIC: ", pstHeader->mic, 8);
                       return -1;
               }
       }



       wpa_printf(MSG_ERROR, "CCKM: Ready for CCKM reassociation");
       pstSm->ccx.resp = os_malloc(pstHeader->length + 2);
       if (!pstSm->ccx.resp) {
               wpa_printf(MSG_ERROR, "CCKM: cannot malloc resp copy");
               return -1;
       }

       os_memcpy(pstSm->ccx.resp, (BYTE*) pstHeader, pstHeader->length + 2);

       /* Supplicant: swap tx/rx Mic keys */
       os_memcpy(abBuff, pstPtk->u.auth.tx_mic_key, 8);
       os_memcpy(pstPtk->u.auth.tx_mic_key, pstPtk->u.auth.rx_mic_key, 8);
       os_memcpy(pstPtk->u.auth.rx_mic_key, abBuff, 8);
       pstSm->ccx.cckm_valid = 1;
       return 0;

}

int ccx_derive_gk(struct wpa_sm *pstSm, const BYTE *cpbSourceAddress,
		const struct wpa_eapol_key *cpstEapolKey, struct wpa_gk *pstGk)

{
	DWORD dwGkLen = sizeof(pstSm->ccx.gk);
	/* PMK is named NSK, while using CCKM */

	BYTE* pbTempBssid = pstSm->own_addr;
	wpa_printf(MSG_DEBUG, "CCKM: Own Address is " MACSTR, MAC2STR(pbTempBssid));
	pbTempBssid = pstSm->bssid;

	wpa_printf(MSG_DEBUG, "CCKM: BSSID is " MACSTR, MAC2STR(pbTempBssid));
	ccx_pmk_to_gk(pstSm->pmk, pstSm->pmk_len, "Fast-Roam Generate Base Key",
			cpbSourceAddress, pstSm->own_addr, pstSm->snonce,
			cpstEapolKey->key_nonce, (BYTE *) pstGk, dwGkLen,
			wpa_key_mgmt_sha256(pstSm->key_mgmt));
	return 0;

}

void ccx_pmk_to_gk(const BYTE *pbPmk, DWORD dwPmkLen, const char * szLabel,
		const BYTE *cpbAddress1, const BYTE *cpbAddress2, const BYTE *pbNonce1,
		const BYTE *pbNonce2, BYTE *pbGk, DWORD dwGkLen, int bUseSha256)

{
	BYTE baData[2 * ETH_ALEN + 2 * WPA_NONCE_LEN];

	os_memcpy(baData, cpbAddress1, ETH_ALEN);
	os_memcpy(baData + ETH_ALEN, cpbAddress2, ETH_ALEN);
	os_memcpy(baData + 2 * ETH_ALEN, pbNonce1, WPA_NONCE_LEN);
	os_memcpy(baData + 2 * ETH_ALEN + WPA_NONCE_LEN, pbNonce2,WPA_NONCE_LEN);

#ifdef CONFIG_IEEE80211W
	if (bUseSha256) {
		sha256_prf(pbPmk, dwPmkLen, szLabel, baData, sizeof(baData),
				pbGk, dwGkLen);
	} else {
		sha1_prf(pbPmk, dwPmkLen, szLabel, baData, sizeof(baData), pbGk, dwGkLen);
	}
#else
	sha1_prf(pbPmk, dwPmkLen, szLabel, baData, sizeof(baData), pbGk, dwGkLen);
#endif /* CONFIG_IEEE80211W */

	wpa_printf(MSG_DEBUG, "WPA: GK derivation - A1=" MACSTR " A2=" MACSTR,
			MAC2STR(cpbAddress1), MAC2STR(cpbAddress2));
	wpa_hexdump_key(MSG_DEBUG, "WPA: PMK", pbPmk, dwPmkLen);
	wpa_hexdump_key(MSG_DEBUG, "WPA: GK", pbGk, dwGkLen);
}

void ccx_btk_to_ptk(const BYTE* cpbBtk, DWORD dwBtkLen, int RN,
		const BYTE* cpbBssid, BYTE* pbPtk, DWORD dwPtkLen) {

	const BYTE* cpabAddresses[3] = { NULL };
	DWORD dwAddressesLengths[3] = { 0 };
	BYTE bCounter = 0;
	DWORD dwPosition = 0;
	DWORD dwLeft = 0;
	BYTE abHash[SHA1_MAC_LEN];
	BYTE abRn[4];
	WPA_PUT_LE32(abRn, RN);

	wpa_printf(MSG_DEBUG, "CCKM: Generates PTK from btk");

	cpabAddresses[0] = abRn;
	dwAddressesLengths[0] = 4;
	cpabAddresses[1] = cpbBssid;
	dwAddressesLengths[1] = ETH_ALEN;
	cpabAddresses[2] = &bCounter;
	dwAddressesLengths[2] = 1;

	dwPosition = 0;
	while (dwPosition < dwPtkLen) {
		dwLeft = dwPtkLen - dwPosition;
		if (dwLeft >= SHA1_MAC_LEN) {
			hmac_sha1_vector(cpbBtk, dwBtkLen, 3, cpabAddresses,
					dwAddressesLengths, &pbPtk[dwPosition]);
			dwPosition += SHA1_MAC_LEN;
		} else {
			hmac_sha1_vector(cpbBtk, dwBtkLen, 3, cpabAddresses,
					dwAddressesLengths, abHash);
			os_memcpy(&pbPtk[dwPosition], abHash, dwLeft);
			break;
		}
		bCounter++;
	}

	wpa_hexdump_key(MSG_MSGDUMP, "CCKM: Source BTK", cpbBtk, dwBtkLen);
	wpa_hexdump_key(MSG_MSGDUMP, "CCKM: Genetrated PTK", pbPtk, dwPtkLen);
	return;
}

int ccx_get_sfa_ie(struct wpa_sm * pstSm, BYTE *pbBuff, DWORD dwBuffLen) {
	if (pstSm->ccx.sfa_ie == NULL) {
		return -1;
	}

	if ((DWORD) pstSm->ccx.sfa_ie_len > dwBuffLen) {
		return pstSm->ccx.sfa_ie_len;
	}

	memset(pbBuff, 0, dwBuffLen);
	memcpy(pbBuff, pstSm->ccx.sfa_ie, pstSm->ccx.sfa_ie_len);
	return 0;
}

struct iapp_hdr *ccx_build_iapp_hdr(struct wpa_supplicant *wpa_s,
		u8 type, u8 subtype, struct iapp_hdr *iapp, int *len)
{
	*len = 0;
	if (iapp == NULL) {
		return NULL;
	}

	os_memcpy(iapp->dst_addr, wpa_s->bssid, ETH_ALEN);
	os_memcpy(iapp->src_addr, wpa_s->own_addr, ETH_ALEN);
	iapp->spare = 0x0;
	os_memcpy(iapp->snap_header, CISCO_AIRONET_SNAP_HEADER, 8);
	iapp->iapp_id_length = 16; /* length of fixed elements */
	iapp->iapp_type = type;
	iapp->iapp_subtype = subtype;
	os_memcpy(iapp->dest_mac_addr, wpa_s->bssid, ETH_ALEN);
	os_memcpy(iapp->source_mac_addr, wpa_s->own_addr, ETH_ALEN);

	*len = 38;
	return iapp;
}

int ccx_send_iapp_information(struct wpa_supplicant *wpa_s) {
	int len;
	struct iapp_frame *iapp =
			os_zalloc(sizeof(struct iapp_hdr) + sizeof(struct iapp_report_info_ie));
	struct iapp_report_info_ie *report_ie;
	struct os_time now, time_diff;

	if (iapp == NULL)
		return -ENOMEM;

	ccx_build_iapp_hdr(wpa_s, 0x30, 0, &iapp->hdr, &len);

	if (len == 0)
		return -1;

	report_ie = (struct iapp_report_info_ie*)iapp->body;
	report_ie->hdr.OUI[0] = 0x00; report_ie->hdr.OUI[1] = 0x40; report_ie->hdr.OUI[2] = 0x96;
	report_ie->hdr.OUI_type = 0;
	report_ie->hdr.id = host_to_be16(0x9b);
	report_ie->hdr.length = host_to_be16(48);
	report_ie->channel = host_to_be16(frequency_to_channel(wpa_s->prev_freq));
	os_memcpy(report_ie->mac_addr, wpa_s->prev_bssid, ETH_ALEN);
	report_ie->ssid_len = host_to_be16(wpa_s->ccx_prev_ssid_len);
	os_memcpy(report_ie->ssid, wpa_s->ccx_prev_ssid, wpa_s->ccx_prev_ssid_len);
	os_get_time(&now);
	os_time_sub(&now, &wpa_s->new_connection_ts, &time_diff);
	/* since the time should be shold the lower 16 bits should be enough */
	report_ie->second_since_dissasoc = host_to_be16(time_diff.sec & 0xffff);

	iapp->hdr.iapp_id_length += sizeof (struct iapp_report_info_ie);

	len = iapp->hdr.iapp_id_length + 22;/* add 22 for the src + dest mac, and snap hdr */
	iapp->hdr.iapp_id_length = ((iapp->hdr.iapp_id_length << 8) & 0xff00) +
			((iapp->hdr.iapp_id_length >> 8) & 0xff);

	l2_packet_send(wpa_s->ccx_l2, iapp->hdr.dest_mac_addr, 0, (u8*)iapp,
			len);
	return 0;

}

u8 ccx_parse_version(const u8 *buff, size_t buff_len)
{
	u8* pos = (u8*)buff;
	int left = buff_len;
	if (buff == NULL || buff_len == 0)
		return 0;

	while (left > 2) {
		if (pos[0] == WLAN_EID_VENDOR_SPECIFIC &&
				(memcmp(pos + 2, CCX_OUI, 3) == 0) && (pos[5] == 3)) {
			return pos[6];

		}
		left -= (pos[1] + 2);
		pos += pos[1] + 2;
	}
	return 0;
}

int ccx_get_ccx_ie(struct wpa_sm* pstSm, BYTE *pbBuff, DWORD dwBuffLen) {

	if (pstSm->ccx.ccx_ie == NULL) {
		return -1;
	}

	if ((DWORD) pstSm->ccx.ccx_ie_len > dwBuffLen) {
		return pstSm->ccx.ccx_ie_len;
	}

	memset(pbBuff, 0, dwBuffLen);
	memcpy(pbBuff, pstSm->ccx.ccx_ie, pstSm->ccx.ccx_ie_len);
	return 0;
}

static void ccx_tsm_timeout(void *eloop_ctx, void *timeout_ctx) {
	int len;
	struct wpa_ts_metric ts_metrics;
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct tsm_data* tsm = (struct tsm_data*)timeout_ctx;
	struct ccx_measurement_report *report;
	struct ccx_measurement_report_ie *report_ie;
	struct ccx_tsm_report *tsm_report;
	struct iapp_frame *frame = os_zalloc(sizeof(struct iapp_frame) +
			sizeof(struct ccx_measurement_report) +
			sizeof(struct ccx_measurement_report_ie) +
			sizeof(struct ccx_tsm_report));

	if (frame == NULL) {
		return;
	}

	len = wpa_ccx_build_iapp_hdr(wpa_s, frame, 0x32, 0x81);
	os_memset(frame->hdr.dest_mac_addr, 0, ETH_ALEN);

	report = (struct ccx_measurement_report*)frame->body;
	report->dialog_token = 0;
	len += sizeof(report->dialog_token);

	report_ie = (struct ccx_measurement_report_ie*)report->report_ie;
	report_ie->hdr.id = CCX_MEASUREMENT_RESP_ID;
	report_ie->hdr.length = 25;
	report_ie->hdr.token = 0;
	report_ie->hdr.mode = 0;
	report_ie->hdr.type = CCX_MSR_TYPE_TSM;
	len += sizeof(struct ccx_measurement_report_ie);

	tsm_report = (struct ccx_tsm_report*)report_ie->measurement_report;

	wpa_printf(MSG_DEBUG, "%s: tid = %d\n",	__FUNCTION__, tsm->tid);
	wpa_drv_get_ts_metrics(wpa_s, tsm->tid, &ts_metrics);

	os_memset(tsm_report, 0, sizeof(*tsm_report));

	if (ts_metrics.packet_count) {
		tsm_report->queue_delay = (ts_metrics.packet_queue_delay/1000) /
				ts_metrics.packet_count;
		tsm_report->transmit_delay = ts_metrics.packet_transmit_delay /
				ts_metrics.packet_count;
	}
	tsm_report->queue_delay_histogram[0] = ts_metrics.packet_delay_histogram[0];
	tsm_report->queue_delay_histogram[1] = ts_metrics.packet_delay_histogram[2];
	tsm_report->queue_delay_histogram[2] = ts_metrics.packet_delay_histogram[2];
	tsm_report->queue_delay_histogram[3] = ts_metrics.packet_delay_histogram[3];

	tsm_report->packet_lost = ts_metrics.packet_lost;
	tsm_report->packet_count = ts_metrics.packet_count;
	tsm_report->roaming_count = wpa_s->roam_count;
	tsm_report->roaming_delay = wpa_s->roam_delay;

	len += sizeof(struct ccx_tsm_report);

	wpa_printf(MSG_DEBUG, "%s: tid = %d, received from kernel:"
			"count %d, lost %d\nqueue_delay %d, transmit_delay %d\n",
			__FUNCTION__, tsm->tid,
			ts_metrics.packet_count, ts_metrics.packet_lost,
			ts_metrics.packet_queue_delay, ts_metrics.packet_transmit_delay);

	frame->hdr.iapp_id_length = len - 22;
	frame->hdr.iapp_id_length = be_to_host16(frame->hdr.iapp_id_length);

	l2_packet_send(wpa_s->ccx_l2, frame->hdr.dest_mac_addr, 0, (u8*)frame, len);

/*	if (i++ < 10)*/
	ccx_register_tsm_timeout(wpa_s, tsm->secs, tsm->usecs, tsm);
}

void ccx_register_tsm_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec, struct tsm_data* tsm)
{
	eloop_cancel_timeout(ccx_tsm_timeout, wpa_s, tsm);
	eloop_register_timeout(sec, usec, ccx_tsm_timeout, wpa_s, tsm);
}

void ccx_event_delts(struct wpa_supplicant *wpa_s,
		u8 tid, u8 reason_code)
{
	eloop_cancel_timeout(ccx_tsm_timeout, wpa_s, &wpa_s->tsm);
	os_free(wpa_s->tspec_ie[tid]);
	wpa_s->tspec_ie[tid] = NULL;
}

void ccx_stop_tsm(struct wpa_supplicant *wpa_s)
{
	eloop_cancel_timeout(ccx_tsm_timeout, wpa_s, &wpa_s->tsm);
}

void ccx_event_addts(struct wpa_supplicant *wpa_s, u8 status,
			u8* ie, u8 ie_len)
{
	struct ieee80211_tspec_ie *tspec = (struct ieee80211_tspec_ie*)ie;
	if (status == 0) {
		u8 tid = tspec->tsinfo >> IEEE80211_WMM_IE_TSPEC_TID_SHIFT &
				IEEE80211_WMM_IE_TSPEC_TID_MASK;

		wpa_s->tspec_ie[tid] = os_malloc(ie_len);
		os_memcpy(wpa_s->tspec_ie[tid], ie, ie_len);
	} else {
		wpa_blacklist_add(wpa_s, wpa_s->bssid);
		wpa_supplicant_deauthenticate(wpa_s, WLAN_REASON_UNSPECIFIED);
		wpa_supplicant_req_scan(wpa_s, 1, 0);
	}
}

void ccx_event_ie(struct wpa_supplicant *wpa_s,u8* ie, u8 ie_len)
{
	u8 type;
	if ((ie[0] != WLAN_EID_VENDOR_SPECIFIC) ||
					(memcmp(ie + 2, CCX_OUI, 3) != 0))
		return;

	type = ie[5];
	switch (type) {
	case 7:
		{
			u8 tid = ie[6];
			u8 state = ie[7];
			u16 interval = WPA_GET_LE16(ie+8);
			int seconds = (interval*1024)/1000000;
			int usecs = (interval*1024)%1000000;
			struct tsm_data *tsm = &wpa_s->tsm;
			tsm->secs = (interval*1024)/1000000;
			tsm->usecs = (interval*1024)%1000000;
			tsm->tid = tid;

			wpa_printf(MSG_ERROR, "%s: TSM IE: tid %d, state %d, interval %d"
					" (%d.%06d sec)\n", __FUNCTION__, tid, state, interval,
					seconds, usecs);
			if (state) {
				ccx_register_tsm_timeout(wpa_s, seconds, usecs, tsm);
			} else
				eloop_cancel_timeout(ccx_tsm_timeout, wpa_s, tsm);
			break;
		}
	}

	return;
}

void ccx_deinit_ies(struct wpa_sm* pstSm) {

	if (pstSm == NULL)
		return;

	if (pstSm->ccx.sfa_ie)
		os_free(pstSm->ccx.sfa_ie);

	if (pstSm->ccx.ccx_ie)
		os_free(pstSm->ccx.ccx_ie);

	if (pstSm->ccx.resp)
		os_free(pstSm->ccx.resp);

	if (pstSm->ccx.wpa_ie)
		os_free(pstSm->ccx.wpa_ie);

	if (pstSm->ccx.combined_ie)
		os_free(pstSm->ccx.combined_ie);

	return;
}

void ccx_free(struct wpa_sm* pstSm) {
	if (pstSm->ccx.resp != NULL) {
		os_free(pstSm->ccx.resp);
	}
	pstSm->ccx.resp = NULL;
	pstSm->ccx.cckm_valid = 0;
	return;

}

void ccx_print_buf(int dwLevel, const char *szTitle, const BYTE *pbBuff,
		DWORD dwBuffLen) {
	DWORD i = 0;
	printf("%s - hexdump(len=%lu):", szTitle, (unsigned long) dwBuffLen);
	if (pbBuff == NULL) {
		printf(" [NULL]");
	} else {
		for (i = 0; i < dwBuffLen; i++)
			printf(" %02x", pbBuff[i]);
	}
	printf("\n");
}
