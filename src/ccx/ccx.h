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

#ifndef _CCX_H_
#define _CCX_H_

#include "includes.h"
#include "common.h"
#include <linux/filter.h>
#include "drivers/driver.h"

#ifndef DWORD
typedef unsigned int DWORD;
#endif /* DWORD */
#ifndef WORD
typedef unsigned short WORD;
#endif /* WORD */
#ifndef BYTE
typedef unsigned char BYTE;
#endif /* BYTE */
#ifndef BOOL
#define BOOL BYTE
#endif /* BOOL */
#ifndef TRUE
#define TRUE (1)
#endif /* TRUE */
#ifndef FALSE
#define FALSE (0)
#endif /* FALSE */
#ifndef NULL
#define NULL ((void *) 0)
#endif /* NULL */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif /* ETH_ALEN */

#define CCX_OUI ("\x00\x40\x96")

#define CCKM_CCX_OUI ("\x00\x40\x96\x03")
#define CCKM_SFA_OUI ("\x00\x40\x96\x14")
#define KEY_MGMT_CCKM_OUI RSN_SELECTOR(0x00, 0x40, 0x96, 0x00)
#define CCKM_ELEMENT_ID			(0x9c)
#define WLAN_EID_AIRONET		(133)
#define AIRONET_DEVTYPE_GENERIC (0x66)
#define AIRONET_FLAGS_MIC BIT	(3)
#define AIRONET_FLAGS_KP BIT	(4)

#define IAPP_TYPE_RADIO_MEASUREMENT (0x32)
#define IAPP_SUBTYPE_RM_REQUEST (0x01)
#define IAPP_SUBTYPE_RM_REPORT  (0x81)
#define CCX_MEASUREMENT_REQ_ID (38)
#define CCX_MEASUREMENT_RESP_ID (39)
#define CCX_MSR_TYPE_CHANNEL_LOAD (1)
#define CCX_MSR_TYPE_NOISE_HIST (2)
#define CCX_MSR_TYPE_BEACON (3)
#define CCX_MSR_TYPE_FRAME (4)
#define CCX_MSR_TYPE_HIDDEN_NODE (5)
#define CCX_MSR_TYPE_TSM (6)

#define CCX_MEASUREMENT_PASSIVE_SCAN (0)
#define CCX_MEASUREMENT_ACTIVE_SCAN (1)
#define CCX_MEASUREMENT_BEACON_TABLE (2)

#define MAX_CCX_MEASUREMENT_REPORT (1500-sizeof(struct iapp_frame))

#define CCX_SUPPORTED_VERSION (4)
#define CCX_VERSION_IE_LEN (5)
#define CCX_VERSION_IE_ID (3)
#define CCX_RM_CAPABILITY_IE_LEN (6)
#define CCX_RM_CAPABILITY_IE_ID (1)

#define CCX_TSRS_IE_LEN (6)

#ifndef TI_IOCTL_CCKM_REQUEST
#define TI_IOCTL_CCKM_REQUEST 0x8001005
#endif

#ifndef TI_IOCTL_CCKM_RESULT
#define TI_IOCTL_CCKM_RESULT  0x8001006
#endif

#ifndef TI_IOCTL_CCX_ROGUE_AP_DETECTED
#define TI_IOCTL_CCX_ROGUE_AP_DETECTED 0x8001002
#endif /* TI_IOCTL_CCX_ROGUE_AP_DETECTED */
typedef struct _OS_CCX_ROGUE_AP_DETECTED {
	unsigned short FailureReason;
	unsigned char RogueAPMacAddress[6];
	char RogueAPName[16];
} OS_CCX_ROGUE_AP_DETECTED, *POS_CCX_ROGUE_AP_DETECTED;

#define CCKM_REQUEST_SIZE 26
#define MD5_HASH_SIZE 16

struct cckm_resp;
struct wpa_supplicant;
struct wpa_sm;
union wpa_event_data;
struct wpa_eapol_key;

struct wpa_gk {
	BYTE krk[16]; /* EAPOL-Key Key Refresh Key (KRK) */
	BYTE btk[32]; /* EAPOL-Key Base Transient Key (BTK) */
}STRUCT_PACKED;

struct iapp_hdr {
	u8 dst_addr[6];
	u8 src_addr[6];
	u16 spare;
	u8 snap_header[8];
	u16 iapp_id_length;
	u8 iapp_type;
	u8 iapp_subtype;
	u8 dest_mac_addr[ETH_ALEN];
	u8 source_mac_addr[ETH_ALEN];
} STRUCT_PACKED;

struct iapp_frame {
	struct iapp_hdr hdr;
	/* must be last */
	u8 body[0];
} STRUCT_PACKED;

struct ccx_ie_hdr {
	u16 id;
	u16 length;
	u8 OUI[3];
	u8 OUI_type;
} STRUCT_PACKED;

struct iapp_report_info_ie {
	struct ccx_ie_hdr hdr;
	u8 mac_addr[ETH_ALEN];
	u16 channel;
	u16 ssid_len;
	u8 ssid[32];
	u16 second_since_dissasoc;
} STRUCT_PACKED;

struct ccx_measurement_request {
	u16 dialog_token;
	u8 activation_delay;
	u8 measurement_offset;
	u8 measurement_request_ie[0];
} STRUCT_PACKED;

struct ccx_measurement_ie_hdr {
	u16 id;
	u16 length;
	u16 token;
	u8 mode;
	u8 type;
} STRUCT_PACKED;

struct ccx_measurement_request_ie {
	struct ccx_measurement_ie_hdr hdr;
	u8 channel;
	u8 scan_mode;
	u16 duration;
} STRUCT_PACKED;

struct ccx_measurement_report {
	u16 dialog_token;
	/* must be last */
	u8 report_ie[0];
} STRUCT_PACKED;

struct ccx_measurement_report_ie {
	struct ccx_measurement_ie_hdr hdr;
	u8 measurement_report[0];
} STRUCT_PACKED;

struct ccx_beacon_report{
	u8 channel;
	u8 spare;
	u16 duration;
	u8 phy_type;
	s8 received_signal_pwr;
	u8 bssid[ETH_ALEN];
	u32 parent_tsf;
	u64 target_tsf;
	u16 beacon_interval;
	u16 capability_info;
	/* must be last */
	u8 received_elements[0];
} STRUCT_PACKED ;

struct ccx_tsm_report {
	u16 queue_delay;
	u16 queue_delay_histogram[4];
	u32 transmit_delay;
	u16 packet_lost;
	u16 packet_count;
	u8 roaming_count;
	u16 roaming_delay;
} STRUCT_PACKED;

typedef struct ccx_data {
	int cckm_available;
	struct cckm_resp* resp;
	int cckm_valid;
	u32 RN;
	struct wpa_gk gk;

	BYTE* wpa_ie;
	DWORD wpa_ie_len;

	BYTE* combined_ie;
	DWORD combined_ie_len;

	BYTE* sfa_ie;
	int sfa_ie_len;
	BYTE* ccx_ie;
	int ccx_ie_len;

	BYTE* ccx_ie_assoc;
	int ccx_ie_assoc_len;

	int ccx_cipher;

	u8 ccx_version;

} ccx_data_t;

//typedef struct _cckm_start {
//	BYTE timestamp[8];
//	BYTE bssid[ETH_ALEN];
//} cckm_start_t;

struct cckm_resp {
	BYTE id;
	BYTE length;
	BYTE oui[3];
	BYTE oui_type;
	BYTE rn[4];
	BYTE uni_key_id;
	BYTE mul_key_id;
	BYTE rsc[8];
	BYTE key_length[2];
	BYTE mic[8];
}STRUCT_PACKED;

struct ccx_aironet_ie {
	BYTE load;
	BYTE hops;
	BYTE device;
	BYTE refresh_rate;
	u16 cwmin;
	u16 cwmax;
	BYTE flags;
	BYTE distance;
	BYTE name[16];
	u16 num_of_assoc;
	u16 radiotype;
}STRUCT_PACKED;

/* RequestCode values*/
typedef enum _OS_CCX_CCKM_REQUEST_CODE {
	Ccx_CckmFirstTime = 0, Ccx_CckmFastHandoff
} OS_CCX_CCKM_REQUEST_CODE;

typedef struct _OS_CCX_CCKM_REQUEST {
	int RequestCode;
	u32 AssociationRequestIELength;
	BYTE AssociationRequestIE[32];
} OS_CCX_CCKM_REQUEST;

typedef struct _OS_CCX_CCKM_START {
	BYTE Timestamp[8];
	char BSSID[6];
} OS_CCX_CCKM_START;

#define L2_SNAP 0xAAAA
#define L2_CMD 0x3
#define ETH_TYPE_CCX 0x0000
#define CCX_OUI_0 0x00
#define CCX_OUI_1 0x40
#define CCX_OUI_2 0x96

struct tsm_data {
	u8 tid;
	int secs;
	int usecs;
};

int ccx_init(struct wpa_supplicant *wpa_s, const u8* mac_addr);

/* function is called when a CCX IAPP packet is
 * received from the AP we are associated to
 */
void ccx_recv(void *ctx, const u8 *src_addr,
		const u8 *buff, size_t len);

/* handle a received ccx iapp packet */
void ccx_iapp_packet_handler(struct wpa_supplicant* wpa_s, const u8* buff, size_t len);

/* parse a iapp packet */
int ccx_parse_iapp_packet(struct wpa_supplicant* wpa_s, const u8* buff, size_t len);

int ccx_handle_next_request_ie(struct wpa_supplicant *wpa_s,
		struct ccx_measurement_request_ie* request_ie,	int left);

int ccx_measurement_beacon_scan_complete(struct wpa_supplicant *wpa_s,
		struct wpa_scan_results *scan_res);

struct iapp_frame* ccx_build_measurement_report(struct wpa_supplicant* wpa_s,
		int *len, struct wpa_scan_results *scan_res);

int wpa_ccx_build_beacon_report(struct wpa_supplicant *wpa_s,
		struct ccx_measurement_request_ie *req_ie,
		struct wpa_scan_results *scan_res,
		u8* buff, int length_left);

int wpa_ccx_build_iapp_hdr(struct wpa_supplicant *wpa_s,
		struct iapp_frame *frame, u8 type, u8 subtype);

/* Creates a new Reassociation Reqest*/
int ccx_create_cckm_reassoc_req(struct wpa_supplicant* pstWpaSupp,
		BYTE * pbWpaIe, DWORD dwWpaIeLen, BYTE* pbTimestamp, BYTE* pbBssid,
		BYTE* pbCCKMRequest, DWORD dwCCKMRequestLen);

/* Parses the Reassosciation Response*/
int ccx_parse_cckm_response(struct wpa_supplicant* pstWpaSupp,
		const BYTE* pbResponseIes, DWORD dwResponseIesLen);

/* Event Handler for CCKM Association */
int ccx_event_cckm_assoc_handler(struct wpa_supplicant* pstWpaSupp);

/* Saves the IE Into the SM Struct */
int ccx_save_wpa_ie(struct wpa_sm* pstSm, const BYTE* pbIe, DWORD dwIeLen);

/* Start Handleing the CCKM */
u8*
ccx_event_cckm_start_handler(void *pCtx,
		BYTE timestamp[8],
		BYTE bssid[ETH_ALEN],
		size_t *ccx_ie_len);

/* Parser for the CCKM IE */
int ccx_parse_cckm_ie(struct wpa_sm* pstSm, const BYTE* pbCCKMIe,
		BYTE* pbOwnAddress, BYTE* pbBssid);

/* Create GK */
int ccx_derive_gk(struct wpa_sm *pstSm, const BYTE *cpbSourceAddress,
		const struct wpa_eapol_key *cpstEapolKey, struct wpa_gk *pstGk);

/* Generates GK from PTK */
void ccx_pmk_to_gk(const BYTE *pbPmk, DWORD dwPmkLen, const char * szLabel,
		const BYTE *cpbAddress1, const BYTE *cpbAddress2, const BYTE *pbNonce1,
		const BYTE *pbNonce2, BYTE *pbGk, DWORD dwGkLen, int bUseSha256);

/* Generates PTK from BTK */
void ccx_btk_to_ptk(const BYTE* cpbBtk, DWORD dwBtkLen, int RN,
		const BYTE* cpbBssid, BYTE* pbPtk, DWORD dwPtkLen);

/*
 * Copies SFA IE Into pbBuff
 * If the IE is not Avilable it will return -1
 * If BuffLen is not enough, it will return needed len,
 * On Success it will return 0
 * */
int ccx_get_sfa_ie(struct wpa_sm * pstSm, BYTE *pbBuff, DWORD dwBuffLen);

/*
 * Copies CCX IE Into pbBuff
 * If the IE is not Avilable it will return -1
 * If BuffLen is not enough, it will return needed len,
 * On Success it will return 0
 * */
int ccx_get_ccx_ie(struct wpa_sm* pstSm, BYTE *pbBuff, DWORD dwBuffLen);

/*
 * Generates a cisco IAPP header
 */
struct iapp_hdr *ccx_build_iapp_hdr(struct wpa_supplicant *wpa_s,
		u8 type, u8 subtype, struct iapp_hdr *iapp, int *len);

/*
 * sends the IAPP information request after a successful reassociation
 * to an AP supporting CCX
 */
 int ccx_send_iapp_information(struct wpa_supplicant *wpa_s);

 /*
  * return the CCX version in the re/association response
  * if CCX version not present in the re/association response
  * return 0
  */
 u8 ccx_parse_version(const u8 *buff, size_t buff_len);

/* Frees CCX */
void ccx_free(struct wpa_sm* pstSm);
void ccx_deinit_ies(struct wpa_sm* pstSm);

/* Debug print of buffer */
void ccx_print_buf(int dwLevel, const char *szTitle, const BYTE *pbBuff,
		DWORD dwBuffLen);

void ccx_event_delts(struct wpa_supplicant *wpa_s,
		u8 tid, u8 reason_code);

void ccx_event_addts(struct wpa_supplicant *wpa_s, u8 status,
		u8* ie, u8 ie_len);

void ccx_event_ie(struct wpa_supplicant *wpa_s,u8* ie, u8 ie_len);

void ccx_register_tsm_timeout(struct wpa_supplicant *wpa_s,
		int sec, int usec, struct tsm_data* tsm);

void ccx_stop_tsm(struct wpa_supplicant *wpa_s);

#endif /* _CCX_H_ */
