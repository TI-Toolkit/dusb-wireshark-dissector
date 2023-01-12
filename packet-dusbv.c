/* packet-dusbv.c
 * Routines for DUSB Virtual dissection
 * Copyright 2021, John Cesarz <bluestemjc@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LICENSE
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */

/* Prototypes */
void proto_reg_handoff_dusbv(void);
void proto_register_dusbv(void);

static int read_name(tvbuff_t *tvb, proto_tree *tree, int offset);
static int read_attribute_values(tvbuff_t *tvb, proto_tree *tree, int offset);

/* Initialize the protocol and registered fields */
static int proto_dusbv = -1;
static int hf_dusbv_len = -1;
static int hf_dusbv_type = -1;
static int hf_dusbv_ping_protocol = -1;
static int hf_dusbv_ping_major = -1;
static int hf_dusbv_ping_minor = -1;
static int hf_dusbv_timeout = -1;
static int hf_dusbv_num_params = -1;
static int hf_dusbv_param_id = -1;
static int hf_dusbv_param_valid = -1;
static int hf_dusbv_param_len = -1;
static int hf_dusbv_param_val = -1;
static int hf_dusbv_num_attrs = -1;
static int hf_dusbv_attr_id = -1;
static int hf_dusbv_attr_valid = -1;
static int hf_dusbv_attr_len = -1;
static int hf_dusbv_attr_val = -1;
static int hf_dusbv_folder_name_len = -1;
static int hf_dusbv_folder_name = -1;
static int hf_dusbv_file_name_len = -1;
static int hf_dusbv_file_name = -1;
static int hf_dusbv_action = -1;
static int hf_dusbv_keycode = -1;
static int hf_dusbv_error = -1;
static int hf_dusbv_data = -1;

/* Initialize the subtree pointers */
static gint ett_dusbv = -1;

#define dusbv_MIN_LENGTH 6

#define DUSB_VPKT_PING      0x0001
#define DUSB_VPKT_OS_BEGIN	0x0002
#define DUSB_VPKT_OS_ACK    0x0003
#define DUSB_VPKT_OS_HEADER 0x0004
#define DUSB_VPKT_OS_DATA   0x0005
#define DUSB_VPKT_EOT_ACK   0x0006
#define DUSB_VPKT_PARM_REQ  0x0007
#define DUSB_VPKT_PARM_DATA 0x0008
#define DUSB_VPKT_DIR_REQ   0x0009
#define DUSB_VPKT_VAR_HDR   0x000A
#define DUSB_VPKT_RTS       0x000B
#define DUSB_VPKT_VAR_REQ   0x000C
#define DUSB_VPKT_VAR_CNTS  0x000D
#define DUSB_VPKT_PARM_SET  0x000E
#define DUSB_VPKT_MODIF_VAR 0x0010
#define DUSB_VPKT_EXECUTE   0x0011
#define DUSB_VPKT_MODE_SET  0x0012

#define DUSB_VPKT_DATA_ACK  0xAA00
#define DUSB_VPKT_DELAY_ACK 0xBB00
#define DUSB_VPKT_EOT       0xDD00
#define DUSB_VPKT_ERROR     0xEE00

#define DUSB_PID_PRODUCT_NUMBER         0x0001
#define DUSB_PID_PRODUCT_NAME           0x0002
#define DUSB_PID_MAIN_PART_ID           0x0003
#define DUSB_PID_HW_VERSION             0x0004
#define DUSB_PID_FULL_ID                0x0005
#define DUSB_PID_LANGUAGE_ID            0x0006
#define DUSB_PID_SUBLANG_ID             0x0007
#define DUSB_PID_DEVICE_TYPE            0x0008
#define DUSB_PID_BOOT_VERSION           0x0009
#define DUSB_PID_OS_MODE                0x000A
#define DUSB_PID_OS_VERSION             0x000B
#define DUSB_PID_PHYS_RAM               0x000C
#define DUSB_PID_USER_RAM               0x000D
#define DUSB_PID_FREE_RAM               0x000E
#define DUSB_PID_PHYS_FLASH             0x000F
#define DUSB_PID_USER_FLASH             0x0010
#define DUSB_PID_FREE_FLASH             0x0011
#define DUSB_PID_USER_PAGES             0x0012
#define DUSB_PID_FREE_PAGES             0x0013
// 0x0014-0x0018 (no access): 84+SE OS 2.43, 84+CSE OS 4.0, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) and 89T AMS 3.10 refuse being requested these parameter IDs.
#define DUSB_PID_HAS_SCREEN             0x0019
// 0x001A (read-only): 84+SE OS 2.43, 84+CSE OS 4.0 and 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) reply 00, 89T AMS 3.10 refuses being requested this parameter ID.
#define DUSB_PID_COLOR_AVAILABLE        0x001B
// 0x001C (read-only): 84+SE OS 2.43 replies 01, 84+CSE OS 4.0 and 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) reply 10, 89T AMS 3.10 refuses being requested this parameter ID.
#define DUSB_PID_BITS_PER_PIXEL         0x001D
#define DUSB_PID_LCD_WIDTH              0x001E
#define DUSB_PID_LCD_HEIGHT             0x001F
// 0x0020 (read-only): 84+SE OS 2.43 and 84+CSE OS 4.0 refuse being requested this parameter ID, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00 C8, 89T AMS 3.10 replies 00 23.
// 0x0021 (read-only): 84+SE OS 2.43 and 84+CSE OS 4.0 refuse being requested this parameter ID, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00 C8, 89T AMS 3.10 replies 00 23.
#define DUSB_PID_SCREENSHOT             0x0022
// 0x0023 (read-only): 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 reply 01; 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested this parameter ID.
#define DUSB_PID_CLASSIC_CLK_SUPPORT    0x0023
#define DUSB_PID_CLK_ON                 0x0024
#define DUSB_PID_CLK_SEC_SINCE_1997     0x0025
// 0x0026 (read-write): 84+SE OS 2.43 and 84+CSE OS 4.0 refuse being requested or set this parameter ID, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) and 89T AMS 3.10 reply 00 00.
#define DUSB_PID_CLK_DATE_FMT           0x0027
#define DUSB_PID_CLK_TIME_FMT           0x0028
// 0x0029 (read-only): 84+SE OS 2.43 replies 00, 84+CSE OS 4.0 and 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) reply 01, 89T AMS 3.10 refuses being requested this parameter ID.
// 0x002A: 84+SE OS 2.43, 84+CSE OS 4.0, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) and 89T AMS 3.10 refuse being requested this parameter ID.
// 0x002B (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies initially 00. 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 refuse being requested or set this parameter ID.
// 0x002C (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00. 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 refuse being requested this parameter ID.
#define DUSB_PID_BATTERY                0x002D
// 0x002E (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 64, 89T AMS 3.10 replies 01, 84+SE OS 2.43 and 84+CSE OS 4.0 refuse being requested this parameter ID.
// 0x002F (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 01. 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 refuse being requested this parameter ID.
// 0x0030 (read-write): 84+SE OS 2.43, 84+CSE OS 4.0 and 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) reply with 0x20 (32) bytes of data, initially all zeros. 89T AMS 3.10 refuses being requested this parameter ID.
// Data does not survive RAM clear. DUSB counterpart of DBUS RID + SID pair.
// 84+SE OS 2.43 reacts oddly to writes: written data does not necessarily read back ?
#define DUSB_PID_USER_DATA_1            0x0030
// 0x0031 (read-only): 83PCE (OS 5.1.5.0019, 5.2.0.0035) and 89T AMS 3.10 reply with a subset of FlashApp headers. 84+SE and 84+CSE perform a lengthy operation.
#define DUSB_PID_FLASHAPPS              0x0031
// 0x0032 (read-only): 84+SE OS 2.43, 84+CSE OS 4.0 and 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) reply 00, 89T AMS 3.10 refuses being requested this parameter ID.
// 0x0033-0x0034 (no access): 84+SE OS 2.43, 84+CSE OS 4.0, 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) and 89T AMS 3.10 refuse being requested these parameter IDs.
// 0x0035 (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies with 0x0A (10) bytes of data, initially all zeros. 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 refuse being requested this parameter ID.
// Data does not survive RAM clear. Behaves like PID 0x0030, only smaller. May have another purpose ?
#define DUSB_PID_USER_DATA_2            0x0035
#define DUSB_PID_MAIN_PART_ID_STRING    0x0036
#define DUSB_PID_HOMESCREEN             0x0037
#define DUSB_PID_BUSY                   0x0038
#define DUSB_PID_SCREEN_SPLIT           0x0039
// ---------- 84+SE OS 2.43, 84+CSE OS 4.0 and 89T AMS 3.10 refuse being requested or set parameter IDs beyond this ----------
// 0x003A (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 01
#define DUSB_PID_NEW_CLK_SUPPORT        0x003A
#define DUSB_PID_CLK_SECONDS            0x003B
#define DUSB_PID_CLK_MINUTES            0x003C
#define DUSB_PID_CLK_HOURS              0x003D
#define DUSB_PID_CLK_DAY                0x003E
#define DUSB_PID_CLK_MONTH              0x003F
#define DUSB_PID_CLK_YEAR               0x0040
// 0x0041 (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) initially replies 07 D0. Value is range-checked.
// 0x0042 (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00
// 0x0043 (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00
// 0x0044 (read-write): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00
// 0x0045 (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies F0 0F 00 00
#define DUSB_PID_ANS                    0x0046
// 0x0047 (read-only): 83PCE replies 00 (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035)
#define DUSB_PID_OS_BUILD_NUMBER        0x0048
#define DUSB_PID_BOOT_BUILD_NUMBER      0x0049
// 0x004A (read-only): 83PCE replies 00 (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035)
#define DUSB_PID_EXACT_MATH             0x004B
// 0x004C (read-only): 83PCE replies with 0x20 (32) bytes of data, no clear pattern: boot code SHA-256 hash.
// boot 5.0.0.0089: D6 98 7E 21 90 54 2F 1C 32 75 F5 EC A1 AF DF B5
//                  B2 20 14 A2 D3 E7 65 04 52 B1 D1 BD 3D 9D 1D 18
#define DUSB_PID_BOOT_HASH              0x004C
// 0x004D (read-only): 83PCE replies with 0x20 (32) bytes of data, no clear pattern: OS SHA-256 hash.
// OS 5.1.0.0110: 0D 83 11 A0 3C 9D 74 F0 6D 8C A4 22 6E 9A 30 BC
//                4F 87 E0 0C 7A 18 7A 6F 01 FC 3E 0C 04 E2 B7 88
// OS 5.1.1.0112: 03 65 22 56 EA 98 7C AE AD A4 29 85 70 A4 9D FA
//                05 28 97 71 0E 65 0B D7 DE 5F 15 93 1D A6 7C DB
// OS 5.1.5.0019: 1C 9A CA 19 26 00 41 B6 0A C4 C8 FB D0 B9 C3 72
//                AA 4F 1B 6C DC 49 B4 23 58 C6 14 E7 5E D6 D8 3D
// OS 5.2.0.0035: C4 52 E6 F4 8C 78 37 13 B8 AB B7 FE F2 20 DD 12
//                C5 C3 28 BA 23 BE A6 F3 68 57 77 DA 4F A5 C3 79
#define DUSB_PID_OS_HASH                0x004D
// 0x004E (write-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested these parameter IDs but acknowledges writes.
// 0x004F (write-only, multiple writes OR together): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested these parameter IDs but acknowledges writes.
// Writing 01 00 00 01 enables PTT mode with features 01 00 00.
// Writing 01 23 45 67 enables PTT mode with features 23 45 67.
// Writing 01 FE DC BA on top of the previous write enables PTT mode with features FF DD FF.
// Writing 01 00 02 00 on top of the previous write enables PTT mode with features FF DF FF.
// Right after writing 01 xx xx xx, the PTT mode is not completely activated yet: the bar at the top of the screen is not automatically updated, the PTT LED doesn't blink.
// Has a side effect on cursor position: moves it to the top left of the screen, overwriting top bar ??
#define DUSB_PID_PTT_MODE_SET           0x004F
// 0x0050 (write-only, but values sometimes refused ?): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested these parameter IDs.
// 0x0051 (no access): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested these parameter IDs
#define DUSB_PID_OS_VERSION_STRING      0x0052
#define DUSB_PID_BOOT_VERSION_STRING    0x0053
// 0x0054 (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00 when not in PTT mode, 01 when in PTT mode.
#define DUSB_PID_PTT_MODE_STATE         0x0054
// 0x0055 (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies 00 00 00 when not in PTT mode, 28 02 00 when in default PTT mode, and whatever was written there
#define DUSB_PID_PTT_MODE_FEATURES      0x0055
// 0x0056-0x0057 (read-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) replies with invalid format.
// 0x0058 (write-once): 83PCE OS 5.2.0.0035 replies with size 0. Error code 0012 occurs upon subsequent writes.
// 0x0059 (write-only): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested this parameter ID. But it can be written on OS 5.2.0.0035.
#define DUSB_PID_STOPWATCH_START        0x0059
// 0x005A (read-only): 83PCE OS 5.2.0.0035 replies 4 bytes. Fast up-counter, which runs even when stopwatch is stopped, reset by reads but not by keypresses.
// 0x005B (read-only): 83PCE OS 5.2.0.0035 replies 4 bytes. Fast up-counter, which runs only when stopwatch is started, not reset by reads.
#define DUSB_PID_STOPWATCH_VALUE1       0x005B
// 0x005C (read-only): 83PCE OS 5.2.0.0035 replies 4 bytes. Fast up-counter, which runs only when stopwatch is started, not reset by reads.
#define DUSB_PID_STOPWATCH_VALUE2       0x005C
// 0x005D-0x008F (no access): 83PCE (OS 5.1.0.0110, 5.1.1.0112, 5.1.5.0019, 5.2.0.0035) refuses being requested these parameter IDs; writes yield a 0004 error code.

#define DUSB_AID_VAR_SIZE               0x01
#define DUSB_AID_VAR_TYPE               0x02
#define DUSB_AID_ARCHIVED               0x03
#define DUSB_AID_IS_FILE             0x04
#define DUSB_AID_4APPVAR                0x05
#define DUSB_AID_VAR_VERSION            0x08
#define DUSB_AID_VAR_TYPE2              0x11
#define DUSB_AID_ARCHIVED2              0x13
#define DUSB_AID_LOCKED                 0x41
#define DUSB_AID_UNKNOWN_42             0x42
#define DUSB_AID_BACKUP_HEADER          0xFFFE

#define DUSB_EID_PRGM                   0x00
#define DUSB_EID_ASM                    0x01
#define DUSB_EID_APP                    0x02
#define DUSB_EID_KEY                    0x03
#define DUSB_EID_UNKNOWN                0x04

/* Code to actually dissect the packets */
static int
dissect_dusbv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *dusbv_tree;

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < dusbv_MIN_LENGTH)
        return 0;

    guint16 type = tvb_get_ntohs(tvb, 4);

    if (tvb_get_ntohl(tvb, 0) + 6 != tvb_reported_length(tvb))
        return 0;
    if (type == 0)
        return 0;

    /*** COLUMN DATA ***/

    /* Set the Protocol column to the constant string of dusbv */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "dusbv");

    switch (type) {
        case DUSB_VPKT_PING:
            col_set_str(pinfo->cinfo, COL_INFO, "Ping / Set Mode");
            break;
        case DUSB_VPKT_OS_BEGIN:
            col_set_str(pinfo->cinfo, COL_INFO, "Begin OS Transfer");
            break;
        case DUSB_VPKT_OS_ACK:
            col_set_str(pinfo->cinfo, COL_INFO, "Acknowledge OS Transfer");
            break;
        case DUSB_VPKT_OS_HEADER:
            col_set_str(pinfo->cinfo, COL_INFO, "OS Header");
            break;
        case DUSB_VPKT_OS_DATA:
            col_set_str(pinfo->cinfo, COL_INFO, "OS Data");
            break;
        case DUSB_VPKT_EOT_ACK:
            col_set_str(pinfo->cinfo, COL_INFO, "Acknowledge EOT");
            break;
        case DUSB_VPKT_PARM_REQ:
            col_set_str(pinfo->cinfo, COL_INFO, "Parameter Request");
            break;
        case DUSB_VPKT_PARM_DATA:
            col_set_str(pinfo->cinfo, COL_INFO, "Parameter Data");
            break;
        case DUSB_VPKT_DIR_REQ:
            col_set_str(pinfo->cinfo, COL_INFO, "Request Directory Listing");
            break;
        case DUSB_VPKT_VAR_HDR:
            col_set_str(pinfo->cinfo, COL_INFO, "Variable Header");
            break;
        case DUSB_VPKT_RTS:
            col_set_str(pinfo->cinfo, COL_INFO, "Request to Send");
            break;
        case DUSB_VPKT_VAR_REQ:
            col_set_str(pinfo->cinfo, COL_INFO, "Request Variable");
            break;
        case DUSB_VPKT_VAR_CNTS:
            col_set_str(pinfo->cinfo, COL_INFO, "Variable Contents");
            break;
        case DUSB_VPKT_PARM_SET:
            col_set_str(pinfo->cinfo, COL_INFO, "Parameter Set");
            break;
        case DUSB_VPKT_MODIF_VAR:
            col_set_str(pinfo->cinfo, COL_INFO, "Modify Variable");
            break;
        case DUSB_VPKT_EXECUTE:
            col_set_str(pinfo->cinfo, COL_INFO, "Remote Control");
            break;
        case DUSB_VPKT_MODE_SET:
            col_set_str(pinfo->cinfo, COL_INFO, "Acknowledge Mode Setting");
            break;
        case DUSB_VPKT_DATA_ACK:
            col_set_str(pinfo->cinfo, COL_INFO, "Acknowledge Data");
            break;
        case DUSB_VPKT_DELAY_ACK:
            col_set_str(pinfo->cinfo, COL_INFO, "Delay Acknowledgement");
            break;
        case DUSB_VPKT_EOT:
            col_set_str(pinfo->cinfo, COL_INFO, "End of Transmission");
            break;
        case DUSB_VPKT_ERROR:
            col_set_str(pinfo->cinfo, COL_INFO, "Error");
            break;
    }

    /*** PROTOCOL TREE ***/

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dusbv, tvb, 0, -1, ENC_NA);

    dusbv_tree = proto_item_add_subtree(ti, ett_dusbv);

    /* Continue adding tree items to process the packet here... */
    proto_tree_add_uint(dusbv_tree, hf_dusbv_len, tvb,
                        0, 4, tvb_get_ntohl(tvb, 0));
    proto_tree_add_uint(dusbv_tree, hf_dusbv_type, tvb,
                        4, 2, tvb_get_ntohs(tvb, 4));

    gint offset = 6;

    switch (type) {
        case DUSB_VPKT_PING:
            // Greet
            proto_tree_add_uint(dusbv_tree, hf_dusbv_ping_protocol, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            proto_tree_add_uint(dusbv_tree, hf_dusbv_ping_major, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            proto_tree_add_uint(dusbv_tree, hf_dusbv_ping_minor, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            proto_tree_add_uint(dusbv_tree, hf_dusbv_timeout, tvb,
                                offset, 4, tvb_get_ntohl(tvb, offset));
            offset += 4;
            break;
        case DUSB_VPKT_OS_BEGIN:
            // SendOS
            // 8 bits: interactive mode
            // 16 bits: type of OS
            // 64 bits: size of OS
            break;
        case DUSB_VPKT_OS_ACK:
            // SendOSResponse
            // 32 bits: bytes per packet
            // 16 bits: max time to wait
            break;
        case DUSB_VPKT_OS_HEADER:
            // OSHeader
            // ???
            break;
        case DUSB_VPKT_OS_DATA:
            // OSData
            // ???
            break;
        case DUSB_VPKT_EOT_ACK:
            // ValidationResponse
            // 8 bits: OS update status
            // 32 bits: silence period
            break;
        case DUSB_VPKT_PARM_REQ: {
            // Query
            // 16 bits: device parameter count
            // device parameter ids:
            //   16 bits: parameters ID
            guint32 num_params = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(dusbv_tree, hf_dusbv_num_params, tvb,
                                offset, 2, num_params);
            offset += 2;
            for (guint32 i = 0; i < num_params; i++) {
                proto_tree_add_uint(dusbv_tree, hf_dusbv_param_id, tvb,
                                    offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
            }
            break;
        }
        case DUSB_VPKT_PARM_DATA: {
            // QueryResponse
            // 16 bits: num params
            // param list:
            //   16 bits: param id
            //   8 bits: ok if 0
            //   if ok:
            //     16 bits: param value length
            //     param data
            guint16 num_params = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(dusbv_tree, hf_dusbv_num_params, tvb,
                                offset, 2, num_params);
            offset += 2;
            for (guint16 i = 0; i < num_params; i++) {
                proto_tree_add_uint(dusbv_tree, hf_dusbv_param_id, tvb,
                                    offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
                gboolean valid = !tvb_get_guint8(tvb, offset);
                proto_tree_add_boolean(dusbv_tree, hf_dusbv_param_valid, tvb,
                                       offset, 1, valid);
                offset++;
                if (valid) {
                    guint16 len = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_uint(dusbv_tree, hf_dusbv_param_len, tvb,
                                        offset, 2, len);
                    offset += 2;
                    proto_tree_add_item(dusbv_tree, hf_dusbv_param_val, tvb,
                                        offset, len, ENC_NA);
                    offset += len;
                }
            }
            break;
        }
        case DUSB_VPKT_DIR_REQ: {
            // GetDirectory
            // 32 bits: number of attributes requested
            // list of 16 bit attributes
            // ????
            guint32 num_attrs = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint(dusbv_tree, hf_dusbv_num_attrs, tvb,
                                offset, 4, num_attrs);
            offset += 4;
            for (guint32 i = 0; i < num_attrs; i++) {
                proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_id, tvb,
                                    offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
            }
            break;
        }
        case DUSB_VPKT_VAR_HDR: {
            // DirectoryData
            // name: name
            // 16 bits: number of attributes
            // attribute list:
            //   16 bits: attribute ID
            //   8 bits: 0 if valid
            //   if 0:
            //     16 bits: attribute data length
            //     attribute data

            offset = read_name(tvb, dusbv_tree, offset);

            guint16 num_attrs = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(dusbv_tree, hf_dusbv_num_attrs, tvb,
                                offset, 2, num_attrs);
            offset += 2;
            for (guint16 i = 0; i < num_attrs; i++) {
                proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_id, tvb,
                                    offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
                gboolean valid = !tvb_get_guint8(tvb, offset);
                proto_tree_add_boolean(dusbv_tree, hf_dusbv_attr_valid, tvb,
                                       offset, 1, valid);
                offset++;
                if (valid) {
                    guint16 len = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_len, tvb,
                                        offset, 2, len);
                    offset += 2;
                    proto_tree_add_item(dusbv_tree, hf_dusbv_attr_val, tvb,
                                        offset, len, ENC_NA);
                    offset += len;
                }
            }
        }
            break;
        case DUSB_VPKT_RTS:
            // Send
            // name: name
            // 00 00 00 09 01
            // attribute list: attributes
            offset = read_name(tvb, dusbv_tree, offset);
            offset += 5;
            offset = read_attribute_values(tvb, dusbv_tree, offset);
            break;
        case DUSB_VPKT_VAR_REQ: {
            // Get
            // name: name
            // 01 FF FF FF FF
            // 16 bits: num attributes requested
            // attribute id list: attributes requested
            // attribute list: actual attributes
            offset = read_name(tvb, dusbv_tree, offset);
            offset += 5;
            guint32 num_attrs = tvb_get_ntohs(tvb, offset);
            // todo: tree item for this?
            proto_tree_add_uint(dusbv_tree, hf_dusbv_num_attrs, tvb,
                                offset, 2, num_attrs);
            offset += 2;
            for (guint32 i = 0; i < num_attrs; i++) {
                proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_id, tvb,
                                    offset, 2, tvb_get_ntohs(tvb, offset));
                offset += 2;
            }
            offset = read_attribute_values(tvb, dusbv_tree, offset);
            break;
        }
        case DUSB_VPKT_VAR_CNTS:
            // Data
            // data
            proto_tree_add_item(dusbv_tree, hf_dusbv_data, tvb,
                                offset, -1, ENC_NA);
            break;
        case DUSB_VPKT_PARM_SET:
            // Set
            // 16 bits: id
            // 16 bits: size
            // data
            proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_id, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            proto_tree_add_uint(dusbv_tree, hf_dusbv_attr_len, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            proto_tree_add_item(dusbv_tree, hf_dusbv_attr_val, tvb,
                                offset, -1, ENC_NA);
            break;
        case 15:
            // SetResponse
            break;
        case DUSB_VPKT_MODIF_VAR:
            // Move
            // name: source name
            // attribute list: source attributes
            // 0x01 ?
            // name: dest name
            // attribute list: dest attributes
            // todo: subtrees for this?
            offset = read_name(tvb, dusbv_tree, offset);
            offset = read_attribute_values(tvb, dusbv_tree, offset);
            offset++;
            offset = read_name(tvb, dusbv_tree, offset);
            offset = read_attribute_values(tvb, dusbv_tree, offset);
            break;
        case DUSB_VPKT_EXECUTE: {
            // Execute
            // name: name
            // 8 bits: action
            // if action == KEY
            //   16 bits: keycode (le on z80, be on ez80)
            offset = read_name(tvb, dusbv_tree, offset);
            int action = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(dusbv_tree, hf_dusbv_action, tvb,
                                offset, 1, action);
            offset++;
            if (action == DUSB_EID_KEY) {
                guint16 keycode = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(dusbv_tree, hf_dusbv_keycode, tvb,
                                    offset, 2, keycode);
                offset += 2;
            }
            break;
        }
        case DUSB_VPKT_MODE_SET:
            // GreetResponse
            proto_tree_add_uint(dusbv_tree, hf_dusbv_timeout, tvb,
                                offset, 4, tvb_get_ntohl(tvb, offset));
            offset += 4;
            break;
        case DUSB_VPKT_DATA_ACK:
            // Ack
            // 8 bits: 1 if success?
            break;
        case DUSB_VPKT_DELAY_ACK:
            // Wait
            proto_tree_add_uint(dusbv_tree, hf_dusbv_timeout, tvb,
                                offset, 4, tvb_get_ntohl(tvb, offset));
            offset += 4;
            break;
        case DUSB_VPKT_EOT:
            // Done
            break;
        case DUSB_VPKT_ERROR:
            // Error
            proto_tree_add_uint(dusbv_tree, hf_dusbv_error, tvb,
                                offset, 2, tvb_get_ntohs(tvb, offset));
            offset += 2;
            break;
    }
    return tvb_captured_length(tvb);
}

static int
read_name(tvbuff_t *tvb, proto_tree *tree, int offset) {
    // 8 bits: length of name of folder
    // if nonzero:
    //   folder name
    //   null terminator
    // 8 bits: length of name of file
    // file name
    // null terminator
    guint8 folder_name_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_dusbv_folder_name_len, tvb,
                        offset, 1, folder_name_len);
    offset++;
    if(folder_name_len) {
        proto_tree_add_item(tree, hf_dusbv_folder_name, tvb,
                              offset, folder_name_len + 1, ENC_UTF_8);
        offset += folder_name_len + 1;
    }
    guint8 file_name_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_dusbv_file_name_len, tvb,
                        offset, 1, file_name_len);
    offset++;
    if(file_name_len) {
        proto_tree_add_item(tree, hf_dusbv_file_name, tvb,
                            offset, file_name_len + 1, ENC_UTF_8);
        offset += file_name_len + 1;
    }
    return offset;
}

static int
read_attribute_values(tvbuff_t *tvb, proto_tree *tree, int offset) {
    // 16 bits: num attributes
    // attribute list:
    //   16 bits: attribute ID
    //   16 bits: attribute length
    //   attribute data
    guint16 num_attrs = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_dusbv_num_attrs, tvb,
                        offset, 2, num_attrs);
    offset += 2;
    for (guint16 i = 0; i < num_attrs; i++) {
        proto_tree_add_uint(tree, hf_dusbv_attr_id, tvb,
                            offset, 2, tvb_get_ntohs(tvb, offset));
        offset += 2;
        guint16 len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_dusbv_attr_len, tvb,
                            offset, 2, len);
        offset += 2;
        proto_tree_add_item(tree, hf_dusbv_attr_val, tvb,
                            offset, len, ENC_NA);
        offset += len;
    }
    return offset;
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_dusbv(void)
{
    static const value_string type_strings[] = {
            { DUSB_VPKT_PING, "Ping / Set Mode" },
            { DUSB_VPKT_OS_BEGIN, "Begin OS Transfer" },
            { DUSB_VPKT_OS_ACK, "Acknowledgement of OS Transfer" },
            { DUSB_VPKT_OS_HEADER, "OS Header" },
            { DUSB_VPKT_OS_DATA, "OS Data" },
            { DUSB_VPKT_EOT_ACK, "Acknowledgement of EOT" },
            { DUSB_VPKT_PARM_REQ, "Parameter Request" },
            { DUSB_VPKT_PARM_DATA, "Parameter Data" },
            { DUSB_VPKT_DIR_REQ, "Request Directory Listing" },
            { DUSB_VPKT_VAR_HDR, "Variable Header" },
            { DUSB_VPKT_RTS, "Request to Send" },
            { DUSB_VPKT_VAR_REQ, "Request Variable" },
            { DUSB_VPKT_VAR_CNTS, "Variable Contents" },
            { DUSB_VPKT_PARM_SET, "Parameter Set" },
            { DUSB_VPKT_MODIF_VAR, "Modify Variable" },
            { DUSB_VPKT_EXECUTE, "Remote Control" },
            { DUSB_VPKT_MODE_SET, "Acknowledgement of Mode Setting" },
            { DUSB_VPKT_DATA_ACK, "Acknowledgement of Data" },
            { DUSB_VPKT_DELAY_ACK, "Delay Acknowledgment" },
            { DUSB_VPKT_EOT, "End of Transmission" },
            { DUSB_VPKT_ERROR, "Error" },
            { 0, NULL }
    };
    static const value_string parameter_names[] = {
            { DUSB_PID_PRODUCT_NUMBER, "Product number" },
            { DUSB_PID_PRODUCT_NAME, "Product name" },
            { DUSB_PID_MAIN_PART_ID, "Main part ID" },
            { DUSB_PID_HW_VERSION, "Hardware version" },
            { DUSB_PID_FULL_ID, "Full ID" },
            { DUSB_PID_LANGUAGE_ID, "Language ID" },
            { DUSB_PID_SUBLANG_ID, "Sub-language ID" },
            { DUSB_PID_DEVICE_TYPE, "Device type" },
            { DUSB_PID_BOOT_VERSION, "Boot version" },
            { DUSB_PID_OS_MODE, "OS mode" },
            { DUSB_PID_OS_VERSION, "OS version" },
            { DUSB_PID_PHYS_RAM, "Physical RAM" },
            { DUSB_PID_USER_RAM, "User RAM" },
            { DUSB_PID_FREE_RAM, "Free RAM" },
            { DUSB_PID_PHYS_FLASH, "Physical Flash" },
            { DUSB_PID_USER_FLASH, "User Flash" },
            { DUSB_PID_FREE_FLASH, "Free Flash" },
            { DUSB_PID_USER_PAGES, "User pages" },
            { DUSB_PID_FREE_PAGES, "Free pages" }, // 0x0013
            { DUSB_PID_HAS_SCREEN, "Has screen" }, // 0x0019
            { DUSB_PID_COLOR_AVAILABLE, "Color is available" }, // 0x001B
            { DUSB_PID_BITS_PER_PIXEL, "Bits per pixel" }, // 0x001D
            { DUSB_PID_LCD_WIDTH, "LCD width" },
            { DUSB_PID_LCD_HEIGHT, "LCD height" }, // 0x001F
            { DUSB_PID_SCREENSHOT, "Screenshot" }, // 0x0022
            { DUSB_PID_CLASSIC_CLK_SUPPORT, "Classic clock supported" },
            { DUSB_PID_CLK_ON, "Clock ON" },
            { DUSB_PID_CLK_SEC_SINCE_1997, "Clock sec since 1997" }, // 0x0025
            { DUSB_PID_CLK_DATE_FMT, "Clock date format" }, // 0x0027
            { DUSB_PID_CLK_TIME_FMT, "Clock time format" }, // 0x0028
            { DUSB_PID_BATTERY, "Battery level" }, // 0x002D
            { DUSB_PID_USER_DATA_1, "User data area 1" }, // 0x0030
            { DUSB_PID_FLASHAPPS, "FlashApps" }, // 0x0031
            { DUSB_PID_USER_DATA_2, "User data area 2" }, // 0x0035
            { DUSB_PID_MAIN_PART_ID_STRING, "Main part ID (as string)" }, // 0x0036
            { DUSB_PID_HOMESCREEN, "Home screen" },
            { DUSB_PID_BUSY, "Busy" },
            { DUSB_PID_SCREEN_SPLIT, "Screen split mode" }, // 0x0039
            { DUSB_PID_NEW_CLK_SUPPORT, "New clock supported" },
            { DUSB_PID_CLK_SECONDS, "Clock seconds" },
            { DUSB_PID_CLK_MINUTES, "Clock minutes" },
            { DUSB_PID_CLK_HOURS, "Clock hours" },
            { DUSB_PID_CLK_DAY, "Clock day" },
            { DUSB_PID_CLK_MONTH, "Clock month" },
            { DUSB_PID_CLK_YEAR, "Clock year" }, // 0x0040
            { DUSB_PID_ANS, "Ans contents" }, // 0x0046
            { DUSB_PID_OS_BUILD_NUMBER, "OS build number" }, // 0x0048
            { DUSB_PID_BOOT_BUILD_NUMBER, "Boot build number" }, // 0x0049
            { DUSB_PID_EXACT_MATH, "Exact math engine" }, // 0x004B
            { DUSB_PID_BOOT_HASH, "Boot hash" }, // 0x004C
            { DUSB_PID_OS_HASH, "OS hash" }, // 0x004D
            { DUSB_PID_PTT_MODE_SET, "PTT mode set" }, // 0x004F
            { DUSB_PID_OS_VERSION_STRING, "OS version (as string)" }, // 0x0052
            { DUSB_PID_BOOT_VERSION_STRING, "Boot version (as string)" }, // 0x0053
            { DUSB_PID_PTT_MODE_STATE, "PTT mode state" }, // 0x0054
            { DUSB_PID_PTT_MODE_FEATURES, "PTT mode features" }, // 0x0055
            { DUSB_PID_STOPWATCH_START, "Stopwatch start" }, // 0x0059
            { DUSB_PID_STOPWATCH_VALUE1, "Stopwatch value 1" }, // 0x005B
            { DUSB_PID_STOPWATCH_VALUE2, "Stopwatch value 2" }, // 0x005C
            { 0, NULL }
    };
    static const value_string attribute_names[] = {
            { DUSB_AID_VAR_SIZE, "Variable Size" },
            { DUSB_AID_VAR_TYPE, "Variable Type" },
            { DUSB_AID_ARCHIVED, "Archived" },
            { DUSB_AID_IS_FILE, "Is Variable" },
            { DUSB_AID_4APPVAR, "Appvar Type" },
            { DUSB_AID_VAR_VERSION, "Variable Version" },
            { DUSB_AID_VAR_TYPE2, "Variable Type 2" },
            { DUSB_AID_ARCHIVED2, "Archived 2" },
            { DUSB_AID_LOCKED, "Locked" },
            { DUSB_AID_UNKNOWN_42, "Variable Access" },
            { DUSB_AID_BACKUP_HEADER, "Backup Header" },
            { 0, NULL }
    };
    static const value_string action_names[]= {
            { DUSB_EID_PRGM, "BASIC Program" },
            { DUSB_EID_ASM, "Assembly Program" },
            { DUSB_EID_APP, "Application" },
            { DUSB_EID_KEY, "Keypress" },
            { DUSB_EID_UNKNOWN, "Unknown Action" },
            { 0, NULL }
    };
    static hf_register_info hf[] = {
            { &hf_dusbv_len,
              { "Length", "dusbv.len",
                FT_UINT32, BASE_DEC, NULL, 0,
                "Length", HFILL }
            },
            { &hf_dusbv_type,
              { "Type", "dusbv.type",
                FT_UINT16, BASE_DEC, VALS(type_strings), 0,
                "Type", HFILL }
            },
            { &hf_dusbv_ping_protocol,
              { "Protocol", "dusbv.ping.protocol",
                      FT_UINT16, BASE_DEC, NULL, 0,
                      "Protocol", HFILL }
            },
            { &hf_dusbv_ping_major,
              { "Major", "dusbv.ping.major",
                      FT_UINT16, BASE_DEC, NULL, 0,
                      "Major Version", HFILL }
            },
            { &hf_dusbv_ping_minor,
              { "Minor", "dusbv.ping.minor",
                      FT_UINT16, BASE_DEC, NULL, 0,
                      "Minor Version", HFILL }
            },
            { &hf_dusbv_timeout,
              { "Timeout", "dusbv.timeout",
                FT_UINT32, BASE_DEC, NULL, 0,
                "Timeout", HFILL }
            },
            { &hf_dusbv_num_params,
                    { "Parameter Count", "dusbv.num_params",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Parameter Count", HFILL }
            },
            { &hf_dusbv_param_id,
                    { "Parameter ID", "dusbv.param.id",
                            FT_UINT16, BASE_HEX, VALS(parameter_names), 0,
                            "Parameter ID", HFILL }
            },
            { &hf_dusbv_param_valid,
                    { "Parameter Valid", "dusbv.param.valid",
                            FT_BOOLEAN, BASE_NONE, NULL, 0,
                            "Parameter Valid", HFILL }
            },
            { &hf_dusbv_param_len,
                    { "Parameter Length", "dusbv.param.len",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Parameter Length", HFILL }
            },
            { &hf_dusbv_param_val,
                    { "Parameter ID", "dusbv.param.val",
                            FT_BYTES, BASE_NONE, NULL, 0,
                            "Parameter ID", HFILL }
            },
            { &hf_dusbv_num_attrs,
                    { "Attribute Count", "dusbv.num_attrs",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Attribute Count", HFILL }
            },
            { &hf_dusbv_attr_id,
                    { "Attribute ID", "dusbv.attr.id",
                            FT_UINT16, BASE_HEX, VALS(attribute_names), 0,
                            "Attribute ID", HFILL }
            },
            { &hf_dusbv_attr_valid,
                        { "Attribute Valid", "dusbv.attr.valid",
                          FT_BOOLEAN, BASE_NONE, NULL, 0,
                          "Attribute Valid", HFILL }
            },
            { &hf_dusbv_attr_len,
                    { "Attribute Length", "dusbv.attr.len",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Attribute length", HFILL }
            },
            { &hf_dusbv_attr_val,
                    { "Attribute Value", "dusbv.attr.val",
                            FT_BYTES, BASE_NONE, NULL, 0,
                            "Attribute Value", HFILL }
            },
            { &hf_dusbv_folder_name_len,
                    { "Folder Name Length", "dusbv.folder_name.len",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Folder Name Length", HFILL }
            },
            { &hf_dusbv_folder_name,
                    { "Folder Name", "dusbv.folder_name",
                            FT_STRING, BASE_NONE, NULL, 0,
                            "Folder Name", HFILL }
            },
            { &hf_dusbv_file_name_len,
                    { "File Name Length", "dusbv.file_name.len",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "File Name Length", HFILL }
            },
            { &hf_dusbv_file_name,
                    { "File Name", "dusbv.file_name",
                            FT_STRING, BASE_NONE, NULL, 0,
                            "File Name", HFILL }
            },
            { &hf_dusbv_action,
                    { "Action", "dusbv.action",
                            FT_UINT8, BASE_DEC, VALS(action_names), 0,
                            "Execute Action", HFILL }
            },
            { &hf_dusbv_keycode,
                    { "Keycode", "dusbv.keycode",
                            FT_UINT16, BASE_HEX, NULL, 0,
                            "Keycode", HFILL }
            },
            { &hf_dusbv_error,
              { "Error", "dusbv.error",
                      FT_UINT16, BASE_HEX, NULL, 0,
                      "Error Code", HFILL }
            },
            { &hf_dusbv_data,
                        { "Data", "dusbv.data",
                          FT_BYTES, BASE_NONE, NULL, 0,
                          "Data", HFILL }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dusbv
    };

    /* Register the protocol name and description */
    proto_dusbv = proto_register_protocol("DUSB Virtual",
            "DUSB Virtual", "dusbv");

    register_dissector("dusbv", dissect_dusbv, proto_dusbv);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_dusbv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Simpler form of proto_reg_handoff_dusbv which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_dusbv(void)
{
    /* Use create_dissector_handle() to indicate that dissect_dusbv()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to DUSB Virtual).
     */
    
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
