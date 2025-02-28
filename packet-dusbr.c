/* packet-dusb.c
 * Routines for DUSB Raw dissection
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
#include <epan/conversation.h>
#include <epan/dissectors/packet-usb.h>
#include <stdio.h>
#include <epan/reassemble.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_dusbr(void);
void proto_register_dusbr(void);

static dissector_handle_t dusbv_handle;

static reassembly_table dusbr_reassembly_table;

static int hf_dusbr_fragments = -1;
static int hf_dusbr_fragment = -1;
static int hf_dusbr_fragment_overlap = -1;
static int hf_dusbr_fragment_overlap_conflicts = -1;
static int hf_dusbr_fragment_multiple_tails = -1;
static int hf_dusbr_fragment_too_long_fragment = -1;
static int hf_dusbr_fragment_error = -1;
static int hf_dusbr_fragment_count = -1;
static int hf_dusbr_reassembled_in = -1;
static int hf_dusbr_reassembled_length = -1;

static gint ett_dusbr_fragment = -1;
static gint ett_dusbr_fragments = -1;

static const fragment_items dusbr_frag_items = {
        /* Fragment subtrees */
        &ett_dusbr_fragment,
        &ett_dusbr_fragments,
        /* Fragment fields */
        &hf_dusbr_fragments,
        &hf_dusbr_fragment,
        &hf_dusbr_fragment_overlap,
        &hf_dusbr_fragment_overlap_conflicts,
        &hf_dusbr_fragment_multiple_tails,
        &hf_dusbr_fragment_too_long_fragment,
        &hf_dusbr_fragment_error,
        &hf_dusbr_fragment_count,
        /* Reassembled in field */
        &hf_dusbr_reassembled_in,
        /* Reassembled length field */
        &hf_dusbr_reassembled_length,
        /* Reassembled data field */
        NULL,
        /* Tag */
        "dusb fragments"
};

/* Initialize the protocol and registered fields */
static int proto_dusbr = -1;
static int hf_dusbr_len = -1;
static int hf_dusbr_type = -1;
static int hf_dusbr_buf_len = -1;
static int hf_dusbr_error = -1;
static int hf_dusbr_data = -1;

/* Initialize the subtree pointers */
static gint ett_dusbr = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define dusbr_MIN_LENGTH 5
#define dusbr_MAX_LENGTH 1028

#define DUSB_RPKT_BUF_SIZE_REQ   1
#define DUSB_RPKT_BUF_SIZE_ALLOC 2
#define DUSB_RPKT_VIRT_DATA      3
#define DUSB_RPKT_VIRT_DATA_LAST 4
#define DUSB_RPKT_VIRT_DATA_ACK  5

/* Code to actually dissect the packets */
static int
dissect_dusbr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *dusbr_tree;

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < dusbr_MIN_LENGTH)
        return 0;
    if (tvb_reported_length(tvb) > dusbr_MAX_LENGTH)
        return 0;

    guint8 type = tvb_get_guint8(tvb, 4);
    guint32 len = tvb_get_ntohl(tvb, 0);

    if (type == 0)
        return 0;
    if (type > DUSB_RPKT_VIRT_DATA_ACK)
        return 0;
    if (len + 5 != tvb_reported_length(tvb))
        return 0;

    /*** COLUMN DATA ***/

    /* Set the Protocol column to the constant string of dusbr */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "dusbr");

    switch (type) {
        case DUSB_RPKT_BUF_SIZE_REQ:
            col_set_str(pinfo->cinfo, COL_INFO, "Buffer size request");
            break;
        case DUSB_RPKT_BUF_SIZE_ALLOC:
            col_set_str(pinfo->cinfo, COL_INFO, "Buffer size alloc");
            break;
        case DUSB_RPKT_VIRT_DATA:
            col_set_str(pinfo->cinfo, COL_INFO, "Virtual data");
            break;
        case DUSB_RPKT_VIRT_DATA_LAST:
            col_set_str(pinfo->cinfo, COL_INFO, "Virtual data last");
            break;
        case DUSB_RPKT_VIRT_DATA_ACK:
            col_set_str(pinfo->cinfo, COL_INFO, "Virtual data ACK");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown dusbr packet");
    }

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dusbr, tvb, 0, -1, ENC_NA);
    dusbr_tree = proto_item_add_subtree(ti, ett_dusbr);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    proto_tree_add_uint(dusbr_tree, hf_dusbr_len, tvb,
                        0, 4, tvb_get_ntohl(tvb, 0));
    proto_tree_add_uint(dusbr_tree, hf_dusbr_type, tvb,
                                    4, 1, tvb_get_guint8(tvb, 4));

    /* Continue adding tree items to process the packet here... */

    switch (type) {
        case DUSB_RPKT_BUF_SIZE_REQ:
        case DUSB_RPKT_BUF_SIZE_ALLOC:
            proto_tree_add_uint(dusbr_tree, hf_dusbr_buf_len, tvb,
                                5, 4, tvb_get_ntohl(tvb, 5));
            break;
        case DUSB_RPKT_VIRT_DATA:
        case DUSB_RPKT_VIRT_DATA_LAST:
            proto_tree_add_item(dusbr_tree, hf_dusbr_data, tvb, 5, -1, ENC_NA);
            break;
        case DUSB_RPKT_VIRT_DATA_ACK:
            proto_tree_add_uint(dusbr_tree, hf_dusbr_error, tvb,
                                5, 2, tvb_get_ntohs(tvb, 5));
            break;
    }

    fragment_head *frag_msg = NULL;
    tvbuff_t *next_tvb = NULL;
    guint32 dusbr_id = 0;

    conversation_t *conversation = find_conversation_pinfo(pinfo, 0);
    if (conversation != NULL) {
        dusbr_id = conversation->conv_index;
    }

    if(type == DUSB_RPKT_VIRT_DATA || type == DUSB_RPKT_VIRT_DATA_LAST) {
        frag_msg = fragment_add_seq_next (&dusbr_reassembly_table,
                                          tvb, 5, pinfo,
                                          dusbr_id, NULL,
                                          len, type == DUSB_RPKT_VIRT_DATA);
    }

    next_tvb = process_reassembled_data (tvb, 5, pinfo, "Reassembled DUSB",
                                         frag_msg, &dusbr_frag_items, NULL, tree);

    if(next_tvb) {
        //proto_tree_add_item(tree, proto_dusbr, next_tvb, 0, -1, ENC_NA);
        call_dissector(dusbv_handle, next_tvb, pinfo, tree);
    }

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_dusbr(void)
{
    static const value_string type_strings[] = {
            {DUSB_RPKT_BUF_SIZE_REQ, "Buffer size request"},
            {DUSB_RPKT_BUF_SIZE_ALLOC, "Buffer size alloc"},
            {DUSB_RPKT_VIRT_DATA, "Virtual data"},
            {DUSB_RPKT_VIRT_DATA_LAST, "Virtual data last"},
            {DUSB_RPKT_VIRT_DATA_ACK, "Virtual data ACK"},
            {0, NULL}
    };

    static const value_string err_strings[] = {
            {52428, "Cancel"},
            {52429, "Cancel All"},
            {57344, "Fragmentation Ack"},
            {61424, "Protocol Violation"},
            {61440, "Bad Device Parameter Block"},
            {61441, "Missing Directory Information"},
            {61442, "Missing Data Information"},
            {61443, "Unable to Allocate Packet"},
            {61444, "Short Send Receive"},
            {61445, "Communications Failure"},
            {61446, "Device Disconnected"},
            {65520, "Not in Correct Receive Mode"},
            {0, NULL}
    };

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_dusbr_len,
          { "Length", "dusbr.len",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Length", HFILL }
        },
        { &hf_dusbr_type,
          { "Type", "dusbr.type",
            FT_UINT8, BASE_DEC, VALS(type_strings), 0,
            "Type", HFILL }
        },
        { &hf_dusbr_buf_len,
          { "Buffer Length", "dusbr.buf_len",
                  FT_UINT32, BASE_HEX_DEC, NULL, 0,
                "Length of allocated buffer", HFILL }
        },
        { &hf_dusbr_error,
          { "Error", "dusbr.error",
                  FT_UINT16, BASE_HEX, VALS(err_strings), 0,
                  "Error code", HFILL }
        },
        { &hf_dusbr_data,
          { "Data", "dusbr.data",
                  FT_BYTES, BASE_NONE, NULL, 0,
                  "Data", HFILL }
        },
        { &hf_dusbr_fragments,
                { "dusb fragments", "dusb.fragments", FT_NONE, BASE_NONE,
                                               NULL, 0x00, NULL, HFILL } },
        { &hf_dusbr_fragment,
                { "dusb fragment", "dusb.fragment", FT_FRAMENUM, BASE_NONE,
                                               NULL, 0x00, NULL, HFILL } },
        { &hf_dusbr_fragment_overlap,
                { "dusb fragment overlap", "dusb.fragment.overlap", FT_BOOLEAN,
                        BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dusbr_fragment_overlap_conflicts,
                { "dusb fragment overlapping with conflicting data",
                        "dusb.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
                                               NULL, 0x0, NULL, HFILL } },
        { &hf_dusbr_fragment_multiple_tails,
                { "dusb has multiple tail fragments",
                        "dusb.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
                                               NULL, 0x0, NULL, HFILL } },
        { &hf_dusbr_fragment_too_long_fragment,
                { "dusb fragment too long", "dusb.fragment.too_long_fragment",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dusbr_fragment_error,
                { "dusb defragmentation error", "dusb.fragment.error", FT_FRAMENUM,
                        BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_dusbr_fragment_count,
                { "dusb fragment count", "dusb.fragment.count", FT_UINT32, BASE_DEC,
                                               NULL, 0x00, NULL, HFILL } },
        { &hf_dusbr_reassembled_in,
                { "Reassembled dusb in frame", "dusb.reassembled.in", FT_FRAMENUM, BASE_NONE,
                                               NULL, 0x00, "This dusb packet is reassembled in this frame", HFILL } },
        { &hf_dusbr_reassembled_length,
                { "Reassembled dusb length", "dusb.reassembled.length", FT_UINT32, BASE_DEC,
                                               NULL, 0x00, "The total length of the reassembled payload", HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dusbr,
        &ett_dusbr_fragment,
        &ett_dusbr_fragments
    };

    /* Register the protocol name and description */
    proto_dusbr = proto_register_protocol("DUSB Raw",
            "DUSB Raw", "dusbr");

    reassembly_table_register (&dusbr_reassembly_table,
                               &addresses_reassembly_table_functions);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_dusbr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_dusbr(void)
{
    static dissector_handle_t dusbr_handle;

    /* Use create_dissector_handle() to indicate that
     * dissect_dusbr() returns the number of bytes it dissected (or 0
     * if it thinks the packet does not belong to DUSB Raw).
     */
    dusbr_handle = create_dissector_handle(dissect_dusbr,
            proto_dusbr);

    dissector_add_uint("usb.product", 0x0451e008, dusbr_handle);
    dissector_add_for_decode_as("usb.device", dusbr_handle);

    dusbv_handle = find_dissector_add_dependency("dusbv", proto_dusbr);
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
