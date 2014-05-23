/* packet-gdbrsp.c
 *
 * Copyright (c) 2013 Simon Marchi <simon.marchi@polymtl.ca>
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 *
 * Based on the Wireshark Dissector template by Reinhold Kainhofer.
 *
 * Based on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <config.h>
#include <epan/packet.h>
#include <stdio.h>
#include <ctype.h>
#include <epan/dissectors/packet-tcp.h>

#define gdbrsp_PORT 1234

/* The protocol handle */
static int proto_gdbrsp = -1;

/* The main subtree handle */
static gint ett_gdbrsp = -1;

/* Other subtrees */
static gint ett_qsupported = -1;
static gint ett_program_signals = -1;

/* Variables for fields */
static int hf_command = -1;
static int hf_ack = -1;
static int hf_qsupported = -1;
static int hf_checksum = -1;
static int hf_reply_to = -1;
static int hf_address = -1;
static int hf_length = -1;
static int hf_bytes = -1;
static int hf_request_in = -1;
static int hf_reply_in = -1;
static int hf_ack_to = -1;
static int hf_reply_ok_error = -1;
static int hf_disable_randomization = -1;
static int hf_vcont_action = -1;
static int hf_vcont_is_supported = -1;
static int hf_program_signal = -1;
static int hf_doc_link = -1;

// strlen("#XX");
static const guint crc_len = 3;

enum gdb_msg_type {
	GDB_HOST_QUERY, GDB_HOST_ACK, GDB_STUB_REPLY, GDB_STUB_ACK, GDB_NOTIFICATION,
};

struct gdbrsp_conv_data;

struct dissect_command_t {
	const char *command;
	void (*command_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
			struct gdbrsp_conv_data *conv);
	void (*reply_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
			struct gdbrsp_conv_data *conv);
	const char *doc_url;
};

struct per_packet_data {
	enum gdb_msg_type type;
	/* The command this request/reply is for */
	struct dissect_command_t *command;
	/* Reply framenum for request and vice-versa. */
	gint matching_framenum;

	union {
		struct {
			int requested_len;
		} m;
	} u;
};

struct gdbrsp_conv_data {
	enum gdb_msg_type next_expected_msg;

	/* Details about last command processed */
	struct dissect_command_t *last_command;
	guint last_packet_framenum;
	struct per_packet_data *last_request_data;

	int ack_enabled;
	/* When we see QStartNoAckMode, we know that the next host ack will be the last. */
	int disable_ack_at_next_host_ack;
};

char* ack_types[] = { "Packet received correctly", "Retransmission requested", };

const char *gdb_signal_names[] = {
#define SET(symbol, constant, name, string) name,
#include "signals.def"
#undef SET
};

const char *gdb_signal_descriptions[] = {
#define SET(symbol, constant, name, string) string,
#include "signals.def"
#undef SET
};

struct split_result {
	gint offset_start;
	const guint8 *val;
};

static GArray *split_payload(tvbuff_t *tvb, guint offset, guint msg_len, gchar split_char) {
	struct split_result elem;
	GArray *ret = g_array_new(FALSE, FALSE, sizeof(elem));
	gint found_offset;
	gint end_offset = offset + msg_len; // past last byte

	found_offset = tvb_find_guint8(tvb, offset, msg_len, split_char);
	while (found_offset != -1) {
		const guint8 *val = tvb_get_ephemeral_string(tvb, offset, found_offset - offset);

		elem.offset_start = offset;
		elem.val = val;

		g_array_append_val(ret, elem);

		// Skip the ;
		offset = found_offset + 1;
		found_offset = tvb_find_guint8(tvb, offset, msg_len, split_char);
	}

	if (end_offset - offset) {
		elem.val = tvb_get_ephemeral_string(tvb, offset, end_offset - offset);
		elem.offset_start = offset;

		g_array_append_val(ret, elem);
	}

	return ret;
}

static const char *vcont_command_description(char c) {
	switch (c) {
	case 'c':
		return "Continue";
	case 'C':
		return "Continue with signal";
	case 's':
		return "Step";
	case 'S':
		return "Step with signal";
	case 't':
		return "Stop";
	case 'r':
		return "Range step";
	}

	return NULL;
}

static void dissect_ok_error_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	if (msg_len == 0) {
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, offset, msg_len, "Target does not support this command");
		return;
	}

	if (tvb_strneql(tvb, offset, "OK", 2) == 0) {
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, offset, msg_len, "OK");
		return;
	}

	if (tvb_get_guint8(tvb, offset) == 'E') {
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, offset, msg_len, "Error");
		return;
	}
}

static void dissect_list_of_signals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	gint i;
	GArray *elements = split_payload(tvb, offset, msg_len, ';');
	proto_tree *ti;

	if (elements->len > 0) {
		ti = proto_tree_add_text(tree, tvb, offset, msg_len, "Signals to pass to the program");
		tree = proto_item_add_subtree(ti, ett_program_signals);

		for (i = 0; i < elements->len; i++) {
			struct split_result res = g_array_index(elements, struct split_result, i);
			unsigned long signal_number = strtoul((const char*) res.val, NULL, 16);
			const char *signal_name = gdb_signal_names[signal_number];
			const char *signal_desc = gdb_signal_descriptions[signal_number];

			proto_tree_add_uint_format(tree, hf_program_signal, tvb, res.offset_start, strlen((char*) res.val),
					signal_number, "%lu - %s - %s", signal_number, signal_name, signal_desc);
		}
	}

	g_array_free(elements, TRUE);
}

static void dissect_cmd_vCont_supported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {

}

static void dissect_reply_vCont_supported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {

	size_t vcont_strlen = strlen("vCont");
	proto_item *ti;
	gchar c;
	gchar *feature;
	const char *feature_description;

	if (tvb_strneql(tvb, offset, "vCont", vcont_strlen)) {
		proto_tree_add_boolean(tree, hf_vcont_is_supported, tvb, offset, 0, FALSE);
	} else {
		proto_tree_add_boolean(tree, hf_vcont_is_supported, tvb, offset, vcont_strlen, TRUE);

		// Skip vCont
		offset += vcont_strlen;

		ti = proto_tree_add_text(tree, tvb, offset, msg_len - vcont_strlen, "Supported commands");
		tree = proto_item_add_subtree(ti, ett_qsupported);

		c = tvb_get_guint8(tvb, offset);
		while (c == ';') {
			feature = (gchar*) tvb_get_ephemeral_string(tvb, offset + 1, 1);
			feature_description = vcont_command_description(feature[0]);

			if (tree) {
				proto_tree_add_string_format(tree, hf_qsupported, tvb, offset + 1, 1, feature, "%s (%s)", feature,
						feature_description);
			}

			offset += 2;
			c = tvb_get_guint8(tvb, offset);
		}

	}
}

static void dissect_cmd_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	gchar action_char;
	const char *action = NULL;

	// Skip ;
	offset++;

	action_char = tvb_get_guint8(tvb, offset);

	action = vcont_command_description(action_char);

	if (action_char) {
		proto_tree_add_string(tree, hf_vcont_action, tvb, offset, 1, action);
	}
}

static void dissect_reply_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_vKill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vKill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_vRun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vRun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_vStopped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vStopped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	proto_item *ti;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset + 1, msg_len - 1, "Supported features");
		tree = proto_item_add_subtree(ti, ett_qsupported);
	}

	gint i;
	GArray *elements = split_payload(tvb, offset, msg_len, ';');

	for (i = 0; i < elements->len; i++) {
		struct split_result res = g_array_index(elements, struct split_result, i);

		proto_tree_add_string_format(tree, hf_qsupported, tvb, res.offset_start, strlen((const char*) res.val),
				(const char*) res.val, "%s", (const char*) res.val);
	}

	g_array_free(elements, TRUE);
}

static void dissect_cmd_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	offset++;
	msg_len--;
	dissect_qSupported(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_reply_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_qSupported(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_QStartNoAckMode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QStartNoAckMode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	conv->disable_ack_at_next_host_ack = 1;

	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	// Skip :
	offset++;
	msg_len--;

	dissect_list_of_signals(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_reply_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_qXfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qXfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_QNonStop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QNonStop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_qAttached(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qAttached(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTfV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTfV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTfP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTfP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTsV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTsV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

/* The ? command */
static void dissect_cmd_haltreason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_haltreason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qC(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qC(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qOffsets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qOffsets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_QPassSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	// Skip :
	offset++;
	msg_len--;

	dissect_list_of_signals(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_reply_QPassSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	struct per_packet_data *pdata = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);
	guint8 digit = 0;

	guint start_offset = offset;

	digit = tvb_get_guint8(tvb, offset);
	while (digit != ',') {
		if (!isxdigit(digit)) {
			// Whaaaaat
			return;
		}

		offset++;
		digit = tvb_get_guint8(tvb, offset);
	}

	gchar *address = (gchar*) tvb_get_ephemeral_string(tvb, start_offset, offset - start_offset);
	proto_tree_add_string_format_value(tree, hf_address, tvb, start_offset, offset - start_offset, address, "0x%s",
			address);

	// Skip ,
	offset++;

	start_offset = offset;

	digit = tvb_get_guint8(tvb, offset);
	while (digit != '#') {
		if (!isxdigit(digit)) {
			// Whaaaaat
			return;
		}

		offset++;
		digit = tvb_get_guint8(tvb, offset);
	}

	gchar *len = (gchar*) tvb_get_ephemeral_string(tvb, start_offset, offset - start_offset);
	long lenn = strtol(len, NULL, 16);
	proto_tree_add_int(tree, hf_length, tvb, start_offset, offset - start_offset, lenn);

	pdata->u.m.requested_len = lenn;
}

static void dissect_reply_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	int expected_len = conv->last_request_data->u.m.requested_len;
	printf("dissect_reply_m pre-allocating %d bytes\n", expected_len);
	GArray *bytes = g_array_sized_new(FALSE, FALSE, sizeof(guint8), expected_len);

	guint8 b;
	guint start_offset = offset;

	b = tvb_get_guint8(tvb, offset);
	while (isxdigit(b)) {
		g_array_append_val(bytes, b);
		offset++;
		b = tvb_get_guint8(tvb, offset);
	}

	proto_tree_add_bytes(tree, hf_bytes, tvb, start_offset, offset - start_offset, (guint8*) bytes->data);
	g_array_free(bytes, TRUE);
}

static void dissect_cmd_Z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_Z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_G(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_G(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

/* The ! command */
static void dissect_cmd_enable_extended(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {

}

static void dissect_reply_enable_extended(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_QDisableRandomization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	guint8 c = tvb_get_guint8(tvb, offset + 1);

	if (c == '1') {
		proto_tree_add_boolean(tree, hf_disable_randomization, tvb, offset + 1, 1, TRUE);
	} else if (c == '0') {
		proto_tree_add_boolean(tree, hf_disable_randomization, tvb, offset + 1, 1, FALSE);
	}
}

static void dissect_reply_QDisableRandomization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
		guint msg_len, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

static void dissect_cmd_T(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_T(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, offset, msg_len, conv);
}

/* The order is important here. For example, vCont? must be before vCont,
 * otherwise vCont would match vCont? packets. */
static struct dissect_command_t cmd_cbs[] = {
	{ "vCont?", dissect_cmd_vCont_supported, dissect_reply_vCont_supported, NULL },
	{ "vCont", dissect_cmd_vCont, dissect_reply_vCont, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#vCont-packet" },
	{ "vKill", dissect_cmd_vKill, dissect_reply_vKill, NULL },
	{ "vRun", dissect_cmd_vRun, dissect_reply_vRun, NULL },
	{ "vStopped", dissect_cmd_vStopped, dissect_reply_vStopped, NULL },
	{ "qSupported", dissect_cmd_qSupported, dissect_reply_qSupported, NULL },
	{ "QStartNoAckMode", dissect_cmd_QStartNoAckMode, dissect_reply_QStartNoAckMode, NULL },
	{ "QProgramSignals", dissect_cmd_QProgramSignals, dissect_reply_QProgramSignals, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QProgramSignals" },
	{ "H", dissect_cmd_H, dissect_reply_H, NULL },
	{ "qXfer", dissect_cmd_qXfer, dissect_reply_qXfer, NULL },
	{ "QNonStop", dissect_cmd_QNonStop, dissect_reply_QNonStop, NULL },
	{ "qAttached", dissect_cmd_qAttached, dissect_reply_qAttached, NULL },
	{ "qTStatus", dissect_cmd_qTStatus, dissect_reply_qTStatus, NULL },
	{ "qTfV", dissect_cmd_qTfV, dissect_reply_qTfV, NULL },
	{ "qTfP", dissect_cmd_qTfP, dissect_reply_qTfP, NULL },
	{ "qTsV", dissect_cmd_qTsV, dissect_reply_qTsV, NULL },
	{ "?", dissect_cmd_haltreason, dissect_reply_haltreason, NULL },
	{ "qC", dissect_cmd_qC, dissect_reply_qC, NULL },
	{ "qOffsets", dissect_cmd_qOffsets, dissect_reply_qOffsets, NULL },
	{ "QPassSignals", dissect_cmd_QPassSignals, dissect_reply_QPassSignals, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QPassSignals" },
	{ "qSymbol", dissect_cmd_qSymbol, dissect_reply_qSymbol, NULL },
	{ "m", dissect_cmd_m, dissect_reply_m, NULL },
	{ "Z", dissect_cmd_Z, dissect_reply_Z, NULL },
	{ "g", dissect_cmd_g, dissect_reply_g, NULL },
	{ "G", dissect_cmd_G, dissect_reply_G, NULL },
	{ "P", dissect_cmd_P, dissect_reply_P, NULL },
	{ "X", dissect_cmd_X, dissect_reply_X, NULL },
	{ "!", dissect_cmd_enable_extended, dissect_reply_enable_extended, NULL },
	{ "QDisableRandomization", dissect_cmd_QDisableRandomization, dissect_reply_QDisableRandomization, NULL },
	{ "T", dissect_cmd_T, dissect_reply_T, NULL },
};

static struct dissect_command_t *find_command(tvbuff_t *tvb, guint offset) {
	struct dissect_command_t *cmd;

	for (cmd = cmd_cbs; cmd->command != NULL; cmd++) {
		int command_len = strlen(cmd->command);

		if (tvb_strneql(tvb, offset, cmd->command, command_len) == 0) {
			return cmd;
		}
	}

	return NULL;
}

static void dissect_one_host_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	struct dissect_command_t *cmd;
	int command_name_len = 0;
	printf("Host query\n");

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!pinfo->fd->flags.visited) {
		/* Skip $ */
		packet_data->command = find_command(tvb, offset + 1);

		conv->last_command = packet_data->command;
		conv->last_packet_framenum = pinfo->fd->num;
		conv->last_request_data = packet_data;
	}

	cmd = packet_data->command;

	if (!cmd) {
		printf("Unknown command\n");
		return;
	}

	printf("> %s\n", cmd->command);
	command_name_len = strlen(cmd->command);

	/* Add command name entry to tree */
	if (tree) {
		proto_tree_add_string(tree, hf_command, tvb, offset + 1, command_name_len, cmd->command);
	}

	/* Set info column */
	col_append_str(pinfo->cinfo, COL_INFO, cmd->command);
	col_append_str(pinfo->cinfo, COL_INFO, " command");

	/* Call command handler, skip $ and command name */

	cmd->command_handler(tvb, pinfo, tree, offset + 1 + command_name_len, msg_len - 1 - command_name_len, conv);

	if (tree) {
		if (packet_data->matching_framenum > 0) {
			proto_tree_add_uint(tree, hf_reply_in, tvb, 0, 0, packet_data->matching_framenum);
		}
		proto_item *pi = proto_tree_add_string(tree, hf_doc_link, tvb, 0, 0, cmd->doc_url);
		PROTO_ITEM_SET_URL(pi);
	}
}
static void dissect_one_stub_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	struct dissect_command_t *cmd;
	printf("Stub reply\n");
	col_append_str(pinfo->cinfo, COL_INFO, "Stub reply");

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!pinfo->fd->flags.visited) {
		packet_data->command = conv->last_command;

		/* Make the links between request and reply */
		packet_data->matching_framenum = conv->last_packet_framenum;
		conv->last_request_data->matching_framenum = pinfo->fd->num;
		conv->last_packet_framenum = pinfo->fd->num;
	}

	cmd = packet_data->command;

	if (!cmd) {
		printf("Reply to unknown command\n");
		return;
	}

	if (tree) {
		proto_tree_add_string(tree, hf_reply_to, tvb, 0, 0, cmd->command);
	}

	col_append_str(pinfo->cinfo, COL_INFO, " to ");
	col_append_str(pinfo->cinfo, COL_INFO, cmd->command);

	/* Skip $ */
	cmd->reply_handler(tvb, pinfo, tree, offset + 1, msg_len - 1, conv);

	if (tree) {
		proto_tree_add_uint(tree, hf_request_in, tvb, 0, 0, packet_data->matching_framenum);
	}
}

static void dissect_one_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	printf("Stub ack %d\n", msg_len);

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!pinfo->fd->flags.visited) {
		packet_data->command = conv->last_command;
		packet_data->matching_framenum = conv->last_packet_framenum;
	}

	guint8 c = tvb_get_guint8(tvb, offset);
	if (msg_len == 1 && (c == '+' || c == '-')) {
		if (tree) {
			// Add protocol section in the packet details
			proto_tree_add_boolean(tree, hf_ack, tvb, offset, 1, c == '+' ? TRUE : FALSE);

			if (packet_data->matching_framenum > 0) {
				proto_tree_add_uint(tree, hf_ack_to, tvb, 0, 0, packet_data->matching_framenum);
			}
		}
	}
}

static void dissect_one_host_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	printf("Host ack %d\n", msg_len);

	if (!pinfo->fd->flags.visited) {
		if (conv->disable_ack_at_next_host_ack) {
			conv->ack_enabled = 0;
			conv->disable_ack_at_next_host_ack = 0;
		}
	}

	dissect_one_ack(tvb, pinfo, tree, offset, msg_len, conv);
	col_append_str(pinfo->cinfo, COL_INFO, "Host acknowledgement");
}

static void dissect_one_stub_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	dissect_one_ack(tvb, pinfo, tree, offset, msg_len, conv);
	col_append_str(pinfo->cinfo, COL_INFO, "Stub acknowledgement");
}

static void dissect_one_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	col_append_str(pinfo->cinfo, COL_INFO, "Notification");
	printf("Notification\n");
}

static struct gdbrsp_conv_data *get_conv_data(packet_info *pinfo) {
	struct gdbrsp_conv_data* conv_data = NULL;
	conversation_t *conv = find_or_create_conversation(pinfo);
	conv_data = (struct gdbrsp_conv_data*) conversation_get_proto_data(conv, proto_gdbrsp);

	if (!conv_data) {
		// New conversation heh ?
		printf("Convo not found, creating new\n");
		conv_data = se_alloc0(sizeof(struct gdbrsp_conv_data));
		conv_data->next_expected_msg = GDB_HOST_ACK;
		conv_data->ack_enabled = 1;
		conversation_add_proto_data(conv, proto_gdbrsp, conv_data);
	}

	return conv_data;
}

static void dissect_crc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
		struct gdbrsp_conv_data *conv) {
	int i;
	char packet_crc[3];
	char computed_crc[3];
	unsigned int crc = 0;

	if (tree) {
		for (i = offset; i < (offset + msg_len - crc_len); i++) {
			crc += tvb_get_guint8(tvb, i);
		}

		crc = crc % 256;

		// Skip #
		i++;

		packet_crc[0] = tvb_get_guint8(tvb, i);
		packet_crc[1] = tvb_get_guint8(tvb, i + 1);
		packet_crc[2] = '\0';

		snprintf(computed_crc, 3, "%02x", crc);

		proto_tree_add_uint_format_value(tree, hf_checksum, tvb, i, 2, crc, "%s (computed crc: %s)", packet_crc,
				computed_crc);
	}
}

// If the available data contains a complete message, return the length of that message. Otherwise, return 0.
static gint find_next_message_len(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset) {
	guint start_offset = offset;

	if (tvb_offset_exists(tvb, offset)) {
		guint8 c = tvb_get_guint8(tvb, offset);

		/* Ack or nack */
		if (c == '+' || c == '-') {
			return 1;
		}

		/* Packet or notification */
		if (c == '$' || c == '%') {
			while (tvb_offset_exists(tvb, offset)) {
				if (tvb_get_guint8(tvb, offset) == '#') {
					// $ABCD#XY
					// ^    ^-- offset
					// `------- start_offset
					offset += 2;
					// $ABCD#XY
					// ^      ^-- offset
					// `------- start_offset
					if (tvb_offset_exists(tvb, offset)) {
						return offset - start_offset + 1;
					} else {
						return 0;
					}
				}

				offset++;
			}

			return 0;
		}
	}

	return -1;
}

/*
 * Returns the type of this msg. Updates conv->next_expected_msg if needed.
 */
static enum gdb_msg_type determine_type(struct gdbrsp_conv_data *conv, guint8 first_char) {
	if (first_char == '%') {
		return GDB_NOTIFICATION;
	}

	enum gdb_msg_type this_type = conv->next_expected_msg;

	switch (this_type) {
	case GDB_HOST_QUERY:
		conv->next_expected_msg = conv->ack_enabled ? GDB_STUB_ACK : GDB_STUB_REPLY;
		break;
	case GDB_HOST_ACK:
		conv->next_expected_msg = GDB_HOST_QUERY;
		break;
	case GDB_STUB_REPLY:
		conv->next_expected_msg = conv->ack_enabled ? GDB_HOST_ACK : GDB_HOST_QUERY;
		break;
	case GDB_STUB_ACK:
		conv->next_expected_msg = GDB_STUB_REPLY;
		break;
	case GDB_NOTIFICATION:
		assert(0);
		break;
	}

	return this_type;
}

static void dissect_one_gdbrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len) {
	proto_item *ti;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GDB-RSP");
	}

	col_clear(pinfo->cinfo, COL_INFO);

	struct gdbrsp_conv_data *conv = get_conv_data(pinfo);

	// Add gdb subtree
	if (tree) {
		ti = proto_tree_add_item(tree, proto_gdbrsp, tvb, offset, msg_len, ENC_NA);
		tree = proto_item_add_subtree(ti, ett_gdbrsp);
	}

	// Check if we already determined
	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);
	if (!packet_data) {
		packet_data = g_malloc0(sizeof(struct per_packet_data));
		// TODO: add check and exception
		// TODO: When to free that memory?

		guint8 first_char = tvb_get_guint8(tvb, 0);

		packet_data->type = determine_type(conv, first_char);

		p_add_proto_data(pinfo->fd, proto_gdbrsp, 0, packet_data);
	}

	// Dissect based on what we expect to have
	switch (packet_data->type) {
	case GDB_HOST_QUERY:
		dissect_one_host_query(tvb, pinfo, tree, offset, msg_len - crc_len, conv);
		dissect_crc(tvb, pinfo, tree, offset + 1, msg_len - 1, conv);
		break;
	case GDB_HOST_ACK:
		dissect_one_host_ack(tvb, pinfo, tree, offset, msg_len, conv);
		break;
	case GDB_STUB_REPLY:
		dissect_one_stub_reply(tvb, pinfo, tree, offset, msg_len - crc_len, conv);
		dissect_crc(tvb, pinfo, tree, offset + 1, msg_len - 1, conv);
		break;
	case GDB_STUB_ACK:
		dissect_one_stub_ack(tvb, pinfo, tree, offset, msg_len, conv);
		break;
	case GDB_NOTIFICATION:
		dissect_one_notification(tvb, pinfo, tree, offset, msg_len - crc_len, conv);
		dissect_crc(tvb, pinfo, tree, offset + 1, msg_len - 1, conv);
		break;
	}
}

static void dissect_gdbrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint offset = 0;
	const guint max_offset = tvb_reported_length(tvb);
	guint msg_len;

	printf("dissect_gdbrsp with %d bytes\n", max_offset);

	while (tvb_offset_exists(tvb, offset)) {
		msg_len = find_next_message_len(tvb, pinfo, tree, offset);
		if (msg_len > 0) {
			dissect_one_gdbrsp(tvb, pinfo, tree, offset, msg_len);
			offset += msg_len;
		} else if (msg_len == 0) {
			printf("Not enough data, asking for more\n");
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			break;
		} else {
			/* oops */
			printf("oops\n");
			return;
		}
	}
}

static hf_register_info hf_gdbrsp[] =
{
	{
		&hf_command,
		{
			"Command", // name
			"gdbrsp.command", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_reply_to,
		{
			"Reply to", // name
			"gdbrsp.reply_to", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_address,
		{
			"Address", // name
			"gdbrsp.address", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_length,
		{
			"Length", // name
			"gdbrsp.length", // abbrev
			FT_INT32, // type
			BASE_DEC, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_bytes,
		{
			"Bytes", // name
			"gdbrsp.bytes", // abbrev
			FT_BYTES, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_request_in,
		{
			"Request in frame", // name
			"gdbrsp.request_in", // abbrev
			FT_FRAMENUM, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_reply_in,
		{
			"Reply in frame", // name
			"gdbrsp.reply_in", // abbrev
			FT_FRAMENUM, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_ack,
		{
			"Transmission succeeded", // name
			"gdbrsp.ack", // abbrev
			FT_BOOLEAN, // type
			BASE_NONE, // display
			&tfs_yes_no, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_ack_to,
		{
			"Acknowledgement to frame", // name
			"gdbrsp.ack_to", // abbrev
			FT_FRAMENUM, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_qsupported,
		{
			"Supported", // name
			"gdbrsp.supported", // abbrev
			FT_STRINGZ, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			"Supported (or not) feature", // blurb
			HFILL
		}
	},
	{
		&hf_checksum,
		{
			"Checksum", // name
			"gdbrsp.checksum", // abbrev
			FT_UINT8, // type
			BASE_HEX, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_reply_ok_error,
		{
			"Reply", // name
			"gdbrsp.reply", // abbrev
			FT_STRINGZ, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_disable_randomization,
		{
			"Disable randomization", // name
			"gdbrsp.disable_randomization", // abbrev
			FT_BOOLEAN, // type
			BASE_NONE, // display
			&tfs_yes_no, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_vcont_action,
		{
			"Action", // name
			"gdbrsp.action", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_vcont_is_supported,
		{
			"vCont support", // name
			"gdbrsp.vcont_supported", // abbrev
			FT_BOOLEAN, // type
			BASE_NONE, // display
			&tfs_yes_no, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_program_signal,
		{
			"Signal", // name
			"gdbrsp.program_signal", // abbrev
			FT_UINT8, // type
			BASE_DEC, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_doc_link,
		{
			"Documentation", // name
			"gdbrsp.documentation", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
};

void proto_register_gdbrsp(void) {

	static gint *ett_gdbrsp_arr[] =
	{ &ett_gdbrsp, &ett_qsupported, &ett_program_signals };

	proto_gdbrsp = proto_register_protocol("GDB Remote Serial Protocol", "GDB RSP", "gdbrsp");
	proto_register_field_array(proto_gdbrsp, hf_gdbrsp, array_length (hf_gdbrsp));
	proto_register_subtree_array(ett_gdbrsp_arr, array_length (ett_gdbrsp_arr));
}

void proto_reg_handoff_gdbrsp_gdbrsp(void) {
	static dissector_handle_t gdbrsp_handle;

	gdbrsp_handle = create_dissector_handle(dissect_gdbrsp, proto_gdbrsp);

	dissector_add_uint("tcp.port", gdbrsp_PORT, gdbrsp_handle);
}

