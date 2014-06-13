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
static gint ett_ptid = -1;

/* Variables for fields */
static int hf_command = -1;
static int hf_ack = -1;
static int hf_qsupported = -1;
static int hf_checksum = -1;
static int hf_reply_to = -1;
static int hf_address = -1;
static int hf_length = -1;
static int hf_offset = -1;
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
static int hf_ptid_pid = -1;
static int hf_ptid_tid = -1;
static int hf_filename = -1;
static int hf_object = -1;

// strlen("#XX");
static const guint crc_len = 3;

enum gdb_msg_type {
	GDB_HOST_QUERY, GDB_HOST_ACK, GDB_STUB_REPLY, GDB_STUB_ACK, GDB_NOTIFICATION,
};

struct gdbrsp_conv_data;

struct dissect_command_t {
	const char *command;
	void (*command_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv);
	void (*reply_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv);
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
	const char *val;
};

struct thread_id_desc {
	gint pid;
	gint tid;

	// Number of character used to represent the thread id
	gint pid_offset, pid_length;
	gint tid_offset, tid_length;
};

/**
 * Split the payload using the specified character.
 *
 * @param tvb subset tvb containing the payload.
 * @param split_char character on which to split.
 *
 * @return GArray of elements. Must be freed by the caller.
 */
static GArray *split_payload(tvbuff_t *tvb, gchar split_char) {
	struct split_result elem;
	GArray *ret = g_array_new(FALSE, FALSE, sizeof(elem));
	gint offset = 0;
	gint found_offset;

	found_offset = tvb_find_guint8(tvb, offset, -1, split_char);
	while (found_offset != -1) {
		elem.val = (char *) tvb_get_ephemeral_string(tvb, offset, found_offset - offset);
		elem.offset_start = offset;

		g_array_append_val(ret, elem);

		// Skip the ;
		offset = found_offset + 1;
		found_offset = tvb_find_guint8(tvb, offset, -1, split_char);
	}

	if (tvb_length(tvb) - offset) {
		elem.val = (char *) tvb_get_ephemeral_string(tvb, offset, tvb_length(tvb) - offset);
		elem.offset_start = offset;

		g_array_append_val(ret, elem);
	}

	return ret;
}

static struct thread_id_desc dissect_thread_id(tvbuff_t *tvb) {
	struct thread_id_desc ret;
	ret.pid = -1;
	ret.tid = -1;
	ret.pid_offset = -1;
	ret.pid_length = -1;
	ret.tid_offset = -1;
	ret.tid_length = -1;

	char* ptid_desc_start = (char *) tvb_get_ephemeral_string(tvb, 0, tvb_length(tvb));
	char* num_start;
	char* num_end;

	if (ptid_desc_start[0] == 'p') {
		num_start = ptid_desc_start + 1;

		ret.pid = strtol(num_start, &num_end, 16);

		ret.pid_offset = num_start - ptid_desc_start;
		ret.pid_length = num_end - num_start;

		if (*num_end == '.') {
			num_start = num_end + 1;
			ret.tid = strtol(num_start, &num_end, 16);

			ret.tid_offset = num_start - ptid_desc_start;
			ret.tid_length = num_end - num_start;
		}

	} else {
		num_start = ptid_desc_start;
		ret.tid = strtol(num_start, &num_end, 16);

		ret.tid_offset = num_start - ptid_desc_start;
		ret.tid_length = num_end - num_start;
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

static void dissect_ok_error_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	if (tvb_length(tvb) == 0) {
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, 0, 0, "Target does not support this command");
		return;
	}

	printf("%c %c\n", tvb_get_guint8(tvb, 0), tvb_get_guint8(tvb, 1));

	if (tvb_strneql(tvb, 0, "OK", 2) == 0) {
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, 0, 2, "OK");
		return;
	}

	if (tvb_get_guint8(tvb, 0) == 'E') {
		// Format is Exx, where xx is the error code. Length is 3.
		proto_tree_add_string(tree, hf_reply_ok_error, tvb, 0, 3, "Error");
		return;
	}
}

/**
 * Dissect a list of signals as found in packets sur as QProgramSignals.
 */
static void dissect_list_of_signals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	gint i;
	GArray *elements = split_payload(tvb, ';');
	proto_tree *ti;

	if (elements->len > 0) {
		ti = proto_tree_add_text(tree, tvb, 0, -1, "Signals to pass to the program");
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

static void dissect_cmd_vCont_supported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {

}

static void dissect_reply_vCont_supported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {

	size_t vcont_strlen = strlen("vCont");
	proto_item *ti;
	const gchar *feature;
	guint i;
	const char *feature_description;

	if (tvb_strneql(tvb, 0, "vCont", vcont_strlen)) {
		proto_tree_add_boolean(tree, hf_vcont_is_supported, tvb, 0, 0, FALSE);
	} else {
		proto_tree_add_boolean(tree, hf_vcont_is_supported, tvb, 0, vcont_strlen, TRUE);

		// Skip vCont
		tvbuff_t *subbuf = tvb_new_subset_remaining(tvb, vcont_strlen);

		ti = proto_tree_add_text(tree, subbuf, 0, tvb_length(subbuf), "Supported commands");
		tree = proto_item_add_subtree(ti, ett_qsupported);

		GArray *elements = split_payload(subbuf, ';');

		for (i = 0; i < elements->len; i++) {
			struct split_result res = g_array_index(elements, struct split_result, i);

			feature = (const gchar *) res.val;
			feature_description = vcont_command_description(feature[0]);

			if (tree) {
				proto_tree_add_string_format(tree, hf_qsupported, subbuf, res.offset_start, 1, feature, "%s (%s)",
						feature, feature_description);
			}
		}

		g_array_free(elements, TRUE);
	}
}

static void dissect_cmd_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	gchar action_char;
	const char *action = NULL;

	// Skip ;
	action_char = tvb_get_guint8(tvb, 1);

	action = vcont_command_description(action_char);

	if (action_char) {
		proto_tree_add_string(tree, hf_vcont_action, tvb, 1, 1, action);
	}
}

static void dissect_reply_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {

	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_vKill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vKill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_vRun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vRun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_vFile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vFile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_vStopped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vStopped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	proto_item *ti;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "Supported features");
		tree = proto_item_add_subtree(ti, ett_qsupported);
	}

	gint i;

	GArray *elements = split_payload(tvb, ';');

	for (i = 0; i < elements->len; i++) {
		struct split_result res = g_array_index(elements, struct split_result, i);

		proto_tree_add_string_format(tree, hf_qsupported, tvb, res.offset_start, strlen((const char*) res.val),
				(const char*) res.val, "%s", (const char*) res.val);
	}

	g_array_free(elements, TRUE);
}

static void dissect_cmd_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	// Skip the :
	tvbuff_t* payload_tvb = tvb_new_subset_remaining(tvb, 1);

	dissect_qSupported(payload_tvb, pinfo, tree, conv);
}

static void dissect_reply_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_qSupported(tvb, pinfo, tree, conv);
}

static void dissect_cmd_QStartNoAckMode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QStartNoAckMode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	conv->disable_ack_at_next_host_ack = 1;

	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	// Skip :
	tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, 1);
	dissect_list_of_signals(payload_tvb, pinfo, tree, conv);
}

static void dissect_reply_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	guint8 affected_command = tvb_get_guint8(tvb, 0);
	proto_tree *ti;

	tvbuff_t *pid_tvb = tvb_new_subset_remaining(tvb, 1);

	struct thread_id_desc ptid = dissect_thread_id(pid_tvb);

	printf("ptid result = %d %d\n", ptid.pid, ptid.tid);

	ti = proto_tree_add_text(tree, pid_tvb, 0, tvb_length(pid_tvb), "Thread ID");
	tree = proto_item_add_subtree(ti, ett_ptid);

	if (ptid.pid_offset >= 0) {
		proto_tree_add_int(tree, hf_ptid_pid, pid_tvb, ptid.pid_offset, ptid.pid_length, ptid.pid);
	}
	proto_tree_add_int(tree, hf_ptid_tid, pid_tvb, ptid.tid_offset, ptid.tid_length, ptid.tid);
}

static void dissect_reply_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_qXfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	GArray *elements = split_payload(tvb, ':');

	struct split_result object = g_array_index(elements, struct split_result, 1);
	struct split_result read_or_write = g_array_index(elements, struct split_result, 2);
	struct split_result annex = g_array_index(elements, struct split_result, 3);
	struct split_result offset_length = g_array_index(elements, struct split_result, 4);

	printf("%s|%s|%s|%s\n", object.val, read_or_write.val, annex.val, offset_length.val);

	proto_tree_add_string(tree, hf_object, tvb, object.offset_start, strlen(object.val), object.val);

	const char *offset_start = NULL, *length_start = NULL;
	char *offset_end = NULL, *length_end = NULL;
	unsigned long offset, length;

	if (strcmp("read", (char *) read_or_write.val) == 0) {
		offset_start = (char *) offset_length.val;
		offset = strtoul(offset_start, &offset_end, 16);
		length_start = offset_end + 1;
		length = strtoul(length_start, &length_end, 16);

		proto_tree_add_int(tree, hf_offset, tvb, offset_length.offset_start, offset_end - offset_start, offset);
		proto_tree_add_int(tree, hf_length, tvb, offset_length.offset_start + offset_end - offset_start + 1, length_end - length_start, length);
	} else if (strcmp("write", (char *) read_or_write.val) == 0) {
		offset_start = (char *) offset_length.val;
		offset = strtoul(offset_start, &offset_end, 16);
		proto_tree_add_int(tree, hf_offset, tvb, offset_length.offset_start, offset_end - offset_start, offset);
	} else {
		// Bad
	}

	if (strcmp("features", (char *) object.val) == 0) {
		proto_tree_add_string(tree, hf_filename, tvb, annex.offset_start, strlen((char *)annex.val), (char *)annex.val);
	}
}

static void dissect_reply_qXfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_QNonStop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QNonStop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_qAttached(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qAttached(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTfV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTfV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTfP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTfP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qTsV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qTsV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

/* The ? command */
static void dissect_cmd_haltreason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_haltreason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qC(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qC(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qOffsets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qOffsets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_QPassSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	// Skip :
	tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, 1);
	dissect_list_of_signals(payload_tvb, pinfo, tree, conv);
}

static void dissect_reply_QPassSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	struct per_packet_data *pdata = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);
	guint8 digit = 0;

	guint start_offset = 0;
	guint offset = 0;

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

	while (tvb_offset_exists(tvb, offset)) {
		digit = tvb_get_guint8(tvb, offset);
		if (!isxdigit(digit)) {
			// Whaaaaat
			return;
		}

		offset++;
	}

	gchar *len = (gchar*) tvb_get_ephemeral_string(tvb, start_offset, offset - start_offset);
	long lenn = strtol(len, NULL, 16);
	proto_tree_add_int_format_value(tree, hf_length, tvb, start_offset, offset - start_offset, lenn, "%ld bytes", lenn);

	pdata->u.m.requested_len = lenn;
}

static void dissect_reply_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	//int expected_len = conv->last_request_data->u.m.requested_len;
	guint len = tvb_length(tvb);
	GArray *bytes = g_array_sized_new(FALSE, FALSE, sizeof(guint8), len);

	guint8 b;
	guint i;

	for (i = 0; i < len; i++) {
		b = tvb_get_guint8(tvb, i);
		g_array_append_val(bytes, b);
	}

	proto_tree_add_bytes(tree, hf_bytes, tvb, 0, len, (guint8*) bytes->data);
	g_array_free(bytes, TRUE);
}

static void dissect_cmd_Z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_Z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_G(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_G(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

/* The ! command */
static void dissect_cmd_enable_extended(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {

}

static void dissect_reply_enable_extended(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_QDisableRandomization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	// Skip :
	guint8 c = tvb_get_guint8(tvb, 1);

	if (c == '1') {
		proto_tree_add_boolean(tree, hf_disable_randomization, tvb, 1, 1, TRUE);
	} else if (c == '0') {
		proto_tree_add_boolean(tree, hf_disable_randomization, tvb, 1, 1, FALSE);
	}
}

static void dissect_reply_QDisableRandomization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

static void dissect_cmd_T(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_T(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct gdbrsp_conv_data *conv) {
	dissect_ok_error_reply(tvb, pinfo, tree, conv);
}

/* The order is important here. For example, vCont? must be before vCont,
 * otherwise vCont would match vCont? packets. */
static struct dissect_command_t cmd_cbs[] = {
	{ "vCont?", dissect_cmd_vCont_supported, dissect_reply_vCont_supported, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-vCont_003f-packet" },
	{ "vCont", dissect_cmd_vCont, dissect_reply_vCont, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#vCont-packet" },
	{ "vKill", dissect_cmd_vKill, dissect_reply_vKill, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-vKill-packet" },
	{ "vRun", dissect_cmd_vRun, dissect_reply_vRun, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-vRun-packet" },
	{ "vFile", dissect_cmd_vFile, dissect_reply_vFile, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-vFile-packet" },
	{ "vStopped", dissect_cmd_vStopped, dissect_reply_vStopped, "https://sourceware.org/gdb/onlinedocs/gdb/Notification-Packets.html#Notification-Packets" },
	{ "qSupported", dissect_cmd_qSupported, dissect_reply_qSupported, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#qSupported" },
	{ "QStartNoAckMode", dissect_cmd_QStartNoAckMode, dissect_reply_QStartNoAckMode, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QStartNoAckMode" },
	{ "QProgramSignals", dissect_cmd_QProgramSignals, dissect_reply_QProgramSignals, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QProgramSignals" },
	{ "H", dissect_cmd_H, dissect_reply_H, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-H-packet" },
	{ "qXfer", dissect_cmd_qXfer, dissect_reply_qXfer, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-qXfer-packet" },
	{ "QNonStop", dissect_cmd_QNonStop, dissect_reply_QNonStop, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-QNonStop-packet" },
	{ "qAttached", dissect_cmd_qAttached, dissect_reply_qAttached, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-qAttached-packet" },
	{ "qTStatus", dissect_cmd_qTStatus, dissect_reply_qTStatus, "https://sourceware.org/gdb/onlinedocs/gdb/Tracepoint-Packets.html#index-qTStatus-packet" },
	{ "qTfV", dissect_cmd_qTfV, dissect_reply_qTfV, "https://sourceware.org/gdb/onlinedocs/gdb/Tracepoint-Packets.html#index-qTfV-packet" },
	{ "qTfP", dissect_cmd_qTfP, dissect_reply_qTfP, "https://sourceware.org/gdb/onlinedocs/gdb/Tracepoint-Packets.html#index-qTfP-packet" },
	{ "qTsV", dissect_cmd_qTsV, dissect_reply_qTsV, "https://sourceware.org/gdb/onlinedocs/gdb/Tracepoint-Packets.html#index-qTsV-packet" },
	{ "?", dissect_cmd_haltreason, dissect_reply_haltreason, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-_003f-packet" },
	{ "qC", dissect_cmd_qC, dissect_reply_qC, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-qC-packet" },
	{ "qOffsets", dissect_cmd_qOffsets, dissect_reply_qOffsets, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-qOffsets-packet" },
	{ "QPassSignals", dissect_cmd_QPassSignals, dissect_reply_QPassSignals, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QPassSignals" },
	{ "qSymbol", dissect_cmd_qSymbol, dissect_reply_qSymbol, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-qSymbol-packet" },
	{ "m", dissect_cmd_m, dissect_reply_m, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-m-packet" },
	{ "Z", dissect_cmd_Z, dissect_reply_Z, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-z-packet" },
	{ "z", dissect_cmd_z, dissect_reply_z, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-z-packet" },
	{ "g", dissect_cmd_g, dissect_reply_g, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-g-packet" },
	{ "G", dissect_cmd_G, dissect_reply_G, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-G-packet" },
	{ "P", dissect_cmd_P, dissect_reply_P, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-P-packet" },
	{ "X", dissect_cmd_X, dissect_reply_X, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-X-packet" },
	{ "!", dissect_cmd_enable_extended, dissect_reply_enable_extended, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#extended-mode" },
	{ "QDisableRandomization", dissect_cmd_QDisableRandomization, dissect_reply_QDisableRandomization, "https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#index-QDisableRandomization-packet" },
	{ "T", dissect_cmd_T, dissect_reply_T, "https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#index-T-packet" },
};

static struct dissect_command_t *find_command(tvbuff_t *tvb) {
	struct dissect_command_t *cmd;

	for (cmd = cmd_cbs; cmd->command != NULL; cmd++) {
		int command_len = strlen(cmd->command);

		if (tvb_strneql(tvb, 0, cmd->command, command_len) == 0) {
			return cmd;
		}
	}

	return NULL;
}

static void dissect_one_host_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	struct dissect_command_t *cmd;
	int command_name_len = 0;
	printf("Host query\n");

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!pinfo->fd->flags.visited) {
		packet_data->command = find_command(tvb);

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
		proto_tree_add_string(tree, hf_command, tvb, 0, command_name_len, cmd->command);
	}

	/* Set info column */
	col_append_str(pinfo->cinfo, COL_INFO, cmd->command);
	col_append_str(pinfo->cinfo, COL_INFO, " command");

	/* Call command handler, skip $ and command name */

	tvbuff_t *subset_tvbuff = tvb_new_subset_remaining(tvb, command_name_len);
	cmd->command_handler(subset_tvbuff, pinfo, tree, conv);

	if (tree) {
		if (packet_data->matching_framenum > 0) {
			proto_tree_add_uint(tree, hf_reply_in, tvb, 0, 0, packet_data->matching_framenum);
		}
		if (cmd->doc_url) {
			proto_item *pi = proto_tree_add_string(tree, hf_doc_link, tvb, 0, 0, cmd->doc_url);
			PROTO_ITEM_SET_URL(pi);
		}
	}
}
static void dissect_one_stub_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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

	cmd->reply_handler(tvb, pinfo, tree, conv);

	if (tree) {
		proto_tree_add_uint(tree, hf_request_in, tvb, 0, 0, packet_data->matching_framenum);
	}
}

static void dissect_one_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	printf("Stub ack %d\n", tvb_length(tvb));

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!pinfo->fd->flags.visited) {
		packet_data->command = conv->last_command;
		packet_data->matching_framenum = conv->last_packet_framenum;
	}

	guint8 c = tvb_get_guint8(tvb, 0);
	if (tvb_length(tvb) == 1 && (c == '+' || c == '-')) {
		if (tree) {
			// Add protocol section in the packet details
			proto_tree_add_boolean(tree, hf_ack, tvb, 0, 1, c == '+' ? TRUE : FALSE);

			if (packet_data->matching_framenum > 0) {
				proto_tree_add_uint(tree, hf_ack_to, tvb, 0, 0, packet_data->matching_framenum);
			}
		}
	}
}

static void dissect_one_host_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	printf("Host ack %d\n", tvb_length(tvb));

	if (!pinfo->fd->flags.visited) {
		if (conv->disable_ack_at_next_host_ack) {
			conv->ack_enabled = 0;
			conv->disable_ack_at_next_host_ack = 0;
		}
	}

	dissect_one_ack(tvb, pinfo, tree, conv);
	col_append_str(pinfo->cinfo, COL_INFO, "Host acknowledgement");
}

static void dissect_one_stub_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	dissect_one_ack(tvb, pinfo, tree, conv);
	col_append_str(pinfo->cinfo, COL_INFO, "Stub acknowledgement");
}

static void dissect_one_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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

/*
 * tvb contains the packet data. crc_tvb contains the crc.
 */
static void dissect_crc(tvbuff_t *tvb, tvbuff_t *crc_tvb, packet_info *pinfo, proto_tree *tree,
		struct gdbrsp_conv_data *conv) {
	int i;
	char packet_crc[3];
	unsigned int crc = 0;

	if (tree) {
		for (i = 0; i < tvb_length(tvb); i++) {
			crc += tvb_get_guint8(tvb, i);
		}

		crc = crc % 256;

		packet_crc[0] = tvb_get_guint8(crc_tvb, 0);
		packet_crc[1] = tvb_get_guint8(crc_tvb, 1);
		packet_crc[2] = '\0';

		proto_tree_add_uint_format_value(tree, hf_checksum, crc_tvb, 0, 2, crc, "%s (computed crc: %02x)", packet_crc,
				crc);
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

static void dissect_one_gdbrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	proto_item *ti;
	tvbuff_t *payload_tvb = NULL;
	tvbuff_t *crc_tvb = NULL;
	guint msg_len;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GDB-RSP");
	}

	col_clear(pinfo->cinfo, COL_INFO);

	struct gdbrsp_conv_data *conv = get_conv_data(pinfo);

	// Add gdb subtree
	if (tree) {
		ti = proto_tree_add_item(tree, proto_gdbrsp, tvb, 0, tvb_length(tvb), ENC_NA);
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
		msg_len = tvb_length(tvb) - 1 /* $ */ - crc_len;
		payload_tvb = tvb_new_subset_length(tvb, 1, msg_len);
		dissect_one_host_query(payload_tvb, pinfo, tree, conv);

		crc_tvb = tvb_new_subset_remaining(tvb, tvb_length(tvb) - crc_len + 1 /* # */);
		dissect_crc(payload_tvb, crc_tvb, pinfo, tree, conv);
		break;
	case GDB_HOST_ACK:
		dissect_one_host_ack(tvb, pinfo, tree, conv);
		break;
	case GDB_STUB_REPLY:
		msg_len = tvb_length(tvb) - 1 /* $ */ - crc_len;
		payload_tvb = tvb_new_subset_length(tvb, 1, msg_len);
		dissect_one_stub_reply(payload_tvb, pinfo, tree, conv);

		crc_tvb = tvb_new_subset_remaining(tvb, tvb_length(tvb) - crc_len + 1 /* # */);
		dissect_crc(payload_tvb, crc_tvb, pinfo, tree, conv);
		break;
	case GDB_STUB_ACK:
		dissect_one_stub_ack(tvb, pinfo, tree, conv);
		break;
	case GDB_NOTIFICATION:
		msg_len = tvb_length(tvb) - 1 /* % */ - crc_len;
		payload_tvb = tvb_new_subset_length(tvb, 1, msg_len);
		dissect_one_notification(tvb, pinfo, tree, conv);

		crc_tvb = tvb_new_subset_remaining(tvb, tvb_length(tvb) - crc_len + 1 /* # */);
		dissect_crc(payload_tvb, crc_tvb, pinfo, tree, conv);
		break;
	}
}

static void dissect_gdbrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint offset = 0;
	const guint max_offset = tvb_reported_length(tvb);
	guint msg_len;
	tvbuff_t *msg_tvb = NULL;

	printf("dissect_gdbrsp with %d bytes\n", max_offset);

	while (tvb_offset_exists(tvb, offset)) {
		msg_len = find_next_message_len(tvb, pinfo, tree, offset);

		if (msg_len > 0) {
			msg_tvb = tvb_new_subset_length(tvb, offset, msg_len);
			dissect_one_gdbrsp(msg_tvb, pinfo, tree);
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
		&hf_offset,
		{
			"Offset", // name
			"gdbrsp.offset", // abbrev
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
	{
		&hf_ptid_pid,
		{
			"PID", // name
			"gdbrsp.pid", // abbrev
			FT_INT32, // type
			BASE_DEC,// display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_ptid_tid,
		{
			"TID", // name
			"gdbrsp.tid", // abbrev
			FT_INT32, // type
			BASE_DEC, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_filename,
		{
			"Filename", // name
			"gdbrsp.filename", // abbrev
			FT_STRING, // type
			BASE_NONE, // display
			0, // strings
			0x0, // bitmask
			NULL, // blurb
			HFILL
		}
	},
	{
		&hf_object,
		{
			"Object", // name
			"gdbrsp.object", // abbrev
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
	{ &ett_gdbrsp, &ett_qsupported, &ett_program_signals, &ett_ptid };

	proto_gdbrsp = proto_register_protocol("GDB Remote Serial Protocol", "GDB RSP", "gdbrsp");
	proto_register_field_array(proto_gdbrsp, hf_gdbrsp, array_length (hf_gdbrsp));
	proto_register_subtree_array(ett_gdbrsp_arr, array_length (ett_gdbrsp_arr));
}

void proto_reg_handoff_gdbrsp_gdbrsp(void) {
	static dissector_handle_t gdbrsp_handle;

	gdbrsp_handle = create_dissector_handle(dissect_gdbrsp, proto_gdbrsp);

	dissector_add_uint("tcp.port", gdbrsp_PORT, gdbrsp_handle);
}

