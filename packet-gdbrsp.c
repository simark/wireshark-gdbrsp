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
#include <epan/dissectors/packet-tcp.h>
#define gdbrsp_PORT 1234

/* The protocol handle */
static int proto_gdbrsp = -1;

/* The main subtree handle */
static gint ett_gdbrsp = -1;

/* Other subtrees */
static gint ett_qsupported = -1;

/* Variables for fields */
static int hf_command = -1;
static int hf_ack = -1;
static int hf_qsupported = -1;
static int hf_checksum = -1;
static int hf_reply_to = -1;
static int hf_request_in = -1;
static int hf_reply_in = -1;

// strlen("#XX");
static const guint crc_len = 3;

enum gdb_msg_type {
  GDB_HOST_QUERY,
  GDB_HOST_ACK,
  GDB_STUB_REPLY,
  GDB_STUB_ACK,
  GDB_NOTIFICATION,
};

struct gdbrsp_conv_data;

struct dissect_command_t {
	char *command;
	void (*command_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
	    struct gdbrsp_conv_data *conv);
	void (*reply_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
	    struct gdbrsp_conv_data *conv);
};

struct per_packet_data {
	gboolean visited;
	enum gdb_msg_type type;
	/* The command this request/reply is for */
	struct dissect_command_t *command;
	/* Reply framenum for request and vice-versa */
	gint matching_framenum;
};

struct gdbrsp_conv_data {
	enum gdb_msg_type next_expected_msg;

	/* Details about last command processed */
	struct dissect_command_t *last_command;
	guint last_command_framenum;
	struct per_packet_data *last_command_data;

	int ack_enabled;
	/* When we see QStartNoAckMode, we know that the next host ack will be the last. */
	int disable_ack_at_next_host_ack;
};

char* ack_types[] =
{ "Packet received correctly", "Retransmission requested", };

static void dissect_cmd_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
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

	guint8 c;

	guint offset_start = offset + 1;
	guint offset_end = offset_start;

	while (offset_end < offset + msg_len) {
		c = tvb_get_guint8(tvb, offset_end);
		while (c != ';' && offset_end < offset + msg_len) {
			offset_end++;
			c = tvb_get_guint8(tvb, offset_end);
		}

		gchar *feature = (gchar*) tvb_get_ephemeral_string(tvb, offset_start, offset_end - offset_start);

		if (tree) {
			proto_tree_add_string(tree, hf_qsupported, tvb, offset_start, offset_end - offset_start, feature);
		}

		offset_end = offset_end + 1;
		offset_start = offset_end;
	}
}

static void dissect_cmd_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
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
}

static void dissect_cmd_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    guint msg_len, struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    guint msg_len, struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
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

static void dissect_cmd_QPassSignal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_QPassSignal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
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
}

static void dissect_cmd_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_cmd_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}

static void dissect_reply_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
}


static struct dissect_command_t cmd_cbs[] = {
	{ "vCont", dissect_cmd_vCont, dissect_reply_vCont },
	{ "vStopped", dissect_cmd_vStopped, dissect_reply_vStopped },
	{ "qSupported", dissect_cmd_qSupported, dissect_reply_qSupported },
	{ "QStartNoAckMode", dissect_cmd_QStartNoAckMode, dissect_reply_QStartNoAckMode },
	{ "QProgramSignals", dissect_cmd_QProgramSignals, dissect_reply_QProgramSignals },
	{ "H", dissect_cmd_H, dissect_reply_H },
	{ "qXfer", dissect_cmd_qXfer, dissect_reply_qXfer },
	{ "QNonStop", dissect_cmd_QNonStop, dissect_reply_QNonStop },
	{ "qAttached", dissect_cmd_qAttached, dissect_reply_qAttached },
	{ "qTStatus", dissect_cmd_qTStatus, dissect_reply_qTStatus },
	{ "qTfV", dissect_cmd_qTfV, dissect_reply_qTfV },
	{ "qTfP", dissect_cmd_qTfP, dissect_reply_qTfP },
	{ "qTsV", dissect_cmd_qTsV, dissect_reply_qTsV },
	{ "?", dissect_cmd_haltreason, dissect_reply_haltreason },
	{ "qC", dissect_cmd_qC, dissect_reply_qC },
	{ "qOffsets", dissect_cmd_qOffsets, dissect_reply_qOffsets },
	{ "QPassSignal", dissect_cmd_QPassSignal, dissect_reply_QPassSignal },
	{ "qSymbol", dissect_cmd_qSymbol, dissect_reply_qSymbol },
	{ "m", dissect_cmd_m, dissect_reply_m },
	{ "Z", dissect_cmd_Z, dissect_reply_Z },
	{ "g", dissect_cmd_g, dissect_reply_g },
	{ "G", dissect_cmd_G, dissect_reply_G },
	{ "P", dissect_cmd_P, dissect_reply_P },
	{ "X", dissect_cmd_X, dissect_reply_X },
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

	if (packet_data->visited) {
		cmd = packet_data->command;
	} else {
		/* Skip $ */
		cmd = find_command(tvb, offset + 1);
		packet_data->visited = TRUE;
		packet_data->command = cmd;
	}

	conv->last_command = cmd;
	conv->last_command_framenum = pinfo->fd->num;
	conv->last_command_data = packet_data;

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
	}
}

static void dissect_one_host_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
	printf("Host ack %d\n", msg_len);
	guint8 c = tvb_get_guint8(tvb, offset);
	col_append_str(pinfo->cinfo, COL_INFO, "Host acknowledgement");

	if (conv->disable_ack_at_next_host_ack) {
		conv->ack_enabled = 0;
		conv->disable_ack_at_next_host_ack = 0;
	}

	if (msg_len == 1 && (c == '+' || c == '-')) {
		if (tree) {
			// Add protocol section in the packet details
			proto_tree_add_boolean(tree, hf_ack, tvb, offset, 1, c == '+' ? TRUE : FALSE);
		}
	}
}

static void dissect_one_stub_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
	struct dissect_command_t *cmd;
	printf("Stub reply\n");
	col_append_str(pinfo->cinfo, COL_INFO, "Stub reply");

	struct per_packet_data *packet_data = p_get_proto_data(pinfo->fd, proto_gdbrsp, 0);

	if (!packet_data->visited) {
		packet_data->command = conv->last_command;
		packet_data->matching_framenum = conv->last_command_framenum;
		conv->last_command_data->matching_framenum = pinfo->fd->num;

		packet_data->visited = TRUE;
	}

	cmd = packet_data->command;

	if (!cmd) {
		printf("Reply to unknown command\n");
		return;
	}

	if (tree) {
		proto_tree_add_string(tree, hf_reply_to, tvb, 0, 0, cmd->command);
	}

	col_append_str(pinfo->cinfo, COL_INFO, " (");
	col_append_str(pinfo->cinfo, COL_INFO, cmd->command);
	col_append_str(pinfo->cinfo, COL_INFO, ")");

	cmd->reply_handler(tvb, pinfo, tree, offset, msg_len, conv);

	if (tree) {
		proto_tree_add_uint(tree, hf_request_in, tvb, 0, 0, packet_data->matching_framenum);
	}
}

static void dissect_one_stub_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
	printf("Stub ack %d\n", msg_len);
	guint8 c = tvb_get_guint8(tvb, offset);
	col_append_str(pinfo->cinfo, COL_INFO, "Stub acknowledgement");

	if (msg_len == 1 && (c == '+' || c == '-')) {
		if (tree) {
			// Add protocol section in the packet details
			proto_tree_add_boolean(tree, hf_ack, tvb, offset, 1, c == '+' ? TRUE : FALSE);
		}
	}
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
		packet_data->visited = FALSE;
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
			"gdbrsp.replyto", // abbrev
			FT_STRING, // type
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
};

void proto_register_gdbrsp(void) {

	static gint *ett_gdbrsp_arr[] =
	{ &ett_gdbrsp, &ett_qsupported };

	proto_gdbrsp = proto_register_protocol("GDB Remote Serial Protocol", "GDB RSP", "gdbrsp");
	proto_register_field_array(proto_gdbrsp, hf_gdbrsp, array_length (hf_gdbrsp));
	proto_register_subtree_array(ett_gdbrsp_arr, array_length (ett_gdbrsp_arr));
}

void proto_reg_handoff_gdbrsp_gdbrsp(void) {
	static dissector_handle_t gdbrsp_handle;

	gdbrsp_handle = create_dissector_handle(dissect_gdbrsp, proto_gdbrsp);

	dissector_add_uint("tcp.port", gdbrsp_PORT, gdbrsp_handle);
}

