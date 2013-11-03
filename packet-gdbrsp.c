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

/* Variables for fields */
static int hf_gdbrsp_command = -1;
static int hf_ack = -1;

struct dissect_command_t {
  char *command;
  void (*handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv);
};

enum gdb_msg_type {
  GDB_HOST_QUERY,
  GDB_HOST_ACK,
  GDB_STUB_REPLY,
  GDB_STUB_ACK,
  GDB_NOTIFICATION,
};

struct gdbrsp_conv_data {
  enum gdb_msg_type next_expected_msg;
  int ack_enabled;
  /* When we see QStartNoAckMode, we know that the next host ack will be the last. */
  int disable_ack_at_next_host_ack;
};

static void dissect_cmd_vCont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_vStopped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qSupported(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_QStartNoAckMode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {
  conv->disable_ack_at_next_host_ack = 1;
}

static void dissect_cmd_QProgramSignals(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_H(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qXfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_QNonStop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qAttached(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qTStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qTfV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qTfP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qTsV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_question(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qC(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qOffsets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_QPassSignal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_qSymbol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_Z(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_G(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_P(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}

static void dissect_cmd_X(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint poffset, struct gdbrsp_conv_data *conv) {

}


static struct dissect_command_t cmd_cbs[] = {
    { "vCont", dissect_cmd_vCont },
    { "vStopped", dissect_cmd_vStopped },
    { "qSupported", dissect_cmd_qSupported },
    { "QStartNoAckMode", dissect_cmd_QStartNoAckMode },
    { "QProgramSignals", dissect_cmd_QProgramSignals },
    { "H", dissect_cmd_H },
    { "qXfer", dissect_cmd_qXfer },
    { "QNonStop", dissect_cmd_QNonStop },
    { "qAttached", dissect_cmd_qAttached },
    { "qTStatus", dissect_cmd_qTStatus },
    { "qTfV", dissect_cmd_qTfV },
    { "qTfP", dissect_cmd_qTfP },
    { "qTsV", dissect_cmd_qTsV },
    { "?", dissect_cmd_question },
    { "qC", dissect_cmd_qC },
    { "qOffsets", dissect_cmd_qOffsets },
    { "QPassSignal", dissect_cmd_QPassSignal },
    { "qSymbol", dissect_cmd_qSymbol },
    { "m", dissect_cmd_m },
    { "Z", dissect_cmd_Z },
    { "g", dissect_cmd_g },
    { "G", dissect_cmd_G },
    { "P", dissect_cmd_P },
    { "X", dissect_cmd_X },


    { NULL, NULL },
};

static void handle_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset) {
  printf("That was an ACK\n");
  col_set_str(pinfo->cinfo, COL_INFO, "ACK");
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GDB-RSP");
  if (tree) {
    proto_item *ti = proto_tree_add_item(tree, proto_gdbrsp, tvb, offset, 1, ENC_NA);
    proto_tree * new_tree = proto_item_add_subtree(ti, ett_gdbrsp);
    proto_tree_add_string(new_tree, hf_gdbrsp_command, tvb, offset, 1, "Message acknowledged");
  }
}

static void dissect_one_host_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
  struct dissect_command_t *cmd;
  printf("Host query\n");

  for (cmd = cmd_cbs; cmd->command != NULL ; cmd++) {
    int len = strlen(cmd->command);

    if (tvb_strneql(tvb, offset + 1, cmd->command, len) == 0) {
      printf("> %s\n", cmd->command);

      if (tree) {
	// Add protocol section in the packet details
	proto_tree_add_string(tree, hf_gdbrsp_command, tvb, offset + 1, len, cmd->command);
      }

      col_append_str(pinfo->cinfo, COL_INFO, cmd->command);
      col_append_str(pinfo->cinfo, COL_INFO, " command");

      cmd->handler(tvb, pinfo, tree, offset, conv);
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
  printf("Stub reply\n");
  col_append_str(pinfo->cinfo, COL_INFO, "Stub reply");
}

static void dissect_one_stub_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint msg_len,
    struct gdbrsp_conv_data *conv) {
  printf("Stub ack %d\n", msg_len);
  guint8 c = tvb_get_guint8(tvb, offset);
  col_append_str(pinfo->cinfo, COL_INFO, "Stub acknowledgement");

  if (msg_len == 1 && c == '+') {
    if (tree) {
	// Add protocol section in the packet details

      proto_tree_add_boolean(tree, hf_ack, tvb, offset, 1, TRUE);

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

struct per_packet_data {
  enum gdb_msg_type type;
};

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
  const guint8 starting_char_ack_win = '+';
  const guint8 starting_char_ack_fail = '-';
  const guint8 starting_char = '$';
  const guint8 terminating_char = '#';
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
    packet_data = malloc(sizeof(packet_data));
    // TODO: add check and exception
    // TODO: When to free that memory?

    guint8 first_char = tvb_get_guint8(tvb, 0);

    packet_data->type = determine_type(conv, first_char);

    p_add_proto_data(pinfo->fd, proto_gdbrsp, 0, packet_data);
  }

  // Dissect based on what we expect to have
  switch (packet_data->type) {
  case GDB_HOST_QUERY:
    dissect_one_host_query(tvb, pinfo, tree, offset, msg_len, conv);
    break;
  case GDB_HOST_ACK:
    dissect_one_host_ack(tvb, pinfo, tree, offset, msg_len, conv);
    break;
  case GDB_STUB_REPLY:
    dissect_one_stub_reply(tvb, pinfo, tree, offset, msg_len, conv);
    break;
  case GDB_STUB_ACK:
    dissect_one_stub_ack(tvb, pinfo, tree, offset, msg_len, conv);
    break;
  case GDB_NOTIFICATION:
    dissect_one_notification(tvb, pinfo, tree, offset, msg_len, conv);
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

void proto_register_gdbrsp(void) {
  static hf_register_info hf_gdbrsp[] = {
      {
	  &hf_gdbrsp_command,
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
      	  &hf_ack,
      	  {
      	      "success", // name
      	      "gdbrsp.ack", // abbrev
      	      FT_BOOLEAN, // type
      	      BASE_NONE, // display
      	      0, // strings
      	      0x0, // bitmask
      	      NULL, // blurb
      	      HFILL
      }
	},
  };
  static gint *ett_gdbrsp_arr[] = { &ett_gdbrsp };

  proto_gdbrsp = proto_register_protocol("GDB Remote Serial Protocol", "gdbrsp", "gdbrsp");
  proto_register_field_array(proto_gdbrsp, hf_gdbrsp, array_length (hf_gdbrsp));
  proto_register_subtree_array(ett_gdbrsp_arr, array_length (ett_gdbrsp_arr));
}

void proto_reg_handoff_gdbrsp_gdbrsp(void) {
  static dissector_handle_t gdbrsp_handle;

  gdbrsp_handle = create_dissector_handle(dissect_gdbrsp, proto_gdbrsp);

  dissector_add_uint("tcp.port", gdbrsp_PORT, gdbrsp_handle);
}

