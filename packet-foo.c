/* packet-foo.c
 * Routines for HP 2101nw wireless USB print server 
 * packet disassembly
 * Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
 * 
 * Base on packet-interlink.c:
 * Routines for Interlink protocol packet disassembly
 * By Uwe Girlich <uwe.girlich@philosys.de>
 * Copyright 2010 Uwe Girlich
 *
 * $Id: packet-foo.c 35224 2010-12-20 05:35:29Z guy $
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

#define FOO_PORT 1234

static int proto_foo = -1;
static gint ett_foo = -1;

/* Variables for foo packets */
static int hf_foo_field = -1;

/* Displayed names of commands */
static const value_string strings_field[] = {
  { 0x00, "temp 1" },
  { 0x01, "temp 2" },
  { 0x00, NULL }
};


static int
dissect_foo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint offset = 0;
  guint8 cmdtype = tvb_get_guint8 (tvb, 0);

  /* TODO: Some sanity checking to determine whether the packet is really
   *       a foo communication packet */
  if (/*not a foo packet*/FALSE)
    return 0;
  /* TODO: How do we detect answers by the device? They don't have any
   *       custom header or standardized format! */


  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "foo communication packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = NULL;
    proto_item *foo_tree = NULL;

    ti = proto_tree_add_item (tree, proto_foo, tvb, 0, -1, ENC_NA);
    foo_tree = proto_item_add_subtree (ti, ett_foo);
    proto_tree_add_item (foo_tree, hf_foo_field, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* TODO: Implement further packet fields here */

    return offset;
  }
  return tvb_length(tvb);
}
void
proto_register_foo(void)
{
  static hf_register_info hf_foo[] = {
    { &hf_foo_field,
        { "First field of the packet", "foo.field",
          FT_UINT8, BASE_DEC_HEX,
          VALS(strings_field), 0x0,
          NULL, HFILL },
    }
    /* TODO: Other packet fields */
    
  };
  static gint *ett_foo_arr[] = { /* protocol subtree array */
    &ett_foo
  };
  proto_foo = proto_register_protocol(
    "FOO communication", "foo", "foo");
  proto_register_field_array (proto_foo, hf_foo, array_length (hf_foo));
  proto_register_subtree_array (ett_foo_arr, array_length (ett_foo_arr));
}

void
proto_reg_handoff_foo_foo(void)
{
  static dissector_handle_t foo_handle;
  foo_handle = new_create_dissector_handle (dissect_foo, proto_foo);
  dissector_add_uint ("tcp.port", FOO_PORT, foo_handle);
}

