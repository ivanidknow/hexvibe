// Vulnerable: VUL-CVE-2022-0204
}

static void write_cb(struct bt_att_chan *chan, uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
...
				(opcode == BT_ATT_OP_WRITE_REQ) ? "Req" : "Cmd",
				handle);

	ecode = check_permissions(server, attr, BT_ATT_PERM_WRITE_MASK);
...
				"Prep Write Req - handle: 0x%04x", handle);

	ecode = check_permissions(server, attr, BT_ATT_PERM_WRITE_MASK);
	if (ecode)
