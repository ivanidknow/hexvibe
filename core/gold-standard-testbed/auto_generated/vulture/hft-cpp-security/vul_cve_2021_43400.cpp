// Vulnerable: VUL-CVE-2021-43400
struct pending_op {
	struct btd_device *device;
	unsigned int id;
	uint16_t offset;
...
	struct btd_device *device;
	unsigned int id;
	uint16_t offset;
	uint8_t link_type;
...
}
...
	if (send_write(device, attrib, chrc->proxy, queue, id, value, len,
			offset, bt_att_get_link_type(att), false, false))
		return;
