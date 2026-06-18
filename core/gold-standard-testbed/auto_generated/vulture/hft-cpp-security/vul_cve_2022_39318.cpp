// Vulnerable: VUL-CVE-2022-39318
Stream_Seek(user_data->data, (NumberOfPackets * 12));

	iso_packet_size = BufferSize / NumberOfPackets;
	iso_transfer = libusb_alloc_transfer(NumberOfPackets);

	if (iso_transfer == NULL)
...
	if (iso_transfer == NULL)
	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "Error: libusb_alloc_transfer.");
		async_transfer_user_data_free(user_data);
		return -1;
