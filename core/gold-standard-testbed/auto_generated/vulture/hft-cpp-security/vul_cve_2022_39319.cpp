// Vulnerable: VUL-CVE-2022-39319
Stream_Read_UINT32(s, OutputBufferSize);
	Stream_Read_UINT32(s, RequestId);
	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = urb_create_iocompletion(InterfaceId, MessageId, RequestId, OutputBufferSize + 4);
...
	Stream_Read_UINT32(s, OutputBufferSize);
	EndpointAddress = (PipeHandle & 0x000000ff);
	/**  process TS_URB_BULK_OR_INTERRUPT_TRANSFER */
	return pdev->bulk_or_interrupt_transfer(
...
	Stream_Seek(s, NumberOfPackets * 12);
	Stream_Read_UINT32(s, OutputBufferSize);
	return pdev->isoch_transfer(
	    pdev, callback, MessageId, RequestId, EndpointAddress, TransferFlags, StartFrame,
