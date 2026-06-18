// Vulnerable: VUL-CVE-2020-11089
UINT32 Length;
	UINT64 Offset;

	if (!drive || !irp || !irp->input || !irp->output || !irp->Complete)
...
	Stream_Read_UINT64(irp->input, Offset);
	Stream_Seek(irp->input, 20); /* Padding */
	file = drive_get_file_by_id(drive, irp->FileId);

...
		Length = 0;
...
	if ((packetLength > INT_MAX) || !Stream_EnsureCapacity(s, packetLength))
	{
		Stream_Free(s, TRUE);
