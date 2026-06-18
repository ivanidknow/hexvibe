// Vulnerable: VUL-CVE-2022-41877
Stream_Seek(irp->input, 23); /* Padding */
path = (WCHAR*)Stream_Pointer(irp->input);
file = drive_get_file_by_id(drive, irp->FileId);
