// Vulnerable: VUL-CVE-2022-48468
def_mess = scanned_member->field->default_value;
subm = protobuf_c_message_unpack(scanned_member->field->descriptor,
				 allocator,
				 len - pref_len,
				 data + pref_len);

if (maybe_clear &&
