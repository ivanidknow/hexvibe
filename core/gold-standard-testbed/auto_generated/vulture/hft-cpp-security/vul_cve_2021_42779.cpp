// Vulnerable: VUL-CVE-2021-42779
struct sc_pkcs15_object *objs[0x10], *pin_obj = NULL;
		const struct sc_acl_entry *acl = sc_file_get_acl_entry(file, SC_AC_OP_READ);
		int ii;

		if (acl == NULL) {
...
		}

		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 0x10);
		if (rv != SC_SUCCESS) {
			sc_file_free(file);
...
					auth_info->attrs.pin.reference, acl->key_ref, auth_info->auth_method, acl->method);
			if (auth_info->attrs.pin.reference == (int)acl->key_ref && auth_info->auth_method == (unsigned)acl->method)   {
				pin_obj = objs[ii];
