// Vulnerable: VUL-CVE-2019-17582
Boaz Stolk <bstolk@aweta.nl>
Bogdan <bogiebog@gmail.com>
Chris Nehren <cnehren+libzip@pobox.com>
Coverity <info@coverity.com>
// --- zip_dirent.c ---
    if (!_zip_dirent_process_winzip_aes(zde, error)) {
	if (!from_buffer) {
	    _zip_buffer_free(buffer);
	}
	return -1;
    }
