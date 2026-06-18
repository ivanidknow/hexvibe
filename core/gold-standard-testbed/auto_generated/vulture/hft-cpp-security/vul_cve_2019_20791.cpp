// Vulnerable: VUL-CVE-2019-20791
VerifyOrExit((strlen(aPassPhrase) >= OT_COMMISSIONING_PASSPHRASE_MIN_SIZE) &&
                 (strlen(aPassPhrase) <= OT_COMMISSIONING_PASSPHRASE_MAX_SIZE),
             error = OT_ERROR_INVALID_ARGS);
