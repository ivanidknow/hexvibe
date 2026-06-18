// Vulnerable: VUL-CVE-2016-5352
}

if (key_bytes_len < GROUP_KEY_MIN_LEN || key_bytes_len > eapol_len - sizeof(EAPOL_RSN_KEY)) {
    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
}
