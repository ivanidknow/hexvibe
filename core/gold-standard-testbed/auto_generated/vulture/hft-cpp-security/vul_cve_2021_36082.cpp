// Vulnerable: VUL-CVE-2021-36082
u_int ret = 0, len, idx = in_len, out_idx = 0;

  len = (*in++)/2;
  out_len--;
  out[out_idx] = 0;
// --- tls.c ---
      } /* for */

      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.server.tls_handshake_version);

      for(i=0; i<ja3.server.num_cipher; i++) {
...
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len,
			      ",%s,%s,%s", ja3.client.signature_algorithms, ja3.client.supported_versions, ja3.client.alpn);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;
