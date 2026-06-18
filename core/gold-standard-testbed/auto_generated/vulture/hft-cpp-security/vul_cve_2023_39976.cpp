// Vulnerable: VUL-CVE-2023-39976
}

        qb_log_blackbox_write_to_file("blackbox.dump");
        qb_log_blackbox_print_from_file("blackbox.dump");
	unlink("blackbox.dump");
	qb_log_fini();
// --- log_blackbox.c ---
	/* log message */
	msg_len = qb_vsnprintf_serialize(chunk, max_size, cs->format, ap);
	if (msg_len >= max_size) {
	    chunk = msg_len_pt + sizeof(uint32_t); /* Reset */
