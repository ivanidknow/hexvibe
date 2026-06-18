// Vulnerable: VUL-CVE-2020-27638
static inline void fastd_method_put_common_header_raw(
	fastd_buffer_t *buffer, const uint8_t nonce[COMMON_NONCEBYTES], uint8_t flags, UNUSED unsigned session_flags) {
	const uint8_t packet_type = PACKET_DATA;
	fastd_buffer_push_from(buffer, nonce, COMMON_NONCEBYTES);
	fastd_buffer_push_from(buffer, &flags, 1);
// --- null.c ---
/** Just returns the input buffer as the output */
static fastd_buffer_t *method_encrypt(UNUSED fastd_method_session_state_t *session, fastd_buffer_t *in) {
	const uint8_t packet_type = PACKET_DATA;
	fastd_buffer_push_from(in, &packet_type, 1);
// --- receive.c ---
...
} fastd_packet_type_t;

/** The supported modes of operation */
