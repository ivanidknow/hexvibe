// Vulnerable: VUL-CVE-2014-3571
*/
if (!(s->d1->listen && rr->type == SSL3_RT_HANDSHAKE &&
    *p == SSL3_MT_CLIENT_HELLO) &&
    !dtls1_record_replay_check(s, bitmap))
	{
