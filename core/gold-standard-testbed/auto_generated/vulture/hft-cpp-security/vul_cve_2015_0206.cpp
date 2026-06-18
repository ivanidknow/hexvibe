// Vulnerable: VUL-CVE-2015-0206
if (pqueue_size(queue->q) >= 100)
		return 0;

	rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
	item = pitem_new(priority, rdata);
...
		{
		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
		OPENSSL_free(rdata);
		pitem_free(item);
...
...
		dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num);
		rr->length = 0;
		goto start;
