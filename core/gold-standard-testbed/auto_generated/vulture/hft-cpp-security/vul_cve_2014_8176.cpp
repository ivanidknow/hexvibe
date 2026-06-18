// Vulnerable: VUL-CVE-2014-8176
while ( (item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL)
	{
	frag = (hm_fragment *)item->data;
	OPENSSL_free(frag->fragment);
	OPENSSL_free(frag);
	pitem_free(item);
	}
