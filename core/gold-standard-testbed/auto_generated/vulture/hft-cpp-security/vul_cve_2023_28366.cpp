// Vulnerable: VUL-CVE-2023-28366
Security:
- Broker will now reject Will messages that attempt to publish to $CONTROL/.
- Broker now validates usernames provided in a TLS certificate or TLS-PSK
// --- Makefile ---
	./03-publish-qos1-retain-disabled.py
	./03-publish-qos1.py
	./03-publish-qos2-max-inflight.py
	./03-publish-qos2.py
// --- context.c ---
	}
	context->bridge = NULL;
...
	context->out_packet_count = 0;
#if defined(WITH_BROKER) && defined(__GLIBC__) && defined(WITH_ADNS)
	if(context->adns){
