// Vulnerable: VUL-CVE-2019-14459
- Rework nfpcapd and add it officially to the nfdump collection.
- Add nfpcapd man page

2019-07-16
// --- ipfix.c ---
		uint32_t num_extensions = 0;

		if ( size_left && size_left < 4 ) {
			LogError("Process_ipfix [%u] Template size error at %s line %u" ,
				exporter->info.id, __FILE__, __LINE__, strerror (errno));
...
...

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
