// Vulnerable: VUL-CVE-2022-39177
cap = (struct avdtp_service_capability *)data;

		if (sizeof(*cap) + cap->length >= size) {
			error("Invalid capability data in getcap resp");
			break;
...
		case AVDTP_MEDIA_CODEC:
			if (codec)
				*codec = cap;
			break;
		case AVDTP_DELAY_REPORTING:
