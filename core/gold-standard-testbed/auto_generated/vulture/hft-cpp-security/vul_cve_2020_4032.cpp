// Vulnerable: VUL-CVE-2020-4032
return FALSE;
	}
	diff = start - end;
	if (diff > 0)
	{
...
		WLog_Print(update->log, WLOG_DEBUG,
		           "SECONDARY_ORDER %s: read %" PRIuz "bytes short, skipping", name, diff);
		Stream_Seek(s, diff);
	}
	return rc;
