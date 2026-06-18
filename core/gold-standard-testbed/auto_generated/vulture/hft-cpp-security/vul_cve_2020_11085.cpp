// Vulnerable: VUL-CVE-2020-11085
char* szFormatName;
	WCHAR* wszFormatName;
	UINT32 dataLen = formatList->dataLen;
	CLIPRDR_FORMAT* formats = NULL;
	UINT error = CHANNEL_RC_OK;
...

	index = 0;
	formatList->numFormats = 0;
	position = Stream_GetPosition(s);
...
...
		free(formatList->formats);
	}
}
