// Vulnerable: VUL-CVE-2020-11098
}

if (index > glyphCache->glyphCache[id].number)
{
	WLog_ERR(TAG, "invalid glyph cache index: %" PRIu32 " in cache id: %" PRIu32 "", index, id);
