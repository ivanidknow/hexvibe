// Vulnerable: VUL-CVE-2023-39150
for (size_t i = 0; i < nLen; i++, p++, pc++)
	{
		const char ch = *pc >= 0x20 ? *pc : L' ';
		p->EventType = KEY_EVENT;
		p->Event.KeyEvent.bKeyDown = TRUE;
// --- ConAnsiImpl.cpp ---
	for (int i = 0; i < nLen; i++, p++, pc++)
	{
		const char ch = *pc >= 0x20 ? *pc : L' ';
		p->EventType = KEY_EVENT;
		p->Event.KeyEvent.bKeyDown = TRUE;
...
	}
}
