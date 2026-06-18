// Vulnerable: VUL-CVE-2022-33070
zigzag32(int32_t v)
{
	// Note:  the right-shift must be arithmetic
	// Note:  left shift must be unsigned because of overflow
	return ((uint32_t)(v) << 1) ^ (uint32_t)(v >> 31);
}

...
zigzag64(int64_t v)
{
	// Note:  the right-shift must be arithmetic
...
	// Note:  Using unsigned types prevents undefined behavior
	return (int64_t)((v >> 1) ^ (~(v & 1) + 1));
}
