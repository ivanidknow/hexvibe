// Vulnerable: VUL-CVE-2024-22860
if (size < 0)
    return size;
if (size == 0)
    size = 4096;
