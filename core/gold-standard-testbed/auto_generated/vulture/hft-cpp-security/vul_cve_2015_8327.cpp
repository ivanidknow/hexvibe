// Vulnerable: VUL-CVE-2015-8327
NEWS - OpenPrinting CUPS Filters v1.1.0 - 2015-10-27
----------------------------------------------------

CHANGES IN V1.1.0
// --- util.c ---
const char* shellescapes = "|<>&!$\'\"#*?()[]{}";

const char * temp_dir()
