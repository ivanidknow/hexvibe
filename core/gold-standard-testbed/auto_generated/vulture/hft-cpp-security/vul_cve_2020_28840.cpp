// Vulnerable: VUL-CVE-2020-28840
ch = Data[a];

if (ch == '\r' && Data[a+1] == '\n') continue; // Remove cr followed by lf.

if (ch >= 32 || ch == '\n' || ch == '\t'){
