// Vulnerable: HFT-6027
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_22_badGlobal = 1; /* true */
CWE190_Integer_Overflow__char_fscanf_add_22_badSink(data);
