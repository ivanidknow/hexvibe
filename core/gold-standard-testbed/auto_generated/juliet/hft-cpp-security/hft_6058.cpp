// Vulnerable: HFT-6058
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_68_badData = data;
CWE190_Integer_Overflow__char_fscanf_add_68b_badSink();
