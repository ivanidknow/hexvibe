// Vulnerable: HFT-6037
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_53b_badSink(data);
