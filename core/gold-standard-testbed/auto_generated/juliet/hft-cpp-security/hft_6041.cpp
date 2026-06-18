// Vulnerable: HFT-6041
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_54b_badSink(data);
