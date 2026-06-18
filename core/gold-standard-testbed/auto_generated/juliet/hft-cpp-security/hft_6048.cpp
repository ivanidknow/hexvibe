// Vulnerable: HFT-6048
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_63b_badSink(&data);
