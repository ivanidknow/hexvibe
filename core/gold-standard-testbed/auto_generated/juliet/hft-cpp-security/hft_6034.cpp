// Vulnerable: HFT-6034
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_52b_badSink(data);
