// Vulnerable: HFT-6032
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_51b_badSink(data);
