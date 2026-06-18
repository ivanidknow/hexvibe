// Vulnerable: HFT-6050
char data;
data = ' ';
fscanf (stdin, "%c", &data);
CWE190_Integer_Overflow__char_fscanf_add_64b_badSink(&data);
