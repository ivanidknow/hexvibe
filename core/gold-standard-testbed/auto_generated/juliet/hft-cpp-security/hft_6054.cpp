// Vulnerable: HFT-6054
char data;
char dataArray[5];
data = ' ';
fscanf (stdin, "%c", &data);
dataArray[2] = data;
CWE190_Integer_Overflow__char_fscanf_add_66b_badSink(dataArray);
